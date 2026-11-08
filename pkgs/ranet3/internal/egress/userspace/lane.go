// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package userspace

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/maphash"
	"net/netip"
	"sync"

	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/packet"
	"ranet3.com/pkgs/wireguard/tun"
)

// Lanes opens the exit's ways into the mesh's outbound path. MeshLanes adapts
// a mesh to it, and a unit test passes a fake.
type Lanes interface {
	OpenLane() Lane
}

// Lane is one of the exit's ways into the outbound path, as *netstack.Lane
// gives it
type Lane interface {
	// Fill takes a free outbound batch, has fill lay packets in its slab as a
	// tun read lays them, and sends them through the checks a read off the
	// tun meets. It reports false once the mesh is closing.
	Fill(fill func(slab []byte, reads []tun.ReadPacket) int) bool
	// Answer sends this node's ICMP error of kind about offending toward its
	// source, mtu being the path's a too big carries
	Answer(offending []byte, kind netstack.ExitAnswer, mtu int) bool
	// MTU is the largest packet the session from source to destination
	// carries, zero where the mesh routes it to no peer
	MTU(source, destination netip.Addr) int
	// SameSession is whether the mesh sends from source to a and to b through
	// one peer's session, a packet a steer entry claims by its first segment's
	SameSession(source, a, b netip.Addr) bool
	// Done is closed once the mesh closes, and Close gives the lane back
	Done() <-chan struct{}
	Close()
}

var _ Lane = (*netstack.Lane)(nil)

// MeshLanes is the lanes of mesh
func MeshLanes(mesh *netstack.Mesh) Lanes { return meshLanes{mesh} }

type meshLanes struct{ mesh *netstack.Mesh }

func (l meshLanes) OpenLane() Lane { return l.mesh.OpenLane() }

// worker is one lane's goroutine and the packets queued to it. Every packet of
// one pair of addresses goes to the same worker, so a flow's segments, its
// fragments and a TCP connection's FIN and the SYN that reuses its ports are
// judged and delivered in the order the sessions handed them over.
type worker struct {
	queue chan *[]byte
}

// buffers are the copies Egress makes of the sessions' frames, in two size
// classes, a packet off a link and the largest IP packet
var buffers = [2]sync.Pool{
	{New: func() any { b := make([]byte, 0, smallBuffer); return &b }},
	{New: func() any { b := make([]byte, 0, largeBuffer); return &b }},
}

func bufferClass(size int) int {
	if size <= smallBuffer {
		return 0
	}
	return 1
}

// Egress copies each frame's packet once into a buffer of the exit's and
// queues it to the worker its addresses pick, dropping and counting it where
// the lanes already hold Limits.Lanes bytes or the worker's queue is full, so
// it never waits on a lane
// it reads no frame after it returns, so it retains nothing of hold
func (x *Exit) Egress(frames [][]byte, _ netstack.Hold) {
	if !x.taking.Load() {
		x.counts.laneDropped.Add(uint64(len(frames)))
		return
	}
	for _, frame := range frames {
		raw := frame[netstack.TUNHeadroom:]
		buf := buffers[bufferClass(len(raw))].Get().(*[]byte)
		size := int64(cap(*buf))
		if x.laneHeld.Add(size) > x.rt.Limits.Lanes {
			x.laneHeld.Add(-size)
			buffers[bufferClass(len(raw))].Put(buf)
			x.counts.laneDropped.Add(1)
			continue
		}
		*buf = append((*buf)[:0], raw...)
		select {
		case x.workers[x.workerOf(raw)].queue <- buf:
		default:
			x.release(buf)
			x.counts.laneDropped.Add(1)
		}
	}
}

// workerOf is the worker raw's addresses pick
func (x *Exit) workerOf(raw []byte) int {
	var addresses []byte
	switch {
	case len(raw) >= 20 && raw[0]>>4 == 4:
		addresses = raw[12:20]
	case len(raw) >= 40 && raw[0]>>4 == 6:
		addresses = raw[8:40]
	}
	return int(maphash.Bytes(x.seed, addresses) % uint64(len(x.workers)))
}

// release gives a buffer Egress queued back to its pool and its bytes back to
// the lanes' bound
func (x *Exit) release(buf *[]byte) {
	x.laneHeld.Add(-int64(cap(*buf)))
	buffers[bufferClass(cap(*buf))].Put(buf)
}

// work judges each packet queued to w and answers, drops or delivers it,
// until the exit stops or the mesh closes, and then gives the lane back
func (x *Exit) work(w *worker, lane Lane) {
	defer lane.Close()
	for {
		select {
		case buf := <-w.queue:
			x.handle(lane, *buf)
			x.release(buf)
		case <-x.stop:
			return
		case <-lane.Done():
			return
		}
	}
}

// handle judges raw and acts on the judgment, handing a UDP datagram, an ICMP
// message other than an error or an ICMP error about a UDP datagram that
// needs no reassembly to its relay without the stack
func (x *Exit) handle(lane Lane, raw []byte) {
	j := judge(raw, x.heldDestination)
	switch j.act {
	case deliver:
		if dontFragment, ok := fastUDP(raw); ok {
			x.udp.take(raw, dontFragment)
			return
		}
		if fastQuery(raw) {
			x.echo.take(raw)
			return
		}
		if fastLeafError(raw) {
			x.udp.leafError(raw)
			return
		}
		if reason := leafTCPError(lane, raw); reason != "" {
			x.counts.drop(reason)
			return
		}
		if x.timeWait.see(x.stack, raw) {
			x.counts.reused.Add(1)
		}
		x.link.deliver(raw)
	case answer:
		x.refused(raw, j.reason)
		lane.Answer(raw, j.kind, 0)
	case drop:
		x.counts.drop(j.reason)
	}
}

// The reasons a leaf's ICMP error about a TCP segment is kept from the stack,
// which takes any quoted source as its own and applies the error to the
// endpoint the quote names
const (
	// an error other than a too big whose quoted destination, the leaf end,
	// sits behind another session than its source
	reasonLeafErrorElsewhere = "leaf error elsewhere"
	// a too big below leastMTU4 over IPv4 or 1280 over IPv6 (RFC 8201
	// section 4)
	reasonLeafErrorMTU = "leaf error mtu"
	// the first fragment of an error, whose quote the exit reads only whole
	reasonLeafErrorFragment = "leaf error fragment"
	// an error whose quote the exit cannot read down to a TCP header, which
	// the stack might still read
	reasonLeafErrorQuote = "leaf error quote"
)

// leastMTU4 is the least MTU a leaf's Fragmentation Needed may carry to the
// stack: Linux's default min_pmtu, in place of RFC 1191 section 3's 68, at
// which gVisor would cut its segments below its own least of 48 bytes
const leastMTU4 = 552

// leafTCPError is why raw, a packet the lane's judgment delivers to the stack,
// is kept from it as a leaf's ICMP error: one whose quote reads to no TCP
// header, a too big about a TCP segment below the family's least MTU, another
// error about a TCP segment whose quoted destination sits behind another
// session than its source, or an error in fragments. "" for any other packet.
// A too big at or above the least MTU passes from any session, since one from
// a waypoint or a later hop has a source the mesh may reach by another first
// hop than the leaf, and dropping it would leave the connection sending
// segments that path drops (RFC 1191 section 3, RFC 8201 section 4).
func leafTCPError(lane Lane, raw []byte) string {
	var (
		message    []byte
		ipv6       bool
		source     netip.Addr
		fragment   bool
		tooBig     bool
		mtu, least uint32
	)
	switch packet.Version(raw) {
	case 4:
		header := int(raw[0]&0x0f) * 4
		flags := binary.BigEndian.Uint16(raw[6:8])
		if raw[9] != 1 || flags&0x1fff != 0 || len(raw) < header+8 {
			return ""
		}
		message, source, fragment = raw[header:], netip.AddrFrom4([4]byte(raw[12:16])), flags&0x2000 != 0
		if message[0] != 3 && message[0] != 11 && message[0] != 12 {
			return ""
		}
		tooBig, mtu, least = message[0] == 3 && message[1] == 4, uint32(binary.BigEndian.Uint16(message[6:8])), leastMTU4
	case 6:
		at, next, first, ok := icmp6At(raw)
		if !ok || next != 58 || len(raw) < at+8 {
			return ""
		}
		message, ipv6, source, fragment = raw[at:], true, netip.AddrFrom16([16]byte(raw[8:24])), first
		if message[0] < 1 || message[0] > 4 {
			return ""
		}
		tooBig, mtu, least = message[0] == 2, binary.BigEndian.Uint32(message[4:8]), 1280
	default:
		return ""
	}
	if fragment {
		return reasonLeafErrorFragment
	}
	from, to, ok := quotedTCP(message[8:], ipv6)
	switch {
	case !ok:
		return reasonLeafErrorQuote
	case tooBig && mtu < least:
		return reasonLeafErrorMTU
	case !tooBig && !lane.SameSession(from, source, to):
		return reasonLeafErrorElsewhere
	}
	return ""
}

// quotedTCP is the source and destination quote names, the packet an ICMP
// error quotes, where it reads whole down to the first 8 bytes of a TCP
// header: an IPv4 header of version 4 at fragment offset 0, or an IPv6 header
// past every extension header icmp6At walks, a fragment header at offset 0
// among them, as gVisor steps over one to find the endpoint. false for any
// other quote, which the stack is never handed.
func quotedTCP(quote []byte, ipv6 bool) (from, to netip.Addr, ok bool) {
	if !ipv6 {
		if len(quote) < 20 || quote[0]>>4 != 4 {
			return netip.Addr{}, netip.Addr{}, false
		}
		header := int(quote[0]&0x0f) * 4
		if header < 20 || len(quote) < header+8 || binary.BigEndian.Uint16(quote[6:8])&0x1fff != 0 || quote[9] != 6 {
			return netip.Addr{}, netip.Addr{}, false
		}
		return netip.AddrFrom4([4]byte(quote[12:16])), netip.AddrFrom4([4]byte(quote[16:20])), true
	}
	if len(quote) < 40 || quote[0]>>4 != 6 {
		return netip.Addr{}, netip.Addr{}, false
	}
	if at, next, _, walked := icmp6At(quote); !walked || next != 6 || len(quote) < at+8 {
		return netip.Addr{}, netip.Addr{}, false
	}
	return netip.AddrFrom16([16]byte(quote[8:24])), netip.AddrFrom16([16]byte(quote[24:40])), true
}

// icmp6At is where raw's upper layer header starts past its extension
// headers, the protocol it names, and whether raw is the first of several
// fragments, false where a header runs past raw or raw is a later fragment
func icmp6At(raw []byte) (at int, next byte, first, ok bool) {
	next, at = raw[6], 40
	for {
		switch next {
		case 0, 43, 60:
			if at+8 > len(raw) {
				return 0, 0, false, false
			}
			next, at = raw[at], at+(int(raw[at+1])+1)*8
		case 44:
			if at+8 > len(raw) || binary.BigEndian.Uint16(raw[at+2:at+4])&0xfff8 != 0 {
				return 0, 0, false, false
			}
			next, first, at = raw[at], raw[at+3]&1 != 0, at+8
		default:
			return at, next, first, at <= len(raw)
		}
	}
}

// heldDestination is an address the host holds, its own mesh addresses among
// them
func (x *Exit) heldDestination(address netip.Addr) bool {
	for _, mesh := range x.rt.MeshAddresses {
		if mesh == address {
			return true
		}
	}
	return x.rt.Platform.Held(address, "")
}

// pump lays what the stack sends into batches of its own lane, as a tun read
// lays a read, until the exit stops or the mesh closes. A frame of the
// stack's segmentation offload is cut into its segments as it is laid.
type pump struct {
	link *link
	// held is the next packet the stack sent, which the last batch had no
	// room left for
	held *stack.PacketBuffer
	// cut holds the segments of a frame that fits no batch whole, laid one
	// at a time into the batches that follow
	cut cutFrame
	// unlaid counts the packets dropped as fitting nowhere
	unlaid func()
}

// cutFrame is a frame cut into its segments in a slab of its own, segments
// next to n still to be laid
type cutFrame struct {
	slab    []byte
	reads   []tun.ReadPacket
	next, n int
}

// run fills lane until stop closes, the mesh closes or the link does, and
// then gives the lane back
func (p *pump) run(lane Lane, stop <-chan struct{}) {
	defer lane.Close()
	defer func() {
		if p.held != nil {
			p.link.release(p.held)
		}
	}()
	for {
		if p.held == nil && p.cut.next == p.cut.n {
			if p.held = p.link.next(stop, lane.Done()); p.held == nil {
				return
			}
		}
		if !lane.Fill(p.fill) {
			return
		}
	}
}

// fill lays the cut frame's segments left, the held packet and then each
// packet the link holds, while they fit, and reports how many reads it laid
func (p *pump) fill(slab []byte, reads []tun.ReadPacket) int {
	used, n := 0, 0
	for {
		if p.cut.next < p.cut.n {
			segment := p.cut.reads[p.cut.next]
			at := used + tun.ReadPacketSpacing
			if n == len(reads) || at+segment.Size+tun.ReadPacketSpacing > len(slab) {
				if n != 0 {
					return n
				}
				// fitting no empty batch, it would never be laid
				p.unlaid()
				p.cut.next++
				continue
			}
			copy(slab[at:], p.cut.slab[segment.Offset:segment.Offset+segment.Size])
			reads[n] = tun.ReadPacket{Offset: at, Size: segment.Size}
			n, used = n+1, at+segment.Size
			p.cut.next++
			continue
		}
		if p.held == nil {
			if p.held = p.link.poll(); p.held == nil {
				return n
			}
		}
		k, end, fits := p.lay(p.held, slab[used:], reads[n:])
		switch {
		case fits:
			for i := n; i < n+k; i++ {
				reads[i].Offset += used
			}
			n, used = n+k, used+end
		case n == 0:
			p.cutHeld()
		default:
			return n
		}
		p.link.release(p.held)
		p.held = nil
	}
}

// lay copies pkt into slab after its spacing and cuts it into its segments
// from reads[0]. It reports the segments, where the last ends, and false where
// they do not fit, leaving slab and reads to be written again. A packet whose
// offload it cannot read, or that it cannot cut, fits as no segments and is
// counted.
func (p *pump) lay(pkt *stack.PacketBuffer, slab []byte, reads []tun.ReadPacket) (int, int, bool) {
	spacing := tun.ReadPacketSpacing
	size := pkt.Size()
	options, err := gsoOptions(pkt)
	if err != nil {
		p.unlaid()
		return 0, 0, true
	}
	count, need := 1, size+2*spacing
	if options.GSOType != tun.GSONone {
		// a segment with no payload, as an ACK, is still one packet
		payload := size - int(options.HdrLen)
		count = max(1, (payload+int(options.GSOSize)-1)/int(options.GSOSize))
		need = count*int(options.HdrLen) + payload + (count+1)*spacing
	}
	if need > len(slab) || count > len(reads) {
		return 0, 0, false
	}
	in := slab[spacing : spacing+size]
	copyPacket(in, pkt)
	k, err := tun.GSOSplit(in, options, slab, reads, spacing)
	if err != nil {
		p.unlaid()
		return 0, 0, true
	}
	last := reads[k-1]
	return k, last.Offset + last.Size, true
}

// cutHeld cuts the held packet, which fits no batch whole, into the cut
// frame's slab, or drops and counts it where it fits there neither
func (p *pump) cutHeld() {
	if p.cut.slab == nil {
		p.cut.slab, p.cut.reads = make([]byte, cutSlab), make([]tun.ReadPacket, cutReads)
	}
	k, _, fits := p.lay(p.held, p.cut.slab, p.cut.reads)
	if !fits {
		p.unlaid()
		k = 0
	}
	p.cut.next, p.cut.n = 0, k
}

// copyPacket writes pkt's headers and payload to dst, which holds pkt.Size
// bytes
func copyPacket(dst []byte, pkt *stack.PacketBuffer) {
	n := copy(dst, pkt.NetworkHeader().Slice())
	n += copy(dst[n:], pkt.TransportHeader().Slice())
	views, offset := pkt.AsViewList()
	offset += pkt.HeaderSize()
	for v := views.Front(); v != nil; v = v.Next() {
		if offset >= v.Size() {
			offset -= v.Size()
			continue
		}
		n += copy(dst[n:], v.AsSlice()[offset:])
		offset = 0
	}
}

// gsoOptions is pkt's segmentation offload as a tun read reports it
func gsoOptions(pkt *stack.PacketBuffer) (tun.GSOOptions, error) {
	gso := pkt.GSOOptions
	options := tun.GSOOptions{CsumStart: gso.L3HdrLen, CsumOffset: gso.CsumOffset, GSOSize: gso.MSS, NeedsCsum: gso.NeedsCsum}
	switch gso.Type {
	case stack.GSONone:
		options.GSOType = tun.GSONone
		return options, nil
	case stack.GSOTCPv4:
		options.GSOType = tun.GSOTCPv4
	case stack.GSOTCPv6:
		options.GSOType = tun.GSOTCPv6
	default:
		return tun.GSOOptions{}, fmt.Errorf("userspace: segmentation offload of type %d", gso.Type)
	}
	transport := pkt.TransportHeader().Slice()
	if len(transport) < header.TCPMinimumSize {
		return tun.GSOOptions{}, errors.New("userspace: segmentation offload frame with a short tcp header")
	}
	options.HdrLen = gso.L3HdrLen + uint16(transport[12]>>4)*4
	if gso.MSS == 0 {
		if pkt.Size() != int(options.HdrLen) {
			return tun.GSOOptions{}, errors.New("userspace: segmentation offload frame with a payload and no segment size")
		}
		options.GSOType = tun.GSONone
	}
	return options, nil
}
