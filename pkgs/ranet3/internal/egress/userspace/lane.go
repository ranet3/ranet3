// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package userspace

import (
	"errors"
	"fmt"
	"hash/maphash"
	"net/netip"
	"sync"

	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"ranet3.com/pkgs/ranet3/internal/netstack"
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

// handle judges raw and acts on the judgment, handing a UDP datagram that
// needs no reassembly to the relay without the stack
func (x *Exit) handle(lane Lane, raw []byte) {
	j := judge(raw, x.heldDestination)
	switch j.act {
	case deliver:
		if dontFragment, ok := fastUDP(raw); ok {
			x.udp.take(raw, dontFragment)
			return
		}
		if x.timeWait.see(x.stack, raw) {
			x.counts.reused.Add(1)
		}
		x.link.deliver(raw)
	case answer:
		x.counts.refuse(j.reason)
		lane.Answer(raw, j.kind, 0)
	case drop:
		x.counts.drop(j.reason)
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
	return x.rt.Platform.Held(address)
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
