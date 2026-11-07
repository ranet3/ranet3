// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package userspace

import (
	"bytes"
	"encoding/binary"
	"testing"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/wireguard/tun"
)

// layFrame is one packet the stack sends, as the test describes it: a TCP
// frame of segmentation offload cut at mss where mss is nonzero, else one
// packet whole
type layFrame struct {
	ipv4    bool
	mss     int
	payload []byte
	seq     uint32
}

// ipLen is the frame's IP header
func (f layFrame) ipLen() int {
	if f.ipv4 {
		return 20
	}
	return 40
}

// packetBuffer is the frame as the stack hands its link one, its headers
// parsed and, for a frame of offload, its TCP checksum the pseudo header's
// sum alone, as the stack leaves it for the device to finish
func (f layFrame) packetBuffer() *stack.PacketBuffer {
	src, dst := server4, leaf4
	if !f.ipv4 {
		src, dst = server6, leaf6
	}
	segment := make([]byte, 20+len(f.payload))
	binary.BigEndian.PutUint16(segment[0:2], 80)
	binary.BigEndian.PutUint16(segment[2:4], 40000)
	binary.BigEndian.PutUint32(segment[4:8], f.seq)
	segment[12], segment[13] = 5<<4, tcpACK|tcpPSH
	copy(segment[20:], f.payload)
	if f.mss != 0 {
		binary.BigEndian.PutUint16(segment[16:18], ^fold(pseudo(src, dst, protoTCP, len(segment))))
	} else {
		binary.BigEndian.PutUint16(segment[16:18], fold(sum(pseudo(src, dst, protoTCP, len(segment)), segment)))
	}
	raw := ipPacket(src, dst, protoTCP, segment)
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(raw)})
	pkt.NetworkHeader().Consume(f.ipLen())
	pkt.TransportHeader().Consume(20)
	if f.mss != 0 {
		kind := stack.GSOTCPv6
		if f.ipv4 {
			kind = stack.GSOTCPv4
		}
		pkt.GSOOptions = stack.GSO{Type: kind, NeedsCsum: true, CsumOffset: 16, MSS: uint16(f.mss), L3HdrLen: uint16(f.ipLen()), MaxSize: linkGSOMaxSize}
	}
	return pkt
}

// segments lists the payload of each segment a tun read of the frame holds,
// in order, from the frame's description
func (f layFrame) segments() [][]byte {
	if f.mss == 0 || len(f.payload) <= f.mss {
		return [][]byte{f.payload}
	}
	var out [][]byte
	for at := 0; at < len(f.payload); at += f.mss {
		out = append(out, f.payload[at:min(at+f.mss, len(f.payload))])
	}
	return out
}

// checkSegment fails tb unless raw is a whole IP packet of the frame's family
// carrying a TCP segment from the frame's ports, its lengths and checksums
// right, and returns its payload and sequence number
func checkSegment(tb testing.TB, raw []byte, ipv4 bool) ([]byte, uint32) {
	tb.Helper()
	ipLen := 40
	if ipv4 {
		ipLen = 20
	}
	if len(raw) < ipLen+20 {
		tb.Fatalf("a %d byte read holds no IP and TCP header", len(raw))
	}
	var src, dst []byte
	if ipv4 {
		if raw[0]>>4 != 4 || int(binary.BigEndian.Uint16(raw[2:4])) != len(raw) || fold(sum(0, raw[:20])) != 0 {
			tb.Fatalf("a %d byte read is no whole IPv4 packet: %x", len(raw), raw[:20])
		}
		src, dst = raw[12:16], raw[16:20]
	} else {
		if raw[0]>>4 != 6 || int(binary.BigEndian.Uint16(raw[4:6])) != len(raw)-40 {
			tb.Fatalf("a %d byte read is no whole IPv6 packet: %x", len(raw), raw[:40])
		}
		src, dst = raw[8:24], raw[24:40]
	}
	segment := raw[ipLen:]
	running := sum(sum(0, src), dst) + protoTCP + uint32(len(segment))
	if fold(sum(running, segment)) != 0 {
		tb.Fatalf("a %d byte segment's checksum %#04x fails", len(segment), binary.BigEndian.Uint16(segment[16:18]))
	}
	if binary.BigEndian.Uint16(segment[0:2]) != 80 || binary.BigEndian.Uint16(segment[2:4]) != 40000 {
		tb.Fatalf("a segment from port %d to %d", binary.BigEndian.Uint16(segment[0:2]), binary.BigEndian.Uint16(segment[2:4]))
	}
	return segment[20:], binary.BigEndian.Uint32(segment[4:8])
}

// for any mix of whole packets and frames of segmentation offload in either
// family, at any segment size, laid into batches of any number of reads, the
// pump lays every segment once, in order, as a whole packet whose lengths and
// checksums hold, carrying its part of the frame's payload at its sequence
// number, with ReadPacketSpacing before, between and after the segments of
// each batch, as a tun read lays them. The sizes at a whole number of segments
// and the least segment size are tried before anything is drawn.
func TestPumpLaysEverySegmentWholeWithItsSpacing(t *testing.T) {
	check := func(tb testing.TB, frames []layFrame, reads int) {
		tb.Helper()
		l := newLink(1 << 30)
		defer l.Close()
		var list stack.PacketBufferList
		for _, f := range frames {
			list.PushBack(f.packetBuffer())
		}
		if n, err := l.WritePackets(list); err != nil || n != len(frames) {
			tb.Fatalf("the link took %d of %d frames: %v", n, len(frames), err)
		}
		list.DecRef()
		unlaid := 0
		p := &pump{link: l, unlaid: func() { unlaid++ }}
		var want []layFrame
		var wantPayloads [][]byte
		var wantSeqs []uint32
		for _, f := range frames {
			at := uint32(0)
			for _, payload := range f.segments() {
				want, wantPayloads, wantSeqs = append(want, f), append(wantPayloads, payload), append(wantSeqs, f.seq+at)
				at += uint32(len(payload))
			}
		}
		slab, batch := make([]byte, 2*65535), make([]tun.ReadPacket, reads)
		got := 0
		for range len(want) + 2 {
			n := p.fill(slab, batch)
			if n == 0 && p.held == nil && p.cut.next == p.cut.n {
				break
			}
			end := 0
			for i, r := range batch[:n] {
				if r.Offset < end+tun.ReadPacketSpacing || r.Offset+r.Size+tun.ReadPacketSpacing > len(slab) {
					tb.Fatalf("read %d of %d at %d for %d bytes, after the last ending at %d in a %d byte slab", i, n, r.Offset, r.Size, end, len(slab))
				}
				end = r.Offset + r.Size
				if got == len(want) {
					tb.Fatalf("more than the %d segments of the frames laid", len(want))
				}
				payload, seq := checkSegment(tb, slab[r.Offset:end], want[got].ipv4)
				if !bytes.Equal(payload, wantPayloads[got]) || seq != wantSeqs[got] {
					tb.Fatalf("segment %d of %d carries %d bytes at sequence %d, want %d at %d", got, len(want), len(payload), seq, len(wantPayloads[got]), wantSeqs[got])
				}
				got++
			}
		}
		if got != len(want) || unlaid != 0 {
			tb.Fatalf("laid %d of %d segments with %d unlaid", got, len(want), unlaid)
		}
	}
	payload := func(size int, seed byte) []byte {
		b := make([]byte, size)
		for i := range b {
			b[i] = seed + byte(i*7)
		}
		return b
	}
	for _, ipv4 := range []bool{true, false} {
		for _, mss := range []int{header.TCPMinimumSendMSS, 1000} {
			for _, size := range []int{0, 1, mss - 1, mss, mss + 1, 3 * mss, 3*mss + 1, linkGSOMaxSize - 60} {
				for _, reads := range []int{1, 3, fakeReads} {
					check(t, []layFrame{{ipv4: ipv4, mss: mss, payload: payload(size, 1), seq: 7}, {ipv4: !ipv4, payload: payload(100, 2), seq: 9}}, reads)
				}
			}
		}
	}
	pbt.Check(t, func(ht *hegel.T) {
		var frames []layFrame
		for range hegel.Draw(ht, hegel.Integers(1, 5)) {
			f := layFrame{ipv4: hegel.Draw(ht, hegel.Booleans()), seq: hegel.Draw(ht, hegel.Integers[uint32](0, 0xffffffff))}
			size := hegel.Draw(ht, pbt.Spanning(0, 1400))
			if hegel.Draw(ht, hegel.Booleans()) {
				f.mss = hegel.Draw(ht, pbt.Spanning(header.TCPMinimumSendMSS, 1460))
				size = hegel.Draw(ht, pbt.Spanning(0, linkGSOMaxSize-f.ipLen()-20))
			}
			f.payload = payload(size, byte(len(frames)))
			frames = append(frames, f)
		}
		check(ht, frames, hegel.Draw(ht, pbt.Spanning(1, fakeReads)))
	})
}
