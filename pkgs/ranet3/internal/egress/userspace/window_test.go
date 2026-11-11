// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package userspace

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

const (
	// fillSegment is the most data one of the leaf's segments carries while it
	// fills the stack's window, and fillSegments the most such segments
	fillSegment  = 16 << 10
	fillSegments = 64
	// leafWindow is the window the leaf advertises while the stack's data in
	// flight fills it, and behindLeafWindow the data the stack holds behind it
	leafWindow       = 10
	behindLeafWindow = 100
)

// A flow in which neither end may send moves on the ACK of a segment the
// stack's zero window refuses. The stack's receive window is zero, as nothing
// reads the endpoint, and the window of 10 bytes the leaf advertises is full
// with the stack's data in flight. The leaf's next segment carries data at
// RCV.NXT, which the zero window refuses, with an ACK of the data in flight
// and a window that opens. The stack takes that ACK and sends the data it
// queued, from past what the ACK covers, still acknowledging RCV.NXT. It rests
// on a change of the gVisor fork that `go.mod` puts in place of upstream:
// upstream's stack drops the ACK of a segment it refuses along with its data,
// so the flow stands until a window opens.
func TestStackTakesTheACKOfASegmentItsZeroWindowRefuses(t *testing.T) {
	h := newStackHarness(t)
	endpoints := h.forward()
	leaf, server := netip.AddrPortFrom(leaf4, 40000), netip.AddrPortFrom(server4, 80)
	ep := h.open(t, endpoints, leaf, server)
	una, rcvNxt := opened(t, h, leaf)

	window := uint16(fillSegment)
	for i := 0; window > 0; i++ {
		if i == fillSegments {
			t.Fatalf("the stack's window stayed open after %d segments of the leaf, at %d bytes", fillSegments, window)
		}
		n := min(int(window), fillSegment)
		h.inject(t, leafSegment(leaf, server, rcvNxt, una, tcpACK|tcpPSH, leafWindow, make([]byte, n)))
		rcvNxt += uint32(n)
		_, window = towardLeaf(t, h, leaf, "ACK of the leaf's data", func(p sent, _ uint16) bool { return p.ack == rcvNxt })
	}

	if _, err := ep.Write(bytes.NewReader(make([]byte, leafWindow)), tcpip.WriteOptions{}); err != nil {
		t.Fatalf("the endpoint's write: %s", err)
	}
	towardLeaf(t, h, leaf, "data filling the leaf's window", func(p sent, _ uint16) bool {
		return p.seq == una && p.payload == leafWindow
	})
	if _, err := ep.Write(bytes.NewReader(make([]byte, behindLeafWindow)), tcpip.WriteOptions{}); err != nil {
		t.Fatalf("the endpoint's write: %s", err)
	}

	h.inject(t, leafSegment(leaf, server, rcvNxt, una+leafWindow, tcpACK|tcpPSH, 65535, []byte{1, 2, 3, 4}))
	p, _ := towardLeaf(t, h, leaf, "queued data once the leaf's ACK of a refused segment opens its window", func(p sent, _ uint16) bool {
		return p.payload > 0 && p.seq == una+leafWindow
	})
	if p.ack != rcvNxt {
		t.Errorf("the stack's data acknowledges %d, want RCV.NXT %d, as the zero window refused the leaf's data", p.ack, rcvNxt)
	}
}

// A server trickling toward a leaf whose window is closed stops at its send
// buffer: the endpoint takes writes of one byte while the test's count of its
// send queue is below its send buffer, and refuses the next once the count
// reaches it, so the count ends past the send buffer by less than one write's
// segment, its structs and its byte. The count is gVisor's receive side's for a
// segment, the bytes of its data with its segment and packet buffer structs,
// which are tcp.SegOverheadSize without the IPv4 header room it adds. Each
// write is a segment of its own while nothing leaves, which the test reads on
// the link once the endpoint refuses. The comparison pins the write at which
// the endpoint refuses by the count the fork keeps, not the bytes it charges a
// segment, since a charge a few bytes off refuses at the same write. The send
// buffer is the window the exit's limits count for each direction of a
// connection. It rests on a change of the gVisor fork that `go.mod` puts in
// place of upstream: upstream's stack counts the payload alone, so it takes a
// write of one byte for each byte of the send buffer, each holding its structs
// besides.
func TestStackStopsTricklingWritesAtItsSendBuffer(t *testing.T) {
	h := newStackHarness(t)
	endpoints := h.forward()
	leaf, server := netip.AddrPortFrom(leaf4, 40000), netip.AddrPortFrom(server4, 80)
	ep := h.open(t, endpoints, leaf, server)
	una, rcvNxt := opened(t, h, leaf)

	// the stack acknowledges the segment that closes the leaf's window, so it
	// has taken the window before the server writes
	h.inject(t, leafSegment(leaf, server, rcvNxt, una, tcpACK|tcpPSH, 0, []byte{'z'}))
	towardLeaf(t, h, leaf, "ACK of the segment closing the leaf's window", func(p sent, _ uint16) bool { return p.ack == rcvNxt+1 })

	buffer := int(ep.SocketOptions().GetSendBufferSize())
	structs := tcp.SegOverheadSize - header.IPv4MaximumHeaderSize
	held, writes := 0, 0
	for {
		n, err := ep.Write(bytes.NewReader([]byte{0}), tcpip.WriteOptions{})
		if _, refused := err.(*tcpip.ErrWouldBlock); refused {
			break
		}
		if err != nil {
			t.Fatalf("the endpoint's write %d: %s", writes, err)
		}
		if held >= buffer {
			t.Fatalf("the endpoint took write %d with the test's count of structs and data at %d bytes, at or past its send buffer of %d", writes, held, buffer)
		}
		held += structs + int(n)
		writes++
	}
	t.Logf("the endpoint took %d writes of one byte, the test's count of structs and data at %d bytes against its send buffer of %d", writes, held, buffer)
	if held < buffer {
		t.Errorf("the endpoint refused write %d with the test's count of structs and data at %d bytes, below its send buffer of %d", writes, held, buffer)
	}
	for pkt := h.link.poll(); pkt != nil; pkt = h.link.poll() {
		view := pkt.ToView()
		p, ok := parse(view.AsSlice())
		view.Release()
		h.link.release(pkt)
		// a zero window probe sends an acknowledged byte again, from before una
		if ok && p.protocol == protoTCP && p.payload > 0 && p.seq-una < 1<<31 {
			t.Errorf("the stack sent %s from %d toward the leaf whose window is closed", p, p.seq)
		}
	}
}

// opened is the stack's and the leaf's next sequence numbers once open has run,
// read from what the stack sent toward leaf: the end of its data, and its ACK
// of the leaf's data past the sequence number its SYN-ACK acknowledged
func opened(t *testing.T, h *stackHarness, leaf netip.AddrPort) (una, rcvNxt uint32) {
	t.Helper()
	var leafStart uint32
	var synAck, data bool
	for _, p := range h.sentSoFar() {
		if p.protocol != protoTCP || netip.AddrPortFrom(p.dst, p.dstPort) != leaf {
			continue
		}
		switch {
		case p.flags&tcpSYN != 0:
			leafStart, synAck = p.ack, true
		case p.payload > 0 && (!data || int32(p.seq+uint32(p.payload)-una) > 0):
			una, data = p.seq+uint32(p.payload), true
		}
	}
	if !synAck || !data {
		t.Fatalf("open left no SYN-ACK and data from the stack toward %s, only %v", leaf, h.sentSoFar())
	}
	for _, p := range h.sentSoFar() {
		if p.protocol == protoTCP && netip.AddrPortFrom(p.dst, p.dstPort) == leaf && int32(p.ack-leafStart) > 0 {
			return una, p.ack
		}
	}
	p, _ := towardLeaf(t, h, leaf, "ACK of the data open's leaf sent", func(p sent, _ uint16) bool { return int32(p.ack-leafStart) > 0 })
	return una, p.ack
}

// leafSegment is tcpSegment from an IPv4 leaf advertising window, its checksum
// set again
func leafSegment(src, dst netip.AddrPort, seq, ack uint32, flags byte, window uint16, payload []byte) []byte {
	raw := tcpSegment(src, dst, seq, ack, flags, payload)
	segment := raw[20:]
	binary.BigEndian.PutUint16(segment[14:16], window)
	binary.BigEndian.PutUint16(segment[16:18], 0)
	binary.BigEndian.PutUint16(segment[16:18], fold(sum(pseudo(src.Addr(), dst.Addr(), protoTCP, len(segment)), segment)))
	return raw
}

// towardLeaf waits for the next TCP segment the stack sends toward an IPv4
// leaf that match picks, given the segment and the window it advertises,
// taking every packet the link holds before it, and reports both
func towardLeaf(t *testing.T, h *stackHarness, leaf netip.AddrPort, what string, match func(sent, uint16) bool) (sent, uint16) {
	t.Helper()
	stop := make(chan struct{})
	timer := time.AfterFunc(stackWait, func() { close(stop) })
	defer timer.Stop()
	var seen []sent
	for {
		pkt := h.link.next(stop, nil)
		if pkt == nil {
			t.Fatalf("the stack sent no %s within %s, only %v", what, stackWait, seen)
		}
		view := pkt.ToView()
		raw := view.AsSlice()
		p, ok := parse(raw)
		var window uint16
		if ok && p.protocol == protoTCP {
			window = binary.BigEndian.Uint16(raw[int(raw[0]&0x0f)*4+14:])
		}
		view.Release()
		h.link.release(pkt)
		if !ok || p.protocol != protoTCP || netip.AddrPortFrom(p.dst, p.dstPort) != leaf {
			continue
		}
		if match(p, window) {
			return p, window
		}
		seen = append(seen, p)
	}
}
