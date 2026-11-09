// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package userspace

import (
	"encoding/binary"
	"net/netip"
	"slices"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"ranet3.com/pkgs/ranet3/internal/codel"
)

// The link holds no more bytes than its bound: a packet past it is dropped,
// counted and reported as a full device queue, and a released packet's bytes
// make room again
func TestLinkDropsWhatItsBoundHasNoRoomFor(t *testing.T) {
	const size = 1000
	l := newLink(2*size + size/2)
	defer l.Close()
	write := func() (int, tcpip.Error) {
		var list stack.PacketBufferList
		list.PushBack(stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(make([]byte, size))}))
		defer list.DecRef()
		return l.WritePackets(list)
	}
	for i := range 2 {
		if n, err := write(); n != 1 || err != nil {
			t.Fatalf("write %d within the bound took %d: %v", i, n, err)
		}
	}
	n, err := write()
	if _, full := err.(*tcpip.ErrNoBufferSpace); n != 0 || !full {
		t.Fatalf("a write past the bound took %d: %v, want none and a full queue", n, err)
	}
	if dropped := l.dropped.Load(); dropped != 1 {
		t.Errorf("dropped %d, want 1", dropped)
	}
	l.release(l.poll())
	if n, err := write(); n != 1 || err != nil {
		t.Errorf("a write once a packet was released took %d: %v", n, err)
	}
}

// fakeClock sets l's clock to one the test moves, at zero to begin with
func fakeClock(l *link) *time.Duration {
	now := new(time.Duration)
	l.clock = func() time.Duration { return *now }
	return now
}

// writeTagged queues a packet of 100 bytes whose payload begins with tag
func writeTagged(t *testing.T, l *link, tag uint32) {
	t.Helper()
	payload := make([]byte, 100)
	binary.BigEndian.PutUint32(payload, tag)
	var list stack.PacketBufferList
	list.PushBack(stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(payload)}))
	defer list.DecRef()
	if n, err := l.WritePackets(list); n != 1 || err != nil {
		t.Fatalf("queue packet %d: took %d: %v", tag, n, err)
	}
}

// tagOf is the tag writeTagged gave pkt, which it releases
func tagOf(l *link, pkt *stack.PacketBuffer) uint32 {
	b := pkt.ToBuffer()
	defer b.Release()
	l.release(pkt)
	return binary.BigEndian.Uint32(b.Flatten())
}

// A pump that falls 300 ms behind a queue fed as fast as it drains leaves a
// standing queue of 300 ms with no delay control, and none past the bound.
// The controlled delay drops at the head until the delay is back under the
// target, with no packet dropped at the tail.
func TestLinkHoldsItsDelayToTheTargetUnderASlowPump(t *testing.T) {
	l := newLink(1 << 30)
	defer l.Close()
	now := fakeClock(l)
	var most time.Duration
	for ms := range 8000 {
		*now = time.Duration(ms) * time.Millisecond
		writeTagged(t, l, uint32(ms))
		if ms < 300 {
			continue
		}
		pkt := l.poll()
		if pkt == nil {
			t.Fatalf("the queue was empty at %d ms", ms)
		}
		// each packet was queued at the millisecond its tag names
		sojourn := *now - time.Duration(tagOf(l, pkt))*time.Millisecond
		if ms >= 7500 {
			most = max(most, sojourn)
		}
	}
	if most > 2*codel.Target {
		t.Errorf("the packets taken in the last 500 ms waited up to %s, want no more than twice the target %s", most, codel.Target)
	}
	if l.delayed.Load() == 0 || l.dropped.Load() != 0 {
		t.Errorf("dropped %d at the head for the delay and %d at the tail, want some at the head and none at the tail", l.delayed.Load(), l.dropped.Load())
	}
}

// Once the delay has stayed above the target for an interval, the pump drops
// the packet at the head of the queue, the oldest, and takes the one behind
// it, and every packet queued after them is still there
func TestLinkDropsAtTheHeadNotTheTail(t *testing.T) {
	l := newLink(1 << 30)
	defer l.Close()
	now := fakeClock(l)
	for tag := range uint32(10) {
		writeTagged(t, l, tag)
	}
	*now = 200 * time.Millisecond
	if got := tagOf(l, l.poll()); got != 0 {
		t.Fatalf("took packet %d first, want 0, which starts the interval", got)
	}
	*now = 301 * time.Millisecond
	if got := tagOf(l, l.poll()); got != 2 {
		t.Errorf("took packet %d an interval later, want 2, the head 1 dropped", got)
	}
	var rest []uint32
	for pkt := l.poll(); pkt != nil; pkt = l.poll() {
		rest = append(rest, tagOf(l, pkt))
	}
	if want := []uint32{3, 4, 5, 6, 7, 8, 9}; !slices.Equal(rest, want) {
		t.Errorf("took %v after it, want the tail %v whole", rest, want)
	}
	if got := l.delayed.Load(); got != 1 {
		t.Errorf("counted %d dropped for the delay, want 1", got)
	}
}

// writeToLeaf queues a packet of 100 bytes from server4 to leaf4, an IPv4
// header and a payload that begins with tag
func writeToLeaf(t *testing.T, l *link, tag uint32) {
	t.Helper()
	payload := make([]byte, 100-header.IPv4MinimumSize)
	binary.BigEndian.PutUint32(payload, tag)
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{ReserveHeaderBytes: header.IPv4MinimumSize, Payload: buffer.MakeWithData(payload)})
	header.IPv4(pkt.NetworkHeader().Push(header.IPv4MinimumSize)).Encode(&header.IPv4Fields{
		TotalLength: 100, TTL: 64, Protocol: uint8(header.TCPProtocolNumber),
		SrcAddr: tcpip.AddrFrom4(server4.As4()), DstAddr: tcpip.AddrFrom4(leaf4.As4()),
	})
	var list stack.PacketBufferList
	list.PushBack(pkt)
	defer list.DecRef()
	if n, err := l.WritePackets(list); n != 1 || err != nil {
		t.Fatalf("queue packet %d: took %d: %v", tag, n, err)
	}
}

// toLeafTag is the tag writeToLeaf gave pkt, which it releases
func toLeafTag(l *link, pkt *stack.PacketBuffer) uint32 {
	b := pkt.ToBuffer()
	defer b.Release()
	l.release(pkt)
	return binary.BigEndian.Uint32(b.Flatten()[header.IPv4MinimumSize:])
}

// A packet whose delay has stayed above the target for an interval is kept
// while less than its leaf session's MTU stays queued behind it, by RFC 8289
// section 4.1, and dropped at the head once at least that does
func TestLinkKeepsAPacketWithLessThanItsSessionsMTUBehindIt(t *testing.T) {
	for _, c := range []struct {
		name string
		mtu  int
		want uint32
	}{
		{"a session MTU past the bytes behind", 1400, 1},
		{"a session MTU below the bytes behind", 50, 2},
	} {
		t.Run(c.name, func(t *testing.T) {
			l := newLink(1 << 30)
			defer l.Close()
			now := fakeClock(l)
			var asked []netip.Addr
			l.mtu = func(source, destination netip.Addr) int {
				asked = append(asked, source, destination)
				return c.mtu
			}
			for tag := range uint32(3) {
				writeToLeaf(t, l, tag)
			}
			*now = 200 * time.Millisecond
			if got := toLeafTag(l, l.poll()); got != 0 {
				t.Fatalf("took packet %d first, want 0, which starts the interval", got)
			}
			*now = 301 * time.Millisecond
			if got := toLeafTag(l, l.poll()); got != c.want {
				t.Errorf("took packet %d an interval later with 100 bytes behind it, want %d", got, c.want)
			}
			if want := []netip.Addr{server4, leaf4}; len(asked) < 2 || !slices.Equal(asked[:2], want) {
				t.Errorf("asked the MTU of the sessions %v, want %v first", asked, want)
			}
		})
	}
}

// The dropping state ends once the pump finds the queue empty, so a packet
// queued after it waits a whole interval above the target before the next
// drop
func TestLinkLeavesTheDroppingStateOnceItsQueueEmpties(t *testing.T) {
	l := newLink(1 << 30)
	defer l.Close()
	now := fakeClock(l)
	for tag := range uint32(3) {
		writeTagged(t, l, tag)
	}
	*now = 200 * time.Millisecond
	tagOf(l, l.poll())
	*now = 301 * time.Millisecond
	tagOf(l, l.poll())
	if !l.delay.Dropping() {
		t.Fatal("the delay is not dropping an interval above the target")
	}
	if pkt := l.poll(); pkt != nil {
		t.Fatalf("took packet %d, want the queue empty", tagOf(l, pkt))
	}
	if l.delay.Dropping() {
		t.Error("the delay is still dropping with the queue empty")
	}
	writeTagged(t, l, 3)
	*now = 400 * time.Millisecond
	if got := tagOf(l, l.poll()); got != 3 {
		t.Errorf("took packet %d, want 3, kept while a new interval starts", got)
	}
}

// The packets dropped for the delay are counted apart from those past the
// bound, and the status reports them as their own reason, as it does the
// stack's ICMP and other packets but TCP
func TestLinkCountsItsDelayDropsApartFromItsBound(t *testing.T) {
	h := newRelayHarness(t, nil)
	defer closeWithin(t, h.x)
	h.x.link.delayed.Add(3)
	h.x.link.dropped.Add(2)
	h.x.link.icmp.Add(5)
	h.x.link.other.Add(7)
	dropped := h.x.Status().Flows.Dropped
	if dropped[reasonLinkCodel] != 3 || dropped[reasonLinkFull] != 2 {
		t.Errorf("the status counts %d as %q and %d as %q, want 3 and 2", dropped[reasonLinkCodel], reasonLinkCodel, dropped[reasonLinkFull], reasonLinkFull)
	}
	if dropped[reasonStackICMP] != 5 || dropped[reasonStackOther] != 7 {
		t.Errorf("the status counts %d as %q and %d as %q, want 5 and 7", dropped[reasonStackICMP], reasonStackICMP, dropped[reasonStackOther], reasonStackOther)
	}
}

// Run gives the link the session MTUs of the pump's lane, which the
// controlled delay keeps queued behind a packet it drops
func TestRunGivesTheLinkItsLanesSessionMTU(t *testing.T) {
	mesh := newFakeMesh()
	mesh.mtu = 1300
	h := newExitHarness(t, mesh, &fakePlatform{routes4: true, routes6: true})
	h.run(t)
	if h.exit.link.mtu == nil {
		t.Fatal("the link has no session MTU once Run started")
	}
	if got := h.exit.link.mtu(server4, leaf4); got != mesh.mtu {
		t.Errorf("the link reads a session MTU of %d, want the lane's %d", got, mesh.mtu)
	}
}
