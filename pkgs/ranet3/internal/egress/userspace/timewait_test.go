// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package userspace

import (
	"net/netip"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// leafFIN is the sequence number of the FIN a leaf closes a flow open opened
// with: its SYN's 1000, then 50 bytes from 1001
const leafFIN = 1051

// inTimeWait opens a flow from leaf to server, closes the stack's end first
// and then the leaf's, and reports the stack's endpoint once it waits in
// TIME_WAIT
func (h *stackHarness) inTimeWait(t *testing.T, endpoints <-chan tcpip.Endpoint, leaf, server netip.AddrPort) *tcp.Endpoint {
	t.Helper()
	ep := h.open(t, endpoints, leaf, server)
	ep.Close()
	fin := h.waitSent(t, "the endpoint's FIN", func(p sent) bool {
		return p.protocol == protoTCP && p.flags&tcpFIN != 0 && netip.AddrPortFrom(p.dst, p.dstPort) == leaf
	})
	h.inject(t, tcpSegment(leaf, server, leafFIN, fin.seq+1, tcpACK|tcpFIN, nil))
	waiting, ok := ep.(*tcp.Endpoint)
	if !ok {
		t.Fatalf("the stack's endpoint is a %T", ep)
	}
	deadline := time.Now().Add(stackWait)
	for waiting.EndpointState() != tcp.StateTimeWait {
		if time.Now().After(deadline) {
			t.Fatalf("the endpoint for %s is %s, not in TIME_WAIT, within %s", leaf, waiting.EndpointState(), stackWait)
		}
		time.Sleep(time.Millisecond)
	}
	return waiting
}

// A bare SYN on the four-tuple of an endpoint in TIME_WAIT aborts the
// endpoint where its sequence number comes after RCV.NXT, the leaf's FIN plus
// one, and leaves it waiting for a SYN at RCV.NXT or before it, a SYN with an
// ACK, and a four-tuple whose FIN was never seen
func TestTimeWaitIsAbortedOnlyForANewSynAfterItsFin(t *testing.T) {
	server := netip.AddrPortFrom(server4, 80)
	for i, c := range []struct {
		name    string
		seq     uint32
		flags   byte
		seen    bool
		aborted bool
	}{
		{"a SYN after the FIN", leafFIN + 2, tcpSYN, true, true},
		{"a SYN far after the FIN", leafFIN + 1<<30, tcpSYN, true, true},
		{"a SYN at RCV.NXT", leafFIN + 1, tcpSYN, true, false},
		{"a SYN at the FIN", leafFIN, tcpSYN, true, false},
		{"a SYN before the FIN", leafFIN - 1, tcpSYN, true, false},
		{"a SYN with an ACK", leafFIN + 2, tcpSYN | tcpACK, true, false},
		{"a FIN never seen", leafFIN + 2, tcpSYN, false, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newStackHarness(t)
			endpoints := h.forward()
			leaf := netip.AddrPortFrom(leaf4, uint16(41000+i))
			ep := h.inTimeWait(t, endpoints, leaf, server)
			w := newTimeWait(4)
			if c.seen {
				w.see(h.stack, tcpSegment(leaf, server, leafFIN, 0, tcpACK|tcpFIN, nil))
			}
			aborted := w.see(h.stack, tcpSegment(leaf, server, c.seq, 0, c.flags, nil))
			if aborted != c.aborted {
				t.Errorf("aborted %t, want %t", aborted, c.aborted)
			}
			if waiting := ep.EndpointState() == tcp.StateTimeWait; waiting == c.aborted {
				t.Errorf("the endpoint is %s after the SYN, aborted %t", ep.EndpointState(), c.aborted)
			}
		})
	}
}

// The FINs recorded never number more than the limit, the oldest dropped
// first
func TestTimeWaitKeepsNoMoreFinsThanItsLimit(t *testing.T) {
	w := newTimeWait(2)
	server := netip.AddrPortFrom(server4, 80)
	for i := range 3 {
		w.see(nil, tcpSegment(netip.AddrPortFrom(leaf4, uint16(42000+i)), server, leafFIN, 0, tcpACK|tcpFIN, nil))
	}
	if len(w.fins) != 2 || len(w.order) != 2 {
		t.Fatalf("recorded %d FINs in an order of %d, want 2", len(w.fins), len(w.order))
	}
	first := stack.TransportEndpointID{
		LocalPort: 80, LocalAddress: tcpip.AddrFrom4(server4.As4()),
		RemotePort: 42000, RemoteAddress: tcpip.AddrFrom4(leaf4.As4()),
	}
	if _, kept := w.fins[first]; kept {
		t.Error("the oldest FIN outlived the limit")
	}
}

// The endpoints the exit closed never number more than Limits.TimeWait: one
// past it aborts the oldest still held, an endpoint the stack has freed
// leaves first, and each abort is counted
func TestClosedEndpointsAbortTheOldestPastTheLimit(t *testing.T) {
	h := newStackHarness(t)
	endpoints := h.forward()
	server := netip.AddrPortFrom(server4, 80)
	var waiting []*tcp.Endpoint
	for i := range 4 {
		waiting = append(waiting, h.inTimeWait(t, endpoints, netip.AddrPortFrom(leaf4, uint16(43000+i)), server))
	}
	c := closedEndpoints{limit: 2}
	for i, want := range []int{0, 0, 1} {
		if aborted := c.add(waiting[i]); aborted != want {
			t.Errorf("adding endpoint %d aborted %d, want %d", i, aborted, want)
		}
	}
	if state := waiting[0].EndpointState(); state == tcp.StateTimeWait {
		t.Errorf("the oldest endpoint is still %s past the limit", state)
	}
	if state := waiting[1].EndpointState(); state != tcp.StateTimeWait {
		t.Errorf("the second endpoint is %s within the limit", state)
	}
	waiting[1].Abort()
	if aborted := c.add(waiting[3]); aborted != 0 {
		t.Errorf("with a freed endpoint held, adding aborted %d, want none", aborted)
	}
	if state := waiting[2].EndpointState(); state != tcp.StateTimeWait {
		t.Errorf("an endpoint is %s though a freed one left in its place", state)
	}
	if len(c.queue) != 2 {
		t.Errorf("holding %d endpoints, want 2", len(c.queue))
	}
}
