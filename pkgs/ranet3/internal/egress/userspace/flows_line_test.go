// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package userspace

import (
	"net/netip"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/egress"
)

// counted is the flows the exit counts against Flows
func (x *Exit) counted() int {
	x.flows.mu.Lock()
	defer x.flows.mu.Unlock()
	return x.flows.open
}

// nextFlow waits for the relay to list a flow seen does not hold, and adds it
func nextFlow(t *testing.T, h *relayHarness, seen map[*tcpFlow]bool) *tcpFlow {
	t.Helper()
	deadline := time.Now().Add(exitWait)
	for {
		h.x.tcp.mu.Lock()
		for f := range h.x.tcp.flows {
			if !seen[f] {
				h.x.tcp.mu.Unlock()
				seen[f] = true
				t.Cleanup(f.ep.Abort)
				return f
			}
		}
		h.x.tcp.mu.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("the relay lists no new flow")
		}
		time.Sleep(time.Millisecond)
	}
}

// flowsState is a state of the exit: a dial held, a connection relaying, and
// the connections closed by the leaf first, each left closing where its last
// ACK is held back, their host sockets read in TIME_WAIT where host bounds the
// host ports
type flowsState struct {
	name    string
	host    *fakeHostSockets
	closing int
	closed  int
}

// flowsStates are the states with no host part, with holds that share no
// flow, and with one or two closing connections each sharing its flow with
// the hold of its host socket
func flowsStates() []flowsState {
	return []flowsState{
		{name: "no_host_part", closing: 1},
		{name: "holds_sharing_nothing", host: newFakeHostSockets(hostClosed), closed: 2},
		{name: "one_closing_connection_sharing", host: newFakeHostSockets(hostClosed), closing: 1},
		{name: "two_closing_connections_sharing", host: newFakeHostSockets(hostClosed), closing: 2, closed: 1},
	}
}

// reach brings a new exit to state and returns its harness
func (state flowsState) reach(t *testing.T) *relayHarness {
	t.Helper()
	var platform *hostSockets
	if state.host != nil {
		platform = state.host.platform()
	}
	h, _, _ := holdHarness(t, platform)
	if reason := h.syn(t, netip.AddrPortFrom(leaf6, 41600), netip.AddrPortFrom(server6, 80)); reason != "" {
		t.Fatalf("the dial was refused past %s", reason)
	}
	server := tcpServer(t, netip.MustParseAddr("127.0.0.1"), readsToTheEnd)
	seen := map[*tcpFlow]bool{}
	relaying := h.open(t, netip.AddrPortFrom(leaf4, 41601), server)
	nextFlow(t, h, seen)
	t.Cleanup(func() {
		h.x.link.deliver(tcpSegment(relaying.leaf, relaying.server, relaying.seq, relaying.ack, tcpACK|tcpRST, nil))
	})
	held := 0
	for i := range state.closed + state.closing {
		c := h.open(t, netip.AddrPortFrom(leaf4, uint16(41610+i)), server)
		f := nextFlow(t, h, seen)
		if state.host != nil {
			state.host.set(f.conn, hostTimeWait)
			held++
		}
		h.x.link.deliver(tcpSegment(c.leaf, c.server, c.seq, c.ack, tcpACK|tcpFIN, nil))
		c.seq++
		c.ack = h.stackFIN(t, c)
		if i < state.closed {
			h.x.link.deliver(tcpSegment(c.leaf, c.server, c.seq, c.ack, tcpACK, nil))
		}
		// the hold is counted before the host admission comes back, so
		// the connection takes two host ports until its end step returns
		waitFor(t, "the host's hold and the admission's return", func() bool {
			f := h.x.Status().Flows
			return f.Host == nil || f.Host.Held == held && f.Host.Ports == 2+held
		})
	}
	waitFor(t, "the closed connections' ends", func() bool { return h.x.tcp.held()[1] == 2+state.closing })
	return h
}

// The status counts each held socket a closing connection shares its flow
// with as shared, and its parts less those make the flows the exit counts
func TestStatusCountsHeldSocketsSharingAFlow(t *testing.T) {
	for _, state := range flowsStates() {
		t.Run(state.name, func(t *testing.T) {
			h := state.reach(t)
			f := h.x.Status().Flows
			if f.TCP != [2]int{1 + state.closing, 0} || f.Dialing != 1 {
				t.Errorf("the status counts TCP %v and %d dialing, want [%d 0] and 1", f.TCP, f.Dialing, 1+state.closing)
			}
			parts := f.TCP[0] + f.TCP[1] + f.UDP[0] + f.UDP[1] + f.Echo[0] + f.Echo[1] + f.Dialing
			switch {
			case state.host == nil && f.Host != nil:
				t.Fatalf("the status holds the host part %+v where no platform bounds the host ports", *f.Host)
			case state.host == nil:
			case f.Host == nil:
				t.Fatal("the status holds no host part where the platform bounds the host ports")
			default:
				if want := (egress.HostHold{Held: state.closed + state.closing, Ports: 2 + state.closed + state.closing, Bound: 6, Shared: state.closing}); *f.Host != want {
					t.Errorf("the status counts the hold %+v, want %+v", *f.Host, want)
				}
				parts += f.Host.Held - f.Host.Shared
			}
			if want := h.x.counted(); parts != want {
				t.Errorf("the status's parts make %d flows, the exit counts %d", parts, want)
			}
		})
	}
}
