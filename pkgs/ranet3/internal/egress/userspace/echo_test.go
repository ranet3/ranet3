// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package userspace

import (
	"net/netip"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/egress"
)

// echoHeld is the echo mappings h's exit holds and its flows of every kind
func (h *relayHarness) echoHeld() (mappings, flows int) {
	h.x.echo.mu.Lock()
	mappings = len(h.x.echo.mappings)
	h.x.echo.mu.Unlock()
	h.x.flows.mu.Lock()
	defer h.x.flows.mu.Unlock()
	return mappings, h.x.flows.open
}

// endsAt moves h's clock through the next pass, then to a nanosecond short of
// end, then to end, and fails where the one echo mapping open is not kept
// through the first two or is left with a flow after the third
func (h *relayHarness) endsAt(t *testing.T, end time.Time) {
	t.Helper()
	h.advance(mappingSweep)
	if live, _ := h.echoHeld(); live != 1 {
		t.Fatalf("the mapping ended at the next pass, %s before it ends", end.Sub(h.now()))
	}
	h.advance(end.Sub(h.now()) - time.Nanosecond)
	if live, _ := h.echoHeld(); live != 1 {
		t.Fatal("the mapping ended a nanosecond before it ends")
	}
	h.advance(time.Nanosecond)
	if live, open := h.echoHeld(); live != 0 || open != 0 {
		t.Errorf("%d mappings and %d flows where the mapping ends, want none", live, open)
	}
}

// A request whose mapping a withdrawal closed while it was sent is refused as
// withdrawn, as one after the withdrawal is, and neither sent nor counted
// unsent: under auto, where darwin sends through the family's socket bound to
// no address, which stays open, and under a class naming an address, whose
// socket closes with its last mapping on darwin
func TestEchoRequestWhoseMappingClosedIsRefusedAsWithdrawn(t *testing.T) {
	server := netip.MustParseAddr("127.0.0.1")
	host := onEchoHost(t)
	for _, c := range []struct {
		name string
		cfg  egress.Egress
	}{{"auto", egress.Egress{}}, {"an address", classed(server)}} {
		t.Run(c.name, func(t *testing.T) {
			h := newRelayHarness(t, nil)
			h.x.cfg.Translate = c.cfg.Translate
			raw := ipPacket(leaf4, server, protoICMP, echoRequest(leaf4, server, 7, 1, []byte("withdrawn")))
			request, _ := readEcho(raw)
			var m *echoMapping
			var reason string
			host(func() { m, reason = h.x.echo.mapping(request) })
			if m == nil {
				t.Fatalf("the mapping was refused for %s", reason)
			}
			h.x.echo.withdraw()
			h.x.echo.send(raw, request, m)
			if withdrawn, unsent := h.count(true, reasonWithdrawn), h.count(false, reasonEchoUnsent); withdrawn != 1 || unsent != 0 {
				t.Errorf("refused %d as withdrawn and counted %d unsent, want the one refusal alone", withdrawn, unsent)
			}
		})
	}
}

// waitTimeWait waits until h's exit holds n of its endpoints in TIME_WAIT,
// which a connection's end lists only after it gives its count among the
// connections back
func (h *relayHarness) waitTimeWait(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(exitWait)
	for h.x.tcp.closed.waiting() != n {
		if time.Now().After(deadline) {
			t.Fatalf("the exit holds %d endpoints in TIME_WAIT, want %d", h.x.tcp.closed.waiting(), n)
		}
		time.Sleep(time.Millisecond)
	}
}

// The status's figures the Flows line sums, the TCP connections open, dialing
// and held for their host sockets with the UDP destinations and the echo
// mappings, are every flow the exit's admission holds against Flows, with one
// of each kind open and the held connection's endpoint in TIME_WAIT, which no
// figure counts. The open connection reads as dialing until its relay starts,
// which comes after the handshake the leaf sees, so it is held to be one of
// the two connections the open and the dialing figures share.
func TestFlowsLineFiguresAreWhatAdmissionHolds(t *testing.T) {
	readyLoopback(t)
	loopback := netip.MustParseAddr("127.0.0.1")
	h, _, _ := holdHarness(t, newFakeHostSockets(hostTimeWait).platform())
	h.x.echo.take(ipPacket(other4, loopback, protoICMP, echoRequest(other4, loopback, 7, 1, []byte("an echo mapping"))))
	if h.count(true, reasonEchoSocket) != 0 {
		t.Skip("no echo socket for this process")
	}
	server := loopbackServer(t, loopback)
	h.x.udp.take(udpDatagram(netip.AddrPortFrom(leaf4, freeUDPPort(t, leaf4)), serverAt(server), []byte("a UDP mapping")), false)
	readDatagramFrom(t, server, []byte("a UDP mapping"))
	h.open(t, netip.AddrPortFrom(leaf4, 42300), tcpServer(t, loopback, readsToTheEnd))
	// the server closes first, so the stack's endpoint waits in TIME_WAIT and
	// the host's socket is held
	h.closeAfter(t, h.open(t, netip.AddrPortFrom(leaf4, 42301), tcpServer(t, loopback, sendsAndCloses)))
	h.waitConnections(t, 1)
	h.waitTimeWait(t, 1)
	if reason := h.syn(t, netip.AddrPortFrom(leaf6, 42302), netip.AddrPortFrom(server6, 80)); reason != "" {
		t.Fatalf("the dial was refused past %s", reason)
	}
	h.waitConnections(t, 2)
	f := h.x.Status().Flows
	held := 0
	if f.Host != nil {
		held = f.Host.Held
	}
	figures := [5]int{f.TCP[0] + f.TCP[1], f.Dialing, held, f.UDP[0] + f.UDP[1], f.Echo[0] + f.Echo[1]}
	sum := 0
	for _, n := range figures {
		sum += n
	}
	_, open := h.echoHeld()
	if figures[0]+figures[1] != 2 || figures[1] == 0 || [3]int(figures[2:]) != [3]int{1, 1, 1} || sum != open || f.TimeWait != 1 {
		t.Errorf("the status counts %v TCP, dialing, held, UDP and echo, %d together, %d in TIME_WAIT, and admission holds %d, want two connections open or dialing, one dialing, one of each other kind, the sum and one apart in TIME_WAIT", figures, sum, f.TimeWait, open)
	}
}
