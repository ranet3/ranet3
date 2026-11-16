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
