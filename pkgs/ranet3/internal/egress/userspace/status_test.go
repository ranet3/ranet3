// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package userspace

import (
	"bytes"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/netstack"
)

// The egress.refused records go an interval apart, the first at once, each
// naming the source and the reason of the refusal that let it out with the
// refusals since the last record, and every refusal is counted whether it was
// recorded or not, those past a source's share in its own family too
func TestRefusalRecordsGoAnIntervalApart(t *testing.T) {
	bus := events.New()
	h := newRelayHarness(t, func(rt *Runtime, _ *egress.Egress) { rt.Events = bus })
	var now atomic.Int64
	h.x.reportClock = now.Load
	from4 := udpDatagram(netip.AddrPortFrom(leaf4, 40000), netip.AddrPortFrom(server4, 53), nil)
	from6 := udpDatagram(netip.AddrPortFrom(leaf6, 40000), netip.AddrPortFrom(server6, 53), nil)
	for _, step := range []struct {
		at     time.Duration
		raw    []byte
		reason string
	}{
		{0, from4, reasonShare},
		{time.Second, from6, reasonTotal},
		{refusedInterval - 1, from6, reasonShare},
		{refusedInterval, from6, reasonDescriptors},
		{refusedInterval + time.Second, from4, reasonShare},
		{3 * refusedInterval, from4, reasonConnections},
	} {
		now.Store(int64(step.at))
		h.x.refused(step.raw, step.reason)
	}
	var got [][3]string
	for _, event := range bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "egress.refused" }, 0) {
		got = append(got, [3]string{event.Attrs["source"], event.Attrs["reason"], event.Attrs["refused"]})
	}
	want := [][3]string{{leaf4.String(), reasonShare, "1"}, {leaf6.String(), reasonDescriptors, "3"}, {leaf4.String(), reasonConnections, "2"}}
	if !slices.Equal(got, want) {
		t.Errorf("recorded %v, want %v", got, want)
	}
	status := h.x.Status()
	if status.Refused4 != 2 || status.Refused6 != 1 {
		t.Errorf("counted %d IPv4 and %d IPv6 refusals past a share, want 2 and 1", status.Refused4, status.Refused6)
	}
	counted := map[string]uint64{reasonShare: 3, reasonTotal: 1, reasonDescriptors: 1, reasonConnections: 1}
	if !maps.Equal(status.Flows.Refused, counted) {
		t.Errorf("the status counts the refusals as %v, want %v", status.Flows.Refused, counted)
	}
}

// The status counts each destination of a UDP mapping one flow in the leaf's
// family, as the source's share counts it, names the source holding them,
// and carries the limits with the budget's source as the status names it
func TestStatusCountsTheFlowsOpen(t *testing.T) {
	h := newRelayHarness(t, nil)
	server := loopbackServer(t, netip.MustParseAddr("127.0.0.1"))
	leaf := netip.AddrPortFrom(leaf4, freeUDPPort(t, leaf4))
	h.x.udp.take(udpDatagram(leaf, serverAt(server), []byte("opens a mapping")), false)
	readDatagramFrom(t, server, []byte("opens a mapping"))
	f := h.x.Status().Flows
	if f.UDP != [2]int{1, 0} || f.TCP != [2]int{} || f.Echo != [2]int{} {
		t.Errorf("the status counts %v UDP, %v TCP and %v echo flows, want the mapping's one destination in IPv4 alone", f.UDP, f.TCP, f.Echo)
	}
	if want := []egress.SourceFlows{{Source: leaf4, Flows: 1}}; !slices.Equal(f.Sources, want) {
		t.Errorf("the status names the sources %v, want %v", f.Sources, want)
	}
	l := testLimits()
	want := egress.FlowLimits{Budget: l.Budget, From: egress.BudgetGoLimit, Flows: l.Flows, Connections: l.Connections, Dials: l.Dials, TimeWait: l.TimeWait, Window: l.Window, Lanes: l.Lanes, Link: l.Link}
	if f.Limits != want {
		t.Errorf("the status carries the limits %+v, want %+v", f.Limits, want)
	}
}

// The status counts each family's packets from a leaf that no flow takes, an
// extended echo request of RFC 8335 among them, apart from the rest it drops
func TestStatusCountsEachFamilysPacketsNoFlowTakes(t *testing.T) {
	h := newRelayHarness(t, nil)
	for _, c := range []struct {
		leaf, server netip.Addr
		extended     byte
	}{{leaf4, server4, 42}, {leaf6, server6, 160}, {leaf6, server6, 160}} {
		message := echoRequest(c.leaf, c.server, 7, 1, []byte("an extended echo request"))
		message[0] = c.extended
		h.x.echo.take(ipPacket(c.leaf, c.server, icmpProtocol(c.leaf), message))
	}
	h.x.counts.drop(reasonMalformed)
	status := h.x.Status()
	if status.Dropped4 != 1 || status.Dropped6 != 2 {
		t.Errorf("the status counts %d IPv4 and %d IPv6 packets no flow takes, want 1 and 2", status.Dropped4, status.Dropped6)
	}
	if n := status.Flows.Dropped[reasonNotEcho]; n != 3 {
		t.Errorf("the status counts %d dropped as no echo, want 3 among %v", n, status.Flows.Dropped)
	}
}

// A flow the host or the process has no descriptor left for is refused,
// counted under the descriptors in the status, answered past the limit and
// recorded, and its source holds no flow for it
func TestRefusalForWantOfDescriptorsIsCounted(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.EMFILE, syscall.ENFILE} {
		t.Run(errno.Error(), func(t *testing.T) {
			bus := events.New()
			h := newRelayHarness(t, func(rt *Runtime, _ *egress.Egress) {
				rt.Events = bus
				rt.Platform.Prepare = func(string, netip.AddrPort, syscall.RawConn) error { return errno }
			})
			raw := udpDatagram(netip.AddrPortFrom(leaf4, 40000), netip.AddrPortFrom(server4, 5300), []byte("no descriptor left"))
			h.x.handle(h.lane, raw)
			status := h.x.Status()
			if n := status.Flows.Refused[reasonDescriptors]; n != 1 {
				t.Errorf("the status counts %d refusals for the descriptors, want 1 among %v", n, status.Flows.Refused)
			}
			if len(status.Flows.Sources) != 0 || status.Flows.UDP != [2]int{} {
				t.Errorf("the refused flow left %v open from %v", status.Flows.UDP, status.Flows.Sources)
			}
			answers := h.mesh.answered()
			if len(answers) != 1 || answers[0].kind != netstack.ExitPastLimit || !bytes.Equal(answers[0].offending, raw) {
				t.Errorf("answered %v, want one past the limit quoting the datagram", answers)
			}
			recorded := bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "egress.refused" }, 0)
			if len(recorded) != 1 || recorded[0].Attrs["reason"] != reasonDescriptors || recorded[0].Attrs["source"] != leaf4.String() {
				t.Errorf("recorded %v, want one refusal of %s for the descriptors", recorded, leaf4)
			}
		})
	}
}
