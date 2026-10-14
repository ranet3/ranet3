// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package client

import (
	"log/slog"
	"math"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/esp"
	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/transport"
)

// pmtuClient is a client at link.mtu link holding the session d searches under its peer's name, with d's bus as its own
func pmtuClient(d *pathDriver, link uint16) *Client {
	c := &Client{events: d.events, sessions: newSessionSet(), Mesh: &netstack.Mesh{Routes: netstack.NewRouteTable()}}
	c.cfg.Store(&config.Config{Link: config.Link{MTU: link}})
	c.sessions.live[d.peer.ID] = &liveSession{pmtu: d}
	return c
}

// the view shows a session's search as the session's goroutine left it, its budget as its peer carries it
// and the session's last budget change, which is the last pmtu.changed the node recorded and which carries the session's name as its peer
// a search that settled on a path that loses what passes 1450 bytes, and neither refuses nor moves, counts every probe it sent as acked or lost, as the totals do
// a peer the session's name does not match shows no session
func TestPMTUViewShowsTheSearchAndItsLastChange(t *testing.T) {
	const link, carries = 1500, 1450
	r := newPathRig(t, loopbackHub(t), "127.0.0.1:4500", link, math.MaxInt, carries)
	c := pmtuClient(r.driver, link)
	r.waitBudget(t, carries)
	waitFor(t, pathWait, "the search to settle", func() bool {
		return c.DebugPMTU("").Sessions[0].State == control.PMTUConfirmed
	})
	info := c.DebugPMTU("peer")
	if info.LinkMTU != link || len(info.Sessions) != 1 {
		t.Fatalf("the view reads link.mtu %d with %d sessions, want %d with the rig's one", info.LinkMTU, len(info.Sessions), link)
	}
	s := info.Sessions[0]
	if s.Peer != r.driver.peer.ID || s.Budget != carries || s.Target != link || s.Route != 0 || s.Probe != nil {
		t.Errorf("the view reads %+v, want the peer %s at a budget of %d under a target of %d, an unread route and no probe out",
			s, r.driver.peer.ID, carries, link)
	}
	if ipv4, ipv6 := netstack.MSSLimits(carries); s.MSSv4 != ipv4 || s.MSSv6 != ipv6 {
		t.Errorf("the view clamps the MSS to %d and %d, want %d and %d", s.MSSv4, s.MSSv6, ipv4, ipv6)
	}
	if s.Sent != uint64(r.probes.Load()) || s.Sent != s.Acked+s.Lost || s.Lost == 0 || s.Last == nil {
		t.Errorf("the view counts %d sent, %d acked and %d lost with the last %+v, want the rig's %d each acked or lost, some lost",
			s.Sent, s.Acked, s.Lost, s.Last, r.probes.Load())
	}
	if s.Acked != r.totals.acked.Load() || s.Lost != r.totals.lost.Load() {
		t.Errorf("the totals count %d acked and %d lost, want the session's %d and %d", r.totals.acked.Load(), r.totals.lost.Load(), s.Acked, s.Lost)
	}
	var last control.Event
	for _, event := range r.bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "pmtu.changed" }, 0) {
		if event.Peer != s.Peer {
			t.Errorf("the search recorded %+v under %q, want the session's name %s", event.Attrs, event.Peer, s.Peer)
		}
		last = event
	}
	if change := s.Changed; change == nil || change.To != carries || change.Reason != movedByProbe || time.Duration(change.Ago) < 0 ||
		strconv.Itoa(change.From) != last.Attrs["budget_was"] || strconv.Itoa(change.To) != last.Attrs["budget"] || change.Reason != last.Attrs["reason"] {
		t.Errorf("the view reads the last change %+v, want the move to %d by a probe the node recorded last as %v", change, carries, last.Attrs)
	}
	if other := c.DebugPMTU("other"); len(other.Sessions) != 0 {
		t.Errorf("a peer no session is with shows %d sessions", len(other.Sessions))
	}
}

// a session's last change is its own, and a session on a path an earlier one held shows none of the earlier one's
// the two sessions' pmtu events carry the same name, the path
// and a session that confirms the budget it starts at records no change of its own
func TestPMTUViewShowsNoChangeOfAnEarlierSession(t *testing.T) {
	r := newPathRig(t, loopbackHub(t), "127.0.0.1:4500", netstack.DefaultMTU, math.MaxInt, math.MaxInt)
	r.bus.Emit("pmtu.changed", r.driver.peer.ID, slog.String("endpoint", "127.0.0.1:4500"),
		slog.Int("budget", floor), slog.Int("budget_was", netstack.DefaultMTU), slog.String("reason", movedByProbe))
	c := pmtuClient(r.driver, netstack.DefaultMTU)
	waitFor(t, pathWait, "the search to settle", func() bool {
		return c.DebugPMTU("").Sessions[0].State == control.PMTUConfirmed
	})
	if s := c.DebugPMTU("").Sessions[0]; s.Budget != netstack.DefaultMTU || s.Changed != nil {
		t.Errorf("a session that confirmed its start of %d reads a budget of %d and the last change %+v, want none", netstack.DefaultMTU, s.Budget, s.Changed)
	}
}

// a probe the speaker refuses never left, so its wait running out counts it as neither sent nor lost
// however many times the search tries it again
func TestProbeThatNeverLeftIsNotCountedLost(t *testing.T) {
	r := probingRig(t, loopbackHub(t), "127.0.0.1:4500", driverProbeTimeout, func(*pathRig, int, uint16) error {
		return netstack.ErrSendQueueFull
	})
	r.serve(t, 1400, math.MaxInt)
	waitFor(t, pathWait, "the search to try its probe again", func() bool { return r.probes.Load() > maxProbes })
	s := pmtuClient(r.driver, 1400).DebugPMTU("").Sessions[0]
	if s.Sent != 0 || s.Lost != 0 || s.Last != nil || r.totals.lost.Load() != 0 {
		t.Errorf("a probe tried %d times and never sent reads as %d sent and %d lost, the last %+v, the totals %d lost",
			r.probes.Load(), s.Sent, s.Lost, s.Last, r.totals.lost.Load())
	}
}

// a probe whose first attempt left unanswered and whose later attempts the speaker refused counts that first attempt lost and no other
// a refused attempt never left, whatever the attempt before it did
func TestRefusedRetryOfAProbeIsNotCountedLost(t *testing.T) {
	r := probingRig(t, loopbackHub(t), "127.0.0.1:4500", driverProbeTimeout, func(r *pathRig, _ int, _ uint16) error {
		if r.probes.Load() == 1 {
			return nil
		}
		return netstack.ErrSendQueueFull
	})
	r.serve(t, 1400, math.MaxInt)
	waitFor(t, pathWait, "the search to try its probe again and again", func() bool { return r.probes.Load() > maxProbes+1 })
	s := pmtuClient(r.driver, 1400).DebugPMTU("").Sessions[0]
	if s.Sent != 1 || s.Lost != 1 || r.totals.lost.Load() != 1 {
		t.Errorf("a probe tried %d times that left once unanswered reads as %d sent and %d lost, the totals %d lost, want 1 each",
			r.probes.Load(), s.Sent, s.Lost, r.totals.lost.Load())
	}
}

// a probe out when a refusal lowers the target under it is dropped, and counts as sent and neither acked nor lost
// counting it lost would put a loss the path never showed into the lost probes total
func TestProbeDroppedByARefusalIsNotCountedLost(t *testing.T) {
	const link = 1500
	carries := esp.Inner(link, 20)
	var largest atomic.Int32
	r := probingRig(t, loopbackHub(t), "127.0.0.1:4500", time.Hour, func(r *pathRig, size int, nonce uint16) error {
		largest.Store(max(largest.Load(), int32(size)))
		return carrying(carries)(r, size, nonce)
	})
	r.serve(t, link, math.MaxInt)
	waitFor(t, pathWait, "a probe past what the path carries to go out", func() bool { return int(largest.Load()) > carries })
	r.driver.reports <- &transport.PathMTUError{Endpoint: r.driver.endpoint, MTU: link}
	c := pmtuClient(r.driver, link)
	waitFor(t, pathWait, "the search to settle on what the path carries", func() bool {
		s := c.DebugPMTU("").Sessions[0]
		return s.State == control.PMTUConfirmed && s.Budget == carries
	})
	s := c.DebugPMTU("").Sessions[0]
	if s.Lost != 0 || r.totals.lost.Load() != 0 || s.Sent != s.Acked+1 || s.Refusals != 1 {
		t.Errorf("a search whose probe a refusal dropped reads %d sent, %d acked, %d lost and %d refusals, the totals %d lost, want one sent past the acked and none lost",
			s.Sent, s.Acked, s.Lost, s.Refusals, r.totals.lost.Load())
	}
}

// a session that sends without DF is not searched and carries link.mtu, which the view says without reading a search
// it names the endpoint the session sends to after IKE moved it
func TestPMTUViewNamesASessionItDoesNotSearch(t *testing.T) {
	hub := loopbackHub(t)
	mux, err := hub.NewMux(net.IPv4(127, 0, 0, 1), 4500)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mux.Close() })
	d := newPathDriver(mux, nil, events.New(), &probeTotals{}, noSteering, driverProbeTimeout, confirmInterval)
	d.peer, d.endpoint = netstack.NewPeer("example/peer/0@0", nil, nil), mux.Endpoint()
	d.start(1400, math.MaxInt)
	c := pmtuClient(d, 1400)
	s := c.DebugPMTU("").Sessions[0]
	if s.State != control.PMTUNotSearched || s.Budget != 1400 || s.Sent != 0 || s.Probe != nil || s.Target != 0 {
		t.Errorf("the view reads %+v for a session it does not search", s)
	}
	other, err := hub.NewMux(net.IPv4(127, 0, 0, 1), 4501)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = other.Close() })
	mux.AdoptEndpoint(other.Endpoint())
	d.move()
	if got, want := c.DebugPMTU("").Sessions[0].Endpoint, mux.Endpoint().String(); got != want {
		t.Errorf("a session sending to %s reads as sending to %s", want, got)
	}
}

// the probe totals, the answers and the clamps reach a scrape under the names the docs give them
func TestMetricsCountProbesAnswersAndClamps(t *testing.T) {
	c := &Client{Mesh: &netstack.Mesh{Routes: netstack.NewRouteTable()}}
	c.probes.acked.Add(7)
	c.probes.lost.Add(3)
	var out strings.Builder
	c.renderPathMTU(&out)
	for _, want := range []string{
		"# TYPE ranet3_packet_too_big_sent_total counter\nranet3_packet_too_big_sent_total 0\n",
		"# TYPE ranet3_mss_clamped_total counter\nranet3_mss_clamped_total 0\n",
		"# TYPE ranet3_pmtu_probes_total counter\n",
		"ranet3_pmtu_probes_total{result=\"acked\"} 7\n",
		"ranet3_pmtu_probes_total{result=\"lost\"} 3\n",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the scrape does not carry %q:\n%s", want, out.String())
		}
	}
}
