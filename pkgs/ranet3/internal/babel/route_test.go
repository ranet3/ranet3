// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

package babel

import (
	"math"
	"net/netip"
	"slices"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/netstack"
)

func TestRouteTableExpiryAndRecovery(t *testing.T) {
	now := time.Now()
	n := &neighborState{peer: &netstack.Peer{ID: "peer"}}
	makeNeighborReachable(n)
	key := routeKey{dest: netip.MustParsePrefix("10.0.0.0/24")}
	var selected routeSelection
	calls := 0
	rt := newRouteTable(func(got routeKey, sel routeSelection) {
		if got != key {
			t.Fatalf("installed unexpected key %v", got)
		}
		selected = sel
		calls++
	})
	rt.update(n, key, advertisement{routerID: [8]byte{1}, seqno: 1, metric: 1}, time.Minute, now)
	if selected.neighbor != n {
		t.Fatal("live route was not installed")
	}
	n.ihuExpiry = now.Add(time.Second)
	rt.sweepExpired(now.Add(time.Second))
	if selected.neighbor != nil {
		t.Fatal("expired IHU did not retract route")
	}
	if len(rt.entries) != 1 {
		t.Fatal("candidate was discarded before its Update expired")
	}
	n.ihuExpiry = now.Add(time.Hour)
	rt.recomputeNeighbor(n, now.Add(2*time.Second))
	if selected.neighbor != n {
		t.Fatal("fresh IHU did not restore retained candidate")
	}
	// RFC 8966 section 3.5.3: the first expiry retracts the route to infinity
	// and holds the prefix. Only the second one flushes it.
	rt.sweepExpired(now.Add(time.Minute))
	if selected.neighbor != nil || len(rt.entries) != 1 || calls != 4 {
		t.Fatalf("expired Update left selection=%+v entries=%d callbacks=%d", selected, len(rt.entries), calls)
	}
	rt.sweepExpired(now.Add(3 * time.Minute))
	if len(rt.entries) != 0 || calls != 4 {
		t.Fatalf("held retraction left entries=%d callbacks=%d", len(rt.entries), calls)
	}
}

func TestRouteTableNeighborExpiryDeletesEmptyEntry(t *testing.T) {
	rt := newRouteTable(func(routeKey, routeSelection) {})
	n := &neighborState{peer: &netstack.Peer{ID: "peer"}}
	key := routeKey{dest: netip.MustParsePrefix("10.0.0.0/24")}
	rt.update(n, key, advertisement{routerID: [8]byte{1}, seqno: 1, metric: 1}, time.Minute, time.Now())
	rt.expireNeighbor(n, time.Now())
	if len(rt.entries) != 0 {
		t.Fatalf("neighbor expiry retained %d empty entries", len(rt.entries))
	}
}

func TestInfiniteLinkCostNeverBecomesReachable(t *testing.T) {
	if got := saturatingAdd(MetricInfinity, 1); got != MetricInfinity {
		t.Fatalf("infinity + 1 = %d, want infinity", got)
	}
	rt := newRouteTable(func(routeKey, routeSelection) { t.Fatal("installed route without live Hello/IHU") })
	n := &neighborState{peer: &netstack.Peer{ID: "peer"}}
	key := routeKey{dest: netip.MustParsePrefix("10.0.0.0/24")}
	rt.update(n, key, advertisement{routerID: [8]byte{1}, seqno: 1, metric: 1}, time.Minute, time.Now())
}

// A worsened link is re-advertised, because this node tells the mesh the
// metric, and is not reinstalled, because the metric is not part of the
// forwarding entry. Reinstalling on it wrote the same entry, logged a line and
// woke the kernel reconciler once per prefix through that neighbor, which
// under RFC 9616 costing is most IHUs.
func TestSelectedMetricChangeIsAdvertisedRatherThanReinstalled(t *testing.T) {
	now := time.Now()
	n := &neighborState{peer: &netstack.Peer{ID: "peer"}}
	makeNeighborReachable(n)
	installs := 0
	var got routeSelection
	rt := newRouteTable(func(_ routeKey, sel routeSelection) { installs, got = installs+1, sel })
	key := routeKey{dest: netip.MustParsePrefix("10.0.0.0/24")}
	rt.update(n, key, advertisement{routerID: [8]byte{1}, seqno: 1, metric: 10}, time.Minute, now)
	if installs != 1 || got.neighbor != n {
		t.Fatalf("the route was installed %d times as %+v", installs, got)
	}
	rt.takeDirty()

	n.reportedCost = 100
	rt.recomputeNeighbor(n, now)
	if rt.entries[key].selected.cost != 110 {
		t.Errorf("the selected cost is %d, want the worsened 110", rt.entries[key].selected.cost)
	}
	if len(rt.takeDirty()) == 0 {
		t.Error("a worsened link was not re-advertised, so the mesh keeps routing through it")
	}
	if installs != 1 {
		t.Errorf("the forwarding entry was rewritten %d times for a change it does not carry", installs)
	}
}

func TestFeasibilityCondition(t *testing.T) {
	key := routeKey{dest: netip.MustParsePrefix("10.0.0.0/24")}
	origin := [8]byte{1}
	for _, test := range []struct {
		name       string
		advertised *advertisement // the distance this node has already sent
		received   advertisement
		want       bool
	}{
		{"no distance for the source", nil, advertisement{origin, 1, 100}, true},
		{"retraction", &advertisement{origin, 1, 10}, advertisement{origin, 1, MetricInfinity}, true},
		{"better metric at the same seqno", &advertisement{origin, 1, 10}, advertisement{origin, 1, 9}, true},
		{"equal metric at the same seqno", &advertisement{origin, 1, 10}, advertisement{origin, 1, 10}, false},
		{"worse metric at the same seqno", &advertisement{origin, 1, 10}, advertisement{origin, 1, 11}, false},
		{"newer seqno with a worse metric", &advertisement{origin, 1, 10}, advertisement{origin, 2, 1000}, true},
		{"older seqno with a better metric", &advertisement{origin, 1, 10}, advertisement{origin, 0, 1}, false},
		{"newer seqno across the wrap", &advertisement{origin, 0xffff, 10}, advertisement{origin, 0, 1000}, true},
		{"another origin for the same prefix", &advertisement{origin, 1, 10}, advertisement{[8]byte{2}, 1, 1000}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			rt := newRouteTable(func(routeKey, routeSelection) {})
			if test.advertised != nil {
				rt.observe(key, *test.advertised, "peer", time.Now())
			}
			if got := rt.feasible(key, test.received, "peer"); got != test.want {
				t.Fatalf("feasible = %v, want %v: selecting an unfeasible route closes a forwarding loop", got, test.want)
			}
		})
	}
}

func TestUnfeasibleUpdateIsNeverSelected(t *testing.T) {
	now := time.Now()
	origin := [8]byte{1}
	key := routeKey{dest: netip.MustParsePrefix("10.0.0.0/24")}
	n := &neighborState{peer: &netstack.Peer{ID: "peer"}}
	makeNeighborReachable(n)
	rt := newRouteTable(func(routeKey, routeSelection) {})
	rt.observe(key, advertisement{routerID: origin, seqno: 1, metric: 40}, "peer", now)

	rt.update(n, key, advertisement{routerID: origin, seqno: 1, metric: 40}, time.Minute, now)
	if entry := rt.entries[key]; entry == nil || entry.selected.neighbor != nil {
		t.Fatal("an unfeasible update was selected or not kept as a candidate")
	}
	rt.update(n, key, advertisement{routerID: origin, seqno: 1, metric: 39}, time.Minute, now)
	if rt.entries[key].selected.neighbor != n {
		t.Fatal("a feasible update was not selected")
	}
	// A metric increase can take the selected route past the distance this
	// node has already advertised, which is exactly the case the feasibility
	// condition exists to refuse.
	rt.update(n, key, advertisement{routerID: origin, seqno: 1, metric: 41}, time.Minute, now)
	if sel := rt.entries[key].selected; sel.neighbor != nil {
		t.Fatalf("an unfeasible update stayed selected via %q", sel.neighbor.peer.ID)
	}
	if len(rt.starved) == 0 {
		t.Fatal("losing the only feasible route asked nobody for a new seqno")
	}
	if got := rt.starved[0]; got.routerID != origin || got.seqno != 2 {
		t.Fatalf("starvation request = %+v, want seqno 2 for the origin", got)
	}
}

// A stored route can turn unfeasible without any update arriving, because this
// node advertised a better distance in the meantime. Selection has to notice.
func TestSelectionRechecksFeasibility(t *testing.T) {
	now := time.Now()
	origin := [8]byte{1}
	key := routeKey{dest: netip.MustParsePrefix("10.0.0.0/24")}
	n := &neighborState{peer: &netstack.Peer{ID: "peer"}}
	makeNeighborReachable(n)
	rt := newRouteTable(func(routeKey, routeSelection) {})
	rt.update(n, key, advertisement{routerID: origin, seqno: 1, metric: 39}, time.Minute, now)
	if rt.entries[key].selected.neighbor != n {
		t.Fatal("the only route was not selected")
	}

	rt.observe(key, advertisement{routerID: origin, seqno: 1, metric: 20}, "peer", now)
	rt.sweepExpired(now)
	if sel := rt.entries[key].selected; sel.neighbor != nil {
		t.Fatalf("a route that is no longer feasible stayed selected via %q", sel.neighbor.peer.ID)
	}
	if len(rt.starved) == 0 {
		t.Fatal("no seqno request went out for the route that became unusable")
	}
}

func TestHysteresisIgnoresFlappingChallenger(t *testing.T) {
	now := time.Now()
	key := routeKey{dest: netip.MustParsePrefix("10.0.0.0/24")}
	steady := &neighborState{peer: &netstack.Peer{ID: "steady"}}
	flappy := &neighborState{peer: &netstack.Peer{ID: "flappy"}}
	makeNeighborReachable(steady)
	makeNeighborReachable(flappy)
	rt := newRouteTable(func(routeKey, routeSelection) {})
	rt.tau = 4 * time.Second

	rt.update(steady, key, advertisement{routerID: [8]byte{1}, seqno: 1, metric: 60}, time.Hour, now)
	rt.update(flappy, key, advertisement{routerID: [8]byte{2}, seqno: 1, metric: 500}, time.Hour, now)
	if rt.entries[key].selected.neighbor != steady {
		t.Fatal("the cheaper route was not selected")
	}
	rt.update(flappy, key, advertisement{routerID: [8]byte{2}, seqno: 1, metric: 1}, time.Hour, now.Add(time.Second))
	if got := rt.entries[key].selected.neighbor; got != steady {
		t.Fatalf("a route that was bad a second ago took over at once, now via %q", got.peer.ID)
	}
	// Consistently good for several time constants is the bar Appendix A.3
	// sets, and it is met here.
	rt.sweepExpired(now.Add(15 * time.Second))
	if got := rt.entries[key].selected.neighbor; got != flappy {
		t.Fatal("a consistently better route never took over")
	}
}

// an unfeasible offer draws a request only where selection would take it were it feasible, weighed with every feasible route, not with the selected one alone, and not with another unfeasible one
// b is selected, c is cheaper but was dear a moment ago, so its smoothed metric keeps b, and z beats b but not c
// were z feasible selection would weigh c first and still keep b, so z draws no request
func TestUnfeasibleOfferIsWeighedWithEveryFeasibleRoute(t *testing.T) {
	now := time.Now()
	key := routeKey{dest: netip.MustParsePrefix("2001:db8:7::/48")}
	b, c, z := &neighborState{peer: &netstack.Peer{ID: "b"}}, &neighborState{peer: &netstack.Peer{ID: "c"}}, &neighborState{peer: &netstack.Peer{ID: "z"}}
	for _, n := range []*neighborState{b, c, z} {
		makeNeighborReachable(n)
	}
	rt := newRouteTable(func(routeKey, routeSelection) {})
	rt.tau, rt.margin = marginTau, defaultMargin
	feasibleOrigin, unfeasibleOrigin := [8]byte{1}, [8]byte{2}
	rt.observe(key, advertisement{routerID: unfeasibleOrigin, seqno: 1, metric: 10}, "z", now)
	rt.update(b, key, advertisement{routerID: feasibleOrigin, seqno: 1, metric: 100}, time.Hour, now)
	rt.update(c, key, advertisement{routerID: feasibleOrigin, seqno: 1, metric: 300}, time.Hour, now)
	rt.update(c, key, advertisement{routerID: feasibleOrigin, seqno: 1, metric: 50}, time.Hour, now)
	if got := rt.entries[key].selected.neighbor; got != b {
		t.Fatalf("selected %v, want b, whose smoothed metric is the lowest", got)
	}
	rt.takeStarved()
	rt.update(z, key, advertisement{routerID: unfeasibleOrigin, seqno: 1, metric: 60}, time.Hour, now)
	for _, request := range rt.takeStarved() {
		if request.neighbor == z {
			t.Errorf("z's offer, which c goes before, drew %+v", request)
		}
	}

	// without c in the way the same offer draws its request
	rt.update(c, key, advertisement{routerID: feasibleOrigin, seqno: 1, metric: MetricInfinity}, time.Hour, now)
	rt.takeStarved()
	rt.update(z, key, advertisement{routerID: unfeasibleOrigin, seqno: 1, metric: 60}, time.Hour, now)
	if got := rt.takeStarved(); len(got) != 1 || got[0].neighbor != z || !got[0].once {
		t.Errorf("with c gone z's offer drew %+v, want one request to z, so the case above proves nothing", got)
	}

	// x's cheaper candidate is unfeasible, so selection could never take it, and z still draws its request
	x := &neighborState{peer: &netstack.Peer{ID: "x"}}
	makeNeighborReachable(x)
	rt.update(x, key, advertisement{routerID: unfeasibleOrigin, seqno: 1, metric: 40}, time.Hour, now)
	rt.takeStarved()
	rt.update(z, key, advertisement{routerID: unfeasibleOrigin, seqno: 1, metric: 60}, time.Hour, now)
	if got := rt.takeStarved(); len(got) != 1 || got[0].neighbor != z || !got[0].once {
		t.Errorf("with x's unfeasible candidate cheaper still z's offer drew %+v, want one request to z", got)
	}
}

// marginTau is the hysteresis time constant the speaker runs at the default hello interval
const marginTau = 12 * time.Second

// twoEqualRoutes is a table at margin holding one prefix through a and b at the same cost, a selected
func twoEqualRoutes(t *testing.T, margin uint16, now time.Time) (*routeTable, routeKey, *neighborState, *neighborState) {
	t.Helper()
	key := routeKey{dest: netip.MustParsePrefix("2001:db8:5::/48")}
	a, b := &neighborState{peer: &netstack.Peer{ID: "a"}}, &neighborState{peer: &netstack.Peer{ID: "b"}}
	makeNeighborReachable(a)
	makeNeighborReachable(b)
	rt := newRouteTable(func(routeKey, routeSelection) {})
	rt.tau, rt.margin = marginTau, margin
	for _, n := range []*neighborState{a, b} {
		rt.update(n, key, advertisement{routerID: [8]byte{1}, seqno: 1, metric: 68}, time.Hour, now)
	}
	if got := rt.entries[key].selected.neighbor; got != a {
		t.Fatalf("the tie went to %v, want a", got)
	}
	return rt, key, a, b
}

// a one-unit rise on the selected route keeps it at the default margin, where with no margin the route at the old cost took over at once
// a challenger better by more than the margin on both measures takes over once its smoothed cost has come down that far
func TestOneUnitRiseKeepsTheSelectedRouteAndAClearlyBetterOneTakesOver(t *testing.T) {
	now := time.Now()
	rt, key, a, b := twoEqualRoutes(t, defaultMargin, now)
	rt.update(a, key, advertisement{routerID: [8]byte{1}, seqno: 1, metric: 69}, time.Hour, now.Add(4*time.Second))
	if got := rt.entries[key].selected.neighbor; got != a {
		t.Fatalf("a one-unit rise moved the prefix to %q", got.peer.ID)
	}

	rt.update(b, key, advertisement{routerID: [8]byte{1}, seqno: 1, metric: 58}, time.Hour, now.Add(5*time.Second))
	rt.sweepExpired(now.Add(6 * time.Second))
	if got := rt.entries[key].selected.neighbor; got != a {
		t.Fatalf("a route 11 cheaper took over a second after it fell, before its smoothed cost was %d below, via %q", defaultMargin, got.peer.ID)
	}
	rt.sweepExpired(now.Add(5*time.Second + marginTau))
	if got := rt.entries[key].selected.neighbor; got != b {
		t.Fatal("a route 11 cheaper for a time constant never took over")
	}

	rt, key, a, _ = twoEqualRoutes(t, 0, now)
	rt.update(a, key, advertisement{routerID: [8]byte{1}, seqno: 1, metric: 69}, time.Hour, now.Add(4*time.Second))
	if got := rt.entries[key].selected.neighbor; got == a {
		t.Error("with no margin a one-unit rise kept the selected route, so the case above proves nothing")
	}
}

// RFC 8966 section 3.7.2 triggers an update on a new router-id, a move to or from unreachable and a cost risen by the threshold, and not on a next hop that changes alone
// a and b offer one prefix under one origin and seqno, the table at no margin and no smoothing so each change is selected at once
func TestTriggeredUpdatesFollowSection372(t *testing.T) {
	now := time.Now()
	setup := func(t *testing.T) (*routeTable, routeKey, *neighborState, *neighborState) {
		t.Helper()
		rt, key, a, b := twoEqualRoutes(t, 0, now)
		rt.tau, rt.trigger = 0, 96
		rt.takeDirty()
		return rt, key, a, b
	}
	offer := func(rt *routeTable, n *neighborState, key routeKey, origin byte, metric uint16) {
		rt.update(n, key, advertisement{routerID: [8]byte{origin}, seqno: 1, metric: metric}, time.Hour, now)
	}
	for _, test := range []struct {
		name    string
		change  func(*routeTable, routeKey, *neighborState, *neighborState)
		trigger bool
	}{
		{"a next hop that changes alone", func(rt *routeTable, key routeKey, a, b *neighborState) { offer(rt, b, key, 1, 58) }, false},
		{"a new router-id", func(rt *routeTable, key routeKey, a, b *neighborState) { offer(rt, b, key, 2, 58) }, true},
		{"a move to unreachable", func(rt *routeTable, key routeKey, a, b *neighborState) {
			offer(rt, a, key, 1, MetricInfinity)
			offer(rt, b, key, 1, MetricInfinity)
		}, true},
		{"a cost risen by the threshold", func(rt *routeTable, key routeKey, a, b *neighborState) {
			offer(rt, b, key, 1, 68+96)
			offer(rt, a, key, 1, 68+96)
		}, true},
		{"a cost risen by less", func(rt *routeTable, key routeKey, a, b *neighborState) {
			offer(rt, b, key, 1, 68+95)
			offer(rt, a, key, 1, 68+95)
		}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			rt, key, a, b := setup(t)
			test.change(rt, key, a, b)
			if got := len(rt.takeDirty()) == 1; got != test.trigger {
				t.Errorf("the change left a triggered update owed %v, want %v", got, test.trigger)
			}
		})
	}

	rt, key, a, b := setup(t)
	offer(rt, a, key, 1, MetricInfinity)
	offer(rt, b, key, 1, MetricInfinity)
	rt.takeDirty()
	offer(rt, b, key, 1, 68)
	if len(rt.takeDirty()) != 1 {
		t.Error("a move from unreachable owed no triggered update")
	}
}

// RFC 8966 Section 3.7.2 triggers on a new seqno only to satisfy a request, here one this node forwarded or one it is still repeating
// a seqno nobody asked for waits for the periodic dump
func TestNewSeqnoTriggersOnlyWhereItAnswersARequest(t *testing.T) {
	origin := [8]byte{0x72, 3}
	dest := netip.MustParsePrefix("2001:db8:6::/48")
	key := routeKey{dest: dest}
	for _, test := range []struct {
		name    string
		asked   func(s *Speaker, now time.Time)
		trigger bool
	}{
		{"no request", func(*Speaker, time.Time) {}, false},
		{"a request forwarded for a neighbor", func(s *Speaker, now time.Time) {
			s.recordSeqnoRequest(sourceKey{route: key, routerID: origin}, 2, "asker", now)
		}, true},
		{"a request forwarded past the window that suppresses a repeat", func(s *Speaker, now time.Time) {
			s.recordSeqnoRequest(sourceKey{route: key, routerID: origin}, 2, "asker", now.Add(-seqnoRequestSuppress-100*time.Millisecond))
		}, true},
		{"a request forwarded longer ago than it is kept", func(s *Speaker, now time.Time) {
			s.recordSeqnoRequest(sourceKey{route: key, routerID: origin}, 2, "asker", now.Add(-seqnoForwardExpiry))
		}, false},
		{"a request forwarded for a later seqno", func(s *Speaker, now time.Time) {
			s.recordSeqnoRequest(sourceKey{route: key, routerID: origin}, 3, "asker", now)
		}, false},
		{"a request this node sent for itself alone", func(s *Speaker, now time.Time) {
			s.recordSeqnoRequest(sourceKey{route: key, routerID: origin}, 2, "", now)
		}, false},
		{"a request this node is still repeating", func(s *Speaker, now time.Time) {
			s.rememberStarved(key, origin, 2, "peer", now)
		}, true},
		{"a request for a later seqno", func(s *Speaker, now time.Time) {
			s.rememberStarved(key, origin, 3, "peer", now)
		}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			speaker, neighbor, _ := captureSpeaker(t, Config{})
			makeNeighborReachable(neighbor)
			announce := func(seqno uint16) {
				speaker.handlePacket(neighbor, EncodePacket([]RawTLV{EncodeRouterID(origin), EncodeUpdate(Update{
					AE: AEIPv6, Plen: dest.Bits(), Prefix: dest.Addr().AsSlice(), Interval: 400, Seqno: seqno, Metric: 10})}))
			}
			announce(1)
			speaker.mu.Lock()
			if speaker.routes.entries[key] == nil || speaker.routes.entries[key].selected.neighbor != neighbor {
				speaker.mu.Unlock()
				t.Fatal("the route was not selected, so this proves nothing")
			}
			speaker.routes.takeDirty()
			test.asked(speaker, time.Now())
			speaker.mu.Unlock()
			announce(2)
			speaker.mu.Lock()
			defer speaker.mu.Unlock()
			if got := len(speaker.routes.takeDirty()) == 1; got != test.trigger {
				t.Errorf("seqno 2 left a triggered update owed %v, want %v", got, test.trigger)
			}
		})
	}
}

// RFC 8966 section 3.5.4 holds a retracted prefix for its whole interval, so a
// packet for it is answered rather than sent down a covering route. The hold
// has to run from the retraction: one arriving just before the deadline of the
// update it replaces otherwise holds for whatever is left of it, which on a
// node carrying an exit-announced default is the difference between an error
// and a packet bouncing until its hop limit is spent.
func TestRetractionHoldsThePrefixForItsOwnInterval(t *testing.T) {
	now := time.Now()
	n := &neighborState{peer: &netstack.Peer{ID: "peer"}}
	makeNeighborReachable(n)
	key := routeKey{dest: netip.MustParsePrefix("10.0.0.0/24")}
	rt := newRouteTable(func(routeKey, routeSelection) {})
	const hold = time.Minute
	rt.update(n, key, advertisement{routerID: [8]byte{1}, seqno: 1, metric: 1}, hold, now)

	// The retraction lands a second before the update it replaces expires.
	retracted := now.Add(hold - time.Second)
	rt.update(n, key, advertisement{routerID: [8]byte{1}, seqno: 1, metric: MetricInfinity}, hold, retracted)
	if len(rt.entries) != 1 {
		t.Fatal("the retraction flushed the prefix instead of holding it")
	}
	rt.sweepExpired(retracted.Add(hold - time.Second))
	if len(rt.entries) != 1 {
		t.Error("the hold ran from the update the retraction replaced, so the prefix falls through to a covering route")
	}
	rt.sweepExpired(retracted.Add(hold + time.Second))
	if len(rt.entries) != 0 {
		t.Error("the hold never ran out, so a retracted prefix is held for the life of the process")
	}
}

// The hold runs once, for the interval of the update it replaces. A neighbor
// choosing either end of that chooses how long this node answers with an error
// for the prefix: repeat the retraction and it never expires, and the entry
// holds a maxRouteKeys slot with it. Carry an interval of one centisecond and
// the prefix falls through to a covering route almost at once.
func TestRepeatedRetractionsNeitherExtendNorCutTheHold(t *testing.T) {
	now := time.Now()
	n := &neighborState{peer: &netstack.Peer{ID: "peer"}}
	makeNeighborReachable(n)
	key := routeKey{dest: netip.MustParsePrefix("10.0.0.0/24")}
	const hold = time.Minute
	retract := func(rt *routeTable, at time.Time, carried time.Duration) {
		rt.update(n, key, advertisement{routerID: [8]byte{1}, seqno: 1, metric: MetricInfinity}, carried, at)
	}

	rt := newRouteTable(func(routeKey, routeSelection) {})
	rt.update(n, key, advertisement{routerID: [8]byte{1}, seqno: 1, metric: 1}, hold, now)
	retract(rt, now, hold)
	for elapsed := time.Second; elapsed < hold; elapsed += time.Second {
		retract(rt, now.Add(elapsed), hold)
	}
	rt.sweepExpired(now.Add(hold + time.Second))
	if len(rt.entries) != 0 {
		t.Error("a retraction every second held the prefix past its own interval, so a neighbor decides when it ends")
	}

	rt = newRouteTable(func(routeKey, routeSelection) {})
	rt.update(n, key, advertisement{routerID: [8]byte{1}, seqno: 1, metric: 1}, hold, now)
	retract(rt, now, 10*time.Millisecond)
	rt.sweepExpired(now.Add(time.Second))
	if len(rt.entries) != 1 {
		t.Error("a retraction carrying its own short interval cut the hold, so the prefix falls through at once")
	}
}

// a prefix that lost its last route is held until every update this node sent for it has expired at a neighbor, unless a route for it is selected first
// an unfeasible candidate that arrives inside the hold is never selected, so the hold still ends when it was due to
func TestUnfeasibleCandidateDoesNotLengthenTheHold(t *testing.T) {
	now := time.Now()
	key := routeKey{dest: netip.MustParsePrefix("10.0.2.0/24")}
	a, b := &neighborState{peer: &netstack.Peer{ID: "a"}}, &neighborState{peer: &netstack.Peer{ID: "b"}}
	makeNeighborReachable(a)
	makeNeighborReachable(b)
	var released []bool
	rt := newRouteTable(func(routeKey, routeSelection) {})
	rt.forget = func(_ routeKey, held bool) { released = append(released, held) }
	rt.updateExpiry = 10 * time.Minute
	const hold = time.Minute
	origin := advertisement{routerID: [8]byte{1}, seqno: 1, metric: 1}
	rt.update(a, key, origin, hold, now)
	rt.observe(key, origin, "a", now)
	rt.noteAdvertised(key, now)
	until := rt.advertisedUntil[key]
	rt.update(a, key, advertisement{routerID: origin.routerID, seqno: 1, metric: MetricInfinity}, hold, now)
	rt.sweepExpired(now.Add(hold + time.Second))
	if rt.entries[key] != nil || !slices.Equal(released, []bool{true}) {
		t.Fatalf("the flushed route left the entry %v and wrote %v, want it held", rt.entries[key] != nil, released)
	}
	rt.update(b, key, advertisement{routerID: origin.routerID, seqno: 1, metric: 50}, time.Hour, now.Add(hold+2*time.Second))
	if entry := rt.entries[key]; entry == nil || entry.selected.neighbor != nil {
		t.Fatal("the unfeasible offer was selected or not kept, so this proves nothing")
	}
	rt.sweepExpired(until.Add(time.Second))
	if !slices.Equal(released, []bool{true, false}) {
		t.Errorf("with a candidate kept the hold wrote %v, want it held and then released when it was due", released)
	}
}

// a prefix whose last route that could carry it goes while an unfeasible candidate kept before is left is held as one that lost its last route, and released when every update this node sent for it has expired
// the route goes by its flush at the end of its hold, or with its neighbor's session
func TestCandidateKeptBeforeTheLossDoesNotLengthenTheHold(t *testing.T) {
	for _, how := range []string{"flushed", "neighbor gone"} {
		t.Run(how, func(t *testing.T) {
			now := time.Now()
			key := routeKey{dest: netip.MustParsePrefix("10.0.3.0/24")}
			a, b := &neighborState{peer: &netstack.Peer{ID: "a"}}, &neighborState{peer: &netstack.Peer{ID: "b"}}
			makeNeighborReachable(a)
			makeNeighborReachable(b)
			var released []bool
			rt := newRouteTable(func(routeKey, routeSelection) {})
			rt.forget = func(_ routeKey, held bool) { released = append(released, held) }
			rt.updateExpiry = 10 * time.Minute
			const hold = time.Minute
			origin := advertisement{routerID: [8]byte{1}, seqno: 1, metric: 1}
			rt.update(a, key, origin, hold, now)
			// the distance this node advertised through a, which b's offer does not beat
			rt.observe(key, advertisement{routerID: origin.routerID, seqno: 1, metric: 30}, "a", now)
			rt.noteAdvertised(key, now)
			until := rt.advertisedUntil[key]
			rt.update(b, key, advertisement{routerID: origin.routerID, seqno: 1, metric: 50}, time.Hour, now)
			if entry := rt.entries[key]; entry.selected.neighbor != a || entry.routes[b] == nil {
				t.Fatal("b's offer was selected or not kept, so this proves nothing")
			}
			if how == "flushed" {
				rt.update(a, key, advertisement{routerID: origin.routerID, seqno: 1, metric: MetricInfinity}, hold, now)
				rt.sweepExpired(now.Add(hold + time.Second))
			} else {
				rt.expireNeighbor(a, now.Add(hold+time.Second))
			}
			if !slices.Equal(released, []bool{true}) {
				t.Fatalf("once a's route went the forwarding writes were %v, want it held", released)
			}
			rt.sweepExpired(until.Add(time.Second))
			if !slices.Equal(released, []bool{true, false}) || rt.entries[key] == nil {
				t.Errorf("with b's candidate kept the forwarding writes were %v and the entry kept %v, want it held, released when due, and the candidate kept",
					released, rt.entries[key] != nil)
			}
		})
	}
}

// a's flush leaves c's retracted route still held at infinity, which counts as a route, so the forwarding entry stays unreachable until it too is flushed
func TestFlushBesideARetractedRouteStillHeldWritesNothing(t *testing.T) {
	now := time.Now()
	key := routeKey{dest: netip.MustParsePrefix("10.0.4.0/24")}
	a, c := &neighborState{peer: &netstack.Peer{ID: "a"}}, &neighborState{peer: &netstack.Peer{ID: "c"}}
	makeNeighborReachable(a)
	makeNeighborReachable(c)
	var released []bool
	rt := newRouteTable(func(routeKey, routeSelection) {})
	rt.forget = func(_ routeKey, held bool) { released = append(released, held) }
	rt.updateExpiry = time.Second
	origin := [8]byte{1}
	rt.update(a, key, advertisement{routerID: origin, seqno: 1, metric: 1}, time.Minute, now)
	rt.update(c, key, advertisement{routerID: origin, seqno: 1, metric: 5}, 2*time.Minute, now)
	rt.update(c, key, advertisement{routerID: origin, seqno: 1, metric: MetricInfinity}, 0, now)
	rt.update(a, key, advertisement{routerID: origin, seqno: 1, metric: MetricInfinity}, 0, now)
	rt.sweepExpired(now.Add(time.Minute + time.Second))
	if entry := rt.entries[key]; entry == nil || entry.routes[a] != nil || entry.routes[c] == nil {
		t.Fatal("a's route was not flushed or c's went with it, so this proves nothing")
	}
	if len(released) != 0 {
		t.Errorf("a's flush, with c's retracted route still held, wrote %v, want the unreachable entry kept", released)
	}
	rt.sweepExpired(now.Add(2*time.Minute + time.Second))
	if !slices.Equal(released, []bool{false}) || rt.entries[key] != nil {
		t.Errorf("once c's route was flushed too the writes were %v and the entry kept %v, want it released", released, rt.entries[key] != nil)
	}
}

// a route that goes by its flush or with its neighbor's session, beside a feasible route selection moves to, writes nothing over the forwarding entry that selection installed
func TestRouteGoneBesideASelectedOneWritesNoUnreachable(t *testing.T) {
	for _, how := range []string{"flushed", "neighbor gone"} {
		t.Run(how, func(t *testing.T) {
			now := time.Now()
			key := routeKey{dest: netip.MustParsePrefix("10.0.6.0/24")}
			a, c := &neighborState{peer: &netstack.Peer{ID: "a"}}, &neighborState{peer: &netstack.Peer{ID: "c"}}
			makeNeighborReachable(a)
			makeNeighborReachable(c)
			var released []bool
			rt := newRouteTable(func(routeKey, routeSelection) {})
			rt.forget = func(_ routeKey, held bool) { released = append(released, held) }
			rt.updateExpiry = 10 * time.Minute
			origin := [8]byte{1}
			rt.update(a, key, advertisement{routerID: origin, seqno: 1, metric: 1}, 10*time.Second, now)
			rt.update(c, key, advertisement{routerID: origin, seqno: 1, metric: 5}, time.Hour, now)
			rt.noteAdvertised(key, now)
			if how == "flushed" {
				rt.update(a, key, advertisement{routerID: origin, seqno: 1, metric: MetricInfinity}, 0, now)
				rt.sweepExpired(now.Add(11 * time.Second))
			} else {
				rt.expireNeighbor(a, now.Add(time.Second))
			}
			if entry := rt.entries[key]; entry == nil || entry.selected.neighbor != c || entry.routes[a] != nil {
				t.Fatal("c is not selected or a's route is still there, so this proves nothing")
			}
			if len(released) != 0 {
				t.Errorf("a's route going beside c's selected one wrote %v over c's forwarding entry", released)
			}
		})
	}
}

// A wildcard retraction takes every route from one neighbor at once, and the
// section 3.5.4 hold runs from it for each of them. The wildcard form carries
// no interval of its own, so each route holds for as long as the update it
// replaces would have.
func TestWildcardRetractionHoldsEveryPrefixItTakes(t *testing.T) {
	now := time.Now()
	n := &neighborState{peer: &netstack.Peer{ID: "peer"}}
	makeNeighborReachable(n)
	rt := newRouteTable(func(routeKey, routeSelection) {})
	const hold = time.Minute
	keys := []routeKey{
		{dest: netip.MustParsePrefix("10.0.0.0/24")},
		{dest: netip.MustParsePrefix("10.0.1.0/24")},
	}
	for _, key := range keys {
		rt.update(n, key, advertisement{routerID: [8]byte{1}, seqno: 1, metric: 1}, hold, now)
	}

	retracted := now.Add(hold - time.Second)
	rt.retractNeighbor(n, retracted)
	rt.sweepExpired(retracted.Add(hold - time.Second))
	if len(rt.entries) != len(keys) {
		t.Errorf("the wildcard retraction held %d of %d prefixes, so the rest fall through to a covering route",
			len(rt.entries), len(keys))
	}
	rt.sweepExpired(retracted.Add(hold + time.Second))
	if len(rt.entries) != 0 {
		t.Error("a wildcard retraction held its prefixes for the life of the process")
	}
}

// A link that goes down and comes back must be selectable again promptly. The
// smoothed metric follows an increase immediately, so feeding it infinity when
// a route is retracted pins ms(R) at 65535, and the cheap path then stays
// unselected while that decays over several time constants.
func TestRetractionDoesNotPoisonSmoothedMetric(t *testing.T) {
	rt := newRouteTable(func(routeKey, routeSelection) {})
	rt.tau = time.Minute
	good := &neighborState{peer: &netstack.Peer{ID: "good"}}
	backup := &neighborState{peer: &netstack.Peer{ID: "backup"}}
	makeNeighborReachable(good)
	makeNeighborReachable(backup)
	key := routeKey{dest: netip.MustParsePrefix("fd00:1::/64")}
	now := time.Now()

	adv := advertisement{routerID: [8]byte{1}, seqno: 1, metric: 8}
	rt.update(good, key, adv, time.Hour, now)
	rt.update(backup, key, advertisement{routerID: [8]byte{1}, seqno: 1, metric: 200}, time.Hour, now)
	if got := rt.entries[key].selected.neighbor; got != good {
		t.Fatalf("the cheap route was not selected, got %v", got)
	}

	// The good link retracts, then returns ten seconds later.
	now = now.Add(time.Second)
	rt.update(good, key, advertisement{routerID: [8]byte{1}, seqno: 1, metric: MetricInfinity}, time.Hour, now)
	if rt.entries[key].selected.neighbor != backup {
		t.Fatal("traffic did not fail over to the backup")
	}
	now = now.Add(10 * time.Second)
	rt.update(good, key, adv, time.Hour, now)

	if got := rt.entries[key].selected.neighbor; got != good {
		name := "nothing"
		if got != nil {
			name = got.peer.ID
		}
		t.Errorf("after a ten second outage the cheap link is still not selected, got %q, "+
			"so its smoothed metric was poisoned by the retraction", name)
	}
}

// A peer decides how many prefixes it sends. Each one costs a map, a trie node
// and a source entry, and the per-wake selection sweep is linear in the count,
// so the ceiling has to be ours rather than theirs.
func TestRouteTableRefusesMorePrefixesThanItsLimit(t *testing.T) {
	rt := newRouteTable(func(routeKey, routeSelection) {})
	peer := &neighborState{peer: &netstack.Peer{ID: "flood"}}
	makeNeighborReachable(peer)
	now := time.Now()
	adv := advertisement{routerID: [8]byte{1}, seqno: 1, metric: 64}

	for i := range maxRouteKeys + 64 {
		key := routeKey{dest: netip.PrefixFrom(netip.AddrFrom16([16]byte{
			0xfd, 0, byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i),
		}), 64)}
		rt.update(peer, key, adv, time.Hour, now)
	}
	if got := len(rt.entries); got > maxRouteKeys {
		t.Errorf("one peer installed %d prefixes against a limit of %d", got, maxRouteKeys)
	}
	if len(rt.entries) == 0 {
		t.Error("the limit refused everything, so no route is ever learned")
	}
}

// The fast path in smooth has to be the same number as the arithmetic it
// skips, not merely close to it: ms(R) decides which route is selected, so a
// disagreement anywhere changes routing. Driven over the shapes a selection
// pass produces (a first sample, a decay with no elapsed time, an
// improvement, a degradation, and a zero tau) against the arithmetic written
// out in full.
func TestSmoothTakesTheShortcutOnlyWhereItAgrees(t *testing.T) {
	reference := func(r routeInfo, cost uint16, now time.Time, tau time.Duration) float64 {
		elapsed := now.Sub(r.smoothedAt)
		switch {
		case r.smoothedAt.IsZero() || tau <= 0:
			r.smoothed = float64(cost)
		case elapsed > 0:
			r.smoothed = float64(cost) + (r.smoothed-float64(cost))*math.Exp(-float64(elapsed)/float64(tau))
		}
		return max(r.smoothed, float64(cost))
	}
	base := time.Now()
	for _, tau := range []time.Duration{0, -time.Second, time.Millisecond, 12 * time.Second} {
		for _, elapsed := range []time.Duration{-time.Second, 0, time.Nanosecond, time.Second, time.Hour} {
			for _, smoothed := range []float64{0, 1, 41.5, 96, 65535} {
				for _, cost := range []uint16{0, 1, 42, 96, 65535} {
					for _, zero := range []bool{false, true} {
						start := routeInfo{smoothed: smoothed, smoothedAt: base}
						if zero {
							start.smoothedAt = time.Time{}
						}
						now := base.Add(elapsed)
						want := reference(start, cost, now, tau)
						got := start
						got.smooth(cost, now, tau)
						if got.smoothed != want {
							t.Fatalf("smooth(cost=%d, elapsed=%v, tau=%v, smoothed=%v, unset=%v) = %v, want %v",
								cost, elapsed, tau, smoothed, zero, got.smoothed, want)
						}
						if !got.smoothedAt.Equal(now) {
							t.Fatalf("smooth did not stamp the sample time")
						}
					}
				}
			}
		}
	}
}
