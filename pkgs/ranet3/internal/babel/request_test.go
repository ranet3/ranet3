// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package babel

import (
	"context"
	"net/netip"
	"slices"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/netstack"
)

// refreshInterval is the update interval the neighbors of the refresh tests name
const refreshInterval = 200 * time.Millisecond

// refreshDue is 2.5 of refreshInterval, when a selected route learned from an update naming it is asked for again
const refreshDue = refreshInterval * 5 / 2

// learnAt hands speaker the updatePacket from n for key at now, under router id 1, naming refreshInterval
func learnAt(speaker *Speaker, n *neighborState, key routeKey, metric uint16, now time.Time) {
	speaker.mu.Lock()
	defer speaker.mu.Unlock()
	speaker.handlePacketLocked(n, n.addr, updatePacket(1, key, metric, refreshInterval), now)
}

// sentRefresh is one Route Request a sweep sent and the neighbor it went to
type sentRefresh struct {
	to      *neighborState
	dest    netip.Addr
	request RouteRequest
}

// refreshesAt sweeps speaker at at and returns the Route Requests that sweep sends
func refreshesAt(t *testing.T, speaker *Speaker, at time.Time) []sentRefresh {
	t.Helper()
	speaker.mu.Lock()
	defer speaker.mu.Unlock()
	speaker.sweepExpiredLocked(at)
	var sent []sentRefresh
	for _, action := range speaker.refreshActions() {
		for _, tlv := range action.tlvs {
			if tlv.Type != TLVRouteRequest {
				t.Fatalf("a refresh carried a TLV of type %d", tlv.Type)
			}
			request, err := DecodeRouteRequest(tlv.Body)
			if err != nil {
				t.Fatal(err)
			}
			sent = append(sent, sentRefresh{action.neighbor, action.dest, request})
		}
	}
	return sent
}

// RFC 8966 section 3.8.2.3: "shortly before a selected route expires, a Babel node SHOULD send a unicast route request to the neighbour that advertised this route"
// the request goes 2.5 of the update's intervals after it, once, and the next update from the neighbor asks for one again
// a source-specific key's request carries its source prefix, and an IPv4 key's goes on AE 1, RFC 9229 section 2.3
func TestSelectedRouteIsAskedForBeforeItExpires(t *testing.T) {
	for _, key := range []routeKey{
		{dest: netip.MustParsePrefix("2001:db8:1::/48")},
		{dest: netip.MustParsePrefix("2001:db8:2::/48"), source: netip.MustParsePrefix("2001:db8:ff::/48")},
		{dest: netip.MustParsePrefix("192.0.2.0/24")},
	} {
		t.Run(key.dest.String(), func(t *testing.T) {
			bus := events.New()
			speaker, neighbor, _ := captureSpeaker(t, Config{}, Runtime{Events: bus})
			makeNeighborReachable(neighbor)
			learned := time.Now()
			learnAt(speaker, neighbor, key, 60, learned)
			if entry := speaker.routes.entries[key]; entry == nil || entry.selected.neighbor != neighbor {
				t.Fatal("the route was not selected, so this proves nothing")
			}
			if sent := refreshesAt(t, speaker, learned.Add(refreshDue-time.Millisecond)); len(sent) != 0 {
				t.Errorf("before 2.5 intervals the speaker sent %+v", sent)
			}
			want := RouteRequest{AE: aeFor(key.dest), Prefix: key.dest, SourcePrefix: key.source}
			sent := refreshesAt(t, speaker, learned.Add(refreshDue))
			if len(sent) != 1 || sent[0].to != neighbor || sent[0].dest != neighbor.addr || sent[0].request != want {
				t.Fatalf("at 2.5 intervals the speaker sent %+v, want %+v to the neighbor's address %s", sent, want, neighbor.addr)
			}
			if sent := refreshesAt(t, speaker, learned.Add(refreshDue+time.Millisecond)); len(sent) != 0 {
				t.Errorf("a second sweep sent %+v again for the same update", sent)
			}

			again := learned.Add(refreshDue + 2*time.Millisecond)
			learnAt(speaker, neighbor, key, 60, again)
			if sent := refreshesAt(t, speaker, again.Add(refreshDue)); len(sent) != 1 || sent[0].request != want {
				t.Errorf("2.5 intervals after the next update the speaker sent %+v, want %+v", sent, want)
			}

			var recorded []string
			for _, event := range bus.Recorded(everything, 0) {
				if event.Kind == "babel.request.sent" {
					recorded = append(recorded, event.Peer+" "+event.Attrs["route"])
				}
			}
			if wantEvents := []string{"peer " + describeRoute(key), "peer " + describeRoute(key)}; !slices.Equal(recorded, wantEvents) {
				t.Errorf("the requests were recorded as %q, want %q", recorded, wantEvents)
			}
		})
	}
}

// a route that is not selected when its refresh falls due draws no request, and is not asked for once selected later
func TestUnselectedRouteIsNotAskedFor(t *testing.T) {
	speaker, near, _ := captureSpeaker(t, Config{})
	makeNeighborReachable(near)
	far := speaker.neighbors[addReachablePeer(t, speaker, "far", 96).ID]
	makeNeighborReachable(far)
	key := routeKey{dest: netip.MustParsePrefix("2001:db8:3::/48")}
	learned := time.Now()
	learnAt(speaker, near, key, 60, learned)
	learnAt(speaker, far, key, 600, learned)
	if speaker.routes.entries[key].selected.neighbor != near {
		t.Fatal("the cheaper route was not selected, so this proves nothing")
	}
	sent := refreshesAt(t, speaker, learned.Add(refreshDue))
	if len(sent) != 1 || sent[0].to != near {
		t.Fatalf("at 2.5 intervals the speaker sent %+v, want 1 request to the selected route's neighbor", sent)
	}
	learnAt(speaker, near, key, MetricInfinity, learned.Add(refreshDue+time.Millisecond))
	if speaker.routes.entries[key].selected.neighbor != far {
		t.Fatal("the other route was not selected once the first was retracted, so this proves nothing")
	}
	if sent := refreshesAt(t, speaker, learned.Add(refreshDue+2*time.Millisecond)); len(sent) != 0 {
		t.Errorf("a route selected past its refresh drew %+v", sent)
	}
}

// a route whose refresh falls due in the pass that unselects it draws no request, here the pass an IHU from its neighbor naming the link down runs
func TestRouteUnselectedAsItsRefreshFallsDueIsNotAskedFor(t *testing.T) {
	speaker, near, _ := captureSpeaker(t, Config{})
	makeNeighborReachable(near)
	far := speaker.neighbors[addReachablePeer(t, speaker, "far", 96).ID]
	makeNeighborReachable(far)
	key := routeKey{dest: netip.MustParsePrefix("2001:db8:3:1::/64")}
	learned := time.Now()
	learnAt(speaker, near, key, 60, learned)
	learnAt(speaker, far, key, 600, learned)
	if speaker.routes.entries[key].selected.neighbor != near {
		t.Fatal("the cheaper route was not selected, so this proves nothing")
	}
	speaker.mu.Lock()
	speaker.handlePacketLocked(near, near.addr, EncodePacket([]RawTLV{EncodeIHU(IHU{RxCost: MetricInfinity, Interval: 400})}), learned.Add(refreshDue))
	selected := speaker.routes.entries[key].selected.neighbor
	speaker.mu.Unlock()
	if selected != far {
		t.Fatal("the IHU did not move the selection to the other route, so this proves nothing")
	}
	if sent := refreshesAt(t, speaker, learned.Add(refreshDue)); len(sent) != 0 {
		t.Errorf("a route unselected in the pass its refresh fell due drew %+v", sent)
	}
}

// a refresh queued for a session that is replaced before it is sent is dropped, rather than sent through a neighbor that no longer owns its peer
func TestRefreshForAReplacedSessionIsDropped(t *testing.T) {
	speaker, near, _ := captureSpeaker(t, Config{})
	makeNeighborReachable(near)
	key := routeKey{dest: netip.MustParsePrefix("2001:db8:3:2::/64")}
	learned := time.Now()
	learnAt(speaker, near, key, 60, learned)
	speaker.mu.Lock()
	speaker.sweepExpiredLocked(learned.Add(refreshDue))
	queued := len(speaker.routes.refresh)
	speaker.mu.Unlock()
	if queued != 1 {
		t.Fatalf("the sweep queued %d refreshes, want 1, so this proves nothing", queued)
	}
	speaker.AddPeer(newTestPeer(t, near.peer.ID, nil).Peer, identity.Identity{})
	speaker.mu.Lock()
	actions := speaker.refreshActions()
	speaker.mu.Unlock()
	if len(actions) != 0 {
		t.Errorf("a refresh for the replaced session went out as %+v", actions)
	}
}

// runRefreshInterval is the update interval near names to a running speaker, short enough that the route's refresh and its expiry both come before the run loop's next Hello pass, so only the refresh's own wake sends the request in time
const runRefreshInterval = time.Second

// a running speaker asks the selected route's neighbor for the route between its refresh and its expiry, near sending nothing more meanwhile
func TestRunningSpeakerAsksForASelectedRouteBeforeItExpires(t *testing.T) {
	speaker, near, captured := captureSpeaker(t, Config{})
	makeNeighborReachable(near)
	key := routeKey{dest: netip.MustParsePrefix("2001:db8:3:3::/64")}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); _ = speaker.Run(ctx) }()
	defer func() { cancel(); <-done }()
	for deadline := time.Now().Add(firstPassWait); speaker.Passes() == 0; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("the run loop made no pass in %s", firstPassWait)
		}
	}
	captured.reset()
	learned := time.Now()
	speaker.Receive(near.peer, routePacket(key.dest, 1, 60, uint16(runRefreshInterval/(10*time.Millisecond))))
	due, expires := learned.Add(refreshAfter(deadTimeout(runRefreshInterval))), learned.Add(deadTimeout(runRefreshInterval))
	want := RouteRequest{AE: aeFor(key.dest), Prefix: key.dest}
	for {
		asked := slices.Contains(routeRequestsIn(t, captured.sent()), want)
		now := time.Now()
		switch {
		case asked && now.Before(due):
			t.Fatalf("near was asked for %s %s after the update, before the refresh at %s", key.dest, now.Sub(learned), due.Sub(learned))
		case asked:
			return
		case now.After(expires):
			t.Fatalf("near was not asked for %s before the route expired %s after the update", key.dest, expires.Sub(learned))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// routeRequestsIn is every Route Request in packets, each an IPv6 packet a peer transmitted
func routeRequestsIn(t *testing.T, packets [][]byte) []RouteRequest {
	t.Helper()
	var requests []RouteRequest
	for _, raw := range packets {
		payload, err := parsePacket(raw)
		if err != nil {
			t.Fatal(err)
		}
		tlvs, err := DecodePacket(payload)
		if err != nil {
			t.Fatal(err)
		}
		for _, tlv := range tlvs {
			if tlv.Type != TLVRouteRequest {
				continue
			}
			request, err := DecodeRouteRequest(tlv.Body)
			if err != nil {
				t.Fatal(err)
			}
			requests = append(requests, request)
		}
	}
	return requests
}

// the run loop sleeps no later than the refresh a selected route is due for, when nothing else is due earlier
func TestRefreshIsADeadlineOfItsOwn(t *testing.T) {
	speaker, neighbor, _ := captureSpeaker(t, Config{})
	makeNeighborReachable(neighbor)
	key := routeKey{dest: netip.MustParsePrefix("2001:db8:4::/48")}
	learnAt(speaker, neighbor, key, 60, time.Now())
	speaker.mu.Lock()
	defer speaker.mu.Unlock()
	route := speaker.routes.route(neighbor, key)
	if route == nil || route.refreshAt.IsZero() {
		t.Fatal("the route carries no refresh, so this proves nothing")
	}
	if got := speaker.deadlineLocked(); got.After(route.refreshAt) {
		t.Errorf("the run loop sleeps until %v, past the refresh due at %v", got, route.refreshAt)
	}
}

// a's route through b is refreshed by b's answer to a's request while b's periodic updates are lost, and never expires
func TestRefreshKeepsARouteWhoseUpdatesAreLost(t *testing.T) {
	fabric := newMeshFabric(t, Config{Update: dur(refreshInterval)}, "a-b")
	dest := netip.MustParsePrefix("2001:db8:5::/48")
	key := routeKey{dest: dest}
	fabric.speakers["b"].Originate(dest)
	fabric.flush("b")
	if fabric.nextHop("a", key) != "b" {
		t.Fatal("a did not learn b's prefix")
	}
	a := fabric.speakers["a"]
	a.mu.Lock()
	route := a.routes.route(fabric.neighbor("a", "b"), key)
	refresh, expires := route.refreshAt, route.expiresAt
	a.mu.Unlock()
	time.Sleep(time.Until(refresh))
	a.mu.Lock()
	a.sweepExpiredLocked(time.Now())
	send := a.emitLocked(a.refreshActions())
	a.mu.Unlock()
	send()
	fabric.deliver()

	time.Sleep(time.Until(expires.Add(refreshInterval / 4)))
	a.mu.Lock()
	a.sweepExpiredLocked(time.Now())
	a.mu.Unlock()
	if got := fabric.nextHop("a", key); got != "b" {
		t.Errorf("past the expiry of the update a learned the route from, a reaches the prefix via %q, want b", got)
	}
}

// a satisfiable seqno request from the selected route's next hop draws nothing where no other route's neighbor can take it, which the protocol deviations page lists under section 3.8.1.2
func TestSatisfiableRequestFromTheNextHopDrawsNothingWithNoOtherRoute(t *testing.T) {
	fabric := newMeshFabric(t, Config{}, "a-b", "b-c")
	dest := netip.MustParsePrefix("2001:db8:b6::/48")
	key := routeKey{dest: dest}
	fabric.speakers["c"].Originate(dest)
	fabric.flush("c", "b")
	sel := fabric.selected("b", key)
	if sel.neighbor == nil || sel.neighbor.peer.ID != "c" {
		t.Fatal("b did not select c's prefix through c")
	}
	fabric.reset()
	fabric.inject("b", "c", EncodeSeqnoRequest(SeqnoRequest{AE: AEIPv6, Prefix: dest, Seqno: sel.seqno, HopCount: 64, RouterID: routerID("c")}))
	for _, to := range []string{"a", "c"} {
		tlvs := fabric.tlvs("b", to)
		if got := updatesFor(t, tlvs, dest); len(got) != 0 {
			t.Errorf("b answered its next hop's request with %+v to %s", got, to)
		}
		if got := seqnoRequestsFor(t, tlvs, dest); len(got) != 0 {
			t.Errorf("b forwarded its next hop's request to %s as %+v", to, got)
		}
	}
}

// RFC 8966 section 3.8.2.1 names "the router-id of the route that it has just lost" in a starvation request, and a node names each unfeasible route's own instead, which the protocol deviations page lists
// a selects origin r1 through x and holds an unfeasible route of origin r2 through y, then loses the r1 route
func TestStarvationNamesTheUnfeasibleRoutesRouterIDNotTheLostOnes(t *testing.T) {
	now := time.Now()
	key := routeKey{dest: netip.MustParsePrefix("2001:db8:b1::/48")}
	x := &neighborState{peer: &netstack.Peer{ID: "x"}}
	y := &neighborState{peer: &netstack.Peer{ID: "y"}}
	makeNeighborReachable(x)
	makeNeighborReachable(y)
	rt := newRouteTable(func(routeKey, routeSelection) {})
	r1, r2 := [8]byte{1}, [8]byte{2}
	// this node once advertised origin r2 at (1, 10), and r1 at (5, 200)
	rt.observe(key, advertisement{routerID: r2, seqno: 1, metric: 10}, "y", now)
	rt.observe(key, advertisement{routerID: r1, seqno: 5, metric: 200}, "x", now)
	rt.update(x, key, advertisement{routerID: r1, seqno: 5, metric: 100}, time.Hour, now)
	if rt.entries[key].selected.neighbor != x {
		t.Fatal("r1 through x was not selected")
	}
	rt.update(y, key, advertisement{routerID: r2, seqno: 1, metric: 20}, time.Hour, now)
	rt.takeStarved()
	rt.update(x, key, advertisement{routerID: r1, seqno: 5, metric: MetricInfinity}, time.Hour, now)
	got := rt.takeStarved()
	if len(got) != 1 || got[0].neighbor != y || got[0].routerID != r2 || got[0].seqno != 2 {
		t.Errorf("the loss drew %+v, want 1 request to y for r2's seqno 2", got)
	}
}

// RFC 8966 section 3.8.1.2 forwards a seqno request only "if the hop count is 2 or more, and the node is advertising the prefix to its neighbours", and a node with cap.transit off advertises no prefix it learns
// b, a leaf that selects c's prefix, forwards nothing to c for a request from a it cannot satisfy
func TestTransitOffForwardsNoSeqnoRequest(t *testing.T) {
	fabric := newRoutedFabric(t, Config{}, Routes{}, true, "a-b", "b-c")
	dest := netip.MustParsePrefix("2001:db8:b4::/48")
	key := routeKey{dest: dest}
	fabric.speakers["c"].Originate(dest)
	fabric.flush("c")
	if got := fabric.nextHop("b", key); got != "c" {
		t.Fatalf("b reaches the prefix via %q, want c", got)
	}
	sel := fabric.selected("b", key)
	fabric.reset()
	fabric.inject("b", "a", EncodeSeqnoRequest(SeqnoRequest{AE: AEIPv6, Prefix: dest, Seqno: sel.seqno + 1, HopCount: 64, RouterID: routerID("c")}))
	if got := seqnoRequestsFor(t, fabric.tlvs("b", "c"), dest); len(got) != 0 {
		t.Errorf("b, with transit off, forwarded %+v for a prefix it does not advertise", got)
	}
}

// with cap.transit off a node answers a route request and a satisfiable seqno request for a prefix it learned with a retraction, which the protocol deviations page lists under sections 3.7.1, 3.8.1.1 and 3.8.1.2
func TestTransitOffAnswersRequestsForALearnedPrefixWithARetraction(t *testing.T) {
	fabric := newRoutedFabric(t, Config{}, Routes{}, true, "a-b", "b-c")
	dest := netip.MustParsePrefix("2001:db8:b2::/48")
	key := routeKey{dest: dest}
	fabric.speakers["c"].Originate(dest)
	fabric.flush("c")
	if got := fabric.nextHop("b", key); got != "c" {
		t.Fatalf("b reaches the prefix via %q, want c", got)
	}
	sel := fabric.selected("b", key)
	for _, request := range []struct {
		name string
		tlv  RawTLV
	}{
		{"route request", EncodeRouteRequest(RouteRequest{AE: AEIPv6, Prefix: dest})},
		{"satisfiable seqno request", EncodeSeqnoRequest(SeqnoRequest{AE: AEIPv6, Prefix: dest, Seqno: sel.seqno, HopCount: 64, RouterID: routerID("c")})},
	} {
		fabric.reset()
		fabric.inject("b", "a", request.tlv)
		if got := updatesFor(t, fabric.tlvs("b", "a"), dest); len(got) != 1 || got[0].Metric != MetricInfinity {
			t.Errorf("b answered a %s with %+v, want 1 retraction", request.name, got)
		}
	}
}
