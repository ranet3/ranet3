// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package babel

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/netstack"
)

// offerOf is the offer node keeps from peer for key, nil for none
func (f *meshFabric) offerOf(node, peer string, key routeKey) *routeInfo {
	s := f.speakers[node]
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.routes.offers[key][f.neighbor(node, peer)]
}

// A route a neighbor offers for a key this node owns, one it announces or the
// host route of an address cap.table assigns, is kept as the neighbor's offer
// under the router-id, seqno and metric the update carries. It enters no route
// table entry, the forwarding entry stays this node's own, the route view and
// the counts name none of it, and no dump carries it: the announced key goes
// out under this node's own seqno at metric 0, and the assigned one not at all.
// An update that expires on arrival is kept as no offer, as it creates no
// route. The decoder ignores the one a neighbor can send, of interval 0, so the
// table is handed it directly.
func TestOfferForAnOwnKeyIsKeptAndNeitherSelectedNorAdvertised(t *testing.T) {
	fabric := newMeshFabric(t, Config{}, "a-b", "a-c")
	plain := routeKey{dest: netip.MustParsePrefix("2001:db8:1::/48")}
	address := netip.MustParseAddr("2001:db8:5::1")
	assigned := routeKey{dest: netip.PrefixFrom(address, address.BitLen())}
	a := fabric.speakers["a"]
	a.Originate(plain.dest)
	a.SetAssigned([]netip.Addr{address})
	for _, test := range []struct {
		key  routeKey
		want *netstack.Peer
	}{{plain, netstack.Local}, {assigned, netstack.Assigned}} {
		fabric.offer("a", "b", "x", test.key, 7, 96)
		if offer := fabric.offerOf("a", "b", test.key); offer == nil || offer.routerID != routerID("x") || offer.seqno != 7 || offer.rxMetric != 96 {
			t.Errorf("a keeps %+v of b's offer of %s, want x's at seqno 7 and metric 96", offer, describeRoute(test.key))
		}
		if _, learned := a.routes.entries[test.key]; learned {
			t.Errorf("b's offer of %s entered the route table", describeRoute(test.key))
		}
		if value, ok := entryAt(fabric.meshes["a"], test.key); !ok || value != test.want {
			t.Errorf("%s holds %s with b's offer kept, want this node's own entry", describeRoute(test.key), peerName(value))
		}
	}
	for _, route := range a.RouteDump() {
		if route.Candidates != 0 || route.Via != "" {
			t.Errorf("the route view lists %s with %d candidates via %q, want none of b's offer", route.Destination, route.Candidates, route.Via)
		}
	}
	stats := a.Stats()
	for _, neighbor := range stats.Neighbors {
		if neighbor.Routes != 0 {
			t.Errorf("a counts %d routes from %s, want none for an offer", neighbor.Routes, neighbor.Peer)
		}
	}
	if stats.Prefixes != 2 || stats.Selected != 0 {
		t.Errorf("a counts %d prefixes and %d selected, want its own 2 and none", stats.Prefixes, stats.Selected)
	}
	a.mu.Lock()
	a.routes.offer(fabric.neighbor("a", "c"), plain, advertisement{routerID: routerID("y"), seqno: 3, metric: 64}, 0, time.Now())
	a.mu.Unlock()
	if offer := fabric.offerOf("a", "c", plain); offer != nil {
		t.Errorf("a keeps %+v of c's update with no time to live, which expired on arrival", offer)
	}

	fabric.reset()
	fabric.flush("a")
	for _, peer := range []string{"b", "c"} {
		if updates := updatesFor(t, fabric.tlvs("a", peer), plain.dest); len(updates) != 1 || updates[0].Metric != 0 || updates[0].Seqno != a.originSeqno {
			t.Errorf("a's dump carried %v for %s to %s, want its own announcement alone", updates, plain.dest, peer)
		}
		if updates := updatesFor(t, fabric.tlvs("a", peer), assigned.dest); len(updates) != 0 {
			t.Errorf("a's dump carried %v for its assigned %s to %s, want nothing", updates, assigned.dest, peer)
		}
	}
}

// An offer goes with its own expiry, which a finite update sets as it sets a
// route's, with a retraction and a wildcard retraction from its neighbor, a
// second wildcard retraction after a new offer included, with a retraction or
// a finite update under this node's own router-id, and with its neighbor,
// whether the neighbor goes down or its session closes before it was ever up.
// The other neighbor's offer stays through each.
func TestOfferGoesWithItsExpiryRetractionAndNeighbor(t *testing.T) {
	key := routeKey{dest: netip.MustParsePrefix("2001:db8:1::/48")}
	for _, test := range []struct {
		name string
		// gone takes b's offer out, or fails the test where the offer had to stay until then
		gone func(t *testing.T, fabric *meshFabric, a *Speaker, b *neighborState)
	}{
		{"its expiry", func(t *testing.T, fabric *meshFabric, a *Speaker, b *neighborState) {
			a.mu.Lock()
			defer a.mu.Unlock()
			end := a.routes.offers[key][b].expiresAt
			a.sweepExpiredLocked(end.Add(-time.Nanosecond))
			if a.routes.offers[key][b] == nil {
				t.Fatal("b's offer went before its expiry")
			}
			a.sweepExpiredLocked(end)
		}},
		{"a retraction", func(t *testing.T, fabric *meshFabric, a *Speaker, b *neighborState) {
			fabric.offer("a", "b", "x", key, 7, MetricInfinity)
		}},
		{"a retraction under this node's own router-id", func(t *testing.T, fabric *meshFabric, a *Speaker, b *neighborState) {
			fabric.offer("a", "b", "a", key, 9, MetricInfinity)
		}},
		{"a finite update under this node's own router-id", func(t *testing.T, fabric *meshFabric, a *Speaker, b *neighborState) {
			fabric.offer("a", "b", "a", key, 9, 96)
		}},
		{"a wildcard retraction", func(t *testing.T, fabric *meshFabric, a *Speaker, b *neighborState) {
			fabric.inject("a", "b", wildcardRetraction())
		}},
		{"a second wildcard retraction after a new offer", func(t *testing.T, fabric *meshFabric, a *Speaker, b *neighborState) {
			fabric.inject("a", "b", wildcardRetraction())
			fabric.offer("a", "b", "x", key, 8, 96)
			if fabric.offerOf("a", "b", key) == nil {
				t.Fatal("b's new offer was not kept, so this proves nothing")
			}
			fabric.inject("a", "b", wildcardRetraction())
		}},
		{"its neighbor going down", func(t *testing.T, fabric *meshFabric, a *Speaker, b *neighborState) {
			a.mu.Lock()
			defer a.mu.Unlock()
			b.lastHelloTime = time.Now().Add(-deadTimeout(b.helloInterval) - time.Second)
			a.sweepExpiredLocked(time.Now())
			if b.alive {
				t.Fatal("b is still up, so this proves nothing")
			}
		}},
		{"its session closing before it was up", func(t *testing.T, fabric *meshFabric, a *Speaker, b *neighborState) {
			fabric.handles["a-b"].Close()
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fabric := newMeshFabric(t, Config{}, "a-b", "a-c")
			a, b := fabric.speakers["a"], fabric.neighbor("a", "b")
			// longer than any expiry this reaches, so only the step under test takes a neighbor down
			b.helloInterval, fabric.neighbor("a", "c").helloInterval = time.Hour, time.Hour
			if test.name == "its session closing before it was up" {
				b.alive = false
			}
			a.Originate(key.dest)
			fabric.offer("a", "b", "x", key, 7, 96)
			fabric.offer("a", "c", "y", key, 3, 64)
			if fabric.offerOf("a", "b", key) == nil {
				t.Fatal("b's offer was not kept, so this proves nothing")
			}
			test.gone(t, fabric, a, b)
			a.mu.Lock()
			defer a.mu.Unlock()
			if offer := a.routes.offers[key][b]; offer != nil {
				t.Errorf("b's offer %+v stayed after %s", offer, test.name)
			}
			if a.routes.offers[key][fabric.neighbor("a", "c")] == nil {
				t.Errorf("c's offer went with %s", test.name)
			}
		})
	}
}

// A prefix this node stops announcing takes the offers kept for it as its
// routes and selects among them at once, so a packet for it leaves by the
// neighbor whose offer is selected. One offered by no neighbor is held, as a
// key this node told a neighbor of is held, and so is one whose only offer
// expires at the instant of the release, which enters the route table as
// nothing.
func TestWithdrawnOwnPrefixSelectsItsOfferAtOnce(t *testing.T) {
	fabric := newMeshFabric(t, Config{}, "a-b", "a-c")
	offered := routeKey{dest: netip.MustParsePrefix("2001:db8:1::/48")}
	alone := routeKey{dest: netip.MustParsePrefix("2001:db8:2::/48")}
	expired := routeKey{dest: netip.MustParsePrefix("2001:db8:3::/48")}
	a := fabric.speakers["a"]
	a.SetOriginated([]OriginatedRoute{{Destination: offered.dest}, {Destination: alone.dest}, {Destination: expired.dest}})
	fabric.flush("a")
	fabric.offer("a", "b", "x", offered, 7, 96)
	fabric.offer("a", "c", "y", offered, 3, 200)
	fabric.offer("a", "b", "x", expired, 7, 96)
	if value, ok := entryAt(fabric.meshes["a"], offered); !ok || value != netstack.Local {
		t.Fatalf("%s holds %s with its offers kept, want this node's own entry", offered.dest, peerName(value))
	}

	a.mu.Lock()
	release := time.Now()
	a.routes.offers[expired][fabric.neighbor("a", "b")].expiresAt = release
	previous := a.originate
	a.originate = map[routeKey]struct{}{}
	a.replaceOwnLocked("originated", previous, a.originate, release)
	a.mu.Unlock()
	if value, ok := entryAt(fabric.meshes["a"], offered); !ok || value != fabric.neighbor("a", "b").peer {
		t.Errorf("%s holds %s once a stopped announcing it, want b, whose offer costs least", offered.dest, peerName(value))
	}
	if sel := fabric.selected("a", offered); sel.routerID != routerID("x") || sel.seqno != 7 {
		t.Errorf("a selected %+v for %s, want b's offer under x at seqno 7", sel, offered.dest)
	}
	for _, key := range []routeKey{alone, expired} {
		if value, ok := entryAt(fabric.meshes["a"], key); !ok || value != netstack.Unreachable {
			t.Errorf("%s holds %s once a stopped announcing it with no live offer, want it held", key.dest, peerName(value))
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, held := a.routes.held[offered]; held {
		t.Errorf("%s is held although a selected an offer for it", offered.dest)
	}
	if entry := a.routes.entries[expired]; entry != nil {
		t.Errorf("the expired offer for %s entered the route table as %d routes", expired.dest, len(entry.routes))
	}
	if len(a.routes.offers) != 0 {
		t.Errorf("a still keeps offers for %d keys it no longer owns", len(a.routes.offers))
	}
}

// A prefix this node stops announcing whose offers are all unfeasible selects
// none of them and asks each neighbor that offered one for the seqno past the
// distance its source table holds, RFC 8966 section 3.8.2.1: "A node that has
// lost all feasible routes to a given destination but still has unexpired
// unfeasible routes to that destination MUST send a seqno request".
func TestWithdrawnOwnPrefixWithOnlyUnfeasibleOffersAsksForASeqno(t *testing.T) {
	fabric := newMeshFabric(t, Config{}, "a-b", "a-c")
	key := routeKey{dest: netip.MustParsePrefix("2001:db8:1::/48")}
	a := fabric.speakers["a"]
	fabric.offer("a", "b", "x", key, 7, 10)
	fabric.flush("a")
	a.Originate(key.dest)
	fabric.offer("a", "b", "x", key, 7, 500)
	a.mu.Lock()
	a.routes.starved = nil
	a.mu.Unlock()

	a.SetOriginated(nil)
	a.mu.Lock()
	defer a.mu.Unlock()
	if source := a.routes.sources[sourceKey{route: key, routerID: routerID("x")}]; source == nil || source.seqno != 7 {
		t.Fatalf("a records %+v for x's %s, so the offer is not unfeasible and this proves nothing", source, key.dest)
	}
	if sel := a.routes.entries[key].selected; sel.neighbor != nil {
		t.Errorf("a selected %+v, an unfeasible offer", sel)
	}
	want := []starveRequest{{key: key, neighbor: fabric.neighbor("a", "b"), routerID: routerID("x"), seqno: 8}}
	if !slices.Equal(a.routes.starved, want) {
		t.Errorf("a asks %+v once it no longer announces %s, want b asked for x's seqno 8", a.routes.starved, key.dest)
	}
}

// A key this node comes to own after it learned a route for it keeps that
// route as its neighbor's offer, under the router-id, seqno and metric it was
// learned with, and takes it back as its route once it no longer owns the key.
// A route already retracted is no offer, and nor is one whose expiry has
// passed before a sweep reached it.
func TestKeyAdoptedAfterItWasLearnedKeepsTheRouteAsAnOffer(t *testing.T) {
	fabric := newMeshFabric(t, Config{}, "a-b", "a-c", "a-d")
	key := routeKey{dest: netip.MustParsePrefix("2001:db8:1::/48")}
	a := fabric.speakers["a"]
	fabric.offer("a", "b", "x", key, 7, 96)
	fabric.offer("a", "c", "y", key, 3, 64)
	fabric.offer("a", "c", "y", key, 3, MetricInfinity)
	fabric.offer("a", "d", "z", key, 5, 400)
	if got := fabric.nextHop("a", key); got != "b" {
		t.Fatalf("a reaches %s via %q, want b, so this proves nothing", key.dest, got)
	}
	a.mu.Lock()
	a.routes.entries[key].routes[fabric.neighbor("a", "d")].expiresAt = time.Now().Add(-time.Second)
	a.mu.Unlock()

	a.Originate(key.dest)
	if offer := fabric.offerOf("a", "b", key); offer == nil || offer.routerID != routerID("x") || offer.seqno != 7 || offer.rxMetric != 96 {
		t.Errorf("a keeps %+v of the route it learned from b, want x's at seqno 7 and metric 96", offer)
	}
	if offer := fabric.offerOf("a", "c", key); offer != nil {
		t.Errorf("a keeps %+v of c's retracted route", offer)
	}
	if offer := fabric.offerOf("a", "d", key); offer != nil {
		t.Errorf("a keeps %+v of d's expired route", offer)
	}
	if value, ok := entryAt(fabric.meshes["a"], key); !ok || value != netstack.Local {
		t.Errorf("%s holds %s once a announces it, want this node's own entry", key.dest, peerName(value))
	}
	a.SetOriginated(nil)
	if got := fabric.nextHop("a", key); got != "b" {
		t.Errorf("a reaches %s via %q once it no longer announces it, want b", key.dest, got)
	}
}

// The keys of the offers count with the route table's own against
// maxRouteKeys, each once however many neighbors offer it: with two places
// left, two neighbors' offers for one key take one and an offer for a second
// key the other, and a further offer and a newly learned prefix are both
// refused. The keys given back then move their offers into the route table,
// which holds the limit and no more.
func TestOffersShareTheRouteTablesLimit(t *testing.T) {
	fabric := newMeshFabric(t, Config{}, "a-b", "a-c")
	first := routeKey{dest: netip.MustParsePrefix("2001:db8:1::/48")}
	second := routeKey{dest: netip.MustParsePrefix("2001:db8:2::/48")}
	third := routeKey{dest: netip.MustParsePrefix("2001:db8:3::/48")}
	learned := routeKey{dest: netip.MustParsePrefix("2001:db8:4::/48")}
	a := fabric.speakers["a"]
	a.SetOriginated([]OriginatedRoute{{Destination: first.dest}, {Destination: second.dest}, {Destination: third.dest}})
	a.mu.Lock()
	for i := range maxRouteKeys - 2 {
		a.routes.entries[routeKey{dest: netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 0}), 24)}] = &keyEntry{routes: make(map[*neighborState]*routeInfo)}
	}
	a.mu.Unlock()

	fabric.offer("a", "b", "x", first, 1, 96)
	fabric.offer("a", "c", "y", first, 1, 96)
	fabric.offer("a", "b", "x", second, 1, 96)
	fabric.offer("a", "b", "x", third, 1, 96)
	fabric.offer("a", "b", "x", learned, 1, 96)
	a.mu.Lock()
	keptFirst := len(a.routes.offers[first])
	_, keptSecond := a.routes.offers[second]
	_, keptThird := a.routes.offers[third]
	_, learnedOne := a.routes.entries[learned]
	a.mu.Unlock()
	if keptFirst != 2 || !keptSecond || keptThird || learnedOne {
		t.Fatalf("with two places left a keeps %d offers for the first key, one for the second %t and for the third %t, and learns a new prefix %t, want both of the first's and the second's alone",
			keptFirst, keptSecond, keptThird, learnedOne)
	}
	a.SetOriginated(nil)
	a.mu.Lock()
	defer a.mu.Unlock()
	if got := len(a.routes.entries); got != maxRouteKeys || a.routes.entries[first] == nil || a.routes.entries[second] == nil {
		t.Errorf("the route table holds %d keys once the keys are given back, want its limit %d with the first and second among them", got, maxRouteKeys)
	}
}

// The router-id read for a key this node owns is that of the offer selection
// weighs first, the one of least cost, however the offers are walked, and an
// offer past its expiry is read as none before any sweep takes it out. Only
// the key of the destination with no source prefix is read, not one covering
// it or one from a source.
func TestOfferedOriginIsTheOfferSelectionWeighsFirst(t *testing.T) {
	fabric := newMeshFabric(t, Config{}, "a-b", "a-c")
	key := routeKey{dest: netip.MustParsePrefix("2001:db8:1::/48")}
	covering := routeKey{dest: netip.MustParsePrefix("2001:db8::/32")}
	sourced := routeKey{source: netip.MustParsePrefix("2001:db8:a::/48"), dest: key.dest}
	a := fabric.speakers["a"]
	a.SetOriginated([]OriginatedRoute{{Destination: key.dest}, {Destination: covering.dest}, {Destination: sourced.dest, Source: sourced.source}})
	fabric.offer("a", "b", "z", covering, 1, 10)
	fabric.offer("a", "c", "w", sourced, 1, 10)
	if fabric.offerOf("a", "b", covering) == nil || fabric.offerOf("a", "c", sourced) == nil {
		t.Fatal("a keeps no offer for the covering key or the one from a source, so this proves nothing")
	}
	if origin, ok := a.OfferedOrigin(key.dest); ok {
		t.Fatalf("a reads %x for a key no neighbor offers", origin)
	}
	fabric.offer("a", "b", "x", key, 7, 200)
	fabric.offer("a", "c", "y", key, 3, 10)
	for range 20 {
		if origin, ok := a.OfferedOrigin(key.dest); !ok || origin != routerID("y") {
			t.Fatalf("a reads %x, %t for %s, want y, whose offer costs least", origin, ok, key.dest)
		}
	}
	a.mu.Lock()
	a.routes.offers[key][fabric.neighbor("a", "c")].expiresAt = time.Now().Add(-time.Second)
	a.mu.Unlock()
	if origin, ok := a.OfferedOrigin(key.dest); !ok || origin != routerID("x") {
		t.Errorf("a reads %x, %t once y's offer expired, want x", origin, ok)
	}
	a.mu.Lock()
	a.routes.offers[key][fabric.neighbor("a", "b")].expiresAt = time.Now().Add(-time.Second)
	a.mu.Unlock()
	if origin, ok := a.OfferedOrigin(key.dest); ok {
		t.Errorf("a reads %x once every offer expired, want none", origin)
	}
}

// A neighbor's update under this node's own router-id, a retraction or a
// finite one, retracts the route the neighbor last advertised for a key this
// node does not own, which keeps the router-id and seqno it was learned with
// and leaves selection to the other neighbor. So does a retraction under
// another router-id, RFC 8966 section 4.6.9 reading none.
func TestUpdateUnderThisNodesRouterIDRetractsTheLearnedRoute(t *testing.T) {
	key := routeKey{dest: netip.MustParsePrefix("2001:db8:1::/48")}
	for _, test := range []struct {
		name   string
		origin string
		metric uint16
	}{
		{"a retraction under this node's router-id", "a", MetricInfinity},
		{"a finite update under this node's router-id", "a", 96},
		{"a retraction under another router-id", "z", MetricInfinity},
	} {
		t.Run(test.name, func(t *testing.T) {
			fabric := newMeshFabric(t, Config{}, "a-b", "a-c")
			a, b := fabric.speakers["a"], fabric.neighbor("a", "b")
			fabric.offer("a", "b", "x", key, 7, 96)
			fabric.offer("a", "c", "y", key, 3, 200)
			if got := fabric.nextHop("a", key); got != "b" {
				t.Fatalf("a reaches %s via %q, want b, so this proves nothing", key.dest, got)
			}
			fabric.offer("a", "b", test.origin, key, 9, test.metric)
			a.mu.Lock()
			route := a.routes.route(b, key)
			a.mu.Unlock()
			if route == nil || route.rxMetric != MetricInfinity || route.routerID != routerID("x") || route.seqno != 7 {
				t.Errorf("a keeps %+v of b's route after %s, want x's at seqno 7 retracted", route, test.name)
			}
			if got := fabric.nextHop("a", key); got != "c" {
				t.Errorf("a reaches %s via %q after %s, want c", key.dest, got, test.name)
			}
		})
	}
}

// A neighbor that comes to route this node's own prefix back here retracts it
// to this node under this node's router-id, as split horizon does, which takes
// the neighbor's offer out. Giving the prefix back then selects no route
// through that neighbor, whose route leads straight back.
func TestOfferOfTheNeighborThatRoutesThePrefixBackIsNotSelected(t *testing.T) {
	fabric := newMeshFabric(t, Config{}, "a-b", "b-c")
	a := fabric.speakers["a"]
	key := routeKey{dest: netip.MustParsePrefix("2001:db8:1::/48")}
	fabric.cost("b", "c", 500)
	fabric.speakers["c"].Originate(key.dest)
	fabric.flush("c", "b")
	if got := fabric.nextHop("a", key); got != "b" {
		t.Fatalf("a reaches %s via %q, want b, so this proves nothing", key.dest, got)
	}
	a.Originate(key.dest)
	fabric.flush("a")
	fabric.trigger("b")
	fabric.flush("b")
	if got := fabric.nextHop("b", key); got != "a" {
		t.Fatalf("b reaches %s via %q, want a, so this proves nothing", key.dest, got)
	}
	if offer := fabric.offerOf("a", "b", key); offer != nil {
		t.Errorf("a keeps b's offer %+v though b routes %s via a", offer, key.dest)
	}
	a.SetOriginated(nil)
	if fabric.nextHop("a", key) == "b" && fabric.nextHop("b", key) == "a" {
		t.Errorf("a and b route %s through each other once a gives it back", key.dest)
	}
}

// When the origin a neighbor offered withdraws and the neighbor turns to this
// node's own route, its retraction under this node's router-id takes its
// offer out, so giving the prefix back selects the other neighbor's live
// offer at once, and the prefix neither loops between this node and the first
// neighbor nor goes to one that holds no route for it, before the next dumps
// and after them.
func TestOfferOfANeighborThatLostItsOriginIsNotSelected(t *testing.T) {
	fabric := newMeshFabric(t, Config{}, "a-b", "b-x", "a-c")
	key := routeKey{dest: netip.MustParsePrefix("2001:db8:1::/48")}
	address := netip.MustParseAddr("2001:db8:1::1")
	a, x := fabric.speakers["a"], fabric.speakers["x"]
	x.Originate(key.dest)
	fabric.flush("x", "b")
	if got := fabric.nextHop("a", key); got != "b" {
		t.Fatalf("a reaches %s via %q, want b, so this proves nothing", key.dest, got)
	}
	a.Originate(key.dest)
	fabric.offer("a", "c", "y", key, 1, 500)
	fabric.flush("a")
	x.SetOriginated(nil)
	fabric.flush("x", "b")
	if got := fabric.nextHop("b", key); got != "a" {
		t.Fatalf("b reaches %s via %q once x withdrew it, want a, so this proves nothing", key.dest, got)
	}
	if offer := fabric.offerOf("a", "b", key); offer != nil {
		t.Errorf("a keeps b's offer %+v though b retracted %s under a's router-id", offer, key.dest)
	}
	a.SetOriginated(nil)
	if got := fabric.forwards("a", address); got != "c" {
		t.Errorf("a forwards %s via %q once it gives %s back, want c, whose offer is live", address, got, key.dest)
	}
	fabric.flush("a", "b")
	if got := fabric.forwards("a", address); got != "c" {
		t.Errorf("a forwards %s via %q after a and b dump, want c", address, got)
	}
}

// A key from a source to a host address of this node's, given back while the
// address stays its own, assigned by cap.table or originated as a /128 with no
// source, drops its offers rather than taking them as its routes, as receive
// drops what a neighbor sends for it, whether the neighbor offered it while the
// key was owned or the node had learned it before. No packet from the source
// to this node's own address leaves by the neighbor, and the node records no
// selection of the neighbor's route for the key. Where the /128 is originated,
// the change that gives the key back takes the address back in the same call,
// so that record is the only trace a selection would leave.
func TestReleasedHostKeyFromASourceDropsItsOffersWhileTheAddressStaysItsOwn(t *testing.T) {
	address := netip.MustParseAddr("2001:db8:5::1")
	host := netip.PrefixFrom(address, address.BitLen())
	key := routeKey{source: netip.MustParsePrefix("2001:db8:a::/48"), dest: host}
	sourced := []OriginatedRoute{{Destination: host, Source: key.source}}
	for _, assigned := range []bool{true, false} {
		// kept holds the keys the node still originates once it gives the key back
		kept := []OriginatedRoute{{Destination: host}}
		if assigned {
			kept = nil
		}
		for _, learnedFirst := range []bool{false, true} {
			fabric := newMeshFabric(t, Config{}, "a-b")
			a := fabric.speakers["a"]
			if learnedFirst {
				fabric.offer("a", "b", "x", key, 7, 96)
				a.SetOriginated(sourced)
			}
			if assigned {
				a.SetAssigned([]netip.Addr{address})
			}
			a.SetOriginated(append(slices.Clone(sourced), kept...))
			if !learnedFirst {
				fabric.offer("a", "b", "x", key, 7, 96)
			}
			if fabric.offerOf("a", "b", key) == nil {
				t.Fatalf("assigned %t, learned first %t: a keeps no offer from b, so this proves nothing", assigned, learnedFirst)
			}
			bus := events.New()
			a.mu.Lock()
			a.events = bus
			a.mu.Unlock()
			a.SetOriginated(kept)
			for _, event := range bus.Recorded(everything, 0) {
				if event.Kind == "babel.route.selected" && event.Attrs["route"] == describeRoute(key) {
					t.Errorf("assigned %t, learned first %t: a selected %s via %s once given back", assigned, learnedFirst, describeRoute(key), event.Peer)
				}
			}
			if value, ok := entryAt(fabric.meshes["a"], key); ok && value == fabric.neighbor("a", "b").peer {
				t.Errorf("assigned %t, learned first %t: %s holds b once given back, though a still holds %s", assigned, learnedFirst, describeRoute(key), address)
			}
			if offer := fabric.offerOf("a", "b", key); offer != nil {
				t.Errorf("assigned %t, learned first %t: a keeps b's offer %+v for a key it no longer owns", assigned, learnedFirst, offer)
			}
		}
	}
}
