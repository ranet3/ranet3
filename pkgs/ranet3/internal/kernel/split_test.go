// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package kernel

import (
	"go/ast"
	"go/constant"
	"go/parser"
	"go/token"
	"go/types"
	"log/slog"
	"math"
	"net/netip"
	"slices"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/netstack"
)

// holdRoute is the hold a pass wants at destination, and meshRoute the live
// route, each with the metric the pass gives it
func holdRoute(destination string) Route {
	return Route{Destination: prefix(destination), Metric: holdMetric, Unreachable: true}
}

func meshRoute(destination string) Route {
	r := Route{Destination: prefix(destination)}
	if r.Destination.Addr().Is6() {
		r.Metric = defaultIPv6Metric
	}
	return r
}

// fromSource is r from source
func fromSource(r Route, source string) Route {
	r.Source = prefix(source)
	return r
}

// pieceRoute is hold's piece at destination, which keeps its fields and is
// scoped
func pieceRoute(hold Route, destination string) Route {
	hold.Destination, hold.Scoped = prefix(destination), true
	return hold
}

// scopesHolds scopes what darwin's scopeRoute scopes of these tests' routes:
// a hold, a route from a source, and one already scoped
func scopesHolds(r Route) bool { return r.Scoped || r.Unreachable || r.Source.IsValid() }

// cutAs is cutHolds of routes, the mesh's own list, under budget, on a tun
// holding holdCutTun's addresses
func cutAs(routes []Route, budget int) ([]Route, holdCut) {
	return cutHolds(routes, routes, scopesHolds, holdCutTun, nil, budget)
}

// A hold the platform scopes is cut around each unscoped live route inside it
// that is no host route, its pieces following the routes it leaves. A hold
// with no such route inside it is written as handed in, also beside a hold
// that is cut, as is a hold the platform skips, from a source holding no
// address of the tun's, and a hold at the destination of another scoped route
// the platform writes, since the platform keeps one scoped route at a
// destination. A route the platform skips at a hold's destination leaves the
// hold alone at its key, so the hold is cut. A scoped route the platform
// writes lies under no piece, also with an unscoped live route inside it, and
// one it skips lies under one. The 64th bit of an address is read and set
// where a live route sets it.
func TestHoldIsCutAroundTheLiveRoutesInsideIt(t *testing.T) {
	wide, inner, at48 := holdRoute("2001:db8::/32"), holdRoute("2001:db8::/56"), holdRoute("2001:db8::/48")
	v4, v6 := holdRoute("198.51.100.0/24"), holdRoute("3fff::/32")
	scoped := fromSource(meshRoute("2001:db8::/34"), "3fff:c::/48")
	ours, foreign := fromSource(meshRoute("2001:db8:8000::/33"), "3fff:c::/48"), fromSource(meshRoute("2001:db8:8000::/33"), "2001:db8:5::/48")
	for _, test := range []struct {
		name   string
		routes []Route
		want   []Route
		pieces int
	}{
		{
			"one live route inside", []Route{wide, meshRoute("2001:db8::/34")},
			[]Route{meshRoute("2001:db8::/34"), pieceRoute(wide, "2001:db8:4000::/34"), pieceRoute(wide, "2001:db8:8000::/33")}, 2,
		},
		{
			"two live routes that are siblings", []Route{wide, meshRoute("2001:db8::/34"), meshRoute("2001:db8:4000::/34")},
			[]Route{meshRoute("2001:db8::/34"), meshRoute("2001:db8:4000::/34"), pieceRoute(wide, "2001:db8:8000::/33")}, 1,
		},
		{"a live route at the hold's own prefix", []Route{wide, meshRoute("2001:db8::/32")}, []Route{wide, meshRoute("2001:db8::/32")}, 0},
		{"a host route inside", []Route{wide, meshRoute("2001:db8::1/128")}, []Route{wide, meshRoute("2001:db8::1/128")}, 0},
		{"a scoped live route inside", []Route{wide, scoped}, []Route{wide, scoped}, 0},
		{
			"a hold of a scoped live route beside a hold cut", []Route{wide, scoped, v6, meshRoute("3fff::/34")},
			[]Route{wide, scoped, meshRoute("3fff::/34"), pieceRoute(v6, "3fff:0:4000::/34"), pieceRoute(v6, "3fff:0:8000::/33")}, 2,
		},
		{
			"a hold at the destination of another scoped route", []Route{wide, fromSource(wide, "3fff:c::/48"), meshRoute("2001:db8::/34")},
			[]Route{wide, fromSource(wide, "3fff:c::/48"), meshRoute("2001:db8::/34")}, 0,
		},
		{
			"a route the platform skips at the hold's destination",
			[]Route{wide, fromSource(meshRoute("2001:db8::/32"), "2001:db8:5::/48"), meshRoute("2001:db8::/34")},
			[]Route{fromSource(meshRoute("2001:db8::/32"), "2001:db8:5::/48"), meshRoute("2001:db8::/34"), pieceRoute(wide, "2001:db8:4000::/34"), pieceRoute(wide, "2001:db8:8000::/33")}, 2,
		},
		{
			"a hold the platform skips", []Route{fromSource(wide, "2001:db8:5::/48"), meshRoute("2001:db8::/34")},
			[]Route{fromSource(wide, "2001:db8:5::/48"), meshRoute("2001:db8::/34")}, 0,
		},
		{
			"a scoped live route the platform writes beside an unscoped one", []Route{wide, meshRoute("2001:db8::/34"), ours},
			[]Route{meshRoute("2001:db8::/34"), ours, pieceRoute(wide, "2001:db8:4000::/34")}, 1,
		},
		{
			"an unscoped live route inside a scoped one", []Route{wide, ours, meshRoute("2001:db8:8000::/40")},
			[]Route{ours, meshRoute("2001:db8:8000::/40"), pieceRoute(wide, "2001:db8::/33")}, 1,
		},
		{
			"a live route the platform skips beside an unscoped one", []Route{wide, meshRoute("2001:db8::/34"), foreign},
			[]Route{meshRoute("2001:db8::/34"), foreign, pieceRoute(wide, "2001:db8:4000::/34"), pieceRoute(wide, "2001:db8:8000::/33")}, 2,
		},
		{
			"a hold inside a live route around another", []Route{meshRoute("2001:db8::/48"), inner, meshRoute("2001:db8::/64")},
			[]Route{
				meshRoute("2001:db8::/48"), meshRoute("2001:db8::/64"),
				pieceRoute(inner, "2001:db8:0:1::/64"), pieceRoute(inner, "2001:db8:0:2::/63"), pieceRoute(inner, "2001:db8:0:4::/62"), pieceRoute(inner, "2001:db8:0:8::/61"),
				pieceRoute(inner, "2001:db8:0:10::/60"), pieceRoute(inner, "2001:db8:0:20::/59"), pieceRoute(inner, "2001:db8:0:40::/58"), pieceRoute(inner, "2001:db8:0:80::/57"),
			}, 8,
		},
		{
			"a live route at an address with its 64th bit set", []Route{at48, meshRoute("2001:db8:0:1::/64")},
			[]Route{
				meshRoute("2001:db8:0:1::/64"),
				pieceRoute(at48, "2001:db8::/64"), pieceRoute(at48, "2001:db8:0:2::/63"), pieceRoute(at48, "2001:db8:0:4::/62"), pieceRoute(at48, "2001:db8:0:8::/61"),
				pieceRoute(at48, "2001:db8:0:10::/60"), pieceRoute(at48, "2001:db8:0:20::/59"), pieceRoute(at48, "2001:db8:0:40::/58"), pieceRoute(at48, "2001:db8:0:80::/57"),
				pieceRoute(at48, "2001:db8:0:100::/56"), pieceRoute(at48, "2001:db8:0:200::/55"), pieceRoute(at48, "2001:db8:0:400::/54"), pieceRoute(at48, "2001:db8:0:800::/53"),
				pieceRoute(at48, "2001:db8:0:1000::/52"), pieceRoute(at48, "2001:db8:0:2000::/51"), pieceRoute(at48, "2001:db8:0:4000::/50"), pieceRoute(at48, "2001:db8:0:8000::/49"),
			}, 16,
		},
		{
			"IPv4 beside IPv6", []Route{wide, meshRoute("2001:db8::/34"), v4, meshRoute("198.51.100.0/26")},
			[]Route{
				meshRoute("2001:db8::/34"), meshRoute("198.51.100.0/26"),
				pieceRoute(wide, "2001:db8:4000::/34"), pieceRoute(wide, "2001:db8:8000::/33"),
				pieceRoute(v4, "198.51.100.64/26"), pieceRoute(v4, "198.51.100.128/25"),
			}, 4,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, made := cutAs(test.routes, holdPieceBudget)
			if !slices.Equal(got, test.want) || made != (holdCut{pieces: test.pieces}) {
				t.Errorf("the cut writes %v and makes %+v, want %v and %d pieces", got, made, test.want, test.pieces)
			}
		})
	}
}

// A hold whose pieces fit in what the budget has left is cut, one with a
// piece more goes in whole, and a later hold whose pieces fit is cut after an
// earlier one that did not fit. A hold handed in twice is counted once. IPv6
// holds go first and IPv4 holds take what is left, each family in the order
// the diff lists routes in, whatever order the pass hands them in, so a budget
// cuts the same holds in every pass and on every node. A hold inside a cut
// hold counts the pieces it shares with it again, and a hold inside a hold
// left whole is cut on its own, the whole hold still over its live routes.
func TestHoldIsCutWholeWithinTheBudgetOrLeftWhole(t *testing.T) {
	wide, later := holdRoute("2001:db8::/32"), holdRoute("3fff::/20")
	inner, v4 := holdRoute("2001:db8::/34"), holdRoute("198.51.100.0/24")
	one := []Route{wide, meshRoute("2001:db8::/40")}
	two := []Route{wide, meshRoute("2001:db8::/40"), later, meshRoute("3fff::/22")}
	nested := []Route{wide, inner, meshRoute("2001:db8::/40")}
	widePieces := []Route{
		pieceRoute(wide, "2001:db8:100::/40"), pieceRoute(wide, "2001:db8:200::/39"), pieceRoute(wide, "2001:db8:400::/38"), pieceRoute(wide, "2001:db8:800::/37"),
		pieceRoute(wide, "2001:db8:1000::/36"), pieceRoute(wide, "2001:db8:2000::/35"), pieceRoute(wide, "2001:db8:4000::/34"), pieceRoute(wide, "2001:db8:8000::/33"),
	}
	for _, test := range []struct {
		name   string
		routes []Route
		budget int
		want   []Route
		made   holdCut
	}{
		{"pieces as many as are left", one, 8, append([]Route{meshRoute("2001:db8::/40")}, widePieces...), holdCut{pieces: 8}},
		{"a piece more than are left", one, 7, one, holdCut{whole: 1}},
		{
			"a later hold that fits after one that did not", two, 7,
			[]Route{wide, meshRoute("2001:db8::/40"), meshRoute("3fff::/22"), pieceRoute(later, "3fff:400::/22"), pieceRoute(later, "3fff:800::/21")},
			holdCut{pieces: 2, whole: 1},
		},
		{
			"a hold handed in twice, counted once", []Route{wide, meshRoute("2001:db8::/34"), wide, later, meshRoute("3fff::/22")}, 4,
			[]Route{
				meshRoute("2001:db8::/34"), meshRoute("3fff::/22"),
				pieceRoute(wide, "2001:db8:4000::/34"), pieceRoute(wide, "2001:db8:8000::/33"), pieceRoute(later, "3fff:400::/22"), pieceRoute(later, "3fff:800::/21"),
			},
			holdCut{pieces: 4},
		},
		{
			"the lower address first", []Route{later, meshRoute("3fff::/22"), wide, meshRoute("2001:db8::/34")}, 2,
			[]Route{later, meshRoute("3fff::/22"), meshRoute("2001:db8::/34"), pieceRoute(wide, "2001:db8:4000::/34"), pieceRoute(wide, "2001:db8:8000::/33")},
			holdCut{pieces: 2, whole: 1},
		},
		{
			"IPv6 before IPv4", []Route{v4, meshRoute("198.51.100.0/26"), wide, meshRoute("2001:db8::/34")}, 2,
			[]Route{v4, meshRoute("198.51.100.0/26"), meshRoute("2001:db8::/34"), pieceRoute(wide, "2001:db8:4000::/34"), pieceRoute(wide, "2001:db8:8000::/33")},
			holdCut{pieces: 2, whole: 1},
		},
		{"a hold inside a cut hold, counted again past what is left", nested, 8, append([]Route{inner, meshRoute("2001:db8::/40")}, widePieces...), holdCut{pieces: 8, whole: 1}},
		{"a hold inside a cut hold, counted again within it", nested, 14, append([]Route{meshRoute("2001:db8::/40")}, widePieces...), holdCut{pieces: 8}},
		{
			"a hold inside a hold left whole", nested, 7,
			[]Route{
				wide, meshRoute("2001:db8::/40"),
				pieceRoute(inner, "2001:db8:100::/40"), pieceRoute(inner, "2001:db8:200::/39"), pieceRoute(inner, "2001:db8:400::/38"),
				pieceRoute(inner, "2001:db8:800::/37"), pieceRoute(inner, "2001:db8:1000::/36"), pieceRoute(inner, "2001:db8:2000::/35"),
			},
			holdCut{pieces: 6, whole: 1},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, made := cutAs(test.routes, test.budget)
			if !slices.Equal(got, test.want) || made != test.made {
				t.Errorf("under a budget of %d the cut writes %v and makes %+v, want %v and %+v", test.budget, got, made, test.want, test.made)
			}
		})
	}
}

// The parts the endpoint cut leaves of a route shorter than a hold, some of
// them inside the hold, are no reason to cut it, so its addresses outside
// every longer route of the mesh's stay held
func TestHoldIsNotCutAroundPartsOfAShorterRoute(t *testing.T) {
	hosts := hostTable{mesh: 9, routes: []hostRoute{{destination: prefix("::/0"), index: 2}, {destination: prefix("2001:db8::/36"), index: 2}}}
	hold := holdRoute("2001:db8::/48")
	table := []Route{meshRoute("2001:db8::/40"), hold}
	parts, _ := cutHoles(table, scopesHolds, []netip.Addr{netip.MustParseAddr("2001:db8::5")}, hosts, nil)
	if !slices.ContainsFunc(parts, func(r Route) bool {
		return !r.Unreachable && hold.Destination.Bits() < r.Destination.Bits() && hold.Destination.Contains(r.Destination.Addr())
	}) {
		t.Fatalf("the endpoint cut leaves %v, no part inside %s", parts, hold.Destination)
	}
	got, made := cutHolds(parts, table, scopesHolds, holdCutTun, nil, holdPieceBudget)
	if !slices.Equal(got, parts) || made != (holdCut{}) {
		t.Errorf("the cut writes %v and makes %+v around the parts of %s, want the parts and the hold as handed in", got, made, table[0].Destination)
	}
}

// Whatever is left, the count of a hold's pieces stops at the run of its
// addresses that takes it past what is left, a run adding at most a family's
// length, here around live /127s, the first of each even /34 of a /20 hold and
// the last of each odd one, so that a run before a live route and one after
// it can each add 93 pieces. The walk of the runs stops at the first its
// caller refuses. Around a full table of such routes the hold goes in whole.
func TestHoldCountStopsAtTheRunPastWhatIsLeft(t *testing.T) {
	hold := holdRoute("3fff::/20")
	routes := []Route{hold}
	var live []liveRoute
	for i := range uint64(meshRouteKeys - 1) {
		slot := benchPrefix(hold.Destination, i, 34)
		at := slot.Addr()
		if i%2 == 1 {
			at = lastAddress(slot).Prev()
		}
		routes = append(routes, Route{Destination: netip.PrefixFrom(at, 127), Metric: defaultIPv6Metric})
		live = append(live, liveRoute{destination: netip.PrefixFrom(at, 127), first: wordOf(at)})
	}
	some := live[:256]
	all, _ := holdPieces(hold.Destination, some, math.MaxInt)
	for left := range all {
		if n, fits := holdPieces(hold.Destination, some, left); fits || n <= left || n-left > hold.Destination.Addr().BitLen() {
			t.Fatalf("with %d left the count of %d pieces stops at %d, fitting %v, want it past what is left by at most %d", left, all, n, fits, hold.Destination.Addr().BitLen())
		}
	}
	runs := 0
	holdGaps(hold.Destination, some, func(liveRoute, int, bool) bool {
		runs++
		return runs < 3
	})
	if runs != 3 {
		t.Errorf("the walk takes %d runs past the one its caller refused, want none", runs-3)
	}
	if got, made := cutAs(routes, holdPieceBudget); !slices.Equal(got, routes) || made != (holdCut{whole: 1}) {
		t.Errorf("the cut makes %+v of the hold around a full table, want it whole and the routes as handed in", made)
	}
}

// On linux, which scopes no route, a hold around a live route goes in whole,
// as the pass wrote it before the cut, the pass gives no budget of pieces, and
// its event carries neither count a pass records on macOS
func TestLinuxWritesAHoldAroundALiveRouteWhole(t *testing.T) {
	bus := events.New()
	reconciler, table, fake := harness(t, Table{}, Runtime{Events: bus})
	table.Set(netip.Prefix{}, prefix("2001:db8::/32"), netstack.Unreachable)
	table.Set(netip.Prefix{}, prefix("2001:db8::/34"), nil)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	var got []Route
	for _, r := range fake.snapshot() {
		if prefix("2001:db8::/32").Overlaps(r.Destination) {
			got = append(got, r)
		}
	}
	slices.SortFunc(got, compareRoutes)
	want := []Route{holdRoute("2001:db8::/32"), meshRoute("2001:db8::/34")}
	if stats := reconciler.Stats(); !slices.Equal(got, want) || stats.HoldPieces != 0 || stats.HoldsWhole != 0 || stats.HoldPieceBudget != 0 {
		t.Errorf("the kernel holds %v and the pass counts %d pieces and %d holds whole past a budget of %d, want %v and none", got, stats.HoldPieces, stats.HoldsWhole, stats.HoldPieceBudget, want)
	}
	recorded := bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "kernel.pass" }, 0)
	if len(recorded) != 1 {
		t.Fatalf("the pass recorded %+v, want one event", recorded)
	}
	for _, name := range []string{"hold_pieces", "holds_whole"} {
		if value, found := recorded[0].Attrs[name]; found {
			t.Errorf("the pass's event carries %s=%s, which only a pass on macOS records", name, value)
		}
	}
}

// insideOf is the routes of fake's at or inside destination, and whether each
// address of it is held once by a piece, scoped, or by an unscoped live route
// longer than it, outermost, or by the hold alone with no route inside, so no
// live route lies under a piece and no address of the hold is held by neither
func insideOf(fake *fakeKernel, hold Route) ([]Route, bool) {
	var routes, live, pieces []Route
	whole := false
	for _, r := range fake.snapshot() {
		switch {
		case !hold.Destination.Overlaps(r.Destination) || r.Destination.Bits() < hold.Destination.Bits():
			continue
		case r.Destination == hold.Destination:
			whole = r.Unreachable
		case r.Unreachable:
			pieces = append(pieces, r)
		default:
			live = append(live, r)
		}
		routes = append(routes, r)
	}
	slices.SortFunc(routes, compareRoutes)
	if whole {
		return routes, len(pieces) == 0 && len(live) == 0
	}
	var held []netip.Prefix
	for _, piece := range pieces {
		held = append(held, piece.Destination)
	}
	return routes, tiles(hold.Destination, held, outermostOf(live))
}

// On a platform that scopes its holds, as darwin's does, each pass of a hold
// whose live routes inside it come and go ends with every address of the hold
// held by a piece or by a live route and not both, or by the hold where no
// live route is inside it, and the pass counts the pieces in place of it
func TestNoPassEndsWithALiveRouteUnderAPieceOrAnAddressOfTheHoldUnheld(t *testing.T) {
	reconciler, table, k := coveredHarness(t, Table{}, Runtime{}, coverAddresses...)
	hold := holdRoute("2001:db8::/32")
	table.Set(netip.Prefix{}, hold.Destination, netstack.Unreachable)
	for _, step := range []struct {
		name   string
		set    string
		remove string
		pieces int
	}{
		{name: "the hold alone"},
		{name: "a live route inside", set: "2001:db8::/34", pieces: 2},
		{name: "a second one", set: "2001:db8:c000::/34", pieces: 2},
		{name: "a third inside a piece", set: "2001:db8:4000::/48", pieces: 15},
		{name: "the first gone", remove: "2001:db8::/34", pieces: 16},
		{name: "the second gone", remove: "2001:db8:c000::/34", pieces: 16},
		{name: "the hold alone again", remove: "2001:db8:4000::/48"},
	} {
		if step.set != "" {
			table.Set(netip.Prefix{}, prefix(step.set), nil)
		}
		if step.remove != "" {
			table.Remove(netip.Prefix{}, prefix(step.remove))
		}
		if err := reconciler.reconcile(); err != nil {
			t.Fatal(err)
		}
		routes, ok := insideOf(k.fakeKernel, hold)
		if stats := reconciler.Stats(); !ok || stats.HoldPieces != step.pieces || stats.HoldsWhole != 0 {
			t.Errorf("after %s the kernel holds %v at or inside %s and the pass counts %d pieces and %d holds whole, want each address held once and %d pieces",
				step.name, routes, hold.Destination, stats.HoldPieces, stats.HoldsWhole, step.pieces)
		}
	}
}

// One live route arriving in a hold at a spent budget moves the budget from a
// hold of nearly all of it, left whole, to as many holds of one piece each,
// cut, and back as it leaves, and each pass deletes no more than 8,192 pieces
// and holds beside the holds around the route, and adds no more than as many,
// the route itself aside
func TestOneRouteMovesAtMostTwiceTheBudgetEachWay(t *testing.T) {
	// The first hold, at 2001:db8::, takes a piece for each bit from its length
	// to its live /127 and lies apart from big and small at a /48 or longer, so
	// it may take 127-48 pieces at most, and big takes the rest of the budget.
	// big, a /48 around k live /64s at its even slots, takes a piece between
	// each two and at most 16 after the last, k-1 at least and k+15 at most, so
	// k counts up from below to the first at which big leaves the first hold
	// that many or fewer, one past that many at the latest.
	const firstMost = 127 - 48
	big := prefix("2001:db8:1::/48")
	var bigLive []Route
	pieces := 0
	for k := uint64(holdPieceBudget - firstMost - 16); pieces < holdPieceBudget-firstMost; k++ {
		if k > holdPieceBudget-firstMost+1 {
			t.Fatalf("the cut makes %d pieces of %s around %d live /64s, want at least %d", pieces, big, k-1, k-2)
		}
		bigLive = bigLive[:0]
		for i := range k {
			bigLive = append(bigLive, Route{Destination: benchPrefix(big, 2*i, 64), Metric: defaultIPv6Metric})
		}
		_, made := cutAs(append([]Route{{Destination: big, Metric: holdMetric, Unreachable: true}}, bigLive...), math.MaxInt)
		pieces = made.pieces
	}
	first := netip.PrefixFrom(prefix("2001:db8::/32").Addr(), 127-(holdPieceBudget-pieces))
	moved := netip.PrefixFrom(benchPrefix(first, 1, first.Bits()+1).Addr(), first.Bits()+3)
	small := prefix("2001:db8:2::/48")
	reconciler, table, k := coveredHarness(t, Table{}, Runtime{}, coverAddresses...)
	table.Set(netip.Prefix{}, first, netstack.Unreachable)
	table.Set(netip.Prefix{}, netip.PrefixFrom(first.Addr(), 127), nil)
	table.Set(netip.Prefix{}, big, netstack.Unreachable)
	for _, r := range bigLive {
		table.Set(netip.Prefix{}, r.Destination, nil)
	}
	for j := range uint64(pieces - 1) {
		table.Set(netip.Prefix{}, benchPrefix(small, j, 63), netstack.Unreachable)
		table.Set(netip.Prefix{}, benchPrefix(small, 2*j, 64), nil)
	}
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if whole := reconciler.Stats().HoldsWhole; whole != pieces-1 {
		t.Fatalf("the first pass left %d holds whole, want %d", whole, pieces-1)
	}
	// one hold, first, holds the route that moved
	most := 8192 + 1
	for _, step := range []struct {
		arrives               bool
		whole                 int
		moreAdds, moreDeletes int
		verb                  string
	}{{arrives: true, whole: 1, moreAdds: 1, verb: "arrived"}, {whole: pieces - 1, moreDeletes: 1, verb: "left"}} {
		adds, dels := k.counts()
		if step.arrives {
			table.Set(netip.Prefix{}, moved, nil)
		} else {
			table.Remove(netip.Prefix{}, moved)
		}
		if err := reconciler.reconcile(); err != nil {
			t.Fatal(err)
		}
		added, deleted := k.counts()
		added, deleted = added-adds, deleted-dels
		if whole := reconciler.Stats().HoldsWhole; whole != step.whole || deleted > most+step.moreDeletes || added > most+step.moreAdds {
			t.Errorf("after %s %s the pass left %d holds whole, deleting %d routes first and adding %d, want %d, at most %d and at most %d",
				moved, step.verb, whole, deleted, added, step.whole, most+step.moreDeletes, most+step.moreAdds)
		}
		t.Logf("%s %s: %d routes deleted first, %d added", moved, step.verb, deleted, added)
	}
}

// The budget of pieces is a quarter of the mesh's table at babel's limit,
// which babel keeps unexported and this package writes down again, read as
// the constant babel's source gives it, and it is 4,096, as design/limits.md
// gives it
func TestHoldPieceBudgetIsAQuarterOfBabelsLimit(t *testing.T) {
	const path = "../babel/constants.go"
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatalf("read babel's limit: %v", err)
	}
	var given ast.Expr
	ast.Inspect(file, func(node ast.Node) bool {
		if spec, ok := node.(*ast.ValueSpec); ok {
			for i, name := range spec.Names {
				if name.Name == "maxRouteKeys" && i < len(spec.Values) {
					given = spec.Values[i]
				}
			}
		}
		return given == nil
	})
	if given == nil {
		t.Fatalf("%s gives maxRouteKeys no value", path)
	}
	value, err := types.Eval(token.NewFileSet(), nil, token.NoPos, types.ExprString(given))
	if err != nil || value.Value == nil || value.Value.Kind() != constant.Int {
		t.Fatalf("%s gives maxRouteKeys as %s, which this test cannot evaluate to a whole number on its own: %v", path, types.ExprString(given), err)
	}
	if babel, exact := constant.Int64Val(value.Value); !exact || babel != meshRouteKeys {
		t.Errorf("babel's limit in %s is %s and the kernel's meshRouteKeys %d, want them equal", path, value.Value, meshRouteKeys)
	}
	if holdPieceBudget != 4096 {
		t.Errorf("the budget of pieces is %d, and design/limits.md and routing.md give 4,096", holdPieceBudget)
	}
}

// On a tun holding an IPv6 address alone, a pass cuts a hold from a source
// holding that address into pieces from the same source, and leaves an IPv4
// hold whole around its live route, a family the tun holds no address of
func TestPassCutsByTheTunsAddressesAndFamilies(t *testing.T) {
	reconciler, table, k := coveredHarness(t, Table{}, Runtime{}, coverAddresses[1:]...)
	sourced, v4 := fromSource(holdRoute("2001:db8::/32"), "3fff:c::/48"), holdRoute("198.51.100.0/24")
	table.Set(sourced.Source, sourced.Destination, netstack.Unreachable)
	table.Set(netip.Prefix{}, prefix("2001:db8::/34"), nil)
	table.Set(netip.Prefix{}, v4.Destination, netstack.Unreachable)
	table.Set(netip.Prefix{}, prefix("198.51.100.0/26"), nil)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	v4.Scoped = true
	want := []Route{v4, meshRoute("198.51.100.0/26"), meshRoute("2001:db8::/34"), pieceRoute(sourced, "2001:db8:4000::/34"), pieceRoute(sourced, "2001:db8:8000::/33")}
	slices.SortFunc(want, compareRoutes)
	var got []Route
	for _, r := range k.snapshot() {
		if v4.Destination.Overlaps(r.Destination) || sourced.Destination.Overlaps(r.Destination) {
			got = append(got, r)
		}
	}
	slices.SortFunc(got, compareRoutes)
	if stats := reconciler.Stats(); !slices.Equal(got, want) || stats.HoldPieces != 2 || stats.HoldsWhole != 0 {
		t.Errorf("the kernel holds %v and the pass counts %d pieces and %d holds whole, want %v and 2 pieces", got, stats.HoldPieces, stats.HoldsWhole, want)
	}
}

// A hold around an overlay prefix and a live route inside it, under a mesh
// route that row L6 cuts around the overlay prefix, is cut after that cut, so
// its pieces give way to the cut's scoped parts at their destinations, as
// darwin holds one scoped route at a destination
func TestPassCutsAHoldAfterTheOtherCuts(t *testing.T) {
	reconciler, table, k := coveredHarness(t, Table{}, Runtime{}, coverAddresses...)
	reconciler.rt.Selection = newFakeSelection(hostRoute{destination: prefix("3fff::/16"), index: 2})
	held := holdRoute("3fff:8::/29")
	table.Set(netip.Prefix{}, prefix("3fff::/16"), nil)
	table.Set(netip.Prefix{}, held.Destination, netstack.Unreachable)
	table.Set(netip.Prefix{}, prefix("3fff:c::/34"), nil)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	scopedPart := func(destination string) Route {
		r := meshRoute(destination)
		r.Scoped = true
		return r
	}
	want := []Route{
		scopedPart("3fff:8::/30"), meshRoute("3fff:c::/32"), meshRoute("3fff:c::/34"),
		pieceRoute(held, "3fff:c:4000::/34"), pieceRoute(held, "3fff:c:8000::/33"), scopedPart("3fff:d::/32"), scopedPart("3fff:e::/31"),
	}
	var got []Route
	for _, r := range k.snapshot() {
		if held.Destination.Overlaps(r.Destination) {
			got = append(got, r)
		}
	}
	slices.SortFunc(got, compareRoutes)
	if stats := reconciler.Stats(); !slices.Equal(got, want) || stats.HoldPieces != 2 {
		t.Errorf("the kernel holds %v inside %s and the pass counts %d pieces, want %v and 2", got, held.Destination, stats.HoldPieces, want)
	}
}

// A pass counts the holds it left whole because their pieces would pass the
// budget beside the pieces of those it cut, with the budget, and records both
// counts with the pass, also where it cut none
func TestPassCountsTheHoldsItLeftWhole(t *testing.T) {
	bus := events.New()
	reconciler, table, k := coveredHarness(t, Table{}, Runtime{Events: bus}, coverAddresses...)
	wide := holdRoute("2001:db8::/32")
	table.Set(netip.Prefix{}, wide.Destination, netstack.Unreachable)
	// a live /127 at the first address of each /38 of the hold, 89 pieces each
	for i := range uint64(64) {
		table.Set(netip.Prefix{}, netip.PrefixFrom(benchPrefix(wide.Destination, i, 38).Addr(), 127), nil)
	}
	table.Set(netip.Prefix{}, prefix("3fff::/32"), netstack.Unreachable)
	table.Set(netip.Prefix{}, prefix("3fff::/34"), nil)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	stats := reconciler.Stats()
	if stats.HoldPieces != 2 || stats.HoldsWhole != 1 || stats.HoldPieceBudget != holdPieceBudget || !k.has(Route{Destination: wide.Destination, Metric: holdMetric, Unreachable: true, Scoped: true}) {
		t.Errorf("the pass counts %d pieces and %d holds whole past a budget of %d, want 2 and 1 past %d, %s held whole", stats.HoldPieces, stats.HoldsWhole, stats.HoldPieceBudget, holdPieceBudget, wide.Destination)
	}
	// the cut hold's live route gone, the pass holds no piece beside the hold
	// left whole
	table.Remove(netip.Prefix{}, prefix("3fff::/34"))
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if stats := reconciler.Stats(); stats.HoldPieces != 0 || stats.HoldsWhole != 1 {
		t.Errorf("the second pass counts %d pieces and %d holds whole, want none and 1", stats.HoldPieces, stats.HoldsWhole)
	}
	recorded := bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "kernel.pass" }, 0)
	if len(recorded) != 2 || recorded[0].Attrs["hold_pieces"] != "2" || recorded[0].Attrs["holds_whole"] != "1" ||
		recorded[1].Attrs["hold_pieces"] != "0" || recorded[1].Attrs["holds_whole"] != "1" {
		t.Errorf("the passes recorded %+v, want 2 hold pieces and 1 hold whole, then none and 1", recorded)
	}
}
