// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package kernel

import (
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/schema"
)

// overlayHold is the hold at destination a pass wants for an overlay prefix
func overlayHold(destination string) Route {
	return Route{Destination: prefix(destination), Metric: holdMetric, Unreachable: true}
}

// holdModes is mode off, mode 2 without the switch and mode 2 with it
var holdModes = map[string]*ExitMode{"off": nil, "uplink": {Fallback: FallbackUplink}, "none": {Fallback: FallbackNone}}

// On a platform writing the overlay holds apart from the tun, with no policy
// rules, a pass in every mode holds each overlay prefix unscoped, a family the
// tun holds no address of among them
func TestOverlayHoldsGoInUnscopedInEveryMode(t *testing.T) {
	for name, mode := range holdModes {
		reconciler, _, k := rejectingHarness(t, mode, prefix("192.0.2.1/24"))
		if err := reconciler.reconcile(); err != nil {
			t.Fatal(err)
		}
		for _, hold := range []Route{overlayHold("192.0.2.0/24"), overlayHold("3fff:c::/32")} {
			if !k.has(hold) {
				t.Errorf("in mode %s the kernel holds %v, want %+v unscoped", name, k.snapshot(), hold)
			}
		}
	}
}

// A carve-out as wide as an overlay prefix takes that prefix's hold away, and
// the other prefix keeps its own
func TestOverlayHoldGivesWayToAnEqualCarveOut(t *testing.T) {
	reconciler, _, k := rejectingHarness(t, nil, coverAddresses...)
	network := NetworkState{IPv4: NetworkFamily{Links: []Link{{Name: "en0", Prefixes: []netip.Prefix{prefix("192.0.2.10/24")}}}}}
	reconciler.rt.Network = func() NetworkState { return network }
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if got := routesAt(k.fakeKernel, "192.0.2.0/24"); len(got) != 0 || !k.has(overlayHold("3fff:c::/32")) {
		t.Errorf("beside a lease as wide as 192.0.2.0/24 the kernel holds %v, want no route there and the hold at 3fff:c::/32", k.snapshot())
	}
}

// A route of the mesh at an overlay prefix goes in as its two halves in every
// mode, and the hold keeps its key, no add refused
func TestOverlayHoldKeepsItsKeyUnderAMeshRouteThere(t *testing.T) {
	for name, mode := range holdModes {
		reconciler, table, k := rejectingHarness(t, mode, coverAddresses...)
		table.Set(netip.Prefix{}, prefix("192.0.2.0/24"), nil)
		table.Set(netip.Prefix{}, prefix("3fff:c::/32"), nil)
		if err := reconciler.reconcile(); err != nil {
			t.Fatal(err)
		}
		want := []Route{
			overlayHold("192.0.2.0/24"), {Destination: prefix("192.0.2.0/25")}, {Destination: prefix("192.0.2.128/25")},
			overlayHold("3fff:c::/32"), {Destination: prefix("3fff:c::/33"), Metric: defaultIPv6Metric}, {Destination: prefix("3fff:c:8000::/33"), Metric: defaultIPv6Metric},
		}
		got := routesAt(k.fakeKernel, "192.0.2.0/24", "192.0.2.0/25", "192.0.2.128/25", "3fff:c::/32", "3fff:c::/33", "3fff:c:8000::/33")
		slices.SortFunc(got, compareRoutes)
		slices.SortFunc(want, compareRoutes)
		_, ops := k.held()
		if !slices.Equal(got, want) || slices.ContainsFunc(ops, func(op string) bool { return strings.HasPrefix(op, "refused") }) {
			t.Errorf("in mode %s the kernel holds %v after %v, want %v and no add refused", name, got, ops, want)
		}
	}
}

// A route of the mesh at a full-length overlay prefix, which has no halves,
// goes in whole in every mode beside the hold there, which stays when the
// route is gone, no add refused
func TestOverlayHoldStaysBeneathAMeshRouteAtAFullLengthPrefix(t *testing.T) {
	for name, mode := range holdModes {
		reconciler, table, k := rejectingHarness(t, mode, coverAddresses...)
		reconciler.rt.Overlay = append(slices.Clone(coverOverlay), prefixes(prefix("192.0.2.53/32"), prefix("3fff:c::53/128"))...)
		pass := func(step string, want ...Route) {
			t.Helper()
			if err := reconciler.reconcile(); err != nil {
				t.Fatal(err)
			}
			got := routesAt(k.fakeKernel, "192.0.2.53/32", "3fff:c::53/128")
			slices.SortFunc(got, compareRoutes)
			slices.SortFunc(want, compareRoutes)
			_, ops := k.held()
			if !slices.Equal(got, want) || slices.ContainsFunc(ops, func(op string) bool { return strings.HasPrefix(op, "refused") }) {
				t.Errorf("in mode %s %s the kernel holds %v after %v, want %v and no add refused", name, step, got, ops, want)
			}
		}
		pass("before any route", overlayHold("192.0.2.53/32"), overlayHold("3fff:c::53/128"))
		table.Set(netip.Prefix{}, prefix("192.0.2.53/32"), nil)
		table.Set(netip.Prefix{}, prefix("3fff:c::53/128"), nil)
		pass("under the mesh's routes", Route{Destination: prefix("192.0.2.53/32")}, Route{Destination: prefix("3fff:c::53/128"), Metric: defaultIPv6Metric},
			overlayHold("192.0.2.53/32"), overlayHold("3fff:c::53/128"))
		table.Remove(netip.Prefix{}, prefix("192.0.2.53/32"))
		table.Remove(netip.Prefix{}, prefix("3fff:c::53/128"))
		pass("once they are gone", overlayHold("192.0.2.53/32"), overlayHold("3fff:c::53/128"))
	}
}

// A mesh route holding an overlay prefix beneath a route of the host's goes
// in as its pieces outside the overlay, row L6 scoping them, and the piece at
// the overlay prefix gives way to the hold, which refuses the prefix as on
// linux
func TestOverlayHoldAloneHoldsItsPrefixUnderARouteRowL6Cuts(t *testing.T) {
	reconciler, table, k := rejectingHarness(t, nil, coverAddresses...)
	reconciler.rt.Selection = newFakeSelection(hostRoute{destination: prefix("192.0.0.0/15"), index: 2})
	table.Set(netip.Prefix{}, prefix("192.0.0.0/16"), nil)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	want := []Route{overlayHold("192.0.2.0/24")}
	got := routesAt(k.fakeKernel, "192.0.2.0/24", "192.0.2.0/25", "192.0.2.128/25")
	slices.SortFunc(got, compareRoutes)
	_, ops := k.held()
	if !slices.Equal(got, want) || slices.ContainsFunc(ops, func(op string) bool { return strings.HasPrefix(op, "refused") }) {
		t.Errorf("the kernel holds %v after %v, want %v and no add refused", got, ops, want)
	}
}

// heldAlone fails t unless the routes of k's at or inside the hold's prefix
// are the hold and scoped, routes of the mesh's an unbound lookup passes over
func heldAlone(t *testing.T, k *rejectingKernel, hold Route, scoped ...Route) {
	t.Helper()
	var got []Route
	for _, r := range k.snapshot() {
		if hold.Destination.Bits() <= r.Destination.Bits() && hold.Destination.Contains(r.Destination.Addr()) {
			got = append(got, r)
		}
	}
	want := append([]Route{hold}, scoped...)
	slices.SortFunc(got, compareRoutes)
	slices.SortFunc(want, compareRoutes)
	if !slices.Equal(got, want) {
		t.Errorf("the kernel holds %v at or inside %s, want its hold and %v alone", got, hold.Destination, scoped)
	}
}

// A source-specific route of the mesh at an overlay prefix that row L6 cuts a
// shorter mesh route around goes in scoped beside the hold, and the shorter
// route's piece at the prefix gives way to the hold in every mode, so the
// hold refuses every unbound send there as on linux
func TestOverlayHoldAloneHoldsItsPrefixBesideASourceRouteThere(t *testing.T) {
	source := Route{Destination: prefix("3fff:c::/32"), Source: prefix("2001:db8::/48"), Metric: defaultIPv6Metric, Scoped: true}
	for name, mode := range holdModes {
		reconciler, table, k := rejectingHarness(t, mode, coverAddresses...)
		reconciler.rt.Selection = newFakeSelection(hostRoute{destination: prefix("3fff::/15"), index: 2})
		table.Set(netip.Prefix{}, prefix("3fff::/16"), nil)
		table.Set(source.Source, source.Destination, nil)
		if err := reconciler.reconcile(); err != nil {
			t.Fatal(err)
		}
		t.Run(name, func(t *testing.T) { heldAlone(t, k, overlayHold("3fff:c::/32"), source) })
	}
}

// A hold of the mesh's inside an overlay prefix goes in scoped beside the
// overlay's hold, and the pieces an endpoint cut leaves of a shorter mesh
// route around it give way to the overlay's hold in every mode
func TestOverlayHoldAloneHoldsItsPrefixBesideAMeshHoldAroundAnEndpoint(t *testing.T) {
	held := Route{Destination: prefix("192.0.2.64/26"), Metric: holdMetric, Unreachable: true, Scoped: true}
	for name, mode := range holdModes {
		reconciler, table, k := rejectingHarness(t, mode, coverAddresses...)
		reconciler.rt.Selection = newFakeSelection(hostRoute{destination: prefix("192.0.0.0/15"), index: 2})
		reconciler.rt.Underlay = func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("192.0.2.77")} }
		table.Set(netip.Prefix{}, prefix("192.0.0.0/16"), nil)
		table.Set(netip.Prefix{}, held.Destination, netstack.Unreachable)
		if err := reconciler.reconcile(); err != nil {
			t.Fatal(err)
		}
		t.Run(name, func(t *testing.T) { heldAlone(t, k, overlayHold("192.0.2.0/24"), held) })
	}
}

// A mesh route shorter than an overlay prefix that row L6 cuts around it,
// whose piece at the prefix is cut again around an endpoint inside it, leaves
// no piece at or inside the prefix in any mode, so the hold refuses every
// address of it as on linux
func TestOverlayHoldAloneHoldsItsPrefixAroundAnEndpointInsideIt(t *testing.T) {
	for name, mode := range holdModes {
		reconciler, table, k := rejectingHarness(t, mode, coverAddresses...)
		reconciler.rt.Selection = newFakeSelection(hostRoute{destination: prefix("192.0.0.0/15"), index: 2})
		reconciler.rt.Underlay = func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("192.0.2.77")} }
		table.Set(netip.Prefix{}, prefix("192.0.0.0/16"), nil)
		if err := reconciler.reconcile(); err != nil {
			t.Fatal(err)
		}
		t.Run(name, func(t *testing.T) { heldAlone(t, k, overlayHold("192.0.2.0/24")) })
	}
}

// Under the switch an overlay prefix at a half of NAT64's key keeps its
// prefix from the half a shorter mesh route holds there, and the other half
// goes in, the reject at the key reading back
func TestOverlayHoldAloneHoldsAHalfOfAKey(t *testing.T) {
	reconciler, table, k := rejectingHarness(t, &ExitMode{Fallback: FallbackNone}, coverAddresses...)
	reconciler.rt.Overlay = append(slices.Clone(coverOverlay), prefixes(prefix("64:ff9b::/97"))...)
	table.Set(netip.Prefix{}, prefix("64:ff9b::/64"), nil)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	heldAlone(t, k, overlayHold("64:ff9b::/97"))
	if !k.has(Route{Destination: prefix("64:ff9b::8000:0/97"), Metric: defaultIPv6Metric}) {
		t.Errorf("the kernel holds %v, want the upper half of 64:ff9b::/96", k.snapshot())
	}
	if held, _ := k.held(); !slices.Equal(held, rejectKeys) {
		t.Errorf("the pass holds rejects at %v, want at %v", held, rejectKeys)
	}
}

// An overlay prefix holding NAT64's keys keeps out of its prefix in every
// mode their halves a shorter mesh route holds under the switch, and the
// members a zero route would go in as
func TestOverlayHoldAloneHoldsNAT64sKeysInsideIt(t *testing.T) {
	for name, mode := range holdModes {
		for _, mesh := range []string{"64::/16", "::/0"} {
			reconciler, table, k := rejectingHarness(t, mode, coverAddresses...)
			reconciler.rt.Overlay = append(slices.Clone(coverOverlay), prefixes(prefix("64:ff9b::/32"))...)
			table.Set(netip.Prefix{}, prefix(mesh), nil)
			if err := reconciler.reconcile(); err != nil {
				t.Fatal(err)
			}
			t.Run(name+" "+mesh, func(t *testing.T) { heldAlone(t, k, overlayHold("64:ff9b::/32")) })
		}
	}
}

// The reconciler hands its underlay's selection the overlay in force at its
// start and again at each reload it adopts, so the selection passes over the
// holds of the overlay the passes write
func TestReconcilerHandsItsSelectionTheOverlayInForce(t *testing.T) {
	selection := newFakeSelection()
	reconciler, _, _ := harness(t, Table{}, Runtime{Overlay: coverOverlay, Selection: selection})
	next := prefixes(prefix("198.51.100.0/24"))
	if err := reconciler.SetTable(reconciler.Table(), next, nil); err != nil {
		t.Fatal(err)
	}
	if !reconciler.adopt() {
		t.Fatal("the reconciler adopted no reload")
	}
	if got := selection.handed(); !reflect.DeepEqual(got, [][]schema.Prefix{coverOverlay, next}) {
		t.Errorf("the selection was handed %v, want %v at the start and %v at the reload", got, coverOverlay, next)
	}
}

// A failed mesh's stop takes the holds with the routes and leaves the switch,
// and an operator's stop takes the holds, the routes and the switch
func TestOverlayHoldsGoAtEveryStop(t *testing.T) {
	for name, mode := range holdModes {
		for _, cause := range []error{ErrMeshFailed, nil} {
			reconciler, _, k := rejectingHarness(t, mode, coverAddresses...)
			stop := runThroughFirstPass(t, reconciler)
			if !k.has(overlayHold("192.0.2.0/24")) {
				t.Fatalf("in mode %s the first pass holds %v, want the overlay's holds", name, k.snapshot())
			}
			stop(cause)
			held, _ := k.held()
			if len(k.snapshot()) != 0 || !slices.Equal(held, map[bool][]netip.Prefix{true: rejectKeys}[name == "none" && cause != nil]) {
				t.Errorf("in mode %s the stop for %v left %v and rejects at %v, want no route and the switch where a failed mesh's stop asks for it", name, cause, k.snapshot(), held)
			}
		}
	}
}
