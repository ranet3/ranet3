// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"net/netip"
	"slices"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/netstack"
)

// A lease as wide as an overlay prefix throws in place of that prefix's hold,
// a lease inside another overlay prefix throws beside its hold, a table entry
// of a lease's own prefix keeps the prefix in the mesh, and a link's network
// outside the overlay and lo carve nothing
func TestCarveOutsThrowInPlaceOfTheHoldAndGiveWayToTheTable(t *testing.T) {
	p := netip.MustParsePrefix
	network := NetworkState{
		IPv4: NetworkFamily{Links: []Link{
			{Name: "eth0", Prefixes: []netip.Prefix{p("192.0.2.10/24"), p("198.51.100.10/24")}},
			{Name: "lo", Prefixes: []netip.Prefix{p("203.0.113.1/32")}},
		}},
		IPv6: NetworkFamily{Links: []Link{
			{Name: "eth0", Prefixes: []netip.Prefix{p("3fff:0:0:7::10/64"), p("3fff:0:0:8::10/64")}},
		}},
	}
	reconciler, routes, _ := harness(t, Table{}, Runtime{
		Overlay: prefixes(p("192.0.2.0/24"), p("203.0.113.0/24"), p("3fff::/48")),
		Network: func() NetworkState { return network },
	})
	peer := &netstack.Peer{ID: "example/peer"}
	routes.Set(netip.Prefix{}, p("192.0.2.77/32"), peer)
	routes.Set(netip.Prefix{}, p("3fff:0:0:8::/64"), peer)
	hold := func(destination string) Route {
		return Route{Destination: p(destination), Metric: holdMetric, Unreachable: true}
	}
	want := []Route{
		{Destination: p("192.0.2.0/24"), Metric: holdMetric, Throw: true},
		{Destination: p("192.0.2.77/32"), Metric: 0},
		hold("203.0.113.0/24"),
		hold("3fff::/48"),
		{Destination: p("3fff:0:0:7::/64"), Metric: holdMetric, Throw: true},
		{Destination: p("3fff:0:0:8::/64"), Metric: defaultIPv6Metric},
	}
	got := reconciler.desired(routes.Snapshot())
	slices.SortFunc(got, compareRoutes)
	if !slices.Equal(got, want) {
		t.Errorf("the mirror wants\n%v\nwant\n%v", got, want)
	}
}

// Under fallback = "none" a lease as wide as the overlay is looked up in main
// past the mesh's throw, and the fallback table passes the lease less the
// mesh's prefixes inside it, so the gateway answers and a mesh peer's address
// never leaves by the link
func TestFallbackPassesACarvedLeaseLessTheMeshsPrefixes(t *testing.T) {
	p := netip.MustParsePrefix
	network := NetworkState{
		IPv4: NetworkFamily{Links: []Link{{Name: "eth0", Prefixes: []netip.Prefix{p("192.0.2.10/24")}}}},
		IPv6: NetworkFamily{Links: []Link{{Name: "eth0", Prefixes: []netip.Prefix{p("3fff::10/48")}}}},
	}
	reconciler, routes, _ := harness(t, Table{}.WithMode(&ExitMode{Fallback: FallbackNone}), Runtime{
		Overlay: prefixes(p("192.0.2.0/24"), p("3fff::/48")),
		Network: func() NetworkState { return network },
	})
	peer := &netstack.Peer{ID: "example/peer"}
	routes.Set(netip.Prefix{}, p("192.0.2.128/25"), peer)
	routes.Set(netip.Prefix{}, p("3fff::/49"), peer)
	snapshot := routes.Snapshot()
	exit, _ := reconciler.exitPass(reconciler.addresses, snapshot)
	exit.own = thrown(reconciler.desired(snapshot))
	var main []Rule
	for _, rule := range derivedRules(DefaultTable, reconciler.rt.Overlay, nil, exit) {
		if rule.Priority == priorityOwnPastMesh {
			main = append(main, rule)
		}
	}
	if len(main) != 2 || main[0].To.Prefix != p("192.0.2.0/24") || main[1].To.Prefix != p("3fff::/48") {
		t.Errorf("5445 looks main up for %v, want the two leases", main)
	}
	sets, asked := reconciler.fallbackFor(exit)
	if !asked {
		t.Fatal("the mode does not ask for the table")
	}
	if want := []netip.Prefix{p("192.0.2.0/25")}; !slices.Equal(sets.lan4, want) {
		t.Errorf("lan4 holds %v, want %v", sets.lan4, want)
	}
	if want := []netip.Prefix{p("3fff:0:0:8000::/49")}; !slices.Equal(sets.lan6, want) {
		t.Errorf("lan6 holds %v, want %v", sets.lan6, want)
	}
	if len(sets.own4) != 0 || len(sets.own6) != 0 {
		t.Errorf("own holds %v and %v, want neither lease", sets.own4, sets.own6)
	}
}

// Under fallback = "none" a pass installs 5445 for each carve-out the mirror
// throws, a lease as wide as an overlay prefix in each family
func TestFallbackPassLooksEachCarveOutUpInMain(t *testing.T) {
	p := netip.MustParsePrefix
	network := NetworkState{
		IPv4: NetworkFamily{Links: []Link{{Name: "eth0", Prefixes: []netip.Prefix{p("192.0.2.10/24")}}}},
		IPv6: NetworkFamily{Links: []Link{{Name: "eth0", Prefixes: []netip.Prefix{p("3fff::10/48")}}}},
	}
	reconciler, routes, fake := harness(t, Table{}.WithMode(&ExitMode{Fallback: FallbackNone}), Runtime{
		Overlay: prefixes(p("192.0.2.0/24"), p("3fff::/48")),
		Network: func() NetworkState { return network },
	})
	peer := &netstack.Peer{ID: "example/peer"}
	routes.Set(netip.Prefix{}, p("192.0.2.128/25"), peer)
	routes.Set(netip.Prefix{}, p("3fff::/49"), peer)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	var main []netip.Prefix
	for rule := range fake.rules {
		if rule.Priority == priorityOwnPastMesh {
			main = append(main, rule.To.Prefix)
		}
	}
	slices.SortFunc(main, comparePrefixes)
	if want := []netip.Prefix{p("192.0.2.0/24"), p("3fff::/48")}; !slices.Equal(main, want) {
		t.Errorf("the pass installs 5445 for %v, want each lease", main)
	}
}
