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
