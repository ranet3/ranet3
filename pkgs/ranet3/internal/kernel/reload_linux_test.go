// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"net/netip"
	"slices"
	"testing"

	"ranet3.com/pkgs/ranet3/schema"
)

// the pass after a reload moves every IPv4 route to the new preferred source at an unchanged metric
// darwin refuses a preferred source, so the move holds on linux alone
func TestReloadMovesTheRoutesToTheNewPreferredSource(t *testing.T) {
	r, table, fake := harness(t, Table{PrefSrc4: schema.MustAddr("198.18.104.5")})
	table.Set(netip.Prefix{}, prefix("10.0.0.0/8"), nil)
	table.Set(netip.Prefix{}, prefix("3fff:a::/36"), nil)
	if err := r.reconcile(); err != nil {
		t.Fatal(err)
	}
	reload(t, r, Table{PrefSrc4: schema.MustAddr("198.18.104.6")})
	want := []Route{
		{Destination: prefix("10.0.0.0/8"), PrefSrc: addr("198.18.104.6")},
		{Destination: prefix("3fff:a::/36"), Metric: defaultIPv6Metric},
	}
	slices.SortFunc(want, compareRoutes)
	if got := fake.snapshot(); !slices.Equal(got, want) {
		t.Fatalf("the pass after the reload left %v with preferred sources %v, want %v with %v", got, prefSrcs(got), want, prefSrcs(want))
	}
}

// prefSrcs is the preferred source of each route, which Route.String leaves out
func prefSrcs(routes []Route) []netip.Addr {
	out := make([]netip.Addr, 0, len(routes))
	for _, route := range routes {
		out = append(out, route.PrefSrc)
	}
	return out
}
