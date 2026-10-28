// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"net/netip"
	"slices"
	"testing"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/transport"
)

// recordedRoutes is a selection that answers each address a test names with
// its route and interface, and no route for any other
type recordedRoutes map[netip.Addr]struct {
	prefix netip.Prefix
	device string
}

func (r recordedRoutes) Route(addr netip.Addr) (netip.Prefix, string, bool) {
	route, ok := r[addr]
	return route.prefix, route.device, ok
}

// each live session's path is one underlay row in address order, a second
// session on a path adds none, an endpoint no route holds reads as no route,
// a link-local endpoint is asked with its zone, and a session's pin names its
// interface whatever the selection answers for its address
func TestUnderlayRowsAreWhereEachSessionsDatagramsLeave(t *testing.T) {
	near, far, v6 := netip.MustParseAddr("198.51.100.77"), netip.MustParseAddr("203.0.113.70"), netip.MustParseAddr("2001:db8:400::7")
	zoned := netip.MustParseAddr("fe80::9%en2")
	routes := recordedRoutes{
		near:  {netip.MustParsePrefix("198.51.100.0/24"), "en0"},
		v6:    {netip.MustParsePrefix("::/0"), "en1"},
		zoned: {netip.Prefix{}, "en2"},
	}
	got := underlayLookups(routes, []transport.UnderlayPath{
		{Address: v6}, {Address: far}, {Address: near}, {Address: v6}, {Address: zoned}, {Address: near, Pin: "en3"},
	})
	want := []control.RuleLookup{
		{Lookup: "underlay", Family: "ipv4", Prefix: netip.MustParsePrefix("198.51.100.0/24"), Address: near, Answer: "dev en0"},
		{Lookup: "underlay", Family: "ipv4", Address: near, Answer: "dev en3"},
		{Lookup: "underlay", Family: "ipv4", Address: far, Answer: "no route"},
		{Lookup: "underlay", Family: "ipv6", Prefix: netip.MustParsePrefix("::/0"), Address: v6, Answer: "dev en1"},
		{Lookup: "underlay", Family: "ipv6", Address: zoned, Answer: "dev en2"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("the underlay rows are %+v, want %+v", got, want)
	}
}
