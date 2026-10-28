// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"net/netip"
	"slices"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/schema"
)

func addressRange(first, last string) egress.Range {
	return egress.Range{First: netip.MustParseAddr(first), Last: netip.MustParseAddr(last)}
}

// An exit whose none class covers the overlay and a block upstream of it, inside
// which a subnet router advertises its LAN, takes inbound connections to the
// overlay whole and to the block less the LAN, held or learned, in both
// families. An auto class inside the block keeps its addresses out, a LAN that
// counts as a default subtracts nothing, and this node's own LAN is no other
// node's.
func TestNoneDestinationsOfAnExitAroundAnotherNodesLAN(t *testing.T) {
	p := netip.MustParsePrefix
	none, auto := egress.Translation{None: true}, egress.Translation{Auto: true}
	classes := []egress.Class{
		{From: schema.PrefixFrom(p("192.0.2.0/24")), To: none},
		{From: schema.PrefixFrom(p("203.0.112.0/23")), To: none},
		{From: schema.PrefixFrom(p("203.0.112.128/25")), To: auto},
		{From: schema.PrefixFrom(p("3fff::/20")), To: none},
		{From: schema.PrefixFrom(p("2001:db8:76::/47")), To: none},
		{From: schema.PrefixFrom(p("0.0.0.0/0")), To: auto},
	}
	overlay := prefixes(p("192.0.2.0/24"), p("3fff::/20"))
	routes := netstack.NewRouteTable()
	routes.SetOverlay(overlay)
	peer := &netstack.Peer{ID: "example/gateway"}
	routes.Set(netip.Prefix{}, p("203.0.113.0/24"), peer)
	routes.Set(netip.Prefix{}, p("2001:db8:77::/64"), netstack.Unreachable)
	routes.Set(netip.Prefix{}, p("192.0.2.64/26"), peer)
	routes.Set(netip.Prefix{}, p("0.0.0.0/0"), peer)
	routes.Set(netip.Prefix{}, p("203.0.112.0/26"), netstack.Local)
	got := NoneDestinations(classes, routes.Snapshot(), overlay)
	want := []egress.Range{
		addressRange("192.0.2.0", "192.0.2.255"),
		addressRange("203.0.112.0", "203.0.112.127"),
		addressRange("2001:db8:76::", "2001:db8:76:ffff:ffff:ffff:ffff:ffff"),
		addressRange("2001:db8:77:1::", "2001:db8:77:ffff:ffff:ffff:ffff:ffff"),
		addressRange("3fff::", "3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff"),
	}
	if !slices.Equal(got, want) {
		t.Errorf("the none sets are\n%v\nwant\n%v", got, want)
	}
	if got := NoneDestinations(nil, routes.Snapshot(), overlay); got != nil {
		t.Errorf("a node with no class holds the none sets %v", got)
	}
}

// The owned sources are every entry of this node's own that counts as no
// default, an address inside an own prefix and two adjoining prefixes joined
// into one range, a source-specific entry by its destination whole, and
// neither a learned or held entry nor an exit's own default
func TestOwnedSourcesJoinThisNodesOwnEntries(t *testing.T) {
	p := netip.MustParsePrefix
	routes := netstack.NewRouteTable()
	routes.SetOverlay(prefixes(p("192.0.2.0/24")))
	routes.Set(netip.Prefix{}, p("192.0.2.0/25"), netstack.Local)
	routes.Set(netip.Prefix{}, p("192.0.2.128/25"), netstack.Local)
	routes.Set(netip.Prefix{}, p("192.0.2.200/32"), netstack.Assigned)
	routes.Set(netip.Prefix{}, p("0.0.0.0/0"), netstack.Local)
	routes.Set(netip.Prefix{}, p("198.51.100.0/24"), &netstack.Peer{ID: "example/gateway"})
	routes.Set(netip.Prefix{}, p("198.51.101.0/24"), netstack.Unreachable)
	routes.Set(p("3fff::/48"), p("2001:db8:5::/48"), netstack.Local)
	got := OwnedSources(routes.Snapshot(), prefixes(p("192.0.2.0/24")))
	want := []egress.Range{
		addressRange("192.0.2.0", "192.0.2.255"),
		addressRange("2001:db8:5::", "2001:db8:5:ffff:ffff:ffff:ffff:ffff"),
	}
	if !slices.Equal(got, want) {
		t.Errorf("the owned sources are\n%v\nwant\n%v", got, want)
	}
}
