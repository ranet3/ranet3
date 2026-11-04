// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package kernel

import (
	"net/netip"
	"slices"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/schema"
)

// a gateway with node address 203.0.113.1 announcing 203.0.113.0/25 for the
// site behind it, exempting it from eth1: its own address is carved, the rest
// of its range is not, another node's more specific prefix inside the range
// and another node's prefix the exemption reaches into are carved as their
// intersection, each with a conflict naming the peer it is routed via, and a
// held prefix, this node's own entries, a default route and a prefix wider
// than the overlay carve nothing. Another node's prefix covering an exemption
// carves it less this node's range inside the prefix, in IPv4 and in IPv6.
func TestExemptCarvedKeepsTheGatewaysOwnRangeAndCarvesAnotherNodes(t *testing.T) {
	p := netip.MustParsePrefix
	overlay := prefixes(p("203.0.113.0/24"), p("3fff::/20"))
	site := egress.Exemption{Interface: "eth1", Prefix: p("203.0.113.0/24")}
	routes := netstack.NewRouteTable()
	routes.Set(netip.Prefix{}, p("203.0.113.1/32"), netstack.Assigned)
	routes.Set(netip.Prefix{}, p("203.0.113.0/25"), netstack.Local)
	routes.Set(netip.Prefix{}, p("203.0.113.64/28"), learned)
	routes.Set(netip.Prefix{}, p("203.0.113.128/25"), learned)
	routes.Set(netip.Prefix{}, p("203.0.113.32/28"), netstack.Unreachable)
	routes.Set(netip.Prefix{}, p("0.0.0.0/0"), learned)
	routes.Set(netip.Prefix{}, p("203.0.112.0/23"), learned)
	carved, conflicts := ExemptCarved([]egress.Exemption{site}, []netip.Prefix{p("203.0.113.0/25")}, []netip.Prefix{p("203.0.113.1/32")}, routes.Snapshot(), overlay)
	if want := Ranges([]netip.Prefix{p("203.0.113.1/32"), p("203.0.113.64/28"), p("203.0.113.128/25")}); !slices.Equal(carved, want) {
		t.Errorf("the exemption's carved sources are %v, want %v", carved, want)
	}
	want := []egress.ExemptConflict{
		{Exemption: site, Prefix: p("203.0.113.64/28"), Carved: p("203.0.113.64/28"), Via: learned.ID},
		{Exemption: site, Prefix: p("203.0.113.128/25"), Carved: p("203.0.113.128/25"), Via: learned.ID},
	}
	if !slices.Equal(conflicts, want) {
		t.Errorf("the conflicts are %v, want %v", conflicts, want)
	}

	// another node's prefix covering the exemption carves the exemption whole, less this node's own range inside the prefix
	inner := egress.Exemption{Prefix: p("203.0.113.0/26")}
	covering := netstack.NewRouteTable()
	covering.Set(netip.Prefix{}, p("203.0.113.0/24"), learned)
	carved, conflicts = ExemptCarved([]egress.Exemption{inner}, []netip.Prefix{p("203.0.113.16/28")}, nil, covering.Snapshot(), overlay)
	if want := Ranges([]netip.Prefix{p("203.0.113.0/28"), p("203.0.113.32/27")}); !slices.Equal(carved, want) {
		t.Errorf("under another node's covering prefix the exemption's carved sources are %v, want %v", carved, want)
	}
	if want := []egress.ExemptConflict{{Exemption: inner, Prefix: p("203.0.113.0/24"), Carved: p("203.0.113.0/26"), Via: learned.ID}}; !slices.Equal(conflicts, want) {
		t.Errorf("under another node's covering prefix the conflicts are %v, want %v", conflicts, want)
	}

	// in IPv6 alike, with this node's own range in its table and a node address inside that range
	inner6 := egress.Exemption{Interface: "eth1", Prefix: p("3fff:a::/47")}
	covering6 := netstack.NewRouteTable()
	covering6.Set(netip.Prefix{}, p("3fff::/28"), learned)
	covering6.Set(netip.Prefix{}, p("3fff:a::/48"), netstack.Local)
	carved, conflicts = ExemptCarved([]egress.Exemption{inner6}, []netip.Prefix{p("3fff:a::/48")}, []netip.Prefix{p("3fff:a::1/128")}, covering6.Snapshot(), overlay)
	if want := Ranges([]netip.Prefix{p("3fff:a::1/128"), p("3fff:a:1::/48")}); !slices.Equal(carved, want) {
		t.Errorf("under another node's covering IPv6 prefix the exemption's carved sources are %v, want %v", carved, want)
	}
	if want := []egress.ExemptConflict{{Exemption: inner6, Prefix: p("3fff::/28"), Carved: p("3fff:a::/47"), Via: learned.ID}}; !slices.Equal(conflicts, want) {
		t.Errorf("under another node's covering IPv6 prefix the conflicts are %v, want %v", conflicts, want)
	}
}

// a gateway with node address 203.0.113.1 announcing 203.0.113.0/25, whose site
// link eth1 is the carve-out of that range
func TestCarvedSetsLiftAnOwnAddressWhereEachCarveOutHoldingItIsNamed(t *testing.T) {
	p := netip.MustParsePrefix
	routes := netstack.NewRouteTable()
	routes.Set(netip.Prefix{}, p("203.0.113.0/25"), netstack.Local)
	routes.Set(netip.Prefix{}, p("203.0.113.1/32"), netstack.Assigned)
	routes.Set(netip.Prefix{}, p("203.0.113.96/28"), learned)
	routes.Set(netip.Prefix{}, p("203.0.113.128/28"), netstack.Unreachable)
	routes.Set(netip.Prefix{}, p("203.0.113.200/32"), learned)
	snapshot := routes.Snapshot()
	site := egress.CarveOut{Link: "eth1", Prefix: p("203.0.113.0/25")}
	lease := egress.CarveOut{Link: "wlan0", Prefix: p("203.0.113.0/24")}
	nested := egress.CarveOut{Link: "wlan0", Prefix: p("203.0.113.0/28")}
	wide := egress.CarveOut{Link: "eth1", Prefix: p("203.0.113.0/24")}
	exempt := func(name, prefix string) egress.Exemption {
		return egress.Exemption{Interface: name, Prefix: p(prefix)}
	}
	whole, lifted := []netip.Prefix{p("203.0.113.0/25")}, []netip.Prefix{p("203.0.113.1/32"), p("203.0.113.96/28")}
	beside := []netip.Prefix{p("203.0.113.128/28"), p("203.0.113.200/32")}
	for name, c := range map[string]struct {
		carveOuts  []egress.CarveOut
		exemptions []egress.Exemption
		want       []netip.Prefix
	}{
		"an exemption naming the carve-out's link": {[]egress.CarveOut{site}, []egress.Exemption{exempt("eth1", "203.0.113.0/25")}, lifted},
		"no exemption":                                      {[]egress.CarveOut{site}, nil, whole},
		"an exemption under another interface":              {[]egress.CarveOut{site}, []egress.Exemption{exempt("eth0", "203.0.113.0/25")}, whole},
		"a * matching the link":                             {[]egress.CarveOut{site}, []egress.Exemption{exempt("eth*", "203.0.113.0/25")}, lifted},
		"a * not matching the link":                         {[]egress.CarveOut{site}, []egress.Exemption{exempt("wl*", "203.0.113.0/25")}, whole},
		"a * the link holds but does not start with":        {[]egress.CarveOut{{Link: "veth0", Prefix: site.Prefix}}, []egress.Exemption{exempt("eth*", "203.0.113.0/25")}, whole},
		"two carve-outs, the first one's link exempt":       {[]egress.CarveOut{site, lease}, []egress.Exemption{exempt("eth1", "203.0.113.0/25")}, slices.Concat(whole, beside)},
		"two carve-outs, the second one's link exempt":      {[]egress.CarveOut{site, lease}, []egress.Exemption{exempt("wlan0", "203.0.113.0/25")}, slices.Concat(whole, beside)},
		"two carve-outs, each one's link exempt":            {[]egress.CarveOut{site, lease}, []egress.Exemption{exempt("eth1", "203.0.113.0/25"), exempt("wl*", "203.0.113.0/25")}, slices.Concat(lifted, beside)},
		"a carve-out inside the range on a link not exempt": {[]egress.CarveOut{site, nested}, []egress.Exemption{exempt("eth1", "203.0.113.0/25")}, []netip.Prefix{p("203.0.113.0/28"), p("203.0.113.96/28")}},
		"a carve-out inside the range on a link exempt too": {[]egress.CarveOut{site, nested}, []egress.Exemption{exempt("eth1", "203.0.113.0/25"), exempt("wlan0", "203.0.113.0/25")}, lifted},
		"an exemption wider than the range it holds":        {[]egress.CarveOut{wide}, []egress.Exemption{exempt("eth1", "203.0.113.0/24")}, slices.Concat(lifted, beside)},
		"an exemption narrower than the range it is under":  {[]egress.CarveOut{site}, []egress.Exemption{exempt("eth1", "203.0.113.64/26")}, []netip.Prefix{p("203.0.113.0/26"), p("203.0.113.96/28")}},
	} {
		t.Run(name, func(t *testing.T) {
			border := egress.Border{
				Overlay:   prefixes(p("203.0.113.0/24")),
				Antispoof: egress.Antispoof{Interface: map[string]egress.AntispoofInterface{}},
				Own:       []netip.Prefix{p("203.0.113.0/25")},
				Addresses: []netip.Prefix{p("203.0.113.1/32")},
			}
			for _, e := range c.exemptions {
				entry := border.Antispoof.Interface[e.Interface]
				entry.Exempt = append(entry.Exempt, schema.PrefixFrom(e.Prefix))
				border.Antispoof.Interface[e.Interface] = entry
			}
			got, _ := CarvedSets(&border, c.carveOuts, snapshot)
			if want := Ranges(c.want); !slices.Equal(got, want) {
				t.Errorf("the carved sets hold %v, want %v", got, want)
			}
		})
	}
}
