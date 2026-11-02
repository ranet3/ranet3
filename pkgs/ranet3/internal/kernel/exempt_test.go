// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package kernel

import (
	"net/netip"
	"slices"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/sadr"
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

// exemptSpaces is the addresses the property draws inside, in either family
// an overlay of 64 addresses
var exemptSpaces = [...]netip.Prefix{netip.MustParsePrefix("192.0.2.0/26"), netip.MustParsePrefix("3fff::/122")}

// drawnExemptPrefix draws a prefix inside space, or once in a while the
// prefix one bit shorter around it, wider than the overlay
func drawnExemptPrefix(tc hegel.TestCase, space netip.Prefix) netip.Prefix {
	if hegel.Draw(tc, pbt.Spanning(0, 9)) == 0 {
		return netip.PrefixFrom(space.Addr(), space.Bits()-1).Masked()
	}
	bits := hegel.Draw(tc, pbt.Spanning(space.Bits(), space.Addr().BitLen()))
	offset := hegel.Draw(tc, pbt.Spanning(0, 63))
	address := space.Addr().AsSlice()
	address[len(address)-1] |= byte(offset)
	drawn, _ := netip.AddrFromSlice(address)
	return netip.PrefixFrom(drawn, bits).Masked()
}

// an address of an exemption is carved exactly where it is this node's own
// address, or where an entry of the mesh's table routed via a peer, inside
// the overlay, holds it and no range of this node's own inside that entry
// does, and each conflict is an exemption and such an entry carving some of
// it, in either family
func TestExemptCarvedDropsWhatTheModelDrops(t *testing.T) {
	hegel.Test(t, func(ht *hegel.T) {
		exemptSpace := exemptSpaces[hegel.Draw(ht, pbt.Spanning(0, len(exemptSpaces)-1))]
		overlay := prefixes(exemptSpace)
		draw := func(most int) []netip.Prefix {
			out := make([]netip.Prefix, hegel.Draw(ht, pbt.Spanning(0, most)))
			for i := range out {
				out[i] = drawnExemptPrefix(ht, exemptSpace)
			}
			return out
		}
		var exemptions []egress.Exemption
		for _, prefix := range draw(3) {
			exemptions = append(exemptions, egress.Exemption{Interface: []string{"", "eth1"}[hegel.Draw(ht, pbt.Spanning(0, 1))], Prefix: prefix})
		}
		own := draw(3)
		var addresses []netip.Prefix
		for _, prefix := range draw(2) {
			addresses = append(addresses, netip.PrefixFrom(prefix.Addr(), prefix.Addr().BitLen()))
		}
		routes := netstack.NewRouteTable()
		values := []*netstack.Peer{learned, netstack.Local, netstack.Assigned, netstack.Unreachable}
		for _, prefix := range draw(4) {
			routes.Set(netip.Prefix{}, prefix, values[hegel.Draw(ht, pbt.Spanning(0, len(values)-1))])
		}
		snapshot := routes.Snapshot()
		carved, conflicts := ExemptCarved(exemptions, own, addresses, snapshot, overlay)
		another := func(entry sadr.Route[*netstack.Peer]) bool {
			return entry.Value == learned && encloses(exemptSpace, entry.Destination)
		}
		takes := func(entry sadr.Route[*netstack.Peer], address netip.Addr) bool {
			return another(entry) && entry.Destination.Contains(address) &&
				!slices.ContainsFunc(own, func(r netip.Prefix) bool { return encloses(entry.Destination, r) && r.Contains(address) })
		}
		var wantConflicts []egress.ExemptConflict
		for _, exemption := range exemptions {
			for _, entry := range snapshot {
				if !another(entry) || !exemption.Prefix.Overlaps(entry.Destination) {
					continue
				}
				both := entry.Destination
				if exemption.Prefix.Bits() > both.Bits() {
					both = exemption.Prefix
				}
				for address := both.Addr(); both.Contains(address); address = address.Next() {
					if takes(entry, address) {
						wantConflicts = append(wantConflicts, egress.ExemptConflict{Exemption: exemption, Prefix: entry.Destination, Carved: both, Via: learned.ID})
						break
					}
				}
			}
		}
		slices.SortFunc(wantConflicts, compareConflicts)
		wantConflicts = slices.Compact(wantConflicts)
		if !slices.Equal(conflicts, wantConflicts) {
			ht.Fatalf("exemptions %v, own %v, table %v: conflicts\n%v\nwant\n%v", exemptions, own, snapshot, conflicts, wantConflicts)
		}
		var want []netip.Prefix
		space := netip.PrefixFrom(exemptSpace.Addr(), exemptSpace.Bits()-1).Masked()
		for address := space.Addr(); space.Contains(address); address = address.Next() {
			inside := slices.ContainsFunc(exemptions, func(e egress.Exemption) bool { return e.Prefix.Contains(address) })
			mine := slices.ContainsFunc(addresses, func(a netip.Prefix) bool { return a.Addr() == address })
			theirs := slices.ContainsFunc(exemptions, func(e egress.Exemption) bool {
				return e.Prefix.Contains(address) && slices.ContainsFunc(snapshot, func(entry sadr.Route[*netstack.Peer]) bool { return takes(entry, address) })
			})
			if inside && (mine || theirs) {
				want = append(want, netip.PrefixFrom(address, address.BitLen()))
			}
		}
		if got := rangePrefixes(carved...); !slices.Equal(Ranges(got), Ranges(want)) {
			ht.Fatalf("exemptions %v, own %v, addresses %v, table %v: carved\n%v\nwant\n%v", exemptions, own, addresses, snapshot, got, rangePrefixes(Ranges(want)...))
		}
	})
}
