// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package kernel

import (
	"cmp"
	"maps"
	"math/big"
	"net/netip"
	"slices"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/schema"
)

// carveBases are the addresses a drawn overlay, network or address lies near,
// so each is drawn inside, around, beside and equal to the others
var carveBases = map[Family][]string{
	FamilyIPv4: {"192.0.2.0", "192.0.2.128", "198.51.100.0", "0.0.0.0"},
	FamilyIPv6: {"3fff::", "3fff:0:0:1::", "2001:db8::", "::"},
}

// carveLinks are the names a drawn host holds its links under, lo among them
var carveLinks = []string{"eth0", "lo", "wlan0"}

// nearAddress draws an address of family a few bits off one of carveBases
func nearAddress(tc hegel.TestCase, family Family) netip.Addr {
	bases := carveBases[family]
	base := netip.MustParseAddr(bases[hegel.Draw(tc, pbt.Spanning(0, len(bases)-1))])
	bytes := base.AsSlice()
	offset := hegel.Draw(tc, pbt.Spanning(0, 0xffff))
	bytes[len(bytes)-2] |= byte(offset >> 8)
	bytes[len(bytes)-1] |= byte(offset)
	if hegel.Draw(tc, pbt.Spanning(0, 1)) == 1 {
		// a bit every base leaves clear, which puts the address beside a base's network
		bytes[len(bytes)/2] |= 0x01
	}
	address, _ := netip.AddrFromSlice(bytes)
	return address
}

// nearPrefix draws an address near carveBases under a drawn length, its host
// bits kept, as a link carries one
func nearPrefix(tc hegel.TestCase, family Family) netip.Prefix {
	address := nearAddress(tc, family)
	return netip.PrefixFrom(address, hegel.Draw(tc, pbt.Spanning(0, address.BitLen())))
}

// drawnCarveNetwork draws each family's links from carveLinks, each with up to
// two prefixes
func drawnCarveNetwork(tc hegel.TestCase) NetworkState {
	links := func(family Family) []Link {
		var out []Link
		for _, name := range carveLinks {
			if hegel.Draw(tc, pbt.Spanning(0, 1)) == 0 {
				continue
			}
			link := Link{Name: name}
			for range hegel.Draw(tc, pbt.Spanning(0, 2)) {
				link.Prefixes = append(link.Prefixes, nearPrefix(tc, family))
			}
			out = append(out, link)
		}
		return out
	}
	return NetworkState{IPv4: NetworkFamily{Links: links(FamilyIPv4)}, IPv6: NetworkFamily{Links: links(FamilyIPv6)}}
}

// drawnCarveOverlay draws up to two masked prefixes of each family
func drawnCarveOverlay(tc hegel.TestCase) []schema.Prefix {
	var out []schema.Prefix
	for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
		for range hegel.Draw(tc, pbt.Spanning(0, 2)) {
			out = append(out, schema.PrefixFrom(nearPrefix(tc, family).Masked()))
		}
	}
	return out
}

// modelLast is the last address of a masked prefix, counted as an integer
func modelLast(prefix netip.Prefix) netip.Addr {
	first := new(big.Int).SetBytes(prefix.Addr().AsSlice())
	span := new(big.Int).Lsh(big.NewInt(1), uint(prefix.Addr().BitLen()-prefix.Bits()))
	last := new(big.Int).Add(first, span.Sub(span, big.NewInt(1))).FillBytes(make([]byte, prefix.Addr().BitLen()/8))
	address, _ := netip.AddrFromSlice(last)
	return address
}

// holds reports each address of inner lying in outer, both masked: its first and its last
func holds(outer, inner netip.Prefix) bool {
	return outer.Contains(inner.Addr()) && outer.Contains(modelLast(inner))
}

// carveModel is 2.6's carve-outs: for each link but lo, each prefix of the
// overlay that one of the link's networks holds whole and each such network
// the overlay holds whole, which is every address the two share
func carveModel(network NetworkState, overlay []schema.Prefix) []CarveOut {
	set := map[CarveOut]bool{}
	for _, link := range slices.Concat(network.IPv4.Links, network.IPv6.Links) {
		if link.Name == "lo" {
			continue
		}
		for _, address := range link.Prefixes {
			n := address.Masked()
			for _, entry := range overlay {
				o := entry.Masked()
				if holds(n, o) {
					set[CarveOut{Link: link.Name, Prefix: o}] = true
				}
				if holds(o, n) {
					set[CarveOut{Link: link.Name, Prefix: n}] = true
				}
			}
		}
	}
	return slices.SortedFunc(maps.Keys(set), func(a, b CarveOut) int {
		return cmp.Or(cmp.Compare(a.Link, b.Link), a.Prefix.Addr().Compare(b.Prefix.Addr()), cmp.Compare(a.Prefix.Bits(), b.Prefix.Bits()))
	})
}

// The carve-outs are exactly 2.6's intersections of each link's networks with
// the overlay, never on lo, sorted by link and prefix and each once, and an
// address lies in a link's carve-out exactly when one of the link's networks
// and the overlay both hold it
func TestCarveOutsAreEachLinksIntersectionWithTheOverlay(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		network, overlay := drawnCarveNetwork(ht), drawnCarveOverlay(ht)
		got := CarveOuts(network, overlay)
		if want := carveModel(network, overlay); !slices.Equal(got, want) {
			ht.Fatalf("the carve-outs of %v under %v are\n%v\nwant\n%v", network, overlay, got, want)
		}
		for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
			address := nearAddress(ht, family)
			links := network.IPv4.Links
			if family == FamilyIPv6 {
				links = network.IPv6.Links
			}
			inOverlay := slices.ContainsFunc(overlay, func(o schema.Prefix) bool { return o.Contains(address) })
			for _, link := range links {
				onLink := link.Name != "lo" && slices.ContainsFunc(link.Prefixes, func(p netip.Prefix) bool { return p.Masked().Contains(address) })
				carved := slices.ContainsFunc(got, func(c CarveOut) bool { return c.Link == link.Name && c.Prefix.Contains(address) })
				if carved != (onLink && inOverlay) {
					ht.Fatalf("%s carved on %s %v, on the link %v and in the overlay %v", address, link.Name, carved, onLink, inOverlay)
				}
			}
		}
	})
}

// The prefixes inside the carve-outs are exactly the destinations of the
// table's entries a carve-out holds whole, learned, held and this node's own
// alike, a source-specific entry by its destination, sorted and each once
func TestCarvedPrefixesAreTheTablesEntriesInsideACarveOut(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		var carveOuts []CarveOut
		for range hegel.Draw(ht, pbt.Spanning(0, 3)) {
			family := FamilyIPv4
			if hegel.Draw(ht, pbt.Spanning(0, 1)) == 1 {
				family = FamilyIPv6
			}
			carveOuts = append(carveOuts, CarveOut{Link: carveLinks[hegel.Draw(ht, pbt.Spanning(0, len(carveLinks)-1))], Prefix: nearPrefix(ht, family).Masked()})
		}
		routes := netstack.NewRouteTable()
		values := []*netstack.Peer{learned, netstack.Unreachable, netstack.Local, netstack.Assigned}
		for range hegel.Draw(ht, pbt.Spanning(0, 8)) {
			family := FamilyIPv4
			if hegel.Draw(ht, pbt.Spanning(0, 1)) == 1 {
				family = FamilyIPv6
			}
			var source netip.Prefix
			if family == FamilyIPv6 && hegel.Draw(ht, pbt.Spanning(0, 1)) == 1 {
				source = nearPrefix(ht, family).Masked()
			}
			routes.Set(source, nearPrefix(ht, family), values[hegel.Draw(ht, pbt.Spanning(0, len(values)-1))])
		}
		set := map[netip.Prefix]bool{}
		for _, entry := range routes.Snapshot() {
			d := entry.Destination.Masked()
			if slices.ContainsFunc(carveOuts, func(c CarveOut) bool { return holds(c.Prefix, d) }) {
				set[d] = true
			}
		}
		want := slices.SortedFunc(maps.Keys(set), comparePrefixes)
		if got := CarvedPrefixes(carveOuts, routes.Snapshot()); !slices.Equal(got, want) {
			ht.Fatalf("inside %v the table holds\n%v\nwant\n%v", carveOuts, got, want)
		}
	})
}

// A lease as wide as the overlay, one inside it and one around it carve the
// lease, the overlay prefix and nothing on lo, and every entry of the table
// inside the lease is carved, this node's own address among them
func TestCarveOutsOfALeaseInsideAroundAndAsWideAsTheOverlay(t *testing.T) {
	p := netip.MustParsePrefix
	overlay := prefixes(p("192.0.2.0/24"), p("3fff::/48"))
	network := NetworkState{
		IPv4: NetworkFamily{Links: []Link{
			{Name: "eth0", Prefixes: []netip.Prefix{p("192.0.2.10/24")}},
			{Name: "lo", Prefixes: []netip.Prefix{p("192.0.2.1/32")}},
			{Name: "wlan0", Prefixes: []netip.Prefix{p("192.0.2.130/25"), p("198.51.100.7/24")}},
		}},
		IPv6: NetworkFamily{Links: []Link{
			{Name: "eth0", Prefixes: []netip.Prefix{p("3fff::10/32")}},
		}},
	}
	got := CarveOuts(network, overlay)
	want := []CarveOut{{"eth0", p("192.0.2.0/24")}, {"eth0", p("3fff::/48")}, {"wlan0", p("192.0.2.128/25")}}
	if !slices.Equal(got, want) {
		t.Fatalf("the carve-outs are %v, want %v", got, want)
	}
	routes := netstack.NewRouteTable()
	routes.Set(netip.Prefix{}, p("192.0.2.77/32"), learned)
	routes.Set(netip.Prefix{}, p("192.0.2.200/32"), netstack.Assigned)
	routes.Set(netip.Prefix{}, p("3fff:0:0:5::/64"), netstack.Unreachable)
	routes.Set(netip.Prefix{}, p("3fff:1::/48"), learned)
	routes.Set(netip.Prefix{}, p("198.51.100.0/24"), netstack.Local)
	if got, want := CarvedPrefixes(got, routes.Snapshot()), []netip.Prefix{p("192.0.2.77/32"), p("192.0.2.200/32"), p("3fff:0:0:5::/64")}; !slices.Equal(got, want) {
		t.Errorf("inside the carve-outs the table holds %v, want %v", got, want)
	}
}
