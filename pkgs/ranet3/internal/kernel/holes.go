// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"cmp"
	"net/netip"
	"slices"
)

// hostTable is the candidate routes one generation of the underlay's selection read, and the interface it leaves out
type hostTable struct {
	routes []hostRoute
	mesh   int
}

// Hole is a route of the mesh's installed as the pieces of it that hold none of Endpoints
type Hole struct {
	Route     netip.Prefix
	Endpoints []netip.Addr
	Pieces    []netip.Prefix
}

// endpoints is every address the underlay sends to beside a selection, Runtime.Underlay's and the live sessions'
// destinations, each once, unmapped and with no zone, as a route's prefix holds them. With no selection it is none, and
// the live sends are not read
func (r *Reconciler) endpoints() []netip.Addr {
	if r.rt.Selection == nil {
		return nil
	}
	var out []netip.Addr
	if r.rt.Underlay != nil {
		out = append(out, r.rt.Underlay()...)
	}
	if r.rt.Sends != nil {
		for _, send := range r.rt.Sends() {
			out = append(out, send.Destination)
		}
	}
	out = slices.DeleteFunc(out, func(address netip.Addr) bool { return !address.IsValid() })
	for i, address := range out {
		out[i] = address.Unmap().WithZone("")
	}
	slices.SortFunc(out, netip.Addr.Compare)
	return slices.Compact(out)
}

// cutHoles is desired with each unscoped route that holds an endpoint E and is
// longer than sel(E) cut around E, unless sel(E) is the family's zero-address
// match, and the holes it cut. A datagram scoped to sel(E)'s interface is
// looked up by rt_lookup_common (bsd/net/route.c), which drops an unscoped
// match on another interface.
// A piece keeps every other field of its route, Cover among them, and gives
// way to an unscoped route of desired, or a piece of a longer route, at its own key
func cutHoles(desired []Route, scoped func(Route) bool, endpoints []netip.Addr, table hostTable) ([]Route, []Hole) {
	type cut struct {
		route     Route
		endpoints []netip.Addr
	}
	var cuts []cut
	var out []Route
	for _, r := range desired {
		var holes []netip.Addr
		if !scoped(r) {
			holes = slices.DeleteFunc(slices.Clone(endpoints), func(endpoint netip.Addr) bool { return !table.shadows(r.Destination, endpoint) })
		}
		if len(holes) == 0 {
			out = append(out, r)
			continue
		}
		cuts = append(cuts, cut{route: r, endpoints: holes})
	}
	if len(cuts) == 0 {
		return desired, nil
	}
	// the kernel keys a scoped route apart from an unscoped one, so only an unscoped route takes a piece's key
	taken := make(map[netip.Prefix]bool, len(out))
	for _, r := range out {
		taken[r.Destination] = taken[r.Destination] || !scoped(r)
	}
	slices.SortStableFunc(cuts, func(a, b cut) int { return cmp.Compare(b.route.Destination.Bits(), a.route.Destination.Bits()) })
	holes := make([]Hole, 0, len(cuts))
	for _, c := range cuts {
		hole := Hole{Route: c.route.Destination, Endpoints: c.endpoints}
		for _, piece := range without(c.route.Destination, c.endpoints) {
			if taken[piece] {
				continue
			}
			taken[piece] = true
			r := c.route
			r.Destination = piece
			out = append(out, r)
			hole.Pieces = append(hole.Pieces, piece)
		}
		holes = append(holes, hole)
	}
	slices.SortFunc(holes, func(a, b Hole) int { return comparePrefixes(a.Route, b.Route) })
	return out, holes
}

// shadows reports a route of ranet3's at destination, unscoped, that a datagram
// scoped to endpoint's selected route would not reach past
func (table hostTable) shadows(destination netip.Prefix, endpoint netip.Addr) bool {
	if endpoint.Is4() != destination.Addr().Is4() || !destination.Contains(endpoint) {
		return false
	}
	selected, ok := selectRoute(table.routes, table.mesh, endpoint, 0)
	if !ok || selected.destination.Bits() >= destination.Bits() {
		return false
	}
	zero := netip.IPv6Unspecified()
	if endpoint.Is4() {
		zero = netip.IPv4Unspecified()
	}
	fallback, ok := selectRoute(table.routes, table.mesh, zero, 0)
	return !ok || selected != fallback
}

// without is the prefixes covering prefix but for the host prefixes of holes,
// at most one per bit of prefix's host part for each hole
func without(prefix netip.Prefix, holes []netip.Addr) []netip.Prefix {
	if !slices.ContainsFunc(holes, prefix.Contains) {
		return []netip.Prefix{prefix}
	}
	bits := prefix.Bits()
	if bits == prefix.Addr().BitLen() {
		return nil
	}
	raw := prefix.Addr().AsSlice()
	raw[bits/8] |= 0x80 >> (bits % 8)
	upper, _ := netip.AddrFromSlice(raw)
	return append(without(netip.PrefixFrom(prefix.Addr(), bits+1), holes), without(netip.PrefixFrom(upper, bits+1), holes)...)
}
