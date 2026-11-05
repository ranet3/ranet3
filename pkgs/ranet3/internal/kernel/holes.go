// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"cmp"
	"net/netip"
	"slices"

	"ranet3.com/pkgs/ranet3/schema"
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

// Beneath is a route of the mesh's installed scoped to the tun beneath Host, a
// route of the host's longer than /0 on another interface holding all of it,
// as row L6 orders the two on Linux
type Beneath struct {
	Route netip.Prefix
	Host  netip.Prefix
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

// part is a route a pass installs, the route of desired it is part of, and the
// endpoints the second cut cuts it around
type part struct {
	route  Route
	of     netip.Prefix
	around []netip.Addr
}

// routeKey is a route's destination and scope, which darwin keys a route on, holding one route a key
type routeKey struct {
	destination netip.Prefix
	scoped      bool
}

// cutHoles is desired with two cuts made, and the holes the second cut.
//
// The first is row L6's. A route that holds a prefix of the overlay, lies
// inside none, carries traffic from no source and lies beneath a route of
// table's is cut around the overlay's prefixes it holds, so each piece outside
// the overlay lies beneath that route and takes L6's scope
// (hostTable.beneath), and each of those prefixes goes in unscoped, as row L3
// sends an address of the overlay into the tun on Linux.
//
// The second cuts each unscoped route that holds an endpoint E and is longer
// than sel(E), a piece of the first cut among them, around E, unless sel(E) is
// the family's zero-address match. A datagram scoped to sel(E)'s interface is
// looked up by rt_lookup_common (bsd/net/route.c), which drops an unscoped
// match on another interface. A hole names the route of desired it was cut
// from.
//
// A piece keeps every other field of its route, Cover among them, and gives
// way to a route not cut, or a piece of a longer route, at its own key.
func cutHoles(desired []Route, scoped func(Route) bool, endpoints []netip.Addr, table hostTable, overlay []schema.Prefix) ([]Route, []Hole) {
	parts := make([]part, len(desired))
	for i, r := range desired {
		parts[i] = part{route: r, of: r.Destination}
	}
	parts = splitParts(parts, scoped, func(p part) ([]netip.Prefix, bool) {
		inside := table.overlaid(p.route, overlay)
		return append(without(p.route.Destination, inside), inside...), len(inside) > 0
	})
	var holes []Hole
	at := make(map[netip.Prefix]int)
	hole := func(of netip.Prefix) *Hole {
		if _, ok := at[of]; !ok {
			at[of] = len(holes)
			holes = append(holes, Hole{Route: of})
		}
		return &holes[at[of]]
	}
	for i, p := range parts {
		if scoped(p.route) {
			continue
		}
		parts[i].around = slices.DeleteFunc(slices.Clone(endpoints), func(endpoint netip.Addr) bool { return !table.shadows(p.route.Destination, endpoint) })
		if len(parts[i].around) > 0 {
			h := hole(p.of)
			h.Endpoints = append(h.Endpoints, parts[i].around...)
		}
	}
	parts = splitParts(parts, scoped, func(p part) ([]netip.Prefix, bool) {
		return without(p.route.Destination, hostPrefixes(p.around...)), len(p.around) > 0
	})
	out := make([]Route, len(parts))
	for i, p := range parts {
		out[i] = p.route
		if len(p.around) > 0 {
			h := hole(p.of)
			h.Pieces = append(h.Pieces, p.route.Destination)
		}
	}
	for i := range holes {
		slices.SortFunc(holes[i].Endpoints, netip.Addr.Compare)
		slices.SortFunc(holes[i].Pieces, comparePrefixes)
	}
	slices.SortFunc(holes, func(a, b Hole) int { return comparePrefixes(a.Route, b.Route) })
	return out, holes
}

// splitParts is parts with each part pieces names pieces for in its place as
// those pieces. A piece keeps every other field of its part, Cover among them,
// and gives way to a part not cut, or a piece of a longer part, at its own key.
func splitParts(parts []part, scoped func(Route) bool, pieces func(part) ([]netip.Prefix, bool)) []part {
	var out []part
	var cuts []int
	split := make(map[int][]netip.Prefix)
	for i, p := range parts {
		prefixes, ok := pieces(p)
		if !ok {
			out = append(out, p)
			continue
		}
		split[i] = prefixes
		cuts = append(cuts, i)
	}
	if len(cuts) == 0 {
		return parts
	}
	key := func(r Route) routeKey { return routeKey{destination: r.Destination, scoped: scoped(r)} }
	taken := make(map[routeKey]bool, len(out))
	for _, p := range out {
		taken[key(p.route)] = true
	}
	slices.SortStableFunc(cuts, func(a, b int) int {
		return cmp.Compare(parts[b].route.Destination.Bits(), parts[a].route.Destination.Bits())
	})
	for _, i := range cuts {
		for _, piece := range split[i] {
			p := parts[i]
			p.route.Destination = piece
			if taken[key(p.route)] {
				continue
			}
			taken[key(p.route)] = true
			out = append(out, p)
		}
	}
	return out
}

// hostPrefixes is each address's host prefix, what without cuts a route around for an endpoint
func hostPrefixes(addresses ...netip.Addr) []netip.Prefix {
	out := make([]netip.Prefix, len(addresses))
	for i, address := range addresses {
		out[i] = netip.PrefixFrom(address, address.BitLen())
	}
	return out
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

// beneath is the route of the host's r lies beneath as row L6 reads it, the
// longest route of the host's holding r (holding), where r's destination
// holds no address of the overlay. On Linux such a route answers ahead of the
// mesh's table at rule 5410 for every address outside the overlay
// (routing.md's row L6), and on darwin one longest match decides, so a mesh
// route beneath it unscoped would take those addresses from it.
func (table hostTable) beneath(r Route, overlay []schema.Prefix) (netip.Prefix, bool) {
	if slices.ContainsFunc(overlay, func(prefix schema.Prefix) bool { return prefix.Overlaps(r.Destination) }) {
		return netip.Prefix{}, false
	}
	return table.holding(r)
}

// overlaid is the prefixes of the overlay r is cut around as row L6 reads it,
// each of them inside r and in no other of them, where r holds one, lies
// inside none and lies beneath a route of the host's but for the overlay
// (holding): its pieces outside them lie beneath that route
func (table hostTable) overlaid(r Route, overlay []schema.Prefix) []netip.Prefix {
	destination := r.Destination.Masked()
	var inside []netip.Prefix
	for _, prefix := range overlay {
		switch held := prefix.Masked(); {
		case !held.Overlaps(destination):
		case held.Bits() <= destination.Bits():
			return nil
		default:
			inside = append(inside, held)
		}
	}
	if _, ok := table.holding(r); !ok {
		return nil
	}
	slices.SortFunc(inside, func(a, b netip.Prefix) int { return cmp.Compare(a.Bits(), b.Bits()) })
	var out []netip.Prefix
	for _, prefix := range inside {
		if !slices.ContainsFunc(out, func(shorter netip.Prefix) bool { return shorter.Contains(prefix.Addr()) }) {
			out = append(out, prefix)
		}
	}
	return out
}

// holding is the longest route of the host's longer than /0, unscoped and out
// of another interface, holding all of r's destination, where r carries
// traffic from no source. A hold and a route from a source are scoped
// already.
func (table hostTable) holding(r Route) (netip.Prefix, bool) {
	if r.Unreachable || r.Source.IsValid() {
		return netip.Prefix{}, false
	}
	destination := r.Destination.Masked()
	var best netip.Prefix
	for _, candidate := range table.routes {
		host := candidate.destination
		if !candidate.candidate(table.mesh) || host.Bits() == 0 || host.Bits() > destination.Bits() ||
			host.Addr().Is4() != destination.Addr().Is4() || !host.Contains(destination.Addr()) {
			continue
		}
		if !best.IsValid() || host.Bits() > best.Bits() {
			best = host.Masked()
		}
	}
	return best, best.IsValid()
}

// without is the prefixes covering prefix but for holes, at most one for each
// bit of prefix's host part for each hole
func without(prefix netip.Prefix, holes []netip.Prefix) []netip.Prefix {
	if !slices.ContainsFunc(holes, prefix.Overlaps) {
		return []netip.Prefix{prefix}
	}
	bits := prefix.Bits()
	if slices.ContainsFunc(holes, func(hole netip.Prefix) bool { return hole.Bits() <= bits && hole.Overlaps(prefix) }) {
		return nil
	}
	raw := prefix.Addr().AsSlice()
	raw[bits/8] |= 0x80 >> (bits % 8)
	upper, _ := netip.AddrFromSlice(raw)
	return append(without(netip.PrefixFrom(prefix.Addr(), bits+1), holes), without(netip.PrefixFrom(upper, bits+1), holes)...)
}
