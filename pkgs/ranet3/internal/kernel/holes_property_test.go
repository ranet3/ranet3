// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package kernel

import (
	"net/netip"
	"slices"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// holeCase is one host table, the endpoints the underlay sends to, and the routes a pass desires, each scoped or not
type holeCase struct {
	table     hostTable
	endpoints []netip.Addr
	desired   []Route
	scoped    map[Route]bool
}

// holeBits is the length of a desired route drawn around endpoint: the host
// route's that endpoint selects, one past it, 0, 1, a host route, or any
func holeBits(tc hegel.TestCase, table hostTable, endpoint netip.Addr) int {
	selected, ok := selectRoute(table.routes, table.mesh, endpoint, 0)
	bitLen := endpoint.BitLen()
	choices := []int{0, 1, bitLen, hegel.Draw(tc, pbt.Spanning(0, bitLen))}
	if ok {
		choices = append(choices, selected.destination.Bits(), min(selected.destination.Bits()+1, bitLen))
	}
	return choices[hegel.Draw(tc, pbt.Spanning(0, len(choices)-1))]
}

// add puts r among the desired routes, scoped where it carries metric 1 or holds against the FIB. Every unscoped
// route gets a metric of its own, so a piece names the route it came from
func (c *holeCase) add(r Route, scoped bool) {
	if scoped || r.Unreachable {
		r.Metric = 1
	} else {
		r.Metric = uint32(2 + len(c.desired))
	}
	c.desired = append(c.desired, r)
	c.scoped[r] = r.Metric == 1
}

func holeCases() hegel.Generator[holeCase] {
	return hegel.Composite(func(tc hegel.TestCase) holeCase {
		bases := []netip.Addr{hegel.Draw(tc, hegel.IPAddresses().IPv4()), hegel.Draw(tc, hegel.IPAddresses().IPv6())}
		c := holeCase{table: hostTable{mesh: selectMesh}, scoped: map[Route]bool{}}
		for range hegel.Draw(tc, pbt.Spanning(0, 8)) {
			address := selectAddress(tc, bases[hegel.Draw(tc, pbt.Spanning(0, 1))])
			c.table.routes = append(c.table.routes, hostRoute{
				destination: netip.PrefixFrom(address, hegel.Draw(tc, pbt.Spanning(0, address.BitLen()))).Masked(),
				index:       hegel.Draw(tc, hegel.SampledFrom(selectIndexes)),
				scoped:      hegel.Draw(tc, hegel.WeightedBooleans(1.0/5)),
			})
		}
		// a route holding each family's zero address, a /0 or a /1, or none
		for _, zero := range []netip.Addr{netip.IPv4Unspecified(), netip.IPv6Unspecified()} {
			if hegel.Draw(tc, hegel.WeightedBooleans(1.0/2)) {
				c.table.routes = append(c.table.routes, hostRoute{
					destination: netip.PrefixFrom(zero, hegel.Draw(tc, pbt.Spanning(0, 1))),
					index:       hegel.Draw(tc, hegel.SampledFrom(selectIndexes[1:])),
				})
			}
		}
		for range hegel.Draw(tc, pbt.Spanning(1, 3)) {
			c.endpoints = append(c.endpoints, selectAddress(tc, bases[hegel.Draw(tc, pbt.Spanning(0, 1))]))
		}
		type around struct {
			route    netip.Prefix
			endpoint netip.Addr
		}
		var nested []around
		for _, endpoint := range slices.Clone(c.endpoints) {
			for range hegel.Draw(tc, pbt.Spanning(1, 3)) {
				r := Route{
					Destination: netip.PrefixFrom(endpoint, holeBits(tc, c.table, endpoint)).Masked(),
					Cover:       hegel.Draw(tc, hegel.WeightedBooleans(1.0/4)),
					Unreachable: hegel.Draw(tc, hegel.WeightedBooleans(1.0/8)),
				}
				c.add(r, hegel.Draw(tc, hegel.WeightedBooleans(1.0/5)))
				// an endpoint at the route's first or last address
				switch hegel.Draw(tc, pbt.Spanning(0, 2)) {
				case 1:
					c.endpoints = append(c.endpoints, r.Destination.Addr())
				case 2:
					c.endpoints = append(c.endpoints, lastAddress(r.Destination))
				}
			}
			// two unscoped routes nested around the endpoint, both longer than its host route, so both are cut and
			// share the pieces below the longer one
			selected, ok := selectRoute(c.table.routes, c.table.mesh, endpoint, 0)
			if bitLen := endpoint.BitLen(); ok && selected.destination.Bits()+2 <= bitLen && hegel.Draw(tc, hegel.WeightedBooleans(1.0/2)) {
				outer := hegel.Draw(tc, pbt.Spanning(selected.destination.Bits()+1, bitLen-1))
				inner := hegel.Draw(tc, pbt.Spanning(outer+1, bitLen))
				for _, bits := range []int{outer, inner} {
					route := netip.PrefixFrom(endpoint, bits).Masked()
					c.add(Route{Destination: route, Cover: hegel.Draw(tc, hegel.Booleans())}, false)
					nested = append(nested, around{route: route, endpoint: endpoint})
				}
			}
		}
		// a route at the key of a piece a nested route is cut into, one scoped and one not, which the piece gives way to
		// only where it is unscoped
		if len(nested) > 0 {
			at := nested[hegel.Draw(tc, pbt.Spanning(0, len(nested)-1))]
			pieces := without(at.route, hostPrefixes(at.endpoint))
			for _, scoped := range []bool{true, false} {
				if len(pieces) > 0 && hegel.Draw(tc, hegel.WeightedBooleans(3.0/4)) {
					c.add(Route{Destination: pieces[hegel.Draw(tc, pbt.Spanning(0, len(pieces)-1))]}, scoped)
				}
			}
		}
		slices.SortFunc(c.endpoints, netip.Addr.Compare)
		c.endpoints = slices.Compact(c.endpoints)
		return c
	})
}

// zeroOf is the family's zero address of address
func zeroOf(address netip.Addr) netip.Addr {
	if address.Is4() {
		return netip.IPv4Unspecified()
	}
	return netip.IPv6Unspecified()
}

// longest is the index of the interface the longest unscoped route holding address leaves by, over the host's
// candidate routes and the mesh's unscoped routes, the host's winning a tie, since the kernel refuses an unscoped
// route at a key the host holds, and false for none
func (c holeCase) longest(mesh []Route, address netip.Addr) (int, bool) {
	var best netip.Prefix
	index := 0
	for _, r := range c.table.routes {
		if r.candidate(c.table.mesh) && r.destination.Contains(address) && (!best.IsValid() || r.destination.Bits() > best.Bits()) {
			best, index = r.destination, r.index
		}
	}
	for _, r := range mesh {
		if r.Destination.Contains(address) && (!best.IsValid() || r.Destination.Bits() > best.Bits()) {
			best, index = r.Destination, c.table.mesh
		}
	}
	return index, best.IsValid()
}

// reaches models rt_lookup_common (bsd/net/route.c) for a datagram to
// endpoint scoped to the interface of its selected route, over the host's
// routes and the mesh's unscoped routes: the longest unscoped match is kept
// only where it leaves by that interface, then the longest route scoped to
// that interface answers, then the family's zero-address match where it
// leaves by that interface. Strict is the lookup the cut answers for: no
// route scoped to the interface, and no zero-address match but the selected
// route itself.
func (c holeCase) reaches(mesh []Route, endpoint netip.Addr, strict bool) bool {
	selected, ok := selectRoute(c.table.routes, c.table.mesh, endpoint, 0)
	if !ok {
		return true
	}
	if index, ok := c.longest(mesh, endpoint); ok && index == selected.index {
		return true
	}
	if strict {
		zero, ok := selectRoute(c.table.routes, c.table.mesh, zeroOf(endpoint), 0)
		return ok && zero == selected
	}
	if slices.ContainsFunc(c.table.routes, func(r hostRoute) bool {
		return r.scoped && r.index == selected.index && r.destination.Contains(endpoint)
	}) {
		return true
	}
	index, ok := c.longest(mesh, zeroOf(endpoint))
	return ok && index == selected.index
}

// longestHolding is the routes of routes at the longest destination holding address
func longestHolding(routes []Route, address netip.Addr) []Route {
	var out []Route
	for _, r := range routes {
		switch {
		case !r.Destination.Contains(address):
		case len(out) == 0 || r.Destination.Bits() > out[0].Destination.Bits():
			out = []Route{r}
		case r.Destination.Bits() == out[0].Destination.Bits():
			out = append(out, r)
		}
	}
	return out
}

// probes are the addresses the property asks about: each endpoint, its neighbors, each address one bit from it, one
// in each piece a route holding it is cut into, and each route's first and last address
func (c holeCase) probes() []netip.Addr {
	var out []netip.Addr
	for _, endpoint := range c.endpoints {
		out = append(out, endpoint, endpoint.Prev(), endpoint.Next())
		for bit := range endpoint.BitLen() {
			raw := endpoint.AsSlice()
			raw[bit/8] ^= 0x80 >> (bit % 8)
			address, _ := netip.AddrFromSlice(raw)
			out = append(out, address)
		}
	}
	for _, r := range c.desired {
		out = append(out, r.Destination.Addr(), lastAddress(r.Destination))
	}
	return slices.DeleteFunc(out, func(address netip.Addr) bool { return !address.IsValid() })
}

// Over drawn routes, endpoints and host tables: after the transform a datagram
// to each endpoint scoped to its selected route's interface reaches that
// interface by rt_lookup_common, wherever the mesh's unscoped routes hold no
// zero address, as every darwin pass keeps them. The unscoped routes hold every
// address they held but the endpoints whose lookup over one route alone does
// not reach, the scoped routes are as they were, each piece carries the fields
// of the longest unscoped route holding it before the transform, as the longest
// unscoped routes holding an address but an endpoint carry the fields of one
// longest holding it before, no key holds two unscoped routes it did not hold
// before, and a route cut around k endpoints goes in as at most k times its
// host bits pieces.
func TestHolesLetEachEndpointPastTheMesh(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		c := hegel.Draw(ht, holeCases())
		scoped := func(r Route) bool { return c.scoped[r] }
		out, holes := cutHoles(c.desired, scoped, c.endpoints, c.table, nil)
		var unscopedIn, unscopedOut []Route
		for _, r := range c.desired {
			if !scoped(r) {
				unscopedIn = append(unscopedIn, r)
			}
		}
		for _, r := range out {
			if scoped(r) {
				continue
			}
			unscopedOut = append(unscopedOut, r)
			if slices.Contains(c.desired, r) {
				continue
			}
			if !slices.ContainsFunc(holes, func(h Hole) bool { return slices.Contains(h.Pieces, r.Destination) }) {
				ht.Fatalf("%s is in no hole's pieces and was not desired\nholes %+v", r, holes)
			}
			var matched Route
			for _, whole := range unscopedIn {
				if whole.Destination.Bits() <= r.Destination.Bits() && whole.Destination.Contains(r.Destination.Addr()) &&
					(!matched.Destination.IsValid() || whole.Destination.Bits() > matched.Destination.Bits()) {
					matched = whole
				}
			}
			if matched.Destination = r.Destination; matched != r {
				ht.Fatalf("the piece %+v carries other fields than the longest unscoped route holding it before the cut\ndesired %+v", r, c.desired)
			}
		}
		for _, r := range c.desired {
			if scoped(r) && !slices.Contains(out, r) {
				ht.Fatalf("the scoped %s left the routes\nout %+v", r, out)
			}
		}
		for _, r := range out {
			if scoped(r) && !slices.Contains(c.desired, r) {
				ht.Fatalf("the scoped %s was not desired\ndesired %+v", r, c.desired)
			}
		}
		for _, endpoint := range c.endpoints {
			zeroFree := !slices.ContainsFunc(unscopedOut, func(r Route) bool { return r.Destination.Contains(zeroOf(endpoint)) })
			if zeroFree && !c.reaches(unscopedOut, endpoint, false) {
				ht.Fatalf("a datagram to %s scoped to its host route's interface does not reach it\nout %+v\ntable %+v", endpoint, out, c.table.routes)
			}
		}
		for _, address := range c.probes() {
			want := slices.ContainsFunc(unscopedIn, func(r Route) bool {
				return r.Destination.Contains(address) && (!slices.Contains(c.endpoints, address) || c.reaches([]Route{r}, address, true))
			})
			got := slices.ContainsFunc(unscopedOut, func(r Route) bool { return r.Destination.Contains(address) })
			if got != want {
				ht.Fatalf("the unscoped routes hold %s %v, want %v\ndesired %+v\nout %+v\ntable %+v\nendpoints %v", address, got, want, c.desired, out, c.table.routes, c.endpoints)
			}
			if slices.Contains(c.endpoints, address) {
				continue
			}
			before := longestHolding(unscopedIn, address)
			for _, r := range longestHolding(unscopedOut, address) {
				if !slices.ContainsFunc(before, func(whole Route) bool { whole.Destination = r.Destination; return whole == r }) {
					ht.Fatalf("%s ends at %+v, want the fields of one of %+v\ndesired %+v\nout %+v", address, r, before, c.desired, out)
				}
			}
		}
		at := func(routes []Route, destination netip.Prefix) int {
			return len(slices.DeleteFunc(slices.Clone(routes), func(r Route) bool { return r.Destination != destination }))
		}
		for _, r := range unscopedOut {
			if n := at(unscopedOut, r.Destination); n > 1 && n > at(unscopedIn, r.Destination) {
				ht.Fatalf("%d unscoped routes take the key %s, which %d desired routes took\nout %+v", n, r.Destination, at(unscopedIn, r.Destination), out)
			}
		}
		for _, h := range holes {
			if bound := len(h.Endpoints) * (h.Route.Addr().BitLen() - h.Route.Bits()); len(h.Pieces) > bound {
				ht.Fatalf("%s cut around %v goes in as %d pieces, more than %d", h.Route, h.Endpoints, len(h.Pieces), bound)
			}
		}
	})
}
