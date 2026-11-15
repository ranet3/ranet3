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

// holdCutCase is the mesh's routes of a pass, the list the cuts leave of them,
// the families the tun holds no address of, the budget of pieces, and whether
// the platform scopes its holds, as darwin does and linux does not
type holdCutCase struct {
	table  []Route
	routes []Route
	bare   []Family
	budget int
	scopes bool
}

// liveScopedMetric marks a live route the platform scopes, as darwin scopes
// one beneath a route of the host's, and liveMetric one it does not
const (
	liveScopedMetric = 7
	liveMetric       = 8
)

// holdCutTun is the tun's addresses, and holdCutSources the sources a route
// is drawn from: none, a prefix holding the tun's IPv6 address, and one
// holding none of its addresses, whose routes the platform skips
var (
	holdCutTun     = []netip.Prefix{prefix("192.0.2.1/24"), prefix("3fff:c::1/64")}
	holdCutSources = []netip.Prefix{{}, prefix("3fff:c::/48"), prefix("2001:db8:5::/48")}
)

func (c holdCutCase) scoped(r Route) bool {
	return r.Scoped || c.scopes && (r.Unreachable || r.Source.IsValid() || r.Metric == liveScopedMetric)
}

// writes reports a route of a family the tun holds an address of, from no
// source or from the one the generator draws holding the tun's IPv6 address
func (c holdCutCase) writes(r Route) bool {
	family := FamilyIPv6
	if r.Destination.Addr().Is4() {
		family = FamilyIPv4
	}
	return !slices.Contains(c.bare, family) && (!r.Source.IsValid() || r.Source == holdCutSources[1])
}

// carries is a route of table a hold is cut around: one that carries traffic,
// is no host route and that the platform writes
func (c holdCutCase) carries(r Route) bool {
	return !r.Unreachable && !r.Throw && !r.Destination.IsSingleIP() && c.writes(r)
}

func holdCutCases() hegel.Generator[holdCutCase] {
	return hegel.Composite(func(tc hegel.TestCase) holdCutCase {
		c := holdCutCase{budget: hegel.Draw(tc, pbt.Spanning(0, 64)), scopes: hegel.Draw(tc, hegel.WeightedBooleans(7.0/8))}
		for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
			if hegel.Draw(tc, hegel.WeightedBooleans(1.0/8)) {
				c.bare = append(c.bare, family)
			}
		}
		bases := []netip.Addr{hegel.Draw(tc, hegel.IPAddresses().IPv4()), hegel.Draw(tc, hegel.IPAddresses().IPv6())}
		flip := func(address netip.Addr, from int) netip.Addr {
			raw := address.AsSlice()
			for range hegel.Draw(tc, pbt.Spanning(0, 2)) {
				bit := hegel.Draw(tc, pbt.Spanning(from, address.BitLen()-1))
				raw[bit/8] ^= 0x80 >> (bit % 8)
			}
			flipped, _ := netip.AddrFromSlice(raw)
			return flipped
		}
		for range hegel.Draw(tc, pbt.Spanning(1, 12)) {
			// a family's base with a bit or two flipped, so the routes nest and
			// lie beside each other at every length
			base := bases[hegel.Draw(tc, pbt.Spanning(0, 1))]
			r := Route{Destination: netip.PrefixFrom(flip(base, 0), hegel.Draw(tc, pbt.Spanning(0, base.BitLen()))).Masked()}
			// another route's destination, whose key a hold then shares
			if len(c.table) > 0 && hegel.Draw(tc, hegel.WeightedBooleans(1.0/8)) {
				r.Destination = c.table[hegel.Draw(tc, pbt.Spanning(0, len(c.table)-1))].Destination
			}
			r.Metric = liveMetric
			switch hegel.Draw(tc, pbt.Spanning(0, 3)) {
			case 0, 1:
				r.Unreachable, r.Metric = true, uint32(hegel.Draw(tc, pbt.Spanning(0, 2)))
			case 2:
				r.Metric = liveScopedMetric
			}
			if r.Destination.Addr().Is6() {
				r.Source = holdCutSources[hegel.Draw(tc, pbt.Spanning(0, len(holdCutSources)-1))]
			}
			c.table = append(c.table, r)
		}
		// half the time two holds are drawn outright in a family, or in each,
		// the halves of a prefix at the family's base, each with an unscoped
		// live route at its first address, the lower's longer than the upper's,
		// so the lower hold has more pieces than the upper one after it, and in
		// IPv6 half the time a live route from the source the platform skips
		// lies in the upper hold, under one of its pieces
		if hegel.Draw(tc, hegel.Booleans()) {
			for _, base := range [][]netip.Addr{bases[:1], bases[1:], bases}[hegel.Draw(tc, pbt.Spanning(0, 2))] {
				upper := hegel.Draw(tc, pbt.Spanning(1, 4))
				lower := upper + hegel.Draw(tc, pbt.Spanning(1, 4))
				bits := hegel.Draw(tc, pbt.Spanning(1, base.BitLen()-1-lower))
				both := halves(netip.PrefixFrom(base, bits-1).Masked())
				for i, longer := range []int{lower, upper} {
					hold := Route{Destination: both[i], Unreachable: true, Metric: uint32(hegel.Draw(tc, pbt.Spanning(0, 2)))}
					c.table = append(c.table, hold, Route{Destination: netip.PrefixFrom(both[i].Addr(), bits+longer), Metric: liveMetric})
				}
				if base.Is6() && hegel.Draw(tc, hegel.Booleans()) {
					skipped := netip.PrefixFrom(halves(both[1])[1].Addr(), bits+1+hegel.Draw(tc, pbt.Spanning(0, 1)))
					c.table = append(c.table, Route{Destination: skipped, Metric: liveMetric, Source: holdCutSources[2]})
				}
			}
		}
		// the cuts leave a route as its parts around an address of it, a hold
		// longer than the route lying among them
		for _, r := range c.table {
			if r.Unreachable || r.Destination.IsSingleIP() || c.scoped(r) || !hegel.Draw(tc, hegel.WeightedBooleans(1.0/4)) {
				c.routes = append(c.routes, r)
				continue
			}
			address := flip(r.Destination.Addr(), r.Destination.Bits())
			for _, part := range without(r.Destination, hostPrefixes(address)) {
				piece := r
				piece.Destination = part
				c.routes = append(c.routes, piece)
			}
		}
		// the budget stays as drawn, or it is the pieces of the first holds the
		// model cuts, so the last of them meets it exactly, or one less, so that
		// hold goes in whole, or it leaves a hold whole and cuts a later one: the
		// pieces of the holds before the one left whole and of the first hold
		// after it with fewer, which meets what is left exactly, the holds
		// between, none with fewer pieces than the one left whole, going in whole
		// too
		switch _, counts := c.model(); hegel.Draw(tc, pbt.Spanning(0, 2)) {
		case 1:
			sums := []int{0}
			for _, n := range counts {
				if n >= 0 {
					sums = append(sums, sums[len(sums)-1]+n)
				}
			}
			c.budget = max(sums[hegel.Draw(tc, pbt.Spanning(0, len(sums)-1))]-hegel.Draw(tc, pbt.Spanning(0, 1)), 0)
		case 2:
			var budgets []int
			before := 0
			for i, n := range counts {
				if n < 0 {
					continue
				}
				if j := slices.IndexFunc(counts[i+1:], func(m int) bool { return m >= 0 && m < n }); j >= 0 {
					budgets = append(budgets, before+counts[i+1+j])
				}
				before += n
			}
			if len(budgets) > 0 {
				c.budget = budgets[hegel.Draw(tc, pbt.Spanning(0, len(budgets)-1))]
			}
		}
		return c
	})
}

// model is the holds the model takes of c's routes, the IPv6 ones first, each
// family in compareRoutes order: scoped, written and alone at their key among
// the routes written there, and the pieces each is cut into, counted by the
// tree's own halving (without) around its outermost live routes, or -1 for one
// with no unscoped live route inside it
func (c holdCutCase) model() ([]Route, []int) {
	var holds []Route
	for _, r := range c.routes {
		alone := !slices.ContainsFunc(c.routes, func(o Route) bool {
			return o != r && o.Destination == r.Destination && c.scoped(o) && c.writes(o)
		})
		if r.Unreachable && c.scoped(r) && c.writes(r) && alone && !slices.Contains(holds, r) {
			holds = append(holds, r)
		}
	}
	slices.SortFunc(holds, func(a, b Route) int {
		if a4, b4 := a.Destination.Addr().Is4(), b.Destination.Addr().Is4(); a4 != b4 {
			return boolOrder(a4) - boolOrder(b4)
		}
		return compareRoutes(a, b)
	})
	counts := make([]int, len(holds))
	for i, hold := range holds {
		live := c.inside(hold.Destination)
		counts[i] = -1
		if slices.ContainsFunc(live, func(r Route) bool { return !c.scoped(r) }) {
			counts[i] = len(without(hold.Destination, outermostOf(live)))
		}
	}
	return holds, counts
}

// inside is the routes of the table strictly inside hold that it is cut around
func (c holdCutCase) inside(hold netip.Prefix) []Route {
	return slices.DeleteFunc(slices.Clone(c.table), func(r Route) bool {
		return !c.carries(r) || r.Destination.Bits() <= hold.Bits() || !hold.Contains(r.Destination.Addr())
	})
}

// outermostOf is each prefix of routes that no other of them holds
func outermostOf(routes []Route) []netip.Prefix {
	var out []netip.Prefix
	for _, r := range routes {
		if !slices.ContainsFunc(routes, func(o Route) bool {
			return o.Destination.Bits() < r.Destination.Bits() && o.Destination.Contains(r.Destination.Addr())
		}) && !slices.Contains(out, r.Destination) {
			out = append(out, r.Destination)
		}
	}
	return out
}

// tiles reports whether pieces and holes, taken as runs of addresses, hold
// each address of hold once and none outside it
func tiles(hold netip.Prefix, pieces, holes []netip.Prefix) bool {
	all := append(slices.Clone(pieces), holes...)
	slices.SortFunc(all, comparePrefixes)
	next := hold.Addr()
	for i, p := range all {
		if p.Addr() != next {
			return false
		}
		if i == len(all)-1 {
			return lastAddress(p) == lastAddress(hold)
		}
		next = lastAddress(p).Next()
	}
	return false
}

// borders is the first and last address of each prefix and the addresses just
// outside it, those of them inside hold
func borders(hold netip.Prefix, prefixes []netip.Prefix) []netip.Addr {
	var out []netip.Addr
	for _, p := range append([]netip.Prefix{hold}, prefixes...) {
		for _, a := range []netip.Addr{p.Addr(), p.Addr().Prev(), lastAddress(p), lastAddress(p).Next()} {
			if a.IsValid() && hold.Contains(a) {
				out = append(out, a)
			}
		}
	}
	return out
}

// Over drawn routes of both families, from no source, one of the tun's and
// one the platform skips, beside them half the time two holds of fewer pieces
// in turn drawn outright in a family or in both, the list the cuts leave of
// them, and a budget drawn, met at a hold's edge or met by a later hold after
// one left whole: the holds cut are those the model takes with an
// unscoped live route of the mesh's own list inside them, in its order, each
// cut while its pieces fit in what is left. Every route but the holds cut is
// in the list as handed in, and the pieces follow, no more than the budget. By
// address membership, every address of a cut hold under no longer such route
// of the mesh, written or scoped, is held by one piece, or by a route written
// at the piece's key, and every address under one by none, and the parent of
// each piece holds an address of such a route.
func TestHoldsAreCutAroundTheirLiveRoutesWithinTheBudget(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		c := hegel.Draw(ht, holdCutCases())
		table, routes := slices.Clone(c.table), slices.Clone(c.routes)
		out, made := cutHolds(c.routes, c.table, c.scoped, holdCutTun, c.bare, c.budget)
		if !slices.Equal(c.routes, routes) || !slices.Equal(c.table, table) {
			ht.Fatalf("the cut changed the lists it was handed")
		}
		holds, counts := c.model()
		left, whole := c.budget, 0
		var cut []Route
		for i, hold := range holds {
			switch n := counts[i]; {
			case n < 0:
			case n <= left:
				left -= n
				cut = append(cut, hold)
			default:
				whole++
			}
		}
		kept := slices.DeleteFunc(slices.Clone(routes), func(r Route) bool { return slices.Contains(cut, r) })
		if len(out) < len(kept) || !slices.Equal(out[:len(kept)], kept) {
			ht.Fatalf("the list is %+v, want it to begin with %+v, the routes handed in but the holds %+v the model cuts", out, kept, cut)
		}
		pieces := out[len(kept):]
		if made.pieces != len(pieces) || made.whole != whole || len(pieces) > c.budget {
			ht.Fatalf("the cut made %+v with %d pieces under a budget of %d, want %d holds left whole\nroutes %+v\nout %+v", made, len(pieces), c.budget, whole, routes, out)
		}
		var prefixes []netip.Prefix
		for _, r := range append(append(slices.Clone(table), routes...), pieces...) {
			prefixes = append(prefixes, r.Destination)
		}
		longest := func(of []Route, a netip.Addr) int {
			bits := -1
			for _, r := range of {
				if r.Destination.Contains(a) {
					bits = max(bits, r.Destination.Bits())
				}
			}
			return bits
		}
		for _, piece := range pieces {
			parent := netip.PrefixFrom(piece.Destination.Addr(), piece.Destination.Bits()-1).Masked()
			own := slices.ContainsFunc(cut, func(hold Route) bool {
				of := hold
				of.Destination, of.Scoped = piece.Destination, true
				return of == piece && encloses(hold.Destination, parent)
			})
			fewest := slices.ContainsFunc(cut, func(hold Route) bool {
				return encloses(hold.Destination, parent) && slices.ContainsFunc(c.inside(hold.Destination), func(r Route) bool { return parent.Overlaps(r.Destination) })
			})
			if !own || !fewest {
				ht.Fatalf("%+v is no piece of a cut hold %+v with its fields, or its parent holds no route of the mesh's inside one", piece, cut)
			}
		}
		for _, hold := range cut {
			for _, a := range borders(hold.Destination, prefixes) {
				held := 0
				for _, piece := range pieces {
					if piece.Destination.Contains(a) {
						held++
					}
				}
				lived := longest(slices.DeleteFunc(slices.Clone(table), func(r Route) bool { return !c.carries(r) }), a)
				switch {
				case lived > longest(cut, a) && held > 0:
					ht.Fatalf("%s lies in a route of the mesh's longer than the cut holds holding it, and in %d pieces\nroutes %+v\nout %+v", a, held, routes, out)
				case lived <= longest(cut, a) && held > 1:
					ht.Fatalf("%s of the cut hold %s lies in %d pieces\nout %+v", a, hold.Destination, held, out)
				case lived <= longest(cut, a) && held == 0 && !slices.ContainsFunc(kept, func(r Route) bool {
					return r.Destination.Contains(a) && encloses(hold.Destination, r.Destination) && r.Destination != hold.Destination && c.scoped(r) && c.writes(r)
				}):
					ht.Fatalf("%s of the cut hold %s lies in no longer route of the mesh's, no piece and no route written in a piece's place\nroutes %+v\nout %+v", a, hold.Destination, routes, out)
				}
			}
		}
	})
}
