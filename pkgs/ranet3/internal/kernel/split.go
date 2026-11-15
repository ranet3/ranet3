// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"encoding/binary"
	"math/bits"
	"net/netip"
	"slices"
	"sort"

	"ranet3.com/pkgs/ranet3/schema"
)

// holdKeyer is a platform that writes the overlay's holds apart from the tun,
// in the key space of the tun's unscoped routes, as darwin writes them on lo0.
// heldApart reports a route it writes so.
type holdKeyer interface{ heldApart(Route) bool }

// overlayKeys is each prefix of overlay in the form the kernel keys it, where
// an overlay hold sits
func overlayKeys(overlay []schema.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for _, entry := range overlay {
		if destination, ok := canonicalPrefix(entry.Prefix); ok {
			out = append(out, destination)
		}
	}
	return out
}

// cutAround is routes with cut's holes cut out of the tun's routes, each at
// one of keys going in as its halves before the cut, so a hole names the half
// the kernel holds, and again after it, so a piece the cut leaves at a key of
// the switch's goes in as its halves too. Before the cut each of rejected a
// shorter route of the tun's holds goes in as its halves as well
// (halvesInside). A hold keyer writes apart from the tun is no route of the
// tun's to cut and goes in beside the pieces, and the routes the cut and the
// splits leave give way to it (givesWay).
func cutAround(routes []Route, keys, rejected []netip.Prefix, keyer holdKeyer, scoped func(Route) bool, hosts hostTable, cut func([]Route) ([]Route, []Hole)) ([]Route, []Hole) {
	var tun, held []Route
	for _, r := range routes {
		if keyer != nil && keyer.heldApart(r) {
			held = append(held, r)
		} else {
			tun = append(tun, r)
		}
	}
	whole := halvesInside(splitAtKeys(tun, keys, scoped), rejected, scoped, hosts)
	pieces, holes := cut(whole)
	return append(givesWay(splitAtKeys(pieces, keys, scoped), tun, held, scoped), held...), holes
}

// givesWay is routes but each unscoped one that lies at or inside a hold of
// held and is part of an unscoped route of tun shorter than that hold. A piece
// or a half of a route gives way to a longer route's at its key (splitParts,
// splitAtKeys), so the unscoped route of tun a route is part of is the longest
// one holding it. The hold then answers every unbound lookup of its prefix
// that no unscoped route of tun at or inside the prefix holds, as linux's hold
// does beneath every route of the mesh shorter than it (routing.md row L4),
// and a route at or inside the prefix answers by length as there. An unbound
// lookup the hold matches leaves by lo0 and so passes a route scoped to the
// tun over, a route from a source or a hold of the mesh's, so that route holds
// no address of the prefix for the hold to give back.
func givesWay(routes, tun, held []Route, scoped func(Route) bool) []Route {
	return slices.DeleteFunc(routes, func(r Route) bool {
		hold, of := -1, -1
		for _, h := range held {
			if encloses(h.Destination, r.Destination) {
				hold = max(hold, h.Destination.Bits())
			}
		}
		if hold < 0 || scoped(r) {
			return false
		}
		for _, t := range tun {
			if !scoped(t) && encloses(t.Destination, r.Destination) {
				of = max(of, t.Destination.Bits())
			}
		}
		return of < hold
	})
}

// halvesInside is routes with the halves of each of keys that a shorter
// unscoped route of routes holds, with the fields of the longest such route,
// so they win over the platform's reject at the key as that route wins where
// linux's switch filters the uplink instead. A half gives way to a route at
// its own key, the halves of a route at the key among them. A key a route of
// hosts as long as that route or longer holds gets no halves, since that route
// of the host's answers ahead of it there.
func halvesInside(routes []Route, keys []netip.Prefix, scoped func(Route) bool, hosts hostTable) []Route {
	key := func(r Route) routeKey { return routeKey{destination: r.Destination, scoped: scoped(r)} }
	taken := make(map[routeKey]bool, len(routes))
	for _, r := range routes {
		taken[key(r)] = true
	}
	out := slices.Clip(routes)
	for _, at := range keys {
		var holder Route
		for _, r := range routes {
			bits := r.Destination.Bits()
			if !scoped(r) && bits < at.Bits() && r.Destination.Contains(at.Addr()) && (!holder.Destination.IsValid() || bits > holder.Destination.Bits()) {
				holder = r
			}
		}
		if !holder.Destination.IsValid() {
			continue
		}
		if host, ok := hosts.holding(Route{Destination: at}); ok && host.Bits() >= holder.Destination.Bits() {
			continue
		}
		for _, half := range halves(at) {
			piece := holder
			piece.Destination = half
			if !taken[key(piece)] {
				taken[key(piece)] = true
				out = append(out, piece)
			}
		}
	}
	return out
}

// splitAtKeys is desired with each unscoped route of the tun's at one of keys
// in its place as its two halves, which keep every other field, Cover among
// them, a half at another of keys in its place as its halves in turn. A
// platform whose own routes beside the tun's are keyed as the tun's
// are, darwin's switch rejects and overlay holds, holds one route a key and
// mask, so a route of ours and one of the platform's at one key cannot both go
// in (bsd/net/radix.c rn_addroute). A scoped route is keyed apart and stays
// whole, and so does a route at a full-length key, which the platform keys
// apart as a host route with no mask. A half gives way to a route at its own
// key, and one key's halves go in once. desired holds no hold the platform
// writes apart, the route at its key the halves make room for.
func splitAtKeys(desired []Route, keys []netip.Prefix, scoped func(Route) bool) []Route {
	at := func(r Route) bool { return !scoped(r) && slices.Contains(keys, r.Destination) }
	if !slices.ContainsFunc(desired, at) {
		return desired
	}
	key := func(r Route) routeKey { return routeKey{destination: r.Destination, scoped: scoped(r)} }
	out := make([]Route, 0, len(desired)+len(keys))
	taken := make(map[routeKey]bool, len(desired))
	for _, r := range desired {
		if !at(r) {
			out = append(out, r)
			taken[key(r)] = true
		}
	}
	for _, r := range desired {
		if !at(r) {
			continue
		}
		var pieces []netip.Prefix
		for next := []netip.Prefix{r.Destination}; len(next) > 0; next = next[1:] {
			if halved := halves(next[0]); len(halved) > 0 && slices.Contains(keys, next[0]) {
				next = append(next, halved...)
			} else {
				pieces = append(pieces, next[0])
			}
		}
		for _, half := range pieces {
			piece := r
			piece.Destination = half
			if taken[key(piece)] {
				continue
			}
			taken[key(piece)] = true
			out = append(out, piece)
		}
	}
	return out
}

// halves is prefix's two halves, none for a full-length prefix
func halves(prefix netip.Prefix) []netip.Prefix {
	if prefix.IsSingleIP() {
		return nil
	}
	bits := prefix.Bits()
	raw := prefix.Addr().AsSlice()
	raw[bits/8] |= 0x80 >> (bits % 8)
	upper, _ := netip.AddrFromSlice(raw)
	return []netip.Prefix{netip.PrefixFrom(prefix.Addr(), bits+1), netip.PrefixFrom(upper, bits+1)}
}

// splitKeys is the keys a route of ours out of the tun goes in as its halves
// at in a pass wanting desired: the switch's rejects' on a platform writing it
// as routes, wherever the pass asks for it or one is left in from an earlier
// pass, and in every mode the key of each hold of desired the platform writes
// apart from the tun. rejected is the rejects' keys alone.
func (r *Reconciler) splitKeys(desired []Route) (keys, rejected []netip.Prefix) {
	if switched := r.switchForm().keys; switched != nil && (r.switchAsked || !r.fallbackClear) {
		keys, rejected = slices.Clone(switched), switched
	}
	if r.keyer != nil {
		for _, route := range desired {
			if r.keyer.heldApart(route) {
				keys = append(keys, route.Destination)
			}
		}
	}
	return keys, rejected
}

// holdCut counts the pieces cutHolds put in the list in place of the holds it
// cut, and the holds it left whole because their pieces would pass what was
// left of the budget
type holdCut struct{ pieces, whole int }

// platformWrites reports whether r is of a family addressless does not name,
// and from no source or from one holding an address of tun's: the two tests
// darwin's AddRoute skips a route by before it writes. A route that passes
// them may still be refused there: at a scoped key it already holds for
// another source, at a key another program holds, at the limited broadcast
// address, which no pass hands it, or where reading the tun's addresses or
// the write fails.
func platformWrites(r Route, tun []netip.Prefix, addressless []Family) bool {
	return !slices.Contains(addressless, familyOf(r.Destination.Addr())) &&
		(!r.Source.IsValid() || slices.ContainsFunc(tun, func(address netip.Prefix) bool { return r.Source.Contains(address.Addr()) }))
}

// cutHolds is routes with each hold the platform scopes and writes cut around
// the routes of table inside it that carry traffic and that the platform
// writes, where an unscoped one is among them. table is the list before the
// cover and the cuts, which leave parts of a shorter route inside a hold, and
// such a part is no reason to cut it. A reject scoped to the tun answers an
// IPv6 lookup ahead of a longer unscoped route out of the tun but not ahead of
// a host route (rt_lookup_common, bsd/net/route.c), so a host route is no
// reason to cut and a piece holds its address. A scoped route answers by its
// own length, so it alone is no reason to cut, and no piece lies inside it.
// The IPv6 holds take the budget first, since the refusal a cut ends is of
// IPv6 datagrams (in6_selectif, bsd/netinet6/in6_src.c), then the IPv4 holds
// take what is left. Within a family the holds go in the order diffRoutes
// lists them in, so every node cuts the same ones of a table, and each is cut
// while its pieces fit in what budget has left, a hold inside a cut hold
// counting the pieces it shares with it again. A hold the platform keeps one
// of at its key goes in whole.
func cutHolds(routes, table []Route, scoped func(Route) bool, tun []netip.Prefix, addressless []Family, budget int) ([]Route, holdCut) {
	writes := func(r Route) bool { return platformWrites(r, tun, addressless) }
	var holds []Route
	for _, r := range routes {
		if r.Unreachable && scoped(r) && writes(r) {
			holds = append(holds, r)
		}
	}
	if len(holds) == 0 {
		return routes, holdCut{}
	}
	alone := make(map[netip.Prefix]Route, len(holds))
	for _, hold := range holds {
		alone[hold.Destination] = hold
	}
	for _, r := range routes {
		if hold, found := alone[r.Destination]; found && hold != r && scoped(r) && writes(r) {
			delete(alone, r.Destination)
		}
	}
	holds = slices.DeleteFunc(holds, func(hold Route) bool { _, found := alone[hold.Destination]; return !found })
	slices.SortFunc(holds, compareRoutes)
	holds = slices.Compact(holds)
	// prefixes nest or lie apart, so the holds no other hold holds are disjoint
	// and in address order, and one of them holds each address a hold does
	var outermost []netip.Prefix
	for _, hold := range holds {
		if len(outermost) == 0 || !encloses(outermost[len(outermost)-1], hold.Destination) {
			outermost = append(outermost, hold.Destination)
		}
	}
	insideHold := func(destination netip.Prefix) bool {
		i := sort.Search(len(outermost), func(i int) bool { return comparePrefixes(outermost[i], destination) > 0 }) - 1
		return i >= 0 && outermost[i].Bits() < destination.Bits() && outermost[i].Contains(destination.Addr())
	}
	var live []liveRoute
	unscoped := false
	for _, r := range table {
		if !r.Unreachable && !r.Throw && !r.Destination.IsSingleIP() && insideHold(r.Destination) && writes(r) {
			live = append(live, liveRoute{destination: r.Destination, first: wordOf(r.Destination.Addr()), scoped: scoped(r)})
			unscoped = unscoped || !scoped(r)
		}
	}
	if !unscoped {
		return routes, holdCut{}
	}
	slices.SortFunc(live, func(a, b liveRoute) int { return comparePrefixes(a.destination, b.destination) })
	writtenAt := map[netip.Prefix]bool{}
	for _, r := range routes {
		if insideHold(r.Destination) && scoped(r) && writes(r) {
			writtenAt[r.Destination] = true
		}
	}
	var counts holdCut
	var pieces []Route
	cut := map[Route]bool{}
	left := budget
	ipv6 := sort.Search(len(holds), func(i int) bool { return holds[i].Destination.Addr().Is6() })
	for _, hold := range slices.Concat(holds[ipv6:], holds[:ipv6]) {
		lo, hi := liveInside(live, hold.Destination)
		if !slices.ContainsFunc(live[lo:hi], func(r liveRoute) bool { return !r.scoped }) {
			continue
		}
		n, fits := holdPieces(hold.Destination, live[lo:hi], left)
		if !fits {
			counts.whole++
			continue
		}
		left -= n
		cut[hold] = true
		for _, destination := range holdPiecesOf(hold.Destination, live[lo:hi]) {
			if !writtenAt[destination] {
				writtenAt[destination] = true
				piece := hold
				piece.Destination, piece.Scoped = destination, true
				pieces = append(pieces, piece)
			}
		}
	}
	if len(cut) == 0 {
		return routes, counts
	}
	out := make([]Route, 0, len(routes)+len(pieces))
	for _, r := range routes {
		if !r.Unreachable || !cut[r] {
			out = append(out, r)
		}
	}
	counts.pieces = len(pieces)
	return append(out, pieces...), counts
}

// liveRoute is a route a hold is cut around: its destination, the
// destination's first address as a word128, and whether the platform scopes it
type liveRoute struct {
	destination netip.Prefix
	first       word128
	scoped      bool
}

// liveInside is the run of live, sorted by comparePrefixes, that lies inside
// prefix and is longer than it
func liveInside(live []liveRoute, prefix netip.Prefix) (lo, hi int) {
	lo = sort.Search(len(live), func(i int) bool { return comparePrefixes(live[i].destination, prefix) > 0 })
	last := lastAddress(prefix)
	hi = lo + sort.Search(len(live)-lo, func(i int) bool { return live[lo+i].destination.Addr().Compare(last) > 0 })
	return lo, hi
}

// holdGaps calls each, until it returns false, with each run of hold's
// addresses outside the live routes inside it, in address order. A run is the
// part before or after the outermost live route r beside it of the prefix of
// length from that holds r. It takes a piece at each bit past from up to r's
// length that r's first address has set before r or clear after it: the half,
// on the run's side, of the prefix of r's first address one bit shorter. from
// is the hold's length outside the first and the last live route, and between
// two neighbors the first bit they differ at.
func holdGaps(hold netip.Prefix, inside []liveRoute, each func(r liveRoute, from int, before bool) bool) {
	last := -1
	for i, r := range inside {
		if last >= 0 && inside[last].destination.Contains(r.destination.Addr()) {
			continue
		}
		from := hold.Bits()
		if last >= 0 {
			from = partAt(inside[last].first, r.first)
			if !each(inside[last], from, false) {
				return
			}
		}
		if !each(r, from, true) {
			return
		}
		last = i
	}
	if last >= 0 {
		each(inside[last], hold.Bits(), false)
	}
}

// holdPieces is how many pieces hold is cut into around inside, holdGaps'
// pieces counted by run until the count passes left, and whether it does not.
// A run adds at most a family's length, so the count stops within that of
// left, and a hold that does not fit has no piece made.
func holdPieces(hold netip.Prefix, inside []liveRoute, left int) (int, bool) {
	n := 0
	holdGaps(hold, inside, func(r liveRoute, from int, before bool) bool {
		ones := r.first.ones(from, r.destination.Bits())
		if before {
			n += ones
		} else {
			n += r.destination.Bits() - from - ones
		}
		return n <= left
	})
	return n, n <= left
}

// holdPiecesOf is holdGaps' pieces of hold around inside, in address order
func holdPiecesOf(hold netip.Prefix, inside []liveRoute) []netip.Prefix {
	var out []netip.Prefix
	holdGaps(hold, inside, func(r liveRoute, from int, before bool) bool {
		length := r.destination.Bits()
		for at := range length - from {
			bit := from + 1 + at
			if !before {
				bit = length - at
			}
			if r.first.bit(bit) == before {
				out = append(out, halves(netip.PrefixFrom(r.destination.Addr(), bit-1).Masked())[boolOrder(!before)])
			}
		}
		return true
	})
	return out
}

// word128 is an address of either family as 128 bits from the left, an IPv4
// address in the first 32, so that the bit a prefix length counts to is the
// same bit in both. Bits count from 1.
type word128 struct{ hi, lo uint64 }

func wordOf(address netip.Addr) word128 {
	if address.Is4() {
		raw := address.As4()
		return word128{hi: uint64(binary.BigEndian.Uint32(raw[:])) << 32}
	}
	raw := address.As16()
	return word128{hi: binary.BigEndian.Uint64(raw[:8]), lo: binary.BigEndian.Uint64(raw[8:])}
}

// leading is the first n bits set
func leading(n int) word128 {
	if n <= 64 {
		return word128{hi: ^uint64(0) << (64 - n)}
	}
	return word128{hi: ^uint64(0), lo: ^uint64(0) << (128 - n)}
}

// ones is how many of w's bits past from up to to are set
func (w word128) ones(from, to int) int {
	upTo, past := leading(to), leading(from)
	return bits.OnesCount64(w.hi&upTo.hi&^past.hi) + bits.OnesCount64(w.lo&upTo.lo&^past.lo)
}

func (w word128) bit(i int) bool {
	if i <= 64 {
		return w.hi>>(64-i)&1 == 1
	}
	return w.lo>>(128-i)&1 == 1
}

// partAt is the first bit a and b differ at, which two disjoint prefixes inside
// one hold do at or before the shorter one's length
func partAt(a, b word128) int {
	if x := a.hi ^ b.hi; x != 0 {
		return bits.LeadingZeros64(x) + 1
	}
	return 64 + bits.LeadingZeros64(a.lo^b.lo) + 1
}
