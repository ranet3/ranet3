// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"net/netip"
	"slices"

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
// lookup passes a scoped route over, a route from a source or a hold of the
// mesh's, so it holds no address of the prefix for the hold to give back.
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
