// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"net/netip"
	"slices"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/sadr"
	"ranet3.com/pkgs/ranet3/schema"
)

// OwnedSources is the sources this node owns, as the tun read judges a source
// its own: every address covered by an entry of this node's own, Local or
// Assigned, that schema.CapturesTheMachine does not count under overlay. A
// source-specific entry covers its destination whole, since one set cannot hold
// a source per destination and the tun read still judges the pair.
func OwnedSources(snapshot []sadr.Route[*netstack.Peer], overlay []schema.Prefix) []egress.Range {
	var prefixes []netip.Prefix
	for _, entry := range ownedEntries(snapshot, overlay) {
		prefixes = append(prefixes, entry.Destination)
	}
	return Ranges(prefixes)
}

// ownedEntries is each entry of this node's own that does not count as a
// default under overlay, its destination masked
func ownedEntries(snapshot []sadr.Route[*netstack.Peer], overlay []schema.Prefix) []sadr.Route[*netstack.Peer] {
	var out []sadr.Route[*netstack.Peer]
	for _, entry := range snapshot {
		destination, ok := canonicalPrefix(entry.Destination)
		if !ok || entry.Value != netstack.Local && entry.Value != netstack.Assigned || schema.CapturesTheMachine(destination, overlay) {
			continue
		}
		entry.Destination = destination
		out = append(out, entry)
	}
	return out
}

// NoneDestinations is the destinations a packet from outside the mesh may
// enter it toward in its flow's original direction at an exit translating
// none: each address whose class among classes, cap.egress translate, is none,
// less every prefix outside the overlay the mesh's table holds learned or held
// that does not count as a default under overlay, the LANs other nodes
// advertise, which an inbound connection reaches through their own routers. A
// LAN routed for one source alone is taken out by its destination whole, since
// the set cannot hold a source per destination. A class is the longest one
// covering an address, as egress.Egress.ClassOf takes it, so a longer class
// inside a none class that is not none takes its addresses out. Empty where no
// class is none. Only the overlay tells a node's own address from a LAN, since
// a route learned for either reads alike, so the loader refuses a none class
// without overlay.
func NoneDestinations(classes []egress.Class, snapshot []sadr.Route[*netstack.Peer], overlay []schema.Prefix) []egress.Range {
	var none []egress.Range
	for _, class := range classes {
		if !class.To.None {
			continue
		}
		from := class.From.Masked()
		var inside []netip.Prefix
		for _, other := range classes {
			if !other.To.None && other.From.Bits() > from.Bits() && encloses(from, other.From.Masked()) {
				inside = append(inside, other.From.Masked())
			}
		}
		none = append(none, subtract([]egress.Range{prefixRange(from)}, Ranges(inside))...)
	}
	if len(none) == 0 {
		return nil
	}
	var learned []netip.Prefix
	for _, entry := range snapshot {
		if destination, ok := learnedDestination(entry, overlay); ok {
			learned = append(learned, destination)
		}
	}
	return subtract(egress.Union(none), subtract(Ranges(learned), Ranges(SchemaPrefixes(overlay))))
}

// ConnectedNoneClass is the class of the first address outside overlay of
// held's network whose class among classes, cap.egress translate, is none, and
// whether there is one. On Linux the kernel routes the network of an address
// held under a shorter length than its own into the tun, outside the order the
// antispoof filter keeps between the reconciler's routes and its sets, so a
// packet from outside the mesh could enter the tun toward such an address. An
// address held at its full length has no network. A class is the longest one
// covering an address, as NoneDestinations takes it.
func ConnectedNoneClass(held netip.Prefix, overlay []schema.Prefix, classes []egress.Class) (egress.Class, bool) {
	if held.IsSingleIP() {
		return egress.Class{}, false
	}
	outside := Without(Ranges([]netip.Prefix{held}), Ranges(SchemaPrefixes(overlay)))
	taken := Without(outside, Without(outside, NoneDestinations(classes, nil, nil)))
	if len(taken) == 0 {
		return egress.Class{}, false
	}
	return egress.Egress{Translate: classes}.ClassOf(taken[0].First), true
}

// learnedDestination is the masked destination of an entry NoneDestinations
// takes out of the none sets outside overlay, and whether entry is one
func learnedDestination(entry sadr.Route[*netstack.Peer], overlay []schema.Prefix) (netip.Prefix, bool) {
	destination, ok := canonicalPrefix(entry.Destination)
	if !ok || entry.Value == netstack.Local || entry.Value == netstack.Assigned || schema.CapturesTheMachine(destination, overlay) {
		return netip.Prefix{}, false
	}
	return destination, true
}

// appendOutside appends to dst the ranges, in Union form, of a masked
// destination's addresses that inside, the overlay's ranges in Union form,
// does not hold. Where inside holds none of them it appends the destination's
// one range without a walk, since most destinations lie outside the overlay
// whole.
func appendOutside(dst []egress.Range, destination netip.Prefix, inside []egress.Range) []egress.Range {
	r := prefixRange(destination)
	if !meetsRange(r, inside) {
		return append(dst, r)
	}
	return append(dst, subtract([]egress.Range{r}, inside)...)
}

// entersTun is the masked destination of a learned entry whose route takes a
// packet into the tun, and whether entry is one. A hold is not: its route
// refuses the packet, so Unentered never holds one back, Promised never
// promises one and Kept keeps no address out for one.
func entersTun(entry sadr.Route[*netstack.Peer], overlay []schema.Prefix) (netip.Prefix, bool) {
	destination, ok := learnedDestination(entry, overlay)
	return destination, ok && entry.Value != netstack.Unreachable
}

// Unentered hands back snapshot with a hold in place of each learned entry
// whose route takes a packet into the tun and whose destination has an
// address outside overlay that none holds, and returns the entries the holds
// replaced as held. none is the ranges the entry chain's none sets may hold,
// in Union form. Such an entry's route would take a stranger's packet those
// sets let into the tun on to another node's LAN. A pass computed from a table
// holding the entry takes those addresses out of the sets, as
// NoneDestinations does, and once that pass is written none no longer holds
// them.
//
// The reconciler installs a hold as an unreachable route in the mesh's table
// at the entry's key, its source with it. A lookup in that table that the
// hold matches meets it before any shorter route there, the default among
// them, and ends refused, so no rule after that lookup's answers either. The
// hold of an IPv6 entry with a source matches a lookup from that source alone:
// one from another source passes it, as it would pass the entry's route, and
// meets what else the table holds for it, the default among them. A lookup
// that ends before the mesh's table, as one a route of main longer than /0
// answers at rule 5410, never meets it, as routing.md's "where a lookup ends
// on Linux" gives. No hold reaches the
// kernel for an IPv4 entry with a source, for which the reconciler installs
// nothing, nor while the reconciler's passes write nothing, and
// design/limits.md gives what a forwarded link's packet meets then in
// cap.exit's mode. The hold and the entry's route lie at two keys, so the pass
// that replaces a hold deletes it before it adds the route, and a lookup
// toward the LAN between the two goes as it went before the learn.
func Unentered(snapshot []sadr.Route[*netstack.Peer], none []egress.Range, overlay []schema.Prefix) (handed, held []sadr.Route[*netstack.Peer]) {
	if len(none) == 0 {
		return snapshot, nil
	}
	inside := Ranges(SchemaPrefixes(overlay))
	handed = make([]sadr.Route[*netstack.Peer], 0, len(snapshot))
	var parts []egress.Range
	for _, entry := range snapshot {
		if destination, ok := entersTun(entry, overlay); ok {
			if parts = appendOutside(parts[:0], destination, inside); meets(parts, none) {
				held = append(held, entry)
				entry.Value = netstack.Unreachable
			}
		}
		handed = append(handed, entry)
	}
	return handed, held
}

// Promised is the route the reconciler may install for each learned entry of
// handed, the entries a Snapshot hands it, whose route takes a packet into the
// tun
func Promised(handed []sadr.Route[*netstack.Peer], overlay []schema.Prefix) []Route {
	out := make([]Route, 0, len(handed))
	for _, entry := range handed {
		destination, ok := entersTun(entry, overlay)
		if !ok {
			continue
		}
		route := Route{Destination: destination, Metric: routeMetric(destination, false)}
		if source, ok := canonicalPrefix(entry.Source); ok {
			route.Source = source
		}
		out = append(out, route)
	}
	return out
}

// Kept is each route of routes that takes a packet into the tun toward a
// learned destination whose addresses outside overlay meet none, and those
// addresses: the part of none such a route still covers. none is in Union
// form. A hold, a throw and a member of a cover take no packet into the tun. A
// default as schema.CapturesTheMachine counts one is left out, as
// learnedDestination leaves it out of NoneDestinations, though on a node in
// cap.exit's mode rule 5440 sends a forwarded link's packet through it into
// the tun, the case Unentered's doc gives.
func Kept(routes []Route, none []egress.Range, overlay []schema.Prefix) (by []Route, kept []egress.Range) {
	inside := Ranges(SchemaPrefixes(overlay))
	var parts []egress.Range
	for _, route := range routes {
		destination, ok := canonicalPrefix(route.Destination)
		if !ok || route.Unreachable || route.Throw || route.Cover || schema.CapturesTheMachine(destination, overlay) {
			continue
		}
		// most routes' addresses are their entries', which none already leaves out
		n := len(parts)
		if parts = appendOutside(parts, destination, inside); meets(parts[n:], none) {
			by = append(by, route)
		} else {
			parts = parts[:n]
		}
	}
	return by, intersect(egress.Union(parts), none)
}

// meets reports whether a range of a holds an address of b, both in Union form
func meets(a, b []egress.Range) bool {
	return slices.ContainsFunc(a, func(r egress.Range) bool { return meetsRange(r, b) })
}

// meetsRange reports whether b, in Union form, holds an address of r, finding
// the first range of b that does not end before r by halving
func meetsRange(r egress.Range, b []egress.Range) bool {
	i, _ := slices.BinarySearchFunc(b, r.First, func(hole egress.Range, first netip.Addr) int {
		if hole.Last.Less(first) {
			return -1
		}
		return 1
	})
	return i < len(b) && !r.Last.Less(b[i].First)
}

// Without is the addresses of from that holes does not hold, in Union form.
// It takes from and holes in any order.
func Without(from, holes []egress.Range) []egress.Range {
	return subtract(egress.Union(from), egress.Union(holes))
}

// Ranges is the addresses prefixes cover in Union form: sorted, none
// overlapping or adjacent to another, as egress.Union leaves ranges and an
// interval set holds them
func Ranges(prefixes []netip.Prefix) []egress.Range {
	ranges := make([]egress.Range, 0, len(prefixes))
	for _, prefix := range prefixes {
		if prefix, ok := canonicalPrefix(prefix); ok {
			ranges = append(ranges, prefixRange(prefix))
		}
	}
	return egress.Union(ranges)
}

// RangePrefixes is the fewest prefixes holding exactly the addresses of
// ranges, in order
func RangePrefixes(ranges ...egress.Range) []netip.Prefix {
	var out []netip.Prefix
	for _, r := range ranges {
		for first := r.First; first.IsValid() && !r.Last.Less(first); {
			bits := first.BitLen()
			for bits > 0 {
				wider := netip.PrefixFrom(first, bits-1).Masked()
				if wider.Addr() != first || r.Last.Less(prefixRange(wider).Last) {
					break
				}
				bits--
			}
			prefix := netip.PrefixFrom(first, bits)
			out = append(out, prefix)
			first = prefixRange(prefix).Last.Next()
		}
	}
	return out
}

// prefixRange is a masked prefix's addresses
func prefixRange(prefix netip.Prefix) egress.Range {
	return egress.Range{First: prefix.Addr(), Last: lastAddress(prefix)}
}

// intersect is the addresses both a and b hold, both in Union form, in one
// walk of the two
func intersect(a, b []egress.Range) []egress.Range {
	var out []egress.Range
	for i, j := 0, 0; i < len(a) && j < len(b); {
		first, last := a[i].First, a[i].Last
		if first.Less(b[j].First) {
			first = b[j].First
		}
		if b[j].Last.Less(last) {
			last = b[j].Last
		}
		if !last.Less(first) {
			out = append(out, egress.Range{First: first, Last: last})
		}
		// the range that ends first meets nothing past the other
		if a[i].Last.Less(b[j].Last) {
			i++
		} else {
			j++
		}
	}
	return out
}

// subtract is the addresses of from that no range of holes holds, both in
// Union form, in one walk of the two
func subtract(from, holes []egress.Range) []egress.Range {
	var out []egress.Range
	next := 0
	for _, r := range from {
		// a hole ending before r ends before every later range of from
		for next < len(holes) && holes[next].Last.Less(r.First) {
			next++
		}
		first, done := r.First, false
		for _, hole := range holes[next:] {
			if r.Last.Less(hole.First) {
				break
			}
			if first.Less(hole.First) {
				out = append(out, egress.Range{First: first, Last: hole.First.Prev()})
			}
			if !hole.Last.Less(r.Last) {
				done = true
				break
			}
			first = hole.Last.Next()
		}
		if !done {
			out = append(out, egress.Range{First: first, Last: r.Last})
		}
	}
	return out
}
