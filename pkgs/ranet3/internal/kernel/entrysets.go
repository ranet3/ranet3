// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"net/netip"

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
// the set cannot hold a source per destination.
// A class is the longest one covering an address, as egress.Egress.ClassOf
// takes it, so a longer class inside a none class that is not none takes its
// addresses out. Empty where no class is none. Only the overlay tells a node's
// own address from a LAN, since a route learned for either reads alike, so the
// loader refuses a none class without overlay.
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
		destination, ok := canonicalPrefix(entry.Destination)
		if !ok || entry.Value == netstack.Local || entry.Value == netstack.Assigned || schema.CapturesTheMachine(destination, overlay) {
			continue
		}
		learned = append(learned, destination)
	}
	lans := subtract(Ranges(learned), Ranges(SchemaPrefixes(overlay)))
	return subtract(egress.Union(none), lans)
}

// Ranges is the addresses prefixes cover as ranges, sorted, none overlapping
// or adjacent to another, the form an interval set holds them in
func Ranges(prefixes []netip.Prefix) []egress.Range {
	ranges := make([]egress.Range, 0, len(prefixes))
	for _, prefix := range prefixes {
		if prefix, ok := canonicalPrefix(prefix); ok {
			ranges = append(ranges, prefixRange(prefix))
		}
	}
	return egress.Union(ranges)
}

// rangePrefixes is the fewest prefixes holding exactly the addresses of
// ranges, in order
func rangePrefixes(ranges ...egress.Range) []netip.Prefix {
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

// a and b are sorted as egress.Union leaves them
func intersect(a, b []egress.Range) []egress.Range {
	return subtract(a, subtract(a, b))
}

// subtract is the addresses of from that no range of holes holds, both sorted
// as egress.Union leaves them
func subtract(from, holes []egress.Range) []egress.Range {
	var out []egress.Range
	for _, r := range from {
		first, done := r.First, false
		for _, hole := range holes {
			if hole.Last.Less(first) || r.Last.Less(hole.First) {
				continue
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
