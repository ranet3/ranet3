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

// Range is the addresses of one family from First through Last, both included
type Range struct {
	First, Last netip.Addr
}

// OwnedSources is the sources this node owns, as the tun read judges a source
// its own: every address covered by an entry of this node's own, Local or
// Assigned, that schema.CapturesTheMachine does not count under overlay. A
// source-specific entry covers its destination whole, since one set cannot hold
// a source per destination and the tun read still judges the pair.
func OwnedSources(snapshot []sadr.Route[*netstack.Peer], overlay []schema.Prefix) []Range {
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
// advertise, which an inbound connection reaches through their own routers.
// A class is the longest one covering an address, as egress.Egress.ClassOf
// takes it, so a longer class inside a none class that is not none takes its
// addresses out. Empty where no class is none.
func NoneDestinations(classes []egress.Class, snapshot []sadr.Route[*netstack.Peer], overlay []schema.Prefix) []Range {
	var none []Range
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
		none = append(none, subtract([]Range{prefixRange(from)}, Ranges(inside))...)
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
	lans := subtract(Ranges(learned), Ranges(schemaPrefixes(overlay)))
	return subtract(union(none), lans)
}

// Ranges is the addresses prefixes cover as ranges, sorted, none overlapping
// or adjacent to another, the form an interval set holds them in
func Ranges(prefixes []netip.Prefix) []Range {
	ranges := make([]Range, 0, len(prefixes))
	for _, prefix := range prefixes {
		if prefix, ok := canonicalPrefix(prefix); ok {
			ranges = append(ranges, prefixRange(prefix))
		}
	}
	return union(ranges)
}

// prefixes is the fewest prefixes holding exactly the range's addresses
func (r Range) prefixes() []netip.Prefix {
	var out []netip.Prefix
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
	return out
}

// prefixRange is a masked prefix's addresses
func prefixRange(prefix netip.Prefix) Range {
	last := prefix.Addr().AsSlice()
	for bit := prefix.Bits(); bit < len(last)*8; bit++ {
		last[bit/8] |= 0x80 >> (bit % 8)
	}
	address, _ := netip.AddrFromSlice(last)
	return Range{First: prefix.Addr(), Last: address}
}

// union sorts ranges and joins each that overlaps or adjoins another
// an IPv4 range orders before every IPv6 one, and the last address of a family adjoins nothing
func union(ranges []Range) []Range {
	slices.SortFunc(ranges, func(a, b Range) int { return a.First.Compare(b.First) })
	var out []Range
	for _, r := range ranges {
		if n := len(out); n > 0 {
			last := &out[n-1]
			if next := last.Last.Next(); r.First.Compare(last.Last) <= 0 || next.IsValid() && r.First == next {
				if last.Last.Less(r.Last) {
					last.Last = r.Last
				}
				continue
			}
		}
		out = append(out, r)
	}
	return out
}

// subtract is the addresses of from that no range of holes holds, both sorted
// as union leaves them
func subtract(from, holes []Range) []Range {
	var out []Range
	for _, r := range from {
		first, done := r.First, false
		for _, hole := range holes {
			if hole.Last.Less(first) || r.Last.Less(hole.First) {
				continue
			}
			if first.Less(hole.First) {
				out = append(out, Range{First: first, Last: hole.First.Prev()})
			}
			if !hole.Last.Less(r.Last) {
				done = true
				break
			}
			first = hole.Last.Next()
		}
		if !done {
			out = append(out, Range{First: first, Last: r.Last})
		}
	}
	return out
}
