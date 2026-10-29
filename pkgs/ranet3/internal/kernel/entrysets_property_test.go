// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package kernel

import (
	"net/netip"
	"slices"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/sadr"
	"ranet3.com/pkgs/ranet3/schema"
)

// inRanges reports address lying in one of ranges
func inRanges(ranges []egress.Range, address netip.Addr) bool {
	return slices.ContainsFunc(ranges, func(r egress.Range) bool { return r.First.Compare(address) <= 0 && address.Compare(r.Last) <= 0 })
}

// checkRanges fails unless ranges are sorted, each of one family and first to
// last, and none overlaps or adjoins the next, as an interval set takes them
func checkRanges(ht *hegel.T, ranges []egress.Range) {
	for i, r := range ranges {
		if !r.First.IsValid() || r.First.BitLen() != r.Last.BitLen() || r.Last.Less(r.First) {
			ht.Fatalf("range %d of %v runs from %s to %s", i, ranges, r.First, r.Last)
		}
		if i > 0 && r.First.BitLen() == ranges[i-1].Last.BitLen() && r.First.Compare(ranges[i-1].Last.Next()) <= 0 {
			ht.Fatalf("range %d of %v overlaps or adjoins the one before", i, ranges)
		}
		if i > 0 && r.First.Less(ranges[i-1].First) {
			ht.Fatalf("range %d of %v comes before the one before", i, ranges)
		}
	}
}

// boundaries is the first and last address of each prefix and the address on
// each side of them, where a set of ranges can be off by one
func boundaries(prefixes []netip.Prefix) []netip.Addr {
	var out []netip.Addr
	for _, prefix := range prefixes {
		first, last := prefix.Masked().Addr(), modelLast(prefix.Masked())
		for _, address := range []netip.Addr{first, last, first.Prev(), last.Next()} {
			if address.IsValid() {
				out = append(out, address)
			}
		}
	}
	return out
}

// drawnEntries sets up to eight entries near carveBases in a table flagged
// under overlay: learned, held and this node's own, an IPv6 one with a source
// now and then, and at times a short one that counts as a default
func drawnEntries(tc hegel.TestCase, overlay []schema.Prefix) *netstack.RouteTable {
	routes := netstack.NewRouteTable()
	routes.SetOverlay(overlay)
	values := []*netstack.Peer{learned, netstack.Unreachable, netstack.Local, netstack.Assigned}
	for range hegel.Draw(tc, pbt.Spanning(0, 8)) {
		family := FamilyIPv4
		if hegel.Draw(tc, pbt.Spanning(0, 1)) == 1 {
			family = FamilyIPv6
		}
		var source netip.Prefix
		if family == FamilyIPv6 && hegel.Draw(tc, pbt.Spanning(0, 1)) == 1 {
			source = nearPrefix(tc, family).Masked()
		}
		routes.Set(source, nearPrefix(tc, family), values[hegel.Draw(tc, pbt.Spanning(0, len(values)-1))])
	}
	return routes
}

// The owned sources agree with the tun read: a source the tun read owns
// toward any destination, an entry of this node's own that counts as no
// default answering the reply, is in the set, and a source in the set is
// covered by such an entry
func TestOwnedSourcesAreWhatTheTunReadOwns(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		overlay := drawnCarveOverlay(ht)
		routes := drawnEntries(ht, overlay)
		snapshot := routes.Snapshot()
		owned := OwnedSources(snapshot, overlay)
		checkRanges(ht, owned)
		var prefixes []netip.Prefix
		for _, entry := range snapshot {
			prefixes = append(prefixes, entry.Destination, entry.Source)
		}
		candidates := boundaries(slices.DeleteFunc(prefixes, func(p netip.Prefix) bool { return !p.IsValid() }))
		for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
			candidates = append(candidates, nearAddress(ht, family), nearAddress(ht, family))
		}
		for _, source := range candidates {
			for _, destination := range candidates {
				if destination.BitLen() != source.BitLen() {
					continue
				}
				// the tun read's reply route, the table looked up from the destination to the source
				if _, verdict, match := routes.Resolve(destination, source); verdict == netstack.RouteLocal && !match.Counted && !inRanges(owned, source) {
					ht.Fatalf("the tun read owns %s toward %s and the set %v does not", source, destination, owned)
				}
			}
			covered := slices.ContainsFunc(snapshot, func(entry sadr.Route[*netstack.Peer]) bool {
				return (entry.Value == netstack.Local || entry.Value == netstack.Assigned) && entry.Destination.Masked().Contains(source) && !schema.CapturesTheMachine(entry.Destination, overlay)
			})
			if inRanges(owned, source) != covered {
				ht.Fatalf("%s in the owned set %v is %v, and covered by an entry of this node's own %v", source, owned, !covered, covered)
			}
		}
	})
}

// noneBases are the addresses a drawn class, LAN or overlay of the none sets
// lies near
var noneBases = map[Family]netip.Addr{FamilyIPv4: netip.MustParseAddr("203.0.112.0"), FamilyIPv6: netip.MustParseAddr("2001:db8:76::")}

// nonePrefix draws a prefix of family near noneBases, its length spanning the
// family's floor and the host lengths
func nonePrefix(tc hegel.TestCase, family Family) netip.Prefix {
	bytes := noneBases[family].AsSlice()
	offset := hegel.Draw(tc, pbt.Spanning(0, 0x3ff))
	at := 2
	if family == FamilyIPv6 {
		at = 5
	}
	bytes[at] |= byte(offset >> 8)
	bytes[at+1] |= byte(offset)
	address, _ := netip.AddrFromSlice(bytes)
	return netip.PrefixFrom(address, hegel.Draw(tc, pbt.Spanning(0, address.BitLen()))).Masked()
}

// The none sets hold an address exactly when its class is none and no learned
// or held prefix outside the overlay that counts as no default covers it, a
// source-specific one by its destination whole, or it lies in the overlay and
// its class is none, for drawn nested classes and LANs, each boundary drawn
// outright
func TestNoneDestinationsAreTheNoneClassLessOtherNodesLANs(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		var classes []egress.Class
		var drawn []netip.Prefix
		for range hegel.Draw(ht, pbt.Spanning(0, 4)) {
			family := FamilyIPv4
			if hegel.Draw(ht, pbt.Spanning(0, 1)) == 1 {
				family = FamilyIPv6
			}
			from := nonePrefix(ht, family)
			if slices.ContainsFunc(classes, func(c egress.Class) bool { return c.From.Prefix == from }) {
				continue
			}
			to := egress.Translation{Auto: true}
			if hegel.Draw(ht, pbt.Spanning(0, 1)) == 1 {
				to = egress.Translation{None: true}
			}
			classes = append(classes, egress.Class{From: schema.PrefixFrom(from), To: to})
			drawn = append(drawn, from)
		}
		var overlay []schema.Prefix
		for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
			if hegel.Draw(ht, pbt.Spanning(0, 1)) == 1 {
				o := nonePrefix(ht, family)
				overlay = append(overlay, schema.PrefixFrom(o))
				drawn = append(drawn, o)
			}
		}
		routes := netstack.NewRouteTable()
		routes.SetOverlay(overlay)
		values := []*netstack.Peer{learned, netstack.Unreachable, netstack.Local, netstack.Assigned}
		for range hegel.Draw(ht, pbt.Spanning(0, 5)) {
			family := FamilyIPv4
			if hegel.Draw(ht, pbt.Spanning(0, 1)) == 1 {
				family = FamilyIPv6
			}
			lan := nonePrefix(ht, family)
			// an IPv6 LAN now and then for a source alone, which the sets take out by its destination whole
			var source netip.Prefix
			if family == FamilyIPv6 && hegel.Draw(ht, pbt.Spanning(0, 2)) == 2 {
				source = nonePrefix(ht, family)
			}
			routes.Set(source, lan, values[hegel.Draw(ht, pbt.Spanning(0, len(values)-1))])
			drawn = append(drawn, lan)
		}
		snapshot := routes.Snapshot()
		none := NoneDestinations(classes, snapshot, overlay)
		checkRanges(ht, none)
		exit := egress.Egress{Translate: classes}
		for _, address := range boundaries(drawn) {
			class := exit.ClassOf(address)
			inOverlay := slices.ContainsFunc(overlay, func(o schema.Prefix) bool { return o.Contains(address) })
			lan := slices.ContainsFunc(snapshot, func(entry sadr.Route[*netstack.Peer]) bool {
				return entry.Value != netstack.Local && entry.Value != netstack.Assigned && entry.Destination.Contains(address) && !schema.CapturesTheMachine(entry.Destination, overlay)
			})
			want := class.To.None && (inOverlay || !lan)
			if got := inRanges(none, address); got != want {
				ht.Fatalf("%s in the none set %v is %v, want %v: its class %s %s, in the overlay %v, in a LAN %v", address, none, got, want, class.From, class.To, inOverlay, lan)
			}
		}
	})
}

// rangeSpan is the most addresses past its first a drawn range holds
const rangeSpan = 1 << 12

// modelPrefixCount is the fewest prefixes holding exactly r's addresses inside
// prefix: one where prefix lies inside r, none where it misses r, and else the
// count of each of its halves
func modelPrefixCount(r egress.Range, prefix netip.Prefix) int {
	first, last := prefix.Addr(), modelLast(prefix)
	switch {
	case last.Less(r.First) || r.Last.Less(first):
		return 0
	case !first.Less(r.First) && !r.Last.Less(last):
		return 1
	}
	low := netip.PrefixFrom(first, prefix.Bits()+1)
	return modelPrefixCount(r, low) + modelPrefixCount(r, netip.PrefixFrom(modelLast(low).Next(), prefix.Bits()+1))
}

// A range of up to rangeSpan addresses past a first one near carveBases, at
// its family's first address or ending at its last, splits into masked
// prefixes that run from its first address to its last with no gap or
// overlap, as few as the model counts
func TestRangePrefixesHoldExactlyTheRange(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		family, whole := FamilyIPv4, netip.PrefixFrom(netip.IPv4Unspecified(), 0)
		if hegel.Draw(ht, pbt.Spanning(0, 1)) == 1 {
			family, whole = FamilyIPv6, netip.PrefixFrom(netip.IPv6Unspecified(), 0)
		}
		span := hegel.Draw(ht, pbt.Spanning(0, rangeSpan))
		r := egress.Range{First: nearAddress(ht, family)}
		switch hegel.Draw(ht, pbt.Spanning(0, 2)) {
		case 0:
			r.First = whole.Addr()
		case 1:
			r.First = modelLast(whole)
			for range span {
				r.First = r.First.Prev()
			}
		}
		r.Last = r.First
		for range span {
			if next := r.Last.Next(); next.IsValid() {
				r.Last = next
			}
		}
		got := rangePrefixes(r)
		next := r.First
		for i, prefix := range got {
			if prefix != prefix.Masked() || prefix.Addr() != next {
				ht.Fatalf("prefix %d of %v for %s to %s is %s, where the one before ended before %s", i, got, r.First, r.Last, prefix, next)
			}
			next = modelLast(prefix).Next()
		}
		if len(got) == 0 || modelLast(got[len(got)-1]) != r.Last {
			ht.Fatalf("%v for %s to %s does not end at its last address", got, r.First, r.Last)
		}
		if want := modelPrefixCount(r, whole); len(got) != want {
			ht.Fatalf("%v for %s to %s holds it in %d prefixes, where %d do", got, r.First, r.Last, len(got), want)
		}
	})
}
