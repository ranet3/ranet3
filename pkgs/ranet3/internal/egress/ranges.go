// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package egress

import (
	"net/netip"
	"slices"
)

// Range is the addresses of one family from First through Last, both
// included, the form the border filter's interval sets hold them in
type Range struct {
	First, Last netip.Addr
}

// String is r as nft prints an interval: its one address bare, the prefix
// holding exactly its addresses where one does, else its first and last
// address. nftables.Set.Text is its twin for a set's element, in a package
// for Linux alone that this one cannot import, and a change to one is a
// change to both.
func (r Range) String() string {
	if r.First == r.Last {
		return r.First.String()
	}
	for bits := r.First.BitLen(); bits >= 0; bits-- {
		prefix := netip.PrefixFrom(r.First, bits)
		if prefix.Masked().Addr() != r.First {
			break
		}
		if next := r.Last.Next(); prefix.Contains(r.Last) && (!next.IsValid() || !prefix.Contains(next)) {
			return prefix.String()
		}
	}
	return r.First.String() + "-" + r.Last.String()
}

// Union sorts ranges and joins each that overlaps or adjoins another. An IPv4
// range orders before every IPv6 one, and the last address of a family
// adjoins nothing.
func Union(ranges []Range) []Range {
	ranges = slices.Clone(ranges)
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
