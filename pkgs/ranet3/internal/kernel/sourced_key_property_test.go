// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package kernel

import (
	"net/netip"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/schema"
)

func prefixEnds(p netip.Prefix) (netip.Addr, netip.Addr) {
	first := p.Masked().Addr().As16()
	last := first
	for bit := p.Bits(); bit < 128; bit++ {
		last[bit/8] |= 1 << (7 - bit%8)
	}
	return netip.AddrFrom16(first), netip.AddrFrom16(last)
}

func intersectsByEnds(a, b netip.Prefix) bool {
	firstA, lastA := prefixEnds(a)
	firstB, lastB := prefixEnds(b)
	return firstA.Compare(lastB) <= 0 && firstB.Compare(lastA) <= 0
}

func TestSourcedPrefixIntersection(t *testing.T) {
	prefix := func(s string) netip.Prefix { return netip.MustParsePrefix(s) }
	pairs := [][2]netip.Prefix{
		{prefix("2001:db8:1::/48"), prefix("2001:db8:3::/48")},
		{prefix("2001:db8:1::/48"), prefix("2001:db8:2::/48")},
		{prefix("2001:db8:1::/48"), prefix("2001:db8:1::/48")},
		{prefix("2001:db8::/32"), prefix("2001:db8:1::/48")},
		{prefix("2001:db8:1::/48"), prefix("2001:db8::/32")},
	}
	pbt.Check(t, func(ht *hegel.T) {
		for _, pair := range pairs {
			a, b := pair[0], pair[1]
			if hegel.Draw(ht, pbt.Spanning(0, 1)) == 1 {
				a, b = b, a
			}
			want := intersectsByEnds(a, b)
			if got := schema.PrefixFrom(a).Overlaps(b); got != want {
				ht.Fatalf("%s and %s intersect: got %t, want %t", a, b, got, want)
			}
			s := &Sourced{To: []schema.Prefix{schema.PrefixFrom(a)}}
			if got := s.Refuse(SourcedLimits{Overlay: []schema.Prefix{schema.PrefixFrom(b)}}) != nil; got != want {
				ht.Fatalf("%s and overlay %s: refused %t, want %t", a, b, got, want)
			}
		}
	})
}
