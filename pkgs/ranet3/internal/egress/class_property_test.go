// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package egress

import (
	"net/netip"
	"slices"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/schema"
)

// froms is the prefixes a drawn class list takes its From from, in both
// families, nested in one another and beside one another
var froms = []schema.Prefix{
	schema.MustPrefix("0.0.0.0/0"), schema.MustPrefix("198.51.100.0/24"), schema.MustPrefix("198.51.100.0/25"),
	schema.MustPrefix("198.51.100.128/25"), schema.MustPrefix("198.51.100.7/32"), schema.MustPrefix("192.0.2.0/24"),
	schema.MustPrefix("::/0"), schema.MustPrefix("2001:db8::/32"), schema.MustPrefix("2001:db8:1::/48"),
	schema.MustPrefix("2001:db8:1::7/128"), schema.MustPrefix("3fff::/20"),
}

// sources is the addresses a drawn source is taken from beside any address of
// either family, each inside some of froms and outside others
var sources = []netip.Addr{
	netip.MustParseAddr("198.51.100.7"), netip.MustParseAddr("198.51.100.8"), netip.MustParseAddr("198.51.100.200"),
	netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("203.0.113.17"),
	netip.MustParseAddr("2001:db8:1::7"), netip.MustParseAddr("2001:db8:1::8"), netip.MustParseAddr("2001:db8:2::1"),
	netip.MustParseAddr("3fff::2"),
}

// For any list of classes in any order, an address takes the class of the
// longest From covering it, and auto with no From where none covers it. Each
// family's Classes holds that family's classes alone, each once, the longest
// From first.
func TestEachAddressTakesTheClassOfTheLongestCoveringFrom(t *testing.T) {
	translations := []Translation{{None: true}, {Auto: true}, {Addr: netip.MustParseAddr("198.51.100.9")}, {Addr: netip.MustParseAddr("2001:db8::9")}}
	pbt.Check(t, func(ht *hegel.T) {
		var cfg Egress
		for _, from := range pbt.Subset(ht, froms, 0, len(froms)) {
			cfg.Translate = append(cfg.Translate, Class{From: from, To: hegel.Draw(ht, hegel.SampledFrom(translations))})
		}
		for range hegel.Draw(ht, pbt.Spanning(1, 8)) {
			address := hegel.Draw(ht, hegel.OneOf(hegel.SampledFrom(sources), hegel.IPAddresses().IPv4(), hegel.IPAddresses().IPv6()))
			want, longest := Class{To: Translation{Auto: true}}, -1
			for _, class := range cfg.Translate {
				if class.From.Contains(address) && class.From.Bits() > longest {
					want, longest = class, class.From.Bits()
				}
			}
			if got := cfg.ClassOf(address); got != want {
				ht.Fatalf("under %v %s takes %v, want %v", cfg.Translate, address, got, want)
			}
		}
		for _, family := range []uint8{FamilyIPv4, FamilyIPv6} {
			ordered := cfg.Classes(family)
			want := slices.DeleteFunc(slices.Clone(cfg.Translate), func(class Class) bool { return AddressFamily(class.From.Addr()) != family })
			if len(ordered) != len(want) || slices.ContainsFunc(want, func(class Class) bool { return !slices.Contains(ordered, class) }) {
				ht.Fatalf("under %v the %s classes are %v, want each of %v once", cfg.Translate, FamilyName(family), ordered, want)
			}
			for i := 1; i < len(ordered); i++ {
				if ordered[i].From.Bits() > ordered[i-1].From.Bits() {
					ht.Fatalf("under %v the %s classes are %v, where a longer From follows a shorter", cfg.Translate, FamilyName(family), ordered)
				}
			}
		}
	})
}
