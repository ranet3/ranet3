// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package egress

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/packet"
	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/schema"
)

// froms is the prefixes a drawn class list takes its From from, in both
// families, nested in one another and beside one another, and blocks of
// sources no router forwards a packet from that drawnFrom does not draw
var froms = []schema.Prefix{
	schema.MustPrefix("0.0.0.0/0"), schema.MustPrefix("198.51.100.0/24"), schema.MustPrefix("198.51.100.0/25"),
	schema.MustPrefix("198.51.100.128/25"), schema.MustPrefix("198.51.100.7/32"), schema.MustPrefix("192.0.2.0/24"),
	schema.MustPrefix("::/0"), schema.MustPrefix("2001:db8::/32"), schema.MustPrefix("2001:db8::/33"), schema.MustPrefix("2001:db8:8000::/33"),
	schema.MustPrefix("2001:db8:1::/48"), schema.MustPrefix("2001:db8:1::7/128"), schema.MustPrefix("3fff::/20"),
	schema.MustPrefix("169.254.0.0/16"), schema.MustPrefix("fe80::/10"), schema.MustPrefix("::1/128"),
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

// For any classes of both families, nested in one another, halving one
// another and reaching the longest lengths, Validate refuses a class that
// translates where packet.InvalidSource holds at every address of its From,
// and otherwise refuses a family as untranslated exactly when every address of
// it InvalidSource does not hold at takes a class of none, and refuses nothing
// where no family is. ClassOf is constant between the boundaries of a family's
// classes, the family's first address and each From's first and the one past
// its last, and InvalidSource between the edges of martians outside
// ::ffff:0:0/96, which one class takes whole, since no From Validate takes
// lies inside it. Every such address therefore takes none exactly when every
// boundary that is one does.
func TestValidateRefusesExactlyAFamilyLeftWhollyUnderNone(t *testing.T) {
	translations := map[uint8][]Translation{
		FamilyIPv4: {{None: true}, {Auto: true}, {Addr: netip.MustParseAddr("198.51.100.9")}},
		FamilyIPv6: {{None: true}, {Auto: true}, {Addr: netip.MustParseAddr("2001:db8::9")}},
	}
	pbt.Check(t, func(ht *hegel.T) {
		cfg := Egress{Advertise: []schema.Prefix{schema.MustPrefix("0.0.0.0/0"), schema.MustPrefix("::/0")}}
		put := func(from schema.Prefix, to Translation) {
			if !slices.ContainsFunc(cfg.Translate, func(class Class) bool { return class.From == from }) {
				cfg.Translate = append(cfg.Translate, Class{From: from, To: to})
			}
		}
		add := func(from schema.Prefix) {
			put(from, translations[AddressFamily(from.Addr())][hegel.Draw(ht, pbt.Spanning(0, 2))])
			// on a drawn choice both its halves under none, so a class longer
			// classes take every source of comes at every length
			if bits := from.Bits(); bits < from.Addr().BitLen() && hegel.Draw(ht, hegel.Booleans()) {
				put(schema.PrefixFrom(netip.PrefixFrom(from.Addr(), bits+1)), Translation{None: true})
				put(schema.PrefixFrom(netip.PrefixFrom(lastAddress(from.Prefix), bits+1).Masked()), Translation{None: true})
			}
		}
		for _, from := range pbt.Subset(ht, froms, 0, len(froms)) {
			add(from)
		}
		for range hegel.Draw(ht, pbt.Spanning(0, 8)) {
			family := FamilyIPv4
			if hegel.Draw(ht, pbt.Spanning(0, 1)) == 1 {
				family = FamilyIPv6
			}
			add(drawnFrom(ht, family))
		}
		want := ""
		for _, family := range []uint8{FamilyIPv6, FamilyIPv4} {
			if everyBoundaryNone(cfg, family) {
				want = "which leaves every " + FamilyName(family) + " source untranslated"
			}
		}
		if slices.ContainsFunc(cfg.Translate, func(class Class) bool { return !class.To.None && holdsNoSource(class.From.Prefix) }) {
			want = "holds only sources a router forwards no packet from"
		}
		err := cfg.Validate()
		if want == "" && err != nil || want != "" && (err == nil || !strings.Contains(err.Error(), want)) {
			ht.Fatalf("under %v Validate answers %v, want a refusal naming %q, or none where that is empty", cfg.Translate, err, want)
		}
	})
}

func drawnFrom(ht *hegel.T, family uint8) schema.Prefix {
	first := everySource(family).Addr()
	most := first.BitLen()
	if hegel.Draw(ht, pbt.Spanning(0, 1)) == 0 {
		most = 3
	}
	bits := hegel.Draw(ht, pbt.Spanning(0, most))
	top, fill := hegel.Draw(ht, pbt.Spanning(0, 7)), hegel.Draw(ht, pbt.Spanning(0, 1))
	raw := first.AsSlice()
	for i := range bits {
		set := fill == 1
		if i < 3 {
			set = top>>(2-i)&1 == 1
		}
		if set {
			raw[i/8] |= 0x80 >> (i % 8)
		}
	}
	address, _ := netip.AddrFromSlice(raw)
	return schema.PrefixFrom(netip.PrefixFrom(address, bits))
}

func everyBoundaryNone(cfg Egress, family uint8) bool {
	boundaries := []netip.Addr{everySource(family).Addr()}
	for _, class := range cfg.Classes(family) {
		boundaries = append(boundaries, class.From.Addr(), lastAddress(class.From.Prefix).Next())
	}
	for _, block := range martians {
		boundaries = append(boundaries, block.Addr(), lastAddress(block).Next())
	}
	return !slices.ContainsFunc(boundaries, func(address netip.Addr) bool {
		return address.IsValid() && AddressFamily(address) == family && !packet.InvalidSource(address) && !cfg.ClassOf(address).To.None
	})
}

// martians is the blocks packet.InvalidSource's doc names, between whose edges
// it does not change outside ::ffff:0:0/96, inside which it also holds at the
// IPv4-mapped forms of 127.0.0.0/8, 224.0.0.0/4 and 169.254.0.0/16
var martians = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"), netip.MustParsePrefix("::1/128"), netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("ff00::/8"),
}

// holdsNoSource is whether packet.InvalidSource holds at every address of
// from, which it does where it holds at from's first address and at each edge
// of martians inside from
func holdsNoSource(from netip.Prefix) bool {
	edges := []netip.Addr{from.Addr()}
	for _, block := range martians {
		edges = append(edges, block.Addr(), lastAddress(block).Next())
	}
	return !slices.ContainsFunc(edges, func(address netip.Addr) bool {
		return address.IsValid() && from.Contains(address) && !packet.InvalidSource(address)
	})
}

// lastAddress is the last address of prefix
func lastAddress(prefix netip.Prefix) netip.Addr {
	raw := prefix.Addr().AsSlice()
	for i := prefix.Bits(); i < len(raw)*8; i++ {
		raw[i/8] |= 0x80 >> (i % 8)
	}
	address, _ := netip.AddrFromSlice(raw)
	return address
}
