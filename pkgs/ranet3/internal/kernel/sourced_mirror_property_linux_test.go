// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"net/netip"
	"slices"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/schema"
)

// The independent endpoint intersection describes which original entries
// reach either named destination. A mirror must not crop or rewrite one.
func TestSourcedMirrorPreservesWholeIntersectingEntries(t *testing.T) {
	destinations := []schema.Prefix{
		schema.MustPrefix("2001:db8:80::/96"), schema.MustPrefix("2001:db8:81::/96"),
	}
	choices := []netip.Prefix{
		netip.MustParsePrefix("::/0"),
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("2001:db8:80::/96"),
		netip.MustParsePrefix("2001:db8:80::2000:0/112"),
		netip.MustParsePrefix("2001:db8:81::/96"),
		netip.MustParsePrefix("2001:db8:82::/48"),
		netip.MustParsePrefix("192.0.2.0/24"),
	}
	office := netip.MustParsePrefix("fd5e:db8:10:1::/64")
	pbt.Check(t, func(ht *hegel.T) {
		original := []Route{
			{Destination: choices[0], Source: office, Metric: 80},
			{Destination: choices[2], Cover: true, Metric: 81},
			{Destination: choices[3], Unreachable: true, Source: office, Metric: 82},
			{Destination: choices[1], Throw: true, Metric: 83},
		}
		for i := range 8 {
			entry := Route{Destination: choices[hegel.Draw(ht, pbt.Spanning(0, len(choices)-1))],
				Metric: uint32(100 + i)}
			if hegel.Draw(ht, pbt.Spanning(0, 1)) != 0 {
				entry.Source = office
			}
			if hegel.Draw(ht, pbt.Spanning(0, 1)) != 0 {
				entry.Unreachable = true
			} else if hegel.Draw(ht, pbt.Spanning(0, 1)) != 0 {
				entry.Throw = true
			}
			entry.Cover = hegel.Draw(ht, pbt.Spanning(0, 1)) != 0
			original = append(original, entry)
		}
		var want []Route
		for _, entry := range original {
			if !entry.Destination.IsValid() || !entry.Destination.Addr().Is6() ||
				entry.Destination.Bits() == 0 || entry.Cover {
				continue
			}
			for _, named := range destinations {
				if intersectsByEnds(entry.Destination, named.Prefix) {
					want = append(want, entry)
					break
				}
			}
		}
		if got := sourcedMirrors(destinations, original); !slices.Equal(got, want) {
			ht.Fatalf("mirrored %v, want original intersecting entries %v, from %v", got, want, original)
		}
	})
}

// A pair exists only where a nondefault peer intersects both the named D
// and a supported source. A hold, default or derived cover cannot admit it.
func TestSourcedPairAdmissionFollowsBothConcreteIntersections(t *testing.T) {
	destinations := []schema.Prefix{
		schema.MustPrefix("2001:db8:80::/96"), schema.MustPrefix("2001:db8:81::/96"),
	}
	office := netip.MustParsePrefix("fd5e:db8:10:1::/64")
	uplink := netip.MustParsePrefix("2001:db8:ff::/64")
	sources := map[netip.Prefix]struct{}{office: {}, uplink: {}}
	pbt.Check(t, func(ht *hegel.T) {
		original := []Route{
			{Destination: netip.MustParsePrefix("::/0")},
			{Destination: destinations[0].Prefix, Cover: true},
			{Destination: netip.MustParsePrefix("2001:db8:80::2000:0/112"), Source: uplink, Unreachable: true},
			{Destination: destinations[0].Prefix, Source: office, Metric: 80},
		}
		second := Route{Destination: destinations[1].Prefix, Source: office, Metric: 81}
		if hegel.Draw(ht, pbt.Spanning(0, 1)) != 0 {
			second.Source = uplink
		}
		original = append(original, second)
		if hegel.Draw(ht, pbt.Spanning(0, 1)) != 0 {
			original = append(original, Route{Destination: netip.MustParsePrefix("2001:db8:81::2000:0/112"),
				Source: office, Throw: true})
		}
		var want []Rule
		for _, named := range destinations {
			for source := range sources {
				for _, entry := range original {
					if entry.Cover || entry.Unreachable || entry.Throw || entry.Destination.Bits() == 0 ||
						!intersectsByEnds(entry.Destination, named.Prefix) ||
						entry.Source.IsValid() && !intersectsByEnds(entry.Source, source) {
						continue
					}
					want = append(want, sourcedPeerRule(named, source, 201))
					break
				}
			}
		}
		got := sourcedPeerRules(destinations, sources, original, 201)
		if len(got) != len(want) {
			ht.Fatalf("pairs %v, want %v, originals %v", got, want, original)
		}
		for _, pair := range want {
			if !slices.Contains(got, pair) {
				ht.Fatalf("missing pair %v in %v, originals %v", pair, got, original)
			}
		}
	})
}
