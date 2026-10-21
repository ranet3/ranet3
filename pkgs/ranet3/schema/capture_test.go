// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package schema

import (
	"net/netip"
	"testing"
)

// Each spelling of a default counts, a split internet and a wide prefix
// outside the overlay among them, as does any prefix over the zero address
// however small and wherever the overlay lies, since the darwin kernel's
// fallback is a lookup of that address
// (TestDarwinStrandsABoundSocketOnlyThroughTheZeroAddress). A prefix at or
// past its family's floor, or inside the overlay, is a subnet.
func TestCapturesTheMachineCountsEverySpellingOfADefault(t *testing.T) {
	overlay := []Prefix{MustPrefix("3ff0::/12"), MustPrefix("198.51.100.0/24")}
	for name, test := range map[string]struct {
		destinations []string
		counts       bool
	}{
		"a default and its halves": {[]string{"0.0.0.0/0", "::/0", "0.0.0.0/1", "::/1", "128.0.0.0/1", "8000::/1"}, true},
		"a split internet":         {[]string{"64.0.0.0/2", "128.0.0.0/2", "192.0.0.0/2", "2000::/3"}, true},
		"wide outside the overlay": {[]string{"fd00::/8", "fc00::/7", "192.0.0.0/7", "2001::/15", "3fe0::/11"}, true},
		"over the zero address": {[]string{
			"0.0.0.0/2", "0.0.0.0/8", "0.0.0.0/24", "0.0.0.0/32", "::/2", "::/16", "::/64", "::/128",
		}, true},
		"at or past the floor": {[]string{"192.0.0.0/8", "203.0.0.0/8", "2001::/16", "2001:db8::/32", "192.0.2.0/24"}, false},
		"inside the overlay":   {[]string{"3ff0::/12", "3ff0::/13", "3ff8::/15", "3fff::/20"}, false},
	} {
		t.Run(name, func(t *testing.T) {
			for _, destination := range test.destinations {
				if got := CapturesTheMachine(netip.MustParsePrefix(destination), overlay); got != test.counts {
					t.Errorf("%s counts %v under the overlay %v, want %v", destination, got, overlay, test.counts)
				}
			}
		})
	}
	// an overlay holding the zero address leaves the arm over it standing
	if !CapturesTheMachine(netip.MustParsePrefix("::/24"), []Prefix{MustPrefix("::/12")}) {
		t.Error("::/24 inside an overlay of ::/12 does not count, and darwin's scoped lookup loses its fallback")
	}
	// an overlay of the other family covers nothing, however short
	if !CapturesTheMachine(netip.MustParsePrefix("fd00::/8"), []Prefix{MustPrefix("203.0.0.0/8")}) {
		t.Error("an IPv4 overlay kept fd00::/8 from counting")
	}
	// an overlay entry longer than the prefix covers only part of it, even where both start
	if !CapturesTheMachine(netip.MustParsePrefix("fd00::/8"), []Prefix{MustPrefix("fd00::/16")}) {
		t.Error("an overlay of fd00::/16 kept fd00::/8 from counting")
	}
	// the overlay is the union of its entries: two adjacent entries hold their
	// aggregate, as do four quarters or eight eighths with no half among them,
	// and a gap between the pieces leaves it counting. A prefix with bits set
	// past its length is read as its masked form, whose upper half alone the
	// overlay holds.
	for _, test := range []struct {
		destination string
		overlay     []Prefix
		counts      bool
	}{
		{"3ff0::/12", []Prefix{MustPrefix("3ff0::/13"), MustPrefix("3ff8::/13")}, false},
		{"192.0.0.0/7", []Prefix{MustPrefix("193.0.0.0/8"), MustPrefix("192.0.0.0/8")}, false},
		{"3ff0::/12", []Prefix{MustPrefix("3ff0::/13"), MustPrefix("3ff8::/14"), MustPrefix("3ffc::/14")}, false},
		{"3ff0::/12", []Prefix{MustPrefix("3ff0::/13"), MustPrefix("3ffc::/14")}, true},
		{"3ff0::/12", []Prefix{MustPrefix("3ffc::/14"), MustPrefix("3ff0::/14"), MustPrefix("3ff8::/14"), MustPrefix("3ff4::/14")}, false},
		{"192.0.0.0/6", []Prefix{MustPrefix("195.0.0.0/8"), MustPrefix("192.0.0.0/8"), MustPrefix("194.0.0.0/8"), MustPrefix("193.0.0.0/8")}, false},
		{"3ff0::/12", []Prefix{
			MustPrefix("3ffa::/15"), MustPrefix("3ff0::/15"), MustPrefix("3ffe::/15"), MustPrefix("3ff4::/15"),
			MustPrefix("3ff8::/15"), MustPrefix("3ff2::/15"), MustPrefix("3ffc::/15"), MustPrefix("3ff6::/15"),
		}, false},
		{"3ff8::/12", []Prefix{MustPrefix("3ff8::/13")}, true},
		{"193.0.0.0/7", []Prefix{MustPrefix("193.0.0.0/8")}, true},
	} {
		if got := CapturesTheMachine(netip.MustParsePrefix(test.destination), test.overlay); got != test.counts {
			t.Errorf("%s counts %v under the overlay %v, want %v", test.destination, got, test.overlay, test.counts)
		}
	}
}
