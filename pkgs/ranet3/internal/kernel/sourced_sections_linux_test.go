// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"net/netip"
	"slices"
	"testing"
)

// Check the emitted answer ranges against each concrete destination, not
// against the partitioning algorithm: every selected prefix must have the
// same route-selector membership at all addresses it covers.
func TestSourcedSectionsCoverEveryAddressWithUniformRouteSelectors(t *testing.T) {
	base := netip.MustParsePrefix("fd5e:db8:10:2::/125")
	candidates := []netip.Prefix{
		base,
		netip.MustParsePrefix("fd5e:db8:10:2::/124"),
		netip.MustParsePrefix("fd5e:db8:10:2::/126"),
		netip.MustParsePrefix("fd5e:db8:10:2::4/126"),
		netip.MustParsePrefix("fd5e:db8:10:2::2/127"),
		netip.MustParsePrefix("fd5e:db8:10:2::3/128"),
		netip.MustParsePrefix("fd5e:db8:10:2::8/128"),
	}
	for mask := range 1 << len(candidates) {
		var cuts []netip.Prefix
		for i, candidate := range candidates {
			if mask&(1<<i) != 0 {
				cuts = append(cuts, candidate)
			}
		}
		if mask&1 != 0 {
			slices.Reverse(cuts)
		}
		sections := sourcedSections(base, cuts)
		address := base.Addr()
		for range 8 {
			covered := 0
			for _, section := range sections {
				if !base.Contains(section.Addr()) || section.Bits() < base.Bits() {
					t.Fatalf("cuts %v emitted a section outside %s: %s", cuts, base, section)
				}
				if !section.Contains(address) {
					continue
				}
				covered++
				for _, cut := range cuts {
					if cut.Contains(section.Addr()) != cut.Contains(address) {
						t.Fatalf("cuts %v gave %s an answer covering %s with a different selector: %s", cuts, section, address, cut)
					}
				}
			}
			if covered != 1 {
				t.Fatalf("cuts %v covered %s %d times with %v", cuts, address, covered, sections)
			}
			address = address.Next()
		}
	}
}
