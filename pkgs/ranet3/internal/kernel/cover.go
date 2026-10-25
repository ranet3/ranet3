// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"net/netip"
	"slices"
)

// zeroFreeCover holds, per family, the prefixes a plain default is installed
// as where the platform asks for it. Together the members hold every address but
// 0.0.0.0/8 and ::/8, and none holds its family's zero address, so a socket
// bound with IP_BOUND_IF keeps falling back to the host's own default.
// Measured by TestZMeasureTheZeroFreeCoverKeepsABoundSocket.
var zeroFreeCover = map[bool][]netip.Prefix{
	true: {
		netip.MustParsePrefix("1.0.0.0/8"), netip.MustParsePrefix("2.0.0.0/7"),
		netip.MustParsePrefix("4.0.0.0/6"), netip.MustParsePrefix("8.0.0.0/5"),
		netip.MustParsePrefix("16.0.0.0/4"), netip.MustParsePrefix("32.0.0.0/3"),
		netip.MustParsePrefix("64.0.0.0/2"), netip.MustParsePrefix("128.0.0.0/1"),
	},
	false: {
		netip.MustParsePrefix("100::/8"), netip.MustParsePrefix("200::/7"),
		netip.MustParsePrefix("400::/6"), netip.MustParsePrefix("800::/5"),
		netip.MustParsePrefix("1000::/4"), netip.MustParsePrefix("2000::/3"),
		netip.MustParsePrefix("4000::/2"), netip.MustParsePrefix("8000::/1"),
	},
}

// coverer is implemented by a platform that installs a plain default as its
// zero-free cover, which is darwin with the underlay socket bound.
type coverer interface{ covers() bool }

// plainDefault is a default with no source that carries traffic, the one
// route a cover stands in for. A hold and a source-specific default stay
// what they are.
func plainDefault(r Route) bool {
	return r.Destination.Bits() == 0 && !r.Source.IsValid() && !r.Unreachable
}

// coverDefaults replaces each plain default with its family's cover members.
// A member is withheld where another route the kernel holds unscoped, of
// length 1 up to the member's own, contains it, so for every address outside
// the hole the kernel's longest match is the route the default's would be,
// or a member where that is the default itself (RFC 8966 Appendix C: the
// protocol keeps the default, only the kernel holds the cover). unmet names
// the routes an unbound lookup will not meet in the kernel, which withhold
// nothing.
func coverDefaults(desired []Route, unmet func(Route) bool) []Route {
	if !slices.ContainsFunc(desired, plainDefault) {
		return desired
	}
	if unmet == nil {
		unmet = func(Route) bool { return false }
	}
	out := make([]Route, 0, len(desired)+len(zeroFreeCover[true]))
	for _, r := range desired {
		if !plainDefault(r) {
			out = append(out, r)
		}
	}
	for _, r := range desired {
		if !plainDefault(r) {
			continue
		}
		for _, member := range zeroFreeCover[r.Destination.Addr().Is4()] {
			if withheld(member, desired, unmet) {
				continue
			}
			covering := Route{Destination: member, Metric: r.Metric, Cover: true}
			if !slices.Contains(out, covering) {
				out = append(out, covering)
			}
		}
	}
	return out
}

func withheld(member netip.Prefix, routes []Route, unmet func(Route) bool) bool {
	return slices.ContainsFunc(routes, func(r Route) bool {
		bits := r.Destination.Bits()
		return !r.Cover && bits >= 1 && bits <= member.Bits() &&
			r.Destination.Addr().Is4() == member.Addr().Is4() &&
			r.Destination.Contains(member.Addr()) && !unmet(r)
	})
}

func coveredFamilies(routes []Route) []Family {
	var out []Family
	for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
		if slices.ContainsFunc(routes, func(r Route) bool { return r.Cover && familyOf(r.Destination.Addr()) == family }) {
			out = append(out, family)
		}
	}
	return out
}
