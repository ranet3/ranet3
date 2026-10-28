// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"net/netip"
	"slices"

	"ranet3.com/pkgs/ranet3/schema"
)

// zeroFreeCover holds, per family, the prefixes a route holding its family's
// zero address is installed as where the platform asks for it. Together the
// members hold every address but 0.0.0.0/8 and ::/8, and none holds its
// family's zero address, so a socket scoped to an interface keeps falling back
// to the host's own default there.
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

// coverer is implemented by a platform that installs a route holding its
// family's zero address as the zero-free cover's members, which is darwin
// with link.underlay.bind.
type coverer interface{ covers() bool }

// zeroRoute is a route with no source that carries traffic and holds its
// family's zero address, the route a cover stands in for. A hold and a
// source-specific route stay what they are.
func zeroRoute(r Route) bool {
	return schema.HoldsUnspecified(r.Destination) && !r.Source.IsValid() && !r.Unreachable
}

// membersOf is the members of destination's family's cover that lie within
// it, none for a destination inside 0.0.0.0/8 or ::/8
func membersOf(destination netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for _, member := range zeroFreeCover[destination.Addr().Is4()] {
		if destination.Bits() <= member.Bits() && destination.Contains(member.Addr()) {
			out = append(out, member)
		}
	}
	return out
}

// memberless is a zero route inside 0.0.0.0/8 or ::/8, which a cover installs
// as nothing
func memberless(r Route) bool { return zeroRoute(r) && len(membersOf(r.Destination)) == 0 }

// coverDefaults replaces each zero route with the cover's members it
// contains, so a real 0.0.0.0/1 goes in as the seven members from 1.0.0.0/8
// to 64.0.0.0/2. A member is withheld where another route the kernel holds
// unscoped, of length 1 up to the member's own, contains it, so for every
// address outside the hole the kernel's longest match is the route the zero
// route's would be, or a member where that is the zero route itself (RFC 8966
// Appendix C: the protocol keeps the route, only the kernel holds the cover).
// unmet names the routes an unbound lookup will not meet in the kernel, which
// withhold nothing.
func coverDefaults(desired []Route, unmet func(Route) bool) []Route {
	if !slices.ContainsFunc(desired, zeroRoute) {
		return desired
	}
	if unmet == nil {
		unmet = func(Route) bool { return false }
	}
	out := make([]Route, 0, len(desired)+len(zeroFreeCover[true]))
	for _, r := range desired {
		if !zeroRoute(r) {
			out = append(out, r)
		}
	}
	for _, r := range desired {
		if !zeroRoute(r) {
			continue
		}
		for _, member := range membersOf(r.Destination) {
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

// withheld reports a route of routes the kernel holds unscoped, of length 1 up
// to the member's own, containing member. A zero route is installed as members
// and withholds nothing.
func withheld(member netip.Prefix, routes []Route, unmet func(Route) bool) bool {
	return slices.ContainsFunc(routes, func(r Route) bool {
		bits := r.Destination.Bits()
		return !r.Cover && !zeroRoute(r) && bits >= 1 && bits <= member.Bits() &&
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
