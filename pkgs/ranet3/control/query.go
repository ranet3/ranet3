// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package control

import (
	"net/netip"
	"slices"
)

// This file is the questions a caller asks of what the reads returned rather
// than of the daemon: which prefix covers an address, which routes carry a
// default, and which addresses this node holds on the mesh. They live beside
// the types they read so that a monitor asks them the way the subcommands do,
// and so that a test asks them of the wire form rather than of a table.

// Covering is every route whose destination contains an address, longest
// prefix first, so the first entry is the one the forwarding table would use.
// Entries of equal length are ordered by their source prefix, since a
// source-specific route is keyed by the pair and several can share one
// destination.
//
// A retracted prefix is in the answer like any other, with no next hop. It is
// held rather than removed exactly so a packet does not follow a shorter
// prefix instead, and a reader asking where an address goes needs to see that.
func Covering(routes []Route, address netip.Addr) []Route {
	out := []Route{}
	for _, route := range routes {
		if route.Destination.Contains(address) {
			out = append(out, route)
		}
	}
	slices.SortStableFunc(out, func(a, b Route) int {
		if order := b.Destination.Bits() - a.Destination.Bits(); order != 0 {
			return order
		}
		return b.From.Bits() - a.From.Bits()
	})
	return out
}

// Defaults is every route carrying a default and both /1 halves of a family
// where one node advertises the pair, which covers the family as a default
// does, and nothing else. A node advertising another prefix that counts as a
// default (schema.CapturesTheMachine), such as 2000::/3, carries its family's
// traffic with no entry here and shows among the routes alone, since which
// prefixes count turns on the daemon's overlay. Both families are included
// and the order the daemon gave is kept, which leaves two entries for one
// family next to each other.
//
// The test is the prefix length against a zero address rather than the length
// alone: a /0 is the only prefix that covers everything, and spelling it this
// way refuses a prefix whose length happens to be zero for another reason.
func Defaults(routes []Route) []Route {
	type advertiser struct {
		routerID   string
		originated bool
		from       netip.Prefix
		v4         bool
	}
	whose := func(route Route) advertiser {
		return advertiser{route.RouterID, route.Originated, route.From, route.Destination.Addr().Is4()}
	}
	halves := map[advertiser][2]bool{}
	for _, route := range routes {
		if upper, ok := half(route.Destination); ok {
			held := halves[whose(route)]
			held[boolIndex(upper)] = true
			halves[whose(route)] = held
		}
	}
	out := []Route{}
	for _, route := range routes {
		_, isHalf := half(route.Destination)
		if route.Destination.Bits() == 0 && route.Destination.Addr().IsUnspecified() ||
			isHalf && halves[whose(route)] == [2]bool{true, true} {
			out = append(out, route)
		}
	}
	return out
}

func half(destination netip.Prefix) (upper, ok bool) {
	if destination.Bits() != 1 {
		return false, false
	}
	return !destination.Addr().IsUnspecified(), true
}

func boolIndex(b bool) int {
	if b {
		return 1
	}
	return 0
}

// MeshAddresses is the addresses this node carries on the mesh, taken from
// what it announces. Only a host prefix counts: a shorter one is a range this
// node carries traffic for rather than an address it answers at, and a
// default announced by an exit is neither. The daemon applies the same rule
// when it decides which addresses its egress translates into the mesh.
func MeshAddresses(status Status) []netip.Addr {
	out := make([]netip.Addr, 0, len(status.Originate))
	for _, announced := range status.Originate {
		prefix := announced.Prefix
		if prefix.Bits() != prefix.Addr().BitLen() || slices.Contains(out, prefix.Addr()) {
			continue
		}
		out = append(out, prefix.Addr())
	}
	return out
}
