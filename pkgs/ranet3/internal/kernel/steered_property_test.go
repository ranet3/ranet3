// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build (linux && !android) || (darwin && !ios)

package kernel

import (
	"maps"
	"net/netip"
	"slices"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/schema"
)

// otherSIDs are the SIDs a drawn via names beside this node's own, two inside
// the overlay the property draws most often and one outside it
var otherSIDs = []netip.Addr{waypointSID, exitSID, addr("2001:db8:5::1")}

// countingShapes are the routes that count a drawn table holds: a default, a
// /1 pair, four /2s, 2000::/3 and a source-specific default
var countingShapes = [][]mirrorEntry{
	{{destination: prefix("0.0.0.0/0")}, {destination: prefix("::/0")}},
	{{destination: prefix("0.0.0.0/1")}, {destination: prefix("128.0.0.0/1")}},
	{{destination: prefix("0.0.0.0/2")}, {destination: prefix("64.0.0.0/2")}, {destination: prefix("128.0.0.0/2")}, {destination: prefix("192.0.0.0/2")}},
	{{destination: prefix("2000::/3")}},
	{{source: prefix("3fff::/20"), destination: prefix("::/0")}},
}

// steeredEntries draws a table for mode 3: the mirror's entries of every kind,
// and some of the shapes that count, each learned or held
// this node's own SID is a /128 of this node's three times in four and swept
// through sidEntry's kinds otherwise, and each other SID's /128 is routed seven
// times in ten, the SID under a subnet alone one time in ten, under a learned
// 2000::/3, which counts, one time in ten, and swept otherwise, so most paths
// are up or down by where via names the own SID
func steeredEntries(ht *hegel.T) []mirrorEntry {
	entries := hegel.Draw(ht, mirrorEntries())
	for _, shape := range pbt.Subset(ht, countingShapes, 0, len(countingShapes)) {
		value := hegel.Draw(ht, hegel.SampledFrom([]*netstack.Peer{learned, netstack.Unreachable}))
		for _, entry := range shape {
			entry.value = value
			entries = append(entries, entry)
		}
	}
	if hegel.Draw(ht, hegel.WeightedBooleans(3.0/4)) {
		entries = append(entries, host(ownSID, netstack.Local))
	} else {
		entries = append(entries, sidEntry(ht, ownSID)...)
	}
	for _, sid := range otherSIDs {
		switch kind := hegel.Draw(ht, hegel.Integers(0, 9)); {
		case kind < 7:
			entries = append(entries, sidEntry(ht, sid, 1)...)
		case kind == 7:
			entries = append(entries, sidEntry(ht, sid, 4)...)
		case kind == 8:
			entries = append(entries, sidEntry(ht, sid, 5)...)
		default:
			entries = append(entries, sidEntry(ht, sid)...)
		}
	}
	return entries
}

// sidEntry is the entry drawn for sid among kinds, every kind where none is
// given, the first and the last drawn outright: 0 nothing, 1 its /128 routed,
// 2 held, 3 this node's own, 4 a subnet covering it, 5 a learned 2000::/3
func sidEntry(ht *hegel.T, sid netip.Addr, kinds ...int) []mirrorEntry {
	if len(kinds) == 0 {
		kinds = []int{0, 1, 2, 3, 4, 5}
	}
	switch kinds[hegel.Draw(ht, pbt.Spanning(0, len(kinds)-1))] {
	case 1:
		return []mirrorEntry{host(sid, learned)}
	case 2:
		return []mirrorEntry{host(sid, netstack.Unreachable)}
	case 3:
		return []mirrorEntry{host(sid, netstack.Local)}
	case 4:
		return []mirrorEntry{{destination: netip.PrefixFrom(sid, 48).Masked(), value: learned}}
	case 5:
		return []mirrorEntry{{destination: prefix("2000::/3"), value: learned}}
	}
	return nil
}

// modelResolve is the entry RFC 9079 section 4 prefers for a packet from
// source to destination, "destination-first ordering", walked linearly: the
// longest destination, then the longest source, an entry with no source the
// least specific
func modelResolve(entries []mirrorEntry, source, destination netip.Addr) (mirrorEntry, bool) {
	sourceBits := func(entry mirrorEntry) int {
		if !entry.source.IsValid() {
			return -1
		}
		return entry.source.Bits()
	}
	var best mirrorEntry
	found := false
	for _, entry := range entries {
		if !entry.destination.Contains(destination) || entry.source.IsValid() && !entry.source.Contains(source) {
			continue
		}
		if !found || entry.destination.Bits() > best.destination.Bits() ||
			entry.destination.Bits() == best.destination.Bits() && sourceBits(entry) > sourceBits(best) {
			best, found = entry, true
		}
	}
	return best, found
}

// modelPathUp is every SID of via resolving to a peer through its own /128, a
// SID after the first being this node's own allowed
func modelPathUp(entries []mirrorEntry, via []netip.Addr) bool {
	for i, sid := range via {
		entry, ok := modelResolve(entries, steeredSource, sid)
		switch {
		case ok && i > 0 && (entry.value == netstack.Local || entry.value == netstack.Assigned):
		case !ok, entry.value != learned, entry.destination != netip.PrefixFrom(sid, 128):
			return false
		}
	}
	return true
}

// Mode 3's mirror is routing.md's table with every route that counts left out
// and the two steered defaults added exactly while the pass may capture this
// machine's traffic and every SID resolves, on an exit and on a node that is none, with and without the
// policy rules, and beside a carve-out's throw half the time. Mode off and mode 2 are the table unchanged.
func TestMirrorInModeThreeHoldsTheSteeredDefaultsAndNoRouteThatCounts(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		overlay := hegel.Draw(ht, hegel.SampledFrom([][]schema.Prefix{
			steeredOverlay,
			prefixes(prefix("3fff::/20")),
			prefixes(prefix("192.0.2.0/24"), prefix("3fff::/20"), prefix("2001:db8::/32")),
			nil,
		}))
		network := drawnCarveNetwork(ht)
		// half the time a link's network inside an overlay prefix, a carve-out whose throw sits beside the steered defaults
		if len(overlay) > 0 && hegel.Draw(ht, hegel.Booleans()) {
			o := overlay[hegel.Draw(ht, pbt.Spanning(0, len(overlay)-1))].Masked()
			link := Link{Name: "br-carve", Prefixes: []netip.Prefix{netip.PrefixFrom(o.Addr(), min(o.Addr().BitLen(), o.Bits()+hegel.Draw(ht, pbt.Spanning(0, 8)))).Masked()}}
			if o.Addr().Is4() {
				network.IPv4.Links = append(network.IPv4.Links, link)
			} else {
				network.IPv6.Links = append(network.IPv6.Links, link)
			}
		}
		var carved []netip.Prefix
		for _, carveOut := range carveModel(network, overlay) {
			carved = append(carved, carveOut.Prefix)
		}
		rt := Runtime{Interface: "ranet0", Overlay: overlay, EgressSegment: hegel.Draw(ht, hegel.Booleans()), Network: func() NetworkState { return network }}
		// mode 3 half the time, since the steered defaults are its alone
		mode := "3"
		if hegel.Draw(ht, hegel.Booleans()) {
			mode = hegel.Draw(ht, hegel.SampledFrom([]string{"off", "2"}))
		}
		var table Table
		var via []netip.Addr
		switch mode {
		case "2":
			table = Table{}.WithMode(&ExitMode{})
		case "3":
			via = pbt.Subset(ht, otherSIDs, 1, 2)
			// this node's own SID, where via names it, takes each place, first and last drawn outright
			if hegel.Draw(ht, hegel.WeightedBooleans(3.0/4)) {
				via = slices.Insert(via, hegel.Draw(ht, pbt.Spanning(0, len(via))), ownSID)
			}
			table = modeThree(via...)
		}
		policy := hegel.Draw(ht, hegel.Booleans())
		var plat platform = newFakeKernel(t)
		if !policy {
			plat = routesOnly{inner: plat.(*fakeKernel)}
		}
		routes := netstack.NewRouteTable()
		r := newReconciler(table.Normalized(), rt, nil, routes, plat)
		r.capture = hegel.Draw(ht, hegel.Booleans())
		for _, entry := range steeredEntries(ht) {
			routes.Set(entry.source, entry.destination, entry.value)
		}
		var held []mirrorEntry
		for _, entry := range routes.Snapshot() {
			held = append(held, mirrorEntry{source: entry.Source, destination: entry.Destination, value: entry.Value})
		}
		got := r.desired(routes.Snapshot(), r.readNetwork())
		want := sectionOneThree(held, overlay, carved, rt.EgressSegment, r.capture, policy)
		if mode == "3" {
			maps.DeleteFunc(want, func(route Route, _ bool) bool { return schema.CapturesTheMachine(route.Destination, overlay) })
			if r.capture && modelPathUp(held, via) {
				for _, route := range steered() {
					want[route] = true
				}
			}
		}
		set := map[Route]bool{}
		for _, route := range got {
			if set[route] {
				ht.Fatalf("the mirror wants %s twice", route)
			}
			set[route] = true
		}
		if !maps.Equal(set, want) {
			ht.Fatalf("mode %s along %v: the mirror wants\n%v\nthe model has\n%v", mode, via, sortedRoutes(set), sortedRoutes(want))
		}
	})
}
