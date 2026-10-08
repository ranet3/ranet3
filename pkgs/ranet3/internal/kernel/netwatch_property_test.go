// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package kernel

import (
	"math"
	"net/netip"
	"slices"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// addressPool holds the addresses a drawn family takes a subset of, in no particular order
var addressPool = []string{"198.51.100.7", "10.0.0.1", "2001:db8::1", "192.0.2.1", "10.0.0.2", "2001:db8::", "203.0.113.9", "172.16.0.1"}

// defaultPool is the default a drawn family has, none among them
var defaultPool = []DefaultRoute{{}, {Interface: "en0", Gateway: netip.MustParseAddr("192.168.1.1")}, {Interface: "en0"}, {Interface: "en7", Gateway: netip.MustParseAddr("192.168.1.1")}}

// drawnFamily is the family one byte of members and an index into defaultPool select
func drawnFamily(members uint8, choice uint8) (NetworkFamily, map[netip.Addr]bool) {
	set := make(map[netip.Addr]bool)
	var list []netip.Addr
	for i, s := range addressPool {
		if members&(1<<i) != 0 {
			address := netip.MustParseAddr(s)
			set[address] = true
			list = append(list, address)
		}
	}
	return NetworkFamily{Default: defaultPool[choice], Addresses: addressSet(list)}, set
}

// a family moves exactly when its default or its set of addresses differs
// what it reports added is the set after less the one before, and removed the reverse, each sorted
// each side draws its members and its default on its own, and a flip of no member keeps the set while the default moves alone
// every pair of defaults over the drawn set is checked as well, so a default moving alone is met in every run
func TestFamilyDiffAgreesWithASetModel(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		members := hegel.Draw(ht, pbt.Spanning[uint8](0, math.MaxUint8))
		flip := hegel.Draw(ht, pbt.Spanning[uint8](0, math.MaxUint8))
		was := hegel.Draw(ht, pbt.Spanning[uint8](0, uint8(len(defaultPool)-1)))
		is := hegel.Draw(ht, pbt.Spanning[uint8](0, uint8(len(defaultPool)-1)))
		agreesWithSets(ht, members, was, members^flip, is)
		for before := range uint8(len(defaultPool)) {
			for after := range uint8(len(defaultPool)) {
				agreesWithSets(ht, members, before, members, after)
			}
		}
	})
}

// agreesWithSets checks the diff of two drawn families against the difference of their sets
func agreesWithSets(ht *hegel.T, members, was, now, is uint8) {
	before, had := drawnFamily(members, was)
	after, has := drawnFamily(now, is)
	change, moved := diffFamily(FamilyIPv4, before, after)

	var added, removed []netip.Addr
	for address := range has {
		if !had[address] {
			added = append(added, address)
		}
	}
	for address := range had {
		if !has[address] {
			removed = append(removed, address)
		}
	}
	slices.SortFunc(added, netip.Addr.Compare)
	slices.SortFunc(removed, netip.Addr.Compare)
	if !slices.Equal(change.Added, added) || !slices.Equal(change.Removed, removed) {
		ht.Fatalf("from %v to %v the diff added %v and removed %v, want %v and %v",
			before.Addresses, after.Addresses, change.Added, change.Removed, added, removed)
	}
	want := before.Default != after.Default || len(added) > 0 || len(removed) > 0
	if moved != want {
		ht.Fatalf("from %+v to %+v the diff moved %v, want %v", before, after, moved, want)
	}
	if change.DefaultBefore != before.Default || change.DefaultAfter != after.Default {
		ht.Fatalf("the diff reports the default as %+v to %+v, want %+v to %+v", change.DefaultBefore, change.DefaultAfter, before.Default, after.Default)
	}
}
