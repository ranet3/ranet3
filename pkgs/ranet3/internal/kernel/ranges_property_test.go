// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package kernel

import (
	"net/netip"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// runAddress is address i of run, each run 256 addresses long: one in the
// middle of IPv4, the last of IPv4, whose last address adjoins nothing, and
// the first of IPv6
func runAddress(run, i int) netip.Addr {
	switch run {
	case 0:
		return netip.AddrFrom4([4]byte{198, 51, 100, byte(i)})
	case 1:
		return netip.AddrFrom4([4]byte{255, 255, 255, byte(i)})
	}
	var address [16]byte
	address[15] = byte(i)
	return netip.AddrFrom16(address)
}

// drawnRanges is up to six ranges inside the runs, in any order, overlapping
// or adjoining as they fall
func drawnRanges(tc hegel.TestCase) []egress.Range {
	var out []egress.Range
	for range hegel.Draw(tc, pbt.Spanning(0, 6)) {
		run := hegel.Draw(tc, pbt.Spanning(0, 2))
		first := hegel.Draw(tc, pbt.Spanning(0, 255))
		last := hegel.Draw(tc, pbt.Spanning(first, 255))
		out = append(out, egress.Range{First: runAddress(run, first), Last: runAddress(run, last)})
	}
	return out
}

// egress.Union, subtract, intersect and meets each answer for every address
// of the runs what that address's check against their inputs answers, and the
// first three leave their ranges in Union form
func TestRangeArithmeticHoldsWhatEachAddressAsks(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		drawnA, drawnB := drawnRanges(ht), drawnRanges(ht)
		a, b := egress.Union(drawnA), egress.Union(drawnB)
		less, both := subtract(a, b), intersect(a, b)
		for _, ranges := range [][]egress.Range{a, b, less, both} {
			checkRanges(ht, ranges)
		}
		met := false
		for run := range 3 {
			for i := range 256 {
				address := runAddress(run, i)
				inA, inB := inRanges(drawnA, address), inRanges(drawnB, address)
				if inRanges(a, address) != inA {
					ht.Fatalf("at %s: %v joined is %v", address, drawnA, a)
				}
				if inRanges(less, address) != (inA && !inB) {
					ht.Fatalf("at %s: %v less %v is %v", address, a, b, less)
				}
				if inRanges(both, address) != (inA && inB) {
					ht.Fatalf("at %s: %v and %v both hold %v", address, a, b, both)
				}
				met = met || inA && inB
			}
		}
		if meets(a, b) != met {
			ht.Fatalf("%v meets %v is %v, an address of both lies there %v", a, b, !met, met)
		}
	})
}
