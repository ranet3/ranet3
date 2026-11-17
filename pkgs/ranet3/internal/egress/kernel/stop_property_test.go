// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package kernel

import (
	"slices"
	"strings"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// faultPool is the texts a drawn readback's faults take, few so that two
// fields often hold the same text, the empty one among them
var faultPool = []string{"", "its table carries flags 0x1", "its set untranslated4 holds another element", "its chain forward holds another line"}

// readbacks draws each family's flag, dormant flag, refusedOn, fault and
// misplaced chain, set or object from faultPool
func readbacks() hegel.Generator[map[uint8]chainReadback] {
	return hegel.Composite(func(tc hegel.TestCase) map[uint8]chainReadback {
		text := func() string { return faultPool[hegel.Draw(tc, pbt.Spanning(0, len(faultPool)-1))] }
		out := map[uint8]chainReadback{}
		for _, family := range []uint8{egress.FamilyIPv4, egress.FamilyIPv6} {
			out[family] = chainReadback{flag: text(), dormant: text(), refusedOn: text(), fault: text(), misplaced: text()}
		}
		return out
	})
}

// A stop names the cause of its fault first, the first of the flags, the
// refusals and the faults in that order, then each way out of place once: the
// dormant flag of either family and the first family's misplaced chain, set or
// object, and no other text, each text once
func TestStopFaultNamesItsCauseFirstAndEachWayOutOfPlaceOnce(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		read := hegel.Draw(ht, readbacks())
		v4, v6 := read[egress.FamilyIPv4], read[egress.FamilyIPv6]
		var cause string
		for _, text := range []string{v4.flag, v6.flag, v4.refusedOn, v6.refusedOn, v4.fault, v6.fault} {
			if text != "" {
				cause = text
				break
			}
		}
		ways := map[string]bool{}
		for _, pair := range [][2]string{{v4.dormant, v6.dormant}, {v4.misplaced, v6.misplaced}} {
			if way := pair[0] + pair[1]; way != "" {
				if pair[0] != "" {
					way = pair[0]
				}
				ways[way] = true
			}
		}
		got := stopFault(read)
		var parts []string
		if got != "" {
			parts = strings.Split(got, ", and ")
		}
		if cause != "" && (len(parts) == 0 || parts[0] != cause) {
			ht.Fatalf("the stop names %q, want it to start with the cause %q", got, cause)
		}
		for i, part := range parts {
			if part == "" || slices.Contains(parts[:i], part) || part != cause && !ways[part] {
				ht.Fatalf("the stop names %q, whose part %q is empty, repeated or neither the cause %q nor a way out of place of %v", got, part, cause, ways)
			}
		}
		for way := range ways {
			if !slices.Contains(parts, way) {
				ht.Fatalf("the stop names %q, which leaves out the way out of place %q", got, way)
			}
		}
		if len(ways) == 0 && got != cause {
			ht.Fatalf("the stop names %q where the stopped rules are in place, want the cause %q alone", got, cause)
		}
	})
}
