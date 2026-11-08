// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package codel

import (
	"slices"
	"testing"
	"time"
)

// the delay control on a fake clock, one item a millisecond unless a phase spaces them out
// every item of a phase reads the same sojourn, and in some phases the queue empties after each item
// each drop falls on the first item at or after the time the RFC 8289 control law gives, the interval over the square root of the count
// the count starts at one on a fresh entry, and at the last state's drops past its first on an entry within 16 intervals of that state's schedule
// an empty queue ends the dropping state and starts the interval over, as RFC 8289 section 5.5 has it
// and keeps the count and the schedule, so a delay back soon after it starts at the rate the state had reached
// the phases run with the clock at zero and an hour in, where a schedule reset to zero is older than the 16 intervals a quick entry allows
func TestCodelEntersStaysLeavesAndReenters(t *testing.T) {
	for _, clock := range []struct {
		name string
		age  time.Duration
	}{{"a clock at zero", 0}, {"a clock an hour in", time.Hour}} {
		t.Run(clock.name, func(t *testing.T) { codelPhases(t, clock.age) })
	}
}

// codelPhases runs the delay control through the phases of TestCodelEntersStaysLeavesAndReenters on a clock that reads age at its start
func codelPhases(t *testing.T, age time.Duration) {
	var c Controller
	for _, phase := range []struct {
		name              string
		from, to, sojourn int // milliseconds
		gap               int // milliseconds between two items, one when zero
		empty             bool
		drops             []int
		dropping          bool // the state the phase ends in
	}{
		{name: "below the target", from: 1, to: 50, sojourn: 1},
		{name: "above it for less than an interval", from: 51, to: 120, sojourn: 20},
		{name: "below it again", from: 121, to: 130, sojourn: 1},
		// an interval after the delay went above, then each drop the interval over the square root of the one before's count after it
		{name: "above it for long enough", from: 131, to: 600, sojourn: 20, dropping: true,
			drops: []int{231, 331, 402, 460, 510, 555, 595}},
		{name: "below it", from: 601, to: 650, sojourn: 1},
		// soon after the last state, so the count starts at the drops that state made past its first
		{name: "above it soon after", from: 651, to: 900, sojourn: 20, dropping: true,
			drops: []int{751, 792, 830, 865, 899}},
		// an item before the next drop is due, after which the queue is empty
		{name: "the queue empties while dropping", from: 901, to: 901, sojourn: 20, empty: true},
		// so the interval starts over rather than finding a drop long due
		// and the entry that follows is soon enough for the count to start at the drops the state made past its first
		{name: "above it again once the queue emptied", from: 902, to: 1150, sojourn: 20, dropping: true,
			drops: []int{1002, 1052, 1097, 1138}},
		{name: "below it until the re-entry window has almost closed", from: 1151, to: 2675, sojourn: 1},
		// just past 16 intervals after the last drop was due, so the count starts over at one
		{name: "above it just past 16 intervals later", from: 2676, to: 2975, sojourn: 20, dropping: true,
			drops: []int{2776, 2876, 2947}},
		{name: "below it until the re-entry window has almost closed again", from: 2976, to: 4503, sojourn: 1},
		// just inside 16 intervals after the last drop was due, so the count starts at the drops the state made past its first
		{name: "above it just inside 16 intervals later", from: 4504, to: 4700, sojourn: 20, dropping: true,
			drops: []int{4604, 4675}},
		{name: "below it once more", from: 4701, to: 4800, sojourn: 1},
		// each item alone in the queue, so none finds the interval of the one before it run out
		{name: "lone items above it further apart than the interval", from: 4801, to: 6801, gap: 200, sojourn: 8, empty: true},
	} {
		var drops []int
		for at := phase.from; at <= phase.to; at += max(phase.gap, 1) {
			if c.Drop(age+time.Duration(at)*time.Millisecond, time.Duration(phase.sojourn)*time.Millisecond) {
				drops = append(drops, at)
			}
			if phase.empty {
				c.Empty()
			}
		}
		if !slices.Equal(drops, phase.drops) {
			t.Errorf("%s: dropped at %v milliseconds, want %v", phase.name, drops, phase.drops)
		}
		if c.Dropping() != phase.dropping {
			t.Errorf("%s: ended in the dropping state %v, want %v", phase.name, c.Dropping(), phase.dropping)
		}
	}
}
