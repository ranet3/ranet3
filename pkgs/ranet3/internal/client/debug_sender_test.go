// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package client

import (
	"slices"
	"testing"
)

// the view shows the sender of each session the peer names, with its budgets and its histograms
func TestSenderViewShowsTheSessionsOfThePeerNamed(t *testing.T) {
	c := senderClient(t, "example/bravo:2@1", "example/bravo2:3@1")
	for _, peer := range []string{"example/bravo:2@1", "example/bravo:2", "example/bravo", "bravo"} {
		var shown []string
		for _, s := range c.DebugSender(peer).Sessions {
			shown = append(shown, s.Path)
		}
		if !slices.Equal(shown, []string{"example/bravo:2@1"}) {
			t.Errorf("the peer %s shows the senders %q, want example/bravo:2@1 alone", peer, shown)
		}
	}
	info := c.DebugSender("")
	if len(info.Sessions) != 2 {
		t.Fatalf("every peer shows %d senders, want both", len(info.Sessions))
	}
	s := info.Sessions[0]
	if s.DataLimit == 0 || s.ControlLimit == 0 || s.DataHeld != 0 || s.ControlHeld != 0 {
		t.Errorf("an idle sender shows %d of %d data bytes and %d of %d control places held", s.DataHeld, s.DataLimit, s.ControlHeld, s.ControlLimit)
	}
	if len(s.Releases.Bounds) != len(s.Releases.Counts)-1 || s.Releases.Bounds[0] != 1 || s.Releases.Counts[0] != 1 || s.Releases.Sum != 1 {
		t.Errorf("the sender's releases read %+v, want the one packet it sent", s.Releases)
	}
	if s.Seals.Bounds[0] != 1000 || s.HeadWaits.Bounds[1] != 2000 {
		t.Errorf("the wait histograms are bounded at %v and %v, want the powers of two of a microsecond in nanoseconds", s.Seals.Bounds, s.HeadWaits.Bounds)
	}
}

// the view's wait sums are in nanoseconds as its bounds are, so the sum of a sender's head waits lies between what the bounds of the buckets counting them allow
func TestSenderViewShowsWaitSumsInNanoseconds(t *testing.T) {
	c := clientWith(t, waitingPeer(t, "example/bravo:2@1"))
	waits := c.DebugSender("").Sessions[0].HeadWaits
	// lower and upper bound the sum the buckets allow, each observation over the bound before its bucket and at or under its own
	var count, lower, upper uint64
	for i, n := range waits.Counts {
		count += n
		if i > 0 {
			lower += n * waits.Bounds[i-1]
		}
		if i < len(waits.Bounds) {
			upper += n * waits.Bounds[i]
		} else if n != 0 {
			t.Fatalf("a head wait ran past every bound, so no bound checks the sum: %+v", waits)
		}
	}
	if count == 0 {
		t.Fatalf("the view shows no head wait: %+v", waits)
	}
	if waits.Sum < lower || waits.Sum > upper {
		t.Errorf("the head waits sum to %d nanoseconds, outside the %d to %d their buckets allow", waits.Sum, lower, upper)
	}
}
