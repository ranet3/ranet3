// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package babel

import (
	"net/netip"
	"testing"
	"time"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// the largest finite cost and smoothed cost
const mostFinite = int64(MetricInfinity) - 1

// the state the selected route is in when a pass runs
const (
	incumbentUnreachable = iota
	incumbentUnfeasible
	incumbentRetracted
	incumbentSelectable
)

// a selection pass keeps the selected route or takes the challenger as the model of the rule says, at margins 0, 4 and one drawn
// the model: a selected route that is still selectable is left only for one whose cost is lower and whose smoothed cost is lower by more than the margin, compared in whole numbers
// at margin 0 that is the rule of RFC 8966 Appendix A.3 alone, a lower cost and a lower smoothed cost
// a selected route that is unreachable, unfeasible or retracted gives way to the challenger whatever the margin
func TestSelectionKeepsOrLeavesTheSelectedRouteAsTheMarginRuleSays(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		finite := pbt.Spanning[int64](reachableLinkCost+1, mostFinite)
		incumbentCost, challengerCost := hegel.Draw(ht, finite), hegel.Draw(ht, finite)
		challengerSmoothed := challengerCost + hegel.Draw(ht, pbt.Spanning[int64](0, mostFinite-challengerCost))
		state := hegel.Draw(ht, pbt.Spanning[int64](incumbentUnreachable, incumbentSelectable+2))
		challengerFirst := hegel.Draw(ht, pbt.Spanning[int64](0, 1)) == 1
		for _, margin := range []int64{0, defaultMargin, hegel.Draw(ht, pbt.Spanning[int64](0, mostFinite))} {
			// drawn near the boundary of the smoothed comparison half the time, and anywhere it can be otherwise
			incumbentSmoothed := incumbentCost + hegel.Draw(ht, pbt.Spanning[int64](0, mostFinite-incumbentCost))
			if hegel.Draw(ht, pbt.Spanning[int64](0, 1)) == 1 {
				incumbentSmoothed = min(max(incumbentCost, challengerSmoothed+margin+hegel.Draw(ht, pbt.Spanning[int64](-1, 1))), mostFinite)
			}

			master := challengerCost < incumbentCost && challengerSmoothed < incumbentSmoothed
			leaves := state < incumbentSelectable || master && challengerSmoothed+margin < incumbentSmoothed

			got := passAfter(ht, uint16(margin), state, challengerFirst,
				uint16(incumbentCost), float64(incumbentSmoothed), uint16(challengerCost), float64(challengerSmoothed))
			if got != leaves {
				ht.Fatalf("at margin %d, a selected route %s at cost %d smoothed %d against one at %d smoothed %d was left %v, want %v",
					margin, []string{"unreachable", "unfeasible", "retracted", "selectable"}[min(state, incumbentSelectable)],
					incumbentCost, incumbentSmoothed, challengerCost, challengerSmoothed, got, leaves)
			}
		}
	})
}

// passAfter selects the incumbent with the smoothed costs given, puts it in state, runs one selection pass, and reports whether the challenger was selected
// the pass runs at the instant the smoothed costs were stamped, so it takes them as they are
func passAfter(ht *hegel.T, margin uint16, state int64, challengerFirst bool,
	incumbentCost uint16, incumbentSmoothed float64, challengerCost uint16, challengerSmoothed float64) bool {
	// a tie in cost goes to the peer ID that sorts first
	names := []string{"a-incumbent", "b-challenger"}
	if challengerFirst {
		names = []string{"b-incumbent", "a-challenger"}
	}
	key := routeKey{dest: netip.MustParsePrefix("2001:db8:7::/48")}
	incumbent, challenger := &neighborState{peer: &netstack.Peer{ID: names[0]}}, &neighborState{peer: &netstack.Peer{ID: names[1]}}
	makeNeighborReachable(incumbent)
	makeNeighborReachable(challenger)
	rt := newRouteTable(func(routeKey, routeSelection) {})
	rt.tau, rt.margin = marginTau, margin
	now := time.Now()
	incumbentID, challengerID := [8]byte{1}, [8]byte{2}
	rt.update(incumbent, key, advertisement{routerID: incumbentID, seqno: 1, metric: incumbentCost - reachableLinkCost}, time.Hour, now)
	rt.update(challenger, key, advertisement{routerID: challengerID, seqno: 1, metric: challengerCost - reachableLinkCost}, time.Hour, now)
	entry := rt.entries[key]
	entry.selected = entry.selectionFor(incumbent, incumbentCost)
	entry.routes[incumbent].smoothed, entry.routes[incumbent].smoothedAt = incumbentSmoothed, now
	entry.routes[challenger].smoothed, entry.routes[challenger].smoothedAt = challengerSmoothed, now
	switch state {
	case incumbentUnreachable:
		incumbent.alive = false
	case incumbentUnfeasible:
		rt.observe(key, advertisement{routerID: incumbentID, seqno: 1, metric: 0}, incumbent.peer.ID, now)
	case incumbentRetracted:
		entry.routes[incumbent].rxMetric = MetricInfinity
	}
	rt.selectRoute(key, entry, now)
	switch got := entry.selected.neighbor; got {
	case challenger:
		return true
	case incumbent:
		return false
	default:
		ht.Fatalf("the pass selected %v, neither route", got)
		return false
	}
}
