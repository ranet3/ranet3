// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

package babel

import (
	"testing"
	"time"
)

func TestCostFormula(t *testing.T) {
	p := CostParams{RTT: RTTCost{Max: dur(1024 * time.Millisecond), Weight: 1024}}

	if c := p.RTTPenalty(2*time.Second, false); c != 0 {
		t.Errorf("no RTT sample: got %d, want 0", c)
	}
	if c := p.RTTPenalty(0, true); c != 0 {
		t.Errorf("rtt=0: got %d, want 0", c)
	}
	if c := p.RTTPenalty(2*time.Second, true); c != 1024 {
		t.Errorf("rtt above max: got %d, want 1024", c)
	}
	if c := p.RTTPenalty(512*time.Millisecond, true); c != 512 {
		t.Errorf("rtt at midpoint: got %d, want 512", c)
	}
}

// RFC 9616 section 4.2 maps the smoothed round trip to a link cost "suitable
// for input to the metric computation procedure (Section 3.5.2 of [RFC8966])",
// and that procedure is the one a node runs on its own routes. Feeding the
// penalty to the advertised rxcost instead leaves selection blind, because the
// other end advertises its nominal cost, so a near and a far neighbor would
// read the same cost.
func TestRoundTripPenaltyLandsOnTheCostThisNodeComputes(t *testing.T) {
	params := DefaultCostParams()
	now := time.Now()
	neighbor := func(rtt time.Duration) *neighborState {
		n := &neighborState{
			alive: true, haveReportedCost: true, reportedCost: 96,
			ihuExpiry: now.Add(time.Minute), measuredRTT: rtt, haveRTT: true,
		}
		n.helloInterval = time.Minute
		n.lastHelloTime = now
		return n
	}
	near, far := neighbor(10*time.Millisecond), neighbor(307*time.Millisecond)
	nearCost, farCost := near.linkCost(now, params), far.linkCost(now, params)
	if nearCost != 96 {
		t.Errorf("a 10ms link costs %d, want the reported 96 with no penalty", nearCost)
	}
	if farCost <= nearCost {
		t.Fatalf("a 307ms link costs %d and a 10ms one %d, so selection cannot tell them apart", farCost, nearCost)
	}
	if farCost != 96+299 {
		t.Errorf("a 307ms link costs %d, want the reported 96 and a penalty of 299", farCost)
	}
}

// A neighbor with no round-trip sample yet must cost exactly what it reports,
// or every link starts penalized before a single timestamp has been exchanged.
func TestNoRoundTripSampleAddsNoPenalty(t *testing.T) {
	now := time.Now()
	n := &neighborState{alive: true, haveReportedCost: true, reportedCost: 96, ihuExpiry: now.Add(time.Minute)}
	n.helloInterval, n.lastHelloTime = time.Minute, now
	if got := n.linkCost(now, DefaultCostParams()); got != 96 {
		t.Errorf("an unmeasured link costs %d, want 96", got)
	}
}
