// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package babel

import (
	"testing"
	"time"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// RFC 8966 section 3.4.3: "the cost is strictly positive", so a neighbor reporting an rxcost of 0 costs 1, in selection and in what the neighbors view shows
func TestLinkCostOfANeighborReportingZeroIsOne(t *testing.T) {
	speaker, neighbor, _ := captureSpeaker(t, Config{})
	speaker.handlePacket(neighbor, EncodePacket([]RawTLV{
		EncodeHello(Hello{Seqno: 1, Interval: 400}),
		EncodeIHU(IHU{RxCost: 0, Interval: 400}),
	}))
	stats := speaker.Stats()
	if len(stats.Neighbors) != 1 || !stats.Neighbors[0].Alive {
		t.Fatalf("the neighbor did not come up: %+v", stats.Neighbors)
	}
	if cost := stats.Neighbors[0].Cost; cost != 1 {
		t.Errorf("the neighbors view shows a link cost of %d for a neighbor reporting rxcost 0, want 1", cost)
	}
	speaker.mu.Lock()
	defer speaker.mu.Unlock()
	if cost := neighbor.linkCost(time.Now(), speaker.cost); cost != 1 {
		t.Errorf("the link cost of a neighbor reporting rxcost 0 is %d, want 1", cost)
	}
}

// RFC 8966 section 3.4.3 asks only that a link's cost be "strictly positive", and section 3.5.2 that a route's metric through it be greater than the metric its neighbor advertised
// both hold for any rxcost a neighbor reports, 0 among them, any Hello history, round trip and extra
func TestLinkCostIsStrictlyPositive(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		var reported uint16
		if hegel.Draw(ht, hegel.Booleans()) {
			reported = hegel.Draw(ht, hegel.SampledFrom([]uint16{0, 1, MetricInfinity - 1}))
		} else {
			reported = hegel.Draw(ht, pbt.Spanning[uint16](0, MetricInfinity-1))
		}
		var extra uint16
		if hegel.Draw(ht, hegel.Booleans()) {
			extra = hegel.Draw(ht, pbt.Spanning[uint16](0, MetricInfinity-1))
		}
		cost := DefaultCostParams()
		cost.Quality = hegel.Draw(ht, hegel.SampledFrom([]LinkQuality{LinkQualityETX, LinkQualityNone}))
		cost.RxCost = hegel.Draw(ht, pbt.Spanning[uint16](1, MetricInfinity-1))
		cost.RTT.Weight = hegel.Draw(ht, pbt.Spanning[uint16](0, MetricInfinity-1))
		samples := hegel.Draw(ht, pbt.Spanning(0, historyDepth))
		now := time.Now()
		n := &neighborState{extra: extra, reportedCost: reported, haveReportedCost: true,
			measuredRTT: time.Duration(hegel.Draw(ht, pbt.Spanning[int64](0, int64(2*time.Second)))),
			haveRTT:     hegel.Draw(ht, hegel.Booleans()),
			ihuExpiry:   now.Add(time.Minute),
			alive:       true, lastHelloTime: now, helloInterval: time.Minute,
			multicastHistory: helloHistory{bits: hegel.Draw(ht, pbt.Spanning[uint16](0, 0xffff)), started: samples > 0, samples: samples}}
		link := n.linkCost(now, cost)
		if link == 0 {
			ht.Fatalf("a neighbor reporting rxcost %d with an extra of %d costs 0", reported, extra)
		}
		metric := hegel.Draw(ht, pbt.Spanning[uint16](0, MetricInfinity-1))
		route := &routeInfo{rxMetric: metric}
		if got := route.cost(n, now, cost); got != MetricInfinity && got <= metric {
			ht.Fatalf("a route advertised at %d over a link costing %d costs %d", metric, link, got)
		}
	})
}
