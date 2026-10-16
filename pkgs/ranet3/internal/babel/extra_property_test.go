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

// for any computed cost and any amount, the link cost and the IHU's rxcost keep RFC 8966 section 3.4.3's conditions
// a cost that was finite stays finite and strictly positive, the amount added and the sum held one short of infinity, and one that was infinite stays infinite
// the speaker computes each figure once without the amount and once with it, so the property states how the two relate and never how either is computed
func TestExtraCostKeepsFiniteCostsFiniteAndInfiniteOnesInfinite(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		rx := hegel.Draw(ht, pbt.Spanning[uint16](1, MetricInfinity-1))
		weight := hegel.Draw(ht, pbt.Spanning[uint16](0, MetricInfinity-1))
		amount := hegel.Draw(ht, pbt.Spanning[uint16](0, MetricInfinity-1))
		reported := hegel.Draw(ht, pbt.Spanning[uint16](1, MetricInfinity))
		rtt := time.Duration(hegel.Draw(ht, pbt.Spanning[int64](0, int64(2*time.Second))))
		bits := hegel.Draw(ht, pbt.Spanning[uint16](0, 0xffff))
		samples := hegel.Draw(ht, pbt.Spanning(0, historyDepth))
		alive := hegel.Draw(ht, hegel.Booleans())
		heard := hegel.Draw(ht, hegel.Booleans())

		cost := DefaultCostParams()
		cost.RxCost, cost.RTT.Weight = rx, weight
		speaker := &Speaker{cost: cost, hello: time.Second}
		now := time.Now()
		figures := func(extra uint16) (link, ihu uint16) {
			n := &neighborState{extra: extra, heard: heard, reportedCost: reported, haveReportedCost: true,
				measuredRTT: rtt, haveRTT: true, ihuExpiry: now.Add(time.Minute),
				multicastHistory: helloHistory{bits: bits, started: samples > 0, samples: samples}}
			if alive {
				n.alive, n.lastHelloTime, n.helloInterval = true, now, time.Minute
			}
			link = n.linkCost(now, cost)
			action := speaker.helloAction(n, now)
			decoded, _, err := DecodeIHU(action.tlvs[1].Body)
			if err != nil {
				ht.Fatal(err)
			}
			return link, decoded.RxCost
		}
		baseLink, baseIHU := figures(0)
		link, ihu := figures(amount)
		for _, place := range []struct {
			name       string
			base, with uint16
		}{{"link cost", baseLink, link}, {"IHU rxcost", baseIHU, ihu}} {
			switch {
			case place.base == MetricInfinity && place.with != MetricInfinity:
				ht.Fatalf("an infinite %s became %d with an extra of %d", place.name, place.with, amount)
			case place.base != MetricInfinity && place.with == MetricInfinity:
				ht.Fatalf("a %s of %d became infinite with an extra of %d", place.name, place.base, amount)
			case place.base != MetricInfinity && place.with == 0:
				ht.Fatalf("a %s of %d became zero with an extra of %d", place.name, place.base, amount)
			case place.base != MetricInfinity && uint32(place.with) != min(uint32(place.base)+uint32(amount), uint32(MetricInfinity)-1):
				ht.Fatalf("a %s of %d became %d with an extra of %d, want the sum held one short of infinity", place.name, place.base, place.with, amount)
			}
		}
		if !alive && link != MetricInfinity {
			ht.Fatalf("a neighbor with no recent Hello costs %d with an extra of %d", link, amount)
		}
		if reported == MetricInfinity && link != MetricInfinity {
			ht.Fatalf("an infinite txcost costs %d with an extra of %d", link, amount)
		}
	})
}
