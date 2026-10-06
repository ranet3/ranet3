// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package babel

import (
	"testing"
	"time"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/schema"
)

// an interval travels in centiseconds in sixteen bits, so the longest one a file can write is 65535 of them
const longestInterval = 65535 * 10 * time.Millisecond

// a hello alone is a valid configuration whenever it is a valid interval
// the update the file leaves out is four hellos, held to the longest interval the protocol carries, so a long hello cannot make an update nobody wrote
func TestHelloAloneIsAValidConfigurationWheneverItIsAnInterval(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		hello := time.Duration(hegel.Draw(ht, pbt.Spanning(int64(10*time.Millisecond), int64(longestInterval))))
		config := Config{Hello: dur(hello)}
		if err := config.Validate(); err != nil {
			ht.Fatalf("a hello of %s alone was refused: %v", hello, err)
		}
		update := config.UpdateInterval()
		switch {
		case update < hello || update > longestInterval:
			ht.Fatalf("a hello of %s leaves an update of %s, outside %s to %s", hello, update, hello, longestInterval)
		case 4*hello <= longestInterval && update != 4*hello:
			ht.Fatalf("a hello of %s leaves an update of %s, want four hellos", hello, update)
		}
	})
}

// a link cost that breaks a rule is refused, whatever else the block says
// the window of round trip times starts at or above zero and does not end before it starts, rx is positive, and rx with the weight stays short of infinity
// the cost it starts from is inside every rule, so the refusal is the one rule that was broken
func TestCostBreakingARuleIsRefused(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		rx := hegel.Draw(ht, pbt.Spanning[uint16](1, 1024))
		weight := hegel.Draw(ht, pbt.Spanning[uint16](0, 4096))
		low := schema.Duration(hegel.Draw(ht, pbt.Spanning[int64](0, int64(time.Second))))
		high := low + schema.Duration(hegel.Draw(ht, pbt.Spanning[int64](0, int64(4*time.Second))))
		cost := CostOptions{Rx: &rx, RTT: RTTOptions{Weight: &weight, Min: &low, Max: &high}}
		if err := (Config{Cost: cost}).Validate(); err != nil {
			ht.Fatalf("a cost inside every rule was refused: %v", err)
		}

		var broke string
		step := schema.Duration(hegel.Draw(ht, pbt.Spanning[int64](1, int64(time.Second))))
		switch hegel.Draw(ht, hegel.Integers(0, 3)) {
		case 0:
			below := -step
			cost.RTT.Min, broke = &below, "an rtt min below zero"
		case 1:
			before := low - step
			cost.RTT.Max, broke = &before, "an rtt max before its min"
		case 2:
			none := uint16(0)
			cost.Rx, broke = &none, "an rx of zero"
		default:
			saturating := uint16(MetricInfinity - rx)
			cost.RTT.Weight, broke = &saturating, "an rx and a weight that reach infinity"
		}
		if err := (Config{Cost: cost}).Validate(); err == nil {
			ht.Fatalf("%s was accepted: rx %d, weight %d, rtt %s to %s", broke, *cost.Rx, *cost.RTT.Weight, *cost.RTT.Min, *cost.RTT.Max)
		}
	})
}
