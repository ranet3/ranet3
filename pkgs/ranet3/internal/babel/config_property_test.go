// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package babel

import (
	"strings"
	"testing"
	"time"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/schema"
)

// an interval travels in centiseconds in sixteen bits, so the longest one a file can write is 65535 of them
const longestInterval = 65535 * 10 * time.Millisecond

// an update interval of 65535 centiseconds is FFFF, which RFC 8966 section 4.6.9 reads as no interval, so the longest one a file can write is one less
const longestUpdate = longestInterval - 10*time.Millisecond

// a hello alone is a valid configuration whenever it is a valid interval
// the update the file leaves out is four hellos, held to the longest update interval, so a long hello cannot make an update nobody wrote
func TestHelloAloneIsAValidConfigurationWheneverItIsAnInterval(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		hello := time.Duration(hegel.Draw(ht, pbt.Spanning[int64](1, 65535))) * 10 * time.Millisecond
		config := Config{Hello: dur(hello)}
		if err := config.Validate(); err != nil {
			ht.Fatalf("a hello of %s alone was refused: %v", hello, err)
		}
		update := config.UpdateInterval()
		switch {
		case update < min(hello, longestUpdate) || update > longestUpdate:
			ht.Fatalf("a hello of %s leaves an update of %s, outside %s to %s", hello, update, min(hello, longestUpdate), longestUpdate)
		case 4*hello <= longestUpdate && update != 4*hello:
			ht.Fatalf("a hello of %s leaves an update of %s, want four hellos", hello, update)
		}
	})
}

// RFC 8966 carries an interval in centiseconds as "an upper bound" on the time to the next TLV, so one that is not a whole number of them is refused, naming its field and the unit, rather than sent as a shorter one
func TestIntervalIsAWholeNumberOfCentiseconds(t *testing.T) {
	for _, test := range []struct {
		interval time.Duration
		whole    bool
	}{
		{15 * time.Millisecond, false},
		{1005 * time.Millisecond, false},
		{10*time.Millisecond + time.Nanosecond, false},
		{10 * time.Millisecond, true},
		{longestUpdate, true},
	} {
		for _, field := range []string{"hello", "update"} {
			config := Config{Hello: dur(test.interval)}
			if field == "update" {
				config = Config{Update: dur(test.interval)}
			}
			err := config.Validate()
			switch {
			case test.whole && err != nil:
				t.Errorf("%s %s was refused: %v", field, test.interval, err)
			case !test.whole && err == nil:
				t.Errorf("%s %s was accepted", field, test.interval)
			case !test.whole && (!strings.Contains(err.Error(), "cap.babel "+field) || !strings.Contains(err.Error(), "centiseconds")):
				t.Errorf("%s %s was refused as %q, which names neither the field nor the unit", field, test.interval, err)
			}
		}
	}
}

// RFC 8966 section 4.6.9 reads an update interval of FFFF as "this announcement will not be repeated unless a request is received", so update is refused at 655.35 seconds, the bound named, where hello is not
func TestUpdateIntervalOfFFFFIsRefused(t *testing.T) {
	if err := (Config{Hello: dur(longestInterval)}).Validate(); err != nil {
		t.Errorf("hello %s was refused: %v", longestInterval, err)
	}
	err := (Config{Update: dur(longestInterval)}).Validate()
	if err == nil || !strings.Contains(err.Error(), "cap.babel update") || !strings.Contains(err.Error(), longestUpdate.String()) {
		t.Errorf("update %s was refused as %v, want a refusal naming update and %s", longestInterval, err, longestUpdate)
	}
}

// an interval outside its bounds is refused with what the field must be and what it was
func TestIntervalOutsideItsBoundsIsRefusedNamingTheBoundsAndTheValue(t *testing.T) {
	for _, test := range []struct {
		config Config
		want   string
	}{
		{Config{Hello: dur(5 * time.Millisecond)}, "babel: cap.babel hello must be a whole number of centiseconds between 10ms and 10m55.35s, not 5ms"},
		{Config{Hello: dur(longestInterval + 10*time.Millisecond)}, "babel: cap.babel hello must be a whole number of centiseconds between 10ms and 10m55.35s, not 10m55.36s"},
		{Config{Update: dur(5 * time.Millisecond)}, "babel: cap.babel update must be a whole number of centiseconds between 10ms and 10m55.34s, not 5ms"},
		{Config{Update: dur(longestInterval)}, "babel: cap.babel update must be a whole number of centiseconds between 10ms and 10m55.34s, not 10m55.35s"},
	} {
		if err := test.config.Validate(); err == nil || err.Error() != test.want {
			t.Errorf("%+v was refused as %v, want %q", test.config, err, test.want)
		}
	}
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
