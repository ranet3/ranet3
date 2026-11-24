// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package control

import (
	"math"
	"testing"
	"time"
)

const (
	durationEdgeNS    = "9223372036854775808ns"
	durationMaxNS     = "9223372036854775807ns"
	durationEdgeS     = "9223372036.854775808s"
	durationEdgeUS    = "9223372036854775.808us"
	durationEdgeDays  = "106751.991167300645928819d"
	durationEdgeSum   = "1d106750d23h47m16.854775808s"
	durationFractionM = "76861433.640456465066666667m"
	durationHalfS     = "4611686018.427387904000000000s"
	durationFractionH = "1281023.894007607751111111h"
	durationHalfMicro = "4611686018427387.904000000000000000\u00b5s"
)

var wrappedDurationInputs = []string{
	durationEdgeS + durationEdgeUS,
	"+" + durationEdgeUS + durationEdgeS + "7ns",
	"-" + durationEdgeS + durationEdgeS + "7ns",
	"1ns" + durationMaxNS + durationEdgeUS,
	"0s" + durationEdgeS + "0ns" + durationEdgeS + durationMaxNS,
	"-" + durationEdgeS + durationEdgeS + durationEdgeS,
	"9223372036854775807.9999999999999999999ns" + durationEdgeS,
	durationEdgeNS + durationEdgeNS,
	durationEdgeDays + durationEdgeNS,
	durationEdgeNS + durationEdgeDays,
	"+" + durationEdgeDays + durationEdgeDays + "7ns",
	"-" + durationEdgeDays + durationEdgeDays + "7ns",
	durationEdgeSum + durationEdgeNS,
	durationEdgeSum + "0d" + durationEdgeNS + "1d",
}

func TestInputDurationRejectsWrappedSum(t *testing.T) {
	for _, text := range wrappedDurationInputs {
		if got, err := ParseInputDuration(text); err == nil {
			t.Errorf("%q read as %v, want a refusal", text, got)
		}
	}
}

func TestInputDurationReadsTerms(t *testing.T) {
	for _, row := range []struct {
		text string
		want time.Duration
	}{
		{"1d", 24 * time.Hour},
		{"1d2h", 26 * time.Hour},
		{"1d2h3m", 26*time.Hour + 3*time.Minute},
		{"42d6h", 1014 * time.Hour},
		{"2h1d", 26 * time.Hour},
		{"1d1d", 48 * time.Hour},
		{"1.5d", 36 * time.Hour},
		{"+1.5d2h", 38 * time.Hour},
		{"-2h.5d1d", -38 * time.Hour},
		{".125d", 3 * time.Hour},
		{"1.d", 24 * time.Hour},
		{"1h.0625d30m", 3 * time.Hour},
		{"0.0000000000001d", 8 * time.Nanosecond},
		{"0d", 0},
		{"-1d2h", -26 * time.Hour},
		{"+1d", 24 * time.Hour},
		{"106751d", 106751 * 24 * time.Hour},
		{"106751d23h47m16.854775807s", math.MaxInt64},
		{"-106751d23h47m16.854775808s", math.MinInt64},
		{"-" + durationEdgeUS, math.MinInt64},
		{"-0d" + durationEdgeDays + "0ns", math.MinInt64},
		{"+" + durationFractionM + durationHalfS + "0.000000000000000000ms", math.MaxInt64},
		{durationFractionM + durationHalfS, math.MaxInt64},
		{"-" + durationFractionH + durationHalfMicro, math.MinInt64},
		{"5m", 5 * time.Minute},
		{"1h30m", 90 * time.Minute},
		{"1.5h", 90 * time.Minute},
		{"26h0m0s", 26 * time.Hour},
		{"0", 0},
	} {
		if got, err := ParseInputDuration(row.text); err != nil || got != row.want {
			t.Errorf("%q read as %v, %v, want %v", row.text, got, err, row.want)
		}
	}
	for _, text := range []string{
		durationEdgeS, durationEdgeS + "1ns" + durationEdgeUS, durationEdgeS + durationEdgeS + durationEdgeS + "1ns",
		durationMaxNS + durationMaxNS + "2ns", durationEdgeDays,
		"106752d", "213504d", "106751d23h47m16.854775808s", "-106751d23h47m16.854775809s", "99999999999999999999d",
		durationFractionH + durationHalfMicro,
		durationFractionM + durationHalfS + "1ns",
		"-" + durationFractionH + durationHalfMicro + "1ns",
		"d", "1D", "1day", "1 d", "1d2", "1hd", "1d+2h", "1d-2h", "1..5d", ".d", "1w", "-", "",
	} {
		if got, err := ParseInputDuration(text); err == nil {
			t.Errorf("%q read as %v, want a refusal", text, got)
		}
	}
}

func TestInputDurationReadsPrintedForms(t *testing.T) {
	const day = 24 * time.Hour
	for _, row := range []struct {
		in, want time.Duration
	}{
		{0, 0},
		{27234 * time.Microsecond, 27200 * time.Microsecond},
		{9*time.Second + 470*time.Millisecond, 9500 * time.Millisecond},
		{time.Minute + 30*time.Second + 400*time.Millisecond, 90 * time.Second},
		{59*time.Minute + 59*time.Second + 400*time.Millisecond, time.Hour - time.Second},
		{59*time.Minute + 59*time.Second + 500*time.Millisecond, time.Hour},
		{time.Hour, time.Hour},
		{time.Hour + 29*time.Second + 900*time.Millisecond, time.Hour},
		{time.Hour + 30*time.Second, 61 * time.Minute},
		{time.Hour + 3*time.Minute + 576*time.Millisecond, 63 * time.Minute},
		{day - 30*time.Second, day},
		{day, day},
		{day + 30*time.Second, day + time.Minute},
		{25*time.Hour + 11*time.Minute, 25*time.Hour + 11*time.Minute},
		{26 * time.Hour, 26 * time.Hour},
		{42*day - 15*time.Second, 42 * day},
		{42*day + 6*time.Hour, 42*day + 6*time.Hour},
		{400 * day, 400 * day},
		{math.MaxInt64, 106751*day + 23*time.Hour + 47*time.Minute},
	} {
		text := shortDuration(row.in)
		if got, err := ParseInputDuration(text); err != nil || got != row.want {
			t.Errorf("%v prints as %q, which read as %v, %v, want %v", row.in, text, got, err, row.want)
		}
	}
	if got, err := ParseInputDuration(shortDuration(-time.Second)); err == nil {
		t.Errorf("printed negative duration read as %v, want a refusal", got)
	}
}
