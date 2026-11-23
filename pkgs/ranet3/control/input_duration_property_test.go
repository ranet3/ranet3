// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package control

import (
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
	"testing"
	"time"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

func TestPrintedDurationParsesAsItsMinute(t *testing.T) {
	const first = time.Hour - 500*time.Millisecond
	check := func(fatalf func(string, ...any), d time.Duration) {
		text := shortDuration(d)
		if got, err := ParseInputDuration(text); err != nil || got != d.Round(time.Minute) {
			fatalf("%v prints as %q and reads as %v, %v, want %v", d, text, got, err, d.Round(time.Minute))
		}
	}
	for _, d := range []time.Duration{first, 24*time.Hour - 30*time.Second, 24 * time.Hour, math.MaxInt64} {
		check(t.Fatalf, d)
	}
	pbt.Check(t, func(ht *hegel.T) {
		d := hegel.Draw(ht, pbt.Spanning(first, time.Duration(math.MaxInt64)))
		check(ht.Fatalf, d)
	})
}

func TestInputDurationMatchesSignedSum(t *testing.T) {
	type unit struct {
		name  string
		scale time.Duration
	}
	units := []unit{
		{"ns", time.Nanosecond}, {"us", time.Microsecond}, {"\u00b5s", time.Microsecond}, {"\u03bcs", time.Microsecond},
		{"ms", time.Millisecond}, {"s", time.Second}, {"m", time.Minute}, {"h", time.Hour}, {"d", 24 * time.Hour},
	}
	type term struct {
		unit  unit
		count uint64
	}
	check := func(fatalf func(string, ...any), sign string, terms []term) {
		var text strings.Builder
		text.WriteString(sign)
		var sum, count, scale big.Int
		for _, term := range terms {
			text.WriteString(strconv.FormatUint(term.count, 10))
			text.WriteString(term.unit.name)
			sum.Add(&sum, count.Mul(count.SetUint64(term.count), scale.SetInt64(int64(term.unit.scale))))
		}
		if sign == "-" {
			sum.Neg(&sum)
		}
		got, err := ParseInputDuration(text.String())
		if sum.IsInt64() {
			if err != nil || got != time.Duration(sum.Int64()) {
				fatalf("%q read as %v, %v, want %s ns", text.String(), got, err, &sum)
			}
		} else if err == nil {
			fatalf("%q read as %v, want a refusal of %s ns", text.String(), got, &sum)
		}
	}
	signs := []string{"", "+", "-"}
	for _, sign := range signs {
		for _, u := range units {
			limit := uint64(math.MaxInt64)
			if sign == "-" {
				limit++
			}
			maxCount := limit / uint64(u.scale)
			check(t.Fatalf, sign, []term{{u, maxCount}})
			check(t.Fatalf, sign, []term{{u, maxCount + 1}})
		}
	}
	pbt.Check(t, func(ht *hegel.T) {
		sign := hegel.Draw(ht, hegel.SampledFrom(signs))
		n := hegel.Draw(ht, pbt.Spanning(1, 5))
		large := hegel.Draw(ht, pbt.Spanning(0, n-1))
		// only one term can approach 1<<63 so the sum never reaches Go's uint64 wrap
		var terms []term
		for i := range n {
			u := hegel.Draw(ht, hegel.SampledFrom(units))
			limit := uint64(100)
			if i == large {
				limit = uint64(math.MaxInt64)/uint64(u.scale) + 1
			}
			terms = append(terms, term{u, hegel.Draw(ht, pbt.Spanning(0, limit))})
		}
		check(ht.Fatalf, sign, terms)
	})
}

func TestInputDurationWithoutDaysMatchesGo(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		sign := hegel.Draw(ht, hegel.SampledFrom([]string{"", "+", "-"}))
		fraction := hegel.Draw(ht, pbt.Spanning(0, 999999999))
		whole := hegel.Draw(ht, pbt.Spanning(0, 2562048))
		unit := hegel.Draw(ht, hegel.SampledFrom([]string{"ns", "us", "ms", "s", "m", "h"}))
		var arbitrary strings.Builder
		const alphabet = "0123456789+- .nushmw_"
		for range hegel.Draw(ht, pbt.Spanning(0, 16)) {
			arbitrary.WriteByte(alphabet[hegel.Draw(ht, hegel.Integers(0, len(alphabet)-1))])
		}
		for _, text := range []string{fmt.Sprintf("%s%d.%09d%s", sign, whole, fraction, unit), arbitrary.String()} {
			want, wantErr := time.ParseDuration(text)
			if got, err := ParseInputDuration(text); got != want || (err == nil) != (wantErr == nil) {
				ht.Fatalf("%q read as %v, %v, Go reads %v, %v", text, got, err, want, wantErr)
			}
		}
	})
}
