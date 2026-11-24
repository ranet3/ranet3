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
		unit    unit
		decimal string
	}
	fractional := func(u unit, ns uint64, quarter int64) term {
		var amount, offset, scale big.Rat
		amount.SetUint64(ns)
		amount.Add(&amount, offset.SetFrac64(quarter, 4))
		amount.Quo(&amount, scale.SetInt64(int64(u.scale)))
		return term{u, amount.FloatString(18)}
	}
	cases := 0
	check := func(fatalf func(string, ...any), sign string, terms []term) {
		cases++
		var text strings.Builder
		text.WriteString(sign)
		var sum big.Int
		valid := true
		for _, term := range terms {
			text.WriteString(term.decimal)
			text.WriteString(term.unit.name)
			spelling := term.decimal + term.unit.name
			if term.unit.name == "d" {
				var hours, factor big.Rat
				if _, ok := hours.SetString(term.decimal); !ok {
					fatalf("invalid decimal %q", term.decimal)
				}
				hours.Mul(&hours, factor.SetInt64(24))
				spelling = hours.FloatString(18) + "h"
			}
			value, err := time.ParseDuration("-" + spelling)
			if err != nil {
				valid = false
				continue
			}
			var magnitude big.Int
			magnitude.SetInt64(int64(value))
			sum.Sub(&sum, &magnitude)
		}
		if sign == "-" {
			sum.Neg(&sum)
		}
		got, err := ParseInputDuration(text.String())
		if valid && sum.IsInt64() {
			if err != nil || got != time.Duration(sum.Int64()) {
				fatalf("%q read as %v, %v, want %s ns", text.String(), got, err, &sum)
			}
		} else if err == nil {
			fatalf("%q read as %v, want a refusal of %s ns", text.String(), got, &sum)
		}
	}
	const edge = uint64(1) << 63
	signs := []string{"", "+", "-"}
	for _, sign := range signs {
		for _, u := range units {
			limit := uint64(math.MaxInt64)
			if sign == "-" {
				limit++
			}
			maxCount := limit / uint64(u.scale)
			check(t.Fatalf, sign, []term{{u, strconv.FormatUint(maxCount, 10)}})
			check(t.Fatalf, sign, []term{{u, strconv.FormatUint(maxCount+1, 10)}})
			check(t.Fatalf, sign, []term{{u, "0"}, fractional(u, edge, 1)})
			for _, next := range units {
				half := fractional(u, edge/2, 1)
				full := fractional(next, edge, 1)
				check(t.Fatalf, sign, []term{fractional(u, edge, 1), full})
				check(t.Fatalf, sign, []term{half, half, {u, "0"}, full})
			}
		}
	}
	pbt.Check(t, func(ht *hegel.T) {
		sign := hegel.Draw(ht, hegel.SampledFrom(signs))
		n := hegel.Draw(ht, pbt.Spanning(1, 5))
		terms := make([]term, n)
		for i := range terms {
			u := hegel.Draw(ht, hegel.SampledFrom(units))
			ns := hegel.Draw(ht, pbt.Spanning(uint64(0), edge+1))
			if hegel.Draw(ht, hegel.Booleans()) {
				ns = hegel.Draw(ht, hegel.SampledFrom([]uint64{0, 1, edge / 2, edge - 1, edge, edge + 1}))
			}
			terms[i] = fractional(u, ns, hegel.Draw(ht, pbt.Spanning(int64(1), 3)))
		}
		check(ht.Fatalf, sign, terms)
	})
	t.Logf("checked %d duration texts against per-term Go values, 0 disagreements", cases)
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
