// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package control

import (
	"math"
	"strconv"
	"strings"
	"testing"
	"time"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// from an hour on the compact form names days, hours and minutes in that order,
// none of them zero and none past the next unit, and they add up to the
// duration rounded to the minute
func TestShortDurationFromAnHourReadsBackAsItsMinute(t *testing.T) {
	units := []struct {
		letter byte
		length time.Duration
		bound  int64
	}{{'d', 24 * time.Hour, math.MaxInt64}, {'h', time.Hour, 24}, {'m', time.Minute, 60}}
	pbt.Check(t, func(ht *hegel.T) {
		d := time.Duration(hegel.Draw(ht, hegel.OneOf(edges(int64(59*time.Minute+59*time.Second+500*time.Millisecond), math.MaxInt64), hegel.Just(int64(24*time.Hour-30*time.Second)), hegel.Just(int64(24*time.Hour)))))
		text := shortDuration(d)
		var sum time.Duration
		next := 0
		for rest := text; rest != ""; {
			digits := strings.IndexFunc(rest, func(r rune) bool { return r < '0' || r > '9' })
			if digits <= 0 {
				ht.Fatalf("shortDuration(%v) = %q, want a count before each unit", d, text)
			}
			count, err := strconv.ParseInt(rest[:digits], 10, 64)
			unit := next
			for unit < len(units) && units[unit].letter != rest[digits] {
				unit++
			}
			if err != nil || unit == len(units) || count == 0 || count >= units[unit].bound {
				ht.Fatalf("shortDuration(%v) = %q, want nonzero days, hours under 24 and minutes under 60, in that order", d, text)
			}
			sum += time.Duration(count) * units[unit].length
			next, rest = unit+1, rest[digits+1:]
		}
		if want := d.Round(time.Minute); sum != want {
			ht.Fatalf("shortDuration(%v) = %q, which reads back as %v, want %v", d, text, sum, want)
		}
	})
}
