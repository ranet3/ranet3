// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package client

import (
	"log/slog"
	"math"
	"testing"
	"time"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// logged implements slog.LogValuer, as an emitter's own type may
type logged string

func (l logged) LogValue() slog.Value { return slog.StringValue(string(l)) }

// attributeValues draws a value of every kind an attribute may be emitted with, a time of any year in any zone included
func attributeValues() hegel.Generator[slog.Value] {
	return hegel.OneOf(
		hegel.Map(hegel.Text().MaxSize(8), slog.StringValue),
		hegel.Map(pbt.Spanning[int64](math.MinInt64, math.MaxInt64), slog.Int64Value),
		hegel.Map(pbt.Spanning[uint64](0, math.MaxUint64), slog.Uint64Value),
		hegel.Map(hegel.Booleans(), slog.BoolValue),
		hegel.Map(pbt.Spanning[int64](math.MinInt64, math.MaxInt64), func(n int64) slog.Value { return slog.DurationValue(time.Duration(n)) }),
		hegel.Map(hegel.Integers[uint64](0, math.MaxUint64), func(bits uint64) slog.Value { return slog.Float64Value(math.Float64frombits(bits)) }),
		hegel.Composite(func(tc hegel.TestCase) slog.Value {
			// half the range of seconds, which time.Unix takes without overflowing
			at := time.Unix(hegel.Draw(tc, pbt.Spanning[int64](math.MinInt64/2, math.MaxInt64/2)), hegel.Draw(tc, pbt.Spanning[int64](0, 999999999)))
			zone := time.FixedZone(hegel.Draw(tc, hegel.Text().MaxSize(5)), hegel.Draw(tc, pbt.Spanning(-24*60*60, 24*60*60)))
			return slog.TimeValue(at.In(zone))
		}),
		hegel.Map(hegel.Text().MaxSize(8), func(s string) slog.Value { return slog.AnyValue(struct{ S string }{s}) }),
		hegel.Map(hegel.Text().MaxSize(8), func(s string) slog.Value { return slog.AnyValue(logged(s)) }),
		hegel.Map(hegel.Text().MaxSize(8), func(s string) slog.Value { return slog.GroupValue(slog.String("g", s)) }),
	)
}

// a query naming an attribute takes an event exactly when the recorder shows the event with that text under that key
// the text is the rendering of a value of any kind or of one the event carries, so digits meet an integer, a float and a string alike
// the event goes through a bus, which keeps it as a ring holds it
func TestAttributeIsTakenAsTheEventRendersIt(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		var attrs []slog.Attr
		for range hegel.Draw(ht, pbt.Spanning(1, 3)) {
			attrs = append(attrs, slog.Attr{Key: hegel.Draw(ht, hegel.SampledFrom([]string{"route", "metric"})), Value: hegel.Draw(ht, attributeValues())})
		}
		text := hegel.Draw(ht, attributeValues()).Resolve().String()
		if hegel.Draw(ht, hegel.Booleans()) {
			text = attrs[hegel.Draw(ht, hegel.Integers(0, len(attrs)-1))].Value.Resolve().String()
		}
		bus := events.New()
		bus.Emit("babel.route.selected", "", attrs...)
		shown, carried := bus.Recorded(func(string, string, []slog.Attr) bool { return true }, 0)[0].Attrs["route"]
		query := control.EventQuery{Attrs: map[string]string{"route": text}}
		if got := len(bus.Recorded(selects(query), 0)) == 1; got != (carried && shown == text) {
			ht.Fatalf("%v shown with route=%q was taken %v for route=%q", attrs, shown, got, text)
		}
	})
}
