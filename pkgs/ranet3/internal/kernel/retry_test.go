// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"slices"
	"testing"
	"time"
)

// The retry the reconciler, the egress translator and the antispoof filter
// share starts disarmed, and each failed pass arms it on a backoff doubling
// from minRetryInterval up to the sweep it is handed then. A pass that
// succeeds disarms it, and the next failure backs off from the start again.
func TestRetryBacksOffUpToTheSweepAndStartsOverAfterAPass(t *testing.T) {
	sweep := 5 * minRetryInterval
	retry := NewRetryTimer()
	t.Cleanup(func() { retry.Stop() })
	if retry.Stop() {
		t.Error("a new retry is armed before any pass failed")
	}
	var got []time.Duration
	for range 5 {
		got = append(got, retry.Failed(sweep))
	}
	// a reload that shortens the sweep caps the next delay at once
	got = append(got, retry.Failed(2*minRetryInterval))
	if want := []time.Duration{minRetryInterval, 2 * minRetryInterval, 4 * minRetryInterval, sweep, sweep, 2 * minRetryInterval}; !slices.Equal(got, want) {
		t.Errorf("6 failed passes backed off %v, want %v", got, want)
	}
	retry.Passed()
	if retry.Stop() {
		t.Error("a pass that succeeded left the retry armed")
	}
	if backoff := retry.Failed(sweep); backoff != minRetryInterval {
		t.Errorf("the first failure after a pass backed off %v, want %v", backoff, minRetryInterval)
	}
	if !retry.Stop() {
		t.Error("a failed pass left the retry disarmed")
	}
}
