// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import "time"

// RetryTimer is a run loop's retry of a failed pass, on a backoff doubling
// from minRetryInterval up to the sweep, armed only while the backoff is set
type RetryTimer struct {
	*time.Timer
	backoff time.Duration
}

func NewRetryTimer() *RetryTimer {
	r := &RetryTimer{Timer: time.NewTimer(0)}
	r.Stop()
	return r
}

// Failed arms the timer with the backoff doubled up to sweep, which it returns.
// sweep is read at each failure, since a reload can change it.
func (r *RetryTimer) Failed(sweep time.Duration) time.Duration {
	r.backoff = min(max(2*r.backoff, minRetryInterval), sweep)
	r.Reset(r.backoff)
	return r.backoff
}

// Passed disarms the timer and starts the backoff over
func (r *RetryTimer) Passed() {
	if r.backoff != 0 {
		r.backoff = 0
		r.Stop()
	}
}
