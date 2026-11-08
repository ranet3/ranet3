// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"math/bits"
	"sync/atomic"
	"time"
)

// histogram counts observations in buckets bounded by the powers of two of their unit from 1 to 1<<(histogramBounds-1)
// its last bucket counting those past every bound
// one goroutine observes and any reads
type histogram struct {
	counts [histogramBounds + 1]atomic.Uint64
	sum    atomic.Uint64
}

// Histogram is a histogram as one read found it
// Counts[i] is the observations at or under 1<<i of their unit and over the bound before it, the last those past every bound, and Sum their total
type Histogram struct {
	Counts [histogramBounds + 1]uint64
	Sum    uint64
}

// observe counts v, in the histogram's unit
func (h *histogram) observe(v uint64) {
	i := 0
	if v > 1 {
		i = min(bits.Len64(v-1), histogramBounds)
	}
	h.counts[i].Add(1)
	h.sum.Add(v)
}

// observeWait counts d in WaitUnit, a part of one counting as one
func (h *histogram) observeWait(d time.Duration) {
	h.observe(uint64(max(d+WaitUnit-1, 0) / WaitUnit))
}

func (h *histogram) read() Histogram {
	var out Histogram
	for i := range h.counts {
		out.Counts[i] = h.counts[i].Load()
	}
	out.Sum = h.sum.Load()
	return out
}
