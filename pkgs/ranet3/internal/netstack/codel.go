// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"math"
	"time"
)

// codel is the controlled delay of RFC 8289 over one peer's queue
// the delay is measured where the sender takes each data batch in ticket order, from the batch's reservation
// a batch whose turn comes while the delay calls for a drop loses the packet at its head
// the sender runs it alone, so it needs no lock
// its times are durations since the peer started, off the monotonic clock
type codel struct {
	// firstAbove is when the delay will have stayed above the target for a whole interval
	// zero while the delay is below the target or the queue is empty
	firstAbove time.Duration
	// dropNext is when the next drop is due in the dropping state
	dropNext time.Duration
	// count is the drops since the dropping state began
	// lastCount is the count it began with
	count, lastCount uint32
	dropping         bool
}

// okToDrop says whether the delay has stayed above the target for a whole interval, this batch's sojourn included
func (c *codel) okToDrop(now, sojourn time.Duration) bool {
	if sojourn < codelTarget {
		c.firstAbove = 0
		return false
	}
	if c.firstAbove == 0 {
		c.firstAbove = now + codelInterval
		return false
	}
	return now >= c.firstAbove
}

// drop says whether the batch the sender takes at now, sojourn after its reservation, loses its head packet
// it follows the dequeue of RFC 8289 section 5.5, with the batch in place of the packet
func (c *codel) drop(now, sojourn time.Duration) bool {
	ok := c.okToDrop(now, sojourn)
	if c.dropping {
		if !ok {
			c.dropping = false
			return false
		}
		if now < c.dropNext {
			return false
		}
		c.count++
		c.dropNext = controlLaw(c.dropNext, c.count)
		return true
	}
	if !ok {
		return false
	}
	c.dropping = true
	// a delay back soon after the last dropping state starts at the rate that state had reached
	// as the dequeue of section 5.5 does
	delta := c.count - c.lastCount
	c.count = 1
	if delta > 1 && now-c.dropNext < 16*codelInterval {
		c.count = delta
	}
	c.lastCount = c.count
	c.dropNext = controlLaw(now, c.count)
	return true
}

// empty is the step RFC 8289 section 5.5 takes when the sender finds the queue empty
// with nothing waiting the delay is not above the target, so its interval starts over and the dropping state ends
// count, lastCount and dropNext stay, so a delay back soon after starts at the rate the state had reached
// it says whether the dropping state ended
func (c *codel) empty() bool {
	ended := c.dropping
	c.firstAbove = 0
	c.dropping = false
	return ended
}

// controlLaw is when the drop after the count-th is due, RFC 8289 section 5.6
func controlLaw(t time.Duration, count uint32) time.Duration {
	return t + time.Duration(float64(codelInterval)/math.Sqrt(float64(count)))
}
