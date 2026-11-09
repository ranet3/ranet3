// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

// Package codel is the controlled delay of RFC 8289 over a queue one consumer
// takes from: a peer's sender in netstack, and the userspace exit's pump.
package codel

import (
	"math"
	"time"
)

// Target is the delay a queue is held to, and Interval how long the delay may
// stay above it before the consumer starts dropping. Both are the defaults RFC
// 8289 gives and the kernel's CoDel uses.
const (
	Target   = 5 * time.Millisecond
	Interval = 100 * time.Millisecond
)

// Controller is the controlled delay over one queue.
// The delay is measured where the consumer takes each item, a peer's batch or
// a packet, from when it was queued, and an item whose turn comes while the
// delay calls for a drop loses its head packet.
// The consumer runs it alone, so it needs no lock.
// Its times are durations since the queue started, off the monotonic clock.
type Controller struct {
	// firstAbove is when the delay will have stayed above the target for a
	// whole interval, zero while the delay is below the target or the queue
	// is empty
	firstAbove time.Duration
	// dropNext is when the next drop is due in the dropping state
	dropNext time.Duration
	// count is the drops since the dropping state began, and lastCount the
	// count it began with
	count, lastCount uint32
	dropping         bool
}

// Dropping is whether c is in the dropping state
func (c *Controller) Dropping() bool { return c.dropping }

// okToDrop says whether the delay has stayed above the target for a whole
// interval, this item's sojourn included, with at least mtu bytes left queued
// behind it. With less, a drop could leave the link idle, so RFC 8289 section
// 4.1 counts the delay as below the target, which ends a dropping state.
func (c *Controller) okToDrop(now, sojourn time.Duration, left, mtu int) bool {
	if sojourn < Target || left < mtu {
		c.firstAbove = 0
		return false
	}
	if c.firstAbove == 0 {
		c.firstAbove = now + Interval
		return false
	}
	return now >= c.firstAbove
}

// Drop says whether the item the consumer takes at now, sojourn after it was
// queued, loses its head packet, where left is the bytes the queue holds
// behind the item and mtu the largest packet the queue's link sends. It
// follows the dequeue of RFC 8289 section 5.5, one call for each item taken.
func (c *Controller) Drop(now, sojourn time.Duration, left, mtu int) bool {
	ok := c.okToDrop(now, sojourn, left, mtu)
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
	// a delay back soon after the last dropping state starts at the rate that
	// state had reached, as the dequeue of section 5.5 does
	delta := c.count - c.lastCount
	c.count = 1
	if delta > 1 && now-c.dropNext < 16*Interval {
		c.count = delta
	}
	c.lastCount = c.count
	c.dropNext = controlLaw(now, c.count)
	return true
}

// Empty is the step RFC 8289 section 5.5 takes when the consumer finds the
// queue empty. With nothing waiting the delay is not above the target, so its
// interval starts over and the dropping state ends. count, lastCount and
// dropNext stay, so a delay back soon after starts at the rate the state had
// reached. It says whether the dropping state ended.
func (c *Controller) Empty() bool {
	ended := c.dropping
	c.firstAbove = 0
	c.dropping = false
	return ended
}

// controlLaw is when the drop after the count-th is due, RFC 8289 section 5.6
func controlLaw(t time.Duration, count uint32) time.Duration {
	return t + time.Duration(float64(Interval)/math.Sqrt(float64(count)))
}
