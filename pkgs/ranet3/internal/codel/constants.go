// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package codel

import "time"

// Target is the delay a queue is held to, and Interval how long the delay may
// stay above it before the consumer starts dropping. Both are the defaults RFC
// 8289 gives and the kernel's CoDel uses.
const (
	Target   = 5 * time.Millisecond
	Interval = 100 * time.Millisecond
)
