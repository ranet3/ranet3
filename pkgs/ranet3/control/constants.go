// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package control

import "time"

const (
	// maxStreams is how many streams a daemon holds open at once, leaving the rest of maxConnections to the reads
	maxStreams = 4
	// streamBudget is how long one stream write may wait on its reader before the stream is dropped
	// long enough for a reader on a loaded host, short enough that a stopped one does not hold a place
	streamBudget = 5 * time.Second
	// streamHeartbeat is how often a quiet stream writes, so a reader can tell a quiet daemon from a dead one
	streamHeartbeat = 15 * time.Second
	// streamBatch is how many events one stream flush carries at most, which bounds the time between flushes
	streamBatch = 64
	// maxLine is the longest stream line a client reads, in bytes, far past any event and short of a runaway
	maxLine = 1 << 20
)
