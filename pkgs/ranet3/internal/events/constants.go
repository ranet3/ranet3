// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package events

const (
	// ringSize is how many events each subsystem's flight recorder keeps
	// a few minutes of a busy subsystem, at a few hundred kilobytes each
	ringSize = 1024
	// queueSize is how many events one subscriber may fall behind by before its events are dropped and counted
	// several flushes' worth, so a reader that keeps up never sees a drop
	queueSize = 256
)
