// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import "time"

const (
	// readTimeout bounds one debug read by default, the bound the control client puts on every read
	readTimeout = 10 * time.Second
	// followFor is how long debug events -f follows by default, a look rather than a watch
	followFor = 30 * time.Second
	// waitTimeout is how long debug wait waits by default, as long as a session takes to come up on a slow link
	waitTimeout = 10 * time.Second
	// completionTimeout bounds a completion that asks the daemon, so a shell does not stall on one that is gone
	completionTimeout = time.Second
	// waitTimedOut is debug wait's status when no event came within --timeout, as grep's when nothing matched
	waitTimedOut exitCode = 1
	// waitUnwatched is its status when it could not watch for the event or lost it, as grep's on an error
	waitUnwatched exitCode = 2
)
