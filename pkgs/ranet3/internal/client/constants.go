// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import "time"

// espDropReportInterval bounds how often refused ESP packets are said out
// loud. The counter behind it is exact, and an operator reads that. The log
// line only has to point at it.
const espDropReportInterval = 10 * time.Second

const (
	// defaultReconnectDelay is how long a dialer waits between attempts unless a test shortens it
	defaultReconnectDelay = 10 * time.Second
	// dialFailureInterval is how long a dialer keeps a failure it already reported at debug
	// one name that never resolves would otherwise say so every reconnect delay
	dialFailureInterval = 10 * time.Minute
	// dialFailureFloor is how soon a dialer reports a failure whose reason changed
	// a reason that carries a port the resolver picked is never the same twice
	dialFailureFloor = time.Minute
	// deleteGrace bounds how long a teardown waits for the peer to acknowledge the Delete
	// the point is to tell the peer, not to be sure it heard
	deleteGrace = 2 * time.Second
)
