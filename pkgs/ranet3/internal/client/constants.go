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

const (
	// downFlag is the file in the state directory whose presence keeps the node off the mesh
	downFlag = "down"
	// flagTemp is the suffix of the file the flag is written whole in before it is renamed into place
	flagTemp = ".tmp"
	// flagMode keeps the flag to the daemon's own user, which writes it and alone reads it
	flagMode = 0o600
	// stateDirMode is the state directory's mode where the daemon makes it, for the same reason
	stateDirMode = 0o700
)
