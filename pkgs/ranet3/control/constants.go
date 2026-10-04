// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package control

import "time"

// DefaultSocket is where the daemon listens and the client looks
// darwin has /var/run alone and linux resolves it to /run, so one path serves both
const DefaultSocket = "/var/run/ranet3/control.sock"

const (
	// socketMode lets the daemon's group use the socket as well as its owner
	// so an operator in the group needs no root, and the unit names that group
	socketMode = 0o660
	// dirMode lets that group reach the socket through its directory
	dirMode = 0o750
	// lockMode keeps the lock file to its owner, since the daemon alone takes the lock
	lockMode = 0o600
	// maxRequest is the largest write body the daemon reads, in bytes
	// a request is a few short fields, so a client near this has lost track of what it sends
	maxRequest = 64 << 10
	// maxAnswer is the largest answer the client reads, in bytes, so a daemon cannot make it allocate without bound
	maxAnswer = 64 << 20
	// maxConnections is how many connections the daemon holds open at once
	// a diagnostic makes one request and exits, and each connection costs a goroutine and a descriptor
	maxConnections = 32
	// readHeaderTimeout bounds a request's headers, which a local client sends at once
	readHeaderTimeout = 5 * time.Second
	// writeTimeout bounds writing an answer to a client that stopped reading, a stream excepted
	writeTimeout = 30 * time.Second
	// idleTimeout closes a connection that finished a request and went quiet, which nothing else bounds
	idleTimeout = 30 * time.Second
	// ReadTimeout bounds one exchange of the client with the daemon, a stream excepted
	ReadTimeout = 10 * time.Second
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
	// maxEventKinds is how many kinds one events query may name, more than a selection a person spells needs
	// past it a query asks the daemon for work and memory nobody bounds
	maxEventKinds = 16
	// maxEventAttrs is how many attributes one events query may name, more than a wait a person spells needs
	// past it a query costs the daemon a parse and a match nobody bounds when it subscribes
	// the match's work at an emit is bounded by the event's own attributes, since it stops at the first named one the event lacks
	maxEventAttrs = 16
)
