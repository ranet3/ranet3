// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package kernel

import "time"

const (
	// Loopback is the name of the loopback link
	Loopback = "lo0"
	// lookupTimeout bounds one request. Without it a reply that never comes holds
	// the goroutine asking for it forever, and one of the callers is the startup
	// path that opens the transport socket.
	lookupTimeout = 2 * time.Second
	// routeReceiveBuffer is the receive queue of a routing socket, in bytes
	// a routing socket that overflows drops the excess without telling its reader
	// the watcher meets a flood of route changes and a lookup meets the replies of the lookups beside it
	routeReceiveBuffer = 1 << 19
	// lookupReadSize is the most one read of a routing socket returns, in bytes
	// a routing message is a few hundred bytes, and a page cuts none of them
	lookupReadSize = 4096
	// selectionSettle is how long the underlay's selection waits after a wake of its watcher before it reads the table again
	// a link coming up is several messages, and a read after the first would be redone after the last
	selectionSettle = 250 * time.Millisecond
	// dumpAttempts bounds the fetches of one read of the routing table or the interface list that fail with ENOMEM or ENOBUFS
	// each fetch is x/net's FetchRIB or a lookup of Go's net, which retries ENOMEM inside the fetch and ends it at its first ENOBUFS
	// each fetch sizes the list again, so a read fails only where the list outgrows its room in every one of its fetches
	// an exhausted read returns the last fetch's error, wrapped as one failed fetch's is
	dumpAttempts = 4
)
