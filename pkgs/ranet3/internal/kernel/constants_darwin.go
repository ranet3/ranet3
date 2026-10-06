// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package kernel

import "time"

const (
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
)
