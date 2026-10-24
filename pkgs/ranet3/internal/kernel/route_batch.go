// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import "net/netip"

// RouteRead is one lookup of RouteGetBatch, the packet RouteGet takes as src,
// dst and iif
type RouteRead struct {
	Source, Destination netip.Addr
	IIF                 string
	// Reply asks for the lookup of the packet answering this one as well, from
	// Destination to Source. It arrives on the device of the forward answer's
	// first live next hop, the first neither Dead nor LinkDown, a device the
	// forward packet can leave by. A forward lookup that fails, or answers a
	// route with no live hop, gives the reply read an error of its own
	Reply bool
}

// BatchAnswer is RouteGetBatch's answer to one read: the route RouteGet answers
// for it or the error it answers, then for a read asking for its reply the
// device that lookup arrived on, empty where none was made, with its route or
// its error
type BatchAnswer struct {
	Route    MatchedRoute
	Err      error
	ReplyIIF string
	Reply    MatchedRoute
	ReplyErr error
}
