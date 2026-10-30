// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import "net/netip"

// RouteRead is one lookup of RouteGetBatch, the packet RouteGet takes as src,
// dst and iif
type RouteRead struct {
	Source, Destination netip.Addr
	IIF                 string
	// OIF is the index of the interface the read names as a send naming one
	// does, none at zero (fib_lookup_good_nhc, rt6_score_route,
	// rt6_need_strict). The reply read names none
	OIF uint32
	// Pair says the send goes on a socket connected to the peer
	Pair bool
	// Mark is the packet's mark, none at zero. The reply read carries none
	Mark uint32
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
	Route MatchedRoute
	Err   error
	// OIF names the read's OIF as the batch's dump of the links did, empty
	// where the read names none or the dump held none
	OIF      string
	ReplyIIF string
	Reply    MatchedRoute
	ReplyErr error
}
