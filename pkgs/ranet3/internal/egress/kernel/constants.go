// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import "time"

// A peer's routes come and go as often as the filter's passes run, so the
// lines that name the routes the route source holds back and the routes whose
// addresses the none sets leave out are spaced. routeReportInterval is the
// least time between two lines of one kind, and reportedRouteNames the most
// routes one line names, its count giving the rest.
const (
	routeReportInterval = 10 * time.Second
	reportedRouteNames  = 8
)

const (
	// ChainName is the translator's nat postrouting base chain, which
	// translates.
	ChainName = "postrouting"
	// LimitChain is the translator's filter forward base chain beside it
	LimitChain = "forward"
	// NoneChain starts the name of each regular chain an earlier translator
	// wrote, one for each class of none, the class's prefix ending it. A pass
	// empties and deletes each it finds.
	NoneChain = "none_"
	// BorderChain is the antispoof filter's chain at prerouting
	BorderChain = "antispoof"
	// EntryChain is the chain beside it that lets into the mesh's tun only
	// the packets it lists (antispoof.md, "The entry chain")
	EntryChain = "entry"
	// carvedSet, ownedSet and noneSet start the names of the filter's sets,
	// the family's digit ending each
	carvedSet = "carved"
	ownedSet  = "owned"
	noneSet   = "none"
	// pfOverlayTable and pfCarvedTable name the pf anchor's tables, each of
	// both families: the overlay, which the pass on the loopback link reads
	// since pf cannot negate two interfaces in one rule, and the carved sets
	pfOverlayTable = "overlay"
	pfCarvedTable  = "carved"
	// pfFaultMax is the most bytes of a fault naming what the filter never
	// writes in its pf anchor that the warning and the not ready reason carry,
	// since the fault quotes what another program loaded there
	pfFaultMax = 1024
)
