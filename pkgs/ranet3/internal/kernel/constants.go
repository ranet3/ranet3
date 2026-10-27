// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import "time"

const (
	// DefaultTable matches the table the fleet's kbabel4 and kbabel6 write,
	// which the policy rules and the End.DT46 SRv6 action look up.
	DefaultTable = 200
	// DefaultProtocol is the rt_proto stamped on every installed route. It
	// deliberately collides with nothing in rtnetlink.h, so a route of this
	// reconciler's stays distinguishable from BIRD's (12) and babeld's (42).
	DefaultProtocol = 155
	// DefaultReconcileInterval bounds how long drift caused by anything else
	// on the box survives when no notification announces it.
	DefaultReconcileInterval = 30 * time.Second

	// minRetryInterval is the first delay after a failed pass or withdrawal,
	// and it doubles up to the reconcile interval. A reconcile interval below
	// it is every delay.
	minRetryInterval = time.Second
	// settleDelay absorbs the rest of a burst of changes, including the route
	// notifications the reconciler's own writes generate, so one batch of
	// babel updates costs one kernel dump rather than one per route.
	settleDelay = 250 * time.Millisecond
	// watchSettle is how long the network watch lets a change finish before it reads the host
	// a laptop moving networks drops an address, a route and a link in one burst, and every session is probed once for it
	watchSettle = 250 * time.Millisecond
)

// The priorities of the policy rules ranet3 derives, in two blocks, one below
// Tailscale's rules at its default base of 5200, 5210 to 5270, and one above.
// The first rule of each block is a goto the underlay's mark matches, to the
// nop that ends the block.
const (
	// priorityUnderlayPastOverlay is the goto the underlay's mark matches, to
	// priorityOverlayEnd.
	priorityUnderlayPastOverlay = 5100
	// priorityOverlay looks each overlay prefix up in the mesh's table.
	priorityOverlay = 5110
	// priorityOverlayEnd is the nop the first block's goto jumps to.
	priorityOverlayEnd = 5190
	// priorityUnderlayPastMesh is the goto the underlay's mark matches, to
	// priorityMeshEnd.
	priorityUnderlayPastMesh = 5400
	// priorityMain looks main up for every route of it longer than /0, and
	// for an unreachable, blackhole or prohibit /0, which suppression never
	// refuses.
	priorityMain = 5410
	// priorityMesh looks the mesh's table up for every route of it at its
	// family's floor or longer, and for a hold of any length, which
	// suppression never refuses.
	priorityMesh = 5420
	// priorityOwn looks the mesh's table up for a source among this node's own prefixes.
	priorityOwn = 5430
	// priorityMeshEnd is the nop the second block's goto jumps to.
	priorityMeshEnd = 5490
)
