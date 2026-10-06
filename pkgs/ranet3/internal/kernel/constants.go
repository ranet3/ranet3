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

	// minRetryInterval is the first delay after a failed pass, and it doubles
	// up to the reconcile interval.
	minRetryInterval = time.Second
	// settleDelay absorbs the rest of a burst of changes, including the route
	// notifications the reconciler's own writes generate, so one batch of
	// babel updates costs one kernel dump rather than one per route.
	settleDelay = 250 * time.Millisecond
)
