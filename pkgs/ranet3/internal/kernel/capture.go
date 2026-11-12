// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"time"

	"ranet3.com/pkgs/ranet3/schema"
)

// DefaultCaptureGrace is how long a route that would capture this machine's
// own traffic stays installed after the last live session went away. It is ten
// seconds because the quantity it has to outlast is a reconnect and not an
// outage: a session that drops and is dialed again completes a handshake in
// well under that, while a session that is gone has already been silent for
// twice the dead peer detection interval before it stops counting as live. A
// longer grace buys nothing and is paid for in seconds during which the
// machine has no working network at all.
const DefaultCaptureGrace = 10 * time.Second

func (r *Reconciler) captures(route Route) bool {
	return schema.CapturesTheMachine(route.Destination, r.rt.Overlay)
}

// MinCaptureGrace is the shortest grace a configuration may name. The
// sessions' liveness is sampled once a reconcile pass and a pass is a route
// dump and an address dump, so a grace shorter than this cannot be honored and
// only sets how often that happens.
const MinCaptureGrace = time.Second

// captureLiveness decides when the mesh may be handed this machine's own
// traffic.
//
// An exit announces a default and the reconciler installs it, and from then on
// every packet this machine sends leaves through the tun. That is the feature.
// It is also the failure: a node whose mesh has gone has no network at all,
// rather than the mesh being down and the uplink still working, and on a
// laptop the mesh goes for ordinary reasons: wifi to ethernet, a dock, sleep
// and wake, a VPN started underneath. With literal endpoints the sessions
// still redial over the uplink, since the underlay keeps off the mesh's
// routes. A lookup of an endpoint name whose query leaves without the
// underlay's Prepare, such as a stub's own query upstream from the host, to a
// nameserver beyond the networks the host reaches directly goes into the tun
// with the rest of the host's traffic, so a node whose endpoints are names
// cannot resolve them through such a nameserver.
//
// So captureLiveness holds three rules, which together turn that failure into
// a fallback that keeps the host's traffic on its uplink while the mesh is
// down:
//
//   - nothing capturing is installed until one session has been live, so a
//     node that comes up next to a stale announcement never takes it.
//   - it is withdrawn once no session has been live for the grace, so a node
//     that loses the mesh falls back to its own uplink.
//   - it is restored on the first live session, so the recovery needs nobody
//     to run a command.
//
// Whether a session is live is the caller's question to answer, and the answer
// this daemon gives is a session that has recently proved its peer is there,
// not one that is merely installed. It only counts them.
type captureLiveness struct {
	grace time.Duration
	// liveAt is when a session was last live, meaningful only once seen is
	// set. seen is the first rule: before any session has been live there is
	// no grace to run, and capture is not allowed rather than counting down
	// from a moment that never happened.
	liveAt  time.Time
	seen    bool
	allowed bool
}

// sample records one liveness observation and reports whether a route that
// would capture the machine may be installed now. changed is set on the
// observation that flips the answer, so a caller says so once rather than
// once per pass.
func (l *captureLiveness) sample(now time.Time, live int) (allowed, changed bool) {
	was := l.allowed
	switch {
	case live > 0:
		l.seen, l.liveAt, l.allowed = true, now, true
	case !l.seen:
		l.allowed = false
	default:
		// Strictly less, so a grace of zero withdraws on the first pass that
		// finds nothing live rather than one pass later.
		l.allowed = now.Sub(l.liveAt) < l.grace
	}
	return l.allowed, l.allowed != was
}

// deadline is when the next sample has to happen for the grace to be honored,
// for a caller that would otherwise wait for its own next wake-up.
//
// It answers while capture is allowed, not only while the grace runs: a session
// stops counting as live when it goes quiet and nothing fires then, so a wake
// one grace after the last live sample bounds the withdrawal at the grace plus
// one sample.
func (l *captureLiveness) deadline() (time.Time, bool) {
	if !l.allowed {
		return time.Time{}, false
	}
	return l.liveAt.Add(l.grace), true
}
