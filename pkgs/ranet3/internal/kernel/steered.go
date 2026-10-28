// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"log/slog"
	"net/netip"

	"ranet3.com/pkgs/ranet3/internal/netstack"
)

// steeredDestinations are mode 3's two defaults, out of the tun like every
// route the mirror installs, where the mesh steers what no route of its own
// covers along cap.exit via. The rules derivedRules gives decide which lookups
// reach them.
var steeredDestinations = [...]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}

// WithPathSource is t sending cap.exit via's path from source, the outer
// source the steering table's default is built with
func (t Table) WithPathSource(source netip.Addr) Table {
	t.pathSource = source
	return t
}

// PathSource is the outer source cap.exit via's path is sent from, invalid
// outside mode 3
func (t Table) PathSource() netip.Addr { return t.pathSource }

// steers reports mode 3, cap.exit with a via
func (t Table) steers() bool { return t.mode != nil && len(t.mode.Via) != 0 }

// resolver answers a lookup in the mesh's table as the dataplane makes it,
// which netstack.RouteTable does
type resolver interface {
	Resolve(src, dst netip.Addr) (*netstack.Peer, netstack.Verdict, netstack.Match)
}

// steeredDefaults adds mode 3's two defaults to the pass's routes while the
// capture gate is open and every SID of cap.exit via resolves, as
// unresolvedSegment reads them. A pass that finds one SID unresolved leaves both out, so the
// pass withdraws them whatever the fallback, and the next pass that finds
// every SID resolved adds them back.
func (r *Reconciler) steeredDefaults(out []Route) []Route {
	down := r.unresolvedSegment()
	r.reportPath(down)
	if !r.capture || down.IsValid() {
		return out
	}
	for _, destination := range steeredDestinations {
		out = append(out, Route{Destination: destination, Metric: routeMetric(r.table.Metric, destination, false)})
	}
	return out
}

// unresolvedSegment is the first SID of cap.exit via the mesh's table does not
// resolve, looked up from the path's outer source as the dataplane looks a segment up,
// and invalid while every one resolves. Every SID is read, not the first alone:
// a retracted exit SID behind a waypoint would otherwise leave the defaults up
// and every packet dropped one hop on.
//
// A SID resolves to a peer through an entry that counts as no default. One
// that only another exit's default, a /1 pair or 2000::/3 covers would carry
// the path to an exit it does not name, which mode 3 forbids. A SID after the
// first may be this node's own, which the waypoint before it reaches through
// the /128 this node originates.
func (r *Reconciler) unresolvedSegment() netip.Addr {
	routes, ok := r.src.(resolver)
	for i, sid := range r.table.mode.Via {
		if !ok {
			return sid.Addr
		}
		_, verdict, match := routes.Resolve(r.table.pathSource, sid.Addr)
		switch {
		case verdict == netstack.RouteLocal && i > 0:
		case verdict != netstack.RoutePeer, r.captures(Route{Destination: netip.PrefixFrom(sid.Addr, match.Bits).Masked()}):
			return sid.Addr
		}
	}
	return netip.Addr{}
}

// reportPath logs the SID that took the path down, once, and the path's return
func (r *Reconciler) reportPath(down netip.Addr) {
	if down == r.pathDown {
		return
	}
	if down.IsValid() {
		slog.Warn("kernel is withdrawing the steered defaults", "segment", down,
			"detail", "the segment of cap.exit via does not resolve to a peer, so the host's traffic meets the fallback until it does")
	} else {
		slog.Info("kernel is installing the steered defaults again", "detail", "every segment of cap.exit via resolves to a peer")
	}
	r.pathDown = down
}
