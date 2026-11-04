// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"log/slog"
	"net/netip"
	"slices"
	"strings"

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

// steers reports mode 3, cap.exit with a via
func (t Table) steers() bool { return t.mode != nil && len(t.mode.Via) != 0 }

// PathStatus is cap.exit via's path as a route pass judged it
type PathStatus struct {
	Via    []netip.Addr
	Source netip.Addr
	// Down is the first SID the pass found unresolved, invalid while every one
	// resolves, and Verdict how the mesh's table answered it
	Down    netip.Addr
	Verdict string
	// Installed is the families whose steered default the pass left in the table, itself or as its cover
	Installed []Family
}

// steeredDefaults adds mode 3's two defaults to the pass's routes while the
// mesh holds a live session and every SID of cap.exit via resolves through its own /128, as
// unresolvedSegment reads them, whatever the fallback.
func (r *Reconciler) steeredDefaults(out []Route) []Route {
	r.pathDown, r.pathVerdict = r.unresolvedSegment()
	if !r.capture || r.pathDown.IsValid() {
		return out
	}
	for _, destination := range steeredDestinations {
		out = append(out, Route{Destination: destination, Metric: routeMetric(destination, false)})
	}
	return out
}

// unresolvedSegment is the first SID of cap.exit via the mesh's table does not
// resolve, looked up from the path's outer source as the dataplane looks a segment up,
// with how the table answered it, and invalid while every one resolves. Every SID is read, not the first alone:
// a retracted exit SID behind a waypoint would otherwise leave the defaults up
// and every packet dropped one hop on.
//
// A SID resolves to a peer through its own /128, the entry whose prefix is the
// SID. Through a shorter entry, another exit's default, a /1 pair, 2000::/3 or
// another node's subnet, the path would carry the host's traffic to a node it
// does not name, which mode 3 forbids. A SID after the first may be this node's
// own, which the waypoint before it reaches through the /128 this node
// originates.
func (r *Reconciler) unresolvedSegment() (netip.Addr, string) {
	for i, sid := range r.table.mode.Via {
		_, verdict, match := r.src.Resolve(r.table.pathSource, sid.Addr)
		switch {
		case verdict == netstack.RouteLocal && i > 0:
		case verdict == netstack.RouteNone:
			return sid.Addr, "no route"
		case verdict == netstack.RouteHeld:
			return sid.Addr, "held"
		case verdict == netstack.RouteLocal:
			return sid.Addr, "this node's own"
		case r.captures(Route{Destination: netip.PrefixFrom(sid.Addr, match.Bits).Masked()}):
			return sid.Addr, "only through a route that counts as a default"
		case verdict == netstack.RoutePeer && match.Bits != sid.Addr.BitLen():
			return sid.Addr, "no route of its own"
		}
	}
	return netip.Addr{}, ""
}

// pathPass is the path as the route pass that left held in the kernel judged
// it, nil outside mode 3, and reports a change of its state or of what it left
// installed, once
func (r *Reconciler) pathPass(held map[Route]bool) *PathStatus {
	if !r.table.steers() {
		r.pathReported = nil
		return nil
	}
	status := &PathStatus{Source: r.table.pathSource, Down: r.pathDown, Verdict: r.pathVerdict}
	for _, sid := range r.table.mode.Via {
		status.Via = append(status.Via, sid.Addr)
	}
	for route := range held {
		steered := slices.Contains(steeredDestinations[:], route.Destination) && !route.Unreachable && !route.Throw && !route.Source.IsValid()
		// mode 3 declines every other route that counts as a default, so a member of the cover stands in for a steered default
		family := familyOf(route.Destination.Addr())
		if (steered || route.Cover) && !slices.Contains(status.Installed, family) {
			status.Installed = append(status.Installed, family)
		}
	}
	slices.Sort(status.Installed)
	r.reportPath(status)
	return status
}

// reportPath logs and emits kernel.path when the path's state, the SID that
// took it down and the table's answer for it, or the families whose steered
// default is installed differ from the last pass's
func (r *Reconciler) reportPath(status *PathStatus) {
	if last := r.pathReported; last != nil && last.Down == status.Down && last.Verdict == status.Verdict && slices.Equal(last.Installed, status.Installed) {
		return
	}
	r.pathReported = status
	attrs := []slog.Attr{slog.String("state", "up"), slog.String("installed", familyList(status.Installed))}
	if status.Down.IsValid() {
		attrs = []slog.Attr{slog.String("state", "down"), slog.String("segment", status.Down.String()), slog.String("verdict", status.Verdict), attrs[1]}
		slog.Warn("kernel is withdrawing the steered defaults", "segment", status.Down, "verdict", status.Verdict,
			"detail", "the segment of cap.exit via resolves to no peer through its own /128, so the host's traffic meets the fallback until it does")
	} else {
		slog.Info("kernel holds the steered defaults while every segment of cap.exit via resolves to a peer through its own /128, or for a segment after the first to this node", "installed", familyList(status.Installed))
	}
	r.rt.Events.Emit("kernel.path", "", attrs...)
}

// familyList is families as one attribute, none for no family
func familyList(families []Family) string {
	if len(families) == 0 {
		return "none"
	}
	names := make([]string, len(families))
	for i, family := range families {
		names[i] = string(family)
	}
	return strings.Join(names, " ")
}
