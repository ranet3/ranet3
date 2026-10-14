// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"cmp"
	"math"
	"slices"
	"time"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/internal/netstack"
)

// phaseNames are the states the view names a search's phases by
var phaseNames = [...]string{
	confirming:    control.PMTUConfirming,
	searchingUp:   control.PMTUSearchingUp,
	searchingDown: control.PMTUSearchingDown,
	confirmed:     control.PMTUConfirmed,
	underFloor:    control.PMTUUnderFloor,
}

// DebugPMTU reads link.mtu, the tun and the counts of answers and clamps from their owners, and the search of each session peer names
// a peer is named the way redial names one, and an empty one names every session
func (c *Client) DebugPMTU(peer string) control.PMTUInfo {
	info := control.PMTUInfo{
		LinkMTU:    c.config().Link.SessionMTU(),
		Steering:   c.Mesh.Steering().Overhead(),
		DeviceMTU:  c.Mesh.MTU(),
		TooBigSent: c.Mesh.TooBigAnswered(),
		MSSClamped: c.Mesh.MSSClamped(),
		Sessions:   []control.PMTUSession{},
	}
	now := time.Now()
	for _, live := range c.sessions.snapshot() {
		if live.pmtu == nil || peer != "" && !identity.Names(live.path, peer) {
			continue
		}
		view := live.pmtu.view(now)
		view.Peer = live.peer.Node().String()
		info.Sessions = append(info.Sessions, view)
	}
	slices.SortFunc(info.Sessions, func(a, b control.PMTUSession) int { return cmp.Compare(a.Path, b.Path) })
	return info
}

// view is the session's search as it stands, with the budget its peer carries
func (d *pathDriver) view(now time.Time) control.PMTUSession {
	budget := d.peer.MTU()
	ipv4, ipv6 := netstack.MSSLimits(budget)
	view := control.PMTUSession{Path: d.peer.ID, State: control.PMTUNotSearched, Budget: budget, MSSv4: ipv4, MSSv6: ipv6}
	d.mu.Lock()
	defer d.mu.Unlock()
	view.DontFragment = d.mux.DontFragment()
	// only a search takes a move, so a session not searched names the endpoint its mux sends to
	if !d.searching {
		view.Endpoint = d.mux.Endpoint().String()
		return view
	}
	view.Endpoint = d.endpoint.String()
	s := &d.search
	view.State, view.Target = phaseNames[s.phase], s.target()
	if s.route != math.MaxInt {
		view.Route = s.route
	}
	view.Sent, view.Acked, view.Lost, view.Refusals = s.tally.sent, s.tally.acked, s.tally.lost, d.refusals
	if s.probe.size != 0 {
		view.Probe = &control.PMTUProbe{Size: s.probe.size, Attempts: s.probe.attempts, MaxAttempts: maxProbes}
	}
	if !s.last.at.IsZero() {
		view.Last = &control.PMTUOutcome{Size: s.last.size, Acked: s.last.acked, Ago: control.Duration(now.Sub(s.last.at))}
	}
	if c := d.changed; !c.at.IsZero() {
		view.Changed = &control.PMTUChange{From: c.from, To: c.to, Reason: c.why, Ago: control.Duration(now.Sub(c.at))}
	}
	return view
}
