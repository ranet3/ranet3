// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"cmp"
	"slices"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/internal/netstack"
)

// DebugSender reads the sender of each session peer names, a peer named the way redial names one and an empty one naming every session
func (c *Client) DebugSender(peer string) control.SenderInfo {
	info := control.SenderInfo{Sessions: []control.SenderSession{}}
	for _, live := range c.sessions.snapshot() {
		if peer != "" && !identity.Names(live.path, peer) {
			continue
		}
		stats := live.pmtu.peer.SendStats()
		info.Sessions = append(info.Sessions, control.SenderSession{
			Path:         live.path,
			Peer:         live.peer.Node().String(),
			DataHeld:     stats.DataHeld,
			DataLimit:    stats.DataLimit,
			ControlHeld:  stats.ControlHeld,
			ControlLimit: stats.ControlLimit,
			Releases:     senderHistogram(stats.Releases, 1),
			HeadWaits:    senderHistogram(stats.HeadWaits, uint64(netstack.WaitUnit)),
			Seals:        senderHistogram(stats.Seals, uint64(netstack.WaitUnit)),
		})
	}
	slices.SortFunc(info.Sessions, func(a, b control.SenderSession) int { return cmp.Compare(a.Path, b.Path) })
	return info
}

// senderHistogram is h with its bounds and sum in the view's units, unit of them to one of h's
func senderHistogram(h netstack.Histogram, unit uint64) control.SenderHistogram {
	out := control.SenderHistogram{Counts: h.Counts[:], Sum: h.Sum * unit}
	for i := range len(h.Counts) - 1 {
		out.Bounds = append(out.Bounds, unit<<i)
	}
	return out
}
