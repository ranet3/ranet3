// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package kernel

import "errors"

// RefuseExitMode refuses forward and inbound. routing.md's "The kill switch on
// macOS" lists what the rejects let leave.
func RefuseExitMode(mode ExitMode) error {
	if len(mode.Forward) > 0 {
		return errors.New("kernel: cap.exit forward is refused on macOS, where this build has no rule that routes a forwarded packet by the link it arrived on: remove forward, and a packet this host forwards toward an exit in a family the mode covers follows the mode into the tun as the host's own does, which drops a source this node does not own")
	}
	if len(mode.Inbound) > 0 {
		return errors.New("kernel: cap.exit inbound is refused on macOS, where this build's kill switch is reject routes with no line passing a listed service's replies: while no exit is live and after a crash a service's replies leave by the uplink over IPv6 TCP whether it is bound to the uplink's address or to the wildcard and over UDP where it is bound to the uplink's address, and are refused over IPv4 TCP and over UDP on the wildcard, whatever inbound lists, so remove inbound")
	}
	return nil
}

// RefuseFallback is nil here, where the rejects on lo0 carry
// fallback = "none"
func RefuseFallback(ExitMode) error { return nil }
