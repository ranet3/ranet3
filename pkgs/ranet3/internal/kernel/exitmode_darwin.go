// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package kernel

import (
	"errors"
	"fmt"
	"strings"
)

// RefuseExitMode refuses forward, where this build has no rule that routes a
// forwarded packet by the link it arrived on: the mode is routes in the one
// table, which carry a forwarded packet as they carry the host's own
func RefuseExitMode(mode ExitMode) error {
	if len(mode.Forward) == 0 {
		return nil
	}
	return errors.New("kernel: cap.exit forward is refused on macOS, where this build has no rule that routes a forwarded packet by the link it arrived on: remove forward, and a packet this host forwards toward an exit in a family the mode covers follows the mode into the tun as the host's own does, which drops a source this node does not own")
}

// RefuseFallback refuses fallback = "none", written or unwritten in mode 3,
// where this build has no filter to hold the host's traffic to the switch's
// lines with, naming inbound and lan where they are written
func RefuseFallback(mode ExitMode) error {
	if !mode.Refuses() {
		return nil
	}
	var keys []string
	if len(mode.Inbound) > 0 {
		keys = append(keys, "inbound")
	}
	if len(mode.LAN) > 0 {
		keys = append(keys, "lan")
	}
	with, remove := "", ""
	if len(keys) > 0 {
		with, remove = " with "+strings.Join(keys, " and "), " and remove "+strings.Join(keys, " and ")
	}
	if mode.Fallback == "" {
		return fmt.Errorf("kernel: cap.exit via%s with fallback unwritten is %q in mode 3, which is refused on macOS, where this build has no filter to keep the host's traffic off the uplink: write fallback = %q beside via%s", with, FallbackNone, FallbackUplink, remove)
	}
	return fmt.Errorf("kernel: cap.exit fallback = %q%s is refused on macOS, where this build has no filter to keep the host's traffic off the uplink: write fallback = %q%s", mode.Fallback, with, FallbackUplink, remove)
}
