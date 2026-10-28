// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !linux || android

package kernel

import (
	"fmt"
	"runtime"
)

// RefuseExitMode refuses cap.exit where this build has no exit mode: darwin
// has no policy rules to write it with, and the BSDs and mobile have no
// reconciler at all
func RefuseExitMode() error {
	return fmt.Errorf("kernel: cap.exit is refused on %s, where this build has no exit mode: remove cap.exit, and this host keeps its own default", runtime.GOOS)
}

// RefuseFallback refuses fallback = "none" where this build has no filter to
// hold the host's traffic to the switch's lines with
func RefuseFallback(mode ExitMode) error {
	if !mode.Refuses() {
		return nil
	}
	return fmt.Errorf("kernel: cap.exit fallback = %q is refused on %s, where this build has no filter to keep the host's traffic off the uplink: remove fallback, and the host's traffic leaves by its own default while no exit is live", mode.Fallback, runtime.GOOS)
}
