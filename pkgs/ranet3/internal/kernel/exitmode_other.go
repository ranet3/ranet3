// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build (!linux && !darwin) || android || ios

package kernel

import (
	"fmt"
	"runtime"
)

// RefuseExitMode refuses cap.exit where this build has no exit mode, the BSDs
// and mobile, which have no reconciler at all
func RefuseExitMode(ExitMode) error {
	return fmt.Errorf("kernel: cap.exit is refused on %s, where this build has no exit mode: remove cap.exit, and this host keeps its own default", runtime.GOOS)
}

// RefuseFallback refuses fallback = "none", written or unwritten in mode 3,
// where this build has no filter to hold the host's traffic to the switch's
// lines with
func RefuseFallback(mode ExitMode) error {
	if !mode.Refuses() {
		return nil
	}
	if mode.Fallback == "" {
		return fmt.Errorf("kernel: cap.exit via is refused on %s with fallback unwritten, which is %q in mode 3, where this build has no filter to keep the host's traffic off the uplink", runtime.GOOS, FallbackNone)
	}
	return fmt.Errorf("kernel: cap.exit fallback = %q is refused on %s, where this build has no filter to keep the host's traffic off the uplink", mode.Fallback, runtime.GOOS)
}
