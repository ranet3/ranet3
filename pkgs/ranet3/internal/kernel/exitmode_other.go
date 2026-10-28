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
