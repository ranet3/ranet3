// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build (!linux && !darwin) || android || ios

package kernel

import "ranet3.com/pkgs/ranet3/internal/egress"

// EntryRuns is whether this platform writes the entry chain, which no
// platform without nftables has
const EntryRuns = false

// Filters reports that this platform runs no filter, with overlay written or
// not
func Filters(*egress.Border) bool { return false }

// newBorderBackend opens no backend, so this platform runs no antispoof filter
// and status says it is not enforced where overlay is written
func newBorderBackend(*egress.Border, egress.BorderRuntime) (borderBackend, error) { return nil, nil }

// RefuseBorder refuses nothing, since no filter runs here
func RefuseBorder(*egress.Border) error { return nil }
