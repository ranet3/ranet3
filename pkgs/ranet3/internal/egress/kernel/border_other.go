// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !linux || android

package kernel

import "ranet3.com/pkgs/ranet3/internal/egress"

// EntryRuns is whether this platform writes the entry chain, which no
// platform without nftables has
const EntryRuns = false

// borderSweep is the periodic pass of a filter this platform never runs
const borderSweep = egress.DefaultSweep

// newBorderBackend opens no backend, so this platform runs no antispoof filter
// and status says it is not enforced where overlay is written
func newBorderBackend(egress.BorderRuntime) (borderBackend, error) { return nil, nil }
