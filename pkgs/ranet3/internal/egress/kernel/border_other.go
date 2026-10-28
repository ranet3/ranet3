// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !linux || android

package kernel

import (
	"fmt"
	"runtime"
)

// errNoBorder refuses cap.border by name where there is no nftables chain to
// write: a node that accepted the block and filtered nothing would carry
// forged mesh sources from its other links while its status said otherwise.
var errNoBorder = fmt.Errorf("egress: cap.border is an nftables chain, which %s does not have, so this node cannot filter what enters the mesh from its other links", runtime.GOOS)

// EntryRuns is whether this platform writes the entry chain, which no
// platform without nftables has
const EntryRuns = false

func newBorderBackend() (borderBackend, error) { return nil, errNoBorder }
