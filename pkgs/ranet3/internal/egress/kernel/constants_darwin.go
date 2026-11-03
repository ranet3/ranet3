// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package kernel

import "time"

// EntryRuns is whether this platform writes the entry chain on every node
// holding a tun. pf is one switch for the whole host, so darwin writes the
// chain only where overlay is written.
const EntryRuns = false

const (
	// borderSweep is the antispoof filter's periodic pass, which bounds how
	// long another writer's change to the anchor goes unnoticed, since pf
	// posts no event of one
	borderSweep = 5 * time.Second
	// pfAnchor is the filter's anchor, a child of com.apple, which the stock
	// main ruleset calls
	pfAnchor = "com.apple/ranet3"
	// pfRecord names the record of the filter's reference on pf in the state
	// directory
	pfRecord = "pf.json"
)
