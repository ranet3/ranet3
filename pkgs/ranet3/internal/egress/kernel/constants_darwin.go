// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package kernel

import "time"

// EntryRuns is whether this platform writes the entry chain. The anchor holds
// no entry rule: darwin runs no exit, so no reply needs a flow table to tell it
// from a forged packet, and the tun read's drop of a source this node does not
// own covers every packet the rule would drop.
const EntryRuns = false

const (
	// pfSweep is the antispoof filter's periodic pass over pf, which bounds
	// how long another writer's change to the anchor goes unnoticed, since pf
	// posts no event of one
	pfSweep = 5 * time.Second
	// pfAnchor is the filter's anchor, a child of com.apple, which the stock
	// main ruleset calls
	pfAnchor = "com.apple/ranet3"
	// pfRecord names the record of the filter's reference on pf in the state
	// directory
	pfRecord = "pf.json"
)
