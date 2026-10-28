// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package pf

import "time"

const (
	// LabelMax is the most bytes a rule's label holds, PF_RULE_LABEL_SIZE less
	// its terminator (bsd/net/pfvar.h), past which pfctl refuses the rule as
	// "rule label too long (max 63 chars)"
	LabelMax = 63
	// pfctlPath is run by its absolute path, so no PATH reaches the writer of
	// the host's packet filter
	pfctlPath = "/sbin/pfctl"
	// pfctlTimeout bounds one pfctl call, against a slowest of 8.6 ms measured
	// over a pass's calls, so a call stuck on pf's lock cannot hold a pass
	pfctlTimeout = 10 * time.Second
)
