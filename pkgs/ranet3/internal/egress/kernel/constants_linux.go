// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

const (
	// natSrcPriority is NF_IP_PRI_NAT_SRC, where source translation runs.
	// Chains of several writers coexist there. See Conflicts.
	natSrcPriority = 100
	// verdictDrop is NF_DROP, which a border chain drop rule ends with
	verdictDrop = 0
	// ipv6DestinationOffset is where the destination sits in an IPv6 header
	ipv6DestinationOffset = 24
)
