// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package egress

import "time"

const (
	// TableName is the nftables table this package owns, and the whole of its
	// ownership claim. It is the binary's own name so that an operator reading
	// `nft list ruleset` on a shared host can tell at a glance who wrote it.
	TableName = "ranet3"
	// ChainName is the one chain in that table, a nat postrouting base chain.
	ChainName = "postrouting"
	// BorderChain is the border filter's one chain, in the inet table of the
	// same name, so the translator's ip and ip6 tables and the filter's table
	// never hold each other's chains
	BorderChain = "border"
	// DefaultSweep is the periodic pass a capability that names none takes.
	DefaultSweep = 30 * time.Second
	// minRetryInterval is the first delay after a failed pass, and it doubles up
	// to the sweep interval, as in internal/kernel.
	minRetryInterval = time.Second
	// rawPriority is NF_IP_PRI_RAW, the hook priority the border chain runs
	// at: after defragmentation at -400 and before conntrack at -200, so a
	// forged packet creates no connection entry
	rawPriority = -300
)
