// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import "time"

const (
	// TableName is the nftables table this package owns, and the whole of its
	// ownership claim. It is the binary's own name so that an operator reading
	// `nft list ruleset` on a shared host can tell at a glance who wrote it.
	TableName = "ranet3"
	// ChainName is the table's nat postrouting base chain, which translates.
	ChainName = "postrouting"
	// LimitChain is the table's filter forward base chain beside it
	LimitChain = "forward"
	// NoneChain starts the name of each of the table's regular chains, one for
	// each class of none, the class's prefix ending it
	NoneChain = "none_"
	// BorderChain is the antispoof filter's chain at prerouting, in the inet
	// table of the same name, so the translator's ip and ip6 tables and the
	// filter's table never hold each other's chains
	BorderChain = "antispoof"
	// EntryChain is the chain beside it that lets a packet into the mesh's
	// tun only as a reply, toward an IPv6 link-local or multicast destination,
	// from a source this node owns or toward a destination a none class takes
	EntryChain = "mesh_entry"
	// carvedSet, ownedSet and noneSet start the names of the table's sets,
	// the family's digit ending each
	carvedSet = "carved"
	ownedSet  = "owned"
	noneSet   = "none"
	// minRetryInterval is the first delay after a failed pass, and it doubles up
	// to the sweep interval, as in internal/kernel.
	minRetryInterval = time.Second
	// rawPriority is NF_IP_PRI_RAW, the hook priority the antispoof chain runs
	// at: after defragmentation at -400 and before conntrack at -200, so a
	// forged packet creates no connection entry
	rawPriority = -300
	// entryPriority is NF_IP_PRI_NAT_SRC plus 10, srcnat + 10 in nft's
	// words: every source translation at postrouting runs inside NAT's own
	// hook at 100 whatever priority its chain names, so the entry chain reads
	// the source a packet leaves with
	entryPriority = 110
)
