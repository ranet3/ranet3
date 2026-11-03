// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

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
	// pfOverlayTable and pfCarvedTable name the pf anchor's tables, each of
	// both families: the overlay, which the pass on the loopback link reads
	// since pf cannot negate two interfaces in one rule, and the carved sets
	pfOverlayTable = "ranet3_overlay"
	pfCarvedTable  = "ranet3_carved"
)
