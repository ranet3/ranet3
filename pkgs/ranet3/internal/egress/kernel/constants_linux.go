// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

const (
	// natPriority is one below NF_IP_PRI_NAT_SRC, where a host's own source
	// translation runs, so this chain runs ahead of every chain there whatever
	// order they were made in. See Conflicts.
	natPriority = 99
	// filterPriority is NF_IP_PRI_FILTER, where the limit's chain runs
	filterPriority = 0
	// flowsSet starts the name of the set LimitChain counts each source's flows
	// in, the family's digit ending it
	flowsSet = "flows"
	// setSize is the most sources a family's set of flows holds. The set then
	// takes no new one, and LimitChain leaves that source's flows uncounted.
	setSize = 65535
	// udpDestinationOffset is where the destination port sits in a UDP header
	udpDestinationOffset = 2
	// timeoutObject starts the name of each timeout object, which nft lists
	// unquoted, so a bare tcp, udp or icmp would read back as a keyword nft -f
	// refuses
	timeoutObject = "translated-"
)

// The seconds a flow this exit translates is kept idle in each state, by the
// timeouts its rules attach on the flow's first packet, where the host's would
// forget a quiet flow before RFC 4787 REQ-5, RFC 5382 REQ-5 and RFC 5508 REQ-2
// allow. Every state is written, since one left out takes the host's setting as
// it stood when the timeouts were made.
const (
	// transitoryTimeout is RFC 5382 REQ-5's floor for a TCP connection opening,
	// or closing with a FIN seen each way
	transitoryTimeout = 240
	// establishedTimeout is the kernel's own for an established connection
	establishedTimeout = 432000
	// establishedFloor is RFC 5382 REQ-5's two hours and four minutes, the
	// least an established connection is kept: one half closed, a FIN seen one
	// way alone, which section 5 still counts established, and one that would
	// keep establishedTimeout but holds data unacknowledged, has seen a zero
	// window, or has spent its retransmissions
	establishedFloor = 7440
	// timeWaitTimeout and closeTimeout are the kernel's own, so a closed
	// connection, which the per-source limit leaves out of its count, frees its
	// entry when the host would
	timeWaitTimeout = 120
	closeTimeout    = 10
	// udpUnrepliedTimeout is RFC 4787 REQ-5's two minutes for a flow the other
	// side has not answered, and udpRepliedTimeout REQ-5c's five once it has
	udpUnrepliedTimeout = 120
	udpRepliedTimeout   = 300
	// icmpTimeout is RFC 5508 REQ-2's 60 seconds, for ICMP and ICMPv6
	icmpTimeout = 60
)
