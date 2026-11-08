// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package userspace

import (
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/header"

	"ranet3.com/pkgs/wireguard/tun"
)

const (
	// nicID is the stack's one NIC, the link toward the lanes
	nicID = 1
	// linkMTU is the largest packet the stack's link takes or sends whole,
	// the largest IP packet, so the stack never cuts what a lane's session
	// then cuts again: classify cuts an IPv4 packet past its session, and the
	// exit an IPv6 one it built
	linkMTU = 1<<16 - 1
	// linkGSOMaxSize is the largest segmentation offload frame the stack
	// writes, which the pump cuts into its segments in a lane's batch, as a
	// tun read lays them
	linkGSOMaxSize = 1<<16 - 1
	// linkQueuePackets bounds the packets the link holds toward the pump
	// beside Limits.Link's bytes, so a burst of small packets meets a bound
	// as a burst of frames does
	linkQueuePackets = 4096

	// maxWorkers caps the lanes' workers, one per CPU below it, since the
	// stack's own goroutines take the rest
	maxWorkers = 16
	// workerQueuePackets bounds the packets queued to one worker beside
	// Limits.Lanes' bytes, so a burst of small packets meets a bound as a
	// burst of large ones does
	workerQueuePackets = 1024
	// smallBuffer holds a packet off any common link, and largeBuffer the
	// largest IP packet, the two sizes of Egress's copies
	smallBuffer = 2048
	largeBuffer = 1<<16 - 1
	// cutReads and cutSlab hold the segments of the largest frame the stack
	// writes at the least segment size its TCP sends, each with the largest
	// headers and ReadPacketSpacing around it
	cutReads = linkGSOMaxSize/header.TCPMinimumSendMSS + 1
	cutSlab  = cutReads*(header.IPv4MaximumHeaderSize+header.TCPHeaderMaximumSize+tun.ReadPacketSpacing) + linkGSOMaxSize + tun.ReadPacketSpacing

	// copyBuffer is the bytes one copy of a relayed connection moves at
	// most, a socket read's worth
	copyBuffer = 32 << 10
	// relayedTTL is the TTL and the hop limit of the packets the exit builds
	// until it is given the host's own
	relayedTTL = 64

	// mappingTimeout keeps a UDP mapping past its last datagram out, RFC
	// 4787 REQ-5's recommended default, and dnsTimeout a mapping whose
	// datagrams go to port 53 alone, as REQ-5a lets a well-known port's
	// application have
	mappingTimeout = 5 * time.Minute
	dnsTimeout     = 30 * time.Second
	// mappingSweep spaces the passes that end the mappings past their time,
	// each ending at most this late. A new mapping holds it before its first
	// datagram's time, so no pass ends it while it opens, and one that no
	// datagram goes out of ends within two passes.
	mappingSweep = 5 * time.Second
	// lowPortSearch bounds the other ports below 1024 a new mapping tries
	// for a leaf's port below 1024 that the host holds, so one datagram costs
	// at most this many binds past the leaf's own and the host's
	lowPortSearch = 16
	// echoIdle ends an echo mapping with no request out or reply in for this
	// long, the least RFC 5508 REQ-2 allows
	echoIdle = time.Minute

	// The shares Within takes of memory: the budget B is half of what Go's
	// limit leaves past the node's own heap, since the limit holds it twice,
	// live and as the collector's headroom, else a sixteenth of the host's
	// memory. Each of the two queues holds a thirty-second of B within its
	// bounds, and the fixed part F is gVisor's reassembly and the two queues.
	// Of R = B - F an eighth goes to the UDP and echo mappings and the rest,
	// T, to TCP: Window is T / (2 * windowFlows) within its bounds, and
	// Connections as many as T holds at two windows, perConnection and
	// perTimeWait each. Flows is Connections and the mappings an eighth of R
	// holds at perFlow each, within the descriptors past daemonFiles at
	// flowFiles a flow, so the node keeps its own under any mix of flows, and
	// Connections is cut to Flows where those hold fewer.
	goLimitShare = 2
	hostShare    = 16
	queueShare   = 32
	flowShare    = 8
	// minQueue and maxQueue bound each queue's bytes, maxQueue at 512 frames
	// of 64 KiB
	minQueue = 256 << 10
	maxQueue = 32 << 20
	// reassembly is gVisor's ceiling on the fragments it holds, 4 MiB for each
	// of the two network protocols, a fixed part of every budget
	reassembly = 2 * 4 << 20
	// windowFlows is the TCP flows a budget holds at the full window, and
	// minWindow and maxWindow bound the window: an unscaled TCP window, and
	// 6 MiB
	windowFlows = 1024
	minWindow   = 64 << 10
	maxWindow   = 6 << 20
	// minConnections is the fewest TCP connections a budget holds at
	// minWindow, below which Within refuses
	minConnections = 16
	// perConnection is a TCP connection's memory past its two windows, as
	// measured with both copy buffers moving, perTimeWait an endpoint's in
	// TIME_WAIT, rounded up from its measure, and perFlow a UDP or echo
	// mapping's, a guess no measure has settled
	perConnection = 128 << 10
	perTimeWait   = 8 << 10
	perFlow       = 8 << 10
	// daemonFiles is the descriptors the node keeps beside the exit's flows,
	// its tun's queues, the transport's sockets, the control socket and the
	// files it reads, a guess no measure has settled
	daemonFiles = 256
	// flowFiles is the most descriptors one flow holds at once: a UDP
	// mapping's first destination holds the mapping's receiving socket and its
	// own connected one, and a TCP flow being dialed its socket and the
	// duplicate its error queue is read through. Every other flow holds one,
	// or none.
	flowFiles = 2
	// maxDials bounds the connections dialed at once, below gVisor's bound on
	// connections in flight
	maxDials = 8192

	// statusSources is the sources the status names, those holding the most
	// flows
	statusSources = 16
	// refusedInterval spaces the egress.refused records, as the mesh spaces
	// its reports of trouble
	refusedInterval = 30 * time.Second
)
