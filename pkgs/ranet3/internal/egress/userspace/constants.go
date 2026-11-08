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
	// relayedTTL is the TTL or hop limit of a packet the exit builds toward a
	// leaf, a reply or an error it relays from the host that raised it
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
)
