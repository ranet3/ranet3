// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package userspace

import (
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
	// relayedTTL is the TTL of an ICMP error the exit relays toward a leaf
	// from the router that raised it
	relayedTTL = 64
)
