// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package userspace

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
)
