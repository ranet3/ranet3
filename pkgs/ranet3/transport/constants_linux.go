// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package transport

import "time"

// the values the linux socket chooses, in a file of their own because no other platform reads them

// unsegmentedFor is how long sends to an endpoint whose path refused segments go one datagram to a message
// it is how long linux keeps a path MTU it learned, net.ipv4.route.mtu_expires and its IPv6 twin by default
// single datagrams cost more CPU per byte, so a path that widened again segments again after it
const unsegmentedFor = 600 * time.Second

const (
	// controlMessageSize is the bytes of control messages one datagram carries in or out
	// a packet info message of either family fits with UDP_GRO or UDP_SEGMENT beside it
	controlMessageSize = 128
	// gsoMaxSegments is the most datagrams one UDP_SEGMENT message carries
	// linux took 64 until 6.9 raised UDP_MAX_SEGMENTS to 128, and an older kernel refuses more
	gsoMaxSegments = 64
)
