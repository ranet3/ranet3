// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package transport

import "time"

// the values the linux socket chooses, in a file of their own because no other platform reads them

// unsegmentedFor is how long sends to an endpoint whose route refused segments its single datagrams passed go one datagram to a message
// single datagrams cost more CPU per byte, so sends offer segments again after it
// a route that still refuses them costs one refused message each time, and one that takes them again waits at most this long
const unsegmentedFor = 600 * time.Second

const (
	// controlMessageSize is the bytes of control messages one datagram carries in or out
	// a packet info message of either family fits with UDP_GRO or UDP_SEGMENT beside it
	controlMessageSize = 128
	// gsoMaxSegments is the most datagrams one UDP_SEGMENT message carries
	// linux took 64 until 6.9 raised UDP_MAX_SEGMENTS to 128, and an older kernel refuses more
	gsoMaxSegments = 64
)
