// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package transport

import "time"

// the values the linux socket chooses, in a file of their own because no other platform reads them

// unsegmentedFor is how long sends to an endpoint whose path refused segments go one datagram to a message
// it is how long linux keeps a path MTU it learned, net.ipv4.route.mtu_expires and its IPv6 twin by default
// single datagrams cost more CPU per byte, so a path that widened again segments again after it
const unsegmentedFor = 600 * time.Second
