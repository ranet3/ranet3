// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import "time"

// the values the netlink backend chooses, apart from constants.go because no other platform reads them

const (
	// Loopback is the name of the loopback link, whose index every lookup of the host's own traffic carries
	Loopback = "lo"
	// monitorReceiveBuffer is the route monitor's receive buffer, in bytes
	// a route flood that overflows it costs an ENOBUFS, survivable but a full resync
	monitorReceiveBuffer = 1 << 20
	// monitorReadSize is one read of the route monitor, in bytes
	// it is larger than any notification datagram the kernel sends
	monitorReadSize = 64 << 10
	// resolvedWait bounds one question to systemd-resolved, which answers from
	// its own state without a query of its own
	resolvedWait = time.Second
	// fallbackPriority runs each chain of the kill switch after every
	// priority nft and iptables name, conntrack's and NAT's among them, and at
	// postrouting ahead of conntrack's confirmation at the last one, so a packet
	// it drops confirms no entry
	fallbackPriority = 2147483646
	// fallbackSetIDs is how many anonymous set IDs each of the switch's chains
	// takes, past the named sets' 1 to 7, more than its lines read
	fallbackSetIDs = 10
)
