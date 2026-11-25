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
	// fallbackSetIDs is how many anonymous set IDs each chain takes, past
	// the named sets' IDs 1 to 9, more than any chain's lines read
	fallbackSetIDs = 10
	// prioritySourcedTun sends unmarked packets arriving on the tun past the
	// sourced block once the 5410 target and tun are both live.
	prioritySourcedTun = 5399
	// prioritySourcedMain looks only for a main route at least as specific as
	// the protected destination, regardless of that route's protocol.
	prioritySourcedMain = 5401
	// prioritySourcedGuard refuses a pair whose foreign rule makes withdrawal
	// of its lookup ambiguous.
	prioritySourcedGuard = 5402
	// prioritySourcedPeer looks admitted pairs up in the mirrored table.
	prioritySourcedPeer = 5403
	// prioritySourcedRefused refuses every protected packet not yet answered.
	prioritySourcedRefused = 5404
)
