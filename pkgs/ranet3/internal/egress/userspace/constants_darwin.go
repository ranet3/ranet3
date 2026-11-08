// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package userspace

import "time"

const (
	// echoDestinations is how many of the destinations an echo mapping sent
	// to it remembers, the latest, a reply from any other being another
	// program's
	echoDestinations = 16
	// echoReplies is how many replies an echo mapping holds toward its leaf,
	// a reply past them dropped and counted
	echoReplies = 16
	// dialErrorWait is how long a dial that failed for an ICMP error waits for
	// the exit's ICMP socket to read the error. XNU hands the error to the
	// dial's socket before it hands the message to the ICMP sockets
	// (icmp_input in bsd/netinet/ip_icmp.c), so the dial can return first.
	dialErrorWait = 10 * time.Millisecond
)
