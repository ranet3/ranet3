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
	// reservationMargin keeps a held slot past the close that ends its
	// socket's TIME_WAIT, while the PCB collector may not yet have given back
	// the port's reservation, which the namespace refuses to the host's
	// Skywalk flows (skywalk/namespace/netns.c). The abort schedules the
	// collector's fast pass (_inpcb_sched_timeout in bsd/netinet/in_pcb.c),
	// and on one Mac in use the reservation is gone within 1 second of it.
	// The margin is two such passes and no ceiling: a pass that gives up on a
	// PCB whose lock it cannot take (tcp_gc in bsd/netinet/tcp_timer.c)
	// re-arms lazily, so the next pass is the one another socket's detach
	// schedules on a busy host and the lazy one on an idle host.
	reservationMargin = 2 * time.Second
)
