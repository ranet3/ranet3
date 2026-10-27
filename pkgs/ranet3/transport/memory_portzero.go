// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !darwin

package transport

import (
	"net/netip"
	"syscall"
)

// portZeroRefusal answers a send to port zero from a socket of either family as linux's loopback does, with EINVAL
// (net/ipv4/udp.c:1296 and net/ipv6/udp.c:1562 at 940de590), and the network answers so on every host but darwin
func portZeroRefusal(netip.Addr) error {
	return syscall.EINVAL
}
