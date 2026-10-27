// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package transport

import (
	"net/netip"
	"syscall"
)

// portZeroRefusal answers a send to port zero from a socket bound to local, invalid for a hub, as darwin's loopback
// does at xnu-12377.121.6
// udp_output keeps the port, "allow 0 port" (bsd/netinet/udp_usrreq.c:1884), and asks in_pcbladdr for a source where
// the socket is bound to the wildcard and the send names none (:1898), which refuses port zero with EADDRNOTAVAIL
// (bsd/netinet/in_pcb.c:1556), so an IPv4 socket bound to its address sends one, to nothing the network holds, while
// a hub's IPv4 socket, bound to the wildcard, is refused
// udp6_output refuses port zero from any IPv6 socket with EADDRNOTAVAIL (bsd/netinet6/udp6_output.c:287)
func portZeroRefusal(local netip.Addr) error {
	if local.Is4() && !local.IsUnspecified() {
		return nil
	}
	return syscall.EADDRNOTAVAIL
}
