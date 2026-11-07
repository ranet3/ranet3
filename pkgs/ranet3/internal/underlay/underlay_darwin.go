// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin

package underlay

import (
	"net/netip"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// Scope scopes raw to the interface index with IP_BOUND_IF or IPV6_BOUND_IF.
// An index of 0 scopes it to none and releases the route it caches,
// inp_bindif_common in bsd/netinet/in_pcb.c.
func Scope(raw syscall.RawConn, ipv6 bool, index int) error {
	level, option := unix.IPPROTO_IP, unix.IP_BOUND_IF
	if ipv6 {
		level, option = unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF
	}
	var setErr error
	if err := raw.Control(func(fd uintptr) { setErr = unix.SetsockoptInt(int(fd), level, option, index) }); err != nil {
		return err
	}
	return setErr
}

// Bound scopes each socket to the interface interfaceOf names for its
// destination, and refuses it with ENETUNREACH where it names none, since a
// socket scoped to nothing follows a route into the mesh. A socket that only
// receives is left unscoped. The option follows the socket's family as network
// names it, since Go opens a socket toward an IPv4-mapped destination as
// AF_INET.
func Bound(interfaceOf func(netip.Addr) (index int, generation uint64)) Prepare {
	return func(network string, to netip.AddrPort, raw syscall.RawConn) error {
		if !to.Addr().IsValid() {
			return nil
		}
		index, _ := interfaceOf(to.Addr().Unmap())
		if index == 0 {
			return unix.ENETUNREACH
		}
		return Scope(raw, isIPv6(network), index)
	}
}

// isIPv6 reads the family from a network as Go hands it to a control
// function, "udp6", "tcp6" or "ip6:ipv6-icmp"
func isIPv6(network string) bool {
	family, _, _ := strings.Cut(network, ":")
	return strings.HasSuffix(family, "6")
}
