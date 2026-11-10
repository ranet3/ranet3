// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package userspace

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// setDontFragment has fd, a UDP socket of family ipv6 or IPv4, refuse a
// datagram past its path's MTU with EMSGSIZE where on is true, and fragment
// it otherwise
func setDontFragment(fd int, ipv6, on bool) error {
	value := 0
	if on {
		value = 1
	}
	if ipv6 {
		return unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_DONTFRAG, value)
	}
	return unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_DONTFRAG, value)
}

// socketPathMTU reads nothing, since darwin keeps no path MTU a socket hands
// out, and the link's MTU stands for it
func socketPathMTU(*net.UDPConn, bool) (int, error) { return 0, errors.ErrUnsupported }

// shareDialPort lets fd, a dial's socket, bind its mapping's address and port
// while another dial of the mapping holds it toward another server, which XNU
// allows two TCP sockets that both hold SO_REUSEPORT. The dial binds one
// address, never the wildcard one: in in_pcbbind (bsd/netinet/in_pcb.c, xnu
// f6217f8) a later bind of the wildcard address beside a socket holding
// SO_REUSEPORT skips the check that both belong to one user, so a socket
// holding it on the wildcard address would let a process of any user share
// the exit's port
func shareDialPort(fd int) error {
	return unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
}

// shareMappingPort lets fd, a socket of a mapping, its receiving socket or
// one toward a server, share the mapping's address and port with the
// mapping's other sockets, by SO_REUSEPORT, which another user cannot share on
// one address (see shareDialPort). XNU refuses a bind of an address and port
// another socket holds unconnected, so a mapping connects its sockets one at a
// time under its lock.
func shareMappingPort(fd int) error {
	return unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
}
