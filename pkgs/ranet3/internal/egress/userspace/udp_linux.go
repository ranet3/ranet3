// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package userspace

import (
	"net"

	"golang.org/x/sys/unix"
)

// setDontFragment has fd, a UDP socket of family ipv6 or IPv4, refuse a
// datagram past its path's MTU with EMSGSIZE where on is true, and fragment
// it otherwise, an IPv4 one sent with no DF
func setDontFragment(fd int, ipv6, on bool) error {
	if ipv6 {
		value := 0
		if on {
			value = 1
		}
		return unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_DONTFRAG, value)
	}
	mode := unix.IP_PMTUDISC_DONT
	if on {
		mode = unix.IP_PMTUDISC_DO
	}
	return unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, mode)
}

// socketPathMTU is the MTU of the path conn, a connected socket, sends by, as
// the kernel last learned it
func socketPathMTU(conn *net.UDPConn, ipv6 bool) (int, error) {
	level, option := unix.IPPROTO_IP, unix.IP_MTU
	if ipv6 {
		level, option = unix.IPPROTO_IPV6, unix.IPV6_MTU
	}
	var mtu int
	err := onSocket(conn, func(fd int) error {
		var err error
		mtu, err = unix.GetsockoptInt(fd, level, option)
		return err
	})
	return mtu, err
}

// shareDialPort lets fd, a dial's socket, bind its mapping's address and port
// while another dial of the mapping holds it toward another server, as
// SO_REUSEADDR lets a connecting TCP socket on Linux
func shareDialPort(fd int) error {
	return unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
}

// shareMappingPort lets fd, a socket of a mapping, its receiving socket or
// one toward a server, share the mapping's address and port with the
// mapping's other sockets. Linux shares a port by SO_REUSEPORT among the
// sockets of one user alone.
func shareMappingPort(fd int) error {
	return unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
}
