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
