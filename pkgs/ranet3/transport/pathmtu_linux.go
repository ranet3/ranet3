// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package transport

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// routeMTU reads the path MTU of the route linux takes for a send to ep from a socket marked mark
// a socket with that mark, and with the source and interface of ep's pin while sends carry it, connects to ep
// connecting looks the route up as the send did and sends nothing
// IP_MTU and IPV6_MTU then read the route's MTU, a path MTU linux learned for it included
func routeMTU(ep *udpEndpoint, mark uint32) (int, error) {
	network, level, option := "udp4", unix.IPPROTO_IP, unix.IP_MTU
	if ep.addr.IP.To4() == nil {
		network, level, option = "udp6", unix.IPPROTO_IPV6, unix.IPV6_MTU
	}
	pinned := ep.pin() != nil
	dialer := net.Dialer{Control: func(_, _ string, raw syscall.RawConn) error {
		var err error
		if controlErr := raw.Control(func(fd uintptr) {
			if mark != 0 {
				err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark))
			}
			if err == nil && pinned && ep.index != 0 {
				err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BINDTOIFINDEX, ep.index)
			}
		}); controlErr != nil {
			return controlErr
		}
		return err
	}}
	if pinned {
		dialer.LocalAddr = &net.UDPAddr{IP: ep.source}
	}
	conn, err := dialer.Dial(network, ep.addr.String())
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	raw, err := conn.(*net.UDPConn).SyscallConn()
	if err != nil {
		return 0, err
	}
	var mtu int
	var readErr error
	if err := raw.Control(func(fd uintptr) { mtu, readErr = unix.GetsockoptInt(int(fd), level, option) }); err != nil {
		return 0, err
	}
	return mtu, readErr
}
