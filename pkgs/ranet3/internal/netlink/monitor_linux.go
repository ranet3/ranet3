// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package netlink

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// Subscribe opens a socket of protocol in the notification groups, a bitmask,
// with receiveBuffer bytes of receive buffer, so a flood of notifications
// costs as few ENOBUFS as it can. The socket is nonblocking, so os.NewFile
// registers it with the runtime poller and Close unblocks its reader without
// racing on the descriptor.
func Subscribe(name string, protocol int, groups uint32, receiveBuffer int) (*os.File, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, protocol)
	if err != nil {
		return nil, fmt.Errorf("netlink: open the %s socket: %w", name, err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: groups}); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("netlink: join the notification groups of %s: %w", name, err)
	}
	growReceiveBuffer(fd, receiveBuffer)
	return os.NewFile(uintptr(fd), name), nil
}

// growReceiveBuffer asks for size bytes of receive buffer on fd, past
// rmem_max where it can. Best effort: the forced form needs CAP_NET_ADMIN in
// the initial user namespace, and a kernel that refuses both leaves the
// smaller buffer rather than a failure to start.
func growReceiveBuffer(fd, size int) {
	if unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, size) != nil {
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, size)
	}
}
