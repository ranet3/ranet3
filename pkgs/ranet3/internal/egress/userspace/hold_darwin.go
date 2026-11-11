// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package userspace

import (
	"encoding/binary"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// xnuHostSockets reads XNU's bound on the host ports: a socket's state through
// TCP_CONNECTION_INFO, the automatic range through net.inet.ip.portrange.first
// and last, the range every program's automatic bind and unbound connect take
// a port from, and the MSL through net.inet.tcp.msl, in milliseconds
func xnuHostSockets() *hostSockets {
	return &hostSockets{state: xnuState, ports: xnuPorts, msl: xnuMSL, margin: reservationMargin}
}

// sonpxSetOptShut is SONPX_SETOPTSHUT of bsd/sys/socket.h, which allows a
// socket's options to be set after both its halves have shut down
const sonpxSetOptShut = 0x1

// prepareHostSocket sets SO_NP_EXTENSIONS with SONPX_SETOPTSHUT on a dial's
// socket before its connect. XNU refuses every setsockopt with EINVAL on a
// socket that can neither send nor receive unless the socket carries that
// flag (sosetoptlock in bsd/kern/uipc_socket.c), and a socket in TIME_WAIT the
// exit shut is such a socket, so without it the linger of 0 that ends a held
// TIME_WAIT would be refused. The flag is itself an option, set while the
// socket still takes one. The value is struct so_np_extensions, npx_flags and
// then npx_mask, each a uint32.
func prepareHostSocket(fd int) error {
	var npx [8]byte
	binary.NativeEndian.PutUint32(npx[0:4], sonpxSetOptShut)
	binary.NativeEndian.PutUint32(npx[4:8], sonpxSetOptShut)
	return unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_NP_EXTENSIONS, string(npx[:]))
}

func xnuState(raw syscall.RawConn) (hostState, error) {
	var info *unix.TCPConnectionInfo
	var err error
	if controlErr := raw.Control(func(fd uintptr) {
		info, err = unix.GetsockoptTCPConnectionInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_CONNECTION_INFO)
	}); controlErr != nil {
		return hostClosed, controlErr
	}
	if err != nil {
		return hostClosed, err
	}
	// XNU's states, bsd/netinet/tcp_fsm.h
	switch info.State {
	case 0:
		return hostClosed, nil
	case 6, 9:
		return hostFinWait, nil
	case 7:
		return hostClosing, nil
	case 8:
		return hostLastAck, nil
	case 10:
		return hostTimeWait, nil
	}
	return hostOther, nil
}

// xnuPorts is the ports of the automatic range, which XNU scans downward
// where first is above last
func xnuPorts() (int, error) {
	first, err := unix.SysctlUint32("net.inet.ip.portrange.first")
	if err != nil {
		return 0, err
	}
	last, err := unix.SysctlUint32("net.inet.ip.portrange.last")
	if err != nil {
		return 0, err
	}
	return int(max(first, last)-min(first, last)) + 1, nil
}

func xnuMSL() (time.Duration, error) {
	msl, err := unix.SysctlUint32("net.inet.tcp.msl")
	if err != nil {
		return 0, err
	}
	return time.Duration(msl) * time.Millisecond, nil
}
