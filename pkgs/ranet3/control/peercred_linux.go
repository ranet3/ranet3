// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package control

import (
	"net"

	"golang.org/x/sys/unix"
)

// peerCred reads SO_PEERCRED, the credentials the peer held when it called connect
func peerCred(conn *net.UnixConn) (Caller, bool) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return Caller{}, false
	}
	var cred *unix.Ucred
	var credErr error
	err = raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if err != nil || credErr != nil {
		return Caller{}, false
	}
	return Caller{UID: cred.Uid, PID: cred.Pid}, true
}
