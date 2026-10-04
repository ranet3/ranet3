// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package control

import (
	"net"

	"golang.org/x/sys/unix"
)

// peerCred reads LOCAL_PEERCRED and LOCAL_PEERPID
func peerCred(conn *net.UnixConn) (Caller, bool) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return Caller{}, false
	}
	var cred *unix.Xucred
	var pid int
	var credErr, pidErr error
	err = raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		pid, pidErr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	})
	if err != nil || credErr != nil {
		return Caller{}, false
	}
	caller := Caller{UID: cred.Uid}
	if pidErr == nil {
		caller.PID = int32(pid)
	}
	return caller, true
}
