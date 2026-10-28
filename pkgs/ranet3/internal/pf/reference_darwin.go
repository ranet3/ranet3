// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package pf

import "golang.org/x/sys/unix"

// Take takes a reference on pf for this process, which enables pf if no
// reference held it, and records its token at path, then gives back the
// references an earlier run recorded there. It needs root.
func Take(ctl Ctl, path string) (*Reference, error) {
	return take(ctl, path, startReference)
}

// startReference issues DIOCSTARTREF through libSystem's ioctl, so the kernel
// records this process's pid and name with the token
func startReference() (uint64, error) {
	fd, err := unix.Open("/dev/pf", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)
	// _IOR('D', 8, u_int64_t), bsd/net/pfvar.h, whose 8 bytes an int holds
	token, err := unix.IoctlGetInt(fd, 0x40084408)
	return uint64(token), err
}
