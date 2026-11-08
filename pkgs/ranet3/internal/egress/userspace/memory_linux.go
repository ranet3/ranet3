// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package userspace

import (
	"runtime/debug"

	"golang.org/x/sys/unix"
)

// HostMemory reads what bounds this process's memory: Go's limit, as
// debug.SetMemoryLimit(-1) reports it, and the host's physical memory, as
// sysinfo totals it. Only a daemon's selection file calls it, since a phone's
// bound is its Go limit alone.
func HostMemory() (Memory, error) {
	var info unix.Sysinfo_t
	if err := unix.Sysinfo(&info); err != nil {
		return Memory{}, err
	}
	return Memory{GoLimit: debug.SetMemoryLimit(-1), Physical: uint64(info.Totalram) * uint64(info.Unit)}, nil
}

// Files is the most descriptors this process may open, its RLIMIT_NOFILE's
// soft limit, 0 where it reads none, which leaves the flows no more than the
// connections
func Files() uint64 {
	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
		return 0
	}
	return limit.Cur
}
