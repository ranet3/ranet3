// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package underlay

import (
	"errors"
	"log/slog"
	"net/netip"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/schema"
)

// mark is probed once. SO_MARK needs CAP_NET_ADMIN or CAP_NET_RAW in the
// socket's network namespace, and a policy rule needs CAP_NET_ADMIN there, so a
// process that cannot mark its sockets writes no rule that reads the mark.
var mark = sync.OnceValue(func() uint32 {
	var fd int
	var err error
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		if fd, err = unix.Socket(family, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0); err == nil {
			break
		}
	}
	if err != nil {
		// the caller's own open reports what keeps a socket from opening
		return schema.UnderlayMark
	}
	defer unix.Close(fd)
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, int(schema.UnderlayMark)); errors.Is(err, unix.EPERM) {
		slog.Info("underlay sockets stay unmarked", "err", err,
			"detail", "this process holds neither CAP_NET_ADMIN nor CAP_NET_RAW, and without CAP_NET_ADMIN it writes no policy rule that reads the mark")
		return 0
	}
	return schema.UnderlayMark
})

// Mark is the mark every underlay socket of this process carries,
// schema.UnderlayMark, or 0 where the process may not set one
func Mark() uint32 { return mark() }

// Marked sets Mark on each socket, and leaves it unmarked where Mark is 0
func Marked() Prepare {
	m := Mark()
	if m == 0 {
		return Unchanged
	}
	return func(_ string, _ netip.AddrPort, raw syscall.RawConn) error {
		var setErr error
		if err := raw.Control(func(fd uintptr) { setErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(m)) }); err != nil {
			return err
		}
		return setErr
	}
}
