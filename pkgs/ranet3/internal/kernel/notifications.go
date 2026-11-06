// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build (linux && !android) || (darwin && !ios)

package kernel

import (
	"errors"
	"io"
	"log/slog"
	"os"

	"golang.org/x/sys/unix"
)

// readNotifications hands each datagram of source to got until source reports os.ErrClosed, or until stop closes while it waits out a backoff
// an error a listener reads reports notifications it lost and is cleared by that read, so each wakes and the reading goes on
// a failure other than ENOBUFS right after another first waits out a backoff, since the read that returns a kernel's error clears it and one that repeats comes from elsewhere
func readNotifications(name string, source io.Reader, buf []byte, stop <-chan struct{}, wake func(), got func([]byte)) {
	retry := NewRetryTimer()
	defer retry.Stop()
	failures := 0
	for {
		n, err := source.Read(buf)
		switch {
		case err == nil:
			if failures > 0 {
				slog.Info("kernel read notifications again", "socket", name, "failures", failures)
				failures = 0
				retry.Passed()
			}
			got(buf[:n])
		case errors.Is(err, os.ErrClosed):
			return
		case errors.Is(err, unix.ENOBUFS):
			wake()
			slog.Debug("kernel notifications dropped, resyncing", "socket", name)
		default:
			wake()
			failures++
			if failures == 1 {
				slog.Warn("kernel could not read notifications, reading on", "socket", name, "err", err)
				continue
			}
			retry.Failed(DefaultReconcileInterval)
			select {
			case <-stop:
				return
			case <-retry.C:
			}
		}
	}
}
