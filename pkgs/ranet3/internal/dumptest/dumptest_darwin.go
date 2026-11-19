// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

// Package dumptest reads the routing table or the interface list again where
// it grew during the read, as the daemon's own reads do. Test files import it
// and nothing else does.
package dumptest

import (
	"errors"

	"golang.org/x/sys/unix"
)

// Attempts is internal/kernel's dumpAttempts, the fetches one read makes in all
const Attempts = 4

// Refetched is fetch's answer, fetched again on ENOMEM or ENOBUFS up to Attempts times in all, as internal/kernel's refetched
func Refetched[T any](fetch func() (T, error)) (T, error) {
	var (
		answer T
		err    error
	)
	for range Attempts {
		if answer, err = fetch(); !errors.Is(err, unix.ENOMEM) && !errors.Is(err, unix.ENOBUFS) {
			break
		}
	}
	return answer, err
}
