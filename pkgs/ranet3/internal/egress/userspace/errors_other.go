// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !linux

package userspace

// errorQueue reads no ICMP errors where the kernel keeps no queue of a
// socket's, so a failed dial is answered with a reset
type errorQueue struct{}

func (*errorQueue) open(int, bool) error    { return nil }
func (*errorQueue) read() (icmpError, bool) { return icmpError{}, false }
func (*errorQueue) close()                  {}
