// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !linux && !darwin

package userspace

import "net/netip"

// errorQueue reads no ICMP errors where the kernel keeps no queue of a
// socket's, so a failed dial is answered with a reset
type errorQueue struct{}

func (*icmpSockets) queue() errorQueue { return errorQueue{} }

func (*errorQueue) open(int, netip.AddrPort) error { return nil }
func (*errorQueue) read(error) (icmpError, bool)   { return icmpError{}, false }
func (*errorQueue) close()                         {}

// watchErrors queues nothing where the kernel keeps no error queue
func watchErrors(int, bool) error { return nil }

// drainErrors finds no error where the kernel keeps no error queue
func drainErrors(int, []byte, func(icmpError, []byte)) {}
