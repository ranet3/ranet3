// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

// the values the netlink backend chooses, apart from constants.go because no other platform reads them

const (
	// netlinkReadSize is the first receive buffer of the request socket, in bytes
	// the kernel caps a dump datagram at 32 KiB
	// a dump then reads into it without the buffer growing
	netlinkReadSize = 64 << 10
	// monitorReceiveBuffer is the route monitor's SO_RCVBUF, in bytes
	// a route flood that overflows it costs an ENOBUFS, survivable but a full resync
	monitorReceiveBuffer = 1 << 20
	// monitorReadSize is one read of the route monitor, in bytes
	// it is larger than any notification datagram the kernel sends
	monitorReadSize = 64 << 10
)
