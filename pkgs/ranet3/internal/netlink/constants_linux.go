// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package netlink

const (
	// readSize is the first receive buffer of a Conn, in bytes, above the 32
	// KiB the kernel caps a dump datagram at, so a dump reads into it without
	// the buffer growing
	readSize = 64 << 10
	// dumpAttempts is how many times a dump a change keeps interrupting is asked before the read fails
	dumpAttempts = 3
	// nlaTypeMask is NLA_TYPE_MASK of linux/netlink.h, which x/sys does not carry
	nlaTypeMask = 0x3fff
)
