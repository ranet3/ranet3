// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package client

import "golang.org/x/sys/unix"

// hostDefaultTTL is net.inet.ip.ttl, the TTL darwin and the BSDs send their own IPv4 packets with
func hostDefaultTTL() (uint8, error) {
	value, err := unix.SysctlUint32("net.inet.ip.ttl")
	return ttlOf("net.inet.ip.ttl", uint64(value), err)
}

// hostDefaultHopLimit is net.inet6.ip6.hlim, the hop limit darwin and the BSDs send their own IPv6 packets with
func hostDefaultHopLimit() (uint8, error) {
	value, err := unix.SysctlUint32("net.inet6.ip6.hlim")
	return ttlOf("net.inet6.ip6.hlim", uint64(value), err)
}
