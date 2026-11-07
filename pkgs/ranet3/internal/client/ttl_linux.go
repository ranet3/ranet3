// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux

package client

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// hostDefaultTTL is net.ipv4.ip_default_ttl, the TTL Linux sends its own IPv4 packets with
func hostDefaultTTL() (uint8, error) { return readDefaultTTL(sysctlRoot) }

// readDefaultTTL reads net.ipv4.ip_default_ttl under root, the tree Linux shows its settings in
func readDefaultTTL(root string) (uint8, error) {
	body, err := os.ReadFile(filepath.Join(root, "net/ipv4/ip_default_ttl"))
	var value uint64
	if err == nil {
		value, err = strconv.ParseUint(strings.TrimSpace(string(body)), 10, 64)
	}
	return ttlOf("net.ipv4.ip_default_ttl", value, err)
}

// hostDefaultHopLimit is net.ipv6.conf.all.hop_limit, the hop limit Linux sends its own IPv6 packets with, which an unconnected socket's IPV6_UNICAST_HOPS reads with no file under /proc to open
func hostDefaultHopLimit() (uint8, error) {
	const setting = "net.ipv6.conf.all.hop_limit"
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return ttlOf(setting, 0, err)
	}
	defer unix.Close(fd)
	value, err := unix.GetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS)
	return ttlOf(setting, uint64(value), err)
}
