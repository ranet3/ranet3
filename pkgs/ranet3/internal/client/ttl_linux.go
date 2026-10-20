// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux

package client

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
