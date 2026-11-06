// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux

package client

import (
	"os"
	"path/filepath"
	"strings"
)

// forwardingEnabled reports whether this host forwards, per family, nil for a family whose setting it cannot read
// an exit egresses only a family its kernel forwards, while the mesh forwards transit itself
// the egress capability, status and the antispoof warning read it here alone, each taking an unread family its own way,
// as Forwarding and forwardedFamilies give
func forwardingEnabled() (v4, v6 *bool) {
	return sysctlIsOne("/proc/sys/net/ipv4/ip_forward"),
		sysctlIsOne("/proc/sys/net/ipv6/conf/all/forwarding")
}

// forwardedFollowsTheMode is false, since a link cap.exit forward leaves out
// keeps the routes it had
const forwardedFollowsTheMode = false

func sysctlIsOne(path string) *bool {
	value := readSysctl(path)
	if value == "" {
		return nil
	}
	return new(value != "0")
}

// Sysctl reads a setting by its path under /proc/sys, the empty string where it
// cannot or where path leaves /proc/sys
func Sysctl(path string) string {
	if !filepath.IsLocal(path) {
		return ""
	}
	return readSysctl(filepath.Join(sysctlRoot, path))
}

func readSysctl(path string) string {
	body, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(body))
}
