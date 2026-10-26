// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux

package client

import (
	"os"
	"strings"
)

// forwardingEnabled reports whether this host forwards, per family
// an exit egresses only a family its kernel forwards, while the mesh forwards transit itself
// it is read here alone, so the egress capability, status and cap.border's warning answer alike
func forwardingEnabled() (v4, v6 bool) {
	return sysctlIsOne("/proc/sys/net/ipv4/ip_forward"),
		sysctlIsOne("/proc/sys/net/ipv6/conf/all/forwarding")
}

func sysctlIsOne(path string) bool {
	// Unreadable is not "off": reporting a warning this node cannot
	// substantiate is worse than staying quiet.
	return readSysctl(path) != "0"
}

// Sysctl reads a setting by its path under /proc/sys, the empty string where it
// cannot, which the egress translator names a failed lookup's setting from and
// reads the host's connection table from
func Sysctl(path string) string { return readSysctl("/proc/sys/" + path) }

func readSysctl(path string) string {
	body, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(body))
}
