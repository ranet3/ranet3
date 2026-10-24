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

// l3mdevAccept reports whether a socket outside a VRF is matched by traffic
// that arrived through one. It is off by default, and with a VRF holding the
// mesh addresses that decides whether anything on this node can use them: a
// reply arriving through the master is looked up only against sockets bound to
// that master, so every TCP and UDP flow to and from a mesh address fails
// while ICMP, which is matched differently, answers. Measured on a fleet node
// on 2026-09-21, where it read as a routing problem for an afternoon.
//
// Both halves have to be on to say yes, since a node with one of them is half
// broken in a way that is harder to find than a node with neither.
func l3mdevAccept() bool {
	return sysctlIsOne("/proc/sys/net/ipv4/tcp_l3mdev_accept") &&
		sysctlIsOne("/proc/sys/net/ipv4/udp_l3mdev_accept")
}

// Sysctl reads a setting by its path under /proc/sys, the empty string where it
// cannot, which the egress translator names a failed lookup's setting from
func Sysctl(path string) string { return readSysctl("/proc/sys/" + path) }

func readSysctl(path string) string {
	body, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(body))
}
