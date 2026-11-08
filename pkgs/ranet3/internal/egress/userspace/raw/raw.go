// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

// Package raw sends a leaf's own ICMP errors about a userspace exit's mapping
// to the mapping's server (RFC 5508 REQ-5), through raw sockets that only a
// process allowed to open them has: the darwin daemon, and the exit's Linux
// tests as root in a network namespace of their own. The exit takes it as its
// platform's Raw, and nothing a phone builds imports it.
package raw
