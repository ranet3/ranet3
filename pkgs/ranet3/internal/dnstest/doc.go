// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

// Package dnstest stands up a nameserver on lo for a test that resolves a name
// through Go's resolver as the daemon does, reading /etc/resolv.conf, and
// records the mark each query arrives with. It binds a resolv.conf of its own
// over /etc/resolv.conf, so it runs on Linux alone, as root in a network and a
// mount namespace of the test process's own, which unshare -rmn makes. Test
// files import it and nothing else does.
package dnstest
