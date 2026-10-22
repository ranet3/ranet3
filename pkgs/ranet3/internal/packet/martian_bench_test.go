// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package packet

import (
	"net/netip"
	"testing"
)

// BenchmarkMartianChecks is the pair of checks every packet a session delivers takes, over each kind of address they tell apart
func BenchmarkMartianChecks(b *testing.B) {
	for _, c := range []struct{ name, address string }{
		{"IPv4 unicast", "192.0.2.1"},
		{"IPv4 network 0", "0.0.0.1"},
		{"IPv4 loopback", "127.0.0.1"},
		{"IPv4 class E", "240.0.0.1"},
		{"IPv4 link-local", "169.254.0.1"},
		{"IPv6 unicast", "3fff::1"},
		{"IPv6 loopback", "::1"},
		{"IPv6 link-local", "fe80::1"},
	} {
		address := netip.MustParseAddr(c.address)
		b.Run(c.name, func(b *testing.B) {
			for b.Loop() {
				InvalidSource(address)
				InvalidDestination(address)
			}
		})
	}
}
