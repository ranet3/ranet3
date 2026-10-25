// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package packet

import "net/netip"

// InvalidSource reports whether a router forwards no packet from address
// IPv4 network 0, network 127, multicast and class E with the limited broadcast, RFC 1812 section 5.3.7, and link-local, RFC 3927 section 7
// IPv6 unspecified, loopback and multicast, RFC 4291 sections 2.5.2, 2.5.3 and 2.7, and link-local, section 2.5.6
func InvalidSource(address netip.Addr) bool {
	if address.Is4() {
		return !SingleHost(address) || address.IsLinkLocalUnicast()
	}
	return address.IsUnspecified() || address.IsLoopback() || address.IsMulticast() || address.IsLinkLocalUnicast()
}

// InvalidDestination reports whether address is a destination other than the limited broadcast and multicast that no router forwards
// IPv4 network 0, network 127 and class E but the limited broadcast, RFC 1812 section 5.3.7, and link-local, RFC 3927 section 7
// IPv6 unspecified and loopback, RFC 4291 sections 2.5.2 and 2.5.3, and link-local, section 2.5.6
func InvalidDestination(address netip.Addr) bool {
	if address.Is4() {
		return special(address) && address != LimitedBroadcast || address.IsLinkLocalUnicast()
	}
	return address.IsUnspecified() || address.IsLoopback() || address.IsLinkLocalUnicast()
}
