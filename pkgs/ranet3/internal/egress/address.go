// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package egress

import "net/netip"

// readAddress is the address a readiness lookup reads for prefix, the first of
// its candidates the kernel's input path takes as a unicast destination, and
// false for a prefix holding none
func readAddress(prefix netip.Prefix) (netip.Addr, bool) {
	for _, address := range readCandidates(prefix) {
		if unicastDestination(address) {
			return address, true
		}
	}
	return netip.Addr{}, false
}

// readCandidates is a host route's own address, and for a wider prefix its
// middle address, the base with the bit after the prefix length set, then its
// base plus one, then its last address less one. The middle alone falls short,
// since 192.0.0.0/2's is the group 224.0.0.0 and 126.0.0.0/7's is 127.0.0.0
func readCandidates(prefix netip.Prefix) []netip.Addr {
	prefix = prefix.Masked()
	base := prefix.Addr()
	if prefix.IsSingleIP() {
		return []netip.Addr{base}
	}
	middle, last := base.AsSlice(), base.AsSlice()
	middle[prefix.Bits()/8] |= 0x80 >> (prefix.Bits() % 8)
	for bit := prefix.Bits(); bit < base.BitLen(); bit++ {
		last[bit/8] |= 0x80 >> (bit % 8)
	}
	mid, _ := netip.AddrFromSlice(middle)
	end, _ := netip.AddrFromSlice(last)
	return []netip.Addr{mid, base.Next(), end.Prev()}
}

// unicastDestination is whether the kernel's input path takes address as a
// unicast destination, by its checks at Linux 940de590. IPv4 refuses the
// limited broadcast, taken as broadcast input (net/ipv4/route.c:2331), the
// zero address alone, which is all ipv4_is_zeronet matches (:2342), loopback
// without route_localnet (:2350) and every group, which the multicast branch
// takes (:2538). IPv6 refuses loopback (net/ipv6/ip6_input.c:255), multicast and
// link-local, whose lookup rt6_need_strict scopes to the arrival device
// (net/ipv6/route.c:2360), and the unspecified address, which RFC 4291 section
// 2.5.2 makes no destination.
//
// ipv4_is_zeronet matches 0.0.0.0 alone from 96125bf9985a, in Linux 5.3. Linux
// 4.20 to 5.2 refuse all of 0.0.0.0/8, so there a read inside it fails and
// holds its family not ready with that read's reason
func unicastDestination(address netip.Addr) bool {
	if address.Is4() {
		a := address.As4()
		return a != [4]byte{255, 255, 255, 255} && a != [4]byte{} && a[0] != 127 && a[0]&0xf0 != 0xe0
	}
	a := address.As16()
	return a != [16]byte{} && a != [16]byte{15: 1} && a[0] != 0xff && (a[0] != 0xfe || a[1]&0xc0 != 0x80)
}
