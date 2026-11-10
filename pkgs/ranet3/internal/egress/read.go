// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package egress

import (
	"net/netip"

	"ranet3.com/pkgs/ranet3/schema"
)

// ReadAddress is the address both exits' readiness reads prefix's route at,
// the first of its candidates the mesh forwards a unicast packet to, one
// schema.Unroutable names no class for, and false for a prefix holding none.
// Validate refuses an advertised prefix holding none.
func ReadAddress(prefix netip.Prefix) (netip.Addr, bool) {
	for _, address := range readCandidates(prefix) {
		if reason, _ := schema.Unroutable(netip.PrefixFrom(address, address.BitLen())); reason == "" {
			return address, true
		}
	}
	return netip.Addr{}, false
}

// readCandidates is a host route's own address, and for a wider prefix its
// middle address, the base with the bit after the prefix length set, then its
// base plus one, then its last address less one. The middle alone falls short,
// since 192.0.0.0/2's is the group 224.0.0.0 and 126.0.0.0/7's is 127.0.0.0.
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
