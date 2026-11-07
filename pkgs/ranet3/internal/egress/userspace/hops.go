// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package userspace

// SetHopLimits sets the TTL and the hop limit of the IPv4 and IPv6 packets the
// exit builds to the host's own defaults, which configure them as RFC 1812
// section 4.2.2.9 has a router's fixed TTL be: "When a fixed TTL value is
// used, it MUST be configurable."
func (x *Exit) SetHopLimits(ttl, hopLimit uint8) {
	x.ttl.Store(uint32(ttl))
	x.hopLimit.Store(uint32(hopLimit))
}

// HopLimits is the TTL and the hop limit the exit's packets carry now
func (x *Exit) HopLimits() (ttl, hopLimit uint8) {
	return x.hops(false), x.hops(true)
}

// hops is the TTL, or where ipv6 the hop limit, of a packet the exit builds
func (x *Exit) hops(ipv6 bool) uint8 {
	if ipv6 {
		return uint8(x.hopLimit.Load())
	}
	return uint8(x.ttl.Load())
}
