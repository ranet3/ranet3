// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package netstack

import (
	"encoding/binary"
	"math"
	"net/netip"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/packet"
	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/schema"
)

// unroutableAnchors are the ranges whose edges the agreement property sweeps,
// the special-purpose blocks of RFC 6890's registries that the data path tells
// apart, wider and narrower ones beside them
var unroutableAnchors = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("255.255.255.255/32"),
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("::/128"), netip.MustParsePrefix("::1/128"), netip.MustParsePrefix("::ffff:0:0/96"),
	netip.MustParsePrefix("64:ff9b::/96"), netip.MustParsePrefix("100::/64"), netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("fc00::/7"), netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("fec0::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

// The loader's classes are the data path's: schema.Unroutable names a class
// for an address's host prefix exactly where the forwarding decision drops a
// packet from it as a martian source, or to it as a martian destination or a
// group, or hands it to the tun as IPv6 link-local. Every edge of each
// special-purpose block and the address on either side of it are swept
// first, then any address of either family is drawn.
func TestUnroutableIsWhereTheDataPathForwardsNoUnicast(t *testing.T) {
	agree := func(t interface{ Fatalf(string, ...any) }, address netip.Addr) {
		reason, _ := schema.Unroutable(netip.PrefixFrom(address, address.BitLen()))
		dropped := packet.InvalidSource(address) || martianDestination(address) || linkScoped(address)
		if (reason != "") != dropped {
			t.Fatalf("%s: schema names %q, and the data path forwards no unicast %v", address, reason, dropped)
		}
	}
	for _, anchor := range unroutableAnchors {
		swept := edges(anchor)
		for _, address := range append(swept, swept[0].Prev(), swept[1].Next()) {
			if address.IsValid() {
				agree(t, address.WithZone(""))
			}
		}
	}
	pbt.Check(t, func(ht *hegel.T) {
		high, low := hegel.Draw(ht, hegel.Integers[uint64](0, math.MaxUint64)), hegel.Draw(ht, hegel.Integers[uint64](0, math.MaxUint64))
		var raw [16]byte
		binary.BigEndian.PutUint64(raw[:8], high)
		binary.BigEndian.PutUint64(raw[8:], low)
		address := netip.AddrFrom16(raw)
		if hegel.Draw(ht, hegel.Integers[uint64](0, 1)) == 1 {
			address = netip.AddrFrom4([4]byte(raw[12:]))
		}
		agree(ht, address)
	})
}
