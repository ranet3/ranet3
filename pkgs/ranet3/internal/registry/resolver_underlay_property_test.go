// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build (linux && !android) || (darwin && !ios)

package registry

import (
	"net/netip"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/schema"
)

// zones holds the zones resolv.conf may write after an IPv6 address: an
// interface's name on Linux or macOS, or its index
var zones = []string{"eth0", "en0", "1"}

// drawAddr draws an address of one family byte by byte, each byte's ends drawn
// outright
func drawAddr(tc hegel.TestCase, is4 bool) netip.Addr {
	raw := make([]byte, 16)
	if is4 {
		raw = raw[:4]
	}
	for i := range raw {
		raw[i] = hegel.Draw(tc, pbt.Spanning[byte](0, 255))
	}
	address, _ := netip.AddrFromSlice(raw)
	return address
}

// drawOverlay draws one to four masked prefixes of either family and any
// length, each after the first fresh, at the first address of an earlier one or
// just past the last address of an earlier one, so prefixes of the overlay nest
// in, contain and abut each other
func drawOverlay(tc hegel.TestCase) []schema.Prefix {
	var drawn []netip.Prefix
	for range hegel.Draw(tc, pbt.Spanning(1, 4)) {
		address := drawAddr(tc, hegel.Draw(tc, pbt.Spanning(0, 1)) == 0)
		if len(drawn) > 0 {
			earlier := drawn[hegel.Draw(tc, pbt.Spanning(0, len(drawn)-1))]
			switch hegel.Draw(tc, pbt.Spanning(0, 2)) {
			case 1:
				address = earlier.Addr()
			case 2:
				if past := lastOf(earlier).Next(); past.IsValid() {
					address = past
				}
			}
		}
		drawn = append(drawn, netip.PrefixFrom(address, hegel.Draw(tc, pbt.Spanning(0, address.BitLen()))).Masked())
	}
	overlay := make([]schema.Prefix, len(drawn))
	for i, prefix := range drawn {
		overlay[i] = schema.PrefixFrom(prefix)
	}
	return overlay
}

// lastOf is a masked prefix's last address, every bit past its length set
func lastOf(prefix netip.Prefix) netip.Addr {
	raw := prefix.Addr().AsSlice()
	for bit := prefix.Bits(); bit < len(raw)*8; bit++ {
		raw[bit/8] |= 0x80 >> (bit % 8)
	}
	last, _ := netip.AddrFromSlice(raw)
	return last
}

// boundsOf is each address at, just inside and just outside a masked prefix's
// first and last address, but for one past either end of the family
func boundsOf(prefix netip.Prefix) []netip.Addr {
	first, last := prefix.Addr(), lastOf(prefix)
	out := []netip.Addr{first, last}
	for _, near := range []netip.Addr{first.Prev(), first.Next(), last.Prev(), last.Next()} {
		if near.IsValid() {
			out = append(out, near)
		}
	}
	return out
}

// formsOf is an address as resolv.conf may write it: an IPv4 address plain,
// IPv4-mapped and mapped with zone, an IPv6 one plain and with zone
func formsOf(address netip.Addr, zone string) []netip.Addr {
	if address.Is4() {
		mapped := netip.AddrFrom16(address.As16())
		return []netip.Addr{address, mapped, mapped.WithZone(zone)}
	}
	return []netip.Addr{address, address.WithZone(zone)}
}

// modelPrepared is whether a query to nameserver is prepared: unless some
// prefix of the overlay of the same width shares its leading bits for as many
// bits as the prefix is long. An IPv4-mapped nameserver is read as the 32 bits
// it maps, as Go dials it on an IPv4 socket, and a zone is no part of the bits.
func modelPrepared(nameserver netip.Addr, overlay []schema.Prefix) bool {
	raw := nameserver.As16()
	bits := raw[:]
	if [12]byte(raw[:12]) == [12]byte{10: 0xff, 11: 0xff} {
		bits = raw[12:]
	}
	for _, entry := range overlay {
		prefix := entry.Addr().AsSlice()
		if len(prefix) == len(bits) && sharesLeadingBits(prefix, bits, entry.Bits()) {
			return false
		}
	}
	return true
}

// sharesLeadingBits is whether a and b agree in their first n bits
func sharesLeadingBits(a, b []byte, n int) bool {
	for bit := range n {
		if (a[bit/8]^b[bit/8])&(0x80>>(bit%8)) != 0 {
			return false
		}
	}
	return true
}

// A query to a nameserver is prepared exactly where no prefix of the overlay
// of its width shares its leading bits for the prefix's length, over overlays
// of one family or both whose prefixes nest, contain and abut, for a
// nameserver at, just inside and just outside each prefix's first and last
// address, written plain, IPv4-mapped and with a zone.
func TestResolverPreparesAQueryWhereNoPrefixSharesItsLeadingBits(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		overlay := drawOverlay(ht)
		zone := zones[hegel.Draw(ht, pbt.Spanning(0, len(zones)-1))]
		for _, entry := range overlay {
			for _, bound := range boundsOf(entry.Prefix) {
				for _, nameserver := range formsOf(bound, zone) {
					if got, want := preparesQueryTo(nameserver, overlay), modelPrepared(nameserver, overlay); got != want {
						ht.Fatalf("a query to %s under the overlay %v is prepared %v, the model says %v", nameserver, overlay, got, want)
					}
				}
			}
		}
	})
}
