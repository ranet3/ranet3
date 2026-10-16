// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package srv6

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/schema"
)

// allowLists draws one to four prefixes of either family and of any length,
// the zero length and the full one drawn outright
func allowLists() hegel.Generator[[]netip.Prefix] {
	prefix := hegel.Composite(func(tc hegel.TestCase) netip.Prefix {
		if hegel.Draw(tc, hegel.Booleans()) {
			return netip.PrefixFrom(hegel.Draw(tc, hegel.IPAddresses().IPv4()), hegel.Draw(tc, pbt.Spanning(0, 32)))
		}
		return netip.PrefixFrom(hegel.Draw(tc, hegel.IPAddresses().IPv6()), hegel.Draw(tc, pbt.Spanning(0, 128)))
	})
	return hegel.Composite(func(tc hegel.TestCase) []netip.Prefix {
		return hegel.Draw(tc, hegel.Lists(prefix).MinSize(1).MaxSize(4))
	})
}

// edges is the first and the last address of prefix and the address on the
// other side of each, where there is one
func edges(prefix netip.Prefix) []netip.Addr {
	first, last := prefix.Addr().AsSlice(), prefix.Addr().AsSlice()
	for bit := prefix.Bits(); bit < 8*len(first); bit++ {
		first[bit/8] &^= 0x80 >> (bit % 8)
		last[bit/8] |= 0x80 >> (bit % 8)
	}
	lo, _ := netip.AddrFromSlice(first)
	hi, _ := netip.AddrFromSlice(last)
	var out []netip.Addr
	for _, address := range []netip.Addr{lo.Prev(), lo, hi, hi.Next()} {
		if address.IsValid() {
			out = append(out, address)
		}
	}
	return out
}

// sources draws an address of one family, three times in four on either side
// of an edge of a listed prefix of that family where the list holds one
func sources(allow []netip.Prefix, v4 bool) hegel.Generator[netip.Addr] {
	return hegel.Composite(func(tc hegel.TestCase) netip.Addr {
		var near []netip.Addr
		for _, prefix := range allow {
			if prefix.Addr().Is4() == v4 {
				near = append(near, edges(prefix)...)
			}
		}
		if len(near) > 0 && hegel.Draw(tc, hegel.WeightedBooleans(3.0/4)) {
			return hegel.Draw(tc, hegel.SampledFrom(near))
		}
		if v4 {
			return hegel.Draw(tc, hegel.IPAddresses().IPv4())
		}
		return hegel.Draw(tc, hegel.IPAddresses().IPv6())
	})
}

// listed is the model of the allow list, by comparing the leading bits of the
// address with the prefix's one at a time
func listed(allow []netip.Prefix, address netip.Addr) bool {
	for _, prefix := range allow {
		if prefix.Addr().BitLen() != address.BitLen() {
			continue
		}
		want, got := prefix.Addr().AsSlice(), address.AsSlice()
		same := true
		for bit := range prefix.Bits() {
			mask := byte(0x80) >> (bit % 8)
			same = same && want[bit/8]&mask == got[bit/8]&mask
		}
		if same {
			return true
		}
	}
	return false
}

// An egress segment at the end of a segment list of any length hands the
// egress device exactly the packets whose outer and inner sources the allow
// list holds, the inner one as its own version spells it, and refuses every
// other with ErrSourceRefused. The sources are drawn on both sides of every
// edge of the list's prefixes, in both families, the outer one now and then as
// a v4-mapped address no v4 prefix may admit, and now and then the routing
// header announces the family the inner packet is not.
func TestEgressNeverCarriesASourceOutsideItsAllowList(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		allow := hegel.Draw(ht, allowLists())
		path := hegel.Draw(ht, usablePaths())
		exit := path[len(path)-1]
		written := make([]schema.Prefix, len(allow))
		for i, prefix := range allow {
			written[i] = schema.PrefixFrom(prefix)
		}
		table, err := NewLocalTable([]Segment{EgressSegment(schema.AddrFrom(exit), written)})
		if err != nil {
			ht.Fatalf("an egress segment allowing %v was refused: %v", allow, err)
		}

		inner := hegel.Draw(ht, innerPackets())
		v4 := inner[0]>>4 == 4
		from := hegel.Draw(ht, sources(allow, v4))
		family, other, offset := uint8(NextHeaderIPv6), uint8(NextHeaderIPv4), 8
		if v4 {
			family, other, offset = NextHeaderIPv4, NextHeaderIPv6, 12
		}
		copy(inner[offset:], from.AsSlice())
		outer := hegel.Draw(ht, mostly(sources(allow, false), hegel.Composite(func(tc hegel.TestCase) netip.Addr {
			return netip.AddrFrom16(hegel.Draw(tc, sources(allow, true)).As16())
		})))

		raw, err := Encapsulate(inner, exit, path)
		if err != nil {
			ht.Fatalf("Encapsulate refused %d bytes over %v: %v", len(inner), path, err)
		}
		source := outer.As16()
		copy(raw[8:24], source[:])
		raw[7] = 255
		mislabeled := hegel.Draw(ht, hegel.WeightedBooleans(1.0/8))
		if mislabeled {
			raw[ipv6HeaderLen] = other
		}
		for step := range path[1:] {
			if _, err := End(raw); err != nil {
				ht.Fatalf("waypoint %d refused the packet: %v", step, err)
			}
		}

		result := table.Handle(raw)
		carried := listed(allow, outer) && listed(allow, from) && !mislabeled
		switch {
		case carried && (result.Action != ActionEgress || result.Family != family || !bytes.Equal(result.Inner, inner)):
			ht.Fatalf("from %s and %s inside %v, Handle returned %v of family %d (%v), want the inner packet of family %d for the egress device",
				outer, from, allow, result.Action, result.Family, result.Err, family)
		case !carried && (result.Action != ActionDrop || !errors.Is(result.Err, ErrSourceRefused)):
			ht.Fatalf("from %s and %s against %v, announced as %d, Handle returned %v (%v), want a refusal of the source",
				outer, from, allow, raw[ipv6HeaderLen], result.Action, result.Err)
		}
	})
}
