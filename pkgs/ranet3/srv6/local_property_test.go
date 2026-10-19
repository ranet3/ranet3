// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package srv6

import (
	"bytes"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/schema"
)

// allowLists draws an allow list the loader takes: one IPv6 prefix and up to
// three more of either family, each of any length from its family's floor to
// the full one, the two ends drawn outright, and none written twice
func allowLists() hegel.Generator[[]netip.Prefix] {
	v6 := hegel.Filter(hegel.Composite(func(tc hegel.TestCase) netip.Prefix {
		return netip.PrefixFrom(hegel.Draw(tc, hegel.IPAddresses().IPv6()), hegel.Draw(tc, pbt.Spanning(minAllowBits6, 128))).Masked()
	}), func(prefix netip.Prefix) bool { return !prefix.Addr().Is4In6() })
	prefix := hegel.Composite(func(tc hegel.TestCase) netip.Prefix {
		if hegel.Draw(tc, hegel.Booleans()) {
			return netip.PrefixFrom(hegel.Draw(tc, hegel.IPAddresses().IPv4()), hegel.Draw(tc, pbt.Spanning(minAllowBits4, 32))).Masked()
		}
		return hegel.Draw(tc, v6)
	})
	return hegel.Composite(func(tc hegel.TestCase) []netip.Prefix {
		drawn := append([]netip.Prefix{hegel.Draw(tc, v6)}, hegel.Draw(tc, hegel.Lists(prefix).MaxSize(3))...)
		var allow []netip.Prefix
		for _, prefix := range drawn {
			if !slices.Contains(allow, prefix) {
				allow = append(allow, prefix)
			}
		}
		return allow
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
		table, err := NewLocalTable([]Segment{{SID: schema.AddrFrom(exit), Behavior: BehaviorEndDT46, Deliver: DeliverEgress, Allow: written}})
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

// allowEntries draws an allow entry a file could write, IPv6 or IPv4 as asked,
// at its family's floor, at full length or anywhere between, with nothing
// below its length
func allowEntries(ipv6 bool) hegel.Generator[schema.Prefix] {
	return hegel.Composite(func(tc hegel.TestCase) schema.Prefix {
		address, floor := hegel.Draw(tc, hegel.IPAddresses().IPv6()), minAllowBits6
		if !ipv6 {
			address, floor = hegel.Draw(tc, hegel.IPAddresses().IPv4()), minAllowBits4
		}
		width := address.BitLen()
		bits := hegel.Draw(tc, hegel.OneOf(hegel.Just(floor), hegel.Just(width), pbt.Spanning(floor, width)))
		return schema.PrefixFrom(netip.PrefixFrom(address, bits).Masked())
	})
}

// allowSlips draws a slip in place of entry, one of a copy of an entry beside
// it, no prefix at all, a length of 0, a length under its family's floor, IPv4
// written as IPv6 or a bit set below its length
// one slip in a list otherwise taken turns the outcome on that check alone
func allowSlips(entry schema.Prefix, beside []schema.Prefix) hegel.Generator[schema.Prefix] {
	return hegel.Composite(func(tc hegel.TestCase) schema.Prefix {
		address, width := entry.Addr(), entry.Addr().BitLen()
		floor := minAllowBits6
		if address.Is4() {
			floor = minAllowBits4
		}
		switch hegel.Draw(tc, pbt.Spanning(0, 5)) {
		case 0:
			if len(beside) > 0 {
				return hegel.Draw(tc, hegel.SampledFrom(beside))
			}
			return schema.Prefix{}
		case 1:
			return schema.Prefix{}
		case 2:
			return schema.PrefixFrom(netip.PrefixFrom(address, 0).Masked())
		case 3:
			bits := hegel.Draw(tc, hegel.OneOf(hegel.Just(floor-1), pbt.Spanning(1, floor-1)))
			return schema.PrefixFrom(netip.PrefixFrom(address, bits).Masked())
		case 4:
			mapped := netip.AddrFrom16(hegel.Draw(tc, hegel.IPAddresses().IPv4()).As16())
			return schema.PrefixFrom(netip.PrefixFrom(mapped, 96+hegel.Draw(tc, pbt.Spanning(minAllowBits4, 32))).Masked())
		default:
			bits := entry.Bits()
			if bits == width {
				bits = hegel.Draw(tc, pbt.Spanning(floor, width-1))
			}
			raw := address.AsSlice()
			bit := hegel.Draw(tc, pbt.Spanning(bits, width-1))
			raw[bit/8] |= 0x80 >> (bit % 8)
			set, _ := netip.AddrFromSlice(raw)
			return schema.PrefixFrom(netip.PrefixFrom(set, bits))
		}
	})
}

// takes is the model of what the loader accepts for one segment: an allow list
// only with the egress delivery and egress only on End.DT46, and every entry a
// prefix with nothing below its length, not an IPv4 address in IPv6 clothing,
// no shorter than its family's registry unit, written once, with one of them
// IPv6
func takes(segment Segment) bool {
	switch {
	case segment.Deliver == DeliverMesh:
		return len(segment.Allow) == 0
	case segment.Behavior != BehaviorEndDT46 || len(segment.Allow) == 0:
		return false
	}
	written := map[string]bool{}
	ipv6 := false
	for _, entry := range segment.Allow {
		if !entry.IsValid() {
			return false
		}
		raw := entry.Addr().AsSlice()
		for bit := entry.Bits(); bit < 8*len(raw); bit++ {
			if raw[bit/8]&(0x80>>(bit%8)) != 0 {
				return false
			}
		}
		mapped := len(raw) == 16 && bytes.Equal(raw[:12], []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff})
		floor := 12
		if len(raw) == 4 {
			floor = 8
		}
		if mapped || entry.Bits() < floor || written[entry.String()] {
			return false
		}
		written[entry.String()] = true
		ipv6 = ipv6 || len(raw) == 16
	}
	return ipv6
}

// A segment loads exactly when the model takes it, whatever its behavior,
// delivery and allow list, and a refusal names the segment
func TestEgressSegmentLoadsExactlyWhenItsAllowListHolds(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		segment := Segment{SID: saddr("2001:db8::3"), Behavior: BehaviorEndDT46, Deliver: DeliverEgress}
		if hegel.Draw(ht, hegel.WeightedBooleans(1.0/4)) {
			segment.Behavior = hegel.Draw(ht, hegel.SampledFrom([]Behavior{BehaviorEnd, BehaviorEndDT46}))
			segment.Deliver = hegel.Draw(ht, hegel.SampledFrom([]Delivery{DeliverMesh, DeliverEgress}))
		}
		// the first entry is mostly IPv6, so a slip in a later one is often the only reason to refuse the list
		for i := range hegel.Draw(ht, pbt.Spanning(0, 4)) {
			weight := 1.0 / 2
			if i == 0 {
				weight = 3.0 / 4
			}
			segment.Allow = append(segment.Allow, hegel.Draw(ht, allowEntries(hegel.Draw(ht, hegel.WeightedBooleans(weight)))))
		}
		// a slip spares the first entry of a longer list, which keeps it holding IPv6
		if len(segment.Allow) > 0 && hegel.Draw(ht, hegel.Booleans()) {
			i := 0
			if len(segment.Allow) > 1 {
				i = hegel.Draw(ht, pbt.Spanning(1, len(segment.Allow)-1))
			}
			beside := slices.Delete(slices.Clone(segment.Allow), i, i+1)
			segment.Allow[i] = hegel.Draw(ht, allowSlips(segment.Allow[i], beside))
		}
		_, err := NewLocalTable([]Segment{segment})
		switch want := takes(segment); {
		case want && err != nil:
			ht.Fatalf("%s was refused: %v", segment, err)
		case !want && err == nil:
			ht.Fatalf("%s was accepted", segment)
		case err != nil && !strings.Contains(err.Error(), "cap.segment local 2001:db8::3"):
			ht.Fatalf("the refusal %q does not name the segment", err)
		}
	})
}

// Two configurations whose egress segments list one set of prefixes in two
// orders, or a mesh segment with an empty list and one with none, normalize
// equal, so a reload sees no change. A set with one entry more or less does
// not.
func TestAllowListsCompareAsSets(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		allow := hegel.Draw(ht, allowLists())
		written := make([]schema.Prefix, len(allow))
		for i, prefix := range allow {
			written[i] = schema.PrefixFrom(prefix)
		}
		shuffled := slices.Clone(written)
		for i := len(shuffled) - 1; i > 0; i-- {
			j := hegel.Draw(ht, pbt.Spanning(0, i))
			shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
		}
		var empty []schema.Prefix
		if hegel.Draw(ht, hegel.Booleans()) {
			empty = []schema.Prefix{}
		}
		of := func(allow []schema.Prefix, meshAllow []schema.Prefix) Segments {
			return Segments{Local: []Segment{
				{SID: saddr("2001:db8::3"), Behavior: BehaviorEndDT46, Deliver: DeliverEgress, Allow: allow},
				{SID: saddr("2001:db8::4"), Behavior: BehaviorEndDT46, Allow: meshAllow},
			}}.Normalized()
		}
		if a, b := of(written, nil), of(shuffled, empty); !reflect.DeepEqual(a, b) {
			ht.Fatalf("%v and %v normalized apart:\n%v\n%v", written, shuffled, a, b)
		}
		var other []schema.Prefix
		if len(written) > 1 && hegel.Draw(ht, hegel.Booleans()) {
			other = shuffled[1:]
		} else {
			extra := netip.PrefixFrom(hegel.Draw(ht, hegel.IPAddresses().IPv6()), 128)
			if slices.Contains(allow, extra) {
				return
			}
			other = append(slices.Clone(shuffled), schema.PrefixFrom(extra))
		}
		if a, b := of(written, nil), of(other, nil); reflect.DeepEqual(a, b) {
			ht.Fatalf("%v and %v normalized equal", written, other)
		}
	})
}
