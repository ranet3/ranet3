// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package nftables

import (
	"bytes"
	"net/netip"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// edgeBytes are the byte values an address is drawn from, so drawn prefixes
// overlap, nest and touch, and reach the first and the last address
var edgeBytes = []byte{0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff}

// Prefixes of one family, overlapping, nested and touching among them, half
// the cases that draw one holding a drawn prefix beside its sibling, the
// prefix of its length that touches it, are written as intervals that hold
// exactly the addresses one of the prefixes holds, at each prefix's first and
// last address and one past each, in order with no two sharing or touching an
// address. Fill's elements, handed back in any order as a dump hands them,
// read back as those intervals.
func TestPrefixesFillAndReadBackAsTheirUnion(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		size, keyType := 4, uint32(TypeIPv4Addr)
		if hegel.Draw(ht, hegel.Booleans()) {
			size, keyType = 16, TypeIPv6Addr
		}
		var prefixes []netip.Prefix
		for range hegel.Draw(ht, hegel.Integers(0, 8)) {
			raw := make([]byte, size)
			for i := range raw {
				raw[i] = hegel.Draw(ht, hegel.SampledFrom(edgeBytes))
			}
			prefix, err := addressOf(raw).Prefix(hegel.Draw(ht, pbt.Spanning(0, size*8)))
			if err != nil {
				ht.Fatal(err)
			}
			prefixes = append(prefixes, prefix)
		}
		if len(prefixes) > 0 && hegel.Draw(ht, pbt.Spanning(0, 1)) == 1 {
			prefix := prefixes[hegel.Draw(ht, pbt.Spanning(0, len(prefixes)-1))]
			if bits := prefix.Bits(); bits > 0 {
				raw := AddressBytes(prefix.Masked().Addr())
				raw[(bits-1)/8] ^= 0x80 >> ((bits - 1) % 8)
				prefixes = append(prefixes, netip.PrefixFrom(addressOf(raw), bits))
			}
		}
		intervals := Prefixes(prefixes)

		held := func(address netip.Addr) bool {
			return slices.ContainsFunc(prefixes, func(p netip.Prefix) bool { return p.Contains(address) })
		}
		within := func(raw []byte) bool {
			return slices.ContainsFunc(intervals, func(i Interval) bool {
				return bytes.Compare(i.First, raw) <= 0 && bytes.Compare(raw, i.Last) <= 0
			})
		}
		for _, prefix := range prefixes {
			first := prefix.Masked().Addr()
			last := AddressBytes(first)
			for i, mask := range prefixMask(prefix) {
				last[i] |= ^mask
			}
			probes := []netip.Addr{first, first.Prev(), addressOf(last), addressOf(last).Next()}
			for _, address := range probes {
				if address.IsValid() && held(address) != within(AddressBytes(address)) {
					ht.Fatalf("%v written as %s: %s held %v, want %v", prefixes, describeIntervals(intervals), address, within(AddressBytes(address)), held(address))
				}
			}
		}
		for i := 1; i < len(intervals); i++ {
			if next, past := successor(intervals[i-1].Last); past || bytes.Compare(next, intervals[i].First) >= 0 {
				ht.Fatalf("%v written as %s, with intervals %d and %d sharing or touching an address", prefixes, describeIntervals(intervals), i-1, i)
			}
		}

		s := Set{Table: "t", Name: "s", KeyType: keyType, KeyLen: uint32(size), Flags: unix.NFT_SET_INTERVAL}
		requests, err := s.Fill(unix.NFPROTO_INET, intervals)
		if err != nil {
			ht.Fatal(err)
		}
		var elements [][]byte
		for _, request := range requests {
			if request.Kind != Command(unix.NFT_MSG_NEWSETELEM) {
				ht.Fatalf("Fill sent a message of kind %#x", request.Kind)
			}
			for kind, value := range (Message{Data: request.Body}).Attributes() {
				if kind == unix.NFTA_SET_ELEM_LIST_ELEMENTS {
					for _, item := range Nested(value) {
						elements = append(elements, PutAttr(nil, unix.NFTA_LIST_ELEM|unix.NLA_F_NESTED, item.Value))
					}
				}
			}
		}
		// a dump hands elements back in the set's own order, rbtree's descending
		for i := len(elements) - 1; i > 0; i-- {
			j := hegel.Draw(ht, hegel.Integers(0, i))
			elements[i], elements[j] = elements[j], elements[i]
		}
		dump := Message{Data: PutAttr(PutNfgenmsg(nil, unix.NFPROTO_INET), unix.NFTA_SET_ELEM_LIST_ELEMENTS|unix.NLA_F_NESTED, slices.Concat(elements...))}
		if got := s.decodeElements([]Message{dump}); s.elementFault(intervals, got) != "" {
			ht.Fatalf("%v written as %s reads back as %s", prefixes, describeIntervals(intervals), describeIntervals(got))
		}
	})
}

// A set of interface names holds each name once, in whatever order and as
// often as it was given, and reads back as written
func TestNamesFillAndReadBackOnce(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		names := hegel.Draw(ht, hegel.Lists(hegel.SampledFrom([]string{"lan1", "lan2", "br0", "eth0", "ranet3"})).MaxSize(8))
		s := Set{Table: "t", Name: "forwarded", KeyType: TypeIfname, KeyLen: unix.IFNAMSIZ}
		var keys []Interval
		for _, name := range names {
			keys = append(keys, Key(InterfaceName(name)))
		}
		requests, err := s.Fill(unix.NFPROTO_INET, keys)
		if err != nil {
			ht.Fatal(err)
		}
		var dump []Message
		for _, request := range requests {
			dump = append(dump, Message{Data: request.Body})
		}
		got := s.decodeElements(dump)
		want := slices.Clone(names)
		slices.Sort(want)
		want = slices.Compact(want)
		if len(got) != len(want) {
			ht.Fatalf("%q reads back as %s", names, s.describe(got))
		}
		for i, name := range want {
			if !bytes.Equal(got[i].First, InterfaceName(name)) || !bytes.Equal(got[i].Last, InterfaceName(name)) {
				ht.Fatalf("%q reads back as %s", names, s.describe(got))
			}
		}
	})
}

func describeIntervals(intervals []Interval) string {
	return Set{KeyType: TypeIPv6Addr}.describe(intervals)
}
