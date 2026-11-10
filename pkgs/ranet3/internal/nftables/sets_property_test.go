// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package nftables

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/netlink"
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
				raw := netlink.AddressBytes(prefix.Masked().Addr())
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
			last := netlink.AddressBytes(first)
			for i, mask := range prefixMask(prefix) {
				last[i] |= ^mask
			}
			probes := []netip.Addr{first, first.Prev(), addressOf(last), addressOf(last).Next()}
			for _, address := range probes {
				if address.IsValid() && held(address) != within(netlink.AddressBytes(address)) {
					ht.Fatalf("%v written as %s: %s held %v, want %v", prefixes, describeIntervals(intervals), address, within(netlink.AddressBytes(address)), held(address))
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
			for kind, value := range (netlink.Message{Data: request.Body}).Attributes(SizeofNfgenmsg) {
				if kind == unix.NFTA_SET_ELEM_LIST_ELEMENTS {
					for _, item := range Nested(value) {
						elements = append(elements, netlink.PutAttr(nil, unix.NFTA_LIST_ELEM|unix.NLA_F_NESTED, item.Value))
					}
				}
			}
		}
		// a dump hands elements back in the set's own order, rbtree's descending
		for i := len(elements) - 1; i > 0; i-- {
			j := hegel.Draw(ht, hegel.Integers(0, i))
			elements[i], elements[j] = elements[j], elements[i]
		}
		dump := netlink.Message{Data: netlink.PutAttr(PutNfgenmsg(nil, unix.NFPROTO_INET), unix.NFTA_SET_ELEM_LIST_ELEMENTS|unix.NLA_F_NESTED, slices.Concat(elements...))}
		if got := s.decodeElements([]netlink.Message{dump}); s.elementFault(intervals, got) != "" {
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
		var dump []netlink.Message
		for _, request := range requests {
			dump = append(dump, netlink.Message{Data: request.Body})
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

// drawnPrefixes draws up to count prefixes of one family from edgeBytes, so
// they overlap, nest and touch, and reach the first and the last address
func drawnPrefixes(ht *hegel.T, size, count int) []netip.Prefix {
	var out []netip.Prefix
	for range hegel.Draw(ht, hegel.Integers(0, count)) {
		raw := make([]byte, size)
		for i := range raw {
			raw[i] = hegel.Draw(ht, hegel.SampledFrom(edgeBytes))
		}
		prefix, err := addressOf(raw).Prefix(hegel.Draw(ht, pbt.Spanning(0, size*8)))
		if err != nil {
			ht.Fatal(err)
		}
		out = append(out, prefix)
	}
	return out
}

// sent is the kind and the elements of each request, as nf_tables reads them,
// a decode of its own rather than decodeElements, so a fault of that one
// cannot hide here
func sent(requests []Request) (kinds []uint16, lists [][]element) {
	for _, request := range requests {
		var list []element
		for kind, value := range (netlink.Message{Data: request.Body}).Attributes(SizeofNfgenmsg) {
			if kind != unix.NFTA_SET_ELEM_LIST_ELEMENTS {
				continue
			}
			for _, item := range Nested(value) {
				var e element
				for _, field := range Nested(item.Value) {
					switch field.Kind {
					case unix.NFTA_SET_ELEM_KEY:
						e.key = dataValue(field.Value)
					case unix.NFTA_SET_ELEM_FLAGS:
						e.flags = binary.BigEndian.Uint32(field.Value)
					case unix.NFTA_SET_ELEM_USERDATA:
						e.userdata = field.Value
					}
				}
				list = append(list, e)
			}
		}
		kinds, lists = append(kinds, request.Kind), append(lists, list)
	}
	return kinds, lists
}

// rbtreeApply applies requests to an interval set holding held, in one
// transaction, as nft_set_rbtree.c at 940de590 takes them, and stricter in one
// case. The cookie a transaction begins with may be any start's, left by one
// begun on the same jiffy (nft_rbtree_maybe_reset_start_cookie, :296-303). An
// element deleted must be held. A start or the end at key zero deleted clears
// the cookie (nft_rbtree_deactivate, :795-797), and a start deleted is then
// the cookie. An end deleted with a cookie set must have that start, deleted,
// as the next key below it, and clears the cookie
// (nft_rbtree_deactivate_same_interval, :748-771). The end at key zero added,
// or a start added, clears the cookie (__nft_rbtree_insert, :453-456). A start
// added where the next held key at or below it is a start, and an end added
// where the next held key at or below it or at or above it is an end, are
// refused (:494-517, -ENOTEMPTY, which nf_tables_api.c:7619-7623 reports as
// EEXIST). An element added whose key and kind are held the kernel takes,
// since Update sends no NLM_F_EXCL (nf_tables_api.c:7585), and the model
// refuses, as the check that Update never sends one. It is the elements held
// after, in key order, or the refusal.
func rbtreeApply(held []element, requests []Request) ([]element, string) {
	end := func(e element) bool { return e.flags&unix.NFT_SET_ELEM_INTERVAL_END != 0 }
	null := func(e element) bool {
		return end(e) && !slices.ContainsFunc(e.key, func(b byte) bool { return b != 0 })
	}
	type node struct {
		element
		gone bool
	}
	var tree []*node
	for _, e := range held {
		tree = append(tree, &node{element: e})
	}
	// stale stands for a start another transaction on the same jiffy deleted
	stale := &node{}
	cookie := stale
	kinds, lists := sent(requests)
	for i, list := range lists {
		for _, e := range list {
			same := slices.IndexFunc(tree, func(h *node) bool { return !h.gone && bytes.Equal(h.key, e.key) && end(h.element) == end(e) })
			switch kinds[i] {
			case Command(unix.NFT_MSG_DELSETELEM):
				if same < 0 {
					return nil, fmt.Sprintf("deletes %x end %v, which the set does not hold", e.key, end(e))
				}
				n := tree[same]
				if !end(e) || null(e) {
					cookie = nil
				}
				if !end(e) {
					n.gone, cookie = true, n
					continue
				}
				if cookie != nil {
					var below []*node
					for _, h := range tree {
						switch c := bytes.Compare(h.key, e.key); {
						case c >= 0:
						case len(below) == 0 || bytes.Equal(h.key, below[0].key):
							below = append(below, h)
						case bytes.Compare(h.key, below[0].key) > 0:
							below = []*node{h}
						}
					}
					if len(below) != 1 || below[0] != cookie {
						return nil, fmt.Sprintf("deletes the end %x with the start cookie not the deleted start below it", e.key)
					}
				}
				n.gone, cookie = true, nil
				continue
			case Command(unix.NFT_MSG_NEWSETELEM):
			default:
				return nil, fmt.Sprintf("sends a message of kind %#x", kinds[i])
			}
			if null(e) || !end(e) {
				cookie = nil
			}
			if same >= 0 {
				return nil, fmt.Sprintf("adds %x end %v, which the set holds", e.key, end(e))
			}
			var le, ge *node
			for _, h := range tree {
				if h.gone {
					continue
				}
				c := bytes.Compare(h.key, e.key)
				if c <= 0 && (le == nil || bytes.Compare(h.key, le.key) >= 0) {
					le = h
				}
				if c >= 0 && (ge == nil || bytes.Compare(h.key, ge.key) < 0) {
					ge = h
				}
			}
			switch {
			case le != nil && !end(le.element) && !end(e):
				return nil, fmt.Sprintf("adds the start %x above the start %x", e.key, le.key)
			case le != nil && end(le.element) && end(e):
				return nil, fmt.Sprintf("adds the end %x above the end %x", e.key, le.key)
			case ge != nil && end(ge.element) && end(e):
				return nil, fmt.Sprintf("adds the end %x below the end %x", e.key, ge.key)
			}
			tree = append(tree, &node{element: e})
		}
	}
	var out []element
	for _, n := range tree {
		if !n.gone {
			out = append(out, n.element)
		}
	}
	slices.SortFunc(out, func(a, b element) int { return bytes.Compare(a.key, b.key) })
	return out, ""
}

// Drawn prefixes held in an interval set and the wanted drawn, or the held with
// one prefix taken out or put in, or the held with one key at an interval's
// edge toggled, move by Update's messages, applied as nft_rbtree checks them,
// to exactly the elements Fill writes for the wanted, with no message where
// they are equal.
// The elements sent, each of an interval one writing holds and the other
// lacks, are at least those the two writings differ by and at most three times
// as many, as where one interval splits in two.
func TestUpdateMovesASetByTheElementsThatDiffer(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		size, keyType := 4, uint32(TypeIPv4Addr)
		if hegel.Draw(ht, hegel.Booleans()) {
			size, keyType = 16, TypeIPv6Addr
		}
		s := Set{Table: "t", Name: "s", KeyType: keyType, KeyLen: uint32(size), Flags: unix.NFT_SET_INTERVAL}
		was := drawnPrefixes(ht, size, 8)
		heldIntervals, wantIntervals := Prefixes(was), Prefixes(drawnPrefixes(ht, size, 8))
		switch hegel.Draw(ht, pbt.Spanning(0, 2)) {
		case 1:
			now := slices.Clone(was)
			if one := drawnPrefixes(ht, size, 1); len(one) > 0 && (len(was) == 0 || hegel.Draw(ht, hegel.Booleans())) {
				now = append(now, one[0])
			} else if len(was) > 0 {
				i := hegel.Draw(ht, hegel.Integers(0, len(was)-1))
				now = slices.Delete(now, i, i+1)
			}
			wantIntervals = Prefixes(now)
		case 2:
			if len(heldIntervals) > 0 {
				wantIntervals = edgeToggled(ht, heldIntervals)
			}
		}
		held, err := s.elements(heldIntervals)
		if err != nil {
			ht.Fatal(err)
		}
		want, err := s.elements(wantIntervals)
		if err != nil {
			ht.Fatal(err)
		}
		requests, err := s.Update(unix.NFPROTO_INET, heldIntervals, wantIntervals)
		if err != nil {
			ht.Fatal(err)
		}
		where := fmt.Sprintf("%s moved to %s", describeIntervals(heldIntervals), describeIntervals(wantIntervals))
		got, refused := rbtreeApply(held, requests)
		if refused != "" {
			ht.Fatalf("%s: the update %s", where, refused)
		}
		same := func(a, b element) bool {
			return bytes.Equal(a.key, b.key) && a.flags == b.flags && bytes.Equal(a.userdata, b.userdata)
		}
		if !slices.EqualFunc(got, want, same) {
			ht.Fatalf("%s: the set holds %v, want %v", where, got, want)
		}
		_, lists := sent(requests)
		count, differ, added := 0, 0, 0
		for _, list := range lists {
			count += len(list)
		}
		for _, e := range held {
			if !slices.ContainsFunc(want, func(w element) bool { return same(e, w) }) {
				differ++
			}
		}
		for _, e := range want {
			if !slices.ContainsFunc(held, func(h element) bool { return same(e, h) }) {
				differ++
				added++
			}
		}
		if count < differ || count > 3*differ || (differ == 0) != (len(requests) == 0) {
			ht.Fatalf("%s: sent %d elements in %d messages, where the writings differ by %d with %d added", where, count, len(requests), differ, added)
		}
	})
}

// edgeToggled is held, as union leaves intervals, with one key at a drawn
// interval's edge toggled: the key below its start or above its end put in,
// which moves that end alone or joins it to the next, or its start, its end or
// the key above its start taken out, which moves an end alone or splits it
func edgeToggled(ht *hegel.T, held []Interval) []Interval {
	r := held[hegel.Draw(ht, pbt.Spanning(0, len(held)-1))]
	first, last := addressOf(r.First), addressOf(r.Last)
	key := [...]netip.Addr{first.Prev(), last.Next(), first, last, first.Next()}[hegel.Draw(ht, pbt.Spanning(0, 4))]
	if !key.IsValid() {
		return held
	}
	at := netlink.AddressBytes(key)
	in := func(i Interval) bool { return bytes.Compare(i.First, at) <= 0 && bytes.Compare(at, i.Last) <= 0 }
	if !slices.ContainsFunc(held, in) {
		return union(append(slices.Clone(held), Key(at)))
	}
	var out []Interval
	for _, i := range held {
		if !in(i) {
			out = append(out, i)
			continue
		}
		if addressOf(i.First) != key {
			out = append(out, Interval{First: i.First, Last: netlink.AddressBytes(key.Prev())})
		}
		if addressOf(i.Last) != key {
			out = append(out, Interval{First: netlink.AddressBytes(key.Next()), Last: i.Last})
		}
	}
	return out
}

func describeIntervals(intervals []Interval) string {
	return Set{KeyType: TypeIPv6Addr}.describe(intervals)
}
