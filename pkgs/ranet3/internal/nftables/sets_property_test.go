// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package nftables

import (
	"bytes"
	"cmp"
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

// Elements of an interval set, from none to many more than a sort orders by
// insertion alone, at a few keys from the edges of the key space or at keys
// drawn from all of it, some held more than once and some keys holding a start
// and an end, with flag bits beside the end bit that the decode does not read,
// so elements tied in the sort differ, handed back in ascending order, with
// two elements swapped, in any order or descending, read back as the keys a
// lookup finds: an element's key up to the next greater one, or to the last
// key, where a start is at that key, since a start sorts after an end at one
// key
func TestElementsInAnyOrderReadBackAsALookupFindsThem(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		s := Set{Table: "t", Name: "ports", KeyType: TypeInetService, KeyLen: 2, Flags: unix.NFT_SET_INTERVAL}
		end := func(e element) bool { return e.flags&unix.NFT_SET_ELEM_INTERVAL_END != 0 }
		// neither the end bit nor the catchall bit, which marks an element of its own
		unread := []uint32{0, 0x4, 0xfffffffc}
		pool := []uint16{0, 0xffff, 0x8000, 1, 0xfffe, 2}[:hegel.Draw(ht, pbt.Spanning(1, 6))]
		fresh := []float64{0, 0.5, 1}[hegel.Draw(ht, pbt.Spanning(0, 2))]
		var drawn []element
		for range hegel.Draw(ht, hegel.Integers(0, 128)) {
			var key uint16
			if hegel.Draw(ht, hegel.WeightedBooleans(fresh)) {
				key = hegel.Draw(ht, hegel.Integers[uint16](0, 0xffff))
				pool = append(pool, key)
			} else {
				key = hegel.Draw(ht, hegel.SampledFrom(pool))
			}
			e := element{key: binary.BigEndian.AppendUint16(nil, key), flags: hegel.Draw(ht, hegel.SampledFrom(unread))}
			if hegel.Draw(ht, hegel.Booleans()) {
				e.flags |= unix.NFT_SET_ELEM_INTERVAL_END
			}
			drawn = append(drawn, e)
		}
		if len(drawn) > 0 && hegel.Draw(ht, pbt.Spanning(0, 1)) == 1 {
			e := drawn[hegel.Draw(ht, hegel.Integers(0, len(drawn)-1))]
			twin := element{key: e.key, flags: e.flags ^ hegel.Draw(ht, hegel.SampledFrom(unread))}
			drawn = append(drawn, twin, element{key: e.key, flags: e.flags ^ unix.NFT_SET_ELEM_INTERVAL_END})
		}
		rank := func(e element) int {
			r := 2 * int(binary.BigEndian.Uint16(e.key))
			if !end(e) {
				r++
			}
			return r
		}
		slices.SortStableFunc(drawn, func(a, b element) int { return cmp.Compare(rank(a), rank(b)) })
		switch hegel.Draw(ht, pbt.Spanning(0, 3)) {
		case 1:
			if len(drawn) > 1 {
				i, j := hegel.Draw(ht, hegel.Integers(0, len(drawn)-1)), hegel.Draw(ht, hegel.Integers(0, len(drawn)-1))
				drawn[i], drawn[j] = drawn[j], drawn[i]
			}
		case 2:
			for i := len(drawn) - 1; i > 0; i-- {
				j := hegel.Draw(ht, hegel.Integers(0, i))
				drawn[i], drawn[j] = drawn[j], drawn[i]
			}
		case 3:
			slices.Reverse(drawn)
		}

		starts := map[uint16]bool{}
		var keys []uint16
		var list []byte
		var text []string
		for _, e := range drawn {
			key := binary.BigEndian.Uint16(e.key)
			keys = append(keys, key)
			starts[key] = starts[key] || !end(e)
			list = append(list, e.encode()...)
			text = append(text, fmt.Sprintf("%x end %v flags %#x", e.key, end(e), e.flags))
		}
		slices.Sort(keys)
		keys = slices.Compact(keys)
		var want []Interval
		for i, key := range keys {
			if !starts[key] {
				continue
			}
			last := uint16(0xffff)
			if i+1 < len(keys) {
				last = keys[i+1] - 1
			}
			want = append(want, Interval{First: binary.BigEndian.AppendUint16(nil, key), Last: binary.BigEndian.AppendUint16(nil, last)})
		}
		dump := netlink.Message{Data: netlink.PutAttr(PutNfgenmsg(nil, unix.NFPROTO_INET), unix.NFTA_SET_ELEM_LIST_ELEMENTS|unix.NLA_F_NESTED, list)}
		if got := s.decodeElements([]netlink.Message{dump}); s.elementFault(want, got) != "" {
			ht.Fatalf("%v read back as %s, want %s", text, s.describe(got), s.describe(s.normal(want)))
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

// Elements of a set of ports, an interval set or one of single keys, with or
// without a catchall, beside them or in a message of its own as the kernel
// dumps it, some carrying one expression or several, the catchall among them,
// and each nest flagged as nested or not, as the kernel sends it, read back as
// the keys a lookup finds: every key where the set holds a catchall, and an
// interval with no key behind them where any element carries an expression
func TestElementsBesideACatchallOrAnExpressionReadBackAsALookupFindsThem(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		ranged := hegel.Draw(ht, hegel.Booleans())
		s := Set{Table: "t", Name: "ports", KeyType: TypeInetService, KeyLen: 2}
		if ranged {
			s.Flags = unix.NFT_SET_INTERVAL
		}
		element := drawnElement(ht, hegel.Draw(ht, hegel.Booleans()))
		var keyed [][]byte
		var text []string
		held := make([]bool, 1<<16)
		starts := map[uint16]bool{}
		var keys []uint16
		carried := false
		for range hegel.Draw(ht, hegel.Integers(0, 12)) {
			key := hegel.Draw(ht, hegel.SampledFrom([]uint16{0, 1, 2, 0x8000, 0xfffe, 0xffff}))
			end := ranged && hegel.Draw(ht, hegel.Booleans())
			var flags uint32
			if end {
				flags = unix.NFT_SET_ELEM_INTERVAL_END
			}
			item, carries := element(binary.BigEndian.AppendUint16(nil, key), flags)
			keyed, carried = append(keyed, item), carried || carries
			keys, starts[key] = append(keys, key), starts[key] || !end
			text = append(text, fmt.Sprintf("%04x end %v expression %v", key, end, carries))
		}
		// 0 is no catchall, 1 one among the elements, 2 one in a message of its own
		place := hegel.Draw(ht, pbt.Spanning(0, 2))
		var own []byte
		if place > 0 {
			// NFT_SET_ELEM_CATCHALL, with no key
			item, carries := element(nil, 0x2)
			carried = carried || carries
			text = append(text, fmt.Sprintf("catchall in message %d expression %v", place, carries))
			if place == 1 {
				at := hegel.Draw(ht, hegel.Integers(0, len(keyed)))
				keyed = slices.Insert(keyed, at, item)
			} else {
				own = item
			}
		}
		// the elements go over one message or two, as a dump of many does
		split := hegel.Draw(ht, hegel.Integers(0, len(keyed)))
		var dump []netlink.Message
		for _, items := range [][][]byte{keyed[:split], keyed[split:], {own}} {
			if body := slices.Concat(items...); len(body) > 0 {
				dump = append(dump, netlink.Message{Data: slices.Concat(PutNfgenmsg(nil, unix.NFPROTO_INET), drawnNest(ht, unix.NFTA_SET_ELEM_LIST_ELEMENTS, body))})
			}
		}

		slices.Sort(keys)
		keys = slices.Compact(keys)
		for i, key := range keys {
			last := key
			if ranged {
				if !starts[key] {
					continue
				}
				last = 0xffff
				if i+1 < len(keys) {
					last = keys[i+1] - 1
				}
			}
			for k := int(key); k <= int(last); k++ {
				held[k] = true
			}
		}
		if place > 0 {
			for k := range held {
				held[k] = true
			}
		}
		var want []Interval
		for k := 0; k < len(held); k++ {
			if !held[k] {
				continue
			}
			first := k
			for (ranged || place > 0) && k+1 < len(held) && held[k+1] {
				k++
			}
			want = append(want, Interval{First: binary.BigEndian.AppendUint16(nil, uint16(first)), Last: binary.BigEndian.AppendUint16(nil, uint16(k))})
		}
		if carried {
			want = append(want, Interval{})
		}
		got := s.decodeElements(dump)
		same := slices.EqualFunc(got, want, func(a, b Interval) bool {
			return (a.First == nil) == (b.First == nil) && bytes.Equal(a.First, b.First) && bytes.Equal(a.Last, b.Last)
		})
		if !same {
			ht.Fatalf("%v in a set ranged %v read back as %s, want %s", text, ranged, s.describe(got), s.describe(want))
		}
	})
}

// drawnElement encodes one element of a dump with key, none for a catchall,
// and flags, which carries an expression where expressed and the draw say so
func drawnElement(ht *hegel.T, expressed bool) func(key []byte, flags uint32) (item []byte, carries bool) {
	counter := func() []byte {
		return slices.Concat(netlink.PutAttrString(nil, unix.NFTA_EXPR_NAME, "counter"), drawnNest(ht, unix.NFTA_EXPR_DATA, nil))
	}
	return func(key []byte, flags uint32) ([]byte, bool) {
		var body []byte
		if key != nil {
			body = drawnNest(ht, unix.NFTA_SET_ELEM_KEY, netlink.PutAttr(nil, unix.NFTA_DATA_VALUE, key))
		}
		if flags != 0 {
			body = PutAttrBE32(body, unix.NFTA_SET_ELEM_FLAGS, flags)
		}
		if !expressed {
			return drawnNest(ht, unix.NFTA_LIST_ELEM, body), false
		}
		// 0 is none, 1 one under NFTA_SET_ELEM_EXPR, 7, and 2 one to three under
		// NFTA_SET_ELEM_EXPRESSIONS, 11
		switch hegel.Draw(ht, pbt.Spanning(0, 2)) {
		case 1:
			body = append(body, drawnNest(ht, 7, counter())...)
		case 2:
			var list []byte
			for range hegel.Draw(ht, hegel.Integers(1, 3)) {
				list = append(list, drawnNest(ht, unix.NFTA_LIST_ELEM, counter())...)
			}
			body = append(body, drawnNest(ht, 11, list)...)
		default:
			return drawnNest(ht, unix.NFTA_LIST_ELEM, body), false
		}
		return drawnNest(ht, unix.NFTA_LIST_ELEM, body), true
	}
}

// drawnNest is the attribute kind holding body, flagged NLA_F_NESTED or not as
// drawn, since the kernel's dumps flag no nest and a request flags each
func drawnNest(ht *hegel.T, kind uint16, body []byte) []byte {
	if hegel.Draw(ht, hegel.Booleans()) {
		kind |= unix.NLA_F_NESTED
	}
	return netlink.PutAttr(nil, kind, body)
}
