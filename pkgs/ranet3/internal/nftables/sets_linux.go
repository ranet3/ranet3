// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package nftables

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Set is a named set one owner writes in its table
type Set struct {
	Table string
	Name  string
	// ID names the set to a rule of the transaction that makes it, which the
	// kernel requires of a new set and keeps no further
	ID      uint32
	KeyType uint32
	KeyLen  uint32
	Flags   uint32
	Size    uint32
	// Comment is the text `nft list` prints as the set's comment, empty for none.
	// nf_tables keeps the one the set was made with.
	Comment string
}

// Create makes the set, or takes one of its name holding the same key and
// flags and gives it the size, leaving its comment as it was. One holding
// another key or other flags fails the transaction.
func (s Set) Create(proto uint8) (Request, error) {
	// a longer comment still lists in `nft list ruleset`, but nft -f will not load that listing back
	if len(s.Comment) > udataCommentMax {
		return Request{}, fmt.Errorf("nftables: set %s's comment %s does not fit in the %d bytes nft takes", s.Name, s.Comment, udataCommentMax)
	}
	body := PutNfgenmsg(nil, proto)
	body = PutAttrString(body, unix.NFTA_SET_TABLE, s.Table)
	body = PutAttrString(body, unix.NFTA_SET_NAME, s.Name)
	body = PutAttrBE32(body, unix.NFTA_SET_FLAGS, s.Flags)
	body = PutAttrBE32(body, unix.NFTA_SET_KEY_TYPE, s.KeyType)
	body = PutAttrBE32(body, unix.NFTA_SET_KEY_LEN, s.KeyLen)
	body = PutAttrBE32(body, unix.NFTA_SET_ID, s.ID)
	body = PutAttr(body, unix.NFTA_SET_DESC|unix.NLA_F_NESTED, PutAttrBE32(nil, unix.NFTA_SET_DESC_SIZE, s.Size))
	var udata []byte
	if s.KeyType == TypeIfname {
		udata = binary.NativeEndian.AppendUint32([]byte{udataSetKeyByteOrder, 4}, byteOrderHost)
	}
	if s.Comment != "" {
		udata = append(udata, userdata(udataSetComment, s.Comment)...)
	}
	if udata != nil {
		body = PutAttr(body, unix.NFTA_SET_USERDATA, udata)
	}
	return Request{Kind: Command(unix.NFT_MSG_NEWSET), Flags: unix.NLM_F_CREATE, Body: body}, nil
}

// DecodeSet reads a set out of a dump, with no ID
func DecodeSet(message Message) Set {
	var s Set
	for kind, value := range message.Attributes() {
		switch {
		case kind == unix.NFTA_SET_TABLE:
			s.Table = unix.ByteSliceToString(value)
		case kind == unix.NFTA_SET_NAME:
			s.Name = unix.ByteSliceToString(value)
		case kind == unix.NFTA_SET_FLAGS && len(value) == 4:
			s.Flags = binary.BigEndian.Uint32(value)
		case kind == unix.NFTA_SET_KEY_TYPE && len(value) == 4:
			s.KeyType = binary.BigEndian.Uint32(value)
		case kind == unix.NFTA_SET_KEY_LEN && len(value) == 4:
			s.KeyLen = binary.BigEndian.Uint32(value)
		case kind == unix.NFTA_SET_DESC:
			for _, field := range Nested(value) {
				if field.Kind == unix.NFTA_SET_DESC_SIZE && len(field.Value) == 4 {
					s.Size = binary.BigEndian.Uint32(field.Value)
				}
			}
		case kind == unix.NFTA_SET_USERDATA:
			s.Comment = comment(udataSetComment, value)
		}
	}
	return s
}

// Fault names how the set a dump holds differs from s as Create writes it,
// empty for s as written and for any other set. remake holds where its key,
// flags or comment differ, which nf_tables will not change in place, and a
// size alone the next Create sets.
func (s Set) Fault(message Message) (fault string, remake bool) {
	held := DecodeSet(message)
	if held.Table != s.Table || held.Name != s.Name {
		return "", false
	}
	held.ID = s.ID
	if held == s {
		return "", false
	}
	return fmt.Sprintf("its set %s reads back with key type %d of %d bytes, flags %#x, size %d and comment %q, where key type %d of %d bytes, flags %#x, size %d and comment %q were written",
			s.Name, held.KeyType, held.KeyLen, held.Flags, held.Size, held.Comment, s.KeyType, s.KeyLen, s.Flags, s.Size, s.Comment),
		held.KeyType != s.KeyType || held.KeyLen != s.KeyLen || held.Flags != s.Flags || held.Comment != s.Comment
}

// Anonymous is a set bound to the one rule whose Lookup names it, made in the
// same transaction before that rule. The kernel takes no change to its
// elements once the rule holds it (nf_tables_api.c, nf_tables_newsetelem and
// nf_tables_delsetelem), and deletes it with the rule.
func Anonymous(table string, id, keyType, keyLen, flags uint32) Set {
	return Set{Table: table, Name: anonymousSet, ID: id, KeyType: keyType, KeyLen: keyLen, Flags: flags | unix.NFT_SET_ANONYMOUS | unix.NFT_SET_CONSTANT}
}

// Interval is the keys First to Last of a set, both included, each as long as
// the set's key and compared as big endian numbers
type Interval struct{ First, Last []byte }

func Key(key []byte) Interval { return Interval{First: key, Last: key} }

// Prefixes is the addresses of prefixes, all of one family, as the fewest
// intervals that hold them
func Prefixes(prefixes []netip.Prefix) []Interval {
	intervals := make([]Interval, 0, len(prefixes))
	for _, prefix := range prefixes {
		first := AddressBytes(prefix.Masked().Addr())
		last := slices.Clone(first)
		for i, mask := range prefixMask(prefix) {
			last[i] |= ^mask
		}
		intervals = append(intervals, Interval{First: first, Last: last})
	}
	return union(intervals)
}

// union is the fewest intervals that hold the keys intervals hold, in order:
// overlapping and adjacent ones joined, so no two share or touch a key. Every
// key is of one length.
func union(intervals []Interval) []Interval {
	sorted := slices.Clone(intervals)
	slices.SortFunc(sorted, func(a, b Interval) int { return bytes.Compare(a.First, b.First) })
	var out []Interval
	for _, interval := range sorted {
		if n := len(out); n > 0 {
			next, past := successor(out[n-1].Last)
			if past || bytes.Compare(interval.First, next) <= 0 {
				if bytes.Compare(interval.Last, out[n-1].Last) > 0 {
					out[n-1].Last = interval.Last
				}
				continue
			}
		}
		out = append(out, interval)
	}
	return out
}

// successor is key plus one, past when key is the last key of its length
func successor(key []byte) (next []byte, past bool) {
	next = slices.Clone(key)
	for i := len(next) - 1; i >= 0; i-- {
		if next[i]++; next[i] != 0 {
			return next, false
		}
	}
	return next, true
}

// predecessor is key minus one, for a key that is not all zero
func predecessor(key []byte) []byte {
	prev := slices.Clone(key)
	for i := len(prev) - 1; i >= 0; i-- {
		if prev[i]--; prev[i] != 0xff {
			break
		}
	}
	return prev
}

// element is one set element as NFTA_LIST_ELEM carries it
type element struct {
	key      []byte
	flags    uint32
	userdata []byte
}

func (e element) encode() []byte {
	body := PutAttr(nil, unix.NFTA_SET_ELEM_KEY|unix.NLA_F_NESTED, PutAttr(nil, unix.NFTA_DATA_VALUE, e.key))
	if e.flags != 0 {
		body = PutAttrBE32(body, unix.NFTA_SET_ELEM_FLAGS, e.flags)
	}
	if e.userdata != nil {
		body = PutAttr(body, unix.NFTA_SET_ELEM_USERDATA, e.userdata)
	}
	return PutAttr(nil, unix.NFTA_LIST_ELEM|unix.NLA_F_NESTED, body)
}

// normal is intervals as s holds them: the union for an interval set, each
// key once and in order for another
func (s Set) normal(intervals []Interval) []Interval {
	if s.Flags&unix.NFT_SET_INTERVAL != 0 {
		return union(intervals)
	}
	out := slices.Clone(intervals)
	slices.SortFunc(out, func(a, b Interval) int { return bytes.Compare(a.First, b.First) })
	return slices.CompactFunc(out, func(a, b Interval) bool { return bytes.Equal(a.First, b.First) })
}

// elements is intervals as nft 1.1.7 writes them into s. An interval set
// holds each interval's first key and the key after its last flagged as an
// end, behind an end at key zero when the first interval starts above it. An
// interval running to the last key has no end, and its first key carries the
// userdata that has nft print it whole.
func (s Set) elements(intervals []Interval) ([]element, error) {
	ranged := s.Flags&unix.NFT_SET_INTERVAL != 0
	var out []element
	for i, interval := range s.normal(intervals) {
		if len(interval.First) != int(s.KeyLen) || len(interval.Last) != int(s.KeyLen) {
			return nil, fmt.Errorf("nftables: set %s takes keys of %d bytes, not %d and %d", s.Name, s.KeyLen, len(interval.First), len(interval.Last))
		}
		if !ranged {
			if !bytes.Equal(interval.First, interval.Last) {
				return nil, fmt.Errorf("nftables: set %s holds single keys, not the interval %s", s.Name, s.describe([]Interval{interval}))
			}
			out = append(out, element{key: interval.First})
			continue
		}
		if i == 0 && slices.ContainsFunc(interval.First, func(b byte) bool { return b != 0 }) {
			out = append(out, element{key: make([]byte, s.KeyLen), flags: unix.NFT_SET_ELEM_INTERVAL_END})
		}
		next, past := successor(interval.Last)
		if past {
			open := binary.NativeEndian.AppendUint32([]byte{udataElementFlags, 4}, elementOpen)
			out = append(out, element{key: interval.First, userdata: open})
			continue
		}
		out = append(out, element{key: interval.First}, element{key: next, flags: unix.NFT_SET_ELEM_INTERVAL_END})
	}
	return out, nil
}

// Fill adds intervals to s, as many messages as its elements need, each to go
// in the transaction that makes or flushes the set
func (s Set) Fill(proto uint8, intervals []Interval) ([]Request, error) {
	elements, err := s.elements(intervals)
	if err != nil {
		return nil, err
	}
	var requests []Request
	var list []byte
	send := func() {
		body := PutAttrBE32(s.elementList(proto), unix.NFTA_SET_ELEM_LIST_SET_ID, s.ID)
		body = PutAttr(body, unix.NFTA_SET_ELEM_LIST_ELEMENTS|unix.NLA_F_NESTED, list)
		requests = append(requests, Request{Kind: Command(unix.NFT_MSG_NEWSETELEM), Flags: unix.NLM_F_CREATE, Body: body})
		list = nil
	}
	for _, e := range elements {
		encoded := e.encode()
		if len(list) > 0 && len(list)+len(encoded) > elementsMax {
			send()
		}
		list = append(list, encoded...)
	}
	if len(list) > 0 {
		send()
	}
	return requests, nil
}

// Flush names no element, which nf_tables reads as every element of the
// named set s
func (s Set) Flush(proto uint8) Request {
	return Request{Kind: Command(unix.NFT_MSG_DELSETELEM), Body: s.elementList(proto)}
}

func (s Set) elementList(proto uint8) []byte {
	body := PutNfgenmsg(nil, proto)
	body = PutAttrString(body, unix.NFTA_SET_ELEM_LIST_TABLE, s.Table)
	return PutAttrString(body, unix.NFTA_SET_ELEM_LIST_SET, s.Name)
}

// Elements reads the keys the named set s holds through conn, as normal has
// them, so they equal the intervals Fill was given exactly when the set holds
// those keys
func (s Set) Elements(conn *Conn, proto uint8) ([]Interval, error) {
	replies, err := conn.Dump(Command(unix.NFT_MSG_GETSETELEM), s.elementList(proto))
	if err != nil {
		return nil, fmt.Errorf("nftables: dump the elements of set %s: %w", s.Name, err)
	}
	return s.decodeElements(replies), nil
}

// decodeElements reads the elements dumps hold, in whatever order, as the
// keys a lookup finds: one is held while the greatest element at or below it
// is not an end, a start sorting after an end at one key
func (s Set) decodeElements(replies []Message) []Interval {
	var held []element
	for _, reply := range replies {
		for kind, value := range reply.Attributes() {
			if kind != unix.NFTA_SET_ELEM_LIST_ELEMENTS {
				continue
			}
			for _, item := range Nested(value) {
				var e element
				for _, field := range Nested(item.Value) {
					switch {
					case field.Kind == unix.NFTA_SET_ELEM_KEY:
						e.key = dataValue(field.Value)
					case field.Kind == unix.NFTA_SET_ELEM_FLAGS && len(field.Value) == 4:
						e.flags = binary.BigEndian.Uint32(field.Value)
					}
				}
				held = append(held, e)
			}
		}
	}
	if s.Flags&unix.NFT_SET_INTERVAL == 0 {
		keys := make([]Interval, 0, len(held))
		for _, e := range held {
			keys = append(keys, Key(e.key))
		}
		return s.normal(keys)
	}
	end := func(e element) bool { return e.flags&unix.NFT_SET_ELEM_INTERVAL_END != 0 }
	slices.SortStableFunc(held, func(a, b element) int {
		if c := bytes.Compare(a.key, b.key); c != 0 {
			return c
		}
		switch {
		case end(a) == end(b):
			return 0
		case end(a):
			return -1
		}
		return 1
	})
	var out []Interval
	var open []byte
	for _, e := range held {
		switch {
		case !end(e) && open == nil:
			open = e.key
		case end(e) && open != nil:
			if !bytes.Equal(e.key, open) {
				out = append(out, Interval{First: open, Last: predecessor(e.key)})
			}
			open = nil
		}
	}
	if open != nil {
		out = append(out, Interval{First: open, Last: bytes.Repeat([]byte{0xff}, len(open))})
	}
	return union(out)
}

func dataValue(data []byte) []byte {
	for _, field := range Nested(data) {
		if field.Kind == unix.NFTA_DATA_VALUE {
			return field.Value
		}
	}
	return nil
}

// ElementFault reads the keys s holds through conn and names how they differ
// from written, empty where they do not
func (s Set) ElementFault(conn *Conn, proto uint8, written []Interval) (string, error) {
	held, err := s.Elements(conn, proto)
	if err != nil {
		return "", err
	}
	return s.elementFault(written, held), nil
}

// elementFault names how held differs from what was written, both as normal
// has them, empty where they are equal
func (s Set) elementFault(written, held []Interval) string {
	written = s.normal(written)
	same := slices.EqualFunc(written, held, func(a, b Interval) bool {
		return bytes.Equal(a.First, b.First) && bytes.Equal(a.Last, b.Last)
	})
	if same {
		return ""
	}
	return fmt.Sprintf("its set %s holds %s, where %s was written", s.Name, s.describe(held), s.describe(written))
}

func (s Set) describe(intervals []Interval) string {
	parts := make([]string, 0, len(intervals))
	for _, interval := range intervals {
		parts = append(parts, s.Text(interval))
	}
	return "{ " + strings.Join(parts, ", ") + " }"
}

// Text spells one interval as nft lists an element of s: a link's name, a port
// or a range of ports, an address, a prefix, or a range's first and last
// address
func (s Set) Text(interval Interval) string {
	switch s.KeyType {
	case TypeIfname:
		return unix.ByteSliceToString(interval.First)
	case TypeInetService:
		if len(interval.First) == 2 && len(interval.Last) == 2 {
			first, last := binary.BigEndian.Uint16(interval.First), binary.BigEndian.Uint16(interval.Last)
			if first == last {
				return strconv.Itoa(int(first))
			}
			return fmt.Sprintf("%d-%d", first, last)
		}
	case TypeIPv4Addr, TypeIPv6Addr:
		first, okFirst := netip.AddrFromSlice(interval.First)
		last, okLast := netip.AddrFromSlice(interval.Last)
		if !okFirst || !okLast {
			break
		}
		if first == last {
			return first.String()
		}
		for bits := range first.BitLen() {
			prefix := netip.PrefixFrom(first, bits)
			if held := Prefixes([]netip.Prefix{prefix}); prefix.Masked().Addr() == first && bytes.Equal(held[0].Last, interval.Last) {
				return prefix.String()
			}
		}
		return first.String() + "-" + last.String()
	}
	if bytes.Equal(interval.First, interval.Last) {
		return hex.EncodeToString(interval.First)
	}
	return hex.EncodeToString(interval.First) + "-" + hex.EncodeToString(interval.Last)
}
