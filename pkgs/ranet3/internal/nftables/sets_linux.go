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

	"ranet3.com/pkgs/ranet3/internal/netlink"
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
	// expressions counts those a set read back carries of its own, which
	// nf_tables gives each element added to it. Create writes none.
	expressions int
}

// Create makes the set, or takes one of its name holding the same key, flags,
// expressions and fields and gives it any size but none, leaving its comment
// as it was. One that differs in any of those fails the transaction with
// EEXIST, which Hold.Rewrite answers. One flagged anonymous fails the
// transaction with EOPNOTSUPP before any of those is compared, which
// Hold.Rewrite does not answer.
func (s Set) Create(proto uint8) (Request, error) {
	// a longer comment still lists in `nft list ruleset`, but nft -f will not load that listing back
	if len(s.Comment) > udataCommentMax {
		return Request{}, fmt.Errorf("nftables: set %s's comment %s does not fit in the %d bytes nft takes", s.Name, s.Comment, udataCommentMax)
	}
	body := PutNfgenmsg(nil, proto)
	body = netlink.PutAttrString(body, unix.NFTA_SET_TABLE, s.Table)
	body = netlink.PutAttrString(body, unix.NFTA_SET_NAME, s.Name)
	body = PutAttrBE32(body, unix.NFTA_SET_FLAGS, s.Flags)
	body = PutAttrBE32(body, unix.NFTA_SET_KEY_TYPE, s.KeyType)
	body = PutAttrBE32(body, unix.NFTA_SET_KEY_LEN, s.KeyLen)
	body = PutAttrBE32(body, unix.NFTA_SET_ID, s.ID)
	body = netlink.PutAttr(body, unix.NFTA_SET_DESC|unix.NLA_F_NESTED, PutAttrBE32(nil, unix.NFTA_SET_DESC_SIZE, s.Size))
	var udata []byte
	if s.KeyType == TypeIfname {
		udata = binary.NativeEndian.AppendUint32([]byte{udataSetKeyByteOrder, 4}, byteOrderHost)
	}
	if s.Comment != "" {
		udata = append(udata, userdata(udataSetComment, s.Comment)...)
	}
	if udata != nil {
		body = netlink.PutAttr(body, unix.NFTA_SET_USERDATA, udata)
	}
	return Request{Kind: Command(unix.NFT_MSG_NEWSET), Flags: unix.NLM_F_CREATE, Body: body}, nil
}

// Delete fails while a rule uses the set
func (s Set) Delete(proto uint8) Request {
	body := PutNfgenmsg(nil, proto)
	body = netlink.PutAttrString(body, unix.NFTA_SET_TABLE, s.Table)
	body = netlink.PutAttrString(body, unix.NFTA_SET_NAME, s.Name)
	return Request{Kind: Command(unix.NFT_MSG_DELSET), Body: body}
}

// DecodeSet reads a set out of a dump, with no ID
func DecodeSet(message netlink.Message) Set {
	var s Set
	for kind, value := range message.Attributes(SizeofNfgenmsg) {
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
		case kind == setExpression:
			s.expressions = 1
		case kind == setExpressions:
			s.expressions = len(Nested(value))
		}
	}
	return s
}

// Fault names how the set a dump holds differs from s as Create writes it,
// empty for s as written and for any other set. A dump shows the fields of a
// concatenation from two up, so a set of one field reads as s, though Create
// fails on it. remake holds where its key,
// flags, comment or expressions differ, which nf_tables will not change in
// place, or where it holds a size and s none, which Create cannot set, and
// another size alone the next Create sets. It never holds for a set flagged
// anonymous: nf_tables takes one out with the one line that holds it, so the
// owner's flush of that line frees the name for its Create, and a delete after
// that flush fails the transaction.
func (s Set) Fault(message netlink.Message) (fault string, remake bool) {
	held := DecodeSet(message)
	if held.Table != s.Table || held.Name != s.Name {
		return "", false
	}
	held.ID = s.ID
	if held == s {
		return "", false
	}
	half := func(set Set) string {
		text := fmt.Sprintf("key type %d of %d bytes, flags %#x, size %d", set.KeyType, set.KeyLen, set.Flags, set.Size)
		switch set.expressions {
		case 0:
			return fmt.Sprintf("%s and comment %q", text, set.Comment)
		case 1:
			return fmt.Sprintf("%s, comment %q and 1 expression", text, set.Comment)
		}
		return fmt.Sprintf("%s, comment %q and %d expressions", text, set.Comment, set.expressions)
	}
	return fmt.Sprintf("its set %s reads back with %s, where %s were written", s.Name, half(held), half(s)),
		held.Flags&unix.NFT_SET_ANONYMOUS == 0 && (held.KeyType != s.KeyType || held.KeyLen != s.KeyLen || held.Flags != s.Flags ||
			held.Comment != s.Comment || held.expressions != s.expressions || held.Size != s.Size && s.Size == 0)
}

// resized is whether the set a dump holds is s but for its size
func (s Set) resized(message netlink.Message) bool {
	held := DecodeSet(message)
	held.ID, held.Size = s.ID, s.Size
	return held == s
}

// Anonymous is a set bound to the one rule whose Lookup names it, made in the
// same transaction before that rule. The kernel takes no change to its
// elements once the rule holds it (nf_tables_api.c, nf_tables_newsetelem and
// nf_tables_delsetelem), and deletes it with the rule.
func Anonymous(table string, id, keyType, keyLen, flags uint32) Set {
	return Set{Table: table, Name: anonymousSet, ID: id, KeyType: keyType, KeyLen: keyLen, Flags: flags | unix.NFT_SET_ANONYMOUS | unix.NFT_SET_CONSTANT}
}

// Interval is the keys First to Last of a set, both included, each as long as
// the set's key and compared as big endian numbers. A set read back may hold
// one with neither, for an element's expression.
type Interval struct{ First, Last []byte }

func Key(key []byte) Interval { return Interval{First: key, Last: key} }

// Prefixes is the addresses of prefixes, all of one family, as the fewest
// intervals that hold them
func Prefixes(prefixes []netip.Prefix) []Interval {
	intervals := make([]Interval, 0, len(prefixes))
	for _, prefix := range prefixes {
		first := netlink.AddressBytes(prefix.Masked().Addr())
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
	body := netlink.PutAttr(nil, unix.NFTA_SET_ELEM_KEY|unix.NLA_F_NESTED, netlink.PutAttr(nil, unix.NFTA_DATA_VALUE, e.key))
	if e.flags != 0 {
		body = PutAttrBE32(body, unix.NFTA_SET_ELEM_FLAGS, e.flags)
	}
	if e.userdata != nil {
		body = netlink.PutAttr(body, unix.NFTA_SET_ELEM_USERDATA, e.userdata)
	}
	return netlink.PutAttr(nil, unix.NFTA_LIST_ELEM|unix.NLA_F_NESTED, body)
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
	return s.lists(proto, unix.NFT_MSG_NEWSETELEM, unix.NLM_F_CREATE, elements), nil
}

// Flush names no element, which nf_tables reads as every element of the
// named set s
func (s Set) Flush(proto uint8) Request {
	return Request{Kind: Command(unix.NFT_MSG_DELSETELEM), Body: s.elementList(proto)}
}

// Replace is Create, Flush and Fill of intervals in that order, the messages
// that leave s holding intervals alone in one transaction
func (s Set) Replace(proto uint8, intervals []Interval) ([]Request, error) {
	made, err := s.Create(proto)
	if err != nil {
		return nil, err
	}
	filled, err := s.Fill(proto, intervals)
	if err != nil {
		return nil, err
	}
	return append([]Request{made, s.Flush(proto)}, filled...), nil
}

func (s Set) elementList(proto uint8) []byte {
	body := PutNfgenmsg(nil, proto)
	body = netlink.PutAttrString(body, unix.NFTA_SET_ELEM_LIST_TABLE, s.Table)
	return netlink.PutAttrString(body, unix.NFTA_SET_ELEM_LIST_SET, s.Name)
}

// Elements reads through conn what a lookup in the named set s finds, as
// decodeElements reads a dump, so they equal the intervals Fill was given
// exactly when a lookup finds those keys and no element carries an expression
func (s Set) Elements(conn *Conn, proto uint8) ([]Interval, error) {
	replies, err := conn.Dump(Command(unix.NFT_MSG_GETSETELEM), s.elementList(proto))
	if err != nil {
		return nil, fmt.Errorf("nftables: dump the elements of set %s: %w", s.Name, err)
	}
	return s.decodeElements(replies), nil
}

// decodeElements reads the elements dumps hold, in whatever order, as the
// keys a lookup finds: one is held while the greatest element at or below it
// is not an end, a start sorting after an end at one key. A catchall element,
// which a lookup finding no other element finds, holds every key. An element
// carrying an expression, which decides whether a lookup finding it matches,
// adds an interval with no key.
func (s Set) decodeElements(replies []netlink.Message) []Interval {
	var held []element
	every, decided := false, false
	for _, reply := range replies {
		for kind, value := range reply.Attributes(SizeofNfgenmsg) {
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
					case field.Kind == unix.NFTA_SET_ELEM_EXPR || field.Kind == elementExpressions:
						decided = true
					}
				}
				every = every || e.flags&elementCatchall != 0
				held = append(held, e)
			}
		}
	}
	finish := func(out []Interval) []Interval {
		if decided {
			return append(out, Interval{})
		}
		return out
	}
	if every {
		return finish([]Interval{{First: make([]byte, s.KeyLen), Last: bytes.Repeat([]byte{0xff}, int(s.KeyLen))}})
	}
	if s.Flags&unix.NFT_SET_INTERVAL == 0 {
		keys := make([]Interval, 0, len(held))
		for _, e := range held {
			keys = append(keys, Key(e.key))
		}
		return finish(s.normal(keys))
	}
	end := func(e element) bool { return e.flags&unix.NFT_SET_ELEM_INTERVAL_END != 0 }
	slices.SortFunc(held, func(a, b element) int {
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
	return finish(union(out))
}

func dataValue(data []byte) []byte {
	for _, field := range Nested(data) {
		if field.Kind == unix.NFTA_DATA_VALUE {
			return field.Value
		}
	}
	return nil
}

// VerdictMap is a map of a table whose elements are verdicts, the anonymous
// one of a rule's vmap or a named one, and the chain each element's goto or
// jump sends a packet on to
type VerdictMap struct {
	Name      string
	Anonymous bool
	Chains    []string
}

// VerdictMaps reads every verdict map of table through conn, with its elements
func VerdictMaps(conn *Conn, proto uint8, table string) ([]VerdictMap, error) {
	sets, err := conn.Dump(Command(unix.NFT_MSG_GETSET), netlink.PutAttrString(PutNfgenmsg(nil, proto), unix.NFTA_SET_TABLE, table))
	if err != nil {
		return nil, fmt.Errorf("nftables: dump the sets of table %s: %w", table, err)
	}
	var out []VerdictMap
	for _, reply := range sets {
		set := DecodeSet(reply)
		if set.Table != table || set.Flags&unix.NFT_SET_MAP == 0 || dataType(reply) != unix.NFT_DATA_VERDICT {
			continue
		}
		elements, err := conn.Dump(Command(unix.NFT_MSG_GETSETELEM), set.elementList(proto))
		if err != nil {
			return nil, fmt.Errorf("nftables: dump the elements of map %s: %w", set.Name, err)
		}
		out = append(out, VerdictMap{Name: set.Name, Anonymous: set.Flags&unix.NFT_SET_ANONYMOUS != 0, Chains: elementChains(elements)})
	}
	return out, nil
}

// dataType is the type of the data a dumped set maps its keys to, 0 for a set
// that maps none
func dataType(message netlink.Message) uint32 {
	for kind, value := range message.Attributes(SizeofNfgenmsg) {
		if kind == unix.NFTA_SET_DATA_TYPE && len(value) == 4 {
			return binary.BigEndian.Uint32(value)
		}
	}
	return 0
}

// elementChains is the chain each verdict of the elements dumps hold sends a
// packet on to, in the order dumped
func elementChains(replies []netlink.Message) []string {
	var out []string
	for _, reply := range replies {
		for kind, value := range reply.Attributes(SizeofNfgenmsg) {
			if kind != unix.NFTA_SET_ELEM_LIST_ELEMENTS {
				continue
			}
			for _, item := range Nested(value) {
				for _, field := range Nested(item.Value) {
					if field.Kind != unix.NFTA_SET_ELEM_DATA {
						continue
					}
					for _, data := range Nested(field.Value) {
						if data.Kind != unix.NFTA_DATA_VERDICT {
							continue
						}
						for _, verdict := range Nested(data.Value) {
							if verdict.Kind == unix.NFTA_VERDICT_CHAIN {
								out = append(out, unix.ByteSliceToString(verdict.Value))
							}
						}
					}
				}
			}
		}
	}
	return out
}

// ElementFault reads s through conn as Elements does and names how it differs
// from written, empty where it does not
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

// Text spells one interval as nft lists an element of s: a link's name or a
// range of names as its first and a star, a port or a range of ports, an
// address, a prefix, or a range's first and last address. An interval with no
// key is an element's expression.
func (s Set) Text(interval Interval) string {
	if interval.First == nil {
		return "an element's expression"
	}
	switch s.KeyType {
	case TypeIfname:
		if !bytes.Equal(interval.First, interval.Last) {
			return unix.ByteSliceToString(interval.First) + "*"
		}
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
