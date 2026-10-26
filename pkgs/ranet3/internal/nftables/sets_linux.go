// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package nftables

import (
	"encoding/binary"
	"fmt"

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
	if s.Comment != "" {
		body = PutAttr(body, unix.NFTA_SET_USERDATA, userdata(udataSetComment, s.Comment))
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

// readSet is s's fault among the sets a dump holds, one missing among them
func readSet(s Set, sets []Message) (fault string, remake bool) {
	for _, reply := range sets {
		if held := DecodeSet(reply); held.Table == s.Table && held.Name == s.Name {
			return s.Fault(reply)
		}
	}
	return fmt.Sprintf("its set %s is missing", s.Name), false
}
