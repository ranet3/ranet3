// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package nftables

import (
	"golang.org/x/sys/unix"
)

// Update moves s, which holds the intervals held, to want in one transaction:
// the messages deleting each interval held that want lacks, then those adding
// each interval want has that held lacks, in key order. nf_tables refuses to
// delete an end when the start it deleted last, in this transaction or one
// begun on the same jiffy, is not the start right below that end
// (nft_rbtree_deactivate's start cookie), so an interval goes or comes whole,
// start then end, as nft deletes and adds a range. The end nft writes at key
// zero has no start and goes or comes alone, since nf_tables clears the cookie
// for it (nft_set_rbtree.c:795-797 at 940de590). A set that holds want already
// sends nothing.
func (s Set) Update(proto uint8, held, want []Interval) ([]Request, error) {
	was, err := s.elements(held)
	if err != nil {
		return nil, err
	}
	now, err := s.elements(want)
	if err != nil {
		return nil, err
	}
	before := units(was)
	kept := make(map[string]bool)
	for _, u := range before {
		kept[u.text()] = true
	}
	wanted := make(map[string]bool)
	var add []element
	for _, u := range units(now) {
		wanted[u.text()] = true
		if !kept[u.text()] {
			add = append(add, u...)
		}
	}
	var del []element
	for _, u := range before {
		if !wanted[u.text()] {
			del = append(del, u...)
		}
	}
	return append(s.lists(proto, unix.NFT_MSG_DELSETELEM, 0, del), s.lists(proto, unix.NFT_MSG_NEWSETELEM, unix.NLM_F_CREATE, add)...), nil
}

// unit is the elements that go or come together: an interval's start and its
// end, a start with no end for an interval running to the last key, the end
// nft writes at key zero, or a key of a set of keys
type unit []element

// units is elements, as elements writes them, in their units
func units(elements []element) []unit {
	var out []unit
	for i := 0; i < len(elements); i++ {
		end := i+1 < len(elements) && elements[i].flags&unix.NFT_SET_ELEM_INTERVAL_END == 0 && elements[i+1].flags&unix.NFT_SET_ELEM_INTERVAL_END != 0
		if end {
			out = append(out, unit(elements[i:i+2]))
			i++
			continue
		}
		out = append(out, unit(elements[i:i+1]))
	}
	return out
}

// text is u as its elements encode, which two units share only when they are
// the same elements
func (u unit) text() string {
	var out []byte
	for _, e := range u {
		out = append(out, e.encode()...)
	}
	return string(out)
}

// lists is the messages of kind carrying elements to s, as many as their
// size needs
func (s Set) lists(proto uint8, kind int, flags uint16, elements []element) []Request {
	var requests []Request
	var list []byte
	send := func() {
		body := PutAttrBE32(s.elementList(proto), unix.NFTA_SET_ELEM_LIST_SET_ID, s.ID)
		body = PutAttr(body, unix.NFTA_SET_ELEM_LIST_ELEMENTS|unix.NLA_F_NESTED, list)
		requests = append(requests, Request{Kind: Command(kind), Flags: flags, Body: body})
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
	return requests
}
