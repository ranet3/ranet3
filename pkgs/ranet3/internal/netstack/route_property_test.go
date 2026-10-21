// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package netstack

import (
	"fmt"
	"net/netip"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// entryKind is the kind of value one entry of a drawn table holds
type entryKind uint8

const (
	learnedEntry entryKind = iota
	heldEntry
	localEntry
	assignedEntry
)

// tableEntry is one entry of a drawn table, peer the index of the peer a learned one goes through
type tableEntry struct {
	source, destination netip.Prefix
	kind                entryKind
	peer                int
}

func (e tableEntry) GoString() string {
	what := [...]string{learnedEntry: "learned", heldEntry: "held", localEntry: "local", assignedEntry: "assigned"}[e.kind]
	if e.kind == learnedEntry {
		what = fmt.Sprintf("learned through peer %d", e.peer)
	}
	if e.source.IsValid() {
		return fmt.Sprintf("%v from %v %s", e.destination, e.source, what)
	}
	return fmt.Sprintf("%v %s", e.destination, what)
}

// matches is whether the entry applies to a packet from src to dst
// a missing source matches every address
func (e tableEntry) matches(src, dst netip.Addr) bool {
	return e.destination.Contains(dst) && (!e.source.IsValid() || e.source.Contains(src))
}

// routeModel is a drawn table as a plain list, one entry per key, the last one written for a key kept
type routeModel struct {
	entries []tableEntry
	peers   []*Peer
}

func (m *routeModel) set(e tableEntry) {
	e.source, e.destination = e.source.Masked(), e.destination.Masked()
	for i, held := range m.entries {
		if held.source == e.source && held.destination == e.destination {
			m.entries[i] = e
			return
		}
	}
	m.entries = append(m.entries, e)
}

// best is the entry RFC 9079 section 4 prefers among every entry matching a
// packet from src to dst, by "destination-first ordering, where routing table
// entry R1 is preferred to routing table entry R2 when either R1's destination
// prefix is more specific than R2's or the destination prefixes are equal and
// R1's source prefix is more specific than R2's". A missing source is less
// specific than every source prefix, its Bits being -1. A hold is a candidate
// like any entry, so a packet inside a held prefix lands on it rather than on
// a shorter one.
func (m *routeModel) best(src, dst netip.Addr) (tableEntry, bool) {
	var best tableEntry
	found := false
	for _, e := range m.entries {
		if !e.matches(src, dst) {
			continue
		}
		longer := e.destination.Bits() > best.destination.Bits() ||
			e.destination.Bits() == best.destination.Bits() && e.source.Bits() > best.source.Bits()
		if !found || longer {
			best, found = e, true
		}
	}
	return best, found
}

// answer resolves a packet from src to dst by the model
// the match carries the best entry's destination length
func (m *routeModel) answer(src, dst netip.Addr) (*Peer, Verdict, Match) {
	e, ok := m.best(src, dst)
	match := Match{Bits: e.destination.Bits()}
	switch {
	case !ok:
		return nil, RouteNone, Match{}
	case e.kind == heldEntry:
		return nil, RouteHeld, match
	case e.kind == localEntry, e.kind == assignedEntry:
		return nil, RouteLocal, match
	}
	return m.peers[e.peer], RoutePeer, match
}

// anchorNear keeps the first keep bits of address and draws the rest
func anchorNear(tc hegel.TestCase, address netip.Addr, keep int) netip.Addr {
	raw := address.AsSlice()
	fresh := hegel.Draw(tc, hegel.Binary(len(raw), len(raw)))
	for bit := keep; bit < len(raw)*8; bit++ {
		mask := byte(0x80) >> (bit % 8)
		raw[bit/8] = raw[bit/8]&^mask | fresh[bit/8]&mask
	}
	out, _ := netip.AddrFromSlice(raw)
	return out
}

// drawEntry draws one entry of the family of anchors, its prefixes near one
// of them so entries nest and diverge at a drawn depth, and a source or none
func drawEntry(tc hegel.TestCase, anchors []netip.Addr, peers int) tableEntry {
	width := anchors[0].BitLen()
	prefix := func() netip.Prefix {
		anchor := hegel.Draw(tc, hegel.SampledFrom(anchors))
		address := anchorNear(tc, anchor, hegel.Draw(tc, pbt.Spanning(0, width)))
		return netip.PrefixFrom(address, hegel.Draw(tc, pbt.Spanning(0, width)))
	}
	e := tableEntry{destination: prefix()}
	if hegel.Draw(tc, hegel.Booleans()) {
		e.source = prefix()
	}
	e.kind = hegel.Draw(tc, hegel.SampledFrom([]entryKind{learnedEntry, heldEntry, localEntry, assignedEntry}))
	e.peer = hegel.Draw(tc, hegel.Integers(0, peers-1))
	return e
}

// edges is the first and last address of p and the first beside it, where an
// entry starts to match and stops, and the same first address with a zone,
// which no prefix holds
func edges(p netip.Prefix) []netip.Addr {
	if !p.IsValid() {
		return nil
	}
	p = p.Masked()
	last := p.Addr().AsSlice()
	for bit := p.Bits(); bit < len(last)*8; bit++ {
		last[bit/8] |= byte(0x80) >> (bit % 8)
	}
	end, _ := netip.AddrFromSlice(last)
	out := []netip.Addr{p.Addr(), end}
	if bit := p.Bits() - 1; bit >= 0 {
		beside := p.Addr().AsSlice()
		beside[bit/8] ^= byte(0x80) >> (bit % 8)
		next, _ := netip.AddrFromSlice(beside)
		out = append(out, next)
	}
	if p.Addr().Is6() {
		out = append(out, p.Addr().WithZone("eth0"))
	}
	return out
}

// Resolve answers every packet as the plain list does under RFC 9079 section
// 4's "destination-first ordering", with each entry's own verdict and a peer
// only for a learned one. A hold never lets a packet through by a shorter
// entry, RFC 8966 section 3.5.4: "packets destined to an address within P MUST
// NOT be forwarded by following a route for a shorter prefix". The tables hold
// learned routes, holds and this node's own entries of both kinds, with and
// without source prefixes, in both families and with the IPv6 anchors
// sometimes an IPv4 one mapped, and each is asked from and to the edges of
// every entry it holds and from and to addresses drawn inside them and
// anywhere.
// the length answered is the preferred entry's destination
// shorter than the deepest destination holding the packet whenever every source there misses it
func TestResolveAgreesWithLongestMatchUnderTheHold(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		anchors4 := hegel.Draw(ht, hegel.Lists(hegel.IPAddresses().IPv4()).MinSize(1).MaxSize(3))
		anchors6 := hegel.Draw(ht, hegel.Lists(hegel.OneOf(
			hegel.Generator[netip.Addr](hegel.IPAddresses().IPv6()),
			hegel.Map(hegel.SampledFrom(anchors4), func(anchor netip.Addr) netip.Addr {
				return netip.AddrFrom16(anchor.As16())
			}),
		)).MinSize(1).MaxSize(3))
		m := &routeModel{peers: []*Peer{{ID: "a"}, {ID: "b"}, {ID: "c"}}}
		rt := NewRouteTable()
		count := hegel.Draw(ht, pbt.Spanning(1, 12))
		for range count {
			anchors := anchors6
			if hegel.Draw(ht, hegel.Booleans()) {
				anchors = anchors4
			}
			e := drawEntry(ht, anchors, len(m.peers))
			value := m.peers[e.peer]
			switch e.kind {
			case heldEntry:
				value = Unreachable
			case localEntry:
				value = Local
			case assignedEntry:
				value = Assigned
			}
			rt.Set(e.source, e.destination, value)
			m.set(e)
		}

		froms := []netip.Addr{{}}
		var tos []netip.Addr
		for _, e := range m.entries {
			froms = append(froms, edges(e.source)...)
			tos = append(tos, edges(e.destination)...)
		}
		for range 8 {
			e := hegel.Draw(ht, hegel.SampledFrom(m.entries))
			to := anchorNear(ht, e.destination.Addr(), e.destination.Bits())
			from := hegel.Draw(ht, hegel.IPAddresses())
			if e.source.IsValid() {
				from = anchorNear(ht, e.source.Addr(), e.source.Bits())
			}
			froms, tos = append(froms, from), append(tos, to, hegel.Draw(ht, hegel.IPAddresses()))
		}

		for _, to := range tos {
			for _, from := range froms {
				peer, verdict, match := rt.Resolve(from, to)
				if wantPeer, want, wantMatch := m.answer(from, to); peer != wantPeer || verdict != want || match != wantMatch {
					best := "no entry"
					if e, found := m.best(from, to); found {
						best = e.GoString()
					}
					ht.Fatalf("a packet from %v to %v resolved as verdict %d through %v under /%d, where the longest match is %s, in %#v",
						from, to, verdict, peer, match.Bits, best, m.entries)
				}
			}
		}
	})
}
