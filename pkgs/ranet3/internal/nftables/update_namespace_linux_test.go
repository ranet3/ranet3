// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package nftables

import (
	"math/rand/v2"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"testing"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/netnstest"
)

// updateMoves is how many moves the kernel test makes in each family
const updateMoves = 300

// Each of a run of moves between prefixes drawn from edgeBytes, so intervals
// overlap, touch, start at the first key and run to the last, and the next
// move half the time the last with one prefix put in or taken out, goes
// through nf_tables as Update's one transaction and leaves the set holding the
// wanted intervals, read back. Where no interval starts at the first key, a
// quarter of the moves put in a prefix from it, so the end at key zero goes.
// Half the moves go after a transaction adding a start the set holds, which
// nf_tables answers by setting the start cookie (__nft_rbtree_insert,
// nft_set_rbtree.c:460-465 at 940de590) and leaving it for a transaction
// begun on the same jiffy. Each family makes at least one move taking out the
// end at key zero after such a transaction.
func TestNftablesUpdateMovesASetInTheKernel(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmptyLoopbackDown(t)
	conn := dial(t)
	random := rand.New(rand.NewPCG(1, 2))
	draw := func(size int) netip.Prefix {
		raw := make([]byte, size)
		for i := range raw {
			raw[i] = edgeBytes[random.IntN(len(edgeBytes))]
		}
		prefix, err := addressOf(raw).Prefix(random.IntN(size*8 + 1))
		if err != nil {
			t.Fatal(err)
		}
		return prefix
	}
	for id, size := range []int{4, 16} {
		keyType := uint32(TypeIPv4Addr)
		if size == 16 {
			keyType = TypeIPv6Addr
		}
		s := Set{Table: "moved", Name: "moved" + string(rune('4'+id*2)), ID: uint32(id + 1), KeyType: keyType, KeyLen: uint32(size), Flags: unix.NFT_SET_INTERVAL}
		made, err := s.Create(unix.NFPROTO_INET)
		if err != nil {
			t.Fatal(err)
		}
		if err := conn.Batch([]Request{NewTable(unix.NFPROTO_INET, s.Table), made}); err != nil {
			t.Fatalf("make the set %s: %v", s.Name, err)
		}
		zero := netip.PrefixFrom(addressOf(make([]byte, size)), 0)
		fromZero := func(prefixes []netip.Prefix) bool {
			return slices.ContainsFunc(prefixes, func(p netip.Prefix) bool { return p.Contains(zero.Addr()) })
		}
		var was []netip.Prefix
		zeroGone := 0
		for move := range updateMoves {
			var now []netip.Prefix
			switch {
			case !fromZero(was) && random.IntN(4) == 0:
				prefix, err := zero.Addr().Prefix(random.IntN(size*8 + 1))
				if err != nil {
					t.Fatal(err)
				}
				now = append(slices.Clone(was), prefix)
			case random.IntN(2) == 0 && len(was) > 0:
				i := random.IntN(len(was))
				now = append(append(now, was[:i]...), was[i+1:]...)
			case random.IntN(2) == 0:
				now = append(append(now, was...), draw(size))
			default:
				for range random.IntN(9) {
					now = append(now, draw(size))
				}
			}
			held, err := s.elements(Prefixes(was))
			if err != nil {
				t.Fatal(err)
			}
			starts := slices.DeleteFunc(held, func(e element) bool { return e.flags&unix.NFT_SET_ELEM_INTERVAL_END != 0 })
			stale := len(starts) > 0 && random.IntN(2) == 0
			if stale {
				if err := conn.Batch(s.lists(unix.NFPROTO_INET, unix.NFT_MSG_NEWSETELEM, unix.NLM_F_CREATE, starts[random.IntN(len(starts)):][:1])); err != nil {
					t.Fatalf("move %d of %s: a start the set holds, added again: %v", move, s.Name, err)
				}
			}
			requests, err := s.Update(unix.NFPROTO_INET, Prefixes(was), Prefixes(now))
			if err != nil {
				t.Fatal(err)
			}
			if err := conn.Batch(requests); err != nil {
				t.Fatalf("move %d of %s from %s to %s, the start cookie set before %v: %v", move, s.Name, s.describe(Prefixes(was)), s.describe(Prefixes(now)), stale, err)
			}
			fault, err := s.ElementFault(conn, unix.NFPROTO_INET, Prefixes(now))
			if err != nil {
				t.Fatal(err)
			}
			if fault != "" {
				t.Fatalf("move %d of %s from %s: %s", move, s.Name, s.describe(Prefixes(was)), fault)
			}
			if stale && !fromZero(was) && fromZero(now) {
				zeroGone++
			}
			was = now
		}
		t.Logf("%s: %d moves, %d of them taking out the end at key zero after a start cookie was set", s.Name, updateMoves, zeroGone)
		if zeroGone == 0 {
			t.Errorf("%s: no move took out the end at key zero after a start cookie was set", s.Name)
		}
	}
}

// Intervals apart, a prefix joining two into one, the prefix gone, leaving
// them apart again, a prefix touching the last, and one from key zero, each
// coming and going, go through nf_tables as Update's one transaction each,
// back to back, and leave the set holding the wanted intervals, read back
func TestNftablesUpdateJoinsTwoIntervalsAndSplitsThemInTheKernel(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmptyLoopbackDown(t)
	conn := dial(t)
	s := Set{Table: "split", Name: "split6", ID: 1, KeyType: TypeIPv6Addr, KeyLen: 16, Flags: unix.NFT_SET_INTERVAL}
	made, err := s.Create(unix.NFPROTO_INET)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Batch([]Request{NewTable(unix.NFPROTO_INET, s.Table), made}); err != nil {
		t.Fatalf("make the set: %v", err)
	}
	prefixes := func(raw ...string) []netip.Prefix {
		var out []netip.Prefix
		for _, p := range raw {
			out = append(out, netip.MustParsePrefix(p))
		}
		return out
	}
	apart := prefixes("2001:db8::/64", "2001:db8:0:2::/64", "2001:db8:0:4::/64")
	joined := prefixes("2001:db8::/64", "2001:db8:0:1::/64", "2001:db8:0:2::/64", "2001:db8:0:4::/64")
	grown := prefixes("2001:db8::/64", "2001:db8:0:2::/64", "2001:db8:0:4::/64", "2001:db8:0:5::/64")
	zero := prefixes("::/64", "2001:db8::/64", "2001:db8:0:2::/64", "2001:db8:0:4::/64")
	var was []netip.Prefix
	for _, step := range []struct {
		what string
		now  []netip.Prefix
	}{
		{"the intervals apart", apart},
		{"a prefix joining two", joined},
		{"it gone, leaving them apart", apart},
		{"a prefix joining two again", joined},
		{"it gone again", apart},
		{"a prefix touching the last", grown},
		{"it gone", apart},
		{"a prefix from key zero", zero},
		{"it gone", apart},
	} {
		requests, err := s.Update(unix.NFPROTO_INET, Prefixes(was), Prefixes(step.now))
		if err != nil {
			t.Fatal(err)
		}
		if err := conn.Batch(requests); err != nil {
			t.Fatalf("%s, from %s to %s: %v", step.what, s.describe(Prefixes(was)), s.describe(Prefixes(step.now)), err)
		}
		fault, err := s.ElementFault(conn, unix.NFPROTO_INET, Prefixes(step.now))
		if err != nil {
			t.Fatal(err)
		}
		if fault != "" {
			t.Fatalf("%s: %s", step.what, fault)
		}
		was = step.now
	}
}
