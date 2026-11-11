// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package nftables

import (
	"slices"
	"testing"

	"golang.org/x/sys/unix"
	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/netlink"
	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// owners is the three writers of Table as the model knows them, each chain,
// chain prefix, named set and ct timeout by the name its owner writes it
// under, written apart from any Scope
var owners = []struct {
	name     string
	chains   []string
	prefix   string
	sets     []string
	timeouts []string
}{
	{"translator", []string{"forward", "forward4", "forward6", "postrouting"}, "none_", []string{"flows4", "flows6"}, []string{"translated-udp4", "translated-tcp6"}},
	{"filter", []string{"antispoof", "mesh_entry"}, "", []string{"carved4", "carved6", "owned4", "owned6", "none4", "none6"}, nil},
	{"switch", []string{"fallback", "output"}, "", []string{"lan4", "forwarded", "lan6", "own4", "own6", "tcp_ports", "udp_ports"}, nil},
}

// ownerOf is the owner the model gives a chain, set or object name, -1 for a
// stranger's
func ownerOf(name string) int {
	for i, o := range owners {
		if slices.Contains(o.chains, name) || slices.Contains(o.sets, name) || slices.Contains(o.timeouts, name) || o.prefix != "" && len(name) > len(o.prefix) && name[:len(o.prefix)] == o.prefix {
			return i
		}
	}
	return -1
}

func ownerScope(i int) Scope {
	o := owners[i]
	return Scope{Chains: o.chains, Prefix: o.prefix, Sets: o.sets, Timeouts: o.timeouts}
}

// requestName is the table, chain, set or object a request names, by its kind
func requestName(r Request) string {
	attrs := map[uint16]uint16{
		unix.NFT_MSG_DELTABLE: unix.NFTA_TABLE_NAME, unix.NFT_MSG_NEWTABLE: unix.NFTA_TABLE_NAME,
		unix.NFT_MSG_DELCHAIN: unix.NFTA_CHAIN_NAME, unix.NFT_MSG_NEWCHAIN: unix.NFTA_CHAIN_NAME,
		unix.NFT_MSG_DELRULE: unix.NFTA_RULE_CHAIN,
		unix.NFT_MSG_DELSET:  unix.NFTA_SET_NAME, unix.NFT_MSG_DELOBJ: unix.NFTA_OBJ_NAME,
	}
	for kind, value := range (netlink.Message{Data: r.Body}).Attributes(SizeofNfgenmsg) {
		if kind == attrs[r.Kind&0xff] {
			return unix.ByteSliceToString(value)
		}
	}
	return ""
}

// A withdrawal over any listing of the table, by the table's last holder or
// another, deletes the table exactly where the owner is the last holder,
// every chain, named set and object in it is the owner's and no flag but
// dormant is set, and then as its one last request, names no other owner's
// or stranger's chain, set or object otherwise, flushes each of the owner's
// chains before it deletes any chain, set or object, deletes each of the
// owner's chains once but one a rule of a chain it does not flush goes to,
// and each of its sets and objects once, and sends nothing where the table
// holds nothing of the owner's
func TestWithdrawalTakesTheOwnersObjectsAlone(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		owner := hegel.Draw(ht, pbt.Spanning(0, len(owners)-1))
		var pool []string
		for _, o := range owners {
			pool = slices.Concat(pool, o.chains, []string{o.prefix + "192_0_2_0_24"}, o.sets, o.timeouts)
		}
		pool = slices.DeleteFunc(pool, func(name string) bool { return name == "192_0_2_0_24" })
		pool = append(pool, "other", "stranger_set", "none", "none_")
		l := listing{flags: hegel.Draw(ht, hegel.SampledFrom([]uint32{0, unix.NFT_TABLE_F_DORMANT, 0x2, 0x4}))}
		drawn := hegel.Draw(ht, hegel.Lists(hegel.SampledFrom(pool)).MaxSize(10))
		slices.Sort(drawn)
		for _, name := range slices.Compact(drawn) {
			i := ownerOf(name)
			switch {
			case i >= 0 && slices.Contains(owners[i].sets, name), name == "stranger_set":
				l.sets = append(l.sets, name)
			case i >= 0 && slices.Contains(owners[i].timeouts, name):
				l.objects = append(l.objects, object{kind: unix.NFT_OBJECT_CT_TIMEOUT, name: name})
			default:
				l.chains = append(l.chains, name)
			}
		}
		// a rule of a chain the withdrawal may or may not flush going to a chain of the prefix
		held := ""
		if len(l.chains) > 1 && hegel.Draw(ht, hegel.Booleans()) {
			from, to := l.chains[0], l.chains[len(l.chains)-1]
			l.rules = []Installed{{Chain: from, Expressions: Goto(to)}}
			if ownerOf(to) == owner && ownerOf(from) != owner {
				held = to
			}
		}
		s := ownerScope(owner)
		// the last holder and any other are swept, since a withdrawal branches on it
		for _, last := range []bool{false, true} {
			withdrawsAlone(ht, owner, l, held, last, s.withdrawal(l, last))
		}
	})
}

// withdrawsAlone fails ht where requests, the withdrawal of the owner at
// index owner over l, by the table's last holder where last, is other than
// TestWithdrawalTakesTheOwnersObjectsAlone says, held being the chain of the
// owner's a rule of a chain it does not flush goes to
func withdrawsAlone(ht *hegel.T, owner int, l listing, held string, last bool, requests []Request) {
	owned := 0
	for _, name := range slices.Concat(l.chains, l.sets) {
		if ownerOf(name) == owner {
			owned++
		}
	}
	for _, o := range l.objects {
		if ownerOf(o.name) == owner {
			owned++
		}
	}
	total := len(l.chains) + len(l.sets) + len(l.objects)
	if owned == 0 {
		if len(requests) != 0 {
			ht.Fatalf("over %+v holding nothing of the %s's the withdrawal sends %d requests", l, owners[owner].name, len(requests))
		}
		return
	}
	deletes := slices.IndexFunc(requests, func(r Request) bool { return r.Kind == Command(unix.NFT_MSG_DELTABLE) })
	if want := last && owned == total && l.flags&^unix.NFT_TABLE_F_DORMANT == 0; (deletes >= 0) != want {
		ht.Fatalf("over %+v the %s's withdrawal, the last holder's %v, deletes the table %v, want %v", l, owners[owner].name, last, deletes >= 0, want)
	}
	if deletes >= 0 {
		if deletes != len(requests)-1 {
			ht.Fatalf("the %s's withdrawal deletes the table at %d of its %d requests, want last", owners[owner].name, deletes, len(requests))
		}
		requests = requests[:deletes]
	}
	lastFlush, firstDelete := -1, len(requests)
	for i, r := range requests {
		name := requestName(r)
		if ownerOf(name) != owner {
			ht.Fatalf("the %s's withdrawal over %+v names %s, which is not its own", owners[owner].name, l, name)
		}
		if r.Kind == Command(unix.NFT_MSG_DELRULE) {
			lastFlush = i
		} else {
			firstDelete = min(firstDelete, i)
		}
		if r.Kind == Command(unix.NFT_MSG_DELCHAIN) && name == held {
			ht.Fatalf("the withdrawal deletes the chain %s a rule of chain %s goes to", name, l.rules[0].Chain)
		}
	}
	if lastFlush > firstDelete {
		ht.Fatalf("the withdrawal flushes at %d after a deletion at %d", lastFlush, firstDelete)
	}
	sent := func(kind int, name string) int {
		n := 0
		for _, r := range requests {
			if r.Kind == Command(kind) && requestName(r) == name {
				n++
			}
		}
		return n
	}
	for _, name := range l.chains {
		if ownerOf(name) != owner {
			continue
		}
		if sent(unix.NFT_MSG_DELRULE, name) == 0 {
			ht.Fatalf("the withdrawal leaves the chain %s of the %s's unflushed", name, owners[owner].name)
		}
		want := 1
		if name == held {
			want = 0
		}
		if sent(unix.NFT_MSG_DELCHAIN, name) != want {
			ht.Fatalf("the %s's withdrawal over %+v deletes its chain %s %d times, want %d", owners[owner].name, l, name, sent(unix.NFT_MSG_DELCHAIN, name), want)
		}
	}
	for _, name := range l.sets {
		if ownerOf(name) == owner && sent(unix.NFT_MSG_DELSET, name) != 1 {
			ht.Fatalf("the %s's withdrawal over %+v deletes its set %s %d times, want once", owners[owner].name, l, name, sent(unix.NFT_MSG_DELSET, name))
		}
	}
	for _, o := range l.objects {
		if ownerOf(o.name) == owner && sent(unix.NFT_MSG_DELOBJ, o.name) != 1 {
			ht.Fatalf("the %s's withdrawal over %+v deletes its object %s %d times, want once", owners[owner].name, l, o.name, sent(unix.NFT_MSG_DELOBJ, o.name))
		}
	}
}

// A rewrite over any stale subset of an owner's chains, sets and objects,
// beside any chains of its prefix it does not write, never deletes the table,
// names nothing but the owner's, makes and flushes each chain it writes,
// flushes each chain of the prefix and deletes none, deletes each stale chain,
// set and object once, each stale chain before it makes it, and each stale set
// or object after every flush
func TestRewriteDeletesTheStaleObjectsAlone(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		owner := hegel.Draw(ht, pbt.Spanning(0, len(owners)-1))
		o := owners[owner]
		var strays []string
		if o.prefix != "" {
			for _, name := range []string{o.prefix + "198_51_100_0_24", o.prefix + "203_0_113_0_24"} {
				if hegel.Draw(ht, hegel.Booleans()) {
					strays = append(strays, name)
				}
			}
		}
		var c, stale Contents
		for _, name := range o.chains {
			chain := Chain{Table: Table, Name: name, Type: "filter", Hook: unix.NF_INET_FORWARD}
			c.Chains = append(c.Chains, chain)
			if hegel.Draw(ht, hegel.Booleans()) {
				stale.Chains = append(stale.Chains, chain)
			}
		}
		for _, name := range o.sets {
			if hegel.Draw(ht, hegel.Booleans()) {
				stale.Sets = append(stale.Sets, Set{Table: Table, Name: name})
			}
		}
		for _, name := range o.timeouts {
			if hegel.Draw(ht, hegel.Booleans()) {
				stale.Timeouts = append(stale.Timeouts, Timeout{Table: Table, Name: name})
			}
		}
		requests := c.Rewrite(unix.NFPROTO_INET, stale, strays)
		lastFlush := -1
		for i, r := range requests {
			if r.Kind == Command(unix.NFT_MSG_DELRULE) {
				lastFlush = i
			}
		}
		sent := func(kind int, name string) int {
			n := 0
			for _, r := range requests {
				if r.Kind == Command(kind) && requestName(r) == name {
					n++
				}
			}
			return n
		}
		for _, chain := range c.Chains {
			if sent(unix.NFT_MSG_NEWCHAIN, chain.Name) != 1 || sent(unix.NFT_MSG_DELRULE, chain.Name) != 1 {
				ht.Fatalf("the %s's rewrite makes its chain %s %d times and flushes it %d times, want once each", o.name, chain.Name, sent(unix.NFT_MSG_NEWCHAIN, chain.Name), sent(unix.NFT_MSG_DELRULE, chain.Name))
			}
		}
		for _, name := range strays {
			if sent(unix.NFT_MSG_DELRULE, name) != 1 || sent(unix.NFT_MSG_DELCHAIN, name) != 0 {
				ht.Fatalf("the %s's rewrite flushes the chain %s it does not write %d times and deletes it %d times, want one flush", o.name, name, sent(unix.NFT_MSG_DELRULE, name), sent(unix.NFT_MSG_DELCHAIN, name))
			}
		}
		for _, chain := range stale.Chains {
			if sent(unix.NFT_MSG_DELCHAIN, chain.Name) != 1 {
				ht.Fatalf("the %s's rewrite deletes its stale chain %s %d times, want once", o.name, chain.Name, sent(unix.NFT_MSG_DELCHAIN, chain.Name))
			}
		}
		for _, set := range stale.Sets {
			if sent(unix.NFT_MSG_DELSET, set.Name) != 1 {
				ht.Fatalf("the %s's rewrite deletes its stale set %s %d times, want once", o.name, set.Name, sent(unix.NFT_MSG_DELSET, set.Name))
			}
		}
		for _, timeout := range stale.Timeouts {
			if sent(unix.NFT_MSG_DELOBJ, timeout.Name) != 1 {
				ht.Fatalf("the %s's rewrite deletes its stale object %s %d times, want once", o.name, timeout.Name, sent(unix.NFT_MSG_DELOBJ, timeout.Name))
			}
		}
		for i, r := range requests {
			name := requestName(r)
			switch r.Kind {
			case Command(unix.NFT_MSG_DELTABLE):
				ht.Fatal("a rewrite deletes the table")
			case Command(unix.NFT_MSG_NEWTABLE):
				continue
			case Command(unix.NFT_MSG_DELCHAIN):
				made := slices.IndexFunc(requests, func(r Request) bool { return r.Kind == Command(unix.NFT_MSG_NEWCHAIN) && requestName(r) == name })
				if made < i {
					ht.Fatalf("the rewrite deletes the chain %s at %d and makes it at %d", name, i, made)
				}
			case Command(unix.NFT_MSG_DELSET), Command(unix.NFT_MSG_DELOBJ):
				if i < lastFlush {
					ht.Fatalf("the rewrite deletes %s at %d, before its last flush at %d", name, i, lastFlush)
				}
			}
			if ownerOf(name) != owner {
				ht.Fatalf("the %s's rewrite names %s", o.name, name)
			}
		}
	})
}
