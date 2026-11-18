// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package nftables

import (
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/netlink"
	"ranet3.com/pkgs/ranet3/internal/netnstest"
)

// retiredTable is a table holding an owner's chain mine, another writer's
// chain other and a named verdict map, object map and counter of another
// writer's, and under retired names: the chains loose and free, which only
// mine and loose go to, jumped, which other jumps to, and mapped, which the
// verdict map holds, the set freeset, which only mine reads, lookedup and
// added, which other looks up and adds to, and objects, the object map, which
// other reads, the ct timeout freeobj, which only mine attaches and whose name
// the counter other counts by shares, attached, which other attaches, and
// inmap, which the object map holds
const retiredTable = `table inet ranet3 {
	ct timeout freeobj { protocol udp; l3proto ip; policy = { unreplied: 120s, replied: 120s }; }
	ct timeout attached { protocol udp; l3proto ip; policy = { unreplied: 120s, replied: 120s }; }
	ct timeout inmap { protocol udp; l3proto ip; policy = { unreplied: 120s, replied: 120s }; }
	counter freeobj { }
	set freeset { type ipv4_addr; }
	set lookedup { type ipv4_addr; }
	set added { type ipv4_addr; flags dynamic; }
	chain free { }
	chain loose { jump free; }
	chain jumped { }
	chain mapped { }
	map verdicts { type inet_service : verdict; elements = { 80 : jump mapped } }
	chain mine { jump free; ip saddr @freeset accept; meta l4proto udp ct timeout set "freeobj"; }
	chain other { jump jumped; ip saddr @lookedup accept; add @added { ip saddr }; meta l4proto udp ct timeout set "attached"; counter name "freeobj"; }
}
`

// Each object of an owner's retired names the table holds is found, chains,
// then sets, then ct timeouts, with what holds it once the owner's chains and
// the retired chains are flushed: another writer's rule or named map for a
// chain, its lookup, dynset or objref map for a set, and its objref or a map's
// element for a ct timeout, while a rule of the owner's chain or of a retired
// chain holds nothing, nor does an objref of an object of another type under
// the timeout's name. Retire in a transaction that flushes those chains first
// deletes each that nothing holds and leaves the rest, and a table holding none
// of the names gives none.
func TestNftablesFindsWhatHoldsARetiredObject(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmpty(t)
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Fatal("the table is written through nft, which is not on the path")
	}
	load := exec.Command(nft, "-f", "-")
	load.Stdin = strings.NewReader(retiredTable)
	if out, err := load.CombinedOutput(); err != nil {
		t.Fatalf("nft -f: %v\n%s", err, out)
	}
	conn := dial(t)
	// nft writes no map of ct timeouts, so the object map is made by its requests
	objects, err := Set{Table: Table, Name: "objects", ID: 1, KeyType: TypeInetService, KeyLen: 2, Flags: unix.NFT_SET_OBJECT}.Create(unix.NFPROTO_INET)
	if err != nil {
		t.Fatal(err)
	}
	objects.Body = PutAttrBE32(objects.Body, unix.NFTA_SET_OBJ_TYPE, unix.NFT_OBJECT_CT_TIMEOUT)
	element := netlink.PutAttr(nil, unix.NFTA_SET_ELEM_KEY|unix.NLA_F_NESTED, netlink.PutAttr(nil, unix.NFTA_DATA_VALUE, []byte{0, 53}))
	element = netlink.PutAttrString(element, unix.NFTA_SET_ELEM_OBJREF, "inmap")
	elements := netlink.PutAttrString(netlink.PutAttrString(PutNfgenmsg(nil, unix.NFPROTO_INET), unix.NFTA_SET_ELEM_LIST_TABLE, Table), unix.NFTA_SET_ELEM_LIST_SET, "objects")
	elements = netlink.PutAttr(elements, unix.NFTA_SET_ELEM_LIST_ELEMENTS|unix.NLA_F_NESTED, netlink.PutAttr(nil, unix.NFTA_LIST_ELEM|unix.NLA_F_NESTED, element))
	if err := conn.Batch([]Request{objects, {Kind: Command(unix.NFT_MSG_NEWSETELEM), Flags: unix.NLM_F_CREATE, Body: elements}}); err != nil {
		t.Fatalf("make the map of objects: %v", err)
	}
	// other's rule attaching the timeout its UDP destination port maps to in objects
	mapped := PutAttrBE32(nil, unix.NFTA_OBJREF_SET_SREG, unix.NFT_REG_1)
	mapped = netlink.PutAttrString(mapped, unix.NFTA_OBJREF_SET_NAME, "objects")
	reads, err := Chain{Table: Table, Name: "other"}.Rule(unix.NFPROTO_INET, "udp dport map @objects", [][]byte{TransportLoad(2, 2), Expression("objref", mapped)})
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Batch([]Request{reads}); err != nil {
		t.Fatalf("write the rule reading the map of objects: %v", err)
	}
	old := Scope{Chains: []string{"loose", "free", "jumped", "mapped", "absent"}, Sets: []string{"freeset", "lookedup", "added", "objects", "absent"}, Timeouts: []string{"freeobj", "attached", "inmap", "absent"}}
	owner := Scope{Chains: []string{"mine"}}
	got, err := Leftovers(conn, old, owner)
	if err != nil {
		t.Fatal(err)
	}
	want := []Retired{
		{"chain", "loose", ""}, {"chain", "free", ""}, {"chain", "jumped", "chain other"}, {"chain", "mapped", "map verdicts"},
		{"set", "freeset", ""}, {"set", "lookedup", "chain other"}, {"set", "added", "chain other"}, {"set", "objects", "chain other"},
		{"ct timeout", "freeobj", ""}, {"ct timeout", "attached", "chain other"}, {"ct timeout", "inmap", "a map"},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("the leftovers read %+v, want %+v", got, want)
	}
	requests := []Request{Chain{Table: Table, Name: "mine"}.Flush(unix.NFPROTO_INET)}
	for _, name := range old.Chains[:4] {
		requests = append(requests, Chain{Table: Table, Name: name}.Flush(unix.NFPROTO_INET))
	}
	if err := conn.Batch(append(requests, Retire(got)...)); err != nil {
		t.Fatalf("the transaction that retires the leftovers: %v", err)
	}
	left, err := Leftovers(conn, old, owner)
	if err != nil {
		t.Fatal(err)
	}
	held := slices.DeleteFunc(slices.Clone(want), func(r Retired) bool { return r.HeldBy == "" })
	if !slices.Equal(left, held) {
		t.Errorf("after the transaction the leftovers read %+v, want those held, %+v", left, held)
	}
	if none, err := Leftovers(conn, Scope{Chains: []string{"absent"}, Sets: []string{"absent"}, Timeouts: []string{"absent"}}, owner); err != nil || none != nil {
		t.Errorf("names the table does not hold read as leftovers %+v (%v), want none", none, err)
	}
}

// A leftover's fault names its kind, its name and its owner, and what holds
// it and until when where anything does
func TestRetiredFaultNamesWhatHoldsIt(t *testing.T) {
	for _, c := range []struct {
		r    Retired
		want string
	}{
		{Retired{"chain", "jumped", ""}, "its chain jumped is not one the filter writes"},
		{Retired{"chain", "jumped", "chain other"}, "its chain jumped is not one the filter writes, and chain other holds a rule going to it, so it stays until that rule goes"},
		{Retired{"chain", "mapped", "map verdicts"}, "its chain mapped is not one the filter writes, and map verdicts holds an element going to it, so it stays until that element goes"},
		{Retired{"set", "lookedup", "chain other"}, "its set lookedup is not one the filter writes, and chain other holds a rule using it, so it stays until that rule goes"},
		{Retired{"ct timeout", "inmap", "a map"}, "its ct timeout inmap is not one the filter writes, and a map holds an element using it, so it stays until that element goes"},
	} {
		if got := c.r.Fault("the filter"); got != c.want {
			t.Errorf("%+v reads %q, want %q", c.r, got, c.want)
		}
	}
}
