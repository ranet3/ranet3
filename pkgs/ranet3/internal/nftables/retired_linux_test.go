// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package nftables

import (
	"errors"
	"os"
	"os/exec"
	"reflect"
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
	got, err := Leftovers(conn, nil, old, owner)
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
	left, err := Leftovers(conn, nil, old, owner)
	if err != nil {
		t.Fatal(err)
	}
	held := slices.DeleteFunc(slices.Clone(want), func(r Retired) bool { return r.HeldBy == "" })
	if !slices.Equal(left, held) {
		t.Errorf("after the transaction the leftovers read %+v, want those held, %+v", left, held)
	}
	if none, err := Leftovers(conn, nil, Scope{Chains: []string{"absent"}, Sets: []string{"absent"}, Timeouts: []string{"absent"}}, owner); err != nil || none != nil {
		t.Errorf("names the table does not hold read as leftovers %+v (%v), want none", none, err)
	}
}

// boundObjects is another writer's transaction that makes under name a binding
// chain, or with set an anonymous set holding 127.0.0.0/8, and binds it by a
// line at the head of from: a goto, or a lookup
func boundObjects(t *testing.T, from Chain, name string, set bool) []Request {
	t.Helper()
	var made []Request
	var line [][]byte
	if set {
		anonymous := Set{Table: Table, Name: name, ID: 1, KeyType: TypeIPv4Addr, KeyLen: 4, Flags: unix.NFT_SET_INTERVAL | unix.NFT_SET_ANONYMOUS | unix.NFT_SET_CONSTANT}
		create, err := anonymous.Create(unix.NFPROTO_INET)
		if err != nil {
			t.Fatal(err)
		}
		filled, err := anonymous.Fill(unix.NFPROTO_INET, Prefixes(prefixList("127.0.0.0/8")))
		if err != nil {
			t.Fatal(err)
		}
		made = append([]Request{create}, filled...)
		line = slices.Concat(NFProto(unix.NFPROTO_IPV4), [][]byte{DestinationLoad(unix.NFPROTO_IPV4), Lookup(anonymous, false)}, CountedDrop())
	} else {
		chain := Chain{Table: Table, Name: name, Hook: NoHook}
		create := chain.Create(unix.NFPROTO_INET)
		create.Body = PutAttrBE32(create.Body, chainFlags, chainBinding)
		drop, err := chain.Rule(unix.NFPROTO_INET, "theirs", CountedDrop())
		if err != nil {
			t.Fatal(err)
		}
		made = []Request{create, drop}
		line = [][]byte{Goto(name)}
	}
	bind, err := from.Rule(unix.NFPROTO_INET, "theirs", line)
	if err != nil {
		t.Fatal(err)
	}
	// with no NLM_F_APPEND nf_tables puts the line at the head of the chain
	bind.Flags = unix.NLM_F_CREATE
	return append(made, bind)
}

// bindingTo is another writer's transaction that makes a binding chain under
// name holding line, and binds it by a goto at the head of from
func bindingTo(t *testing.T, from Chain, name string, line [][]byte) []Request {
	t.Helper()
	chain := Chain{Table: Table, Name: name, Hook: NoHook}
	create := chain.Create(unix.NFPROTO_INET)
	create.Body = PutAttrBE32(create.Body, chainFlags, chainBinding)
	held, err := chain.Rule(unix.NFPROTO_INET, "theirs", line)
	if err != nil {
		t.Fatal(err)
	}
	return []Request{create, held, headLine(t, from, [][]byte{Goto(name)})}
}

// headLine is another writer's line at the head of chain
func headLine(t *testing.T, chain Chain, line [][]byte) Request {
	t.Helper()
	rule, err := chain.Rule(unix.NFPROTO_INET, "theirs", line)
	if err != nil {
		t.Fatal(err)
	}
	// with no NLM_F_APPEND nf_tables puts the line at the head of the chain
	rule.Flags = unix.NLM_F_CREATE
	return rule
}

// sendLoopback sends one datagram from 127.0.0.1 to 127.0.0.2, which a drop at
// output refuses with EPERM
func sendLoopback() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return unix.Sendto(fd, []byte("probe"), 0, &unix.SockaddrInet4{Port: 9, Addr: [4]byte{127, 0, 0, 2}})
}

// A binding chain under a retired name that another writer binds from a chain
// of its own is no chain the owner's transaction flushes, so the regular chain
// under another retired name it goes to is a leftover held by it, named by the
// chain that binds it, and the
// regular chain of the owner's prefix that a binding chain of that prefix goes
// to stays through the withdrawal. Nor is a regular chain of that writer's
// that a line of the owner's chain goes to, so a set under a retired name it
// reads is held by it. The owner's transaction and the withdrawal commit, and each
// takes out the drop that writer put at the head of the owner's chain.
func TestNftablesCountsABindingChainFlushedOnlyWithItsBinder(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmpty(t)
	conn, another := dial(t), dial(t)
	mine := Chain{Table: Table, Name: "mine", Type: "filter", Hook: unix.NF_INET_LOCAL_OUT, Priority: 0}
	other := Chain{Table: Table, Name: "other", Type: "filter", Hook: unix.NF_INET_LOCAL_OUT, Priority: 1}
	if err := conn.Batch([]Request{NewTable(unix.NFPROTO_INET, Table), mine.Create(unix.NFPROTO_INET)}); err != nil {
		t.Fatalf("the owner's chain: %v", err)
	}
	reading := Chain{Table: Table, Name: "reading", Hook: NoHook}
	oldset := Set{Table: Table, Name: "oldset", ID: 1, KeyType: TypeIPv4Addr, KeyLen: 4}
	madeSet, err := oldset.Create(unix.NFPROTO_INET)
	if err != nil {
		t.Fatal(err)
	}
	reads, err := reading.Rule(unix.NFPROTO_INET, "theirs", slices.Concat(NFProto(unix.NFPROTO_IPV4), [][]byte{DestinationLoad(unix.NFPROTO_IPV4), Lookup(oldset, false)}))
	if err != nil {
		t.Fatal(err)
	}
	requests := slices.Concat([]Request{other.Create(unix.NFPROTO_INET), Chain{Table: Table, Name: "old2", Hook: NoHook}.Create(unix.NFPROTO_INET), Chain{Table: Table, Name: "none_y", Hook: NoHook}.Create(unix.NFPROTO_INET)},
		[]Request{reading.Create(unix.NFPROTO_INET), madeSet, reads, headLine(t, mine, [][]byte{Goto(reading.Name)})},
		bindingTo(t, other, "gone", [][]byte{Goto("old2")}), bindingTo(t, other, "none_x", [][]byte{Goto("none_y")}), []Request{headLine(t, mine, CountedDrop())})
	if err := another.Batch(requests); err != nil {
		t.Fatalf("another writer's chains, binding chains, set and drop: %v", err)
	}
	if err := sendLoopback(); !errors.Is(err, unix.EPERM) {
		t.Fatalf("with the drop a datagram left with %v, want EPERM", err)
	}
	old, owner := Scope{Chains: []string{"gone", "old2"}, Sets: []string{oldset.Name}}, Scope{Chains: []string{"mine"}, Prefix: "none_"}
	held := []Retired{{"chain", "gone", "chain other"}, {"chain", "old2", "chain other"}, {"set", oldset.Name, "chain reading"}}
	leftovers, err := Leftovers(conn, nil, old, owner)
	if err != nil || !slices.Equal(leftovers, held) {
		t.Fatalf("the leftovers read %+v (%v), want %+v", leftovers, err, held)
	}
	pass := []Request{mine.Flush(unix.NFPROTO_INET), Chain{Table: Table, Name: "old2"}.Flush(unix.NFPROTO_INET)}
	if err := conn.Batch(append(pass, Retire(leftovers)...)); err != nil {
		t.Errorf("the owner's transaction: %v", err)
	}
	if err := sendLoopback(); err != nil {
		t.Errorf("after the owner's transaction a datagram left with %v, want sent", err)
	}
	if left, err := Leftovers(conn, nil, old, owner); err != nil || !slices.Equal(left, held) {
		t.Errorf("after the owner's transaction the leftovers read %+v (%v), want %+v", left, err, held)
	}
	if err := another.Batch([]Request{headLine(t, mine, CountedDrop())}); err != nil {
		t.Fatalf("another writer's drop again: %v", err)
	}
	var hold Hold
	if _, err := hold.Withdraw(conn, owner); err != nil {
		t.Errorf("the withdrawal: %v", err)
	}
	if err := sendLoopback(); err != nil {
		t.Errorf("after the withdrawal a datagram left with %v, want sent", err)
	}
	if names := chainNames(t, conn); !slices.Equal(names, []string{"other", "old2", "none_y", "reading", "gone", "none_x"}) {
		t.Errorf("after the withdrawal the table holds the chains %v, want other, old2, none_y, reading, gone and none_x", names)
	}
}

// chainNames is the name of every chain of Table a dump lists, binding chains
// among them
func chainNames(t *testing.T, conn *Conn) []string {
	t.Helper()
	replies, err := conn.Dump(Command(unix.NFT_MSG_GETCHAIN), PutNfgenmsg(nil, unix.NFPROTO_INET))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, reply := range replies {
		if table, name, _, _, _ := DecodeChain(reply); table == Table {
			out = append(out, name)
		}
	}
	return out
}

// A binding chain and an anonymous set another writer makes under an owner's
// retired names are left out of what TableChains lists and of the leftovers
// where a line in the owner's chain binds them, and are leftovers held by
// another writer's chain where a line there binds them. The owner's
// transaction, which flushes its chain and each retired chain TableChains
// lists and retires the leftovers, commits, takes the first two out with the
// line and keeps the others, which still read as leftovers. A withdrawal of
// names some of which binding chains carry commits the same way.
func TestNftablesLeavesWhatItsFlushTakesOutToIt(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmpty(t)
	conn, another := dial(t), dial(t)
	mine := Chain{Table: Table, Name: "mine", Type: "filter", Hook: unix.NF_INET_LOCAL_OUT, Priority: 0}
	other := Chain{Table: Table, Name: "other", Type: "filter", Hook: unix.NF_INET_LOCAL_OUT, Priority: 1}
	if err := conn.Batch([]Request{NewTable(unix.NFPROTO_INET, Table), mine.Create(unix.NFPROTO_INET)}); err != nil {
		t.Fatalf("the owner's chain: %v", err)
	}
	requests := slices.Concat([]Request{other.Create(unix.NFPROTO_INET)},
		boundObjects(t, mine, "gone", false), boundObjects(t, other, "kept", false), boundObjects(t, mine, "goneset", true), boundObjects(t, other, "keptset", true))
	if err := another.Batch(requests); err != nil {
		t.Fatalf("another writer's binding chains and anonymous sets: %v", err)
	}
	old, owner := Scope{Chains: []string{"gone", "kept"}, Sets: []string{"goneset", "keptset"}}, Scope{Chains: []string{"mine"}}
	if listed, err := TableChains(conn, unix.NFPROTO_INET, Table); err != nil || !slices.Equal(listed, []string{"mine", "other"}) {
		t.Errorf("TableChains lists %v (%v), want mine and other", listed, err)
	}
	held := []Retired{{"chain", "kept", "chain other"}, {"set", "keptset", "chain other"}}
	leftovers, err := Leftovers(conn, nil, old, owner)
	if err != nil || !slices.Equal(leftovers, held) {
		t.Fatalf("the leftovers read %+v (%v), want %+v", leftovers, err, held)
	}
	listed, err := TableChains(conn, unix.NFPROTO_INET, Table)
	if err != nil {
		t.Fatal(err)
	}
	pass := []Request{mine.Flush(unix.NFPROTO_INET)}
	for _, name := range old.Chains {
		if slices.Contains(listed, name) {
			pass = append(pass, Chain{Table: Table, Name: name}.Flush(unix.NFPROTO_INET))
		}
	}
	if err := conn.Batch(append(pass, Retire(leftovers)...)); err != nil {
		t.Errorf("the owner's transaction: %v", err)
	}
	if left, err := Leftovers(conn, nil, old, owner); err != nil || !slices.Equal(left, held) {
		t.Errorf("after the owner's transaction the leftovers read %+v (%v), want %+v", left, err, held)
	}
	if names := chainNames(t, conn); !slices.Equal(names, []string{"mine", "other", "kept"}) {
		t.Errorf("after the owner's transaction the table holds the chains %v, want mine, other and kept", names)
	}
	if err := another.Batch(boundObjects(t, mine, "again", false)); err != nil {
		t.Fatalf("another writer's binding chain again: %v", err)
	}
	var hold Hold
	if _, err := hold.Withdraw(conn, Scope{Chains: []string{"mine", "gone", "again", "kept"}}); err != nil {
		t.Fatalf("the withdrawal: %v", err)
	}
	if names := chainNames(t, conn); !slices.Equal(names, []string{"other", "kept"}) {
		t.Errorf("after the withdrawal the table holds the chains %v, want other and kept", names)
	}
}

// readTable holds under retired names the chain loose, the set freeset and the
// ct timeout freeobj, which nothing holds
const readTable = `table inet ranet3 {
	ct timeout freeobj { protocol udp; l3proto ip; policy = { unreplied: 120s, replied: 120s }; }
	set freeset { type ipv4_addr; }
	chain loose { }
}
`

// Leftovers finds the same objects whether or not its owner read the tables,
// dumps the tables only where it did not, then nothing more where the family
// holds no table, and otherwise one dump of each kind its scope names and none
// of what holds an object where it finds none
func TestLeftoversDumpTheTablesOnlyWhereTheOwnerReadNone(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmpty(t)
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Fatal("the table is written through nft, which is not on the path")
	}
	load := exec.Command(nft, "-f", "-")
	load.Stdin = strings.NewReader(readTable)
	if out, err := load.CombinedOutput(); err != nil {
		t.Fatalf("nft -f: %v\n%s", err, out)
	}
	conn := dial(t)
	tables, err := Tables(conn, Table)
	if err != nil {
		t.Fatal(err)
	}
	owner := Scope{Chains: []string{"mine"}}
	retired := Scope{Chains: []string{"loose"}, Sets: []string{"freeset"}, Timeouts: []string{"freeobj"}}
	want := []Retired{{"chain", "loose", ""}, {"set", "freeset", ""}, {"ct timeout", "freeobj", ""}}
	for _, read := range []map[uint8]uint32{tables, nil} {
		if got, err := Leftovers(conn, read, retired, owner); err != nil || !slices.Equal(got, want) {
			t.Errorf("with tables %v the leftovers read %+v (%v), want %+v", read, got, err, want)
		}
	}
	absent := Scope{Chains: []string{"absent"}, Sets: []string{"absent"}, Timeouts: []string{"absent"}}
	type count struct {
		name   string
		tables map[uint8]uint32
		old    Scope
		dumps  uint32
	}
	counts := func(cases []count) {
		for _, c := range cases {
			// one sequence number for each request the socket sends
			before := conn.link.Next()
			none, err := Leftovers(conn, c.tables, c.old, owner)
			if sent := conn.link.Next() - before - 1; err != nil || none != nil || sent != c.dumps {
				t.Errorf("%s: names the table does not hold read as leftovers %+v (%v) in %d dumps, want none in %d", c.name, none, err, sent, c.dumps)
			}
		}
	}
	counts([]count{
		{"the owner's tables and every kind", tables, absent, 3},
		{"no tables and every kind", nil, absent, 4},
		{"the owner's tables and chains", tables, Scope{Chains: absent.Chains}, 1},
		{"the owner's tables and sets", tables, Scope{Sets: absent.Sets}, 1},
		{"the owner's tables and ct timeouts", tables, Scope{Timeouts: absent.Timeouts}, 1},
	})
	if out, err := exec.Command(nft, "delete", "table", "inet", Table).CombinedOutput(); err != nil {
		t.Fatalf("nft delete table: %v\n%s", err, out)
	}
	gone, err := Tables(conn, Table)
	if err != nil {
		t.Fatal(err)
	}
	counts([]count{
		{"the owner's tables without the table", gone, absent, 0},
		{"no tables without the table", nil, absent, 1},
	})
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
	read := "its set s reads back with key type 7 of 4 bytes, flags 0x0, size 10 and comment \"\", where key type 7 of 4 bytes, flags 0x0, size 0 and comment \"\" were written"
	if got, want := (Retired{Kind: "set", Name: "s", HeldBy: "chain other"}).stays(read), read+", and chain other holds a rule using it, so it stays until that rule goes"; got != want {
		t.Errorf("a stale set's fault with its holder reads %q, want %q", got, want)
	}
	if got := (Retired{Kind: "set", Name: "s"}).stays(read); got != read {
		t.Errorf("a stale set's fault with no holder reads %q, want %q", got, read)
	}
}

// staleTable holds, beside the owner's chain mine, a regular chain c where the
// owner writes a base chain, the sets s with a size, small with a size of one,
// f with no interval flag and free with a size, and the ct timeouts t and m
// with other timeouts and p of another protocol than the owner writes: another
// writer's chain other goes to c, uses s, small and f and attaches t and p,
// mine alone uses free, and no rule attaches m
const staleTable = `table inet ranet3 {
	ct timeout t { protocol udp; l3proto ip; policy = { unreplied: 30s, replied: 30s }; }
	ct timeout m { protocol udp; l3proto ip; policy = { unreplied: 30s, replied: 30s }; }
	ct timeout p { protocol tcp; l3proto ip; policy = { established: 100s }; }
	set s { type ipv4_addr; size 10; }
	set small { type ipv4_addr; size 1; }
	set f { type ipv4_addr; }
	set free { type ipv4_addr; size 10; }
	chain c { }
	chain mine { ip daddr @free accept; ip daddr @s accept; }
	chain other { jump c; ip saddr @s accept; ip saddr @small accept; ip saddr @f accept; meta l4proto udp ct timeout set "t"; meta l4proto tcp ct timeout set "p"; }
}
`

// A stale chain, set or ct timeout another writer's rule holds reads back with
// what holds it, and stays stale, but for a set that differs in its size alone
// where that size holds the owner's elements, and a ct timeout in its timeouts
// alone, which the read leaves out of stale, the timeout m among them, which
// an element of another writer's map of objects alone holds, so the owner's
// transaction over m with its create commits. A set whose size is below the
// count of the owner's elements stays stale with its holder named. One only
// the owner's own chain uses stays stale with no holder. The owner's
// transaction over what stays stale is refused, and once the other writer's
// chain is flushed every one of them reads stale with no holder and the
// transaction commits.
func TestNftablesReadNamesWhatHoldsAStaleObject(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmpty(t)
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Fatal("the table is written through nft, which is not on the path")
	}
	load := exec.Command(nft, "-f", "-")
	load.Stdin = strings.NewReader(staleTable)
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
	element = netlink.PutAttrString(element, unix.NFTA_SET_ELEM_OBJREF, "m")
	elements := netlink.PutAttrString(netlink.PutAttrString(PutNfgenmsg(nil, unix.NFPROTO_INET), unix.NFTA_SET_ELEM_LIST_TABLE, Table), unix.NFTA_SET_ELEM_LIST_SET, "objects")
	elements = netlink.PutAttr(elements, unix.NFTA_SET_ELEM_LIST_ELEMENTS|unix.NLA_F_NESTED, netlink.PutAttr(nil, unix.NFTA_LIST_ELEM|unix.NLA_F_NESTED, element))
	if err := conn.Batch([]Request{objects, {Kind: Command(unix.NFT_MSG_NEWSETELEM), Flags: unix.NLM_F_CREATE, Body: elements}}); err != nil {
		t.Fatalf("make the map of objects: %v", err)
	}
	c := Chain{Table: Table, Name: "c", Type: "filter", Hook: unix.NF_INET_LOCAL_OUT, Priority: 0}
	mine := Chain{Table: Table, Name: "mine", Hook: NoHook}
	set := func(name string, flags uint32) Set {
		return Set{Table: Table, Name: name, ID: 1, KeyType: TypeIPv4Addr, KeyLen: 4, Flags: flags}
	}
	s, f, free := set("s", 0), set("f", unix.NFT_SET_INTERVAL), set("free", 0)
	timeout := func(name string) Timeout {
		return Timeout{Table: Table, Name: name, L3Proto: unix.NFPROTO_IPV4, L4Proto: unix.IPPROTO_UDP, Policy: []uint32{120, 120}}
	}
	contents := Contents{Chains: []Chain{c, mine}, Sets: []Set{s, f, free}, Timeouts: []Timeout{timeout("t"), timeout("p")}}
	read := func(of Contents) Readback {
		t.Helper()
		tables, err := Tables(conn, Table)
		if err != nil {
			t.Fatal(err)
		}
		read, err := of.Read(conn, tables, unix.NFPROTO_INET, contents.Scope())
		if err != nil {
			t.Fatal(err)
		}
		return read
	}
	rule := ", and chain other holds a rule using it, so it stays until that rule goes"
	two := []Interval{Key([]byte{192, 0, 2, 1}), Key([]byte{192, 0, 2, 2})}
	for _, x := range []struct {
		name  string
		of    Contents
		stale bool
		held  string
	}{
		{"chain c", Contents{Chains: []Chain{c}}, true, ", and chain other holds a rule going to it, so it stays until that rule goes"},
		{"set s", Contents{Sets: []Set{s}}, false, rule},
		{"set s of size 10 for two elements", Contents{Sets: []Set{s}, Elements: map[string][]Interval{"s": two}}, false, rule},
		{"set small of size 1 for two elements", Contents{Sets: []Set{set("small", 0)}, Elements: map[string][]Interval{"small": two}}, true, rule},
		{"set f", Contents{Sets: []Set{f}}, true, rule},
		{"set free", Contents{Sets: []Set{free}}, true, `size 0 and comment "" were written`},
		{"ct timeout t", Contents{Timeouts: []Timeout{timeout("t")}}, false, rule},
		{"ct timeout p", Contents{Timeouts: []Timeout{timeout("p")}}, true, rule},
		{"ct timeout m", Contents{Timeouts: []Timeout{timeout("m")}}, false, ", and a map holds an element using it, so it stays until that element goes"},
	} {
		if got := read(x.of); got.Remake() != x.stale || !strings.HasSuffix(got.Fault, x.held) {
			t.Errorf("%s reads back with %q, stale %v, want stale %v and a fault ending %q", x.name, got.Fault, got.Remake(), x.stale, x.held)
		}
	}
	mapped := Contents{Timeouts: []Timeout{timeout("m")}}
	if err := conn.Batch(append(mapped.Rewrite(unix.NFPROTO_INET, read(mapped).Stale, nil), timeout("m").Create(unix.NFPROTO_INET))); err != nil {
		t.Errorf("the owner's transaction over ct timeout m with its create: %v", err)
	}
	got := read(contents)
	want := Contents{Chains: []Chain{c}, Sets: []Set{f, free}, Timeouts: []Timeout{timeout("p")}}
	if !reflect.DeepEqual(got.Stale, want) {
		t.Errorf("the owner's read finds stale %+v, want %+v", got.Stale, want)
	}
	if err := conn.Batch(contents.Rewrite(unix.NFPROTO_INET, got.Stale, nil)); !errors.Is(err, unix.EBUSY) {
		t.Errorf("the owner's transaction over what reads stale: %v, want %v", err, unix.EBUSY)
	}
	if err := conn.Batch([]Request{Chain{Table: Table, Name: "other"}.Flush(unix.NFPROTO_INET)}); err != nil {
		t.Fatalf("another writer flushes its chain: %v", err)
	}
	got = read(contents)
	want = Contents{Chains: []Chain{c}, Sets: []Set{s, f, free}, Timeouts: []Timeout{timeout("t"), timeout("p")}}
	if !reflect.DeepEqual(got.Stale, want) || strings.Contains(got.Fault, "holds") {
		t.Errorf("with the other chain flushed the owner's read finds stale %+v with %q, want %+v and no holder", got.Stale, got.Fault, want)
	}
	if err := conn.Batch(contents.Rewrite(unix.NFPROTO_INET, got.Stale, nil)); err != nil {
		t.Errorf("with the other chain flushed the owner's transaction: %v", err)
	}
}

// A stale chain that a rule another writer put in one of the owner's own
// chains goes to reads back with that chain of the owner's as what holds it,
// since Rewrite deletes a stale chain before it flushes any, and the owner's
// transaction is refused
func TestNftablesReadNamesTheOwnersChainThatHoldsAStaleChain(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmpty(t)
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Fatal("the table is written through nft, which is not on the path")
	}
	load := exec.Command(nft, "-f", "-")
	load.Stdin = strings.NewReader("table inet ranet3 {\n\tchain c { }\n\tchain mine { jump c; }\n}\n")
	if out, err := load.CombinedOutput(); err != nil {
		t.Fatalf("nft -f: %v\n%s", err, out)
	}
	conn := dial(t)
	contents := Contents{Chains: []Chain{{Table: Table, Name: "c", Type: "filter", Hook: unix.NF_INET_LOCAL_OUT, Priority: 0}, {Table: Table, Name: "mine", Hook: NoHook}}}
	tables, err := Tables(conn, Table)
	if err != nil {
		t.Fatal(err)
	}
	read, err := contents.Read(conn, tables, unix.NFPROTO_INET, contents.Scope())
	if err != nil {
		t.Fatal(err)
	}
	if want := ", and chain mine holds a rule going to it, so it stays until that rule goes"; !read.Remake() || !strings.HasSuffix(read.Fault, want) {
		t.Errorf("the owner's read finds stale %+v with %q, want chain c and a fault ending %q", read.Stale, read.Fault, want)
	}
	if err := conn.Batch(contents.Rewrite(unix.NFPROTO_INET, read.Stale, nil)); !errors.Is(err, unix.EBUSY) {
		t.Errorf("the owner's transaction over chain c: %v, want %v", err, unix.EBUSY)
	}
}
