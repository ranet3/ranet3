// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"context"
	"encoding/binary"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/nftables"
	"ranet3.com/pkgs/ranet3/schema"
)

// The tests of this file are the only ones here that speak to a real kernel.
// Everything else in the package is checked against a fake, which can only
// ever agree with the encoder it was written beside. What nf_tables accepts,
// and what it hands back afterward, is the half a fake cannot answer for.
//
// Each refuses to run anywhere but inside a network namespace it created
// itself, because the code under test writes into the host's packet filter and
// the machine running the suite may well be translating real traffic.
// internal/kernel's netlink round trips take the same guard, and the netlink
// VM check runs these as root.

// The rules this package writes come back from nf_tables as written, in a
// namespace first proved empty of this tool's tables
func TestNftablesRoundTripInNetworkNamespace(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	enterThrowawayNamespace(t)

	cfg := egress.Egress{
		Return:    true,
		Advertise: prefixes(t, "198.51.100.0/24", "2001:db8:1::/48", "0.0.0.0/0"),
		Translate: []egress.Class{
			{From: schema.MustPrefix("192.0.2.0/24"), To: egress.Translation{None: true}},
			{From: schema.MustPrefix("3fff::/20"), To: egress.Translation{Addr: netip.MustParseAddr("2001:db8::7")}},
		},
	}
	rt := Runtime{
		Interface:     "ranet0",
		Steered:       true,
		MeshAddresses: []netip.Addr{netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("3fff::2")},
		Forwarding:    func() (bool, bool) { return true, true },
	}
	be, err := newBackend(cfg, rt)
	if err != nil {
		t.Fatalf("open the nftables backend: %v", err)
	}
	t.Cleanup(func() { _ = be.Close() })
	requireEmptyRuleset(t, be)

	tr := newTranslator(cfg, rt, be)
	desired := tr.desired()
	if len(desired) != 21 {
		t.Fatalf("the configuration asks for %d rules, want four out of the mesh device, three in and two from this node's own addresses, with twelve timeout rules", len(desired))
	}
	if err := be.Apply(desired, nil); err != nil {
		t.Fatalf("install %d rules: %v", len(desired), err)
	}

	// The whole round trip in one assertion: the kernel took every expression,
	// kept the rules in the order they were written, and handed back the
	// spelling this package wrote into each one's comment. A mismatch here is
	// a ruleset the reconcile loop would rewrite on every pass forever.
	read, err := be.Rules()
	if err != nil {
		t.Fatalf("read the rules back: %v", err)
	}
	held, faulted, remake := flatten(read)
	if faulted || len(remake) != 0 {
		t.Errorf("the tables read back as %+v, want both as written", read)
	}
	want := make([]string, 0, len(desired))
	for _, rule := range desired {
		want = append(want, rule.String())
	}
	got := make([]string, 0, len(held))
	for _, rule := range held {
		got = append(got, rule.Spec)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("the kernel holds %q, want %q", got, want)
	}
	if !sameRules(held, desired) {
		t.Error("a pass would rewrite rules the kernel already holds")
	}
	// each table holds the timeout objects its rules name, every state at the
	// seconds it was written with
	for _, family := range []uint8{egress.FamilyIPv4, egress.FamilyIPv6} {
		if got, want := heldTimeouts(t, be.(*natTables).conn, family), timeoutObjects(family); !reflect.DeepEqual(got, want) {
			t.Errorf("the %s table holds the timeout objects %+v, want %+v", tableFamilyName(family), got, want)
		}
	}

	// A rule with no comment in this tool's chain is another writer's, and the
	// readback holds it where the kernel does, in the family it was read from,
	// so a diff built from it rewrites the chain and the ip family alone stops
	// reading back as written.
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Fatal("another writer's rule is written through nft, which is not on the path")
	}
	if out, err := exec.Command(nft, "insert", "rule", "ip", TableName, ChainName, "accept").CombinedOutput(); err != nil {
		t.Fatalf("insert another writer's rule: %v\n%s", err, out)
	}
	read, err = be.Rules()
	if err != nil {
		t.Fatalf("read the rules back beside another writer's: %v", err)
	}
	withOther, _, _ := flatten(read)
	got = got[:0]
	for _, rule := range withOther {
		got = append(got, rule.Spec)
	}
	if !slices.Equal(got, append([]string{""}, want...)) {
		t.Errorf("with another writer's uncommented rule at the head of the ip chain the readback holds %q, want it ahead of %q", got, want)
	}
	if v4, v6 := sameFamilyRules(withOther, desired, egress.FamilyIPv4), sameFamilyRules(withOther, desired, egress.FamilyIPv6); v4 || !v6 {
		t.Errorf("with another writer's rule in the ip chain alone the ip readback reads as written %v and the ip6 one %v, want false and true", v4, v6)
	}

	// A counter in every rule but the timeout rules, at zero, since nothing has
	// crossed this namespace. Reading it back at all is the part that can
	// break: it is a 64-bit attribute the kernel aligns with a padding
	// attribute of its own.
	for i, rule := range held {
		if rule.Packets != 0 || rule.Bytes != 0 {
			t.Errorf("rule %d came back with %d flows and %d bytes in an empty namespace", i, rule.Packets, rule.Bytes)
		}
	}

	// This tool's own tables are the only ones here, so nothing can be
	// reported as another writer's.
	conflicts, err := be.Conflicts()
	if err != nil {
		t.Fatalf("look for other translation: %v", err)
	}
	if len(conflicts) != 0 {
		t.Errorf("reported %q in a namespace holding nothing else", conflicts)
	}

	// Applying the same rules again replaces the chain rather than appending
	// to it, the path a changed configuration takes on a running node.
	if err := be.Apply(desired, nil); err != nil {
		t.Fatalf("reinstall the rules: %v", err)
	}
	read, err = be.Rules()
	if held, _, _ = flatten(read); err != nil || len(held) != len(desired) {
		t.Fatalf("a second install left %d rules (%v), want %d", len(held), err, len(desired))
	}

	if err := be.Withdraw(); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	requireEmptyRuleset(t, be)
	// And a withdrawal of nothing is not an error, which every shutdown on a
	// node that never installed anything depends on.
	if err := be.Withdraw(); err != nil {
		t.Errorf("withdrawing an empty host failed: %v", err)
	}

	// an exit advertising nothing still owns a table in each family, for what its egress segment writes to the tun
	steered, err := newBackend(egress.Egress{}, rt)
	if err != nil {
		t.Fatalf("open the nftables backend for an exit advertising nothing: %v", err)
	}
	t.Cleanup(func() { _ = steered.Close() })
	only := newTranslator(egress.Egress{}, rt, steered).desired()
	if err := steered.Apply(only, nil); err != nil {
		t.Fatalf("install %d rules: %v", len(only), err)
	}
	read, err = steered.Rules()
	if held, _, _ = flatten(read); err != nil || !sameRules(held, only) {
		t.Fatalf("the kernel holds %v (%v), want %v", held, err, only)
	}
	tables, err := nftables.Tables(steered.(*natTables).conn, TableName)
	_, v4 := tables[unix.NFPROTO_IPV4]
	_, v6 := tables[unix.NFPROTO_IPV6]
	if err != nil || len(tables) != 2 || !v4 || !v6 {
		t.Errorf("an exit advertising nothing holds tables in %v (%v), want both families", tables, err)
	}
	if err := steered.Withdraw(); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	requireEmptyRuleset(t, steered)
}

// notificationWait is how long a test waits for a notification the kernel sends at once, generous for a loaded machine
// quietFor is how long a test watches for one that must not come
// foreignRules is the size of another writer's transaction, whose notifications overflow the smallest receive buffer while its acknowledgments, one per message, fit the writer's at the kernel's default size, and foreignTransactions how many such transactions a test commits at most before the kernel drops a notification
const (
	notificationWait    = 10 * time.Second
	quietFor            = 500 * time.Millisecond
	foreignRules        = 100
	foreignTransactions = 50
)

// The kernel tells the backend at once when another writer adds a rule to its
// chain, sets its table dormant or deletes it, well inside a sweep, and its
// own installs and withdrawals wake nothing.
func TestNftablesNotifiesAnotherWritersChange(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	enterThrowawayNamespace(t)
	rt := Runtime{Interface: "ranet0", Steered: true}
	be, err := newBackend(egress.Egress{}, rt)
	if err != nil {
		t.Fatalf("open the nftables backend: %v", err)
	}
	t.Cleanup(func() { _ = be.Close() })
	requireEmptyRuleset(t, be)
	quiet := func(what string) {
		t.Helper()
		select {
		case <-be.Changed():
			t.Fatalf("%s woke the translator", what)
		case <-time.After(quietFor):
		}
	}
	rules := newTranslator(egress.Egress{}, rt, be).desired()
	install := func() {
		t.Helper()
		if err := be.Apply(rules, nil); err != nil {
			t.Fatalf("install %d rules: %v", len(rules), err)
		}
	}
	install()
	install()
	quiet("its own install and reinstall")

	another, err := nftables.Dial()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = another.Close() })
	for _, change := range []struct {
		name    string
		request nftables.Request
	}{
		{"inserted an accept at the head of the ip6 chain", anotherWritersAccept(unix.NFPROTO_IPV6, ChainName)},
		{"set the ip table dormant", dormantTable(unix.NFPROTO_IPV4)},
		{"deleted the ip6 table", delTable(egress.FamilyIPv6)},
	} {
		if err := another.Batch([]nftables.Request{change.request}); err != nil {
			t.Fatalf("another writer %s: %v", change.name, err)
		}
		if !woken(be.Changed()) {
			t.Fatalf("another writer %s and the translator was not woken", change.name)
		}
		install()
		quiet("its own install after another writer " + change.name)
	}

	if err := be.Withdraw(); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	quiet("its own withdrawal")
}

// woken waits up to notificationWait for a wake on changed, then for quietFor
// with none, so every notification of the writes before it has been read, and
// reports whether one came
func woken(changed <-chan struct{}) bool {
	select {
	case <-changed:
	case <-time.After(notificationWait):
		return false
	}
	for {
		select {
		case <-changed:
		case <-time.After(quietFor):
			return true
		}
	}
}

// anotherWritersAccept is another writer's rule with no comment accepting
// every packet, at the head of chain in this tool's table of the family proto
func anotherWritersAccept(proto uint8, chain string) nftables.Request {
	body := nftables.PutAttrString(nftables.PutAttrString(nftables.PutNfgenmsg(nil, proto), unix.NFTA_RULE_TABLE, TableName), unix.NFTA_RULE_CHAIN, chain)
	body = nftables.PutAttr(body, unix.NFTA_RULE_EXPRESSIONS|unix.NLA_F_NESTED, verdict(nftables.Accept))
	// with no NLM_F_APPEND the kernel inserts the rule at the head of the chain
	return nftables.Request{Kind: nftables.Command(unix.NFT_MSG_NEWRULE), Flags: unix.NLM_F_CREATE, Body: body}
}

// dormantTable is another writer's update setting this tool's table of the
// family proto dormant
func dormantTable(proto uint8) nftables.Request {
	body := nftables.PutAttrString(nftables.PutNfgenmsg(nil, proto), unix.NFTA_TABLE_NAME, TableName)
	body = nftables.PutAttrBE32(body, unix.NFTA_TABLE_FLAGS, unix.NFT_TABLE_F_DORMANT)
	return nftables.Request{Kind: nftables.Command(unix.NFT_MSG_NEWTABLE), Flags: unix.NLM_F_CREATE, Body: body}
}

// A rule with no comment that another writer inserts at the head of the
// translator's own chain is read back with it, so the next pass rewrites the
// chain and leaves only the translator's rules, in the table it found, so with
// the timeout objects in it, which a deletion would detach from every flow they
// time
func TestNftablesRewritesAnotherWritersRuleInItsChain(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	enterThrowawayNamespace(t)
	rt := Runtime{
		Interface:  "ranet0",
		Steered:    true,
		Forwarding: func() (bool, bool) { return true, true },
	}
	be, err := newBackend(egress.Egress{}, rt)
	if err != nil {
		t.Fatalf("open the nftables backend: %v", err)
	}
	t.Cleanup(func() { _ = be.Close() })
	requireEmptyRuleset(t, be)
	tr := newTranslator(egress.Egress{}, rt, be)
	if err := tr.reconcile(); err != nil {
		t.Fatalf("first pass: %v", err)
	}

	another, err := nftables.Dial()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = another.Close() })
	if err := another.Batch([]nftables.Request{anotherWritersAccept(unix.NFPROTO_IPV6, ChainName)}); err != nil {
		t.Fatalf("insert another writer's accept rule: %v", err)
	}
	if read, err := be.Rules(); err != nil || !slices.ContainsFunc(read[egress.FamilyIPv6].rules, func(rule Installed) bool { return rule.Spec == "" }) {
		t.Errorf("with another writer's accept rule at the head of the ip6 chain the readback holds %v (%v), want that rule with no comment among them", read, err)
	}
	handles := tableHandles(t, another)

	if err := tr.reconcile(); err != nil {
		t.Fatalf("second pass: %v", err)
	}
	// a table made again takes a handle the namespace has not given before
	if got := tableHandles(t, another); len(got) != 2 || !maps.Equal(got, handles) {
		t.Errorf("after the pass rewrote the chains the tables have the handles %v, want the ones they had, %v", got, handles)
	}
	want := make([]string, 0, len(tr.desired()))
	for _, rule := range tr.desired() {
		want = append(want, rule.String())
	}
	// read through the other socket, so the chain compared holds every rule the kernel does, whatever this tool's readback keeps
	var got []string
	for _, family := range []uint8{egress.FamilyIPv4, egress.FamilyIPv6} {
		replies, err := another.Dump(nftables.Command(unix.NFT_MSG_GETRULE), nftables.PutNfgenmsg(nil, nftFamily(family)))
		if err != nil {
			t.Fatalf("dump the %s rules: %v", tableFamilyName(family), err)
		}
		for _, reply := range replies {
			if table, chain, spec, _, _ := nftables.DecodeRule(reply); table == TableName && chain == ChainName {
				got = append(got, spec)
			}
		}
	}
	if !slices.Equal(got, want) {
		t.Errorf("after the next pass the kernel holds %q, want only the translator's %q", got, want)
	}
	if s := tr.lastPass(); !s.Ready4 || !s.Ready6 {
		t.Errorf("after the next pass the translator reads %+v, want both families ready", s)
	}
}

// A timeout object the table holds with other seconds than this build writes,
// as an earlier build may have left it, reads back as a fault that remakes the
// table, since nf_tables changes no ct timeout in place, and after the pass
// every object reads back as written and both families are ready
func TestNftablesRemakesATableHoldingAStaleTimeout(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	enterThrowawayNamespace(t)
	rt := Runtime{Interface: "ranet0", Steered: true, Forwarding: func() (bool, bool) { return true, true }}
	be, err := newBackend(egress.Egress{}, rt)
	if err != nil {
		t.Fatalf("open the nftables backend: %v", err)
	}
	t.Cleanup(func() { _ = be.Close() })
	requireEmptyRuleset(t, be)
	another, err := nftables.Dial()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = another.Close() })
	stale := nftables.Timeout{Table: TableName, Name: timeoutObject + UDPTimeouts.String(), L3Proto: unix.NFPROTO_IPV4, L4Proto: unix.IPPROTO_UDP,
		Policy: []uint32{2 * udpUnrepliedTimeout, 2 * udpRepliedTimeout}}
	if err := another.Batch([]nftables.Request{nftables.NewTable(unix.NFPROTO_IPV4, TableName), stale.Create(unix.NFPROTO_IPV4)}); err != nil {
		t.Fatalf("leave a stale timeout object: %v", err)
	}
	if read, err := be.Rules(); err != nil || read[egress.FamilyIPv4].fault == "" || !read[egress.FamilyIPv4].remake {
		t.Errorf("with a stale timeout object the ip table reads back as %+v (%v), want a fault that remakes it", read[egress.FamilyIPv4], err)
	}
	tr := newTranslator(egress.Egress{}, rt, be)
	if err := tr.reconcile(); err != nil {
		t.Fatalf("the pass: %v", err)
	}
	for _, family := range []uint8{egress.FamilyIPv4, egress.FamilyIPv6} {
		if got, want := heldTimeouts(t, another, family), timeoutObjects(family); !reflect.DeepEqual(got, want) {
			t.Errorf("after the pass the %s table holds the timeout objects %+v, want %+v", tableFamilyName(family), got, want)
		}
	}
	if s := tr.lastPass(); !s.Ready4 || !s.Ready6 {
		t.Errorf("after the pass the translator reads %+v, want both families ready", s)
	}
}

// heldTimeouts is the timeout objects this tool's table of family holds, in
// the order the kernel dumps them, which is the order they were made in
func heldTimeouts(t *testing.T, conn *nftables.Conn, family uint8) []nftables.Timeout {
	t.Helper()
	replies, err := conn.Dump(nftables.Command(unix.NFT_MSG_GETOBJ), nftables.PutNfgenmsg(nil, nftFamily(family)))
	if err != nil {
		t.Fatalf("dump the %s objects: %v", tableFamilyName(family), err)
	}
	var held []nftables.Timeout
	for _, reply := range replies {
		if object, ok := nftables.DecodeTimeout(reply); ok && object.Table == TableName {
			held = append(held, object)
		}
	}
	return held
}

// tableHandle is NFTA_TABLE_HANDLE, the attribute of a table's handle in a
// dump, which x/sys does not carry
const tableHandle = 4

// tableHandles is the handle of this tool's table in each nf_tables family
// that holds one
func tableHandles(t *testing.T, conn *nftables.Conn) map[uint8]uint64 {
	t.Helper()
	replies, err := conn.Dump(nftables.Command(unix.NFT_MSG_GETTABLE), nftables.PutNfgenmsg(nil, unix.NFPROTO_UNSPEC))
	if err != nil {
		t.Fatalf("dump the tables: %v", err)
	}
	handles := map[uint8]uint64{}
	for _, reply := range replies {
		var name string
		var handle uint64
		for kind, value := range reply.Attributes() {
			switch {
			case kind == unix.NFTA_TABLE_NAME:
				name = unix.ByteSliceToString(value)
			case kind == tableHandle && len(value) == 8:
				handle = binary.BigEndian.Uint64(value)
			}
		}
		if name == TableName && len(reply.Data) >= nftables.SizeofNfgenmsg {
			handles[reply.Data[0]] = handle
		}
	}
	return handles
}

// Another writer setting a family's table dormant, or making its chain again
// at another priority or as a regular chain, wakes the translator, which
// reports both families not ready until the pass that follows, with no sweep
// due, writes the table back, deleting and making it again in the second and
// third case, and reads both ready
func TestNftablesPutsBackAnotherWritersChangeToItsTable(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	enterThrowawayNamespace(t)
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Fatal("another writer's changes are made through nft, which is not on the path")
	}
	run := func(args ...string) string {
		t.Helper()
		out, err := exec.Command(nft, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("nft %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return string(out)
	}
	var mu sync.Mutex
	var told []string
	entries := func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(told)
	}
	rt := Runtime{
		Interface:  "ranet0",
		Steered:    true,
		Forwarding: func() (bool, bool) { return true, true },
		Hooks: egress.Hooks{Ready: func(v4, v6, _ bool) {
			mu.Lock()
			defer mu.Unlock()
			told = append(told, fmt.Sprintf("ready %v %v", v4, v6))
		}},
	}
	// no sweep comes within notificationWait, so only a wake explains a pass
	cfg := egress.Egress{Sweep: schema.Duration(lateSweep)}
	be, err := newBackend(cfg, rt)
	if err != nil {
		t.Fatalf("open the nftables backend: %v", err)
	}
	requireEmptyRuleset(t, be)
	// a backend of its own reads the tables back, since the run goroutine holds be's socket
	check, err := newBackend(cfg, rt)
	if err != nil {
		t.Fatalf("open a second nftables backend: %v", err)
	}
	t.Cleanup(func() { _ = check.Close() })
	tr := newTranslator(cfg, rt, be)
	desired := tr.desired()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- tr.Run(ctx) }()
	moved := func(what string, mark int, want ...string) {
		t.Helper()
		for deadline := time.Now().Add(notificationWait); ; time.Sleep(passPoll) {
			got := entries()[mark:]
			if len(got) >= len(want) && slices.Equal(got[:1], want[:1]) && got[len(got)-1] == want[len(want)-1] {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: the translator went %q, want %q", what, got, want)
			}
		}
	}
	moved("the first pass", 0, "ready true true")
	for _, change := range []struct {
		name   string
		family string
		// command is one transaction, so no pass runs between its parts
		command string
		// nft lists gone in the family's table while the change stands
		gone string
	}{
		{"the ip6 table set dormant", "ip6", fmt.Sprintf("add table ip6 %s { flags dormant; }", TableName), "flags dormant"},
		{"the ip chain made again at priority 0", "ip",
			fmt.Sprintf("delete chain ip %[1]s %[2]s; add chain ip %[1]s %[2]s { type nat hook postrouting priority 0; policy accept; }", TableName, ChainName),
			"priority filter;"},
		{"the ip6 chain made again as a regular chain", "ip6",
			fmt.Sprintf("delete chain ip6 %[1]s %[2]s; add chain ip6 %[1]s %[2]s", TableName, ChainName),
			fmt.Sprintf("chain %s {\n\t}", ChainName)},
	} {
		mark := len(entries())
		run(change.command)
		moved(change.name, mark, "ready false false", "ready true true")
		read, err := check.Rules()
		held, faulted, remake := flatten(read)
		if err != nil || faulted || len(remake) != 0 || !sameRules(held, desired) {
			t.Errorf("%s: after the pass the tables read back as %+v (%v), want %v as written", change.name, read, err, desired)
		}
		if listing := run("list", "table", change.family, TableName); strings.Contains(listing, change.gone) {
			t.Errorf("%s: after the pass nft still lists %q in:\n%s", change.name, change.gone, listing)
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("stop the translator: %v", err)
	}
	requireEmptyRuleset(t, check)
}

// foreignTransaction is another writer's table, chain and count rules, never naming this tool's table
func foreignTransaction(table string, count int) []nftables.Request {
	const chain = "input"
	requests := []nftables.Request{
		{Kind: nftables.Command(unix.NFT_MSG_NEWTABLE), Flags: unix.NLM_F_CREATE, Body: nftables.PutAttrString(nftables.PutNfgenmsg(nil, unix.NFPROTO_IPV4), unix.NFTA_TABLE_NAME, table)},
		{Kind: nftables.Command(unix.NFT_MSG_NEWCHAIN), Flags: unix.NLM_F_CREATE, Body: nftables.PutAttrString(nftables.PutAttrString(nftables.PutNfgenmsg(nil, unix.NFPROTO_IPV4), unix.NFTA_CHAIN_TABLE, table), unix.NFTA_CHAIN_NAME, chain)},
	}
	for i := range count {
		var expressions []byte
		for _, e := range append(nftables.MetaCompare(unix.NFT_META_IIFNAME, unix.NFT_CMP_EQ, fmt.Sprintf("eth%d", i%100)), nftables.Expression("counter", nil)) {
			expressions = append(expressions, e...)
		}
		body := nftables.PutAttrString(nftables.PutAttrString(nftables.PutNfgenmsg(nil, unix.NFPROTO_IPV4), unix.NFTA_RULE_TABLE, table), unix.NFTA_RULE_CHAIN, chain)
		requests = append(requests, nftables.Request{Kind: nftables.Command(unix.NFT_MSG_NEWRULE), Flags: unix.NLM_F_CREATE | unix.NLM_F_APPEND,
			Body: nftables.PutAttr(body, unix.NFTA_RULE_EXPRESSIONS|unix.NLA_F_NESTED, expressions)})
	}
	return requests
}

// netlinkSockets is each netlink socket of this thread's namespace, by its
// inode, as /proc lists it: sk Eth Pid Groups Rmem Wmem Dump Locks Drops Inode
func netlinkSockets(t *testing.T) map[string][]string {
	t.Helper()
	body, err := os.ReadFile("/proc/thread-self/net/netlink")
	if err != nil {
		t.Fatalf("read the netlink sockets: %v", err)
	}
	out := map[string][]string{}
	for line := range strings.Lines(string(body)) {
		if fields := strings.Fields(line); len(fields) == 10 {
			out[fields[9]] = fields
		}
	}
	return out
}

// notificationSocket is the descriptor of the one NETLINK_NETFILTER socket of
// this process that joined a group, the backend's notification socket
func notificationSocket(t *testing.T) int {
	t.Helper()
	sockets := netlinkSockets(t)
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	var found []int
	for _, entry := range entries {
		target, err := os.Readlink("/proc/self/fd/" + entry.Name())
		inode, ok := strings.CutPrefix(target, "socket:[")
		if err != nil || !ok {
			continue
		}
		fields := sockets[strings.TrimSuffix(inode, "]")]
		if fields == nil || fields[1] != strconv.Itoa(unix.NETLINK_NETFILTER) || strings.Trim(fields[3], "0") == "" {
			continue
		}
		fd, err := strconv.Atoi(entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		found = append(found, fd)
	}
	if len(found) != 1 {
		t.Fatalf("found %d netfilter netlink sockets in a group, want the backend's one", len(found))
	}
	return found[0]
}

// socketDrops is how many datagrams the kernel has dropped for the netlink socket fd, and the bytes it holds queued, read from this thread's namespace
func socketDrops(t *testing.T, fd int) (dropped, queued uint64) {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		t.Fatalf("stat the notification socket: %v", err)
	}
	for _, fields := range netlinkSockets(t) {
		if fields[9] != strconv.FormatUint(st.Ino, 10) {
			continue
		}
		var err error
		queued, err = strconv.ParseUint(fields[4], 10, 64)
		if err == nil {
			dropped, err = strconv.ParseUint(fields[8], 10, 64)
		}
		if err != nil {
			t.Fatalf("the netlink socket of inode %d reads %q: %v", st.Ino, fields, err)
		}
		return dropped, queued
	}
	t.Fatalf("no netlink socket of inode %d is listed", st.Ino)
	return 0, 0
}

// Another writer's transaction too large for the notification socket's
// buffer reaches the translator through the backend's Missed, and never
// through Changed, since the transaction writes none of this tool's tables
func TestNftablesWakesMissedOnAnOverflow(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	enterThrowawayNamespace(t)
	be, err := newBackend(egress.Egress{}, Runtime{Interface: "ranet0", Steered: true})
	if err != nil {
		t.Fatalf("open the nftables backend: %v", err)
	}
	t.Cleanup(func() { _ = be.Close() })
	monitor := notificationSocket(t)
	if err := unix.SetsockoptInt(monitor, unix.SOL_SOCKET, unix.SO_RCVBUF, 1); err != nil {
		t.Fatalf("shrink the notification socket's buffer: %v", err)
	}
	another, err := nftables.Dial()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = another.Close() })
	// a reader the scheduler favors can keep up with one transaction's notifications, so transactions go on until the kernel has dropped one
	transactions := 0
	for dropped, _ := socketDrops(t, monitor); dropped == 0; dropped, _ = socketDrops(t, monitor) {
		if transactions == foreignTransactions {
			t.Fatalf("after %d transactions of %d rules the kernel had dropped no notification", transactions, foreignRules)
		}
		if err := another.Batch(foreignTransaction(fmt.Sprintf("fw%d", transactions), foreignRules)); err != nil {
			t.Fatalf("commit another writer's transaction: %v", err)
		}
		transactions++
	}
	t.Logf("the kernel dropped a notification after %d transactions of %d rules", transactions, foreignRules)
	select {
	case <-be.Missed():
	case <-time.After(notificationWait):
		rcvbuf, err := unix.GetsockoptInt(monitor, unix.SOL_SOCKET, unix.SO_RCVBUF)
		if err != nil {
			t.Logf("read the notification socket's buffer back: %v", err)
		}
		dropped, queued := socketDrops(t, monitor)
		t.Fatalf("an overflow of the notification socket never woke missed: %d transactions, its receive buffer at %d bytes, %d notifications dropped and %d bytes queued", transactions, rcvbuf, dropped, queued)
	}
	select {
	case <-be.Changed():
		t.Error("another writer's transaction that writes none of this tool's tables woke changed")
	default:
	}
}

// requireEmptyRuleset is the second guard, and the assertion after a
// withdrawal. A namespace already holding a table is somebody's real one,
// whatever the inode said.
func requireEmptyRuleset(t *testing.T, be backend) {
	t.Helper()
	tables, err := nftables.Tables(be.(*natTables).conn, TableName)
	if err != nil {
		t.Fatalf("list this tool's tables: %v", err)
	}
	if len(tables) != 0 {
		t.Fatalf("the namespace holds %d tables named %s", len(tables), TableName)
	}
	read, err := be.Rules()
	if err != nil {
		t.Fatalf("list rules: %v", err)
	}
	if rules, _, _ := flatten(read); len(rules) != 0 {
		t.Fatalf("the namespace holds %d rules of this tool's", len(rules))
	}
}

// enterThrowawayNamespace moves this thread into a network namespace of its
// own and refuses to continue if it did not move, the same pair of guards
// internal/kernel's netlink test takes.
func enterThrowawayNamespace(t *testing.T) {
	t.Helper()
	runtime.LockOSThread()
	before := namespaceID(t)
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		t.Fatalf("unshare a network namespace: %v", err)
	}
	if namespaceID(t) == before {
		t.Fatal("refusing to continue: the network namespace did not change")
	}
}

func namespaceID(t *testing.T) uint64 {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat("/proc/thread-self/ns/net", &st); err != nil {
		t.Fatalf("stat this thread's network namespace: %v", err)
	}
	return st.Ino
}
