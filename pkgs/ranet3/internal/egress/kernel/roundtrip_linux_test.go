// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

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
			{From: schema.MustPrefix("192.0.2.128/25"), To: egress.Translation{Addr: netip.MustParseAddr("198.51.100.7")}},
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
	if len(desired) != 60 {
		t.Fatalf("the configuration asks for %d rules, want 60", len(desired))
	}
	if err := be.Apply(desired, nil); err != nil {
		t.Fatalf("install %d rules: %v", len(desired), err)
	}

	// The whole round trip in one assertion: the kernel took every expression,
	// kept the rules in the order they were written, and handed back the
	// spelling this package wrote into each one's comment and the expressions
	// it encoded, as a dump spells them. A mismatch here is a ruleset the
	// reconcile loop would rewrite on every pass forever. Each table, its two
	// chains, its set and its objects read back as written.
	read, err := be.Rules(desired)
	if err != nil {
		t.Fatalf("read the rules back: %v", err)
	}
	held, faulted, remake := flatten(read)
	for _, family := range []uint8{egress.FamilyIPv4, egress.FamilyIPv6} {
		if read[family].fault != "" || len(remake) != 0 {
			t.Errorf("the %s table reads back with the fault %q and remake %v, want it as written", tableFamilyName(family), read[family].fault, remake)
		}
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
	if faulted {
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
	read, err = be.Rules(desired)
	if err != nil {
		t.Fatalf("read the rules back beside another writer's: %v", err)
	}
	withOther, _, _ := flatten(read)
	got = got[:0]
	for _, rule := range withOther {
		got = append(got, rule.Spec)
	}
	// behind the ip forward chain and its classes of none's chains, which read
	// back first
	forwardRules := 0
	for _, rule := range desired {
		if rule.Family == egress.FamilyIPv4 && rule.chain() != ChainName {
			forwardRules++
		}
	}
	if !slices.Equal(got, slices.Insert(slices.Clone(want), forwardRules, "")) {
		t.Errorf("with another writer's uncommented rule at the head of the ip chain the readback holds %q, want it ahead of the ip translation's rules in %q", got, want)
	}
	if v4, v6 := read[egress.FamilyIPv4].fault, read[egress.FamilyIPv6].fault; v4 == "" || v6 != "" {
		t.Errorf("with another writer's rule in the ip chain alone the ip readback reads the fault %q and the ip6 one %q, want one and none", v4, v6)
	}

	// A counter in every rule but the timeout rules and the pass, at zero, since nothing has
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
	read, err = be.Rules(desired)
	if held, faulted, _ = flatten(read); err != nil || faulted || len(held) != len(desired) {
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
	read, err = steered.Rules(only)
	if held, faulted, _ = flatten(read); err != nil || faulted || len(held) != len(only) {
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
	return anotherWritersRule(proto, chain, nftables.Verdict(nftables.Accept))
}

// anotherWritersRule is another writer's rule with no comment of expressions,
// at the head of chain in this tool's table of the family proto
func anotherWritersRule(proto uint8, chain string, expressions ...[]byte) nftables.Request {
	body := nftables.PutAttrString(nftables.PutAttrString(nftables.PutNfgenmsg(nil, proto), unix.NFTA_RULE_TABLE, TableName), unix.NFTA_RULE_CHAIN, chain)
	body = nftables.PutAttr(body, unix.NFTA_RULE_EXPRESSIONS|unix.NLA_F_NESTED, slices.Concat(expressions...))
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

// A rule with no comment that another writer inserts at the head of one of the
// translator's own chains is read back with it, so the next pass rewrites the
// chains and leaves only the translator's rules, in the table it found, so
// with the timeout objects in it, which a deletion would detach from every
// flow they time, and the set, which a deletion would empty of every source's
// count
func TestNftablesRewritesAnotherWritersRuleInItsChain(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	enterThrowawayNamespace(t)
	rt := Runtime{
		Interface:  "ranet0",
		Steered:    true,
		Forwarding: func() (bool, bool) { return true, true },
		Sysctl:     readsNothing,
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
	// the ip6 one counted, which the debug read names by its chain
	counted := anotherWritersRule(unix.NFPROTO_IPV6, ChainName, nftables.Expression("counter", nil), nftables.Verdict(nftables.Accept))
	if err := another.Batch([]nftables.Request{counted, anotherWritersAccept(unix.NFPROTO_IPV4, LimitChain)}); err != nil {
		t.Fatalf("insert another writer's accept rules: %v", err)
	}
	read, err := be.Rules(tr.desired())
	for family, want := range map[uint8]Installed{
		egress.FamilyIPv4: {Family: egress.FamilyIPv4, Chain: LimitChain},
		egress.FamilyIPv6: {Family: egress.FamilyIPv6, Chain: ChainName, Counted: true},
	} {
		if err != nil || !slices.Contains(read[family].rules, want) {
			t.Errorf("with another writer's accept rule at the head of the ip forward and ip6 postrouting chains the %s readback holds %v (%v), want %+v among them",
				tableFamilyName(family), read[family], err, want)
		}
	}
	var extra []egress.RuleReading
	for _, rule := range tr.Debug().Rules {
		if !rule.Wanted {
			extra = append(extra, rule)
		}
	}
	if want := []egress.RuleReading{{Held: true}, {Held: true, Counter: "flows"}}; !slices.Equal(extra, want) {
		t.Errorf("the debug read names another writer's rules %+v, want the ip forward one uncounted and the ip6 postrouting one counting flows, %+v", extra, want)
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
	// read through the other socket, so the chains compared hold every rule the kernel does, whatever this tool's readback keeps
	var got []string
	for _, family := range []uint8{egress.FamilyIPv4, egress.FamilyIPv6} {
		replies, err := another.Dump(nftables.Command(unix.NFT_MSG_GETRULE), nftables.PutNfgenmsg(nil, nftFamily(family)))
		if err != nil {
			t.Fatalf("dump the %s rules: %v", tableFamilyName(family), err)
		}
		for _, written := range translatorChains(family, tr.desired()) {
			for _, reply := range replies {
				if table, chain, spec, _, _, _ := nftables.DecodeRule(reply); table == TableName && chain == written.Name {
					got = append(got, spec)
				}
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

// A line another writer replaces in place with an accept under the comment it
// was written with, in either chain of either family, reads back as a fault of
// its family alone that names the line, and the next pass writes the line back
// and reads both families ready
func TestNftablesRewritesALineEditedUnderItsComment(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	enterThrowawayNamespace(t)
	run := nftRun(t)
	rt := Runtime{Interface: "ranet0", Steered: true, Forwarding: func() (bool, bool) { return true, true }, Sysctl: readsNothing}
	be, err := newBackend(egress.Egress{}, rt)
	if err != nil {
		t.Fatalf("open the nftables backend: %v", err)
	}
	t.Cleanup(func() { _ = be.Close() })
	requireEmptyRuleset(t, be)
	tr := newTranslator(egress.Egress{}, rt, be)
	if err := tr.reconcile(); err != nil {
		t.Fatalf("the first pass: %v", err)
	}
	desired := tr.desired()
	for _, edit := range []struct {
		family uint8
		chain  string
		rule   Rule
		// kept is a part of nft's listing of the line as it was written
		kept string
	}{
		{egress.FamilyIPv4, ChainName, Rule{Family: egress.FamilyIPv4, Direction: Out, Interface: "ranet0"}, "masquerade"},
		{egress.FamilyIPv4, LimitChain, Rule{Family: egress.FamilyIPv4, Direction: Out, Interface: "ranet0", Limit: egress.DefaultFlowsPerSource}, "ct count over"},
		{egress.FamilyIPv6, ChainName, Rule{Family: egress.FamilyIPv6, Direction: Out, Interface: "ranet0"}, "masquerade"},
		{egress.FamilyIPv6, LimitChain, Rule{Family: egress.FamilyIPv6, Direction: Out, Interface: "ranet0", Untracked: true}, "ct state invalid,untracked"},
	} {
		spec, family := edit.rule.String(), tableFamilyName(edit.family)
		if !slices.ContainsFunc(desired, func(rule Rule) bool { return rule.String() == spec }) {
			t.Fatalf("the translator writes no line %q", spec)
		}
		listing := run("-a", "list", "chain", family, TableName, edit.chain)
		handle := regexp.MustCompile(`comment "` + regexp.QuoteMeta(spec) + `" # handle (\d+)`).FindStringSubmatch(listing)
		if handle == nil {
			t.Fatalf("no line of the %s chain %s is commented %q in:\n%s", family, edit.chain, spec, listing)
		}
		accepted := fmt.Sprintf("counter accept comment %q", spec)
		run(append([]string{"replace", "rule", family, TableName, edit.chain, "handle", handle[1]}, strings.Fields(accepted)...)...)
		read, err := be.Rules(desired)
		other := egress.FamilyIPv6
		if edit.family == other {
			other = egress.FamilyIPv4
		}
		if err != nil || !strings.Contains(read[edit.family].fault, spec) || read[edit.family].remake || read[other].fault != "" {
			t.Errorf("%q made an accept: the %s table reads the fault %q, remake %v, and the other the fault %q (%v), want the %s table alone at a fault naming the line",
				spec, family, read[edit.family].fault, read[edit.family].remake, read[other].fault, err, family)
		}
		if err := tr.reconcile(); err != nil {
			t.Fatalf("%q made an accept: the pass: %v", spec, err)
		}
		if s := tr.lastPass(); !s.Ready4 || !s.Ready6 {
			t.Errorf("%q made an accept: after the pass the translator reads %+v, want both families ready", spec, s)
		}
		listing = run("list", "chain", family, TableName, edit.chain)
		line := regexp.MustCompile(`(?m)^.*comment "` + regexp.QuoteMeta(spec) + `"$`).FindString(listing)
		if !strings.Contains(line, edit.kept) || strings.Contains(line, "accept") {
			t.Errorf("%q made an accept: after the pass nft lists the line %q, want it as written, with %q:\n%s", spec, line, edit.kept, listing)
		}
	}
}

// The chain of a class of none is read back as the base chains are. Its set of
// the 2 classes that translate inside it reads back ready, and a second pass
// rewrites nothing. Its line another writer makes an accept under its comment,
// its line written again under its comment over a set holding an element more
// or missing its second, a chain named as a class of none's that no class
// writes, and a class's chain deleted once its pass is made an accept each read
// back as a fault of the ip family alone naming the line or the chain, and the
// next pass writes the line back, deletes the stray chain or writes the missing
// one, and reads both families ready
func TestNftablesReadsTheChainsOfClassesOfNoneBack(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	enterThrowawayNamespace(t)
	run := nftRun(t)
	cfg := egress.Egress{Translate: []egress.Class{
		{From: schema.MustPrefix("192.0.2.0/24"), To: egress.Translation{None: true}},
		{From: schema.MustPrefix("192.0.2.0/26"), To: egress.Translation{Auto: true}},
		{From: schema.MustPrefix("192.0.2.128/26"), To: egress.Translation{Auto: true}},
		{From: schema.MustPrefix("198.51.100.0/24"), To: egress.Translation{None: true}},
	}}
	rt := Runtime{Interface: "ranet0", Steered: true, Forwarding: func() (bool, bool) { return true, true }, Sysctl: readsNothing}
	be, err := newBackend(cfg, rt)
	if err != nil {
		t.Fatalf("open the nftables backend: %v", err)
	}
	t.Cleanup(func() { _ = be.Close() })
	requireEmptyRuleset(t, be)
	tr := newTranslator(cfg, rt, be)
	if err := tr.reconcile(); err != nil {
		t.Fatalf("the first pass: %v", err)
	}
	handles := regexp.MustCompile(`# handle \d+`)
	before := handles.FindAllString(run("-a", "list", "table", "ip", TableName), -1)
	if err := tr.reconcile(); err != nil {
		t.Fatalf("the second pass: %v", err)
	}
	after := handles.FindAllString(run("-a", "list", "table", "ip", TableName), -1)
	if s := tr.lastPass(); !s.Ready4 || !s.Ready6 || !slices.Equal(before, after) {
		t.Errorf("after the second pass the translator reads %+v, the ip table's handles %v then %v, want both families ready and no rewrite", s, before, after)
	}
	desired := tr.desired()
	// replace makes the line of chain commented spec an accept under that comment
	replace := func(chain, spec string) {
		t.Helper()
		listing := run("-a", "list", "chain", "ip", TableName, chain)
		handle := regexp.MustCompile(`comment "` + regexp.QuoteMeta(spec) + `" # handle (\d+)`).FindStringSubmatch(listing)
		if handle == nil {
			t.Fatalf("no line of the ip chain %s is commented %q in:\n%s", chain, spec, listing)
		}
		run(append([]string{"replace", "rule", "ip", TableName, chain, "handle", handle[1]}, strings.Fields(fmt.Sprintf("counter accept comment %q", spec))...)...)
	}
	// elsewhere writes rule's line again under its comment, its set holding
	// members in place of Sources
	conn, err := nftables.Dial()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	elsewhere := func(rule Rule, members ...string) {
		t.Helper()
		listing := run("-a", "list", "chain", "ip", TableName, rule.chain())
		handle := regexp.MustCompile(`comment "` + regexp.QuoteMeta(rule.String()) + `" # handle (\d+)`).FindStringSubmatch(listing)
		if handle == nil {
			t.Fatalf("no line of the ip chain %s is commented %q in:\n%s", rule.chain(), rule, listing)
		}
		number, err := strconv.ParseUint(handle[1], 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		edited := rule
		var prefixes []netip.Prefix
		for _, member := range members {
			prefixes = append(prefixes, netip.MustParsePrefix(member))
		}
		edited.Sources = prefixSet(prefixes)
		requests, err := sourceRequests(edited, 7)
		if err != nil {
			t.Fatal(err)
		}
		replaced, err := newRule(edited, 7)
		if err != nil {
			t.Fatal(err)
		}
		replaced.Flags = unix.NLM_F_REPLACE
		replaced.Body = nftables.PutAttr(replaced.Body, unix.NFTA_RULE_HANDLE, binary.BigEndian.AppendUint64(nil, number))
		if err := conn.Batch(append(requests, replaced)); err != nil {
			t.Fatalf("write %s again over %v: %v", rule, members, err)
		}
	}
	inside := Rule{Family: egress.FamilyIPv4, Direction: Out, Interface: "ranet0",
		Sources: prefixSet([]netip.Prefix{netip.MustParsePrefix("192.0.2.0/26"), netip.MustParsePrefix("192.0.2.128/26")}),
		Limit:   egress.DefaultFlowsPerSource, Under: netip.MustParsePrefix("192.0.2.0/24")}
	untracked := inside
	untracked.Limit, untracked.Untracked = 0, true
	empty := Rule{Family: egress.FamilyIPv4, Direction: Out, Interface: "ranet0", From: netip.MustParsePrefix("198.51.100.0/24"), Passes: true}
	for _, rule := range []Rule{inside, untracked, empty} {
		if !slices.ContainsFunc(desired, func(held Rule) bool { return held == rule }) {
			t.Fatalf("the translator writes no line %s in the chain %s", rule, rule.chain())
		}
	}
	for _, edit := range []struct {
		name string
		// edit changes the host, and named is the line or the chain the fault names
		edit  func()
		named string
		// after is whether nft lists the chain named after the pass
		after bool
	}{
		{"a line of a class's chain made an accept", func() { replace(inside.chain(), inside.String()) }, inside.String(), true},
		{"a line of a class's chain written again over a set holding an element more", func() { elsewhere(inside, "192.0.2.0/26", "192.0.2.64/26", "192.0.2.128/26") }, inside.String(), true},
		{"a line of a class's chain written again over a set missing its second element", func() { elsewhere(untracked, "192.0.2.0/26") }, untracked.String(), true},
		{"a chain no class writes", func() { run("add", "chain", "ip", TableName, "none_203_0_113_0_24") }, "none_203_0_113_0_24", false},
		{"a class's chain deleted once its pass is an accept", func() {
			replace(LimitChain, empty.String())
			run("delete", "chain", "ip", TableName, noneChain(empty.From))
		}, noneChain(empty.From) + " is missing", true},
	} {
		edit.edit()
		read, err := be.Rules(desired)
		if err != nil || !strings.Contains(read[egress.FamilyIPv4].fault, edit.named) || read[egress.FamilyIPv4].remake || read[egress.FamilyIPv6].fault != "" {
			t.Errorf("%s: the ip table reads the fault %q, remake %v, and the ip6 one the fault %q (%v), want the ip table alone at a fault naming %q",
				edit.name, read[egress.FamilyIPv4].fault, read[egress.FamilyIPv4].remake, read[egress.FamilyIPv6].fault, err, edit.named)
		}
		if err := tr.reconcile(); err != nil {
			t.Fatalf("%s: the pass: %v", edit.name, err)
		}
		if s := tr.lastPass(); !s.Ready4 || !s.Ready6 {
			t.Errorf("%s: after the pass the translator reads %+v, want both families ready", edit.name, s)
		}
		listing := run("list", "table", "ip", TableName)
		if chain := strings.Fields(edit.named)[0]; strings.HasPrefix(chain, NoneChain) && strings.Contains(listing, "chain "+chain+" {") != edit.after {
			t.Errorf("%s: after the pass nft lists the chain %s: %v, want %v:\n%s", edit.name, chain, !edit.after, edit.after, listing)
		}
		if strings.Contains(listing, "accept comment") {
			t.Errorf("%s: after the pass nft still lists an accept another writer made:\n%s", edit.name, listing)
		}
	}
}

// A chain named as a class of none's that no class writes, which a rule of
// another writer's chain goes to, by a goto or by its vmap, or an element of a
// named map goes to, so nf_tables will not delete it, holds the ip family alone
// not ready with a fault naming that chain or map, while the pass writes the
// rest and fails nothing. Once the rule or the element goes, the next pass
// deletes the chain and reads both families ready, the other writer's chain
// and map left in place.
func TestNftablesNamesTheChainThatKeepsAStrayChainOfNone(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	enterThrowawayNamespace(t)
	run := nftRun(t)
	cfg := egress.Egress{Translate: []egress.Class{{From: schema.MustPrefix("192.0.2.0/24"), To: egress.Translation{None: true}}}}
	rt := Runtime{Interface: "ranet0", Steered: true, Forwarding: func() (bool, bool) { return true, true }, Sysctl: readsNothing}
	be, err := newBackend(cfg, rt)
	if err != nil {
		t.Fatalf("open the nftables backend: %v", err)
	}
	t.Cleanup(func() { _ = be.Close() })
	requireEmptyRuleset(t, be)
	tr := newTranslator(cfg, rt, be)
	if err := tr.reconcile(); err != nil {
		t.Fatalf("the first pass: %v", err)
	}
	stray := "none_203_0_113_0_24"
	run("add", "chain", "ip", TableName, "other")
	run("add", "map", "ip", TableName, "vm", "{", "type", "ipv4_addr", ":", "verdict", ";", "}")
	for _, c := range []struct {
		name string
		// hold makes what goes to the stray chain, and release takes it away
		hold, release func()
		held          string
	}{
		{"a goto of chain other", func() { run("add", "rule", "ip", TableName, "other", "goto", stray) },
			func() { run("flush", "chain", "ip", TableName, "other") }, "and chain other holds a rule going to it"},
		{"a vmap of chain other", func() {
			run("add", "rule", "ip", TableName, "other", "ip", "saddr", "vmap", "{", "192.0.2.1", ":", "goto", stray, "}")
		},
			func() { run("flush", "chain", "ip", TableName, "other") }, "and chain other holds a rule going to it"},
		{"an element of map vm", func() { run("add", "element", "ip", TableName, "vm", "{", "192.0.2.1", ":", "goto", stray, "}") },
			func() { run("delete", "element", "ip", TableName, "vm", "{", "192.0.2.1", "}") }, "and map vm holds an element going to it"},
	} {
		run("add", "chain", "ip", TableName, stray)
		c.hold()
		if err := tr.reconcile(); err != nil {
			t.Fatalf("%s: the pass beside it going to %s: %v", c.name, stray, err)
		}
		held := "its chain " + stray + " is not one a class of none writes, " + c.held
		if s := tr.lastPass(); s.Ready4 || !s.Ready6 || !strings.Contains(s.Unready, held) {
			t.Errorf("%s: beside it going to %s the translator reads %+v, want ipv4 alone not ready for %q", c.name, stray, s, held)
		}
		if listing := run("list", "table", "ip", TableName); !strings.Contains(listing, "chain "+stray+" {") || !strings.Contains(listing, "from 192.0.2.0/24 passed") {
			t.Errorf("%s: after the pass beside it going to %s nft lists, want that chain and the pass written:\n%s", c.name, stray, listing)
		}
		c.release()
		if err := tr.reconcile(); err != nil {
			t.Fatalf("%s: the pass once it is gone: %v", c.name, err)
		}
		if s := tr.lastPass(); !s.Ready4 || !s.Ready6 {
			t.Errorf("%s: once it is gone the translator reads %+v, want both families ready", c.name, s)
		}
		if listing := run("list", "table", "ip", TableName); strings.Contains(listing, "chain "+stray+" {") || !strings.Contains(listing, "chain other {") || !strings.Contains(listing, "map vm {") {
			t.Errorf("%s: once it is gone nft lists, want %s deleted and chain other and map vm left:\n%s", c.name, stray, listing)
		}
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
	rt := Runtime{Interface: "ranet0", Steered: true, Forwarding: func() (bool, bool) { return true, true }, Sysctl: readsNothing}
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
	if read, err := be.Rules(newTranslator(egress.Egress{}, rt, be).desired()); err != nil || read[egress.FamilyIPv4].fault == "" || !read[egress.FamilyIPv4].remake {
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

// A set another writer resized reads back as a fault the next pass writes
// back without remaking the table, and every pass keeps each set's elements,
// each source's count of flows, which a remake would empty
func TestNftablesKeepsTheSetsCountsAcrossARewrite(t *testing.T) {
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
	rt := Runtime{Interface: "ranet0", Steered: true, Forwarding: func() (bool, bool) { return true, true }, Sysctl: readsNothing}
	be, err := newBackend(egress.Egress{}, rt)
	if err != nil {
		t.Fatalf("open the nftables backend: %v", err)
	}
	t.Cleanup(func() { _ = be.Close() })
	requireEmptyRuleset(t, be)
	tr := newTranslator(egress.Egress{}, rt, be)
	if err := tr.reconcile(); err != nil {
		t.Fatalf("the first pass: %v", err)
	}
	another, err := nftables.Dial()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = another.Close() })
	// an element for a source in each family's set, with no count, which the
	// set's collection would take once it read zero
	counted := []struct {
		family uint8
		source string
	}{{egress.FamilyIPv4, "192.0.2.2"}, {egress.FamilyIPv6, "3fff::2"}}
	for _, c := range counted {
		run("add", "element", tableFamilyName(c.family), TableName, flowSet(c.family, egress.DefaultFlowsPerSource).Name, "{ "+c.source+" }")
	}
	run("add", "set", "ip6", TableName, flowSet(egress.FamilyIPv6, egress.DefaultFlowsPerSource).Name, "{ type ipv6_addr; size 100; flags dynamic; }")
	read, err := be.Rules(tr.desired())
	if err != nil || read[egress.FamilyIPv6].fault == "" || read[egress.FamilyIPv6].remake || read[egress.FamilyIPv4].fault != "" {
		t.Errorf("with the ip6 set resized the tables read back as %+v (%v), want the ip6 table alone at fault, with no remake", read, err)
	}
	handles := tableHandles(t, another)
	if err := tr.reconcile(); err != nil {
		t.Fatalf("the pass after the resize: %v", err)
	}
	if got := tableHandles(t, another); len(got) != 2 || !maps.Equal(got, handles) {
		t.Errorf("after the pass wrote the set back the tables have the handles %v, want the ones they had, %v", got, handles)
	}
	read, err = be.Rules(tr.desired())
	if _, faulted, remake := flatten(read); err != nil || faulted || len(remake) != 0 {
		t.Errorf("after the pass the tables read back as %+v (%v), want both as written", read, err)
	}
	for _, c := range counted {
		if listing := run("list", "set", tableFamilyName(c.family), TableName, flowSet(c.family, egress.DefaultFlowsPerSource).Name); !strings.Contains(listing, "elements = { "+c.source+" }") {
			t.Errorf("after the pass the %s set no longer holds %s's element:\n%s", tableFamilyName(c.family), c.source, listing)
		}
	}
	if s := tr.lastPass(); !s.Ready4 || !s.Ready6 {
		t.Errorf("after the pass the translator reads %+v, want both families ready", s)
	}
}

// A table an instance of another limit left behind, as one that stopped
// without withdrawing would, reads back with each set at a fault that remakes
// it, since each element keeps the limit it was added under. After the pass
// each table is a new one, its set holding no element and reading back under
// the translator's limit, and both families are ready.
func TestNftablesRemakesATableWhoseSetCountsAnotherLimit(t *testing.T) {
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
	rt := Runtime{Interface: "ranet0", Steered: true, Forwarding: func() (bool, bool) { return true, true }, Sysctl: readsNothing}
	earlier, later := egress.Egress{FlowsPerSource: 64}, egress.Egress{}
	before, err := newBackend(earlier, rt)
	if err != nil {
		t.Fatalf("open the nftables backend: %v", err)
	}
	requireEmptyRuleset(t, before)
	if err := newTranslator(earlier, rt, before).reconcile(); err != nil {
		t.Fatalf("the earlier instance's pass: %v", err)
	}
	counted := map[uint8]string{egress.FamilyIPv4: "192.0.2.2", egress.FamilyIPv6: "3fff::2"}
	for family, source := range counted {
		run("add", "element", tableFamilyName(family), TableName, flowSet(family, earlier.SourceLimit()).Name, "{ "+source+" }")
	}
	if err := before.Close(); err != nil {
		t.Fatal(err)
	}
	be, err := newBackend(later, rt)
	if err != nil {
		t.Fatalf("open the nftables backend again: %v", err)
	}
	t.Cleanup(func() { _ = be.Close() })
	read, err := be.Rules(newTranslator(later, rt, be).desired())
	for _, family := range []uint8{egress.FamilyIPv4, egress.FamilyIPv6} {
		if err != nil || !strings.Contains(read[family].fault, "limit 64") || !read[family].remake {
			t.Errorf("with the earlier instance's set the %s table reads back as %+v (%v), want a fault naming its limit that remakes it", tableFamilyName(family), read[family], err)
		}
	}
	another, err := nftables.Dial()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = another.Close() })
	handles := tableHandles(t, another)
	tr := newTranslator(later, rt, be)
	if err := tr.reconcile(); err != nil {
		t.Fatalf("the pass: %v", err)
	}
	after := tableHandles(t, another)
	if len(after) != 2 {
		t.Errorf("after the pass the tables have the handles %v, want one table in each family", after)
	}
	for family, handle := range after {
		if handle == handles[family] {
			t.Errorf("after the pass the %s table has the handle %d it had, so it was not remade", tableFamilyName(family), handle)
		}
	}
	read, err = be.Rules(tr.desired())
	if _, faulted, remake := flatten(read); err != nil || faulted || len(remake) != 0 {
		t.Errorf("after the pass the tables read back as %+v (%v), want both as written", read, err)
	}
	for family, source := range counted {
		listing := run("list", "set", tableFamilyName(family), TableName, flowSet(family, later.SourceLimit()).Name)
		if strings.Contains(listing, source) || !strings.Contains(listing, fmt.Sprintf("comment %q", flowSet(family, later.SourceLimit()).Comment)) {
			t.Errorf("after the pass the %s set lists, want it without %s's element and under its comment:\n%s", tableFamilyName(family), source, listing)
		}
	}
	if s := tr.lastPass(); !s.Ready4 || !s.Ready6 {
		t.Errorf("after the pass the translator reads %+v, want both families ready", s)
	}
}

// Another writer's nat chains at the source translation hook are reported at
// natPriority and below, where they may translate a flow ahead of the exit's,
// and not at srcnat, past it, in each family and in inet, which hooks both. One
// in the exit's own table beside its chain, and one under the exit's chain's
// name in an inet table of the exit's table's name, are reported as another
// writer's.
func TestNftablesReportsTheNatChainsAtItsPriorityOrBelow(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	enterThrowawayNamespace(t)
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Fatal("another writer's chains are made through nft, which is not on the path")
	}
	rt := Runtime{Interface: "ranet0", Steered: true, Forwarding: func() (bool, bool) { return true, true }, Sysctl: readsNothing}
	be, err := newBackend(egress.Egress{}, rt)
	if err != nil {
		t.Fatalf("open the nftables backend: %v", err)
	}
	t.Cleanup(func() { _ = be.Close() })
	requireEmptyRuleset(t, be)
	if err := be.Apply(newTranslator(egress.Egress{}, rt, be).desired(), nil); err != nil {
		t.Fatalf("install the translator's rules: %v", err)
	}
	sneak := fmt.Sprintf("{ type nat hook postrouting priority %d ; }", natPriority-49)
	if out, err := exec.Command(nft, "add", "chain", "ip", TableName, "sneak", sneak).CombinedOutput(); err != nil {
		t.Fatalf("make another writer's chain in the translator's ip table: %v\n%s", err, out)
	}
	want := []string{fmt.Sprintf("ip table %s chain sneak at priority %d", TableName, natPriority-49)}
	// the exit's own chain's name in an inet table of its own table's name, as
	// the border's is, hooks both families and is another writer's
	inet := fmt.Sprintf("{ type nat hook postrouting priority %d ; }", natPriority)
	if out, err := exec.Command(nft, "add", "table", "inet", TableName).CombinedOutput(); err != nil {
		t.Fatalf("make an inet table named %s: %v\n%s", TableName, err, out)
	}
	if out, err := exec.Command(nft, "add", "chain", "inet", TableName, ChainName, inet).CombinedOutput(); err != nil {
		t.Fatalf("make another writer's chain %s in the inet table %s: %v\n%s", ChainName, TableName, err, out)
	}
	want = append(want, fmt.Sprintf("inet table %s chain %s at priority %d", TableName, ChainName, natPriority))
	for _, name := range []string{"ip", "ip6", "inet"} {
		if out, err := exec.Command(nft, "add", "table", name, "other").CombinedOutput(); err != nil {
			t.Fatalf("make another writer's %s table: %v\n%s", name, err, out)
		}
		for _, priority := range []int{natPriority - 1, natPriority, natPriority + 1} {
			chain := fmt.Sprintf("at%d", priority)
			spec := fmt.Sprintf("{ type nat hook postrouting priority %d ; }", priority)
			if out, err := exec.Command(nft, "add", "chain", name, "other", chain, spec).CombinedOutput(); err != nil {
				t.Fatalf("make another writer's %s chain at %d: %v\n%s", name, priority, err, out)
			}
			if priority <= natPriority {
				want = append(want, fmt.Sprintf("%s table other chain %s at priority %d", name, chain, priority))
			}
		}
	}
	slices.Sort(want)
	if got, err := be.Conflicts(); err != nil || !slices.Equal(got, want) {
		t.Errorf("beside another writer's nat chains at %d, %d and %d the backend reports %q (%v), want %q",
			natPriority-1, natPriority, natPriority+1, got, err, want)
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

// Another writer setting a family's table dormant, or making one of its chains
// again at another priority or as a regular chain, wakes the translator, which
// reports both families not ready until the pass that follows, with no sweep
// due, writes the table back, deleting and making it again but in the first
// case, and reads both ready
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
		Sysctl:     readsNothing,
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
			"hook postrouting priority filter;"},
		{"the ip6 chain made again as a regular chain", "ip6",
			fmt.Sprintf("delete chain ip6 %[1]s %[2]s; add chain ip6 %[1]s %[2]s", TableName, ChainName),
			fmt.Sprintf("chain %s {\n\t}", ChainName)},
		{"the ip limit's chain made again at priority 10", "ip",
			fmt.Sprintf("delete chain ip %[1]s %[2]s; add chain ip %[1]s %[2]s { type filter hook forward priority 10; policy accept; }", TableName, LimitChain),
			"hook forward priority filter + 10;"},
	} {
		mark := len(entries())
		run(change.command)
		moved(change.name, mark, "ready false false", "ready true true")
		read, err := check.Rules(desired)
		_, faulted, remake := flatten(read)
		if err != nil || faulted || len(remake) != 0 {
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

// notificationSocket is the descriptor of the one NETLINK_NETFILTER socket of
// this process that joined a group, the backend's notification socket
func notificationSocket(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	var found []int
	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		// the descriptor ReadDir read through is closed by now, and one that is no socket has no domain
		domain, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_DOMAIN)
		if errors.Is(err, unix.EBADF) || errors.Is(err, unix.ENOTSOCK) {
			continue
		}
		if err != nil {
			t.Fatalf("read the domain of descriptor %d: %v", fd, err)
		}
		if domain != unix.AF_NETLINK {
			continue
		}
		protocol, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PROTOCOL)
		if err != nil {
			t.Fatalf("read the protocol of netlink socket %d: %v", fd, err)
		}
		bound, err := unix.Getsockname(fd)
		if err != nil {
			t.Fatalf("read the address of netlink socket %d: %v", fd, err)
		}
		if protocol == unix.NETLINK_NETFILTER && bound.(*unix.SockaddrNetlink).Groups != 0 {
			found = append(found, fd)
		}
	}
	if len(found) != 1 {
		t.Fatalf("found %d netfilter netlink sockets in a group, want the backend's one", len(found))
	}
	return found[0]
}

// socketDrops is how many datagrams the kernel has dropped for the socket fd, and the bytes it holds queued
func socketDrops(t *testing.T, fd int) (dropped, queued uint64) {
	t.Helper()
	var meminfo [unix.SK_MEMINFO_VARS]uint32
	size := uint32(unsafe.Sizeof(meminfo))
	// x/sys wraps no getsockopt that reads SO_MEMINFO's array
	if _, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), unix.SOL_SOCKET, unix.SO_MEMINFO,
		uintptr(unsafe.Pointer(&meminfo)), uintptr(unsafe.Pointer(&size)), 0); errno != 0 {
		t.Fatalf("read the memory of socket %d: %v", fd, errno)
	}
	if size != uint32(unsafe.Sizeof(meminfo)) {
		t.Fatalf("the kernel wrote %d bytes of socket %d's memory, want %d", size, fd, unsafe.Sizeof(meminfo))
	}
	return uint64(meminfo[unix.SK_MEMINFO_DROPS]), uint64(meminfo[unix.SK_MEMINFO_RMEM_ALLOC])
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
	read, err := be.Read(nil)
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
func enterThrowawayNamespace(t testing.TB) {
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

func namespaceID(t testing.TB) uint64 {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat("/proc/thread-self/ns/net", &st); err != nil {
		t.Fatalf("stat this thread's network namespace: %v", err)
	}
	return st.Ino
}
