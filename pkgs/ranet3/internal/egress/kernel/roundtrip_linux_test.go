// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"cmp"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
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
	"ranet3.com/pkgs/ranet3/internal/logtest"
	"ranet3.com/pkgs/ranet3/internal/netlink"
	"ranet3.com/pkgs/ranet3/internal/netnstest"
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
	netnstest.EnterEmpty(t)

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
	if len(desired) != 56 {
		t.Fatalf("the configuration asks for %d rules, want 56", len(desired))
	}
	if err := be.Apply(desired, false); err != nil {
		t.Fatalf("install %d rules: %v", len(desired), err)
	}

	// The whole round trip in one assertion: the kernel took every expression,
	// kept the rules in the order they were written, and handed back the
	// spelling this package wrote into each one's comment and the expressions
	// it encoded, as a dump spells them. A mismatch here is a ruleset the
	// reconcile loop would rewrite on every pass forever. Each family's
	// chains, set and timeout objects read back as written.
	read, err := be.Rules(desired)
	if err != nil {
		t.Fatalf("read the rules back: %v", err)
	}
	held, faulted, remake := flatten(read)
	for _, family := range []uint8{egress.FamilyIPv4, egress.FamilyIPv6} {
		if read[family].fault != "" || remake {
			t.Errorf("the %s family reads back with the fault %q and remake %v, want it as written", familyLabel(family), read[family].fault, remake)
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
	// the table holds the timeout objects each family's rules name, every
	// state at the seconds it was written with
	for _, family := range []uint8{egress.FamilyIPv4, egress.FamilyIPv6} {
		if got, want := heldTimeouts(t, be.(*natTables).conn, family), timeoutObjects(family); !reflect.DeepEqual(got, want) {
			t.Errorf("the table holds the %s timeout objects %+v, want %+v", familyLabel(family), got, want)
		}
	}

	// A rule with no comment in this tool's chain is another writer's, and the
	// readback holds it where the kernel does, in the first family, so a diff
	// built from it rewrites the chain, and every family stops reading back as
	// written, since every family shares the chain.
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Fatal("another writer's rule is written through nft, which is not on the path")
	}
	if out, err := exec.Command(nft, "insert", "rule", "inet", nftables.Table, ChainName, "accept").CombinedOutput(); err != nil {
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
	// behind the ip rules of the forward chain, which read back first
	forwardRules := 0
	for _, rule := range desired {
		if rule.Family == egress.FamilyIPv4 && rule.chain() != ChainName {
			forwardRules++
		}
	}
	if !slices.Equal(got, slices.Insert(slices.Clone(want), forwardRules, "")) {
		t.Errorf("with another writer's uncommented rule at the head of the postrouting chain the readback holds %q, want it ahead of the ip translation's rules in %q", got, want)
	}
	if v4, v6 := read[egress.FamilyIPv4].fault, read[egress.FamilyIPv6].fault; v4 == "" || v6 == "" {
		t.Errorf("with another writer's rule in the postrouting chain the ip readback reads the fault %q and the ip6 one %q, want one in each", v4, v6)
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
	if err := be.Apply(desired, false); err != nil {
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

	// an exit advertising nothing still writes the set and timeout objects of each family, for what its egress segment writes to the tun
	steered, err := newBackend(egress.Egress{}, rt)
	if err != nil {
		t.Fatalf("open the nftables backend for an exit advertising nothing: %v", err)
	}
	t.Cleanup(func() { _ = steered.Close() })
	only := newTranslator(egress.Egress{}, rt, steered).desired()
	if err := steered.Apply(only, false); err != nil {
		t.Fatalf("install %d rules: %v", len(only), err)
	}
	read, err = steered.Rules(only)
	if held, faulted, _ = flatten(read); err != nil || faulted || len(held) != len(only) {
		t.Fatalf("the kernel holds %v (%v), want %v", held, err, only)
	}
	tables, err := nftables.Tables(steered.(*natTables).conn, nftables.Table)
	if _, inet := tables[unix.NFPROTO_INET]; err != nil || len(tables) != 1 || !inet {
		t.Errorf("an exit advertising nothing holds tables in %v (%v), want inet alone", tables, err)
	}
	for _, family := range []uint8{egress.FamilyIPv4, egress.FamilyIPv6} {
		if got, want := heldTimeouts(t, steered.(*natTables).conn, family), timeoutObjects(family); !reflect.DeepEqual(got, want) {
			t.Errorf("an exit advertising nothing holds the %s timeout objects %+v, want %+v", familyLabel(family), got, want)
		}
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
	netnstest.EnterEmpty(t)
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
		if err := be.Apply(rules, false); err != nil {
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
		{"inserted an accept at the head of the postrouting chain", anotherWritersAccept(unix.NFPROTO_INET, ChainName)},
		{"set the table dormant", dormantTable(unix.NFPROTO_INET)},
		{"deleted the table", nftables.DeleteTable(unix.NFPROTO_INET, nftables.Table)},
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

// familyLabel is the word nft spells family's packets with, ip or ip6
func familyLabel(family uint8) string {
	if family == egress.FamilyIPv4 {
		return "ip"
	}
	return "ip6"
}

// anotherWritersAccept is another writer's rule with no comment accepting
// every packet, at the head of chain in this tool's table of the family proto
func anotherWritersAccept(proto uint8, chain string) nftables.Request {
	return anotherWritersRule(proto, chain, nftables.Verdict(nftables.Accept))
}

// anotherWritersRule is another writer's rule with no comment of expressions,
// at the head of chain in this tool's table of the family proto
func anotherWritersRule(proto uint8, chain string, expressions ...[]byte) nftables.Request {
	body := netlink.PutAttrString(netlink.PutAttrString(nftables.PutNfgenmsg(nil, proto), unix.NFTA_RULE_TABLE, nftables.Table), unix.NFTA_RULE_CHAIN, chain)
	body = netlink.PutAttr(body, unix.NFTA_RULE_EXPRESSIONS|unix.NLA_F_NESTED, slices.Concat(expressions...))
	// with no NLM_F_APPEND the kernel inserts the rule at the head of the chain
	return nftables.Request{Kind: nftables.Command(unix.NFT_MSG_NEWRULE), Flags: unix.NLM_F_CREATE, Body: body}
}

// dormantTable is another writer's update setting this tool's table of the
// family proto dormant
func dormantTable(proto uint8) nftables.Request {
	body := netlink.PutAttrString(nftables.PutNfgenmsg(nil, proto), unix.NFTA_TABLE_NAME, nftables.Table)
	body = nftables.PutAttrBE32(body, unix.NFTA_TABLE_FLAGS, unix.NFT_TABLE_F_DORMANT)
	return nftables.Request{Kind: nftables.Command(unix.NFT_MSG_NEWTABLE), Flags: unix.NLM_F_CREATE, Body: body}
}

// A rule with no comment that another writer inserts at the head of one of the
// translator's own chains is read back with it, in the first family, so the
// next pass rewrites the chains and leaves only the translator's rules, in the
// table it found, so with the timeout objects in it, which a deletion would
// detach from every flow they time, and the sets, which a deletion would empty
// of every source's count
func TestNftablesRewritesAnotherWritersRuleInItsChain(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmpty(t)
	rt := Runtime{
		Interface:  "ranet0",
		Steered:    true,
		Forwarding: func() (bool, bool) { return true, true },
		Sysctl:     readsNothing,
		Hooks:      unheard,
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
	// the postrouting one counted, which the debug read names by its chain
	counted := anotherWritersRule(unix.NFPROTO_INET, ChainName, nftables.Expression("counter", nil), nftables.Verdict(nftables.Accept))
	if err := another.Batch([]nftables.Request{counted, anotherWritersAccept(unix.NFPROTO_INET, LimitChain)}); err != nil {
		t.Fatalf("insert another writer's accept rules: %v", err)
	}
	read, err := be.Rules(tr.desired())
	for _, want := range []Installed{{Family: egress.FamilyIPv4, Chain: LimitChain}, {Family: egress.FamilyIPv4, Chain: ChainName, Counted: true}} {
		if err != nil || !slices.Contains(read[egress.FamilyIPv4].rules, want) {
			t.Errorf("with another writer's accept rule at the head of the forward and postrouting chains the ip readback holds %v (%v), want %+v among them",
				read[egress.FamilyIPv4], err, want)
		}
	}
	if err != nil || read[egress.FamilyIPv6].fault == "" {
		t.Errorf("with another writer's accept rule in the chains every family shares the ip6 readback reads %+v (%v), want a fault", read[egress.FamilyIPv6], err)
	}
	var extra []egress.RuleReading
	for _, rule := range tr.Debug().Rules {
		if !rule.Wanted {
			extra = append(extra, rule)
		}
	}
	if want := []egress.RuleReading{{Held: true}, {Held: true, Counter: "flows"}}; !slices.Equal(extra, want) {
		t.Errorf("the debug read names another writer's rules %+v, want the forward one uncounted and the postrouting one counting flows, %+v", extra, want)
	}
	handles := tableHandles(t, another)

	if err := tr.reconcile(); err != nil {
		t.Fatalf("second pass: %v", err)
	}
	// a table made again takes a handle the namespace has not given before
	if got := tableHandles(t, another); len(got) != 1 || !maps.Equal(got, handles) {
		t.Errorf("after the pass rewrote the chains the table has the handles %v, want the one it had, %v", got, handles)
	}
	// each chain holds the lines desired writes in it, in desired's order, and
	// forward its one line
	var want []string
	for _, written := range translatorChains {
		if written.Name == LimitChain {
			want = append(want, dispatchSpec)
		}
		for _, rule := range tr.desired() {
			if rule.chain() == written.Name {
				want = append(want, rule.String())
			}
		}
	}
	// read through the other socket, so the chains compared hold every rule the kernel does, whatever this tool's readback keeps
	replies, err := another.Dump(nftables.Command(unix.NFT_MSG_GETRULE), nftables.PutNfgenmsg(nil, unix.NFPROTO_INET))
	if err != nil {
		t.Fatalf("dump the rules: %v", err)
	}
	var got []string
	for _, written := range translatorChains {
		for _, reply := range replies {
			if table, chain, spec, _, _, _ := nftables.DecodeRule(reply); table == nftables.Table && chain == written.Name {
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

// A line another writer replaces in place with an accept under the comment it
// was written with, in the translation's chain, in forward or in IPv6's chain,
// reads back as a fault that names the line, in every family for the
// translation's chain and for forward, which every packet at the forward hook
// meets, and in IPv6 alone for IPv6's chain, and the next pass writes the line
// back and reads both families ready
func TestNftablesRewritesALineEditedUnderItsComment(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmpty(t)
	run := nftRun(t)
	rt := Runtime{Interface: "ranet0", Steered: true, Forwarding: func() (bool, bool) { return true, true }, Sysctl: readsNothing, Hooks: unheard}
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
		{egress.FamilyIPv6, "forward6", Rule{Family: egress.FamilyIPv6, Direction: Out, Interface: "ranet0", Untracked: true}, "ct state invalid,untracked"},
	} {
		spec, family := edit.rule.String(), familyLabel(edit.family)
		if !slices.ContainsFunc(desired, func(rule Rule) bool { return rule.String() == spec }) {
			t.Fatalf("the translator writes no line %q", spec)
		}
		listing := run("-a", "list", "chain", "inet", nftables.Table, edit.chain)
		handle := regexp.MustCompile(`comment "` + regexp.QuoteMeta(spec) + `" # handle (\d+)`).FindStringSubmatch(listing)
		if handle == nil {
			t.Fatalf("no line of the chain %s is commented %q in:\n%s", edit.chain, spec, listing)
		}
		accepted := fmt.Sprintf("meta nfproto %s counter accept comment %q", map[string]string{"ip": "ipv4", "ip6": "ipv6"}[family], spec)
		run(append([]string{"replace", "rule", "inet", nftables.Table, edit.chain, "handle", handle[1]}, strings.Fields(accepted)...)...)
		read, err := be.Rules(desired)
		other := egress.FamilyIPv6
		if edit.family == other {
			other = egress.FamilyIPv4
		}
		shared := edit.chain != forward6.Name
		if err != nil || !strings.Contains(read[edit.family].fault, spec) || read[edit.family].remake || strings.Contains(read[other].fault, spec) != shared ||
			!shared && read[other].fault != "" {
			t.Errorf("%q made an accept in the chain %s: the %s family reads the fault %q, remake %v, and the other the fault %q (%v), want a fault naming the line, in the other too: %v",
				spec, edit.chain, family, read[edit.family].fault, read[edit.family].remake, read[other].fault, err, shared)
		}
		if err := tr.reconcile(); err != nil {
			t.Fatalf("%q made an accept: the pass: %v", spec, err)
		}
		if s := tr.lastPass(); !s.Ready4 || !s.Ready6 {
			t.Errorf("%q made an accept: after the pass the translator reads %+v, want both families ready", spec, s)
		}
		listing = run("list", "chain", "inet", nftables.Table, edit.chain)
		line := regexp.MustCompile(`(?m)^.*comment "` + regexp.QuoteMeta(spec) + `"$`).FindString(listing)
		if !strings.Contains(line, edit.kept) || strings.Contains(line, "accept") {
			t.Errorf("%q made an accept: after the pass nft lists the line %q, want it as written, with %q:\n%s", spec, line, edit.kept, listing)
		}
	}
}

// Forward's first line sends IPv6's packets on to IPv6's chain, IPv4's lines
// follow it in forward, in the order desired writes them, and the table holds
// no chain of IPv4's own. Another writer's rule in IPv6's chain holds IPv6
// alone not ready, with a fault naming that chain, and forward's first line
// written again under its comment, sending IPv4 on in place of IPv6 or
// jumping to IPv6's chain, holds both not ready, with a fault naming the line.
// nf_tables keeps IPv6's chain while forward's line goes to it, so it goes
// missing only with that line, which holds both not ready, and Read, which
// reads no line, names the chain missing in IPv6 alone. After each the next
// pass writes the chains back and reads both families ready.
func TestNftablesReadsForwardAndIPv6sChainBack(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmpty(t)
	run := nftRun(t)
	rt := Runtime{Interface: "ranet0", Steered: true, Forwarding: func() (bool, bool) { return true, true }, Sysctl: readsNothing, Hooks: unheard}
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
	v6 := familyChain(egress.FamilyIPv6)
	written := fmt.Sprintf("meta nfproto ipv6 goto %s comment %q", v6, dispatchSpec)
	want := []string{dispatchSpec}
	for _, rule := range desired {
		if rule.chain() == LimitChain {
			if rule.Family != egress.FamilyIPv4 {
				t.Errorf("forward holds the line %s of %s", rule, egress.FamilyName(rule.Family))
			}
			want = append(want, rule.String())
		}
	}
	commented := regexp.MustCompile(`(?m)^\s+(\S.*comment "([^"]*)")$`)
	listing := run("list", "chain", "inet", nftables.Table, LimitChain)
	var got []string
	for _, line := range commented.FindAllStringSubmatch(listing, -1) {
		got = append(got, line[2])
	}
	if first := commented.FindStringSubmatch(listing); first == nil || first[1] != written || !slices.Equal(got, want) || len(want) < 2 {
		t.Fatalf("forward lists the lines %q, want %s first, then IPv4's %q:\n%s", got, written, want[1:], listing)
	}
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(nft, "delete", "chain", "inet", nftables.Table, v6).CombinedOutput(); err == nil {
		t.Fatalf("nf_tables deleted the chain %s while forward's line goes to it: %s", v6, out)
	}
	another, err := nftables.Dial()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = another.Close() })
	ready := func(what string) {
		t.Helper()
		if err := tr.reconcile(); err != nil {
			t.Fatalf("%s: the pass: %v", what, err)
		}
		if s := tr.lastPass(); !s.Ready4 || !s.Ready6 {
			t.Errorf("%s: after the pass the translator reads %+v, want both families ready", what, s)
		}
		if listing := run("list", "table", "inet", nftables.Table); !strings.Contains(listing, written) || regexp.MustCompile(`(?m)^\s+accept$`).MatchString(listing) ||
			!strings.Contains(listing, "chain "+v6+" {") || strings.Contains(listing, "chain "+retiredChain+" {") {
			t.Errorf("%s: after the pass nft lists, want forward's line and the chain %s as written, no chain %s and no accept:\n%s", what, v6, retiredChain, listing)
		}
	}

	if err := another.Batch([]nftables.Request{anotherWritersAccept(unix.NFPROTO_INET, v6)}); err != nil {
		t.Fatalf("insert another writer's accept rule: %v", err)
	}
	read, err := be.Rules(desired)
	if err != nil || !strings.Contains(read[egress.FamilyIPv6].fault, "its chain "+v6+" holds") || read[egress.FamilyIPv4].fault != "" {
		t.Errorf("another writer's rule in %s: the ip6 family reads the fault %q and the ip one %q (%v), want one naming %s in the ip6 family alone",
			v6, read[egress.FamilyIPv6].fault, read[egress.FamilyIPv4].fault, err, v6)
	}
	ready("another writer's rule in " + v6)

	for _, edit := range []string{
		fmt.Sprintf("meta nfproto ipv4 goto %s comment %q", v6, dispatchSpec),
		fmt.Sprintf("meta nfproto ipv6 jump %s comment %q", v6, dispatchSpec),
	} {
		handle := regexp.MustCompile(`comment "` + regexp.QuoteMeta(dispatchSpec) + `" # handle (\d+)`).FindStringSubmatch(run("-a", "list", "chain", "inet", nftables.Table, LimitChain))
		if handle == nil {
			t.Fatalf("no line of forward is commented %q", dispatchSpec)
		}
		run(append([]string{"replace", "rule", "inet", nftables.Table, LimitChain, "handle", handle[1]}, strings.Fields(edit)...)...)
		read, err = be.Rules(desired)
		if err != nil || !strings.Contains(read[egress.FamilyIPv4].fault, dispatchSpec) || !strings.Contains(read[egress.FamilyIPv6].fault, dispatchSpec) {
			t.Errorf("forward's first line written again as %s: the ip family reads the fault %q and the ip6 one %q (%v), want both naming the line",
				edit, read[egress.FamilyIPv4].fault, read[egress.FamilyIPv6].fault, err)
		}
		ready("forward's first line written again as " + edit)
	}

	run(fmt.Sprintf("flush chain inet %[1]s %[2]s; delete chain inet %[1]s %[3]s", nftables.Table, LimitChain, v6))
	read, err = be.Rules(desired)
	gone := "its chain " + LimitChain + " holds []"
	if err != nil || !strings.Contains(read[egress.FamilyIPv4].fault, gone) || !strings.Contains(read[egress.FamilyIPv6].fault, gone) {
		t.Errorf("forward emptied and %s deleted: the ip family reads the fault %q and the ip6 one %q (%v), want both at %q",
			v6, read[egress.FamilyIPv4].fault, read[egress.FamilyIPv6].fault, err, gone)
	}
	read, err = be.Read(desired)
	if missing := "its chain " + v6 + " is missing"; err != nil || read[egress.FamilyIPv6].fault != missing || read[egress.FamilyIPv4].fault != "" {
		t.Errorf("forward emptied and %s deleted: Read reads the ip6 family's fault %q and the ip one's %q (%v), want %q in the ip6 family alone",
			v6, read[egress.FamilyIPv6].fault, read[egress.FamilyIPv4].fault, err, missing)
	}
	ready("forward emptied and " + v6 + " deleted")
}

// A table an earlier translator wrote, whose forward held one line, a vmap
// sending each family's packets on to a chain of that family's, and IPv4's
// lines in a chain of IPv4's own, reads back with a fault in both families,
// and the next pass, in one transaction, empties every chain before it
// deletes IPv4's, which the map's goto held until its line went, writes
// forward's first line and IPv4's lines into forward, and reads both families
// ready, the table's handle kept
func TestNftablesRemakesTheTableAnEarlierLayoutWrote(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmpty(t)
	run := nftRun(t)
	rt := Runtime{Interface: "ranet0", Steered: true, Forwarding: func() (bool, bool) { return true, true }, Sysctl: readsNothing, Hooks: unheard}
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
	another, err := nftables.Dial()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = another.Close() })
	handles := tableHandles(t, another)

	// the earlier layout: IPv4's lines, as they are written, in a chain of
	// their own, and forward's one line the vmap sending each family to its chain
	earlier := regularChain(retiredChain)
	run("flush", "chain", "inet", nftables.Table, LimitChain)
	requests := []nftables.Request{earlier.Create(unix.NFPROTO_INET)}
	var moved []string
	for _, rule := range desired {
		if rule.chain() != LimitChain {
			continue
		}
		line, err := translatorLine(rule, unix.NFT_CT_LABELS)
		if err != nil {
			t.Fatal(err)
		}
		request, err := earlier.Rule(unix.NFPROTO_INET, line.Spec, line.Expressions)
		if err != nil {
			t.Fatal(err)
		}
		requests, moved = append(requests, request), append(moved, line.Spec)
	}
	if err := another.Batch(requests); err != nil {
		t.Fatalf("write IPv4's lines into the chain %s: %v", retiredChain, err)
	}
	run("add", "rule", "inet", nftables.Table, LimitChain, "meta", "nfproto", "vmap", "{", "ipv4", ":", "goto", retiredChain, ",", "ipv6", ":", "goto", forward6.Name, "}",
		"comment", `"ipv4 to `+retiredChain+`, ipv6 to `+forward6.Name+`"`)
	if listing := run("list", "table", "inet", nftables.Table); len(moved) == 0 || !strings.Contains(listing, "chain "+retiredChain+" {") || !strings.Contains(listing, "vmap") {
		t.Fatalf("the earlier layout lists, want IPv4's lines %q in the chain %s and forward's vmap:\n%s", moved, retiredChain, listing)
	}

	read, err := be.Rules(desired)
	for _, family := range []uint8{egress.FamilyIPv4, egress.FamilyIPv6} {
		if err != nil || read[family].fault == "" {
			t.Errorf("the earlier layout: the %s family reads the fault %q (%v), want one", egress.FamilyName(family), read[family].fault, err)
		}
	}
	if err := tr.reconcile(); err != nil {
		t.Fatalf("the pass over the earlier layout: %v", err)
	}
	if s := tr.lastPass(); !s.Ready4 || !s.Ready6 {
		t.Errorf("after the pass over the earlier layout the translator reads %+v, want both families ready", s)
	}
	listing := run("list", "table", "inet", nftables.Table)
	if strings.Contains(listing, "chain "+retiredChain+" {") || strings.Contains(listing, "vmap") ||
		!strings.Contains(listing, fmt.Sprintf("meta nfproto ipv6 goto %s comment %q", forward6.Name, dispatchSpec)) {
		t.Errorf("after the pass over the earlier layout nft lists, want no chain %s, no vmap and forward's line to %s:\n%s", retiredChain, forward6.Name, listing)
	}
	for _, spec := range moved {
		if line := regexp.MustCompile(`(?m)^.*comment "` + regexp.QuoteMeta(spec) + `"$`).FindString(run("list", "chain", "inet", nftables.Table, LimitChain)); line == "" {
			t.Errorf("after the pass over the earlier layout forward holds no line %q", spec)
		}
	}
	if got := tableHandles(t, another); !maps.Equal(got, handles) {
		t.Errorf("after the pass over the earlier layout the table has the handles %v, want the one it had, %v", got, handles)
	}
}

// A chain an earlier translator wrote for a class of none, which the table
// lists ahead of the chain an earlier translator held IPv4's lines in and
// which a goto of that chain holds, reads back with a fault in both families.
// The next pass, in one transaction, empties both chains before it deletes
// either, so nf_tables lets the goto go and deletes both, and both families
// read ready.
func TestNftablesDeletesTheRetiredChainBesideAStrayItGoesTo(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmpty(t)
	run := nftRun(t)
	rt := Runtime{Interface: "ranet0", Steered: true, Forwarding: func() (bool, bool) { return true, true }, Sysctl: readsNothing, Hooks: unheard}
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

	stray := NoneChain + "198_51_100_0_24"
	run("add", "chain", "inet", nftables.Table, stray)
	run("add", "chain", "inet", nftables.Table, retiredChain)
	run("add", "rule", "inet", nftables.Table, retiredChain, "ip", "saddr", "198.51.100.0/24", "goto", stray)
	listing := run("list", "table", "inet", nftables.Table)
	first, second := strings.Index(listing, "chain "+stray+" {"), strings.Index(listing, "chain "+retiredChain+" {")
	if first < 0 || second < first || !strings.Contains(listing, "goto "+stray) {
		t.Fatalf("the table lists, want the chain %s ahead of %s, which goes to it:\n%s", stray, retiredChain, listing)
	}
	read, err := be.Rules(desired)
	for _, family := range []uint8{egress.FamilyIPv4, egress.FamilyIPv6} {
		if err != nil || read[family].fault == "" {
			t.Errorf("beside both chains the %s family reads the fault %q (%v), want one", egress.FamilyName(family), read[family].fault, err)
		}
	}

	if err := tr.reconcile(); err != nil {
		t.Fatalf("the pass beside both chains: %v", err)
	}
	if s := tr.lastPass(); !s.Ready4 || !s.Ready6 {
		t.Errorf("after the pass beside both chains the translator reads %+v, want both families ready", s)
	}
	listing = run("list", "table", "inet", nftables.Table)
	for _, gone := range []string{"chain " + stray + " {", "chain " + retiredChain + " {"} {
		if strings.Contains(listing, gone) {
			t.Errorf("after the pass beside both chains nft lists %q, want it deleted:\n%s", gone, listing)
		}
	}
}

// `ranet3 down` on a node whose pass wrote the translator's chains, sets and
// objects keeps the translation's chain as the pass wrote it, its rules and its
// objects among it, and writes the forward hook's chains with a stopped
// translator's lines in them, each reading back as written. Nft lists each line
// of the stop with its counter, and debug egress reads each held. The
// translation's chain is one chain from the first write to the withdrawal,
// never deleted, so the host's translation hooks stay with it. A start over the
// chains of a run that died, up or down, writes its own in place, and a
// withdrawal at shutdown after a stop leaves the ruleset empty.
func TestNftablesHoldsAStoppedTranslatorsChainsUntilTheNextPass(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmpty(t)
	run := nftRun(t)
	cfg := egress.Egress{Translate: []egress.Class{
		{From: schema.MustPrefix("192.0.2.0/24"), To: egress.Translation{None: true}},
		{From: schema.MustPrefix("192.0.2.128/25"), To: egress.Translation{Auto: true}},
		{From: schema.MustPrefix("2001:db8::/32"), To: egress.Translation{None: true}},
	}}
	rt := Runtime{Interface: "ranet0", Steered: true, Forwarding: func() (bool, bool) { return true, true }, Sysctl: readsNothing, Hooks: unheard}
	// start is a new process's translator over the host's chains as it finds
	// them, and what ends that process without a withdrawal
	start := func() (*Translator, func()) {
		t.Helper()
		be, err := newBackend(cfg, rt)
		if err != nil {
			t.Fatalf("open the nftables backend: %v", err)
		}
		end := sync.OnceFunc(func() { _ = be.Close() })
		t.Cleanup(end)
		return newTranslator(cfg, rt, be), end
	}
	tr, died := start()
	requireEmptyRuleset(t, tr.be)
	// handle is the handle nft lists the translation's chain under
	handle := func() string {
		t.Helper()
		listing := run("-a", "list", "chain", "inet", nftables.Table, ChainName)
		_, after, ok := strings.Cut(listing, "chain "+ChainName+" { # handle ")
		if !ok {
			t.Fatalf("nft lists the translation's chain with no handle:\n%s", listing)
		}
		number, _, _ := strings.Cut(after, "\n")
		return number
	}
	// stopped checks the host holds tr's stopped rules as written, the lines of
	// the stop as an operator reads them, and debug egress reading each held
	stopped := func(tr *Translator, when string) {
		t.Helper()
		read, err := tr.be.Rules(tr.stopped())
		if _, faulted, _ := flatten(read); err != nil || faulted {
			t.Errorf("%s the chains read back with a fault (%v): %+v", when, err, read)
		}
		// each line of the stop, as the start and the end of its line, the first
		// line of forward sending all of IPv6 on as a pass's does
		for chain, want := range map[string][][2]string{
			LimitChain: {
				{`meta nfproto ipv6 goto ` + forward6.Name, `comment "` + dispatchSpec + `"`},
				{`iifname "ranet0" oifname != "ranet0" ip saddr @untranslated4 ct label 127 counter`, `drop comment "out via ranet0 ipv4 untranslated leaving by another link dropped while stopped"`},
				{`iifname "ranet0" oifname != "ranet0" counter`, `drop comment "out via ranet0 ipv4 dropped while stopped"`},
				{`oifname != "ranet0" ct label 127 counter`, `drop comment "translated via ranet0 ipv4 leaving by another link dropped while stopped"`},
			},
			forward6.Name: {
				{`iifname "ranet0" oifname != "ranet0" ip6 saddr @untranslated6 ct label 127 counter`, `drop comment "out via ranet0 ipv6 untranslated leaving by another link dropped while stopped"`},
				{`iifname "ranet0" oifname != "ranet0" counter`, `drop comment "out via ranet0 ipv6 dropped while stopped"`},
				{`oifname != "ranet0" ct label 127 counter`, `drop comment "translated via ranet0 ipv6 leaving by another link dropped while stopped"`},
			},
		} {
			listing := run("list", "chain", "inet", nftables.Table, chain)
			var lines []string
			for line := range strings.Lines(listing) {
				if line = strings.TrimSpace(line); strings.Contains(line, ` while stopped"`) || strings.Contains(line, `"`+dispatchSpec+`"`) {
					lines = append(lines, line)
				}
			}
			if !slices.EqualFunc(lines, want, func(line string, ends [2]string) bool {
				return strings.HasPrefix(line, ends[0]) && strings.HasSuffix(line, ends[1])
			}) {
				t.Errorf("%s nft lists the chain %s as\n%s\nwant its lines of the stop to read %q", when, chain, listing, want)
			}
		}
		tr.Enabled.Store(false)
		for _, rule := range tr.Debug().Rules {
			if !rule.Wanted || !rule.Held || strings.HasSuffix(rule.Spec, "dropped while stopped") && rule.Counter != "packets" {
				t.Errorf("%s debug egress reads %+v, want it wanted and held, a drop of the stop counting packets", when, rule)
			}
		}
	}
	// running checks the host holds tr's own rules as written, none of a stop's
	running := func(tr *Translator, when string) {
		t.Helper()
		listing := run("list", "table", "inet", nftables.Table)
		if s := tr.lastPass(); !s.Ready4 || !s.Ready6 || strings.Contains(listing, "while stopped") ||
			!strings.Contains(listing, fmt.Sprintf("meta nfproto ipv6 goto %s comment %q", forward6.Name, dispatchSpec)) {
			t.Errorf("%s the translator reads %+v and nft lists, want both families ready, forward's first line sending all of IPv6 on and no line of the stop:\n%s", when, s, listing)
		}
	}

	if err := tr.reconcile(); err != nil {
		t.Fatalf("the first pass: %v", err)
	}
	running(tr, "after the first pass")
	chain, translation := handle(), run("list", "chain", "inet", nftables.Table, ChainName)
	if err := tr.stop(); err != nil {
		t.Fatalf("the stop after a pass: %v", err)
	}
	stopped(tr, "after a pass")
	if got := run("list", "chain", "inet", nftables.Table, ChainName); got != translation {
		t.Errorf("the stop lists the translation's chain as\n%s\nwant it as the pass wrote it\n%s", got, translation)
	}
	// each start below is a new process's over the chains the last one left as
	// it died
	died()
	up, died := start()
	if err := up.reconcile(); err != nil {
		t.Fatalf("the first pass of a start over a stop's chains: %v", err)
	}
	running(up, "after a start up over a stop's chains")
	if got := run("list", "chain", "inet", nftables.Table, ChainName); got != translation {
		t.Errorf("a start up over a stop's chains lists the translation's chain as\n%s\nwant it as the pass wrote it\n%s", got, translation)
	}
	died()
	down, died := start()
	if err := down.stop(); err != nil {
		t.Fatalf("the stop of a start down over a pass's chains: %v", err)
	}
	stopped(down, "after a start down over a pass's chains")
	died()
	again, _ := start()
	if err := again.stop(); err != nil {
		t.Fatalf("the stop of a start down over a stop's chains: %v", err)
	}
	stopped(again, "after a start down over a stop's chains")
	if got := handle(); got != chain {
		t.Errorf("the translation's chain went from handle %s to %s, want one chain throughout", chain, got)
	}
	if err := again.be.Withdraw(); err != nil {
		t.Fatalf("the withdrawal after a stop: %v", err)
	}
	requireEmptyRuleset(t, again.be)
}

// A stopped translator's run writes its chains back on the wake of another
// writer's change, its drop deleted alone or its table whole, with no sweep
// due, and reads stopped again once they read back as the stop writes them.
func TestNftablesPutsBackAStoppedTranslatorsChainsAnotherWriterDeletes(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmpty(t)
	run := nftRun(t)
	// no sweep comes within notificationWait, so only a wake explains a rewrite
	cfg := egress.Egress{Sweep: schema.Duration(lateSweep)}
	rt := Runtime{Interface: "ranet0", Steered: true, Forwarding: func() (bool, bool) { return true, true }, Sysctl: readsNothing, Hooks: unheard}
	be, err := newBackend(cfg, rt)
	if err != nil {
		t.Fatalf("open the nftables backend: %v", err)
	}
	requireEmptyRuleset(t, be)
	// a backend of its own reads the chains back, since the run goroutine holds be's socket
	check, err := newBackend(cfg, rt)
	if err != nil {
		t.Fatalf("open a second nftables backend: %v", err)
	}
	t.Cleanup(func() { _ = check.Close() })
	reader := check.(*natTables)
	tr := newTranslator(cfg, rt, be)
	tr.Enabled.Store(false)
	held := tr.stopped()
	const drop = `drop comment "out via ranet0 ipv4 dropped while stopped"`
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- tr.Run(ctx) }()
	// back waits for the stop's rules to read back as written and the
	// translator to read stopped
	back := func(what string) {
		t.Helper()
		for deadline := time.Now().Add(notificationWait); ; time.Sleep(passPoll) {
			read, err := reader.read(reader.conn, held, true)
			_, faulted, _ := flatten(read)
			s := tr.Status()
			if err == nil && !faulted && s.Unready == "the translator is stopped" {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: the chains read back as %+v (%v) and the translator reads %q, want the stop's rules as written and it stopped",
					what, read, err, s.Unready)
			}
		}
	}
	// handle is the handle nft lists the drop under
	handle := func() string {
		t.Helper()
		listing := run("-a", "list", "chain", "inet", nftables.Table, LimitChain)
		for line := range strings.Lines(listing) {
			if before, after, ok := strings.Cut(strings.TrimSpace(line), " # handle "); ok && strings.HasSuffix(before, drop) {
				return after
			}
		}
		t.Fatalf("nft lists forward with no line ending %s:\n%s", drop, listing)
		return ""
	}
	back("the start down")
	deleted := handle()
	run("delete", "rule", "inet", nftables.Table, LimitChain, "handle", deleted)
	back("the drop deleted")
	if got := handle(); got == deleted {
		t.Errorf("the drop is listed under handle %s once that handle is deleted, want it written again under another", got)
	}
	run("delete", "table", "inet", nftables.Table)
	back("the table deleted")
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("stop the translator: %v", err)
	}
	requireEmptyRuleset(t, check)
}

// On a kernel that refuses connection labels, as one built without them
// refuses their key, the translator writes its rules without the label and
// they read back as written: each translation without its labelling, both
// families ready, and a stop's rules without the drops of a labelled flow's
// packets, read in effect. It warns once, at the first write, naming the
// kernel's refusal of the label once as the cause and carrying the kernel's
// answer, and its debug view names that refusal up and down and, down, no rule
// wanted that the stop does not write.
func TestNftablesWritesNoLabelWhereTheKernelRefusesIt(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmpty(t)
	run := nftRun(t)
	var lines strings.Builder
	logtest.SetDefault(t, slog.New(slog.NewTextHandler(&lines, nil)))
	cfg := egress.Egress{}
	rt := Runtime{Interface: "ranet0", Steered: true, Forwarding: func() (bool, bool) { return true, true }, Sysctl: readsNothing, Hooks: unheard}
	be, err := newBackend(cfg, rt)
	if err != nil {
		t.Fatalf("open the nftables backend: %v", err)
	}
	t.Cleanup(func() { _ = be.Close() })
	requireEmptyRuleset(t, be)
	// a key no kernel knows, which nft_ct refuses as a kernel without labels
	// refuses theirs
	be.(*natTables).label.Store(255)
	tr := newTranslator(cfg, rt, be)
	if err := tr.reconcile(); err != nil {
		t.Fatalf("the first pass: %v", err)
	}
	if s := tr.lastPass(); !s.Ready4 || !s.Ready6 || s.Err != "" {
		t.Errorf("the pass without the label reads ready %v and %v with the error %q, want both and none", s.Ready4, s.Ready6, s.Err)
	}
	if listing := run("list", "table", "inet", nftables.Table); strings.Contains(listing, "ct label") || !strings.Contains(listing, "masquerade") {
		t.Errorf("the pass without the label lists, want its translations and no label:\n%s", listing)
	}
	const refused = "the kernel refused a rule that sets or reads a connection label"
	if why := tr.Debug().Unlabelled; !strings.HasPrefix(why, refused) {
		t.Errorf("while up the debug view reads %q of the label, want the kernel's refusal named", why)
	}
	if err := tr.stop(); err != nil {
		t.Fatalf("the stop: %v", err)
	}
	labelled := 0
	for _, rule := range tr.stopped() {
		if rule.Stopped == Labelled {
			labelled++
		}
	}
	if s := tr.Status(); s.Unready != "the translator is stopped" || s.Err != "" || s.Rules.Installed != len(tr.stopped())-labelled {
		t.Errorf("the stop without the label reads %q, the error %q and %d installed, want it in effect with %d", s.Unready, s.Err, s.Rules.Installed, len(tr.stopped())-labelled)
	}
	if listing := run("list", "table", "inet", nftables.Table); strings.Contains(listing, "ct label") || !strings.Contains(listing, "dropped while stopped") {
		t.Errorf("the stop without the label lists, want its drops and no label:\n%s", listing)
	}
	tr.Enabled.Store(false)
	debug := tr.Debug()
	if !strings.HasPrefix(debug.Unlabelled, refused) {
		t.Errorf("while down the debug view reads %q of the label, want the kernel's refusal named", debug.Unlabelled)
	}
	for _, rule := range debug.Rules {
		if rule.Wanted && !rule.Held {
			t.Errorf("while down the debug view names %q wanted and not held, a rule the stop without the label does not write", rule.Spec)
		}
	}
	var warnings []string
	for line := range strings.Lines(lines.String()) {
		if strings.Contains(line, `level=WARN msg="egress cannot label the flows it translates"`) {
			warnings = append(warnings, line)
		}
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], ` why="`+refused) || strings.Count(warnings[0], refused) != 1 || !strings.Contains(warnings[0], ` err="`+unix.EOPNOTSUPP.Error()+`"`) {
		t.Errorf("the translator warned %q that it cannot label, want once, naming the kernel's refusal once as why and carrying its answer as err", warnings)
	}
	if err := be.Withdraw(); err != nil {
		t.Fatalf("the withdrawal: %v", err)
	}
	requireEmptyRuleset(t, be)
}

// The pass's line and each family's set of untranslated sources read back as
// written under nested classes of none in each family, and a second pass
// rewrites nothing. The pass's line another writer makes an accept under its
// comment reads back as a fault of every family naming the line, since
// forward meets every family, and a source another writer adds to a family's
// set or takes from it as a fault of that family alone naming the set, with
// what it holds and what was written. The next pass writes the line or the
// set back and reads both families ready.
func TestNftablesReadsTheUntranslatedSetsBack(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmpty(t)
	run := nftRun(t)
	cfg := egress.Egress{Translate: []egress.Class{
		{From: schema.MustPrefix("192.0.2.0/24"), To: egress.Translation{None: true}},
		{From: schema.MustPrefix("192.0.2.0/26"), To: egress.Translation{Auto: true}},
		{From: schema.MustPrefix("192.0.2.0/27"), To: egress.Translation{None: true}},
		{From: schema.MustPrefix("198.51.100.0/24"), To: egress.Translation{None: true}},
		{From: schema.MustPrefix("2001:db8::/32"), To: egress.Translation{None: true}},
		{From: schema.MustPrefix("2001:db8:1::/48"), To: egress.Translation{Auto: true}},
	}}
	rt := Runtime{Interface: "ranet0", Steered: true, Forwarding: func() (bool, bool) { return true, true }, Sysctl: readsNothing, Hooks: unheard}
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
	before := handles.FindAllString(run("-a", "list", "table", "inet", nftables.Table), -1)
	if err := tr.reconcile(); err != nil {
		t.Fatalf("the second pass: %v", err)
	}
	after := handles.FindAllString(run("-a", "list", "table", "inet", nftables.Table), -1)
	if s := tr.lastPass(); !s.Ready4 || !s.Ready6 || !slices.Equal(before, after) {
		t.Errorf("after the second pass the translator reads %+v, the table's handles %v then %v, want both families ready and no rewrite", s, before, after)
	}
	desired := tr.desired()
	pass := desired[slices.IndexFunc(desired, func(rule Rule) bool { return rule.Family == egress.FamilyIPv4 && rule.Passes })]
	written := "{ 192.0.2.0/27, 192.0.2.64-192.0.2.255, 198.51.100.0/24 }"
	for _, edit := range []struct {
		name string
		// edit changes the host, family is the family the fault holds not
		// ready, 0 for both, and named what the fault names
		edit   func()
		family uint8
		named  string
	}{
		{"the pass made an accept", func() {
			handle := regexp.MustCompile(`comment "` + regexp.QuoteMeta(pass.String()) + `" # handle (\d+)`).FindStringSubmatch(run("-a", "list", "chain", "inet", nftables.Table, LimitChain))
			if handle == nil {
				t.Fatalf("no line of forward is commented %q", pass)
			}
			run(append([]string{"replace", "rule", "inet", nftables.Table, LimitChain, "handle", handle[1]}, strings.Fields(fmt.Sprintf("counter accept comment %q", pass))...)...)
		}, 0, pass.String()},
		{"a source added to untranslated4", func() { run("add", "element", "inet", nftables.Table, untranslatedSet+"4", "{", "203.0.113.0/24", "}") },
			egress.FamilyIPv4, "its set untranslated4 holds { 192.0.2.0/27, 192.0.2.64-192.0.2.255, 198.51.100.0/24, 203.0.113.0/24 }, where " + written + " was written"},
		{"a source taken from untranslated6", func() {
			run("delete", "element", "inet", nftables.Table, untranslatedSet+"6", "{", "2001:db8::/48", "}")
		},
			egress.FamilyIPv6, "its set untranslated6 holds { 2001:db8:2::-2001:db8:ffff:ffff:ffff:ffff:ffff:ffff }, where { 2001:db8::/48, 2001:db8:2::-2001:db8:ffff:ffff:ffff:ffff:ffff:ffff } was written"},
	} {
		edit.edit()
		read, err := be.Rules(desired)
		for _, family := range []uint8{egress.FamilyIPv4, egress.FamilyIPv6} {
			if faulted := edit.family == 0 || edit.family == family; err != nil || strings.Contains(read[family].fault, edit.named) != faulted || !faulted && read[family].fault != "" {
				t.Errorf("%s: the %s family reads the fault %q (%v), want one naming %q: %v", edit.name, familyLabel(family), read[family].fault, err, edit.named, faulted)
			}
		}
		if err := tr.reconcile(); err != nil {
			t.Fatalf("%s: the pass: %v", edit.name, err)
		}
		if s := tr.lastPass(); !s.Ready4 || !s.Ready6 {
			t.Errorf("%s: after the pass the translator reads %+v, want both families ready", edit.name, s)
		}
		if listing := run("list", "set", "inet", nftables.Table, untranslatedSet+"4"); !strings.Contains(listing, "elements = { 192.0.2.0/27, 192.0.2.64-192.0.2.255,") {
			t.Errorf("%s: after the pass nft lists, want %s as written:\n%s", edit.name, written, listing)
		}
		if listing := run("list", "table", "inet", nftables.Table); regexp.MustCompile(`bytes \d+ accept comment`).MatchString(listing) {
			t.Errorf("%s: after the pass nft still lists an accept another writer made:\n%s", edit.name, listing)
		}
	}
}

// The chains an earlier translator wrote for two classes of none, one nested
// in the other, with the pass to the outer one in forward and the inner one's
// pass in the outer one's chain, read back as a fault of every family. The
// next pass empties both, deletes the outer one, which only chains it empties
// went to, and keeps the inner one, which another writer's chain goes to too,
// naming that chain while it stays, with every family not ready. Once that
// rule goes, the next pass deletes the inner chain and reads both families
// ready, and a withdrawal leaves nothing of the translator's, its sets of
// untranslated sources and a chain an earlier translator wrote among them,
// and the other writer's chain in place.
func TestNftablesRetiresTheChainsAnEarlierTranslatorWroteForClassesOfNone(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmpty(t)
	run := nftRun(t)
	cfg := egress.Egress{Translate: []egress.Class{
		{From: schema.MustPrefix("192.0.2.0/24"), To: egress.Translation{None: true}},
		{From: schema.MustPrefix("192.0.2.0/25"), To: egress.Translation{None: true}},
	}}
	rt := Runtime{Interface: "ranet0", Steered: true, Forwarding: func() (bool, bool) { return true, true }, Sysctl: readsNothing, Hooks: unheard}
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
	outer, inner := NoneChain+"192_0_2_0_24", NoneChain+"192_0_2_0_25"
	match := []string{"iifname", "ranet0", "oifname", "!=", "ranet0", "ip", "saddr"}
	run("add", "chain", "inet", nftables.Table, outer)
	run("add", "chain", "inet", nftables.Table, inner)
	run(slices.Concat([]string{"add", "rule", "inet", nftables.Table, outer}, match, []string{"192.0.2.0/25", "goto", inner, "comment", `"out via ranet0 ipv4 from 192.0.2.0/25 passed"`})...)
	run(slices.Concat([]string{"insert", "rule", "inet", nftables.Table, LimitChain}, match, []string{"192.0.2.0/24", "goto", outer, "comment", `"out via ranet0 ipv4 from 192.0.2.0/24 passed"`})...)
	run("add", "chain", "inet", nftables.Table, "other")
	run("add", "rule", "inet", nftables.Table, "other", "goto", inner)
	read, err := be.Rules(tr.desired())
	for _, family := range []uint8{egress.FamilyIPv4, egress.FamilyIPv6} {
		if err != nil || read[family].fault == "" {
			t.Errorf("beside the earlier translator's chains the %s family reads the fault %q (%v), want one", familyLabel(family), read[family].fault, err)
		}
	}

	if err := tr.reconcile(); err != nil {
		t.Fatalf("the pass beside the earlier translator's chains: %v", err)
	}
	held := "its chain " + inner + " is not one the translator writes, and chain other holds a rule going to it, so it stays until that rule goes"
	if s := tr.lastPass(); s.Ready4 || s.Ready6 || !strings.Contains(s.Unready, held) {
		t.Errorf("after the pass beside the earlier translator's chains the translator reads %+v, want both families not ready for %q", s, held)
	}
	listing := run("list", "table", "inet", nftables.Table)
	if strings.Contains(listing, "chain "+outer+" {") || !strings.Contains(listing, "chain "+inner+" {") || strings.Contains(listing, "goto "+outer) ||
		strings.Count(listing, "goto "+inner) != 1 || !strings.Contains(listing, "untranslated passed") {
		t.Errorf("after the pass beside the earlier translator's chains nft lists, want %s deleted, %s empty and kept, other's goto to it and the pass written:\n%s", outer, inner, listing)
	}

	run("flush", "chain", "inet", nftables.Table, "other")
	if err := tr.reconcile(); err != nil {
		t.Fatalf("the pass once other's rule is gone: %v", err)
	}
	if s := tr.lastPass(); !s.Ready4 || !s.Ready6 {
		t.Errorf("once other's rule is gone the translator reads %+v, want both families ready", s)
	}
	if listing := run("list", "table", "inet", nftables.Table); strings.Contains(listing, "chain "+inner+" {") || !strings.Contains(listing, "chain other {") {
		t.Errorf("once other's rule is gone nft lists, want %s deleted and chain other left:\n%s", inner, listing)
	}
	run("add", "chain", "inet", nftables.Table, outer)
	if err := be.Withdraw(); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	listing = run("list", "table", "inet", nftables.Table)
	for _, gone := range []string{"chain " + ChainName + " {", "chain " + LimitChain + " {", "chain " + forward6.Name + " {", "chain " + outer + " {", untranslatedSet + "4", untranslatedSet + "6", flowsSet + "4"} {
		if strings.Contains(listing, gone) {
			t.Errorf("after the withdrawal nft lists %q, want it withdrawn:\n%s", gone, listing)
		}
	}
	if !strings.Contains(listing, "chain other {") {
		t.Errorf("after the withdrawal nft lists, want chain other left:\n%s", listing)
	}
}

// A chain an earlier translator wrote for a class of none, which a rule of
// another writer's chain goes to, by a goto or by its vmap, or an element of a
// named map goes to, so nf_tables will not delete it, holds every family not
// ready with a fault naming that chain or map, while the pass writes the
// rest and fails nothing. Once the rule or the element goes, the next pass
// deletes the chain and reads both families ready, the other writer's chain
// and map left in place. A withdrawal beside such a chain takes the rest of
// the translator's chains, sets and objects in one transaction, which
// nf_tables would refuse whole for a delete of that chain, and leaves it.
func TestNftablesNamesTheChainThatKeepsAStrayChainOfNone(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmpty(t)
	run := nftRun(t)
	cfg := egress.Egress{Translate: []egress.Class{{From: schema.MustPrefix("192.0.2.0/24"), To: egress.Translation{None: true}}}}
	rt := Runtime{Interface: "ranet0", Steered: true, Forwarding: func() (bool, bool) { return true, true }, Sysctl: readsNothing, Hooks: unheard}
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
	run("add", "chain", "inet", nftables.Table, "other")
	run("add", "map", "inet", nftables.Table, "vm", "{", "type", "ipv4_addr", ":", "verdict", ";", "}")
	for _, c := range []struct {
		name string
		// hold makes what goes to the stray chain, and release takes it away
		hold, release func()
		held          string
	}{
		{"a goto of chain other", func() { run("add", "rule", "inet", nftables.Table, "other", "goto", stray) },
			func() { run("flush", "chain", "inet", nftables.Table, "other") }, "and chain other holds a rule going to it"},
		{"a vmap of chain other", func() {
			run("add", "rule", "inet", nftables.Table, "other", "ip", "saddr", "vmap", "{", "192.0.2.1", ":", "goto", stray, "}")
		},
			func() { run("flush", "chain", "inet", nftables.Table, "other") }, "and chain other holds a rule going to it"},
		{"an element of map vm", func() { run("add", "element", "inet", nftables.Table, "vm", "{", "192.0.2.1", ":", "goto", stray, "}") },
			func() { run("delete", "element", "inet", nftables.Table, "vm", "{", "192.0.2.1", "}") }, "and map vm holds an element going to it"},
	} {
		run("add", "chain", "inet", nftables.Table, stray)
		c.hold()
		if err := tr.reconcile(); err != nil {
			t.Fatalf("%s: the pass beside it going to %s: %v", c.name, stray, err)
		}
		held := "its chain " + stray + " is not one the translator writes, " + c.held
		if s := tr.lastPass(); s.Ready4 || s.Ready6 || !strings.Contains(s.Unready, held) {
			t.Errorf("%s: beside it going to %s the translator reads %+v, want both families not ready for %q", c.name, stray, s, held)
		}
		if listing := run("list", "table", "inet", nftables.Table); !strings.Contains(listing, "chain "+stray+" {") || !strings.Contains(listing, "untranslated passed") {
			t.Errorf("%s: after the pass beside it going to %s nft lists, want that chain and the pass written:\n%s", c.name, stray, listing)
		}
		c.release()
		if err := tr.reconcile(); err != nil {
			t.Fatalf("%s: the pass once it is gone: %v", c.name, err)
		}
		if s := tr.lastPass(); !s.Ready4 || !s.Ready6 {
			t.Errorf("%s: once it is gone the translator reads %+v, want both families ready", c.name, s)
		}
		if listing := run("list", "table", "inet", nftables.Table); strings.Contains(listing, "chain "+stray+" {") || !strings.Contains(listing, "chain other {") || !strings.Contains(listing, "map vm {") {
			t.Errorf("%s: once it is gone nft lists, want %s deleted and chain other and map vm left:\n%s", c.name, stray, listing)
		}
	}

	run("add", "chain", "inet", nftables.Table, stray)
	run("add", "rule", "inet", nftables.Table, "other", "goto", stray)
	if err := be.Withdraw(); err != nil {
		t.Fatalf("the withdrawal beside a goto of chain other to %s: %v", stray, err)
	}
	listing := run("list", "table", "inet", nftables.Table)
	for _, gone := range []string{"chain " + ChainName + " {", "chain " + LimitChain + " {", "chain " + forward6.Name + " {", untranslatedSet + "4", "flows4", "ct timeout " + timeoutName(egress.FamilyIPv4, UDPTimeouts) + " {"} {
		if strings.Contains(listing, gone) {
			t.Errorf("after the withdrawal beside a goto to %s nft lists %q, want it withdrawn:\n%s", stray, gone, listing)
		}
	}
	if !strings.Contains(listing, "chain "+stray+" {") || !strings.Contains(listing, "goto "+stray) {
		t.Errorf("after the withdrawal beside a goto to %s nft lists, want that chain left with the goto:\n%s", stray, listing)
	}
}

// An earlier translator killed under a share of 64 with a class of none
// holding a class that translates leaves that class of none's chain, whose
// limit line counts flows in flows4. The next instance, under the default
// share and no class, reads flows4 and flows6 stale and that chain stray. Its
// first pass flushes the stray chain before it deletes the stale sets that
// chain's line uses, so nf_tables takes the transaction, both families read
// ready, and nothing of the killed instance's is left: neither its chain nor a
// set or line under its share.
func TestNftablesRemakesBesideAKilledInstancesChainOfNone(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmpty(t)
	run := nftRun(t)
	rt := Runtime{Interface: "ranet0", Steered: true, Forwarding: func() (bool, bool) { return true, true }, Sysctl: readsNothing, Hooks: unheard}
	killed := egress.Egress{FlowsPerSource: 64}
	before, err := newBackend(killed, rt)
	if err != nil {
		t.Fatalf("open the nftables backend: %v", err)
	}
	requireEmptyRuleset(t, before)
	if err := newTranslator(killed, rt, before).reconcile(); err != nil {
		t.Fatalf("the killed instance's pass: %v", err)
	}
	// the earlier translator's chain of the class of none, holding the limit
	// of the class that translates inside it under the killed share
	stray := NoneChain + "192_0_2_0_24"
	limit, err := translatorLine(Rule{Family: egress.FamilyIPv4, Direction: Out, Interface: "ranet0", From: netip.MustParsePrefix("192.0.2.0/26"), Limit: 64}, unix.NFT_CT_LABELS)
	if err != nil {
		t.Fatal(err)
	}
	line, err := regularChain(stray).Rule(unix.NFPROTO_INET, limit.Spec, limit.Expressions)
	if err != nil {
		t.Fatal(err)
	}
	another, err := nftables.Dial()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = another.Close() })
	if err := another.Batch([]nftables.Request{regularChain(stray).Create(unix.NFPROTO_INET), line}); err != nil {
		t.Fatalf("write the chain %s: %v", stray, err)
	}
	if chain := run("list", "chain", "inet", nftables.Table, stray); !strings.Contains(chain, "@flows4") {
		t.Fatalf("the killed instance's chain %s holds no line counting flows in flows4:\n%s", stray, chain)
	}
	// a kill closes the socket and withdraws nothing
	if err := before.Close(); err != nil {
		t.Fatal(err)
	}

	be, err := newBackend(egress.Egress{}, rt)
	if err != nil {
		t.Fatalf("open the nftables backend again: %v", err)
	}
	t.Cleanup(func() { _ = be.Close() })
	tr := newTranslator(egress.Egress{}, rt, be)
	if err := tr.reconcile(); err != nil {
		t.Fatalf("the first pass after the killed instance: %v", err)
	}
	if s := tr.lastPass(); !s.Ready4 || !s.Ready6 {
		t.Errorf("after its first pass the translator reads %+v, want both families ready", s)
	}
	listing := run("list", "table", "inet", nftables.Table)
	for _, left := range []string{"chain " + stray + " {", "limit 64", "over 64"} {
		if strings.Contains(listing, left) {
			t.Errorf("after the first pass nft lists %q of the killed instance's:\n%s", left, listing)
		}
	}
}

// A timeout object the table holds with other seconds than this build writes,
// as an earlier build may have left it, reads back as a fault of its family
// that remakes it, since nf_tables changes no ct timeout in place, and the
// pass deletes and makes again that object alone: every other object and both
// sets keep their handles, so no flow they time or count is detached, and
// every object reads back as written with both families ready
func TestNftablesRemakesAStaleTimeoutAlone(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmpty(t)
	run := nftRun(t)
	rt := Runtime{Interface: "ranet0", Steered: true, Forwarding: func() (bool, bool) { return true, true }, Sysctl: readsNothing, Hooks: unheard}
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
	tr := newTranslator(egress.Egress{}, rt, be)
	if err := tr.reconcile(); err != nil {
		t.Fatalf("the first pass: %v", err)
	}
	name := timeoutName(egress.FamilyIPv4, UDPTimeouts)
	stale := nftables.Timeout{Table: nftables.Table, Name: name, L3Proto: unix.NFPROTO_IPV4, L4Proto: unix.IPPROTO_UDP,
		Policy: []uint32{2 * udpUnrepliedTimeout, 2 * udpRepliedTimeout}}
	// the rules that name it go first, as nf_tables will not delete an object a rule uses
	run(fmt.Sprintf("flush chain inet %[1]s %[2]s; flush chain inet %[1]s %[3]s; delete ct timeout inet %[1]s %[4]s", nftables.Table, LimitChain, ChainName, name))
	if err := another.Batch([]nftables.Request{stale.Create(unix.NFPROTO_INET)}); err != nil {
		t.Fatalf("leave a stale timeout object: %v", err)
	}
	if read, err := be.Rules(tr.desired()); err != nil || read[egress.FamilyIPv4].fault == "" || !read[egress.FamilyIPv4].remake {
		t.Errorf("with a stale timeout object the ip family reads back as %+v (%v), want a fault that remakes it", read[egress.FamilyIPv4], err)
	}
	before := objectHandles(t, another)
	if err := tr.reconcile(); err != nil {
		t.Fatalf("the pass: %v", err)
	}
	after := objectHandles(t, another)
	for object, handle := range before {
		if moved := after[object] != handle; moved != (object == name) {
			t.Errorf("after the pass %s has the handle %d where it had %d, want it moved %v", object, after[object], handle, object == name)
		}
	}
	for _, family := range []uint8{egress.FamilyIPv4, egress.FamilyIPv6} {
		if got, want := heldTimeouts(t, another, family), timeoutObjects(family); !reflect.DeepEqual(got, want) {
			t.Errorf("after the pass the table holds the %s timeout objects %+v, want %+v", familyLabel(family), got, want)
		}
	}
	if s := tr.lastPass(); !s.Ready4 || !s.Ready6 {
		t.Errorf("after the pass the translator reads %+v, want both families ready", s)
	}
}

// nft lists a timeout object's name unquoted, and each name the translator
// gives one, given to a UDP object with a line attaching it, lists as a name
// nft -f loads back, and the loaded table lists the same again. nft -f takes
// no ICMP object whatever its name, so each name is read under a UDP object.
func TestNftablesListingOfEachTimeoutObjectsNameLoadsBack(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmpty(t)
	run := nftRun(t)
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := nftables.Dial()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	protocol, policy := timeoutPolicy(UDPTimeouts)
	for _, family := range []uint8{egress.FamilyIPv4, egress.FamilyIPv6} {
		for _, written := range timeoutObjects(family) {
			object := nftables.Timeout{Table: nftables.Table, Name: written.Name, L3Proto: written.L3Proto, L4Proto: protocol, Policy: policy}
			expressions := slices.Concat(nftables.NFProto(nftFamily(family)), nftables.MetaCompareValue(unix.NFT_META_L4PROTO, unix.NFT_CMP_EQ, []byte{protocol}),
				[][]byte{nftables.ObjectReference(unix.NFT_OBJECT_CT_TIMEOUT, object.Name)})
			rule, err := forward.Rule(unix.NFPROTO_INET, "attach "+object.Name, expressions)
			if err != nil {
				t.Fatal(err)
			}
			if err := conn.Batch([]nftables.Request{nftables.NewTable(unix.NFPROTO_INET, nftables.Table), forward.Create(unix.NFPROTO_INET), object.Create(unix.NFPROTO_INET), rule}); err != nil {
				t.Fatalf("write the object %s and its line: %v", object.Name, err)
			}
			listing := run("list", "table", "inet", nftables.Table)
			run("delete", "table", "inet", nftables.Table)
			load := exec.Command(nft, "-f", "-")
			load.Stdin = strings.NewReader(listing)
			if out, err := load.CombinedOutput(); err != nil {
				t.Fatalf("nft -f of the listing of the object %s: %v\n%s\nthe listing:\n%s", object.Name, err, out, listing)
			}
			if again := run("list", "table", "inet", nftables.Table); again != listing {
				t.Errorf("the loaded listing of the object %s lists\n%s\nwant\n%s", object.Name, again, listing)
			}
			run("delete", "table", "inet", nftables.Table)
		}
	}
}

// A set another writer resized reads back as a fault of its family the next
// pass writes back without remaking the set, and every pass keeps each set's
// elements, each source's count of flows, which a remake would empty
func TestNftablesKeepsTheSetsCountsAcrossARewrite(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmpty(t)
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
	rt := Runtime{Interface: "ranet0", Steered: true, Forwarding: func() (bool, bool) { return true, true }, Sysctl: readsNothing, Hooks: unheard}
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
		run("add", "element", "inet", nftables.Table, flowSet(c.family, egress.DefaultFlowsPerSource).Name, "{ "+c.source+" }")
	}
	run("add", "set", "inet", nftables.Table, flowSet(egress.FamilyIPv6, egress.DefaultFlowsPerSource).Name, "{ type ipv6_addr; size 100; flags dynamic; }")
	read, err := be.Rules(tr.desired())
	if err != nil || read[egress.FamilyIPv6].fault == "" || read[egress.FamilyIPv6].remake || read[egress.FamilyIPv4].fault != "" {
		t.Errorf("with the ip6 set resized the families read back as %+v (%v), want the ip6 family alone at fault, with no remake", read, err)
	}
	handles := objectHandles(t, another)
	if err := tr.reconcile(); err != nil {
		t.Fatalf("the pass after the resize: %v", err)
	}
	if got := objectHandles(t, another); !maps.Equal(got, handles) {
		t.Errorf("after the pass wrote the set back the sets and objects have the handles %v, want the ones they had, %v", got, handles)
	}
	read, err = be.Rules(tr.desired())
	if _, faulted, remake := flatten(read); err != nil || faulted || remake {
		t.Errorf("after the pass the families read back as %+v (%v), want both as written", read, err)
	}
	for _, c := range counted {
		if listing := run("list", "set", "inet", nftables.Table, flowSet(c.family, egress.DefaultFlowsPerSource).Name); !strings.Contains(listing, "elements = { "+c.source+" }") {
			t.Errorf("after the pass the %s set no longer holds %s's element:\n%s", familyLabel(c.family), c.source, listing)
		}
	}
	if s := tr.lastPass(); !s.Ready4 || !s.Ready6 {
		t.Errorf("after the pass the translator reads %+v, want both families ready", s)
	}
}

// Sets an instance of another limit left behind, as one that stopped without
// withdrawing would, read back each at a fault that remakes it, since each
// element keeps the limit it was added under. After the pass each set is a new
// one, holding no element and reading back under the translator's limit, the
// timeout objects keep their handles, and both families are ready.
func TestNftablesRemakesASetThatCountsAnotherLimit(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmpty(t)
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
	rt := Runtime{Interface: "ranet0", Steered: true, Forwarding: func() (bool, bool) { return true, true }, Sysctl: readsNothing, Hooks: unheard}
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
		run("add", "element", "inet", nftables.Table, flowSet(family, earlier.SourceLimit()).Name, "{ "+source+" }")
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
			t.Errorf("with the earlier instance's set the %s family reads back as %+v (%v), want a fault naming its limit that remakes it", familyLabel(family), read[family], err)
		}
	}
	another, err := nftables.Dial()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = another.Close() })
	handles, tables := objectHandles(t, another), tableHandles(t, another)
	tr := newTranslator(later, rt, be)
	if err := tr.reconcile(); err != nil {
		t.Fatalf("the pass: %v", err)
	}
	if after := tableHandles(t, another); !maps.Equal(after, tables) {
		t.Errorf("after the pass the table has the handles %v, want the one it had, %v", after, tables)
	}
	after := objectHandles(t, another)
	for object, handle := range handles {
		set := strings.HasPrefix(object, flowsSet)
		if moved := after[object] != handle; moved != set {
			t.Errorf("after the pass %s has the handle %d where it had %d, want it moved %v", object, after[object], handle, set)
		}
	}
	read, err = be.Rules(tr.desired())
	if _, faulted, remake := flatten(read); err != nil || faulted || remake {
		t.Errorf("after the pass the families read back as %+v (%v), want both as written", read, err)
	}
	for family, source := range counted {
		listing := run("list", "set", "inet", nftables.Table, flowSet(family, later.SourceLimit()).Name)
		if strings.Contains(listing, source) || !strings.Contains(listing, fmt.Sprintf("comment %q", flowSet(family, later.SourceLimit()).Comment)) {
			t.Errorf("after the pass the %s set lists, want it without %s's element and under its comment:\n%s", familyLabel(family), source, listing)
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
// name in an ip or ip6 table of the exit's table's name, as an older instance
// left them, are reported as another writer's.
func TestNftablesReportsTheNatChainsAtItsPriorityOrBelow(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmpty(t)
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Fatal("another writer's chains are made through nft, which is not on the path")
	}
	rt := Runtime{Interface: "ranet0", Steered: true, Forwarding: func() (bool, bool) { return true, true }, Sysctl: readsNothing, Hooks: unheard}
	be, err := newBackend(egress.Egress{}, rt)
	if err != nil {
		t.Fatalf("open the nftables backend: %v", err)
	}
	t.Cleanup(func() { _ = be.Close() })
	requireEmptyRuleset(t, be)
	if err := be.Apply(newTranslator(egress.Egress{}, rt, be).desired(), false); err != nil {
		t.Fatalf("install the translator's rules: %v", err)
	}
	sneak := fmt.Sprintf("{ type nat hook postrouting priority %d ; }", natPriority-49)
	if out, err := exec.Command(nft, "add", "chain", "inet", nftables.Table, "sneak", sneak).CombinedOutput(); err != nil {
		t.Fatalf("make another writer's chain in the translator's table: %v\n%s", err, out)
	}
	want := []string{fmt.Sprintf("inet table %s chain sneak at priority %d", nftables.Table, natPriority-49)}
	// the exit's own chain's name in an ip or ip6 table of its own table's
	// name, as an older instance wrote them, is another writer's
	older := fmt.Sprintf("{ type nat hook postrouting priority %d ; }", natPriority)
	for _, family := range []string{"ip", "ip6"} {
		if out, err := exec.Command(nft, "add", "table", family, nftables.Table).CombinedOutput(); err != nil {
			t.Fatalf("make an %s table named %s: %v\n%s", family, nftables.Table, err, out)
		}
		if out, err := exec.Command(nft, "add", "chain", family, nftables.Table, ChainName, older).CombinedOutput(); err != nil {
			t.Fatalf("make another writer's chain %s in the %s table %s: %v\n%s", ChainName, family, nftables.Table, err, out)
		}
		want = append(want, fmt.Sprintf("%s table %s chain %s at priority %d", family, nftables.Table, ChainName, natPriority))
	}
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

// An answer to the label's probe that says neither that the kernel takes the
// label nor that it refuses it, here the refusal of the probe's table, which
// another socket owns, fails the Apply and leaves the label on and unlearned,
// so the Apply after that socket's close asks again and learns the answer
func TestNftablesLearnsNothingOfTheLabelFromAProbeRefusedAtItsTable(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmpty(t)
	cfg := egress.Egress{Advertise: prefixes(t, "0.0.0.0/0", "::/0")}
	rt := Runtime{Interface: "ranet0", Steered: true, Forwarding: func() (bool, bool) { return true, true }, Sysctl: readsNothing, Hooks: unheard}
	be, err := newBackend(cfg, rt)
	if err != nil {
		t.Fatalf("open the nftables backend: %v", err)
	}
	t.Cleanup(func() { _ = be.Close() })
	requireEmptyRuleset(t, be)
	n := be.(*natTables)
	owner, err := nftables.Dial()
	if err != nil {
		t.Fatal(err)
	}
	// NFT_TABLE_F_OWNER: the kernel refuses every other socket's request on the
	// table while the socket that made it stays open, and deletes the table at
	// its close
	const owned = 0x2
	made := nftables.Request{Kind: nftables.Command(unix.NFT_MSG_NEWTABLE), Flags: unix.NLM_F_CREATE,
		Body: nftables.PutAttrBE32(netlink.PutAttrString(nftables.PutNfgenmsg(nil, unix.NFPROTO_INET), unix.NFTA_TABLE_NAME, nftables.Table), unix.NFTA_TABLE_FLAGS, owned)}
	if err := owner.Batch([]nftables.Request{made}); err != nil {
		_ = owner.Close()
		t.Skipf("the kernel refused a table its maker owns, as one before 5.12 does: %v", err)
	}
	tr := newTranslator(cfg, rt, be)
	if err := be.Apply(tr.desired(), false); err == nil {
		t.Error("an Apply beside another socket's table returned no error")
	}
	if label := n.label.Load(); label != unix.NFT_CT_LABELS || n.learned {
		t.Errorf("an Apply whose probe the kernel refused at its table left the label key %d and learned %v, want %d and unlearned", label, n.learned, unix.NFT_CT_LABELS)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(notificationWait); ; time.Sleep(passPoll) {
		tables, err := nftables.Tables(n.conn, nftables.Table)
		if err != nil {
			t.Fatal(err)
		}
		if len(tables) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the owner's table was still held %s after its close", notificationWait)
		}
	}
	if err := be.Apply(tr.desired(), false); err != nil {
		t.Fatalf("the Apply after the owner's close: %v", err)
	}
	if !n.learned {
		t.Error("the Apply after the owner's close learned nothing of the label")
	}
}

// What the backend says it writes, in Status.Where and in the warning that it
// cannot label, names each chain of its table the kernel holds once it has
// written and no other, in each state of the label, up and stopped
func TestNftablesSaysWhereTheChainsItHoldsAre(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	// a key no kernel knows, which nft_ct refuses as a kernel without labels
	// refuses theirs
	const unknown = 255
	// shape reads the chains a where names, as the backend words them
	shape := regexp.MustCompile(`^nftables table inet ` + nftables.Table + ` chains (.+)$`)
	for _, key := range []uint32{unix.NFT_CT_LABELS, unknown} {
		t.Run(fmt.Sprintf("under the key %d", key), func(t *testing.T) {
			netnstest.EnterEmpty(t)
			var lines strings.Builder
			logtest.SetDefault(t, slog.New(slog.NewTextHandler(&lines, nil)))
			cfg := egress.Egress{Advertise: prefixes(t, "0.0.0.0/0", "::/0"), Translate: manyClasses(6)}
			rt := Runtime{Interface: "ranet0", Steered: true, Forwarding: func() (bool, bool) { return true, true }, Sysctl: readsNothing, Hooks: unheard}
			be, err := newBackend(cfg, rt)
			if err != nil {
				t.Fatalf("open the nftables backend: %v", err)
			}
			t.Cleanup(func() { _ = be.Close() })
			requireEmptyRuleset(t, be)
			n := be.(*natTables)
			n.label.Store(key)
			tr := newTranslator(cfg, rt, be)
			for _, state := range []struct {
				name  string
				rules []Rule
			}{{"up", tr.desired()}, {"stopped", tr.stopped()}} {
				if err := be.Apply(state.rules, false); err != nil {
					t.Fatalf("write the rules %s: %v", state.name, err)
				}
				held, err := nftables.TableChains(n.conn, unix.NFPROTO_INET, nftables.Table)
				if err != nil {
					t.Fatal(err)
				}
				says := map[string]string{"the status": tr.Status().Where}
				if key == unknown {
					warning := regexp.MustCompile(`level=WARN msg="egress cannot label the flows it translates" .* where="([^"]*)"`).FindStringSubmatch(lines.String())
					if warning == nil {
						t.Fatalf("no warning that the backend cannot label names where it writes:\n%s", lines.String())
					}
					says["the warning"] = warning[1]
				}
				for who, where := range says {
					parts := shape.FindStringSubmatch(where)
					if parts == nil {
						t.Errorf("%s %s reads %q, which names its chains in no form this test reads", state.name, who, where)
						continue
					}
					named := regexp.MustCompile(`, | and `).Split(parts[1], -1)
					for _, chain := range named {
						if !slices.Contains(held, chain) {
							t.Errorf("%s %s names the chain %s, which the table does not hold, holding %v", state.name, who, chain, held)
						}
					}
					for _, chain := range held {
						if !slices.Contains(named, chain) {
							t.Errorf("%s %s does not name the chain %s the table holds, naming %v", state.name, who, chain, named)
						}
					}
				}
			}
		})
	}
}

// heldTimeouts is the timeout objects of family this tool's table holds, in
// the order timeoutObjects writes them, and any other after them
func heldTimeouts(t *testing.T, conn *nftables.Conn, family uint8) []nftables.Timeout {
	t.Helper()
	replies, err := conn.Dump(nftables.Command(unix.NFT_MSG_GETOBJ), nftables.PutNfgenmsg(nil, unix.NFPROTO_INET))
	if err != nil {
		t.Fatalf("dump the %s objects: %v", familyLabel(family), err)
	}
	var held []nftables.Timeout
	for _, reply := range replies {
		if object, ok := nftables.DecodeTimeout(reply); ok && object.Table == nftables.Table && object.L3Proto == uint16(nftFamily(family)) {
			held = append(held, object)
		}
	}
	written := timeoutObjects(family)
	at := func(object nftables.Timeout) int {
		return slices.IndexFunc(written, func(w nftables.Timeout) bool { return w.Name == object.Name })
	}
	slices.SortStableFunc(held, func(a, b nftables.Timeout) int { return cmp.Compare(uint(at(a)), uint(at(b))) })
	return held
}

// tableHandle, setHandle and objectHandle are NFTA_TABLE_HANDLE,
// NFTA_SET_HANDLE and NFTA_OBJ_HANDLE, the attributes of a handle in a dump,
// which x/sys does not carry
const (
	tableHandle  = 4
	setHandle    = 16
	objectHandle = 6
)

// objectHandles is the handle of each named set and object of this tool's
// table, by its name
func objectHandles(t *testing.T, conn *nftables.Conn) map[string]uint64 {
	t.Helper()
	handles := map[string]uint64{}
	for _, dump := range []struct {
		command             int
		table, name, handle uint16
	}{
		{unix.NFT_MSG_GETSET, unix.NFTA_SET_TABLE, unix.NFTA_SET_NAME, setHandle},
		{unix.NFT_MSG_GETOBJ, unix.NFTA_OBJ_TABLE, unix.NFTA_OBJ_NAME, objectHandle},
	} {
		replies, err := conn.Dump(nftables.Command(dump.command), nftables.PutNfgenmsg(nil, unix.NFPROTO_INET))
		if err != nil {
			t.Fatalf("dump the sets and objects: %v", err)
		}
		for _, reply := range replies {
			var table, name string
			var handle uint64
			for kind, value := range reply.Attributes(nftables.SizeofNfgenmsg) {
				switch {
				case kind == dump.table:
					table = unix.ByteSliceToString(value)
				case kind == dump.name:
					name = unix.ByteSliceToString(value)
				case kind == dump.handle && len(value) == 8:
					handle = binary.BigEndian.Uint64(value)
				}
			}
			if table == nftables.Table && !strings.HasPrefix(name, "__") {
				handles[name] = handle
			}
		}
	}
	return handles
}

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
		for kind, value := range reply.Attributes(nftables.SizeofNfgenmsg) {
			switch {
			case kind == unix.NFTA_TABLE_NAME:
				name = unix.ByteSliceToString(value)
			case kind == tableHandle && len(value) == 8:
				handle = binary.BigEndian.Uint64(value)
			}
		}
		if name == nftables.Table && len(reply.Data) >= nftables.SizeofNfgenmsg {
			handles[reply.Data[0]] = handle
		}
	}
	return handles
}

// Another writer setting the table dormant, or making one of the translator's
// chains again at another priority, as a regular chain or, for IPv6's chain
// once forward's line is gone, as a base chain, wakes the translator, which
// reports both families not ready until the pass that follows, with no sweep
// due, writes the chains back, deleting and making again the chain changed
// but in the first case, and reads both ready. So does another writer making
// again the chain an earlier translator held IPv4's lines in, which that pass
// deletes.
func TestNftablesPutsBackAnotherWritersChangeToItsTable(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmpty(t)
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
		Ready: func(v4, v6, _ bool) {
			mu.Lock()
			defer mu.Unlock()
			told = append(told, fmt.Sprintf("ready %v %v", v4, v6))
		},
		Republish: unheard.Republish,
	}
	// no sweep comes within notificationWait, so only a wake explains a pass
	cfg := egress.Egress{Sweep: schema.Duration(lateSweep)}
	be, err := newBackend(cfg, rt)
	if err != nil {
		t.Fatalf("open the nftables backend: %v", err)
	}
	requireEmptyRuleset(t, be)
	// a backend of its own reads the chains back, since the run goroutine holds be's socket
	check, err := newBackend(cfg, rt)
	if err != nil {
		t.Fatalf("open a second nftables backend: %v", err)
	}
	t.Cleanup(func() { _ = check.Close() })
	// it reads through read, not Rules, so it holds no table beside the translator
	reader := check.(*natTables)
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
		name string
		// command is one transaction, so no pass runs between its parts
		command string
		// nft lists gone in the table while the change stands
		gone string
	}{
		{"the table set dormant", fmt.Sprintf("add table inet %s { flags dormant; }", nftables.Table), "flags dormant"},
		{"the translating chain made again at priority 0",
			fmt.Sprintf("delete chain inet %[1]s %[2]s; add chain inet %[1]s %[2]s { type nat hook postrouting priority 0; policy accept; }", nftables.Table, ChainName),
			"hook postrouting priority filter;"},
		{"the translating chain made again as a regular chain",
			fmt.Sprintf("delete chain inet %[1]s %[2]s; add chain inet %[1]s %[2]s", nftables.Table, ChainName),
			fmt.Sprintf("chain %s {\n\t}", ChainName)},
		{"the forward hook's chain made again at priority 10",
			fmt.Sprintf("delete chain inet %[1]s %[2]s; add chain inet %[1]s %[2]s { type filter hook forward priority 10; policy accept; }", nftables.Table, LimitChain),
			"hook forward priority filter + 10;"},
		{"IPv6's chain made again as a base chain once forward's line goes",
			fmt.Sprintf("flush chain inet %[1]s %[2]s; delete chain inet %[1]s %[3]s; add chain inet %[1]s %[3]s { type filter hook forward priority 0; policy accept; }",
				nftables.Table, LimitChain, forward6.Name),
			fmt.Sprintf("chain %s {\n\t\ttype filter hook forward", forward6.Name)},
		{"the chain of IPv4's an earlier translator wrote made again",
			fmt.Sprintf("add chain inet %s %s", nftables.Table, retiredChain),
			fmt.Sprintf("chain %s {", retiredChain)},
	} {
		mark := len(entries())
		run(change.command)
		moved(change.name, mark, "ready false false", "ready true true")
		read, err := reader.read(reader.conn, desired, true)
		_, faulted, remake := flatten(read)
		if err != nil || faulted || remake {
			t.Errorf("%s: after the pass the chains read back as %+v (%v), want %v as written", change.name, read, err, desired)
		}
		if listing := run("list", "table", "inet", nftables.Table); strings.Contains(listing, change.gone) {
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
		{Kind: nftables.Command(unix.NFT_MSG_NEWTABLE), Flags: unix.NLM_F_CREATE, Body: netlink.PutAttrString(nftables.PutNfgenmsg(nil, unix.NFPROTO_IPV4), unix.NFTA_TABLE_NAME, table)},
		{Kind: nftables.Command(unix.NFT_MSG_NEWCHAIN), Flags: unix.NLM_F_CREATE, Body: netlink.PutAttrString(netlink.PutAttrString(nftables.PutNfgenmsg(nil, unix.NFPROTO_IPV4), unix.NFTA_CHAIN_TABLE, table), unix.NFTA_CHAIN_NAME, chain)},
	}
	for i := range count {
		var expressions []byte
		for _, e := range append(nftables.MetaCompare(unix.NFT_META_IIFNAME, unix.NFT_CMP_EQ, fmt.Sprintf("eth%d", i%100)), nftables.Expression("counter", nil)) {
			expressions = append(expressions, e...)
		}
		body := netlink.PutAttrString(netlink.PutAttrString(nftables.PutNfgenmsg(nil, unix.NFPROTO_IPV4), unix.NFTA_RULE_TABLE, table), unix.NFTA_RULE_CHAIN, chain)
		requests = append(requests, nftables.Request{Kind: nftables.Command(unix.NFT_MSG_NEWRULE), Flags: unix.NLM_F_CREATE | unix.NLM_F_APPEND,
			Body: netlink.PutAttr(body, unix.NFTA_RULE_EXPRESSIONS|unix.NLA_F_NESTED, expressions)})
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
	netnstest.EnterEmpty(t)
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
	tables, err := nftables.Tables(be.(*natTables).conn, nftables.Table)
	if err != nil {
		t.Fatalf("list this tool's tables: %v", err)
	}
	if len(tables) != 0 {
		t.Fatalf("the namespace holds %d tables named %s", len(tables), nftables.Table)
	}
	read, err := be.Read(nil)
	if err != nil {
		t.Fatalf("list rules: %v", err)
	}
	if rules, _, _ := flatten(read); len(rules) != 0 {
		t.Fatalf("the namespace holds %d rules of this tool's", len(rules))
	}
}
