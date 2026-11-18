// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"os"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/netnstest"
	"ranet3.com/pkgs/ranet3/internal/nftables"
	"ranet3.com/pkgs/ranet3/schema"
)

// earlierTimeouts is the name an earlier translator gave each timeout object,
// by the name this build gives it, written apart from the translator's own
// list
var earlierTimeouts = map[string]string{
	"udp4": "translated-udp4", "tcp4": "translated-tcp4", "icmp4": "translated-icmp4",
	"udp6": "translated-udp6", "tcp6": "translated-tcp6", "icmp6": "translated-icmpv66",
}

// timedLine is a line of nft -a's listing that attaches a timeout object, its
// text, the object and its handle
var timedLine = regexp.MustCompile(`^\s*(.*ct timeout set "([^"]+)".*) # handle (\d+)$`)

// startEarlierTimeouts runs the first pass of the translator of cfg in an
// empty namespace and returns it with what nft lists of the table, then moves
// each timeout object to the name an earlier translator gave it through
// another socket: each object made again under that name, each line attaching
// one replaced in place by one attaching the object under that name, and the
// object under this build's name deleted, which leaves the table as an earlier
// translator that ended without its withdrawal left it
func startEarlierTimeouts(t *testing.T, cfg egress.Egress) (*Translator, backend, func(args ...string) string, string) {
	t.Helper()
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmpty(t)
	run := nftRun(t)
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
	fresh := run("list", "table", "inet", nftables.Table)
	another, err := nftables.Dial()
	if err != nil {
		t.Fatal(err)
	}
	defer another.Close()
	var made []nftables.Request
	for _, family := range []uint8{egress.FamilyIPv4, egress.FamilyIPv6} {
		for _, object := range timeoutObjects(family) {
			object.Name = earlierTimeouts[object.Name]
			made = append(made, object.Create(unix.NFPROTO_INET))
		}
	}
	if err := another.Batch(made); err != nil {
		t.Fatalf("make the timeout objects under their earlier names: %v", err)
	}
	chain, replaced := "", 0
	for _, line := range strings.Split(run("-a", "list", "table", "inet", nftables.Table), "\n") {
		if fields := strings.Fields(line); len(fields) > 2 && fields[0] == "chain" && fields[2] == "{" {
			chain = fields[1]
			continue
		}
		timed := timedLine.FindStringSubmatch(line)
		if timed == nil {
			continue
		}
		earlier, ok := earlierTimeouts[timed[2]]
		if !ok {
			t.Fatalf("the chain %s's line %q attaches the object %s, which has no earlier name", chain, timed[1], timed[2])
		}
		run("replace", "rule", "inet", nftables.Table, chain, "handle", timed[3], strings.Replace(timed[1], `"`+timed[2]+`"`, `"`+earlier+`"`, 1))
		replaced++
	}
	for name := range earlierTimeouts {
		run("delete", "ct", "timeout", "inet", nftables.Table, name)
	}
	listing := run("list", "table", "inet", nftables.Table)
	for name, earlier := range earlierTimeouts {
		if replaced == 0 || strings.Contains(listing, "ct timeout "+name+" {") || !strings.Contains(listing, "ct timeout "+earlier+" {") {
			t.Fatalf("the earlier layout of %d lines lists, want the object %s and no object %s:\n%s", replaced, earlier, name, listing)
		}
	}
	return tr, be, run, fresh
}

// passOverEarlier reads back the table an earlier translator left, runs one
// pass over it, and fails unless both families read a fault before the pass
// and ready after it, and nft lists no object under an earlier name and none
// of chains. It returns what nft lists of the table after the pass.
func passOverEarlier(t *testing.T, tr *Translator, be backend, run func(args ...string) string, chains ...string) string {
	t.Helper()
	read, err := be.Rules(tr.desired())
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
	for _, earlier := range earlierTimeouts {
		if strings.Contains(listing, earlier) {
			t.Errorf("after the pass nft lists the object %s:\n%s", earlier, listing)
		}
	}
	for _, chain := range chains {
		if strings.Contains(listing, "chain "+chain+" {") {
			t.Errorf("after the pass nft lists the chain %s:\n%s", chain, listing)
		}
	}
	return listing
}

// tableObjects is each set, object and chain nft lists of a table, each with
// what it holds, sorted, since nft lists the objects of a kind in the order
// they were made
func tableObjects(listing string) []string {
	var out, current []string
	for _, line := range strings.Split(listing, "\n") {
		switch {
		case strings.HasPrefix(line, "\t") && !strings.HasPrefix(line, "\t\t") && strings.HasSuffix(line, "{"):
			current = []string{line}
		case line == "\t}" && current != nil:
			out, current = append(out, strings.Join(append(current, line), "\n")), nil
		case current != nil:
			current = append(current, line)
		}
	}
	slices.Sort(out)
	return out
}

// A table an earlier translator left, its timeout objects under the names it
// gave them and attached by its lines, reads back with a fault in both
// families, and the next pass deletes every object under an earlier name in
// the transaction that writes the lines again, so the table lists as a fresh
// one the same pass wrote and both families read ready
func TestNftablesRetiresTheEarlierTimeoutObjects(t *testing.T) {
	tr, be, run, fresh := startEarlierTimeouts(t, egress.Egress{})
	if listing := passOverEarlier(t, tr, be, run); listing != fresh {
		t.Errorf("after the pass the table lists\n%s\nwhere the pass over no table wrote\n%s", listing, fresh)
	}
}

// A table an earlier translator left under a class of none in each family,
// its timeout objects under the names it gave them and attached by its lines,
// and each class's pass going on to a chain of that class's in place of the
// line that looks the family's set of untranslated sources up, with no such
// set, reads back with a fault in both families. The next pass, in one
// transaction, empties and deletes both chains, deletes every object under an
// earlier name and writes the sets and their lines, so the table lists the
// objects a fresh one the same pass wrote lists, and both families read ready.
func TestNftablesRetiresTheEarlierTimeoutObjectsBesideChainsOfNone(t *testing.T) {
	tr, be, run, fresh := startEarlierTimeouts(t, egress.Egress{Translate: []egress.Class{
		{From: schema.MustPrefix("192.0.2.0/24"), To: egress.Translation{None: true}},
		{From: schema.MustPrefix("2001:db8::/32"), To: egress.Translation{None: true}},
	}})
	earlier := []struct{ chain, set, match, none, spec string }{
		{"forward", "untranslated4", "ip saddr 192.0.2.0/24", "none_192_0_2_0_24", "out via ranet0 ipv4 from 192.0.2.0/24 passed"},
		{"forward6", "untranslated6", "ip6 saddr 2001:db8::/32", "none_2001_db8___32", "out via ranet0 ipv6 from 2001:db8::/32 passed"},
	}
	var chains []string
	for _, e := range earlier {
		run("add", "chain", "inet", nftables.Table, e.none)
		handle := regexp.MustCompile(`@` + e.set + ` .*# handle (\d+)$`)
		var found []string
		for _, line := range strings.Split(run("-a", "list", "chain", "inet", nftables.Table, e.chain), "\n") {
			if found = handle.FindStringSubmatch(line); found != nil {
				break
			}
		}
		if found == nil {
			t.Fatalf("no line of the chain %s looks up %s", e.chain, e.set)
		}
		run(slices.Concat([]string{"replace", "rule", "inet", nftables.Table, e.chain, "handle", found[1], "iifname", "ranet0", "oifname", "!=", "ranet0"},
			strings.Fields(e.match), []string{"goto", e.none, "comment", `"` + e.spec + `"`})...)
		run("delete", "set", "inet", nftables.Table, e.set)
		chains = append(chains, e.none)
	}
	listing := run("list", "table", "inet", nftables.Table)
	for _, e := range earlier {
		if !strings.Contains(listing, "chain "+e.none+" {") || !strings.Contains(listing, "goto "+e.none) || strings.Contains(listing, e.set) {
			t.Fatalf("the earlier layout lists, want the chain %s, the goto to it and no set %s:\n%s", e.none, e.set, listing)
		}
	}
	if listing = passOverEarlier(t, tr, be, run, chains...); !slices.Equal(tableObjects(listing), tableObjects(fresh)) {
		t.Errorf("after the pass the table lists\n%s\nwhere the pass over no table wrote\n%s", listing, fresh)
	}
}

// A timeout object under an earlier name beside the translator as written,
// that another writer's rule attaches, holds both families not ready with a
// fault naming that rule's chain, and the pass after the rule goes deletes it
// and reads both ready
func TestNftablesKeepsAnEarlierTimeoutObjectAnotherWritersRuleAttaches(t *testing.T) {
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
	earlier := earlierTimeouts[timeoutName(egress.FamilyIPv4, UDPTimeouts)]
	run("add", "ct", "timeout", "inet", nftables.Table, earlier, "{ protocol udp; l3proto ip; policy = { unreplied: 120s, replied: 120s }; }")
	run("add", "chain", "inet", nftables.Table, "other")
	run("add", "rule", "inet", nftables.Table, "other", "meta", "l4proto", "udp", "ct", "timeout", "set", `"`+earlier+`"`)
	const fault = "its ct timeout translated-udp4 is not one the translator writes, and chain other holds a rule using it, so it stays until that rule goes"
	read, err := be.Rules(tr.desired())
	for _, family := range []uint8{egress.FamilyIPv4, egress.FamilyIPv6} {
		if err != nil || read[family].fault != fault {
			t.Errorf("beside the object the %s family reads the fault %q (%v), want %q", egress.FamilyName(family), read[family].fault, err, fault)
		}
	}
	if err := tr.reconcile(); err != nil {
		t.Fatalf("the pass beside the object: %v", err)
	}
	if s := tr.lastPass(); s.Ready4 || s.Ready6 {
		t.Errorf("after the pass beside the object the translator reads %+v, want neither family ready", s)
	}
	run("flush", "chain", "inet", nftables.Table, "other")
	if err := tr.reconcile(); err != nil {
		t.Fatalf("the pass after the rule went: %v", err)
	}
	if s := tr.lastPass(); !s.Ready4 || !s.Ready6 {
		t.Errorf("after the rule went the translator reads %+v, want both families ready", s)
	}
	if listing := run("list", "table", "inet", nftables.Table); strings.Contains(listing, earlier) || !strings.Contains(listing, "chain other {") {
		t.Errorf("after the rule went nft lists, want no object %s and the chain other:\n%s", earlier, listing)
	}
}

// The translator's withdrawal over the table an earlier translator left takes
// the objects under their earlier names with the rest, and the table with
// them
func TestNftablesWithdrawsTheEarlierTimeoutObjects(t *testing.T) {
	_, be, run, _ := startEarlierTimeouts(t, egress.Egress{})
	if err := be.Withdraw(); err != nil {
		t.Fatalf("the withdrawal over the earlier layout: %v", err)
	}
	if listing := run("list", "ruleset"); listing != "" {
		t.Errorf("after the withdrawal over the earlier layout nft lists:\n%s", listing)
	}
}
