// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/nftables"
)

// What nf_tables takes of the antispoof filter's table and hands back, against a real
// kernel in a namespace this test made and proved empty: every spec of both
// chains in order with its counter at zero, each chain's hook and priority,
// nft's own reading of the
// expressions where nft is installed, no wake from the filter's own writes,
// the chain put back by the pass that another writer wakes well inside a
// sweep by deleting the table, inserting an accept at the head of the chain
// or setting the table dormant, and no table left after the filter stops
func TestBorderRoundTrip(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	enterThrowawayNamespace(t)
	be, err := newBorderBackend()
	if err != nil {
		t.Fatalf("open the antispoof filter's backend: %v", err)
	}
	conn, err := nftables.Dial()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if inetTables(t, conn) != 0 {
		t.Fatalf("the namespace already holds an inet table named %s", TableName)
	}

	bus := events.New()
	rt := borderRuntime(bus)
	rt.Tun, rt.Inside = "ranet3", []string{"ranet3", "lo"}
	cfg := overlay(t, "198.18.0.0/15", "3fff::/20")
	cfg.Antispoof = egress.Antispoof{
		Exempt:    prefixes(t, "198.18.1.0/24"),
		Interface: map[string]egress.AntispoofInterface{"eth1": {Exempt: prefixes(t, "198.18.2.0/24")}, "wl*": {Exempt: prefixes(t, "3fff:0:2::/48")}},
	}
	f, err := startBorderFilter(cfg, rt, be)
	if err != nil {
		t.Fatalf("start the antispoof filter: %v", err)
	}
	desired, sets, _ := f.desired()
	read, err := be.Rules(desired, sets)
	if err != nil {
		t.Fatal(err)
	}
	held := read.rules
	if read.fault != "" {
		t.Fatalf("the kernel holds %v with the fault %q, want %v", held, read.fault, desired)
	}
	for _, rule := range held {
		if rule.Packets != 0 || rule.Bytes != 0 {
			t.Errorf("%s came back with %d packets and %d bytes in an empty namespace", rule.Spec, rule.Packets, rule.Bytes)
		}
	}
	for _, chain := range f.Debug().Chains {
		for _, rule := range chain.Rules {
			if !rule.Held {
				t.Errorf("a debug read through its own socket does not find %s", rule.Spec)
			}
		}
	}
	select {
	case <-be.Changed():
		t.Error("the filter's own install woke it")
	case <-time.After(quietFor):
	}

	replies, err := conn.Dump(nftables.Command(unix.NFT_MSG_GETCHAIN), nftables.PutNfgenmsg(nil, unix.NFPROTO_INET))
	if err != nil {
		t.Fatal(err)
	}
	chains := 0
	for _, reply := range replies {
		table, chain, kind, hook, priority := nftables.DecodeChain(reply)
		if table != TableName {
			continue
		}
		chains++
		switch {
		case chain == BorderChain && kind == "filter" && hook == unix.NF_INET_PRE_ROUTING && priority == -300:
		case chain == EntryChain && kind == "filter" && hook == unix.NF_INET_POST_ROUTING && priority == 110:
		default:
			t.Errorf("the kernel holds a %q chain %s at hook %d priority %d, want a filter chain %s at prerouting priority -300 or %s at postrouting priority 110", kind, chain, hook, priority, BorderChain, EntryChain)
		}
	}
	if chains != 2 {
		t.Errorf("the kernel holds %d chains in table inet %s, want two", chains, TableName)
	}

	// nft decodes the expressions itself, so an encoding it cannot read back
	// as the rule shows here as raw payload offsets
	if nft, err := exec.LookPath("nft"); err != nil {
		t.Log("nft is not installed, so the chain is not read back through it")
	} else {
		out, err := exec.Command(nft, "list", "table", "inet", TableName).CombinedOutput()
		if err != nil {
			t.Fatalf("nft list table inet %s: %v\n%s", TableName, err, out)
		}
		listing := string(out)
		if !strings.Contains(listing, "type filter hook prerouting priority raw; policy accept;") &&
			!strings.Contains(listing, "type filter hook prerouting priority -300; policy accept;") {
			t.Errorf("nft reads the chain otherwise:\n%s", listing)
		}
		for _, want := range []string{
			`iifname "ranet3" accept comment "accept via ranet3"`,
			`iifname "lo" accept comment "accept via lo"`,
			`ip saddr 198.18.0.0/15 counter packets 0 bytes 0 drop comment "drop ipv4 source 198.18.0.0/15"`,
			`ip saddr @carved4 counter packets 0 bytes 0 drop comment "drop ipv4 source @carved4"`,
			`ip saddr 198.18.1.0/24 accept comment "accept exempt source 198.18.1.0/24"`,
			`iifname "eth1" ip saddr 198.18.2.0/24 accept comment "accept exempt via eth1 source 198.18.2.0/24"`,
			`iifname "wl*" ip6 saddr 3fff:0:2::/48 accept comment "accept exempt via wl* source 3fff:0:2::/48"`,
			`ip6 saddr 3fff::/20 counter packets 0 bytes 0 drop comment "drop ipv6 source 3fff::/20"`,
			`oifname != "ranet3" return comment "return via other than ranet3"`,
			`ct direction reply return comment "return a reply"`,
			`ip saddr @owned4 return comment "return ipv4 source @owned4"`,
			`ip6 daddr @none6 return comment "return ipv6 to @none6"`,
			`counter packets 0 bytes 0 drop comment "drop ipv6 entering the mesh"`,
		} {
			if !strings.Contains(listing, want) {
				t.Errorf("nft does not read %s in:\n%s", want, listing)
			}
		}
	}

	// no sweep comes within notificationWait, so only a wake explains a pass
	f.sweep = lateSweep
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- f.Run(ctx) }()
	another, err := nftables.Dial()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = another.Close() })
	for _, change := range []struct {
		name    string
		request nftables.Request
	}{
		{"deleted the table", nftables.DeleteTable(unix.NFPROTO_INET, TableName)},
		{"inserted an accept at the head of the chain", anotherWritersAccept(unix.NFPROTO_INET, BorderChain)},
		{"set the table dormant", dormantTable(unix.NFPROTO_INET)},
	} {
		mark := len(readyMoves(bus))
		if err := another.Batch([]nftables.Request{change.request}); err != nil {
			t.Fatalf("another writer %s: %v", change.name, err)
		}
		for deadline := time.Now().Add(notificationWait); ; time.Sleep(passPoll) {
			moved := readyMoves(bus)[mark:]
			if len(moved) >= 2 && moved[0] == "false" && moved[len(moved)-1] == "true" {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("after another writer %s the filter's readiness moved %q, want not ready and then ready", change.name, moved)
			}
		}
		// read on the test's own socket, since the running filter's passes use the backend's
		if read, err := readBorder(conn, desired, sets); err != nil || read.fault != "" {
			t.Fatalf("after another writer %s the kernel holds %v with the fault %q (%v), want %v", change.name, read.rules, read.fault, err, desired)
		}
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("stop the antispoof filter: %v", err)
	}
	if inetTables(t, conn) != 0 {
		t.Error("the inet table outlived the filter")
	}
	// a withdrawal of nothing is not an error, and removes nothing
	again, err := newBorderBackend()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = again.Close() })
	if removed, err := again.Withdraw(); err != nil || removed {
		t.Errorf("withdrawing from a host holding no table answered %t, %v, want nothing removed", removed, err)
	}
}

// inetTables counts the inet tables of this tool's name
func inetTables(t *testing.T, conn *nftables.Conn) int {
	t.Helper()
	tables, err := nftables.Tables(conn, TableName)
	if err != nil {
		t.Fatalf("list inet tables: %v", err)
	}
	if _, held := tables[unix.NFPROTO_INET]; held {
		return 1
	}
	return 0
}

// A rule another writer puts in the antispoof chain with no comment, a line of
// either chain written again doing otherwise under its own comment, a line
// written again under another comment, the table set dormant, the chain's
// policy turned to drop, the chain made again at
// another priority or as a regular chain, and the table made again with a flag
// nf_tables will not clear in place each wake the filter, read back as
// other than the filter wrote them, and the next pass writes the table and the
// chain back, waking nothing, and reads them ready. The readback asks for a
// remake where nf_tables will not change a chain in place, and every pass that
// writes deletes the table and makes it again in any case, which takes a chain
// another writer put in it along from the start on. Another inet table holding
// a rule under the filter's own spelling stays out of the readback and the
// passes.
func TestBorderRoundTripPutsBackWhatAnotherWriterChanged(t *testing.T) {
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
	run("add", "table", "inet", "other")
	run("add", "chain", "inet", "other", BorderChain, "{ type filter hook prerouting priority 0; policy accept; }")
	run("add", "rule", "inet", "other", BorderChain, "accept")
	run("add", "rule", "inet", "other", BorderChain, "iifname", "eth0", "accept", "comment", `"accept via ranet3"`)
	run("add", "table", "inet", TableName)
	run("add", "chain", "inet", TableName, "extra")
	run("add", "rule", "inet", TableName, "extra", "iifname", "eth0", "accept", "comment", `"accept via ranet3"`)
	be, err := newBorderBackend()
	if err != nil {
		t.Fatalf("open the antispoof filter's backend: %v", err)
	}
	rt := borderRuntime(nil)
	rt.Inside = []string{"ranet3", "lo"}
	f, err := startBorderFilter(overlay(t, "198.18.0.0/15", "3fff::/20"), rt, be)
	if err != nil {
		t.Fatalf("start the antispoof filter beside another inet table: %v", err)
	}
	t.Cleanup(func() { _ = f.finish() })
	desired, sets, _ := f.desired()
	const foreign = `iifname "eth0" accept comment "accept via ranet3"`
	// replace is nft's replace of the line chain holds under comment by rule
	replace := func(chain, comment, rule string) []string {
		listing := run("-a", "list", "chain", "inet", TableName, chain)
		handle := regexp.MustCompile(`comment "` + regexp.QuoteMeta(comment) + `" # handle (\d+)`).FindStringSubmatch(listing)
		if handle == nil {
			t.Fatalf("no line of chain %s is commented %q in:\n%s", chain, comment, listing)
		}
		return append([]string{"replace", "rule", "inet", TableName, chain, "handle", handle[1]}, strings.Fields(rule)...)
	}
	for _, change := range []struct {
		name string
		args [][]string
		// replaced is a line replace takes in place, as chain, comment and the rule nft writes
		replaced [3]string
		// nft lists gone in the table while the change stands
		gone string
		// remade is whether the readback asks for the table made again
		remade bool
	}{
		{name: "an uncommented accept at the head of the chain", args: [][]string{{"insert", "rule", "inet", TableName, BorderChain, "accept"}}, gone: "\t\taccept\n"},
		// a line edited under its own comment reads by its comment as written, so only its expressions tell
		{name: "the overlay's drop made an accept under its comment", replaced: [3]string{BorderChain, "drop ipv4 source 198.18.0.0/15", `meta nfproto ipv4 accept comment "drop ipv4 source 198.18.0.0/15"`},
			gone: `ipv4 accept comment "drop ipv4 source 198.18.0.0/15"`},
		{name: "the reply's return made the original direction's under its comment", replaced: [3]string{EntryChain, "return a reply", `ct direction original return comment "return a reply"`},
			gone: `ct direction original return comment "return a reply"`},
		// as many lines as written, one under another comment
		{name: "the overlay's drop written again under another comment", replaced: [3]string{BorderChain, "drop ipv4 source 198.18.0.0/15", `ip saddr 198.18.0.0/15 counter drop comment "another writer drops"`},
			gone: `comment "another writer drops"`},
		{"the table set dormant", [][]string{{"add", "table", "inet", TableName, "{ flags dormant; }"}}, [3]string{}, "flags dormant", false},
		{"the chain's policy turned to drop", [][]string{{"chain", "inet", TableName, BorderChain, "{ policy drop; }"}}, [3]string{}, "policy drop;", false},
		{"the chain made again at priority 0", [][]string{
			{"delete", "chain", "inet", TableName, BorderChain},
			{"add", "chain", "inet", TableName, BorderChain, "{ type filter hook prerouting priority 0; policy accept; }"},
		}, [3]string{}, "priority filter;", true},
		{"the chain made again as a regular chain", [][]string{
			{"delete", "chain", "inet", TableName, BorderChain},
			{"add", "chain", "inet", TableName, BorderChain},
		}, [3]string{}, "chain antispoof {\n\t}", true},
		// nft's socket owns the table until nft exits, and the kernel then keeps it with the persist flag alone
		{"the table made again to persist past its owner", [][]string{
			{fmt.Sprintf("delete table inet %[1]s; add table inet %[1]s { flags owner, persist; }", TableName)},
		}, [3]string{}, "flags persist", true},
	} {
		if change.replaced[0] != "" {
			change.args = [][]string{replace(change.replaced[0], change.replaced[1], change.replaced[2])}
		}
		for _, args := range change.args {
			run(args...)
		}
		if listing := run("list", "table", "inet", TableName); !strings.Contains(listing, change.gone) {
			t.Fatalf("%s: nft does not list %q in:\n%s", change.name, change.gone, listing)
		}
		if !woken(be.Changed()) {
			t.Errorf("%s: another writer's change did not wake the filter", change.name)
		}
		if read, err := be.Rules(desired, sets); err != nil || read.fault == "" || read.remake != change.remade {
			t.Errorf("%s: the readback finds the fault %q, remade %v, over %v (%v), want a difference, remade %v", change.name, read.fault, read.remake, read.rules, err, change.remade)
		}
		if err := f.reconcile(); err != nil {
			t.Fatalf("%s: the pass failed: %v", change.name, err)
		}
		read, err := be.Rules(desired, sets)
		if err != nil || read.fault != "" || !f.ready {
			t.Errorf("%s: after the pass the filter reads ready %v (%q) over %v with the fault %q (%v)", change.name, f.ready, f.unready, read.rules, read.fault, err)
		}
		listing := run("list", "table", "inet", TableName)
		if strings.Contains(listing, change.gone) {
			t.Errorf("%s: after the pass nft still lists %q in:\n%s", change.name, change.gone, listing)
		}
		if strings.Contains(listing, foreign) {
			t.Errorf("%s: after a pass, another writer's chain in the table lists:\n%s", change.name, listing)
		}
		select {
		case <-be.Changed():
			t.Errorf("%s: the filter's own pass woke it", change.name)
		case <-time.After(quietFor):
		}
	}
	if listing := run("list", "table", "inet", "other"); !strings.Contains(listing, foreign) {
		t.Errorf("the filter's passes reached another writer's table:\n%s", listing)
	}
	// withdrawn twice beside another writer's inet table, the second finds no
	// table of this tool's name and deletes nothing
	for i := range 2 {
		removed, err := be.Withdraw()
		if err != nil {
			t.Fatalf("withdrawal %d beside another writer's inet table: %v", i+1, err)
		}
		if removed != (i == 0) {
			t.Errorf("withdrawal %d beside another writer's inet table reported a table removed %t", i+1, removed)
		}
	}
	if listing := run("list", "table", "inet", "other"); !strings.Contains(listing, `iifname "eth0" accept comment "accept via ranet3"`) {
		t.Errorf("the withdrawals reached another writer's table:\n%s", listing)
	}
}

// borderCrashNamespace names, in the crash helper's environment, the network
// namespace it writes the table in
const borderCrashNamespace = "RANET3_BORDER_CRASH_NAMESPACE"

// entrySets is sets of each kind in both families, for a table whose sets a
// readback can find flushed
func entrySets(*egress.Border) egress.BorderSets {
	return egress.BorderSets{
		Owned: ranges("192.0.2.7/32", "2001:db8:7::/64"),
		None:  ranges("203.0.113.0/24", "2001:db8:9::/48"),
	}
}

// entryRuntime is a runtime on the tun ranet3 with entrySets
func entryRuntime(bus *events.Bus) egress.BorderRuntime {
	rt := borderRuntime(bus)
	rt.Tun, rt.Inside, rt.Sets = "ranet3", []string{"ranet3", "lo"}, entrySets
	return rt
}

// nftRun runs nft with args and returns what it lists
func nftRun(t *testing.T) func(args ...string) string {
	t.Helper()
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Fatal("another writer's changes are made through nft, which is not on the path")
	}
	return func(args ...string) string {
		t.Helper()
		out, err := exec.Command(nft, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("nft %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return string(out)
	}
}

// A set another writer flushes and a chain another writer empties each wake
// the filter, read back as other than it wrote them, and the next pass puts
// the elements and the rules back and reads them ready
func TestBorderRoundTripRefillsAFlushedSet(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	enterThrowawayNamespace(t)
	run := nftRun(t)
	be, err := newBorderBackend()
	if err != nil {
		t.Fatalf("open the antispoof filter's backend: %v", err)
	}
	f, err := startBorderFilter(overlay(t, "198.18.0.0/15", "3fff::/20"), entryRuntime(nil), be)
	if err != nil {
		t.Fatalf("start the antispoof filter: %v", err)
	}
	t.Cleanup(func() { _ = f.finish() })
	desired, sets, _ := f.desired()
	for _, change := range []struct {
		name string
		args []string
		// nft lists listed in the table once the pass put it back
		listed string
	}{
		{"the set owned4 flushed", []string{"flush", "set", "inet", TableName, ownedSet + "4"}, "192.0.2.7"},
		{"the set none6 flushed", []string{"flush", "set", "inet", TableName, noneSet + "6"}, "2001:db8:9::/48"},
		{"the chain mesh_entry flushed", []string{"flush", "chain", "inet", TableName, EntryChain}, `comment "return a reply"`},
	} {
		run(change.args...)
		if listing := run("list", "table", "inet", TableName); strings.Contains(listing, change.listed) {
			t.Fatalf("%s: nft still lists %q in:\n%s", change.name, change.listed, listing)
		}
		if !woken(be.Changed()) {
			t.Errorf("%s: another writer's change did not wake the filter", change.name)
		}
		if read, err := be.Rules(desired, sets); err != nil || read.fault == "" {
			t.Errorf("%s: the readback finds the fault %q over %v (%v), want a difference", change.name, read.fault, read.rules, err)
		}
		if err := f.reconcile(); err != nil {
			t.Fatalf("%s: the pass failed: %v", change.name, err)
		}
		if read, err := be.Rules(desired, sets); err != nil || read.fault != "" || !f.ready {
			t.Errorf("%s: after the pass the filter reads ready %v (%q) over %v with the fault %q (%v)", change.name, f.ready, f.unready, read.rules, read.fault, err)
		}
		if listing := run("list", "table", "inet", TableName); !strings.Contains(listing, change.listed) {
			t.Errorf("%s: after the pass nft does not list %q in:\n%s", change.name, change.listed, listing)
		}
	}
}

// A node with no overlay holds the entry chain alone, on a host holding no
// table as on one where a start with overlay left its antispoof chain, which
// its first pass takes away
func TestBorderRoundTripHoldsTheEntryChainAloneWithNoBorder(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	enterThrowawayNamespace(t)
	// on a host holding no table the first start makes one
	fresh, err := newBorderBackend()
	if err != nil {
		t.Fatal(err)
	}
	first, err := startBorderFilter(nil, entryRuntime(nil), fresh)
	if err != nil {
		t.Fatalf("start the filter with no overlay on a host holding no table: %v", err)
	}
	if err := first.finish(); err != nil {
		t.Fatal(err)
	}
	earlier, err := newBorderBackend()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := startBorderFilter(overlay(t), entryRuntime(nil), earlier); err != nil {
		t.Fatalf("start a filter with overlay: %v", err)
	}
	// the earlier start ends without its withdrawal, as a crash ends it
	_ = earlier.Close()
	be, err := newBorderBackend()
	if err != nil {
		t.Fatal(err)
	}
	f, err := startBorderFilter(nil, entryRuntime(nil), be)
	if err != nil {
		t.Fatalf("start the filter with no overlay: %v", err)
	}
	t.Cleanup(func() { _ = f.finish() })
	conn, err := nftables.Dial()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	replies, err := conn.Dump(nftables.Command(unix.NFT_MSG_GETCHAIN), nftables.PutNfgenmsg(nil, unix.NFPROTO_INET))
	if err != nil {
		t.Fatal(err)
	}
	var chains []string
	for _, reply := range replies {
		if table, chain, _, _, _ := nftables.DecodeChain(reply); table == TableName {
			chains = append(chains, chain)
		}
	}
	if !slices.Equal(chains, []string{EntryChain}) {
		t.Errorf("table inet %s holds the chains %q, want %s alone", TableName, chains, EntryChain)
	}
	desired, sets, _ := f.desired()
	if read, err := be.Rules(desired, sets); err != nil || read.fault != "" {
		t.Errorf("the kernel holds %v with the fault %q (%v), want %v", read.rules, read.fault, err, desired)
	}
	if got := f.Where(); got != "nftables table inet "+TableName+" chain "+EntryChain {
		t.Errorf("the filter says it is in %s", got)
	}
}

// A start over a table holding a prerouting chain the filter does not write,
// named border, takes that chain away with the rest of the table, with
// overlay written and without it, the second over an entry chain and sets
// that read back exactly as the filter writes them. The table then holds the
// filter's chains alone and reads back ready, so nothing of the other chain
// drops a packet beside the filter.
func TestBorderRoundTripTakesOverATableWithAStrayChain(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	enterThrowawayNamespace(t)
	run := nftRun(t)
	conn, err := nftables.Dial()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	for _, c := range []struct {
		name string
		cfg  *egress.Border
		want []string
	}{
		{"with overlay", overlay(t, "198.18.0.0/15", "3fff::/20"), []string{BorderChain, EntryChain}},
		{"without overlay", nil, []string{EntryChain}},
	} {
		// the entry chain and sets are the filter's, and the filter that wrote
		// them ends without its withdrawal, as a killed process ends it
		earlier, err := newBorderBackend()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := startBorderFilter(nil, entryRuntime(nil), earlier); err != nil {
			t.Fatalf("%s: write the entry chain: %v", c.name, err)
		}
		_ = earlier.Close()
		run("add", "chain", "inet", TableName, "border", "{ type filter hook prerouting priority -300; policy accept; }")
		run("add", "rule", "inet", TableName, "border", "iifname", "ranet3", "accept", "comment", `"accept via ranet3"`)
		run("add", "rule", "inet", TableName, "border", "ip", "saddr", "198.18.0.0/15", "counter", "drop", "comment", `"drop ipv4 source 198.18.0.0/15"`)

		be, err := newBorderBackend()
		if err != nil {
			t.Fatal(err)
		}
		f, err := startBorderFilter(c.cfg, entryRuntime(nil), be)
		if err != nil {
			t.Fatalf("%s: start the filter over a table with a stray chain: %v", c.name, err)
		}
		replies, err := conn.Dump(nftables.Command(unix.NFT_MSG_GETCHAIN), nftables.PutNfgenmsg(nil, unix.NFPROTO_INET))
		if err != nil {
			t.Fatal(err)
		}
		var chains []string
		for _, reply := range replies {
			if table, chain, _, _, _ := nftables.DecodeChain(reply); table == TableName {
				chains = append(chains, chain)
			}
		}
		if !slices.Equal(slices.Sorted(slices.Values(chains)), c.want) {
			t.Errorf("%s: table inet %s holds the chains %q, want %q alone", c.name, TableName, chains, c.want)
		}
		desired, sets, _ := f.desired()
		if read, err := be.Rules(desired, sets); err != nil || read.fault != "" || !f.ready {
			t.Errorf("%s: over a table with a stray chain the filter reads ready %v (%q) over %v with the fault %q (%v)", c.name, f.ready, f.unready, read.rules, read.fault, err)
		}
		if listing := run("list", "table", "inet", TableName); strings.Contains(listing, "chain border") {
			t.Errorf("%s: the stray chain outlived the start:\n%s", c.name, listing)
		}
		if err := f.finish(); err != nil {
			t.Fatal(err)
		}
	}
}

// the crash helper of TestBorderRoundTripOutlivesAKilledOwner, which writes the
// table in the namespace its environment names and waits to be killed
func TestBorderCrashHelper(t *testing.T) {
	path := os.Getenv(borderCrashNamespace)
	if path == "" {
		t.Skip("TestBorderRoundTripOutlivesAKilledOwner runs the crash helper in a process of its own")
	}
	runtime.LockOSThread()
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Setns(fd, unix.CLONE_NEWNET); err != nil {
		t.Fatal(err)
	}
	be, err := newBorderBackend()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := startBorderFilter(overlay(t), entryRuntime(nil), be); err != nil {
		t.Fatal(err)
	}
	fmt.Println("written")
	// the parent kills this process, and a parent gone before it closes stdin
	_, _ = io.Copy(io.Discard, os.Stdin)
}

// A table whose owner is killed stays, with every rule and element as the owner
// wrote it, and the next start adopts it without a write
func TestBorderRoundTripOutlivesAKilledOwner(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	enterThrowawayNamespace(t)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	helper := exec.Command(executable, "-test.run=^TestBorderCrashHelper$", "-test.v")
	helper.Env = append(os.Environ(), fmt.Sprintf("%s=/proc/%d/task/%d/ns/net", borderCrashNamespace, os.Getpid(), unix.Gettid()))
	stdin, err := helper.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := helper.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := helper.Start(); err != nil {
		t.Fatalf("start the crash helper: %v", err)
	}
	t.Cleanup(func() { _ = stdin.Close() })
	var written []string
	for lines := bufio.NewScanner(stdout); !slices.Contains(written, "written") && lines.Scan(); {
		written = append(written, lines.Text())
	}
	_ = helper.Process.Signal(unix.SIGKILL)
	_ = helper.Wait()
	if !slices.Contains(written, "written") {
		t.Fatalf("the crash helper did not write the table:\n%s", strings.Join(written, "\n"))
	}

	conn, err := nftables.Dial()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if inetTables(t, conn) != 1 {
		t.Fatalf("table inet %s went with its owner", TableName)
	}
	bus := events.New()
	rt := entryRuntime(bus)
	desired, sets, _ := newBorderFilter(overlay(t), rt, &fakeBorder{}).desired()
	if read, err := readBorder(conn, desired, sets); err != nil || read.fault != "" {
		t.Fatalf("after its owner was killed the kernel holds %v with the fault %q (%v), want %v", read.rules, read.fault, err, desired)
	}
	be, err := newBorderBackend()
	if err != nil {
		t.Fatal(err)
	}
	f, err := startBorderFilter(overlay(t), rt, be)
	if err != nil {
		t.Fatalf("start an antispoof filter over the table a killed owner left: %v", err)
	}
	t.Cleanup(func() { _ = f.finish() })
	if passes := bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "antispoof.pass" }, 0); len(passes) != 0 {
		t.Errorf("the start over the table a killed owner left wrote it: %v", passes)
	}
}
