// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/nftables"
)

// What nf_tables takes of the border chain and hands back, against a real
// kernel in a namespace this test made and proved empty: every spec in order
// with its counter at zero, the hook and priority, nft's own reading of the
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
		t.Fatalf("open the border backend: %v", err)
	}
	conn, err := nftables.Dial()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if inetTables(t, conn) != 0 {
		t.Fatalf("the namespace already holds an inet table named %s", TableName)
	}

	fake := &fakeBorder{}
	rt := borderRuntime(fake, nil, "3fff:a::1")
	rt.Inside = []string{"ranet3", "lo"}
	f, err := startBorderFilter(overlay(t, "198.18.0.0/15", "3fff::/20"), rt, be)
	if err != nil {
		t.Fatalf("start the border filter: %v", err)
	}
	desired := f.desired()
	read, err := be.Rules()
	if err != nil {
		t.Fatal(err)
	}
	held := read.rules
	if !sameBorderRules(held, desired) || read.fault != "" {
		t.Fatalf("the kernel holds %v with the fault %q, want %v", held, read.fault, desired)
	}
	for _, rule := range held {
		if rule.Packets != 0 || rule.Bytes != 0 {
			t.Errorf("%s came back with %d packets and %d bytes in an empty namespace", rule.Spec, rule.Packets, rule.Bytes)
		}
	}
	for _, rule := range f.Debug().Rules {
		if !rule.Held {
			t.Errorf("a debug read through its own socket does not find %s", rule.Spec)
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
		if chain != BorderChain || kind != "filter" || hook != unix.NF_INET_PRE_ROUTING || priority != -300 {
			t.Errorf("the kernel holds a %q chain %s at hook %d priority %d, want a filter chain %s at prerouting priority -300", kind, chain, hook, priority, BorderChain)
		}
	}
	if chains != 1 {
		t.Errorf("the kernel holds %d chains in table inet %s, want one", chains, TableName)
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
			`ip6 saddr 3fff::/20 counter packets 0 bytes 0 drop comment "drop ipv6 source 3fff::/20"`,
			`exthdr rt exists counter packets 0 bytes 0 drop comment "drop ipv6 routing header"`,
			`ip6 daddr 3fff:a::1 counter packets 0 bytes 0 drop comment "drop ipv6 destination 3fff:a::1"`,
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
		mark := len(fake.entries())
		if err := another.Batch([]nftables.Request{change.request}); err != nil {
			t.Fatalf("another writer %s: %v", change.name, err)
		}
		for deadline := time.Now().Add(notificationWait); ; time.Sleep(passPoll) {
			moved := fake.entries()[mark:]
			if len(moved) >= 2 && moved[0] == "ready false" && moved[len(moved)-1] == "ready true" {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("after another writer %s the filter went %q, want not ready and then ready", change.name, fake.entries()[mark:])
			}
		}
		if read, err := be.Rules(); err != nil || read.fault != "" || !sameBorderRules(read.rules, desired) {
			t.Fatalf("after another writer %s the kernel holds %v with the fault %q (%v), want %v", change.name, read.rules, read.fault, err, desired)
		}
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("stop the border filter: %v", err)
	}
	if inetTables(t, conn) != 0 {
		t.Error("the inet table outlived the filter")
	}
	// a withdrawal of nothing is not an error
	again, err := newBorderBackend()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = again.Close() })
	if err := again.Withdraw(); err != nil {
		t.Errorf("withdrawing from a host holding no table failed: %v", err)
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

// A rule another writer puts in the border chain with no comment, the table
// set dormant, the chain's policy turned to drop, the chain made again at
// another priority or as a regular chain, and the table made again with a flag
// nf_tables will not clear in place each wake the filter, read back as
// other than the filter wrote them, and the next pass writes the table and the
// chain back, waking nothing, and reads them ready. A chain nf_tables will not
// change in place is put back by deleting the table and making it again,
// which takes another chain in it along. Another inet table holding a rule
// under the filter's own spelling stays out of the readback and the passes.
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
		t.Fatalf("open the border backend: %v", err)
	}
	fake := &fakeBorder{}
	rt := borderRuntime(fake, nil, "3fff:a::1")
	rt.Inside = []string{"ranet3", "lo"}
	f, err := startBorderFilter(overlay(t, "198.18.0.0/15", "3fff::/20"), rt, be)
	if err != nil {
		t.Fatalf("start the border filter beside another inet table: %v", err)
	}
	t.Cleanup(func() { _ = f.finish() })
	desired := f.desired()
	const foreign = `iifname "eth0" accept comment "accept via ranet3"`
	for _, change := range []struct {
		name string
		args [][]string
		// nft lists gone in the table while the change stands
		gone string
		// remade is whether the pass deletes the table and makes it again
		remade bool
	}{
		{"an uncommented accept at the head of the chain", [][]string{{"insert", "rule", "inet", TableName, BorderChain, "accept"}}, "\t\taccept\n", false},
		{"the table set dormant", [][]string{{"add", "table", "inet", TableName, "{ flags dormant; }"}}, "flags dormant", false},
		{"the chain's policy turned to drop", [][]string{{"chain", "inet", TableName, BorderChain, "{ policy drop; }"}}, "policy drop;", false},
		{"the chain made again at priority 0", [][]string{
			{"delete", "chain", "inet", TableName, BorderChain},
			{"add", "chain", "inet", TableName, BorderChain, "{ type filter hook prerouting priority 0; policy accept; }"},
		}, "priority filter;", true},
		{"the chain made again as a regular chain", [][]string{
			{"delete", "chain", "inet", TableName, BorderChain},
			{"add", "chain", "inet", TableName, BorderChain},
		}, "chain border {\n\t}", true},
		// nft's socket owns the table until nft exits, and the kernel then keeps it with the persist flag alone
		{"the table made again to persist past its owner", [][]string{
			{fmt.Sprintf("delete table inet %[1]s; add table inet %[1]s { flags owner, persist; }", TableName)},
		}, "flags persist", true},
	} {
		for _, args := range change.args {
			run(args...)
		}
		if listing := run("list", "table", "inet", TableName); !strings.Contains(listing, change.gone) {
			t.Fatalf("%s: nft does not list %q in:\n%s", change.name, change.gone, listing)
		}
		if !woken(be.Changed()) {
			t.Errorf("%s: another writer's change did not wake the filter", change.name)
		}
		if read, err := be.Rules(); err != nil || read.fault == "" && sameBorderRules(read.rules, desired) || read.remake != change.remade {
			t.Errorf("%s: the readback finds the fault %q, remade %v, over %v (%v), want a difference, remade %v", change.name, read.fault, read.remake, read.rules, err, change.remade)
		}
		if err := f.reconcile(); err != nil {
			t.Fatalf("%s: the pass failed: %v", change.name, err)
		}
		read, err := be.Rules()
		if err != nil || read.fault != "" || !sameBorderRules(read.rules, desired) || !f.ready {
			t.Errorf("%s: after the pass the filter reads ready %v (%q) over %v with the fault %q (%v)", change.name, f.ready, f.unready, read.rules, read.fault, err)
		}
		listing := run("list", "table", "inet", TableName)
		if strings.Contains(listing, change.gone) {
			t.Errorf("%s: after the pass nft still lists %q in:\n%s", change.name, change.gone, listing)
		}
		if strings.Contains(listing, foreign) == change.remade {
			t.Errorf("%s: after a pass that remade the table %v, another chain in it lists:\n%s", change.name, change.remade, listing)
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
		if err := be.Withdraw(); err != nil {
			t.Fatalf("withdrawal %d beside another writer's inet table: %v", i+1, err)
		}
	}
	if listing := run("list", "table", "inet", "other"); !strings.Contains(listing, `iifname "eth0" accept comment "accept via ranet3"`) {
		t.Errorf("the withdrawals reached another writer's table:\n%s", listing)
	}
}
