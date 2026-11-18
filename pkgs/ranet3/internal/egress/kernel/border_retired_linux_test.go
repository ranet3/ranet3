// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"os"
	"runtime"
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/netnstest"
	"ranet3.com/pkgs/ranet3/internal/nftables"
)

// earlierEntry is the name an earlier filter gave its chain at postrouting,
// written apart from the filter's own list
const earlierEntry = "mesh_entry"

// startEarlierEntry starts the filter over overlay in an empty namespace and
// returns it with what nft lists of the table its first pass wrote, then
// renames the filter's chain at postrouting to earlierEntry, which leaves the
// table as an earlier filter that ended without its withdrawal left it
func startEarlierEntry(t *testing.T) (*BorderFilter, borderBackend, func(args ...string) string, string) {
	t.Helper()
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmpty(t)
	run := nftRun(t)
	be, err := newBorderBackend(nil, egress.BorderRuntime{})
	if err != nil {
		t.Fatalf("open the antispoof filter's backend: %v", err)
	}
	f, err := startBorderFilter(overlay(t, "198.18.0.0/15", "3fff::/20"), entryRuntime(nil), be)
	if err != nil {
		t.Fatalf("start the antispoof filter: %v", err)
	}
	t.Cleanup(func() { _ = f.finish() })
	fresh := run("list", "table", "inet", nftables.Table)
	run("rename", "chain", "inet", nftables.Table, EntryChain, earlierEntry)
	if listing := run("list", "table", "inet", nftables.Table); !strings.Contains(listing, "chain "+earlierEntry+" {\n\t\ttype filter hook postrouting") || strings.Contains(listing, "chain "+EntryChain+" {") {
		t.Fatalf("the earlier layout lists, want the chain %s at postrouting and no chain %s:\n%s", earlierEntry, EntryChain, listing)
	}
	return f, be, run, fresh
}

// A table an earlier filter left, its chain at postrouting under the name it
// gave it, wakes the filter's monitor and reads back with a fault, and the
// next pass deletes that chain in the transaction that writes the entry chain,
// so the table lists as a fresh one the same pass wrote and the filter reads
// ready
func TestBorderRoundTripRetiresTheEarlierEntryChain(t *testing.T) {
	f, be, run, fresh := startEarlierEntry(t)
	if !woken(be.Changed()) {
		t.Errorf("the chain %s made did not wake the filter", earlierEntry)
	}
	desired, sets, _ := f.desired()
	if read, err := be.Rules(desired, sets); err != nil || read.fault == "" {
		t.Errorf("the earlier layout reads back with the fault %q (%v), want one", read.fault, err)
	}
	if err := f.reconcile(); err != nil {
		t.Fatalf("the pass over the earlier layout: %v", err)
	}
	if read, err := be.Rules(desired, sets); err != nil || read.fault != "" || !f.ready {
		t.Errorf("after the pass the filter reads ready %v (%q) with the fault %q (%v)", f.ready, f.unready, read.fault, err)
	}
	listing := run("list", "table", "inet", nftables.Table)
	if strings.Contains(listing, "chain "+earlierEntry+" {") {
		t.Errorf("after the pass nft lists the chain %s:\n%s", earlierEntry, listing)
	}
	if listing != fresh {
		t.Errorf("after the pass the table lists\n%s\nwhere the pass over no table wrote\n%s", listing, fresh)
	}
}

// A regular chain under the earlier entry chain's name that another writer's
// rule goes to stays, emptied, with a fault that names that rule's chain, and
// the pass after the rule goes deletes it and reads ready
func TestBorderRoundTripKeepsTheEarlierEntryChainAnotherWritersRuleGoesTo(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmpty(t)
	run := nftRun(t)
	be, err := newBorderBackend(nil, egress.BorderRuntime{})
	if err != nil {
		t.Fatalf("open the antispoof filter's backend: %v", err)
	}
	f, err := startBorderFilter(overlay(t, "198.18.0.0/15", "3fff::/20"), entryRuntime(nil), be)
	if err != nil {
		t.Fatalf("start the antispoof filter: %v", err)
	}
	t.Cleanup(func() { _ = f.finish() })
	run("add", "chain", "inet", nftables.Table, earlierEntry)
	run("add", "rule", "inet", nftables.Table, earlierEntry, "ip", "saddr", "198.51.100.0/24", "counter", "drop")
	run("add", "chain", "inet", nftables.Table, "other")
	run("add", "rule", "inet", nftables.Table, "other", "jump", earlierEntry)
	const fault = "its chain " + earlierEntry + " is not one the filter writes, and chain other holds a rule going to it, so it stays until that rule goes"
	desired, sets, _ := f.desired()
	if read, err := be.Rules(desired, sets); err != nil || read.fault != fault {
		t.Errorf("beside the held chain the filter reads the fault %q (%v), want %q", read.fault, err, fault)
	}
	if err := f.reconcile(); err != nil {
		t.Fatalf("the pass beside the held chain: %v", err)
	}
	if f.ready || f.unready != fault {
		t.Errorf("after the pass beside the held chain the filter reads ready %v (%q), want not ready with %q", f.ready, f.unready, fault)
	}
	if listing := run("list", "chain", "inet", nftables.Table, earlierEntry); strings.Contains(listing, "drop") {
		t.Errorf("after the pass the held chain holds its line:\n%s", listing)
	}
	run("flush", "chain", "inet", nftables.Table, "other")
	if err := f.reconcile(); err != nil {
		t.Fatalf("the pass after the rule went: %v", err)
	}
	if !f.ready {
		t.Errorf("after the rule went the filter reads not ready (%q)", f.unready)
	}
	listing := run("list", "table", "inet", nftables.Table)
	if strings.Contains(listing, "chain "+earlierEntry+" {") || !strings.Contains(listing, "chain other {") {
		t.Errorf("after the rule went nft lists, want no chain %s and the chain other:\n%s", earlierEntry, listing)
	}
}

// The filter's withdrawal over the table an earlier filter left takes the
// chain under the earlier name with the rest, and the table with it
func TestBorderRoundTripWithdrawsTheEarlierEntryChain(t *testing.T) {
	f, _, run, _ := startEarlierEntry(t)
	if err := f.finish(); err != nil {
		t.Fatalf("the filter's stop over the earlier layout: %v", err)
	}
	if listing := run("list", "ruleset"); listing != "" {
		t.Errorf("after the stop over the earlier layout nft lists:\n%s", listing)
	}
}
