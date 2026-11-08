// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"encoding/binary"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/nftables"
)

// switchChains and switchSet are the kill switch's chains and one of its sets
// as internal/kernel names them, which a test here writes from a socket of its
// own, as the reconciler does, and switchScope what its monitor watches
var (
	switchChains = []nftables.Chain{
		{Table: nftables.Table, Name: "fallback", Type: "filter", Hook: unix.NF_INET_POST_ROUTING, Priority: 2147483646},
		{Table: nftables.Table, Name: "output", Type: "filter", Hook: unix.NF_INET_LOCAL_OUT, Priority: 2147483646},
	}
	switchSet   = nftables.Set{Table: nftables.Table, Name: "lan4", ID: 1, KeyType: nftables.TypeIPv4Addr, KeyLen: 4, Flags: unix.NFT_SET_INTERVAL}
	switchScope = nftables.Contents{Chains: switchChains, Sets: []nftables.Set{switchSet}}.Scope()
)

// writeSwitch writes the kill switch's chains, each with a counted drop under
// a comment, and its set lan4 with an element, in one transaction of conn
func writeSwitch(t *testing.T, conn *nftables.Conn) {
	t.Helper()
	requests := nftables.Contents{Chains: switchChains}.Rewrite(unix.NFPROTO_INET, nftables.Contents{}, nil)
	replaced, err := switchSet.Replace(unix.NFPROTO_INET, nftables.Prefixes([]netip.Prefix{netip.MustParsePrefix("198.51.100.0/25")}))
	if err != nil {
		t.Fatal(err)
	}
	requests = append(requests, replaced...)
	for _, chain := range switchChains {
		rule, err := chain.Rule(unix.NFPROTO_INET, "counter drop", nftables.CountedDrop())
		if err != nil {
			t.Fatal(err)
		}
		requests = append(requests, rule)
	}
	if err := conn.Batch(requests); err != nil {
		t.Fatalf("write the kill switch's chains: %v", err)
	}
}

// chainHandle and ruleHandle are NFTA_CHAIN_HANDLE and NFTA_RULE_HANDLE, the
// attributes of a handle in a dump
const (
	chainHandle = 3
	ruleHandle  = 3
)

// tableHandlesByName is the handle of each chain of this tool's table, of each
// rule in it by its chain and place, and of each named set and object, by name
func tableHandlesByName(t *testing.T, conn *nftables.Conn) map[string]uint64 {
	t.Helper()
	handles := objectHandles(t, conn)
	for _, dump := range []struct {
		command             int
		table, name, handle uint16
	}{
		{unix.NFT_MSG_GETCHAIN, unix.NFTA_CHAIN_TABLE, unix.NFTA_CHAIN_NAME, chainHandle},
		{unix.NFT_MSG_GETRULE, unix.NFTA_RULE_TABLE, unix.NFTA_RULE_CHAIN, ruleHandle},
	} {
		replies, err := conn.Dump(nftables.Command(dump.command), nftables.PutNfgenmsg(nil, unix.NFPROTO_INET))
		if err != nil {
			t.Fatalf("dump the chains and rules: %v", err)
		}
		places := map[string]int{}
		for _, reply := range replies {
			var table, name string
			var handle uint64
			for kind, value := range reply.Attributes() {
				switch {
				case kind == dump.table:
					table = unix.ByteSliceToString(value)
				case kind == dump.name:
					name = unix.ByteSliceToString(value)
				case kind == dump.handle && len(value) == 8:
					handle = binary.BigEndian.Uint64(value)
				}
			}
			if table != nftables.Table {
				continue
			}
			key := "chain " + name
			if dump.command == unix.NFT_MSG_GETRULE {
				key = fmt.Sprintf("rule %s %d", name, places[name])
				places[name]++
			}
			handles[key] = handle
		}
	}
	return handles
}

// owned is whether a handle's key names a chain, a rule or a set of the
// owner whose names owns gives
func owned(key string, owns func(string) bool) bool {
	fields := strings.Fields(key)
	if len(fields) > 1 {
		return owns(fields[1])
	}
	return owns(key)
}

// startOwners writes the kill switch's chains from a socket of the test's own,
// then runs the first pass of a translator of both families and of an
// antispoof filter in this namespace, and answers the translator, its
// backend, the filter's backend, the filter and the switch's socket
func startOwners(t *testing.T) (*Translator, backend, borderBackend, *BorderFilter, *nftables.Conn) {
	t.Helper()
	switchConn, err := nftables.Dial()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = switchConn.Close() })
	writeSwitch(t, switchConn)
	rt := Runtime{Interface: "ranet0", Steered: true, Forwarding: func() (bool, bool) { return true, true }, Sysctl: readsNothing}
	be, err := newBackend(egress.Egress{}, rt)
	if err != nil {
		t.Fatalf("open the translator's backend: %v", err)
	}
	t.Cleanup(func() { _ = be.Close() })
	tr := newTranslator(egress.Egress{}, rt, be)
	if err := tr.reconcile(); err != nil {
		t.Fatalf("the translator's first pass: %v", err)
	}
	filterBackend, err := newBorderBackend(nil, egress.BorderRuntime{})
	if err != nil {
		t.Fatalf("open the antispoof filter's backend: %v", err)
	}
	f, err := startBorderFilter(overlay(t, "198.18.0.0/15", "3fff::/20"), entryRuntime(nil), filterBackend)
	if err != nil {
		t.Fatalf("start the antispoof filter: %v", err)
	}
	t.Cleanup(func() { _ = f.finish() })
	return tr, be, filterBackend, f, switchConn
}

// Each owner's remake, of a chain made again at another priority or the table
// set dormant, deletes and makes again at most its own chains: every chain,
// rule, set and object of the other two keeps its handle, and its counters
// with it, through the pass of the owner the change faulted
func TestEachOwnersRemakeKeepsTheOthers(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	enterThrowawayNamespace(t)
	run := nftRun(t)
	tr, _, _, f, switchConn := startOwners(t)
	translates := func(name string) bool {
		return chainOwner(name) == 0 || setOwner(name) == 0 || strings.HasPrefix(name, timeoutObject)
	}
	filters := func(name string) bool { return chainOwner(name) == 1 || setOwner(name) == 1 }
	for _, c := range []struct {
		name   string
		change string
		// pass is the owner's pass the change faults, and owns that owner's names
		pass func() error
		owns func(string) bool
	}{
		{"the antispoof chain made again at priority 0", fmt.Sprintf("delete chain inet %[1]s %[2]s; add chain inet %[1]s %[2]s { type filter hook prerouting priority 0; policy accept; }", nftables.Table, BorderChain),
			f.reconcile, filters},
		{"the translating chain made again at priority 0", fmt.Sprintf("delete chain inet %[1]s %[2]s; add chain inet %[1]s %[2]s { type nat hook postrouting priority 0; policy accept; }", nftables.Table, ChainName),
			tr.reconcile, translates},
		{"the table set dormant, the filter's pass", fmt.Sprintf("add table inet %s { flags dormant; }", nftables.Table), f.reconcile, filters},
	} {
		before := tableHandlesByName(t, switchConn)
		run(c.change)
		if err := c.pass(); err != nil {
			t.Fatalf("%s: the pass: %v", c.name, err)
		}
		after := tableHandlesByName(t, switchConn)
		for key, handle := range before {
			if !owned(key, c.owns) && after[key] != handle {
				t.Errorf("%s: after the pass %s has the handle %d where it had %d", c.name, key, after[key], handle)
			}
		}
		// the other passes put back what the change took of theirs
		if err := tr.reconcile(); err != nil {
			t.Fatal(err)
		}
		if err := f.reconcile(); err != nil {
			t.Fatal(err)
		}
	}
	if read, err := kernelSwitch(switchConn); err != nil || read != "" {
		t.Errorf("after every pass the kill switch reads back with %q (%v)", read, err)
	}
}

// kernelSwitch is the fault the kill switch's chains and set read back with
func kernelSwitch(conn *nftables.Conn) (string, error) {
	tables, err := nftables.Tables(conn, nftables.Table)
	if err != nil {
		return "", err
	}
	read, err := nftables.Contents{Chains: switchChains, Sets: []nftables.Set{switchSet}}.Read(conn, tables, unix.NFPROTO_INET)
	return read.Fault, err
}

// woke is whether changed carries a wake within quietFor
func woke(changed <-chan struct{}) bool {
	select {
	case <-changed:
		return true
	case <-time.After(quietFor):
		return false
	}
}

// Each owner's routine write, the filter's fill of a set, the translator's
// apply and the kill switch's rewrite, wakes neither other owner, another
// writer's rule in one owner's chain wakes that owner alone, and a flush of
// the whole ruleset wakes all three
func TestOwnersWakeOnTheirOwnChangesAlone(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	enterThrowawayNamespace(t)
	run := nftRun(t)
	tr, be, filterBackend, f, switchConn := startOwners(t)
	switchMonitor, err := nftables.OpenMonitor(switchConn, switchScope)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = switchMonitor.Close() })
	monitors := map[string]<-chan struct{}{"translator": be.Changed(), "filter": filterBackend.Changed(), "switch": switchMonitor.Changed()}
	for _, changed := range monitors {
		for woke(changed) {
		}
	}
	expect := func(what string, want ...string) {
		t.Helper()
		for name, changed := range monitors {
			if got := woke(changed); got != slices.Contains(want, name) {
				t.Errorf("%s woke the %s %v, want %v", what, name, got, slices.Contains(want, name))
			}
		}
	}
	_, written, _ := f.desired()
	moved := maps.Clone(written)
	moved[noneSet+"4"] = ranges("203.0.113.0/24")
	if err := filterBackend.Fill(nil, written, moved); err != nil {
		t.Fatalf("the filter's fill: %v", err)
	}
	expect("the filter's fill")
	if err := be.Apply(tr.desired(), false); err != nil {
		t.Fatalf("the translator's apply: %v", err)
	}
	expect("the translator's apply")
	writeSwitch(t, switchConn)
	expect("the kill switch's rewrite")
	for chain, owner := range map[string]string{BorderChain: "filter", LimitChain: "translator", familyChain(egress.FamilyIPv6): "translator", "fallback": "switch"} {
		run("insert", "rule", "inet", nftables.Table, chain, "accept")
		expect("another writer's rule in chain "+chain, owner)
	}
	run("flush", "ruleset")
	expect("a flush of the whole ruleset", "translator", "filter", "switch")
}
