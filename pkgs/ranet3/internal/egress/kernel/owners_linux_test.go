// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/netlink"
	"ranet3.com/pkgs/ranet3/internal/netnstest"
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
	rt := Runtime{Interface: "ranet0", Steered: true, Forwarding: func() (bool, bool) { return true, true }, Sysctl: readsNothing, Hooks: unheard}
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

// A translator that ended without withdrawing holds the table no more, and the
// next one, whose first pass finds what the first wrote as written and keeps
// every handle of it, holds the table in its place: its withdrawal, the
// table's last holder's, deletes the table
func TestTranslatorTakingAnEndedOnesChainsOverDeletesTheTableAtItsWithdrawal(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmpty(t)
	rt := Runtime{Interface: "ranet0", Steered: true, Forwarding: func() (bool, bool) { return true, true }, Sysctl: readsNothing, Hooks: unheard}
	ended, err := newBackend(egress.Egress{}, rt)
	if err != nil {
		t.Fatalf("open the first translator's backend: %v", err)
	}
	requireEmptyRuleset(t, ended)
	if err := newTranslator(egress.Egress{}, rt, ended).reconcile(); err != nil {
		t.Fatalf("the first translator's pass: %v", err)
	}
	if err := ended.Close(); err != nil {
		t.Fatal(err)
	}
	reader, err := nftables.Dial()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close() })
	written := tableHandlesByName(t, reader)

	be, err := newBackend(egress.Egress{}, rt)
	if err != nil {
		t.Fatalf("open the next translator's backend: %v", err)
	}
	t.Cleanup(func() { _ = be.Close() })
	if err := newTranslator(egress.Egress{}, rt, be).reconcile(); err != nil {
		t.Fatalf("the next translator's pass: %v", err)
	}
	if kept := tableHandlesByName(t, reader); !maps.Equal(kept, written) {
		t.Fatalf("the next translator's pass changed the handles %v to %v, want what the first wrote kept", written, kept)
	}
	if err := be.Withdraw(); err != nil {
		t.Fatalf("the next translator's withdrawal: %v", err)
	}
	if tables, err := nftables.Tables(reader, nftables.Table); err != nil || len(tables) != 0 {
		t.Errorf("after the withdrawal of the translator that took the chains over, the table %s is in the families %v (%v), want none", nftables.Table, tables, err)
	}
}

// Each owner's remake, of a chain made again at another priority or the table
// set dormant, deletes and makes again at most its own chains: every chain,
// rule, set and object of the other two keeps its handle, and its counters
// with it, through the pass of the owner the change faulted
func TestEachOwnersRemakeKeepsTheOthers(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmpty(t)
	run := nftRun(t)
	tr, _, _, f, switchConn := startOwners(t)
	objects := slices.Concat(timeoutObjects(egress.FamilyIPv4), timeoutObjects(egress.FamilyIPv6))
	translates := func(name string) bool {
		return chainOwner(name) == 0 || setOwner(name) == 0 || slices.ContainsFunc(objects, func(object nftables.Timeout) bool { return object.Name == name })
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

// oneField is set's Create with a description of one concatenated field as
// long as its key, NFTA_SET_DESC_CONCAT holding one NFTA_SET_FIELD_LEN, after
// Create's own description, which nf_tables takes the last of. A dump shows
// the set as Create makes it, and nf_tables refuses Create over it.
func oneField(t *testing.T, set nftables.Set) nftables.Request {
	t.Helper()
	made, err := set.Create(unix.NFPROTO_INET)
	if err != nil {
		t.Fatal(err)
	}
	field := netlink.PutAttr(nil, unix.NFTA_LIST_ELEM|unix.NLA_F_NESTED, nftables.PutAttrBE32(nil, 1, set.KeyLen))
	desc := netlink.PutAttr(nftables.PutAttrBE32(nil, unix.NFTA_SET_DESC_SIZE, set.Size), 2|unix.NLA_F_NESTED, field)
	made.Body = netlink.PutAttr(made.Body, unix.NFTA_SET_DESC|unix.NLA_F_NESTED, desc)
	return made
}

// A set of the antispoof filter's, carved4, and one of the translator's,
// flows4, each made again by another writer with one concatenated field, which
// nf_tables refuses the owner's create for, and the owner's chains flushed,
// which its pass reads as a fault, are made again by that pass once nothing
// else uses them. While another writer's rule looks the set up the pass is
// refused with EBUSY, and the owner is not ready with a reason that says so.
// The translator's retry makes its other set of flows again too, which loses
// that set's counts.
func TestEachOwnerMakesAgainASetItsCreateIsRefusedFor(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	flows6 := flowSet(egress.FamilyIPv6, egress.DefaultFlowsPerSource)
	for _, c := range []struct {
		name   string
		set    nftables.Set
		chains []nftables.Chain
		pass   func(*Translator, *BorderFilter) error
		// state is the owner's readiness and the text that says why it is not
		state func(*Translator, *BorderFilter) (bool, string)
		// counted is whether flows6 holds a count the pass's retry takes
		counted bool
	}{
		{
			"the antispoof filter", borderSet(carvedSet + "4"), borderContents.Chains,
			func(_ *Translator, f *BorderFilter) error { return f.reconcile() },
			func(_ *Translator, f *BorderFilter) (bool, string) { return f.ready, f.unready }, false,
		},
		{
			"the translator", flowSet(egress.FamilyIPv4, egress.DefaultFlowsPerSource), translatorChains,
			func(tr *Translator, _ *BorderFilter) error { return tr.reconcile() },
			func(tr *Translator, _ *BorderFilter) (bool, string) {
				s := tr.lastPass()
				return s.Ready4 && s.Ready6, s.Err
			}, true,
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			netnstest.EnterEmpty(t)
			tr, _, _, f, another := startOwners(t)
			counts := []nftables.Interval{nftables.Key(netip.MustParseAddr("3fff::2").AsSlice())}
			if c.counted {
				filled, err := flows6.Fill(unix.NFPROTO_INET, counts)
				if err != nil {
					t.Fatal(err)
				}
				if err := another.Batch(filled); err != nil {
					t.Fatalf("a count in %s: %v", flows6.Name, err)
				}
				if held, err := flows6.Elements(another, unix.NFPROTO_INET); err != nil || len(held) != 1 {
					t.Fatalf("with a count %s holds %v (%v), want it", flows6.Name, held, err)
				}
			}
			var requests []nftables.Request
			for _, chain := range c.chains {
				requests = append(requests, chain.Flush(unix.NFPROTO_INET))
			}
			if err := another.Batch(append(requests, c.set.Delete(unix.NFPROTO_INET), oneField(t, c.set))); err != nil {
				t.Fatalf("another writer makes %s again: %v", c.set.Name, err)
			}
			made, err := c.set.Create(unix.NFPROTO_INET)
			if err != nil {
				t.Fatal(err)
			}
			if err := another.Batch([]nftables.Request{made}); !errors.Is(err, unix.EEXIST) {
				t.Fatalf("the owner's create of %s made again: %v, want %v", c.set.Name, err, unix.EEXIST)
			}
			other := nftables.Chain{Table: nftables.Table, Name: "other", Hook: nftables.NoHook}
			rule, err := other.Rule(unix.NFPROTO_INET, "other", [][]byte{nftables.SourceLoad(unix.NFPROTO_IPV4), nftables.Lookup(c.set, false)})
			if err != nil {
				t.Fatal(err)
			}
			if err := another.Batch([]nftables.Request{other.Create(unix.NFPROTO_INET), rule}); err != nil {
				t.Fatalf("another writer's rule that looks %s up: %v", c.set.Name, err)
			}
			if err := c.pass(tr, f); !errors.Is(err, unix.EBUSY) {
				t.Errorf("the owner's pass while another writer's rule looks %s up: %v, want %v", c.set.Name, err, unix.EBUSY)
			}
			if ready, why := c.state(tr, f); ready || !strings.Contains(why, unix.EBUSY.Error()) {
				t.Errorf("after the refused pass the owner reads ready %v with %q, want not ready with %q", ready, why, unix.EBUSY.Error())
			}
			if err := another.Batch([]nftables.Request{other.Flush(unix.NFPROTO_INET), other.Delete(unix.NFPROTO_INET)}); err != nil {
				t.Fatalf("another writer deletes its rule: %v", err)
			}
			if err := c.pass(tr, f); err != nil {
				t.Fatalf("the owner's pass: %v", err)
			}
			if ready, why := c.state(tr, f); !ready {
				t.Errorf("after the owner's pass the owner is not ready: %q", why)
			}
			if !c.counted {
				return
			}
			if held, err := flows6.Elements(another, unix.NFPROTO_INET); err != nil || len(held) != 0 {
				t.Errorf("after the pass's retry %s holds %v (%v), want no count", flows6.Name, held, err)
			}
		})
	}
}

// A set of the antispoof filter's, carved4, and one of the translator's,
// untranslated4, each made again by another writer as an anonymous set held by
// a line of that writer's in the owner's chain, are made again by the owner's
// pass, which flushes that line, after which the owner is ready and the set
// reads back as written
func TestEachOwnerMakesAgainASetAnotherWriterMadeAnonymous(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	for _, c := range []struct {
		name   string
		set    nftables.Set
		chains []nftables.Chain
		pass   func(*Translator, *BorderFilter) error
		ready  func(*Translator, *BorderFilter) bool
	}{
		{
			"the antispoof filter", borderSet(carvedSet + "4"), borderContents.Chains,
			func(_ *Translator, f *BorderFilter) error { return f.reconcile() },
			func(_ *Translator, f *BorderFilter) bool { return f.ready },
		},
		{
			"the translator", untranslatedSources(egress.FamilyIPv4), translatorChains,
			func(tr *Translator, _ *BorderFilter) error { return tr.reconcile() },
			func(tr *Translator, _ *BorderFilter) bool { return tr.lastPass().Ready4 && tr.lastPass().Ready6 },
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			netnstest.EnterEmpty(t)
			tr, _, _, f, another := startOwners(t)
			made := c.set
			made.Flags |= unix.NFT_SET_ANONYMOUS | unix.NFT_SET_CONSTANT
			create, err := made.Create(unix.NFPROTO_INET)
			if err != nil {
				t.Fatal(err)
			}
			filled, err := made.Fill(unix.NFPROTO_INET, nftables.Prefixes([]netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}))
			if err != nil {
				t.Fatal(err)
			}
			line, err := c.chains[0].Rule(unix.NFPROTO_INET, "theirs", [][]byte{nftables.SourceLoad(unix.NFPROTO_IPV4), nftables.Lookup(made, false)})
			if err != nil {
				t.Fatal(err)
			}
			var requests []nftables.Request
			for _, chain := range c.chains {
				requests = append(requests, chain.Flush(unix.NFPROTO_INET))
			}
			if err := another.Batch(slices.Concat(requests, []nftables.Request{c.set.Delete(unix.NFPROTO_INET), create}, filled, []nftables.Request{line})); err != nil {
				t.Fatalf("another writer makes %s again anonymous: %v", c.set.Name, err)
			}
			if err := c.pass(tr, f); err != nil {
				t.Fatalf("the owner's pass: %v", err)
			}
			if !c.ready(tr, f) {
				t.Errorf("after the owner's pass the owner is not ready")
			}
			tables, err := nftables.Tables(another, nftables.Table)
			if err != nil {
				t.Fatal(err)
			}
			if read, err := (nftables.Contents{Sets: []nftables.Set{c.set}}).Read(another, tables, unix.NFPROTO_INET); err != nil || read.Fault != "" {
				t.Errorf("after the owner's pass %s reads back with the fault %q (%v)", c.set.Name, read.Fault, err)
			}
		})
	}
}

// chainFlags and chainBinding are NFTA_CHAIN_FLAGS and NFT_CHAIN_BINDING,
// which x/sys does not carry
const (
	chainFlags   = 10
	chainBinding = 0x4
)

// bindingChain is another writer's transaction that makes a binding chain
// named name, holding a line that drops, and puts a goto to it at the head of
// chain, which binds it
func bindingChain(t *testing.T, chain nftables.Chain, name string) []nftables.Request {
	t.Helper()
	return bindingChainOf(t, chain, name, nftables.CountedDrop())
}

// bindingChainOf is bindingChain with line in the binding chain
func bindingChainOf(t *testing.T, chain nftables.Chain, name string, line [][]byte) []nftables.Request {
	t.Helper()
	bound := nftables.Chain{Table: nftables.Table, Name: name, Hook: nftables.NoHook}
	made := bound.Create(unix.NFPROTO_INET)
	made.Body = nftables.PutAttrBE32(made.Body, chainFlags, chainBinding)
	held, err := bound.Rule(unix.NFPROTO_INET, "theirs", line)
	if err != nil {
		t.Fatal(err)
	}
	return []nftables.Request{made, held, headLine(t, chain, [][]byte{nftables.Goto(name)})}
}

// headLine is another writer's line at the head of chain
func headLine(t *testing.T, chain nftables.Chain, line [][]byte) nftables.Request {
	t.Helper()
	rule, err := chain.Rule(unix.NFPROTO_INET, "theirs", line)
	if err != nil {
		t.Fatal(err)
	}
	// with no NLM_F_APPEND nf_tables puts the line at the head of the chain
	rule.Flags = unix.NLM_F_CREATE
	return rule
}

// otherOutput is another writer's own chain at the output hook
var otherOutput = nftables.Chain{Table: nftables.Table, Name: "other", Type: "filter", Hook: unix.NF_INET_LOCAL_OUT, Priority: 0}

// anotherWriter is a socket of another writer's
func anotherWriter(t *testing.T) *nftables.Conn {
	t.Helper()
	another, err := nftables.Dial()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = another.Close() })
	return another
}

// sourcePorts counts the datagrams sent, each of which binds a source port of
// its own: nf_nat runs the nat chains for the first packet of a flow alone, so
// a datagram whose port repeated an earlier one's would pass postrouting's by
var sourcePorts atomic.Int32

// datagram sends one datagram to 127.0.0.2, which a drop at postrouting
// refuses with EPERM
func datagram() error { return datagramTo(9) }

// datagramTo sends one datagram from 127.0.0.1 to port of 127.0.0.2
func datagramTo(port int) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrInet4{Port: 40000 + int(sourcePorts.Add(1)), Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		return err
	}
	return unix.Sendto(fd, []byte("probe"), 0, &unix.SockaddrInet4{Port: port, Addr: [4]byte{127, 0, 0, 2}})
}

// received is whether a datagram from 127.0.0.1 reaches a socket of
// 127.0.0.2's, which a drop at prerouting keeps from it
func received(t *testing.T) bool {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrInet4{Port: 7, Addr: [4]byte{127, 0, 0, 2}}); err != nil {
		t.Fatal(err)
	}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Usec: 200000}); err != nil {
		t.Fatal(err)
	}
	if err := datagramTo(7); err != nil {
		t.Fatalf("a datagram to 127.0.0.2 left with %v, want sent", err)
	}
	_, _, err = unix.Recvfrom(fd, make([]byte, 16), 0)
	return err == nil
}

// startTranslator is the translator's backend and the translator after its
// first pass
func startTranslator(t *testing.T) (*Translator, backend) {
	t.Helper()
	rt := Runtime{Interface: "ranet0", Steered: true, Forwarding: func() (bool, bool) { return true, true }, Sysctl: readsNothing, Hooks: unheard}
	be, err := newBackend(egress.Egress{}, rt)
	if err != nil {
		t.Fatalf("open the translator's backend: %v", err)
	}
	t.Cleanup(func() { _ = be.Close() })
	tr := newTranslator(egress.Egress{}, rt, be)
	if err := tr.reconcile(); err != nil {
		t.Fatalf("the translator's first pass: %v", err)
	}
	return tr, be
}

// A binding chain another writer makes under mesh_entry, the name an earlier
// filter gave its entry chain, holding a line that drops and reached by that
// writer's goto at the head of the filter's entry chain, drops a datagram the
// filter passes. The filter's pass, whose flush of the goto takes the chain
// out with it, is ready, and the datagram passes again. One reached from
// another writer's chain stays through the pass, which commits, and the
// filter is not ready with a reason that names that chain.
func TestBorderLeavesABindingChainUnderAnEarlierNameToItsFlush(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmpty(t)
	be, err := newBorderBackend(nil, egress.BorderRuntime{})
	if err != nil {
		t.Fatalf("open the antispoof filter's backend: %v", err)
	}
	f, err := startBorderFilter(overlay(t, "198.18.0.0/15", "3fff::/20"), entryRuntime(nil), be)
	if err != nil {
		t.Fatalf("start the antispoof filter: %v", err)
	}
	t.Cleanup(func() { _ = f.finish() })
	if err := datagram(); err != nil {
		t.Fatalf("with the filter written a datagram left with %v, want sent", err)
	}
	another, err := nftables.Dial()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = another.Close() })
	if err := another.Batch(bindingChain(t, entry, retiredEntry[0])); err != nil {
		t.Fatalf("another writer makes the binding chain %s: %v", retiredEntry[0], err)
	}
	if err := datagram(); !errors.Is(err, unix.EPERM) {
		t.Fatalf("with the binding chain a datagram left with %v, want EPERM", err)
	}
	if err := f.reconcile(); err != nil {
		t.Errorf("the filter's pass: %v", err)
	}
	if !f.ready {
		t.Errorf("after the filter's pass it is not ready: %q", f.unready)
	}
	if err := datagram(); err != nil {
		t.Errorf("after the filter's pass a datagram left with %v, want sent", err)
	}
	other := nftables.Chain{Table: nftables.Table, Name: "other", Type: "filter", Hook: unix.NF_INET_LOCAL_OUT, Priority: 0}
	if err := another.Batch(append([]nftables.Request{other.Create(unix.NFPROTO_INET)}, bindingChain(t, other, retiredEntry[0])...)); err != nil {
		t.Fatalf("another writer makes the binding chain %s from its own chain: %v", retiredEntry[0], err)
	}
	held := "its chain " + retiredEntry[0] + " is not one the filter writes, and chain other holds a rule going to it, so it stays until that rule goes"
	if err := f.reconcile(); err != nil {
		t.Errorf("the filter's pass beside the binding chain another writer's chain holds: %v", err)
	}
	if f.ready || !strings.Contains(f.unready, held) {
		t.Errorf("beside the binding chain another writer's chain holds the filter reads ready %v with %q, want not ready with %q", f.ready, f.unready, held)
	}
}

// A binding chain another writer makes under a stray chain's name, holding a
// line that drops and reached by that writer's goto at the head of the
// translator's chain at postrouting, drops a datagram the translator passes.
// The translator's pass, whose flush of the goto takes the chain out with it,
// is ready in both families, and the datagram passes again. One reached from
// another writer's chain stays through the pass, which commits, and neither
// family is ready, with a reason that names that chain.
func TestTranslatorLeavesABindingChainUnderAStrayNameToItsFlush(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmpty(t)
	rt := Runtime{Interface: "ranet0", Steered: true, Forwarding: func() (bool, bool) { return true, true }, Sysctl: readsNothing, Hooks: unheard}
	be, err := newBackend(egress.Egress{}, rt)
	if err != nil {
		t.Fatalf("open the translator's backend: %v", err)
	}
	t.Cleanup(func() { _ = be.Close() })
	tr := newTranslator(egress.Egress{}, rt, be)
	if err := tr.reconcile(); err != nil {
		t.Fatalf("the translator's first pass: %v", err)
	}
	if err := datagram(); err != nil {
		t.Fatalf("with the translator written a datagram left with %v, want sent", err)
	}
	another, err := nftables.Dial()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = another.Close() })
	stray := NoneChain + "192_0_2_0_24"
	if err := another.Batch(bindingChain(t, postrouting, stray)); err != nil {
		t.Fatalf("another writer makes the binding chain %s: %v", stray, err)
	}
	if err := datagram(); !errors.Is(err, unix.EPERM) {
		t.Fatalf("with the binding chain a datagram left with %v, want EPERM", err)
	}
	if err := tr.reconcile(); err != nil {
		t.Errorf("the translator's pass: %v", err)
	}
	if s := tr.lastPass(); !s.Ready4 || !s.Ready6 {
		t.Errorf("after the translator's pass it reads %+v, want ready in both families", s)
	}
	if err := datagram(); err != nil {
		t.Errorf("after the translator's pass a datagram left with %v, want sent", err)
	}
	other := nftables.Chain{Table: nftables.Table, Name: "other", Type: "filter", Hook: unix.NF_INET_LOCAL_OUT, Priority: 0}
	if err := another.Batch(append([]nftables.Request{other.Create(unix.NFPROTO_INET)}, bindingChain(t, other, stray)...)); err != nil {
		t.Fatalf("another writer makes the binding chain %s from its own chain: %v", stray, err)
	}
	held := "its chain " + stray + " is not one the translator writes, and chain other holds a rule going to it, so it stays until that rule goes"
	if err := tr.reconcile(); err != nil {
		t.Errorf("the translator's pass beside the binding chain another writer's chain holds: %v", err)
	}
	if s := tr.lastPass(); s.Ready4 || s.Ready6 || !strings.Contains(s.Unready, held) {
		t.Errorf("beside the binding chain another writer's chain holds the translator reads ready %v and %v with %q, want not ready with %q", s.Ready4, s.Ready6, s.Unready, held)
	}
}

// A ct timeout under a name an earlier translator gave one, attached by a line
// of a binding chain another writer makes under a stray chain's name and binds
// from a chain of its own, beside that writer's drop at the head of the
// translator's chain at postrouting, is held by that binding chain, which no
// flush of the translator's takes out. The translator's pass commits, keeps
// the timeout and takes out the drop, and neither family is ready, with a
// reason that names the binding chain and the chain that binds it.
func TestTranslatorKeepsATimeoutABindingChainOfAnotherWriterUses(t *testing.T) {
	for _, name := range []string{NoneChain + "192_0_2_0_24", retiredChain} {
		t.Run(name, func(t *testing.T) {
			if runtime.GOOS != "linux" || os.Getuid() != 0 {
				t.Skip("the real nftables path needs root on linux")
			}
			netnstest.EnterEmpty(t)
			tr, _ := startTranslator(t)
			another := anotherWriter(t)
			timeout := nftables.Timeout{Table: nftables.Table, Name: retiredTimeouts[0], L3Proto: unix.NFPROTO_IPV4, L4Proto: unix.IPPROTO_UDP, Policy: []uint32{30, 120}}
			requests := slices.Concat([]nftables.Request{otherOutput.Create(unix.NFPROTO_INET), timeout.Create(unix.NFPROTO_INET)},
				bindingChainOf(t, otherOutput, name, [][]byte{nftables.ObjectReference(unix.NFT_OBJECT_CT_TIMEOUT, timeout.Name)}),
				[]nftables.Request{headLine(t, postrouting, nftables.CountedDrop())})
			if err := another.Batch(requests); err != nil {
				t.Fatalf("another writer makes the timeout, the binding chain attaching it and the drop: %v", err)
			}
			if err := datagram(); !errors.Is(err, unix.EPERM) {
				t.Fatalf("with the drop a datagram left with %v, want EPERM", err)
			}
			if err := tr.reconcile(); err != nil {
				t.Errorf("the translator's pass: %v", err)
			}
			if err := datagram(); err != nil {
				t.Errorf("after the translator's pass a datagram left with %v, want sent", err)
			}
			held := "its chain " + name + " is not one the translator writes, and chain other holds a rule going to it, so it stays until that rule goes"
			if s := tr.lastPass(); s.Ready4 || s.Ready6 || !strings.Contains(s.Unready, held) {
				t.Errorf("after the translator's pass it reads ready %v and %v with %q, want not ready with %q", s.Ready4, s.Ready6, s.Unready, held)
			}
			want := []nftables.Retired{{Kind: "ct timeout", Name: timeout.Name, HeldBy: "chain " + name}}
			if left, err := nftables.Leftovers(another, nil, translatorRetired, translatorScope); err != nil || !slices.Equal(left, want) {
				t.Errorf("after the translator's pass the leftovers read %+v (%v), want %+v", left, err, want)
			}
		})
	}
}

// A binding chain another writer makes under a stray chain's name, binds from
// a chain of its own and sends on to the translator's IPv6 chain, beside that
// writer's drop at the head of the translator's chain at postrouting, holds
// that chain through the translator's withdrawal, which no flush of the
// translator's takes the binding chain out of. The withdrawal commits, takes
// out the drop, and leaves IPv6's chain empty beside the other writer's.
func TestTranslatorWithdrawalKeepsAChainABindingChainOfAnotherWriterGoesTo(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmpty(t)
	_, be := startTranslator(t)
	another := anotherWriter(t)
	requests := slices.Concat([]nftables.Request{otherOutput.Create(unix.NFPROTO_INET)},
		bindingChainOf(t, otherOutput, NoneChain+"192_0_2_0_24", [][]byte{nftables.Goto(forward6.Name)}),
		[]nftables.Request{headLine(t, postrouting, nftables.CountedDrop())})
	if err := another.Batch(requests); err != nil {
		t.Fatalf("another writer makes the binding chain going to %s and the drop: %v", forward6.Name, err)
	}
	if err := datagram(); !errors.Is(err, unix.EPERM) {
		t.Fatalf("with the drop a datagram left with %v, want EPERM", err)
	}
	if err := be.Withdraw(); err != nil {
		t.Errorf("the translator's withdrawal: %v", err)
	}
	if err := datagram(); err != nil {
		t.Errorf("after the withdrawal a datagram left with %v, want sent", err)
	}
	if chains, err := nftables.TableChains(another, unix.NFPROTO_INET, nftables.Table); err != nil || !slices.Equal(chains, []string{forward6.Name, otherOutput.Name}) {
		t.Errorf("after the withdrawal the table lists the chains %v (%v), want %s and %s", chains, err, forward6.Name, otherOutput.Name)
	}
	rules, err := nftables.TableRules(another, unix.NFPROTO_INET, nftables.Table)
	if err != nil {
		t.Fatal(err)
	}
	if i := slices.IndexFunc(rules, func(rule nftables.Installed) bool { return rule.Chain == forward6.Name }); i >= 0 {
		t.Errorf("after the withdrawal %s holds %+v, want it empty", forward6.Name, rules[i])
	}
}

// A binding chain another writer makes under the filter's entry chain's name,
// in the transaction that deletes that chain, holding a line that drops and
// bound from the head of the filter's chain at prerouting, keeps a datagram
// from its socket. The filter's pass, which flushes the chain at prerouting
// before it makes entry, takes the binding chain out with the goto and makes
// entry again, is ready, and the datagram arrives again.
func TestBorderMakesAgainAChainUnderItsNameItsFlushTakesOut(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmpty(t)
	be, err := newBorderBackend(nil, egress.BorderRuntime{})
	if err != nil {
		t.Fatalf("open the antispoof filter's backend: %v", err)
	}
	f, err := startBorderFilter(overlay(t, "198.18.0.0/15", "3fff::/20"), entryRuntime(nil), be)
	if err != nil {
		t.Fatalf("start the antispoof filter: %v", err)
	}
	t.Cleanup(func() { _ = f.finish() })
	if !received(t) {
		t.Fatal("with the filter written a datagram did not arrive")
	}
	another := anotherWriter(t)
	if err := another.Batch(append([]nftables.Request{entry.Delete(unix.NFPROTO_INET)}, bindingChain(t, prerouting, entry.Name)...)); err != nil {
		t.Fatalf("another writer makes the binding chain %s: %v", entry.Name, err)
	}
	if received(t) {
		t.Fatal("with the binding chain a datagram arrived, want it dropped")
	}
	if read, err := be.Read(nil); err != nil || read.fault == "" {
		t.Errorf("with the binding chain the filter reads back with %q (%v), want a fault", read.fault, err)
	}
	if err := f.reconcile(); err != nil {
		t.Errorf("the filter's pass: %v", err)
	}
	if !f.ready {
		t.Errorf("after the filter's pass it is not ready: %q", f.unready)
	}
	if !received(t) {
		t.Error("after the filter's pass a datagram did not arrive")
	}
}

// A chain another writer makes in a table of its own under mesh_entry, the
// name an earlier filter gave its entry chain, is no leftover of the filter's,
// and the filter's pass over that writer's line in entry commits and is ready
func TestBorderLeavesAnEarlierNameInAnotherTableAlone(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmpty(t)
	be, err := newBorderBackend(nil, egress.BorderRuntime{})
	if err != nil {
		t.Fatalf("open the antispoof filter's backend: %v", err)
	}
	f, err := startBorderFilter(overlay(t, "198.18.0.0/15", "3fff::/20"), entryRuntime(nil), be)
	if err != nil {
		t.Fatalf("start the antispoof filter: %v", err)
	}
	t.Cleanup(func() { _ = f.finish() })
	another := anotherWriter(t)
	theirs := nftables.Chain{Table: "other", Name: retiredEntry[0], Hook: nftables.NoHook}
	requests := []nftables.Request{nftables.NewTable(unix.NFPROTO_INET, theirs.Table), theirs.Create(unix.NFPROTO_INET), headLine(t, entry, [][]byte{nftables.Verdict(nftables.Accept)})}
	if err := another.Batch(requests); err != nil {
		t.Fatalf("another writer makes chain %s in its table and a line in %s: %v", theirs.Name, entry.Name, err)
	}
	if left, err := nftables.Leftovers(another, nil, borderRetired, borderScope); err != nil || left != nil {
		t.Errorf("the leftovers read %+v (%v), want none", left, err)
	}
	if err := f.reconcile(); err != nil {
		t.Errorf("the filter's pass: %v", err)
	}
	if !f.ready {
		t.Errorf("after the filter's pass it is not ready: %q", f.unready)
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
	netnstest.EnterEmpty(t)
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
