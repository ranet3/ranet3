// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package egress

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
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

	cfg := Egress{
		Return:    true,
		Advertise: prefixes(t, "198.51.100.0/24", "2001:db8:1::/48", "0.0.0.0/0"),
	}
	rt := Runtime{
		Interface:     "ranet0",
		Egress:        "ranet0e",
		MeshAddresses: []netip.Addr{netip.MustParseAddr("10.88.0.2"), netip.MustParseAddr("2001:db8::2")},
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
	if len(desired) != 7 {
		t.Fatalf("the configuration asks for %d rules, want two out of the mesh device, two out of the egress device and three in", len(desired))
	}
	if err := be.Apply(desired); err != nil {
		t.Fatalf("install %d rules: %v", len(desired), err)
	}

	// The whole round trip in one assertion: the kernel took every expression,
	// kept the rules in the order they were written, and handed back the
	// spelling this package wrote into each one's comment. A mismatch here is
	// a ruleset the reconcile loop would rewrite on every pass forever.
	held, err := be.Rules()
	if err != nil {
		t.Fatalf("read the rules back: %v", err)
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

	// A rule with no comment in this tool's chain is another writer's, and the
	// readback holds it where the kernel does, so a diff built from it rewrites
	// the chain.
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Fatal("another writer's rule is written through nft, which is not on the path")
	}
	if out, err := exec.Command(nft, "insert", "rule", "ip", TableName, ChainName, "accept").CombinedOutput(); err != nil {
		t.Fatalf("insert another writer's rule: %v\n%s", err, out)
	}
	withOther, err := be.Rules()
	if err != nil {
		t.Fatalf("read the rules back beside another writer's: %v", err)
	}
	got = got[:0]
	for _, rule := range withOther {
		got = append(got, rule.Spec)
	}
	if !slices.Equal(got, append([]string{""}, want...)) {
		t.Errorf("with another writer's uncommented rule at the head of the ip chain the readback holds %q, want it ahead of %q", got, want)
	}

	// A counter in every rule, at zero, since nothing has crossed this
	// namespace. Reading it back at all is the part that can break: it is a
	// 64-bit attribute the kernel aligns with a padding attribute of its own.
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
	if err := be.Apply(desired); err != nil {
		t.Fatalf("reinstall the rules: %v", err)
	}
	if held, err = be.Rules(); err != nil || len(held) != len(desired) {
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

	// an exit advertising nothing still owns a table in each family, for what arrives on its egress device
	steered, err := newBackend(Egress{}, rt)
	if err != nil {
		t.Fatalf("open the nftables backend for an exit advertising nothing: %v", err)
	}
	t.Cleanup(func() { _ = steered.Close() })
	only := newTranslator(Egress{}, rt, steered).desired()
	if err := steered.Apply(only); err != nil {
		t.Fatalf("install %d rules: %v", len(only), err)
	}
	if held, err = steered.Rules(); err != nil || !sameRules(held, only) {
		t.Fatalf("the kernel holds %v (%v), want %v", held, err, only)
	}
	tables, err := ownTables(steered.(*nftables).conn)
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
	rt := Runtime{Interface: "ranet0", Egress: "ranet0e"}
	be, err := newBackend(Egress{}, rt)
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
	rules := newTranslator(Egress{}, rt, be).desired()
	install := func() {
		t.Helper()
		if err := be.Apply(rules); err != nil {
			t.Fatalf("install %d rules: %v", len(rules), err)
		}
	}
	install()
	install()
	quiet("its own install and reinstall")

	another, err := dialNetfilter()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = another.Close() })
	for _, change := range []struct {
		name    string
		request nftRequest
	}{
		{"inserted an accept at the head of the ip6 chain", anotherWritersAccept(unix.NFPROTO_IPV6, ChainName)},
		{"set the ip table dormant", dormantTable(unix.NFPROTO_IPV4)},
		{"deleted the ip6 table", delTable(FamilyIPv6)},
	} {
		if err := another.batch([]nftRequest{change.request}); err != nil {
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
func anotherWritersAccept(proto uint8, chain string) nftRequest {
	body := putAttrString(putAttrString(putNfgenmsg(nil, proto), unix.NFTA_RULE_TABLE, TableName), unix.NFTA_RULE_CHAIN, chain)
	body = putAttr(body, unix.NFTA_RULE_EXPRESSIONS|nlaNested, verdict(chainAccept))
	// with no NLM_F_APPEND the kernel inserts the rule at the head of the chain
	return nftRequest{kind: nftCommand(unix.NFT_MSG_NEWRULE), flags: unix.NLM_F_CREATE, body: body}
}

// dormantTable is another writer's update setting this tool's table of the
// family proto dormant
func dormantTable(proto uint8) nftRequest {
	table := tableRequest(unix.NFT_MSG_NEWTABLE, unix.NLM_F_CREATE, proto)
	table.body = putAttrBE32(table.body, unix.NFTA_TABLE_FLAGS, unix.NFT_TABLE_F_DORMANT)
	return table
}

// A rule with no comment that another writer inserts at the head of the
// translator's own chain is read back with it, so the next pass rewrites the
// chain and leaves only the translator's rules
func TestNftablesRewritesAnotherWritersRuleInItsChain(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	enterThrowawayNamespace(t)
	rt := Runtime{
		Interface:  "ranet0",
		Egress:     "ranet0e",
		Forwarding: func() (bool, bool) { return true, true },
		Device:     func() (error, error) { return nil, nil },
	}
	be, err := newBackend(Egress{}, rt)
	if err != nil {
		t.Fatalf("open the nftables backend: %v", err)
	}
	t.Cleanup(func() { _ = be.Close() })
	requireEmptyRuleset(t, be)
	tr := newTranslator(Egress{}, rt, be)
	if err := tr.reconcile(); err != nil {
		t.Fatalf("first pass: %v", err)
	}

	another, err := dialNetfilter()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = another.Close() })
	if err := another.batch([]nftRequest{anotherWritersAccept(unix.NFPROTO_IPV6, ChainName)}); err != nil {
		t.Fatalf("insert another writer's accept rule: %v", err)
	}
	if held, err := be.Rules(); err != nil || !slices.ContainsFunc(held, func(rule Installed) bool { return rule.Spec == "" }) {
		t.Errorf("with another writer's accept rule at the head of the ip6 chain the readback holds %v (%v), want that rule with no comment among them", held, err)
	}

	if err := tr.reconcile(); err != nil {
		t.Fatalf("second pass: %v", err)
	}
	want := make([]string, 0, len(tr.desired()))
	for _, rule := range tr.desired() {
		want = append(want, rule.String())
	}
	// read through the other socket, so the chain compared holds every rule the kernel does, whatever this tool's readback keeps
	var got []string
	for _, family := range []uint8{FamilyIPv4, FamilyIPv6} {
		replies, err := another.dump(nftCommand(unix.NFT_MSG_GETRULE), putNfgenmsg(nil, nftFamily(family)))
		if err != nil {
			t.Fatalf("dump the %s rules: %v", tableFamilyName(family), err)
		}
		for _, reply := range replies {
			if table, chain, spec, _, _ := decodeRule(reply); table == TableName && chain == ChainName {
				got = append(got, spec)
			}
		}
	}
	if !slices.Equal(got, want) {
		t.Errorf("after the next pass the kernel holds %q, want only the translator's %q", got, want)
	}
	if s := tr.Stats(); !s.Ready4 || !s.Ready6 {
		t.Errorf("after the next pass the translator reads %+v, want both families ready", s)
	}
}

// foreignTransaction is another writer's table, chain and count rules, never naming this tool's table
func foreignTransaction(table string, count int) []nftRequest {
	const chain = "input"
	requests := []nftRequest{
		{kind: nftCommand(unix.NFT_MSG_NEWTABLE), flags: unix.NLM_F_CREATE, body: putAttrString(putNfgenmsg(nil, unix.NFPROTO_IPV4), unix.NFTA_TABLE_NAME, table)},
		{kind: nftCommand(unix.NFT_MSG_NEWCHAIN), flags: unix.NLM_F_CREATE, body: putAttrString(putAttrString(putNfgenmsg(nil, unix.NFPROTO_IPV4), unix.NFTA_CHAIN_TABLE, table), unix.NFTA_CHAIN_NAME, chain)},
	}
	for i := range count {
		var expressions []byte
		for _, e := range append(metaCompare(unix.NFT_META_IIFNAME, unix.NFT_CMP_EQ, fmt.Sprintf("eth%d", i%100)), expression("counter", nil)) {
			expressions = append(expressions, e...)
		}
		body := putAttrString(putAttrString(putNfgenmsg(nil, unix.NFPROTO_IPV4), unix.NFTA_RULE_TABLE, table), unix.NFTA_RULE_CHAIN, chain)
		requests = append(requests, nftRequest{kind: nftCommand(unix.NFT_MSG_NEWRULE), flags: unix.NLM_F_CREATE | unix.NLM_F_APPEND,
			body: putAttr(body, unix.NFTA_RULE_EXPRESSIONS|nlaNested, expressions)})
	}
	return requests
}

// socketDrops is how many datagrams the kernel has dropped for the netlink socket behind raw, and the bytes it holds queued, read from this thread's namespace
func socketDrops(t *testing.T, raw syscall.RawConn) (dropped, queued uint64) {
	t.Helper()
	var st unix.Stat_t
	var statErr error
	if err := raw.Control(func(fd uintptr) { statErr = unix.Fstat(int(fd), &st) }); err != nil || statErr != nil {
		t.Fatalf("stat the notification socket: %v, %v", err, statErr)
	}
	body, err := os.ReadFile("/proc/thread-self/net/netlink")
	if err != nil {
		t.Fatalf("read the netlink sockets: %v", err)
	}
	// sk Eth Pid Groups Rmem Wmem Dump Locks Drops Inode
	for line := range strings.Lines(string(body)) {
		fields := strings.Fields(line)
		if len(fields) != 10 || fields[9] != strconv.FormatUint(st.Ino, 10) {
			continue
		}
		queued, err = strconv.ParseUint(fields[4], 10, 64)
		if err == nil {
			dropped, err = strconv.ParseUint(fields[8], 10, 64)
		}
		if err != nil {
			t.Fatalf("the netlink socket of inode %d reads %q: %v", st.Ino, line, err)
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
	be, err := newBackend(Egress{}, Runtime{Interface: "ranet0", Egress: "ranet0e"})
	if err != nil {
		t.Fatalf("open the nftables backend: %v", err)
	}
	t.Cleanup(func() { _ = be.Close() })
	raw, err := be.(*nftables).monitor.file.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var shrunk error
	if err := raw.Control(func(fd uintptr) { shrunk = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, 1) }); err != nil || shrunk != nil {
		t.Fatalf("shrink the notification socket's buffer: %v, %v", err, shrunk)
	}
	another, err := dialNetfilter()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = another.Close() })
	// a reader the scheduler favors can keep up with one transaction's notifications, so transactions go on until the kernel has dropped one
	transactions := 0
	for dropped, _ := socketDrops(t, raw); dropped == 0; dropped, _ = socketDrops(t, raw) {
		if transactions == foreignTransactions {
			t.Fatalf("after %d transactions of %d rules the kernel had dropped no notification", transactions, foreignRules)
		}
		if err := another.batch(foreignTransaction(fmt.Sprintf("fw%d", transactions), foreignRules)); err != nil {
			t.Fatalf("commit another writer's transaction: %v", err)
		}
		transactions++
	}
	t.Logf("the kernel dropped a notification after %d transactions of %d rules", transactions, foreignRules)
	select {
	case <-be.Missed():
	case <-time.After(notificationWait):
		var rcvbuf int
		var readErr error
		if err := raw.Control(func(fd uintptr) { rcvbuf, readErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF) }); err != nil || readErr != nil {
			t.Logf("read the notification socket's buffer back: %v, %v", err, readErr)
		}
		dropped, queued := socketDrops(t, raw)
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
	tables, err := ownTables(be.(*nftables).conn)
	if err != nil {
		t.Fatalf("list this tool's tables: %v", err)
	}
	if len(tables) != 0 {
		t.Fatalf("the namespace holds %d tables named %s", len(tables), TableName)
	}
	rules, err := be.Rules()
	if err != nil {
		t.Fatalf("list rules: %v", err)
	}
	if len(rules) != 0 {
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
