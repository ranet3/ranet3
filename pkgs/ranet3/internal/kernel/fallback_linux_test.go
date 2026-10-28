// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"context"
	"errors"
	"net/netip"
	"os/exec"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/nftables"
	"ranet3.com/pkgs/ranet3/schema"
)

const (
	// fallbackRestoreBudget is how soon a pass answers another writer's change
	// to the table, the settle window and one pass, where the periodic pass the
	// test sets takes an hour
	fallbackRestoreBudget = time.Second
	// tableOwner is NFT_TABLE_F_OWNER of linux/netfilter/nf_tables.h, which
	// x/sys does not carry
	tableOwner = 0x2
)

// fallbackText is fallbackSample's table as nft spells it
const fallbackText = `table inet ranet3_fallback {
	set forwarded { type ifname; elements = { "ranetfw0" } }
	set lan4 { type ipv4_addr; flags interval; elements = { 198.51.100.0/25 } }
	set lan6 { type ipv6_addr; flags interval; elements = { 2001:db8:a::/64 } }
	set own4 { type ipv4_addr; flags interval; elements = { 203.0.113.0/24 } }
	set own6 { type ipv6_addr; flags interval; }
	set tcp_ports { type inet_service; flags interval; elements = { 22, 2222 } }
	set udp_ports { type inet_service; flags interval; elements = { 53, 60000-61000 } }
	chain fallback {
		type filter hook postrouting priority 2147483646; policy accept;
		oifname { "lo", "ranetsw0" } accept
		meta mark 0x00000072 accept
		meta iif != 0 iifname != @forwarded accept
		ip daddr @lan4 accept
		ip6 daddr @lan6 accept
		ip daddr { 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255 } accept
		ip6 daddr { fe80::/10, ff00::/8 } accept
		ip daddr @own4 accept
		ip6 daddr @own6 accept
		ct direction reply ct protocol tcp ct original proto-dst @tcp_ports accept
		ct direction reply ct protocol udp ct original proto-dst @udp_ports accept
		counter drop
	}
}
`

// fallbackSample is a table of every line, on the tun ranetsw0, each port set
// holding a port beside another port or a range
var fallbackSample = fallbackSets{
	tun: "ranetsw0", forwarded: []string{"ranetfw0"},
	lan4: []netip.Prefix{prefix("198.51.100.0/25")}, lan6: []netip.Prefix{prefix("2001:db8:a::/64")},
	own4: []netip.Prefix{prefix("203.0.113.0/24")},
	tcp:  []Service{{Protocol: "tcp", First: 22, Last: 22}, {Protocol: "tcp", First: 2222, Last: 2222}},
	udp:  []Service{{Protocol: "udp", First: 53, Last: 53}, {Protocol: "udp", First: 60000, Last: 61000}},
}

// The table the platform writes lists as nft 1.1.7 lists the same text, but
// for the comments it writes, reads back as written, outlives the socket
// that wrote it, and drops the host's own datagram beyond the LAN with EPERM
// while passing one to the LAN. Another writer's flushed set or chain reads
// back as a fault until the next write, and the delete takes the table.
func TestNetlinkFallbackTableListsAsNftsOwnAndOutlivesItsWriter(t *testing.T) {
	plat := rootRulePlatform(t, "ranetsw0")
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Fatal("the table to compare with is written through nft, which is not on the path")
	}
	run := func(args ...string) string {
		t.Helper()
		cmd := exec.Command(nft, args...)
		if args[0] == "-f" {
			cmd.Stdin = strings.NewReader(fallbackText)
		}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("nft %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return regexp.MustCompile(` comment "[^"]*"`).ReplaceAllString(string(out), "")
	}
	run("-f", "-")
	theirs := run("list", "table", "inet", FallbackTable)
	if err := plat.deleteFallback(); err != nil {
		t.Fatal(err)
	}

	// closing the platform's socket for the table deletes a table carrying the
	// owner flag
	if err := plat.writeFallback(fallbackSample); err != nil {
		t.Fatalf("write the table: %v", err)
	}
	if err := plat.unwatchFallback(); err != nil {
		t.Fatal(err)
	}
	if mine := run("list", "table", "inet", FallbackTable); mine != theirs {
		t.Errorf("the platform's table lists as\n%s\nwhere nft's lists as\n%s", mine, theirs)
	}
	if read, err := plat.readFallback(fallbackSample); read.fault != "" || err != nil {
		t.Errorf("the table reads back with %q (err %v)", read.fault, err)
	}

	conn, err := dialNetlink()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	createTUN(t, "ranetup0")
	link, err := conn.link(0, "ranetup0")
	if err != nil {
		t.Fatal(err)
	}
	setLinkFlags(t, conn, link.index, unix.IFF_UP)
	writeBatchAddress(t, conn, link.index, prefix("198.51.100.10/25"))
	writeBatchRoute(t, conn, unix.RT_TABLE_MAIN, prefix("0.0.0.0/0"), batchHop{index: link.index})
	send := func(to string) error {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd)
		return unix.Sendto(fd, []byte("x"), 0, &unix.SockaddrInet4{Port: 9, Addr: netip.MustParseAddr(to).As4()})
	}
	if err := send("192.0.2.200"); !errors.Is(err, unix.EPERM) {
		t.Errorf("a datagram beyond the LAN left with %v, want EPERM", err)
	}
	if err := send("198.51.100.5"); err != nil {
		t.Errorf("a datagram to the LAN was refused: %v", err)
	}
	// the refused datagram is 29 bytes, its IPv4 header and UDP's and one byte
	if read, err := plat.readFallback(fallbackSample); read.dropped != 1 || read.bytes != 29 || err != nil {
		t.Errorf("the drop counted %d packets and %d bytes (err %v), want the one refused datagram", read.dropped, read.bytes, err)
	}
	debug, err := ReadFallback()
	if err != nil {
		t.Fatal(err)
	}
	sets := map[string][]string{}
	for _, set := range debug.Sets {
		sets[set.Name] = set.Elements
	}
	if !debug.Held || len(debug.Rules) != 12 {
		t.Fatalf("the debug read finds %+v, want the table's twelve lines", debug)
	}
	if last := debug.Rules[11]; last.Spec != fallbackDrop || last.Packets != 1 ||
		!reflect.DeepEqual(sets, map[string][]string{"forwarded": {"ranetfw0"}, "lan4": {"198.51.100.0/25"}, "lan6": {"2001:db8:a::/64"}, "own4": {"203.0.113.0/24"}, "own6": {},
			"tcp_ports": {"22", "2222"}, "udp_ports": {"53", "60000-61000"}}) {
		t.Errorf("the debug read finds %+v", debug)
	}

	for _, change := range [][]string{{"flush", "set", "inet", FallbackTable, "lan4"}, {"flush", "chain", "inet", FallbackTable, "fallback"}} {
		run(change...)
		if read, err := plat.readFallback(fallbackSample); read.fault == "" || err != nil {
			t.Errorf("after nft %s the table reads back with %q (err %v), want a fault", strings.Join(change, " "), read.fault, err)
		}
		if err := plat.writeFallback(fallbackSample); err != nil {
			t.Fatal(err)
		}
		if read, err := plat.readFallback(fallbackSample); read.fault != "" || err != nil {
			t.Errorf("after nft %s and a write the table reads back with %q (err %v)", strings.Join(change, " "), read.fault, err)
		}
	}

	if err := plat.deleteFallback(); err != nil {
		t.Fatal(err)
	}
	if read, err := plat.readFallback(fallbackSample); read.fault != "the table is missing" || err != nil {
		t.Errorf("after the delete the table reads back with %q (err %v)", read.fault, err)
	}
	if err := send("192.0.2.200"); err != nil {
		t.Errorf("with the table gone a datagram beyond the LAN was refused: %v", err)
	}
	if err := plat.deleteFallback(); err != nil {
		t.Errorf("a delete with no table failed: %v", err)
	}
}

// Another writer's flushed set and deleted rule are written back within a pass
// of the change, where the periodic pass is an hour away. A table another
// writer holds under its own socket, which the reconciler cannot write, takes
// 5405 and 5435 out within a pass, and once that socket closes the
// reconciler's next try writes the table back and puts them in again.
func TestNetlinkFallbackTableAnswersAnotherWritersChangeWithinAPass(t *testing.T) {
	const device, uplink = "ranetsw0", "ranetup0"
	plat := rootRulePlatform(t, device)
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Fatal("another writer's changes are made through nft, which is not on the path")
	}
	conn, err := dialNetlink()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	createTUN(t, uplink)
	link, err := conn.link(0, uplink)
	if err != nil {
		t.Fatal(err)
	}
	setLinkFlags(t, conn, link.index, unix.IFF_UP)
	lan4, lan6 := prefix("198.51.100.10/25"), prefix("2001:db8:a::10/64")
	for address, unspecified := range map[netip.Prefix]netip.Addr{lan4: netip.IPv4Unspecified(), lan6: netip.IPv6Unspecified()} {
		writeBatchAddress(t, conn, link.index, address)
		writeBatchRoute(t, conn, unix.RT_TABLE_MAIN, netip.PrefixFrom(unspecified, 0), batchHop{index: link.index})
	}

	tbl, rt := platformFor(device)
	tbl.Reconcile = schema.Duration(time.Hour)
	// an overlay address of each family on the tun, without which mode 2 adds no 5405 or 5435
	tbl.Addresses = prefixes(prefix("192.0.2.1/32"), prefix("3fff::1/128"))
	rt.Overlay = exitPassOverlay
	network := NetworkState{
		IPv4: NetworkFamily{Default: DefaultRoute{Interface: uplink}, Links: []Link{{Name: uplink, Prefixes: []netip.Prefix{lan4}}}},
		IPv6: NetworkFamily{Default: DefaultRoute{Interface: uplink}, Links: []Link{{Name: uplink, Prefixes: []netip.Prefix{lan6}}}},
	}
	rt.Network = func() NetworkState { return network }
	reconciler := newReconciler(tbl.WithMode(&ExitMode{Fallback: FallbackNone}).Normalized(), rt, tbl.Assigned(nil), netstack.NewRouteTable(), plat)
	exit, _ := reconciler.exitPass(reconciler.addresses)
	sets, asked := reconciler.fallbackFor(exit)
	if !asked {
		t.Fatal("the mode does not ask for the table")
	}

	// read through sockets of the test's own, since the loop owns the platform's
	reader, err := nftables.Dial()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close() })
	fault := func() string {
		read, err := fallbackFault(reader, sets)
		if err != nil {
			t.Fatalf("read the table back: %v", err)
		}
		return read.fault
	}
	uplinkSources := func() int {
		replies, err := conn.execute(unix.RTM_GETRULE, unix.NLM_F_DUMP, make([]byte, sizeofFibRuleHdr))
		if err != nil {
			t.Fatalf("dump rules: %v", err)
		}
		held := 0
		for _, reply := range replies {
			if rule, ok := plat.decodeRule(reply); ok && (rule.Priority == priorityUplinkSource || rule.Priority == priorityLinkSource) {
				held++
			}
		}
		return held
	}
	// one address and one network of each family
	const sources = 4
	// settle waits for the table to read back as written, or not, and for
	// held of 5405 and 5435, naming what it last read when it gives up
	settle := func(written bool, held int) {
		t.Helper()
		var last string
		var count int
		for deadline := time.Now().Add(waitBudget); time.Now().Before(deadline); time.Sleep(waitPoll) {
			last, count = fault(), uplinkSources()
			if (last == "") == written && count == held {
				return
			}
		}
		t.Fatalf("the table reads back with %q and the kernel holds %d of 5405 and 5435, want written %v and %d", last, count, written, held)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- reconciler.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("the reconciler stopped with %v", err)
		}
	})
	settle(true, sources)

	run := func(args ...string) string {
		t.Helper()
		out, err := exec.Command(nft, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("nft %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return string(out)
	}
	handle := regexp.MustCompile(`comment "counter drop" # handle (\d+)`)
	for _, change := range []func() string{
		func() string {
			run("flush", "set", "inet", FallbackTable, "lan4")
			return "a flushed set"
		},
		func() string {
			found := handle.FindStringSubmatch(run("-a", "list", "chain", "inet", FallbackTable, "fallback"))
			if found == nil {
				t.Fatal("the chain lists no drop")
			}
			run("delete", "rule", "inet", FallbackTable, "fallback", "handle", found[1])
			return "a deleted drop"
		},
	} {
		what := change()
		changed := time.Now()
		settle(true, sources)
		if took := time.Since(changed); took > fallbackRestoreBudget {
			t.Errorf("after %s the table took %s to read back as written, want at most %s", what, took, fallbackRestoreBudget)
		}
	}

	holder, err := nftables.Dial()
	if err != nil {
		t.Fatal(err)
	}
	owned := nftables.Request{Kind: nftables.Command(unix.NFT_MSG_NEWTABLE), Flags: unix.NLM_F_CREATE,
		Body: nftables.PutAttrBE32(nftables.PutAttrString(nftables.PutNfgenmsg(nil, unix.NFPROTO_INET), unix.NFTA_TABLE_NAME, FallbackTable), unix.NFTA_TABLE_FLAGS, tableOwner)}
	if err := holder.Batch([]nftables.Request{nftables.DeleteTable(unix.NFPROTO_INET, FallbackTable), owned}); err != nil {
		_ = holder.Close()
		t.Fatalf("take the table under another writer's socket: %v", err)
	}
	changed := time.Now()
	settle(false, 0)
	if took := time.Since(changed); took > fallbackRestoreBudget {
		t.Errorf("with the table held by another writer 5405 and 5435 took %s to go, want at most %s", took, fallbackRestoreBudget)
	}
	if err := holder.Close(); err != nil {
		t.Fatal(err)
	}
	settle(true, sources)
}
