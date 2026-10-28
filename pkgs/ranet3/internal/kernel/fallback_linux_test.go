// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"errors"
	"net/netip"
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// fallbackText is fallbackSample's table as nft spells it
const fallbackText = `table inet ranet3_fallback {
	set forwarded { type ifname; elements = { "ranetfw0" } }
	set lan4 { type ipv4_addr; flags interval; elements = { 198.51.100.0/25 } }
	set lan6 { type ipv6_addr; flags interval; elements = { 2001:db8:a::/64 } }
	set own4 { type ipv4_addr; flags interval; elements = { 203.0.113.0/24 } }
	set own6 { type ipv6_addr; flags interval; }
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
		ct direction reply ct protocol tcp ct original proto-dst { 22, 2222 } accept
		ct direction reply ct protocol udp ct original proto-dst { 53, 60000-61000 } accept
		counter drop
	}
}
`

// fallbackSample is a table of every line, on the tun ranetsw0. Each port set
// holds two members, since nft writes a set of one as a compare and the
// platform writes a set whatever it holds.
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

	// the platform's socket for the table is closed once the write returns,
	// which deletes a table carrying the owner flag
	if err := plat.writeFallback(fallbackSample); err != nil {
		t.Fatalf("write the table: %v", err)
	}
	if mine := run("list", "table", "inet", FallbackTable); mine != theirs {
		t.Errorf("the platform's table lists as\n%s\nwhere nft's lists as\n%s", mine, theirs)
	}
	if fault, err := plat.readFallback(fallbackSample); fault != "" || err != nil {
		t.Errorf("the table reads back with %q (err %v)", fault, err)
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

	for _, change := range [][]string{{"flush", "set", "inet", FallbackTable, "lan4"}, {"flush", "chain", "inet", FallbackTable, "fallback"}} {
		run(change...)
		if fault, err := plat.readFallback(fallbackSample); fault == "" || err != nil {
			t.Errorf("after nft %s the table reads back with %q (err %v), want a fault", strings.Join(change, " "), fault, err)
		}
		if err := plat.writeFallback(fallbackSample); err != nil {
			t.Fatal(err)
		}
		if fault, err := plat.readFallback(fallbackSample); fault != "" || err != nil {
			t.Errorf("after nft %s and a write the table reads back with %q (err %v)", strings.Join(change, " "), fault, err)
		}
	}

	if err := plat.deleteFallback(); err != nil {
		t.Fatal(err)
	}
	if fault, err := plat.readFallback(fallbackSample); fault != "the table is missing" || err != nil {
		t.Errorf("after the delete the table reads back with %q (err %v)", fault, err)
	}
	if err := send("192.0.2.200"); err != nil {
		t.Errorf("with the table gone a datagram beyond the LAN was refused: %v", err)
	}
	if err := plat.deleteFallback(); err != nil {
		t.Errorf("a delete with no table failed: %v", err)
	}
}
