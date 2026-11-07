// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package underlay

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// loopbackIndex is lo0's index, a real interface the kernel accepts a scope to
func loopbackIndex(t *testing.T) int {
	t.Helper()
	loopback, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Fatal(err)
	}
	return loopback.Index
}

// selecting answers index for every address and records each address it was asked for
func selecting(index int, asked *[]netip.Addr) func(netip.Addr) (int, uint64) {
	return func(address netip.Addr) (int, uint64) {
		*asked = append(*asked, address)
		return index, 1
	}
}

// scopeOf reads back the interface a socket of conn is scoped to
func scopeOf(t *testing.T, conn syscall.Conn, ipv6 bool) int {
	t.Helper()
	level, option := unix.IPPROTO_IP, unix.IP_BOUND_IF
	if ipv6 {
		level, option = unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var index int
	var readErr error
	if err := raw.Control(func(fd uintptr) { index, readErr = unix.GetsockoptInt(int(fd), level, option) }); err != nil || readErr != nil {
		t.Fatalf("read the scope back: %v %v", err, readErr)
	}
	return index
}

// dialPrepared dials to from a socket prepare readied
func dialPrepared(network string, to netip.AddrPort, prepare Prepare) (net.Conn, error) {
	dialer := net.Dialer{Control: func(network, _ string, raw syscall.RawConn) error { return prepare(network, to, raw) }}
	return dialer.Dial(network, to.String())
}

// a socket Bound prepares is scoped to the interface the selection names for its destination, in either family
// an IPv4-mapped destination opens an AF_INET socket, which takes IP_BOUND_IF, and the selection is asked for the IPv4 address
// a zoned link-local destination is asked for with its zone
func TestBoundScopesEachSocketToTheSelectedInterface(t *testing.T) {
	index := loopbackIndex(t)
	for _, test := range []struct {
		network string
		to      string
		ipv6    bool
		asked   string
	}{
		{"udp4", "127.0.0.1:9", false, "127.0.0.1"},
		{"udp6", "[::1]:9", true, "::1"},
		{"udp", "[::ffff:127.0.0.1]:9", false, "127.0.0.1"},
		{"udp6", "[fe80::1%lo0]:9", true, "fe80::1%lo0"},
	} {
		var asked []netip.Addr
		conn, err := dialPrepared(test.network, netip.MustParseAddrPort(test.to), Bound(selecting(index, &asked)))
		if err != nil {
			t.Fatalf("dial %s through Bound: %v", test.to, err)
		}
		if got := scopeOf(t, conn.(syscall.Conn), test.ipv6); got != index {
			t.Errorf("the socket to %s is scoped to %d, want lo0's %d", test.to, got, index)
		}
		_ = conn.Close()
		if len(asked) != 1 || asked[0] != netip.MustParseAddr(test.asked) {
			t.Errorf("the selection was asked for %v on a dial to %s, want %s", asked, test.to, test.asked)
		}
	}
}

// a destination the selection names no interface for is refused with ENETUNREACH before the socket connects
func TestBoundRefusesADestinationTheSelectionNamesNoInterfaceFor(t *testing.T) {
	var asked []netip.Addr
	_, err := dialPrepared("udp4", netip.MustParseAddrPort("127.0.0.1:9"), Bound(selecting(0, &asked)))
	if !errors.Is(err, unix.ENETUNREACH) {
		t.Fatalf("a dial the selection names no interface for answered %v, want ENETUNREACH", err)
	}
}

// a socket that only receives, whose destination is zero, is left unscoped and asks the selection nothing
func TestBoundLeavesAReceivingSocketUnscoped(t *testing.T) {
	for _, family := range []struct {
		network string
		ipv6    bool
	}{{"udp4", false}, {"udp6", true}} {
		var asked []netip.Addr
		prepare := Bound(selecting(loopbackIndex(t), &asked))
		config := net.ListenConfig{Control: func(network, _ string, raw syscall.RawConn) error { return prepare(network, netip.AddrPort{}, raw) }}
		conn, err := config.ListenPacket(context.Background(), family.network, ":0")
		if err != nil {
			t.Fatal(err)
		}
		if got := scopeOf(t, conn.(syscall.Conn), family.ipv6); got != 0 {
			t.Errorf("the receiving %s socket is scoped to %d, want none", family.network, got)
		}
		_ = conn.Close()
		if len(asked) != 0 {
			t.Errorf("a receiving socket asked the selection for %v", asked)
		}
	}
}

// Scope sets the interface and 0 clears it again, in either family
func TestScopeSetsAndClearsTheInterface(t *testing.T) {
	index := loopbackIndex(t)
	for _, family := range []struct {
		network string
		ipv6    bool
	}{{"udp4", false}, {"udp6", true}} {
		conn, err := net.ListenPacket(family.network, ":0")
		if err != nil {
			t.Fatal(err)
		}
		raw, err := conn.(syscall.Conn).SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []int{index, 0} {
			if err := Scope(raw, family.ipv6, want); err != nil {
				t.Fatal(err)
			}
			if got := scopeOf(t, conn.(syscall.Conn), family.ipv6); got != want {
				t.Errorf("the %s socket Scope set to %d reads %d", family.network, want, got)
			}
		}
		_ = conn.Close()
	}
}
