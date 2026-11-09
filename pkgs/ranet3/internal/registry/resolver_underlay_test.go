// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build (linux && !android) || (darwin && !ios)

package registry

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"syscall"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/schema"
)

// acceptWait is how long a listener waits for a connection a refused dial must not have made
const acceptWait = 200 * time.Millisecond

// dialWait bounds a dial toward a nameserver nothing answers at, should its socket go unrefused
const dialWait = 5 * time.Second

// errRefusedByTheTest is the error a test's prepare refuses a socket with, which no kernel returns
var errRefusedByTheTest = errors.New("refused by the test's prepare")

// A query to a nameserver lying in some prefix of the overlay goes unprepared,
// in either family, in IPv4's mapped form and with a zone, which resolv.conf
// may write after any IPv6 address, and every other one is prepared, a
// link-local one among them
func TestResolverPreparesAQueryOnlyOutsideTheOverlay(t *testing.T) {
	overlay := overlayOf("192.0.2.0/24", "3fff::/20")
	for _, test := range []struct {
		nameserver string
		want       bool
	}{
		{"192.0.2.53", false},
		{"::ffff:192.0.2.53", false},
		{"::ffff:192.0.2.53%eth0", false},
		{"::ffff:192.0.2.53%en0", false},
		{"3fff:0:1::53", false},
		{"3fff:0:1::53%eth0", false},
		{"3fff:0:1::53%en0", false},
		{"3fff:0:1::53%1", false},
		{"198.51.100.53", true},
		{"::ffff:198.51.100.53", true},
		{"::ffff:198.51.100.53%eth0", true},
		{"::ffff:198.51.100.53%en0", true},
		{"2001:db8::53", true},
		{"2001:db8::53%eth0", true},
		{"2001:db8::53%en0", true},
		{"fe80::53%eth0", true},
		{"fe80::53%en0", true},
		{"127.0.0.53", true},
	} {
		if got := preparesQueryTo(netip.MustParseAddr(test.nameserver), overlay); got != test.want {
			t.Errorf("a query to %s is prepared %v, want %v", test.nameserver, got, test.want)
		}
	}
	if !preparesQueryTo(netip.MustParseAddr("192.0.2.53"), nil) {
		t.Error("a query with no overlay goes unprepared")
	}
}

// The resolver is Go's own whatever the build, dialing through its own Dial,
// and the Prepare it is handed sees each socket of a query to a nameserver
// outside the overlay, by its network and the nameserver with its zone, a
// query's datagram and its fallback over TCP alike, and none to a nameserver
// inside it. Nothing listens at the zoned link-local nameserver, so the
// Prepare refuses its sockets once it has seen them.
func TestResolverPreparesOnlyQueriesOutsideTheOverlay(t *testing.T) {
	loopbackReady(t)
	listener := listenTCP(t, "127.0.0.1:0")
	port := netip.MustParseAddrPort(listener.Addr().String()).Port()
	for _, test := range []struct {
		name       string
		nameserver netip.AddrPort
		overlay    []schema.Prefix
		refused    bool
		want       []string
	}{
		{"an IPv4 nameserver outside the overlay", netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port), overlayOf("192.0.2.0/24"), false, []string{"udp4", "tcp4"}},
		{"an IPv4-mapped nameserver outside the overlay", netip.AddrPortFrom(netip.MustParseAddr("::ffff:127.0.0.1"), port), overlayOf("192.0.2.0/24"), false, []string{"udp4", "tcp4"}},
		{"a zoned link-local nameserver", netip.MustParseAddrPort("[fe80::53%1]:53"), overlayOf("3fff::/20"), true, []string{"udp6", "tcp6"}},
		{"an IPv4 nameserver inside the overlay", netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port), overlayOf("127.0.0.0/8"), false, nil},
		{"an IPv4-mapped nameserver inside the overlay", netip.AddrPortFrom(netip.MustParseAddr("::ffff:127.0.0.1"), port), overlayOf("127.0.0.0/8"), false, nil},
	} {
		var seen []string
		prepare := func(network string, to netip.AddrPort, _ syscall.RawConn) error {
			if to != test.nameserver {
				t.Errorf("a query to %s readied a socket toward %s", test.nameserver, to)
			}
			seen = append(seen, network)
			if test.refused {
				return errRefusedByTheTest
			}
			return nil
		}
		resolver := resolverFor(test.overlay, prepare)
		if !resolver.PreferGo || resolver.Dial == nil {
			t.Fatalf("the resolver prefers go %t with a dial %t, want Go's own resolver dialing through the prepare", resolver.PreferGo, resolver.Dial != nil)
		}
		for _, network := range []string{"udp", "tcp"} {
			ctx, cancel := context.WithTimeout(context.Background(), dialWait)
			conn, err := resolver.Dial(ctx, network, test.nameserver.String())
			cancel()
			if err == nil {
				_ = conn.Close()
			}
			switch {
			case test.refused && !errors.Is(err, errRefusedByTheTest):
				t.Errorf("%s: dial %s answered %v, want %v", test.name, network, err, errRefusedByTheTest)
			case !test.refused && err != nil:
				t.Errorf("%s: dial %s: %v", test.name, network, err)
			}
		}
		if !slices.Equal(seen, test.want) {
			t.Errorf("the queries to %s readied %v, want %v", test.name, seen, test.want)
		}
	}
}

// A query to a nameserver outside the overlay whose socket the Prepare refuses
// fails with the Prepare's error, its datagram and its fallback over TCP alike,
// and the TCP one connects nothing
func TestResolverFailsAQueryItsPrepareRefuses(t *testing.T) {
	loopbackReady(t)
	listener := listenTCP(t, "127.0.0.1:0")
	nameserver := listener.Addr().String()
	resolver := resolverFor(overlayOf("192.0.2.0/24"), func(string, netip.AddrPort, syscall.RawConn) error { return errRefusedByTheTest })
	for _, network := range []string{"udp", "tcp"} {
		conn, err := resolver.Dial(context.Background(), network, nameserver)
		if err == nil {
			_ = conn.Close()
			t.Errorf("a %s query to %s its prepare refused was dialed", network, nameserver)
			continue
		}
		if !errors.Is(err, errRefusedByTheTest) {
			t.Errorf("a %s query to %s its prepare refused failed with %v, want %v", network, nameserver, err, errRefusedByTheTest)
		}
	}
	if err := listener.(*net.TCPListener).SetDeadline(time.Now().Add(acceptWait)); err != nil {
		t.Fatal(err)
	}
	if conn, err := listener.Accept(); err == nil {
		_ = conn.Close()
		t.Errorf("a refused query connected to %s", nameserver)
	}
}

func overlayOf(prefixes ...string) []schema.Prefix {
	var out []schema.Prefix
	for _, prefix := range prefixes {
		out = append(out, schema.PrefixFrom(netip.MustParsePrefix(prefix)))
	}
	return out
}

func listenTCP(t *testing.T, address string) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}
