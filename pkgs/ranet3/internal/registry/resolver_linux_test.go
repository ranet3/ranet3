// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package registry

import (
	"context"
	"net"
	"net/netip"
	"os"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/schema"
)

// The resolver's sockets to a nameserver outside the overlay, a query's
// datagram and its fallback over TCP alike, carry the underlay's mark wherever
// the process may set one, root among them, and none where it may not. One to a
// nameserver inside the overlay carries none. SO_MARK needs CAP_NET_ADMIN or
// CAP_NET_RAW, which the sandbox does not grant and the root tests' namespace
// does, so both outcomes are asserted rather than one skipped.
func TestResolverSocketsCarryTheUnderlayMark(t *testing.T) {
	outside := schema.UnderlayMark
	if !mayMark(t) {
		if os.Geteuid() == 0 {
			t.Fatal("root could not set the underlay's mark")
		}
		outside = 0
	} else {
		// the root tests' namespace holds lo down
		loopbackUp(t)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	for _, overlay := range []struct {
		name     string
		prefixes []schema.Prefix
		want     uint32
	}{
		{"outside the overlay", overlayOf("192.0.2.0/24"), outside},
		{"with no overlay", nil, outside},
		{"inside the overlay", overlayOf("192.0.2.0/24", "127.0.0.0/8"), 0},
	} {
		for _, network := range []string{"udp", "tcp"} {
			conn, err := resolverFor(overlay.prefixes).Dial(context.Background(), network, listener.Addr().String())
			if err != nil {
				t.Fatalf("dial %s: %v", network, err)
			}
			raw, err := conn.(syscall.Conn).SyscallConn()
			if err != nil {
				t.Fatal(err)
			}
			var got int
			var readErr error
			if err := raw.Control(func(fd uintptr) { got, readErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK) }); err != nil || readErr != nil {
				t.Fatalf("read the mark of the %s socket: %v %v", network, err, readErr)
			}
			_ = conn.Close()
			if uint32(got) != overlay.want {
				t.Errorf("the resolver's %s socket to a nameserver %s carries mark %#x, want %#x", network, overlay.name, got, overlay.want)
			}
		}
	}
}

// A query to a nameserver lying in some prefix of the overlay is unmarked, in
// either family, in IPv4's mapped form and with a zone, which resolv.conf may
// write after any IPv6 address, and every other one is marked, a link-local one
// among them
func TestResolverMarksAQueryOnlyOutsideTheOverlay(t *testing.T) {
	overlay := overlayOf("192.0.2.0/24", "3fff::/20")
	for _, test := range []struct {
		nameserver string
		want       bool
	}{
		{"192.0.2.53", false},
		{"::ffff:192.0.2.53", false},
		{"::ffff:192.0.2.53%eth0", false},
		{"3fff:0:1::53", false},
		{"3fff:0:1::53%eth0", false},
		{"3fff:0:1::53%1", false},
		{"198.51.100.53", true},
		{"::ffff:198.51.100.53", true},
		{"::ffff:198.51.100.53%eth0", true},
		{"2001:db8::53", true},
		{"2001:db8::53%eth0", true},
		{"fe80::53%eth0", true},
		{"127.0.0.53", true},
	} {
		if got := marksQueryTo(netip.MustParseAddr(test.nameserver), overlay); got != test.want {
			t.Errorf("a query to %s is marked %v, want %v", test.nameserver, got, test.want)
		}
	}
	if !marksQueryTo(netip.MustParseAddr("192.0.2.53"), nil) {
		t.Error("a query with no overlay is left unmarked")
	}
}

func overlayOf(prefixes ...string) []schema.Prefix {
	var out []schema.Prefix
	for _, prefix := range prefixes {
		out = append(out, schema.PrefixFrom(netip.MustParsePrefix(prefix)))
	}
	return out
}

// mayMark is whether this process may set a socket's mark
func mayMark(t *testing.T) bool {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	return unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, 1) == nil
}

// loopbackUp brings lo up, which a namespace unshare made holds down
func loopbackUp(t *testing.T) {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		t.Fatal(err)
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr); err != nil {
		t.Fatal(err)
	}
}
