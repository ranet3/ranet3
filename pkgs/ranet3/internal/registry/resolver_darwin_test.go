// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package registry

import (
	"context"
	"net"
	"net/netip"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/underlay"
)

// A query's fallback over TCP to a nameserver outside the overlay is scoped to
// the interface underlay.Bound asks the selection for, with IP_BOUND_IF toward
// an IPv4 nameserver and IPV6_BOUND_IF toward an IPv6 one, read back
func TestResolverScopesAQueryOverTCPToTheSelectedInterface(t *testing.T) {
	loopback, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Fatal(err)
	}
	resolver := resolverFor(overlayOf("192.0.2.0/24", "3fff::/20"), underlay.Bound(func(netip.Addr) (int, uint64) { return loopback.Index, 1 }))
	for _, test := range []struct {
		listener      string
		level, option int
	}{
		{"127.0.0.1:0", unix.IPPROTO_IP, unix.IP_BOUND_IF},
		{"[::1]:0", unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF},
	} {
		nameserver := listenTCP(t, test.listener).Addr().String()
		conn, err := resolver.Dial(context.Background(), "tcp", nameserver)
		if err != nil {
			t.Fatalf("dial tcp %s: %v", nameserver, err)
		}
		raw, err := conn.(syscall.Conn).SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var got int
		var readErr error
		if err := raw.Control(func(fd uintptr) { got, readErr = unix.GetsockoptInt(int(fd), test.level, test.option) }); err != nil || readErr != nil {
			t.Fatalf("read the scope of the tcp socket to %s: %v %v", nameserver, err, readErr)
		}
		_ = conn.Close()
		if got != loopback.Index {
			t.Errorf("the tcp socket to %s is scoped to %d, want lo0's %d", nameserver, got, loopback.Index)
		}
	}
}

// loopbackReady does nothing, since lo0 is always up
func loopbackReady(*testing.T) {}
