// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package client

import (
	"context"
	"net"
	"net/netip"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// The prepare a daemon readies its endpoint queries with, the one
// TestEndpointQueryTakesTheNodesPrepare shows a dial hands the resolver, scopes
// a socket dialed with it toward a nameserver's port 53 to the interface the
// daemon's selection answers for the nameserver, the recorded host's uplink on
// lo0 here, with IP_BOUND_IF or IPV6_BOUND_IF, read back
func TestDaemonPrepareScopesANameserverSocketToTheSelectedInterface(t *testing.T) {
	d := startDaemon(t, false, recordedHost(t))
	for _, test := range []struct {
		nameserver string
		ipv6       bool
	}{
		{"127.0.0.1:53", false},
		{"[::ffff:127.0.0.1]:53", false},
		{"[::1]:53", true},
	} {
		dialer := net.Dialer{Control: func(network, _ string, raw syscall.RawConn) error {
			return d.node.prepare(network, netip.MustParseAddrPort(test.nameserver), raw)
		}}
		conn, err := dialer.DialContext(context.Background(), "udp", test.nameserver)
		if err != nil {
			t.Fatalf("dial %s: %v", test.nameserver, err)
		}
		raw, err := conn.(syscall.Conn).SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		level, option := unix.IPPROTO_IP, unix.IP_BOUND_IF
		if test.ipv6 {
			level, option = unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF
		}
		var got int
		var readErr error
		if err := raw.Control(func(fd uintptr) { got, readErr = unix.GetsockoptInt(int(fd), level, option) }); err != nil || readErr != nil {
			t.Fatalf("read the scope of the socket to %s: %v %v", test.nameserver, err, readErr)
		}
		_ = conn.Close()
		if got != d.uplink {
			t.Errorf("the socket to %s is scoped to %d, want the uplink %d", test.nameserver, got, d.uplink)
		}
	}
}
