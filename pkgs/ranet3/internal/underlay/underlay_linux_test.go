// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package underlay

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

// markOf reads back the mark a socket prepare readied carries
func markOf(t *testing.T, network string, prepare Prepare) uint32 {
	t.Helper()
	to := netip.MustParseAddrPort("127.0.0.1:9")
	if network == "udp6" {
		to = netip.MustParseAddrPort("[::1]:9")
	}
	var got int
	var readErr error
	// a socket that binds alone needs no route, which a fresh namespace's loopback, held down, would not give
	config := net.ListenConfig{Control: func(network, _ string, raw syscall.RawConn) error {
		if err := prepare(network, to, raw); err != nil {
			return err
		}
		return raw.Control(func(fd uintptr) { got, readErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK) })
	}}
	conn, err := config.ListenPacket(context.Background(), network, ":0")
	if err != nil {
		t.Fatalf("open a %s socket: %v", network, err)
	}
	_ = conn.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	return uint32(got)
}

// Marked's sockets carry the underlay's mark wherever the process may set one, root among them, and none where it may not
// SO_MARK needs CAP_NET_ADMIN or CAP_NET_RAW, which the sandbox does not grant and the root tests' namespace does, so both outcomes are asserted rather than one skipped
// Unchanged's sockets carry none either way
func TestMarkedSetsTheUnderlayMarkWhereTheProcessMaySetOne(t *testing.T) {
	want := schema.UnderlayMark
	if Mark() == 0 {
		if os.Geteuid() == 0 {
			t.Fatal("root could not set the underlay's mark")
		}
		want = 0
	} else if Mark() != schema.UnderlayMark {
		t.Fatalf("Mark is %#x, want %#x or none", Mark(), schema.UnderlayMark)
	}
	for _, network := range []string{"udp4", "udp6"} {
		if got := markOf(t, network, Marked()); got != want {
			t.Errorf("a %s socket Marked readied carries mark %#x, want %#x", network, got, want)
		}
		if got := markOf(t, network, Unchanged); got != 0 {
			t.Errorf("a %s socket Unchanged readied carries mark %#x, want none", network, got)
		}
	}
}
