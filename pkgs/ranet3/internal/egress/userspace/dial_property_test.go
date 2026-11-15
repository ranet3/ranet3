// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package userspace

import (
	"context"
	"net/netip"
	"os"
	"runtime"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// for any sequence of dials, each readying a new socket through the dial's
// Control for each connect that failed with EADDRNOTAVAIL, as Go does up to
// twice, and ending in a connection, a refusal, a cancellation or a third
// EADDRNOTAVAIL, the process holds, once each dial's error queue is read and
// closed, the descriptors of the connections left open and no other
func TestDialHoldsNoDescriptorPastItsConnections(t *testing.T) {
	x := dialingExit(t, egress.Egress{}, func(string, netip.AddrPort, syscall.RawConn) error { return nil })
	r := &tcpRelay{x: x}
	server := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 80)
	unbound := func(int) error { return nil }
	pbt.Check(t, func(ht *hegel.T) {
		var open []*os.File
		defer func() {
			for _, socket := range open {
				_ = socket.Close()
			}
		}()
		before := openFiles(ht)
		for range hegel.Draw(ht, hegel.Integers(1, 3)) {
			notAvailable := hegel.Draw(ht, hegel.Integers(0, 3))
			end := []error{nil, syscall.ECONNREFUSED, context.Canceled}[hegel.Draw(ht, hegel.Integers(0, 2))]
			queue := x.icmp.queue()
			control := r.control(server, unbound, &queue)
			var failure error
			for attempt := range min(notAvailable, 2) + 1 {
				socket := streamSocket(ht)
				raw, err := socket.SyscallConn()
				if err != nil {
					ht.Fatal(err)
				}
				if err := control("tcp4", server.String(), raw); err != nil {
					_ = socket.Close()
					ht.Fatalf("the dial's control refused socket %d: %v", attempt, err)
				}
				failure = end
				if attempt < notAvailable {
					failure = syscall.EADDRNOTAVAIL
				}
				if failure == nil {
					open = append(open, socket)
				} else {
					_ = socket.Close()
				}
			}
			queue.read(failure)
			queue.close()
			if held := openFiles(ht) - before; held != len(open) {
				ht.Fatalf("the process holds %d descriptors past its own with %d connections open, want theirs alone", held, len(open))
			}
		}
	})
}

// openFiles is how many descriptors the process holds open
func openFiles(t fataler) int {
	dir := "/dev/fd"
	if runtime.GOOS == "linux" {
		dir = "/proc/self/fd"
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read the process's descriptors: %v", err)
	}
	return len(entries)
}

// streamSocket is a new TCP socket of IPv4, as Go's dial makes for each try
func streamSocket(t fataler) *os.File {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("open a socket: %v", err)
	}
	unix.CloseOnExec(fd)
	return os.NewFile(uintptr(fd), "dial")
}
