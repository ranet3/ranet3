// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"errors"
	"net/netip"
	"os"
	"slices"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/egress"
	meshkernel "ranet3.com/pkgs/ranet3/internal/kernel"
)

// elementListener is a socket on nf_tables' notification group, as nft monitor
// and every other owner's monitor listens
type elementListener struct{ fd int }

func openElementListener(t testing.TB) elementListener {
	t.Helper()
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_NETFILTER)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: 1 << (unix.NFNLGRP_NFTABLES - 1)}); err != nil {
		t.Fatal(err)
	}
	// room for a whole table at 10,000 LANs where the host allows it: SO_RCVBUFFORCE
	// needs CAP_NET_ADMIN in the first user namespace, and SO_RCVBUF stops at net.core.rmem_max
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, 64<<20); err != nil {
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 64<<20); err != nil {
			t.Fatal(err)
		}
	}
	size, _ := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF)
	t.Logf("the listener's receive buffer holds %d bytes", size)
	return elementListener{fd: fd}
}

// elements reads every notification queued, which a transaction's commit
// queues before it acknowledges the batch, and answers the element messages
// among them, and whether the socket overflowed, which leaves the count short
func (l elementListener) elements(t testing.TB) (count int, overflowed bool) {
	t.Helper()
	buf := make([]byte, 1<<17)
	for {
		n, _, err := unix.Recvfrom(l.fd, buf, unix.MSG_DONTWAIT)
		switch {
		case errors.Is(err, unix.EAGAIN):
			return count, overflowed
		case errors.Is(err, unix.ENOBUFS):
			overflowed = true
			continue
		case err != nil:
			t.Fatal(err)
		}
		messages, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range messages {
			if kind := m.Header.Type & 0xff; kind == unix.NFT_MSG_NEWSETELEM || kind == unix.NFT_MSG_DELSETELEM {
				count++
			}
		}
	}
}

// deltaLAN is the /64 LAN of index i in 2001:db8::/32, so LANs of indexes one
// apart touch and two apart do not
func deltaLAN(i int) netip.Prefix {
	raw := netip.MustParseAddr("2001:db8::").As16()
	raw[4], raw[5], raw[6], raw[7] = byte(i>>24), byte(i>>16), byte(i>>8), byte(i)
	return netip.PrefixFrom(netip.AddrFrom16(raw), 64)
}

// A pass that moves none6 by one LAN, at 10, 1,000 and 10,000 LANs held, sends
// every nf_tables listener at most 6 element messages: 2 where the LAN stands
// apart from the others, 4 where it touches the end of one, and 6 where it
// joins two or leaves them apart again, the intervals that go and come each
// whole. Each pass leaves the table read back as written.
func TestBorderPassSendsAOneLANChangeAsItsDelta(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	// one goroutine throughout, since a subtest's would run outside the namespace
	enterThrowawayNamespace(t)
	listener := openElementListener(t)
	for _, n := range []int{10, 1000, 10000} {
		// every other index, so no two LANs touch
		var lans []netip.Prefix
		for i := range n {
			lans = append(lans, deltaLAN(2*i))
		}
		rt := egress.BorderRuntime{Tun: "ranet3", Inside: []string{"ranet3", "lo"}, Sets: func(*egress.Border) egress.BorderSets {
			return egress.BorderSets{None: meshkernel.Ranges(lans)}
		}}
		be, err := newBorderBackend()
		if err != nil {
			t.Fatal(err)
		}
		f, err := startBorderFilter(nil, rt, be)
		if err != nil {
			t.Fatal(err)
		}
		started, overflowed := listener.elements(t)
		t.Logf("%d LANs: the start sent %d element messages, the listener overflowing %v", n, started, overflowed)
		apart, between, past := deltaLAN(2*n+10), deltaLAN(1), deltaLAN(2*n-1)
		for _, step := range []struct {
			what string
			lans []netip.Prefix
		}{
			{"a LAN apart from the others came", append(slices.Clone(lans), apart)},
			{"it went", lans},
			{"a LAN joining two came", append(slices.Clone(lans), between)},
			{"it went, leaving them apart", lans},
			{"a LAN touching the last came", append(slices.Clone(lans), past)},
			{"it went", lans},
		} {
			lans = step.lans
			f.trigger = "routes"
			if err := f.reconcile(); err != nil {
				t.Fatalf("%d LANs, %s: the pass failed: %v", n, step.what, err)
			}
			if !f.ready {
				t.Fatalf("%d LANs, %s: the pass left the table not ready: %s", n, step.what, f.unready)
			}
			sent, overflowed := listener.elements(t)
			t.Logf("%d LANs, %s: %d element messages", n, step.what, sent)
			if sent > 6 || overflowed {
				t.Errorf("%d LANs, %s: the pass sent %d element messages, the listener overflowing %v, want at most 6", n, step.what, sent, overflowed)
			}
		}
		if err := f.finish(); err != nil {
			t.Fatal(err)
		}
		listener.elements(t)
	}
}
