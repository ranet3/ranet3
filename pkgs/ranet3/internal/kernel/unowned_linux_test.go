// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"net/netip"
	"os"
	"slices"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/netnstest"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/schema"
)

// linkLocalWait bounds the wait for the link-local address the kernel puts on
// a tun that came up, and linkLocalPoll is the time between two listings in it
const (
	linkLocalWait = 5 * time.Second
	linkLocalPoll = 10 * time.Millisecond
)

// Passes on a real tun leave an address another writer put there under a
// shorter length, at a host the file assigns and at one it does not name, with
// the connected route the kernel made for it, and warn once of each where that
// network holds an address outside the overlay under a none class, but not of
// the link-local address the kernel put there under a none class covering it
func TestUnownedAddressOnRealTunIsWarnedOnceAndLeft(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("a real tun needs root on linux")
	}
	netnstest.EnterEmpty(t)

	conn, err := dialNetlink()
	if err != nil {
		t.Fatalf("dial rtnetlink: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	const device = "ranettest0"
	createTUN(t, device)
	tun, err := conn.link(0, device)
	if err != nil {
		t.Fatalf("look up %s: %v", device, err)
	}
	setLinkFlags(t, conn, tun.index, unix.IFF_UP)

	tbl, rt := platformFor(device)
	tbl.Addresses = prefixes(prefix("198.51.100.1/32"), prefix("2001:db8::1/128"))
	tbl = tbl.Normalized()
	rt.Overlay = []schema.Prefix{schema.PrefixFrom(prefix("198.51.100.0/25")), schema.PrefixFrom(prefix("2001:db8::/64"))}
	none := egress.Translation{None: true}
	rt.Classes = []egress.Class{{From: schema.PrefixFrom(prefix("198.51.100.128/25")), To: none}, {From: schema.PrefixFrom(prefix("::/0")), To: none}}
	opened, err := newPlatform(tbl, rt)
	if err != nil {
		t.Fatalf("open the netlink platform: %v", err)
	}
	t.Cleanup(func() { _ = opened.Close() })

	var linkLocal netip.Prefix
	for deadline := time.Now().Add(linkLocalWait); !linkLocal.IsValid() && time.Now().Before(deadline); time.Sleep(linkLocalPoll) {
		listed, err := opened.Addrs()
		if err != nil {
			t.Fatalf("list addresses: %v", err)
		}
		if at := slices.IndexFunc(listed, func(p netip.Prefix) bool { return p.Addr().IsLinkLocalUnicast() }); at >= 0 {
			linkLocal = listed[at]
		}
	}
	if !linkLocal.IsValid() {
		t.Fatalf("the kernel put no link-local address on %s within %s", device, linkLocalWait)
	}

	unowned := []struct {
		held   netip.Prefix
		beyond netip.Addr
	}{
		{prefix("198.51.100.1/24"), addr("198.51.100.200")},
		{prefix("2001:db8::99/63"), addr("2001:db8:0:1::9")},
	}
	for _, address := range unowned {
		if err := opened.AddAddr(address.held); err != nil {
			t.Fatalf("assign %s as another writer: %v", address.held, err)
		}
	}
	logs := captureKernelLogs(t)
	r := newReconciler(tbl, rt, tbl.Assigned(nil), netstack.NewRouteTable(), opened)
	for pass := range 2 {
		if err := r.reconcile(); err != nil {
			t.Fatalf("pass %d: %v", pass, err)
		}
	}

	warned := unownedWarnings(t, logs)
	if len(warned[linkLocal]) != 0 {
		t.Errorf("the kernel's own %s was warned of: %s", linkLocal, logs)
	}
	held, err := opened.Addrs()
	if err != nil {
		t.Fatalf("list addresses: %v", err)
	}
	for _, address := range unowned {
		if len(warned[address.held]) != 1 {
			t.Errorf("%s was warned of %d times over two passes, want once: %s", address.held, len(warned[address.held]), logs)
		}
		if !slices.Contains(held, address.held) {
			t.Errorf("%s is gone from the tun, which holds %v", address.held, held)
		}
		route, err := RouteGet(netip.Addr{}, address.beyond, "")
		if err != nil || route.Table != unix.RT_TABLE_MAIN || route.Prefix != address.held.Masked() || len(route.NextHops) != 1 || route.NextHops[0].Device != device {
			t.Errorf("the lookup of %s answered %+v (err %v), want the connected route %s by %s", address.beyond, route, err, address.held.Masked(), device)
		}
	}
}
