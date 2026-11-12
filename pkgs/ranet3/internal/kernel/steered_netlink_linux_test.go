// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"net/netip"
	"os"
	"slices"
	"testing"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/netnstest"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/schema"
)

// Mode 3 against a real kernel: a pass installs 0.0.0.0/0 and ::/0 out of the
// tun once every SID of via resolves, withdraws both when the exit's SID is
// retracted or the waypoint's goes, installs them again when it comes back,
// and never installs another exit's routes that count
func TestNetlinkSteeredDefaultsComeAndGoWithTheSegments(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("the real netlink path needs root on linux")
	}
	netnstest.EnterEmpty(t)
	conn, err := dialNetlink()
	if err != nil {
		t.Fatalf("dial rtnetlink: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	const device = "ranetpath0"
	createTUN(t, device)
	tun, err := conn.link(0, device)
	if err != nil {
		t.Fatal(err)
	}
	setLinkFlags(t, conn, tun.index, unix.IFF_UP)

	mesh := netstack.NewRouteTable()
	for _, entry := range learnedDefaults() {
		mesh.Set(entry.source, entry.destination, entry.value)
	}
	r, err := New(modeThree(waypointSID, exitSID), Runtime{Interface: device, Overlay: steeredOverlay, Sessions: func() int { return 1 }}, mesh)
	if err != nil {
		t.Fatalf("start the reconciler: %v", err)
	}
	t.Cleanup(func() { _ = r.plat.Close() })
	plat := r.plat.(*netlinkPlatform)
	pass := func(step string, want []Route) {
		t.Helper()
		if err := r.reconcile(); err != nil {
			t.Fatalf("%s: %v", step, err)
		}
		routes, err := plat.Routes()
		if err != nil {
			t.Fatalf("%s: list routes: %v", step, err)
		}
		counted := slices.DeleteFunc(routes, func(route Route) bool { return !schema.CapturesTheMachine(route.Destination, steeredOverlay) })
		// a dump of a family this kernel lacks answers with the other one's entries, so it is read as a set
		if got := slices.Compact(slices.SortedFunc(slices.Values(counted), compareRoutes)); !slices.Equal(got, want) {
			t.Errorf("%s: the table holds %v of the routes that count, want %v", step, got, want)
		}
	}
	waypoint, exit := netip.PrefixFrom(waypointSID, 128), netip.PrefixFrom(exitSID, 128)

	pass("no segment routed, another exit's routes learned", nil)
	mesh.Set(netip.Prefix{}, waypoint, learned)
	mesh.Set(netip.Prefix{}, exit, learned)
	pass("both segments routed", steered())
	mesh.Set(netip.Prefix{}, exit, netstack.Unreachable)
	pass("the exit's segment retracted and held", nil)
	mesh.Remove(netip.Prefix{}, exit)
	pass("the exit's hold flushed", nil)
	mesh.Set(netip.Prefix{}, exit, learned)
	pass("the exit's segment back", steered())
	mesh.Remove(netip.Prefix{}, waypoint)
	pass("the waypoint's segment gone", nil)
	mesh.Set(netip.Prefix{}, waypoint, learned)
	pass("the waypoint's segment back", steered())

	if err := r.withdraw(nil); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if routes, _ := plat.Routes(); len(routes) != 0 {
		t.Errorf("the withdrawal left %v in the table", routes)
	}
}
