// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package kernel

import (
	"net"
	"net/netip"
	"path/filepath"
	"testing"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/netstack"
)

// heldOn is every prefix the host's table holds out of one interface, with
// whether the kernel scoped it, read from a dump rather than from Routes.
func heldOn(t *testing.T, index int) map[netip.Prefix]bool {
	t.Helper()
	rib, err := route.FetchRIB(unix.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		t.Fatal(err)
	}
	messages, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		t.Fatal(err)
	}
	out := map[netip.Prefix]bool{}
	for _, message := range messages {
		rm, ok := message.(*route.RouteMessage)
		if !ok || rm.Type != unix.RTM_GET || rm.Index != index {
			continue
		}
		if destination, ok := dumpedPrefix(rm); ok {
			out[destination] = rm.Flags&unix.RTF_IFSCOPE != 0
		}
	}
	return out
}

// coverRig is a test utun with a reconciler on it under a bound underlay, a
// live session, and the host's defaults of both families to fall back on.
type coverRig struct {
	meshIndex int
	tun       int
	host4     int
	table     *netstack.RouteTable
	reconcile *Reconciler
}

func newCoverRig(t *testing.T, endpoints ...netip.Addr) *coverRig {
	t.Helper()
	mesh, tun := createUTUNWithFD(t)
	setInterfaceUp(t, mesh)
	meshIndex := interfaceIndex(t, mesh)
	links, err := WatchLinks(nil, meshIndex)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = links.Close() })
	host4, _, err := links.Default(netip.IPv4Unspecified())
	if err != nil {
		t.Skipf("this host has no IPv4 default to fall back on: %v", err)
	}
	hostDefault6(t, meshIndex)
	underlay, err := NewUnderlayDefaults(nil, links, meshIndex, filepath.Join(t.TempDir(), "underlay.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = underlay.Close() })
	table := netstack.NewRouteTable()
	reconciler, err := New(Table{ID: DefaultTable, Proto: DefaultProtocol}, Runtime{
		Interface:     mesh,
		BoundUnderlay: true,
		Sessions:      func() int { return 1 },
		Underlay:      func() []netip.Addr { return endpoints },
		Capture:       underlay,
	}, table)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reconciler.withdraw(); _ = reconciler.plat.Close() })
	plat := reconciler.plat.(*routePlatform)
	if err := plat.AddAddr(prefix("198.51.100.1/24")); err != nil {
		t.Fatal(err)
	}
	if err := plat.AddAddr(prefix("2001:db8:bb::1/64")); err != nil {
		t.Fatal(err)
	}
	return &coverRig{meshIndex: meshIndex, tun: tun, host4: host4, table: table, reconcile: reconciler}
}

// The reconciler puts a plain default in as every member, unscoped though a
// peer's endpoint lies in one, and the host's table holds no default out of
// the tun. Routes reads the members back, a bound socket still reaches the
// endpoint through the host's interface, and the withdrawal takes every
// member out.
func TestDarwinReconcilerInstallsTheCoverAndReadsItBack(t *testing.T) {
	requireNetTest(t)
	endpoint := netip.MustParseAddr("192.0.2.1")
	rig := newCoverRig(t, endpoint)
	before := defaultRoutesOnHost(t)
	rig.table.Set(netip.Prefix{}, prefix("0.0.0.0/0"), nil)
	rig.table.Set(netip.Prefix{}, prefix("::/0"), nil)
	if err := rig.reconcile.reconcile(); err != nil {
		t.Fatal(err)
	}

	routes, err := rig.reconcile.plat.Routes()
	if err != nil {
		t.Fatal(err)
	}
	read := map[netip.Prefix]Route{}
	for _, r := range routes {
		read[r.Destination] = r
	}
	held := heldOn(t, rig.meshIndex)
	for _, family := range []bool{true, false} {
		for _, member := range zeroFreeCover[family] {
			if r, ok := read[member]; !ok || !r.Cover || r.Scoped {
				t.Errorf("Routes reads %s back as %+v (found %v), want an unscoped member", member, r, ok)
			}
			if scoped, ok := held[member]; !ok || scoped {
				t.Errorf("the host's table holds %s as found %v scoped %v, want it unscoped", member, ok, scoped)
			}
		}
	}
	for destination := range held {
		if destination.Bits() == 0 {
			t.Errorf("the host's table holds %s out of the tun", destination)
		}
	}
	if got := rig.reconcile.Stats().Cover; len(got) != 2 {
		t.Errorf("the pass reports the cover %v, want both families", got)
	}

	if !reaches(t, rig.tun, netip.MustParseAddr("203.0.113.9"), netip.Addr{}, 0) {
		t.Error("an unbound socket did not follow the cover into the tun")
	}
	device, err := net.InterfaceByIndex(rig.host4)
	if err != nil {
		t.Fatal(err)
	}
	if err := boundReach(rig.host4, endpoint); err != nil {
		t.Errorf("a socket bound to %s cannot reach the endpoint %s inside a member: %v", device.Name, endpoint, err)
	}
	if got := scopedLookup(t, device.Name, endpoint); got != device.Name {
		t.Errorf("the lookup scoped to %s for %s names %q", device.Name, endpoint, got)
	}

	rig.table.Remove(netip.Prefix{}, prefix("0.0.0.0/0"))
	rig.table.Remove(netip.Prefix{}, prefix("::/0"))
	if err := rig.reconcile.reconcile(); err != nil {
		t.Fatal(err)
	}
	held = heldOn(t, rig.meshIndex)
	for _, family := range []bool{true, false} {
		for _, member := range zeroFreeCover[family] {
			if _, ok := held[member]; ok {
				t.Errorf("%s is still in the host's table after the default left", member)
			}
		}
	}
	if after := defaultRoutesOnHost(t); !sameDefaults(before, after) {
		t.Errorf("the host's default routes changed over the test\nbefore: %v\nafter:  %v", before, after)
	}
}

// A member another program already holds, as a full-tunnel VPN holds
// 128.0.0.0/1 on its own utun, keeps every member of its family out of the
// host's table, so that family's traffic is not split between the mesh and
// that route. The other family's cover goes in, the refusal names the route
// that holds the member, and once that route is gone the family goes in
// whole.
func TestDarwinRefusedMemberKeepsItsWholeFamilyOut(t *testing.T) {
	requireNetTest(t)
	rig := newCoverRig(t)
	other, _ := createUTUNWithFD(t)
	setInterfaceUp(t, other)
	blocker := testTUNPlatform(t, other)
	if err := blocker.AddAddr(prefix("192.0.2.1/24")); err != nil {
		t.Fatal(err)
	}
	upper := Route{Destination: prefix("128.0.0.0/1")}
	if err := blocker.AddRoute(upper); err != nil {
		t.Fatal(err)
	}
	rig.table.Set(netip.Prefix{}, prefix("0.0.0.0/0"), nil)
	rig.table.Set(netip.Prefix{}, prefix("::/0"), nil)
	if err := rig.reconcile.reconcile(); err != nil {
		t.Fatal(err)
	}
	held := heldOn(t, rig.meshIndex)
	for _, member := range zeroFreeCover[true] {
		if _, ok := held[member]; ok {
			t.Errorf("the host's table holds %s out of the tun beside another program's %s", member, upper.Destination)
		}
	}
	for _, member := range zeroFreeCover[false] {
		if _, ok := held[member]; !ok {
			t.Errorf("the IPv6 cover lacks %s, though only an IPv4 member was refused", member)
		}
	}
	if got := rig.reconcile.Stats().Cover; len(got) != 1 || got[0] != FamilyIPv6 {
		t.Errorf("the pass reports the cover %v, want IPv6 alone", got)
	}
	if _, ok := heldOn(t, interfaceIndex(t, other))[upper.Destination]; !ok {
		t.Errorf("another program's %s left the host's table", upper.Destination)
	}
	if got, want := rig.reconcile.plat.(*routePlatform).holder(upper.Destination), upper.Destination.String()+" on "+other; got != want {
		t.Errorf("the refusal names %q as the holder, want %q", got, want)
	}

	if err := blocker.DelRoute(upper); err != nil {
		t.Fatal(err)
	}
	if err := rig.reconcile.reconcile(); err != nil {
		t.Fatal(err)
	}
	held = heldOn(t, rig.meshIndex)
	for _, member := range zeroFreeCover[true] {
		if _, ok := held[member]; !ok {
			t.Errorf("the IPv4 cover lacks %s once the other program's route is gone", member)
		}
	}
}

// A real 128.0.0.0/1 beside the default withholds the member at its own key.
// While another program holds that key on its own utun, as a full-tunnel VPN
// does, the real half is refused and so is the member it hands back, so no
// IPv4 member is left in the host's table beside the other program's route
// and the IPv6 cover goes in whole. Once that route is gone the real half
// goes in, read back as no member, with the rest of the IPv4 cover around it.
func TestDarwinRefusedRouteAtAMemberKeyKeepsItsWholeFamilyOut(t *testing.T) {
	requireNetTest(t)
	rig := newCoverRig(t)
	other, _ := createUTUNWithFD(t)
	setInterfaceUp(t, other)
	blocker := testTUNPlatform(t, other)
	if err := blocker.AddAddr(prefix("192.0.2.1/24")); err != nil {
		t.Fatal(err)
	}
	upper := Route{Destination: prefix("128.0.0.0/1")}
	if err := blocker.AddRoute(upper); err != nil {
		t.Fatal(err)
	}
	for _, destination := range []netip.Prefix{prefix("0.0.0.0/0"), prefix("::/0"), upper.Destination} {
		rig.table.Set(netip.Prefix{}, destination, nil)
	}
	if err := rig.reconcile.reconcile(); err != nil {
		t.Fatal(err)
	}
	held := heldOn(t, rig.meshIndex)
	for _, member := range zeroFreeCover[true] {
		if _, ok := held[member]; ok {
			t.Errorf("the host's table holds %s out of the tun while another program holds %s", member, upper.Destination)
		}
	}
	for _, member := range zeroFreeCover[false] {
		if _, ok := held[member]; !ok {
			t.Errorf("the IPv6 cover lacks %s, though only an IPv4 key is taken", member)
		}
	}
	if got := rig.reconcile.Stats().Cover; len(got) != 1 || got[0] != FamilyIPv6 {
		t.Errorf("the pass reports the cover %v, want IPv6 alone", got)
	}
	if _, ok := heldOn(t, interfaceIndex(t, other))[upper.Destination]; !ok {
		t.Errorf("another program's %s left the host's table", upper.Destination)
	}

	if err := blocker.DelRoute(upper); err != nil {
		t.Fatal(err)
	}
	if err := rig.reconcile.reconcile(); err != nil {
		t.Fatal(err)
	}
	routes, err := rig.reconcile.plat.Routes()
	if err != nil {
		t.Fatal(err)
	}
	read := map[netip.Prefix]Route{}
	for _, r := range routes {
		read[r.Destination] = r
	}
	for _, member := range zeroFreeCover[true] {
		r, ok := read[member]
		switch {
		case member == upper.Destination && (!ok || r.Cover):
			t.Errorf("once the other program's route is gone %s reads back as %+v (found %v), want the real route", member, r, ok)
		case member != upper.Destination && (!ok || !r.Cover):
			t.Errorf("once the other program's route is gone %s reads back as %+v (found %v), want a member", member, r, ok)
		}
	}
}
