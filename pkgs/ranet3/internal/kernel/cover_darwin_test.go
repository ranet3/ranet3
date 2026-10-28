// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package kernel

import (
	"net"
	"net/netip"
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

// coverRig is a test utun with a reconciler on it under link.underlay.bind, a
// live session, and the host's defaults of both families to fall back on,
// which the underlay's selection on the tun reports.
type coverRig struct {
	meshIndex int
	tun       int
	host4     int
	device4   string
	host6     int
	table     *netstack.RouteTable
	reconcile *Reconciler
}

// coverRigOptions name what one root test changes about the rig.
type coverRigOptions struct {
	endpoints []netip.Addr
}

func newCoverRig(t *testing.T, options coverRigOptions) *coverRig {
	t.Helper()
	mesh, tun := createUTUNWithFD(t)
	setInterfaceUp(t, mesh)
	meshIndex := interfaceIndex(t, mesh)
	host4, _, err := lookupDefault(runningKernel{}, meshIndex, netip.IPv4Unspecified())
	if err != nil {
		t.Skipf("this host has no IPv4 default to fall back on: %v", err)
	}
	device, err := net.InterfaceByIndex(host4)
	if err != nil {
		t.Fatal(err)
	}
	host6 := hostDefault6(t, meshIndex)
	selection, err := OpenSelection(nil, mesh)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = selection.Close() })
	rig := &coverRig{meshIndex: meshIndex, tun: tun, host4: host4, device4: device.Name, host6: host6,
		table: netstack.NewRouteTable()}
	reconciler, err := New(Table{ID: DefaultTable, Proto: DefaultProtocol}, Runtime{
		Interface:     mesh,
		BoundUnderlay: true,
		Sessions:      func() int { return 1 },
		Underlay:      func() []netip.Addr { return options.endpoints },
		Capture:       selection,
	}, rig.table)
	if err != nil {
		t.Fatal(err)
	}
	rig.reconcile = reconciler
	plat := reconciler.plat.(*routePlatform)
	if err := plat.AddAddr(prefix("198.51.100.1/24")); err != nil {
		t.Fatal(err)
	}
	if err := plat.AddAddr(prefix("2001:db8:bb::1/64")); err != nil {
		t.Fatal(err)
	}
	return rig
}

// passByHand closes the reconciler when the test ends, for a test that runs
// its passes itself.
func (rig *coverRig) passByHand(t *testing.T) {
	t.Cleanup(func() { _ = rig.reconcile.withdraw(); _ = rig.reconcile.plat.Close() })
}

// The reconciler puts a plain default in as every member, unscoped though a
// peer's endpoint lies in one, and the host's table holds no default out of
// the tun. Routes reads the members back, a bound socket still reaches the
// endpoint through the host's interface, and the withdrawal takes every
// member out.
func TestDarwinReconcilerInstallsTheCoverAndReadsItBack(t *testing.T) {
	requireNetTest(t)
	endpoint := netip.MustParseAddr("192.0.2.1")
	rig := newCoverRig(t, coverRigOptions{endpoints: []netip.Addr{endpoint}})
	rig.passByHand(t)
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
	if err := boundReach(rig.host4, endpoint); err != nil {
		t.Errorf("a socket bound to %s cannot reach the endpoint %s inside a member: %v", rig.device4, endpoint, err)
	}
	if got := scopedLookup(t, rig.device4, endpoint); got != rig.device4 {
		t.Errorf("the lookup scoped to %s for %s names %q", rig.device4, endpoint, got)
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

// A real 0.0.0.0/1 goes in as the seven members it holds, 1.0.0.0/8 to
// 64.0.0.0/2, unscoped, and a socket scoped to the interface the host's own
// default leaves by still reaches 192.0.2.1, which a mesh 192.0.2.0/24 beside
// it holds: no route of the tun holds the zero address, so the scoped lookup
// falls back on the host's default. Installed whole, 0.0.0.0/1 strands that
// socket (TestDarwinStrandsABoundSocketOnlyThroughTheZeroAddress). The pass
// that takes the route out takes its members out.
func TestDarwinRealZeroRouteGoesInAsItsMembers(t *testing.T) {
	requireNetTest(t)
	rig := newCoverRig(t, coverRigOptions{})
	rig.passByHand(t)
	before := defaultRoutesOnHost(t)
	half, beside := prefix("0.0.0.0/1"), prefix("192.0.2.0/24")
	target := netip.MustParseAddr("192.0.2.1")
	if err := boundReach(rig.host4, target); err != nil {
		t.Skipf("a socket bound to %s cannot reach %s before anything is installed: %v", rig.device4, target, err)
	}
	rig.table.Set(netip.Prefix{}, half, nil)
	rig.table.Set(netip.Prefix{}, beside, nil)
	if err := rig.reconcile.reconcile(); err != nil {
		t.Fatal(err)
	}
	held := heldOn(t, rig.meshIndex)
	if _, ok := held[half]; ok {
		t.Errorf("the host's table holds %s whole out of the tun", half)
	}
	for _, member := range measuredCover4[:7] {
		if scoped, ok := held[prefix(member)]; !ok || scoped {
			t.Errorf("the host's table holds the member %s as found %v scoped %v, want it unscoped", member, ok, scoped)
		}
	}
	if _, ok := held[prefix(measuredCover4[7])]; ok {
		t.Errorf("the host's table holds %s, which %s does not contain", measuredCover4[7], half)
	}
	if scoped, ok := held[beside]; !ok || scoped {
		t.Errorf("the host's table holds %s as found %v scoped %v, want it unscoped", beside, ok, scoped)
	}
	if stats := rig.reconcile.Stats(); stats.Desired != 8 || stats.Installed != 8 || stats.Skipped != 0 {
		t.Errorf("the pass reports %d desired, %d installed and %d skipped, want the 7 members and %s installed", stats.Desired, stats.Installed, stats.Skipped, beside)
	}
	if !reaches(t, rig.tun, target, netip.Addr{}, 0) {
		t.Errorf("an unbound socket's datagram to %s did not follow %s into the tun", target, beside)
	}
	if err := boundReach(rig.host4, target); err != nil {
		t.Errorf("a socket bound to %s lost %s beside the members of %s: %v", rig.device4, target, half, err)
	}
	if got := scopedLookup(t, rig.device4, target); got != rig.device4 {
		t.Errorf("the lookup scoped to %s for %s names %q", rig.device4, target, got)
	}

	rig.table.Remove(netip.Prefix{}, half)
	if err := rig.reconcile.reconcile(); err != nil {
		t.Fatal(err)
	}
	held = heldOn(t, rig.meshIndex)
	for _, member := range measuredCover4 {
		if _, ok := held[prefix(member)]; ok {
			t.Errorf("the member %s is still in the host's table after %s left", member, half)
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
	rig := newCoverRig(t, coverRigOptions{})
	rig.passByHand(t)
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
	rig := newCoverRig(t, coverRigOptions{})
	rig.passByHand(t)
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

// A default from a source is scoped to the tun, out of every unscoped lookup.
// The hold Babel keeps at a retracted default stays out of the tun's table.
func TestDarwinScopedCaptureGoesInScopedAndAHeldDefaultStaysOut(t *testing.T) {
	requireNetTest(t)
	rig := newCoverRig(t, coverRigOptions{})
	rig.passByHand(t)
	rig.table.Set(netip.Prefix{}, prefix("0.0.0.0/0"), netstack.Unreachable)
	rig.table.Set(prefix("2001:db8:bb::/48"), prefix("::/0"), nil)
	if err := rig.reconcile.reconcile(); err != nil {
		t.Fatal(err)
	}
	held := heldOn(t, rig.meshIndex)
	if scoped, ok := held[prefix("::/0")]; !ok || !scoped {
		t.Errorf("the tun's table holds ::/0 as found %v scoped %v, want it scoped", ok, scoped)
	}
	if _, ok := held[prefix("0.0.0.0/0")]; ok {
		t.Error("the tun's table holds the retracted 0.0.0.0/0")
	}
}

// 128.0.0.0/1 and 8000::/1 alone hold no zero address, which leaves a bound
// socket its fallback: both go in unscoped. An unbound socket follows each
// half into the tun, and a socket bound to the host's interface still reaches
// an address inside it by the host's own route.
func TestDarwinUpperHalvesGoInUnscoped(t *testing.T) {
	requireNetTest(t)
	rig := newCoverRig(t, coverRigOptions{})
	rig.passByHand(t)
	before := defaultRoutesOnHost(t)
	halves := []struct {
		destination netip.Prefix
		inside      netip.Addr
		host        int
	}{
		{prefix("128.0.0.0/1"), netip.MustParseAddr("192.0.2.1"), rig.host4},
		{prefix("8000::/1"), netip.MustParseAddr("8000::1"), rig.host6},
	}
	for _, half := range halves {
		rig.table.Set(netip.Prefix{}, half.destination, nil)
	}
	if err := rig.reconcile.reconcile(); err != nil {
		t.Fatal(err)
	}
	held := heldOn(t, rig.meshIndex)
	for _, half := range halves {
		if scoped, ok := held[half.destination]; !ok || scoped {
			t.Errorf("the tun's table holds %s as found %v scoped %v, want it unscoped", half.destination, ok, scoped)
		}
		if !arrivesUnbound(t, rig.tun, half.inside) {
			t.Errorf("an unbound socket's datagram to %s did not follow %s into the tun", half.inside, half.destination)
		}
		device, err := net.InterfaceByIndex(half.host)
		if err != nil {
			t.Fatal(err)
		}
		if err := boundConnect(half.host, half.inside); err != nil {
			t.Errorf("a socket bound to %s lost %s to %s: %v", device.Name, half.inside, half.destination, err)
		}
		if got := scopedLookup(t, device.Name, half.inside); got != device.Name {
			t.Errorf("the lookup scoped to %s for %s names %q", device.Name, half.inside, got)
		}
	}
	if after := defaultRoutesOnHost(t); !sameDefaults(before, after) {
		t.Errorf("the host's default routes changed over the test\nbefore: %v\nafter:  %v", before, after)
	}
}
