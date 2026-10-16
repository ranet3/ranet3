// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package kernel

import (
	"context"
	"net"
	"net/netip"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/schema"
)

const (
	// coverWakeBound is the settle plus one pass, with room for a loaded
	// machine, inside which a change of another program's routes is acted on
	coverWakeBound = 2 * time.Second
	// coverSweep is a sweep long enough that nothing in a test waits for it
	coverSweep = 10 * time.Minute
	// coverBurstPasses is the most passes a burst of unrelated route changes
	// within a second may cost
	coverBurstPasses = 6
	// coverBurst is how many adds and deletes the burst makes
	coverBurst = 20
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
// live session, the host's defaults of both families to fall back on, and the
// underlay socket's interface prepared the way the transport prepares it.
type coverRig struct {
	meshIndex int
	tun       int
	host4     int
	device4   string
	host6     int
	table     *netstack.RouteTable
	reconcile *Reconciler
	underlay  *UnderlayDefaults
	// passes counts the reconcile passes, each of which asks for the
	// sessions once
	passes atomic.Int32
}

// coverRigOptions name what one root test changes about the rig.
type coverRigOptions struct {
	endpoints []netip.Addr
	// reconcile is the sweep interval, zero for the default
	reconcile time.Duration
	// links answers where the host's defaults leave, nil for the real ones
	links func(*Links) defaultRoutes
}

func newCoverRig(t *testing.T, options coverRigOptions) *coverRig {
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
	device, err := net.InterfaceByIndex(host4)
	if err != nil {
		t.Fatal(err)
	}
	startWithNoScopedDefault(t, host4)
	host6 := hostDefault6(t, meshIndex)
	var answers defaultRoutes = links
	if options.links != nil {
		answers = options.links(links)
	}
	underlay, err := NewUnderlayDefaults(nil, answers, meshIndex, filepath.Join(t.TempDir(), "underlay.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = underlay.Close() })
	if err := underlay.Prepare(host4); err != nil {
		t.Fatal(err)
	}
	rig := &coverRig{meshIndex: meshIndex, tun: tun, host4: host4, device4: device.Name, host6: host6,
		table: netstack.NewRouteTable(), underlay: underlay}
	reconciler, err := New(Table{ID: DefaultTable, Proto: DefaultProtocol, Reconcile: schema.Duration(options.reconcile)}, Runtime{
		Interface:     mesh,
		BoundUnderlay: true,
		Sessions:      func() int { rig.passes.Add(1); return 1 },
		Underlay:      func() []netip.Addr { return options.endpoints },
		Capture:       underlay,
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

// run starts the reconcile loop, which withdraws and closes when the test
// ends.
func (rig *coverRig) run(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = rig.reconcile.Run(ctx)
	}()
	t.Cleanup(func() { cancel(); <-done })
}

// The reconciler puts a plain default in as every member, unscoped though a
// peer's endpoint lies in one, and the host's table holds no default out of
// the tun and nothing scoped to the underlay's interface. Routes reads the
// members back, a bound socket still reaches the endpoint through the host's
// interface, and the withdrawal takes every member out.
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
	for _, is4 := range []bool{true, false} {
		if scopedDefaultOn(t, rig.host4, is4) {
			t.Errorf("the cover alone left a default scoped to %s (IPv4 %v)", rig.device4, is4)
		}
	}
	if written := rig.underlay.Written(); len(written) != 0 {
		t.Errorf("the cover alone wrote %+v outside the tun", written)
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

// A route of the reconciler's over the zero address, a real 0.0.0.0/1, draws
// the default scoped to the underlay's interface, a bound socket reaches
// through it, and the pass that takes the route out withdraws it.
func TestDarwinOwnCaptureDrawsTheScopedDefaultUntilItGoes(t *testing.T) {
	requireNetTest(t)
	rig := newCoverRig(t, coverRigOptions{})
	rig.passByHand(t)
	before := defaultRoutesOnHost(t)
	half := prefix("0.0.0.0/1")
	rig.table.Set(netip.Prefix{}, half, nil)
	if err := rig.reconcile.reconcile(); err != nil {
		t.Fatal(err)
	}
	if scoped, ok := heldOn(t, rig.meshIndex)[half]; !ok || scoped {
		t.Fatalf("%s is in the tun's table as found %v scoped %v, want it unscoped", half, ok, scoped)
	}
	if !scopedDefaultOn(t, rig.host4, true) {
		t.Errorf("a real %s left %s with no default scoped to it", half, rig.device4)
	}
	if err := boundReach(rig.host4, netip.MustParseAddr("1.2.3.4")); err != nil {
		t.Errorf("a socket bound to %s lost 1.2.3.4 to %s: %v", rig.device4, half, err)
	}
	if scopedDefaultOn(t, rig.host4, false) {
		t.Errorf("an IPv4 capture left an IPv6 default scoped to %s", rig.device4)
	}

	rig.table.Remove(netip.Prefix{}, half)
	if err := rig.reconcile.reconcile(); err != nil {
		t.Fatal(err)
	}
	if scopedDefaultOn(t, rig.host4, true) {
		t.Errorf("the pass that took %s out left the default scoped to %s", half, rig.device4)
	}
	if written := rig.underlay.Written(); len(written) != 0 {
		t.Errorf("the pass that took %s out left %+v written", half, written)
	}
	if after := defaultRoutesOnHost(t); !sameDefaults(before, after) {
		t.Errorf("the host's default routes changed over the test\nbefore: %v\nafter:  %v", before, after)
	}
}

// movingLinks answers the host's IPv4 default as the test moves it, and
// everything else as the host does.
type movingLinks struct {
	*Links
	index   atomic.Int32
	gateway netip.Addr
}

func (m *movingLinks) Default(family netip.Addr) (int, netip.Addr, error) {
	if index := int(m.index.Load()); index != 0 && family.Is4() {
		return index, m.gateway, nil
	}
	return m.Links.Default(family)
}

// A move while the scoped default is needed writes it on the interface moved
// to before the socket goes there, and the settle after the move withdraws
// the one left behind.
func TestDarwinMoveCarriesTheScopedDefault(t *testing.T) {
	requireNetTest(t)
	moving := &movingLinks{gateway: netip.MustParseAddr("203.0.113.254")}
	rig := newCoverRig(t, coverRigOptions{links: func(links *Links) defaultRoutes { moving.Links = links; return moving }})
	rig.passByHand(t)
	dock, _ := createUTUNWithFD(t)
	setInterfaceUp(t, dock)
	if err := testTUNPlatform(t, dock).AddAddr(prefix("203.0.113.1/24")); err != nil {
		t.Fatal(err)
	}
	dockIndex := interfaceIndex(t, dock)

	rig.table.Set(netip.Prefix{}, prefix("0.0.0.0/1"), nil)
	if err := rig.reconcile.reconcile(); err != nil {
		t.Fatal(err)
	}
	if !scopedDefaultOn(t, rig.host4, true) {
		t.Fatalf("the capture left %s with no default scoped to it", rig.device4)
	}
	moving.index.Store(int32(dockIndex))
	if err := rig.underlay.Prepare(dockIndex); err != nil {
		t.Skipf("this kernel takes no scoped default through %s: %v", dock, err)
	}
	if !scopedDefaultOn(t, dockIndex, true) {
		t.Fatalf("the move left %s with no default scoped to it", dock)
	}
	if err := rig.underlay.Settle(dockIndex); err != nil {
		t.Fatal(err)
	}
	if scopedDefaultOn(t, rig.host4, true) {
		t.Errorf("the settle after the move left the default scoped to %s", rig.device4)
	}
	moving.index.Store(0)
	if err := rig.underlay.Prepare(rig.host4); err != nil {
		t.Fatal(err)
	}
	if err := rig.underlay.Settle(rig.host4); err != nil {
		t.Fatal(err)
	}
}

// routeCommand changes the table from another process, the way another
// program does, so the watcher does not take it for this process's own write.
func routeCommand(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("route", append([]string{"-n"}, args...)...).CombinedOutput(); err != nil {
		t.Fatalf("route %v: %v %s", args, err, out)
	}
}

// within polls until ok holds, and reports how long that took.
func within(t *testing.T, bound time.Duration, ok func() bool) (time.Duration, bool) {
	t.Helper()
	started := time.Now()
	for time.Since(started) < bound {
		if ok() {
			return time.Since(started), true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return time.Since(started), ok()
}

// Another program's route over a zero address, a full-tunnel VPN's 0.0.0.0/1
// on its own utun, draws the default scoped to the underlay's interface
// within the settle and one pass, with the sweep far away, and its removal
// withdraws it as fast. A route holding no zero address draws nothing, and a
// burst of unrelated changes costs a few passes.
func TestDarwinAnotherProgramsCaptureDrawsTheScopedDefaultWithinAPass(t *testing.T) {
	requireNetTest(t)
	rig := newCoverRig(t, coverRigOptions{reconcile: coverSweep})
	other, _ := createUTUNWithFD(t)
	setInterfaceUp(t, other)
	if err := testTUNPlatform(t, other).AddAddr(prefix("192.0.2.1/24")); err != nil {
		t.Fatal(err)
	}
	if err := testTUNPlatform(t, other).AddAddr(prefix("2001:db8:cc::1/64")); err != nil {
		t.Fatal(err)
	}
	rig.run(t)
	if _, ok := within(t, coverWakeBound, func() bool { return rig.passes.Load() > 0 }); !ok {
		t.Fatal("the reconciler ran no first pass")
	}
	// the IPv6 default is scoped only where the host's own leaves by the
	// same interface through a next hop, which a stand-in uplink has not
	index6, gateway6, err6 := rig.underlay.links.Default(netip.IPv6Unspecified())
	v6 := err6 == nil && gateway6.IsValid() && index6 == rig.host4

	routeCommand(t, "add", "-net", "0.0.0.0/1", "-interface", other)
	routeCommand(t, "add", "-inet6", "-net", "::/1", "-interface", other)
	took, ok := within(t, coverWakeBound, func() bool {
		return scopedDefaultOn(t, rig.host4, true) && (!v6 || scopedDefaultOn(t, rig.host4, false))
	})
	t.Logf("another program's capture drew the scoped default in %s (IPv6 checked %v)", took, v6)
	if !ok {
		t.Errorf("another program's 0.0.0.0/1 left %s with no default scoped to it after %s", rig.device4, took)
	}
	routeCommand(t, "delete", "-net", "0.0.0.0/1", "-interface", other)
	routeCommand(t, "delete", "-inet6", "-net", "::/1", "-interface", other)
	took, ok = within(t, coverWakeBound, func() bool {
		return !scopedDefaultOn(t, rig.host4, true) && !scopedDefaultOn(t, rig.host4, false)
	})
	t.Logf("its removal withdrew the scoped default in %s", took)
	if !ok {
		t.Errorf("the default scoped to %s outlived another program's capture by %s", rig.device4, took)
	}

	routeCommand(t, "add", "-net", "1.0.0.0/8", "-interface", other)
	passes := rig.passes.Load()
	if _, ok := within(t, coverWakeBound, func() bool { return rig.passes.Load() > passes }); !ok {
		t.Error("another program's route woke no pass")
	}
	if scopedDefaultOn(t, rig.host4, true) || len(rig.underlay.Written()) != 0 {
		t.Errorf("a route holding no zero address drew %+v", rig.underlay.Written())
	}
	routeCommand(t, "delete", "-net", "1.0.0.0/8", "-interface", other)
	time.Sleep(coverWakeBound)

	passes = rig.passes.Load()
	for range coverBurst {
		routeCommand(t, "add", "-host", "192.0.2.77", "-interface", other)
		routeCommand(t, "delete", "-host", "192.0.2.77", "-interface", other)
	}
	time.Sleep(coverWakeBound)
	cost := rig.passes.Load() - passes
	t.Logf("%d adds and deletes of a host route cost %d passes", 2*coverBurst, cost)
	if cost > coverBurstPasses {
		t.Errorf("%d unrelated route changes cost %d passes, want at most %d", 2*coverBurst, cost, coverBurstPasses)
	}
}

// The hold Babel keeps at a retracted default and a default from a source are
// scoped to the tun, out of every unscoped lookup, so both go in and neither
// draws a default scoped to the underlay's interface.
func TestDarwinScopedCaptureDrawsNoScopedDefault(t *testing.T) {
	requireNetTest(t)
	rig := newCoverRig(t, coverRigOptions{})
	rig.passByHand(t)
	rig.table.Set(netip.Prefix{}, prefix("0.0.0.0/0"), netstack.Unreachable)
	rig.table.Set(prefix("2001:db8:bb::/48"), prefix("::/0"), nil)
	if err := rig.reconcile.reconcile(); err != nil {
		t.Fatal(err)
	}
	held := heldOn(t, rig.meshIndex)
	for _, destination := range []netip.Prefix{prefix("0.0.0.0/0"), prefix("::/0")} {
		if scoped, ok := held[destination]; !ok || !scoped {
			t.Errorf("the tun's table holds %s as found %v scoped %v, want it scoped", destination, ok, scoped)
		}
	}
	for _, is4 := range []bool{true, false} {
		if scopedDefaultOn(t, rig.host4, is4) {
			t.Errorf("a scoped capture left a default scoped to %s (IPv4 %v)", rig.device4, is4)
		}
	}
	if written := rig.underlay.Written(); len(written) != 0 {
		t.Errorf("a scoped capture wrote %+v outside the tun", written)
	}
}

// 128.0.0.0/1 and 8000::/1 alone hold no zero address, which leaves a bound
// socket its fallback: both go in unscoped and nothing is written outside the
// tun. An unbound socket follows each half into the tun, and a socket bound to
// the host's interface still reaches an address inside it by the host's own
// route.
func TestDarwinUpperHalvesDrawNoScopedDefault(t *testing.T) {
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
	for _, is4 := range []bool{true, false} {
		if scopedDefaultOn(t, rig.host4, is4) {
			t.Errorf("an upper half left a default scoped to %s (IPv4 %v)", rig.device4, is4)
		}
	}
	if written := rig.underlay.Written(); len(written) != 0 {
		t.Errorf("the upper halves wrote %+v outside the tun", written)
	}
	if after := defaultRoutesOnHost(t); !sameDefaults(before, after) {
		t.Errorf("the host's default routes changed over the test\nbefore: %v\nafter:  %v", before, after)
	}
}
