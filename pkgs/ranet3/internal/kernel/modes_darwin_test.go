// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package kernel

import (
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/netstack"
)

var (
	// modeHeld is a real route at a member's key holding modeEndpoint, which
	// mode off scopes as counting as a default and the mode puts in unscoped
	// and whole, in place of the member, since the host's own route to the
	// endpoint is the one holding the zero address
	modeHeld     = prefix("128.0.0.0/1")
	modeEndpoint = netip.MustParseAddr("192.0.2.9")
	modeTargets  = []netip.Addr{netip.MustParseAddr("203.0.113.7"), netip.MustParseAddr("2001:db8:ff::7"), modeEndpoint}
)

// A reconciler on a test utun M with a live session and the endpoint
// 192.0.2.9 holds 0.0.0.0/0, ::/0 and 128.0.0.0/1. Mode off puts all three in
// scoped to M. A reload into mode 2 puts the two defaults in as the 16
// members unscoped, 128.0.0.0/1 among them as the real route in place of the
// member at its key. Then an unbound lookup of each target answers M, a
// lookup scoped to U, the interface the host's own default of the family
// leaves by, answers U, a socket bound to U connects from an address of U,
// and an unbound datagram comes out of M. A reload back to mode off restores
// the first pass's routes and the host's table.
func TestDarwinModeMovesTheDefaultsThroughTheReconciler(t *testing.T) {
	requireNetTest(t)
	rig := newCoverRig(t, coverRigOptions{endpoints: []netip.Addr{modeEndpoint}, off: true})
	rig.passByHand(t)
	underlay := map[bool]int{true: rig.host4, false: rig.host6}
	for _, index := range underlay {
		if index == rig.meshIndex {
			t.Fatal("the test utun is the interface the host's own traffic leaves by")
		}
	}
	defaults := defaultRoutesOnHost(t)
	zeros := defaultPrefixes
	for _, destination := range append(slices.Clone(zeros), modeHeld) {
		rig.table.Set(netip.Prefix{}, destination, nil)
	}
	members := append(slices.Clone(zeroFreeCover[true]), zeroFreeCover[false]...)
	off := rig.reconcile.Table()

	first := modePass(t, rig.reconcile, "mode off")
	var want []Route
	for _, destination := range append(slices.Clone(zeros), modeHeld) {
		want = append(want, modeRoute(destination, true, false))
	}
	if slices.SortFunc(want, compareRoutes); !slices.Equal(first, want) {
		t.Errorf("mode off reads back %v, want %v", first, want)
	}
	rows := modeRowsOn(t, rig.meshIndex)
	for _, destination := range append(slices.Clone(zeros), modeHeld) {
		if !modeHolds(rows, destination, true) || modeHolds(rows, destination, false) {
			t.Errorf("mode off leaves %s on M scoped %v and unscoped %v, want it scoped alone", destination,
				modeHolds(rows, destination, true), modeHolds(rows, destination, false))
		}
	}
	table := hostRows(t)

	modeReload(t, rig, off.WithMode(&ExitMode{}))
	on := modePass(t, rig.reconcile, "mode 2")
	want = []Route{modeRoute(modeHeld, false, false)}
	for _, member := range members {
		if member != modeHeld {
			want = append(want, modeRoute(member, false, true))
		}
	}
	if slices.SortFunc(want, compareRoutes); !slices.Equal(on, want) {
		t.Errorf("mode 2 reads back %v, want %v", on, want)
	}
	rows = modeRowsOn(t, rig.meshIndex)
	for _, member := range members {
		if !modeHolds(rows, member, false) {
			t.Errorf("mode 2 leaves the member %s off M unscoped", member)
		}
	}
	for _, zero := range zeros {
		if modeHolds(rows, zero, true) || modeHolds(rows, zero, false) {
			t.Errorf("mode 2 leaves %s on M, want nothing at its key", zero)
		}
	}
	if modeHolds(rows, modeHeld, true) || !modeHolds(rows, modeHeld, false) {
		t.Errorf("mode 2 leaves %s on M scoped %v and unscoped %v, want the real route unscoped alone", modeHeld,
			modeHolds(rows, modeHeld, true), modeHolds(rows, modeHeld, false))
	}

	for _, target := range modeTargets {
		u := underlay[target.Is4()]
		if got := askRoute(t, target, 0); got != rig.meshIndex {
			t.Errorf("an unbound lookup of %s answers index %d, want M at %d", target, got, rig.meshIndex)
		}
		if got := askRoute(t, target, u); got != u {
			t.Errorf("a lookup of %s scoped to U at %d answers index %d", target, u, got)
		}
		if source, err := boundSource(u, target); err != nil || !slices.Contains(addressesOf(t, u), source) {
			t.Errorf("a socket bound to U at %d connects to %s from %s (%v), want an address of U", u, target, source, err)
		}
		if !arrivesUnbound(t, rig.tun, target) {
			t.Errorf("an unbound datagram to %s did not come out of M", target)
		}
	}

	modeReload(t, rig, off)
	if back := modePass(t, rig.reconcile, "back to mode off"); !slices.Equal(back, first) {
		t.Errorf("mode off again reads back %v, want the first pass's %v", back, first)
	}
	if gone, added := rowsDiff(table, hostRows(t)); len(gone) > 0 || len(added) > 0 {
		t.Errorf("the host's table differs from the first pass's\ngone:  %q\nadded: %q", gone, added)
	}
	if orphans := modeOrphans(modeRowsOn(t, rig.meshIndex)); len(orphans) > 0 {
		t.Errorf("rows the kernel cloned on M outlive the routes they were cloned from: %v", orphans)
	}
	if !sameDefaults(defaults, defaultRoutesOnHost(t)) {
		t.Error("the host's default routes changed over the steps")
	}
}

// On a utun holding an IPv4 address alone, the kernel answers a scoped ::/0
// with ENETUNREACH, so mode off's ::/0 is skipped: each pass leaves it out
// with no error and counts it skipped, the two passes warn once, and the pass
// after the utun gains an IPv6 address installs it.
func TestDarwinRouteOfABareFamilyIsSkipped(t *testing.T) {
	requireNetTest(t)
	logs := captureKernelLogs(t)
	mesh, _ := createUTUNWithFD(t)
	setInterfaceUp(t, mesh)
	routes := netstack.NewRouteTable()
	reconciler, err := New(Table{ID: DefaultTable, Proto: DefaultProtocol}, Runtime{Interface: mesh, Sessions: func() int { return 1 }}, routes)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reconciler.withdraw(nil); _ = reconciler.plat.Close() })
	plat := reconciler.plat.(*routePlatform)
	if err := plat.AddAddr(prefix("198.51.100.1/24")); err != nil {
		t.Fatal(err)
	}
	zero := Route{Destination: prefix("::/0"), Metric: routeMetric(prefix("::/0"), false)}
	message, err := plat.routeMessage(unix.RTM_ADD, zero)
	if err != nil {
		t.Fatal(err)
	}
	message.Flags |= unix.RTF_IFSCOPE
	if err := plat.sock.WriteRoute(message); !errors.Is(err, unix.ENETUNREACH) {
		t.Fatalf("the kernel answered a scoped ::/0 on a utun holding no IPv6 address with %v, want ENETUNREACH", err)
	}

	routes.Set(netip.Prefix{}, zero.Destination, nil)
	for pass := range 2 {
		if err := reconciler.reconcile(); err != nil {
			t.Fatalf("pass %d: %v", pass, err)
		}
		if stats := reconciler.Stats(); stats.Installed != 0 || stats.Skipped != 1 {
			t.Errorf("pass %d installed %d and skipped %d, want 0 and 1", pass, stats.Installed, stats.Skipped)
		}
	}
	if n := strings.Count(logs.String(), "the tun holds no address of its family"); n != 1 {
		t.Errorf("two passes warned %d times, want once: %s", n, logs.String())
	}

	if err := plat.AddAddr(prefix("2001:db8:ff::1/64")); err != nil {
		t.Fatal(err)
	}
	if err := reconciler.reconcile(); err != nil {
		t.Fatalf("the pass after an IPv6 address: %v", err)
	}
	if stats := reconciler.Stats(); stats.Installed != 1 || stats.Skipped != 0 {
		t.Errorf("the pass after an IPv6 address installed %d and skipped %d, want 1 and 0", stats.Installed, stats.Skipped)
	}
}

// modeReload hands the rig's reconciler next over the rig's overlay and has
// it taken before the next pass
func modeReload(t *testing.T, rig *coverRig, next Table) {
	t.Helper()
	if err := rig.reconcile.SetTable(next, coverRigOverlay, nil); err != nil {
		t.Fatal(err)
	}
	if !rig.reconcile.adopt() {
		t.Fatal("the reload was not taken")
	}
}

// modePass runs one pass and reads the routes back, sorted
func modePass(t *testing.T, reconciler *Reconciler, step string) []Route {
	t.Helper()
	if err := reconciler.reconcile(); err != nil {
		t.Fatalf("%s: %v", step, err)
	}
	routes, err := reconciler.plat.Routes()
	if err != nil {
		t.Fatalf("%s: %v", step, err)
	}
	slices.SortFunc(routes, compareRoutes)
	return routes
}

func modeRoute(destination netip.Prefix, scoped, cover bool) Route {
	return Route{Destination: destination, Metric: routeMetric(destination, false), Scoped: scoped, Cover: cover}
}

// modeRow is one row of the host's table out of one interface
type modeRow struct {
	destination netip.Prefix
	scoped      bool
	cloned      bool
}

func modeRowsOn(t *testing.T, index int) []modeRow {
	t.Helper()
	var out []modeRow
	for _, rm := range dumpedRoutes(t) {
		if rm.Index != index {
			continue
		}
		if destination, ok := dumpedPrefix(rm); ok {
			out = append(out, modeRow{destination: destination, scoped: rm.Flags&unix.RTF_IFSCOPE != 0, cloned: rm.Flags&unix.RTF_WASCLONED != 0})
		}
	}
	return out
}

func modeHolds(rows []modeRow, destination netip.Prefix, scoped bool) bool {
	return slices.Contains(rows, modeRow{destination: destination, scoped: scoped})
}

// modeOrphans is the cloned rows that no route of the same scope among rows
// holds. The kernel clones a host row off a route it sends through and
// deletes the clones with that route, so an orphan sends its destination out
// of the interface after the route that took it there is gone.
func modeOrphans(rows []modeRow) []netip.Prefix {
	var out []netip.Prefix
	for _, clone := range rows {
		if clone.cloned && !slices.ContainsFunc(rows, func(parent modeRow) bool {
			return !parent.cloned && parent.scoped == clone.scoped &&
				parent.destination.Bits() < clone.destination.Bits() && parent.destination.Contains(clone.destination.Addr())
		}) {
			out = append(out, clone.destination)
		}
	}
	return out
}

func dumpedRoutes(t *testing.T) []*route.RouteMessage {
	t.Helper()
	rib, err := route.FetchRIB(unix.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		t.Fatal(err)
	}
	messages, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		t.Fatal(err)
	}
	var out []*route.RouteMessage
	for _, message := range messages {
		if rm, ok := message.(*route.RouteMessage); ok && rm.Type == unix.RTM_GET {
			out = append(out, rm)
		}
	}
	return out
}

// hostRows is every row of the host's table but ARP and NDP entries and the
// host rows the kernel clones for a destination any program sends to, each as
// its destination, next hop, interface index and flags
func hostRows(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, rm := range dumpedRoutes(t) {
		if rm.Flags&(unix.RTF_LLINFO|unix.RTF_WASCLONED) != 0 {
			continue
		}
		destination, next := "?", "?"
		if held, ok := dumpedPrefix(rm); ok {
			destination = held.String()
		} else if len(rm.Addrs) > unix.RTAX_DST {
			if address, ok := addressFromRouteAddr(rm.Addrs[unix.RTAX_DST]); ok {
				destination = address.String() + " with an unread mask"
			}
		}
		if len(rm.Addrs) > unix.RTAX_GATEWAY {
			switch gateway := rm.Addrs[unix.RTAX_GATEWAY].(type) {
			case *route.LinkAddr:
				next = fmt.Sprintf("link#%d", gateway.Index)
			default:
				if address, ok := addressFromRouteAddr(gateway); ok {
					next = address.String()
				}
			}
		}
		out = append(out, fmt.Sprintf("%s via %s on index %d flags %#x", destination, next, rm.Index, rm.Flags))
	}
	slices.Sort(out)
	return out
}

// rowsDiff is the rows of before missing from after and the rows of after
// missing from before, each counted as often as it repeats
func rowsDiff(before, after []string) (gone, added []string) {
	count := map[string]int{}
	for _, row := range before {
		count[row]++
	}
	for _, row := range after {
		count[row]--
	}
	for _, row := range slices.Sorted(maps.Keys(count)) {
		for n := count[row]; n > 0; n-- {
			gone = append(gone, row)
		}
		for n := count[row]; n < 0; n++ {
			added = append(added, row)
		}
	}
	return gone, added
}

// boundSource is the source a UDP socket bound to index connects to target
// from, sending nothing
func boundSource(index int, target netip.Addr) (netip.Addr, error) {
	family, level, option := unix.AF_INET6, unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF
	var to unix.Sockaddr = &unix.SockaddrInet6{Addr: target.As16(), Port: 9}
	if target.Is4() {
		family, level, option = unix.AF_INET, unix.IPPROTO_IP, unix.IP_BOUND_IF
		to = &unix.SockaddrInet4{Addr: target.As4(), Port: 9}
	}
	fd, err := unix.Socket(family, unix.SOCK_DGRAM, 0)
	if err != nil {
		return netip.Addr{}, err
	}
	defer unix.Close(fd)
	if err := unix.SetsockoptInt(fd, level, option, index); err != nil {
		return netip.Addr{}, err
	}
	if err := unix.Connect(fd, to); err != nil {
		return netip.Addr{}, err
	}
	local, err := unix.Getsockname(fd)
	if err != nil {
		return netip.Addr{}, err
	}
	switch local := local.(type) {
	case *unix.SockaddrInet4:
		return netip.AddrFrom4(local.Addr), nil
	case *unix.SockaddrInet6:
		return netip.AddrFrom16(local.Addr), nil
	}
	return netip.Addr{}, fmt.Errorf("the socket names %T", local)
}

// addressesOf is every address the interface at index holds
func addressesOf(t *testing.T, index int) []netip.Addr {
	t.Helper()
	device, err := net.InterfaceByIndex(index)
	if err != nil {
		t.Fatal(err)
	}
	held, err := device.Addrs()
	if err != nil {
		t.Fatal(err)
	}
	var out []netip.Addr
	for _, one := range held {
		if network, ok := one.(*net.IPNet); ok {
			if address, ok := netip.AddrFromSlice(network.IP); ok {
				out = append(out, address.Unmap())
			}
		}
	}
	return out
}
