// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package kernel

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/schema"
)

// The IPv6 half of schema.CapturesTheMachine's arm over the unspecified
// address, measured rather than inferred from the IPv4 one.
//
// It needs the host to hold no unscoped ::/0, and skips before it creates
// anything where the host holds one. The uplink is then built rather than
// borrowed, on a throwaway utun carrying the only unscoped ::/0, so this is a
// measurement of the kernel's lookup rather than of this machine's uplink,
// which is the part the predicate rests on. While it runs the kernel refuses
// another program's add of an unscoped ::/0 with EEXIST, since the key holds
// the test's. It fails where the host's unscoped ::/0 is not at its end what
// it was at its start (keepUnscopedAt).
//
// The expected rule, the same one IPv4 measures: a socket bound with
// IPV6_BOUND_IF loses destination D exactly when the tun's unscoped routes
// best-match both D and ::.
func TestDarwinStrandsABoundIPv6SocketThroughTheZeroAddress(t *testing.T) {
	requireNetTest(t)
	keepUnscopedAt(t, defaultPrefixes[1])
	if index, ok := unscopedRouteAt(dumpRoutes(t), defaultPrefixes[1]); ok {
		t.Skipf("this host holds an unscoped ::/0 on interface %d, and the fallback can be measured only on one the test adds", index)
	}
	_, uplinkIndex, reason := uplinkWithDefault6(t)
	if reason != "" {
		t.Skip(reason)
	}
	mesh, _ := createUTUNWithFD(t)
	setInterfaceUp(t, mesh)
	meshPlat := testTUNPlatform(t, mesh)
	if err := meshPlat.AddAddr(prefix("2001:db8:bb::1/64")); err != nil {
		t.Fatal(err)
	}

	// In ::/1, so the lower half covers it and the upper half does not.
	target := netip.MustParseAddr("2001:db8:ffff::1")
	if err := boundReach6(uplinkIndex, target); err != nil {
		t.Skipf("a socket bound to the built uplink cannot reach %s to begin with: %v", target, err)
	}

	for _, test := range []struct {
		set     []string
		strands bool
	}{
		// Covers the target and the zero address.
		{[]string{"::/1", "8000::/1"}, true},
		{[]string{"::/1"}, true},
		{[]string{"::/64", "2001:db8::/32"}, true},
		{[]string{"::/16", "2001:db8::/32"}, true},
		// Covers the target and no zero address.
		{[]string{"2001:db8::/32"}, false},
		// Covers neither.
		{[]string{"8000::/1"}, false},
	} {
		t.Run(strings.Join(test.set, " "), func(t *testing.T) {
			for _, one := range test.set {
				route := Route{Destination: prefix(one), Metric: defaultIPv6Metric}
				if err := meshPlat.AddRoute(route); err != nil {
					t.Skipf("%s is held by another program on this host: %v", one, err)
				}
				t.Cleanup(func() { _ = meshPlat.DelRoute(route) })
			}
			reachErr := boundReach6(uplinkIndex, target)
			if test.strands && reachErr == nil {
				t.Errorf("a bound socket still reaches %s, so IPv6 no longer needs the fallback", target)
			}
			if !test.strands && reachErr != nil {
				t.Errorf("a bound socket lost %s to a set covering no zero address: %v", target, reachErr)
			}
			held := false
			for _, one := range test.set {
				if schema.CapturesTheMachine(prefix(one), nil) {
					held = true
				}
			}
			if test.strands && !held {
				t.Error("the set strands a bound IPv6 socket and the capture rule holds none of it back")
			}
		})
	}
}

// uplinkWithDefault6 makes a utun carrying an unscoped ::/0, for a test that
// found the host holding none, and answers why it could not as the reason
// the test skips for. route(8) exits 0 when the kernel refuses the add
// (newroute in network_cmds' route.c), so the route counts as added only once
// the dump shows it on the utun. The route goes with the utun, whose detach
// removes the routes out of it and no other (if_rtdel in bsd/net/if.c). A
// delete names no interface (rnh_deladdr in bsd/net/route.c), so one runs
// only where the route outlives the utun by waitBudget, and only while the
// dump shows the key's one unscoped route on the utun's index.
func uplinkWithDefault6(t *testing.T) (string, int, string) {
	t.Helper()
	index := 0
	// registered before the utun, so it runs after the descriptor is closed
	t.Cleanup(func() {
		if index == 0 {
			return
		}
		for deadline := time.Now().Add(waitBudget); unscopedDefaultOn(t, index); time.Sleep(waitPoll) {
			if time.Now().After(deadline) {
				out, err := exec.Command("route", "-n", "delete", "-inet6", "-net", "::/0").CombinedOutput()
				t.Errorf("the ::/0 on interface %d outlived its utun by %s and was deleted by its key: %v %s", index, waitBudget, err, out)
				return
			}
		}
	})
	name, _ := createUTUNWithFD(t)
	setInterfaceUp(t, name)
	if err := testTUNPlatform(t, name).AddAddr(prefix("2001:db8:aa::1/64")); err != nil {
		t.Fatal(err)
	}
	index = interfaceIndex(t, name)
	// `route add -interface` writes it without a next hop, the one shape that
	// installs on a point-to-point device
	out, err := exec.Command("route", "-n", "add", "-inet6", "-net", "::/0", "-interface", name).CombinedOutput()
	if err != nil {
		return name, index, fmt.Sprintf("route add ::/0 on %s: %v %s", name, err, out)
	}
	if !unscopedDefaultOn(t, index) {
		return name, index, fmt.Sprintf("%s did not take an unscoped ::/0: %s", name, out)
	}
	return name, index, ""
}

// keepUnscopedAt fails the test where the interface the host's unscoped route
// at key leaves by, or its having none, differs between the call and the
// cleanup it registers, which runs after the cleanups registered after it and
// before those registered before it. The IPv6 test and the netwatch test call
// it before they make anything, so it reads after every other cleanup.
// hostDefault6 calls it once its caller has made the mesh utun (the cover rig,
// the measure test) or registered killLeavesTheHost (two switch tests), so
// there it reads before the mesh's descriptor closes and before the sweep and
// the table check, and sees nothing those do. What it rests on is that neither
// deletes an unscoped ::/0 out of another interface. The sweep deletes rejects
// on lo0 at the keys killSwept names, none of them ::/0. XNU's close of a
// utun deletes each of its IPv6 addresses with the host route at it, which
// sits on lo0 (utun_ctl_disconnect in bsd/net/if_utun.c, in6_purgeif and
// in6_ifremloop in bsd/netinet6/in6.c), and no such host route is a ::/0. A
// ::/0 the test left on the mesh it reads as a change.
func keepUnscopedAt(t *testing.T, key netip.Prefix) {
	t.Helper()
	before := unscopedRead(t, key)
	t.Cleanup(func() {
		if after := unscopedRead(t, key); after != before {
			t.Errorf("the host's unscoped route at %s was %s when the test began to watch it and is %s when it stopped", key, before, after)
		}
	})
}

// unscopedRead says which interface the host's unscoped route at key leaves by
func unscopedRead(t *testing.T, key netip.Prefix) string {
	t.Helper()
	if index, ok := unscopedRouteAt(dumpRoutes(t), key); ok {
		return fmt.Sprintf("on interface %d", index)
	}
	return "none"
}

func interfaceIndex(t *testing.T, name string) int {
	t.Helper()
	device, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatal(err)
	}
	return device.Index
}

// testTUNPlatform opens the backend on one device, covering both families so
// that only a hold or a source-specific route it writes is scoped.
func testTUNPlatform(t *testing.T, name string) *routePlatform {
	t.Helper()
	opened, err := newPlatform(
		Table{ID: DefaultTable, Proto: DefaultProtocol}.WithMode(&ExitMode{}),
		Runtime{Interface: name})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = opened.Close() })
	plat := opened.(*routePlatform)
	plat.cover(nil, bothFamilies, nil, hostTable{})
	return plat
}

// unscopedDefaultOn reports whether the kernel holds an unscoped ::/0 on that
// interface, the route the scoped lookup falls back to.
func unscopedDefaultOn(t *testing.T, index int) bool {
	t.Helper()
	found, ok := unscopedRouteAt(dumpRoutes(t), defaultPrefixes[1])
	return ok && found == index
}

// unscopedRouteAt is the interface the route at key carrying no scope leaves by,
// read from the dump, where the kernel holds at most one such route at a key.
// A route the kernel cloned is none, since an add at its key takes its place
// (rtrequest's RTM_ADD in bsd/net/route.c).
func unscopedRouteAt(messages []route.Message, key netip.Prefix) (int, bool) {
	for _, message := range messages {
		rm, ok := message.(*route.RouteMessage)
		if !ok || rm.Type != unix.RTM_GET || rm.Flags&(unix.RTF_IFSCOPE|unix.RTF_WASCLONED) != 0 {
			continue
		}
		if held, ok := dumpedPrefix(rm); ok && held == key {
			return rm.Index, true
		}
	}
	return 0, false
}

// routedElsewhere is the interface the host's unscoped route at key leaves by,
// where the dump holds one and it is not own, the test's interface, or 0
// before the test has made one. A test that writes at key skips there.
func routedElsewhere(messages []route.Message, key netip.Prefix, own int) (int, bool) {
	if index, ok := unscopedRouteAt(messages, key); ok && index != own {
		return index, true
	}
	return 0, false
}

// dumpRoutes is the kernel's routing table of both families.
func dumpRoutes(t *testing.T) []route.Message {
	t.Helper()
	rib, err := route.FetchRIB(unix.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		t.Fatal(err)
	}
	messages, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		t.Fatal(err)
	}
	return messages
}

// The read every root test takes before it adds an unscoped ::/0: a default
// scoped to an interface, another family's default and a longer prefix over
// :: are none, and the unscoped one is told from a scoped one at its key.
func TestUnscopedDefaultIndexReadsOnlyTheFamilysUnscopedDefault(t *testing.T) {
	entry := func(destination string, flags, index int) route.Message {
		return dumpEntryAt(t, destination, flags, index)
	}
	added := entry("::/0", 0, 9).(*route.RouteMessage)
	added.Type = unix.RTM_ADD
	for _, test := range []struct {
		name  string
		dump  []route.Message
		index int
		ok    bool
	}{
		{"empty", nil, 0, false},
		{"scoped", []route.Message{entry("::/0", unix.RTF_IFSCOPE, 7)}, 0, false},
		{"ipv4", []route.Message{entry("0.0.0.0/0", 0, 7)}, 0, false},
		{"longer", []route.Message{entry("::/1", 0, 7), entry("::/64", 0, 8)}, 0, false},
		{"no dump entry", []route.Message{added}, 0, false},
		{"unscoped", []route.Message{entry("0.0.0.0/0", 0, 5), entry("::/0", 0, 9)}, 9, true},
		{"beside scoped", []route.Message{entry("::/0", unix.RTF_IFSCOPE, 7), entry("::/0", 0, 9), entry("::/0", unix.RTF_IFSCOPE, 8)}, 9, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			index, ok := unscopedDefaultIndex(test.dump, defaultPrefixes[1])
			if index != test.index || ok != test.ok {
				t.Errorf("got %d %v, want %d %v", index, ok, test.index, test.ok)
			}
		})
	}
}

// The read a test takes before it deletes a route by its key: a route scoped
// to an interface, one at a longer or a shorter key, one the kernel cloned and
// an entry no dump holds are none, a host route is keyed by its address, and
// the unscoped route is told from a scoped one at its key.
func TestUnscopedRouteAtReadsOnlyTheUnscopedRouteAtItsKey(t *testing.T) {
	entry := func(destination string, flags, index int) route.Message {
		return dumpEntryAt(t, destination, flags, index)
	}
	added := entry("198.51.100.0/24", 0, 9).(*route.RouteMessage)
	added.Type = unix.RTM_ADD
	for _, test := range []struct {
		name, key string
		dump      []route.Message
		index     int
		ok        bool
	}{
		{"empty", "198.51.100.0/24", nil, 0, false},
		{"scoped", "198.51.100.0/24", []route.Message{entry("198.51.100.0/24", unix.RTF_IFSCOPE, 7)}, 0, false},
		{"longer", "198.51.100.0/24", []route.Message{entry("198.51.100.0/25", 0, 7)}, 0, false},
		{"shorter", "198.51.100.0/24", []route.Message{entry("198.51.100.0/23", 0, 7), entry("0.0.0.0/0", 0, 6)}, 0, false},
		{"no dump entry", "198.51.100.0/24", []route.Message{added}, 0, false},
		{"unscoped", "198.51.100.0/24", []route.Message{entry("198.51.100.0/24", 0, 9)}, 9, true},
		{"beside scoped", "198.51.100.0/24", []route.Message{entry("198.51.100.0/24", unix.RTF_IFSCOPE, 7), entry("198.51.100.0/24", 0, 9)}, 9, true},
		{"default", "::/0", []route.Message{entry("0.0.0.0/0", 0, 5), entry("::/0", unix.RTF_IFSCOPE, 6), entry("::/0", 0, 7)}, 7, true},
		{"cloned", "203.0.113.20/32", []route.Message{entry("203.0.113.20/32", unix.RTF_HOST|unix.RTF_WASCLONED, 6)}, 0, false},
		{"host", "203.0.113.20/32", []route.Message{entry("203.0.113.20/32", unix.RTF_HOST, 6)}, 6, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			index, ok := unscopedRouteAt(test.dump, prefix(test.key))
			if index != test.index || ok != test.ok {
				t.Errorf("got %d %v, want %d %v", index, ok, test.index, test.ok)
			}
		})
	}
}

// The read a test takes before it writes at a key: the host's unscoped route
// there counts, the test's own and a scoped route of another interface do not,
// and before the test has made an interface any unscoped route counts.
func TestRoutedElsewhereReadsOnlyAnotherInterfacesUnscopedRoute(t *testing.T) {
	entry := func(flags, index int) route.Message {
		return dumpEntryAt(t, "198.51.100.0/24", flags, index)
	}
	for _, test := range []struct {
		name       string
		dump       []route.Message
		own, index int
		ok         bool
	}{
		{"no row", nil, 9, 0, false},
		{"the host's row", []route.Message{entry(0, 7)}, 9, 7, true},
		{"the test's own row", []route.Message{entry(0, 9)}, 9, 0, false},
		{"a scoped row of another interface", []route.Message{entry(unix.RTF_IFSCOPE, 7)}, 9, 0, false},
		{"the host's row before the test has an interface", []route.Message{entry(0, 7)}, 0, 7, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			index, ok := routedElsewhere(test.dump, prefix("198.51.100.0/24"), test.own)
			if index != test.index || ok != test.ok {
				t.Errorf("got %d %v, want %d %v", index, ok, test.index, test.ok)
			}
		})
	}
}

// dumpEntryAt is one route at destination as NET_RT_DUMP reports it, with a
// netmask of the destination's own family
func dumpEntryAt(t *testing.T, destination string, flags, index int) route.Message {
	t.Helper()
	key := prefix(destination)
	mask, ok := prefixMask(key)
	if !ok {
		t.Fatalf("no mask for %s", key)
	}
	addrs := make([]route.Addr, unix.RTAX_NETMASK+1)
	addrs[unix.RTAX_DST] = routeAddr(key.Addr())
	addrs[unix.RTAX_NETMASK] = routeAddr(mask)
	return &route.RouteMessage{Type: unix.RTM_GET, Flags: unix.RTF_UP | flags, Index: index, Addrs: addrs}
}

// boundReach6 resolves the route a socket bound to index would take for an
// IPv6 destination, sending nothing.
func boundReach6(index int, target netip.Addr) error {
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, index); err != nil {
		return err
	}
	return unix.Connect(fd, &unix.SockaddrInet6{Addr: target.As16(), Port: 9})
}
