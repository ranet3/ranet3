// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin

package netstack

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"slices"
	"testing"
	"time"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// the addresses of the test below, in 3fff::/20, which RFC 9637 sets aside for documentation
var (
	// entryOwn is the mesh utun's own address, which the mesh's table holds as this node's
	entryOwn = netip.MustParseAddr("3fff:10::1")
	// entryNode is another node's prefix, which the mesh routes to that node's peer, and entryTarget an address inside it
	entryNode   = netip.MustParsePrefix("3fff:20::/32")
	entryTarget = netip.MustParseAddr("3fff:20::1")
	// entryUplink is the address of a second utun that stands in for the uplink, which no entry of the mesh's table covers
	entryUplink = netip.MustParseAddr("3fff:30::1")
)

const (
	ifconfigBin = "/sbin/ifconfig"
	routeBin    = "/sbin/route"
	// tentativeWait bounds the wait for an IPv6 address just added to take a bind, since it may be tentative at first
	// and tentativePoll is how often a bind is tried again
	tentativeWait = 5 * time.Second
	tentativePoll = 50 * time.Millisecond
)

// a socket bound to the uplink's address and held to the mesh's utun by IPV6_BOUND_IF sends toward another node's prefix
// the read of a mesh opened ownedOnly, as a host whose kernel runs no entry rule opens it, takes it from a source this node does not own
// and drops it as unowned_source rather than handing it to that node's peer
// the uplink is a second utun, so the test needs no IPv6 address of the host's own
// creating a utun needs root, which a run does here only with RANET3_DARWIN_NETTEST=1
func TestTUNDropsAnUnownedReadTowardAnotherNode(t *testing.T) {
	requireUTUN(t)
	routesKept(t)
	m, uplink := openUTUNMesh(t, true), openUTUNMesh(t, false)
	aliasUTUN(t, m.Name, netip.PrefixFrom(entryOwn, 128))
	aliasUTUN(t, uplink.Name, netip.PrefixFrom(entryUplink, 128))
	if reason := routeIntoUTUN(t, entryNode, m.Name); reason != "" {
		t.Skip(reason)
	}
	link, err := net.InterfaceByName(m.Name)
	if err != nil {
		t.Fatalf("look up %s: %v", m.Name, err)
	}
	sent := &recordingPeer{}
	m.Routes.Set(netip.Prefix{}, netip.PrefixFrom(entryOwn, 128), Local)
	m.Routes.Set(netip.Prefix{}, entryNode, sent.peer(t, "another node"))

	was := m.TransitCounters()
	if err := sendHeld(entryUplink, link.Index, entryTarget); err != nil {
		t.Fatalf("send from %s held to %s toward %s: %v", entryUplink, m.Name, entryTarget, err)
	}
	forwarded := func() (n int) {
		sent.mu.Lock()
		defer sent.mu.Unlock()
		for _, p := range sent.sent {
			if len(p) >= 40 && netip.AddrFrom16([16]byte(p[24:40])) == entryTarget {
				n++
			}
		}
		return n
	}
	judged := func(now TransitCounters) bool {
		return now.UnownedSource != was.UnownedSource || now.Forged != was.Forged || now.NoRoute != was.NoRoute || now.Held != was.Held || now.Looped != was.Looped || now.Invalid != was.Invalid
	}
	for deadline := time.Now().Add(deliveryTimeout); forwarded() == 0 && !judged(m.TransitCounters()); time.Sleep(deliveryPoll) {
		if time.Now().After(deadline) {
			t.Fatalf("waited %s and the read neither handed the datagram from %s to %s to the peer nor dropped it, the counters reading %+v", deliveryTimeout, entryUplink, entryTarget, m.TransitCounters())
		}
	}
	now := m.TransitCounters()
	if n, dropped := forwarded(), now.UnownedSource-was.UnownedSource; n != 0 || dropped != 1 {
		t.Fatalf("the read handed the datagram from %s to %s to the peer %d times and counted unowned_source %d times, want it dropped and counted once, the counters reading %+v", entryUplink, entryTarget, n, dropped, now)
	}
}

// openUTUNMesh opens a mesh on the next free utun, ownedOnly as given, closed when the test ends
func openUTUNMesh(t *testing.T, ownedOnly bool) *Mesh {
	t.Helper()
	m, err := NewNamed(utunJumbo, "", ownedOnly, nil)
	if err != nil {
		t.Fatalf("open the mesh: %v", err)
	}
	t.Cleanup(m.Close)
	return m
}

// aliasUTUN adds prefix's address to the utun name as ranet3 does until the test ends, an IPv4 address with itself as the destination and an IPv6 address with none
func aliasUTUN(t *testing.T, name string, prefix netip.Prefix) {
	t.Helper()
	add := []string{name, "inet6", prefix.String(), "alias"}
	remove := []string{name, "inet6", prefix.Addr().String(), "-alias"}
	if prefix.Addr().Is4() {
		add = []string{name, "inet", prefix.String(), prefix.Addr().String(), "alias"}
		remove = []string{name, "inet", prefix.Addr().String(), "-alias"}
	}
	if err := runTool(ifconfigBin, add...); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := runTool(ifconfigBin, remove...); err != nil {
			t.Error(err)
		}
	})
}

// routeIntoUTUN routes prefix out of the utun name until the test ends, or answers why the test skips
// route(8) exits 0 where the kernel refuses an add (newroute in network_cmds' route.c) and a delete names no interface
// (rnh_deladdr in bsd/net/route.c), so the test adds nothing where another interface's route holds prefix, takes the route
// as added only once the dump shows it out of the utun, and deletes it by its key only while the dump does
// the kernel holds one unscoped route at a key, so that one is the test's
// the caller skips, so that the skip's line is the test's own
func routeIntoUTUN(t *testing.T, prefix netip.Prefix, name string) string {
	t.Helper()
	link, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatalf("look up %s: %v", name, err)
	}
	family := "-inet"
	if prefix.Addr().Is6() {
		family = "-inet6"
	}
	if held, ok := unscopedAt(routeDump(t), prefix); ok && held != link.Index {
		return fmt.Sprintf("the host routes %s out of interface %d already, and the route this test deletes by its key would be that one", prefix, held)
	}
	if err := runTool(routeBin, "-q", "-n", "add", family, prefix.String(), "-interface", name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if held, ok := unscopedAt(routeDump(t), prefix); !ok || held != link.Index {
			return
		}
		if err := runTool(routeBin, "-q", "-n", "delete", family, prefix.String()); err != nil {
			t.Error(err)
		}
	})
	if held, ok := unscopedAt(routeDump(t), prefix); !ok {
		t.Fatalf("route(8) answered the add of %s out of %s as done and the dump holds no route there", prefix, name)
	} else if held != link.Index {
		return fmt.Sprintf("the host routes %s out of interface %d, which took the key before this test's add", prefix, held)
	}
	return ""
}

// unscopedAt is the interface the route at key carrying no scope leaves by, read from the dump, where the kernel holds at
// most one such route at a key
// a route the kernel cloned is none, since an add at its key takes its place (rtrequest's RTM_ADD in bsd/net/route.c)
func unscopedAt(messages []route.Message, key netip.Prefix) (int, bool) {
	for _, message := range messages {
		rm, ok := message.(*route.RouteMessage)
		if !ok || rm.Type != unix.RTM_GET || rm.Flags&(unix.RTF_IFSCOPE|unix.RTF_WASCLONED) != 0 {
			continue
		}
		if held, ok := dumpedKey(rm); ok && held == key {
			return rm.Index, true
		}
	}
	return 0, false
}

// dumpedKey is the prefix a dumped route is keyed by: its destination, under its netmask unless it is a host route
func dumpedKey(rm *route.RouteMessage) (netip.Prefix, bool) {
	if len(rm.Addrs) <= unix.RTAX_NETMASK {
		return netip.Prefix{}, false
	}
	destination, ok := dumpedAddr(rm.Addrs[unix.RTAX_DST])
	if !ok {
		return netip.Prefix{}, false
	}
	bits := destination.BitLen()
	if rm.Flags&unix.RTF_HOST == 0 {
		mask, ok := dumpedAddr(rm.Addrs[unix.RTAX_NETMASK])
		if !ok || mask.BitLen() != bits {
			return netip.Prefix{}, false
		}
		ones, total := net.IPMask(mask.AsSlice()).Size()
		if total == 0 {
			return netip.Prefix{}, false
		}
		bits = ones
	}
	return netip.PrefixFrom(destination, bits).Masked(), true
}

func dumpedAddr(addr route.Addr) (netip.Addr, bool) {
	switch a := addr.(type) {
	case *route.Inet4Addr:
		return netip.AddrFrom4(a.IP), true
	case *route.Inet6Addr:
		return netip.AddrFrom16(a.IP), true
	}
	return netip.Addr{}, false
}

// the read routeIntoUTUN takes before it adds and before it deletes: a route scoped to an interface, one at a longer or a
// shorter key, one with a netmask that is not one, one the kernel cloned and an entry no dump holds are none
// a host route is keyed by its address, and the unscoped route is told from a scoped one at its key
func TestUnscopedAtReadsOnlyTheUnscopedRouteAtItsKey(t *testing.T) {
	entry := func(destination string, mask netip.Addr, flags, index int) *route.RouteMessage {
		addrs := make([]route.Addr, unix.RTAX_NETMASK+1)
		for i, address := range map[int]netip.Addr{unix.RTAX_DST: netip.MustParseAddr(destination), unix.RTAX_NETMASK: mask} {
			switch {
			case !address.IsValid():
			case address.Is4():
				addrs[i] = &route.Inet4Addr{IP: address.As4()}
			default:
				addrs[i] = &route.Inet6Addr{IP: address.As16()}
			}
		}
		return &route.RouteMessage{Type: unix.RTM_GET, Flags: unix.RTF_UP | flags, Index: index, Addrs: addrs}
	}
	mask24, mask25, mask32 := netip.MustParseAddr("255.255.255.0"), netip.MustParseAddr("255.255.255.128"), netip.MustParseAddr("ffff:ffff::")
	added := entry("192.0.2.0", mask24, 0, 9)
	added.Type = unix.RTM_ADD
	for _, test := range []struct {
		name, key string
		dump      []route.Message
		index     int
		ok        bool
	}{
		{"empty", "192.0.2.0/24", nil, 0, false},
		{"scoped", "192.0.2.0/24", []route.Message{entry("192.0.2.0", mask24, unix.RTF_IFSCOPE, 7)}, 0, false},
		{"longer", "192.0.2.0/24", []route.Message{entry("192.0.2.0", mask25, 0, 7)}, 0, false},
		{"shorter", "192.0.2.0/25", []route.Message{entry("192.0.2.0", mask24, 0, 7)}, 0, false},
		{"not a mask", "192.0.2.0/24", []route.Message{entry("192.0.2.0", netip.MustParseAddr("255.0.255.0"), 0, 7)}, 0, false},
		{"not a mask over the default", "0.0.0.0/0", []route.Message{entry("0.0.0.0", netip.MustParseAddr("255.0.255.0"), 0, 7)}, 0, false},
		{"other family's mask", "192.0.2.0/24", []route.Message{entry("192.0.2.0", netip.MustParseAddr("ffff:ff00::"), 0, 7)}, 0, false},
		{"host", "3fff:10::1/128", []route.Message{entry("3fff:10::1", netip.Addr{}, unix.RTF_HOST, 4)}, 4, true},
		{"cloned", "192.0.2.1/32", []route.Message{entry("192.0.2.1", netip.Addr{}, unix.RTF_HOST|unix.RTF_WASCLONED, 7)}, 0, false},
		{"no dump entry", "192.0.2.0/24", []route.Message{added}, 0, false},
		{"unscoped", "192.0.2.0/24", []route.Message{entry("192.0.2.0", mask24, 0, 9)}, 9, true},
		{"beside scoped", "3fff:20::/32", []route.Message{entry("3fff:20::", mask32, unix.RTF_IFSCOPE, 7), entry("3fff:20::", mask32, 0, 9)}, 9, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			index, ok := unscopedAt(test.dump, netip.MustParsePrefix(test.key))
			if index != test.index || ok != test.ok {
				t.Errorf("got %d %v, want %d %v", index, ok, test.index, test.ok)
			}
		})
	}
}

func runTool(name string, args ...string) error {
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("%s %v: %w: %s", name, args, err, out)
	}
	return nil
}

// routesKept checks at the test's end, once its utuns are gone, that every route the kernel holds reads back as it was before the test
// registered first, so it runs after every other cleanup
func routesKept(t *testing.T) {
	t.Helper()
	before := routesElsewhere(t, 0)
	t.Cleanup(func() {
		var after []string
		for deadline := time.Now().Add(utunSettle); ; time.Sleep(deliveryPoll) {
			if after = routesElsewhere(t, 0); slices.Equal(after, before) || time.Now().After(deadline) {
				break
			}
		}
		for _, gone := range missing(before, after) {
			t.Errorf("the route %s was there before the test and is not after it", gone)
		}
		for _, added := range missing(after, before) {
			t.Errorf("the route %s was not there before the test and is after it", added)
		}
	})
}

// sendHeld sends one UDP datagram to destination's port 9 from a socket bound to source and held to the interface index by IPV6_BOUND_IF
func sendHeld(source netip.Addr, index int, destination netip.Addr) error {
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, index); err != nil {
		return fmt.Errorf("hold to interface %d: %w", index, err)
	}
	for deadline := time.Now().Add(tentativeWait); ; time.Sleep(tentativePoll) {
		err = unix.Bind(fd, &unix.SockaddrInet6{Addr: source.As16()})
		if err == nil || !errors.Is(err, unix.EADDRNOTAVAIL) || time.Now().After(deadline) {
			break
		}
	}
	if err != nil {
		return fmt.Errorf("bind %s: %w", source, err)
	}
	return unix.Sendto(fd, []byte("unowned"), 0, &unix.SockaddrInet6{Addr: destination.As16(), Port: 9})
}
