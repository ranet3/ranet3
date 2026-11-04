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
	aliasUTUN(t, m.Name, entryOwn)
	aliasUTUN(t, uplink.Name, entryUplink)
	routeIntoUTUN(t, entryNode, m.Name)
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

// aliasUTUN adds address to the utun name as a /128 until the test ends
func aliasUTUN(t *testing.T, name string, address netip.Addr) {
	t.Helper()
	if err := runTool(ifconfigBin, name, "inet6", netip.PrefixFrom(address, 128).String(), "alias"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := runTool(ifconfigBin, name, "inet6", address.String(), "-alias"); err != nil {
			t.Error(err)
		}
	})
}

// routeIntoUTUN routes prefix out of the utun name until the test ends
func routeIntoUTUN(t *testing.T, prefix netip.Prefix, name string) {
	t.Helper()
	if err := runTool(routeBin, "-q", "-n", "add", "-inet6", prefix.String(), "-interface", name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := runTool(routeBin, "-q", "-n", "delete", "-inet6", prefix.String(), "-interface", name); err != nil {
			t.Error(err)
		}
	})
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
