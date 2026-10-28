// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package kernel

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// defaultRoutesOnHost is every unscoped default in the table, described so two
// snapshots can be compared.
func defaultRoutesOnHost(t *testing.T) []string {
	t.Helper()
	rib, err := route.FetchRIB(unix.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		t.Fatal(err)
	}
	messages, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, message := range messages {
		rm, ok := message.(*route.RouteMessage)
		if !ok || rm.Type != unix.RTM_GET || rm.Flags&unix.RTF_IFSCOPE != 0 {
			continue
		}
		for _, destination := range defaultPrefixes {
			if !isDefaultKey(rm, destination) {
				continue
			}
			gateway := netip.Addr{}
			if len(rm.Addrs) > unix.RTAX_GATEWAY {
				gateway, _ = addressFromRouteAddr(rm.Addrs[unix.RTAX_GATEWAY])
			}
			out = append(out, fmt.Sprintf("%s index %d via %s", destination, rm.Index, gateway))
		}
	}
	return out
}

func sameDefaults(before, after []string) bool {
	if len(before) != len(after) {
		return false
	}
	held := make(map[string]int, len(before))
	for _, line := range before {
		held[line]++
	}
	for _, line := range after {
		held[line]--
	}
	for _, count := range held {
		if count != 0 {
			return false
		}
	}
	return true
}

// boundReach resolves the route a socket bound to index would take, without
// sending anything: connect on a UDP socket consults the forwarding table and
// puts nothing on the wire. Index zero leaves the socket unbound.
func boundReach(index int, target netip.Addr) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if index != 0 {
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_BOUND_IF, index); err != nil {
			return err
		}
	}
	return unix.Connect(fd, &unix.SockaddrInet4{Addr: target.As4(), Port: 9})
}

// The lookup of the host's own default never answers with the mesh's own tun.
// Once the mesh holds routes covering the address space, an ordinary
// longest-prefix lookup does, and the cover would wait on a default of the
// mesh's own.
func TestDefaultInterfaceIgnoresTheMeshItself(t *testing.T) {
	requireNetTest(t)
	mesh, _ := createUTUNWithFD(t)
	setInterfaceUp(t, mesh)
	device, err := net.InterfaceByName(mesh)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := newPlatform(
		Table{ID: DefaultTable, Proto: DefaultProtocol},
		Runtime{Interface: mesh, BoundUnderlay: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = opened.Close() })
	plat := opened.(*routePlatform)
	if err := plat.AddAddr(prefix("198.51.100.1/24")); err != nil {
		t.Fatal(err)
	}
	if err := plat.AddAddr(prefix("2001:db8:99::1/64")); err != nil {
		t.Fatal(err)
	}
	for _, half := range []Route{
		{Destination: prefix("0.0.0.0/1")}, {Destination: prefix("128.0.0.0/1")},
		{Destination: prefix("::/1")}, {Destination: prefix("8000::/1")},
	} {
		if err := plat.AddRoute(half); err != nil {
			t.Logf("could not install %s: %v", half.Destination, err)
			continue
		}
		t.Cleanup(func() { _ = plat.DelRoute(half) })
	}

	// The ordinary question answers with the tun, which is the trap.
	if answer, err := routeRequest(netip.IPv4Unspecified(), netip.Addr{}); err == nil && answer.Index != plat.index {
		t.Logf("a longest-prefix lookup answered index %d rather than the tun, so the trap is not armed here", answer.Index)
	}
	for _, family := range []netip.Addr{netip.IPv4Unspecified(), netip.IPv6Unspecified()} {
		index, _, err := lookupDefault(runningKernel{}, device.Index, family)
		switch {
		case errors.Is(err, ErrNoDefaultRoute):
			t.Logf("with the mesh holding the address space the lookup of %s reports no default", family)
		case err != nil:
			t.Errorf("look up the default of %s: %v", family, err)
		case index == plat.index:
			t.Errorf("the lookup of %s answered the mesh tun itself (index %d)", family, index)
		default:
			t.Logf("the lookup of %s answered index %d with the mesh holding the address space", family, index)
		}
	}
}
