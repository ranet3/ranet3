// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package kernel

import (
	"errors"
	"fmt"
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

// lookupDefault names the host's own default interface while another program's
// utun holds the halves over the zero address, which a longest-prefix lookup
// answers with
func TestLookupDefaultIgnoresAnotherProgramsHalves(t *testing.T) {
	requireNetTest(t)
	mesh, _ := createUTUNWithFD(t)
	setInterfaceUp(t, mesh)
	meshIndex := interfaceIndex(t, mesh)
	hosts := map[netip.Addr]int{}
	for _, family := range []netip.Addr{netip.IPv4Unspecified(), netip.IPv6Unspecified()} {
		index, _, err := lookupDefault(runningKernel{}, meshIndex, family)
		switch {
		case errors.Is(err, ErrNoDefaultRoute):
			t.Logf("the host has no default of %s, so its family is not asked", family)
		case err != nil:
			t.Fatalf("look up the default of %s: %v", family, err)
		default:
			hosts[family] = index
		}
	}
	if len(hosts) == 0 {
		t.Skip("the host has no default of either family")
	}

	other, _ := createUTUNWithFD(t)
	setInterfaceUp(t, other)
	plat := testTUNPlatform(t, other)
	if err := plat.AddAddr(prefix("198.51.100.1/24")); err != nil {
		t.Fatal(err)
	}
	if err := plat.AddAddr(prefix("2001:db8:99::1/64")); err != nil {
		t.Fatal(err)
	}
	halves := map[netip.Addr][]Route{
		netip.IPv4Unspecified(): {{Destination: prefix("0.0.0.0/1")}, {Destination: prefix("128.0.0.0/1")}},
		netip.IPv6Unspecified(): {{Destination: prefix("::/1")}, {Destination: prefix("8000::/1")}},
	}
	for family, host := range hosts {
		for _, half := range halves[family] {
			if err := plat.AddRoute(half); err != nil {
				t.Fatalf("install %s out of %s: %v", half.Destination, other, err)
			}
			t.Cleanup(func() { _ = plat.DelRoute(half) })
		}
		if answer, err := routeRequest(family, netip.Addr{}); err != nil || answer.Index != plat.index {
			t.Fatalf("a longest-prefix lookup of %s answered %v, %v, want %s's index %d", family, answer, err, other, plat.index)
		}
		index, _, err := lookupDefault(runningKernel{}, meshIndex, family)
		if err != nil || index != host {
			t.Errorf("with %s holding the halves the lookup of %s answered index %d, %v, want the host's index %d", other, family, index, err, host)
		}
	}
}
