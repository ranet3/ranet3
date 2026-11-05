// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package kernel

import (
	"errors"
	"net/netip"
	"os/exec"
	"slices"
	"testing"
	"time"
)

// The two interfaces the reads below move between.
const (
	// far above the indexes a host hands out
	// and a test that reaches the running kernel fails alike on every machine
	uplinkIndex = 916
	dockIndex   = 919
)

// namedDevices is the interface list these tests decide, so the two indexes
// above name the same devices on every machine the suite runs on.
type namedDevices struct{ Host }

func (namedDevices) InterfaceName(index int) (string, error) {
	switch index {
	case uplinkIndex:
		return "uplink0", nil
	case dockIndex:
		return "dock0", nil
	}
	return "", errors.New("no such interface")
}

// watchedMeshIndex stands for the tun in the reads below, an index no host hands out as uplinkIndex and dockIndex are
const watchedMeshIndex = 923

// readHost is a machine whose interfaces and defaults a test decides
type readHost struct {
	namedDevices
	interfaces []HostInterface
	linksErr   error
	v4, v6     RouteAnswer
}

func (h readHost) Links() ([]HostInterface, error) { return h.interfaces, h.linksErr }

func (h readHost) Lookup(destination, _ netip.Addr) (RouteAnswer, error) {
	answer := h.v4
	if destination.Is6() {
		answer = h.v6
	}
	if answer.Index == 0 {
		return RouteAnswer{}, ErrNoDefaultRoute
	}
	return answer, nil
}

// the read holds every up interface outside the mesh as a link of both families, the loopback among them, with its ready global unicast
// addresses: an IPv4 address on a point-to-point link is a host and its far end a peer, a broadcast link's broadcast is no peer
// a default that names the mesh is none of the host's own
func TestDarwinNetworkReadSkipsTheMeshAndDownInterfaces(t *testing.T) {
	gateway := netip.MustParseAddr("192.0.2.1")
	host := readHost{
		interfaces: []HostInterface{
			{Index: 1, Name: Loopback, Up: true, Loopback: true, Addresses: []HostAddress{
				{Prefix: prefix("127.0.0.1/8")}, {Prefix: prefix("::1/128")}, {Prefix: prefix("fe80::1/64")}}},
			{Index: uplinkIndex, Name: "uplink0", Up: true, Addresses: []HostAddress{
				{Prefix: prefix("192.0.2.10/24"), Far: netip.MustParseAddr("192.0.2.255")},
				{Prefix: prefix("fe80::1/64")},
				{Prefix: prefix("2001:db8::10/64"), Far: netip.IPv6Unspecified()},
				{Prefix: prefix("2001:db8::11/64"), Unready: true}}},
			{Index: dockIndex, Name: "dock0", Addresses: []HostAddress{{Prefix: prefix("198.51.100.1/24")}}},
			{Index: 920, Name: "utun4", Up: true, PointToPoint: true, Addresses: []HostAddress{
				{Prefix: prefix("203.0.113.7/24"), Far: netip.MustParseAddr("203.0.113.8")}}},
			{Index: watchedMeshIndex, Name: "utun9", Up: true, PointToPoint: true, Addresses: []HostAddress{
				{Prefix: prefix("10.99.0.1/32"), Far: netip.MustParseAddr("10.99.0.1")}, {Prefix: prefix("3fff:a::1/128")}}},
		},
		v4: RouteAnswer{Index: uplinkIndex, Gateway: gateway},
		v6: RouteAnswer{Index: watchedMeshIndex},
	}
	reader := hostReader{host: host, mesh: watchedMeshIndex}
	state, err := reader.read()
	if err != nil {
		t.Fatal(err)
	}
	want := NetworkState{
		IPv4: NetworkFamily{
			Default: DefaultRoute{Interface: "uplink0", Gateway: gateway}, Addresses: addrs("192.0.2.10", "203.0.113.7"),
			Links: []Link{
				{Name: Loopback},
				{Name: "uplink0", Prefixes: []netip.Prefix{prefix("192.0.2.10/24")}},
				{Name: "utun4", Prefixes: []netip.Prefix{prefix("203.0.113.7/32")}, Peers: []netip.Prefix{prefix("203.0.113.8/32")}},
			},
		},
		IPv6: NetworkFamily{
			Addresses: addrs("2001:db8::10"),
			Links:     []Link{{Name: Loopback}, {Name: "uplink0", Prefixes: []netip.Prefix{prefix("2001:db8::10/64")}}, {Name: "utun4"}},
		},
	}
	for _, family := range []struct{ got, want NetworkFamily }{{state.IPv4, want.IPv4}, {state.IPv6, want.IPv6}} {
		if family.got.Default != family.want.Default || !slices.Equal(family.got.Addresses, family.want.Addresses) || !sameLinks(family.got.Links, family.want.Links) {
			t.Errorf("a family reads as %+v, want %+v", family.got, family.want)
		}
	}

	host.v4 = RouteAnswer{}
	host.linksErr = errors.New("no listing")
	reader.host = host
	if _, err := reader.read(); err == nil {
		t.Error("a read without the interface list succeeded")
	}
}

// against the real kernel, an address on a utun this test creates signals as it comes and goes
// a route out of it to somewhere other than default, and an address on a second utun standing in for the mesh, signal nothing
// the default route is never touched
func TestDarwinNetworkWatchOnRealKernel(t *testing.T) {
	requireNetTest(t)
	mesh, uplink := createUTUN(t), createUTUN(t)
	w, err := WatchNetwork(nil, mesh)
	if err != nil {
		t.Fatalf("open the watch: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })
	for _, step := range []struct {
		name    string
		command []string
		signals bool
	}{
		{"an uplink address", []string{"ifconfig", uplink, "inet", "198.18.77.1", "198.18.77.2", "up"}, true},
		{"a route out of the uplink", []string{"route", "-n", "add", "-net", "198.51.100.0/24", "-interface", uplink}, false},
		{"the route gone", []string{"route", "-n", "delete", "-net", "198.51.100.0/24", "-interface", uplink}, false},
		{"an address on the mesh", []string{"ifconfig", mesh, "inet", "198.18.78.1", "198.18.78.2", "up"}, false},
		{"the mesh address gone", []string{"ifconfig", mesh, "inet", "198.18.78.1", "delete"}, false},
		{"the uplink address gone", []string{"ifconfig", uplink, "inet", "198.18.77.1", "delete"}, true},
	} {
		if out, err := exec.Command(step.command[0], step.command[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%s: %v: %s", step.name, err, out)
		}
		select {
		case change := <-w.Changes():
			if !step.signals {
				t.Errorf("%s signaled %+v", step.name, change.Families())
			}
		case <-time.After(quietWindow):
			if step.signals {
				t.Errorf("%s signaled nothing", step.name)
			}
		}
	}
}
