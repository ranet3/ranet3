// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package kernel

import (
	"errors"
	"net"
	"net/netip"
	"os/exec"
	"slices"
	"testing"
	"time"
)

// watchedMeshIndex stands for the tun in the reads below, an index no host hands out as uplinkIndex and dockIndex are
const watchedMeshIndex = 923

// readHost is a machine whose addresses and defaults a test decides
type readHost struct {
	namedDevices
	assigned map[int][]netip.Prefix
	v4, v6   RouteAnswer
}

func (h readHost) Addresses(index int) ([]netip.Prefix, error) { return h.assigned[index], nil }

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

// the read keeps the global unicast addresses of the up interfaces outside the mesh, per family
// a default that names the mesh is none of the host's own
func TestDarwinNetworkReadSkipsTheMeshAndDownInterfaces(t *testing.T) {
	gateway := netip.MustParseAddr("192.0.2.1")
	host := readHost{
		assigned: map[int][]netip.Prefix{
			uplinkIndex:      {prefix("192.0.2.10/24"), prefix("fe80::1/64"), prefix("2001:db8::10/64")},
			dockIndex:        {prefix("198.51.100.1/24")},
			watchedMeshIndex: {prefix("10.99.0.1/32"), prefix("3fff:a::1/128")},
		},
		v4: RouteAnswer{Index: uplinkIndex, Gateway: gateway},
		v6: RouteAnswer{Index: watchedMeshIndex},
	}
	reader := hostReader{host: host, mesh: watchedMeshIndex, interfaces: func() ([]net.Interface, error) {
		return []net.Interface{
			{Index: uplinkIndex, Name: "uplink0", Flags: net.FlagUp},
			{Index: dockIndex, Name: "dock0"},
			{Index: watchedMeshIndex, Name: "utun9", Flags: net.FlagUp},
		}, nil
	}}
	state, err := reader.read()
	if err != nil {
		t.Fatal(err)
	}
	want := NetworkState{
		IPv4: NetworkFamily{Default: DefaultRoute{Interface: "uplink0", Gateway: gateway}, Addresses: addrs("192.0.2.10")},
		IPv6: NetworkFamily{Addresses: addrs("2001:db8::10")},
	}
	if state.IPv4.Default != want.IPv4.Default || state.IPv6.Default != want.IPv6.Default ||
		!slices.Equal(state.IPv4.Addresses, want.IPv4.Addresses) || !slices.Equal(state.IPv6.Addresses, want.IPv6.Addresses) {
		t.Errorf("the host reads as %+v, want %+v", state, want)
	}

	host.v4 = RouteAnswer{}
	reader.host = host
	reader.interfaces = func() ([]net.Interface, error) { return nil, errors.New("no listing") }
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
