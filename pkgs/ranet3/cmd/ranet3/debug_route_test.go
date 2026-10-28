// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"encoding/json"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"ranet3.com/pkgs/ranet3/control"
)

// arguments debug route cannot take are refused before the daemon is asked,
// the addresses' own refusals left to control.ParseRoutePacket's test
func TestDebugRouteRefusesItsArguments(t *testing.T) {
	socket := serveStub(t)
	for name, args := range map[string][]string{
		"one address":     {"192.0.2.1"},
		"no such link":    {"192.0.2.1", "203.0.113.1", "--iif", "nosuchlink0"},
		"three addresses": {"192.0.2.1", "203.0.113.1", "198.51.100.1"},
	} {
		if out, err := execute(t, append([]string{"debug", "route", "--control", socket}, args...)...); err == nil {
			t.Errorf("%s was followed: %q", name, out)
		}
	}
}

// routeStub answers debug route with the arrival it was asked about
type routeStub struct{ stubSource }

func (routeStub) DebugRoute(src, dst netip.Addr, iif, peer string) (control.RouteInfo, error) {
	return control.RouteInfo{Src: src, Dst: dst, IIF: iif, Peer: peer}, nil
}

// --peer reaches the daemon as the node whose session the packet arrives
// through, and beside --iif is refused before the daemon is asked, since a
// packet arrives one way
func TestDebugRouteAsksThroughTheSessionNamed(t *testing.T) {
	socket := serve(t, routeStub{})
	out, err := execute(t, "debug", "route", "--control", socket, "--json", "--peer", "example/gateway", "192.0.2.1", "192.0.2.2")
	if err != nil {
		t.Fatal(err)
	}
	var info control.RouteInfo
	if err := json.Unmarshal([]byte(out), &info); err != nil || info.Peer != "example/gateway" || info.IIF != "" {
		t.Errorf("--peer asked the daemon about %+v (%v), want a packet through the session of example/gateway", info, err)
	}
	links, err := net.Interfaces()
	if err != nil || len(links) == 0 {
		t.Skipf("this host lists no links: %v", err)
	}
	if out, err := execute(t, "debug", "route", "--control", socket, "--iif", links[0].Name, "--peer", "example/gateway", "192.0.2.1", "192.0.2.2"); err == nil {
		t.Errorf("--iif and --peer together were followed: %q", out)
	}
}

// the addresses complete to nothing, --peer to the peers the daemon names, and --iif to the host's links
func TestDebugRouteCompletes(t *testing.T) {
	socket := serveStub(t)
	out, err := execute(t, cobra.ShellCompRequestCmd, "debug", "route", "--control", socket, "")
	if err != nil {
		t.Fatal(err)
	}
	if offered, _, _ := strings.Cut(out, ":"); strings.TrimSpace(offered) != "" || !strings.Contains(out, ":4") {
		t.Errorf("an address completed to %q, want nothing and no files", out)
	}
	out, err = execute(t, cobra.ShellCompRequestCmd, "debug", "route", "--control", socket, "192.0.2.1", "198.51.100.1", "--peer", "")
	if err != nil {
		t.Fatal(err)
	}
	if offered, _, _ := strings.Cut(out, ":"); strings.TrimSpace(offered) != "example/gateway" || !strings.Contains(out, ":4") {
		t.Errorf("--peer completed to %q, want example/gateway and no files", out)
	}
	links, err := net.Interfaces()
	if err != nil || len(links) == 0 {
		t.Skipf("this host lists no links: %v", err)
	}
	out, err = execute(t, cobra.ShellCompRequestCmd, "debug", "route", "--control", socket, "192.0.2.1", "198.51.100.1", "--iif", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, link := range links {
		if !strings.Contains(out, link.Name+"\n") {
			t.Errorf("--iif completed to %q, want it to offer %s", out, link.Name)
		}
	}
}
