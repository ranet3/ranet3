// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"net"
	"strings"
	"testing"

	"github.com/spf13/cobra"
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

// the addresses complete to nothing and --iif to the host's links
func TestDebugRouteCompletes(t *testing.T) {
	socket := serveStub(t)
	out, err := execute(t, cobra.ShellCompRequestCmd, "debug", "route", "--control", socket, "")
	if err != nil {
		t.Fatal(err)
	}
	if offered, _, _ := strings.Cut(out, ":"); strings.TrimSpace(offered) != "" || !strings.Contains(out, ":4") {
		t.Errorf("an address completed to %q, want nothing and no files", out)
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
