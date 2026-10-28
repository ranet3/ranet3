// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package client

import (
	"net/netip"
	"slices"
	"testing"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/internal/config"
)

// XNU's own lookup answers this host's packet to loopback by lo0 from its one
// table, with no policy rules to name and the source left out of the lookup,
// and refuses an arrival before any rule is dumped
func TestDebugRouteLooksUpThroughXNU(t *testing.T) {
	c, _, _, _ := reloadOf(t, func(*config.Config) {})
	loopback := netip.MustParseAddr("127.0.0.1")
	info, err := c.DebugRoute(netip.Addr{}, loopback, "", "")
	if err != nil {
		t.Fatal(err)
	}
	k := info.Kernel
	if k == nil || !k.Route.Contains(loopback) || !slices.Equal(k.NextHops, []control.RouteNextHop{{Dev: "lo0"}}) || k.Table != 0 || k.Err != "" {
		t.Fatalf("this host's own packet to %s reads %+v", loopback, k)
	}
	if k.RuleErr != "this platform has no policy rules" || k.Rule != nil || k.Candidate != nil || k.NoSource {
		t.Errorf("this host's own packet to %s with no source names %+v, %q, no source %v", loopback, k.Rule, k.RuleErr, k.NoSource)
	}

	info, err = c.DebugRoute(netip.MustParseAddr("192.0.2.7"), loopback, "", "")
	if err != nil || !info.Kernel.NoSource || !info.Kernel.Route.Contains(loopback) {
		t.Errorf("this host's own packet from 192.0.2.7 to %s reads %+v, %v, want it looked up without its source", loopback, info.Kernel, err)
	}

	info, err = c.DebugRoute(netip.MustParseAddr("192.0.2.7"), loopback, "en0", "")
	if err != nil || info.Kernel == nil || info.Kernel.Why != control.WhyUnsupported || info.Kernel.Rule != nil || info.Kernel.RuleErr != "" {
		t.Errorf("an arrival on en0 reads %+v, %v, want it refused before the rules are dumped", info.Kernel, err)
	}
}
