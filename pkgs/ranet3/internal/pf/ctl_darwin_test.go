// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package pf

import (
	"net/netip"
	"os"
	"strings"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// testAnchor is the anchor the root tests load, beside the daemon's own
const testAnchor = "com.apple/ranet3-test"

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Getenv("RANET3_DARWIN_NETTEST") != "1" {
		t.Skip("set RANET3_DARWIN_NETTEST=1 and run as root to drive the real pf")
	}
	if os.Geteuid() != 0 {
		t.Skip("run as root to drive the real pf")
	}
}

// with pfctl as the oracle: every drawn anchor loaded into pf reads back as
// rendered, its rules in order with no counter moved, one holding a prefix
// pfctl's parse would change is refused before pfctl runs, an
// IPv4-compatible address reads back as written, and a withdrawal
// leaves the anchor empty. pf stays disabled throughout, so no drawn rule filters the host's
// own traffic, and pfctl loads and reads an anchor all the same.
func TestPfLoadedAnchorReadsBackAsRendered(t *testing.T) {
	requireRoot(t)
	ctl := NewCtl()
	running, err := ctl.Running()
	if err != nil {
		t.Fatal(err)
	}
	if running {
		t.Skip("pf is enabled, and the drawn rules would filter this host's traffic")
	}
	t.Cleanup(func() {
		if err := ctl.Withdraw(testAnchor); err != nil {
			t.Error(err)
		}
	})
	pbt.Check(t, func(ht *hegel.T) {
		rs := hegel.Draw(ht, hegel.Composite(drawRuleset))
		// pfctl would load such an anchor with another prefix, so the load
		// refuses it before pfctl runs
		if pfctlClears(rs) {
			if err := ctl.Load(testAnchor, rs); err == nil || !strings.Contains(err.Error(), "fe80::/10") {
				ht.Fatalf("an anchor holding a prefix pfctl would change loads: %v\n%+v", err, rs)
			}
			return
		}
		if err := ctl.Load(testAnchor, rs); err != nil {
			ht.Fatalf("%v\n%+v", err, rs)
		}
		got, err := ctl.Read(testAnchor)
		if err != nil {
			ht.Fatal(err)
		}
		if !got.Ruleset().Equal(rs) {
			text, _ := rs.Render()
			ht.Fatalf("loaded as\n%s\nit reads back as\n%+v", text, got)
		}
		for _, c := range got.Rules {
			if c.Packets != 0 || c.Bytes != 0 {
				ht.Fatalf("a rule just loaded reads counters %+v", c)
			}
		}
	})
	// an IPv4-compatible address in <ranet3_overlay> and as a drop's source,
	// which pfctl prints with its last 32 bits dotted, reads back as written
	compatible := Ruleset{
		Tables: []Table{{Name: "ranet3_overlay", Const: true, Prefixes: []netip.Prefix{
			netip.MustParsePrefix("192.0.2.1/32"), netip.MustParsePrefix("::c000:201/128"),
		}}},
		Rules: []Rule{
			{Action: Pass, Quick: true, Interface: "lo0", From: Address{Table: "ranet3_overlay"}, Label: "accept via lo0"},
			{Action: Block, Quick: true, Interface: "utun250", NotInterface: true, Family: Inet6,
				From: Address{Prefix: netip.MustParsePrefix("::c000:201/128")}, Label: "drop ipv6 source ::c000:201/128"},
		},
	}
	if err := ctl.Load(testAnchor, compatible); err != nil {
		t.Fatal(err)
	}
	if got, err := ctl.Read(testAnchor); err != nil || !got.Ruleset().Equal(compatible) {
		t.Errorf("an IPv4-compatible address reads back as %+v (%v), want %+v", got, err, compatible)
	}
	if err := ctl.Withdraw(testAnchor); err != nil {
		t.Fatal(err)
	}
	if got, err := ctl.Read(testAnchor); err != nil || len(got.Rules) != 0 || len(got.Tables) != 0 {
		t.Errorf("the withdrawn anchor reads %+v (%v)", got, err)
	}
}
