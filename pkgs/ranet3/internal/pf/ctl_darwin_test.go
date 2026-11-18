// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package pf

import (
	"errors"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

const (
	// testAnchor is the anchor the root tests load, beside the daemon's own
	testAnchor = "com.apple/ranet3-test"
	// unrouted is an interface name no XNU driver gives, so no packet arrives
	// on it
	unrouted = "ranet3t0"
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Getenv("RANET3_DARWIN_NETTEST") != "1" {
		t.Skip("set RANET3_DARWIN_NETTEST=1 and run as root to drive the real pf")
	}
	if os.Geteuid() != 0 {
		t.Skip("run as root to drive the real pf")
	}
}

// clearTestAnchor withdraws the test anchor before a test begins, since a run
// that ended with no cleanup, as a test timeout's panic does, leaves what it
// loaded there
func clearTestAnchor(t *testing.T, ctl Ctl) {
	t.Helper()
	if err := ctl.Withdraw(testAnchor); err != nil {
		t.Fatal(err)
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
	clearTestAnchor(t, ctl)
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
	// an IPv4-compatible address in <overlay> and as a drop's source,
	// which pfctl prints with its last 32 bits dotted, reads back as written
	compatible := Ruleset{
		Tables: []Table{{Name: "overlay", Const: true, Prefixes: []netip.Prefix{
			netip.MustParsePrefix("192.0.2.1/32"), netip.MustParsePrefix("::c000:201/128"),
		}}},
		Rules: []Rule{
			{Action: Pass, Quick: true, Interface: "lo0", From: Address{Table: "overlay"}, Label: "accept via lo0"},
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

// a translation rule loaded into the anchor with -N, which leaves the anchor's
// filter rules as they are, reads back as ErrUnreadable naming it, a load of
// the anchor whole replaces it, and a withdrawal empties the anchor's
// translation rules as pfctl -s nat prints them. Persistent tables pfctl -T
// add makes in the anchor, which the filter never names, one name holding a
// tab and one a newline, read back under their names and are gone after a
// load.
// The rule is an rdr pass of a documentation source on an interface no packet
// arrives on, the test sends no packet, and it leaves the main ruleset's
// filter and translation rules, every other anchor and whether pf runs as it
// found them.
func TestPfTranslationRuleInTheAnchorIsAFaultALoadAndAWithdrawalRemove(t *testing.T) {
	requireRoot(t)
	ctl := NewCtl()
	clearTestAnchor(t, ctl)
	if held, err := ctl.Read(testAnchor); err != nil || len(held.Rules) != 0 || len(held.Tables) != 0 {
		t.Fatalf("%s reads %+v (%v) after its withdrawal", testAnchor, held, err)
	}
	found := func() (string, error) {
		var b strings.Builder
		for _, args := range [][]string{{"-sr"}, {"-s", "nat"}, {"-s", "Anchors", "-v"}} {
			out, err := ctl.run("", args...)
			if err != nil {
				return "", err
			}
			for line := range strings.SplitSeq(out, "\n") {
				if strings.TrimSpace(line) != testAnchor {
					b.WriteString(line + "\n")
				}
			}
		}
		return b.String(), nil
	}
	before, err := found()
	if err != nil {
		t.Fatal(err)
	}
	running, err := ctl.Running()
	if err != nil {
		t.Fatal(err)
	}
	translations := func() string {
		t.Helper()
		out, err := ctl.run("", "-a", testAnchor, "-s", "nat")
		if err != nil {
			t.Error(err)
		}
		return strings.TrimSpace(out)
	}
	t.Cleanup(func() {
		if err := ctl.Withdraw(testAnchor); err != nil {
			t.Error(err)
		}
		if left := translations(); left != "" {
			t.Errorf("the test left %s holding %q", testAnchor, left)
		}
		if after, err := found(); err != nil || after != before {
			t.Errorf("the test left pf reading\n%s(%v), which it found reading\n%s", after, err, before)
		}
		if now, err := ctl.Running(); err != nil || now != running {
			t.Errorf("the test left pf running %v (%v), which it found running %v", now, err, running)
		}
	})

	filter := Ruleset{Rules: []Rule{{Action: Block, Quick: true, Interface: unrouted, Family: Inet,
		From: Address{Prefix: netip.MustParsePrefix("192.0.2.0/24")}, Label: "drop ipv4 source 192.0.2.0/24"}}}
	if err := ctl.Load(testAnchor, filter); err != nil {
		t.Fatal(err)
	}
	rdr := "rdr pass on " + unrouted + " inet from 192.0.2.0/24 to any -> 192.0.2.1\n"
	translate := func() {
		t.Helper()
		if _, err := ctl.run(rdr, "-a", testAnchor, "-N", "-f", "-"); err != nil {
			t.Fatal(err)
		}
	}

	translate()
	printed := translations()
	t.Logf("pfctl -s nat prints %q as %q", rdr, printed)
	if !strings.Contains(printed, "rdr pass on "+unrouted) {
		t.Fatalf("pfctl -s nat prints %q after the rdr rule's load", printed)
	}
	out, err := ctl.run("", "-a", testAnchor, "-sr", "-vv")
	if err != nil {
		t.Fatal(err)
	}
	if rules, err := ParseRules(out); err != nil || !(Readback{Rules: rules}).Ruleset().Equal(filter) {
		t.Errorf("after the rdr rule's load the filter rules read %q (%v), want %+v", out, err, filter)
	}
	if _, err := ctl.Read(testAnchor); !errors.Is(err, ErrUnreadable) || !strings.Contains(err.Error(), "rdr pass on "+unrouted) {
		t.Errorf("the anchor holding the rdr rule reads back as %v, want ErrUnreadable naming it", err)
	}

	if err := ctl.Load(testAnchor, filter); err != nil {
		t.Fatal(err)
	}
	if left := translations(); left != "" {
		t.Errorf("the anchor's load left %q", left)
	}
	if got, err := ctl.Read(testAnchor); err != nil || !got.Ruleset().Equal(filter) {
		t.Errorf("the anchor loaded whole reads back as %+v (%v), want %+v", got, err, filter)
	}

	strays := []string{"stray", "x\ty", "x\ny"}
	for _, name := range strays {
		if _, err := ctl.run("", "-a", testAnchor, "-t", name, "-T", "add", "192.0.2.1"); err != nil {
			t.Fatal(err)
		}
	}
	got, err := ctl.Read(testAnchor)
	names := make([]string, len(got.Tables))
	for i, table := range got.Tables {
		names[i] = table.Name
	}
	slices.Sort(names)
	if err != nil || !slices.Equal(names, strays) {
		t.Fatalf("after pfctl -T add of %q the anchor reads %+v (%v)", strays, got, err)
	}
	if err := ctl.Load(testAnchor, filter); err != nil {
		t.Fatal(err)
	}
	if got, err := ctl.Read(testAnchor); err != nil || !got.Ruleset().Equal(filter) {
		t.Errorf("the load over the tables %q reads back as %+v (%v), want %+v", strays, got, err, filter)
	}

	translate()
	if err := ctl.Withdraw(testAnchor); err != nil {
		t.Fatal(err)
	}
	if left := translations(); left != "" {
		t.Errorf("the withdrawal left %q", left)
	}
	if out, err := ctl.run("", "-a", testAnchor, "-sr"); err != nil || strings.TrimSpace(out) != "" {
		t.Errorf("the withdrawal left the filter rules %q (%v)", out, err)
	}
}
