// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package client

import (
	"net/netip"
	"reflect"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/schema"
)

// exitLeafStart is a node running the reconciler and the border, which cap.exit needs
func exitLeafStart(old *config.Config) {
	old.Cap.Table = &kernel.Table{}
	old.Cap.Border = &egress.Border{Overlay: []schema.Prefix{schema.MustPrefix("192.0.2.0/24"), schema.MustPrefix("3fff::/20")}}
}

// a reload adding cap.exit hands the reconciler its table running the mode, and one removing it hands the table in mode off
// each applies in place, and a forward list written in another order hands nothing
func TestReloadAddingAndRemovingCapExitHandsTheReconcilerItsMode(t *testing.T) {
	c, path, reconciler, bus := reloadOf(t, exitLeafStart)
	next := *c.config()
	next.Cap.Exit = &kernel.ExitMode{Forward: []string{"docker*", "br-*"}}
	writeConfig(t, path, &next)
	if err := c.ReloadFrom(path); err != nil {
		t.Fatalf("a reload adding cap.exit was refused: %v", err)
	}
	want := &kernel.ExitMode{Forward: []string{"br-*", "docker*"}}
	if len(reconciler.tables) != 1 || !reflect.DeepEqual(reconciler.tables[0].Normalized().Mode(), want) {
		t.Fatalf("the reconciler was handed %+v, want one table running %+v", reconciler.tables, want)
	}
	if got := lastReload(t, bus)["applied"]; got != "cap.exit" {
		t.Errorf("the reload was recorded as applying %q, want cap.exit", got)
	}

	next.Cap.Exit = &kernel.ExitMode{Forward: []string{"br-*", "docker*", "br-*"}}
	writeConfig(t, path, &next)
	if err := c.ReloadFrom(path); err != nil {
		t.Fatal(err)
	}
	if len(reconciler.tables) != 1 {
		t.Errorf("a forward list in another order handed the reconciler %d tables in all", len(reconciler.tables))
	}

	next.Cap.Exit = nil
	writeConfig(t, path, &next)
	if err := c.ReloadFrom(path); err != nil {
		t.Fatalf("a reload removing cap.exit was refused: %v", err)
	}
	if len(reconciler.tables) != 2 || reconciler.tables[1].Mode() != nil {
		t.Fatalf("the reconciler was handed %+v, want a second table in mode off", reconciler.tables)
	}
	if got := lastReload(t, bus)["applied"]; got != "cap.exit" {
		t.Errorf("the reload was recorded as applying %q, want cap.exit", got)
	}
}

// a reload changing fallback, inbound or lan applies in place, handing the reconciler one table running the new mode, and inbound or lan written in another order or inbound split another way hands nothing
func TestReloadChangingFallbackOrInboundHandsTheReconcilerOneTable(t *testing.T) {
	c, path, reconciler, bus := reloadOf(t, func(old *config.Config) {
		exitLeafStart(old)
		old.Cap.Exit = &kernel.ExitMode{}
	})
	next := *c.config()
	lan := []schema.Prefix{schema.MustPrefix("198.51.100.0/24"), schema.MustPrefix("2001:db8:a::/64")}
	for i, step := range []struct {
		mode   kernel.ExitMode
		passes int
	}{
		{kernel.ExitMode{Fallback: kernel.FallbackNone}, 1},
		{kernel.ExitMode{Fallback: kernel.FallbackNone, Inbound: []string{"22/tcp", "60000-61000/udp"}}, 2},
		{kernel.ExitMode{Fallback: kernel.FallbackNone, Inbound: []string{"60000-60500/udp", "60501-61000/udp", "22/tcp"}}, 2},
		{kernel.ExitMode{Fallback: kernel.FallbackNone, Inbound: []string{"22/tcp"}}, 3},
		{kernel.ExitMode{Fallback: kernel.FallbackNone, Inbound: []string{"22/tcp"}, LAN: lan}, 4},
		{kernel.ExitMode{Fallback: kernel.FallbackNone, Inbound: []string{"22/tcp"}, LAN: []schema.Prefix{lan[1], lan[0]}}, 4},
		{kernel.ExitMode{Fallback: kernel.FallbackNone, Inbound: []string{"22/tcp"}, LAN: lan[1:]}, 5},
		{kernel.ExitMode{Fallback: kernel.FallbackUplink}, 6},
	} {
		next.Cap.Exit = &step.mode
		writeConfig(t, path, &next)
		if err := c.ReloadFrom(path); err != nil {
			t.Fatalf("step %d: the reload to %+v was refused: %v", i, step.mode, err)
		}
		if len(reconciler.tables) != step.passes {
			t.Fatalf("step %d: the reconciler was handed %d tables in all, want %d", i, len(reconciler.tables), step.passes)
		}
		want := step.mode.Normalized()
		if got := reconciler.tables[len(reconciler.tables)-1].Normalized().Mode(); !reflect.DeepEqual(got, &want) {
			t.Errorf("step %d: the reconciler runs %+v, want %+v", i, got, want)
		}
		if got := lastReload(t, bus)["applied"]; got != "cap.exit" && i != 2 && i != 5 {
			t.Errorf("step %d: the reload was recorded as applying %q, want cap.exit", i, got)
		}
	}
	// lan reaching into the overlay and lan under fallback = "uplink" are refused, handing the reconciler nothing
	for _, mode := range []kernel.ExitMode{
		{Fallback: kernel.FallbackNone, LAN: []schema.Prefix{schema.MustPrefix("192.0.2.128/25")}},
		{Fallback: kernel.FallbackUplink, LAN: lan},
	} {
		next.Cap.Exit = &mode
		writeConfig(t, path, &next)
		if err := c.ReloadFrom(path); err == nil {
			t.Errorf("the reload to %+v was taken", mode)
		}
		if len(reconciler.tables) != 6 {
			t.Errorf("a refused reload to %+v handed the reconciler a table, %d in all", mode, len(reconciler.tables))
		}
	}
}

// a reload adding, changing and removing cap.exit via applies in place: the mesh steers by default along the path written, sent from the node's overlay address
// the reconciler is handed the path, and the tun's plan moves by the path's overhead, counting an outer IPv6 header, the fixed part of the segment routing header and 16 bytes a segment
func TestReloadOfCapExitViaSwapsTheDefaultPolicyAndTheMTU(t *testing.T) {
	a, b := schema.MustAddr("3fff:b:0:306::3"), schema.MustAddr("3fff:b:0:206::1")
	c, path, reconciler, bus := reloadOf(t, func(old *config.Config) {
		exitLeafStart(old)
		old.Cap.Table.Addresses = []schema.Prefix{schema.MustPrefix("192.0.2.2/24"), schema.MustPrefix("3fff::2/20")}
		old.Cap.Exit = &kernel.ExitMode{}
	})
	segmentsOf(t, c)
	header := func(segments int) int { return 40 + 8 + 16*segments }
	from := 1400
	for _, via := range [][]schema.Addr{{a}, {a, b}, {b, a}, nil} {
		next := *c.config()
		next.Cap.Exit = &kernel.ExitMode{Via: via}
		plan, err := c.planTUN(c.config(), &next)
		if err != nil {
			t.Fatal(err)
		}
		to := 1400
		if len(via) != 0 {
			to -= header(len(via))
		}
		if !plan.tables || plan.from != from || plan.to != to {
			t.Errorf("via %v: the plan rebuilds the tables %t and moves the tun from %d to %d bytes, want from %d to %d", via, plan.tables, plan.from, plan.to, from, to)
		}
		writeConfig(t, path, &next)
		if err := c.ReloadFrom(path); err != nil {
			t.Fatalf("a reload to via %v was refused: %v", via, err)
		}
		policy := c.Mesh.Steering().Default()
		switch {
		case len(via) == 0 && policy != nil:
			t.Errorf("with via removed the mesh steers by default along %v", policy)
		case len(via) != 0 && (policy == nil || policy.Source != netip.MustParseAddr("3fff::2") || len(policy.Path) != len(via) || policy.Path[0] != via[0].Addr):
			t.Errorf("with via %v the mesh steers by default along %+v", via, policy)
		}
		if got := c.Mesh.Steering().Overhead(); got != 1400-to {
			t.Errorf("with via %v the steering table costs %d bytes, want %d", via, got, 1400-to)
		}
		if got := reconciler.tables[len(reconciler.tables)-1].Mode(); got == nil || !reflect.DeepEqual(got.Via, via) {
			t.Errorf("with via %v the reconciler was handed %+v", via, got)
		}
		if got := lastReload(t, bus)["applied"]; got != "cap.exit" {
			t.Errorf("a reload to via %v was recorded as applying %q, want cap.exit", via, got)
		}
		from = to
	}
}

// a reload moving cap.segment source alone hands the reconciler the outer source it resolves the path's SIDs from, which the mesh's default policy is sent from too
// removing it hands back the node's overlay address
func TestReloadOfTheOuterSourceAloneHandsTheReconcilerTheSource(t *testing.T) {
	via := []schema.Addr{schema.MustAddr("3fff:b:0:306::3")}
	c, path, reconciler, bus := reloadOf(t, func(old *config.Config) {
		exitLeafStart(old)
		old.Cap.Table.Addresses = []schema.Prefix{schema.MustPrefix("192.0.2.2/24"), schema.MustPrefix("3fff::2/20")}
		old.Cap.Exit = &kernel.ExitMode{Via: via}
	})
	segmentsOf(t, c)
	for _, written := range []string{"3fff::5", ""} {
		next := *c.config()
		segment := next.Segments()
		segment.Source = schema.Addr{}
		want := netip.MustParseAddr("3fff::2")
		if written != "" {
			segment.Source = schema.MustAddr(written)
			want = segment.Source.Addr
		}
		next.Cap.Segment = &segment
		writeConfig(t, path, &next)
		handed := len(reconciler.tables)
		if err := c.ReloadFrom(path); err != nil {
			t.Fatalf("a reload writing cap.segment source %q was refused: %v", written, err)
		}
		// a table WithPathSource(want) leaves as it is already sends the path from want
		if len(reconciler.tables) != handed+1 || !reflect.DeepEqual(reconciler.tables[handed], reconciler.tables[handed].WithPathSource(want)) {
			t.Fatalf("with cap.segment source %q the reconciler was handed %+v, want one more table sending the path from %s", written, reconciler.tables, want)
		}
		if policy := c.Mesh.Steering().Default(); policy == nil || policy.Source != want {
			t.Errorf("with cap.segment source %q the mesh steers by default along %+v, want it sent from %s", written, policy, want)
		}
		if got := lastReload(t, bus)["applied"]; got != "cap.segment" {
			t.Errorf("a reload writing cap.segment source %q was recorded as applying %q, want cap.segment", written, got)
		}
	}
}

// eth0 carries the host's IPv4 default and wlan0 its IPv6 one, beside a bridge
var exitHost = kernel.NetworkState{
	IPv4: kernel.NetworkFamily{Default: kernel.DefaultRoute{Interface: "eth0"}, Links: []kernel.Link{{Name: "docker0"}, {Name: "eth0"}, {Name: "wlan0"}}},
	IPv6: kernel.NetworkFamily{Default: kernel.DefaultRoute{Interface: "wlan0"}, Links: []kernel.Link{{Name: "docker0"}, {Name: "eth0"}, {Name: "wlan0"}}},
}

// forward naming the tun or the link either default leaves by is refused at the start and at a reload, as the watch reads the host
// a pattern matching one is left to the reconciler, which skips it, and a reload refused here hands the reconciler nothing
func TestForwardRefusesTheTunAndTheUplinkAtStartAndAtReload(t *testing.T) {
	network := &fakeNetwork{current: exitHost}
	for _, entry := range []string{"ranet7", "eth0", "wlan0"} {
		cfg := &config.Config{}
		exitLeafStart(cfg)
		cfg.Cap.Exit = &kernel.ExitMode{Forward: []string{"docker0", entry}}
		says := cfg.Cap.Exit.RefuseNamed("ranet7", exitHost)
		if err := refuseForwardedHere(cfg, "ranet7", network); err == nil || says == nil || err.Error() != says.Error() {
			t.Errorf("a start forwarding %s was refused with %v, want %v", entry, err, says)
		}

		c, path, reconciler, _ := reloadOf(t, exitLeafStart)
		c.Mesh.Name, c.network = "ranet7", network
		next := *c.config()
		next.Cap.Exit = cfg.Cap.Exit
		writeConfig(t, path, &next)
		if err := c.ReloadFrom(path); err == nil || says == nil || err.Error() != says.Error() {
			t.Errorf("a reload forwarding %s was refused with %v, want %v", entry, err, says)
		}
		if len(reconciler.tables) != 0 || c.config().Cap.Exit != nil {
			t.Errorf("a reload forwarding %s that was refused handed the reconciler %+v and stored cap.exit %+v", entry, reconciler.tables, c.config().Cap.Exit)
		}
	}
	for _, forward := range [][]string{{"docker0"}, {"eth*", "wlan?"}, {"ranet*"}} {
		cfg := &config.Config{}
		exitLeafStart(cfg)
		cfg.Cap.Exit = &kernel.ExitMode{Forward: forward}
		if err := refuseForwardedHere(cfg, "ranet7", network); err != nil {
			t.Errorf("a start forwarding %v was refused: %v", forward, err)
		}
	}
}
