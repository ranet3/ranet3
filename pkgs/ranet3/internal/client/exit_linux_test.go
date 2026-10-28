// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package client

import (
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
