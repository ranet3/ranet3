// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package client

import (
	"reflect"
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/schema"
)

// macExitStart is a node running the reconciler, with an IPv6 address inside
// the overlay to send a path from
func macExitStart(old *config.Config) {
	old.Cap.Table = &kernel.Table{Addresses: []schema.Prefix{schema.MustPrefix("192.0.2.2/24"), schema.MustPrefix("3fff::2/20")}}
	old.Overlay = []schema.Prefix{schema.MustPrefix("192.0.2.0/24"), schema.MustPrefix("3fff::/20")}
}

var macVia = []schema.Addr{schema.MustAddr("3fff:b:0:306::3")}

// forward, fallback = "none" and via with fallback unwritten are refused at
// the start and at a reload by their own messages, naming inbound and lan
// where they are written, and a refused reload hands the reconciler nothing
func TestExitModeRefusesWhatThisBuildLacksAtTheStartAndAtReload(t *testing.T) {
	const filter = "is refused on macOS, where this build has no filter to keep the host's traffic off the uplink"
	for _, c := range []struct {
		mode kernel.ExitMode
		want string
	}{
		{kernel.ExitMode{Forward: []string{"bridge*"}},
			"kernel: cap.exit forward is refused on macOS, where this build has no rule that routes a forwarded packet by the link it arrived on: remove forward, and a packet this host forwards toward an exit in a family the mode covers follows the mode into the tun as the host's own does, which drops a source this node does not own"},
		{kernel.ExitMode{Fallback: kernel.FallbackNone},
			`kernel: cap.exit fallback = "none" ` + filter + `: write fallback = "uplink"`},
		{kernel.ExitMode{Fallback: kernel.FallbackNone, Inbound: []string{"22/tcp"}},
			`kernel: cap.exit fallback = "none" with inbound ` + filter + `: write fallback = "uplink" and remove inbound`},
		{kernel.ExitMode{Fallback: kernel.FallbackNone, Inbound: []string{"22/tcp"}, LAN: []schema.Prefix{schema.MustPrefix("198.51.100.0/24")}},
			`kernel: cap.exit fallback = "none" with inbound and lan ` + filter + `: write fallback = "uplink" and remove inbound and lan`},
		{kernel.ExitMode{Via: macVia},
			`kernel: cap.exit via with fallback unwritten is "none" in mode 3, which ` + filter + `: write fallback = "uplink" beside via`},
	} {
		cfg, privateKey, reg := runtimeFixture(t)
		macExitStart(cfg)
		cfg.Cap.Exit = &c.mode
		if err := validateRuntimeConfig(cfg, privateKey, trust(t, reg)); err == nil || err.Error() != c.want {
			t.Errorf("the start under %+v was refused with %v, want %q", c.mode, err, c.want)
		}

		node, path, reconciler, _ := reloadOf(t, macExitStart)
		segmentsOf(t, node)
		next := *node.config()
		next.Cap.Exit = &c.mode
		writeConfig(t, path, &next)
		if err := node.ReloadFrom(path); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("a reload to %+v was refused with %v, want %q", c.mode, err, c.want)
		}
		if len(reconciler.tables) != 0 || node.config().Cap.Exit != nil {
			t.Errorf("a refused reload to %+v handed the reconciler %+v", c.mode, reconciler.tables)
		}
	}
}

// mode 2 with fallback unwritten or "uplink", and mode 3 with via and
// "uplink", start and reload, the reload handing the reconciler the mode
func TestExitModeThisBuildHasStartsAndReloads(t *testing.T) {
	for _, mode := range []kernel.ExitMode{
		{},
		{Fallback: kernel.FallbackUplink},
		{Via: macVia, Fallback: kernel.FallbackUplink},
	} {
		cfg, privateKey, reg := runtimeFixture(t)
		macExitStart(cfg)
		cfg.Cap.Exit = &mode
		if err := validateRuntimeConfig(cfg, privateKey, trust(t, reg)); err != nil {
			t.Errorf("the start under %+v was refused: %v", mode, err)
		}

		node, path, reconciler, _ := reloadOf(t, macExitStart)
		segmentsOf(t, node)
		next := *node.config()
		next.Cap.Exit = &mode
		writeConfig(t, path, &next)
		if err := node.ReloadFrom(path); err != nil {
			t.Errorf("a reload to %+v was refused: %v", mode, err)
			continue
		}
		want := mode.Normalized()
		if len(reconciler.tables) != 1 || !reflect.DeepEqual(reconciler.tables[0].Normalized().Mode(), &want) {
			t.Errorf("a reload to %+v handed the reconciler %+v, want one table running %+v", mode, reconciler.tables, want)
		}
	}
}
