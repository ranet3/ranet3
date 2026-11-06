// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package client

import (
	"log/slog"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/logtest"
	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
)

// macExitStart is a node running the reconciler, with an IPv6 address inside
// the overlay to send a path from
func macExitStart(old *config.Config) {
	old.Cap.Table = &kernel.Table{Addresses: []schema.Prefix{schema.MustPrefix("192.0.2.2/24"), schema.MustPrefix("3fff::2/20")}}
	old.Overlay = []schema.Prefix{schema.MustPrefix("192.0.2.0/24"), schema.MustPrefix("3fff::/20")}
}

var macVia = []schema.Addr{schema.MustAddr("3fff:b:0:306::3")}

// forward and inbound are refused at the start and at a reload by their own
// messages, and a refused reload hands the reconciler nothing
func TestExitModeRefusesWhatThisBuildLacksAtTheStartAndAtReload(t *testing.T) {
	const inbound = "kernel: cap.exit inbound is refused on macOS, where this build's kill switch is reject routes with no line passing a listed service's replies: while no exit is live and after a crash a service's replies leave by the uplink over IPv6 TCP whether it is bound to the uplink's address or to the wildcard and over UDP where it is bound to the uplink's address, and are refused over IPv4 TCP and over UDP on the wildcard, whatever inbound lists, so remove inbound"
	for _, c := range []struct {
		mode kernel.ExitMode
		want string
	}{
		{kernel.ExitMode{Forward: []string{"bridge*"}},
			"kernel: cap.exit forward is refused on macOS, where this build has no rule that routes a forwarded packet by the link it arrived on: remove forward, and a packet this host forwards toward an exit in a family the mode covers follows the mode into the tun as the host's own does, which drops a source this node does not own"},
		{kernel.ExitMode{Fallback: kernel.FallbackNone, Inbound: []string{"22/tcp"}}, inbound},
		{kernel.ExitMode{Via: macVia, Inbound: []string{"22/tcp"}, LAN: []schema.Prefix{schema.MustPrefix("198.51.100.0/24")}}, inbound},
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

// mode 2 with fallback unwritten, "uplink" or "none", lan beside "none", and
// mode 3 with via and fallback "uplink" or unwritten, which is "none" there,
// start and reload, the reload handing the reconciler the mode
func TestExitModeThisBuildHasStartsAndReloads(t *testing.T) {
	for _, mode := range []kernel.ExitMode{
		{},
		{Fallback: kernel.FallbackUplink},
		{Fallback: kernel.FallbackNone},
		{Fallback: kernel.FallbackNone, LAN: []schema.Prefix{schema.MustPrefix("198.51.100.0/24")}},
		{Via: macVia, Fallback: kernel.FallbackUplink},
		{Via: macVia},
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

// hostForwards has the host's forwarding read as forwards until the test ends
func hostForwards(t *testing.T, forwards func() (v4, v6 *bool)) {
	previous := hostForwarding
	t.Cleanup(func() { hostForwarding = previous })
	hostForwarding = forwards
}

// under cap.exit a Mac that forwards is told so at the start and at a reload,
// with one exit.forwarding per family it forwards, and one forwarding nothing,
// or running no mode, is not
func TestForwardingMacUnderTheModeIsWarnedAtTheStartAndAtReload(t *testing.T) {
	const warning = "under cap.exit, and on macOS a forwarded packet toward an exit in a family the mode covers follows the mode into the tun, which drops a source this node does not own"
	for i, c := range []struct {
		v4, v6   *bool
		exit     bool
		families []string
	}{
		{new(true), new(true), true, []string{"ipv4", "ipv6"}},
		{new(false), new(true), true, []string{"ipv6"}},
		{new(true), nil, true, []string{"ipv4"}},
		{new(false), new(false), true, nil},
		{new(true), new(true), false, nil},
	} {
		hostForwards(t, func() (*bool, *bool) { return c.v4, c.v6 })
		start := func(cfg *config.Config) {
			macExitStart(cfg)
			if c.exit {
				cfg.Cap.Exit = &kernel.ExitMode{}
			}
		}
		check := func(when string, lines *syncBuffer, bus *events.Bus) {
			t.Helper()
			want := 0
			if len(c.families) > 0 {
				want = 1
			}
			if n := lines.count(warning); n != want {
				t.Errorf("case %d: %s warned %d times, want %d: %q", i, when, n, want, lines.lines("forwards"))
			}
			var families []string
			for _, event := range bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "exit.forwarding" }, 0) {
				families = append(families, event.Attrs["family"])
			}
			if !slices.Equal(families, c.families) {
				t.Errorf("case %d: %s recorded exit.forwarding for %v, want %v", i, when, families, c.families)
			}
		}

		var started syncBuffer
		logtest.SetDefault(t, slog.New(slog.NewTextHandler(&started, nil)))
		cfg, privateKey, reg := runtimeFixture(t)
		start(cfg)
		dir := t.TempDir()
		cfg.Auth.Key, cfg.Auth.Trust = filepath.Join(dir, "key.pem"), filepath.Join(dir, "registry.json")
		writeKey(t, cfg.Auth.Key, privateKey)
		writeRegistry(t, cfg.Auth.Trust, reg)
		cfg.Cap.Segment = &srv6.Segments{Steer: []srv6.Steer{{}}}
		bus := events.New()
		if node, err := New(cfg, bus); err == nil {
			node.Close()
			t.Fatalf("case %d: a node steering by an entry selecting nothing started", i)
		} else if !strings.Contains(err.Error(), "cap.segment steer") {
			t.Fatalf("case %d: the start was refused before the warnings with %v", i, err)
		}
		check("the start", &started, bus)

		var reloaded syncBuffer
		logtest.SetDefault(t, slog.New(slog.NewTextHandler(&reloaded, nil)))
		node, path, _, bus := reloadOf(t, macExitStart)
		segmentsOf(t, node)
		next := *node.config()
		start(&next)
		writeConfig(t, path, &next)
		if err := node.ReloadFrom(path); err != nil {
			t.Fatalf("case %d: the reload was refused: %v", i, err)
		}
		check("a reload", &reloaded, bus)
	}
}
