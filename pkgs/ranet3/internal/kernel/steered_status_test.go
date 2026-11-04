// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build (linux && !android) || (darwin && !ios)

package kernel

import (
	"log/slog"
	"net/netip"
	"slices"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/schema"
)

// Each pass reports the path: its SIDs and outer source, the first SID that
// does not resolve with the table's answer, and the families whose steered
// default it left installed. kernel.path goes out when the defaults go in and
// when they come out, naming the state and the SID that moved it, once for a
// change and never for a pass that changes nothing. Outside mode 3 there is no
// path to report.
func TestPathReportsItsStateAndEmitsOnEachChange(t *testing.T) {
	bus := events.New()
	live := 1
	reconciler, table, _ := harness(t, modeThree(waypointSID, exitSID), Runtime{Overlay: steeredOverlay, Sessions: func() int { return live }, Events: bus})
	reconciler.now = func() time.Time { return start }
	both := []Family{FamilyIPv4, FamilyIPv6}
	pass := func(step string, down netip.Addr, verdict string, installed []Family) {
		t.Helper()
		if err := reconciler.reconcile(); err != nil {
			t.Fatalf("%s: %v", step, err)
		}
		path := reconciler.Stats().Path
		if path == nil {
			t.Fatalf("%s: mode 3 reports no path", step)
		}
		if !slices.Equal(path.Via, []netip.Addr{waypointSID, exitSID}) || path.Source != steeredSource {
			t.Errorf("%s: the path reads via %v from %s", step, path.Via, path.Source)
		}
		if path.Down != down || path.Verdict != verdict || !slices.Equal(path.Installed, installed) {
			t.Errorf("%s: the path reads down at %s (%q) with %v installed, want %s (%q) and %v", step, path.Down, path.Verdict, path.Installed, down, verdict, installed)
		}
	}
	pass("no segment routed", waypointSID, "no route", nil)
	pass("no segment routed again", waypointSID, "no route", nil)
	table.Set(netip.Prefix{}, netip.PrefixFrom(waypointSID, 128), learned)
	table.Set(netip.Prefix{}, netip.PrefixFrom(exitSID, 128), learned)
	pass("both segments routed", netip.Addr{}, "", both)
	pass("both segments routed again", netip.Addr{}, "", both)
	table.Set(netip.Prefix{}, netip.PrefixFrom(exitSID, 128), netstack.Unreachable)
	pass("the exit's segment held", exitSID, "held", nil)
	table.Set(netip.Prefix{}, prefix("::/0"), learned)
	table.Remove(netip.Prefix{}, netip.PrefixFrom(exitSID, 128))
	pass("the exit's segment under another exit's default alone", exitSID, "only through a route that counts as a default", nil)
	table.Set(netip.Prefix{}, netip.PrefixFrom(exitSID, 128), learned)
	pass("the exit's segment back", netip.Addr{}, "", both)
	live = 0
	reconciler.now = func() time.Time { return start.Add(time.Hour) }
	pass("no live session", netip.Addr{}, "", nil)

	var got []string
	for _, event := range bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "kernel.path" }, 0) {
		got = append(got, event.Attrs["state"]+" "+event.Attrs["segment"]+" "+event.Attrs["verdict"]+" "+event.Attrs["installed"])
	}
	want := []string{
		"down 3fff:7::1 no route none",
		"up   ipv4 ipv6",
		"down 3fff:8::46 held none",
		"down 3fff:8::46 only through a route that counts as a default none",
		"up   ipv4 ipv6",
		"up   none",
	}
	if !slices.Equal(got, want) {
		t.Errorf("kernel.path went out as %q, want %q", got, want)
	}

	if err := reconciler.SetTable(Table{}.WithMode(&ExitMode{}), steeredOverlay, nil); err != nil {
		t.Fatal(err)
	}
	if !reconciler.adopt() {
		t.Fatal("the reload to mode 2 was not adopted")
	}
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if path := reconciler.Stats().Path; path != nil {
		t.Errorf("mode 2 reports the path %+v", path)
	}
}

// kernel.forward and kernel.exit go out after the pass's route writes, so a
// pass that moves the path, skips a link and finds both families unaddressed
// records kernel.path first
func TestExitEventsFollowThePassesRouteWrites(t *testing.T) {
	bus := events.New()
	network := &hostNetwork{state: exitPassHost()}
	mode := &ExitMode{Via: []schema.Addr{schema.AddrFrom(waypointSID)}, Forward: []string{"eth*"}}
	reconciler, _, _ := harness(t, Table{}.WithMode(mode).WithPathSource(steeredSource), Runtime{Overlay: steeredOverlay, Network: network.read, Events: bus})
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, event := range bus.Recorded(func(kind, _ string, _ []slog.Attr) bool {
		return kind == "kernel.path" || kind == "kernel.forward" || kind == "kernel.exit"
	}, 0) {
		got = append(got, event.Kind)
	}
	if want := []string{"kernel.path", "kernel.forward", "kernel.exit", "kernel.exit"}; !slices.Equal(got, want) {
		t.Errorf("the pass recorded %v, want %v", got, want)
	}
}
