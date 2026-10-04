// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/schema"
)

// a pass that changed the kernel, skipped a route it had not skipped before or failed is recorded
// with what woke the reconciler and how long the pass took, and the steady state is not
// a refused route leaving as another is refused counts as a route refused anew, though the count stays
func TestReconcilerRecordsThePassesThatDidSomething(t *testing.T) {
	bus := events.New()
	reconciler, table, fake := harness(t, Table{}, Runtime{Events: bus})
	reconciler.trigger = "mesh"
	table.Set(netip.Prefix{}, prefix("198.51.100.0/24"), nil)
	reconciler.reconcile()
	reconciler.reconcile()
	skipped := Route{Destination: prefix("::/0"), Source: prefix("2001:db8::/48"), Metric: defaultIPv6Metric}
	fake.failAdd[skipped] = errRouteSkipped
	table.Set(skipped.Source, skipped.Destination, nil)
	reconciler.reconcile()
	reconciler.reconcile()
	other := Route{Destination: prefix("::/0"), Source: prefix("2001:db8:1::/48"), Metric: defaultIPv6Metric}
	fake.failAdd[other] = errRouteSkipped
	table.Remove(skipped.Source, skipped.Destination)
	table.Set(other.Source, other.Destination, nil)
	reconciler.reconcile()
	// a route refused anew sorts before one refused already, and the pass is one to record though its last refusal is no news
	table.Set(skipped.Source, skipped.Destination, nil)
	reconciler.reconcile()
	fake.failList = errors.New("netlink is busy")
	reconciler.reconcile()

	var got [][]string
	for _, event := range bus.Recorded(func(string, string, []slog.Attr) bool { return true }, 0) {
		if event.Attrs["took"] == "" {
			t.Errorf("a pass was recorded without its duration: %+v", event)
		}
		got = append(got, []string{event.Kind, event.Attrs["trigger"], event.Attrs["added"], event.Attrs["skipped"], event.Attrs["err"]})
	}
	want := [][]string{
		{"kernel.pass", "mesh", "1", "0", ""},
		{"kernel.pass", "mesh", "0", "1", ""},
		{"kernel.pass", "mesh", "0", "1", ""},
		{"kernel.pass", "mesh", "0", "2", ""},
		{"kernel.pass", "mesh", "0", "0", "list routes: netlink is busy"},
	}
	if !slices.EqualFunc(got, want, slices.Equal) {
		t.Errorf("the reconciler recorded %q, want %q", got, want)
	}
}

// a pass that wrote a rule, an address, the master or the vrf changed the kernel, and is recorded though no route moved
func TestReconcilerRecordsAPassThatMovedNoRoute(t *testing.T) {
	bus := events.New()
	reconciler, _, fake := harness(t, Table{
		Rules:     []Rule{{Family: FamilyIPv4, FWMark: 0x726c, Table: 254, Priority: 40}},
		Addresses: prefixes(prefix("192.0.2.1/24")),
		VRF:       &VRF{Name: "mesh", Create: true},
	}, Runtime{Events: bus})
	reconciler.trigger = "sweep"
	passes := func() int {
		return len(bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "kernel.pass" }, 0))
	}
	reconciler.reconcile()
	reconciler.reconcile()
	if got := passes(); got != 1 {
		t.Fatalf("the first pass and a steady one recorded %d passes, want the first alone", got)
	}
	// somebody else undoes one thing at a time, and the pass that puts it back is recorded
	for _, undo := range []struct {
		what   string
		change func()
	}{
		{"a rule", func() { clear(fake.rules) }},
		{"an address", func() { clear(fake.addrs) }},
		{"the master", func() { fake.master = "" }},
		{"the vrf", func() { clear(fake.vrfs) }},
	} {
		before := passes()
		undo.change()
		reconciler.reconcile()
		if passes() != before+1 {
			t.Errorf("the pass that put back %s was not recorded", undo.what)
		}
	}
}

// passWait is how long a test waits for a pass it expects, generous for a loaded machine
// passPoll is how often it looks
const (
	passWait = 30 * time.Second
	passPoll = 5 * time.Millisecond
)

// a running reconciler names what woke it for each pass it records
// its first pass, a change of the mesh, a change somebody else made to the kernel, the retry of a failed pass, a stop over the control socket whose withdrawal failed, and the start after it
func TestReconcilerNamesWhatWokeIt(t *testing.T) {
	bus := events.New()
	reconciler, table, fake := harness(t, Table{}, Runtime{Events: bus})
	table.Set(netip.Prefix{}, prefix("198.51.100.0/24"), nil)
	last := runToRecord(t, reconciler, table, bus)
	always := func() bool { return true }
	// the reconcile goroutine reads the fake under its lock
	locked := func(change func()) {
		fake.mu.Lock()
		defer fake.mu.Unlock()
		change()
	}

	awaitPass(t, last, "the first pass", "start", always)
	table.Set(netip.Prefix{}, prefix("203.0.113.0/24"), nil)
	awaitPass(t, last, "the pass the mesh asked for", "mesh", always)
	installed := fake.snapshot()[0]
	locked(func() { delete(fake.routes, installed) })
	fake.signal <- struct{}{}
	awaitPass(t, last, "the pass the kernel's notice asked for", "kernel", always)
	locked(func() { fake.failList = errors.New("netlink is busy") })
	table.Set(netip.Prefix{}, prefix("192.0.2.0/24"), nil)
	awaitPass(t, last, "the retry of a failed pass", "retry", always)
	locked(func() { fake.failList, fake.failDel[installed] = nil, errors.New("netlink is busy") })
	reconciler.SetEnabled(false)
	awaitPass(t, last, "the withdrawal that failed", "disable", always)
	locked(func() { delete(fake.failDel, installed) })
	reconciler.SetEnabled(true)
	awaitPass(t, last, "the pass the start asked for", "enable", always)
}

// sweepEvery is the reconcile interval of a test that waits for the sweep
const sweepEvery = 100 * time.Millisecond

// runToRecord starts the reconciler on a table that already holds its routes, and returns a function reading the trigger of the last pass recorded
// the first pass reads those routes, so the change they made wakes nothing after it
func runToRecord(t *testing.T, reconciler *Reconciler, table *netstack.RouteTable, bus *events.Bus) func() string {
	t.Helper()
	<-table.Changed()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- reconciler.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return func() string {
		passes := bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "kernel.pass" }, 0)
		if len(passes) == 0 {
			return ""
		}
		return passes[len(passes)-1].Attrs["trigger"]
	}
}

// awaitPass waits until done holds and the last pass recorded was woken by trigger
func awaitPass(t *testing.T, last func() string, what, trigger string, done func() bool) {
	t.Helper()
	for deadline := time.Now().Add(passWait); !done() || last() != trigger; time.Sleep(passPoll) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s, the last pass recorded was woken by %q", what, last())
		}
	}
}

// a pass the sweep woke, putting back a route somebody else removed without a word, is named for the sweep
func TestReconcilerNamesTheSweep(t *testing.T) {
	bus := events.New()
	reconciler, table, fake := harness(t, Table{Reconcile: schema.Duration(sweepEvery)}, Runtime{Events: bus})
	ordinary := Route{Destination: prefix("2001:db8:5::/48"), Metric: defaultIPv6Metric}
	table.Set(netip.Prefix{}, ordinary.Destination, nil)
	last := runToRecord(t, reconciler, table, bus)
	awaitPass(t, last, "the first pass", "start", func() bool { return fake.has(ordinary) })
	fake.mu.Lock()
	delete(fake.routes, ordinary)
	fake.mu.Unlock()
	awaitPass(t, last, "the sweep to put the route back", "sweep", func() bool { return fake.has(ordinary) })
}

// a pass the capture grace woke, withdrawing a capture once the sessions went quiet, is named for the grace
// the sweep is a minute out, so only the grace can reach the withdrawal
func TestReconcilerNamesTheGrace(t *testing.T) {
	bus := events.New()
	var live atomic.Int64
	live.Store(1)
	reconciler, table, fake := harness(t,
		Table{Reconcile: schema.Duration(time.Minute), CaptureGrace: schema.Duration(MinCaptureGrace)},
		Runtime{Events: bus, Sessions: func() int { return int(live.Load()) }})
	capture := Route{Destination: prefix("::/0"), Metric: defaultIPv6Metric}
	table.Set(netip.Prefix{}, capture.Destination, nil)
	last := runToRecord(t, reconciler, table, bus)
	awaitPass(t, last, "the capture", "start", func() bool { return fake.has(capture) })
	live.Store(0)
	awaitPass(t, last, "the grace to withdraw the capture", "grace", func() bool { return !fake.has(capture) })
}
