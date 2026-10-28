// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/schema"
)

// start is an arbitrary fixed instant, so every elapsed time below reads as
// the offset it is.
var start = time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)

// step is one liveness observation at an offset from start, and what the gate
// must answer for it.
type step struct {
	at   time.Duration
	live int
	open bool
}

// The three rules the gate exists to hold, each stated as a sequence of
// observations: nothing capturing before the first live session, a withdrawal
// once none has been live for the grace, and a restore on the next one.
func TestCaptureGateOpensOnlyWhileTheMeshIsLive(t *testing.T) {
	const grace = 10 * time.Second
	for name, steps := range map[string][]step{
		"a node that has never had a session installs nothing": {
			{at: 0, live: 0, open: false},
			{at: time.Hour, live: 0, open: false},
		},
		"the first live session opens it": {
			{at: 0, live: 0, open: false},
			{at: time.Second, live: 1, open: true},
		},
		"the grace runs from the last live sample, not from the first idle one": {
			{at: 0, live: 1, open: true},
			{at: 2 * time.Second, live: 0, open: true},
			{at: 9 * time.Second, live: 0, open: true},
			{at: grace, live: 0, open: false},
		},
		"a session that comes back before the grace expires restarts it": {
			{at: 0, live: 1, open: true},
			{at: 9 * time.Second, live: 0, open: true},
			{at: 9500 * time.Millisecond, live: 2, open: true},
			{at: 19 * time.Second, live: 0, open: true},
			{at: 19500 * time.Millisecond, live: 0, open: false},
		},
		"a session after a withdrawal restores it at once": {
			{at: 0, live: 1, open: true},
			{at: grace, live: 0, open: false},
			{at: grace + time.Second, live: 1, open: true},
		},
		"a pass that finds nothing live long after the grace keeps it shut": {
			{at: 0, live: 1, open: true},
			{at: time.Hour, live: 0, open: false},
			{at: 2 * time.Hour, live: 0, open: false},
		},
	} {
		t.Run(name, func(t *testing.T) {
			gate := captureGate{grace: grace}
			for _, s := range steps {
				open, _ := gate.sample(start.Add(s.at), s.live)
				if open != s.open {
					t.Errorf("at %s with %d live sessions the gate reported %v, want %v",
						s.at, s.live, open, s.open)
				}
			}
		})
	}
}

// changed says a caller may report the transition once. A gate that reported
// it on every pass would log a line per pass for as long as the mesh is down,
// which is exactly the stretch an operator is reading the log.
func TestCaptureGateReportsEachTransitionOnce(t *testing.T) {
	gate := captureGate{grace: 10 * time.Second}
	var transitions []bool
	for _, s := range []step{
		{at: 0, live: 0}, {at: time.Second, live: 1}, {at: 2 * time.Second, live: 1},
		{at: 3 * time.Second, live: 0}, {at: 20 * time.Second, live: 0},
		{at: 30 * time.Second, live: 0}, {at: 40 * time.Second, live: 1},
	} {
		open, changed := gate.sample(start.Add(s.at), s.live)
		if changed {
			transitions = append(transitions, open)
		}
	}
	// Opened at the first live session, shut once the grace expired, opened
	// again on the session after it, and nothing in between.
	if want := []bool{true, false, true}; !slices.Equal(transitions, want) {
		t.Errorf("the gate reported the transitions %v, want %v", transitions, want)
	}
}

// Only a running grace needs a wake-up of its own. A gate that is open because
// a session is live will be woken by the next mesh change, and a shut one has
// nothing scheduled to happen at all.
func TestCaptureGateAsksToBeWokenOnlyWhileTheGraceRuns(t *testing.T) {
	const grace = 10 * time.Second
	gate := captureGate{grace: grace}
	if _, ok := gate.deadline(); ok {
		t.Error("a gate that has seen nothing asked to be woken")
	}
	// Open, and asking to be woken one grace after the last live sample. A
	// session stops counting as live because it went quiet and nothing fires
	// when that happens, so a gate that waited for its own next pass to
	// notice took the periodic sweep rather than the grace: measured at about
	// a minute against the ten seconds the grace promises.
	gate.sample(start, 1)
	at, ok := gate.deadline()
	if !ok {
		t.Fatal("an open gate did not ask to be woken, so nothing samples it until the sweep")
	}
	if want := start.Add(grace); !at.Equal(want) {
		t.Errorf("an open gate asks to be woken at %s, want %s", at, want)
	}
	gate.sample(start.Add(time.Second), 0)
	at, ok = gate.deadline()
	if !ok {
		t.Fatal("a running grace did not ask to be woken")
	}
	// The grace runs from the last live sample, not from the pass that found
	// nothing live, so the deadline cannot move by waiting.
	if want := start.Add(grace); !at.Equal(want) {
		t.Errorf("the grace expires at %s, want %s", at, want)
	}
	gate.sample(start.Add(grace), 0)
	if _, ok := gate.deadline(); ok {
		t.Error("a gate that has already withdrawn asked to be woken again")
	}
}

// The gate as the reconciler applies it: an announced default reaches the
// kernel only while the mesh can carry it, and the ordinary mesh prefixes
// around it are never held back, because a prefix route leaves the machine's
// own uplink alone.
func TestReconcileInstallsAnAnnouncedDefaultOnlyWhileASessionIsLive(t *testing.T) {
	live := 0
	reconciler, table, fake := harness(t,
		Table{CaptureGrace: schema.Duration(10 * time.Second)},
		Runtime{Sessions: func() int { return live }})
	clock := start
	reconciler.now = func() time.Time { return clock }
	table.Set(netip.Prefix{}, prefix("::/0"), nil)
	table.Set(netip.Prefix{}, prefix("3fff:a::/36"), nil)

	mesh := Route{Destination: prefix("3fff:a::/36"), Metric: defaultIPv6Metric}
	def := Route{Destination: prefix("::/0"), Metric: defaultIPv6Metric}

	// The mesh announces a default before anything has connected, which is
	// what a node reading a peer's stale announcement at startup would see.
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if fake.has(def) {
		t.Fatal("a default was installed before any session had been live")
	}
	if !fake.has(mesh) {
		t.Fatal("an ordinary mesh prefix was held back with the default")
	}

	live = 1
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if !fake.has(def) {
		t.Fatal("a live session did not install the announced default")
	}

	// The session goes, and the default stays for the grace: a reconnect
	// inside it must not cost the machine its route.
	live = 0
	clock = start.Add(9 * time.Second)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if !fake.has(def) {
		t.Fatal("the default was withdrawn inside the grace")
	}

	clock = start.Add(11 * time.Second)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if fake.has(def) {
		t.Fatal("the default survived the grace with nothing live")
	}
	if !fake.has(mesh) {
		t.Fatal("the mesh prefixes went with the default")
	}

	// And it comes back on its own, which is the half that makes the
	// withdrawal a fallback rather than an outage.
	live = 2
	clock = start.Add(12 * time.Second)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if !fake.has(def) {
		t.Fatal("the default was not restored by the next live session")
	}
}

// A retracted default is a hold: unscoped it answers with an error for every
// destination, which is the same machine with no network in a different shape.
// It is held back by the same gate.
func TestReconcileHoldsBackARetractedDefaultToo(t *testing.T) {
	reconciler, table, fake := harness(t, Table{}, Runtime{Sessions: func() int { return 0 }})
	reconciler.now = func() time.Time { return start }
	table.Set(netip.Prefix{}, prefix("::/0"), netstack.Unreachable)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if got := fake.snapshot(); len(got) != 0 {
		t.Fatalf("installed %v with nothing live, want nothing", got)
	}
}

// This node's own prefix that counts, an exit's default from its transit
// prefix and a split internet it originates among them, never reaches the
// kernel, with nothing live or with a session live, while its own prefix that
// does not count goes in as the throw, outside the overlay and on a platform
// with the policy rules.
func TestReconcileNeverInstallsThisNodesOwnCountedPrefix(t *testing.T) {
	live := 0
	reconciler, table, fake := harness(t, Table{}, Runtime{Sessions: func() int { return live }})
	reconciler.now = func() time.Time { return start }
	for _, destination := range []string{"0.0.0.0/0", "64.0.0.0/2", "2000::/3"} {
		table.Set(netip.Prefix{}, prefix(destination), netstack.Local)
	}
	table.Set(prefix("2001:db8:a::/48"), prefix("::/0"), netstack.Local)
	table.Set(netip.Prefix{}, prefix("2001:db8:a::/48"), netstack.Local)
	want := []Route{{Destination: prefix("2001:db8:a::/48"), Metric: holdMetric, Throw: true}}
	for _, live = range []int{0, 1} {
		if err := reconciler.reconcile(); err != nil {
			t.Fatal(err)
		}
		if got := fake.snapshot(); !slices.Equal(got, want) {
			t.Errorf("installed %v with %d sessions live, want only %v", got, live, want)
		}
	}
}

// A short prefix outside the overlay counts and is held back while nothing is
// live, and once a reload moves the overlay over it the same prefix is a
// subnet and installs.
func TestReconcileReadsTheOverlayItIsHanded(t *testing.T) {
	reconciler, table, fake := harness(t, Table{}, Runtime{
		Sessions: func() int { return 0 },
		Overlay:  []schema.Prefix{schema.MustPrefix("3fff::/20")},
	})
	reconciler.now = func() time.Time { return start }
	wide := Route{Destination: prefix("3ff0::/14"), Metric: defaultIPv6Metric}
	table.Set(netip.Prefix{}, wide.Destination, nil)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if fake.has(wide) {
		t.Fatal("3ff0::/14 outside the overlay installed with nothing live")
	}
	if err := reconciler.SetTable(Table{}, []schema.Prefix{schema.MustPrefix("3ff0::/12")}, nil); err != nil {
		t.Fatal(err)
	}
	if !reconciler.adopt() {
		t.Fatal("an accepted reload handed the loop nothing")
	}
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if !fake.has(wide) {
		t.Errorf("3ff0::/14 was held back with nothing live once the overlay held it: %v", fake.snapshot())
	}
}

// A split internet, four IPv4 /2s and 2000::/3, takes this machine's traffic
// as a default does: it reaches the kernel only once a session is live, and
// once its exit retracts it, with other sessions still live, it leaves no
// unreachable hold that would answer the host's own traffic with an error.
func TestReconcileLeavesNoHoldOfARetractedSplitInternet(t *testing.T) {
	live := 0
	reconciler, table, fake := harness(t, Table{}, Runtime{Sessions: func() int { return live }})
	reconciler.now = func() time.Time { return start }
	split := []string{"0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/2", "192.0.0.0/2", "2000::/3"}
	for _, destination := range split {
		table.Set(netip.Prefix{}, prefix(destination), nil)
	}
	subnet := Route{Destination: prefix("3fff:a::/36"), Metric: defaultIPv6Metric}
	table.Set(netip.Prefix{}, subnet.Destination, nil)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if got := fake.snapshot(); !slices.Equal(got, []Route{subnet}) {
		t.Fatalf("installed %v with nothing live, want only %v", got, subnet)
	}
	live = 1
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	for _, destination := range split {
		route := Route{Destination: prefix(destination)}
		if route.Destination.Addr().Is6() {
			route.Metric = defaultIPv6Metric
		}
		if !fake.has(route) {
			t.Errorf("%s did not install with a session live: %v", destination, fake.snapshot())
		}
	}
	for _, destination := range split {
		table.Set(netip.Prefix{}, prefix(destination), netstack.Unreachable)
	}
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if got := fake.snapshot(); !slices.Equal(got, []Route{subnet}) {
		t.Errorf("installed %v once the split was retracted with a session live, want only %v", got, subnet)
	}
}

// A reconciler nobody told about sessions keeps the behavior it had before the
// gate existed. It is driven by something that has no sessions to report, and
// answering zero for it would leave every default uninstallable.
func TestReconcileInstallsADefaultWhenNothingReportsSessions(t *testing.T) {
	reconciler, table, fake := harness(t, Table{})
	table.Set(netip.Prefix{}, prefix("::/0"), nil)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if !fake.has(Route{Destination: prefix("::/0"), Metric: defaultIPv6Metric}) {
		t.Fatal("a reconciler with no session source held back an announced default")
	}
}

// Run has to wake at the moment the grace expires. Nothing else will: the mesh
// has stopped changing, which is why the grace is running.
func TestReconcilerAsksToBeWokenWhenTheGraceExpires(t *testing.T) {
	live := 1
	reconciler, table, _ := harness(t,
		Table{CaptureGrace: schema.Duration(10 * time.Second)},
		Runtime{Sessions: func() int { return live }})
	clock := start
	reconciler.now = func() time.Time { return clock }
	table.Set(netip.Prefix{}, prefix("::/0"), nil)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if _, ok := reconciler.captureDeadline(); !ok {
		t.Fatal("a reconciler holding a capture did not ask to be woken, so nothing samples the gate until the sweep")
	}
	live = 0
	clock = start.Add(time.Second)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	at, ok := reconciler.captureDeadline()
	if !ok {
		t.Fatal("a reconciler running the grace did not ask to be woken")
	}
	if want := start.Add(10 * time.Second); !at.Equal(want) {
		t.Errorf("it asked to be woken at %s, want %s", at, want)
	}
}

// link.underlay.bind with nothing to ask about liveness is refused at startup.
// The two are halves of one arrangement: bind lets an announced default
// install unscoped, where every socket sees it, and the gate is the only thing
// keeping it out of the kernel until the mesh has carried traffic.
func TestNewRefusesBindWithNoSessionSource(t *testing.T) {
	table := netstack.NewRouteTable()
	_, err := New(Table{}, Runtime{Interface: "lo0", BoundUnderlay: true}, table)
	if err == nil {
		t.Fatal("bind with no session source was accepted")
	}
	if !strings.Contains(err.Error(), "session source") {
		t.Errorf("the refusal reads %q", err)
	}
	// And the same runtime with a session source gets past that check, so the
	// refusal is about the pair rather than about bind.
	if _, err := New(Table{}, Runtime{
		Interface: "lo0", BoundUnderlay: true, Sessions: func() int { return 0 },
	}, table); err != nil && strings.Contains(err.Error(), "session source") {
		t.Errorf("bind with a session source was refused for the same reason: %v", err)
	}
}

// The deadline is an answer nobody has to ask for: the run loop arms a timer
// from it, and nothing else wakes at the moment the grace expires, because the
// mesh has stopped changing and that silence is why the grace is running.
// Driven through the real loop with the sweep a minute out, so the grace timer
// is the only thing that can reach the withdrawal.
func TestRunWithdrawsTheCaptureOnTheGraceRatherThanTheSweep(t *testing.T) {
	var live atomic.Int64
	live.Store(1)
	reconciler, table, fake := harness(t,
		Table{Reconcile: schema.Duration(time.Minute), CaptureGrace: schema.Duration(MinCaptureGrace)},
		Runtime{Sessions: func() int { return int(live.Load()) }})
	capture := Route{Destination: prefix("::/0"), Metric: defaultIPv6Metric}
	table.Set(netip.Prefix{}, capture.Destination, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- reconciler.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	waitFor(t, func() bool { return fake.has(capture) })

	// The change this test made before the loop started drives one pass of its
	// own, so the sessions go quiet after it rather than under it: from here
	// the route source never changes again and the platform never notifies,
	// and the sweep is a minute out.
	installed := reconciler.Stats().At
	waitFor(t, func() bool { return reconciler.Stats().At.After(installed) })

	live.Store(0)
	waitFor(t, func() bool { return !fake.has(capture) })
}

// The grace must not set the reconcile rate. The gate is open whenever a
// session is live, which on an ordinary node is always, so arming the wake
// from that alone made a full pass run once per grace: measured at 239 passes
// in 300 ms with a one millisecond grace against two, and at the shipped
// defaults three times as often as reconcile says.
//
// The wake is needed only while a capturing route is installed or wanted,
// which is the state whose withdrawal nothing else would schedule. A split
// internet holding no zero address counts as a default and arms it too.
func TestGraceWakesOnlyWhileACaptureIsInPlay(t *testing.T) {
	for name, test := range map[string]struct {
		announce netip.Prefix
		armed    bool
	}{
		"nothing capturing announced": {prefix("3fff:a::/36"), false},
		"a capture announced":         {prefix("::/0"), true},
		"a split internet announced":  {prefix("2000::/3"), true},
	} {
		t.Run(name, func(t *testing.T) {
			reconciler, table, _ := harness(t,
				Table{CaptureGrace: schema.Duration(time.Second)},
				Runtime{Sessions: func() int { return 1 }})
			reconciler.now = func() time.Time { return start }
			table.Set(netip.Prefix{}, test.announce, nil)
			if err := reconciler.reconcile(); err != nil {
				t.Fatal(err)
			}
			if _, armed := reconciler.captureDeadline(); armed != test.armed {
				t.Errorf("the grace wake is armed %v with %s announced, want %v", armed, test.announce, test.armed)
			}
		})
	}
}

// And a grace too short to honor is refused by name rather than spun on. The
// gate is sampled once a pass and a pass reads the routing table, so a
// millisecond grace only sets how often that happens.
func TestCaptureGraceBelowTheFloorIsRefused(t *testing.T) {
	for name, grace := range map[string]time.Duration{
		"a millisecond":       time.Millisecond,
		"just under a second": MinCaptureGrace - time.Nanosecond,
	} {
		t.Run(name, func(t *testing.T) {
			err := Table{CaptureGrace: schema.Duration(grace)}.Validate()
			if err == nil {
				t.Fatal("a grace the reconciler cannot honor was accepted")
			}
			if !strings.Contains(err.Error(), "capture_grace") {
				t.Errorf("the refusal reads %q", err)
			}
		})
	}
	// The floor itself and the default are both fine, and an omitted one still
	// means the default rather than an error.
	for _, grace := range []time.Duration{0, MinCaptureGrace, DefaultCaptureGrace} {
		if err := (Table{CaptureGrace: schema.Duration(grace)}).Validate(); err != nil {
			t.Errorf("a grace of %s was refused: %v", grace, err)
		}
	}
}
