// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/schema"
)

// start is an arbitrary fixed instant, so every elapsed time below reads as
// the offset it is.
var start = time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)

// step is one sample at an offset from start, with the sessions live then, and
// whether capture must be allowed for it.
type step struct {
	at      time.Duration
	live    int
	allowed bool
}

// The three rules captureLiveness exists to hold, each stated as a sequence of
// observations: nothing capturing before the first live session, a withdrawal
// once none has been live for the grace, and a restore on the next one.
func TestCaptureLivenessAllowsCaptureFromTheFirstLiveSessionUntilTheGraceExpires(t *testing.T) {
	const grace = 10 * time.Second
	for name, steps := range map[string][]step{
		"a node that has never had a session installs nothing": {
			{at: 0, live: 0, allowed: false},
			{at: time.Hour, live: 0, allowed: false},
		},
		"the first live session allows capture": {
			{at: 0, live: 0, allowed: false},
			{at: time.Second, live: 1, allowed: true},
		},
		"the grace runs from the last live sample, not from the first idle one": {
			{at: 0, live: 1, allowed: true},
			{at: 2 * time.Second, live: 0, allowed: true},
			{at: 9 * time.Second, live: 0, allowed: true},
			{at: grace, live: 0, allowed: false},
		},
		"a session that comes back before the grace expires restarts it": {
			{at: 0, live: 1, allowed: true},
			{at: 9 * time.Second, live: 0, allowed: true},
			{at: 9500 * time.Millisecond, live: 2, allowed: true},
			{at: 19 * time.Second, live: 0, allowed: true},
			{at: 19500 * time.Millisecond, live: 0, allowed: false},
		},
		"a session after a withdrawal restores it at once": {
			{at: 0, live: 1, allowed: true},
			{at: grace, live: 0, allowed: false},
			{at: grace + time.Second, live: 1, allowed: true},
		},
		"a pass that finds nothing live long after the grace keeps capture not allowed": {
			{at: 0, live: 1, allowed: true},
			{at: time.Hour, live: 0, allowed: false},
			{at: 2 * time.Hour, live: 0, allowed: false},
		},
	} {
		t.Run(name, func(t *testing.T) {
			liveness := captureLiveness{grace: grace}
			for _, s := range steps {
				allowed, _ := liveness.sample(start.Add(s.at), s.live)
				if allowed != s.allowed {
					t.Errorf("at %s with %d live sessions capture allowed was %v, want %v",
						s.at, s.live, allowed, s.allowed)
				}
			}
		})
	}
}

// changed says a caller may report the transition once. A captureLiveness that
// reported it on every pass would log a line per pass for as long as the mesh
// is down, which is exactly the stretch an operator is reading the log.
func TestCaptureLivenessReportsEachTransitionOnce(t *testing.T) {
	liveness := captureLiveness{grace: 10 * time.Second}
	var transitions []bool
	for _, s := range []step{
		{at: 0, live: 0}, {at: time.Second, live: 1}, {at: 2 * time.Second, live: 1},
		{at: 3 * time.Second, live: 0}, {at: 20 * time.Second, live: 0},
		{at: 30 * time.Second, live: 0}, {at: 40 * time.Second, live: 1},
	} {
		allowed, changed := liveness.sample(start.Add(s.at), s.live)
		if changed {
			transitions = append(transitions, allowed)
		}
	}
	// Allowed at the first live session, not allowed once the grace expired,
	// allowed again on the next, and nothing in between.
	if want := []bool{true, false, true}; !slices.Equal(transitions, want) {
		t.Errorf("sample reported the transitions %v, want %v", transitions, want)
	}
}

// A session stops counting as live when it goes quiet and nothing fires then,
// so while capture is allowed captureLiveness asks to be woken one grace after
// its last live sample, and with nothing seen or after a withdrawal it asks for
// nothing.
func TestCaptureLivenessAsksToBeWokenOnlyWhileCaptureIsAllowed(t *testing.T) {
	const grace = 10 * time.Second
	liveness := captureLiveness{grace: grace}
	if _, ok := liveness.deadline(); ok {
		t.Error("captureLiveness that has seen nothing asked to be woken")
	}
	liveness.sample(start, 1)
	at, ok := liveness.deadline()
	if !ok {
		t.Fatal("captureLiveness allowing capture did not ask to be woken, so nothing samples it until the sweep")
	}
	if want := start.Add(grace); !at.Equal(want) {
		t.Errorf("captureLiveness allowing capture asks to be woken at %s, want %s", at, want)
	}
	liveness.sample(start.Add(time.Second), 0)
	at, ok = liveness.deadline()
	if !ok {
		t.Fatal("a running grace did not ask to be woken")
	}
	// The grace runs from the last live sample, not from the pass that found
	// nothing live, so the deadline cannot move by waiting.
	if want := start.Add(grace); !at.Equal(want) {
		t.Errorf("the grace expires at %s, want %s", at, want)
	}
	liveness.sample(start.Add(grace), 0)
	if _, ok := liveness.deadline(); ok {
		t.Error("captureLiveness that has already withdrawn asked to be woken again")
	}
}

// captureLiveness as the reconciler applies it: an announced default reaches
// the kernel only while the mesh can carry it, and the ordinary mesh prefixes
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

// Capture becoming allowed or not is logged only where it moves a route that
// carries this machine's traffic: a leaf that learns a default says it installs
// it and withdraws it, once each, and an exit that announces its own default
// says nothing, since it installs none.
func TestCaptureIsLoggedOnlyWhereARouteCarriesTheMachine(t *testing.T) {
	const (
		installed = "kernel is installing the routes that carry this machine's own traffic over the mesh"
		withdrawn = "kernel is withdrawing the routes that would carry this machine's own traffic"
	)
	for name, test := range map[string]struct {
		source *netstack.Peer
		want   int
	}{
		"a leaf learning a default": {nil, 1},
		"an exit announcing one":    {netstack.Local, 0},
	} {
		t.Run(name, func(t *testing.T) {
			said := logged(t)
			live := 0
			reconciler, table, _ := harness(t,
				Table{CaptureGrace: schema.Duration(10 * time.Second)},
				Runtime{Sessions: func() int { return live }})
			clock := start
			reconciler.now = func() time.Time { return clock }
			table.Set(netip.Prefix{}, prefix("::/0"), test.source)
			for _, pass := range []struct {
				at   time.Duration
				live int
			}{{0, 0}, {time.Second, 1}, {2 * time.Second, 1}, {13 * time.Second, 0}, {14 * time.Second, 0}} {
				clock, live = start.Add(pass.at), pass.live
				if err := reconciler.reconcile(); err != nil {
					t.Fatal(err)
				}
			}
			text := said.String()
			if got := strings.Count(text, installed); got != test.want {
				t.Errorf("logged the install %d times, want %d:\n%s", got, test.want, text)
			}
			if got := strings.Count(text, withdrawn); got != test.want {
				t.Errorf("logged the withdrawal %d times, want %d:\n%s", got, test.want, text)
			}
		})
	}
}

// The install is logged from the routes a pass installed: again at the start
// after a stop, not at an install the kernel refused, and at the pass after it
// that lands. Capture not allowed at the start after a stop logs no
// withdrawal of the routes the stop removed.
func TestCaptureIsLoggedFromWhatAPassInstalled(t *testing.T) {
	const (
		installed = "kernel is installing the routes that carry this machine's own traffic over the mesh"
		withdrawn = "kernel is withdrawing the routes that would carry this machine's own traffic"
	)
	said := logged(t)
	live := 0
	reconciler, table, fake := harness(t,
		Table{CaptureGrace: schema.Duration(10 * time.Second)},
		Runtime{Sessions: func() int { return live }})
	clock := start
	reconciler.now = func() time.Time { return clock }
	table.Set(netip.Prefix{}, prefix("::/0"), nil)
	pass := func(at time.Duration, sessions int) {
		t.Helper()
		clock, live = start.Add(at), sessions
		if err := reconciler.reconcile(); err != nil {
			t.Fatal(err)
		}
	}
	stop := func() {
		t.Helper()
		if err := reconciler.withdraw(nil); err != nil {
			t.Fatal(err)
		}
	}
	pass(0, 1)
	routes := fake.snapshot()
	if len(routes) != 1 {
		t.Fatalf("the first pass installed %v, want the default alone", routes)
	}
	stop()
	pass(time.Second, 1)
	stop()
	pass(12*time.Second, 0)
	fake.failAdd[routes[0]] = errRouteSkipped
	pass(13*time.Second, 1)
	delete(fake.failAdd, routes[0])
	pass(14*time.Second, 1)
	text := said.String()
	if got := strings.Count(text, installed); got != 3 {
		t.Errorf("logged the install %d times over an install, a stop and a start, a refused install and the one after it, want 3:\n%s", got, text)
	}
	if got := strings.Count(text, withdrawn); got != 0 {
		t.Errorf("logged the withdrawal %d times with capture not allowed only after a stop, want 0:\n%s", got, text)
	}
}

// A stop that fails leaves the capture as the kernel holds it: where the
// listing or the capturing route's delete fails, the start's pass with capture
// not allowed withdraws the route and logs that, and where only another
// route's delete fails, it logs nothing.
func TestCaptureWithdrawalIsLoggedForWhatAFailedStopLeft(t *testing.T) {
	const withdrawn = "kernel is withdrawing the routes that would carry this machine's own traffic"
	defaultRoute, other := prefix("::/0"), prefix("3fff:1::/48")
	for name, test := range map[string]struct {
		listing bool
		failing netip.Prefix
		want    int
	}{
		"the capturing route's delete fails": {failing: defaultRoute, want: 1},
		"the listing fails":                  {listing: true, want: 1},
		"another route's delete fails":       {failing: other},
	} {
		t.Run(name, func(t *testing.T) {
			said := logged(t)
			live := 1
			reconciler, table, fake := harness(t,
				Table{CaptureGrace: schema.Duration(10 * time.Second)},
				Runtime{Sessions: func() int { return live }})
			clock := start
			reconciler.now = func() time.Time { return clock }
			table.Set(netip.Prefix{}, defaultRoute, nil)
			table.Set(netip.Prefix{}, other, nil)
			if err := reconciler.reconcile(); err != nil {
				t.Fatal(err)
			}
			routes := fake.snapshot()
			if len(routes) != 2 {
				t.Fatalf("the first pass installed %v, want the default and %s", routes, other)
			}
			if test.listing {
				fake.failList = syscall.EBUSY
			}
			for _, route := range routes {
				if route.Destination == test.failing {
					fake.failDel[route] = syscall.EPERM
				}
			}
			if err := reconciler.withdraw(nil); err == nil {
				t.Fatal("the stop succeeded where it should fail")
			}
			fake.failList = nil
			clear(fake.failDel)
			clock, live = start.Add(12*time.Second), 0
			if err := reconciler.reconcile(); err != nil {
				t.Fatal(err)
			}
			if left := fake.snapshot(); slices.ContainsFunc(left, reconciler.captures) {
				t.Fatalf("the start's pass with capture not allowed left %v, want no capture", left)
			}
			if got := strings.Count(said.String(), withdrawn); got != test.want {
				t.Errorf("logged the withdrawal %d times, want %d:\n%s", got, test.want, said.String())
			}
		})
	}
}

// A retracted default is a hold: unscoped it answers with an error for every
// destination, which is the same machine with no network in a different shape.
// captureLiveness holds it back the same way.
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

// A reconciler nobody told about sessions lets every capture in. It is driven by something that has no sessions to report, and
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
		t.Fatal("a reconciler holding a capture did not ask to be woken, so nothing samples the sessions until the sweep")
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

// cap.exit with nothing to ask about liveness is refused at startup and at a
// reload, on every platform. captureLiveness is the only thing keeping the
// mode's default out of the kernel until the mesh has carried traffic. The
// same runtime with a session source starts, and mode off needs none.
func TestModeNeedsASessionSource(t *testing.T) {
	table := netstack.NewRouteTable()
	moded := Table{}.WithMode(&ExitMode{})
	onFake := func(Table, Runtime) (platform, error) { return newFakeKernel(t), nil }
	for _, sessions := range []func() int{nil, func() int { return 0 }} {
		_, err := newOn(moded, Runtime{Interface: "ranet0", Sessions: sessions}, table, onFake)
		if refused := err != nil && strings.Contains(err.Error(), "session source"); refused != (sessions == nil) || sessions != nil && err != nil {
			t.Errorf("New of the mode with a session source %v gave %v", sessions != nil, err)
		}
		reconciler, _, _ := harness(t, Table{}, Runtime{Sessions: sessions})
		err = reconciler.SetTable(moded, nil, nil)
		if refused := err != nil && strings.Contains(err.Error(), "session source"); refused != (sessions == nil) {
			t.Errorf("a reload into the mode with a session source %v gave %v", sessions != nil, err)
		}
		if err := reconciler.SetTable(Table{}, nil, nil); err != nil {
			t.Errorf("a reload into mode off with a session source %v gave %v", sessions != nil, err)
		}
	}
	if _, err := newOn(Table{}, Runtime{Interface: "ranet0"}, table, onFake); err != nil {
		t.Errorf("New in mode off with no session source gave %v", err)
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

// The wake is armed only while a capturing route is installed or wanted, the
// state whose withdrawal nothing else would schedule. A split internet holding
// no zero address counts as a default and arms it too.
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
// sessions' liveness is sampled once a pass and a pass reads the routing
// table, so a millisecond grace only sets how often that happens.
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
