// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"errors"
	"net/netip"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/netstack"
)

// watchedKernel is the fake with a monitor watching its switch: rec is the
// record the monitor reports to, stopped a monitor no longer reading, reads
// counts the reads of the switch, and during runs inside each read
type watchedKernel struct {
	*fakeKernel
	rec     *switchRecord
	stopped bool
	reads   int
	during  func()
}

func (k *watchedKernel) readFallback(s fallbackSets) (fallbackRead, error) {
	k.reads++
	if k.during != nil {
		k.during()
	}
	return k.fakeKernel.readFallback(s)
}

func (k *watchedKernel) liveRecord() *switchRecord {
	if k.stopped {
		return nil
	}
	return k.rec
}

// readingTriggers is every trigger of Run but the two a route change alone wakes a pass for
var readingTriggers = []string{"start", "sweep", "retry", "grace", "disable", "enable", "reload", "network", "underlay"}

// recordHost is exitPassHost with docker0, and recordMovedHost the same with a LAN on wlan0 as well, which moves the switch's lan4
var (
	recordHost      = exitPassHost("docker0")
	recordMovedHost = func() NetworkState {
		host := exitPassHost("docker0")
		host.IPv4.Links = append(host.IPv4.Links, Link{Name: "wlan0", Prefixes: []netip.Prefix{prefix("192.168.7.2/24")}})
		return host
	}()
)

// recordReconciler is a reconciler under fallback none on network, on a fake
func recordReconciler(t *testing.T, network *hostNetwork) (*Reconciler, *fakeKernel) {
	t.Helper()
	tbl := Table{Addresses: prefixes(prefix("192.0.2.1/32"), prefix("3fff::1/128"))}.WithMode(&ExitMode{Fallback: FallbackNone, LAN: exitPassLAN})
	reconciler, routes, fake := harness(t, tbl, Runtime{Interface: "ranet3", Overlay: exitPassOverlay, Network: network.read, Sessions: func() int { return 1 }})
	routes.Set(netip.Prefix{}, prefix("203.0.113.0/24"), netstack.Local)
	return reconciler, fake
}

// watchedHarness is a reconciler on recordHost whose switch a monitor
// watches, past a start that wrote the switch
func watchedHarness(t *testing.T) (*Reconciler, *watchedKernel, *hostNetwork) {
	t.Helper()
	network := &hostNetwork{state: recordHost}
	reconciler, fake := recordReconciler(t, network)
	watched := &watchedKernel{fakeKernel: fake, rec: &switchRecord{}}
	reconciler.use(watched)
	if reads, err := watched.pass(reconciler, "start"); reads != 2 || err != nil {
		t.Fatalf("the start read the switch %d times with %v, want a read, a write and a read of what it wrote", reads, err)
	}
	return reconciler, watched, network
}

// unwatchedHarness is a reconciler on network with no monitor watching its switch, which every pass that asks for
// the switch reads, past its start
func unwatchedHarness(t *testing.T, network *hostNetwork) (*Reconciler, *fakeKernel) {
	t.Helper()
	reconciler, fake := recordReconciler(t, network)
	reconciler.trigger = "start"
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	return reconciler, fake
}

// pass runs one pass of r woken by trigger and answers how often it read the switch
func (k *watchedKernel) pass(r *Reconciler, trigger string) (int, error) {
	before := k.reads
	r.trigger = trigger
	err := r.reconcile()
	return k.reads - before, err
}

// A pass woken by a route change alone reads the switch only where the
// switch's monitor reported a change or a loss since the last read began, its
// sets moved, the last read did not find it as written or the monitor
// stopped, and every pass woken otherwise reads it
func TestFallbackReadOnlyWhereSomethingItReadsMayHaveMoved(t *testing.T) {
	for _, step := range []struct {
		name    string
		before  func(*watchedKernel, *hostNetwork)
		trigger string
		want    int
	}{
		{"a route change", nil, "mesh", 0},
		{"the route monitor", nil, "kernel", 0},
		{"a change the switch's monitor reported", func(k *watchedKernel, _ *hostNetwork) { k.rec.moved.Store(true) }, "kernel", 1},
		// the read finds the switch holding the old sets, so the pass writes it and reads it again
		{"the switch's sets moved", func(_ *watchedKernel, n *hostNetwork) { n.set(recordMovedHost) }, "mesh", 2},
		{"the switch's monitor stopped", func(k *watchedKernel, _ *hostNetwork) { k.stopped = true }, "mesh", 1},
	} {
		t.Run(step.name, func(t *testing.T) {
			reconciler, watched, network := watchedHarness(t)
			if step.before != nil {
				step.before(watched, network)
			}
			if reads, err := watched.pass(reconciler, step.trigger); reads != step.want || err != nil {
				t.Fatalf("a pass woken by %s read the switch %d times with %v, want %d", step.trigger, reads, err, step.want)
			}
			// the read takes what moved, but a stopped monitor leaves every pass reading
			want := 0
			if watched.stopped {
				want = 1
			}
			for range 2 {
				if reads, err := watched.pass(reconciler, "mesh"); reads != want || err != nil {
					t.Fatalf("a route change after it read the switch %d times with %v, want %d", reads, err, want)
				}
			}
		})
	}
	for _, trigger := range readingTriggers {
		t.Run(trigger, func(t *testing.T) {
			reconciler, watched, _ := watchedHarness(t)
			if reads, err := watched.pass(reconciler, trigger); reads != 1 || err != nil {
				t.Fatalf("a pass woken by %s with nothing moved read the switch %d times with %v, want 1", trigger, reads, err)
			}
		})
	}
}

// A read that does not find the switch as written, rewritten or not, leaves
// the passes after it reading until one finds it so, and a read that fails
// leaves the next reading as well
func TestFallbackReadOnEveryPassUntilOneFindsTheSwitchAsWritten(t *testing.T) {
	reconciler, watched, _ := watchedHarness(t)
	watched.spoiled, watched.failWrite = "its set lan4 holds { }", errors.New("netlink: write refused")
	watched.rec.moved.Store(true)
	for i := range 3 {
		if reads, err := watched.pass(reconciler, "mesh"); reads != 1 || err == nil {
			t.Fatalf("route change %d over a switch that does not read back read it %d times with %v, want once and an error", i, reads, err)
		}
	}
	watched.spoiled, watched.failWrite = "", nil
	if reads, err := watched.pass(reconciler, "mesh"); reads != 1 || err != nil {
		t.Fatalf("the route change after the switch read back again read it %d times with %v, want 1", reads, err)
	}
	watched.failFallback = errors.New("netlink: dump interrupted")
	watched.rec.moved.Store(true)
	if reads, err := watched.pass(reconciler, "mesh"); reads != 1 || err == nil {
		t.Fatalf("a read that fails read %d times with %v, want once and an error", reads, err)
	}
	watched.failFallback = nil
	for _, want := range []int{1, 0} {
		if reads, err := watched.pass(reconciler, "mesh"); reads != want || err != nil {
			t.Fatalf("a route change after a failed read read the switch %d times with %v, want %d", reads, err, want)
		}
	}
}

// A pass that skips the read reports the switch as the last read left it,
// its drops as that read counted them, and the next read counts them anew
func TestFallbackSkippedReadReportsTheLastRead(t *testing.T) {
	reconciler, watched, _ := watchedHarness(t)
	watched.fallbackDropped = 5
	if reads, _ := watched.pass(reconciler, "sweep"); reads != 1 {
		t.Fatalf("the sweep read the switch %d times, want 1", reads)
	}
	watched.fallbackDropped = 9
	if reads, _ := watched.pass(reconciler, "mesh"); reads != 0 {
		t.Fatalf("the route change read the switch %d times, want none", reads)
	}
	if got, want := dropsReported(reconciler), "5 packets of 300 bytes, holding"; got != want {
		t.Errorf("the pass that skipped the read reported %q, want %q", got, want)
	}
	if reads, _ := watched.pass(reconciler, "sweep"); reads != 1 {
		t.Fatalf("the sweep read the switch %d times, want 1", reads)
	}
	if got, want := dropsReported(reconciler), "9 packets of 540 bytes, holding"; got != want {
		t.Errorf("the sweep after it reported %q, want %q", got, want)
	}
}

// A change the switch's monitor reports while a pass reads the switch has the
// next pass a route change alone wakes read it, and the pass after that skip
func TestFallbackChangeReportedDuringAReadHasTheNextPassRead(t *testing.T) {
	reconciler, watched, _ := watchedHarness(t)
	watched.during = func() { watched.rec.moved.Store(true) }
	if reads, err := watched.pass(reconciler, "sweep"); reads != 1 || err != nil {
		t.Fatalf("the sweep read the switch %d times with %v, want 1", reads, err)
	}
	watched.during = nil
	for _, want := range []int{1, 0} {
		if reads, err := watched.pass(reconciler, "mesh"); reads != want || err != nil {
			t.Fatalf("a route change after the read the monitor reported a change during read the switch %d times with %v, want %d", reads, err, want)
		}
	}
}
