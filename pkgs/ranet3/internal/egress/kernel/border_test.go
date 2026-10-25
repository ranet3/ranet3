// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/logtest"
	"ranet3.com/pkgs/ranet3/schema"
)

// fakeBorder stands in for the kernel under the border filter, as fakeBackend
// does under the translator
type fakeBorder struct {
	mu        sync.Mutex
	held      []Installed
	applied   int
	withdrawn int
	// failRules makes a host whose chain cannot be listed
	failRules bool
	// failApply makes a host that will not take the chain
	failApply bool
	// failWithdraw makes a host that will not let the table go
	failWithdraw bool
	// garble makes a host that holds the last rule written under a comment cut short
	garble bool
	// fault is how the table or the chain differs from what Apply writes. An
	// apply clears it unless stuck holds it, or remake does and the apply
	// does not delete the table first.
	fault         string
	remake, stuck bool
	// counts is each rule's packet counter by spec, as a readback finds it
	counts map[string]uint64
	// changed stands for another writer's changes to the table, nil for none
	changed chan struct{}
	// missed stands for notifications the backend lost, nil for none
	missed chan struct{}
	// log records each listing, apply and withdrawal in order, beside what record adds
	log []string
}

func (f *fakeBorder) record(entry string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log = append(f.log, entry)
}

func (f *fakeBorder) entries() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.log)
}

func (f *fakeBorder) readback() chainReadback {
	out := slices.Clone(f.held)
	for i := range out {
		out[i].Packets = f.counts[out[i].Spec]
	}
	return chainReadback{rules: out, fault: f.fault, remake: f.fault != "" && f.remake}
}

func (f *fakeBorder) Rules() (chainReadback, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log = append(f.log, "rules")
	if f.failRules {
		return chainReadback{}, errors.New("no")
	}
	return f.readback(), nil
}

func (f *fakeBorder) Read() (chainReadback, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.readback(), nil
}

// Apply logs remake for an apply that deletes the table first
func (f *fakeBorder) Apply(rules []BorderRule, remake bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	entry := "apply"
	if remake {
		entry = "remake"
	}
	f.log = append(f.log, entry)
	if f.failApply {
		return errors.New("no")
	}
	f.applied++
	if !f.stuck && (remake || !f.remake) {
		f.fault, f.remake = "", false
	}
	f.held = nil
	for _, rule := range rules {
		f.held = append(f.held, Installed{Spec: rule.String()})
	}
	if f.garble && len(f.held) != 0 {
		last := &f.held[len(f.held)-1]
		last.Spec = last.Spec[:len(last.Spec)-1]
	}
	return nil
}

func (f *fakeBorder) Withdraw() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log = append(f.log, "withdraw")
	if f.failWithdraw {
		return errors.New("no")
	}
	f.withdrawn++
	f.held = nil
	return nil
}

func (f *fakeBorder) Changed() <-chan struct{} { return f.changed }

func (f *fakeBorder) Missed() <-chan struct{} { return f.missed }

func (f *fakeBorder) Close() error { return nil }

func (f *fakeBorder) specs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.held))
	for _, rule := range f.held {
		out = append(out, rule.Spec)
	}
	return out
}

func (f *fakeBorder) setCount(spec string, packets uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.counts == nil {
		f.counts = map[string]uint64{}
	}
	f.counts[spec] = packets
}

// borderRuntime is a filter's runtime over the mesh tun and lo, whose
// readiness goes into be's log between its listings and applies
func borderRuntime(be *fakeBorder, bus *events.Bus, sids ...string) egress.BorderRuntime {
	rt := egress.BorderRuntime{Inside: []string{"ranet0", "lo"}, Events: bus, Ready: func(ok bool) { be.record(fmt.Sprintf("ready %v", ok)) }}
	for _, sid := range sids {
		rt.SIDs = append(rt.SIDs, netip.MustParseAddr(sid))
	}
	return rt
}

// overlay is a valid overlay list of both families
func overlay(t *testing.T, raw ...string) egress.Border {
	t.Helper()
	if len(raw) == 0 {
		raw = []string{"198.18.0.0/15", "3fff::/20"}
	}
	return egress.Border{Overlay: prefixes(t, raw...)}
}

// runBorder runs f until the test ends
func runBorder(t *testing.T, f *BorderFilter) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- f.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
}

// waitForPass waits for a border.pass event woken by trigger
func waitForPass(t *testing.T, bus *events.Bus, trigger string) {
	t.Helper()
	for deadline := time.Now().Add(passWait); ; time.Sleep(passPoll) {
		var triggers []string
		for _, event := range bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "border.pass" }, 0) {
			triggers = append(triggers, event.Attrs["trigger"])
		}
		if slices.Contains(triggers, trigger) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the border filter recorded passes woken by %q, none by %s", triggers, trigger)
		}
	}
}

// The chain takes everything arriving on a device inside the mesh before it
// drops anything, then drops by source, by routing header and by SID in that
// order, each list in one order whatever order it was written in
func TestBorderChainAcceptsTheInsideBeforeAnyDrop(t *testing.T) {
	be := &fakeBorder{}
	rt := borderRuntime(be, nil, "3fff:a::2", "3fff:a::1")
	rt.Inside = []string{"ranet0", "lo", "gravity"}
	f, err := startBorderFilter(overlay(t, "3fff::/20", "198.18.0.0/15", "192.0.2.0/24"), rt, be)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"accept via ranet0",
		"accept via lo",
		"accept via gravity",
		"drop ipv4 source 192.0.2.0/24",
		"drop ipv4 source 198.18.0.0/15",
		"drop ipv6 source 3fff::/20",
		"drop ipv6 routing header",
		"drop ipv6 destination 3fff:a::1",
		"drop ipv6 destination 3fff:a::2",
	}
	if got := be.specs(); !slices.Equal(got, want) {
		t.Errorf("installed %q, want %q", got, want)
	}
	if !f.Stats().Ready || f.Stats().Installed != len(want) {
		t.Errorf("the pass reports %+v, want ready with %d rules", f.Stats(), len(want))
	}
}

// Validation runs in this package, so an overlay list sent by a control plane
// is judged by the rules a written one is, and the SIDs a reload hands the
// filter by the rules the first pass judged
func TestBorderRefusesWhatWouldNotFilter(t *testing.T) {
	for _, one := range []struct {
		name string
		cfg  egress.Border
		sids []string
		want string
	}{
		{"an empty overlay", egress.Border{}, nil, "overlay is empty, so the filter would pass every forged mesh source"},
		{"an entry that is not a prefix", egress.Border{Overlay: []schema.Prefix{{}}}, nil, "is not a prefix"},
		{"bits below the length", egress.Border{Overlay: []schema.Prefix{schema.MustPrefix("198.18.0.1/15")}}, nil, "has bits set below its prefix length"},
		{"an IPv4 prefix written as IPv6", overlay(t, "::ffff:198.18.0.0/111"), nil, "written as IPv6, so write it as 198.18.0.0/15"},
		{"every IPv4 address", overlay(t, "0.0.0.0/0"), nil, "covers every address of its family"},
		{"every IPv6 address", overlay(t, "::/0"), nil, "covers every address of its family"},
		{"an IPv4 prefix under the floor", overlay(t, "8.0.0.0/7"), nil, "is shorter than /8 for IPv4 or /12 for IPv6"},
		{"an IPv6 prefix under the floor", overlay(t, "2000::/11"), nil, "is shorter than /8 for IPv4 or /12 for IPv6"},
		{"an entry written twice", overlay(t, "198.18.0.0/15", "3fff::/20", "198.18.0.0/15"), nil, "198.18.0.0/15 is written twice"},
		{"an IPv4 SID", overlay(t), []string{"192.0.2.1"}, "192.0.2.1 is not one"},
		{"a SID written as IPv4 in IPv6", overlay(t), []string{"::ffff:192.0.2.1"}, "::ffff:192.0.2.1 is not one"},
		{"a SID with a zone", overlay(t), []string{"fe80::1%eth0"}, "fe80::1%eth0 is not one"},
	} {
		t.Run(one.name, func(t *testing.T) {
			var sids []netip.Addr
			for _, sid := range one.sids {
				sids = append(sids, netip.MustParseAddr(sid))
			}
			f := newBorderFilter(overlay(t), borderRuntime(&fakeBorder{}, nil), &fakeBorder{})
			err := f.SetConfig(one.cfg, sids)
			if err == nil || !strings.Contains(err.Error(), one.want) {
				t.Fatalf("refused with %v, want a message containing %q", err, one.want)
			}
			if got := f.Capability(); len(got.Overlay) != 2 || len(f.SIDs()) != 0 {
				t.Errorf("a refused reload left the filter at %v and %v, want the overlay it ran", got, f.SIDs())
			}
			if one.sids == nil {
				if err := one.cfg.Validate(); err == nil || !strings.Contains(err.Error(), one.want) {
					t.Errorf("Validate refused with %v, want a message containing %q", err, one.want)
				}
			}
		})
	}
	// each floor is the shortest prefix taken, not the longest refused
	if err := overlay(t, "10.0.0.0/8", "2000::/12", "192.0.2.7/32", "3fff::7/128").Validate(); err != nil {
		t.Errorf("an overlay at the floors and at full length was refused: %v", err)
	}
}

// The filter runs only with a device inside the mesh, the tun at least, since
// a chain with no accept would drop the mesh's own traffic on every hop
func TestBorderNeedsTheDevicesInsideTheMesh(t *testing.T) {
	_, err := NewBorderFilter(overlay(t), egress.BorderRuntime{})
	if err == nil || !strings.Contains(err.Error(), "needs the devices inside the mesh") {
		t.Fatalf("NewBorderFilter returned %v, want the missing inside list refused", err)
	}
}

// A node that asked for the filter does not start without it: the first pass
// runs before NewBorderFilter returns, and a chain that will not install or
// does not read back as written refuses the start and leaves no table behind
func TestNewBorderRefusesAChainItCannotReadBack(t *testing.T) {
	for _, one := range []struct {
		name string
		be   *fakeBorder
		want string
	}{
		{"a chain the host will not take", &fakeBorder{failApply: true}, "could not be installed in nftables table inet ranet3 chain border: install rules: no"},
		{"a chain that reads back otherwise", &fakeBorder{garble: true}, "is not ready, since its chain reads back other than it was written"},
	} {
		t.Run(one.name, func(t *testing.T) {
			f, err := startBorderFilter(overlay(t), borderRuntime(one.be, nil), one.be)
			if err == nil || !strings.Contains(err.Error(), one.want) {
				t.Fatalf("the start returned %v, want a refusal containing %q", err, one.want)
			}
			if f != nil {
				t.Error("a refused start handed back a filter")
			}
			if one.be.withdrawn != 1 {
				t.Errorf("the refused start withdrew %d times, want once", one.be.withdrawn)
			}
			if slices.Contains(one.be.entries(), "ready true") {
				t.Errorf("the refused start reported the border ready: %q", one.be.entries())
			}
		})
	}
	be := &fakeBorder{}
	if _, err := startBorderFilter(overlay(t), borderRuntime(be, nil), be); err != nil {
		t.Fatal(err)
	}
	if got := be.entries(); !slices.Equal(got, []string{"rules", "apply", "rules", "ready true"}) {
		t.Errorf("the start went %q, want a pass that installs and reads back, then ready", got)
	}
}

// A pass that rewrote the chain or failed is recorded with what woke it, and
// a quiet one is not
func TestBorderRecordsThePassesThatDidSomething(t *testing.T) {
	bus := events.New()
	be := &fakeBorder{}
	f := newBorderFilter(overlay(t), borderRuntime(be, bus), be)
	f.trigger = "sweep"
	f.reconcile()
	f.reconcile()
	be.held = nil
	be.failApply = true
	f.reconcile()
	var got [][]string
	for _, event := range bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "border.pass" }, 0) {
		if event.Attrs["took"] == "" || event.Attrs["trigger"] != "sweep" {
			t.Errorf("a pass was recorded without its trigger or duration: %+v", event)
		}
		got = append(got, []string{event.Attrs["installed"], event.Attrs["err"]})
	}
	if want := [][]string{{"5", ""}, {"0", "install rules: no"}}; !slices.EqualFunc(got, want, slices.Equal) {
		t.Errorf("the border filter recorded %q, want %q", got, want)
	}
}

// Each pass reads the drop counters and records what each class dropped
// since the pass before, once, and only on a pass in which one moved
func TestBorderReportsDropsOncePerPass(t *testing.T) {
	var lines strings.Builder
	logtest.SetDefault(t, slog.New(slog.NewTextHandler(&lines, nil)))
	bus := events.New()
	be := &fakeBorder{}
	f := newBorderFilter(overlay(t), borderRuntime(be, bus, "3fff:a::1"), be)
	f.reconcile()
	be.setCount("drop ipv4 source 198.18.0.0/15", 3)
	be.setCount("drop ipv6 routing header", 1)
	f.reconcile()
	f.reconcile()
	be.setCount("drop ipv4 source 198.18.0.0/15", 5)
	be.setCount("drop ipv6 source 3fff::/20", 2)
	be.setCount("drop ipv6 destination 3fff:a::1", 7)
	// another writer flushed the chain, so this pass lists, rewrites and reads back
	be.mu.Lock()
	be.held = nil
	be.mu.Unlock()
	f.reconcile()
	var got []string
	for _, event := range bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "border.dropped" }, 0) {
		got = append(got, fmt.Sprintf("%s %s %s %s", event.Attrs["overlay_source_ipv4"], event.Attrs["overlay_source_ipv6"], event.Attrs["routing_header"], event.Attrs["sid_destination"]))
	}
	if want := []string{"3 0 1 0", "2 2 0 7"}; !slices.Equal(got, want) {
		t.Errorf("recorded border.dropped %q, want %q", got, want)
	}
	if n := strings.Count(lines.String(), "border filter dropped packets"); n != 2 {
		t.Errorf("logged the drops %d times, want twice:\n%s", n, lines.String())
	}
	if want := (egress.BorderDrops{Source4: 5, Source6: 2, RoutingHeader: 1, Destination: 7}); f.Stats().Dropped != want {
		t.Errorf("the last pass reports %+v dropped, want %+v", f.Stats().Dropped, want)
	}
}

// A counter below its last reading is a chain rewritten in between, which
// starts its counters from zero, so what it reads is all new
func TestBorderDropsAfterARewriteCountFromZero(t *testing.T) {
	was := egress.BorderDrops{Source4: 10, RoutingHeader: 4}
	now := egress.BorderDrops{Source4: 2, RoutingHeader: 6}
	if got, want := dropsSince(now, was), (egress.BorderDrops{Source4: 2, RoutingHeader: 2}); got != want {
		t.Errorf("read %+v since %+v as %+v, want %+v", now, was, got, want)
	}
}

// Another writer changing the filter's table wakes it, and it reports the
// border not ready before the pass that puts the chain back and ready again
// after it, with no sweep due
func TestAnotherWritersChangeTakesTheBorderDownUntilThePassRestoresIt(t *testing.T) {
	bus := events.New()
	be := &fakeBorder{changed: make(chan struct{}, 1)}
	f, err := startBorderFilter(overlay(t), borderRuntime(be, bus), be)
	if err != nil {
		t.Fatal(err)
	}
	f.sweep = lateSweep
	runBorder(t, f)
	be.mu.Lock()
	be.held = nil
	be.mu.Unlock()
	mark := len(be.entries())
	be.changed <- struct{}{}
	waitForPass(t, bus, "changed")
	if got, want := be.entries()[mark:], []string{"ready false", "rules", "apply", "rules", "ready true"}; !slices.Equal(got, want) {
		t.Errorf("after the change the border filter went %q, want %q", got, want)
	}
}

// A rule another writer put in the chain, read back with no comment wherever
// it sits, the chain's rules in another order, and a table or a chain whose
// settings read back other than written each make the pass rewrite them,
// after which the filter reads ready. A chain nf_tables will not change in
// place is rewritten by deleting the table first. A setting the rewrite cannot
// put back leaves the filter not ready, naming it.
func TestBorderRewritesWhatReadsBackOtherThanWritten(t *testing.T) {
	be := &fakeBorder{}
	f, err := startBorderFilter(overlay(t), borderRuntime(be, nil), be)
	if err != nil {
		t.Fatal(err)
	}
	const dormant = "its table carries flags 0x1, where none are written and 0x1 is dormant"
	for _, change := range []struct {
		name  string
		apply func()
		pass  []string
	}{
		{"a rule with no comment at the head of the chain", func() { be.held = append([]Installed{{}}, be.held...) }, []string{"rules", "apply", "rules"}},
		{"a rule with no comment at the tail of the chain", func() { be.held = append(be.held, Installed{}) }, []string{"rules", "apply", "rules"}},
		{"the chain's rules in another order", func() { slices.Reverse(be.held) }, []string{"rules", "apply", "rules"}},
		{"a table set dormant", func() { be.fault = dormant }, []string{"rules", "apply", "rules"}},
		{"the chain made again at another priority", func() { be.fault, be.remake = "its chain reads back at priority 0", true }, []string{"rules", "remake", "rules"}},
	} {
		be.mu.Lock()
		change.apply()
		be.mu.Unlock()
		mark := len(be.entries())
		if err := f.reconcile(); err != nil {
			t.Fatalf("%s: %v", change.name, err)
		}
		if got := be.entries()[mark:]; !slices.Equal(got, change.pass) || !f.ready {
			t.Errorf("%s: the pass went %q and left the filter ready %v, want %q and ready", change.name, got, f.ready, change.pass)
		}
	}
	be.mu.Lock()
	be.fault, be.stuck = dormant, true
	be.mu.Unlock()
	if err := f.reconcile(); err != nil {
		t.Fatal(err)
	}
	if f.ready || f.unready != dormant || f.Stats().Unready != dormant {
		t.Errorf("a table the rewrite leaves dormant reads ready %v, unready %q", f.ready, f.unready)
	}
}

// Notifications the backend lost wake a pass with no sweep due that puts back
// whatever a lost deletion took, and never report the border not ready, since
// another table's large transaction overflows the socket as readily as a flush
// of this one
func TestMissedNotificationsWakeTheBorderAndLeaveItReady(t *testing.T) {
	bus := events.New()
	be := &fakeBorder{missed: make(chan struct{}, 1)}
	f, err := startBorderFilter(overlay(t), borderRuntime(be, bus), be)
	if err != nil {
		t.Fatal(err)
	}
	f.sweep = lateSweep
	runBorder(t, f)
	be.mu.Lock()
	be.held = nil
	be.mu.Unlock()
	mark := len(be.entries())
	be.missed <- struct{}{}
	waitForPass(t, bus, "missed")
	if got, want := be.entries()[mark:], []string{"rules", "apply", "rules"}; !slices.Equal(got, want) {
		t.Errorf("after the lost notifications the border filter went %q, want %q", got, want)
	}
}

// A reload hands the filter a new overlay and new SIDs, and the run
// goroutine rewrites the chain at once rather than at the next sweep
func TestBorderReloadRewritesTheChainInPlace(t *testing.T) {
	bus := events.New()
	be := &fakeBorder{}
	f, err := startBorderFilter(overlay(t), borderRuntime(be, bus), be)
	if err != nil {
		t.Fatal(err)
	}
	f.sweep = lateSweep
	runBorder(t, f)
	if err := f.SetConfig(overlay(t, "192.0.2.0/24"), []netip.Addr{netip.MustParseAddr("3fff:a::1")}); err != nil {
		t.Fatal(err)
	}
	waitForPass(t, bus, "reload")
	want := []string{"accept via ranet0", "accept via lo", "drop ipv4 source 192.0.2.0/24", "drop ipv6 routing header", "drop ipv6 destination 3fff:a::1"}
	if got := be.specs(); !slices.Equal(got, want) {
		t.Errorf("after the reload the chain holds %q, want %q", got, want)
	}
}

// A pass that fails is tried again on the backoff rather than at the next sweep
func TestBorderRetriesAFailedPass(t *testing.T) {
	bus := events.New()
	be := &fakeBorder{changed: make(chan struct{}, 1)}
	f, err := startBorderFilter(overlay(t), borderRuntime(be, bus), be)
	if err != nil {
		t.Fatal(err)
	}
	f.sweep = lateSweep
	be.mu.Lock()
	be.held, be.failApply = nil, true
	be.mu.Unlock()
	runBorder(t, f)
	be.changed <- struct{}{}
	waitForPass(t, bus, "retry")
}

// The retry both run loops share starts disarmed, and each failed pass arms it
// on a backoff doubling from minRetryInterval up to the sweep. A pass that
// succeeds disarms it, and the next failure backs off from the start again.
func TestRetryBacksOffUpToTheSweepAndStartsOverAfterAPass(t *testing.T) {
	sweep := 5 * minRetryInterval
	retry := newRetryTimer(sweep)
	t.Cleanup(func() { retry.Stop() })
	if retry.Stop() {
		t.Error("a new retry is armed before any pass failed")
	}
	var got []time.Duration
	for range 5 {
		got = append(got, retry.failed())
	}
	if want := []time.Duration{minRetryInterval, 2 * minRetryInterval, 4 * minRetryInterval, sweep, sweep}; !slices.Equal(got, want) {
		t.Errorf("5 failed passes backed off %v, want %v", got, want)
	}
	retry.passed()
	if retry.Stop() {
		t.Error("a pass that succeeded left the retry armed")
	}
	if backoff := retry.failed(); backoff != minRetryInterval {
		t.Errorf("the first failure after a pass backed off %v, want %v", backoff, minRetryInterval)
	}
	if !retry.Stop() {
		t.Error("a failed pass left the retry disarmed")
	}
}

// A filter that stops reports the border not ready before its table goes,
// so the egress segments stop before a forged source can pass, and Run
// returns the withdrawal's error
func TestBorderStopsNotReadyBeforeItWithdraws(t *testing.T) {
	for _, failing := range []bool{false, true} {
		be := &fakeBorder{}
		f, err := startBorderFilter(overlay(t), borderRuntime(be, nil), be)
		if err != nil {
			t.Fatal(err)
		}
		be.failWithdraw = failing
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err = f.Run(ctx)
		if failing != (err != nil) {
			t.Errorf("a withdrawal failing %v stopped with %v", failing, err)
		}
		entries := be.entries()
		if got := entries[len(entries)-2:]; !slices.Equal(got, []string{"ready false", "withdraw"}) {
			t.Errorf("the border filter stopped by %q, want not ready and then the withdrawal", got)
		}
	}
}

// A debug read lays the chain held now beside the one the configuration asks
// for: each desired rule with its counters or as not held yet, then any rule
// held that the configuration does not ask for
func TestBorderDebugReadsTheChainBesideTheDesiredOne(t *testing.T) {
	be := &fakeBorder{}
	f, err := startBorderFilter(overlay(t), borderRuntime(be, nil), be)
	if err != nil {
		t.Fatal(err)
	}
	be.setCount("drop ipv4 source 198.18.0.0/15", 12)
	be.setCount("", 3)
	be.mu.Lock()
	be.held = slices.DeleteFunc(be.held, func(rule Installed) bool { return rule.Spec == "accept via lo" })
	be.held = append(be.held, Installed{Spec: "drop ipv4 source 192.0.2.0/24"}, Installed{})
	be.mu.Unlock()
	debug := f.Debug()
	if debug.Where != "nftables table inet ranet3 chain border" || debug.Hook != "prerouting" || debug.Priority != -300 || !debug.Ready {
		t.Errorf("the debug read reports %+v", debug)
	}
	var got []string
	for _, rule := range debug.Rules {
		got = append(got, fmt.Sprintf("%s|%s|%s|%s|%v|%d", rule.Spec, rule.Verdict, rule.Reason, rule.Family, rule.Held, rule.Packets))
	}
	want := []string{
		"accept via ranet0|accept|inside||true|0",
		"accept via lo|accept|inside||false|0",
		"drop ipv4 source 198.18.0.0/15|drop|overlay_source|ipv4|true|12",
		"drop ipv6 source 3fff::/20|drop|overlay_source|ipv6|true|0",
		"drop ipv6 routing header|drop|routing_header|ipv6|true|0",
		"drop ipv4 source 192.0.2.0/24|drop|||true|0",
		"a rule with no comment||||true|3",
	}
	if !slices.Equal(got, want) {
		t.Errorf("the debug read lists\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
