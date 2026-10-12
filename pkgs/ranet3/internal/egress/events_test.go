// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package egress

import (
	"context"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/schema"
)

// passWait is how long a test waits for a pass it expects, generous for a loaded machine
// passPoll is how often it looks
// sweepEvery is the sweep of a test that waits for one
// stoppedFor is how long a stopped translator is watched for a sweep that installs anything, four of those sweeps
// lateSweep is the sweep of a test in which only a retry may act, out past passWait
const (
	passWait   = 30 * time.Second
	passPoll   = 5 * time.Millisecond
	sweepEvery = 100 * time.Millisecond
	stoppedFor = 4 * sweepEvery
	lateSweep  = 2 * passWait
)

// a pass that rewrote the rules, moved the announcement or failed is recorded, and a quiet one is not
func TestTranslatorRecordsThePassesThatDidSomething(t *testing.T) {
	bus := events.New()
	be := &fakeBackend{}
	forwards := true
	tr := translator(t, Egress{Advertise: prefixes(t, "0.0.0.0/0", "::/0")},
		Runtime{Events: bus, Forwarding: func() (bool, bool) { return forwards, true }}, be)
	tr.trigger = "sweep"
	tr.reconcile()
	tr.reconcile()
	// somebody else flushed the table, so the pass puts the rules back and announces what it announced
	be.held = nil
	tr.reconcile()
	forwards = false
	tr.reconcile()
	be.failApply, be.held = true, nil
	tr.reconcile()

	var got [][]string
	for _, event := range bus.Recorded(func(string, string, []slog.Attr) bool { return true }, 0) {
		if event.Attrs["took"] == "" || event.Attrs["trigger"] != "sweep" {
			t.Errorf("a pass was recorded without its trigger or duration: %+v", event)
		}
		got = append(got, []string{event.Kind, event.Attrs["installed"], event.Attrs["announced"], event.Attrs["err"]})
	}
	want := [][]string{
		{"egress.pass", "2", "2", ""},
		{"egress.pass", "2", "2", ""},
		{"egress.pass", "2", "1", ""},
		{"egress.pass", "0", "0", "install rules: no"},
	}
	if !slices.EqualFunc(got, want, slices.Equal) {
		t.Errorf("the translator recorded %q, want %q", got, want)
	}
}

// a running translator names what woke it for each pass it records, its first pass and the retry of a failed one
func TestTranslatorNamesWhatWokeIt(t *testing.T) {
	bus := events.New()
	tr := translator(t, Egress{Advertise: prefixes(t, "0.0.0.0/0")}, Runtime{Events: bus}, &fakeBackend{failApply: true})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- tr.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	for deadline := time.Now().Add(passWait); ; time.Sleep(passPoll) {
		var triggers []string
		for _, event := range bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "egress.pass" }, 0) {
			triggers = append(triggers, event.Attrs["trigger"])
		}
		if len(triggers) >= 2 && slices.Equal(triggers[:2], []string{"start", "retry"}) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the translator recorded passes woken by %q, want start and then retry", triggers)
		}
	}
}

// a running translator told to stop retracts its advertisement, then withdraws its tables, and holds nothing across its sweeps
// told to start again it installs the rules and announces on the pass the start woke
func TestStoppedTranslatorWithdrawsUntilItIsStartedAgain(t *testing.T) {
	bus := events.New()
	be := &fakeBackend{}
	tr := translator(t, Egress{Advertise: prefixes(t, "0.0.0.0/0"), Sweep: schema.Duration(sweepEvery)}, Runtime{Events: bus}, be)
	var mu sync.Mutex
	withdrawnWhenRetracted := -1
	tr.rt.Announce = func(p []netip.Prefix) {
		if len(p) != 0 {
			return
		}
		be.mu.Lock()
		withdrawn := be.withdrawn
		be.mu.Unlock()
		mu.Lock()
		withdrawnWhenRetracted = withdrawn
		mu.Unlock()
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- tr.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	state := func() (held, withdrawn int) {
		be.mu.Lock()
		defer be.mu.Unlock()
		return len(be.held), be.withdrawn
	}
	await := func(what, trigger string, ok func() bool) {
		t.Helper()
		for deadline := time.Now().Add(passWait); ; time.Sleep(passPoll) {
			passes := bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "egress.pass" }, 0)
			if len(passes) > 0 && passes[len(passes)-1].Attrs["trigger"] == trigger && ok() {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s, the translator recorded %d passes", what, len(passes))
			}
		}
	}
	await("the first pass", "start", func() bool {
		held, _ := state()
		return held > 0 && len(tr.Announce()) == 1
	})

	tr.SetEnabled(false)
	await("the stop", "disable", func() bool {
		held, withdrawn := state()
		return held == 0 && withdrawn == 1 && len(tr.Announce()) == 0
	})
	mu.Lock()
	if withdrawnWhenRetracted != 0 {
		t.Errorf("the advertisement was retracted after %d withdrawals, want before the first", withdrawnWhenRetracted)
	}
	mu.Unlock()
	if stats := tr.Stats(); stats.Installed != 0 || len(stats.Announced) != 0 {
		t.Errorf("a stopped translator reports %+v, want nothing installed or announced", stats)
	}
	time.Sleep(stoppedFor)
	if held, withdrawn := state(); held != 0 || withdrawn != 1 {
		t.Errorf("the sweeps after the stop left %d rules held and withdrew %d times, want none held and one withdrawal", held, withdrawn)
	}

	tr.SetEnabled(true)
	await("the start", "enable", func() bool {
		held, _ := state()
		return held > 0 && len(tr.Announce()) == 1
	})
}

// a start whose pass a sweep ran before its wake was read still ends the record of the last stop
// the stop after it then withdraws what that pass installed
// enabled is stored without the wake, which is how the select leaves a start whose wake it passed over for the tick
func TestStartTheSweepReachedFirstIsStoppedAgain(t *testing.T) {
	be := &fakeBackend{}
	tr := translator(t, Egress{Advertise: prefixes(t, "0.0.0.0/0"), Sweep: schema.Duration(sweepEvery)}, Runtime{Events: events.New()}, be)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- tr.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	state := func() (held, withdrawn int) {
		be.mu.Lock()
		defer be.mu.Unlock()
		return len(be.held), be.withdrawn
	}
	await := func(what string, ok func() bool) {
		t.Helper()
		for deadline := time.Now().Add(passWait); !ok(); time.Sleep(passPoll) {
			if time.Now().After(deadline) {
				held, withdrawn := state()
				t.Fatalf("timed out waiting for %s, with %d rules held after %d withdrawals and %v announced", what, held, withdrawn, tr.Announce())
			}
		}
	}
	installed := func() bool {
		held, _ := state()
		return held > 0 && len(tr.Announce()) == 1
	}
	stopped := func(times int) func() bool {
		return func() bool {
			held, withdrawn := state()
			return held == 0 && withdrawn == times && len(tr.Announce()) == 0
		}
	}
	await("the first pass", installed)
	tr.SetEnabled(false)
	await("the stop", stopped(1))
	tr.enabled.Store(true)
	await("a sweep to install the rules again", installed)
	tr.SetEnabled(false)
	await("the second stop", stopped(2))
}

// a stop whose withdrawal failed is still a stop the translator owes
// it tries again rather than recording the tables as gone
// the sweep is out past the wait
// only the retry a failed pass takes can then withdraw the tables within it
func TestStoppedTranslatorRetriesAWithdrawalThatFailed(t *testing.T) {
	be := &fakeBackend{}
	tr := translator(t, Egress{Advertise: prefixes(t, "0.0.0.0/0"), Sweep: schema.Duration(lateSweep)}, Runtime{Events: events.New()}, be)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- tr.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	await := func(what string, ok func() bool) {
		t.Helper()
		for deadline := time.Now().Add(passWait); !ok(); time.Sleep(passPoll) {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s, the last pass reading %+v", what, tr.Stats())
			}
		}
	}
	held := func() int {
		be.mu.Lock()
		defer be.mu.Unlock()
		return len(be.held)
	}
	await("the first pass", func() bool { return held() > 0 })

	be.mu.Lock()
	be.failWithdraw = true
	be.mu.Unlock()
	tr.SetEnabled(false)
	await("the stop to fail", func() bool { return tr.Stats().Err != "" })

	be.mu.Lock()
	be.failWithdraw = false
	be.mu.Unlock()
	await("the retry to withdraw the tables", func() bool { return held() == 0 && tr.Stats().Err == "" })
}

// a pass the sweep woke, putting back rules somebody else flushed, is named for the sweep
func TestTranslatorNamesTheSweep(t *testing.T) {
	bus := events.New()
	be := &fakeBackend{}
	tr := translator(t, Egress{Advertise: prefixes(t, "0.0.0.0/0"), Sweep: schema.Duration(sweepEvery)}, Runtime{Events: bus}, be)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- tr.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	held := func() bool {
		be.mu.Lock()
		defer be.mu.Unlock()
		return len(be.held) > 0
	}
	await := func(what, trigger string) {
		t.Helper()
		for deadline := time.Now().Add(passWait); ; time.Sleep(passPoll) {
			passes := bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "egress.pass" }, 0)
			if len(passes) > 0 && passes[len(passes)-1].Attrs["trigger"] == trigger && held() {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s, the translator recorded %d passes", what, len(passes))
			}
		}
	}
	await("the first pass", "start")
	be.mu.Lock()
	be.held = nil
	be.mu.Unlock()
	await("the sweep to put the rules back", "sweep")
}
