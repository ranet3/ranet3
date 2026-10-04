// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package egress

import (
	"context"
	"log/slog"
	"slices"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/schema"
)

// passWait is how long a test waits for a pass it expects, generous for a loaded machine
// passPoll is how often it looks
// sweepEvery is the sweep of a test that waits for one
const (
	passWait   = 30 * time.Second
	passPoll   = 5 * time.Millisecond
	sweepEvery = 100 * time.Millisecond
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
