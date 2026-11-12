// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package egress

import (
	"log/slog"
	"net/netip"
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/logtest"
)

// readyEvents is each egress.ready the bus recorded, as its ipv4, ipv6 and
// reason
func readyEvents(bus *events.Bus) []string {
	var out []string
	for _, event := range bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "egress.ready" }, 0) {
		out = append(out, event.Attrs["ipv4"]+" "+event.Attrs["ipv6"]+" "+event.Attrs["reason"])
	}
	return out
}

// An exit's first pass logs each family it judged, ready at info and not ready
// at warn with its reason, and records egress.ready even where no family moved
// from the starting state, which no pass judged
func TestFirstPassReportsEachFamilyItJudged(t *testing.T) {
	const why = "no route leaves outside the mesh"
	hooks := &Hooks{Ready: func(bool, bool, bool) {}, Republish: func() {}}

	var lines strings.Builder
	logtest.SetDefault(t, slog.New(slog.NewTextHandler(&lines, nil)))
	hooks.Events = events.New()
	shell := NewShell(hooks)
	readiness := Readiness{Ready4: true, Why6: why, Carries4: true, Carries6: true}
	shell.SetReady(readiness)
	for _, want := range []string{
		`level=INFO msg="egress ready" family=ipv4`,
		`level=WARN msg="egress not ready" family=ipv6 detail="` + why + `"`,
	} {
		if got := strings.Count(lines.String(), want); got != 1 {
			t.Errorf("the first pass with ipv6 not ready logged %s %d times, want once:\n%s", want, got, lines.String())
		}
	}
	logged, recorded := lines.String(), readyEvents(hooks.Events)
	shell.SetReady(readiness)
	if lines.String() != logged || len(readyEvents(hooks.Events)) != len(recorded) {
		t.Errorf("a second pass judging the same logged %q and recorded %q, want nothing new",
			strings.TrimPrefix(lines.String(), logged), readyEvents(hooks.Events)[len(recorded):])
	}

	lines.Reset()
	hooks.Events = events.New()
	NewShell(hooks).SetReady(Readiness{Why4: why, Why6: why, Carries4: true, Carries6: true})
	if got, want := readyEvents(hooks.Events), []string{"false false " + why}; strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("the first pass with no family ready recorded egress.ready %q, want %q", got, want)
	}
	for _, family := range []string{"ipv4", "ipv6"} {
		if got := strings.Count(lines.String(), `level=WARN msg="egress not ready" family=`+family+" "); got != 1 {
			t.Errorf("the first pass with no family ready logged %s not ready %d times, want once:\n%s", family, got, lines.String())
		}
	}

	lines.Reset()
	NewShell(hooks).SetReady(Readiness{Ready4: true, Carries4: true})
	if strings.Contains(lines.String(), "family=ipv6") {
		t.Errorf("the first pass logged ipv6, a family with no reason, which the exit does not carry:\n%s", lines.String())
	}
}

// A retraction before any pass, as a node started down makes, logs no family,
// and the first judged pass after it is still the first: it logs each family
// it judged and records egress.ready
func TestRetractBeforeAnyPassLeavesTheFirstPassFirst(t *testing.T) {
	const why = "no route leaves outside the mesh"
	hooks := &Hooks{Ready: func(bool, bool, bool) {}, Republish: func() {}, Events: events.New()}
	var lines strings.Builder
	logtest.SetDefault(t, slog.New(slog.NewTextHandler(&lines, nil)))
	shell := NewShell(hooks)
	shell.Retract("the exit is stopped")
	if got := strings.Count(lines.String(), `msg="egress not ready"`); got != 0 {
		t.Errorf("a retraction before any pass logged egress not ready %d times, want none:\n%s", got, lines.String())
	}
	shell.SetReady(Readiness{Why4: why, Why6: why, Carries4: true, Carries6: true})
	for _, family := range []string{"ipv4", "ipv6"} {
		if got := strings.Count(lines.String(), `level=WARN msg="egress not ready" family=`+family+" "); got != 1 {
			t.Errorf("the first pass after a retraction logged %s not ready %d times at warn, want once:\n%s", family, got, lines.String())
		}
	}
	if got, want := readyEvents(hooks.Events), []string{"false false " + why}; strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("the first pass after a retraction recorded egress.ready %q, want %q", got, want)
	}
}

// A retraction before any pass publishes nothing, since nothing was announced,
// so the first pass's announcement after it is no change to log
func TestRetractBeforeAnyPassPublishesNothing(t *testing.T) {
	republished := 0
	hooks := &Hooks{Ready: func(bool, bool, bool) {}, Republish: func() { republished++ }}
	var lines strings.Builder
	logtest.SetDefault(t, slog.New(slog.NewTextHandler(&lines, nil)))
	shell := NewShell(hooks)
	shell.Retract("the exit is stopped")
	if republished != 0 {
		t.Errorf("a retraction before any pass republished %d times, want none", republished)
	}
	shell.Publish([]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")})
	if strings.Contains(lines.String(), `msg="egress advertisement changed"`) {
		t.Errorf("the first announcement after a retraction before any pass logged a change:\n%s", lines.String())
	}
}
