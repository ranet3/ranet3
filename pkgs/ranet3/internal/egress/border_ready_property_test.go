// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package egress

import (
	"slices"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/schema"
)

// borderStep is the host under one pass of the border filter
type borderStep struct {
	held                         []Installed
	fault                        string
	remake, stuck                bool
	failRules, failApply, garble bool
}

// borderSteps draws the host before each pass. Its chain holds every rule the
// filter asks for half the time and some of them otherwise, now and then
// reversed, and now and then another writer's rule among them, at the tail
// half the time, with no spelling or one the filter never writes. The table or
// the chain now and then reads back with a setting a rewrite puts back in
// place, one only a remade table puts back, or one nothing puts back, and a
// listing or an apply now and then fails, or the chain comes back garbled.
func borderSteps(desired []BorderRule) hegel.Generator[borderStep] {
	foreign := []string{"", "drop ipv4 source 192.0.2.0/24"}
	faults := []string{
		"its table carries flags 0x1, where none are written and 0x1 is dormant",
		`its chain reads back as type "filter" at hook 0, priority 0, policy 1, where a filter chain at hook 0, priority -300, policy accept was written`,
	}
	return hegel.Composite(func(tc hegel.TestCase) borderStep {
		s := borderStep{
			failRules: hegel.Draw(tc, hegel.WeightedBooleans(1.0/8)),
			failApply: hegel.Draw(tc, hegel.WeightedBooleans(1.0/8)),
			garble:    hegel.Draw(tc, hegel.WeightedBooleans(1.0/8)),
		}
		every := hegel.Draw(tc, hegel.Booleans())
		for _, rule := range desired {
			if every || hegel.Draw(tc, hegel.WeightedBooleans(3.0/4)) {
				s.held = append(s.held, Installed{Spec: rule.String()})
			}
		}
		if hegel.Draw(tc, hegel.WeightedBooleans(1.0/4)) {
			slices.Reverse(s.held)
		}
		if hegel.Draw(tc, hegel.WeightedBooleans(1.0/4)) {
			at := len(s.held)
			if hegel.Draw(tc, hegel.Booleans()) {
				at = hegel.Draw(tc, hegel.Integers(0, len(s.held)))
			}
			s.held = slices.Insert(s.held, at, Installed{Spec: hegel.Draw(tc, hegel.SampledFrom(foreign))})
		}
		if hegel.Draw(tc, hegel.WeightedBooleans(1.0/4)) {
			s.fault = hegel.Draw(tc, hegel.SampledFrom(faults))
			s.remake = hegel.Draw(tc, hegel.Booleans())
			s.stuck = hegel.Draw(tc, hegel.WeightedBooleans(1.0/4))
		}
		return s
	})
}

// borderPassAfter is the model of one pass over now: the listings and
// applies it makes in order, the chain the host holds after it, the rules the
// pass counts and its readiness with the reason it is not ready. The pass
// rewrites the chain when the readback carries a fault or its spellings are
// not the desired ones in order, deleting the table first where the fault says
// only that puts it back, and reads ready when the readback after it carries
// no fault and every desired spelling in order with nothing else.
func borderPassAfter(now borderStep, desired []BorderRule) (log, chain []string, installed int, ready bool, unready string) {
	want := make([]string, 0, len(desired))
	for _, rule := range desired {
		want = append(want, rule.String())
	}
	for _, rule := range now.held {
		chain = append(chain, rule.Spec)
	}
	log = []string{"rules"}
	if now.failRules {
		return log, chain, 0, false, "a pass failed: list rules: no"
	}
	if now.fault == "" && slices.Equal(chain, want) {
		return log, chain, len(chain), true, ""
	}
	if now.fault != "" && now.remake {
		log = append(log, "remake")
	} else {
		log = append(log, "apply")
	}
	if now.failApply {
		return log, chain, len(chain), false, "a pass failed: install rules: no"
	}
	log = append(log, "rules")
	chain = slices.Clone(want)
	if now.garble {
		chain[len(chain)-1] = chain[len(chain)-1][:len(chain[len(chain)-1])-1]
	}
	switch {
	case now.stuck:
		return log, chain, len(chain), false, now.fault
	case !slices.Equal(chain, want):
		return log, chain, len(chain), false, "its chain reads back other than it was written"
	}
	return log, chain, len(chain), true, ""
}

// Over a run of passes on a host drawn anew for each, the border filter lists,
// rewrites and reads back as borderPassAfter does, leaves the host holding the
// model's chain, and reports the model's readiness and reason in Stats and
// through Ready, which hears only a change.
func TestBorderReadinessFollowsWhatThePassReadBack(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		var sids []string
		for _, sid := range []string{"3fff:a::1", "3fff:a::2"} {
			if hegel.Draw(ht, hegel.Booleans()) {
				sids = append(sids, sid)
			}
		}
		be := &fakeBorder{}
		var calls []bool
		rt := borderRuntime(be, nil, sids...)
		rt.Ready = func(ok bool) { calls = append(calls, ok) }
		cfg := Border{Overlay: []schema.Prefix{schema.MustPrefix("198.18.0.0/15"), schema.MustPrefix("3fff::/20")}}
		f := newBorderFilter(cfg, rt, be)
		desired := f.desired()
		ready := false
		for range hegel.Draw(ht, pbt.Spanning(1, 5)) {
			now := hegel.Draw(ht, borderSteps(desired))
			be.mu.Lock()
			be.held, be.fault, be.remake, be.stuck = slices.Clone(now.held), now.fault, now.remake, now.stuck
			be.failRules, be.failApply, be.garble = now.failRules, now.failApply, now.garble
			be.log = nil
			be.mu.Unlock()
			log, chain, installed, wantReady, unready := borderPassAfter(now, desired)
			told := len(calls)
			_ = f.reconcile()
			if got := be.entries(); !slices.Equal(got, log) {
				ht.Fatalf("over %+v the pass went %q, want %q", now, got, log)
			}
			if got := be.specs(); !slices.Equal(got, chain) {
				ht.Fatalf("over %+v the pass left the host holding %q, want %q", now, got, chain)
			}
			if stats := f.Stats(); stats.Ready != wantReady || stats.Unready != unready || stats.Installed != installed {
				ht.Fatalf("over %+v the pass reports ready %v (%q) over %d rules, want ready %v (%q) over %d", now, stats.Ready, stats.Unready, stats.Installed, wantReady, unready, installed)
			}
			if wantReady == ready && len(calls) != told || wantReady != ready && !slices.Equal(calls[told:], []bool{wantReady}) {
				ht.Fatalf("over %+v Ready was told %v after %v, want only a change to %v", now, calls[told:], ready, wantReady)
			}
			ready = wantReady
		}
	})
}
