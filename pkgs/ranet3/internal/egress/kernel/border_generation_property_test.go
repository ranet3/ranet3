// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package kernel

import (
	"maps"
	"slices"
	"strings"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// hostView is the filter's sets and chain specs a host holds, and the rules a
// read of them was asked about
type hostView struct {
	sets  borderSets
	held  []string
	rules []BorderRule
}

// same reports whether v and o hold the same sets and specs
func (v hostView) same(o hostView) bool {
	for name := range maps.Keys(v.sets) {
		if !slices.Equal(v.sets[name], o.sets[name]) {
			return false
		}
	}
	for name := range maps.Keys(o.sets) {
		if !slices.Equal(v.sets[name], o.sets[name]) {
			return false
		}
	}
	return slices.Equal(v.held, o.held)
}

// watchedBorder is a counted host that keeps what the last read found where
// it found the filter as written, nil where it did not, and whether a step of
// another writer's committed during a read
type watchedBorder struct {
	*countedBorder
	clean *hostView
	fired bool
}

func (w *watchedBorder) view() hostView {
	w.mu.Lock()
	defer w.mu.Unlock()
	v := hostView{sets: borderSets{}}
	for name, ranges := range w.sets {
		v.sets[name] = slices.Clone(ranges)
	}
	for _, rule := range w.held {
		v.held = append(v.held, rule.Spec)
	}
	return v
}

func (w *watchedBorder) Rules(rules []BorderRule, sets borderSets) (chainReadback, error) {
	seen := w.view()
	read, err := w.countedBorder.Rules(rules, sets)
	w.clean = nil
	if err == nil && read.fault == "" {
		seen.rules = rules
		w.clean = &seen
	}
	return read, err
}

// borderTriggers is every trigger of Run's
var borderTriggers = []string{"sweep", "retry", "reload", "routes", "kernel", "network", "changed", "missed"}

// Over a drawn order of another writer's transactions, committed, empty or
// refused, transactions that commit while a read runs, changes of the sets and
// the rules, fills short or refused, failed reads and passes of every
// trigger, on a host whose generation each committed transaction moves, a pass
// that skips its read fills only over the sets and chains the last read found
// as written for the rules the pass writes, and a pass that touched the host
// and ended ready leaves the host as written, so a filter not as written is
// found by the pass that fills it or the next pass that reads
func TestBorderSkipFillsOnlyOverWhatTheLastReadFoundAsWritten(t *testing.T) {
	cfg := overlay(t)
	pbt.Check(t, func(ht *hegel.T) {
		host := &countedBorder{fakeBorder: &fakeBorder{}, counted: 1}
		be := &watchedBorder{countedBorder: host}
		moving := map[string]bool{}
		derived := func() egress.BorderSets {
			raw := []string{"203.0.113.0/24", "2001:db8:5::/48"}
			for _, lan := range slices.Sorted(maps.Keys(moving)) {
				if moving[lan] {
					raw = append(raw, lan)
				}
			}
			return egress.BorderSets{None: ranges(raw...)}
		}
		rt := borderRuntime(nil)
		rt.Sets = func(*egress.Border) egress.BorderSets { return derived() }
		f, err := startBorderFilter(nil, rt, be)
		if err != nil {
			ht.Fatalf("start: %v", err)
		}
		var steps []string
		for range hegel.Draw(ht, pbt.Spanning(1, 40)) {
			kind := hegel.Draw(ht, hegel.Integers(0, 99))
			switch {
			case kind < 35:
			case kind < 50:
				lan := hegel.Draw(ht, hegel.SampledFrom([]string{"2001:db8::/48", "198.51.100.0/24"}))
				moving[lan] = !moving[lan]
				steps = append(steps, "change "+lan)
				continue
			case kind < 55:
				if f.config.Load() == nil {
					f.config.Store(cfg)
				} else {
					f.config.Store(nil)
				}
				steps = append(steps, "new rules")
				continue
			case kind < 65:
				what := hegel.Draw(ht, hegel.SampledFrom([]string{"empties none4", "empties none6", "adds to none6", "adds a rule"}))
				host.mu.Lock()
				switch what {
				case "empties none4":
					host.sets[noneSet+"4"] = nil
				case "empties none6":
					host.sets[noneSet+"6"] = nil
				case "adds to none6":
					host.sets[noneSet+"6"] = append(slices.Clone(host.sets[noneSet+"6"]), ranges("2001:db8:9::/48")...)
				default:
					host.fault = "its chain antispoof holds another writer's rule"
				}
				host.counted++
				host.mu.Unlock()
				steps = append(steps, "another writer's transaction "+what)
				continue
			case kind < 70:
				host.mu.Lock()
				host.counted++
				host.mu.Unlock()
				steps = append(steps, "a transaction in another table")
				continue
			case kind < 75:
				steps = append(steps, "an empty or a refused transaction")
				continue
			case kind < 82:
				host.during = func() {
					be.fired = true
					host.another(noneSet + "4")
				}
				steps = append(steps, "a transaction during the next read")
				continue
			case kind < 90:
				host.short = true
				steps = append(steps, "the next fill short")
				continue
			case kind < 95:
				host.mu.Lock()
				host.failFill = true
				host.mu.Unlock()
				steps = append(steps, "the next pass's fill refused")
			default:
				host.mu.Lock()
				host.failRules = true
				host.mu.Unlock()
				steps = append(steps, "the next pass's reads failed")
			}
			trigger := hegel.Draw(ht, hegel.SampledFrom(borderTriggers))
			steps = append(steps, "pass "+trigger)
			rules, _, _ := f.desired()
			before, clean := be.view(), be.clean
			mark := len(host.entries())
			be.fired = false
			if trigger == "changed" {
				// as Run takes another writer's change
				f.setReady(false, "another writer changed its table")
			}
			f.trigger = trigger
			_ = f.reconcile()
			log := host.entries()[mark:]
			host.mu.Lock()
			host.failFill, host.failRules = false, false
			host.mu.Unlock()
			if len(log) > 0 && strings.HasPrefix(log[0], "fill ") && (clean == nil || !clean.same(before) || !slices.Equal(clean.rules, rules)) {
				ht.Fatalf("after %q the pass went %q, filling with no read over %+v, where the last read found as written %+v", steps, log, before, clean)
			}
			if len(log) > 0 && !be.fired && f.Stats().Ready {
				wantRules, wantSets, _ := f.desired()
				host.mu.Lock()
				read := host.readback(wantRules, wantSets)
				host.mu.Unlock()
				if read.fault != "" {
					ht.Fatalf("after %q the pass went %q and ended ready over a host whose read finds %q", steps, log, read.fault)
				}
			}
		}
	})
}
