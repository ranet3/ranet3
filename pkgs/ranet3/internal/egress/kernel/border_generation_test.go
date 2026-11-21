// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/egress"
)

// retryWait bounds the wait for the pass the retry owes, past its first delay
// of 1 second
const retryWait = 3 * time.Second

// countedBorder is the fake host with nf_tables' generation, which each
// transaction the host commits moves by one, and with a fill that answers as
// nf_tables answers the filter's. short makes the next fill send one range
// less of each set it changes, as a fault of the delta would, and during is a
// step of another writer's that the next read takes after it has read the host.
type countedBorder struct {
	*fakeBorder
	counted uint32
	short   bool
	during  func()
}

func (c *countedBorder) generation() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.counted
}

// Rules reads the host and then takes during, as a dump misses a transaction
// that commits after it read
func (c *countedBorder) Rules(rules []BorderRule, sets borderSets) (chainReadback, error) {
	read, err := c.fakeBorder.Rules(rules, sets)
	if during := c.during; during != nil {
		c.during = nil
		during()
	}
	return read, err
}

// Fill answers as nf_tables answers the filter's transaction, whose adds carry
// no NLM_F_EXCL: it refuses the whole transaction where it deletes a range the
// host lacks, takes an add of a range the host holds, and moves the generation
// where it commits
func (c *countedBorder) Fill(_ []BorderRule, was, sets borderSets) error {
	if c.short {
		c.short = false
		sets = shortened(sets)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.log = append(c.log, "fill "+strings.Join(slices.Sorted(maps.Keys(sets)), " "))
	if c.failFill {
		return errors.New("no")
	}
	next := borderSets{}
	maps.Copy(next, c.sets)
	for name, ranges := range sets {
		held := slices.Clone(c.sets[name])
		for _, gone := range was[name] {
			if slices.Contains(ranges, gone) {
				continue
			}
			at := slices.Index(held, gone)
			if at < 0 {
				return fmt.Errorf("fill deletes %v from set %s, which lacks it", gone, name)
			}
			held = slices.Delete(held, at, at+1)
		}
		for _, added := range ranges {
			if !slices.Contains(was[name], added) && !slices.Contains(held, added) {
				held = append(held, added)
			}
		}
		slices.SortFunc(held, func(a, b egress.Range) int { return cmp.Or(a.First.Compare(b.First), a.Last.Compare(b.Last)) })
		next[name] = held
	}
	c.sets = next
	c.counted++
	return nil
}

func (c *countedBorder) Apply(rules []BorderRule, sets borderSets) error {
	err := c.fakeBorder.Apply(rules, sets)
	if err == nil {
		c.mu.Lock()
		c.counted++
		c.mu.Unlock()
	}
	return err
}

// another is another writer's committed transaction that empties set
func (c *countedBorder) another(set string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sets[set] = nil
	c.counted++
}

// anotherUnseen is another writer's transaction that empties set where the
// generation does not show it, as a read of the generation ahead of the
// transaction's elements leaves it, which nftables.Conn.Generation tells
func (c *countedBorder) anotherUnseen(set string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sets[set] = nil
}

// shortened is sets with the last range of each set of more than one cut
func shortened(sets borderSets) borderSets {
	out := maps.Clone(sets)
	for name, ranges := range out {
		if len(ranges) > 1 {
			out[name] = slices.Clone(ranges[:len(ranges)-1])
		}
	}
	return out
}

// movingFilter is a filter started on be whose none6 set changes by one range
// at each call of step
func movingFilter(t *testing.T, be borderBackend) (*BorderFilter, func()) {
	t.Helper()
	derived := egress.BorderSets{Owned: ranges("192.0.2.1/32"), None: ranges("203.0.113.0/24", "2001:db8:5::/48")}
	rt := borderRuntime(nil)
	rt.Sets = func(*egress.Border) egress.BorderSets { return derived }
	f, err := startBorderFilter(nil, rt, be)
	if err != nil {
		t.Fatal(err)
	}
	in := false
	step := func() {
		if in = !in; in {
			derived.None = ranges("203.0.113.0/24", "2001:db8::/48", "2001:db8:5::/48")
		} else {
			derived.None = ranges("203.0.113.0/24", "2001:db8:5::/48")
		}
	}
	return f, step
}

// countedFilter is a filter on a counted host at generation 1, the host, and
// the step that changes none6
func countedFilter(t *testing.T) (*BorderFilter, *countedBorder, func()) {
	t.Helper()
	be := &countedBorder{fakeBorder: &fakeBorder{}, counted: 1}
	f, step := movingFilter(t, be)
	return f, be, step
}

// woken runs a pass woken by trigger and answers what the host saw of it
func (c *countedBorder) woken(t *testing.T, f *BorderFilter, trigger string) ([]string, error) {
	t.Helper()
	mark := len(c.entries())
	f.trigger = trigger
	err := f.reconcile()
	return c.entries()[mark:], err
}

var (
	readFillRead = []string{"rules", "fill " + noneSet + "6", "rules"}
	fillRead     = []string{"fill " + noneSet + "6", "rules"}
	rewrite      = []string{"rules", "apply", "rules"}
)

// A pass woken by the mesh's table, the host's links, the reconciler or a
// reload that changes a set, where no transaction has committed since the last
// read that found the filter as written, fills from what that read found with
// no read before the fill and reads after it, pass after pass
func TestBorderFillsWithNoReadBeforeWhereNoTransactionCommitted(t *testing.T) {
	for _, trigger := range []string{"routes", "network", "kernel", "reload", "missed"} {
		f, be, step := countedFilter(t)
		for i := range 3 {
			step()
			got, err := be.woken(t, f, trigger)
			if err != nil || !slices.Equal(got, fillRead) || !f.ready || f.retryOnFault {
				t.Errorf("%s pass %d went %q with %v, ready %v, retry armed %v, want %q, ready and no retry", trigger, i, got, err, f.ready, f.retryOnFault, fillRead)
			}
		}
	}
}

// A pass reads before its fill where another writer's transaction committed
// since the last read, and finds and rewrites what it changed
func TestBorderReadsBeforeTheFillWhereAnotherWritersTransactionCommitted(t *testing.T) {
	f, be, step := countedFilter(t)
	be.another(noneSet + "4")
	step()
	if got, err := be.woken(t, f, "routes"); err != nil || !slices.Equal(got, rewrite) || !f.ready {
		t.Errorf("a change after another writer's transaction went %q with %v, ready %v, want %q", got, err, f.ready, rewrite)
	}
}

// The sweep reads before its fill where no transaction has committed
func TestBorderSweepReadsBeforeItsFill(t *testing.T) {
	f, be, step := countedFilter(t)
	step()
	if got, err := be.woken(t, f, "sweep"); err != nil || !slices.Equal(got, readFillRead) || !f.ready {
		t.Errorf("the sweep went %q with %v, ready %v, want %q", got, err, f.ready, readFillRead)
	}
}

// A pass another writer's change woke reads before its fill, also where the
// generation does not show that change
func TestBorderPassAnotherWritersChangeWokeReadsBeforeItsFill(t *testing.T) {
	f, be, step := countedFilter(t)
	be.anotherUnseen(noneSet + "4")
	step()
	if got, err := be.woken(t, f, "changed"); err != nil || !slices.Equal(got, rewrite) || !f.ready {
		t.Errorf("the pass the change woke went %q with %v, ready %v, want %q", got, err, f.ready, rewrite)
	}
}

// A reload that changes the rules reads before it writes, where no
// transaction has committed
func TestBorderReloadOfTheRulesReadsBeforeItsWrite(t *testing.T) {
	f, be, step := countedFilter(t)
	f.config.Store(overlay(t))
	step()
	if got, err := be.woken(t, f, "reload"); err != nil || !slices.Equal(got, rewrite) || !f.ready {
		t.Errorf("the reload went %q with %v, ready %v, want %q", got, err, f.ready, rewrite)
	}
}

// A pass that would fill nothing reads the filter, where no transaction has
// committed
func TestBorderPassThatWouldFillNothingReads(t *testing.T) {
	for _, trigger := range []string{"reload", "missed", "retry", "changed", "sweep"} {
		f, be, _ := countedFilter(t)
		if got, err := be.woken(t, f, trigger); err != nil || !slices.Equal(got, []string{"rules"}) || !f.ready {
			t.Errorf("a %s pass with nothing to fill went %q with %v, ready %v, want one read", trigger, got, err, f.ready)
		}
	}
}

// A read that finds the filter as written but not ready records no
// generation, so the next pass that fills reads before it
func TestBorderReadsBeforeTheFillAfterAReadThatFoundTheFilterNotReady(t *testing.T) {
	f, be, step := countedFilter(t)
	be.mu.Lock()
	be.unready = "its host is not ready"
	be.mu.Unlock()
	if got, err := be.woken(t, f, "sweep"); err != nil || !slices.Equal(got, []string{"rules"}) || f.ready {
		t.Fatalf("a sweep over a host not ready went %q with %v, ready %v, want one read and not ready", got, err, f.ready)
	}
	step()
	if got, err := be.woken(t, f, "routes"); err != nil || !slices.Equal(got, readFillRead) {
		t.Errorf("the change after went %q with %v, want %q", got, err, readFillRead)
	}
}

// The pass after a refused fill reads the sets against what the last read
// found and fills from there
func TestBorderPassAfterARefusedFillReadsAndFillsFromWhatTheLastReadFound(t *testing.T) {
	f, be, step := countedFilter(t)
	be.mu.Lock()
	be.failFill = true
	be.mu.Unlock()
	step()
	if got, err := be.woken(t, f, "routes"); err == nil || !slices.Equal(got, []string{"fill " + noneSet + "6"}) || f.ready {
		t.Fatalf("a refused fill went %q with %v, ready %v, want it refused", got, err, f.ready)
	}
	be.mu.Lock()
	be.failFill = false
	be.mu.Unlock()
	if got, err := be.woken(t, f, "retry"); err != nil || !slices.Equal(got, readFillRead) || !f.ready {
		t.Errorf("the retry went %q with %v, ready %v, want %q", got, err, f.ready, readFillRead)
	}
}

// A pass that fills with no read before it reports the count of rules its
// read after found
func TestBorderSkippedPassReportsTheCountItsReadAfterFound(t *testing.T) {
	f, be, step := countedFilter(t)
	installed := f.Stats().Installed
	be.mu.Lock()
	be.held = append(be.held, Installed{Spec: "another writer's rule"})
	be.mu.Unlock()
	step()
	if got, err := be.woken(t, f, "routes"); err != nil || !slices.Equal(got, fillRead) {
		t.Fatalf("the change went %q with %v, want %q", got, err, fillRead)
	}
	if stats := f.Stats(); installed == 0 || stats.Installed != installed+1 {
		t.Errorf("the pass reported %d rules installed, want the %d its read after found", stats.Installed, installed+1)
	}
}

// A pass reads before its fill where the last read found a fault after a
// fill, before and after a rewrite, or failed
func TestBorderReadsBeforeTheFillAfterAReadThatFoundAFault(t *testing.T) {
	t.Run("after a fill", func(t *testing.T) {
		f, be, step := countedFilter(t)
		be.short = true
		step()
		if got, err := be.woken(t, f, "routes"); err != nil || !slices.Equal(got, fillRead) || f.ready {
			t.Fatalf("a fill one range short went %q with %v, ready %v, want the read after it to find it", got, err, f.ready)
		}
		step()
		if got, err := be.woken(t, f, "routes"); err != nil || !slices.Equal(got, rewrite) || !f.ready {
			t.Errorf("the change after went %q with %v, ready %v, want %q", got, err, f.ready, rewrite)
		}
	})
	t.Run("before and after a rewrite", func(t *testing.T) {
		f, be, step := countedFilter(t)
		be.mu.Lock()
		be.fault, be.stuck = "its table carries flags 0x1", true
		be.mu.Unlock()
		if got, err := be.woken(t, f, "sweep"); err != nil || !slices.Equal(got, rewrite) || f.ready {
			t.Fatalf("a sweep over a fault a rewrite leaves went %q with %v, ready %v, want the rewrite read faulted", got, err, f.ready)
		}
		be.mu.Lock()
		be.fault, be.stuck = "", false
		be.mu.Unlock()
		step()
		if got, err := be.woken(t, f, "routes"); err != nil || !slices.Equal(got, readFillRead) || !f.ready {
			t.Errorf("the change after went %q with %v, ready %v, want %q", got, err, f.ready, readFillRead)
		}
	})
	t.Run("a failed read", func(t *testing.T) {
		f, be, step := countedFilter(t)
		be.mu.Lock()
		be.failRules = true
		be.mu.Unlock()
		if _, err := be.woken(t, f, "sweep"); err == nil {
			t.Fatal("a sweep whose read failed reported no error")
		}
		be.mu.Lock()
		be.failRules = false
		be.mu.Unlock()
		step()
		if got, err := be.woken(t, f, "routes"); err != nil || !slices.Equal(got, readFillRead) || !f.ready {
			t.Errorf("the change after went %q with %v, ready %v, want %q", got, err, f.ready, readFillRead)
		}
	})
}

// The generation a read records is the one read before it, so a transaction
// that commits while the read runs, missed by it, makes the next change read
// before its fill, for the read before a fill and for the read after one
func TestBorderRecordsTheGenerationReadBeforeEachRead(t *testing.T) {
	t.Run("before a fill", func(t *testing.T) {
		f, be, step := countedFilter(t)
		be.during = func() { be.another(noneSet + "4") }
		if got, err := be.woken(t, f, "sweep"); err != nil || !slices.Equal(got, []string{"rules"}) || !f.ready {
			t.Fatalf("a sweep whose read missed a transaction went %q with %v, ready %v, want one clean read", got, err, f.ready)
		}
		step()
		if got, err := be.woken(t, f, "routes"); err != nil || !slices.Equal(got, rewrite) || !f.ready {
			t.Errorf("the change after went %q with %v, ready %v, want %q", got, err, f.ready, rewrite)
		}
	})
	t.Run("after a fill", func(t *testing.T) {
		f, be, step := countedFilter(t)
		be.during = func() { be.another(noneSet + "4") }
		step()
		if got, err := be.woken(t, f, "routes"); err != nil || !slices.Equal(got, fillRead) || !f.ready {
			t.Fatalf("a fill whose read after missed a transaction went %q with %v, ready %v, want %q", got, err, f.ready, fillRead)
		}
		step()
		if got, err := be.woken(t, f, "routes"); err != nil || !slices.Equal(got, rewrite) || !f.ready {
			t.Errorf("the change after went %q with %v, ready %v, want %q", got, err, f.ready, rewrite)
		}
	})
}

// A filter on a backend that counts no generation reads before every fill
func TestBorderReadsBeforeEveryFillWhereTheBackendCountsNoGeneration(t *testing.T) {
	be := &fakeBorder{}
	f, step := movingFilter(t, be)
	for i := range 3 {
		step()
		mark := len(be.entries())
		f.trigger = "routes"
		err := f.reconcile()
		if got := be.entries()[mark:]; err != nil || !slices.Equal(got, readFillRead) || !f.ready {
			t.Errorf("pass %d went %q with %v, ready %v, want %q", i, got, err, f.ready, readFillRead)
		}
	}
}

// Another writer's transaction the generation does not show, which emptied
// the set a fill adds to, lets the fill commit, and the read after finds the
// set short, arms the retry, and the retry reads and rewrites
func TestBorderFillOnASetAnotherWriterEmptiedCommitsAndTheReadAfterFindsIt(t *testing.T) {
	f, be, step := countedFilter(t)
	be.anotherUnseen(noneSet + "6")
	step()
	if got, err := be.woken(t, f, "routes"); err != nil || !slices.Equal(got, fillRead) || f.ready || !f.retryOnFault {
		t.Fatalf("a fill that adds to a set another writer emptied went %q with %v, ready %v, retry armed %v, want %q, not ready and the retry armed", got, err, f.ready, f.retryOnFault, fillRead)
	}
	if got, err := be.woken(t, f, "retry"); err != nil || !slices.Equal(got, rewrite) || !f.ready {
		t.Errorf("the retry went %q with %v, ready %v, want %q", got, err, f.ready, rewrite)
	}
}

// A fill that deletes a range another writer took, where the generation does
// not show it, is refused whole, reports the count of the last read beside
// its error, and the retry reads and rewrites
func TestBorderFillThatDeletesWhatAnotherWriterTookIsRefused(t *testing.T) {
	f, be, step := countedFilter(t)
	step()
	if got, err := be.woken(t, f, "routes"); err != nil || !slices.Equal(got, fillRead) {
		t.Fatalf("the first change went %q with %v, want %q", got, err, fillRead)
	}
	installed := f.Stats().Installed
	be.anotherUnseen(noneSet + "6")
	step()
	got, err := be.woken(t, f, "routes")
	if err == nil || !slices.Equal(got, []string{"fill " + noneSet + "6"}) || f.ready {
		t.Fatalf("a fill that deletes what another writer took went %q with %v, ready %v, want it refused", got, err, f.ready)
	}
	if stats := f.Stats(); installed == 0 || stats.Installed != installed {
		t.Errorf("the refused pass reported %d rules installed, want the %d of the last read", stats.Installed, installed)
	}
	if got, err := be.woken(t, f, "retry"); err != nil || !slices.Equal(got, rewrite) || !f.ready {
		t.Errorf("the retry went %q with %v, ready %v, want %q", got, err, f.ready, rewrite)
	}
}

// Under Run, with no sweep due, a pass that fills with no read before it and
// whose read after finds the filter as written arms no retry, so no read
// follows over a stretch longer than the retry's delay
func TestBorderRunReadsNothingAfterACleanSkippedPass(t *testing.T) {
	be := &countedBorder{fakeBorder: &fakeBorder{every: lateSweep}, counted: 1}
	f, step := movingFilter(t, be)
	runBorder(t, f)
	mark := len(be.entries())
	step()
	f.kernel <- struct{}{}
	started := time.Now()
	for !slices.Equal(be.entries()[mark:], fillRead) {
		if time.Since(started) > retryWait {
			t.Fatalf("%v after the wake the host saw %q, want %q", retryWait, be.entries()[mark:], fillRead)
		}
		time.Sleep(passPoll)
	}
	time.Sleep(retryWait)
	if got := be.entries()[mark:]; !slices.Equal(got, fillRead) {
		t.Errorf("%v after the pass the host saw %q, want %q alone", retryWait, got, fillRead)
	}
}

// Under Run, with no wake of another writer's change and no sweep due, a fault
// the read after a fill with no read before it found is repaired by the retry
// within its delay
func TestBorderRunRetriesAFaultTheReadAfterAFillFound(t *testing.T) {
	be := &countedBorder{fakeBorder: &fakeBorder{every: lateSweep}, counted: 1}
	f, step := movingFilter(t, be)
	runBorder(t, f)
	mark := len(be.entries())
	be.anotherUnseen(noneSet + "4")
	step()
	f.kernel <- struct{}{}
	want := append(slices.Clone(fillRead), rewrite...)
	started := time.Now()
	for !slices.Equal(be.entries()[mark:], want) || !f.Stats().Ready {
		if time.Since(started) > retryWait {
			t.Fatalf("%v after the wake the host saw %q, ready %v, want %q and ready, the retry repairing the fault", retryWait, be.entries()[mark:], f.Stats().Ready, want)
		}
		time.Sleep(passPoll)
	}
}
