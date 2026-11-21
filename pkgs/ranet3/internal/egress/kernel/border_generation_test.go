// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"maps"
	"slices"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/egress"
)

// countedBorder is the fake host with a generation, which each write the host
// takes moves by one, as nf_tables' does, and short, which makes the next fill
// send one range less of each set it moves, as a fault of the delta would
type countedBorder struct {
	*fakeBorder
	counted uint32
	short   bool
}

func (c *countedBorder) generation() (uint32, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.counted, nil
}

func (c *countedBorder) Fill(rules []BorderRule, was, sets borderSets) error {
	if c.short {
		c.short = false
		sets = maps.Clone(sets)
		for name, ranges := range sets {
			if len(ranges) > 0 {
				sets[name] = slices.Clone(ranges[:len(ranges)-1])
			}
		}
	}
	err := c.fakeBorder.Fill(rules, was, sets)
	if err == nil {
		c.move()
	}
	return err
}

func (c *countedBorder) Apply(rules []BorderRule, sets borderSets) error {
	err := c.fakeBorder.Apply(rules, sets)
	if err == nil {
		c.move()
	}
	return err
}

// move counts one transaction
func (c *countedBorder) move() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.counted++
}

// another is another writer's transaction that empties set, moving the
// generation where it commits as nf_tables counts it, and leaving it where
// moved is false, as a generation read ahead of the transaction's elements is
func (c *countedBorder) another(set string, moved bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sets[set] = nil
	if moved {
		c.counted++
	}
}

// countedFilter is a filter on a counted host at generation 1 whose none set
// moves by one range at each call of step, and the host
func countedFilter(t *testing.T) (*BorderFilter, *countedBorder, func()) {
	t.Helper()
	derived := egress.BorderSets{Owned: ranges("192.0.2.1/32"), None: ranges("203.0.113.0/24", "2001:db8:5::/48")}
	rt := borderRuntime(nil)
	rt.Sets = func(*egress.Border) egress.BorderSets { return derived }
	be := &countedBorder{fakeBorder: &fakeBorder{}, counted: 1}
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
	return f, be, step
}

// pass runs a pass woken by trigger and answers what the host saw of it
func (c *countedBorder) pass(t *testing.T, f *BorderFilter, trigger string) ([]string, error) {
	t.Helper()
	mark := len(c.entries())
	f.trigger = trigger
	err := f.reconcile()
	return c.entries()[mark:], err
}

// A pass woken by the mesh's table or the host's links or the reconciler that
// moves a set, where no transaction moved the generation since the last read
// that found the filter as written, fills from what that read found with no
// read before the fill and reads after it, pass after pass
func TestBorderFillsWithNoReadBeforeWhereTheGenerationHasNotMoved(t *testing.T) {
	for _, trigger := range []string{"routes", "network", "kernel", "reload", "missed"} {
		f, be, step := countedFilter(t)
		for i := range 3 {
			step()
			got, err := be.pass(t, f, trigger)
			if want := []string{"fill none6", "rules"}; err != nil || !slices.Equal(got, want) || !f.ready {
				t.Errorf("%s pass %d went %q with %v, ready %v, want %q", trigger, i, got, err, f.ready, want)
			}
		}
	}
}

// A pass reads before it fills where another writer's transaction moved the
// generation, which it finds and rewrites, where it is a sweep or a start, and
// where it would fill on a filter the last pass did not read back as written
func TestBorderReadsBeforeTheFillWhereTheGenerationMovedOrThePassReadsInFull(t *testing.T) {
	f, be, step := countedFilter(t)
	be.another(noneSet+"4", true)
	step()
	if got, err := be.pass(t, f, "routes"); err != nil || !slices.Equal(got, []string{"rules", "apply", "rules"}) || !f.ready {
		t.Errorf("a move after another writer's transaction went %q with %v, ready %v, want the read, a rewrite and the read after", got, err, f.ready)
	}
	step()
	if got, err := be.pass(t, f, "sweep"); err != nil || !slices.Equal(got, []string{"rules", "fill none6", "rules"}) {
		t.Errorf("a sweep at an unmoved generation went %q with %v, want the read before the fill", got, err)
	}
	step()
	mark := len(be.entries())
	if _, err := startBorderFilter(nil, f.rt, be); err != nil {
		t.Fatal(err)
	}
	// a start reads against the sets it derives, so it finds the moved set and rewrites
	if got := be.entries()[mark:]; !slices.Equal(got, []string{"rules", "apply", "rules"}) {
		t.Errorf("a start at an unmoved generation went %q, want the read, a rewrite and the read after", got)
	}
	f, be, step = countedFilter(t)
	be.short = true
	step()
	if got, err := be.pass(t, f, "routes"); err != nil || !slices.Equal(got, []string{"fill none6", "rules"}) || f.ready {
		t.Fatalf("a fill one range short went %q with %v, ready %v, want the read after it to find it", got, err, f.ready)
	}
	step()
	if got, err := be.pass(t, f, "routes"); err != nil || !slices.Equal(got, []string{"rules", "apply", "rules"}) || !f.ready {
		t.Errorf("the move after a fill the read after found short went %q with %v, ready %v, want the read before it", got, err, f.ready)
	}
}

// Another writer's transaction the generation does not show, as a read of the
// generation ahead of its elements leaves it, fails the fill computed from the
// last read, and the retry reads and rewrites the filter: the cost is a pass,
// and nothing is left unread
func TestBorderFillOnAGenerationThatMissedAChangeFailsAndTheRetryRewrites(t *testing.T) {
	f, be, step := countedFilter(t)
	be.another(noneSet+"6", false)
	step()
	got, err := be.pass(t, f, "routes")
	if err == nil || !slices.Equal(got, []string{"fill none6"}) || f.ready {
		t.Fatalf("a fill from a base another writer emptied went %q with %v, ready %v, want the fill refused", got, err, f.ready)
	}
	if stats := f.Stats(); stats.Installed == 0 {
		t.Errorf("the failed pass reported %d rules installed, want the count of the last read", stats.Installed)
	}
	if got, err := be.pass(t, f, "retry"); err != nil || !slices.Equal(got, []string{"rules", "apply", "rules"}) || !f.ready {
		t.Errorf("the retry went %q with %v, ready %v, want the read, a rewrite and the read after", got, err, f.ready)
	}
}
