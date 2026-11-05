// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"net/netip"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/events"
)

// fakeSelection is an underlay selection a test publishes generations of by hand
type fakeSelection struct {
	changed chan struct{}
}

func newFakeSelection() *fakeSelection {
	return &fakeSelection{changed: make(chan struct{}, 1)}
}

func (s *fakeSelection) Changed() <-chan struct{} { return s.changed }

// publish signals a new generation, as the selection does once it stored one
func (s *fakeSelection) publish() {
	select {
	case s.changed <- struct{}{}:
	default:
	}
}

// a generation the underlay's selection publishes wakes a pass at once, named for the underlay
func TestReconcilerRunsAPassWhenTheSelectionChanges(t *testing.T) {
	bus := events.New()
	selection := newFakeSelection()
	reconciler, table, fake := harness(t, Table{}, Runtime{Events: bus, Selection: selection})
	ordinary := Route{Destination: prefix("2001:db8:5::/48"), Metric: defaultIPv6Metric}
	table.Set(netip.Prefix{}, ordinary.Destination, nil)
	last := runToRecord(t, reconciler, table, bus)
	awaitPass(t, last, "the first pass", "start", func() bool { return fake.has(ordinary) })
	fake.mu.Lock()
	delete(fake.routes, ordinary)
	fake.mu.Unlock()
	selection.publish()
	awaitPass(t, last, "the pass the selection asked for", "underlay", func() bool { return fake.has(ordinary) })
}
