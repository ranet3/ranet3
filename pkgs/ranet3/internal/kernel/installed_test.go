// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"net/netip"
	"slices"
	"sync"
	"syscall"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/schema"
)

// toldSource is the mesh's table as a route source told which routes each
// pass may have left in the kernel, keeping the last report
type toldSource struct {
	*netstack.RouteTable
	mu      sync.Mutex
	reports int
	routes  []Route
}

func (s *toldSource) Installed(routes []Route) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reports++
	s.routes = slices.Clone(routes)
}

// last is the destinations of the last report's routes, sorted, and how many
// reports came
func (s *toldSource) last() ([]netip.Prefix, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []netip.Prefix
	for _, route := range s.routes {
		out = append(out, route.Destination)
	}
	slices.SortFunc(out, comparePrefixes)
	return out, s.reports
}

// newToldReconciler is a reconciler over a fake kernel whose source is a
// toldSource holding lan
func newToldReconciler(t *testing.T, lan netip.Prefix) (*Reconciler, *toldSource, *fakeKernel) {
	src := &toldSource{RouteTable: netstack.NewRouteTable()}
	fake := newFakeKernel(t)
	reconciler := newReconciler(Table{}.Normalized(), Runtime{Interface: "ranet0"}, nil, src, fake)
	src.Set(netip.Prefix{}, lan, nil)
	return reconciler, src, fake
}

// The reconciler tells a source that asks which routes each pass may have
// left in the kernel. A route whose delete the kernel refused stays in the
// report, and leaves at the pass whose delete the kernel took. An add the
// kernel answered with an error stays until the next pass whose listing read
// the kernel, and an add the platform skipped is never told. A pass whose
// listing failed tells the last report again, a withdrawal whose listing
// failed tells nothing and leaves an add answered with an error in later
// reports, and a withdrawal tells the routes whose delete failed and no add.
func TestReconcilerTellsItsSourceWhatEachPassMayHaveLeftInTheKernel(t *testing.T) {
	lan, refused, skipped := prefix("198.51.100.32/27"), prefix("192.0.2.128/25"), prefix("192.0.2.0/26")
	reconciler, src, fake := newToldReconciler(t, lan)
	step := func(what string, want ...netip.Prefix) {
		t.Helper()
		_ = reconciler.reconcile()
		if got, _ := src.last(); !slices.Equal(got, want) {
			t.Fatalf("%s: the source was told %v, want %v", what, got, want)
		}
	}
	step("a pass that installed the route", lan)
	route := slices.Collect(func(yield func(Route) bool) {
		fake.mu.Lock()
		defer fake.mu.Unlock()
		for route := range fake.routes {
			if !yield(route) {
				return
			}
		}
	})[0]

	src.Set(netip.Prefix{}, refused, nil)
	src.Set(netip.Prefix{}, skipped, nil)
	fake.mu.Lock()
	fake.failAdd[Route{Destination: refused, Metric: route.Metric}] = syscall.ENOBUFS
	fake.failAdd[Route{Destination: skipped, Metric: route.Metric}] = errRouteSkipped
	fake.mu.Unlock()
	step("a pass whose add the kernel answered with an error", refused, lan)

	fake.mu.Lock()
	fake.failList = syscall.EBUSY
	fake.mu.Unlock()
	step("a pass whose listing failed", refused, lan)
	_, reports := src.last()
	if err := reconciler.withdraw(nil); err == nil {
		t.Fatal("a withdrawal whose listing failed reported no error")
	}
	if told, now := src.last(); now != reports {
		t.Fatalf("a withdrawal whose listing failed told the source %v, want nothing told", told)
	}
	step("a pass whose listing failed after a withdrawal whose listing failed", refused, lan)

	fake.mu.Lock()
	fake.failList = nil
	delete(fake.failAdd, Route{Destination: refused, Metric: route.Metric})
	fake.mu.Unlock()
	step("a pass whose listing read the kernel and whose add landed", refused, lan)

	fake.mu.Lock()
	fake.failDel[route] = syscall.EPERM
	fake.mu.Unlock()
	if err := reconciler.withdraw(nil); err == nil {
		t.Fatal("a withdrawal whose delete the kernel refused reported no error")
	}
	if told, _ := src.last(); !slices.Equal(told, []netip.Prefix{lan}) {
		t.Fatalf("a withdrawal whose delete failed told %v, want %v alone", told, lan)
	}

	src.Remove(netip.Prefix{}, refused)
	src.Remove(netip.Prefix{}, skipped)
	src.Remove(netip.Prefix{}, lan)
	step("a pass whose delete the kernel refused", lan)

	fake.mu.Lock()
	delete(fake.failDel, route)
	fake.mu.Unlock()
	step("a pass whose delete the kernel took")
}

// A withdrawal whose listing read the kernel leaves the reconciler's record of
// what it installed as that listing and its deletes left it, so a pass whose
// listing fails after one tells none of the routes the withdrawal deleted. An
// add answered with an error before the withdrawal, whose listing read it, is
// not told again.
func TestPassWhoseListingFailsAfterAWithdrawalTellsWhatTheWithdrawalLeft(t *testing.T) {
	lan, refused := prefix("198.51.100.32/27"), prefix("192.0.2.128/25")
	reconciler, src, fake := newToldReconciler(t, lan)
	_ = reconciler.reconcile()
	fake.mu.Lock()
	for route := range fake.routes {
		fake.failAdd[Route{Destination: refused, Metric: route.Metric}] = syscall.ENOBUFS
	}
	fake.mu.Unlock()
	src.Set(netip.Prefix{}, refused, nil)
	_ = reconciler.reconcile()
	if told, _ := src.last(); !slices.Equal(told, []netip.Prefix{refused, lan}) {
		t.Fatalf("setup: a pass whose add the kernel answered with an error told %v, want %v and %v", told, refused, lan)
	}
	if err := reconciler.withdraw(nil); err != nil {
		t.Fatal(err)
	}
	if told, _ := src.last(); told != nil {
		t.Fatalf("a withdrawal that deleted every route told %v, want none", told)
	}
	src.Remove(netip.Prefix{}, refused)
	src.Remove(netip.Prefix{}, lan)
	fake.mu.Lock()
	fake.failList = syscall.EBUSY
	fake.mu.Unlock()
	_ = reconciler.reconcile()
	if told, _ := src.last(); told != nil {
		t.Fatalf("a pass whose listing failed after the withdrawal told %v, want none, the record the withdrawal left", told)
	}
	fake.mu.Lock()
	fake.failList = nil
	fake.mu.Unlock()
	_ = reconciler.reconcile()
	if told, _ := src.last(); told != nil {
		t.Fatalf("a pass whose listing read the kernel told %v, want none", told)
	}
}

// Kept takes out of none the part outside the overlay of each route that
// takes a packet into the tun toward a learned destination, and nothing for a
// hold, a throw, a member of a cover or a default
func TestKeptIsWhatRoutesTheKernelHoldsTakeOutOfNone(t *testing.T) {
	overlay := []schema.Prefix{schema.MustPrefix("203.0.113.0/24")}
	none := Ranges([]netip.Prefix{prefix("198.51.100.0/24"), prefix("203.0.113.0/25")})
	lan := Route{Destination: prefix("198.51.100.32/27")}
	wide := Route{Destination: prefix("198.51.100.0/25")}
	overlaid := Route{Destination: prefix("203.0.113.16/28")}
	outside := Route{Destination: prefix("192.0.2.0/24")}
	installed := []Route{
		lan, wide, overlaid, outside,
		{Destination: prefix("198.51.100.64/27"), Unreachable: true},
		{Destination: prefix("198.51.100.96/27"), Throw: true},
		{Destination: prefix("128.0.0.0/1"), Cover: true},
		{Destination: prefix("198.51.100.200/29"), Cover: true},
		{Destination: prefix("0.0.0.0/0")},
	}
	routes, kept := Kept(installed, none, overlay)
	if want := []Route{lan, wide}; !slices.Equal(routes, want) {
		t.Errorf("the routes keeping addresses out are %v, want %v", routes, want)
	}
	if want := Ranges([]netip.Prefix{prefix("198.51.100.0/25")}); !slices.Equal(kept, want) {
		t.Errorf("kept %v, want %v", kept, want)
	}
	if got := Without(none, kept); !slices.Equal(got, Ranges([]netip.Prefix{prefix("198.51.100.128/25"), prefix("203.0.113.0/25")})) {
		t.Errorf("none less what is kept is %v", got)
	}
	// a route wider than none keeps out what none holds of it alone
	if _, kept := Kept([]Route{{Destination: prefix("198.51.100.0/23")}}, none, overlay); !slices.Equal(kept, Ranges([]netip.Prefix{prefix("198.51.100.0/24")})) {
		t.Errorf("a route wider than none kept %v", kept)
	}
}

// Promised is the route of each handed learned entry that routes into the
// tun, a source-specific one with its source, and nothing for a hold, an entry
// of this node's own or a default
func TestPromisedIsWhatHandedEntriesMayInstall(t *testing.T) {
	overlay := []schema.Prefix{schema.MustPrefix("203.0.113.0/24")}
	peer := &netstack.Peer{ID: "example/router"}
	table := netstack.NewRouteTable()
	table.Set(netip.Prefix{}, prefix("198.51.100.32/27"), peer)
	table.Set(netip.Prefix{}, prefix("203.0.113.0/23"), peer)
	table.Set(prefix("2001:db8:5::/48"), prefix("2001:db8:76::/48"), peer)
	table.Set(netip.Prefix{}, prefix("198.51.100.64/27"), netstack.Unreachable)
	table.Set(netip.Prefix{}, prefix("198.51.100.96/27"), netstack.Local)
	table.Set(netip.Prefix{}, prefix("0.0.0.0/0"), peer)
	want := []Route{
		{Destination: prefix("198.51.100.32/27")},
		{Destination: prefix("203.0.112.0/23")},
		{Destination: prefix("2001:db8:76::/48"), Source: prefix("2001:db8:5::/48"), Metric: defaultIPv6Metric},
	}
	got := Promised(table.Snapshot(), overlay)
	slices.SortFunc(got, compareRoutes)
	if !slices.Equal(got, want) {
		t.Errorf("promised %v, want %v", got, want)
	}
}

// Unentered hands a hold at the key of each learned entry whose destination
// meets none, and the entry itself where it does not, and leaves a hold, an
// entry of this node's own and a default as they are
func TestUnenteredHandsAHoldAtTheKeyOfEachEntryItHoldsBack(t *testing.T) {
	overlay := []schema.Prefix{schema.MustPrefix("203.0.113.0/24")}
	peer := &netstack.Peer{ID: "example/router"}
	none := Ranges([]netip.Prefix{prefix("198.51.100.0/24")})
	table := netstack.NewRouteTable()
	lan, outside := prefix("198.51.100.32/27"), prefix("192.0.2.0/24")
	table.Set(netip.Prefix{}, lan, peer)
	table.Set(netip.Prefix{}, outside, peer)
	table.Set(netip.Prefix{}, prefix("198.51.100.64/27"), netstack.Unreachable)
	table.Set(netip.Prefix{}, prefix("198.51.100.96/27"), netstack.Local)
	table.Set(netip.Prefix{}, prefix("0.0.0.0/0"), peer)
	handed, held := Unentered(table.Snapshot(), none, overlay)
	if len(held) != 1 || held[0].Destination != lan || held[0].Value != peer {
		t.Fatalf("held back %v, want %s through its peer alone", held, lan)
	}
	for _, entry := range handed {
		want := peer
		switch entry.Destination {
		case lan, prefix("198.51.100.64/27"):
			want = netstack.Unreachable
		case prefix("198.51.100.96/27"):
			want = netstack.Local
		}
		if entry.Value != want {
			t.Errorf("handed %s as %v, want %v", entry.Destination, entry.Value, want)
		}
	}
	if len(handed) != 5 {
		t.Errorf("handed %d entries of 5", len(handed))
	}
}
