// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package kernel

import (
	"errors"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/events"
)

// fakeSelection is an underlay selection a test publishes generations of by hand
type fakeSelection struct {
	// changed is unbuffered, so a signal handOff sends is one Run took
	changed chan struct{}
	mu      sync.Mutex
	current hostTable
}

func newFakeSelection(routes ...hostRoute) *fakeSelection {
	return &fakeSelection{changed: make(chan struct{}), current: hostTable{routes: routes, mesh: selectMesh}}
}

func (s *fakeSelection) Changed() <-chan struct{} { return s.changed }

func (s *fakeSelection) table() hostTable {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.current
}

// publish stores routes as a new generation for a test that runs each pass itself
func (s *fakeSelection) publish(routes ...hostRoute) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.current = hostTable{routes: routes, mesh: selectMesh}
}

// handOff publishes routes and signals the generation, failing the test unless Run takes the signal within waitBudget
func (s *fakeSelection) handOff(t *testing.T, routes ...hostRoute) {
	t.Helper()
	s.publish(routes...)
	select {
	case s.changed <- struct{}{}:
	case <-time.After(waitBudget):
		t.Fatalf("the reconciler took no signal of the new generation within %s", waitBudget)
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
	selection.handOff(t)
	awaitPass(t, last, "the pass the selection asked for", "underlay", func() bool { return fake.has(ordinary) })
}

// unscopedAt is each unscoped route fake holds, by destination
func unscopedAt(fake *fakeKernel) map[netip.Prefix]Route {
	out := map[netip.Prefix]Route{}
	for _, r := range fake.snapshot() {
		if !r.Scoped {
			out[r.Destination] = r
		}
	}
	return out
}

// holeTable is a host table whose 192.0.2.0/24 leaves by interface 2, and
// holeEndpoint and holeSent are a listed endpoint and a live session's
// destination inside it and the overlay
var (
	holeTable    = []hostRoute{{destination: prefix("192.0.2.0/24"), index: 2}}
	holeEndpoint = netip.MustParseAddr("192.0.2.9")
	holeSent     = netip.MustParseAddr("192.0.2.100")
)

// A pass beside a selection installs the mesh's 192.0.2.0/25, longer than the
// host route of a listed endpoint and of a live session's destination and
// inside the overlay, as the pieces around both, at most seven for each, the
// listed endpoint named once though a live session sends to it too, and the
// generation that gives them a host route as long as the mesh's wakes a pass
// that puts the route back whole. With no selection the route goes in whole
// from the first pass.
func TestPassCutsTheEndpointOutOfALongerMeshRoute(t *testing.T) {
	mesh := Route{Destination: prefix("192.0.2.0/25")}
	endpoints := []netip.Addr{holeEndpoint, holeSent}
	pieces := without(mesh.Destination, endpoints)
	underlay := func() []netip.Addr { return []netip.Addr{holeEndpoint} }
	sends := func() []Send { return []Send{{Destination: holeSent}, {Destination: holeEndpoint}} }

	bus := events.New()
	selection := newFakeSelection(holeTable...)
	reconciler, table, kernel := coveredHarness(t, Table{}, Runtime{Events: bus, Underlay: underlay, Sends: sends, Selection: selection}, coverAddresses...)
	table.Set(netip.Prefix{}, mesh.Destination, nil)
	last := runToRecord(t, reconciler, table, bus)
	awaitPass(t, last, "the first pass", "start", func() bool { return len(unscopedAt(kernel.fakeKernel)) == len(pieces) })
	held := unscopedAt(kernel.fakeKernel)
	for _, piece := range pieces {
		if _, ok := held[piece]; !ok {
			t.Errorf("the kernel lacks the piece %s: %v", piece, kernel.snapshot())
		}
	}
	if _, ok := held[mesh.Destination]; ok || len(pieces) > 14 {
		t.Errorf("the kernel holds %s whole beside %d pieces, want at most 14 pieces alone: %v", mesh.Destination, len(pieces), kernel.snapshot())
	}
	if holes := reconciler.Stats().Holes; len(holes) != 1 || holes[0].Route != mesh.Destination || !slices.Equal(holes[0].Endpoints, endpoints) {
		t.Errorf("the pass reports the holes %+v, want %s cut around %v", holes, mesh.Destination, endpoints)
	}
	selection.handOff(t, append(slices.Clone(holeTable), hostRoute{destination: prefix("192.0.2.0/25"), index: 2})...)
	awaitPass(t, last, "the pass the new generation asked for", "underlay", func() bool { return kernel.has(mesh) })
	if n := len(unscopedAt(kernel.fakeKernel)); n != 1 {
		t.Errorf("with the endpoint's host route as long as the mesh's the kernel holds %d routes, want %s alone: %v", n, mesh.Destination, kernel.snapshot())
	}

	plain, table, fake := coveredHarness(t, Table{}, Runtime{Underlay: underlay}, coverAddresses...)
	table.Set(netip.Prefix{}, mesh.Destination, nil)
	if err := plain.reconcile(); err != nil {
		t.Fatal(err)
	}
	if !fake.has(mesh) || len(plain.Stats().Holes) != 0 {
		t.Errorf("with no selection the kernel holds %v and the pass reports the holes %+v, want %s whole and none", fake.snapshot(), plain.Stats().Holes, mesh.Destination)
	}
}

// kernel.underlay is recorded for the pass that cuts the endpoints and the one
// that stops cutting them, naming them, and for no pass between, and HoleAt
// names the mesh's route for each piece of it and for no other route, still
// after a pass that could not list the routes
func TestUnderlayEventFollowsTheCutEndpoints(t *testing.T) {
	mesh := Route{Destination: prefix("192.0.2.0/25")}
	bus := events.New()
	selection := newFakeSelection(holeTable...)
	underlay := func() []netip.Addr { return []netip.Addr{holeEndpoint} }
	sends := func() []Send { return []Send{{Destination: holeSent}} }
	reconciler, table, kernel := coveredHarness(t, Table{}, Runtime{Events: bus, Underlay: underlay, Sends: sends, Selection: selection}, coverAddresses...)
	table.Set(netip.Prefix{}, mesh.Destination, nil)
	pass := func(step string) {
		t.Helper()
		if err := reconciler.reconcile(); err != nil {
			t.Fatalf("%s: %v", step, err)
		}
	}
	pass("the first pass")
	pass("a pass cutting the same endpoints")
	kernel.mu.Lock()
	kernel.failList = errors.New("the dump is broken")
	kernel.mu.Unlock()
	if err := reconciler.reconcile(); err == nil {
		t.Fatal("a pass that could not list the routes reports no error")
	}
	kernel.mu.Lock()
	kernel.failList = nil
	kernel.mu.Unlock()
	for _, piece := range without(mesh.Destination, []netip.Addr{holeEndpoint, holeSent}) {
		if hole, ok := reconciler.HoleAt(piece); !ok || hole.Route != mesh.Destination {
			t.Errorf("HoleAt(%s) is %+v, %v, want %s", piece, hole, ok, mesh.Destination)
		}
	}
	if hole, ok := reconciler.HoleAt(mesh.Destination); ok {
		t.Errorf("HoleAt(%s) names %+v for the route cut", mesh.Destination, hole)
	}
	selection.publish(append(slices.Clone(holeTable), hostRoute{destination: prefix("192.0.2.0/25"), index: 2})...)
	pass("the pass that stops cutting")
	pass("a pass cutting nothing")
	var got []string
	for _, event := range bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "kernel.underlay" }, 0) {
		got = append(got, event.Attrs["cut"]+" / "+event.Attrs["restored"])
	}
	want := []string{"192.0.2.9 192.0.2.100 / none", "none / 192.0.2.9 192.0.2.100"}
	if !slices.Equal(got, want) {
		t.Errorf("the underlay events are %q, want %q", got, want)
	}
}

// In mode 2, an endpoint whose host route is a /0 other than the zero
// address's match cuts the member 128.0.0.0/1 holding it, and each piece goes
// in unscoped as a member, named by Stats and CoverInstalled
func TestPieceOfAMemberStaysAMember(t *testing.T) {
	endpoint := netip.MustParseAddr("203.0.113.9")
	selection := newFakeSelection(
		hostRoute{destination: prefix("0.0.0.0/1"), index: 2},
		hostRoute{destination: prefix("0.0.0.0/0"), index: 3},
	)
	reconciler, _, kernel := modeCovering(t, Table{}.WithMode(&ExitMode{}), nil, coverAddresses...)
	reconciler.rt.Underlay = func() []netip.Addr { return []netip.Addr{endpoint} }
	reconciler.rt.Selection = selection
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	half := prefix("128.0.0.0/1")
	pieces := without(half, []netip.Addr{endpoint})
	held := unscopedAt(kernel.fakeKernel)
	if _, ok := held[half]; ok {
		t.Errorf("the member %s holding %s went in whole", half, endpoint)
	}
	for _, piece := range pieces {
		if r, ok := held[piece]; !ok || !r.Cover {
			t.Errorf("the piece %s of the member %s is held as %+v (found %v), want an unscoped member", piece, half, r, ok)
		}
		if !reconciler.CoverInstalled(piece) {
			t.Errorf("the piece %s is not named a member: %v", piece, reconciler.Stats().Members)
		}
	}
	if len(pieces) != 31 {
		t.Errorf("%s cut around %s is %d pieces, want 31", half, endpoint, len(pieces))
	}
}

// an endpoint the node gained wakes a pass at once, named for the underlay,
// beside a selection
func TestReconcilerRunsAPassForAnEndpointItGained(t *testing.T) {
	wakesAPass(t, (*Reconciler).EndpointsChanged)
}

// wakesAPass fails t unless wake, called on a running reconciler beside a
// selection once its first pass has run, wakes a pass named for the underlay
func wakesAPass(t *testing.T, wake func(*Reconciler)) {
	t.Helper()
	bus := events.New()
	reconciler, table, fake := harness(t, Table{}, Runtime{Events: bus, Selection: newFakeSelection()})
	ordinary := Route{Destination: prefix("2001:db8:5::/48"), Metric: defaultIPv6Metric}
	table.Set(netip.Prefix{}, ordinary.Destination, nil)
	last := runToRecord(t, reconciler, table, bus)
	awaitPass(t, last, "the first pass", "start", func() bool { return fake.has(ordinary) })
	fake.mu.Lock()
	delete(fake.routes, ordinary)
	fake.mu.Unlock()
	wake(reconciler)
	awaitPass(t, last, "the pass the endpoint asked for", "underlay", func() bool { return fake.has(ordinary) })
}

// with no selection an endpoint the node gained wakes no pass, since such a pass reads no endpoint
func TestReconcilerWithNoSelectionWakesForNoEndpoint(t *testing.T) {
	reconciler, _, _ := harness(t, Table{}, Runtime{})
	reconciler.EndpointsChanged()
	if len(reconciler.gained) != 0 {
		t.Error("an endpoint woke a pass on a reconciler with no selection")
	}
}

// halfCut is mode 2 on the covering fake beside a host table whose default
// out of interface 3 is the host route of halfEndpoint and not the zero
// address's match, which is 0.0.0.0/1 out of interface 2, so the member
// 128.0.0.0/1 is cut around the endpoint, the mesh holding mesh beside its
// zero routes
func halfCut(t *testing.T, mesh ...netip.Prefix) (*Reconciler, *coveringKernel) {
	t.Helper()
	reconciler, table, kernel := modeCovering(t, Table{}.WithMode(&ExitMode{}), nil, coverAddresses...)
	reconciler.rt.Underlay = func() []netip.Addr { return []netip.Addr{halfEndpoint} }
	reconciler.rt.Selection = newFakeSelection(
		hostRoute{destination: prefix("0.0.0.0/1"), index: 2},
		hostRoute{destination: prefix("0.0.0.0/0"), index: 3},
	)
	for _, destination := range mesh {
		table.Set(netip.Prefix{}, destination, nil)
	}
	return reconciler, kernel
}

// halfEndpoint is the endpoint halfCut cuts out of the member 128.0.0.0/1
var halfEndpoint = netip.MustParseAddr("203.0.113.9")

// A mesh route the kernel refuses hands the members back, and the member
// holding the endpoint goes back as its pieces, never whole, on this pass and
// the next
func TestRefusedRouteHandsTheMemberHoldingAnEndpointBackCut(t *testing.T) {
	refused := Route{Destination: prefix("198.51.100.0/24")}
	reconciler, kernel := halfCut(t, refused.Destination)
	kernel.failAdd[refused] = errRouteSkipped
	for pass := range 2 {
		if err := reconciler.reconcile(); err != nil {
			t.Fatalf("pass %d: %v", pass, err)
		}
		if reconciler.Stats().Skipped == 0 {
			t.Fatalf("pass %d skipped nothing, so no member was handed back", pass)
		}
		for _, r := range kernel.snapshot() {
			if r.Destination.Contains(halfEndpoint) && !r.Scoped {
				t.Errorf("pass %d: %s, cover %v, holds %s unscoped: %v", pass, r.Destination, r.Cover, halfEndpoint, kernel.snapshot())
			}
		}
	}
}

// A mesh route inside the member 128.0.0.0/1, both holding the endpoint, is
// cut, and each of its pieces keeps its own fields rather than the member's,
// as the longest match did before the cut
func TestPieceOfARouteInsideAMemberKeepsItsOwnFields(t *testing.T) {
	inner := prefix("203.0.113.0/24")
	reconciler, kernel := halfCut(t, inner)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	for _, r := range kernel.snapshot() {
		if inner.Contains(r.Destination.Addr()) && r.Destination.Bits() > inner.Bits() && r.Cover {
			t.Errorf("%s inside the mesh's %s went in as a member of the cover: %v", r.Destination, inner, kernel.snapshot())
		}
	}
}

// A pass reads each endpoint unmapped and with no zone, as a route's prefix
// holds it: a listed endpoint written IPv4-mapped and a live send's
// destination carrying a zone are cut out of the mesh's routes as the plain
// addresses are
func TestPassCutsAnEndpointWrittenMappedOrZoned(t *testing.T) {
	zoned := netip.MustParseAddr("3fff:c::9")
	selection := newFakeSelection(append(slices.Clone(holeTable), hostRoute{destination: prefix("3fff:c::/48"), index: 2})...)
	underlay := func() []netip.Addr { return []netip.Addr{netip.AddrFrom16(holeEndpoint.As16())} }
	sends := func() []Send { return []Send{{Destination: zoned.WithZone("2")}} }
	reconciler, table, kernel := coveredHarness(t, Table{}, Runtime{Underlay: underlay, Sends: sends, Selection: selection}, coverAddresses...)
	cut := map[netip.Addr]netip.Prefix{holeEndpoint: prefix("192.0.2.0/25"), zoned: prefix("3fff:c::/56")}
	for _, mesh := range cut {
		table.Set(netip.Prefix{}, mesh, nil)
	}
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	held := unscopedAt(kernel.fakeKernel)
	for endpoint, mesh := range cut {
		if _, ok := held[mesh]; ok {
			t.Errorf("%s holding %s went in whole: %v", mesh, endpoint, kernel.snapshot())
		}
		for _, piece := range without(mesh, []netip.Addr{endpoint}) {
			if _, ok := held[piece]; !ok {
				t.Errorf("the kernel lacks the piece %s of %s cut around %s: %v", piece, mesh, endpoint, kernel.snapshot())
			}
		}
	}
}
