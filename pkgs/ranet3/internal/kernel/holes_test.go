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
	"ranet3.com/pkgs/ranet3/schema"
)

// fakeSelection is an underlay selection a test publishes generations of by hand
type fakeSelection struct {
	// changed is unbuffered, so a signal handOff sends is one Run took
	changed chan struct{}
	mu      sync.Mutex
	current hostTable
	// overlays is each overlay the selection was handed, in order
	overlays [][]schema.Prefix
}

func (s *fakeSelection) holdOverlay(overlay []schema.Prefix) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.overlays = append(s.overlays, overlay)
}

// handed is each overlay the selection was handed so far
func (s *fakeSelection) handed() [][]schema.Prefix {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.overlays)
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
	pieces := without(mesh.Destination, hostPrefixes(endpoints...))
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
	for _, piece := range without(mesh.Destination, hostPrefixes(holeEndpoint, holeSent)) {
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

// Two nested mesh routes outside the overlay beneath a host route go in scoped
// while the selection holds that route and unscoped once it does not, and
// kernel.underlay is recorded for each of the two passes alone, naming both.
// Between, BeneathAt names the longer of them where both hold an address and
// the host's route, still after a pass that could not list the routes.
func TestUnderlayEventFollowsTheRoutesBeneathTheHosts(t *testing.T) {
	outer, inner := prefix("198.51.100.0/25"), prefix("198.51.100.0/26")
	host := hostRoute{destination: prefix("198.51.100.0/24"), index: 2}
	bus := events.New()
	selection := newFakeSelection(host)
	reconciler, table, kernel := coveredHarness(t, Table{}, Runtime{Events: bus, Selection: selection}, coverAddresses...)
	table.Set(netip.Prefix{}, outer, nil)
	table.Set(netip.Prefix{}, inner, nil)
	pass := func(step string, scoped bool) {
		t.Helper()
		if err := reconciler.reconcile(); err != nil {
			t.Fatalf("%s: %v", step, err)
		}
		for _, mesh := range []netip.Prefix{outer, inner} {
			if !kernel.has(Route{Destination: mesh, Scoped: scoped}) {
				t.Errorf("%s: the kernel lacks %s scoped %v: %v", step, mesh, scoped, kernel.snapshot())
			}
		}
	}
	pass("the first pass", true)
	pass("a pass beneath the same route", true)
	kernel.mu.Lock()
	kernel.failList = errors.New("the dump is broken")
	kernel.mu.Unlock()
	if err := reconciler.reconcile(); err == nil {
		t.Fatal("a pass that could not list the routes reports no error")
	}
	kernel.mu.Lock()
	kernel.failList = nil
	kernel.mu.Unlock()
	for address, mesh := range map[string]netip.Prefix{"198.51.100.7": inner, "198.51.100.77": outer} {
		if b, ok := reconciler.BeneathAt(netip.MustParseAddr(address)); !ok || b != (Beneath{Route: mesh, Host: host.destination}) {
			t.Errorf("BeneathAt(%s) names %+v %v, want %s beneath %s", address, b, ok, mesh, host.destination)
		}
	}
	if b, ok := reconciler.BeneathAt(netip.MustParseAddr("198.51.100.200")); ok {
		t.Errorf("BeneathAt names %+v outside every route scoped beneath", b)
	}
	selection.publish()
	pass("the pass with the host's route gone", false)
	pass("a pass beneath nothing", false)
	var got []string
	for _, event := range bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "kernel.underlay" }, 0) {
		got = append(got, event.Attrs["scoped"]+" / "+event.Attrs["unscoped"]+" / "+event.Attrs["cut"])
	}
	both := outer.String() + " " + inner.String()
	want := []string{both + " / none / none", "none / " + both + " / none"}
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
	pieces := without(half, hostPrefixes(endpoint))
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
		for _, piece := range without(mesh, hostPrefixes(endpoint)) {
			if _, ok := held[piece]; !ok {
				t.Errorf("the kernel lacks the piece %s of %s cut around %s: %v", piece, mesh, endpoint, kernel.snapshot())
			}
		}
	}
}

// darwinKeyed is the covering fake holding one route a key, a destination and
// scope, as darwin keys them: it refuses a second route at a key it holds, or
// an unscoped route at the key of one of hosts, with errRouteSkipped, as
// darwin's AddRoute answers EEXIST
type darwinKeyed struct {
	*coveringKernel
	hosts []hostRoute
}

func (k darwinKeyed) AddRoute(r Route) error {
	scoped := k.scopes(r)
	for _, held := range k.snapshot() {
		if held.Destination == r.Destination && held.Scoped == scoped {
			return errRouteSkipped
		}
	}
	for _, h := range k.hosts {
		if !scoped && !h.scoped && h.destination == r.Destination {
			return errRouteSkipped
		}
	}
	return k.coveringKernel.AddRoute(r)
}

// unbound is where an unbound lookup of destination ends, the longest of the
// host's candidate routes and the fake's unscoped routes holding it, the
// host's winning a tie, and whether that is a route of the host's
func unbound(hosts []hostRoute, kernel *coveringKernel, destination netip.Addr) (netip.Prefix, bool) {
	var best netip.Prefix
	byHost := false
	for _, h := range hosts {
		if h.candidate(selectMesh) && h.destination.Contains(destination) && (!best.IsValid() || h.destination.Bits() > best.Bits()) {
			best, byHost = h.destination, true
		}
	}
	for _, r := range kernel.snapshot() {
		if !r.Scoped && r.Destination.Contains(destination) && (!best.IsValid() || r.Destination.Bits() > best.Bits()) {
			best, byHost = r.Destination, false
		}
	}
	return best, byHost
}

// Under cap.exit mode 2 beside another program's full tunnel, 0.0.0.0/1 and
// 128.0.0.0/1 and the IPv6 halves out of interface 2, every address outside
// the overlay lies beneath a route of the host's longer than /0, so row L6
// sends each by the host's route, as Linux's rule 5410 does. The members
// holding the overlay go in as their pieces around it, each a member, those
// outside it scoped and those inside it unscoped, one route a key, so an
// address of the overlay ends at the mesh and the cover stays in.
func TestFullTunnelTakesEveryAddressOutsideTheOverlay(t *testing.T) {
	hosts := []hostRoute{
		{destination: prefix("0.0.0.0/0"), index: 3},
		{destination: prefix("0.0.0.0/1"), index: 2},
		{destination: prefix("128.0.0.0/1"), index: 2},
		{destination: prefix("::/0"), index: 3},
		{destination: prefix("::/1"), index: 2},
		{destination: prefix("8000::/1"), index: 2},
	}
	reconciler, _, kernel := modeCovering(t, Table{}.WithMode(&ExitMode{}), nil, coverAddresses...)
	reconciler.rt.Selection = newFakeSelection(hosts...)
	reconciler.use(darwinKeyed{kernel, hosts})
	for pass := range 2 {
		if err := reconciler.reconcile(); err != nil {
			t.Fatalf("pass %d: %v", pass, err)
		}
	}
	if stats := reconciler.Stats(); stats.Skipped != 0 || !slices.Equal(stats.Cover, []Family{FamilyIPv4, FamilyIPv6}) {
		t.Errorf("the passes leave the cover of %v and skip %d routes, want both families and none: %v", stats.Cover, stats.Skipped, kernel.snapshot())
	}
	for address, byHost := range map[string]bool{"198.51.100.1": true, "203.0.113.7": true, "2001:db8::1": true, "192.0.2.9": false, "3fff:c::9": false} {
		if route, ok := unbound(hosts, kernel, netip.MustParseAddr(address)); ok != byHost {
			t.Errorf("an unbound lookup of %s ends at %s, the host's %v, want %v: %v", address, route, ok, byHost, kernel.snapshot())
		}
	}
	for _, r := range kernel.snapshot() {
		inside := slices.ContainsFunc(coverOverlay, func(prefix schema.Prefix) bool {
			return prefix.Contains(r.Destination.Addr()) && prefix.Bits() <= r.Destination.Bits()
		})
		if !r.Cover || r.Scoped == inside {
			t.Errorf("%s went in as %+v, want a member scoped %v: %v", r.Destination, r, !inside, kernel.snapshot())
		}
	}
}

// A real route of the mesh at a member's key withholds the member in mode 2,
// with no host route above it as beneath one: 64.0.0.0/2, which holds no
// address of the overlay, goes in scoped beneath another program's 0.0.0.0/1,
// and 128.0.0.0/1, which holds the overlay, goes in as its pieces beneath
// another program's 128.0.0.0/1, scoped outside the overlay. The cover stays
// in with no route refused, pass after pass.
func TestRealRouteAtAMemberKeyWithholdsTheMemberBeneathAHostRoute(t *testing.T) {
	for _, c := range []struct {
		name  string
		real  netip.Prefix
		hosts []hostRoute
		held  []routeKey
	}{
		{"with no host route above it", prefix("64.0.0.0/2"), nil, []routeKey{{destination: prefix("64.0.0.0/2")}}},
		{"beneath 0.0.0.0/1", prefix("64.0.0.0/2"), []hostRoute{{destination: prefix("0.0.0.0/1"), index: 2}},
			[]routeKey{{destination: prefix("64.0.0.0/2"), scoped: true}}},
		{"holding the overlay beneath 128.0.0.0/1", prefix("128.0.0.0/1"), []hostRoute{{destination: prefix("128.0.0.0/1"), index: 2}},
			[]routeKey{{destination: prefix("192.0.2.0/24")}, {destination: prefix("128.0.0.0/2"), scoped: true}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			hosts := append([]hostRoute{{destination: prefix("0.0.0.0/0"), index: 3}}, c.hosts...)
			reconciler, table, kernel := modeCovering(t, Table{}.WithMode(&ExitMode{}), nil, coverAddresses...)
			reconciler.rt.Selection = newFakeSelection(hosts...)
			reconciler.use(darwinKeyed{kernel, hosts})
			table.Set(netip.Prefix{}, c.real, nil)
			for pass := range 3 {
				if err := reconciler.reconcile(); err != nil {
					t.Fatalf("pass %d: %v", pass, err)
				}
				if stats := reconciler.Stats(); stats.Skipped != 0 || !slices.Contains(stats.Cover, FamilyIPv4) {
					t.Fatalf("pass %d leaves the cover of %v and skips %d routes: %v", pass, stats.Cover, stats.Skipped, kernel.snapshot())
				}
			}
			for _, r := range kernel.snapshot() {
				if r.Cover && c.real.Contains(r.Destination.Addr()) {
					t.Errorf("the member %s went in beside the real route %s: %v", r.Destination, c.real, kernel.snapshot())
				}
			}
			for _, key := range c.held {
				if !slices.ContainsFunc(kernel.snapshot(), func(r Route) bool {
					return !r.Cover && r.Destination == key.destination && r.Scoped == key.scoped
				}) {
					t.Errorf("the kernel holds no part of the real route at %s scoped %v: %v", key.destination, key.scoped, kernel.snapshot())
				}
			}
		})
	}
}

// A mesh route holding two prefixes of the overlay beneath a route of the
// host's goes in as its pieces around them, and an endpoint inside each prefix
// cuts that prefix around it. The pass reports one hole for it, the mesh's
// route cut around both endpoints with the pieces of both prefixes, and HoleAt
// names the mesh's route for each piece. A second mesh route inside the
// overlay, cut around an endpoint of its own and left whole by the first cut,
// is a hole of its own, the holes in the order of their routes.
func TestRouteCutAroundTheOverlayIsOneHole(t *testing.T) {
	mesh, second := prefix("198.51.100.0/24"), prefix("203.0.113.0/25")
	overlay := []netip.Prefix{prefix("198.51.100.0/26"), prefix("198.51.100.128/26"), prefix("203.0.113.0/24")}
	endpoints := []netip.Addr{netip.MustParseAddr("198.51.100.9"), netip.MustParseAddr("198.51.100.137"), netip.MustParseAddr("203.0.113.9")}
	selection := newFakeSelection(hostRoute{destination: mesh, index: 2}, hostRoute{destination: overlay[2], index: 2})
	underlay := func() []netip.Addr { return endpoints }
	reconciler, table, fake := harness(t, Table{}, Runtime{Overlay: prefixes(overlay...), Selection: selection, Underlay: underlay})
	kernel := onCovering(reconciler, fake, coverAddresses...)
	table.Set(netip.Prefix{}, mesh, nil)
	table.Set(netip.Prefix{}, second, nil)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	pieces := slices.Concat(without(overlay[0], hostPrefixes(endpoints[0])), without(overlay[1], hostPrefixes(endpoints[1])))
	want := []Hole{
		{Route: mesh, Endpoints: endpoints[:2], Pieces: pieces},
		{Route: second, Endpoints: endpoints[2:], Pieces: without(second, hostPrefixes(endpoints[2]))},
	}
	holes := reconciler.Stats().Holes
	if !slices.EqualFunc(holes, want, func(got, want Hole) bool {
		return got.Route == want.Route && slices.Equal(got.Endpoints, want.Endpoints) && slices.Equal(got.Pieces, want.Pieces)
	}) {
		t.Fatalf("the pass reports the holes %+v, want %+v: %v", holes, want, kernel.snapshot())
	}
	held := unscopedAt(kernel.fakeKernel)
	for _, piece := range pieces {
		if _, ok := held[piece]; !ok {
			t.Errorf("the kernel lacks the piece %s unscoped: %v", piece, kernel.snapshot())
		}
		if hole, ok := reconciler.HoleAt(piece); !ok || hole.Route != mesh {
			t.Errorf("HoleAt(%s) is %+v, %v, want %s", piece, hole, ok, mesh)
		}
	}
}

// A route is cut around the prefixes of the overlay it holds, each in no other
// of them whatever order the overlay lists them in, where it lies beneath a
// route of the host's but for them, and around none where it lies inside one,
// holds none, lies beneath no route of the host's or holds against the FIB
func TestOverlaidIsTheOutermostPrefixesARouteHolds(t *testing.T) {
	table := hostTable{mesh: selectMesh, routes: []hostRoute{{destination: prefix("198.51.100.0/24"), index: 2}}}
	overlay := prefixes(prefix("198.51.100.0/28"), prefix("198.51.100.0/26"), prefix("198.51.100.128/26"), prefix("192.0.2.0/25"))
	for _, c := range []struct {
		route Route
		want  []netip.Prefix
	}{
		{Route{Destination: prefix("198.51.100.0/24")}, []netip.Prefix{prefix("198.51.100.0/26"), prefix("198.51.100.128/26")}},
		{Route{Destination: prefix("198.51.100.0/25")}, []netip.Prefix{prefix("198.51.100.0/26")}},
		{Route{Destination: prefix("198.51.100.0/27")}, nil},
		{Route{Destination: prefix("198.51.100.64/26")}, nil},
		{Route{Destination: prefix("192.0.2.0/24")}, nil},
		{Route{Destination: prefix("198.51.100.0/24"), Unreachable: true}, nil},
	} {
		if got := table.overlaid(c.route, overlay); !slices.Equal(got, c.want) {
			t.Errorf("%+v is cut around %v, want %v", c.route, got, c.want)
		}
	}
}

// A real route at a member's key beneath a route of the host's, refused in the
// pass that also left the family's cover out, withholds the member in the pass
// that installs it, so the cover goes in beside it in that pass
func TestRealRouteBeneathAHostRouteWithholdsTheMemberInThePassItGoesIn(t *testing.T) {
	hosts := []hostRoute{{destination: prefix("0.0.0.0/0"), index: 3}, {destination: prefix("0.0.0.0/1"), index: 2}}
	reconciler, table, kernel := modeCovering(t, Table{}.WithMode(&ExitMode{}), nil, coverAddresses...)
	reconciler.rt.Selection = newFakeSelection(hosts...)
	reconciler.use(darwinKeyed{kernel, hosts})
	real := Route{Destination: prefix("64.0.0.0/2"), Scoped: true}
	table.Set(netip.Prefix{}, real.Destination, nil)
	member := Route{Destination: prefix("1.0.0.0/8"), Cover: true, Scoped: true}
	kernel.failAdd[real], kernel.failAdd[member] = errRouteSkipped, errRouteSkipped
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(reconciler.Stats().Cover, FamilyIPv4) || kernel.has(real) {
		t.Fatalf("the first pass left the cover of %v with the real route held %v, want neither: %v", reconciler.Stats().Cover, kernel.has(real), kernel.snapshot())
	}
	delete(kernel.failAdd, real)
	delete(kernel.failAdd, member)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if stats := reconciler.Stats(); stats.Skipped != 0 || !slices.Contains(stats.Cover, FamilyIPv4) || !kernel.has(real) {
		t.Errorf("the pass installing the real route leaves the cover of %v, skips %d routes and holds it %v: %v", stats.Cover, stats.Skipped, kernel.has(real), kernel.snapshot())
	}
}
