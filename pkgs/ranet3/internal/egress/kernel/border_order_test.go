// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux

package kernel

import (
	"bytes"
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/events"
	meshkernel "ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/logtest"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/sadr"
	"ranet3.com/pkgs/ranet3/schema"
)

const (
	// orderWake bounds the wait for a wake the source owes
	orderWake = 5 * time.Second
	// orderStill is how long a wake that must not come is waited for
	orderStill = 200 * time.Millisecond
	// orderRetry bounds the wait for the pass the retry timer owes, past the
	// retry's first delay
	orderRetry = 3 * time.Second
)

// orderSets derives a pass's sets from table as the node does, its none sets
// from classes
func orderSets(classes []egress.Class, table *netstack.RouteTable) func(*egress.Border) egress.BorderSets {
	return func(cfg *egress.Border) egress.BorderSets {
		return egress.BorderSets{None: meshkernel.NoneDestinations(classes, table.Snapshot(), cfg.Overlay)}
	}
}

// orderFilter is a filter over be deriving its none sets from table as the
// node does, recording on bus, after its first pass
func orderFilter(t *testing.T, table *netstack.RouteTable, be borderBackend, bus *events.Bus) *BorderFilter {
	t.Helper()
	rt := borderRuntime(bus)
	rt.Sets = orderSets(orderClasses, table)
	f := newBorderFilter(&egress.Border{Overlay: orderOverlay}, rt, be)
	if err := f.reconcile(); err != nil {
		t.Fatalf("the first pass: %v", err)
	}
	f.trigger = "routes"
	t.Cleanup(func() { _ = f.Close() })
	return f
}

// sourceWoken reports whether src's channel carries a wake within orderWake
func sourceWoken(src meshkernel.RouteSource) bool {
	select {
	case <-src.Changes():
		return true
	case <-time.After(orderWake):
		return false
	}
}

// sourceDrained empties src's channel
func sourceDrained(src meshkernel.RouteSource) {
	select {
	case <-src.Changes():
	default:
	}
}

// reportMoves is each antispoof event of kind bus recorded, as route and its flag
func reportMoves(bus *events.Bus, kind string) []string {
	var out []string
	for _, event := range bus.Recorded(func(k, _ string, _ []slog.Attr) bool { return k == "antispoof."+kind }, 0) {
		out = append(out, event.Attrs["route"]+" "+event.Attrs[kind])
	}
	return out
}

// hands reports whether handed holds an entry to destination that is a hold
// where hold is true and no hold where it is false
func hands(handed []sadr.Route[*netstack.Peer], destination netip.Prefix, hold bool) bool {
	return slices.ContainsFunc(handed, func(entry sadr.Route[*netstack.Peer]) bool {
		return entry.Destination == destination && (entry.Value == netstack.Unreachable) == hold
	})
}

// orderRouter is the peer the LANs of a test are routed through
var orderRouter = &netstack.Peer{ID: "example/router"}

// orderLearn has table learn lan from orderRouter
func orderLearn(table *netstack.RouteTable, lan netip.Prefix) {
	table.Set(netip.Prefix{}, lan, orderRouter)
}

// orderPass runs one pass of f as trigger wakes it and fails the test where it fails
func orderPass(t *testing.T, f *BorderFilter, trigger string) {
	t.Helper()
	f.trigger = trigger
	if err := f.reconcile(); err != nil {
		t.Fatalf("a pass woken by %s: %v", trigger, err)
	}
}

// holdsAddress reports whether ranges hold address
func holdsAddress(ranges []egress.Range, address netip.Addr) bool {
	return slices.ContainsFunc(ranges, func(r egress.Range) bool { return !address.Less(r.First) && !r.Last.Less(address) })
}

// noneHolds reports whether be's none sets hold address
func noneHolds(be *fakeBorder, address netip.Addr) bool {
	be.mu.Lock()
	defer be.mu.Unlock()
	return holdsAddress(be.sets.none(), address)
}

// noneFamilies is be's IPv4 and IPv6 none sets, and whether each holds its
// own family's ranges alone
func noneFamilies(be *fakeBorder) (v4, v6 []egress.Range, apart bool) {
	be.mu.Lock()
	defer be.mu.Unlock()
	v4, v6 = slices.Clone(be.sets[noneSet+"4"]), slices.Clone(be.sets[noneSet+"6"])
	apart = !slices.ContainsFunc(v4, func(r egress.Range) bool { return !r.First.Is4() }) && !slices.ContainsFunc(v6, func(r egress.Range) bool { return !r.First.Is6() })
	return v4, v6, apart
}

// duringFilter is a filter over be deriving its sets from table as
// orderFilter's does, after its first pass, and the hook it runs once inside
// the next derivation after the hook is set
func duringFilter(t *testing.T, table *netstack.RouteTable, be borderBackend) (*BorderFilter, *func()) {
	t.Helper()
	during := new(func())
	rt := borderRuntime(nil)
	derive := orderSets(orderClasses, table)
	rt.Sets = func(cfg *egress.Border) egress.BorderSets {
		sets := derive(cfg)
		if hook := *during; hook != nil {
			*during = nil
			hook()
		}
		return sets
	}
	f := newBorderFilter(&egress.Border{Overlay: orderOverlay}, rt, be)
	orderPass(t, f, "start")
	t.Cleanup(func() { _ = f.Close() })
	return f, during
}

// The route source wakes its reader on a change of the mesh's table, holds a
// LAN a none class takes back over a failed pass without waking it, and wakes
// it on the pass that wrote the none set without the LAN, from which the LAN
// is handed over, and a pass that moves no set does not wake it
func TestRoutesWakeTheirReaderOnTheTableAndOnThePassThatFreesALAN(t *testing.T) {
	table := netstack.NewRouteTable()
	be := &fakeBorder{}
	f := orderFilter(t, table, be, nil)
	src := f.Routes(table)
	lan := netip.MustParsePrefix("198.51.100.32/27")
	orderLearn(table, lan)
	if !sourceWoken(src) {
		t.Fatal("a change of the mesh's table woke no reader")
	}
	be.failRules = true
	if err := f.reconcile(); err == nil {
		t.Fatal("a pass whose read fails reported no error")
	}
	if got := src.Snapshot(); len(got) != 1 || !hands(got, lan, true) {
		t.Fatalf("over a failed pass the source handed %v, want a hold at the LAN alone", got)
	}
	select {
	case <-src.Changes():
		t.Fatal("a failed pass woke the reader")
	default:
	}
	be.failRules = false
	orderPass(t, f, "routes")
	if !sourceWoken(src) {
		t.Fatal("the pass that wrote the none set without the LAN woke no reader")
	}
	if got := src.Snapshot(); !slices.Equal(got, table.Snapshot()) {
		t.Fatalf("after the pass the source handed %v, want %v", got, table.Snapshot())
	}
	sourceDrained(src)
	orderPass(t, f, "sweep")
	select {
	case <-src.Changes():
		t.Fatal("a pass that moved no set woke the reader")
	default:
	}
}

// The filter builds one route source, and a second call hands it again
func TestRoutesBuildOneSourceThatEachCallHands(t *testing.T) {
	table := netstack.NewRouteTable()
	f := orderFilter(t, table, &fakeBorder{}, nil)
	if first, second := f.Routes(table), f.Routes(netstack.NewRouteTable()); first != second {
		t.Fatalf("a second call built a second source %p beside %p", second, first)
	}
}

// A reload that takes a LAN's addresses out of the overlay moves the entry
// into the held ones at once, and wakes the source's reader with it, though
// the reload's own pass fails
func TestRoutesWakeTheirReaderOnAReloadThatMovesTheOverlay(t *testing.T) {
	table := netstack.NewRouteTable()
	lan := netip.MustParsePrefix("203.0.113.16/28")
	orderLearn(table, lan)
	be := &fakeBorder{}
	f := orderFilter(t, table, be, nil)
	src := f.Routes(table)
	if !hands(src.Snapshot(), lan, false) {
		t.Fatalf("inside the overlay the source holds %s back", lan)
	}
	sourceDrained(src)
	be.failRules = true
	if err := f.SetConfig(egress.Border{Overlay: []schema.Prefix{schema.MustPrefix("203.0.113.128/25"), schema.MustPrefix("3fff::/20")}}); err != nil {
		t.Fatal(err)
	}
	f.trigger = "reload"
	_ = f.reconcile()
	if !sourceWoken(src) {
		t.Fatal("a reload that took the LAN out of the overlay woke no reader")
	}
	if got := src.Snapshot(); !hands(got, lan, true) {
		t.Fatalf("after the reload the source hands %v, want a hold at %s, whose addresses the host's none set holds", got, lan)
	}
}

// The none sets leave a LAN's addresses out while the reconciler says the
// kernel may hold its route, though the mesh's table no longer holds the LAN.
// The report that the route went wakes the filter, whose pass takes them
// back, and a report that moves nothing the sets leave out wakes nothing.
func TestSetsLeaveOutALANWhileTheKernelHoldsItsRoute(t *testing.T) {
	table := netstack.NewRouteTable()
	be := &fakeBorder{}
	f := orderFilter(t, table, be, nil)
	src := f.Routes(table)
	sink := src.(meshkernel.InstalledSink)
	lan := netip.MustParsePrefix("198.51.100.32/27")
	host := lan.Addr().Next()
	route := []meshkernel.Route{{Destination: lan}}
	kernelWoke := func() bool {
		select {
		case <-f.kernel:
			return true
		default:
			return false
		}
	}
	orderLearn(table, lan)
	orderPass(t, f, "routes")
	if !hands(src.Snapshot(), lan, false) {
		t.Fatal("after the pass that wrote the sets without the LAN the source holds it back")
	}
	sink.Installed(route)
	if kernelWoke() {
		t.Fatal("a report of a route whose LAN the sets already leave out woke a pass")
	}
	table.Remove(netip.Prefix{}, lan)
	orderPass(t, f, "routes")
	if noneHolds(be, host) {
		t.Fatalf("with the LAN gone from the table and its route in the kernel the none set holds %s", host)
	}
	sink.Installed(nil)
	if !kernelWoke() {
		t.Fatal("the report that the route went woke no pass")
	}
	orderPass(t, f, "kernel")
	if !noneHolds(be, host) {
		t.Fatalf("once the route went the none set leaves %s out", host)
	}
}

// A LAN the mesh no longer carries comes back into the none sets at the
// filter's pass after the report of the reconciler's pass that deleted its
// route, though that report still names a route outside every class, whose
// add failed, and that route keeps its own addresses out alone
func TestLANComesBackThoughAnUnrelatedAddFailsAtEveryPass(t *testing.T) {
	table := netstack.NewRouteTable()
	be := &fakeBorder{}
	f := orderFilter(t, table, be, nil)
	src := f.Routes(table)
	sink := src.(meshkernel.InstalledSink)
	lan, refused := netip.MustParsePrefix("198.51.100.32/27"), netip.MustParsePrefix("192.0.2.128/25")
	orderLearn(table, refused)
	orderLearn(table, lan)
	orderPass(t, f, "routes")
	src.Snapshot()
	// the pass installed the LAN's route, and the kernel answered the other add with an error
	sink.Installed([]meshkernel.Route{{Destination: lan}, {Destination: refused}})
	table.Remove(netip.Prefix{}, lan)
	orderPass(t, f, "routes")
	if noneHolds(be, lan.Addr().Next()) {
		t.Fatal("the none set took the LAN back while its route was in the kernel")
	}
	src.Snapshot()
	sink.Installed([]meshkernel.Route{{Destination: refused}})
	orderPass(t, f, "kernel")
	if !noneHolds(be, lan.Addr().Next()) {
		t.Fatal("at the filter's pass after the report that the LAN's route went, the none set leaves it out")
	}
}

// The route the source promised at a snapshot keeps its addresses out of the
// none sets across a later snapshot that no longer hands its entry, until the
// reconciler reports
func TestPromiseOfASnapshotStandsUntilTheReconcilerReports(t *testing.T) {
	table := netstack.NewRouteTable()
	be := &fakeBorder{}
	f := orderFilter(t, table, be, nil)
	src := f.Routes(table)
	sink := src.(meshkernel.InstalledSink)
	lan := netip.MustParsePrefix("198.51.100.32/27")
	host := lan.Addr().Next()
	orderLearn(table, lan)
	orderPass(t, f, "routes")
	if !hands(src.Snapshot(), lan, false) {
		t.Fatal("setup: after the pass that wrote the sets without the LAN the source holds it back")
	}
	table.Remove(netip.Prefix{}, lan)
	if hands(src.Snapshot(), lan, false) {
		t.Fatal("setup: a snapshot after the LAN left the table handed it")
	}
	orderPass(t, f, "routes")
	if noneHolds(be, host) {
		t.Fatalf("with the route promised at the first snapshot unreported, a later snapshot not handing it, the none set holds %s", host)
	}
	sink.Installed(nil)
	orderPass(t, f, "kernel")
	if !noneHolds(be, host) {
		t.Fatalf("after a report naming no route to the LAN the none set leaves %s out", host)
	}
}

// A pass writes each family's none ranges into that family's set, and takes
// out the addresses of a route the kernel holds and of a route the source
// promised though the held route's addresses sort after the promised one's
func TestPassTakesEachRouteOutOfItsFamilysNoneSet(t *testing.T) {
	table := netstack.NewRouteTable()
	be := &fakeBorder{}
	f := orderFilter(t, table, be, nil)
	src := f.Routes(table)
	sink := src.(meshkernel.InstalledSink)
	held, promised := netip.MustParsePrefix("2001:db8:76:5::/64"), netip.MustParsePrefix("198.51.100.32/27")
	sink.Installed([]meshkernel.Route{{Destination: held}})
	orderLearn(table, promised)
	orderPass(t, f, "routes")
	if !hands(src.Snapshot(), promised, false) {
		t.Fatalf("setup: after the pass that wrote the sets without %s the source holds it back", promised)
	}
	table.Remove(netip.Prefix{}, promised)
	orderPass(t, f, "routes")
	v4, v6, apart := noneFamilies(be)
	if !apart || len(v6) == 0 {
		t.Fatalf("the IPv4 none set holds %v and the IPv6 one %v, want each its own family's ranges and the IPv6 class in the IPv6 set", v4, v6)
	}
	if holdsAddress(v4, promised.Addr().Next()) || holdsAddress(v6, held.Addr().Next()) {
		t.Fatalf("the IPv4 none set %v holds the promised %s or the IPv6 one %v holds the held %s", v4, promised, v6, held)
	}
}

// A reload that lands while a pass derives its sets has the pass leave out
// what a route the kernel holds keeps out under either overlay: the addresses
// of a route inside the overlay before the reload and outside it after, and of
// a route outside both, which sort after them
func TestPassAcrossAReloadLeavesOutWhatEitherOverlayKeepsOut(t *testing.T) {
	table := netstack.NewRouteTable()
	be := &fakeBorder{}
	f, during := duringFilter(t, table, be)
	sink := f.Routes(table).(meshkernel.InstalledSink)
	overlaid, outside := netip.MustParsePrefix("203.0.113.64/28"), netip.MustParsePrefix("2001:db8:76:5::/64")
	sink.Installed([]meshkernel.Route{{Destination: overlaid}, {Destination: outside}})
	*during = func() {
		if err := f.SetConfig(egress.Border{Overlay: []schema.Prefix{schema.MustPrefix("203.0.113.128/25"), schema.MustPrefix("3fff::/20")}}); err != nil {
			t.Error(err)
		}
	}
	orderPass(t, f, "reload")
	if noneHolds(be, overlaid.Addr().Next()) || noneHolds(be, outside.Addr().Next()) {
		t.Fatalf("across the reload the none set holds %s %v and %s %v, want both left out", overlaid.Addr().Next(), noneHolds(be, overlaid.Addr().Next()), outside.Addr().Next(), noneHolds(be, outside.Addr().Next()))
	}
}

// A report of a route whose addresses the last pass's none sets hold, as of a
// route whose delete the kernel refused after its entry left the mesh's table,
// wakes the filter, and the pass it wakes takes them out
func TestReportOfARouteTheSetsHoldWakesAPass(t *testing.T) {
	be := &fakeBorder{}
	f := orderFilter(t, netstack.NewRouteTable(), be, nil)
	sink := f.Routes(netstack.NewRouteTable()).(meshkernel.InstalledSink)
	lan := netip.MustParsePrefix("198.51.100.32/27")
	host := lan.Addr().Next()
	if !noneHolds(be, host) {
		t.Fatalf("setup: the none set leaves %s out", host)
	}
	sink.Installed([]meshkernel.Route{{Destination: lan}})
	select {
	case <-f.kernel:
	default:
		t.Fatal("the report of a route whose addresses the sets hold woke no pass")
	}
	orderPass(t, f, "kernel")
	if noneHolds(be, host) {
		t.Fatalf("the pass the report woke left %s in the none set", host)
	}
}

// A pass the reconciler's report wakes that asks for the sets the last pass
// read back as written reads nothing
func TestPassWokenByAReportThatMovesNoSetReadsNothing(t *testing.T) {
	be := &fakeBorder{}
	f := orderFilter(t, netstack.NewRouteTable(), be, nil)
	be.mu.Lock()
	was := len(be.log)
	be.mu.Unlock()
	orderPass(t, f, "kernel")
	be.mu.Lock()
	defer be.mu.Unlock()
	if len(be.log) != was {
		t.Fatalf("a pass the report woke that moved no set did %q", be.log[was:])
	}
}

// A snapshot taken while a pass derives its sets from a table that no longer
// holds a LAN, the LAN advertised again in between, hands the LAN, and that
// pass leaves the LAN's addresses out of the sets it writes
func TestSnapshotInsideAPassKeepsWhatItHandsOutOfThatPassesSets(t *testing.T) {
	table := netstack.NewRouteTable()
	be := &fakeBorder{}
	lan := netip.MustParsePrefix("198.51.100.32/27")
	f, during := duringFilter(t, table, be)
	src := f.Routes(table)
	orderLearn(table, lan)
	orderPass(t, f, "routes")
	table.Remove(netip.Prefix{}, lan)
	var handed bool
	*during = func() {
		orderLearn(table, lan)
		handed = hands(src.Snapshot(), lan, false)
	}
	orderPass(t, f, "routes")
	if !handed || noneHolds(be, lan.Addr().Next()) {
		t.Fatalf("the snapshot inside the pass handed %s %v, and the pass wrote %s into the none set %v, want it handed and left out", lan, handed, lan.Addr().Next(), noneHolds(be, lan.Addr().Next()))
	}
}

// A LAN the route source holds back as two passes in a row end is reported
// once, at the second, by its destination and the source it is routed for,
// and its release once, at the pass that frees it, while a LAN learned as a
// pass reads, held as that pass ends and freed by the next, is never reported
func TestRoutesReportALANHeldAcrossAPass(t *testing.T) {
	table := netstack.NewRouteTable()
	be := &orderFake{fakeBorder: &fakeBorder{}, landed: func(string) {}}
	bus := events.New()
	f := orderFilter(t, table, be, bus)
	src := f.Routes(table)
	router := orderRouter
	lan := netip.MustParsePrefix("198.51.100.0/28")
	be.during = func() { orderLearn(table, lan) }
	orderPass(t, f, "reload")
	if hands(src.Snapshot(), lan, false) {
		t.Fatalf("as the pass it was learned in ended the source handed %v, want the LAN held", src.Snapshot())
	}
	orderPass(t, f, "routes")
	if got := reportMoves(bus, "held"); len(got) != 0 {
		t.Fatalf("a LAN the next pass freed was reported %q", got)
	}
	table.Set(netip.MustParsePrefix("2001:db8:5::/48"), netip.MustParsePrefix("2001:db8:76:6::/64"), router)
	be.failRules = true
	for range 3 {
		_ = f.reconcile()
	}
	want := []string{"2001:db8:76:6::/64 from 2001:db8:5::/48 true"}
	if got := reportMoves(bus, "held"); !slices.Equal(got, want) {
		t.Fatalf("over three failed passes the reports read %q, want %q", got, want)
	}
	be.failRules = false
	orderPass(t, f, "routes")
	want = append(want, "2001:db8:76:6::/64 from 2001:db8:5::/48 false")
	if got := reportMoves(bus, "held"); !slices.Equal(got, want) {
		t.Fatalf("after the pass that freed it the reports read %q, want %q", got, want)
	}
}

// A route the kernel still holds whose LAN left the mesh's table, kept out of
// the sets, is reported once it stays across two pass ends, and its end once,
// at the pass the report that it went wakes
func TestRoutesReportWhatTheKernelHoldsThatTheSetsLeaveOut(t *testing.T) {
	table := netstack.NewRouteTable()
	be := &fakeBorder{}
	bus := events.New()
	f := orderFilter(t, table, be, bus)
	src := f.Routes(table)
	sink := src.(meshkernel.InstalledSink)
	lan := netip.MustParsePrefix("198.51.100.32/27")
	route := meshkernel.Route{Destination: lan}
	sink.Installed([]meshkernel.Route{route})
	orderPass(t, f, "kernel")
	orderPass(t, f, "sweep")
	want := []string{route.String() + " true"}
	if got := reportMoves(bus, "kept"); !slices.Equal(got, want) {
		t.Fatalf("over two passes the reports read %q, want %q", got, want)
	}
	sink.Installed(nil)
	orderPass(t, f, "kernel")
	want = append(want, route.String()+" false")
	if got := reportMoves(bus, "kept"); !slices.Equal(got, want) {
		t.Fatalf("after the route went the reports read %q, want %q", got, want)
	}

	// a route promised to the reconciler for an entry the table has dropped
	// since keeps its addresses out under its name
	other := netip.MustParsePrefix("198.51.100.96/27")
	orderLearn(table, other)
	orderPass(t, f, "routes")
	src.Snapshot()
	table.Remove(netip.Prefix{}, other)
	// the sets stay as they were, so a pass the table wakes reads nothing
	orderPass(t, f, "sweep")
	orderPass(t, f, "sweep")
	promised := meshkernel.Route{Destination: other}
	want = append(want, promised.String()+" true")
	if got := reportMoves(bus, "kept"); !slices.Equal(got, want) || noneHolds(be, other.Addr().Next()) {
		t.Fatalf("with a route promised for a dropped entry the reports read %q, want %q, and the none set holds it %v", got, want, noneHolds(be, other.Addr().Next()))
	}
	sink.Installed(nil)
	orderPass(t, f, "kernel")
	if want = append(want, promised.String()+" false"); !slices.Equal(reportMoves(bus, "kept"), want) || !noneHolds(be, other.Addr().Next()) {
		t.Fatalf("once a report named no route to it the reports read %q, want %q, and the none set holds it %v", reportMoves(bus, "kept"), want, noneHolds(be, other.Addr().Next()))
	}
}

// A reload that brings a kept route's addresses inside the overlay ends its
// keeping though the reconciler still reports the route and the sets as
// derived still hold its addresses, and the event and the release line that
// name its end give that case
func TestKeptRouteEndsAtAReloadThatBringsItInsideTheOverlay(t *testing.T) {
	var lines bytes.Buffer
	logtest.SetDefault(t, slog.New(slog.NewTextHandler(&lines, nil)))
	table := netstack.NewRouteTable()
	be := &fakeBorder{}
	bus := events.New()
	rt := borderRuntime(bus)
	rt.Sets = orderSets(orderClasses, table)
	f := newBorderFilter(&egress.Border{Overlay: []schema.Prefix{schema.MustPrefix("203.0.113.0/26"), schema.MustPrefix("3fff::/20")}}, rt, be)
	orderPass(t, f, "start")
	t.Cleanup(func() { _ = f.Close() })
	sink := f.Routes(table).(meshkernel.InstalledSink)
	// inside the none class of the overlay's first half, outside the overlay before the reload
	route := meshkernel.Route{Destination: netip.MustParsePrefix("203.0.113.64/28")}
	host := route.Destination.Addr().Next()
	sink.Installed([]meshkernel.Route{route})
	orderPass(t, f, "kernel")
	orderPass(t, f, "sweep")
	if got, want := reportMoves(bus, "kept"), []string{route.String() + " true"}; !slices.Equal(got, want) {
		t.Fatalf("setup: before the reload the reports read %q, want %q", got, want)
	}
	if err := f.SetConfig(egress.Border{Overlay: orderOverlay}); err != nil {
		t.Fatal(err)
	}
	lines.Reset()
	orderPass(t, f, "reload")
	f.noneMu.Lock()
	reported, derived := slices.Contains(f.reported, route), holdsAddress(f.derived, host)
	f.noneMu.Unlock()
	if !reported || !derived {
		t.Fatalf("setup: after the reload the report names the route %v and the sets as derived hold %s %v, want both", reported, host, derived)
	}
	if got, want := reportMoves(bus, "kept"), []string{route.String() + " true", route.String() + " false"}; !slices.Equal(got, want) {
		t.Fatalf("after the reload the reports read %q, want %q", got, want)
	}
	if !strings.Contains(lines.String(), route.String()) || !strings.Contains(lines.String(), "a reload brings them inside the overlay") {
		t.Fatalf("the release line after the reload gives no reload's case for %s:\n%s", route, lines.String())
	}
}

// Routes coming and going at every pass draw an event each, and at most one
// line of each kind every routeReportInterval, which names only the routes in
// the state it states as it is logged, each once
func TestRouteReportsDrawOneLineOfEachKindAnInterval(t *testing.T) {
	var lines bytes.Buffer
	logtest.SetDefault(t, slog.New(slog.NewTextHandler(&lines, nil)))
	bus := events.New()
	r := routeReport{what: "held", warn: "came", release: "went"}
	at := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	const routes = 100
	for i := range routes {
		route := fmt.Sprintf("198.51.100.%d/32", i)
		for _, now := range [][]string{{route}, {route}, nil} {
			r.pass(now, bus, at)
			at = at.Add(time.Millisecond)
		}
	}
	count := func(msg string) int { return strings.Count(lines.String(), "msg="+msg+" ") }
	if came, went := count("came"), count("went"); came != 1 || went != 1 {
		t.Fatalf("%d routes coming and going within %s drew %d lines of came and %d of went, want one each", routes, routeReportInterval, came, went)
	}
	if got := len(reportMoves(bus, "held")); got != 2*routes {
		t.Fatalf("%d routes coming and going drew %d events, want %d", routes, got, 2*routes)
	}
	r.pass(nil, bus, at.Add(routeReportInterval))
	if came, went := count("came"), count("went"); came != 1 || went != 2 || !strings.Contains(lines.String(), fmt.Sprintf("count=%d", routes-1)) {
		t.Fatalf("a pass %s on drew %d lines of came and %d of went, want one and two, the second counting %d, none of the routes held then:\n%s", routeReportInterval, came, went, routes-1, lines.String())
	}
	all := strings.TrimSuffix(lines.String(), "\n")
	last := all[strings.LastIndex(all, "\n")+1:]
	if named := strings.Count(last, "198.51.100."); named != reportedRouteNames || !strings.Contains(last, ", ...") {
		t.Fatalf("the line counting %d routes names %d of them, want the first %d and the rest left to the count:\n%s", routes-1, named, reportedRouteNames, last)
	}
}

// A route that comes, goes and comes again inside one spacing is named by a
// line in the state the line states as it is logged alone, and once
func TestRouteReportNamesARouteInTheStateItsLineStates(t *testing.T) {
	var lines bytes.Buffer
	logtest.SetDefault(t, slog.New(slog.NewTextHandler(&lines, nil)))
	r := routeReport{what: "held", warn: "came", release: "went"}
	start := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	lan := []string{"198.51.100.16/28"}
	for _, step := range []struct {
		at   time.Duration
		now  []string
		want string
	}{
		{0, lan, ""},
		{time.Second, lan, "came"},
		{2 * time.Second, nil, "went"},
		{3 * time.Second, lan, ""},
		{4 * time.Second, lan, ""},
		// the route that came again went again before the warning was due
		{5 * time.Second, nil, ""},
		{11 * time.Second, nil, ""},
		{12 * time.Second, nil, "went"},
		{13 * time.Second, lan, ""},
		{14 * time.Second, lan, "came"},
		// the route that went at 15 seconds came back before the release was due
		{15 * time.Second, nil, ""},
		{16 * time.Second, lan, ""},
		{22 * time.Second, lan, ""},
		{25 * time.Second, lan, "came"},
		{26 * time.Second, nil, "went"},
	} {
		lines.Reset()
		r.pass(step.now, events.New(), start.Add(step.at))
		got := ""
		if msg := strings.Index(lines.String(), "msg="); msg >= 0 {
			got = strings.Fields(lines.String()[msg+len("msg="):])[0]
		}
		if got != step.want || got != "" && !strings.Contains(lines.String(), "count=1") {
			t.Fatalf("at %v with %v held the report wrote %q, want %s", step.at, step.now, lines.String(), cmp.Or(step.want, "nothing"))
		}
	}
}

// A pass whose write lands while the readback after it still faults leaves a
// LAN inside a none class held, since the sets may still admit it, and the
// pass that reads them back as written hands it
func TestRoutesHoldALANWhileTheReadbackAfterAWriteFaults(t *testing.T) {
	table := netstack.NewRouteTable()
	be := &fakeBorder{}
	f := orderFilter(t, table, be, nil)
	src := f.Routes(table)
	lan := netip.MustParsePrefix("198.51.100.32/27")
	orderLearn(table, lan)
	be.mu.Lock()
	be.fault, be.stuck = "its table reads back otherwise", true
	be.mu.Unlock()
	_ = f.reconcile()
	if f.ready || be.applied == 0 {
		t.Fatalf("setup: the pass left the filter ready %v after %d rewrites, want it rewritten and not ready", f.ready, be.applied)
	}
	if hands(src.Snapshot(), lan, false) {
		t.Fatalf("after a pass whose readback after its write faults the source handed %s", lan)
	}
	be.mu.Lock()
	be.fault, be.stuck = "", false
	be.mu.Unlock()
	orderPass(t, f, "routes")
	if !hands(src.Snapshot(), lan, false) {
		t.Fatalf("after the pass that read the sets back as written the source holds %s back", lan)
	}
}

// A pass that ends with the route source holding a LAN back over a readback
// fault is followed by a pass within the retry's delay, with no other wake,
// and the pass whose readback is clean hands the LAN
func TestRoutesHeldOverAReadbackFaultAreRetried(t *testing.T) {
	table := netstack.NewRouteTable()
	be := &fakeBorder{}
	f := orderFilter(t, table, be, nil)
	src := f.Routes(table)
	lan := netip.MustParsePrefix("198.51.100.32/27")
	orderLearn(table, lan)
	be.mu.Lock()
	be.fault, be.stuck = "its table reads back otherwise", true
	be.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- f.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	f.kernel <- struct{}{}
	for deadline := time.Now().Add(orderWake); f.Stats().Ready; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the wake drew no pass")
		}
	}
	// the pass rewrote the table and read it back faulty, the LAN held
	if hands(src.Snapshot(), lan, false) {
		t.Fatalf("after a pass whose readback faulted the source handed %s", lan)
	}
	be.mu.Lock()
	be.fault, be.stuck = "", false
	be.mu.Unlock()
	for deadline := time.Now().Add(orderRetry); !hands(src.Snapshot(), lan, false); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("no pass followed the one that held %s over a readback fault within %v", lan, orderRetry)
		}
	}
}

// A pass that reads before its fill arms the retry only where it ends on a
// readback fault with the route source holding a route back: neither a clean
// pass nor a faulted pass that holds nothing back arms it
func TestRetryIsArmedOnlyForARouteHeldOverAReadbackFault(t *testing.T) {
	table := netstack.NewRouteTable()
	be := &fakeBorder{}
	f := orderFilter(t, table, be, nil)
	f.Routes(table)
	orderPass(t, f, "sweep")
	if f.retryOnFault {
		t.Fatal("a clean pass armed the retry")
	}
	be.mu.Lock()
	be.fault, be.stuck = "its table reads back otherwise", true
	be.mu.Unlock()
	_ = f.reconcile()
	if f.ready || f.retryOnFault {
		t.Fatalf("a faulted pass holding nothing back left the filter ready %v and armed the retry %v, want neither", f.ready, f.retryOnFault)
	}
	orderLearn(table, netip.MustParsePrefix("198.51.100.32/27"))
	_ = f.reconcile()
	if !f.retryOnFault {
		t.Fatal("a faulted pass holding a LAN back armed no retry")
	}
}

// The route source holds back a LAN the none sets may still admit as long as
// they stay: past a withdrawal the host refuses, past the close of a filter
// that took over another start's chains and leaves them, and past the leave
// after the mesh failed. A withdrawal that took them hands it.
func TestRoutesHoldWhatTheSetsMayAdmitWhileTheChainsStay(t *testing.T) {
	lan := netip.MustParsePrefix("198.51.100.32/27")
	// heldOver learns the LAN and fails a pass, so the sets may still admit it
	heldOver := func(t *testing.T, f *BorderFilter, table *netstack.RouteTable, be *fakeBorder) meshkernel.RouteSource {
		t.Helper()
		src := f.Routes(table)
		orderLearn(table, lan)
		be.failRules = true
		_ = f.reconcile()
		be.failRules = false
		if hands(src.Snapshot(), lan, false) {
			t.Fatalf("setup: over a failed pass the source handed %s", lan)
		}
		return src
	}
	for _, stop := range []struct {
		name  string
		hands bool
		run   func(*testing.T, *netstack.RouteTable, *fakeBorder) meshkernel.RouteSource
	}{
		{"a withdrawal", true, func(t *testing.T, table *netstack.RouteTable, be *fakeBorder) meshkernel.RouteSource {
			f := orderFilter(t, table, be, nil)
			src := heldOver(t, f, table, be)
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			return src
		}},
		{"a withdrawal the host refuses", false, func(t *testing.T, table *netstack.RouteTable, be *fakeBorder) meshkernel.RouteSource {
			f := orderFilter(t, table, be, nil)
			src := heldOver(t, f, table, be)
			be.failWithdraw = true
			if err := f.Close(); err == nil {
				t.Fatal("a withdrawal the host refused reported no error")
			}
			return src
		}},
		{"the close of a filter that took over another start's chains", false, func(t *testing.T, table *netstack.RouteTable, be *fakeBorder) meshkernel.RouteSource {
			rt := borderRuntime(nil)
			rt.Sets = orderSets(orderClasses, table)
			cfg := &egress.Border{Overlay: orderOverlay}
			if _, err := startBorderFilter(cfg, rt, be); err != nil {
				t.Fatal(err)
			}
			f, err := startBorderFilter(cfg, rt, be)
			if err != nil {
				t.Fatal(err)
			}
			if f.made {
				t.Fatal("setup: the second start made the chains, want it to take them over")
			}
			f.trigger = "routes"
			src := heldOver(t, f, table, be)
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			return src
		}},
		{"the leave after the mesh failed", false, func(t *testing.T, table *netstack.RouteTable, be *fakeBorder) meshkernel.RouteSource {
			f := orderFilter(t, table, be, nil)
			src := heldOver(t, f, table, be)
			// a pass the run might take first fails too
			be.failRules = true
			ctx, cancel := context.WithCancelCause(context.Background())
			cancel(meshkernel.ErrMeshFailed)
			if err := f.Run(ctx); err != nil {
				t.Fatal(err)
			}
			return src
		}},
	} {
		t.Run(stop.name, func(t *testing.T) {
			src := stop.run(t, netstack.NewRouteTable(), &fakeBorder{})
			if got := hands(src.Snapshot(), lan, false); got != stop.hands {
				t.Errorf("after %s the source hands %s %v, want %v", stop.name, lan, got, stop.hands)
			}
		})
	}
}

// The filter's watch of the mesh's table ends with the filter, so a change of
// the table after the filter stopped wakes no reader of the source
func TestRoutesWatchOfTheTableEndsWithTheFilter(t *testing.T) {
	table := netstack.NewRouteTable()
	f := orderFilter(t, table, &fakeBorder{}, nil)
	src := f.Routes(table)
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	lan := netip.MustParsePrefix("198.51.100.32/27")
	// the watch may forward a change that comes as it ends, so the test looks until one wakes nothing
	for there, deadline := false, time.Now().Add(orderWake); ; there = !there {
		sourceDrained(src)
		if there {
			table.Remove(netip.Prefix{}, lan)
		} else {
			orderLearn(table, lan)
		}
		select {
		case <-src.Changes():
		case <-time.After(orderStill):
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("a change of the table after the filter stopped still wakes the source's reader")
		}
	}
}

// Before the filter's first pass has read its sets back the route source
// holds back each learned entry outside the overlay, inside a none class or
// outside every class, since the sets may hold any address, and hands one
// inside the overlay. The pass that read the sets back hands the rest.
func TestRoutesHoldEachLearnedLANBeforeTheFirstPass(t *testing.T) {
	table := netstack.NewRouteTable()
	rt := borderRuntime(nil)
	rt.Sets = orderSets(orderClasses, table)
	f := newBorderFilter(&egress.Border{Overlay: orderOverlay}, rt, &fakeBorder{})
	t.Cleanup(func() { _ = f.Close() })
	src := f.Routes(table)
	node := netip.MustParsePrefix("203.0.113.16/28")
	for _, destination := range []netip.Prefix{node, netip.MustParsePrefix("198.51.100.32/27"), netip.MustParsePrefix("192.0.2.128/25")} {
		orderLearn(table, destination)
	}
	got := src.Snapshot()
	if !hands(got, node, false) || slices.ContainsFunc(got, func(entry sadr.Route[*netstack.Peer]) bool {
		return entry.Destination != node && entry.Value != netstack.Unreachable
	}) {
		t.Fatalf("before any pass the source handed %v, want %s and holds alone", got, node)
	}
	orderPass(t, f, "start")
	if got := src.Snapshot(); !slices.Equal(got, table.Snapshot()) {
		t.Fatalf("after the first pass the source handed %v, want %v", got, table.Snapshot())
	}
}

// A nil filter hands the mesh's table itself
func TestRoutesOfNoFilterAreTheTable(t *testing.T) {
	table := netstack.NewRouteTable()
	var f *BorderFilter
	if src := f.Routes(table); src != meshkernel.RouteSource(table) {
		t.Fatalf("a nil filter handed %T, want the table", src)
	}
}
