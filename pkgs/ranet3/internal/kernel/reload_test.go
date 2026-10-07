// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build (linux && !android) || (darwin && !ios)

package kernel

import (
	"context"
	"errors"
	"log/slog"
	"maps"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/schema"
)

// reload hands r the capability and runs the pass the loop runs after taking it
func reload(t *testing.T, r *Reconciler, next Table, announced ...netip.Prefix) {
	t.Helper()
	if err := r.SetTable(next, announced); err != nil {
		t.Fatalf("the reload was refused: %v", err)
	}
	if !r.adopt() {
		t.Fatal("an accepted reload handed the loop nothing")
	}
	if err := r.reconcile(); err != nil {
		t.Fatalf("the pass after the reload: %v", err)
	}
}

func (f *fakeKernel) heldRules() map[Rule]bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return maps.Clone(f.rules)
}

func TestReloadMovesTheRoutesToTheNewMetric(t *testing.T) {
	r, table, fake := harness(t, Table{})
	table.Set(netip.Prefix{}, prefix("10.0.0.0/8"), nil)
	table.Set(netip.Prefix{}, prefix("3fff:a::/36"), nil)
	table.Set(prefix("3fff:a:1::/48"), prefix("::/0"), nil)
	if err := r.reconcile(); err != nil {
		t.Fatal(err)
	}
	next := Table{Metric: 32}
	reload(t, r, next)
	want := []Route{
		{Destination: prefix("10.0.0.0/8"), Metric: 32},
		{Destination: prefix("::/0"), Source: prefix("3fff:a:1::/48"), Metric: 32},
		{Destination: prefix("3fff:a::/36"), Metric: 32},
	}
	slices.SortFunc(want, compareRoutes)
	if got := fake.snapshot(); !slices.Equal(got, want) {
		t.Fatalf("the pass after the reload left %v, want %v", got, want)
	}
	// darwin mirrors the metric into every dump from the platform's own copy
	if got := fake.retabled; len(got) != 1 || !reflect.DeepEqual(got[0], next.Normalized()) {
		t.Errorf("the platform was handed %+v, want the capability the loop took", got)
	}
	if got := r.Table(); !reflect.DeepEqual(got, next.Normalized()) {
		t.Errorf("the reconciler reports %+v as its capability, want %+v", got, next.Normalized())
	}
}

// a pass over an empty rule set withdraws every rule rather than skipping the step
func TestReloadReplacesTheRulesAndWithdrawsTheLastOfThem(t *testing.T) {
	underlay := Rule{FWMark: 0x726c, Table: schema.TableMain, Priority: 40, Family: FamilyBoth}
	mesh := Rule{From: schema.MustPrefix("2001:db8::/32"), Table: 200, Priority: 150}
	moved := Rule{From: schema.MustPrefix("2001:db8::/32"), Table: 200, Priority: 160}
	r, _, fake := harness(t, Table{Rules: []Rule{underlay, mesh}})
	if err := r.reconcile(); err != nil {
		t.Fatal(err)
	}
	reload(t, r, Table{Rules: []Rule{underlay, moved}})
	want := map[Rule]bool{
		{FWMark: 0x726c, Table: schema.TableMain, Priority: 40, Family: FamilyIPv4}:               true,
		{FWMark: 0x726c, Table: schema.TableMain, Priority: 40, Family: FamilyIPv6}:               true,
		{From: schema.MustPrefix("2001:db8::/32"), Table: 200, Priority: 160, Family: FamilyIPv6}: true,
	}
	if got := fake.heldRules(); !maps.Equal(got, want) {
		t.Fatalf("the pass after the reload left the rules %v, want %v", slices.Collect(maps.Keys(got)), slices.Collect(maps.Keys(want)))
	}
	reload(t, r, Table{})
	if got := fake.heldRules(); len(got) != 0 {
		t.Errorf("a reload naming no rule left %v", slices.Collect(maps.Keys(got)))
	}
}

// the address another writer holds stays whether or not the capability names it, and so does one of ours somebody rewrote
// one of ours given another length is replaced in the one pass, rather than taken for somebody else's
// an address of ours a reload gave up is another writer's from then on, even put back as the reconciler first added it
func TestReloadRemovesOnlyTheAddressesItAdded(t *testing.T) {
	ours, renumbered := prefix("198.18.104.5/32"), prefix("198.18.104.6/32")
	theirs := prefix("192.0.2.1/32")
	rewritten, rewrittenAs := prefix("2001:db8::1/128"), prefix("2001:db8::1/64")
	short, long := prefix("198.18.104.7/32"), prefix("198.18.104.7/24")
	r, _, fake := harness(t, Table{Addresses: prefixes(ours, theirs, rewritten, short)})
	fake.addrs[theirs] = true
	if err := r.reconcile(); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	delete(fake.addrs, rewritten)
	fake.addrs[rewrittenAs] = true
	fake.mu.Unlock()

	reload(t, r, Table{Addresses: prefixes(renumbered, long)})
	want := []netip.Prefix{theirs, rewrittenAs, renumbered, long}
	slices.SortFunc(want, comparePrefixes)
	if got := fake.heldAddresses(); !slices.Equal(got, want) {
		t.Fatalf("the pass after the reload left %v on the link, want %v", got, want)
	}

	fake.mu.Lock()
	delete(fake.addrs, rewrittenAs)
	fake.addrs[ours], fake.addrs[rewritten] = true, true
	fake.mu.Unlock()
	if err := r.reconcile(); err != nil {
		t.Fatal(err)
	}
	for _, address := range []netip.Prefix{ours, rewritten} {
		if !slices.Contains(fake.heldAddresses(), address) {
			t.Errorf("a pass took %s off the link after the reconciler gave it up", address)
		}
	}

	reload(t, r, Table{})
	want = []netip.Prefix{theirs, ours, rewritten}
	slices.SortFunc(want, comparePrefixes)
	if got := fake.heldAddresses(); !slices.Equal(got, want) {
		t.Errorf("a reload naming no address left %v on the link, want %v", got, want)
	}
	for _, deleted := range fake.deleted {
		if deleted.Addr() == theirs.Addr() || deleted.Addr() == rewritten.Addr() {
			t.Errorf("the reconciler asked to delete %s, which is not its own", deleted)
		}
	}
}

// the addresses assign_announced expands cap.route into follow the announcements a reload hands over
func TestReloadAssignsWhatTheNewAnnouncementsExpandInto(t *testing.T) {
	first, second := prefix("2001:db8:1::1/64"), prefix("2001:db8:2::1/64")
	r, _, fake := harness(t, Table{AssignAnnounced: true}, Runtime{Announced: []netip.Prefix{first}})
	if err := r.reconcile(); err != nil {
		t.Fatal(err)
	}
	reload(t, r, Table{AssignAnnounced: true}, second, prefix("::/0"))
	if got := fake.heldAddresses(); !slices.Equal(got, []netip.Prefix{second}) {
		t.Errorf("the pass after the reload left %v on the link, want %s alone", got, second)
	}
}

func TestReloadSweepsAtTheNewInterval(t *testing.T) {
	bus := events.New()
	r, table, fake := harness(t, Table{Reconcile: schema.Duration(time.Hour)}, Runtime{Events: bus})
	ordinary := Route{Destination: prefix("2001:db8:5::/48"), Metric: defaultIPv6Metric}
	table.Set(netip.Prefix{}, ordinary.Destination, nil)
	last := runToRecord(t, r, table, bus)
	awaitPass(t, last, "the first pass", "start", func() bool { return fake.has(ordinary) })
	if err := r.SetTable(Table{Reconcile: schema.Duration(sweepEvery)}, nil); err != nil {
		t.Fatal(err)
	}
	// a route deleted before the reload pass reads the kernel is put back by that pass rather than by a sweep
	awaitPass(t, last, "the pass after the reload", "reload", func() bool { return true })
	fake.mu.Lock()
	delete(fake.routes, ordinary)
	fake.mu.Unlock()
	awaitPass(t, last, "the sweep to put the route back", "sweep", func() bool { return fake.has(ordinary) })
}

func TestReloadWithdrawsTheCaptureOnTheNewGrace(t *testing.T) {
	bus := events.New()
	var live atomic.Int64
	live.Store(1)
	r, table, fake := harness(t,
		Table{Reconcile: schema.Duration(time.Hour), CaptureGrace: schema.Duration(time.Hour)},
		Runtime{Events: bus, Sessions: func() int { return int(live.Load()) }})
	capture := Route{Destination: prefix("::/0"), Metric: defaultIPv6Metric}
	table.Set(netip.Prefix{}, capture.Destination, nil)
	last := runToRecord(t, r, table, bus)
	awaitPass(t, last, "the capture", "start", func() bool { return fake.has(capture) })
	shorter := Table{Reconcile: schema.Duration(time.Hour), CaptureGrace: schema.Duration(MinCaptureGrace)}
	if err := r.SetTable(shorter, nil); err != nil {
		t.Fatal(err)
	}
	awaitPass(t, last, "the pass after the reload", "reload", func() bool { return true })
	live.Store(0)
	awaitPass(t, last, "the new grace to withdraw the capture", "grace", func() bool { return !fake.has(capture) })
}

// the loop takes the second reload only once it has finished with the first, so the kernel read after it shows whether the first installed anything
func TestStoppedReconcilerTakesAReloadAndInstallsItOnlyOnceStarted(t *testing.T) {
	route := prefix("10.0.0.0/8")
	rule := Rule{FWMark: 0x726c, Table: schema.TableMain, Priority: 40, Family: FamilyIPv4}
	r, table, fake := harness(t, Table{Addresses: prefixes(prefix("198.18.104.5/32"))})
	table.Set(netip.Prefix{}, route, nil)
	<-table.Changed()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	waitFor(t, func() bool { return fake.has(Route{Destination: route}) })
	r.SetEnabled(false)
	waitFor(t, func() bool { return len(fake.snapshot()) == 0 && len(fake.heldAddresses()) == 0 })

	next := Table{Metric: 32, Addresses: prefixes(prefix("198.18.104.6/32")), Rules: []Rule{rule}}
	if err := r.SetTable(next, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return r.Table().Metric == 32 })
	later := next
	later.Reconcile = schema.Duration(time.Minute)
	if err := r.SetTable(later, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return r.Table().Reconcile.Duration() == time.Minute })
	if routes, addresses, rules := fake.snapshot(), fake.heldAddresses(), fake.heldRules(); len(routes)+len(addresses)+len(rules) != 0 {
		t.Fatalf("a stopped reconciler installed %v, %v and %v on a reload", routes, addresses, slices.Collect(maps.Keys(rules)))
	}

	r.SetEnabled(true)
	waitFor(t, func() bool {
		return fake.has(Route{Destination: route, Metric: 32}) && slices.Equal(fake.heldAddresses(), []netip.Prefix{prefix("198.18.104.6/32")}) &&
			fake.heldRules()[rule]
	})
}

// a reload is refused before anything is handed to the loop, so the capability in force, the platform and the kernel stay as they were
func TestReloadRefusesWhatTheReconcilerCannotTake(t *testing.T) {
	underlay := Rule{FWMark: 0x726c, Table: schema.TableMain, Priority: 40, Family: FamilyBoth}
	start := Table{Rules: []Rule{underlay}, Addresses: prefixes(prefix("198.18.104.5/32")), VRF: &VRF{Name: "mesh"}}
	vrf := func(table Table, to *VRF) Table { table.VRF = to; return table }
	for name, refused := range map[string]struct {
		next   Table
		naming string
	}{
		"another id":         {Table{ID: 201, VRF: start.VRF}, "cap.table id changed"},
		"another proto":      {Table{Proto: DefaultProtocol + 1, VRF: start.VRF}, "cap.table proto changed"},
		"no vrf":             {vrf(start, nil), "cap.table vrf changed"},
		"another vrf":        {vrf(start, &VRF{Name: "other"}), "cap.table vrf changed"},
		"the vrf made here":  {vrf(start, &VRF{Name: "mesh", Create: true}), "cap.table vrf changed"},
		"a reserved proto":   {Table{Proto: protocolStatic, VRF: start.VRF}, "is reserved"},
		"a negative sweep":   {Table{Reconcile: -1, VRF: start.VRF}, "not an interval"},
		"one rule twice":     {Table{Rules: []Rule{underlay, underlay}, VRF: start.VRF}, "configured twice"},
		"an address at zero": {Table{Addresses: []schema.Prefix{{}}, VRF: start.VRF}, "not a prefix"},
	} {
		t.Run(name, func(t *testing.T) {
			r, table, fake := harness(t, start)
			table.Set(netip.Prefix{}, prefix("10.0.0.0/8"), nil)
			if err := r.reconcile(); err != nil {
				t.Fatal(err)
			}
			routes, addresses, rules := fake.snapshot(), fake.heldAddresses(), fake.heldRules()
			err := r.SetTable(refused.next, nil)
			if err == nil || !strings.Contains(err.Error(), refused.naming) {
				t.Fatalf("the reload was refused with %v, want it to say %q", err, refused.naming)
			}
			if r.adopt() {
				t.Fatal("a refused reload handed the loop a capability")
			}
			if err := r.reconcile(); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(fake.snapshot(), routes) || !slices.Equal(fake.heldAddresses(), addresses) || !maps.Equal(fake.heldRules(), rules) {
				t.Error("the pass after a refused reload changed the kernel")
			}
			if got := r.Table(); !reflect.DeepEqual(got, start.Normalized()) || len(fake.retabled) != 0 {
				t.Errorf("a refused reload left the reconciler on %+v", got)
			}
		})
	}
	// a platform with no policy routing refuses a reload that asks for a rule, as New refuses one
	r := newReconciler(Table{}.Normalized(), Runtime{Interface: "utun9"}, nil, nil, netstack.NewRouteTable(), routesOnly{inner: newFakeKernel(t)})
	if err := r.SetTable(Table{Rules: []Rule{underlay}}, nil); err == nil || !strings.Contains(err.Error(), "no policy routing") {
		t.Errorf("a rule on a platform without them was refused with %v", err)
	}
	if r.adopt() {
		t.Error("a refused reload handed the loop a capability")
	}
}

// the pass a reload runs is recorded whatever it moved, so a reload that changed only a timer still shows the reconciler took it
func TestReloadPassIsRecordedAsAReload(t *testing.T) {
	bus := events.New()
	r, table, _ := harness(t, Table{}, Runtime{Events: bus})
	table.Set(netip.Prefix{}, prefix("198.51.100.0/24"), nil)
	last := runToRecord(t, r, table, bus)
	awaitPass(t, last, "the first pass", "start", func() bool { return true })
	reloadPasses := func() [][2]string {
		var out [][2]string
		for _, event := range bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "kernel.pass" }, 0) {
			if event.Attrs["trigger"] == "reload" {
				out = append(out, [2]string{event.Attrs["added"], event.Attrs["removed"]})
			}
		}
		return out
	}
	if err := r.SetTable(Table{Reconcile: schema.Duration(time.Minute)}, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return len(reloadPasses()) == 1 })
	if err := r.SetTable(Table{Reconcile: schema.Duration(time.Minute), Metric: 32}, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return len(reloadPasses()) == 2 })
	if got, want := reloadPasses(), [][2]string{{"0", "0"}, {"1", "1"}}; !slices.Equal(got, want) {
		t.Errorf("the reload passes were recorded with added and removed %v, want %v", got, want)
	}
}

// a status over the control socket reads Where while the loop takes a reload
// nothing orders those reads after the loop took the table, so a read of the table the loop writes is a race
func TestWhereIsReadWhileTheLoopTakesAReload(t *testing.T) {
	bus := events.New()
	r, table, _ := harness(t, Table{}, Runtime{Events: bus})
	table.Set(netip.Prefix{}, prefix("10.0.0.0/8"), nil)
	last := runToRecord(t, r, table, bus)
	awaitPass(t, last, "the first pass", "start", func() bool { return true })
	if err := r.SetTable(Table{Metric: 32}, nil); err != nil {
		t.Fatal(err)
	}
	awaitPass(t, last, "the pass after the reload", "reload", func() bool { return r.Where() == "table 200" })
}

// reloadsApart is how long a second reload follows the first, long enough for the loop to have taken the first
const reloadsApart = 100 * time.Millisecond

// a second reload is checked against the table the loop took from the first, and nothing between the two observes the loop
// nothing orders that read after the loop's write, so a read of the table the loop writes is a race
func TestSecondReloadReadsTheTableTheLoopTook(t *testing.T) {
	bus := events.New()
	r, table, _ := harness(t, Table{}, Runtime{Events: bus})
	table.Set(netip.Prefix{}, prefix("10.0.0.0/8"), nil)
	last := runToRecord(t, r, table, bus)
	awaitPass(t, last, "the first pass", "start", func() bool { return true })
	if err := r.SetTable(Table{Metric: 32}, nil); err != nil {
		t.Fatal(err)
	}
	time.Sleep(reloadsApart)
	if err := r.SetTable(Table{Metric: 64}, nil); err != nil {
		t.Fatal(err)
	}
	awaitPass(t, last, "the pass after the second reload", "reload", func() bool { return r.Table().Metric == 64 })
}

// insideSettle is how long after a mesh change a reload is handed over, half the settle window the change opened
const insideSettle = settleDelay / 2

// a reload handed over while the loop settles a mesh change is taken once the loop is back in its select
// the loop is not receiving then, so the wake-up has to be kept until it is
func TestReloadInsideTheSettleWindowIsTaken(t *testing.T) {
	bus := events.New()
	r, table, _ := harness(t, Table{}, Runtime{Events: bus})
	table.Set(netip.Prefix{}, prefix("10.0.0.0/8"), nil)
	last := runToRecord(t, r, table, bus)
	awaitPass(t, last, "the first pass", "start", func() bool { return true })
	table.Set(netip.Prefix{}, prefix("10.1.0.0/16"), nil)
	time.Sleep(insideSettle)
	if err := r.SetTable(Table{Metric: 32}, nil); err != nil {
		t.Fatal(err)
	}
	awaitPass(t, last, "the pass after the reload", "reload", func() bool { return r.Table().Metric == 32 })
}

// an address a reload dropped and whose delete failed stays recorded, and the later pass that takes it off is recorded
// that pass moves no route and follows no reload, so the removal alone has to record it
// the pass after it moves nothing and is not recorded, since the reload marked only the pass that followed it
func TestPassTakingOffAnAddressAReloadDroppedIsRecorded(t *testing.T) {
	bus := events.New()
	ours := prefix("198.18.104.5/32")
	r, _, fake := harness(t, Table{Addresses: prefixes(ours)}, Runtime{Events: bus})
	if err := r.reconcile(); err != nil {
		t.Fatal(err)
	}
	if err := r.SetTable(Table{}, nil); err != nil {
		t.Fatal(err)
	}
	if !r.adopt() {
		t.Fatal("an accepted reload handed the loop nothing")
	}
	fake.failDelAddr = errors.New("the link would not let the address go")
	if err := r.reconcile(); err == nil {
		t.Fatal("the pass after the reload succeeded on a link that would not let the address go")
	}
	fake.failDelAddr = nil
	passes := func() int {
		return len(bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "kernel.pass" }, 0))
	}
	before := passes()
	if err := r.reconcile(); err != nil {
		t.Fatal(err)
	}
	if got := fake.heldAddresses(); len(got) != 0 {
		t.Fatalf("the pass after the failed one left %v on the link", got)
	}
	if got := passes(); got != before+1 {
		t.Errorf("the pass that took %s off the link was not recorded, %d passes recorded before it and %d after", ours, before, got)
	}
	if err := r.reconcile(); err != nil {
		t.Fatal(err)
	}
	if got := passes(); got != before+1 {
		t.Errorf("a pass that moved nothing was recorded, %d passes recorded before the removal and %d after the pass that followed it", before, got)
	}
}
