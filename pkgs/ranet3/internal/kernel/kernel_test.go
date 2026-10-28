// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/logtest"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/schema"
)

func prefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }
func addr(s string) netip.Addr     { return netip.MustParseAddr(s) }

// prefixes is a capability's address list written from the prefixes the rest
// of a test already holds.
func prefixes(list ...netip.Prefix) []schema.Prefix {
	out := make([]schema.Prefix, 0, len(list))
	for _, prefix := range list {
		out = append(out, schema.PrefixFrom(prefix))
	}
	return out
}

// fakeKernel is an in-memory stand-in for rtnetlink. It models the ownership
// boundary the real platform enforces rather than the wire format: foreign
// holds routes written by somebody else, Routes never returns them, and a
// delete that reaches one fails the test.
type fakeKernel struct {
	t *testing.T

	mu      sync.Mutex
	routes  map[Route]bool
	foreign map[Route]bool
	addrs   map[netip.Prefix]bool
	deleted []netip.Prefix
	name    string
	closed  bool
	adds    int
	dels    int

	rules    map[Rule]bool
	ruleAdds int
	ruleDels int
	// ruleAdded is every rule added, in the order it was
	ruleAdded []Rule

	failAdd     map[Route]error
	failDel     map[Route]error
	failList    error
	failAddrs   error
	failDelAddr error
	failRules   error
	failAddRule map[Rule]error
	failAssign  map[netip.Prefix]error

	signal chan struct{}
	// addressNotes signals on each change of the link's addresses, the reconciler's own and another writer's, as linux's address groups do
	// listed counts the reads of the link's addresses, one a pass in mode 2
	addressNotes bool
	listed       int
	// retabled is every capability the reconciler handed over after a reload
	retabled []Table
	// byLength keys an IPv4 address by its length as well, as linux does
	// emptied is set by a delete that takes the last IPv4 address off the link
	byLength bool
	emptied  bool

	// fallback is the table ranet3_fallback the fake holds, nil for none.
	// spoiled is a fault every read reports, as another writer's change no
	// rewrite outlasts, and failFallback fails every write, read and delete.
	fallback        *fallbackSets
	fallbackWrites  int
	fallbackDeletes int
	spoiled         string
	failFallback    error
	// fallbackDropped is the packets the table's last line has dropped, each of 60 bytes
	fallbackDropped uint64
}

func (f *fakeKernel) writeFallback(s fallbackSets) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failFallback != nil {
		return f.failFallback
	}
	f.fallback = &s
	f.fallbackWrites++
	return nil
}

func (f *fakeKernel) readFallback(s fallbackSets) (fallbackRead, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case f.failFallback != nil:
		return fallbackRead{}, f.failFallback
	case f.fallback == nil:
		return fallbackRead{fault: "the table is missing"}, nil
	case f.spoiled != "":
		return fallbackRead{fault: f.spoiled, dropped: f.fallbackDropped}, nil
	case !reflect.DeepEqual(*f.fallback, s):
		return fallbackRead{fault: "it holds other sets", dropped: f.fallbackDropped}, nil
	}
	return fallbackRead{dropped: f.fallbackDropped, bytes: 60 * f.fallbackDropped}, nil
}

func (f *fakeKernel) deleteFallback() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failFallback != nil {
		return f.failFallback
	}
	f.fallback = nil
	f.fallbackDeletes++
	return nil
}

func newFakeKernel(t *testing.T) *fakeKernel {
	return &fakeKernel{
		t:           t,
		routes:      make(map[Route]bool),
		foreign:     make(map[Route]bool),
		addrs:       make(map[netip.Prefix]bool),
		rules:       make(map[Rule]bool),
		failAdd:     make(map[Route]error),
		failDel:     make(map[Route]error),
		failAddRule: make(map[Rule]error),
		failAssign:  make(map[netip.Prefix]error),
		signal:      make(chan struct{}, 1),
	}
}

// noteAddresses signals Notify where addressNotes is set, called with mu held
func (f *fakeKernel) noteAddresses() {
	if !f.addressNotes {
		return
	}
	select {
	case f.signal <- struct{}{}:
	default:
	}
}

// byHand adds address to the link, or takes it off, as another writer would
func (f *fakeKernel) byHand(address netip.Prefix, add bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if add {
		f.addrs[address] = true
	} else {
		delete(f.addrs, address)
	}
	f.noteAddresses()
}

func (f *fakeKernel) Routes() ([]Route, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failList != nil {
		return nil, f.failList
	}
	out := make([]Route, 0, len(f.routes))
	for route := range f.routes {
		out = append(out, route)
	}
	slices.SortFunc(out, compareRoutes)
	return out, nil
}

func (f *fakeKernel) AddRoute(route Route) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.failAdd[route]; err != nil {
		return err
	}
	f.adds++
	f.routes[route] = true
	return nil
}

func (f *fakeKernel) DelRoute(route Route) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.foreign[route] {
		f.t.Errorf("reconciler deleted a route it did not install: %s", route)
	}
	if err := f.failDel[route]; err != nil {
		return err
	}
	f.dels++
	delete(f.routes, route)
	return nil
}

func (f *fakeKernel) Addrs() ([]netip.Prefix, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listed++
	if f.failAddrs != nil {
		return nil, f.failAddrs
	}
	out := make([]netip.Prefix, 0, len(f.addrs))
	for address := range f.addrs {
		out = append(out, address)
	}
	slices.SortFunc(out, comparePrefixes)
	return out, nil
}

// AddAddr and DelAddr model what both platforms do rather than what a map
// does: assignment is an upsert keyed on the address, and darwin's SIOCDIFADDR
// matches on the address alone, so a delete takes whatever length the link is
// carrying it under. The ownership checks exist for that asymmetry.
func (f *fakeKernel) AddAddr(address netip.Prefix) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.failAssign[address]; err != nil {
		return err
	}
	for held := range f.addrs {
		if held.Addr() == address.Addr() && !f.keysByLength(held.Addr()) {
			delete(f.addrs, held)
		}
	}
	f.addrs[address] = true
	f.noteAddresses()
	return nil
}

func (f *fakeKernel) DelAddr(address netip.Prefix) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	// Recorded as asked, not as matched: the address-only match models what
	// the kernels do and would otherwise hide a withdrawal that named the
	// wrong prefix length, which linux does refuse.
	f.deleted = append(f.deleted, address)
	if f.failDelAddr != nil {
		return f.failDelAddr
	}
	holdsIPv4 := func() bool {
		for held := range f.addrs {
			if held.Addr().Is4() {
				return true
			}
		}
		return false
	}
	had := holdsIPv4()
	for held := range f.addrs {
		if held == address || held.Addr() == address.Addr() && !f.keysByLength(held.Addr()) {
			delete(f.addrs, held)
		}
	}
	if had && !holdsIPv4() {
		f.emptied = true
	}
	f.noteAddresses()
	return nil
}

// keysByLength reads byLength without the lock, which is set before the reconciler runs
func (f *fakeKernel) keysByLength(address netip.Addr) bool { return f.byLength && address.Is4() }

func (f *fakeKernel) Notify() <-chan struct{} { return f.signal }

func (f *fakeKernel) retable(t Table) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.retabled = append(f.retabled, t)
}

func (f *fakeKernel) where(t Table) string {
	if f.name != "" {
		return f.name
	}
	return fmt.Sprintf("table %d", uint32(t.ID))
}

func (f *fakeKernel) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func (f *fakeKernel) has(route Route) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.routes[route]
}

func (f *fakeKernel) snapshot() []Route {
	routes, _ := f.Routes()
	return routes
}

func (f *fakeKernel) heldAddresses() []netip.Prefix {
	addresses, _ := f.Addrs()
	return addresses
}

func (f *fakeKernel) counts() (adds, dels int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.adds, f.dels
}

// harness wires one reconciler onto a real netstack.RouteTable, so the tests
// exercise the same Changed and Snapshot seam the daemon uses. The peer value
// is nil throughout: it tells the reconciler a route exists and nothing else.
func harness(t *testing.T, tbl Table, runtime ...Runtime) (*Reconciler, *netstack.RouteTable, *fakeKernel) {
	t.Helper()
	rt := Runtime{Interface: "ranet0"}
	if len(runtime) == 1 {
		rt = runtime[0]
		if rt.Interface == "" {
			rt.Interface = "ranet0"
		}
	}
	tbl = tbl.Normalized()
	table := netstack.NewRouteTable()
	fake := newFakeKernel(t)
	return newReconciler(tbl, rt, tbl.Assigned(rt.Announced), table, fake), table, fake
}

// platformFor is the pair newPlatform takes, for a test that varies only the
// device it is opened on.
func platformFor(device string) (Table, Runtime) {
	return Table{ID: DefaultTable, Proto: DefaultProtocol}, Runtime{Interface: device}
}

// assign_announced puts what cap.route announces on the device as well, and a
// prefix announced twice, or announced and written out, is one address. An
// exit announces a default from its transit prefix, and a default is announced
// and never assigned: AddAddr would be called with "::/0" on every pass and
// fail on every one.
func TestAssignedAddressesExpandWhatIsAnnounced(t *testing.T) {
	explicit := prefix("192.0.2.7/24")
	announced := []netip.Prefix{explicit, prefix("2001:db8:1::7/64"), prefix("::/0"), prefix("0.0.0.0/0")}
	for _, test := range []struct {
		name  string
		which bool
		want  []netip.Prefix
	}{
		{
			name:  "every announced prefix but a default",
			which: true,
			want:  []netip.Prefix{explicit, prefix("2001:db8:1::7/64")},
		},
		{
			name: "only the written addresses while assignment is off",
			want: []netip.Prefix{explicit},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			table := Table{
				Addresses:       prefixes(explicit, explicit),
				AssignAnnounced: test.which,
			}
			if got := table.Assigned(announced); !slices.Equal(got, test.want) {
				t.Fatalf("assigned addresses = %v, want %v", got, test.want)
			}
		})
	}
}

func TestReconcileInstallsSnapshotRoutes(t *testing.T) {
	reconciler, table, fake := harness(t, Table{})
	table.Set(netip.Prefix{}, prefix("10.0.0.0/8"), nil)
	table.Set(netip.Prefix{}, prefix("3fff:a::/36"), nil)
	table.Set(prefix("3fff:a:1::/48"), prefix("::/0"), nil)

	if err := reconciler.reconcile(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	// an unset metric is the kernel's own default, which is 0 for IPv4 and
	// IP6_RT_PRIO_USER for IPv6.
	want := []Route{
		{Destination: prefix("10.0.0.0/8")},
		{Destination: prefix("::/0"), Source: prefix("3fff:a:1::/48"), Metric: defaultIPv6Metric},
		{Destination: prefix("3fff:a::/36"), Metric: defaultIPv6Metric},
	}
	slices.SortFunc(want, compareRoutes)
	if got := fake.snapshot(); !slices.Equal(got, want) {
		t.Fatalf("installed %v, want %v", got, want)
	}
}

func TestReconcileRemovesWithdrawnRoutes(t *testing.T) {
	reconciler, table, fake := harness(t, Table{})
	table.Set(netip.Prefix{}, prefix("10.0.0.0/8"), nil)
	table.Set(netip.Prefix{}, prefix("10.1.0.0/16"), nil)
	if err := reconciler.reconcile(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	table.Remove(netip.Prefix{}, prefix("10.1.0.0/16"))
	if err := reconciler.reconcile(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if fake.has(Route{Destination: prefix("10.1.0.0/16")}) {
		t.Fatal("withdrawn route is still in the kernel")
	}
	if !fake.has(Route{Destination: prefix("10.0.0.0/8")}) {
		t.Fatal("surviving route was removed")
	}
}

func TestReconcileLeavesUnchangedRoutesAlone(t *testing.T) {
	reconciler, table, fake := harness(t, Table{})
	table.Set(netip.Prefix{}, prefix("10.0.0.0/8"), nil)
	table.Set(prefix("3fff:a:1::/48"), prefix("::/0"), nil)
	if err := reconciler.reconcile(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	adds, dels := fake.counts()
	if adds != 2 || dels != 0 {
		t.Fatalf("first pass made %d adds and %d deletes, want 2 and 0", adds, dels)
	}

	for range 3 {
		if err := reconciler.reconcile(); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
	}
	if adds, dels := fake.counts(); adds != 2 || dels != 0 {
		t.Fatalf("idle passes made %d adds and %d deletes, want 2 and 0", adds, dels)
	}
}

// A source-specific route and an ordinary route to the same destination are
// two kernel routes, not one, which is the distinction RTA_SRC carries.
func TestReconcileKeepsSourceSpecificAndOrdinaryApart(t *testing.T) {
	reconciler, table, fake := harness(t, Table{})
	table.Set(netip.Prefix{}, prefix("3fff:a::/36"), nil)
	table.Set(prefix("3fff:a:1::/48"), prefix("3fff:a::/36"), nil)
	if err := reconciler.reconcile(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if got := len(fake.snapshot()); got != 2 {
		t.Fatalf("installed %d routes, want 2", got)
	}

	// retracting only the source-specific entry must leave the ordinary one.
	table.Remove(prefix("3fff:a:1::/48"), prefix("3fff:a::/36"))
	if err := reconciler.reconcile(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	want := []Route{{Destination: prefix("3fff:a::/36"), Metric: defaultIPv6Metric}}
	if got := fake.snapshot(); !slices.Equal(got, want) {
		t.Fatalf("installed %v, want %v", got, want)
	}
}

// The metric is part of a route's identity in the kernel, so changing it has
// to withdraw the routes installed under the old one instead of leaving a
// second copy of every prefix behind.
func TestReconcileReplacesRoutesWhenMetricChanges(t *testing.T) {
	reconciler, table, fake := harness(t, Table{})
	table.Set(netip.Prefix{}, prefix("10.0.0.0/8"), nil)
	if err := reconciler.reconcile(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	reconciler.table.Metric = 32
	if err := reconciler.reconcile(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	want := []Route{{Destination: prefix("10.0.0.0/8"), Metric: 32}}
	if got := fake.snapshot(); !slices.Equal(got, want) {
		t.Fatalf("installed %v, want %v", got, want)
	}
}

// The IPv4 FIB has no source-specific lookup, so such an entry is reported
// and dropped rather than installed as an ordinary route that would steal
// every other source's traffic.
func TestReconcileSkipsSourceSpecificIPv4(t *testing.T) {
	reconciler, table, fake := harness(t, Table{})
	table.Set(prefix("10.1.0.0/16"), prefix("10.0.0.0/8"), nil)
	table.Set(netip.Prefix{}, prefix("192.0.2.0/24"), nil)
	if err := reconciler.reconcile(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	want := []Route{{Destination: prefix("192.0.2.0/24")}}
	if got := fake.snapshot(); !slices.Equal(got, want) {
		t.Fatalf("installed %v, want %v", got, want)
	}
}

// Ownership: a route the reconciler did not install never appears in a dump
// and must never be deleted, even when the mesh does not want its prefix.
func TestReconcileNeverTouchesForeignRoutes(t *testing.T) {
	reconciler, table, fake := harness(t, Table{})
	foreign := Route{Destination: prefix("198.51.100.0/24")}
	fake.foreign[foreign] = true
	table.Set(netip.Prefix{}, prefix("10.0.0.0/8"), nil)

	if err := reconciler.reconcile(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if err := reconciler.withdraw(); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if _, dels := fake.counts(); dels != 1 {
		t.Fatalf("made %d deletes, want 1", dels)
	}
}

// A pass that fails halfway leaves the kernel short of a route. The next pass
// recomputes the difference from a fresh dump and installs it.
func TestReconcileRepairsAfterFailedApply(t *testing.T) {
	reconciler, table, fake := harness(t, Table{})
	broken := Route{Destination: prefix("10.1.0.0/16")}
	fake.failAdd[broken] = errors.New("netlink says no")
	table.Set(netip.Prefix{}, prefix("10.0.0.0/8"), nil)
	table.Set(netip.Prefix{}, prefix("10.1.0.0/16"), nil)

	err := reconciler.reconcile()
	if err == nil {
		t.Fatal("a failed apply must be reported, not swallowed")
	}
	if !fake.has(Route{Destination: prefix("10.0.0.0/8")}) {
		t.Fatal("a failed route must not stop the rest of the pass")
	}
	if fake.has(broken) {
		t.Fatal("the failed route was installed anyway")
	}

	delete(fake.failAdd, broken)
	if err := reconciler.reconcile(); err != nil {
		t.Fatalf("repairing reconcile: %v", err)
	}
	if !fake.has(broken) {
		t.Fatal("the repairing pass did not install the missing route")
	}
}

func captureKernelLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var logs bytes.Buffer
	logtest.SetDefault(t, slog.New(slog.NewJSONHandler(&logs, nil)))
	return &logs
}

// auditingKernel is the fake with a startup census
// it names the writers each case sets
type auditingKernel struct {
	*fakeKernel
	writers []string
}

func (a *auditingKernel) foreignWriters() ([]string, error) { return a.writers, nil }

// logRecord is the one record carrying msg among the logs captureKernelLogs collected, and nil when there is none
func logRecord(t *testing.T, logs *bytes.Buffer, msg string) map[string]any {
	t.Helper()
	var found map[string]any
	for line := range strings.Lines(logs.String()) {
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("a log line is not a json record: %q", line)
		}
		if record["msg"] != msg {
			continue
		}
		if found != nil {
			t.Fatalf("%q was logged twice: %q", msg, logs.String())
		}
		found = record
	}
	return found
}

// the census says what sharing a table costs and names the writers it found
func TestCensusNamesTheWritersAndTheFix(t *testing.T) {
	reconciler, _, fake := harness(t, Table{})
	reconciler.plat = &auditingKernel{fakeKernel: fake, writers: []string{"bird (12)"}}
	logs := captureKernelLogs(t)
	reconciler.audit()
	record := logRecord(t, logs, "kernel is sharing its table with another routing protocol")
	if record == nil {
		t.Fatalf("the census said nothing about bird: %q", logs.String())
	}
	if record["protocols"] != "bird (12)" {
		t.Errorf("the census names %v, want bird (12)", record["protocols"])
	}
	if want := "give this reconciler a table of its own"; record["fix"] != want {
		t.Errorf("the fix reads %q, want %q", record["fix"], want)
	}
	if detail, _ := record["detail"].(string); strings.Contains(detail, "a table of its own") {
		t.Errorf("the detail reads %q, which gives advice beside the fix", detail)
	}
}

func TestRunTakesTheCensus(t *testing.T) {
	reconciler, table, fake := harness(t, Table{})
	reconciler.plat = &auditingKernel{fakeKernel: fake, writers: []string{"bird (12)"}}
	route := Route{Destination: prefix("10.0.0.0/8")}
	table.Set(netip.Prefix{}, route.Destination, nil)
	logs := captureKernelLogs(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- reconciler.Run(ctx) }()
	waitFor(t, func() bool { return fake.has(route) })
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := logs.String(); !strings.Contains(got, "sharing its table") {
		t.Fatalf("a run over a table bird writes into said nothing about it: %q", got)
	}
}

func TestReconcileCountsOnlyAppliedRoutes(t *testing.T) {
	logs := captureKernelLogs(t)
	reconciler, table, fake := harness(t, Table{})
	installed := Route{Destination: prefix("198.51.100.0/24")}
	occupied := Route{Destination: prefix("203.0.113.0/24")}
	removed := Route{Destination: prefix("192.0.2.0/25")}
	retained := Route{Destination: prefix("192.0.2.128/25")}
	fake.routes[removed], fake.routes[retained] = true, true
	fake.failAdd[occupied] = syscall.EEXIST
	fake.failDel[retained] = syscall.EPERM
	table.Set(netip.Prefix{}, installed.Destination, nil)
	table.Set(netip.Prefix{}, occupied.Destination, nil)
	// the derived rules are in place, so the one line a pass logs is the route count
	for _, rule := range derivedRules(reconciler.table.ID, nil, nil, exitView{}) {
		fake.rules[rule] = true
	}
	for pass := range 2 {
		logs.Reset()
		err := reconciler.reconcile()
		if pass == 0 && (!errors.Is(err, syscall.EEXIST) || !errors.Is(err, syscall.EPERM)) {
			t.Fatalf("reconcile returned %v, want both refused operations", err)
		}
		if pass == 1 && err != nil {
			t.Fatal(err)
		}
		var counts struct {
			Added   int
			Removed int
		}
		if err := json.Unmarshal(logs.Bytes(), &counts); err != nil {
			t.Fatal(err)
		}
		if counts.Added != 1 || counts.Removed != 1 {
			t.Errorf("pass %d reported added=%d removed=%d, want added=1 removed=1", pass, counts.Added, counts.Removed)
		}
		want := []Route{installed, retained}
		if pass == 1 {
			want = []Route{installed, occupied}
		}
		slices.SortFunc(want, compareRoutes)
		if got := fake.snapshot(); !slices.Equal(got, want) {
			t.Fatalf("pass %d holds %v, want %v", pass, got, want)
		}
		delete(fake.failAdd, occupied)
		delete(fake.failDel, retained)
	}
}

// A route the platform refuses stays in the diff on purpose, because the
// install is retried until it lands. It must not be counted as added, and a
// pass that moved nothing must say nothing: a node holding one permanently
// unrepresentable route would otherwise log once per pass for its whole life.
func TestReconcileSaysNothingAboutPassThatMovedNothing(t *testing.T) {
	logs := captureKernelLogs(t)
	reconciler, table, fake := harness(t, Table{})
	skipped := Route{Destination: prefix("::/0"), Source: prefix("2001:db8::/48"), Metric: defaultIPv6Metric}
	fake.failAdd[skipped] = errRouteSkipped
	table.Set(skipped.Source, skipped.Destination, nil)
	for pass := range 3 {
		if err := reconciler.reconcile(); err != nil {
			t.Fatalf("pass %d: an unrepresentable route triggered retry: %v", pass, err)
		}
	}
	if bytes.Contains(logs.Bytes(), []byte("kernel routes reconciled")) {
		t.Errorf("a pass that installed nothing reported itself: %s", logs.Bytes())
	}

	// The line is still there for a pass that does move something.
	logs.Reset()
	table.Set(netip.Prefix{}, prefix("198.51.100.0/24"), nil)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	var counts map[string]any
	if err := json.Unmarshal(logs.Bytes(), &counts); err != nil {
		t.Fatal(err)
	}
	if counts["added"] != float64(1) {
		t.Errorf("the installed route was counted as %v, want one", counts["added"])
	}
}

// A dump that fails must not be read as an empty kernel, which would delete
// nothing but would also install every route a second time.
func TestReconcileReportsFailedDump(t *testing.T) {
	reconciler, table, fake := harness(t, Table{})
	table.Set(netip.Prefix{}, prefix("10.0.0.0/8"), nil)
	fake.failList = errors.New("netlink says no")
	if err := reconciler.reconcile(); err == nil {
		t.Fatal("a failed dump must be reported")
	}
	if adds, _ := fake.counts(); adds != 0 {
		t.Fatalf("made %d adds after a failed dump, want 0", adds)
	}
}

func TestApplyAddressesOnlyRemovesWhatItAdded(t *testing.T) {
	operator := prefix("192.0.2.1/32")
	ours := prefix("203.0.113.5/32")
	reconciler, _, fake := harness(t, Table{Addresses: prefixes(operator, ours)})
	fake.addrs[operator] = true

	if err := reconciler.reconcile(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if !fake.addrs[ours] {
		t.Fatal("configured address was not assigned")
	}
	if err := reconciler.withdraw(); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if fake.addrs[ours] {
		t.Fatal("the reconciler's own address survived withdrawal")
	}
	if !fake.addrs[operator] {
		t.Fatal("an address the reconciler did not add was removed")
	}
	// Named exactly as it was assigned. Both kernels match a delete on the
	// address, so naming another length would take the same entry away and
	// nothing here would notice, and linux refuses one, which is a withdrawal that
	// silently leaves the address behind.
	if !slices.Equal(fake.deleted, []netip.Prefix{ours}) {
		t.Errorf("withdrawal asked to delete %v, want only %s", fake.deleted, ours)
	}
}

func TestRunWithdrawsOnCancel(t *testing.T) {
	reconciler, table, fake := harness(t, Table{
		Addresses: prefixes(prefix("203.0.113.5/32")),
		Reconcile: schema.Duration(10 * time.Millisecond),
	})
	table.Set(netip.Prefix{}, prefix("10.0.0.0/8"), nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- reconciler.Run(ctx) }()

	waitFor(t, func() bool { return fake.has(Route{Destination: prefix("10.0.0.0/8")}) })
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(waitBudget):
		t.Fatal("run did not return after cancellation")
	}

	if got := fake.snapshot(); len(got) != 0 {
		t.Fatalf("routes survived shutdown: %v", got)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.addrs) != 0 {
		t.Fatalf("addresses survived shutdown: %v", fake.addrs)
	}
	if !fake.closed {
		t.Fatal("the platform was not closed")
	}
}

// A rule pass deletes every rule carrying this reconciler's protocol that it
// does not derive and could have written, so claiming RTPROT_STATIC would
// delete every such static rule on the host, since systemd-networkd stamps it
// on its own.
func TestNewRejectsReservedProtocol(t *testing.T) {
	for _, protocol := range []uint8{2, protocolStatic} {
		_, err := New(Table{Proto: protocol}, Runtime{Interface: "ranet0"}, netstack.NewRouteTable())
		if err == nil || !strings.Contains(err.Error(), "is reserved") {
			t.Errorf("protocol %d was refused with %v, want it named as reserved", protocol, err)
		}
	}
}

// A prefix that is set and is not one, an entry left at zero or an address
// under a length it cannot carry, has no spelling in any file, so a capability
// built with one is refused here rather than taken and rendered into a file
// that does not load. Assigned skipped such an address without a word.
func TestValidateRefusesAPrefixThatIsNotOne(t *testing.T) {
	notOne := schema.PrefixFrom(netip.PrefixFrom(addr("2001:db8::"), 200))
	for name, table := range map[string]Table{
		"an address left at zero":                   {Addresses: []schema.Prefix{schema.MustPrefix("10.66.0.5/32"), {}}},
		"an address under a length it cannot carry": {Addresses: []schema.Prefix{notOne}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := table.Validate(); err == nil || !strings.Contains(err.Error(), "not a prefix") {
				t.Errorf("refused with %v, want it refused as not a prefix", err)
			}
		})
	}
}

// An announced default is installed unscoped on linux, so a reconciler given
// the main table would put the whole machine's default out of the tun and take
// the ESP underlay with it. Nothing else refuses a route in main, and the one
// warning that would have said so is off outside it.
func TestNewRejectsReservedTable(t *testing.T) {
	// On the reason, not on failure: New never succeeds here, because there is
	// no such interface on the machine running the suite.
	for _, table := range []uint32{253, 254, 255} {
		_, err := New(Table{ID: schema.TableID(table)}, Runtime{Interface: "ranet0"}, netstack.NewRouteTable())
		if err == nil || !strings.Contains(err.Error(), "is reserved") {
			t.Errorf("table %d was refused with %v, and the kernel keeps it for itself", table, err)
		}
	}
	// A table the kernel does not reserve goes through, and the reservation is
	// three byte-sized ids rather than everything above 252:
	// the linux backend sends RT_TABLE_UNSPEC plus a 32-bit RTA_TABLE for a
	// table above 255, which is how ids like 51820 reach the kernel at all.
	// New still fails here, because there is no such interface on the machine
	// running the suite, so the check is on the reason rather than on success.
	for _, table := range []uint32{1, 52, 200, 252, 256, 1000, 51820, ^uint32(0)} {
		_, err := New(Table{ID: schema.TableID(table)}, Runtime{Interface: "ranet0"}, netstack.NewRouteTable())
		if err != nil && strings.Contains(err.Error(), "is reserved") {
			t.Errorf("table %d was refused as reserved: %v", table, err)
		}
	}
}

// Both lists come out sorted, so one pass produces the same order as the next
// and a log line or a diff of two passes is comparable. A one-element list is
// sorted whatever the code does, so this needs several on each side.
func TestDiffRoutesIsSorted(t *testing.T) {
	desired := []Route{
		{Destination: prefix("10.1.0.0/16")},
		{Destination: prefix("10.0.0.0/8")},
		{Destination: prefix("2001:db8:1::/48")},
		{Destination: prefix("2001:db8::/48")},
		{Destination: prefix("10.2.0.0/16")},
	}
	actual := []Route{
		{Destination: prefix("10.1.0.0/16")},
		{Destination: prefix("192.0.2.0/24")},
		{Destination: prefix("203.0.113.0/24")},
		{Destination: prefix("2001:db8:99::/48")},
		{Destination: prefix("198.51.100.0/24")},
	}
	add, del := diffRoutes(desired, actual, nil)
	if len(add) < 2 || len(del) < 2 {
		t.Fatalf("add %v and del %v are too short to be a test of ordering", add, del)
	}
	if !slices.IsSortedFunc(add, compareRoutes) {
		t.Errorf("the routes to install came out unsorted: %v", add)
	}
	if !slices.IsSortedFunc(del, compareRoutes) {
		t.Errorf("the routes to withdraw came out unsorted: %v", del)
	}
	// And the sets themselves are still right.
	want := []Route{
		{Destination: prefix("10.0.0.0/8")}, {Destination: prefix("10.2.0.0/16")},
		{Destination: prefix("2001:db8::/48")}, {Destination: prefix("2001:db8:1::/48")},
	}
	slices.SortFunc(want, compareRoutes)
	if !slices.Equal(add, want) {
		t.Errorf("add is %v, want %v", add, want)
	}
}

// waitBudget is how long a test waits for the reconcile goroutine, generous for a loaded machine
// it stays well short of DefaultReconcileInterval
// a wait the default sweep alone would end then tells a broken interval from a slow machine
// waitPoll is how often it looks
const (
	waitBudget = 5 * time.Second
	waitPoll   = time.Millisecond
)

func waitFor(t testing.TB, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(waitBudget)
	for time.Now().Before(deadline) {
		if done() {
			return
		}
		time.Sleep(waitPoll)
	}
	t.Fatal("condition was not reached in time")
}

// A route the platform refuses is neither installed nor a failure. Counting it
// as added makes the reconcile line report the opposite of what the kernel
// holds, for as long as the other writer keeps the key, and the route stays in
// the diff so the count repeats every pass.
func TestSkippedRoutesAreNotCountedAndDoNotFailPass(t *testing.T) {
	r, table, kernel := harness(t, Table{})
	occupied := prefix("2001:db8::/48")
	table.Set(netip.Prefix{}, occupied, nil)
	table.Set(netip.Prefix{}, prefix("2001:db8:1::/48"), nil)
	for _, route := range r.desired(table.Snapshot()) {
		if route.Destination == occupied {
			kernel.failAdd[route] = fmt.Errorf("another writer holds it: %w", errRouteSkipped)
		}
	}
	if len(kernel.failAdd) != 1 {
		t.Fatalf("the occupied route was not among the desired ones: %v", r.desired(table.Snapshot()))
	}

	if err := r.applyRoutes(r.src.Snapshot()); err != nil {
		t.Fatalf("a refused route failed the whole pass: %v", err)
	}
	if kernel.adds != 1 {
		t.Fatalf("the kernel took %d routes, want 1", kernel.adds)
	}
	// Still wanted, so the next pass tries again rather than forgetting it.
	if err := r.applyRoutes(r.src.Snapshot()); err != nil {
		t.Fatalf("second pass: %v", err)
	}
	if kernel.adds != 1 {
		t.Fatalf("the kernel took %d routes across two passes, want 1", kernel.adds)
	}
}

// RFC 8966 section 3.5.4 holds a retracted prefix until it is flushed, so a
// packet for it does not follow a shorter prefix instead. The mesh's own table
// does that. The kernel table this mirrors into has to as well, or longest
// prefix match falls through to the covering route for the whole window, which
// on a node holding a default is straight back out to the neighbor that just
// retracted it.
func TestRetractedPrefixIsHeldInKernelTable(t *testing.T) {
	r, table, kernel := harness(t, Table{})
	peer := &netstack.Peer{ID: "peer"}
	covering := prefix("2001:db8::/32")
	retracted := prefix("2001:db8:1::/48")
	table.Set(netip.Prefix{}, covering, peer)
	table.Set(netip.Prefix{}, retracted, peer)
	if err := r.applyRoutes(r.src.Snapshot()); err != nil {
		t.Fatal(err)
	}

	table.Set(netip.Prefix{}, retracted, netstack.Unreachable)
	if err := r.applyRoutes(r.src.Snapshot()); err != nil {
		t.Fatal(err)
	}
	routes, err := kernel.Routes()
	if err != nil {
		t.Fatal(err)
	}
	var held, carried bool
	var heldAt, carriedAt uint32
	for _, route := range routes {
		switch route.Destination {
		case retracted:
			held, carried = route.Unreachable, !route.Unreachable
			heldAt = route.Metric
		case covering:
			carriedAt = route.Metric
		}
	}
	if carried {
		t.Error("the retracted prefix is still a unicast route, so the mesh and the kernel disagree")
	}
	if !held {
		t.Errorf("the retracted prefix left the kernel table, so a packet for it follows %s instead", covering)
	}
	// A lookup is longest prefix first and only then by metric, so the hold
	// keeps its job while losing to anything else holding that exact prefix.
	// A converted fleet node has one: its mesh /60 is a connected route in
	// the table this reconciler owns, and the node has to originate that same
	// /60, so a hold that wins there rejects every packet for the node's own
	// prefix.
	if heldAt <= carriedAt {
		t.Errorf("the hold sits at metric %d against %d for a carried route, so it outranks a connected route to the same prefix",
			heldAt, carriedAt)
	}

	// And it goes when the hold is flushed, rather than staying an error route
	// nothing announces.
	table.Remove(netip.Prefix{}, retracted)
	if err := r.applyRoutes(r.src.Snapshot()); err != nil {
		t.Fatal(err)
	}
	routes, err = kernel.Routes()
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range routes {
		if route.Destination == retracted {
			t.Errorf("the hold outlived the entry it was holding: %v", route)
		}
	}
}

// This node's own entry inside the overlay goes into the kernel exactly as a
// hold does, and outside it, on a platform with the policy rules, as a throw at
// the hold's metric, whatever its key: a prefix, a host route, a
// source-specific route, and an IPv4 prefix and host route. The overlay's own
// holds are taken out, so each pass compares the
// entries alone.
func TestLocalIsInstalledAsTheHoldInsideTheOverlayAndAsAThrowOutside(t *testing.T) {
	keys := []struct{ source, destination netip.Prefix }{
		{netip.Prefix{}, prefix("2001:db8:1::/48")},
		{netip.Prefix{}, prefix("2001:db8:2::1/128")},
		{prefix("2001:db8:a::/48"), prefix("2001:db8:3::/48")},
		{netip.Prefix{}, prefix("192.0.2.0/24")},
		{netip.Prefix{}, prefix("198.51.100.7/32")},
	}
	overlay := []schema.Prefix{schema.MustPrefix("2001:db8::/32"), schema.MustPrefix("192.0.0.0/8"), schema.MustPrefix("198.51.100.0/24")}
	installed := func(value *netstack.Peer, overlay []schema.Prefix) []Route {
		r, table, kernel := harness(t, Table{}, Runtime{Overlay: overlay})
		for _, key := range keys {
			table.Set(key.source, key.destination, value)
		}
		if err := r.applyRoutes(r.src.Snapshot()); err != nil {
			t.Fatal(err)
		}
		return slices.DeleteFunc(kernel.snapshot(), func(route Route) bool {
			return slices.ContainsFunc(overlay, func(entry schema.Prefix) bool { return route.Destination == entry.Prefix })
		})
	}
	held, local := installed(netstack.Unreachable, overlay), installed(netstack.Local, overlay)
	if len(held) != len(keys) {
		t.Fatalf("the holds installed as %v, want one route for each of %d keys", held, len(keys))
	}
	for _, route := range held {
		if !route.Unreachable || route.Metric != holdMetric {
			t.Fatalf("a hold installed as %v", route)
		}
	}
	if !slices.Equal(local, held) {
		t.Errorf("this node's own entries inside the overlay installed as %v, want what the holds installed, %v", local, held)
	}
	outside := installed(netstack.Local, nil)
	if len(outside) != len(keys) {
		t.Fatalf("this node's own entries outside the overlay installed as %v, want one route for each of %d keys", outside, len(keys))
	}
	for _, route := range outside {
		if !route.Throw || route.Unreachable || route.Metric != holdMetric {
			t.Errorf("this node's own entry outside the overlay installed as %v, want a throw at the hold's metric", route)
		}
	}
}

// An address cap.table assigns and this node does not originate gets no route
// of the reconciler's in either family, and is neither wanted nor skipped,
// while a prefix this node originates beside it, outside the overlay and
// counting as no default, goes in as the throw on a platform with the policy
// rules.
func TestAssignedAddressIsLeftOutOfTheKernel(t *testing.T) {
	reconciler, table, fake := harness(t, Table{})
	table.Set(netip.Prefix{}, prefix("2001:db8:2::1/128"), netstack.Assigned)
	table.Set(netip.Prefix{}, prefix("198.51.100.7/32"), netstack.Assigned)
	table.Set(netip.Prefix{}, prefix("2001:db8:1::/48"), netstack.Local)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if got := fake.snapshot(); len(got) != 1 || got[0].Destination != prefix("2001:db8:1::/48") || !got[0].Throw {
		t.Errorf("the kernel holds %v, want only the throw for 2001:db8:1::/48", got)
	}
	if stats := reconciler.Stats(); stats.Desired != 1 || stats.Skipped != 0 {
		t.Errorf("the pass reports %+v, want one route desired and none skipped", stats)
	}
}

// The startup line tells an operator where this reconciler's routes went. On a
// platform with no routing tables it used to print table 0, the config's
// zero value read before defaults were applied, on a machine that has no
// tables at all.
func TestWhereComesFromThePlatform(t *testing.T) {
	r, _, fake := harness(t, Table{ID: DefaultTable}, Runtime{Interface: "utun9"})
	fake.name = "somewhere"
	if got := r.Where(); got != "somewhere" {
		t.Errorf("the reconciler reports %q rather than asking the platform", got)
	}
}

// A prefix whose meaning is the link it sits on has no business in a routing
// table that forwards out of a tunnel. The kernel keys its own entries for
// these per interface, and only a default or a source-specific route is
// interface-scoped on darwin, so an announced "ff00::/8" or "fe80::/64" went
// into the one FIB every program on that machine shares and shadowed its own
// multicast and link-local plumbing. Coexisting with whatever else is on the
// box is a requirement of this tool, not a nicety.
func TestPrefixesTheMeshCannotCarryAreNotInstalled(t *testing.T) {
	r, table, kernel := harness(t, Table{})
	peer := &netstack.Peer{ID: "peer"}
	refused := []netip.Prefix{
		prefix("ff00::/8"),
		prefix("ff02::1/128"),
		prefix("fe80::/64"),
		prefix("224.0.0.0/4"),
		prefix("169.254.0.0/16"),
		prefix("127.0.0.0/8"),
		prefix("::1/128"),
		limitedBroadcast,
	}
	wanted := prefix("2001:db8::/48")
	for _, p := range append(refused, wanted) {
		table.Set(netip.Prefix{}, p, peer)
	}
	if err := r.applyRoutes(r.src.Snapshot()); err != nil {
		t.Fatal(err)
	}
	installed := kernel.snapshot()
	if len(installed) != 1 {
		t.Fatalf("the reconciler installed %v, want only %s", installed, wanted)
	}
	if installed[0].Destination != wanted {
		t.Errorf("the reconciler installed %s rather than %s", installed[0].Destination, wanted)
	}
}

// "Only an address this reconciler added itself, in this process lifetime, is
// ever removed again." Both platforms assign by upsert, so the same address
// under a different prefix length rewrites an entry somebody else put there
// and reports success. Recording that as owned takes it away at shutdown, and
// ranet3 attaches to a tun it did not necessarily create.
func TestAddressAnotherWriterHoldsIsLeftAlone(t *testing.T) {
	wanted := prefix("2001:db8::1/128")
	r, _, kernel := harness(t, Table{Addresses: prefixes(wanted)})
	kernel.addrs[prefix("2001:db8::1/64")] = true

	if _, _, err := r.applyAddresses(); err != nil {
		t.Fatalf("applying addresses failed rather than skipping one: %v", err)
	}
	if r.owned[wanted] {
		t.Error("an address another writer put on the link was recorded as ours, so shutdown takes it away")
	}
	if kernel.addrs[wanted] {
		t.Error("the reconciler rewrote an address it does not own")
	}
	if !kernel.addrs[prefix("2001:db8::1/64")] {
		t.Error("the other writer's address is gone")
	}

	// An address nothing else holds is still assigned and still owned.
	free := prefix("2001:db8::2/128")
	r.addresses = append(r.addresses, free)
	if _, _, err := r.applyAddresses(); err != nil {
		t.Fatal(err)
	}
	if !r.owned[free] || !kernel.addrs[free] {
		t.Error("a free address was not assigned")
	}
}

// darwin's SIOCDIFADDR matches on the address alone, so another writer that
// rewrote this reconciler's address under a different prefix length, which its
// SIOCAIFADDR upsert lets it do, would have its entry taken away by shutdown.
// The rule is that only an address this reconciler added itself is ever
// removed, and an address that no longer looks the way it was installed is no
// longer that address.
func TestWithdrawLeavesAnAddressAnotherWriterRewrote(t *testing.T) {
	ours := prefix("2001:db8::1/128")
	kept := prefix("2001:db8::2/128")
	r, _, kernel := harness(t, Table{Addresses: prefixes(ours, kept)})
	if _, _, err := r.applyAddresses(); err != nil {
		t.Fatal(err)
	}
	if !r.owned[ours] || !r.owned[kept] {
		t.Fatal("the reconciler did not record what it assigned, so this proves nothing")
	}

	// Somebody rewrites one of them under a different length.
	delete(kernel.addrs, ours)
	kernel.addrs[prefix("2001:db8::1/64")] = true

	if err := r.withdraw(); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if !kernel.addrs[prefix("2001:db8::1/64")] {
		t.Error("shutdown removed an address this reconciler no longer held as it installed it")
	}
	if kernel.addrs[kept] {
		t.Error("shutdown left an address it did install")
	}
}

// The same rule when the link will not say what it holds. A readback that did
// not happen is not one that said yes, and treating it as one deletes exactly
// the address the guard above exists to protect. applyAddresses refuses the
// whole pass on the identical failure.
func TestWithdrawLeavesEveryAddressWhenTheLinkWillNotReadBack(t *testing.T) {
	ours := prefix("2001:db8::1/128")
	r, _, kernel := harness(t, Table{Addresses: prefixes(ours)})
	if _, _, err := r.applyAddresses(); err != nil {
		t.Fatal(err)
	}
	if !r.owned[ours] {
		t.Fatal("the reconciler did not record what it assigned, so this proves nothing")
	}

	kernel.failAddrs = errors.New("link is gone")
	if err := r.withdraw(); err == nil {
		t.Error("a shutdown that could not read the link back reported success")
	}
	if !kernel.addrs[ours] {
		t.Error("shutdown removed an address it could not confirm it still held as it installed it")
	}
	if !r.owned[ours] {
		t.Error("shutdown forgot an address it did not withdraw")
	}
}

// An address another writer holds is reported once, not once per pass: the
// record rotates the way the route warning set does, so a report costs one log
// line for as long as the situation lasts rather than one every reconcile
// interval for the life of the process.
func TestAddressReportIsNotRepeatedEveryPass(t *testing.T) {
	logs := captureKernelLogs(t)
	wanted := prefix("2001:db8::1/128")
	r, _, kernel := harness(t, Table{Addresses: prefixes(wanted)})
	kernel.addrs[prefix("2001:db8::1/64")] = true

	const passes = 4
	for pass := range passes {
		if _, _, err := r.applyAddresses(); err != nil {
			t.Fatalf("pass %d: %v", pass, err)
		}
	}
	if got := bytes.Count(logs.Bytes(), []byte("another writer holds")); got != 1 {
		t.Errorf("the address was reported %d times across %d passes, want once", got, passes)
	}
}

// A prefix the mesh has and the kernel does not is explained by Skipped, by
// Err, or by nothing at all, so both have to survive a pass rather than being
// counted only into a log line.
func TestStatsReportWhatThePassDidAndDidNotInstall(t *testing.T) {
	reconciler, table, fake := harness(t, Table{})
	if before := reconciler.Stats(); !before.At.IsZero() {
		t.Fatalf("stats before the first pass read %+v, want the zero value", before)
	}

	table.Set(netip.Prefix{}, prefix("10.0.0.0/8"), nil)
	table.Set(netip.Prefix{}, prefix("3fff:a::/36"), nil)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	first := reconciler.Stats()
	if first.At.IsZero() {
		t.Fatal("a finished pass left no timestamp")
	}
	if first.Desired != 2 || first.Installed != 2 || first.Added != 2 || first.Removed != 0 || first.Skipped != 0 {
		t.Fatalf("the first pass reports %+v, want two desired, installed and added", first)
	}

	// A route another writer holds is refused rather than taken over, which
	// the platform reports as errRouteSkipped.
	refused := Route{Destination: prefix("10.1.0.0/16")}
	fake.failAdd[refused] = errRouteSkipped
	table.Set(netip.Prefix{}, prefix("10.1.0.0/16"), nil)
	table.Remove(netip.Prefix{}, prefix("10.0.0.0/8"))
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	second := reconciler.Stats()
	if second.Skipped != 1 {
		t.Errorf("a refused install reports %+v, want one skipped", second)
	}
	if second.Removed != 1 || second.Added != 0 {
		t.Errorf("the second pass reports %+v, want one removed and none added", second)
	}
	if second.Installed != 1 {
		t.Errorf("the second pass reports %d installed, want the one route the kernel still holds", second.Installed)
	}
	if second.Err != "" {
		t.Errorf("a skipped route was reported as a failure: %s", second.Err)
	}
}

// The fake's policy engine. It models what the linux backend guarantees rather
// than the wire format: Rules returns only what this reconciler installed, so
// a test that saw another writer's rule in the list would be testing a promise
// the backend does not make.
func (f *fakeKernel) Rules() ([]Rule, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failRules != nil {
		return nil, f.failRules
	}
	out := make([]Rule, 0, len(f.rules))
	for rule := range f.rules {
		out = append(out, rule)
	}
	slices.SortFunc(out, func(a, b Rule) int { return strings.Compare(a.String(), b.String()) })
	return out, nil
}

// configuredRules holds the fake's rules but for those r derives
func (f *fakeKernel) configuredRules(r *Reconciler) map[Rule]bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	held := maps.Clone(f.rules)
	for _, rule := range derivedRules(r.table.ID, r.rt.Overlay, r.ownPrefixes(r.src.Snapshot()), exitView{}) {
		delete(held, rule)
	}
	return held
}

// holdsDerived is whether the fake holds every rule r derives
func (f *fakeKernel) holdsDerived(r *Reconciler) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, rule := range derivedRules(r.table.ID, r.rt.Overlay, r.ownPrefixes(r.src.Snapshot()), exitView{}) {
		if !f.rules[rule] {
			return false
		}
	}
	return true
}

func (f *fakeKernel) AddRule(rule Rule) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.failAddRule[rule]; err != nil {
		return err
	}
	f.ruleAdds++
	f.ruleAdded = append(f.ruleAdded, rule)
	f.rules[rule] = true
	return nil
}

func (f *fakeKernel) DelRule(rule Rule) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ruleDels++
	delete(f.rules, rule)
	return nil
}

// routesOnly is a platform with no policy engine, which is every platform but
// linux. It delegates rather than embedding, because embedding promotes the
// rule methods and the point of this type is not having them.
type routesOnly struct{ inner *fakeKernel }

func (p routesOnly) Routes() ([]Route, error)          { return p.inner.Routes() }
func (p routesOnly) where(t Table) string              { return p.inner.where(t) }
func (p routesOnly) AddRoute(r Route) error            { return p.inner.AddRoute(r) }
func (p routesOnly) DelRoute(r Route) error            { return p.inner.DelRoute(r) }
func (p routesOnly) Addrs() ([]netip.Prefix, error)    { return p.inner.Addrs() }
func (p routesOnly) AddAddr(prefix netip.Prefix) error { return p.inner.AddAddr(prefix) }
func (p routesOnly) DelAddr(prefix netip.Prefix) error { return p.inner.DelAddr(prefix) }
func (p routesOnly) Notify() <-chan struct{}           { return p.inner.Notify() }
func (p routesOnly) retable(t Table)                   { p.inner.retable(t) }
func (p routesOnly) Close() error                      { return p.inner.Close() }

// A rule an earlier instance left behind under this reconciler's protocol is
// adopted by the readback and withdrawn, the pass publishes the rules it
// derived as a dump of them reads, and a withdrawal takes every rule and
// publishes none.
func TestRulePassWithdrawsWhatItDoesNotDeriveAndPublishesWhatItDoes(t *testing.T) {
	overlay := prefixes(prefix("192.0.2.0/24"))
	reconciler, _, fake := harness(t, Table{}, Runtime{Overlay: overlay})
	if got := reconciler.DerivedRules(); got != nil {
		t.Fatalf("a reconciler that ran no pass publishes %v", got)
	}
	stale := Rule{Family: FamilyIPv4, To: schema.MustPrefix("10.0.0.0/8"), Table: 200, Priority: 100}
	fake.rules[stale] = true
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	derived := derivedRules(DefaultTable, overlay, nil, exitView{})
	if got := fake.configuredRules(reconciler); len(got) != 0 {
		t.Fatalf("the pass left %v beside the derived rules", slices.Collect(maps.Keys(got)))
	}
	var want []DumpedRule
	for _, rule := range derived {
		if !fake.rules[rule] {
			t.Errorf("the pass did not install %s", rule)
		}
		want = append(want, rule.dumped(DefaultProtocol))
	}
	if got := reconciler.DerivedRules(); !slices.Equal(got, want) {
		t.Errorf("the reconciler publishes\n%v\nwant\n%v", got, want)
	}
	marked := slices.IndexFunc(want, func(rule DumpedRule) bool { return rule.Priority == priorityUnderlayPastOverlay })
	if rule := want[marked]; rule.FWMask != ^uint32(0) || rule.Action != "goto" || rule.Goto != priorityOverlayEnd || rule.Table != 0 {
		t.Errorf("the goto at 5100 reads %+v, want the all-ones mask the kernel dumps and no table", rule)
	}
	if err := reconciler.withdraw(); err != nil {
		t.Fatal(err)
	}
	if got, _ := fake.Rules(); len(got) != 0 {
		t.Errorf("shutdown left %v behind", got)
	}
	if got := reconciler.DerivedRules(); got != nil {
		t.Errorf("a withdrawn reconciler publishes %v", got)
	}
}

// A pass that fails anywhere has to say so where an operator reads it. Only
// applyRoutes counts, so a node whose rules fail on every pass would
// otherwise report a clean route count and no error at all.
func TestStatsCarryTheWholePassError(t *testing.T) {
	reconciler, _, fake := harness(t, Table{})
	fake.failRules = errors.New("no permission to read the rules")

	if err := reconciler.reconcile(); err == nil {
		t.Fatal("a failing rule pass did not fail the pass")
	}
	stats := reconciler.Stats()
	if stats.Err == "" {
		t.Error("the pass failed and Stats reported no error")
	}
	if stats.At.IsZero() {
		t.Error("a failing pass left no timestamp, so a stale one reads as current")
	}
}

// An address that cannot be assigned stops neither routes nor rules, and a
// route that cannot be installed does not stop rules
func TestFailingStepLeavesTheLaterStepsToRun(t *testing.T) {
	route := Route{Destination: prefix("10.0.0.0/8")}
	reconciler, table, fake := harness(t, Table{Addresses: prefixes(prefix("203.0.113.5/32"))})
	table.Set(netip.Prefix{}, route.Destination, nil)
	fake.failAddrs = errors.New("the link refuses the address")
	if err := reconciler.reconcile(); err == nil {
		t.Fatal("a failing address step did not fail the pass")
	}
	if !fake.has(route) {
		t.Error("a failing address step stopped the route step")
	}
	if !fake.holdsDerived(reconciler) {
		t.Errorf("a failing address step left the derived rules out: %v", fake.rules)
	}

	reconciler, table, fake = harness(t, Table{})
	table.Set(netip.Prefix{}, route.Destination, nil)
	fake.failAdd[route] = errors.New("netlink says no")
	if err := reconciler.reconcile(); err == nil {
		t.Fatal("a failing route did not fail the pass")
	}
	if !fake.holdsDerived(reconciler) {
		t.Errorf("a failing route left the derived rules out: %v", fake.rules)
	}
}

// A pass that fails before it can count anything reports nothing rather than
// the counts of the last pass that worked. Reporting "2 added" on a pass that
// listed no routes at all is a number an operator acts on.
func TestFailingPassDoesNotRepublishTheLastGoodCounts(t *testing.T) {
	reconciler, table, fake := harness(t, Table{})
	table.Set(netip.Prefix{}, prefix("2001:db8::/32"), nil)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if got := reconciler.Stats(); got.Added == 0 {
		t.Fatalf("the first pass installed nothing: %+v", got)
	}

	fake.failList = errors.New("the dump is broken")
	if err := reconciler.reconcile(); err == nil {
		t.Fatal("a failing dump did not fail the pass")
	}
	switch got := reconciler.Stats(); {
	case got.Err == "":
		t.Error("the failing pass reported no error")
	case got.Added != 0 || got.Installed != 0 || got.Desired != 0:
		t.Errorf("the failing pass republished the last good counts: %+v", got)
	}
}

// Stopping a running reconciler takes its routes and addresses out of the
// kernel, and starting it again puts them back on the next pass. A stop that
// only paused would leave a table holding routes nobody maintains, the state
// an operator reaches for the verb to get out of, and `birdc disable` on a
// kernel protocol did not leave it either.
func TestStoppedReconcilerWithdrawsAndStartsAgain(t *testing.T) {
	reconciler, table, fake := harness(t, Table{
		Addresses: prefixes(prefix("203.0.113.5/32")),
		Reconcile: schema.Duration(10 * time.Millisecond),
	})
	table.Set(netip.Prefix{}, prefix("10.0.0.0/8"), nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- reconciler.Run(ctx) }()
	waitFor(t, func() bool { return fake.has(Route{Destination: prefix("10.0.0.0/8")}) })

	reconciler.SetEnabled(false)
	if reconciler.Enabled() {
		t.Error("the reconciler reports itself as writing to the kernel after being stopped")
	}
	// Both halves, in one condition. withdraw deletes every route and only
	// then every address, which is the order the kernel needs, so a wait on
	// the routes alone returns in the middle of the withdrawal and reads the
	// addresses before they have been touched.
	withdrawn := func() bool {
		if len(fake.snapshot()) != 0 {
			return false
		}
		fake.mu.Lock()
		defer fake.mu.Unlock()
		return len(fake.addrs) == 0
	}
	deadline := time.Now().Add(waitBudget)
	for !withdrawn() && time.Now().Before(deadline) {
		time.Sleep(waitPoll)
	}
	if !withdrawn() {
		fake.mu.Lock()
		addresses := len(fake.addrs)
		fake.mu.Unlock()
		t.Fatalf("the stop left %d routes and %d addresses behind", len(fake.snapshot()), addresses)
	}
	// The pass recorded after a withdrawal reads zero installed, so a
	// diagnostic does not go on reporting the routes of the last pass that ran.
	waitFor(t, func() bool { return reconciler.Stats().Installed == 0 })

	reconciler.SetEnabled(true)
	waitFor(t, func() bool { return fake.has(Route{Destination: prefix("10.0.0.0/8")}) })

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(waitBudget):
		t.Fatal("run did not return after cancellation")
	}
}

// a stop whose withdrawal failed is still a stop the reconciler owes
// it tries again rather than recording the routes as gone
// the sweep is a minute out
// only the retry a failed pass takes can then withdraw the route within the wait
func TestStoppedReconcilerRetriesAWithdrawalThatFailed(t *testing.T) {
	reconciler, table, fake := harness(t, Table{Reconcile: schema.Duration(time.Minute)})
	route := Route{Destination: prefix("10.0.0.0/8")}
	table.Set(netip.Prefix{}, route.Destination, nil)
	// the first pass reads the route
	// the change it made then wakes nothing after it
	// one failed withdrawal leaves the retry minRetryInterval out
	<-table.Changed()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- reconciler.Run(ctx) }()
	waitFor(t, func() bool { return fake.has(route) })

	fake.mu.Lock()
	fake.failDel[route] = syscall.EPERM
	fake.mu.Unlock()
	reconciler.SetEnabled(false)
	waitFor(t, func() bool { return strings.Contains(reconciler.Stats().Err, "operation not permitted") })

	fake.mu.Lock()
	delete(fake.failDel, route)
	fake.mu.Unlock()
	waitFor(t, func() bool { return !fake.has(route) && reconciler.Stats().Err == "" })

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("run: %v", err)
	}
}

// retryDelays is a log handler keeping the retry_in of every record that carries one
// the reconcile goroutine logs while the test reads
type retryDelays struct {
	mu     sync.Mutex
	delays []time.Duration
}

func (h *retryDelays) Enabled(context.Context, slog.Level) bool { return true }
func (h *retryDelays) WithAttrs([]slog.Attr) slog.Handler       { return h }
func (h *retryDelays) WithGroup(string) slog.Handler            { return h }

func (h *retryDelays) Handle(_ context.Context, record slog.Record) error {
	record.Attrs(func(attr slog.Attr) bool {
		if attr.Key == "retry_in" {
			h.mu.Lock()
			h.delays = append(h.delays, attr.Value.Duration())
			h.mu.Unlock()
		}
		return true
	})
	return nil
}

func (h *retryDelays) seen() []time.Duration {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.delays)
}

// a failed pass and a failed withdrawal are retried after minRetryInterval
// each retry after that waits twice the delay before it, and never longer than the sweep
// without the doubling a kernel refusing every pass costs a full pass each minRetryInterval for as long as it refuses
// the sweep sits between one and two minRetryInterval
// the second delay then tells the doubling and the cap apart from a delay that never grows
func TestRetryDoublesItsDelayUpToTheSweep(t *testing.T) {
	sweep := minRetryInterval * 3 / 2
	for name, fail := range map[string]func(*Reconciler, *fakeKernel, Route){
		"a failed pass": func(_ *Reconciler, fake *fakeKernel, _ Route) {
			fake.mu.Lock()
			fake.failList = errors.New("netlink is busy")
			fake.mu.Unlock()
			fake.signal <- struct{}{}
		},
		"a failed withdrawal": func(reconciler *Reconciler, fake *fakeKernel, route Route) {
			fake.mu.Lock()
			fake.failDel[route] = syscall.EPERM
			fake.mu.Unlock()
			reconciler.SetEnabled(false)
		},
	} {
		t.Run(name, func(t *testing.T) {
			delays := &retryDelays{}
			logtest.SetDefault(t, slog.New(delays))
			reconciler, table, fake := harness(t, Table{Reconcile: schema.Duration(sweep)})
			route := Route{Destination: prefix("10.0.0.0/8")}
			table.Set(netip.Prefix{}, route.Destination, nil)
			<-table.Changed()
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- reconciler.Run(ctx) }()
			waitFor(t, func() bool { return fake.has(route) })
			fail(reconciler, fake, route)
			waitFor(t, func() bool { return len(delays.seen()) >= 1 })
			// a wake other than the retry brings the second failure before the first delay is out
			fake.signal <- struct{}{}
			waitFor(t, func() bool { return len(delays.seen()) >= 2 })
			if got, want := delays.seen()[:2], []time.Duration{minRetryInterval, sweep}; !slices.Equal(got, want) {
				t.Errorf("the retries waited %v, want %v", got, want)
			}
			fake.mu.Lock()
			fake.failList = nil
			delete(fake.failDel, route)
			fake.mu.Unlock()
			cancel()
			if err := <-done; err != nil {
				t.Fatalf("run: %v", err)
			}
		})
	}
}
