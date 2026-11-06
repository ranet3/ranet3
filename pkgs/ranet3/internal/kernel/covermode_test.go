// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build (linux && !android) || (darwin && !ios)

package kernel

import (
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/schema"
)

var (
	zero4 = Route{Destination: prefix("0.0.0.0/0")}
	zero6 = Route{Destination: prefix("::/0"), Metric: defaultIPv6Metric}
)

// scopedAs is r held under the scope the covering fake gives it
func scopedAs(r Route) Route { r.Scoped = true; return r }

// modeCovering is a reconciler under tbl on the covering fake over
// coverOverlay with a live session, the tun holding addresses, and the mesh
// holding both zero routes
func modeCovering(t *testing.T, tbl Table, bus *events.Bus, addresses ...netip.Prefix) (*Reconciler, *netstack.RouteTable, *coveringKernel) {
	t.Helper()
	reconciler, table, kernel := coveredHarness(t, tbl, Runtime{Sessions: func() int { return 1 }, Events: bus}, addresses...)
	reconciler.now = func() time.Time { return start }
	table.Set(netip.Prefix{}, zero4.Destination, nil)
	table.Set(netip.Prefix{}, zero6.Destination, nil)
	return reconciler, table, kernel
}

// wantZeroRoutes fails the test unless the covering fake holds members of the
// families in covered alone and each other family's zero route as itself,
// scoped
func wantZeroRoutes(t *testing.T, what string, kernel *coveringKernel, covered ...Family) {
	t.Helper()
	v4, v6 := coverMembers(kernel.fakeKernel)
	for _, c := range []struct {
		family  Family
		members int
		zero    Route
	}{{FamilyIPv4, v4, zero4}, {FamilyIPv6, v6, zero6}} {
		want, held := 0, !slices.Contains(covered, c.family)
		if !held {
			want = 8
		}
		if c.members != want || kernel.has(scopedAs(c.zero)) != held || kernel.has(c.zero) {
			t.Errorf("%s: %s holds %d members and its zero route scoped %v, unscoped %v, want %d members and the zero route scoped %v: %v",
				what, c.family, c.members, kernel.has(scopedAs(c.zero)), kernel.has(c.zero), want, held, kernel.snapshot())
		}
	}
	for _, r := range kernel.snapshot() {
		if r.Cover && r.Scoped {
			t.Errorf("%s: the member %s is scoped", what, r.Destination)
		}
	}
}

// On a covering platform in mode 2 with an overlay address of each family on
// the tun, each zero route goes in as its family's members, unscoped. In mode
// off it goes in as itself, scoped as the platform scopes a route that counts
// as a default there.
func TestCoveringPlatformCoversAZeroRouteInTheMode(t *testing.T) {
	for _, c := range []struct {
		name    string
		tbl     Table
		covered []Family
	}{
		{"mode 2", Table{}.WithMode(&ExitMode{}), bothFamilies},
		{"mode off", Table{}, nil},
	} {
		reconciler, _, kernel := modeCovering(t, c.tbl, nil, coverAddresses...)
		if err := reconciler.reconcile(); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		wantZeroRoutes(t, c.name, kernel, c.covered...)
		if got := reconciler.Stats().Cover; !slices.Equal(got, c.covered) {
			t.Errorf("%s: the pass reports the cover %v, want %v", c.name, got, c.covered)
		}
	}
}

// A family the tun holds no overlay address of keeps mode off's form in the
// mode, its zero route scoped as itself, the status naming it and one
// kernel.exit saying so. Once the tun holds an address of it, the next pass
// covers it too, with the event's edge back.
func TestLeftOutFamilyKeepsModeOffsForm(t *testing.T) {
	bus := events.New()
	reconciler, _, kernel := modeCovering(t, Table{}.WithMode(&ExitMode{}), bus, coverAddresses[0])
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	wantZeroRoutes(t, "the tun holding an IPv4 overlay address alone", kernel, FamilyIPv4)
	if status := reconciler.Stats().Exit; status == nil || !slices.Equal(status.Unaddressed, []Family{FamilyIPv6}) {
		t.Errorf("the status reads %+v, want IPv6 unaddressed", status)
	}
	if got, want := exitEvents(bus), [][]string{{"ipv6", "false"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("the events read %v, want %v", got, want)
	}
	kernel.byHand(coverAddresses[1], true)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	wantZeroRoutes(t, "the pass after an IPv6 overlay address", kernel, bothFamilies...)
	if status := reconciler.Stats().Exit; status == nil || len(status.Unaddressed) != 0 {
		t.Errorf("with both addresses the status reads %+v, want none unaddressed", status)
	}
	if got, want := exitEvents(bus), [][]string{{"ipv6", "false"}, {"ipv6", "true"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("the events read %v, want %v", got, want)
	}
}

// A zero route inside ::/8 in a family the mode leaves out, the tun holding an
// address of it outside the overlay alone, keeps mode off's form too: it goes
// in as itself, scoped, and the pass neither skips it nor warns that the cover
// holds nothing of it.
func TestLeftOutFamilysRouteInsideTheHoleGoesInAsItself(t *testing.T) {
	logs := captureKernelLogs(t)
	reconciler, table, kernel := modeCovering(t, Table{}.WithMode(&ExitMode{}), nil, coverAddresses[0], prefix("2001:db8:1::1/64"))
	inside := Route{Destination: prefix("::/16"), Metric: defaultIPv6Metric}
	table.Set(netip.Prefix{}, inside.Destination, nil)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if !kernel.has(scopedAs(inside)) {
		t.Errorf("the left-out family's %s is not held as itself, scoped: %v", inside.Destination, kernel.snapshot())
	}
	if skipped := reconciler.Stats().Skipped; skipped != 0 {
		t.Errorf("the pass reports %d skipped, want none", skipped)
	}
	if strings.Contains(logs.String(), "its cover holds nothing of") {
		t.Errorf("the pass warned of a route its cover holds nothing of: %s", logs.String())
	}
}

// Each pass hands the covering platform the families the tun holds no address
// of, an address outside the overlay counting as much as one inside it. In
// mode off with no address of cap.table's the listing serves that read alone,
// so a pass that cannot list keeps the last listing's families, fails on none
// of it, and warns once for each run of failures.
func TestPassHandsThePlatformTheBareFamilies(t *testing.T) {
	logs := captureKernelLogs(t)
	reconciler, _, kernel := modeCovering(t, Table{}, nil, coverAddresses[0])
	pass := func(what string, want ...Family) {
		t.Helper()
		if err := reconciler.reconcile(); err != nil {
			t.Errorf("%s: %v", what, err)
		}
		if !slices.Equal(kernel.bare, want) {
			t.Errorf("%s: the pass handed %v bare, want %v", what, kernel.bare, want)
		}
	}
	pass("the tun holding an IPv4 address alone", FamilyIPv6)
	pass("a second listing that finds IPv6 bare still", FamilyIPv6)
	kernel.failAddrs = errors.New("the link will not list")
	kernel.byHand(prefix("fe80::1/64"), true)
	pass("a pass that could not list the tun", FamilyIPv6)
	pass("a second pass that could not list it", FamilyIPv6)
	kernel.failAddrs = nil
	pass("a link-local IPv6 address beside it, listed")
	kernel.failAddrs = errors.New("the link will not list")
	pass("a pass that could not list the tun again")
	if n := strings.Count(logs.String(), "kernel could not list the tun's addresses"); n != 2 {
		t.Errorf("two runs of failed listings warned %d times, want twice: %s", n, logs.String())
	}
}

// Where the pass lists the tun for an address of cap.table's, as it does on
// every platform, a failed listing fails the pass and keeps the last
// listing's bare families.
func TestFailedListingForTheTablesAddressFailsThePass(t *testing.T) {
	reconciler, _, kernel := modeCovering(t, Table{Addresses: prefixes(prefix("192.0.2.1/32"))}, nil)
	if err := reconciler.reconcile(); err != nil || !slices.Equal(kernel.bare, []Family{FamilyIPv6}) {
		t.Fatalf("the first pass answered %v and handed %v bare, want IPv6", err, kernel.bare)
	}
	kernel.failAddrs = errors.New("the link will not list")
	if err := reconciler.reconcile(); err == nil || !strings.Contains(err.Error(), "list addresses") {
		t.Errorf("a pass that could not list the tun answered %v, want the listing's error", err)
	}
	if !slices.Equal(kernel.bare, []Family{FamilyIPv6}) {
		t.Errorf("a pass that could not list the tun handed %v bare, want the last listing's IPv6", kernel.bare)
	}
}

// A pass that cannot list the tun's addresses keeps the families the last
// pass covered, the cover in place and no kernel.exit, and a first pass that
// cannot list them covers none.
func TestFailedListingKeepsTheLastFamilies(t *testing.T) {
	bus := events.New()
	reconciler, _, kernel := modeCovering(t, Table{}.WithMode(&ExitMode{}), bus, coverAddresses[0])
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	kernel.failAddrs = errors.New("the link will not list")
	if err := reconciler.reconcile(); err == nil {
		t.Error("a pass that could not list the tun's addresses succeeded")
	}
	wantZeroRoutes(t, "a pass that could not list the tun's addresses", kernel, FamilyIPv4)
	if got, want := exitEvents(bus), [][]string{{"ipv6", "false"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("the events read %v, want %v", got, want)
	}

	first, _, unlisted := modeCovering(t, Table{}.WithMode(&ExitMode{}), nil, coverAddresses...)
	unlisted.failAddrs = errors.New("the link will not list")
	if err := first.reconcile(); err == nil {
		t.Error("a first pass that could not list the tun's addresses succeeded")
	}
	wantZeroRoutes(t, "a first pass that could not list the tun's addresses", unlisted)
}

// A reload into the mode moves each zero route into its cover on the next
// pass, and one out of it moves the zero route back and the members out.
func TestReloadMovesTheZeroRouteIntoTheCoverAndBack(t *testing.T) {
	reconciler, _, kernel := modeCovering(t, Table{}, nil, coverAddresses...)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	wantZeroRoutes(t, "mode off", kernel)
	for _, step := range []struct {
		name    string
		table   Table
		covered []Family
	}{
		{"a reload into mode 2", Table{}.WithMode(&ExitMode{}), bothFamilies},
		{"a reload back to mode off", Table{}, nil},
	} {
		if err := reconciler.SetTable(step.table, coverOverlay, nil); err != nil {
			t.Fatalf("%s: %v", step.name, err)
		}
		if !reconciler.adopt() {
			t.Fatalf("%s: the reload was not adopted", step.name)
		}
		if err := reconciler.reconcile(); err != nil {
			t.Fatalf("%s: %v", step.name, err)
		}
		wantZeroRoutes(t, step.name, kernel, step.covered...)
	}
}

// Mode 3's steered defaults go in as the cover on a covering platform, and the
// path's status counts both families installed.
func TestSteeredDefaultsCountAsInstalledThroughTheCover(t *testing.T) {
	mode := &ExitMode{Via: []schema.Addr{schema.AddrFrom(waypointSID), schema.AddrFrom(exitSID)}, Fallback: FallbackUplink}
	reconciler, table, kernel := modeCovering(t, Table{}.WithMode(mode).WithPathSource(steeredSource), nil, coverAddresses...)
	for _, entry := range []mirrorEntry{host(waypointSID, learned), host(exitSID, learned)} {
		table.Set(entry.source, entry.destination, entry.value)
	}
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	wantZeroRoutes(t, "mode 3 with the path up", kernel, bothFamilies...)
	if path := reconciler.Stats().Path; path == nil || !slices.Equal(path.Installed, bothFamilies) {
		t.Errorf("the path reads %+v, want both families installed", path)
	}
}

// CoverInstalled names a member the last pass left installed and nothing
// else: no route on a platform that does not cover, a source-specific
// 8000::/1 among them, a mode 3 member beside the mesh's 128.0.0.0/1, which
// mode 3 declines, in mode 2 no member that half withholds, and no member the
// pass wanted of a family whose cover another program's route at one member's
// key keeps out.
func TestCoverInstalledNamesWhatThePassLeftIn(t *testing.T) {
	half, upper := prefix("128.0.0.0/1"), prefix("8000::/1")
	plain, table, fake := harness(t, Table{}, Runtime{Overlay: coverOverlay, Sessions: func() int { return 1 }})
	plain.now = func() time.Time { return start }
	table.Set(prefix("2001:db8:1::/48"), upper, nil)
	if err := plain.reconcile(); err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(fake.snapshot(), func(r Route) bool { return r.Destination == upper }) || plain.CoverInstalled(upper) {
		t.Errorf("with a source-specific %s held %v, a platform that does not cover names it a member %v", upper, fake.snapshot(), plain.CoverInstalled(upper))
	}

	mode := &ExitMode{Via: []schema.Addr{schema.AddrFrom(waypointSID), schema.AddrFrom(exitSID)}, Fallback: FallbackUplink}
	steered, table, _ := modeCovering(t, Table{}.WithMode(mode).WithPathSource(steeredSource), nil, coverAddresses...)
	for _, entry := range []mirrorEntry{host(waypointSID, learned), host(exitSID, learned)} {
		table.Set(entry.source, entry.destination, entry.value)
	}
	table.Set(netip.Prefix{}, half, nil)
	if err := steered.reconcile(); err != nil {
		t.Fatal(err)
	}
	if !steered.CoverInstalled(half) {
		t.Errorf("mode 3 beside the mesh's %s names no member there: %v", half, steered.Stats().Members)
	}

	covered, table, _ := modeCovering(t, Table{}.WithMode(&ExitMode{}), nil, coverAddresses...)
	table.Set(netip.Prefix{}, half, nil)
	if err := covered.reconcile(); err != nil {
		t.Fatal(err)
	}
	if covered.CoverInstalled(half) || !covered.CoverInstalled(prefix("64.0.0.0/2")) {
		t.Errorf("mode 2 beside the mesh's %s names the members %v, want every IPv4 member but that half", half, covered.Stats().Members)
	}

	refused, kernel, table := keyHarness(t)
	taken := prefix("64.0.0.0/2")
	kernel.taken[taken] = errRouteSkipped
	table.Set(netip.Prefix{}, zero4.Destination, nil)
	table.Set(netip.Prefix{}, zero6.Destination, nil)
	if err := refused.reconcile(); err != nil {
		t.Fatal(err)
	}
	for ipv4, members := range zeroFreeCover {
		for _, member := range members {
			if got, want := refused.CoverInstalled(member), !ipv4; got != want {
				t.Errorf("with another program at %s, %s is named a member %v, want %v: %v", taken, member, got, want, refused.Stats().Members)
			}
		}
	}
}

// A pass whose route dump fails leaves the cover the last pass installed in
// place, so CoverInstalled goes on naming its members while the pass's counts
// read nothing.
func TestFailedRouteDumpKeepsTheMembersNamed(t *testing.T) {
	reconciler, _, kernel := modeCovering(t, Table{}.WithMode(&ExitMode{}), nil, coverAddresses...)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	kernel.failList = errors.New("the dump is broken")
	if err := reconciler.reconcile(); err == nil {
		t.Fatal("a failing dump did not fail the pass")
	}
	if stats := reconciler.Stats(); stats.Installed != 0 || stats.Added != 0 {
		t.Errorf("the failing pass republished the last good counts: %+v", stats)
	}
	for _, members := range zeroFreeCover {
		for _, member := range members {
			if !reconciler.CoverInstalled(member) {
				t.Errorf("after a failed dump %s is named no member, want the last pass's: %v", member, reconciler.Stats().Members)
			}
		}
	}

	// the next good pass counts its own members, and in mode off it has none
	kernel.failList = nil
	if err := reconciler.SetTable(Table{}, coverOverlay, nil); err != nil {
		t.Fatal(err)
	}
	if !reconciler.adopt() {
		t.Fatal("the reload to mode off was not adopted")
	}
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if members := reconciler.Stats().Members; len(members) != 0 {
		t.Errorf("a good pass in mode off after a failed dump names %v members of the cover, want none", members)
	}
}

// A platform with no policy rules reports the mode's status all the same,
// with the families the tun holds no overlay address of.
func TestExitStatusIsReportedWithoutPolicyRules(t *testing.T) {
	reconciler, _, fake := harness(t, Table{}.WithMode(&ExitMode{}), Runtime{Overlay: coverOverlay, Sessions: func() int { return 1 }})
	reconciler.rules = nil
	fake.addrs[coverAddresses[0]] = true
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if status := reconciler.Stats().Exit; status == nil || !slices.Equal(status.Unaddressed, []Family{FamilyIPv6}) {
		t.Errorf("the status reads %+v, want the mode with IPv6 unaddressed", status)
	}
}
