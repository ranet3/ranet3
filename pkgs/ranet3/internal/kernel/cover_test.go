// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/schema"
)

func destinations(routes []Route) []string {
	out := make([]string, 0, len(routes))
	for _, r := range routes {
		out = append(out, r.Destination.String())
	}
	slices.Sort(out)
	return out
}

func coverOf(family bool, except ...string) []string {
	var out []string
	for _, member := range zeroFreeCover[family] {
		if !slices.Contains(except, member.String()) {
			out = append(out, member.String())
		}
	}
	slices.Sort(out)
	return out
}

// Where the platform covers a default, darwin with link.underlay.bind, a plain
// default goes in as the members of its family, carrying its metric, and
// leaves every member's zero address out.
func TestPlainDefaultBecomesItsZeroFreeCover(t *testing.T) {
	got := coverDefaults([]Route{
		{Destination: prefix("0.0.0.0/0"), Metric: 7},
		{Destination: prefix("::/0"), Metric: defaultIPv6Metric},
	}, nil)
	if want := append(coverOf(true), coverOf(false)...); !slices.Equal(destinations(got), sortedCopy(want)) {
		t.Fatalf("the cover is %v, want %v", destinations(got), want)
	}
	for _, r := range got {
		if !r.Cover {
			t.Errorf("%s is not marked a cover member", r.Destination)
		}
		if schema.HoldsUnspecified(r.Destination) {
			t.Errorf("%s holds its family's zero address", r.Destination)
		}
		if r.Destination.Addr().Is4() && r.Metric != 7 {
			t.Errorf("%s did not carry the default's metric: %+v", r.Destination, r)
		}
		if r.Destination.Addr().Is6() && r.Metric != defaultIPv6Metric {
			t.Errorf("%s did not carry the default's metric: %+v", r.Destination, r)
		}
	}
	for _, hole := range []string{"0.1.2.3", "1::1", "64:ff9b::c000:201"} {
		if slices.ContainsFunc(got, func(r Route) bool { return r.Destination.Contains(addr(hole)) }) {
			t.Errorf("a member holds %s, which the hole leaves on the host", hole)
		}
	}
}

func sortedCopy(in []string) []string {
	out := slices.Clone(in)
	slices.Sort(out)
	return out
}

// A hold at the default and a source-specific default stay what they are, and
// a table with no plain default is returned as it was.
func TestOnlyAPlainDefaultIsCovered(t *testing.T) {
	kept := []Route{
		{Destination: prefix("::/0"), Unreachable: true, Metric: holdMetric},
		{Destination: prefix("::/0"), Source: prefix("2001:db8::/32"), Metric: defaultIPv6Metric},
		{Destination: prefix("3fff:a::/36"), Metric: defaultIPv6Metric},
	}
	if got := coverDefaults(kept, nil); !slices.Equal(got, kept) {
		t.Errorf("routes with no plain default became %v", got)
	}
}

// A member is withheld where a route installed unscoped in its family, of
// length 1 up to the member's own, contains it, and only there.
func TestCoverWithholdsWhatALongerOrEqualUnscopedRouteHolds(t *testing.T) {
	scoped := prefix("2000::/3")
	scopes := func(r Route) bool { return !r.Cover && r.Destination == scoped }
	for _, test := range []struct {
		name    string
		route   Route
		without []string
		family  bool
	}{
		{"a lower half withholds every member it holds", Route{Destination: prefix("0.0.0.0/1")}, []string{"1.0.0.0/8", "2.0.0.0/7", "4.0.0.0/6", "8.0.0.0/5", "16.0.0.0/4", "32.0.0.0/3", "64.0.0.0/2"}, true},
		{"an upper half withholds its own member", Route{Destination: prefix("128.0.0.0/1")}, []string{"128.0.0.0/1"}, true},
		{"a route the member's own length withholds it", Route{Destination: prefix("4000::/2")}, []string{"4000::/2"}, false},
		{"a route between withholds the members inside it", Route{Destination: prefix("0.0.0.0/4")}, []string{"1.0.0.0/8", "2.0.0.0/7", "4.0.0.0/6", "8.0.0.0/5"}, true},
		{"a longer route withholds nothing", Route{Destination: prefix("1.0.0.0/16")}, nil, true},
		{"a scoped route withholds nothing", Route{Destination: scoped, Metric: defaultIPv6Metric}, nil, false},
		{"a hold withholds nothing", Route{Destination: prefix("64.0.0.0/2"), Unreachable: true}, nil, true},
		{"the other family withholds nothing", Route{Destination: prefix("::/1")}, nil, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			defaultRoute := Route{Destination: prefix("0.0.0.0/0")}
			if !test.family {
				defaultRoute = Route{Destination: prefix("::/0"), Metric: defaultIPv6Metric}
			}
			hold := func(r Route) bool { return scopes(r) || r.Unreachable }
			got := coverDefaults([]Route{test.route, defaultRoute}, hold)
			var members []Route
			for _, r := range got {
				if r.Cover {
					members = append(members, r)
				}
			}
			if want := coverOf(test.family, test.without...); !slices.Equal(destinations(members), want) {
				t.Errorf("the members are %v, want %v", destinations(members), want)
			}
			if !slices.Contains(got, test.route) {
				t.Errorf("%s itself left the table", test.route.Destination)
			}
		})
	}
}

// coveringKernel is the fake kernel on a platform that asks for the cover.
type coveringKernel struct{ *fakeKernel }

func (coveringKernel) covers() bool { return true }

func coveringHarness(t *testing.T, tbl Table, rt Runtime) (*Reconciler, *fakeKernel, func(netip.Prefix)) {
	t.Helper()
	reconciler, table, fake := harness(t, tbl, rt)
	reconciler.plat = coveringKernel{fake}
	return reconciler, fake, func(destination netip.Prefix) { table.Set(netip.Prefix{}, destination, nil) }
}

func coverHeld(fake *fakeKernel) (members int, defaults int) {
	for _, r := range fake.snapshot() {
		if r.Cover {
			members++
		}
		if r.Destination.Bits() == 0 {
			defaults++
		}
	}
	return members, defaults
}

// coverMembers counts the members of each family the fake kernel holds.
func coverMembers(fake *fakeKernel) (v4, v6 int) {
	for _, r := range fake.snapshot() {
		switch {
		case r.Cover && r.Destination.Addr().Is4():
			v4++
		case r.Cover:
			v6++
		}
	}
	return v4, v6
}

// The cover is gated as the default is: nothing before a session is live,
// every member once one is, all of them through the grace, and none after
// it. Its readiness is the host's own default, never the underlay's scoped
// one, and each change of a family's cover is one event.
func TestCoverIsInstalledAndWithdrawnWholeAcrossTheGate(t *testing.T) {
	live := 0
	bus := events.New()
	reconciler, fake, set := coveringHarness(t,
		Table{CaptureGrace: schema.Duration(10 * time.Second)},
		Runtime{Sessions: func() int { return live }, Events: bus})
	capture := &recordingCapture{fake: fake, hosts: Covered{V4: true, V6: true}}
	reconciler.rt.Capture = capture
	clock := start
	reconciler.now = func() time.Time { return clock }
	set(prefix("0.0.0.0/0"))
	set(prefix("::/0"))
	set(prefix("3fff:a::/36"))

	for _, step := range []struct {
		at      time.Duration
		live    int
		members int
	}{
		{0, 0, 0},
		{time.Second, 1, 16},
		{2 * time.Second, 0, 16},
		{10 * time.Second, 0, 16},
		{11 * time.Second, 0, 0},
		{12 * time.Second, 1, 16},
	} {
		clock, live = start.Add(step.at), step.live
		if err := reconciler.reconcile(); err != nil {
			t.Fatal(err)
		}
		members, defaults := coverHeld(fake)
		if members != step.members || defaults != 0 {
			t.Errorf("at %s with %d live the kernel holds %d members and %d defaults, want %d and none",
				step.at, step.live, members, defaults, step.members)
		}
		if !fake.has(Route{Destination: prefix("3fff:a::/36"), Metric: defaultIPv6Metric}) {
			t.Errorf("at %s an ordinary prefix was not installed", step.at)
		}
		want := []Family(nil)
		if step.members > 0 {
			want = []Family{FamilyIPv4, FamilyIPv6}
		}
		if got := reconciler.Stats().Cover; !slices.Equal(got, want) {
			t.Errorf("at %s the pass reports the cover %v, want %v", step.at, got, want)
		}
	}
	if slices.ContainsFunc(capture.at, func(s string) bool { return strings.HasPrefix(s, "asked") }) {
		t.Errorf("a cover asked the underlay for its scoped default: %v", capture.at)
	}
	var got []string
	for _, event := range bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "kernel.cover" }, 0) {
		got = append(got, event.Attrs["family"]+" "+event.Attrs["installed"])
	}
	want := []string{"ipv4 true", "ipv6 true", "ipv4 false", "ipv6 false", "ipv4 true", "ipv6 true"}
	if !slices.Equal(got, want) {
		t.Errorf("the cover events are %v, want %v", got, want)
	}
}

// A family whose host has no default of its own gets no cover, and the other
// family's is unaffected.
func TestCoverWaitsForTheHostsOwnDefaultOfItsFamily(t *testing.T) {
	reconciler, fake, set := coveringHarness(t, Table{}, Runtime{Sessions: func() int { return 1 }})
	capture := &recordingCapture{fake: fake, hosts: Covered{V4: true}}
	reconciler.rt.Capture = capture
	reconciler.now = func() time.Time { return start }
	set(prefix("0.0.0.0/0"))
	set(prefix("::/0"))
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if v4, v6 := coverMembers(fake); v4 != 8 || v6 != 0 {
		t.Errorf("the kernel holds %d IPv4 and %d IPv6 members, want 8 and none", v4, v6)
	}
}

// A member the kernel refuses, as it refuses 128.0.0.0/1 while a full-tunnel
// VPN holds that route, takes its family's whole cover out in the same pass
// and leaves the other family's alone. A pass while it stays refused installs
// nothing of that family, and once the kernel takes it the family goes in
// whole.
func TestRefusedMemberLeavesNoPartialCover(t *testing.T) {
	bus := events.New()
	reconciler, fake, set := coveringHarness(t, Table{}, Runtime{Sessions: func() int { return 1 }, Events: bus})
	reconciler.rt.Capture = &recordingCapture{fake: fake, hosts: Covered{V4: true, V6: true}}
	reconciler.now = func() time.Time { return start }
	refused := Route{Destination: prefix("128.0.0.0/1"), Cover: true}
	fake.failAdd[refused] = errRouteSkipped
	set(prefix("0.0.0.0/0"))
	set(prefix("::/0"))
	for pass := range 2 {
		adds, dels := fake.counts()
		if err := reconciler.reconcile(); err != nil {
			t.Fatal(err)
		}
		if v4, v6 := coverMembers(fake); v4 != 0 || v6 != 8 {
			t.Errorf("pass %d leaves %d IPv4 and %d IPv6 members, want none and 8", pass, v4, v6)
		}
		stats := reconciler.Stats()
		if !slices.Equal(stats.Cover, []Family{FamilyIPv6}) || stats.Skipped != 8 {
			t.Errorf("pass %d reports the cover %v with %d skipped, want IPv6 alone and the 8 IPv4 members skipped", pass, stats.Cover, stats.Skipped)
		}
		if nowAdds, nowDels := fake.counts(); pass == 1 && (nowAdds != adds || nowDels != dels) {
			t.Errorf("a pass with the member still refused added %d and deleted %d routes", nowAdds-adds, nowDels-dels)
		}
	}
	delete(fake.failAdd, refused)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if v4, _ := coverMembers(fake); v4 != 8 {
		t.Errorf("the IPv4 cover is %d members once the refusal ends, want 8", v4)
	}
	var got []string
	for _, event := range bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "kernel.cover" }, 0) {
		got = append(got, event.Attrs["family"]+" "+event.Attrs["installed"])
	}
	if want := []string{"ipv6 true", "ipv4 true"}; !slices.Equal(got, want) {
		t.Errorf("the cover events are %v, want %v", got, want)
	}
}

// A refusal takes out the members of its family that earlier passes
// installed as well as the ones its own pass added.
func TestRefusedMemberWithdrawsWhatEarlierPassesInstalled(t *testing.T) {
	reconciler, table, fake := harness(t, Table{}, Runtime{Sessions: func() int { return 1 }})
	reconciler.plat = coveringKernel{fake}
	reconciler.rt.Capture = &recordingCapture{fake: fake, hosts: Covered{V4: true}}
	reconciler.now = func() time.Time { return start }
	withholding := prefix("16.0.0.0/4")
	table.Set(netip.Prefix{}, prefix("0.0.0.0/0"), nil)
	table.Set(netip.Prefix{}, withholding, nil)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if v4, _ := coverMembers(fake); v4 != 7 {
		t.Fatalf("the cover beside %s is %d members, want the 7 it does not hold", withholding, v4)
	}
	table.Remove(netip.Prefix{}, withholding)
	fake.failAdd[Route{Destination: withholding, Cover: true}] = errRouteSkipped
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if v4, _ := coverMembers(fake); v4 != 0 {
		t.Errorf("the refusal left %d IPv4 members in, want none: %v", v4, fake.snapshot())
	}
	if stats := reconciler.Stats(); len(stats.Cover) != 0 || stats.Skipped != 8 {
		t.Errorf("the pass reports the cover %v with %d skipped, want none and the 8 members skipped", stats.Cover, stats.Skipped)
	}
}

// A member the kernel fails to take for any other reason takes its family's
// cover out the same way, and the pass reports the failure.
func TestFailedMemberLeavesNoPartialCover(t *testing.T) {
	reconciler, fake, set := coveringHarness(t, Table{}, Runtime{Sessions: func() int { return 1 }})
	reconciler.rt.Capture = &recordingCapture{fake: fake, hosts: Covered{V4: true}}
	reconciler.now = func() time.Time { return start }
	fake.failAdd[Route{Destination: prefix("128.0.0.0/1"), Cover: true}] = errors.New("no buffer space available")
	set(prefix("0.0.0.0/0"))
	if err := reconciler.reconcile(); err == nil {
		t.Fatal("a pass that could not install a member reported success")
	}
	if v4, _ := coverMembers(fake); v4 != 0 {
		t.Errorf("the failure left %d IPv4 members in, want none", v4)
	}
	if stats := reconciler.Stats(); len(stats.Cover) != 0 || stats.Skipped != 7 || stats.Err == "" {
		t.Errorf("the pass reports the cover %v with %d skipped and the error %q, want none, the other 7 skipped and the failure",
			stats.Cover, stats.Skipped, stats.Err)
	}
}

// Only a member takes its family's cover out, and only members go with it: a
// refused route outside the cover leaves its family's cover whole, and a
// route outside the cover stays while its family's cover goes.
func TestCoverRefusalStaysWithinTheCover(t *testing.T) {
	reconciler, fake, set := coveringHarness(t, Table{}, Runtime{Sessions: func() int { return 1 }})
	reconciler.rt.Capture = &recordingCapture{fake: fake, hosts: Covered{V4: true, V6: true}}
	reconciler.now = func() time.Time { return start }
	fake.failAdd[Route{Destination: prefix("128.0.0.0/1"), Cover: true}] = errRouteSkipped
	fake.failAdd[Route{Destination: prefix("2001:db8::/32"), Metric: defaultIPv6Metric}] = errRouteSkipped
	for _, destination := range []string{"0.0.0.0/0", "::/0", "198.51.100.0/24", "2001:db8::/32"} {
		set(prefix(destination))
	}
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if v4, v6 := coverMembers(fake); v4 != 0 || v6 != 8 {
		t.Errorf("the kernel holds %d IPv4 and %d IPv6 members, want none and 8", v4, v6)
	}
	if !fake.has(Route{Destination: prefix("198.51.100.0/24")}) {
		t.Error("a route outside the cover left with its family's cover")
	}
}

// The IPv6 twin of the refused IPv4 member: a refused 8000::/1, as wg-quick's
// IPv6 full tunnel holds it, takes the IPv6 cover out whole, leaves the IPv4
// cover whole, and moves nothing while it stays refused.
func TestRefusedIPv6MemberLeavesNoPartialCover(t *testing.T) {
	reconciler, fake, set := coveringHarness(t, Table{}, Runtime{Sessions: func() int { return 1 }})
	reconciler.rt.Capture = &recordingCapture{fake: fake, hosts: Covered{V4: true, V6: true}}
	reconciler.now = func() time.Time { return start }
	fake.failAdd[Route{Destination: prefix("8000::/1"), Metric: defaultIPv6Metric, Cover: true}] = errRouteSkipped
	set(prefix("0.0.0.0/0"))
	set(prefix("::/0"))
	for pass := range 2 {
		adds, dels := fake.counts()
		if err := reconciler.reconcile(); err != nil {
			t.Fatal(err)
		}
		if v4, v6 := coverMembers(fake); v4 != 8 || v6 != 0 {
			t.Errorf("pass %d leaves %d IPv4 and %d IPv6 members, want 8 and none", pass, v4, v6)
		}
		if stats := reconciler.Stats(); !slices.Equal(stats.Cover, []Family{FamilyIPv4}) || stats.Skipped != 8 {
			t.Errorf("pass %d reports the cover %v with %d skipped, want IPv4 alone and the 8 IPv6 members skipped", pass, stats.Cover, stats.Skipped)
		}
		if nowAdds, nowDels := fake.counts(); pass == 1 && (nowAdds != adds || nowDels != dels) {
			t.Errorf("a pass with the member still refused added %d and deleted %d routes", nowAdds-adds, nowDels-dels)
		}
	}
}

// keyKernel is the fake on a covering platform that keys a route by its
// destination alone, as darwin keys an unscoped route, so an add at a key it
// already holds is refused. Other programs hold some keys, so an add at one
// of them in taken fails with that key's error whatever route it carries, and
// an add at a key in flaky fails only for a route that is not a member. A
// delete of a member at a key in stuck fails. It records each add that failed
// and the key of each member whose delete failed.
type keyKernel struct {
	*fakeKernel
	taken, flaky, stuck map[netip.Prefix]error
	failed              []failedAdd
	kept                map[netip.Prefix]bool
}

type failedAdd struct {
	route Route
	err   error
}

func (*keyKernel) covers() bool { return true }

func (k *keyKernel) AddRoute(r Route) error {
	err := k.taken[r.Destination]
	if err == nil && !r.Cover {
		err = k.flaky[r.Destination]
	}
	if held, _ := heldAt(k.fakeKernel, r.Destination); err == nil && held {
		err = errRouteSkipped
	}
	if err != nil {
		k.failed = append(k.failed, failedAdd{r, err})
		return err
	}
	return k.fakeKernel.AddRoute(r)
}

func (k *keyKernel) DelRoute(r Route) error {
	if err := k.stuck[r.Destination]; err != nil && r.Cover {
		k.kept[r.Destination] = true
		return err
	}
	return k.fakeKernel.DelRoute(r)
}

func keyHarness(t *testing.T) (*Reconciler, *keyKernel, *netstack.RouteTable) {
	t.Helper()
	reconciler, table, fake := harness(t, Table{}, Runtime{Sessions: func() int { return 1 }})
	kernel := &keyKernel{fakeKernel: fake, taken: map[netip.Prefix]error{}, flaky: map[netip.Prefix]error{}, stuck: map[netip.Prefix]error{}, kept: map[netip.Prefix]bool{}}
	reconciler.plat = kernel
	reconciler.rt.Capture = &recordingCapture{fake: fake, covered: Covered{V4: true, V6: true}, hosts: Covered{V4: true, V6: true}}
	reconciler.now = func() time.Time { return start }
	return reconciler, kernel, table
}

// wantAllInstalled fails the test unless the last pass skipped nothing and
// installed every route it desired.
func wantAllInstalled(t *testing.T, reconciler *Reconciler, label string) {
	t.Helper()
	if stats := reconciler.Stats(); stats.Skipped != 0 || stats.Desired != stats.Installed {
		t.Errorf("%s reports %d skipped, %d desired and %d installed, want none skipped and every desired route installed",
			label, stats.Skipped, stats.Desired, stats.Installed)
	}
}

// heldAt reports whether the fake holds a route at destination, and whether
// that route is a member.
func heldAt(fake *fakeKernel, destination netip.Prefix) (held, member bool) {
	for _, r := range fake.snapshot() {
		if r.Destination == destination {
			return true, r.Cover
		}
	}
	return false, false
}

// longestHeld is the route an unbound lookup of a takes among what the fake
// holds, which the covering fakes install unscoped.
func longestHeld(fake *fakeKernel, a netip.Addr) (Route, bool) {
	var best Route
	found := false
	for _, r := range fake.snapshot() {
		if r.Destination.Contains(a) && (!found || r.Destination.Bits() > best.Destination.Bits()) {
			best, found = r, true
		}
	}
	return best, found
}

// A real upper half beside the default withholds the member at its own key.
// While another program holds that key, as a full-tunnel VPN holds
// 128.0.0.0/1 and 8000::/1, the real half is refused and so is the member it
// hands back, so the family's cover stays out whole rather than splitting the
// family between the mesh and that program. The member is tried right after
// the route, so no member sorting after it goes in only to be withdrawn. The
// other family is untouched, a pass while the key stays taken moves nothing,
// and once it is free the real route goes in with the rest of the cover
// around it.
func TestRefusedRouteAtAMemberKeyLeavesNoPartialCover(t *testing.T) {
	for _, test := range []struct {
		name               string
		upper, zero, other netip.Prefix
		family, kept       Family
	}{
		{"an IPv4 upper half", prefix("128.0.0.0/1"), prefix("0.0.0.0/0"), prefix("::/0"), FamilyIPv4, FamilyIPv6},
		{"an IPv6 upper half", prefix("8000::/1"), prefix("::/0"), prefix("0.0.0.0/0"), FamilyIPv6, FamilyIPv4},
		{"a route with members on both sides", prefix("64.0.0.0/2"), prefix("0.0.0.0/0"), prefix("::/0"), FamilyIPv4, FamilyIPv6},
	} {
		t.Run(test.name, func(t *testing.T) {
			reconciler, kernel, table := keyHarness(t)
			kernel.taken[test.upper] = errRouteSkipped
			for _, destination := range []netip.Prefix{test.zero, test.other, test.upper} {
				table.Set(netip.Prefix{}, destination, nil)
			}
			for pass := range 2 {
				adds, dels := kernel.counts()
				if err := reconciler.reconcile(); err != nil {
					t.Fatal(err)
				}
				v4, v6 := coverMembers(kernel.fakeKernel)
				members, kept := v4, v6
				if test.family == FamilyIPv6 {
					members, kept = v6, v4
				}
				if members != 0 || kept != 8 {
					t.Errorf("pass %d leaves %d members of %s beside the refused %s and %d of %s, want none and 8",
						pass, members, test.family, test.upper, kept, test.kept)
				}
				stats := reconciler.Stats()
				if !slices.Equal(stats.Cover, []Family{test.kept}) {
					t.Errorf("pass %d reports the cover %v, want %s alone", pass, stats.Cover, test.kept)
				}
				before := 0
				for _, member := range zeroFreeCover[test.family == FamilyIPv4] {
					if comparePrefixes(member, test.upper) < 0 {
						before++
					}
				}
				if pass == 0 && stats.Removed != before {
					t.Errorf("the first pass withdrew %d members, want the %d sorting before %s", stats.Removed, before, test.upper)
				}
				if nowAdds, nowDels := kernel.counts(); pass == 1 && (nowAdds != adds || nowDels != dels) {
					t.Errorf("a pass with %s still taken added %d and deleted %d routes", test.upper, nowAdds-adds, nowDels-dels)
				}
			}
			delete(kernel.taken, test.upper)
			if err := reconciler.reconcile(); err != nil {
				t.Fatal(err)
			}
			v4, v6 := coverMembers(kernel.fakeKernel)
			members := v4
			if test.family == FamilyIPv6 {
				members = v6
			}
			if held, member := heldAt(kernel.fakeKernel, test.upper); !held || member || members != 7 {
				t.Errorf("once %s is free the kernel holds it %v as a member %v beside %d members, want the real route beside 7",
					test.upper, held, member, members)
			}
		})
	}
}

// A withholding route the kernel fails to take for a reason that may pass
// hands its members back in the same pass, so its range stays in the tun as
// the plain default would carry it, and the pass reports the failure. Once
// the route goes in, the members it withholds leave.
func TestFailedWithholdingRouteHandsItsMembersBack(t *testing.T) {
	reconciler, kernel, table := keyHarness(t)
	withholding := prefix("64.0.0.0/2")
	kernel.flaky[withholding] = errors.New("no buffer space available")
	table.Set(netip.Prefix{}, prefix("0.0.0.0/0"), nil)
	table.Set(netip.Prefix{}, withholding, nil)
	if err := reconciler.reconcile(); err == nil {
		t.Fatal("a pass that could not install a route reported success")
	}
	if got, ok := longestHeld(kernel.fakeKernel, addr("100.64.0.1")); !ok || got.Destination != withholding || !got.Cover {
		t.Errorf("100.64.0.1 takes %v (found %v) with %s failed, want its member", got, ok, withholding)
	}
	if v4, _ := coverMembers(kernel.fakeKernel); v4 != 8 {
		t.Errorf("the IPv4 cover is %d members beside the failed %s, want 8", v4, withholding)
	}
	stats := reconciler.Stats()
	if !slices.Equal(stats.Cover, []Family{FamilyIPv4}) {
		t.Errorf("the pass reports the cover %v, want IPv4", stats.Cover)
	}
	if stats.Desired != 9 || stats.Installed != 8 {
		t.Errorf("the pass reports %d desired and %d installed, want every member and the failed route against the members", stats.Desired, stats.Installed)
	}
	delete(kernel.flaky, withholding)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if held, member := heldAt(kernel.fakeKernel, withholding); !held || member {
		t.Errorf("once it goes in, the kernel holds %s %v as a member %v, want the real route", withholding, held, member)
	}
	if v4, _ := coverMembers(kernel.fakeKernel); v4 != 7 {
		t.Errorf("the IPv4 cover is %d members beside %s, want 7", v4, withholding)
	}
	if stats := reconciler.Stats(); stats.Desired != 8 || stats.Installed != 8 {
		t.Errorf("the pass reports %d desired and %d installed, want 8 and 8", stats.Desired, stats.Installed)
	}
}

// A refused route that goes in while the members it withholds are still to
// be added leaves them out, and none of them counts as desired.
func TestRefusedRouteThatGoesInCountsNoMemberItWithholds(t *testing.T) {
	reconciler, kernel, table := keyHarness(t)
	lower := prefix("0.0.0.0/1")
	kernel.taken[lower] = errRouteSkipped
	table.Set(netip.Prefix{}, lower, nil)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	delete(kernel.taken, lower)
	table.Set(netip.Prefix{}, prefix("0.0.0.0/0"), nil)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if v4, _ := coverMembers(kernel.fakeKernel); v4 != 1 || !kernel.has(Route{Destination: lower}) {
		t.Errorf("once %s goes in the kernel holds %d IPv4 members, want the upper one alone: %v", lower, v4, kernel.snapshot())
	}
	if stats := reconciler.Stats(); stats.Desired != 2 || stats.Installed != 2 || stats.Skipped != 0 {
		t.Errorf("the pass reports %d desired, %d installed and %d skipped, want 2, 2 and 0", stats.Desired, stats.Installed, stats.Skipped)
	}
}

// A real route refused at the key of a member this process holds takes the
// key on the next pass whose delete of the member works. Until then the
// member stays, its family whole, and each pass reports the failed delete.
func TestRealRouteTakesItsKeyOnceTheMembersDeleteWorks(t *testing.T) {
	reconciler, kernel, table := keyHarness(t)
	upper := prefix("128.0.0.0/1")
	table.Set(netip.Prefix{}, prefix("0.0.0.0/0"), nil)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	var member Route
	for _, r := range kernel.snapshot() {
		if r.Destination == upper {
			member = r
		}
	}
	if !member.Cover {
		t.Fatalf("no member at %s: %v", upper, kernel.snapshot())
	}
	kernel.stuck[upper] = errors.New("no buffer space available")
	table.Set(netip.Prefix{}, upper, nil)
	for pass := range 2 {
		if err := reconciler.reconcile(); err == nil {
			t.Errorf("pass %d that could not delete %s reported success", pass, member)
		}
		if v4, _ := coverMembers(kernel.fakeKernel); v4 != 8 {
			t.Errorf("pass %d leaves %d IPv4 members with the delete of %s failing, want 8", pass, v4, member)
		}
		if got := reconciler.Stats().Cover; !slices.Equal(got, []Family{FamilyIPv4}) {
			t.Errorf("pass %d reports the cover %v, want IPv4", pass, got)
		}
	}
	delete(kernel.stuck, upper)
	adds, dels := kernel.counts()
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if nowAdds, nowDels := kernel.counts(); nowAdds-adds != 1 || nowDels-dels != 1 {
		t.Errorf("the pass whose delete works added %d and deleted %d routes, want 1 and 1", nowAdds-adds, nowDels-dels)
	}
	if held, isMember := heldAt(kernel.fakeKernel, upper); !held || isMember {
		t.Errorf("once the delete works the kernel holds %s %v as a member %v, want the real route", upper, held, isMember)
	}
	wantAllInstalled(t, reconciler, "the pass whose delete works")
}

// releasingKernel frees a taken key right after the first add there fails,
// as another program withdrawing between two writes of one pass would.
type releasingKernel struct {
	*keyKernel
}

func (k *releasingKernel) AddRoute(r Route) error {
	_, was := k.taken[r.Destination]
	err := k.keyKernel.AddRoute(r)
	if was {
		delete(k.taken, r.Destination)
	}
	return err
}

// A real route refused while another program holds its key, which frees
// before the member handed back goes in, takes the key from that member on
// the next pass. TestDarwinRealRouteTakesItsKeyAfterARace holds the same on
// darwin's own record of refused keys, which this fake does not keep.
func TestRealRouteTakesItsKeyAfterARaceWithAnotherWriter(t *testing.T) {
	reconciler, kernel, table := keyHarness(t)
	upper := prefix("128.0.0.0/1")
	kernel.taken[upper] = errRouteSkipped
	reconciler.plat = &releasingKernel{kernel}
	table.Set(netip.Prefix{}, prefix("0.0.0.0/0"), nil)
	table.Set(netip.Prefix{}, upper, nil)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if held, member := heldAt(kernel.fakeKernel, upper); !held || !member {
		t.Fatalf("the race leaves %s held %v as a member %v, want the member handed back", upper, held, member)
	}
	for pass := range 2 {
		if err := reconciler.reconcile(); err != nil {
			t.Fatal(err)
		}
		if held, member := heldAt(kernel.fakeKernel, upper); !held || member {
			t.Errorf("pass %d after the race holds %s %v as a member %v, want the real route", pass, upper, held, member)
		}
		wantAllInstalled(t, reconciler, fmt.Sprintf("pass %d after the race", pass))
	}
}

// A route refused against a route of this process that is not a member, an
// old one at its key, takes no key from the members it would withhold. When
// the old route leaves and another program takes the key at once, a member
// still in stays rather than leaving to be handed back in the same pass.
func TestRouteRefusedAgainstAnOldRouteOfOursKeepsItsMembers(t *testing.T) {
	reconciler, kernel, table := keyHarness(t)
	lower, inside := prefix("0.0.0.0/1"), prefix("64.0.0.0/2")
	table.Set(netip.Prefix{}, prefix("0.0.0.0/0"), nil)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	old := Route{Destination: lower, Metric: 7}
	kernel.routes[old] = true
	kernel.failDel[old] = errors.New("no buffer space available")
	kernel.stuck[inside] = errors.New("no buffer space available")
	table.Set(netip.Prefix{}, lower, nil)
	if err := reconciler.reconcile(); err == nil {
		t.Fatal("a pass that could not delete its old route reported success")
	}
	if held, member := heldAt(kernel.fakeKernel, inside); !held || !member {
		t.Fatalf("the pass with %s refused leaves %s held %v as a member %v, want the member whose delete failed", lower, inside, held, member)
	}
	delete(kernel.failDel, old)
	delete(kernel.stuck, inside)
	kernel.taken[lower] = errRouteSkipped
	_, dels := kernel.counts()
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if _, nowDels := kernel.counts(); nowDels-dels != 1 || kernel.has(old) {
		t.Errorf("the pass that took %s out deleted %d routes, want that one alone: %v", old, nowDels-dels, kernel.snapshot())
	}
	if v4, _ := coverMembers(kernel.fakeKernel); v4 != 8 {
		t.Errorf("the pass holds %d IPv4 members beside the refused %s, want 8", v4, lower)
	}
}

// A withholding route refused at a key no member has, as a VPN holds
// 0.0.0.0/1, hands its members back and they go in, since the range then
// leaves through the mesh as the plain default's would. While it stays
// refused the next pass tries it first and moves nothing, and once the kernel
// takes it the members it withholds leave in that pass.
func TestRefusedWithholdingRouteMovesNothingWhileRefused(t *testing.T) {
	reconciler, kernel, table := keyHarness(t)
	lower := prefix("0.0.0.0/1")
	kernel.taken[lower] = errRouteSkipped
	table.Set(netip.Prefix{}, prefix("0.0.0.0/0"), nil)
	table.Set(netip.Prefix{}, lower, nil)
	for pass := range 2 {
		adds, dels := kernel.counts()
		if err := reconciler.reconcile(); err != nil {
			t.Fatal(err)
		}
		if v4, _ := coverMembers(kernel.fakeKernel); v4 != 8 {
			t.Errorf("pass %d holds %d IPv4 members beside the refused %s, want 8", pass, v4, lower)
		}
		if stats := reconciler.Stats(); !slices.Equal(stats.Cover, []Family{FamilyIPv4}) || stats.Skipped != 1 {
			t.Errorf("pass %d reports the cover %v with %d skipped, want IPv4 and the refused route", pass, stats.Cover, stats.Skipped)
		}
		if nowAdds, nowDels := kernel.counts(); pass == 1 && (nowAdds != adds || nowDels != dels) {
			t.Errorf("a pass with %s still refused added %d and deleted %d routes", lower, nowAdds-adds, nowDels-dels)
		}
	}
	delete(kernel.taken, lower)
	adds, dels := kernel.counts()
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if v4, _ := coverMembers(kernel.fakeKernel); v4 != 1 || !kernel.has(Route{Destination: lower}) {
		t.Errorf("once %s goes in the kernel holds %d IPv4 members, want the upper one alone: %v", lower, v4, kernel.snapshot())
	}
	if nowAdds, nowDels := kernel.counts(); nowAdds-adds != 1 || nowDels-dels != 7 {
		t.Errorf("the pass that took %s added %d and deleted %d routes, want 1 and 7", lower, nowAdds-adds, nowDels-dels)
	}
	if stats := reconciler.Stats(); stats.Desired != 2 || stats.Installed != 2 {
		t.Errorf("the pass reports %d desired and %d installed, want 2 and 2", stats.Desired, stats.Installed)
	}
}

// coverPass is one pass's table, the host's own defaults and the keys other
// programs refuse.
type coverPass struct {
	routes []string
	hosts  Covered
	taken  []string
}

// A member a route the kernel holds after the pass withholds is not wanted,
// so it counts neither as desired nor as skipped when a refusal at another
// member takes its family out. The route went in this pass after a refusal
// in the last, and the member is either one the pass would add or one an
// earlier pass installed in that route's place.
func TestWithheldMemberIsNotSkippedWithItsFamily(t *testing.T) {
	v4 := []string{"0.0.0.0/1", "128.0.0.0/1", "64.0.0.0/2", "0.0.0.0/4", "16.0.0.0/4", "1.0.0.0/16", "198.51.100.0/24"}
	v6 := []string{"8000::/1", "2000::/3", "4000::/2", "2001:db8::/32"}
	without := func(routes []string, gone ...string) []string {
		return slices.DeleteFunc(slices.Clone(routes), func(r string) bool { return slices.Contains(gone, r) })
	}
	for _, test := range []struct {
		name    string
		passes  []coverPass
		skipped int
	}{
		{
			"IPv6 member the pass would add",
			[]coverPass{
				{slices.Concat(v4, []string{"::/1"}, v6), Covered{}, []string{"8000::/1"}},
				{slices.Concat([]string{"::/0"}, v4, v6), Covered{V6: true}, []string{"1.0.0.0/8", "100::/8"}},
			},
			5,
		},
		{
			"IPv6 member the pass would add a pass later",
			[]coverPass{
				{slices.Concat(v4, []string{"::/1"}, without(v6, "8000::/1")), Covered{}, nil},
				{slices.Concat(v4, []string{"::/1"}, v6), Covered{}, []string{"8000::/1"}},
				{slices.Concat([]string{"::/0"}, v4, v6), Covered{V6: true}, []string{"100::/8"}},
			},
			5,
		},
		{
			"IPv6 member beside a member refused with its route",
			[]coverPass{
				{slices.Concat([]string{"::/0", "0.0.0.0/1", "::/1"}, v6), Covered{V6: true}, []string{"2000::/3", "8000::/1"}},
				{slices.Concat([]string{"::/0"}, v4, v6), Covered{V6: true}, []string{"8000::/1"}},
			},
			7,
		},
		{
			"IPv4 member an earlier pass installed",
			[]coverPass{
				{[]string{"0.0.0.0/0", "0.0.0.0/4", "128.0.0.0/1"}, Covered{V4: true}, []string{"0.0.0.0/4"}},
				{[]string{"0.0.0.0/0", "0.0.0.0/4"}, Covered{V4: true}, []string{"128.0.0.0/1"}},
			},
			4,
		},
		{
			"IPv4 member the pass would add",
			[]coverPass{
				{slices.Concat(without(v4, "128.0.0.0/1"), []string{"::/1"}, v6), Covered{}, nil},
				{slices.Concat(v4, []string{"::/1"}, v6), Covered{}, []string{"128.0.0.0/1"}},
				{slices.Concat([]string{"0.0.0.0/0"}, without(v4, "0.0.0.0/1"), []string{"::/1"}, v6), Covered{V4: true}, []string{"32.0.0.0/3"}},
			},
			1,
		},
		{
			"IPv4 member beside a refused route that hands one back",
			[]coverPass{
				{slices.Concat(without(v4, "16.0.0.0/4"), []string{"::/1"}, v6), Covered{}, []string{"64.0.0.0/2"}},
				{slices.Concat([]string{"0.0.0.0/0"}, without(v4, "0.0.0.0/1"), []string{"::/1"}, v6), Covered{V4: true}, []string{"16.0.0.0/4"}},
			},
			3,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			reconciler, kernel, table := keyHarness(t)
			capture := reconciler.rt.Capture.(*recordingCapture)
			var last []string
			for pass, step := range test.passes {
				for _, destination := range last {
					table.Remove(netip.Prefix{}, prefix(destination))
				}
				for _, destination := range step.routes {
					table.Set(netip.Prefix{}, prefix(destination), nil)
				}
				capture.hosts = step.hosts
				kernel.taken = map[netip.Prefix]error{}
				for _, destination := range step.taken {
					kernel.taken[prefix(destination)] = errRouteSkipped
				}
				if err := reconciler.reconcile(); err != nil {
					t.Fatalf("pass %d: %v", pass, err)
				}
				last = step.routes
			}
			pass := len(test.passes) - 1
			if v4, v6 := coverMembers(kernel.fakeKernel); v4 != 0 || v6 != 0 {
				t.Errorf("pass %d leaves %d IPv4 and %d IPv6 members, want none", pass, v4, v6)
			}
			stats := reconciler.Stats()
			if stats.Skipped != test.skipped {
				t.Errorf("pass %d reports %d skipped, want %d", pass, stats.Skipped, test.skipped)
			}
			if stats.Desired != stats.Installed+stats.Skipped {
				t.Errorf("pass %d reports %d desired, %d installed and %d skipped, want desired to be the other two",
					pass, stats.Desired, stats.Installed, stats.Skipped)
			}
		})
	}
}

// A route over the zero address still needs the underlay's own default,
// beside a cover that does not.
func TestCaptureBesideTheCoverStillAsksTheUnderlay(t *testing.T) {
	reconciler, fake, set := coveringHarness(t, Table{}, Runtime{Sessions: func() int { return 1 }})
	capture := &recordingCapture{fake: fake, hosts: Covered{V4: true, V6: true}}
	reconciler.rt.Capture = capture
	reconciler.now = func() time.Time { return start }
	set(prefix("0.0.0.0/0"))
	set(prefix("::/0"))
	set(prefix("0.0.0.0/24"))
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if fake.has(Route{Destination: prefix("0.0.0.0/24")}) {
		t.Error("a route holding the zero address installed with the underlay uncovered")
	}
	if members, _ := coverHeld(fake); members != 16 {
		t.Errorf("the cover is %d members beside an uncovered capture, want 16", members)
	}
	// the family of the capture alone, since the covers need nothing of it
	if want := []Covered{{V4: true}}; !slices.Equal(capture.wants, want) {
		t.Errorf("the underlay was asked to cover %v, want %v", capture.wants, want)
	}
}

// scopingCoveringKernel is the fake on a platform that asks for the cover and
// scopes what darwin scopes under a bound underlay with no endpoint inside the
// mesh's routes: a hold, and a route from a source.
type scopingCoveringKernel struct{ *fakeKernel }

func (scopingCoveringKernel) covers() bool { return true }

func (scopingCoveringKernel) scopes(r Route) bool {
	return !r.Cover && (r.Unreachable || r.Source.IsValid())
}

// A route the platform scopes takes none of the machine's unscoped lookups, so
// it withholds no member, neither in the pass that installs both nor in a
// later one that finds both held.
func TestScopedRouteWithholdsNoMember(t *testing.T) {
	reconciler, table, fake := harness(t, Table{}, Runtime{Sessions: func() int { return 1 }})
	reconciler.plat = scopingCoveringKernel{fake}
	reconciler.rt.Capture = &recordingCapture{fake: fake, hosts: Covered{V4: true, V6: true}}
	reconciler.now = func() time.Time { return start }
	table.Set(netip.Prefix{}, prefix("::/0"), nil)
	table.Set(prefix("2001:db8:bb::/48"), prefix("2000::/3"), nil)
	for pass := range 2 {
		if err := reconciler.reconcile(); err != nil {
			t.Fatal(err)
		}
		if _, v6 := coverMembers(fake); v6 != 8 {
			t.Errorf("pass %d holds %d IPv6 members beside a scoped 2000::/3 from a source, want 8: %v", pass, v6, fake.snapshot())
		}
	}
}

// A capture the platform scopes takes none of the machine's unscoped lookups:
// a default from a source asks the underlay for nothing and goes in with the
// underlay uncovered. The hold Babel keeps at a retracted default stays out of
// the kernel, scoped or not.
func TestScopedCaptureAsksTheUnderlayForNothingAndAHeldDefaultStaysOut(t *testing.T) {
	reconciler, table, fake := harness(t, Table{}, Runtime{Sessions: func() int { return 1 }})
	reconciler.plat = scopingCoveringKernel{fake}
	capture := &recordingCapture{fake: fake, hosts: Covered{V4: true, V6: true}}
	reconciler.rt.Capture = capture
	reconciler.now = func() time.Time { return start }
	table.Set(netip.Prefix{}, prefix("0.0.0.0/0"), netstack.Unreachable)
	table.Set(prefix("2001:db8:bb::/48"), prefix("::/0"), nil)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(capture.wants, func(want Covered) bool { return want != (Covered{}) }) {
		t.Errorf("a scoped capture asked the underlay to cover %v", capture.wants)
	}
	sourced := Route{Destination: prefix("::/0"), Source: prefix("2001:db8:bb::/48"), Metric: defaultIPv6Metric}
	if got := fake.snapshot(); !slices.Equal(got, []Route{sourced}) {
		t.Errorf("installed %v, want only %+v", got, sourced)
	}
}
