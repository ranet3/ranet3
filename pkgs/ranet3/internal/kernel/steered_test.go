// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build (linux && !android) || (darwin && !ios)

package kernel

import (
	"context"
	"maps"
	"net/netip"
	"reflect"
	"slices"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/schema"
)

var (
	steeredOverlay = prefixes(prefix("192.0.2.0/24"), prefix("3fff::/20"))
	steeredSource  = addr("3fff::1")
	waypointSID    = addr("3fff:7::1")
	exitSID        = addr("3fff:8::46")
	ownSID         = addr("3fff:9::9")
	meshSubnet     = Route{Destination: prefix("198.51.100.0/24")}
)

// modeThree is cap.table in mode 3 along via, sent from steeredSource
func modeThree(via ...netip.Addr) Table {
	mode := &ExitMode{}
	for _, sid := range via {
		mode.Via = append(mode.Via, schema.AddrFrom(sid))
	}
	return Table{}.WithMode(mode).WithPathSource(steeredSource)
}

// steered is mode 3's two defaults as the kernel holds them
func steered() []Route {
	return []Route{{Destination: prefix("0.0.0.0/0")}, {Destination: prefix("::/0"), Metric: defaultIPv6Metric}}
}

// countedHeld is every route the fake holds that counts as a default with the overlay, sorted
func countedHeld(f *fakeKernel, overlay []schema.Prefix) []Route {
	return slices.DeleteFunc(f.snapshot(), func(route Route) bool { return !schema.CapturesTheMachine(route.Destination, overlay) })
}

// learnedDefaults is another exit's routes that count, plain and source-specific, a /1 pair among them
func learnedDefaults() []mirrorEntry {
	return []mirrorEntry{
		{destination: prefix("0.0.0.0/1"), value: learned},
		{destination: prefix("128.0.0.0/1"), value: learned},
		{destination: prefix("::/0"), value: learned},
		{source: prefix("3fff::/20"), destination: prefix("::/0"), value: learned},
	}
}

// host is a SID's /128 as the node serving it originates it, held by value
func host(sid netip.Addr, value *netstack.Peer) mirrorEntry {
	return mirrorEntry{destination: netip.PrefixFrom(sid, 128), value: value}
}

// Mode 3 installs its two defaults, and no route that counts, exactly while
// every SID of via resolves to a peer through its own /128, or for a SID after
// the first to this node, and the mesh holds a live session
func TestSteeredDefaultsStandWhileEverySegmentResolves(t *testing.T) {
	both := []mirrorEntry{host(waypointSID, learned), host(exitSID, learned)}
	for name, c := range map[string]struct {
		via     []netip.Addr
		entries []mirrorEntry
		shut    bool
		up      bool
	}{
		"no segment routed, no default":                        {},
		"no segment routed, under another exit's default":      {entries: learnedDefaults()},
		"the first segment alone":                              {entries: append(learnedDefaults(), host(waypointSID, learned))},
		"the exit's segment alone":                             {entries: append(learnedDefaults(), host(exitSID, learned))},
		"every segment routed":                                 {entries: append(learnedDefaults(), both...), up: true},
		"every segment routed, no default learned":             {entries: both, up: true},
		"every segment routed, no live session":                {entries: append(learnedDefaults(), both...), shut: true},
		"the exit's segment held":                              {entries: append(learnedDefaults(), host(waypointSID, learned), host(exitSID, netstack.Unreachable))},
		"the exit's segment under a held 2000::/3":             {entries: []mirrorEntry{host(waypointSID, learned), {destination: prefix("2000::/3"), value: netstack.Unreachable}}},
		"the exit's segment under a learned 3000::/4 alone":    {entries: []mirrorEntry{host(waypointSID, learned), {destination: prefix("3000::/4"), value: learned}}},
		"the waypoint's segment under an overlay subnet alone": {entries: []mirrorEntry{{destination: prefix("3fff:7::/48"), value: learned}, host(exitSID, learned)}},
		"the exit's segment through its /128 from the path's source": {
			entries: []mirrorEntry{host(waypointSID, learned), {source: prefix("3fff::/48"), destination: netip.PrefixFrom(exitSID, 128), value: learned}}, up: true,
		},
		"the exit's segment through its /128 from another source": {
			entries: []mirrorEntry{host(waypointSID, learned), {source: prefix("3fff:1::/48"), destination: netip.PrefixFrom(exitSID, 128), value: learned}},
		},
		"a later segment this node's own": {
			via: []netip.Addr{waypointSID, ownSID, exitSID}, entries: append(both, host(ownSID, netstack.Local)), up: true,
		},
		"the first segment this node's own": {
			via: []netip.Addr{ownSID, exitSID}, entries: []mirrorEntry{host(ownSID, netstack.Local), host(exitSID, learned)},
		},
	} {
		via := c.via
		if via == nil {
			via = []netip.Addr{waypointSID, exitSID}
		}
		live := 1
		if c.shut {
			live = 0
		}
		reconciler, table, fake := harness(t, modeThree(via...), Runtime{Overlay: steeredOverlay, Sessions: func() int { return live }})
		reconciler.now = func() time.Time { return start }
		table.Set(netip.Prefix{}, meshSubnet.Destination, learned)
		for _, entry := range c.entries {
			table.Set(entry.source, entry.destination, entry.value)
		}
		if err := reconciler.reconcile(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var want []Route
		if c.up {
			want = steered()
		}
		if got := countedHeld(fake, steeredOverlay); !slices.Equal(got, want) {
			t.Errorf("%s: the routes that count are %v, want %v", name, got, want)
		}
		if !fake.has(meshSubnet) {
			t.Errorf("%s: the mesh's subnet went with the defaults", name)
		}
	}
}

// A SID of via that only another node's subnet covers, a route counting as no
// default, keeps the steered defaults out, the path down at it with no route of
// its own, since the subnet's node and not the exit via names would take the
// host's traffic, for a SID outside the overlay and one inside, first or later.
// The SID's /128 beside the subnet brings them in.
func TestSteeredDefaultsStayOutWhileASegmentHasNoRouteOfItsOwn(t *testing.T) {
	outside := addr("2001:db8:0:6::3")
	for _, c := range []struct {
		via    []netip.Addr
		subnet netip.Prefix
	}{
		{[]netip.Addr{outside}, prefix("2001:db8:0:6::/64")},
		{[]netip.Addr{exitSID}, prefix("3fff:8::/48")},
		{[]netip.Addr{waypointSID, outside}, prefix("2001:db8:0:6::/64")},
	} {
		sid := c.via[len(c.via)-1]
		for _, own := range []bool{false, true} {
			reconciler, table, fake := harness(t, modeThree(c.via...), Runtime{Overlay: steeredOverlay})
			reconciler.now = func() time.Time { return start }
			for _, entry := range append(learnedDefaults(), host(waypointSID, learned)) {
				table.Set(entry.source, entry.destination, entry.value)
			}
			table.Set(netip.Prefix{}, c.subnet, learned)
			if own {
				table.Set(netip.Prefix{}, netip.PrefixFrom(sid, 128), learned)
			}
			if err := reconciler.reconcile(); err != nil {
				t.Fatal(err)
			}
			var want []Route
			if own {
				want = steered()
			}
			if got := countedHeld(fake, steeredOverlay); !slices.Equal(got, want) {
				t.Errorf("along %v under %s, the SID's own route %v: the routes that count are %v, want %v", c.via, c.subnet, own, got, want)
			}
			path := reconciler.Stats().Path
			if !own && (path.Down != sid || path.Verdict != "no route of its own") || own && path.Down.IsValid() {
				t.Errorf("along %v under %s, the SID's own route %v: the path reads down at %v, %q", c.via, c.subnet, own, path.Down, path.Verdict)
			}
		}
	}
}

// One reconciler follows the path from pass to pass: the defaults go with the
// exit's SID and come back with it, the waypoint's the same
func TestSteeredDefaultsFollowTheSegmentsFromPassToPass(t *testing.T) {
	reconciler, table, fake := harness(t, modeThree(waypointSID, exitSID), Runtime{Overlay: steeredOverlay})
	for _, entry := range learnedDefaults() {
		table.Set(entry.source, entry.destination, entry.value)
	}
	pass := func(step string, want []Route) {
		t.Helper()
		if err := reconciler.reconcile(); err != nil {
			t.Fatalf("%s: %v", step, err)
		}
		if got := countedHeld(fake, steeredOverlay); !slices.Equal(got, want) {
			t.Errorf("%s: the routes that count are %v, want %v", step, got, want)
		}
	}
	pass("no segment routed", nil)
	table.Set(netip.Prefix{}, netip.PrefixFrom(waypointSID, 128), learned)
	table.Set(netip.Prefix{}, netip.PrefixFrom(exitSID, 128), learned)
	pass("both segments routed", steered())
	table.Set(netip.Prefix{}, netip.PrefixFrom(exitSID, 128), netstack.Unreachable)
	pass("the exit's segment retracted and held", nil)
	table.Remove(netip.Prefix{}, netip.PrefixFrom(exitSID, 128))
	pass("the exit's hold flushed, another exit's default left", nil)
	table.Set(netip.Prefix{}, netip.PrefixFrom(exitSID, 128), learned)
	pass("the exit's segment back", steered())
	table.Remove(netip.Prefix{}, netip.PrefixFrom(waypointSID, 128))
	pass("the waypoint's segment gone", nil)
	table.Set(netip.Prefix{}, netip.PrefixFrom(waypointSID, 128), learned)
	pass("the waypoint's segment back", steered())
}

// Mode 3 is mode 2 family by family, so with its path up and with it down it
// selects for main a carved lease's address and network as mode 2 does
func TestModeThreeSelectsACarvedLeaseForMainAsModeTwoDoes(t *testing.T) {
	overlay := prefixes(prefix("192.0.2.0/24"), prefix("3fff::/20"))
	network := NetworkState{IPv4: NetworkFamily{Links: []Link{
		{Name: "eth0", Prefixes: []netip.Prefix{prefix("192.0.2.10/24")}},
		{Name: Loopback, Prefixes: []netip.Prefix{prefix("192.0.2.200/32"), prefix("192.0.2.1/32")}},
	}}}
	selected := func(table Table, routed bool) []Rule {
		reconciler, routes, _ := harness(t, table, Runtime{Overlay: overlay, Network: func() NetworkState { return network }})
		routes.Set(netip.Prefix{}, prefix("192.0.2.200/32"), netstack.Assigned)
		routes.Set(netip.Prefix{}, prefix("192.0.2.1/32"), netstack.Local)
		routes.Set(netip.Prefix{}, prefix("0.0.0.0/0"), learned)
		if routed {
			routes.Set(netip.Prefix{}, netip.PrefixFrom(exitSID, 128), learned)
		}
		exit, _ := reconciler.exitPass([]netip.Prefix{prefix("192.0.2.200/32")}, routes.Snapshot(), reconciler.readNetwork())
		var out []Rule
		for _, rule := range derivedRules(DefaultTable, overlay, nil, exit) {
			if rule.Priority == priorityUplinkSource || rule.Priority == priorityLinkSource {
				out = append(out, rule)
			}
		}
		return out
	}
	two := selected(Table{}.WithMode(&ExitMode{}), false)
	if len(two) != 2 {
		t.Fatalf("mode 2 selects %v for main, not the lease's address and network, so this proves nothing of mode 3", two)
	}
	for _, up := range []bool{true, false} {
		if three := selected(modeThree(exitSID), up); !reflect.DeepEqual(three, two) {
			t.Errorf("mode 3 with its path up %v selects for main\n%v\nwhere mode 2 selects\n%v", up, three, two)
		}
	}
}

// A running reconciler wakes on a change of the exit's SID's own /128 alone,
// through the channel the route table gives it, and the steered defaults
// follow the SID routed, held, routed again and gone
func TestSteeredDefaultsFollowTheSegmentAsTheReconcilerRuns(t *testing.T) {
	reconciler, table, fake := harness(t, modeThree(exitSID), Runtime{Overlay: steeredOverlay})
	for _, entry := range learnedDefaults() {
		table.Set(entry.source, entry.destination, entry.value)
	}
	sid := netip.PrefixFrom(exitSID, 128)
	table.Set(netip.Prefix{}, sid, learned)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- reconciler.Run(ctx) }()
	holds := func(want []Route) func() bool {
		return func() bool { return slices.Equal(countedHeld(fake, steeredOverlay), want) }
	}
	waitFor(t, holds(steered()))
	table.Set(netip.Prefix{}, sid, netstack.Unreachable)
	waitFor(t, holds(nil))
	table.Set(netip.Prefix{}, sid, learned)
	waitFor(t, holds(steered()))
	table.Remove(netip.Prefix{}, sid)
	waitFor(t, holds(nil))
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("run: %v", err)
	}
}

// A reload from mode 2 under fallback = "none" to mode 3, whose fallback is
// "none" where unwritten, and back applies in the one pass after it: mode 3
// holds the steered defaults in place of every route that counts, mode 2 the
// learned routes again, and the rules and the switch's chains stay mode 2's
// throughout
func TestReloadBetweenModesTwoAndThreeTakesOnePass(t *testing.T) {
	two := Table{}.WithMode(&ExitMode{Fallback: FallbackNone})
	reconciler, table, fake := harness(t, two, Runtime{Overlay: steeredOverlay, Sessions: func() int { return 1 }})
	for _, entry := range append(learnedDefaults(), host(waypointSID, learned), host(exitSID, learned)) {
		table.Set(entry.source, entry.destination, entry.value)
	}
	learnedRoutes := []Route{
		{Destination: prefix("0.0.0.0/1")},
		{Destination: prefix("128.0.0.0/1")},
		{Destination: prefix("::/0"), Metric: defaultIPv6Metric},
		{Destination: prefix("::/0"), Source: prefix("3fff::/20"), Metric: defaultIPv6Metric},
	}
	slices.SortFunc(learnedRoutes, compareRoutes)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if got := countedHeld(fake, steeredOverlay); !slices.Equal(got, learnedRoutes) {
		t.Fatalf("mode 2 holds %v of the routes that count, want %v", got, learnedRoutes)
	}
	rules, switched := fake.heldRules(), fake.fallback
	if switched == nil {
		t.Fatal("mode 2 under fallback = \"none\" holds no kill switch")
	}
	for _, step := range []struct {
		name  string
		table Table
		want  []Route
	}{
		{"mode 2 to mode 3", modeThree(waypointSID, exitSID), steered()},
		{"mode 3 back to mode 2", two, learnedRoutes},
	} {
		if err := reconciler.SetTable(step.table, steeredOverlay, nil); err != nil {
			t.Fatalf("%s: %v", step.name, err)
		}
		if !reconciler.adopt() {
			t.Fatalf("%s: the reload was not adopted", step.name)
		}
		if err := reconciler.reconcile(); err != nil {
			t.Fatalf("%s: %v", step.name, err)
		}
		if got := countedHeld(fake, steeredOverlay); !slices.Equal(got, step.want) {
			t.Errorf("%s: the pass after the reload holds %v of the routes that count, want %v", step.name, got, step.want)
		}
		if got := fake.heldRules(); !maps.Equal(got, rules) {
			t.Errorf("%s: the rules moved to %v from %v", step.name, slices.Collect(maps.Keys(got)), slices.Collect(maps.Keys(rules)))
		}
		if fake.fallback == nil || !reflect.DeepEqual(*fake.fallback, *switched) || fake.fallbackDeletes != 0 {
			t.Errorf("%s: the switch's chains moved to %+v from %+v, deleted %d times", step.name, fake.fallback, switched, fake.fallbackDeletes)
		}
	}
}

// Mode 3 with fallback unwritten holds the switch, mode 2 with it unwritten
// does not: its chains written and 5450 refusing the host's own lookups, holding
// while the path is down and passing while the steered defaults stand. Under
// fallback = "uplink" written, mode 3 writes neither and deletes the switch.
func TestModeThreeRefusesUnlessFallbackSaysUplink(t *testing.T) {
	refused := func(fake *fakeKernel) bool {
		return slices.ContainsFunc(slices.Collect(maps.Keys(fake.heldRules())), func(rule Rule) bool { return rule.Priority == priorityRefused })
	}
	reconciler, table, fake := harness(t, modeThree(exitSID), Runtime{Overlay: steeredOverlay, Sessions: func() int { return 1 }})
	for _, entry := range learnedDefaults() {
		table.Set(entry.source, entry.destination, entry.value)
	}
	for _, step := range []struct {
		name    string
		table   Table
		sid     bool
		refuses bool
		state   FallbackState
	}{
		{"mode 3, the path down", modeThree(exitSID), false, true, FallbackHolding},
		{"mode 3, the path up", modeThree(exitSID), true, true, FallbackPassing},
		{"mode 3 under fallback = \"uplink\"", Table{}.WithMode(&ExitMode{Via: []schema.Addr{schema.AddrFrom(exitSID)}, Fallback: FallbackUplink}).WithPathSource(steeredSource), true, false, ""},
		{"mode 2 with fallback unwritten", Table{}.WithMode(&ExitMode{}), true, false, ""},
		{"mode 3 again, the path down", modeThree(exitSID), false, true, FallbackHolding},
	} {
		if step.sid {
			table.Set(netip.Prefix{}, netip.PrefixFrom(exitSID, 128), learned)
		} else {
			table.Remove(netip.Prefix{}, netip.PrefixFrom(exitSID, 128))
		}
		if err := reconciler.SetTable(step.table, steeredOverlay, nil); err != nil {
			t.Fatalf("%s: %v", step.name, err)
		}
		reconciler.adopt()
		if err := reconciler.reconcile(); err != nil {
			t.Fatalf("%s: %v", step.name, err)
		}
		if held, unreachable := fake.fallback != nil, refused(fake); held != step.refuses || unreachable != step.refuses {
			t.Errorf("%s: the table is held %v and 5450 written %v, want %v", step.name, held, unreachable, step.refuses)
		}
		if got := reconciler.fallbackState; got != step.state {
			t.Errorf("%s: the switch reads %q, want %q", step.name, got, step.state)
		}
	}
}
