// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package kernel

import (
	"maps"
	"net/netip"
	"slices"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/schema"
)

// nearPrefixes draws prefixes around a few bases, so a drawn entry falls
// inside, across and outside a drawn overlay, and some count as a default
func nearPrefixes(v6 bool) hegel.Generator[netip.Prefix] {
	bases := []string{"10.0.0.0", "10.1.0.0", "0.0.0.0", "192.0.2.0", "64.0.0.0"}
	if v6 {
		bases = []string{"3fff::", "3fff:1::", "::", "2001:db8::", "2000::"}
	}
	return hegel.Composite(func(tc hegel.TestCase) netip.Prefix {
		base := netip.MustParseAddr(hegel.Draw(tc, hegel.SampledFrom(bases)))
		return netip.PrefixFrom(base, hegel.Draw(tc, edges(0, base.BitLen()))).Masked()
	})
}

// anyNearPrefix draws a near prefix of either family
func anyNearPrefix() hegel.Generator[netip.Prefix] {
	return hegel.OneOf(nearPrefixes(false), nearPrefixes(true))
}

// mirrorEntry is one entry of ranet3's table
type mirrorEntry struct {
	source, destination netip.Prefix
	value               *netstack.Peer
}

var learned = &netstack.Peer{ID: "example/peer"}

// mirrorEntries draws entries of every kind, an IPv6 one with a source now and then
func mirrorEntries() hegel.Generator[[]mirrorEntry] {
	return hegel.Lists(hegel.Composite(func(tc hegel.TestCase) mirrorEntry {
		entry := mirrorEntry{
			destination: hegel.Draw(tc, anyNearPrefix()),
			value:       hegel.Draw(tc, hegel.SampledFrom([]*netstack.Peer{learned, netstack.Unreachable, netstack.Local, netstack.Assigned})),
		}
		if !entry.destination.Addr().Is4() && hegel.Draw(tc, hegel.Booleans()) {
			entry.source = hegel.Draw(tc, nearPrefixes(true))
		}
		return entry
	})).MaxSize(8)
}

// sectionOneThree is routing.md's table of what the reconciler installs, row
// by row, for one table of entries: what the kernel's table holds for each,
// and on a platform with the policy rules an unreachable hold for each overlay
// prefix the mesh can carry that holds no unspecified address. policy is a
// platform with the policy rules, gate the capture gate's answer.
func sectionOneThree(entries []mirrorEntry, overlay []schema.Prefix, exit, gate, policy bool) map[Route]bool {
	out := map[Route]bool{}
	counts := func(prefix netip.Prefix) bool { return schema.CapturesTheMachine(prefix, overlay) }
	for _, entry := range entries {
		d := entry.destination
		if entry.value == netstack.Assigned || unroutable(d) != "" || entry.source.IsValid() && d.Addr().Is4() {
			continue
		}
		route := Route{Destination: d, Source: entry.source}
		switch {
		case entry.value == learned && counts(d) && (exit || !gate):
			// a learned route that counts, on an exit or while the gate is shut
			continue
		case entry.value == learned:
			route.Metric = routeMetric(0, d, false)
		case counts(d):
			// a hold that counts, and this node's own prefix that counts
			continue
		case entry.value == netstack.Unreachable, schema.InsideOverlay(d, overlay):
			route.Metric, route.Unreachable = holdMetric, true
		case policy:
			route.Metric, route.Throw = holdMetric, true
		default:
			// darwin has no throw, and installs nothing for the prefix
			continue
		}
		out[route] = true
	}
	for _, prefix := range overlay {
		if policy && !counts(prefix.Prefix) && unroutable(prefix.Masked()) == "" {
			out[Route{Destination: prefix.Masked(), Metric: holdMetric, Unreachable: true}] = true
		}
	}
	return out
}

// The mirror installs what routing.md's table says for every kind of entry,
// on an exit and on a node that is none, with the gate open and shut, on a
// platform with the policy rules and on one without, and each route once.
func TestMirrorIsSectionOneThreesTable(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		var overlay []schema.Prefix
		for _, prefix := range hegel.Draw(ht, hegel.Lists(anyNearPrefix()).MaxSize(2)) {
			overlay = append(overlay, schema.PrefixFrom(prefix))
		}
		rt := Runtime{
			Interface:     "ranet0",
			Overlay:       overlay,
			EgressSegment: hegel.Draw(ht, hegel.Booleans()),
			Advertised:    hegel.Draw(ht, hegel.Lists(anyNearPrefix()).MaxSize(2)),
			Announced:     hegel.Draw(ht, hegel.Lists(anyNearPrefix()).MaxSize(2)),
		}
		exit := rt.EgressSegment
		for _, prefix := range slices.Concat(rt.Advertised, rt.Announced) {
			exit = exit || schema.CapturesTheMachine(prefix, overlay)
		}
		policy := hegel.Draw(ht, hegel.Booleans())
		var plat platform = newFakeKernel(t)
		if !policy {
			plat = routesOnly{inner: plat.(*fakeKernel)}
		}
		routes := netstack.NewRouteTable()
		r := newReconciler(Table{}.Normalized(), rt, nil, nil, routes, plat)
		r.capture = hegel.Draw(ht, hegel.Booleans())
		for _, entry := range hegel.Draw(ht, mirrorEntries()) {
			routes.Set(entry.source, entry.destination, entry.value)
		}
		var held []mirrorEntry
		for _, entry := range routes.Snapshot() {
			held = append(held, mirrorEntry{source: entry.Source, destination: entry.Destination, value: entry.Value})
		}
		got := r.desired(routes.Snapshot())
		want := sectionOneThree(held, overlay, exit, r.capture, policy)
		set := map[Route]bool{}
		for _, route := range got {
			if set[route] {
				ht.Fatalf("the mirror wants %s twice", route)
			}
			set[route] = true
		}
		if !maps.Equal(set, want) {
			ht.Fatalf("the mirror wants\n%v\nrouting.md's table has\n%v", sortedRoutes(set), sortedRoutes(want))
		}
	})
}

func sortedRoutes(set map[Route]bool) []Route {
	return slices.SortedFunc(maps.Keys(set), compareRoutes)
}

// Each of an exit's three inputs alone makes the node an exit, which withholds
// a learned default with the gate open, and a node with none installs it
func TestEachExitInputWithholdsALearnedDefault(t *testing.T) {
	for name, c := range map[string]struct {
		rt   Runtime
		exit bool
	}{
		"no input":                           {rt: Runtime{Announced: []netip.Prefix{prefix("2001:db8:1::/48")}}},
		"an egress segment":                  {rt: Runtime{EgressSegment: true}, exit: true},
		"a counted cap.egress advertisement": {rt: Runtime{Advertised: []netip.Prefix{prefix("2000::/3")}}, exit: true},
		"a counted cap.route announcement":   {rt: Runtime{Announced: []netip.Prefix{prefix("::/0")}}, exit: true},
	} {
		reconciler, table, fake := harness(t, Table{}, c.rt)
		learnedDefault := Route{Destination: prefix("::/0"), Metric: defaultIPv6Metric}
		table.Set(netip.Prefix{}, learnedDefault.Destination, learned)
		if err := reconciler.reconcile(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !reconciler.capture {
			t.Fatalf("%s: the gate is shut", name)
		}
		if got := fake.has(learnedDefault); got == c.exit {
			t.Errorf("%s: the learned default is installed %v, want %v", name, got, !c.exit)
		}
	}
}

// An overlay prefix the mesh cannot carry gets no hold, and one the pass
// already holds, as this node's own prefix or the mesh's hold, is held once
func TestOverlayHoldsLeaveOutTheUnroutableAndHoldEachPrefixOnce(t *testing.T) {
	hold := func(destination string) Route {
		return Route{Destination: prefix(destination), Metric: holdMetric, Unreachable: true}
	}
	for name, c := range map[string]struct {
		overlay []netip.Prefix
		entries []mirrorEntry
		want    []Route
	}{
		"link-local and multicast overlay prefixes": {
			overlay: []netip.Prefix{prefix("fe80::/10"), prefix("ff00::/8"), prefix("169.254.0.0/16"), prefix("224.0.0.0/4"), prefix("3fff::/20")},
			want:    []Route{hold("3fff::/20")},
		},
		"an overlay prefix this node originates": {
			overlay: []netip.Prefix{prefix("3fff::/20")},
			entries: []mirrorEntry{{destination: prefix("3fff::/20"), value: netstack.Local}},
			want:    []Route{hold("3fff::/20")},
		},
		"an overlay prefix the mesh holds back": {
			overlay: []netip.Prefix{prefix("192.0.2.0/24")},
			entries: []mirrorEntry{{destination: prefix("192.0.2.0/24"), value: netstack.Unreachable}},
			want:    []Route{hold("192.0.2.0/24")},
		},
	} {
		reconciler, table, _ := harness(t, Table{}, Runtime{Overlay: prefixes(c.overlay...)})
		for _, entry := range c.entries {
			table.Set(entry.source, entry.destination, entry.value)
		}
		if got := reconciler.desired(table.Snapshot()); !slices.Equal(got, c.want) {
			t.Errorf("%s: the mirror wants %v, want %v", name, got, c.want)
		}
	}
}

// A reload that announces a default makes the node an exit from the next
// pass on, which takes the learned default out with the gate open.
func TestReloadAnnouncingADefaultWithdrawsTheLearnedOne(t *testing.T) {
	reconciler, table, fake := harness(t, Table{})
	learnedDefault := Route{Destination: prefix("::/0"), Metric: defaultIPv6Metric}
	table.Set(netip.Prefix{}, learnedDefault.Destination, learned)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if !fake.has(learnedDefault) {
		t.Fatal("a node that is no exit left out the learned default")
	}
	if err := reconciler.SetTable(Table{}, nil, []netip.Prefix{prefix("::/0")}); err != nil {
		t.Fatal(err)
	}
	if !reconciler.adopt() {
		t.Fatal("the reload was not adopted")
	}
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if fake.has(learnedDefault) {
		t.Error("an exit kept the learned default")
	}
}
