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

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/packet"
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

// classBases are the ranges the data path forwards no unicast in, which
// aroundClass draws prefixes around
var classBases = []netip.Prefix{
	prefix("0.0.0.0/8"), prefix("127.0.0.0/8"), prefix("169.254.0.0/16"), prefix("224.0.0.0/4"),
	prefix("240.0.0.0/4"), prefix("255.255.255.255/32"), prefix("::/128"), prefix("::1/128"),
	prefix("::ffff:0:0/96"), prefix("fe80::/10"), prefix("ff00::/8"),
}

// aroundClass draws a prefix at a class's base, as long as the class, up to
// two bits longer, or up to two bits shorter
func aroundClass() hegel.Generator[netip.Prefix] {
	return hegel.Composite(func(tc hegel.TestCase) netip.Prefix {
		class := hegel.Draw(tc, hegel.SampledFrom(classBases))
		bits := min(class.Addr().BitLen(), class.Bits()+hegel.Draw(tc, pbt.Spanning(-2, 2)))
		return netip.PrefixFrom(class.Addr(), bits).Masked()
	})
}

// mirrorEntries draws entries of every kind, an IPv6 one with a source now
// and then, up to eight near prefixes and up to two around a class
func mirrorEntries() hegel.Generator[[]mirrorEntry] {
	entries := func(destinations hegel.Generator[netip.Prefix]) hegel.Generator[mirrorEntry] {
		return hegel.Composite(func(tc hegel.TestCase) mirrorEntry {
			entry := mirrorEntry{
				destination: hegel.Draw(tc, destinations),
				value:       hegel.Draw(tc, hegel.SampledFrom([]*netstack.Peer{learned, netstack.Unreachable, netstack.Local, netstack.Assigned})),
			}
			if !entry.destination.Addr().Is4() && hegel.Draw(tc, hegel.Booleans()) {
				entry.source = hegel.Draw(tc, nearPrefixes(true))
			}
			return entry
		})
	}
	return hegel.Composite(func(tc hegel.TestCase) []mirrorEntry {
		near := hegel.Draw(tc, hegel.Lists(entries(anyNearPrefix())).MaxSize(8))
		return append(near, hegel.Draw(tc, hegel.Lists(entries(aroundClass())).MaxSize(2))...)
	})
}

// classOf names the class of an address ranet3's data path forwards no unicast
// packet from or to by the predicate of netip's that holds for it, rather than
// by schema's list, or is empty for an address of none. The limited broadcast
// is named with class E, which holds it. An address packet refuses that no
// predicate here names is a class of its own.
func classOf(address netip.Addr) string {
	if !packet.InvalidSource(address) && !address.Is4In6() && address != packet.LimitedBroadcast {
		return ""
	}
	v4 := address.Is4()
	switch {
	case address.Is4In6():
		return "IPv4-mapped"
	case address.IsMulticast():
		return "multicast"
	case address.IsLinkLocalUnicast():
		return "link-local"
	case address.IsLoopback():
		return "loopback"
	case !v4 && address.IsUnspecified():
		return "unspecified"
	case v4 && address.As4()[0] == 0:
		return "this network"
	case v4 && address.As4()[0] >= 240:
		return "class E"
	}
	return address.String()
}

// classWhole reports a prefix one class holds every address of: each class is
// a prefix, so its first and last address lie in the same one
func classWhole(prefix netip.Prefix) bool {
	first := classOf(prefix.Masked().Addr())
	return first != "" && first == classOf(lastAddress(prefix.Masked()))
}

// sectionOneThree is routing.md's table of what the reconciler installs, row
// by row, for one table of entries: what the kernel's table holds for each but
// one a class holds whole, and on a platform with the policy rules an
// unreachable hold for each overlay prefix and a throw for each carve-out,
// which takes the place of the hold of an overlay prefix it equals and gives
// way to an entry of its own destination for every source. policy is a
// platform with the policy rules, gate the capture gate's answer.
func sectionOneThree(entries []mirrorEntry, overlay []schema.Prefix, carved []netip.Prefix, exit, gate, policy bool) map[Route]bool {
	out := map[Route]bool{}
	counts := func(prefix netip.Prefix) bool { return schema.CapturesTheMachine(prefix, overlay) }
	for _, entry := range entries {
		d := entry.destination
		if entry.value == netstack.Assigned || classWhole(d) || entry.source.IsValid() && d.Addr().Is4() {
			continue
		}
		route := Route{Destination: d, Source: entry.source}
		switch {
		case entry.value == learned && counts(d) && (exit || !gate):
			// a learned route that counts, on an exit or while the gate is shut
			continue
		case entry.value == learned && d.Addr().Is4():
			// at the kernel's default priority, 0 for IPv4 and IP6_RT_PRIO_USER for IPv6
		case entry.value == learned:
			route.Metric = 1024
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
		if policy && !slices.Contains(carved, prefix.Masked()) {
			out[Route{Destination: prefix.Masked(), Metric: holdMetric, Unreachable: true}] = true
		}
	}
	for _, prefix := range carved {
		own := slices.ContainsFunc(entries, func(entry mirrorEntry) bool { return entry.destination == prefix && !entry.source.IsValid() })
		if policy && !own {
			out[Route{Destination: prefix, Metric: holdMetric, Throw: true}] = true
		}
	}
	return out
}

// The mirror installs what routing.md's table says for every kind of entry,
// on an exit and on a node that is none, with the gate open and shut, on a
// platform with the policy rules and on one without, and each route once,
// half the time with a carve-out of a whole overlay prefix holding an entry.
// The overlay is one the loader takes, as the reconciler's always is.
func TestMirrorIsSectionOneThreesTable(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		var overlay []schema.Prefix
		for _, prefix := range hegel.Draw(ht, hegel.Lists(anyNearPrefix()).MaxSize(2)) {
			if taken := append(slices.Clone(overlay), schema.PrefixFrom(prefix)); (egress.Border{Overlay: taken}).Validate() == nil {
				overlay = taken
			}
		}
		network := drawnCarveNetwork(ht)
		// half the time a link's network equal to or around an overlay prefix, a carve-out of it whole, and a learned entry inside it
		var inside netip.Prefix
		if len(overlay) > 0 && hegel.Draw(ht, pbt.Spanning(0, 1)) == 1 {
			o := overlay[hegel.Draw(ht, pbt.Spanning(0, len(overlay)-1))].Masked()
			link := Link{Name: "br-carve", Prefixes: []netip.Prefix{netip.PrefixFrom(o.Addr(), o.Bits()-hegel.Draw(ht, pbt.Spanning(0, min(2, o.Bits()))))}}
			if o.Addr().Is4() {
				network.IPv4.Links = append(network.IPv4.Links, link)
			} else {
				network.IPv6.Links = append(network.IPv6.Links, link)
			}
			inside = netip.PrefixFrom(o.Addr(), min(o.Addr().BitLen(), o.Bits()+hegel.Draw(ht, pbt.Spanning(1, 8)))).Masked()
		}
		rt := Runtime{
			Interface:     "ranet0",
			Overlay:       overlay,
			EgressSegment: hegel.Draw(ht, hegel.Booleans()),
			Advertised:    hegel.Draw(ht, hegel.Lists(anyNearPrefix()).MaxSize(2)),
			Announced:     hegel.Draw(ht, hegel.Lists(anyNearPrefix()).MaxSize(2)),
			Network:       func() NetworkState { return network },
		}
		var carved []netip.Prefix
		for _, carveOut := range carveModel(network, overlay) {
			carved = append(carved, carveOut.Prefix)
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
		r := newReconciler(Table{}.Normalized(), rt, nil, routes, plat)
		r.capture = hegel.Draw(ht, hegel.Booleans())
		for _, entry := range hegel.Draw(ht, mirrorEntries()) {
			routes.Set(entry.source, entry.destination, entry.value)
		}
		if inside.IsValid() {
			routes.Set(netip.Prefix{}, inside, learned)
		}
		var held []mirrorEntry
		for _, entry := range routes.Snapshot() {
			held = append(held, mirrorEntry{source: entry.Source, destination: entry.Destination, value: entry.Value})
		}
		got := r.desired(routes.Snapshot(), r.readNetwork())
		want := sectionOneThree(held, overlay, carved, exit, r.capture, policy)
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

// An overlay prefix the pass already holds, as this node's own prefix or the
// mesh's hold, is held once
func TestOverlayHoldsHoldEachPrefixOnce(t *testing.T) {
	hold := func(destination string) Route {
		return Route{Destination: prefix(destination), Metric: holdMetric, Unreachable: true}
	}
	for name, c := range map[string]struct {
		overlay []netip.Prefix
		entries []mirrorEntry
		want    []Route
	}{
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
		if got := reconciler.desired(table.Snapshot(), reconciler.readNetwork()); !slices.Equal(got, c.want) {
			t.Errorf("%s: the mirror wants %v, want %v", name, got, c.want)
		}
	}
}
