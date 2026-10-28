// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"errors"
	"net/netip"
	"slices"
	"testing"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/schema"
)

// Under fallback = "none" a pass installs 5445 and 5450 in a real kernel, which
// reads them back as derived, 5450 as unreachable, and the walk ends where the
// rules say while the mesh holds no default. The host's own lookup beyond the
// LAN fails with ENETUNREACH at 5450, its own prefix the mesh's table throws
// leaves by main's default at 5445, and a LAN destination by its connected
// route at 5410. A packet forwarded from the link forward names fails at 5450
// too, and one from a link forward leaves out takes main's default. The
// withdrawal takes every rule. Each holds with the tun holding an overlay
// address of each family and with it holding none.
func TestNetlinkFallbackNoneEndsTheWalkAsTheRulesSay(t *testing.T) {
	const (
		device    = "ranetnone0"
		uplink    = "ranetup0"
		forwarded = "ranetfw0"
		left      = "ranetlan0"
	)
	plat := rootRulePlatform(t, device)
	conn, err := dialNetlink()
	if err != nil {
		t.Fatalf("dial rtnetlink: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	index := map[string]uint32{}
	for _, name := range []string{uplink, forwarded, left} {
		createTUN(t, name)
		link, err := conn.link(0, name)
		if err != nil {
			t.Fatalf("look up %s: %v", name, err)
		}
		setLinkFlags(t, conn, link.index, unix.IFF_UP)
		index[name] = link.index
	}
	// a new namespace takes its IPv4 settings from the host's, forwarding and
	// reverse path filtering among them
	writeBatchSysctl(t, "ipv4/ip_forward", "1")
	writeBatchSysctl(t, "ipv6/conf/all/forwarding", "1")
	for _, name := range []string{"all", "default", forwarded, left} {
		writeBatchSysctl(t, "ipv4/conf/"+name+"/rp_filter", "0")
	}
	lan4, lan6 := prefix("198.51.100.10/25"), prefix("2001:db8:a::10/64")
	for address, unspecified := range map[netip.Prefix]netip.Addr{lan4: netip.IPv4Unspecified(), lan6: netip.IPv6Unspecified()} {
		writeBatchAddress(t, conn, index[uplink], address)
		writeBatchRoute(t, conn, unix.RT_TABLE_MAIN, netip.PrefixFrom(unspecified, 0), batchHop{index: index[uplink]})
	}

	network := NetworkState{
		IPv4: NetworkFamily{Default: DefaultRoute{Interface: uplink}, Links: []Link{{Name: forwarded}, {Name: left}, {Name: uplink, Prefixes: []netip.Prefix{lan4}}}},
		IPv6: NetworkFamily{Default: DefaultRoute{Interface: uplink}, Links: []Link{{Name: forwarded}, {Name: left}, {Name: uplink, Prefixes: []netip.Prefix{lan6}}}},
	}
	routes := netstack.NewRouteTable()
	own4, own6 := prefix("203.0.113.0/24"), prefix("2001:db8:5::/48")
	for _, own := range []netip.Prefix{own4, own6} {
		routes.Set(netip.Prefix{}, own, netstack.Local)
	}
	// a family the tun holds no overlay address of runs mode off's rules with 5445 and 5450, so the walk ends as it does in one it
	// holds. The cases run on the test's own goroutine, whose thread is in the namespace the links were made in, so no subtest.
	for _, c := range []struct {
		name      string
		addresses []schema.Prefix
	}{
		{"the tun holding an overlay address of each family", prefixes(prefix("192.0.2.1/32"), prefix("3fff::1/128"))},
		{"the tun holding no overlay address", nil},
	} {
		t.Logf("with %s", c.name)
		tbl, rt := platformFor(device)
		tbl.Addresses = c.addresses
		rt.Overlay = exitPassOverlay
		rt.Network = func() NetworkState { return network }
		mode := &ExitMode{Forward: []string{forwarded}, Fallback: FallbackNone}
		reconciler := newReconciler(tbl.WithMode(mode).Normalized(), rt, tbl.Assigned(nil), routes, plat)
		if err := reconciler.reconcile(); err != nil {
			t.Fatalf("with %s: %v", c.name, err)
		}
		checkFallbackNoneWalk(t, plat, uplink, forwarded, left, lan4, lan6)
		if err := reconciler.withdraw(); err != nil {
			t.Fatalf("with %s: %v", c.name, err)
		}
		if got, err := plat.Rules(); err != nil || len(got) != 0 {
			t.Fatalf("with %s, after withdrawal the kernel holds %v (err %v)", c.name, got, err)
		}
	}
}

// checkFallbackNoneWalk reads 5445 and 5450 back from plat and walks the lookups TestNetlinkFallbackNoneEndsTheWalkAsTheRulesSay names
func checkFallbackNoneWalk(t *testing.T, plat *netlinkPlatform, uplink, forwarded, left string, lan4, lan6 netip.Prefix) {
	t.Helper()
	got, err := plat.Rules()
	if err != nil {
		t.Fatalf("list rules: %v", err)
	}
	var held []string
	for _, rule := range got {
		if rule.Priority == priorityOwnPastMesh || rule.Priority == priorityRefused {
			held = append(held, rule.String())
		}
	}
	slices.Sort(held)
	want := []string{
		"priority 5445 to 2001:db8:5::/48 family ipv6 lookup main",
		"priority 5445 to 203.0.113.0/24 family ipv4 lookup main",
		"priority 5450 iif lo family ipv4 unreachable",
		"priority 5450 iif lo family ipv6 unreachable",
		"priority 5450 iif " + forwarded + " family ipv4 unreachable",
		"priority 5450 iif " + forwarded + " family ipv6 unreachable",
	}
	if !slices.Equal(held, want) {
		t.Errorf("the kernel holds\n%v\nwant\n%v", held, want)
	}

	addr := netip.MustParseAddr
	byDefault := func(step string, route MatchedRoute, err error) {
		t.Helper()
		if err != nil || route.Table != unix.RT_TABLE_MAIN || route.Prefix.Bits() != 0 || len(route.NextHops) != 1 || route.NextHops[0].Device != uplink {
			t.Errorf("%s answered %+v (err %v), want main's default by %s", step, route, err, uplink)
		}
	}
	refused := func(step string, route MatchedRoute, err error) {
		t.Helper()
		if !errors.Is(err, unix.ENETUNREACH) {
			t.Errorf("%s answered %+v (err %v), want ENETUNREACH", step, route, err)
		}
	}
	for _, f := range []struct {
		beyond, own, lan, source netip.Addr
		connected                netip.Prefix
	}{
		{addr("198.51.100.200"), addr("203.0.113.9"), addr("198.51.100.5"), addr("198.51.100.150"), lan4.Masked()},
		{addr("2001:db8:f::1"), addr("2001:db8:5::9"), addr("2001:db8:a::5"), addr("2001:db8:b::7"), lan6.Masked()},
	} {
		route, err := RouteGet(netip.Addr{}, f.beyond, "")
		refused("the host's own lookup of "+f.beyond.String(), route, err)
		route, err = RouteGet(netip.Addr{}, f.own, "")
		byDefault("the host's own lookup of its own "+f.own.String(), route, err)
		route, err = RouteGet(netip.Addr{}, f.lan, "")
		if err != nil || route.Table != unix.RT_TABLE_MAIN || route.Prefix != f.connected {
			t.Errorf("the host's own lookup of %s on the LAN answered %+v (err %v), want %s", f.lan, route, err, f.connected)
		}
		route, err = RouteGet(f.source, f.beyond, forwarded)
		refused("a packet forwarded from "+forwarded+" to "+f.beyond.String(), route, err)
		route, err = RouteGet(f.source, f.beyond, left)
		byDefault("a packet forwarded from "+left+" to "+f.beyond.String(), route, err)
	}
}
