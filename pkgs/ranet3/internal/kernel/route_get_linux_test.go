// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"errors"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
	"ranet3.com/pkgs/ranet3/schema"
)

// The kernel names the route it took, rather than the host route it would
// cache for the packet, only under RTM_F_FIB_MATCH. A rule selects the table
// by the packet's source, so the source has to reach it, and a packet arriving
// on a device takes the input lookup, which IPv4 refuses with EHOSTUNREACH
// while forwarding is off. A packet to this host's own address takes the local
// route of the local table
func TestNetlinkRouteGetNamesTheMatchedRouteAndTable(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real netlink path needs root on linux")
	}
	enterThrowawayNamespace(t)
	conn, err := dialNetlink()
	if err != nil {
		t.Fatalf("dial rtnetlink: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	requireEmptyNamespace(t, conn)

	const device = "routeget0"
	createTUN(t, device)
	tun, err := conn.link(0, device)
	if err != nil {
		t.Fatalf("look up %s: %v", device, err)
	}
	setLinkFlags(t, conn, tun.index, unix.IFF_UP)
	tbl, rt := platformFor(device)
	opened, err := newPlatform(tbl, rt)
	if err != nil {
		t.Fatalf("open the netlink platform: %v", err)
	}
	t.Cleanup(func() { _ = opened.Close() })
	plat := opened.(*netlinkPlatform)

	for _, address := range []netip.Prefix{prefix("10.99.0.1/32"), prefix("3fff:a:1::1/128")} {
		if err := plat.AddAddr(address); err != nil {
			t.Fatalf("assign %s: %v", address, err)
		}
	}
	for _, route := range []Route{{Destination: prefix("198.18.0.0/15")}, {Destination: prefix("3fff:b::/32"), Metric: defaultIPv6Metric}} {
		if err := plat.AddRoute(route); err != nil {
			t.Fatalf("install %s: %v", route, err)
		}
	}
	for _, rule := range []Rule{
		{Family: FamilyIPv4, From: schema.MustPrefix("10.99.0.0/24"), Table: DefaultTable, Priority: 100},
		{Family: FamilyIPv6, From: schema.MustPrefix("3fff:a:1::/48"), Table: DefaultTable, Priority: 100},
	} {
		if err := plat.AddRule(rule); err != nil {
			t.Fatalf("install %s: %v", rule, err)
		}
	}

	matched := func(destination string) MatchedRoute {
		return MatchedRoute{Prefix: prefix(destination), Table: DefaultTable, Type: "unicast", NextHops: []NextHop{{Device: device}}}
	}
	holds := func(step string, got MatchedRoute, err error, want MatchedRoute) {
		t.Helper()
		if err != nil || got.Prefix != want.Prefix || got.Source != want.Source || got.Table != want.Table ||
			got.Type != want.Type || !slices.Equal(got.NextHops, want.NextHops) {
			t.Fatalf("%s answered %+v (err %v), want %+v", step, got, err, want)
		}
	}
	got, err := RouteGet(netip.MustParseAddr("10.99.0.1"), netip.MustParseAddr("198.18.1.1"), "")
	holds("this host's own IPv4 packet", got, err, matched("198.18.0.0/15"))
	got, err = RouteGet(netip.MustParseAddr("3fff:a:1::1"), netip.MustParseAddr("3fff:b::1"), "")
	holds("this host's own IPv6 packet", got, err, matched("3fff:b::/32"))
	got, err = RouteGet(netip.Addr{}, netip.MustParseAddr("10.99.0.1"), "")
	holds("a packet to this host's own address", got, err,
		MatchedRoute{Prefix: prefix("10.99.0.1/32"), Table: unix.RT_TABLE_LOCAL, Type: "local", NextHops: []NextHop{{Device: device}}})

	const arrival = "routeget1"
	createTUN(t, arrival)
	link, err := conn.link(0, arrival)
	if err != nil {
		t.Fatalf("look up %s: %v", arrival, err)
	}
	setLinkFlags(t, conn, link.index, unix.IFF_UP)
	sysctl := func(path, value string) {
		t.Helper()
		if err := os.WriteFile("/proc/sys/net/ipv4/"+path, []byte(value), 0); err != nil {
			t.Fatalf("set %s to %s: %v", path, value, err)
		}
	}
	// a new namespace takes its IPv4 settings from the host's, forwarding and
	// reverse path filtering among them
	sysctl("conf/all/rp_filter", "0")
	sysctl("conf/"+arrival+"/rp_filter", "0")
	sysctl("ip_forward", "0")
	forwarded := netip.MustParseAddr("10.99.0.7")
	if got, err := RouteGet(forwarded, netip.MustParseAddr("198.18.1.1"), arrival); !errors.Is(err, unix.EHOSTUNREACH) {
		t.Fatalf("a packet arriving on %s with forwarding off answered %+v and %v, want EHOSTUNREACH", arrival, got, err)
	}
	sysctl("ip_forward", "1")
	got, err = RouteGet(forwarded, netip.MustParseAddr("198.18.1.1"), arrival)
	holds("a packet arriving with forwarding on", got, err, matched("198.18.0.0/15"))
}
