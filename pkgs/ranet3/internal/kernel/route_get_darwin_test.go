// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package kernel

import (
	"fmt"
	"net/netip"
	"slices"
	"testing"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// The route is read from the RTM_GET answer, the prefix from the netmask or
// the host flag, the type from the reject and blackhole flags, and a gateway
// only where RTF_GATEWAY says the gateway field holds one. A loopback host
// route holds the interface's own address there, and an answer without an
// interface has no next hop
func TestDarwinRouteGetReadsTheAnswer(t *testing.T) {
	addrs := func(destination, gateway, mask route.Addr) []route.Addr {
		out := make([]route.Addr, unix.RTAX_MAX)
		out[unix.RTAX_DST], out[unix.RTAX_GATEWAY], out[unix.RTAX_NETMASK] = destination, gateway, mask
		return out
	}
	name := func(index int) (string, error) {
		if index == 0 {
			return "", fmt.Errorf("no interface has index 0")
		}
		return fmt.Sprintf("en%d", index), nil
	}
	for _, c := range []struct {
		name   string
		answer route.RouteMessage
		want   MatchedRoute
	}{
		{"through a gateway", route.RouteMessage{Flags: unix.RTF_UP | unix.RTF_GATEWAY, Index: 5,
			Addrs: addrs(&route.Inet4Addr{IP: [4]byte{198, 18, 0, 0}}, &route.Inet4Addr{IP: [4]byte{192, 0, 2, 1}}, &route.Inet4Addr{IP: [4]byte{255, 254, 0, 0}})},
			MatchedRoute{Prefix: netip.MustParsePrefix("198.18.0.0/15"), Type: "unicast", NextHops: []NextHop{{Device: "en5", Gateway: netip.MustParseAddr("192.0.2.1")}}}},
		{"through a link", route.RouteMessage{Flags: unix.RTF_UP, Index: 4,
			Addrs: addrs(&route.Inet4Addr{IP: [4]byte{192, 0, 2, 0}}, &route.LinkAddr{Index: 4}, &route.Inet4Addr{IP: [4]byte{255, 255, 255, 0}})},
			MatchedRoute{Prefix: netip.MustParsePrefix("192.0.2.0/24"), Type: "unicast", NextHops: []NextHop{{Device: "en4"}}}},
		{"to the loopback", route.RouteMessage{Flags: unix.RTF_UP | unix.RTF_HOST, Index: 1,
			Addrs: addrs(&route.Inet4Addr{IP: [4]byte{127, 0, 0, 1}}, &route.Inet4Addr{IP: [4]byte{127, 0, 0, 1}}, nil)},
			MatchedRoute{Prefix: netip.MustParsePrefix("127.0.0.1/32"), Type: "unicast", NextHops: []NextHop{{Device: "en1"}}}},
		{"rejected", route.RouteMessage{Flags: unix.RTF_UP | unix.RTF_REJECT | unix.RTF_HOST, Index: 6,
			Addrs: addrs(&route.Inet6Addr{IP: netip.MustParseAddr("2001:db8::1").As16()}, &route.LinkAddr{Index: 6}, nil)},
			MatchedRoute{Prefix: netip.MustParsePrefix("2001:db8::1/128"), Type: "unreachable", NextHops: []NextHop{{Device: "en6"}}}},
		{"blackholed", route.RouteMessage{Flags: unix.RTF_UP | unix.RTF_BLACKHOLE, Index: 6,
			Addrs: addrs(&route.Inet6Addr{IP: netip.MustParseAddr("2001:db8::").As16()}, &route.LinkAddr{Index: 6}, &route.Inet6Addr{IP: netip.MustParseAddr("ffff:ffff::").As16()})},
			MatchedRoute{Prefix: netip.MustParsePrefix("2001:db8::/32"), Type: "blackhole", NextHops: []NextHop{{Device: "en6"}}}},
		{"without an interface", route.RouteMessage{Flags: unix.RTF_UP | unix.RTF_HOST,
			Addrs: addrs(&route.Inet4Addr{IP: [4]byte{198, 51, 100, 7}}, nil, nil)},
			MatchedRoute{Prefix: netip.MustParsePrefix("198.51.100.7/32"), Type: "unicast"}},
	} {
		got, err := decodeRouteAnswer(&c.answer, name)
		if err != nil || got.Prefix != c.want.Prefix || got.Type != c.want.Type || !slices.Equal(got.NextHops, c.want.NextHops) {
			t.Errorf("%s read as %+v (err %v), want %+v", c.name, got, err, c.want)
		}
	}
}

// XNU's lookup has no input device, so a packet said to arrive on one is
// refused rather than answered as this host's own
func TestDarwinRouteGetRefusesAnArrivalDevice(t *testing.T) {
	if got, err := RouteGet(netip.MustParseAddr("192.0.2.7"), netip.MustParseAddr("127.0.0.1"), "en0"); err == nil {
		t.Errorf("a packet arriving on en0 was answered with %+v", got)
	}
}

// The lookup against this host's own kernel, which needs no privilege: the
// loopback address leaves by lo0 on every darwin host.
func TestDarwinRouteGetNamesTheLoopbackRoute(t *testing.T) {
	loopback := netip.MustParseAddr("127.0.0.1")
	got, err := RouteGet(netip.Addr{}, loopback, "")
	if err != nil {
		t.Fatalf("look up the route to %s: %v", loopback, err)
	}
	if !got.Prefix.Contains(loopback) || len(got.NextHops) != 1 || got.NextHops[0].Device != "lo0" {
		t.Fatalf("the route to %s read as %+v, want one through lo0", loopback, got)
	}
}
