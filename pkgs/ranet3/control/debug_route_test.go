// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package control

import (
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"
)

// routeRule is a lookup rule as the route view names it
func routeRule(family string, priority, table uint32, protocol uint8, owned bool) *PolicyRule {
	return &PolicyRule{Family: family, Priority: priority, Action: "lookup", Table: table, Protocol: protocol, Owned: owned, Wanted: owned}
}

// routeFixtures is one answer of the route view for each golden file: this
// host's own packet by main's default with a dead and link-down second hop
// and one through an exception and its IPv6 packet to ::, an arrival refused
// by another program's prohibit rule, to a subnet's broadcast and to an IPv6
// group, one refused and one dropped with forwarding off, one refused by an
// unreachable route with forwarding unread and with it on, and an arrival to
// a group refused with multicast routing on and unread, one under reverse
// path filtering beside a blackhole rule it may not have reached, an arrival
// to a group not joined with reverse path filtering on and off and one to
// 0.0.0.0, darwin's arrival, own packet, one with no route looked up without
// its source and one to ::, a lookup with no route from a source and from
// none, one no rule fits, one from a source the host may not hold beside an
// unreachable rule and an IPv4 and an IPv6 EINVAL past a lookup, this host's
// own packet into the tun in mode 2, and the routes of no table entry the
// kernel makes for this host's multicast, its packet to 0.0.0.0, an arrival
// to the limited broadcast, and an arrival to a group beyond the link with
// multicast routing off, on and unread and to one on the link
func routeFixtures() map[string][]RouteInfo {
	own := RouteInfo{Dst: netip.MustParseAddr("203.0.113.200"), Arrival: ArrivalLocal, Kernel: &RouteKernel{
		Rule:  routeRule("ipv4", 32766, 254, 2, false),
		Route: netip.MustParsePrefix("0.0.0.0/0"), Table: 254, Type: "unicast",
		NextHops: []RouteNextHop{
			{Dev: "up0", Gateway: netip.MustParseAddr("198.51.100.1")},
			{Dev: "lan0", Gateway: netip.MustParseAddr("198.51.100.129"), Dead: true, LinkDown: true},
		},
	}}
	prohibit := &PolicyRule{Family: "ipv6", Priority: 1001, To: netip.MustParsePrefix("2001:db8:beef::/48"), Action: "prohibit", Protocol: 99}
	link := RouteInfo{Src: netip.MustParseAddr("2001:db8:2::5"), Dst: netip.MustParseAddr("2001:db8:beef::10"), IIF: "lan0", Arrival: ArrivalLink, Kernel: &RouteKernel{
		Rule: prohibit, RouteType: "prohibit", Err: "kernel: look up the route to 2001:db8:beef::10: permission denied", Errno: "EACCES",
	}}
	arrival4 := RouteInfo{Src: netip.MustParseAddr("198.51.100.140"), Dst: netip.MustParseAddr("203.0.113.200"), IIF: "lan0", Arrival: ArrivalLink}
	refused := arrival4
	refused.Kernel = &RouteKernel{
		RouteType: "unreachable", Err: "kernel: look up the route to 203.0.113.200: no route to host", Errno: "EHOSTUNREACH",
		Why: WhyForwardingOff, Settings: []RouteSetting{{Name: "net/ipv4/conf/lan0/forwarding", Value: "0"}},
	}
	// an unreachable route's EHOSTUNREACH, which forwarding off answers too
	unreachable := arrival4
	unreachable.Kernel = &RouteKernel{
		RouteType: "unreachable", Err: refused.Kernel.Err, Errno: "EHOSTUNREACH",
		Settings: []RouteSetting{{Name: "net/ipv4/conf/lan0/forwarding", Err: "unreadable"}},
	}
	forwarded := arrival4
	forwarded.Kernel = &RouteKernel{
		RouteType: "unreachable", Err: refused.Kernel.Err, Errno: "EHOSTUNREACH",
		Settings: []RouteSetting{{Name: "net/ipv4/conf/lan0/forwarding", Value: "1"}},
	}
	dropped := RouteInfo{Src: netip.MustParseAddr("2001:db8:2::5"), Dst: netip.MustParseAddr("2001:db8:ffff::10"), IIF: "lan0", Arrival: ArrivalLink, Kernel: &RouteKernel{
		Rule:  routeRule("ipv6", 32766, 254, 2, false),
		Route: netip.MustParsePrefix("::/0"), Table: 254, Type: "unicast",
		NextHops: []RouteNextHop{{Dev: "up0", Gateway: netip.MustParseAddr("2001:db8:1::1")}},
		Why:      WhyForwardingOff, Settings: []RouteSetting{{Name: "net/ipv6/conf/all/forwarding", Value: "0"}, {Name: "net/ipv6/conf/lan0/force_forwarding", Err: "absent"}},
	}}
	forged := arrival4
	forged.Src = netip.MustParseAddr("203.0.113.50")
	forged.Kernel = &RouteKernel{
		RouteType: "blackhole", Err: "kernel: look up the route to 203.0.113.200: invalid argument", Errno: "EINVAL", Why: WhyReversePath,
		Settings: []RouteSetting{{Name: "net/ipv4/conf/all/rp_filter", Value: "0"}, {Name: "net/ipv4/conf/lan0/rp_filter", Value: "1"}},
	}
	unread := forged
	unread.Kernel = &RouteKernel{
		RouteType: "blackhole", Err: forged.Kernel.Err, Errno: "EINVAL",
		Settings: []RouteSetting{{Name: "net/ipv4/conf/all/rp_filter", Value: "0"}, {Name: "net/ipv4/conf/lan0/rp_filter", Err: "unreadable"}},
	}
	darwinArrival := RouteInfo{Src: netip.MustParseAddr("192.0.2.7"), Dst: netip.MustParseAddr("203.0.113.200"), IIF: "en0", Arrival: ArrivalLink, Kernel: &RouteKernel{
		Err: "kernel: unsupported on this platform: darwin looks up the route of this host's own packet only, not of one arriving on en0", Why: WhyUnsupported,
	}}
	darwinOwn := RouteInfo{Dst: netip.MustParseAddr("203.0.113.200"), Arrival: ArrivalLocal, Kernel: &RouteKernel{
		RuleErr: "this platform has no policy rules", Route: netip.MustParsePrefix("0.0.0.0/0"), Type: "unicast",
		NextHops: []RouteNextHop{{Dev: "en0", Gateway: netip.MustParseAddr("198.51.100.1")}},
	}}
	darwinUnrouted := RouteInfo{Src: netip.MustParseAddr("192.0.2.9"), Dst: netip.MustParseAddr("203.0.113.1"), Arrival: ArrivalLocal, Kernel: &RouteKernel{
		RuleErr: "this platform has no policy rules", NoSource: true,
		Err: "kernel: look up the route to 203.0.113.1: network is unreachable", Errno: "ENETUNREACH", Why: WhyNoRoute,
	}}
	darwinUnspecified := RouteInfo{Dst: netip.IPv6Unspecified(), Arrival: ArrivalLocal, Kernel: &RouteKernel{
		RuleErr: "this platform has no policy rules", Route: netip.MustParsePrefix("::/0"), Type: "unicast",
		NextHops: []RouteNextHop{{Dev: "en0", Gateway: netip.MustParseAddr("2001:db8:1::1")}},
	}}
	cached := RouteInfo{Src: netip.MustParseAddr("2001:db8:1::2"), Dst: netip.MustParseAddr("2001:db8:ffff::10"), Arrival: ArrivalLocal, Kernel: &RouteKernel{
		Rule:  routeRule("ipv6", 32766, 254, 2, false),
		Route: netip.MustParsePrefix("::/0"), Table: 254, Type: "unicast", Exception: true,
		NextHops: []RouteNextHop{{Dev: "up0", Gateway: netip.MustParseAddr("2001:db8:1::1")}},
	}}
	unspecified6 := RouteInfo{Src: netip.MustParseAddr("2001:db8:1::2"), Dst: netip.IPv6Unspecified(), Arrival: ArrivalLocal, Kernel: &RouteKernel{
		Rule:  routeRule("ipv6", 32766, 254, 2, false),
		Route: netip.MustParsePrefix("::/0"), Table: 254, Type: "unicast",
		NextHops: []RouteNextHop{{Dev: "up0", Gateway: netip.MustParseAddr("2001:db8:1::1")}},
	}}
	unrouted := RouteInfo{Src: netip.MustParseAddr("192.0.2.99"), Dst: netip.MustParseAddr("203.0.113.200"), Arrival: ArrivalLocal, Kernel: &RouteKernel{
		Err: "kernel: look up the route to 203.0.113.200: network is unreachable", Errno: "ENETUNREACH", Why: WhyNoRoute,
	}}
	// with no source only the walk answers ENETUNREACH
	unsourced := unrouted
	unsourced.Src = netip.Addr{}
	unfit := RouteInfo{Dst: netip.MustParseAddr("203.0.113.200"), Arrival: ArrivalLocal, Kernel: &RouteKernel{
		Route: netip.MustParsePrefix("0.0.0.0/0"), Table: 7, Type: "unicast", NextHops: []RouteNextHop{{Dev: "up0"}},
	}}
	tun := routeRule("ipv4", 5440, 100, 155, true)
	tun.IIF = "lo"
	intoTun := RouteInfo{Dst: netip.MustParseAddr("203.0.113.200"), Arrival: ArrivalLocal, Kernel: &RouteKernel{
		Rule: tun, Route: netip.MustParsePrefix("128.0.0.0/1"), Table: 100, Type: "unicast",
		NextHops: []RouteNextHop{{Dev: "ranet0"}}, IntoTun: true,
	}}
	// a terminal rule whose errno a check outside the walk raises too
	blackholed := forged
	blackholed.Kernel = &RouteKernel{
		Candidate: &PolicyRule{Family: "ipv4", Priority: 40000, To: netip.MustParsePrefix("203.0.113.0/24"), Action: "blackhole", Protocol: 99},
		RouteType: "blackhole", Err: forged.Kernel.Err, Errno: "EINVAL", Why: WhyReversePath, Settings: forged.Kernel.Settings,
	}
	unheld := RouteInfo{Src: netip.MustParseAddr("198.51.100.99"), Dst: netip.MustParseAddr("203.0.113.70"), Arrival: ArrivalLocal, Kernel: &RouteKernel{
		Candidate: &PolicyRule{Family: "ipv4", Priority: 1000, To: netip.MustParsePrefix("203.0.113.64/27"), Action: "unreachable", Protocol: 99},
		Err:       "kernel: look up the route to 203.0.113.70: network is unreachable", Errno: "ENETUNREACH", Why: WhyNoRoute,
	}}
	// an EINVAL past a lookup, which in IPv4 a check outside the walk raises too
	refused4 := RouteInfo{Dst: netip.MustParseAddr("203.0.113.200"), Arrival: ArrivalLocal, Kernel: &RouteKernel{
		RouteType: "blackhole", Err: "kernel: look up the route to 203.0.113.200: invalid argument", Errno: "EINVAL",
	}}
	blackhole6 := RouteInfo{Dst: netip.MustParseAddr("2001:db8:ffff::20"), Arrival: ArrivalLocal, Kernel: &RouteKernel{
		RouteType: "blackhole", Err: "kernel: look up the route to 2001:db8:ffff::20: invalid argument", Errno: "EINVAL",
	}}
	behind := own
	behind.Kernel = &RouteKernel{
		Unread: []PolicyRule{
			{Family: "ipv4", Priority: 300, Action: "lookup", Table: 400, Protocol: 4, Unread: []string{"uidrange"}},
			{Family: "ipv4", Priority: 310, To: netip.MustParsePrefix("203.0.113.0/24"), Action: "goto", Goto: 32766, Protocol: 4, Unread: []string{"ipproto", "dport"}},
		},
		Rule:  own.Kernel.Rule,
		Route: own.Kernel.Route, Table: 254, Type: "unicast", NextHops: own.Kernel.NextHops[:1],
	}
	multicast := RouteInfo{Src: netip.MustParseAddr("198.51.100.2"), Dst: netip.MustParseAddr("224.0.0.251"), Arrival: ArrivalLocal, Kernel: &RouteKernel{
		NoEntry: true, Route: netip.MustParsePrefix("224.0.0.251/32"), Type: "multicast", NextHops: []RouteNextHop{{Dev: "up0"}},
	}}
	unspecified := RouteInfo{Dst: netip.IPv4Unspecified(), Arrival: ArrivalLocal, Kernel: &RouteKernel{
		NoEntry: true, Route: netip.MustParsePrefix("0.0.0.0/32"), Type: "local", NextHops: []RouteNextHop{{Dev: "lo"}},
	}}
	broadcast := RouteInfo{Src: netip.MustParseAddr("198.51.100.9"), Dst: netip.MustParseAddr("255.255.255.255"), IIF: "up0", Arrival: ArrivalLink, Kernel: &RouteKernel{
		NoEntry: true, Route: netip.MustParsePrefix("255.255.255.255/32"), Type: "broadcast", NextHops: []RouteNextHop{{Dev: "lo"}},
	}}
	subnetBroadcast := RouteInfo{Src: netip.MustParseAddr("198.51.100.140"), Dst: netip.MustParseAddr("198.51.100.255"), IIF: "lan0", Arrival: ArrivalLink, Kernel: &RouteKernel{
		Rule:  routeRule("ipv4", 0, 255, 2, false),
		Route: netip.MustParsePrefix("198.51.100.255/32"), Table: 255, Type: "broadcast", NextHops: []RouteNextHop{{Dev: "lan0"}},
	}}
	group6 := RouteInfo{Src: netip.MustParseAddr("2001:db8:2::5"), Dst: netip.MustParseAddr("ff0e::123"), IIF: "lan0", Arrival: ArrivalLink, Kernel: &RouteKernel{
		Err: "kernel: look up the route to ff0e::123: message too long", Errno: "EMSGSIZE",
	}}
	unjoined := arrival4
	unjoined.Dst = netip.MustParseAddr("239.1.2.4")
	unjoined.Kernel = &RouteKernel{
		Err: "kernel: look up the route to 239.1.2.4: invalid argument", Errno: "EINVAL", Why: WhyReversePath, Settings: forged.Kernel.Settings,
	}
	unfiltered := unjoined
	unfiltered.Kernel = &RouteKernel{
		Err: unjoined.Kernel.Err, Errno: "EINVAL", Settings: []RouteSetting{{Name: "net/ipv4/conf/all/rp_filter", Value: "0"}, {Name: "net/ipv4/conf/lan0/rp_filter", Value: "0"}},
	}
	martian := arrival4
	martian.Dst = netip.IPv4Unspecified()
	martian.Kernel = &RouteKernel{Err: "kernel: look up the route to 0.0.0.0: invalid argument", Errno: "EINVAL", Why: WhyMartianDestination}
	joined := arrival4
	joined.Dst = netip.MustParseAddr("239.1.2.3")
	routing := func(all, link RouteSetting) []RouteSetting {
		all.Name, link.Name = "net/ipv4/conf/all/mc_forwarding", "net/ipv4/conf/lan0/mc_forwarding"
		return []RouteSetting{all, link}
	}
	joined.Kernel = &RouteKernel{
		NoEntry: true, Route: netip.MustParsePrefix("239.1.2.3/32"), Type: "multicast", NextHops: []RouteNextHop{{Dev: "lo"}},
		Settings: routing(RouteSetting{Value: "0"}, RouteSetting{Value: "0"}),
	}
	routed := joined
	routed.Kernel = &RouteKernel{
		NoEntry: true, Route: joined.Kernel.Route, Type: "multicast", NextHops: joined.Kernel.NextHops,
		Why: WhyMulticastRouting, Settings: routing(RouteSetting{Value: "1"}, RouteSetting{Value: "1"}),
	}
	routingUnread := joined
	routingUnread.Kernel = &RouteKernel{
		NoEntry: true, Route: joined.Kernel.Route, Type: "multicast", NextHops: joined.Kernel.NextHops,
		Settings: routing(RouteSetting{Value: "1"}, RouteSetting{Err: "unreadable"}),
	}
	// a group's EHOSTUNREACH with all's mc_forwarding on and unread
	withheld := joined
	withheld.Kernel = &RouteKernel{
		Err: "kernel: look up the route to 239.1.2.3: no route to host", Errno: "EHOSTUNREACH", Why: WhyMulticastRouting,
		Settings: []RouteSetting{{Name: "net/ipv4/conf/all/mc_forwarding", Value: "1"}},
	}
	withheldUnread := joined
	withheldUnread.Kernel = &RouteKernel{
		Err: withheld.Kernel.Err, Errno: "EHOSTUNREACH", Why: WhyMulticastRouting,
		Settings: []RouteSetting{{Name: "net/ipv4/conf/all/mc_forwarding", Err: "unreadable"}},
	}
	allHosts := arrival4
	allHosts.Dst = netip.MustParseAddr("224.0.0.1")
	allHosts.Kernel = &RouteKernel{NoEntry: true, Route: netip.MustParsePrefix("224.0.0.1/32"), Type: "multicast", NextHops: []RouteNextHop{{Dev: "lo"}}}
	return map[string][]RouteInfo{
		"route-unread":         {behind},
		"route-own":            {own, cached, unspecified6},
		"route-link":           {link, subnetBroadcast, group6},
		"route-forwarding-off": {refused, dropped, unreachable, forwarded, withheld, withheldUnread},
		"route-rp-filter":      {forged, unread, blackholed, unjoined, unfiltered, martian},
		"route-darwin":         {darwinArrival, darwinOwn, darwinUnrouted, darwinUnspecified},
		"route-no-rule":        {unrouted, unsourced, unfit, unheld, refused4, blackhole6},
		"route-into-tun":       {intoTun},
		"route-no-entry":       {multicast, unspecified, broadcast, joined, routed, routingUnread, allHosts},
	}
}

func TestRouteRendersAsTheGoldenFiles(t *testing.T) {
	for name, infos := range routeFixtures() {
		var out strings.Builder
		for i, info := range infos {
			if i > 0 {
				out.WriteString("\n")
			}
			RenderRoute(&out, info)
		}
		golden(t, name+".txt", []byte(out.String()))
	}
	goldenJSON(t, "route-own.json", routeFixtures()["route-own"][0])
}

// the source and destination are of one family and carry no zone, and an
// unspecified source is a packet sent with none
func TestRoutePacketIsParsed(t *testing.T) {
	for name, test := range map[string]struct {
		src, dst string
		want     netip.Addr
		fails    bool
	}{
		"two IPv4 addresses":          {src: "192.0.2.1", dst: "203.0.113.1", want: netip.MustParseAddr("192.0.2.1")},
		"no IPv6 source":              {src: "::", dst: "2001:db8::1"},
		"no IPv4 source":              {src: "0.0.0.0", dst: "203.0.113.1"},
		"two families":                {src: "192.0.2.1", dst: "2001:db8::1", fails: true},
		"a zone":                      {src: "fe80::1%eth0", dst: "2001:db8::1", fails: true},
		"a destination that is no IP": {src: "192.0.2.1", dst: "example.org", fails: true},
	} {
		t.Run(name, func(t *testing.T) {
			src, _, err := ParseRoutePacket(test.src, test.dst)
			if (err != nil) != test.fails || err == nil && src != test.want {
				t.Fatalf("parsed %s to %s as %v and %v", test.src, test.dst, src, err)
			}
		})
	}
}

// routeSource answers the route view with the packet it was asked for
type routeSource struct{ fakeSource }

func (*routeSource) DebugRoute(src, dst netip.Addr, iif string) (RouteInfo, error) {
	return RouteInfo{Src: src, Dst: dst, IIF: iif, Arrival: ArrivalLink}, nil
}

// the route view discloses what the kernel and the rule dump tell any user,
// so a caller the root class refuses still reads it, and the packet reaches
// the source as asked
func TestRouteIsReadByACallerTheRootClassRefuses(t *testing.T) {
	server := injected(t, &routeSource{}, Caller{UID: 4242})
	query := url.Values{"src": {"0.0.0.0"}, "dst": {"203.0.113.1"}, "iif": {"lan0"}}
	status, body := get(t, server.Client(), server.URL+PathDebugRoute+"?"+query.Encode())
	if status != http.StatusOK || !strings.Contains(body, `"dst":"203.0.113.1"`) || !strings.Contains(body, `"iif":"lan0"`) || strings.Contains(body, `"src"`) {
		t.Errorf("uid 4242 asking for the route view was answered %d %q", status, body)
	}
	query.Set("dst", "2001:db8::1")
	if status, body := get(t, server.Client(), server.URL+PathDebugRoute+"?"+query.Encode()); status != http.StatusBadRequest {
		t.Errorf("a packet of two families was answered %d %q", status, body)
	}
}
