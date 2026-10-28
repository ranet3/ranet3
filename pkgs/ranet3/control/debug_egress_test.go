// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package control

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

// egressFixtures is one answer of the egress view for each golden file: an
// exit ready in IPv4 with each kind of counter, a rule not held and another
// writer's rule, and IPv6 not forwarded, a node with no exit, and an exit
// whose reply lookup leaves by its uplink while its listing failed now
func egressFixtures(passAt time.Time) map[string]EgressInfo {
	advertise := []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("2001:db8::/32")}
	status := EgressStatus{
		Enabled: true, Where: "nftables table ip and ip6 ranet3 chains limit and egress",
		Ready: []string{"ipv4"}, Unready: "the kernel does not forward ipv6",
		Advertise: advertise, Announced: advertise[:1], FlowsPerSource: 1000,
		PassAt: passAt, Installed: 5, Flows: 12, Bytes: 960,
	}
	lookup := EgressLookup{
		Source: netip.MustParseAddr("192.0.2.65"), Destination: netip.MustParseAddr("203.0.113.128"), IIF: "ranet0", Reply: true, Answered: true,
		Route:    &EgressRoute{Type: "unicast", NextHops: []RouteNextHop{{Dev: "up0"}, {Dev: "up1", Dead: true, LinkDown: true}}},
		ReplyIIF: "up0", ReplyRoute: &EgressRoute{Type: "unicast", NextHops: []RouteNextHop{{Dev: "ranet0"}}},
	}
	ready := EgressInfo{
		Enabled: true, Status: status,
		Rules: []EgressRule{
			{Spec: "out via ranet0 ipv4 untracked dropped", Wanted: true, Held: true, Counter: "packets", Packets: 2, Bytes: 120},
			{Spec: "out via ranet0 ipv4 limit 1000", Wanted: true, Held: true, Counter: "packets", Packets: 0},
			{Spec: "out via ranet0 ipv4 timeouts udp", Wanted: true, Held: true},
			{Spec: "out via ranet0 ipv4 masquerade", Wanted: true, Held: true, Counter: "flows", Packets: 12, Bytes: 960},
			{Spec: "local via ranet0 ipv4 from 192.0.2.1/32 masquerade", Wanted: true, Counter: "flows"},
			{Spec: "", Held: true, Counter: "packets", Packets: 4, Bytes: 240},
		},
		Families: []EgressFamily{
			{Family: "ipv4", Ready: true, Forwarding: true, Lookups: []EgressLookup{lookup}},
			{Family: "ipv6", Why: "the kernel does not forward ipv6"},
		},
		RPFilter: []RouteSetting{{Name: "net/ipv4/conf/all/rp_filter", Value: "0"}, {Name: "net/ipv4/conf/up0/rp_filter", Value: "2"}, {Name: "net/ipv4/conf/up1/rp_filter", Err: "unreadable"}},
	}
	unready := ready
	unreadyStatus := status
	unreadyStatus.Ready, unreadyStatus.Unready, unreadyStatus.Announced = nil, "the reply lookup of 192.0.2.65 for 203.0.113.0/24 from 203.0.113.128 arriving on up0 leaves by up0 rather than ranet0", nil
	unready.Status = unreadyStatus
	unready.Rules, unready.ReadErr = nil, "egress: read table ip ranet3: operation not permitted"
	failed := lookup
	failed.ReplyRoute = &EgressRoute{Type: "unicast", NextHops: []RouteNextHop{{Dev: "up0"}}}
	unready.Families = []EgressFamily{
		{Family: "ipv4", Why: unreadyStatus.Unready, Forwarding: true, Lookups: []EgressLookup{
			{Destination: netip.MustParseAddr("198.51.100.7"), Answered: true, Err: "kernel: look up the route to 198.51.100.7: network is unreachable"},
			failed,
		}},
		{Family: "ipv6", Why: "the route lookups answered 1 of 2", Unwritten: "its chains do not read back as written", Forwarding: true, Lookups: []EgressLookup{
			{Source: netip.MustParseAddr("3fff::41"), Destination: netip.MustParseAddr("2001:db8:8000::"), IIF: "ranet0", Reply: true},
		}},
	}
	return map[string]EgressInfo{"egress": ready, "egress-off": {}, "egress-unready": unready}
}

func TestEgressRendersAsTheGoldenFiles(t *testing.T) {
	for name, info := range egressFixtures(time.Now().Add(-2 * time.Minute)) {
		var out strings.Builder
		RenderEgress(&out, info)
		golden(t, name+".txt", []byte(out.String()))
	}
	goldenJSON(t, "egress.json", egressFixtures(time.Date(2026, 10, 28, 19, 0, 0, 0, time.UTC))["egress"])
}
