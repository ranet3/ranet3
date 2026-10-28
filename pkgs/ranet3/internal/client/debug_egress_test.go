// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"errors"
	"net/netip"
	"reflect"
	"testing"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/internal/egress"
)

// debugExit is an exit whose backend holds rules a debug read lists
type debugExit struct {
	fakeExit
	debug egress.ExitDebug
}

func (d *debugExit) Debug() egress.ExitDebug { return d.debug }

// A node with no exit answers that it holds none, an exit holding no rules
// answers its status alone, and one holding rules answers each rule, each
// family's lookups with their answers, and the settings read, the reply's
// answer only where the lookup asked for it
func TestDebugEgressCarriesTheExitsDebugRead(t *testing.T) {
	c := writable(t)
	if got := c.DebugEgress(); !reflect.DeepEqual(got, control.EgressInfo{}) {
		t.Errorf("a node with no exit answers %+v", got)
	}
	status := egress.Status{Backend: "nftables", Where: "a host", Ready4: true}
	c.SetExit(&fakeExit{status: status})
	plain := c.DebugEgress()
	if !plain.Enabled || !plain.Status.Enabled || !reflect.DeepEqual(plain.Status.Ready, []string{"ipv4"}) || plain.Rules != nil || plain.Families != nil {
		t.Errorf("an exit holding no rules answers %+v", plain)
	}

	member, read := netip.MustParseAddr("192.0.2.65"), netip.MustParseAddr("203.0.113.128")
	route := egress.Route{Type: "unicast", Hops: []egress.Hop{{Device: "up0"}, {Device: "up1", Dead: true, LinkDown: true}}}
	c.SetExit(&debugExit{fakeExit: fakeExit{status: status}, debug: egress.ExitDebug{
		Status: status,
		Rules:  []egress.RuleReading{{Spec: "out via ranet0 ipv4 masquerade", Wanted: true, Held: true, Counter: "flows", Packets: 3, Bytes: 180}},
		Families: []egress.FamilyReading{{Family: egress.FamilyIPv4, Ready: true, Forwarding: true,
			Lookups: []egress.Lookup{
				{Source: member, Destination: read, IIF: "ranet0", Reply: true},
				{Destination: netip.MustParseAddr("198.51.100.7")},
				{Destination: netip.MustParseAddr("198.51.100.8")},
			},
			Answers: []egress.Answer{
				{Route: route, ReplyIIF: "up0", Reply: egress.Route{Type: "unicast", Hops: []egress.Hop{{Device: "ranet0"}}}},
				{Err: errors.New("network is unreachable"), ReplyIIF: "up9"},
			},
		}},
		RPFilter: []egress.Setting{{Name: "net/ipv4/conf/all/rp_filter", Value: "1"}, {Name: "net/ipv4/conf/up0/rp_filter"}},
	}})
	got := c.DebugEgress()
	want := control.EgressInfo{
		Enabled: true, Status: plain.Status,
		Rules: []control.EgressRule{{Spec: "out via ranet0 ipv4 masquerade", Wanted: true, Held: true, Counter: "flows", Packets: 3, Bytes: 180}},
		Families: []control.EgressFamily{{Family: "ipv4", Ready: true, Forwarding: true, Lookups: []control.EgressLookup{
			{Source: member, Destination: read, IIF: "ranet0", Reply: true, Answered: true,
				Route:    &control.EgressRoute{Type: "unicast", NextHops: []control.RouteNextHop{{Dev: "up0"}, {Dev: "up1", Dead: true, LinkDown: true}}},
				ReplyIIF: "up0", ReplyRoute: &control.EgressRoute{Type: "unicast", NextHops: []control.RouteNextHop{{Dev: "ranet0"}}}},
			{Destination: netip.MustParseAddr("198.51.100.7"), Answered: true, Err: "network is unreachable"},
			{Destination: netip.MustParseAddr("198.51.100.8")},
		}}},
		RPFilter: []control.RouteSetting{{Name: "net/ipv4/conf/all/rp_filter", Value: "1"}, {Name: "net/ipv4/conf/up0/rp_filter", Err: "unreadable"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("the debug read answers\n%+v\nwant\n%+v", got, want)
	}
}
