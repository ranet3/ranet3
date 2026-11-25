// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"encoding/binary"
	"net/netip"
	"slices"
	"testing"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/netlink"
	"ranet3.com/pkgs/ranet3/schema"
)

func TestSourcedMirrorDistinguishesRouteAttributesWithoutDeleting(t *testing.T) {
	cases := []struct {
		name   string
		change func([]byte) []byte
	}{
		{"gateway", func(b []byte) []byte {
			return netlink.PutAttr(b, unix.RTA_GATEWAY, netlink.AddressBytes(netip.MustParseAddr("2001:db8::1")))
		}},
		{"preferred source", func(b []byte) []byte {
			return netlink.PutAttr(b, unix.RTA_PREFSRC, netlink.AddressBytes(netip.MustParseAddr("2001:db8::2")))
		}},
		{"unknown attribute", func(b []byte) []byte { return netlink.PutAttr(b, 0x1234, []byte{1}) }},
		{"route flags", func(b []byte) []byte { b[8] = 1; return b }},
		{"nondefault preference", func(b []byte) []byte { return netlink.PutAttr(b, unix.RTA_PREF, []byte{1}) }},
		{"expiring cache", func(b []byte) []byte {
			cache := make([]byte, 32)
			binary.NativeEndian.PutUint32(cache[8:], 10)
			return netlink.PutAttr(b, unix.RTA_CACHEINFO, cache)
		}},
		{"duplicate metric", func(b []byte) []byte { return netlink.PutAttrU32(b, unix.RTA_PRIORITY, 1024) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, plat, conn := sourcedMirrorHarness(t)
			destination := r.table.Sourced.To[0].Prefix
			route := Route{Destination: destination, Metric: routeMetric(destination, false)}
			body := conn.view.routeMessage(route, false)
			conn.mirror = []netlink.Message{{Kind: unix.RTM_NEWROUTE, Data: tc.change(body)}}
			ours, foreign, err := plat.SourcedRoutes(201)
			if err != nil || foreign != 1 || len(ours) != 0 {
				t.Fatalf("route with %s counted as owned: routes %v foreign %d error %v", tc.name, ours, foreign, err)
			}
			if err := plat.preflightSourcedOccupancy(r.table, r.rt.Interface); err == nil {
				t.Fatal("preflight accepted distinguishable mirror occupant")
			}
			if err := plat.mirrorSourced(r, nil); err == nil || len(conn.writes) != 0 {
				t.Fatalf("mirror changed foreign occupant: error %v writes %v", err, conn.writes)
			}
		})
	}
}

func TestSourcedMirrorAcceptsExactRouteWithKernelMetadata(t *testing.T) {
	r, plat, conn := sourcedMirrorHarness(t)
	destination := r.table.Sourced.To[0].Prefix
	peer := Route{Destination: destination, Source: netip.MustParsePrefix("fd5e:db8:10:1::/64"),
		Metric: routeMetric(destination, false)}
	hold := Route{Destination: destination, Metric: routeMetric(destination, true), Unreachable: true}
	peerBody := conn.view.routeMessage(peer, false)
	peerBody = netlink.PutAttr(peerBody, unix.RTA_CACHEINFO, make([]byte, 32))
	peerBody = netlink.PutAttr(peerBody, unix.RTA_PREF, []byte{0})
	holdBody := netlink.PutAttrU32(conn.view.routeMessage(hold, false), unix.RTA_OIF, 1)
	conn.mirror = []netlink.Message{{Kind: unix.RTM_NEWROUTE, Data: peerBody},
		{Kind: unix.RTM_NEWROUTE, Data: holdBody}}
	ours, foreign, err := plat.SourcedRoutes(201)
	if err != nil || foreign != 0 || !slices.Contains(ours, peer) || !slices.Contains(ours, hold) || len(ours) != 2 {
		t.Fatalf("canonical sourced mirror lost ownership: routes %v foreign %d error %v", ours, foreign, err)
	}
}

func TestSourcedRetiringPairGuardsForeignOnlyRuleUntilBothViewsResolve(t *testing.T) {
	r, plat, conn := sourcedMirrorHarness(t)
	source := netip.MustParsePrefix("fd5e:db8:10:1::/64")
	peer := sourcedPeerRule(r.table.Sourced.To[0], source, 201)
	guard := sourcedGuardRule(peer.To, source)
	foreign := netlink.Message{Kind: unix.RTM_NEWRULE,
		Data: netlink.PutAttr(plat.ruleMessage(peer), unix.FRA_IP_PROTO, []byte{unix.IPPROTO_UDP})}
	conn.rules = []netlink.Message{foreign}
	for sweep := range 2 {
		if err := plat.retireSourced(r, nil, true); err != nil {
			t.Fatalf("sweep %d: %v", sweep, err)
		}
		if err := plat.releaseSourcedGuards(r); err != nil {
			t.Fatalf("sweep %d: %v", sweep, err)
		}
		all, err := plat.SourcedRules()
		if err != nil || len(all) != 2 || all[0].Unread != SelectorIPProto ||
			!slices.ContainsFunc(all, func(rule DumpedRule) bool { return sourcedExactShape(rule, guard, r.table.Proto) }) {
			t.Fatalf("sweep %d lost foreign-only guard: %v, %v", sweep, all, err)
		}
	}
	conn.rules = slices.Delete(conn.rules, 0, 1)
	if err := plat.releaseSourcedGuards(r); err != nil || len(conn.rules) != 0 {
		t.Fatalf("resolved pair retained guard: %v, rules %v", err, conn.rules)
	}
}

func TestSourcedReloadRetiresPreviousNamedPairEvenWithoutOwnedPeer(t *testing.T) {
	r, plat, conn := sourcedMirrorHarness(t)
	old := r.table
	r.reloadPrevious = &accepted{table: old}
	next := old
	next.Sourced = &Sourced{To: []schema.Prefix{schema.MustPrefix("fd5e:db8:10:3::/96")}, ID: 201}
	r.table = next
	plat.retable(next)
	source := netip.MustParsePrefix("fd5e:db8:10:1::/64")
	peer := sourcedPeerRule(old.Sourced.To[0], source, 201)
	conn.rules = []netlink.Message{{Kind: unix.RTM_NEWRULE,
		Data: netlink.PutAttr(plat.ruleMessage(peer), unix.FRA_IP_PROTO, []byte{unix.IPPROTO_UDP})}}
	if err := plat.retireSourced(r, nil, true); err != nil {
		t.Fatal(err)
	}
	guard := sourcedGuardRule(peer.To, source)
	all, err := plat.SourcedRules()
	if err != nil || len(all) != 2 || all[0].Unread != SelectorIPProto ||
		!slices.ContainsFunc(all, func(rule DumpedRule) bool { return sourcedExactShape(rule, guard, r.table.Proto) }) {
		t.Fatalf("old pair lost its guard during destination move: %v, %v", all, err)
	}
}
