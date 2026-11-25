// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/netlink"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/schema"
)

func namedDestinations(count int) []schema.Prefix {
	out := make([]schema.Prefix, count)
	for i := range out {
		out[i] = schema.MustPrefix(fmt.Sprintf("2001:db8:%x::/48", i+1))
	}
	return out
}

func TestSourcedCapacityRefusesBeforeOpeningKernel(t *testing.T) {
	for _, tc := range []struct {
		name         string
		destinations int
		own          []schema.Announce
		want         string
	}{
		{"seventeen destinations with no sources", 17, nil, "needs 17 destinations and 0 destination-source pairs, up to 35 IPv6 rules"},
		{"six destinations with three sources", 6, []schema.Announce{
			{Prefix: schema.MustPrefix("2001:db8:aa::/64")},
			{Prefix: schema.MustPrefix("2001:db8:bb::/64")},
			{Prefix: schema.MustPrefix("2001:db8:cc::/64")},
		}, "needs 6 destinations and 18 destination-source pairs, up to 85 IPv6 rules"},
		{"sixteen destinations and one source", 16, []schema.Announce{{Prefix: schema.MustPrefix("2001:db8:aa::/64")}}, "opened"},
		{"sixteen isolated destinations", 16, nil, "opened"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opened := false
			table := (Table{Sourced: &Sourced{To: namedDestinations(tc.destinations)}}).WithSourcedOwn(tc.own, nil)
			_, err := newOn(table, Runtime{Interface: "tun0"}, netstack.NewRouteTable(), func(Table, Runtime) (platform, error) {
				opened = true
				return nil, errors.New("opened")
			})
			if err == nil || !strings.Contains(err.Error(), tc.want) || opened != (tc.want == "opened") {
				t.Fatalf("opened=%v, err=%v, want %q", opened, err, tc.want)
			}
		})
	}
}

func TestSourcedCapacityCountsAcceptedNetworksAndKeepsRefusedReload(t *testing.T) {
	link := netip.MustParsePrefix("2001:db8:aa::7/64")
	state := func() NetworkState {
		return NetworkState{IPv6: NetworkFamily{Links: []Link{{Name: "lan0", Prefixes: []netip.Prefix{link}}}}}
	}
	own := netip.MustParsePrefix("2001:db8:bb::/64")
	assigned := schema.MustPrefix("2001:db8:cc::1/64")
	base := (Table{Addresses: []schema.Prefix{assigned}, Sourced: &Sourced{To: namedDestinations(2)}}).WithSourcedOwn(
		[]schema.Announce{{Prefix: schema.PrefixFrom(own)}, {Prefix: schema.MustPrefix("2001:db8:bb::/80")}}, nil)
	if got := len(base.sourcedSources(state, nil)); got != 4 {
		t.Fatalf("nested unsourced announcements, link and assigned address yielded %d networks, want 4", got)
	}
	if err := base.refuseSourcedCapacity(state, nil); err != nil {
		t.Fatal(err)
	}
	reconciler, _, fake := harness(t, Table{}, Runtime{Network: state})
	oversize := base
	oversize.Sourced = &Sourced{To: namedDestinations(5)}
	if err := reconciler.SetTable(oversize, nil, nil); err == nil || !strings.Contains(err.Error(), "needs 5 destinations and 20 destination-source pairs, up to 91 IPv6 rules") {
		t.Fatalf("oversize reload: %v", err)
	}
	if reconciler.next.Load() != nil || reconciler.Table().Sourced != nil {
		t.Fatal("a refused reload published the sourced table")
	}
	if adds, deletes := fake.counts(); adds != 0 || deletes != 0 {
		t.Fatalf("refused reload wrote %d routes and removed %d", adds, deletes)
	}
}

func TestSourcedCapacityDeduplicatesAndFiltersSources(t *testing.T) {
	own := []schema.Announce{
		{Prefix: schema.MustPrefix("2001:db8:dd::/64")},
		{Prefix: schema.MustPrefix("2001:db8:ee::/64")},
		{Prefix: schema.MustPrefix("fe80::/64")},
		{Prefix: schema.MustPrefix("::/0")},
		{Prefix: schema.MustPrefix("2001:db8:ff::/64"), From: schema.MustPrefix("3fff:f00::/32")},
	}
	table := (Table{Sourced: &Sourced{To: namedDestinations(2)}}).WithSourcedOwn(own, []netip.Prefix{own[1].Prefix.Prefix})
	state := func() NetworkState {
		return NetworkState{IPv6: NetworkFamily{Links: []Link{{Name: "lan0", Prefixes: []netip.Prefix{
			netip.MustParsePrefix("2001:db8:dd::a/64"), netip.MustParsePrefix("::ffff:192.0.2.1/128"),
		}}}}}
	}
	if got := len(table.sourcedSources(state, nil)); got != 1 {
		t.Fatalf("duplicate link network and ineligible announcements yielded %d sources, want one", got)
	}
	if err := table.refuseSourcedCapacity(state, nil); err != nil {
		t.Fatal(err)
	}
}

func TestAbsentSourcedKeyDoesNotReadNetworksAtStartOrReload(t *testing.T) {
	network := func() NetworkState {
		t.Fatal("a keyless reconciler read sourced admission networks")
		return NetworkState{}
	}
	_, err := newOn(Table{}, Runtime{Interface: "tun0", Network: network}, netstack.NewRouteTable(), func(Table, Runtime) (platform, error) {
		return nil, errors.New("opened")
	})
	if err == nil || err.Error() != "opened" {
		t.Fatalf("keyless start: %v", err)
	}
	reconciler, _, _ := harness(t, Table{}, Runtime{Network: network})
	if err := reconciler.SetTable(Table{}, nil, nil); err != nil {
		t.Fatalf("keyless reload: %v", err)
	}
}

func TestSourcedStandingShapesProtectUnboundAndForwarded(t *testing.T) {
	destination := schema.MustPrefix("2001:db8:80::/96")
	source := netip.MustParsePrefix("2001:db8:aa::/64")
	forwarded := schema.PrefixFrom(source)
	got := sourcedStandingRules([]schema.Prefix{destination}, map[netip.Prefix]struct{}{source: {}})
	want := []Rule{
		{Family: FamilyIPv6, To: destination, IIF: linuxLoopback, Table: schema.TableMain, Priority: 5401, suppress: SuppressUpTo(95)},
		{Family: FamilyIPv6, To: destination, From: forwarded, Table: schema.TableMain, Priority: 5401, suppress: SuppressUpTo(95)},
		{Family: FamilyIPv6, To: destination, IIF: linuxLoopback, Priority: 5404, action: actionUnreachable},
		{Family: FamilyIPv6, To: destination, From: forwarded, Priority: 5404, action: actionUnreachable},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("sourced host and forwarded shapes = %v, want %v", got, want)
	}
	if skip := sourcedIngressRule("ranet0"); skip != (Rule{Family: FamilyIPv6, Priority: 5399, IIF: "ranet0", FWMask: ^uint32(0), action: actionGoto, target: 5410}) {
		t.Fatalf("unmarked tun skip = %v", skip)
	}
	if peer := sourcedPeerRule(destination, source, 201); peer != (Rule{Family: FamilyIPv6, To: destination, From: forwarded, Priority: 5403, Table: 201}) {
		t.Fatalf("admitted lookup = %v", peer)
	}
	if guard := sourcedGuardRule(destination, source); guard != (Rule{Family: FamilyIPv6, To: destination, From: forwarded, Priority: 5402, action: actionUnreachable}) {
		t.Fatalf("ambiguous-pair refusal = %v", guard)
	}
}

func TestSourcedMirrorKeepsWholeNondefaultEntries(t *testing.T) {
	destinations := []schema.Prefix{schema.MustPrefix("2001:db8:80::/96"), schema.MustPrefix("2001:db8:81::/96")}
	broad := Route{Destination: netip.MustParsePrefix("2001:db8::/32"), Metric: 42}
	bareThrow := Route{Destination: broad.Destination, Metric: 55, Throw: true}
	held := Route{Destination: netip.MustParsePrefix("2001:db8:80::/112"), Source: netip.MustParsePrefix("2001:db8:aa::/64"), Unreachable: true}
	thrown := Route{Destination: broad.Destination, Source: netip.MustParsePrefix("2001:db8:bb::/64"), Throw: true}
	desired := []Route{
		{Destination: netip.MustParsePrefix("::/0"), Metric: 1},
		{Destination: netip.MustParsePrefix("2001:db8::/32"), Metric: 1, Cover: true},
		broad,
		bareThrow,
		held,
		thrown,
		{Destination: netip.MustParsePrefix("2001:db8:90::/48")},
		{Destination: netip.MustParsePrefix("198.51.100.0/24")},
	}
	if got, want := sourcedMirrors(destinations, desired), []Route{broad, bareThrow, held, thrown}; !slices.Equal(got, want) {
		t.Fatalf("nondefault whole-prefix mirror = %v, want %v", got, want)
	}
}

func TestSourcedRuleReadbackRejectsUnreadAndAlteredSelectors(t *testing.T) {
	destination := schema.MustPrefix("2001:db8:80::/96")
	source := schema.MustPrefix("2001:db8:aa::/64")
	main := Rule{
		Family: FamilyIPv6, Priority: 5401, To: destination, From: source,
		Table: schema.TableMain, suppress: SuppressUpTo(95),
	}
	held := DumpedRule{
		Family: FamilyIPv6, Priority: 5401, To: destination.Prefix, From: source.Prefix,
		Action: "lookup", Table: 254, Suppress: SuppressUpTo(95), Protocol: DefaultProtocol,
	}
	if !sourcedExactShape(held, main, DefaultProtocol) {
		t.Fatal("the complete forwarded main-exception shape was not recognized")
	}
	for _, tc := range []struct {
		name string
		move func(*DumpedRule)
	}{
		{"unread selector", func(r *DumpedRule) { r.Unread = SelectorIPProto }},
		{"foreign protocol", func(r *DumpedRule) { r.Protocol = 99 }},
		{"wrong cutoff", func(r *DumpedRule) { r.Suppress = SuppressUpTo(96) }},
		{"wrong table", func(r *DumpedRule) { r.Table = 201 }},
		{"inverted", func(r *DumpedRule) { r.Invert = true }},
		{"output device", func(r *DumpedRule) { r.OIF = "eth0" }},
		{"mark selector", func(r *DumpedRule) { r.FWMask = ^uint32(0) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			altered := held
			tc.move(&altered)
			if sourcedExactShape(altered, main, DefaultProtocol) {
				t.Fatalf("lookalike was accepted: %+v", altered)
			}
		})
	}
	skip := sourcedIngressRule("ranet0")
	zeroMark := DumpedRule{Family: FamilyIPv6, Priority: 5399, IIF: "ranet0", FWMask: ^uint32(0), Action: "goto", Goto: 5410, Protocol: DefaultProtocol}
	if !sourcedExactShape(zeroMark, skip, DefaultProtocol) {
		t.Fatal("the explicit-zero-mark tun skip was not recognized")
	}
	zeroMark.FWMask = 0
	if sourcedExactShape(zeroMark, skip, DefaultProtocol) {
		t.Fatal("the tun skip accepted an unmasked mark")
	}
}

func TestSourcedAllProtocolDumpSeparatesLookalikesFromOrdinaryRules(t *testing.T) {
	plat, conn := writePlatform(t)
	destination := schema.MustPrefix("2001:db8:80::/96")
	from := netip.MustParsePrefix("2001:db8:aa::/64")
	peer := sourcedPeerRule(destination, from, 201)
	owned := plat.ruleMessage(peer)
	lookalike := netlink.PutAttr(plat.ruleMessage(peer), unix.FRA_IP_PROTO, []byte{unix.IPPROTO_UDP})
	foreign := replaceProtocol(t, plat.ruleMessage(peer), unix.RTPROT_STATIC)
	conn.replies = []netlink.Message{
		{Kind: unix.RTM_NEWRULE, Data: lookalike},
		{Kind: unix.RTM_NEWRULE, Data: owned},
		{Kind: unix.RTM_NEWRULE, Data: foreign},
	}
	plat.table.Sourced = &Sourced{To: []schema.Prefix{destination}, ID: 201}
	ordinary, err := plat.Rules()
	if err != nil || len(ordinary) != 0 {
		t.Fatalf("a sourced block leaked into ordinary pruning: %v, %v", ordinary, err)
	}
	all, err := plat.SourcedRules()
	if err != nil || len(all) != 3 || all[0].Unread != SelectorIPProto ||
		all[0].Protocol != DefaultProtocol || sourcedExactShape(all[0], peer, DefaultProtocol) ||
		!sourcedExactShape(all[1], peer, DefaultProtocol) || all[2].Protocol != unix.RTPROT_STATIC {
		t.Fatalf("all-protocol sourced readback = %v, %v", all, err)
	}
	plat.table.Sourced = nil
	ordinary, err = plat.Rules()
	if err != nil || len(ordinary) != 0 {
		t.Fatalf("the keyless ordinary reader took reserved rules for its own: %v, %v", ordinary, err)
	}
	all, err = plat.SourcedRules()
	if err != nil || len(all) != 3 {
		t.Fatalf("key removal hid reserved foreign occupants from the all-protocol reader: %v, %v", all, err)
	}
}

func TestSourcedPeerAdmissionExcludesDefaultHoldsAndCovers(t *testing.T) {
	first := schema.MustPrefix("2001:db8:80::/96")
	second := schema.MustPrefix("2001:db8:81::/96")
	a := netip.MustParsePrefix("2001:db8:aa::/64")
	b := netip.MustParsePrefix("2001:db8:bb::/64")
	c := netip.MustParsePrefix("2001:db8:cc::/64")
	desired := []Route{
		{Destination: netip.MustParsePrefix("::/0")},
		{Destination: first.Prefix, Cover: true},
		{Destination: netip.MustParsePrefix("2001:db8:80::/112"), Source: b, Unreachable: true},
		{Destination: netip.MustParsePrefix("2001:db8:80::/112"), Source: a},
		{Destination: first.Prefix, Source: netip.MustParsePrefix("2001:db8:cc::/80")},
		{Destination: second.Prefix, Source: a, Throw: true},
		{Destination: second.Prefix, Source: b},
	}
	got := sourcedPeerRules([]schema.Prefix{first, second}, map[netip.Prefix]struct{}{a: {}, b: {}, c: {}}, desired, 201)
	want := []Rule{sourcedPeerRule(first, a, 201), sourcedPeerRule(first, c, 201), sourcedPeerRule(second, b, 201)}
	if !slices.Equal(got, want) {
		t.Fatalf("coarse peer admissions = %v, want only the independent eligible entries %v", got, want)
	}
}

type sourcedRouteReplies struct{ *fakeNetlink }

func (f *sourcedRouteReplies) execute(kind, flags uint16, body []byte) ([]netlink.Message, error) {
	replies, err := f.fakeNetlink.execute(kind, flags, body)
	if kind == unix.RTM_GETROUTE && body[0] == unix.AF_INET {
		return nil, err
	}
	return replies, err
}

func TestSourcedRouteViewUsesSecondTableAndKeepsForeign(t *testing.T) {
	conn := &sourcedRouteReplies{fakeNetlink: &fakeNetlink{}}
	plat := &netlinkPlatform{table: Table{ID: 200, Proto: DefaultProtocol}, index: 7, conn: conn}
	route := Route{Destination: netip.MustParsePrefix("2001:db8::/32"), Source: netip.MustParsePrefix("2001:db8:aa::/64"), Metric: 42}
	view := plat.sourcedRouteView(201)
	foreign := view.routeMessage(Route{Destination: netip.MustParsePrefix("2001:db8:80::/96"), Metric: 42}, false)
	foreign[5] = unix.RTPROT_STATIC
	conn.replies = []netlink.Message{
		{Kind: unix.RTM_NEWROUTE, Data: view.routeMessage(route, false)},
		{Kind: unix.RTM_NEWROUTE, Data: foreign},
	}
	owned, others, err := plat.SourcedRoutes(201)
	if err != nil || !slices.Equal(owned, []Route{route}) || others != 1 {
		t.Fatalf("table-201 readback owned=%v foreign=%d err=%v", owned, others, err)
	}
	if err := plat.AddSourcedRoute(201, route); err != nil {
		t.Fatal(err)
	}
	if err := plat.DelSourcedRoute(201, route); err != nil {
		t.Fatal(err)
	}
	if len(conn.sent) != 4 || plat.table.ID != 200 {
		t.Fatalf("table-201 operations moved the mesh table: %d messages, table %d", len(conn.sent), plat.table.ID)
	}
	for _, sent := range conn.sent {
		message := netlink.Message{Data: sent.body}
		found := false
		for kind, value := range message.Attributes(unix.SizeofRtMsg) {
			if kind == unix.RTA_TABLE && len(value) == 4 && binary.NativeEndian.Uint32(value) == 201 {
				found = true
			}
		}
		if !found || sent.kind == unix.RTM_GETROUTE && sent.body[5] != 0 {
			t.Fatalf("table-201 operation carried another table or filtered the dump: kind %d, body %v", sent.kind, sent.body)
		}
	}
}

func TestSourcedRuleDeleteRespectsForeignFirstMatch(t *testing.T) {
	destination := schema.MustPrefix("2001:db8:80::/96")
	source := netip.MustParsePrefix("2001:db8:aa::/64")
	wanted := sourcedPeerRule(destination, source, 201)
	ours := DumpedRule{
		Family: FamilyIPv6, Priority: 5403, To: destination.Prefix, From: source,
		Action: "lookup", Table: 201, Protocol: DefaultProtocol,
	}
	foreign := ours
	foreign.Unread = SelectorIPProto
	for _, tc := range []struct {
		name      string
		all       []DumpedRule
		shadowed  bool
		ambiguous bool
	}{
		{"lookalike first", []DumpedRule{foreign, ours}, true, true},
		{"owned rule first", []DumpedRule{ours, foreign}, false, true},
		{"only lookalike remains", []DumpedRule{foreign}, true, true},
		{"nothing remains", nil, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := sourcedShadowed(tc.all, wanted, DefaultProtocol); got != tc.shadowed {
				t.Fatalf("first-match delete hazard = %v, want %v", got, tc.shadowed)
			}
			if got := sourcedAmbiguous(tc.all, wanted, DefaultProtocol); got != tc.ambiguous {
				t.Fatalf("foreign deletion ambiguity = %v, want %v", got, tc.ambiguous)
			}
		})
	}
	foreign.Protocol = unix.RTPROT_STATIC
	if sourcedShadowed([]DumpedRule{foreign, ours}, wanted, DefaultProtocol) ||
		sourcedAmbiguous([]DumpedRule{foreign, ours}, wanted, DefaultProtocol) {
		t.Fatal("a foreign protocol was treated as a matching delete target")
	}
}

type sourcedPreflightReplies struct {
	*fakeNetlink
	routeReplies []netlink.Message
	ruleReplies  []netlink.Message
}

func (f *sourcedPreflightReplies) execute(kind, flags uint16, body []byte) ([]netlink.Message, error) {
	_, err := f.fakeNetlink.execute(kind, flags, body)
	switch kind {
	case unix.RTM_GETROUTE:
		if body[0] == unix.AF_INET6 {
			return f.routeReplies, err
		}
	case unix.RTM_GETRULE:
		return f.ruleReplies, err
	}
	return nil, err
}

func TestSourcedInitialOccupancyRefusesForeignBeforeWrites(t *testing.T) {
	destination := schema.MustPrefix("2001:db8:80::/96")
	table := Table{ID: 200, Proto: DefaultProtocol, Sourced: &Sourced{To: []schema.Prefix{destination}, ID: 201}}
	conn := &sourcedPreflightReplies{fakeNetlink: &fakeNetlink{}}
	plat := &netlinkPlatform{table: table, index: 7, conn: conn}
	standing := sourcedStandingRules([]schema.Prefix{destination}, nil)
	owned := netlink.Message{Kind: unix.RTM_NEWRULE, Data: plat.ruleMessage(standing[0])}
	conn.ruleReplies = []netlink.Message{owned}
	if err := plat.preflightSourcedOccupancy(table, "tun7"); err != nil {
		t.Fatalf("an exact owned rule must be adoptable: %v", err)
	}
	conn.ruleReplies = []netlink.Message{{Kind: unix.RTM_NEWRULE,
		Data: netlink.PutAttr(plat.ruleMessage(standing[0]), unix.FRA_IP_PROTO, []byte{unix.IPPROTO_UDP})}}
	if err := plat.preflightSourcedOccupancy(table, "tun7"); err == nil {
		t.Fatal("an unread-selector occupant bypassed initial preflight")
	}
	conn.ruleReplies = []netlink.Message{owned}
	view := plat.sourcedRouteView(201)
	route := Route{Destination: destination.Prefix}
	foreign := view.routeMessage(route, false)
	foreign[5] = unix.RTPROT_STATIC
	conn.routeReplies = []netlink.Message{{Kind: unix.RTM_NEWROUTE, Data: foreign}}
	if err := plat.preflightSourcedOccupancy(table, "tun7"); err == nil {
		t.Fatal("a foreign table-201 route bypassed initial preflight")
	}
	conn.routeReplies = []netlink.Message{{Kind: unix.RTM_NEWROUTE, Data: view.routeMessage(route, false)}}
	if err := plat.preflightSourcedOccupancy(table, "tun7"); err != nil {
		t.Fatalf("an owned mirror must be adoptable: %v", err)
	}
	before := len(conn.sent)
	table.Sourced = nil
	if err := plat.preflightSourcedOccupancy(table, "tun7"); err != nil || len(conn.sent) != before {
		t.Fatalf("keyless preflight read the kernel: error %v, before %d, after %d", err, before, len(conn.sent))
	}
	for _, sent := range conn.sent {
		if sent.kind != unix.RTM_GETRULE && sent.kind != unix.RTM_GETROUTE {
			t.Fatalf("preflight wrote a kernel object: kind %d", sent.kind)
		}
	}
}

func TestSourcedStartupReadsOwnershipBeforeAnyKernelWrite(t *testing.T) {
	destination := schema.MustPrefix("2001:db8:80::/96")
	table := Table{ID: 200, Proto: DefaultProtocol, Sourced: &Sourced{To: []schema.Prefix{destination}, ID: 201}}
	route := Route{Destination: destination.Prefix, Throw: true}
	for _, tc := range []struct {
		name, refusal string
		foreignRoute  bool
		unreadRule    bool
	}{
		{name: "foreign mirror", refusal: "foreign routes", foreignRoute: true},
		{name: "unread rule", refusal: "unexpected occupant", unreadRule: true},
		{name: "exact occupants"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := &sourcedPreflightReplies{fakeNetlink: &fakeNetlink{}}
			plat := &netlinkPlatform{table: table, conn: conn}
			view := plat.sourcedRouteView(table.Sourced.ID)
			routeData := view.routeMessage(route, false)
			if tc.foreignRoute {
				routeData[5] = unix.RTPROT_STATIC
			}
			conn.routeReplies = []netlink.Message{{Kind: unix.RTM_NEWROUTE, Data: routeData}}
			ruleData := plat.ruleMessage(sourcedStandingRules(table.Sourced.To, nil)[0])
			if tc.unreadRule {
				ruleData = netlink.PutAttr(ruleData, unix.FRA_IP_PROTO, []byte{unix.IPPROTO_UDP})
			}
			conn.ruleReplies = []netlink.Message{{Kind: unix.RTM_NEWRULE, Data: ruleData}}
			err := preflightSourcedOn(conn, table, nil, "tun7")
			if tc.refusal == "" && err != nil || tc.refusal != "" && (err == nil || !strings.Contains(err.Error(), tc.refusal)) {
				t.Fatalf("preflight error %v, want %q", err, tc.refusal)
			}
			if len(conn.sent) < 3 || conn.sent[0].kind != unix.RTM_GETLINK ||
				conn.sent[1].kind != unix.RTM_GETADDR || conn.sent[2].kind != unix.RTM_GETROUTE {
				t.Fatalf("capacity and occupancy order: %+v", conn.sent)
			}
			for _, sent := range conn.sent {
				switch sent.kind {
				case unix.RTM_GETLINK, unix.RTM_GETADDR, unix.RTM_GETROUTE, unix.RTM_GETRULE:
				default:
					t.Fatalf("preconstruction preflight wrote kernel object %d", sent.kind)
				}
			}
		})
	}
}

func TestSourcedInitialOccupancyChecksEveryRuleShape(t *testing.T) {
	destination := schema.MustPrefix("2001:db8:80::/96")
	source := netip.MustParsePrefix("2001:db8:aa::/64")
	table := Table{ID: 200, Proto: DefaultProtocol, Sourced: &Sourced{To: []schema.Prefix{destination}, ID: 201}}
	plat, _ := writePlatform(t)
	rules := append(sourcedStandingRules([]schema.Prefix{destination}, map[netip.Prefix]struct{}{source: {}}),
		sourcedIngressRule("tun7"), sourcedGuardRule(destination, source), sourcedPeerRule(destination, source, 201))
	for _, rule := range rules {
		dump, ok := decodeDumpedRule(netlink.Message{Kind: unix.RTM_NEWRULE, Data: plat.ruleMessage(rule)})
		if !ok || !sourcedOccupiedShape(dump, table, "tun7") {
			t.Fatalf("exact rule at priority %d rejected: %+v", rule.Priority, dump)
		}
		dump.Unread = SelectorIPProto
		if sourcedOccupiedShape(dump, table, "tun7") {
			t.Fatalf("unread-selector rule at priority %d adopted", rule.Priority)
		}
	}
	ingress := sourcedExpectedDump(sourcedIngressRule("tun7"), DefaultProtocol)
	ingress.FWMask = 0
	if sourcedOccupiedShape(ingress, table, "tun7") {
		t.Fatal("a zero mark without an explicit mask was adopted")
	}
	main := sourcedExpectedDump(rules[0], DefaultProtocol)
	main.Suppress = SuppressUpTo(0)
	if sourcedOccupiedShape(main, table, "tun7") {
		t.Fatal("a main exception without the n-1 suppression was adopted")
	}
}
