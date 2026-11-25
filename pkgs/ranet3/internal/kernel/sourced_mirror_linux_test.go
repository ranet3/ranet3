// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/netlink"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/schema"
)

type sourcedMirrorConn struct {
	*fakeNetlink
	mirror       []netlink.Message
	main         []netlink.Message
	mainReads    int
	failMain     bool
	failMainOnce bool
	rules        []netlink.Message
	writes       []netlink.Message
	reads        int
	failAck      bool
	failAckOnce  bool
	up           bool
	view         netlinkPlatform
}

func (c *sourcedMirrorConn) link(index uint32, _ string) (linkInfo, error) {
	info := linkInfo{index: index, name: "tun7"}
	if c.up {
		info.flags = unix.IFF_UP
	}
	return info, nil
}

func (c *sourcedMirrorConn) execute(kind, flags uint16, body []byte) ([]netlink.Message, error) {
	_, err := c.fakeNetlink.execute(kind, flags, body)
	if err != nil {
		return nil, err
	}
	switch kind {
	case unix.RTM_GETRULE:
		return c.rules, nil
	case unix.RTM_NEWRULE:
		c.rules = append(c.rules, netlink.Message{Kind: kind, Data: slices.Clone(body)})
		return nil, nil
	case unix.RTM_DELRULE:
		target, ok := decodeDumpedRule(netlink.Message{Kind: kind, Data: body})
		if !ok {
			return nil, unix.EINVAL
		}
		for i, held := range c.rules {
			rule, ok := decodeDumpedRule(held)
			if ok && sourcedDeleteEquivalent(rule, target) {
				c.rules = slices.Delete(c.rules, i, i+1)
				break
			}
		}
		return nil, nil
	}
	if kind == unix.RTM_GETROUTE {
		message := netlink.Message{Data: body}
		for attr, value := range message.Attributes(unix.SizeofRtMsg) {
			if attr != unix.RTA_TABLE || len(value) != 4 || body[0] != unix.AF_INET6 {
				continue
			}
			switch binary.NativeEndian.Uint32(value) {
			case 201:
				c.reads++
				return c.mirror, nil
			case uint32(schema.TableMain):
				c.mainReads++
				if c.failMain || c.failMainOnce {
					c.failMainOnce = false
					return nil, unix.EIO
				}
				return c.main, nil
			}
		}
		return nil, nil
	}
	if body[4] != 201 {
		return nil, nil
	}
	switch kind {
	case unix.RTM_NEWROUTE:
		write := netlink.Message{Kind: kind, Data: slices.Clone(body)}
		c.writes = append(c.writes, write)
		c.mirror = append(c.mirror, write)
		if c.failAck || c.failAckOnce {
			c.failAckOnce = false
			return nil, unix.ENOBUFS
		}
	case unix.RTM_DELROUTE:
		for i, held := range c.mirror {
			route, ok := c.view.decodeRoute(held)
			if ok && slices.Equal(c.view.routeMessage(route, true), body) {
				c.mirror = slices.Delete(c.mirror, i, i+1)
				break
			}
		}
	}
	return nil, nil
}

func sourcedMirrorHarness(t *testing.T) (*Reconciler, *netlinkPlatform, *sourcedMirrorConn) {
	t.Helper()
	plat, fake := writePlatform(t)
	conn := &sourcedMirrorConn{fakeNetlink: fake}
	plat.conn = conn
	table := plat.table
	table.Sourced = &Sourced{To: []schema.Prefix{schema.MustPrefix("fd5e:db8:10:2::/96")}, ID: 201}
	plat.retable(table)
	conn.view = plat.sourcedRouteView(201)
	return newReconciler(table, Runtime{Interface: "tun7"}, nil, netstack.NewRouteTable(), plat), plat, conn
}

func mirrorFixture() (wanted []Route, original []Route) {
	broad := netip.MustParsePrefix("fd5e:db8:10::/48")
	child := netip.MustParsePrefix("fd5e:db8:10:2::2000:0/112")
	peer := Route{Destination: broad, Metric: 60}
	hold := Route{Destination: child, Source: netip.MustParsePrefix("fd5e:db8:10:1::/64"), Metric: 42, Unreachable: true}
	throw := Route{Destination: broad, Source: netip.MustParsePrefix("fd5e:db8:11::/48"), Metric: 55, Throw: true}
	return []Route{hold, throw, peer}, []Route{
		{Destination: netip.MustParsePrefix("::/0"), Metric: 1},
		{Destination: broad, Metric: 2, Cover: true},
		peer, hold, throw,
		{Destination: netip.MustParsePrefix("fd5e:db8:12::/48"), Metric: 3},
	}
}

func TestSourcedMirrorStagesWholeRefusalsBeforePeerAndExcludesDefault(t *testing.T) {
	r, plat, conn := sourcedMirrorHarness(t)
	want, original := mirrorFixture()
	if err := plat.mirrorSourced(r, original); err != nil {
		t.Fatal(err)
	}
	if len(conn.writes) != len(want) {
		t.Fatalf("201 writes = %d, want hold, throw and peer", len(conn.writes))
	}
	view := plat.sourcedRouteView(201)
	for index, route := range want {
		got, ok := view.decodeRoute(conn.writes[index])
		if !ok || got != route {
			t.Fatalf("201 write %d = %v, want %v", index, got, route)
		}
	}
	got, foreign, err := plat.SourcedRoutes(201)
	if err != nil || foreign != 0 || !slices.Equal(got, want) {
		t.Fatalf("whole mirror readback = %v, foreign %d, error %v", got, foreign, err)
	}
}

func TestSourcedMirrorRefusesForeignBeforeWrites(t *testing.T) {
	r, plat, conn := sourcedMirrorHarness(t)
	want, original := mirrorFixture()
	view := plat.sourcedRouteView(201)
	foreign := view.routeMessage(want[0], false)
	foreign[5] = unix.RTPROT_BOOT
	conn.mirror = []netlink.Message{{Kind: unix.RTM_NEWROUTE, Data: foreign}}
	if err := plat.mirrorSourced(r, original); err == nil || len(conn.writes) != 0 {
		t.Fatalf("foreign table object did not prevent mirror writes: %v, writes %v", err, conn.writes)
	}
}

func TestSourcedMirrorLostAckRereadsAndRefusesAdmission(t *testing.T) {
	r, plat, conn := sourcedMirrorHarness(t)
	_, original := mirrorFixture()
	conn.failAck = true
	if err := plat.mirrorSourced(r, original); !errors.Is(err, unix.ENOBUFS) || conn.reads < 3 || len(conn.writes) != 1 {
		t.Fatalf("lost acknowledgement was not reread and reported: %v, dumps %d, writes %d", err, conn.reads, len(conn.writes))
	}
}

func TestSourcedAdmissionWaitsForTargetTunAndFullMirror(t *testing.T) {
	r, plat, conn := sourcedMirrorHarness(t)
	source := netip.MustParsePrefix("fd5e:db8:10:1::/64")
	r.sourcedSources = map[netip.Prefix]struct{}{source: {}}
	_, original := mirrorFixture()
	if err := plat.armSourced(r, original); err == nil || len(conn.rules) != 0 {
		t.Fatalf("missing 5410 permitted ingress: %v, rules %v", err, conn.rules)
	}
	main := Rule{Family: FamilyIPv6, Priority: priorityMain, Table: schema.TableMain, suppress: SuppressUpTo(0)}
	conn.rules = []netlink.Message{{Kind: unix.RTM_NEWRULE, Data: plat.ruleMessage(main)}}
	if err := plat.armSourced(r, original); err != nil || len(conn.rules) != 1 {
		t.Fatalf("a down tun gained a sourced skip: %v, rules %v", err, conn.rules)
	}
	conn.up = true
	if err := plat.armSourced(r, original); err == nil || len(conn.rules) != 2 {
		t.Fatalf("missing 201 entries permitted pair admission: %v, rules %v", err, conn.rules)
	}
	if err := plat.mirrorSourced(r, original); err != nil {
		t.Fatal(err)
	}
	if err := plat.armSourced(r, original); err != nil {
		t.Fatal(err)
	}
	peer := sourcedPeerRule(r.table.Sourced.To[0], source, 201)
	all, err := plat.SourcedRules()
	if err != nil || !slices.ContainsFunc(all, func(held DumpedRule) bool {
		return sourcedExactShape(held, sourcedIngressRule(r.rt.Interface), r.table.Proto)
	}) || !slices.ContainsFunc(all, func(held DumpedRule) bool {
		return sourcedExactShape(held, peer, r.table.Proto)
	}) {
		t.Fatalf("5399 and eligible 5403 not read back: %v, %v", all, err)
	}
	var admission []uint32
	for _, sent := range conn.sent {
		if sent.kind != unix.RTM_NEWRULE {
			continue
		}
		rule, ok := decodeDumpedRule(netlink.Message{Kind: sent.kind, Data: sent.body})
		if ok {
			admission = append(admission, rule.Priority)
		}
	}
	if !slices.Equal(admission, []uint32{prioritySourcedTun, prioritySourcedPeer}) {
		t.Fatalf("sourced admission write order = %v", admission)
	}
}

func TestSourcedWithdrawalGuardsForeignFirstMatchUntilItLeaves(t *testing.T) {
	r, plat, conn := sourcedMirrorHarness(t)
	source := netip.MustParsePrefix("fd5e:db8:10:1::/64")
	peer := sourcedPeerRule(r.table.Sourced.To[0], source, 201)
	ingress := sourcedIngressRule(r.rt.Interface)
	conn.rules = []netlink.Message{
		{Kind: unix.RTM_NEWRULE, Data: plat.ruleMessage(ingress)},
		{Kind: unix.RTM_NEWRULE, Data: netlink.PutAttr(plat.ruleMessage(peer), unix.FRA_IP_PROTO, []byte{unix.IPPROTO_UDP})},
		{Kind: unix.RTM_NEWRULE, Data: plat.ruleMessage(peer)},
	}
	safe, err := plat.withdrawSourcedAdmission(r)
	if !safe || err == nil {
		t.Fatalf("ambiguous peer did not leave a guarded withdrawal debt: safe %v, error %v", safe, err)
	}
	all, err := plat.SourcedRules()
	guard := sourcedGuardRule(peer.To, source)
	if err != nil || len(all) != 3 || all[0].Unread != SelectorIPProto ||
		!slices.ContainsFunc(all, func(rule DumpedRule) bool { return sourcedExactShape(rule, peer, r.table.Proto) }) ||
		!slices.ContainsFunc(all, func(rule DumpedRule) bool { return sourcedExactShape(rule, guard, r.table.Proto) }) {
		t.Fatalf("first-match obstacle lost or unguarded: %v, %v", all, err)
	}
	for _, sent := range conn.sent {
		if sent.kind != unix.RTM_DELRULE {
			continue
		}
		dump, _ := decodeDumpedRule(netlink.Message{Kind: sent.kind, Data: sent.body})
		if dump.Priority == prioritySourcedPeer {
			t.Fatal("deleted a foreign first-match rule")
		}
	}
	conn.rules = slices.Delete(conn.rules, 0, 1)
	safe, err = plat.withdrawSourcedAdmission(r)
	if !safe || err != nil || len(conn.rules) != 0 {
		t.Fatalf("guard did not leave after the foreign selector: safe %v, error %v, rules %v", safe, err, conn.rules)
	}
}

func TestSourcedWithdrawalDoesNotDrop5410BehindForeignIngress(t *testing.T) {
	r, plat, conn := sourcedMirrorHarness(t)
	ingress := sourcedIngressRule(r.rt.Interface)
	conn.rules = []netlink.Message{
		{Kind: unix.RTM_NEWRULE, Data: netlink.PutAttr(plat.ruleMessage(ingress), unix.FRA_IP_PROTO, []byte{unix.IPPROTO_UDP})},
		{Kind: unix.RTM_NEWRULE, Data: plat.ruleMessage(ingress)},
	}
	safe, err := plat.withdrawSourcedAdmission(r)
	if safe || err == nil || len(conn.sent) != 1 || conn.sent[0].kind != unix.RTM_GETRULE {
		t.Fatalf("ambiguous 5399 allowed ordinary withdrawal: safe %v, error %v, writes %v", safe, err, conn.sent)
	}
	if err := r.withdraw(nil); err == nil || len(conn.sent) != 2 || conn.sent[1].kind != unix.RTM_GETRULE {
		t.Fatalf("ordinary 5410 changed behind a foreign 5399: %v, writes %v", err, conn.sent)
	}
}

func TestSourcedWithdrawalKeepsGuardAcrossSweepsWhileOnlyForeignRemains(t *testing.T) {
	r, plat, conn := sourcedMirrorHarness(t)
	source := netip.MustParsePrefix("fd5e:db8:10:1::/64")
	peer := sourcedPeerRule(r.table.Sourced.To[0], source, 201)
	guard := sourcedGuardRule(peer.To, source)
	conn.rules = []netlink.Message{
		{Kind: unix.RTM_NEWRULE, Data: plat.ruleMessage(peer)},
		{Kind: unix.RTM_NEWRULE, Data: netlink.PutAttr(plat.ruleMessage(peer), unix.FRA_IP_PROTO, []byte{unix.IPPROTO_UDP})},
	}
	for sweep := range 2 {
		safe, err := plat.withdrawSourcedAdmission(r)
		all, readErr := plat.SourcedRules()
		if !safe || err == nil || readErr != nil || len(all) != 2 || all[0].Unread != SelectorIPProto ||
			!slices.ContainsFunc(all, func(rule DumpedRule) bool { return sourcedExactShape(rule, guard, r.table.Proto) }) {
			t.Fatalf("sweep %d dropped foreign selector or its guard: safe %v, error %v, rules %v, read %v", sweep, safe, err, all, readErr)
		}
	}
	conn.rules = slices.Delete(conn.rules, 0, 1)
	safe, err := plat.withdrawSourcedAdmission(r)
	if !safe || err != nil || len(conn.rules) != 0 {
		t.Fatalf("guard stayed after its foreign selector left: safe %v, error %v, rules %v", safe, err, conn.rules)
	}
}

func TestSourcedReplacementDisarmsBeforeRemovingWholeMirror(t *testing.T) {
	r, plat, conn := sourcedMirrorHarness(t)
	source := netip.MustParsePrefix("fd5e:db8:10:1::/64")
	r.sourcedSources = map[netip.Prefix]struct{}{source: {}}
	conn.up = true
	main := Rule{Family: FamilyIPv6, Priority: priorityMain, Table: schema.TableMain, suppress: SuppressUpTo(0)}
	conn.rules = []netlink.Message{{Kind: unix.RTM_NEWRULE, Data: plat.ruleMessage(main)}}
	_, original := mirrorFixture()
	if err := plat.mirrorSourced(r, original); err != nil {
		t.Fatal(err)
	}
	if err := plat.armSourced(r, original); err != nil {
		t.Fatal(err)
	}
	changed := slices.Clone(original)
	var newHold Route
	for i := range changed {
		if changed[i].Unreachable {
			changed[i].Metric++
			newHold = changed[i]
		}
	}
	if err := plat.retireSourced(r, changed, false); err != nil {
		t.Fatal(err)
	}
	peer := sourcedPeerRule(r.table.Sourced.To[0], source, 201)
	all, err := plat.SourcedRules()
	if err != nil || slices.ContainsFunc(all, func(rule DumpedRule) bool { return sourcedExactShape(rule, peer, r.table.Proto) }) {
		t.Fatalf("old pair remained live during mirror replacement: %v, %v", all, err)
	}
	if err := plat.mirrorSourced(r, changed); err != nil {
		t.Fatal(err)
	}
	if err := plat.armSourced(r, changed); err != nil {
		t.Fatal(err)
	}
	want := sourcedMirrors(r.table.Sourced.To, changed)
	held, foreign, err := plat.SourcedRoutes(201)
	if err != nil || foreign != 0 || len(held) != len(want) {
		t.Fatalf("replacement mirror = %v, foreign %d, error %v, want %v", held, foreign, err, want)
	}
	for _, route := range want {
		if !slices.Contains(held, route) {
			t.Fatalf("missing replacement entry %s: %v", route, held)
		}
	}
	all, err = plat.SourcedRules()
	if err != nil || !slices.ContainsFunc(all, func(rule DumpedRule) bool { return sourcedExactShape(rule, peer, r.table.Proto) }) {
		t.Fatalf("pair was not rearmed after full mirror readback: %v, %v", all, err)
	}
	delPeer, delOld, addNew, rearm := -1, -1, -1, -1
	for i, sent := range conn.sent {
		if sent.kind == unix.RTM_DELRULE {
			dump, ok := decodeDumpedRule(netlink.Message{Kind: sent.kind, Data: sent.body})
			if ok && dump.Priority == prioritySourcedPeer {
				delPeer = i
			}
		}
		if sent.kind == unix.RTM_DELROUTE && sent.body[4] == 201 {
			delOld = i
		}
		if sent.kind == unix.RTM_NEWROUTE && sent.body[4] == 201 {
			route, ok := conn.view.decodeRoute(netlink.Message{Kind: sent.kind, Data: sent.body})
			if ok && route == newHold {
				addNew = i
			}
		}
		if sent.kind == unix.RTM_NEWRULE {
			dump, ok := decodeDumpedRule(netlink.Message{Kind: sent.kind, Data: sent.body})
			if ok && dump.Priority == prioritySourcedPeer {
				rearm = i
			}
		}
	}
	if delPeer < 0 || delPeer >= delOld || delOld >= addNew || addNew >= rearm {
		t.Fatalf("unsafe replacement order: peer delete %d, old mirror delete %d, new hold %d, peer rearm %d", delPeer, delOld, addNew, rearm)
	}
}

func TestSourcedDisableKeepsForeignFirstMatchAndRetiresOldSources(t *testing.T) {
	r, plat, conn := sourcedMirrorHarness(t)
	source := netip.MustParsePrefix("fd5e:db8:10:1::/64")
	standing := sourcedStandingRules(r.table.Sourced.To, map[netip.Prefix]struct{}{source: {}})
	for _, rule := range standing {
		conn.rules = append(conn.rules, netlink.Message{Kind: unix.RTM_NEWRULE, Data: plat.ruleMessage(rule)})
	}
	refusal := standing[len(standing)-1]
	foreign := netlink.Message{Kind: unix.RTM_NEWRULE,
		Data: netlink.PutAttr(plat.ruleMessage(refusal), unix.FRA_IP_PROTO, []byte{unix.IPPROTO_UDP})}
	conn.rules = slices.Insert(conn.rules, 0, foreign)
	if err := plat.clearSourcedStanding(); err == nil || len(conn.rules) != 2 {
		t.Fatalf("disable removed a foreign first-match refusal or did not retire other owned rules: %v, held %v", err, conn.rules)
	}
	all, err := plat.SourcedRules()
	if err != nil || all[0].Unread != SelectorIPProto ||
		!slices.ContainsFunc(all, func(rule DumpedRule) bool { return sourcedExactShape(rule, refusal, r.table.Proto) }) {
		t.Fatalf("foreign selector was touched while F was retained: %v, %v", all, err)
	}
	conn.rules = slices.Delete(conn.rules, 0, 1)
	if err := plat.clearSourcedStanding(); err != nil || len(conn.rules) != 0 {
		t.Fatalf("old source refusal was not retired after X left: %v, held %v", err, conn.rules)
	}
	guard := sourcedGuardRule(refusal.To, source)
	conn.rules = []netlink.Message{
		{Kind: unix.RTM_NEWRULE, Data: plat.ruleMessage(guard)},
		{Kind: unix.RTM_NEWRULE, Data: plat.ruleMessage(refusal)},
	}
	if err := plat.clearSourcedStanding(); err == nil || len(conn.rules) != 2 {
		t.Fatalf("disable removed standing protection while a pair guard remains: %v, held %v", err, conn.rules)
	}
}

func TestSourcedRunningGuardStaysForXAndReleasesAfterTwoRuleViews(t *testing.T) {
	r, plat, conn := sourcedMirrorHarness(t)
	source := netip.MustParsePrefix("fd5e:db8:10:1::/64")
	r.sourcedSources = map[netip.Prefix]struct{}{source: {}}
	conn.up = true
	peer := sourcedPeerRule(r.table.Sourced.To[0], source, 201)
	guard := sourcedGuardRule(peer.To, source)
	main := Rule{Family: FamilyIPv6, Priority: priorityMain, Table: schema.TableMain, suppress: SuppressUpTo(0)}
	conn.rules = []netlink.Message{
		{Kind: unix.RTM_NEWRULE, Data: plat.ruleMessage(main)},
		{Kind: unix.RTM_NEWRULE, Data: netlink.PutAttr(plat.ruleMessage(peer), unix.FRA_IP_PROTO, []byte{unix.IPPROTO_UDP})},
		{Kind: unix.RTM_NEWRULE, Data: plat.ruleMessage(guard)},
	}
	_, desired := mirrorFixture()
	if err := plat.mirrorSourced(r, desired); err != nil {
		t.Fatal(err)
	}
	if err := plat.armSourced(r, desired); err != nil {
		t.Fatal(err)
	}
	if err := plat.releaseSourcedGuards(r); err != nil {
		t.Fatal(err)
	}
	all, err := plat.SourcedRules()
	if err != nil || !slices.ContainsFunc(all, func(rule DumpedRule) bool { return sourcedExactShape(rule, guard, r.table.Proto) }) {
		t.Fatalf("guard left while a foreign pair selector still stood: %v, %v", all, err)
	}
	conn.rules = slices.Delete(conn.rules, 1, 2)
	if err := plat.releaseSourcedGuards(r); err != nil {
		t.Fatal(err)
	}
	all, err = plat.SourcedRules()
	if err != nil || slices.ContainsFunc(all, func(rule DumpedRule) bool { return sourcedExactShape(rule, guard, r.table.Proto) }) ||
		!slices.ContainsFunc(all, func(rule DumpedRule) bool { return sourcedExactShape(rule, peer, r.table.Proto) }) {
		t.Fatalf("eligible peer was not admitted after X left: %v, %v", all, err)
	}
}

func TestSourcedPassRetiresObsoleteDestinationsAndSources(t *testing.T) {
	r, plat, conn := sourcedMirrorHarness(t)
	old := r.table.Sourced.To[0]
	next := schema.MustPrefix("fd5e:db8:10:3::/96")
	source := netip.MustParsePrefix("fd5e:db8:10:1::/64")
	prior := sourcedStandingRules([]schema.Prefix{old}, map[netip.Prefix]struct{}{source: {}})
	current := sourcedStandingRules([]schema.Prefix{next}, nil)
	for _, rule := range append(prior, current...) {
		conn.rules = append(conn.rules, netlink.Message{Kind: unix.RTM_NEWRULE, Data: plat.ruleMessage(rule)})
	}
	r.table.Sourced = &Sourced{To: []schema.Prefix{next}, ID: 201}
	plat.retable(r.table)
	if err := plat.retireSourcedStanding(r); err != nil {
		t.Fatal(err)
	}
	all, err := plat.SourcedRules()
	if err != nil || len(all) != len(current) {
		t.Fatalf("old destination/source rules stayed active: %v, error %v", all, err)
	}
	for _, rule := range current {
		if !slices.ContainsFunc(all, func(held DumpedRule) bool { return sourcedExactShape(held, rule, r.table.Proto) }) {
			t.Fatalf("new standing protection was deleted: %s, held %v", rule, all)
		}
	}
}

func TestSourcedEffectiveMainUsesAnyOriginAndSignalsOnlyChangedAnswers(t *testing.T) {
	r, plat, conn := sourcedMirrorHarness(t)
	destination := r.table.Sourced.To[0]
	office := netip.MustParsePrefix("fd5e:db8:10:1::/64")
	r.sourcedSources = map[netip.Prefix]struct{}{office: {}}
	for _, rule := range sourcedStandingRules(r.table.Sourced.To, r.sourcedSources) {
		conn.rules = append(conn.rules, netlink.Message{Kind: unix.RTM_NEWRULE, Data: plat.ruleMessage(rule)})
	}
	main := plat.sourcedRouteView(schema.TableMain)
	addMain := func(prefix string, protocol uint8) {
		body := main.routeMessage(Route{Destination: netip.MustParsePrefix(prefix), Metric: 42}, false)
		body[5] = protocol
		conn.main = append(conn.main, netlink.Message{Kind: unix.RTM_NEWROUTE, Data: body})
	}
	addMain("fd5e:db8:10:2::/80", unix.RTPROT_KERNEL) // n-1 cannot escape the suppressor
	addMain("fd5e:db8:10:2::1000:0/112", unix.RTPROT_RA)
	if err := r.observeSourced(nil); err != nil {
		t.Fatal(err)
	}
	changed := r.SourcedChanges()
	select {
	case <-changed:
	default:
		t.Fatal("first kernel answer produced no change")
	}
	status, ok := r.SourcedStatus()
	child := netip.MustParsePrefix("fd5e:db8:10:2::1000:0/112")
	sections := sourcedSections(destination.Prefix, []netip.Prefix{child})
	if !ok || status.Named != 1 || status.Supported != 1 || status.Pairs != 1 || status.Rules != 4 ||
		len(status.Answers) != len(sections) {
		t.Fatalf("effective destination partition missing: %+v", status)
	}
	for i, section := range sections {
		answer := status.Answers[i]
		if answer.To != section || answer.From.IsValid() {
			t.Fatalf("false whole-destination or source answer: %+v", status)
		}
		if section == child {
			if answer.Kind != "main" || answer.MainPrefix != child || answer.MainProtocol != unix.RTPROT_RA {
				t.Fatalf("RA winner missing from child: %+v", answer)
			}
		} else if answer.Kind != "refused" || answer.MainPrefix.IsValid() {
			t.Fatalf("suppressed n-1 route escaped into sibling: %+v", answer)
		}
	}
	if err := r.observeSourced(nil); err != nil {
		t.Fatal(err)
	}
	select {
	case <-changed:
		t.Fatal("identical readback emitted a second kernel change")
	default:
	}
	addMain(destination.String(), unix.RTPROT_KERNEL)
	if err := r.observeSourced(nil); err != nil {
		t.Fatal(err)
	}
	select {
	case <-changed:
	default:
		t.Fatal("new n-exact connected winner did not signal")
	}
	status, ok = r.SourcedStatus()
	if !ok || len(status.Answers) != len(sections) ||
		!slices.ContainsFunc(status.Answers, func(answer SourcedAnswer) bool {
			return answer.Kind == "main" && answer.MainPrefix == destination.Prefix &&
				answer.MainProtocol == unix.RTPROT_KERNEL && answer.To != destination.Prefix
		}) || !slices.ContainsFunc(status.Answers, func(answer SourcedAnswer) bool {
		return answer.Kind == "main" && answer.MainPrefix == child && answer.MainProtocol == unix.RTPROT_RA
	}) {
		t.Fatalf("connected n-exact winner displaced a more specific route: %+v", status)
	}
	status.Answers[0].Kind = "corrupt"
	again, _ := r.SourcedStatus()
	if again.Answers[0].Kind != "main" {
		t.Fatal("a reader mutated the published kernel answer")
	}
}

func TestSourcedEffectiveHeldChildOverridesEligibleBroadPeer(t *testing.T) {
	r, plat, conn := sourcedMirrorHarness(t)
	destination := r.table.Sourced.To[0]
	source := netip.MustParsePrefix("fd5e:db8:10:1::/64")
	child := netip.MustParsePrefix("fd5e:db8:10:2::2000:0/112")
	r.sourcedSources = map[netip.Prefix]struct{}{source: {}}
	for _, rule := range append(sourcedStandingRules(r.table.Sourced.To, r.sourcedSources),
		sourcedIngressRule(r.rt.Interface), sourcedPeerRule(destination, source, 201),
		Rule{Family: FamilyIPv6, Priority: priorityMain, Table: schema.TableMain}) {
		conn.rules = append(conn.rules, netlink.Message{Kind: unix.RTM_NEWRULE, Data: plat.ruleMessage(rule)})
	}
	peer := Route{Destination: destination.Prefix, Metric: routeMetric(destination.Prefix, false)}
	hold := Route{Destination: child, Metric: routeMetric(child, true), Unreachable: true}
	for _, route := range []Route{peer, hold} {
		conn.mirror = append(conn.mirror, netlink.Message{Kind: unix.RTM_NEWROUTE, Data: conn.view.routeMessage(route, false)})
	}
	mesh := netstack.NewRouteTable()
	mesh.Set(netip.Prefix{}, destination.Prefix, &netstack.Peer{ID: "remote"})
	mesh.Set(netip.Prefix{}, child, netstack.Unreachable)
	r.src = mesh
	if err := r.observeSourced([]Route{peer, hold}); err != nil {
		t.Fatal(err)
	}
	status, ok := r.SourcedStatus()
	sections := sourcedSections(destination.Prefix, []netip.Prefix{child})
	if !ok || status.Rules != 6 || len(status.Answers) != 1+len(sections) ||
		status.Answers[0].Kind != "refused" || status.Answers[0].To != destination.Prefix ||
		!slices.ContainsFunc(status.Answers, func(answer SourcedAnswer) bool {
			return answer.Kind == "tunnel" && answer.From == source && answer.To != destination.Prefix
		}) || !slices.ContainsFunc(status.Answers, func(answer SourcedAnswer) bool {
		return answer.Kind == "refused" && answer.From == source && answer.To == child
	}) {
		t.Fatalf("coarse eligible pair swallowed a held child: %+v", status)
	}
	if conn.mainReads != 1 {
		t.Fatalf("one sourced pass made %d main dumps, not one", conn.mainReads)
	}
	conn.mirror = conn.mirror[:1] // the current hold has not yet reached 201
	if err := r.observeSourced([]Route{peer, hold}); err != nil {
		t.Fatal(err)
	}
	status, _ = r.SourcedStatus()
	if status.State != "pending" || !slices.ContainsFunc(status.Answers, func(answer SourcedAnswer) bool {
		return answer.Kind == "pending" && answer.From == source && answer.To == child
	}) {
		t.Fatalf("unmirrored hold reported settled packet carriage: %+v", status)
	}
	conn.mirror = append(conn.mirror, netlink.Message{Kind: unix.RTM_NEWROUTE, Data: conn.view.routeMessage(hold, false)})
	r.sourcedLimited = true
	if err := r.observeSourced([]Route{peer, hold}); err != nil {
		t.Fatal(err)
	}
	status, _ = r.SourcedStatus()
	if status.State != "limited" || !status.Limited || status.Rules != 6 {
		t.Fatalf("link growth did not expose the retained rule count and limit: %+v", status)
	}
	conn.failMain = true
	err := r.observeSourced([]Route{peer, hold})
	if !errors.Is(err, unix.EIO) {
		t.Fatalf("main dump failure was swallowed: %v", err)
	}
	r.sourcedFailure(err)
	status, _ = r.SourcedStatus()
	if status.State != "failing" || !strings.Contains(status.Error, "main routes") ||
		len(status.Answers) != 1 || status.Answers[0].Kind != "unknown" {
		t.Fatalf("failed main listing fabricated a known answer: %+v", status)
	}
}

func TestSourcedMainThrowContinuesIntoProtectedAdmission(t *testing.T) {
	r, _, _ := sourcedMirrorHarness(t)
	destination := r.table.Sourced.To[0]
	source := netip.MustParsePrefix("fd5e:db8:10:1::/64")
	child := netip.MustParsePrefix("fd5e:db8:10:2::1000:0/112")
	r.sourcedSources = map[netip.Prefix]struct{}{source: {}}
	var rules []DumpedRule
	for _, rule := range append(sourcedStandingRules(r.table.Sourced.To, r.sourcedSources),
		sourcedPeerRule(destination, source, 201)) {
		rules = append(rules, sourcedExpectedDump(rule, r.table.Proto))
	}
	peer := Route{Destination: destination.Prefix, Metric: routeMetric(destination.Prefix, false)}
	mesh := netstack.NewRouteTable()
	mesh.Set(netip.Prefix{}, destination.Prefix, &netstack.Peer{ID: "synthetic"})
	r.src = mesh
	main := []sourcedMainRoute{{to: child, protocol: unix.RTPROT_RA, kind: unix.RTN_THROW}}
	answer := sourcedAnswerAt(r, destination, source.Addr(), child.Addr(), main, []Route{peer}, []Route{peer}, rules, true, true)
	if answer.Kind != "tunnel" || !answer.Protection || answer.MainPrefix.IsValid() {
		t.Fatalf("main throw was incorrectly terminal: %+v", answer)
	}
	rules = append(rules, sourcedExpectedDump(sourcedGuardRule(destination, source), r.table.Proto))
	answer = sourcedAnswerAt(r, destination, source.Addr(), child.Addr(), main, []Route{peer}, []Route{peer}, rules, true, true)
	if answer.Kind != "refused" || !answer.Protection || answer.MainPrefix.IsValid() {
		t.Fatalf("throw bypassed retiring-pair guard: %+v", answer)
	}
	main[0].kind = unix.RTN_UNREACHABLE
	answer = sourcedAnswerAt(r, destination, source.Addr(), child.Addr(), main, []Route{peer}, []Route{peer}, rules, true, true)
	if answer.Kind != "refused" || answer.MainPrefix != child || answer.MainProtocol != unix.RTPROT_RA {
		t.Fatalf("terminal main refusal continued past its winning route: %+v", answer)
	}
}

func TestAbsentSourcedKeyDoesNotDumpMainOrAllocateSourcedState(t *testing.T) {
	plat, fake := writePlatform(t)
	conn := &sourcedMirrorConn{fakeNetlink: fake}
	plat.conn = conn
	r := newReconciler(plat.table, Runtime{Interface: "tun7"}, nil, netstack.NewRouteTable(), plat)
	if r.SourcedChanges() != nil {
		t.Fatal("a keyless node allocated a sourced signal")
	}
	allocations := testing.AllocsPerRun(100, func() {
		if err := r.observeSourced(nil); err != nil {
			panic(err)
		}
	})
	_, present := r.SourcedStatus()
	if allocations != 0 || conn.mainReads != 0 || present {
		t.Fatalf("a keyless node observed sourced policy: allocations %.1f, main dumps %d, state %v",
			allocations, conn.mainReads, present)
	}
}
