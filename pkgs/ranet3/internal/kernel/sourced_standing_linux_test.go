// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/netlink"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/schema"
)

type sourcedStandingConn struct {
	*fakeNetlink
	rules   []netlink.Message
	failNew bool
	writes  atomic.Int64
	up      bool
}

func (c *sourcedStandingConn) link(index uint32, _ string) (linkInfo, error) {
	info := linkInfo{index: index, name: "tun7"}
	if c.up {
		info.flags = unix.IFF_UP
	}
	return info, nil
}

func (c *sourcedStandingConn) execute(kind, flags uint16, body []byte) ([]netlink.Message, error) {
	switch kind {
	case unix.RTM_NEWRULE, unix.RTM_DELRULE, unix.RTM_NEWROUTE, unix.RTM_DELROUTE, unix.RTM_NEWADDR, unix.RTM_DELADDR:
		c.writes.Add(1)
	}
	_, err := c.fakeNetlink.execute(kind, flags, body)
	if err != nil {
		return nil, err
	}
	switch kind {
	case unix.RTM_GETRULE:
		return c.rules, nil
	case unix.RTM_NEWRULE:
		if c.failNew {
			return nil, unix.ENOBUFS
		}
		c.rules = append(c.rules, netlink.Message{Kind: kind, Data: slices.Clone(body)})
	}
	return nil, nil
}

func sourcedStandingHarness(t *testing.T) (*Reconciler, *netlinkPlatform, *sourcedStandingConn) {
	t.Helper()
	plat, fake := writePlatform(t)
	conn := &sourcedStandingConn{fakeNetlink: fake}
	plat.conn = conn
	key := &Sourced{To: []schema.Prefix{schema.MustPrefix("fd5e:db8:10:2::/96")}, ID: 201}
	table := plat.table
	table.Sourced = key
	plat.retable(table)
	return newReconciler(table, Runtime{Interface: "tun7"}, nil, netstack.NewRouteTable(), plat), plat, conn
}

func TestSourcedStandingRefusesBeforeOrdinaryWritesAndReadsBack(t *testing.T) {
	r, plat, conn := sourcedStandingHarness(t)
	if err := r.reconcile(); err != nil {
		t.Fatal(err)
	}
	var writes []netlink.Message
	for _, sent := range conn.sent {
		switch sent.kind {
		case unix.RTM_NEWRULE, unix.RTM_NEWROUTE, unix.RTM_NEWADDR:
			writes = append(writes, netlink.Message{Kind: sent.kind, Data: sent.body})
		}
	}
	if len(writes) < 2 {
		t.Fatalf("no protection written: %v", writes)
	}
	for index, priority := range []uint32{prioritySourcedRefused, prioritySourcedMain} {
		got, ok := decodeDumpedRule(writes[index])
		if !ok || got.Priority != priority {
			t.Fatalf("write %d is not sourced priority %d: %+v", index, priority, writes[index])
		}
	}
	rules, err := plat.SourcedRules()
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range sourcedStandingRules(r.table.Sourced.To, map[netip.Prefix]struct{}{}) {
		if !slices.ContainsFunc(rules, func(held DumpedRule) bool { return sourcedExactShape(held, rule, r.table.Proto) }) {
			t.Fatalf("the standing rule did not read back: %s", rule)
		}
	}
}

func TestSourcedStandingFailurePreventsOrdinaryKernelWrites(t *testing.T) {
	r, _, conn := sourcedStandingHarness(t)
	conn.failNew = true
	if err := r.reconcile(); !errors.Is(err, unix.ENOBUFS) {
		t.Fatalf("failed refusal write was not returned: %v", err)
	}
	for _, sent := range conn.sent {
		if sent.kind == unix.RTM_NEWRULE || sent.kind == unix.RTM_NEWROUTE || sent.kind == unix.RTM_NEWADDR {
			if sent.kind != unix.RTM_NEWRULE {
				t.Fatalf("an ordinary kernel object was written after failed protection: kind %d", sent.kind)
			}
			got, ok := decodeDumpedRule(netlink.Message{Kind: sent.kind, Data: sent.body})
			if !ok || got.Priority != prioritySourcedRefused {
				t.Fatalf("an ordinary rule preceded the failed refusal: %+v", got)
			}
		}
	}
}

func TestSourcedStandingDoesNotMistakeUnreadSelectorForOwnRefusal(t *testing.T) {
	r, plat, conn := sourcedStandingHarness(t)
	refusal := sourcedStandingRules(r.table.Sourced.To, nil)[1]
	x := netlink.PutAttr(plat.ruleMessage(refusal), unix.FRA_IP_PROTO, []byte{unix.IPPROTO_UDP})
	conn.rules = []netlink.Message{{Kind: unix.RTM_NEWRULE, Data: x}}
	if err := plat.standSourced(r, passNetwork{}); err != nil {
		t.Fatal(err)
	}
	all, err := plat.SourcedRules()
	if err != nil || len(all) != 3 || all[0].Unread != SelectorIPProto ||
		!slices.ContainsFunc(all, func(held DumpedRule) bool { return sourcedExactShape(held, refusal, r.table.Proto) }) {
		t.Fatalf("unread X and the owned refusal did not both stand: %v, %v", all, err)
	}
}

type sourcedRunPlatform struct{ *netlinkPlatform }

func (*sourcedRunPlatform) Notify() <-chan struct{} {
	return nil
}

func (*sourcedRunPlatform) Close() error {
	return nil
}

func TestSourcedFirstPassReportsUninstalledProtection(t *testing.T) {
	r, plat, conn := sourcedStandingHarness(t)
	conn.failNew = true
	r.use(&sourcedRunPlatform{plat})
	r.table.Reconcile = schema.Duration(time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ended := make(chan error, 1)
	go func() { ended <- r.Run(ctx) }()
	select {
	case <-r.FirstPass():
		if err := r.FirstPassError(); !errors.Is(err, unix.ENOBUFS) {
			t.Errorf("first pass published success despite a failed refusal: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("first pass did not report its failure")
	}
	if err := r.SetEnabled(true); !errors.Is(err, unix.ENOBUFS) || r.Enabled() {
		t.Errorf("sourced enable did not report the next kernel failure: %v, enabled %v", err, r.Enabled())
	}
	cancel()
	select {
	case <-ended:
	case <-time.After(3 * time.Second):
		t.Error("failed reconciler did not stop")
	}
}

func TestSourcedReloadRefusesForeignSelectorWithoutPublishingOrWriting(t *testing.T) {
	r, plat, conn := sourcedStandingHarness(t)
	r.use(&sourcedRunPlatform{plat})
	r.table.Reconcile = schema.Duration(time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ended := make(chan error, 1)
	go func() { ended <- r.Run(ctx) }()
	select {
	case <-r.FirstPass():
		if err := r.FirstPassError(); err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("initial sourced pass did not finish")
	}
	before := conn.writes.Load()
	conn.up = true
	conn.rules = append(conn.rules, netlink.Message{Kind: unix.RTM_NEWRULE, Data: plat.ruleMessage(sourcedIngressRule(r.rt.Interface))})
	refusal := sourcedStandingRules(r.table.Sourced.To, nil)[1]
	conn.rules = append(conn.rules, netlink.Message{Kind: unix.RTM_NEWRULE,
		Data: netlink.PutAttr(plat.ruleMessage(refusal), unix.FRA_IP_PROTO, []byte{unix.IPPROTO_UDP})})
	if err := r.SetTable(Table{}, nil, nil); err == nil || r.Table().Sourced == nil || plat.table.Sourced == nil {
		t.Errorf("foreign sourced object was accepted by a removal reload: %v, table %v", err, r.Table().Sourced)
	}
	if got := conn.writes.Load(); got != before {
		t.Errorf("a refused reload wrote %d kernel objects", got-before)
	}
	cancel()
	select {
	case <-ended:
	case <-time.After(3 * time.Second):
		t.Error("reconciler did not stop after a refused reload")
	}
}

func TestSourcedEnablePreflightsForeignOccupancyBeforeWrites(t *testing.T) {
	r, plat, conn := sourcedStandingHarness(t)
	refusal := sourcedStandingRules(r.table.Sourced.To, nil)[1]
	conn.rules = []netlink.Message{{Kind: unix.RTM_NEWRULE,
		Data: netlink.PutAttr(plat.ruleMessage(refusal), unix.FRA_IP_PROTO, []byte{unix.IPPROTO_UDP})}}
	r.trigger = "enable"
	if err := r.reconcile(); err == nil || conn.writes.Load() != 0 {
		t.Fatalf("enable wrote before refusing foreign occupancy: %v, writes %d", err, conn.writes.Load())
	}
}
