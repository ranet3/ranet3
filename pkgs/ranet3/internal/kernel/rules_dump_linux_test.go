// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"encoding/binary"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"testing"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/schema"
)

// A dump reads every policy rule, whoever wrote it and whatever it does: the
// kernel's own, the reconciler's, another writer's, one taking a packet to no
// table, one matching what its selectors do not and the l3mdev rule a VRF of
// any owner brings, each with its family, priority, selectors, action, table
// and protocol as the kernel holds them
func TestNetlinkDumpRulesReadsEveryOwner(t *testing.T) {
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
	const device = "ranettest0"
	createTUN(t, device)
	tbl, rt := platformFor(device)
	opened, err := newPlatform(tbl, rt)
	if err != nil {
		t.Fatalf("open the netlink platform: %v", err)
	}
	t.Cleanup(func() { _ = opened.Close() })
	plat := opened.(*netlinkPlatform)

	for _, rule := range []Rule{
		{Family: FamilyIPv4, To: schema.MustPrefix("203.0.113.0/24"), Table: DefaultTable, Priority: 100},
		{Family: FamilyIPv6, FWMark: 0x72, FWMask: 0xffff, Table: schema.TableMain, Priority: 40},
	} {
		if err := plat.AddRule(rule); err != nil {
			t.Fatalf("install %s: %v", rule, err)
		}
	}
	foreign := replaceProtocol(t, plat.ruleMessage(Rule{Family: FamilyIPv6, From: schema.MustPrefix("3fff:1::/32"), Table: 300, Priority: 101}), unix.RTPROT_STATIC)
	unreachable := make([]byte, sizeofFibRuleHdr)
	unreachable[0], unreachable[7] = unix.AF_INET, unix.FR_ACT_UNREACHABLE
	binary.NativeEndian.PutUint32(unreachable[8:], unix.FIB_RULE_INVERT)
	unreachable = putAttrU32(unreachable, unix.FRA_PRIORITY, 200)
	unreachable = putAttrString(unreachable, unix.FRA_IIFNAME, device)
	unreachable = putAttr(unreachable, unix.FRA_PROTOCOL, []byte{unix.RTPROT_STATIC})
	l3mdev := make([]byte, sizeofFibRuleHdr)
	l3mdev[0], l3mdev[7] = unix.AF_INET6, unix.FR_ACT_TO_TBL
	l3mdev = putAttrU32(l3mdev, unix.FRA_PRIORITY, 1000)
	l3mdev = putAttr(l3mdev, unix.FRA_L3MDEV, []byte{1})
	l3mdev = putAttr(l3mdev, unix.FRA_PROTOCOL, []byte{unix.RTPROT_KERNEL})
	for _, body := range [][]byte{foreign, unreachable, l3mdev} {
		if _, err := conn.execute(unix.RTM_NEWRULE, unix.NLM_F_CREATE|unix.NLM_F_EXCL|unix.NLM_F_ACK, body); err != nil {
			t.Fatalf("install another writer's rule: %v", err)
		}
	}

	dumped, err := DumpRules()
	if err != nil {
		t.Fatalf("dump the rules: %v", err)
	}
	for _, want := range []DumpedRule{
		{Family: FamilyIPv4, Priority: 0, Action: "lookup", Table: unix.RT_TABLE_LOCAL, Protocol: unix.RTPROT_KERNEL},
		{Family: FamilyIPv4, Priority: 32766, Action: "lookup", Table: unix.RT_TABLE_MAIN, Protocol: unix.RTPROT_KERNEL},
		{Family: FamilyIPv4, Priority: 32767, Action: "lookup", Table: unix.RT_TABLE_DEFAULT, Protocol: unix.RTPROT_KERNEL},
		{Family: FamilyIPv6, Priority: 0, Action: "lookup", Table: unix.RT_TABLE_LOCAL, Protocol: unix.RTPROT_KERNEL},
		{Family: FamilyIPv6, Priority: 32766, Action: "lookup", Table: unix.RT_TABLE_MAIN, Protocol: unix.RTPROT_KERNEL},
		{Family: FamilyIPv4, Priority: 100, To: netip.MustParsePrefix("203.0.113.0/24"), Action: "lookup", Table: uint32(DefaultTable), Protocol: DefaultProtocol},
		{Family: FamilyIPv6, Priority: 40, FWMark: 0x72, FWMask: 0xffff, Action: "lookup", Table: unix.RT_TABLE_MAIN, Protocol: DefaultProtocol},
		{Family: FamilyIPv6, Priority: 101, From: netip.MustParsePrefix("3fff:1::/32"), Action: "lookup", Table: 300, Protocol: unix.RTPROT_STATIC},
		{Family: FamilyIPv4, Priority: 200, IIF: device, Invert: true, Action: "unreachable", Protocol: unix.RTPROT_STATIC},
		{Family: FamilyIPv6, Priority: 1000, L3mdev: true, Action: "lookup", Protocol: unix.RTPROT_KERNEL},
	} {
		if !slices.Contains(dumped, want) {
			t.Errorf("the dump does not hold %+v in:\n%+v", want, dumped)
		}
	}
	if len(dumped) != 10 {
		t.Errorf("the dump holds %d rules, want the kernel's five and the five written:\n%+v", len(dumped), dumped)
	}
}
