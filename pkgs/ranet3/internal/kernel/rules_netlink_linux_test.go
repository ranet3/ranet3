// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"os"
	"runtime"
	"slices"
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/schema"
)

// rootRulePlatform is a netlink platform on a fresh tun in a namespace this
// test made and proved empty
func rootRulePlatform(t *testing.T, device string) *netlinkPlatform {
	t.Helper()
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
	createTUN(t, device)
	tbl, rt := platformFor(device)
	opened, err := newPlatform(tbl, rt)
	if err != nil {
		t.Fatalf("open the netlink platform: %v", err)
	}
	t.Cleanup(func() { _ = opened.Close() })
	return opened.(*netlinkPlatform)
}

func sortedByText(rules []Rule) []Rule {
	out := slices.Clone(rules)
	slices.SortFunc(out, func(a, b Rule) int { return strings.Compare(a.String(), b.String()) })
	return out
}

// Each action and the suppress length reach a real kernel and read back as
// written through RTM_GETRULE, in both families, and a delete takes the rule
// it names and not another at the same priority that differs from it only by
// its mask, or by a suppress length the rule deleted carries.
func TestNetlinkRuleActionsReadBackAndDeleteExactly(t *testing.T) {
	plat := rootRulePlatform(t, "ranetrule0")
	var want []Rule
	for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
		overlay, floor := schema.MustPrefix("192.0.2.0/24"), 7
		if family == FamilyIPv6 {
			overlay, floor = schema.MustPrefix("3fff::/20"), 15
		}
		want = append(want,
			Rule{Family: family, action: ActionNop, Priority: 5190},
			Rule{Family: family, FWMark: 0x726c, action: ActionGoto, target: 5190, Priority: 5100},
			Rule{Family: family, To: overlay, Table: DefaultTable, Priority: 5110},
			Rule{Family: family, Table: 254, suppress: SuppressUpTo(0), Priority: 5410},
			Rule{Family: family, Table: DefaultTable, suppress: SuppressUpTo(floor), Priority: 5420},
		)
	}
	for _, rule := range want {
		if err := plat.AddRule(rule); err != nil {
			t.Fatalf("install %s: %v", rule, err)
		}
	}
	got, err := plat.Rules()
	if err != nil {
		t.Fatalf("list rules: %v", err)
	}
	if !slices.Equal(sortedByText(got), sortedByText(want)) {
		t.Fatalf("the kernel holds\n%v\nwant\n%v", sortedByText(got), sortedByText(want))
	}

	// each pair is added plain first, so the kernel lists the plain one ahead
	// at the priority, the one a delete that left the other's selector out takes
	plain := Rule{Family: FamilyIPv4, Table: DefaultTable, Priority: 5500}
	suppressing := plain
	suppressing.suppress = SuppressUpTo(7)
	exact := Rule{Family: FamilyIPv6, FWMark: 0x726c, Table: 254, Priority: 5600}
	masked := exact
	masked.FWMask = 0xffff
	for _, rule := range []Rule{plain, suppressing, exact, masked} {
		if err := plat.AddRule(rule); err != nil {
			t.Fatalf("install %s: %v", rule, err)
		}
	}
	for _, rule := range []Rule{suppressing, masked} {
		if err := plat.DelRule(rule); err != nil {
			t.Fatalf("delete %s: %v", rule, err)
		}
	}
	got, err = plat.Rules()
	if err != nil {
		t.Fatalf("list rules: %v", err)
	}
	left := sortedByText(append(slices.Clone(want), plain, exact))
	if !slices.Equal(sortedByText(got), left) {
		t.Fatalf("after deleting %s and %s the kernel holds\n%v\nwant\n%v", suppressing, masked, sortedByText(got), left)
	}

	for _, rule := range append(want, plain, exact) {
		if err := plat.DelRule(rule); err != nil {
			t.Fatalf("delete %s: %v", rule, err)
		}
	}
	if got, err := plat.Rules(); err != nil || len(got) != 0 {
		t.Fatalf("after withdrawal the kernel holds %v (err %v)", got, err)
	}
}

// A throw route of either family reaches a real kernel at the hold's metric
// and reads back as itself, the IPv6 one dumped with lo as its device.
func TestNetlinkThrowRouteReadsBack(t *testing.T) {
	plat := rootRulePlatform(t, "ranetthrow0")
	want := []Route{
		{Destination: prefix("203.0.113.128/25"), Throw: true, Metric: holdMetric},
		{Destination: prefix("2001:db8:c:8000::/49"), Throw: true, Metric: holdMetric},
	}
	for _, route := range want {
		if err := plat.AddRoute(route); err != nil {
			t.Fatalf("install %s: %v", route, err)
		}
	}
	got, err := plat.Routes()
	if err != nil {
		t.Fatal(err)
	}
	slices.SortFunc(got, compareRoutes)
	if !slices.Equal(got, want) {
		t.Fatalf("the table holds %v, want %v", got, want)
	}
	for _, route := range want {
		if err := plat.DelRoute(route); err != nil {
			t.Fatalf("withdraw %s: %v", route, err)
		}
	}
	if got, err := plat.Routes(); err != nil || len(got) != 0 {
		t.Fatalf("the throw routes outlived their withdrawal: %v, error %v", got, err)
	}
}
