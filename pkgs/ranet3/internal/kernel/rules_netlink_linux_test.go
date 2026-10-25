// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/netstack"
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

// countingRules is a netlink platform that counts the rules written through it
type countingRules struct {
	*netlinkPlatform
	writes int
}

func (c *countingRules) AddRule(rule Rule) error {
	c.writes++
	return c.netlinkPlatform.AddRule(rule)
}

func (c *countingRules) DelRule(rule Rule) error {
	c.writes++
	return c.netlinkPlatform.DelRule(rule)
}

// A pass installs the derived rules in a real kernel, which reads them back as
// derived, so the next pass writes none, and the withdrawal takes them all.
func TestNetlinkPassConvergesOnTheDerivedRules(t *testing.T) {
	const device = "ranetderived0"
	plat := &countingRules{netlinkPlatform: rootRulePlatform(t, device)}
	tbl, rt := platformFor(device)
	rt.Overlay = []schema.Prefix{schema.MustPrefix("3fff::/20"), schema.MustPrefix("198.18.0.0/15")}
	routes := netstack.NewRouteTable()
	routes.Set(netip.Prefix{}, prefix("3fff:1::/48"), netstack.Local)
	routes.Set(netip.Prefix{}, prefix("192.0.2.0/24"), netstack.Local)
	routes.Set(netip.Prefix{}, prefix("198.18.104.5/32"), netstack.Assigned)
	reconciler := newReconciler(tbl.Normalized(), rt, nil, routes, plat)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	want := derivedRules(DefaultTable, rt.Overlay, []netip.Prefix{prefix("3fff:1::/48"), prefix("192.0.2.0/24"), prefix("198.18.104.5/32")})
	got, err := plat.Rules()
	if err != nil {
		t.Fatalf("list rules: %v", err)
	}
	if !slices.Equal(sortedByText(got), sortedByText(want)) {
		t.Fatalf("the kernel holds\n%v\nwant\n%v", sortedByText(got), sortedByText(want))
	}
	writes := plat.writes
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if plat.writes != writes {
		t.Errorf("a second pass wrote %d rules", plat.writes-writes)
	}
	if err := reconciler.withdraw(); err != nil {
		t.Fatal(err)
	}
	if got, err := plat.Rules(); err != nil || len(got) != 0 {
		t.Fatalf("after withdrawal the kernel holds %v (err %v)", got, err)
	}
}

// The mirror's rows of routing.md's table reach a real kernel and read back as the
// pass wanted them: this node's own prefix outside the overlay as a throw,
// inside it as the hold, and the overlay's holds. The next pass moves none.
func TestNetlinkMirrorReadsBackTheThrowAndTheOverlayHolds(t *testing.T) {
	const device = "ranetmirror0"
	plat := rootRulePlatform(t, device)
	tbl, rt := platformFor(device)
	rt.Overlay = []schema.Prefix{schema.MustPrefix("3fff::/20"), schema.MustPrefix("198.18.0.0/15")}
	routes := netstack.NewRouteTable()
	routes.Set(netip.Prefix{}, prefix("3fff:1::/48"), netstack.Local)
	routes.Set(netip.Prefix{}, prefix("192.0.2.0/24"), netstack.Local)
	routes.Set(netip.Prefix{}, prefix("2001:db8:1::/48"), netstack.Local)
	reconciler := newReconciler(tbl.Normalized(), rt, nil, routes, plat)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	want := []Route{
		{Destination: prefix("3fff:1::/48"), Metric: holdMetric, Unreachable: true},
		{Destination: prefix("192.0.2.0/24"), Metric: holdMetric, Throw: true},
		{Destination: prefix("2001:db8:1::/48"), Metric: holdMetric, Throw: true},
		{Destination: prefix("3fff::/20"), Metric: holdMetric, Unreachable: true},
		{Destination: prefix("198.18.0.0/15"), Metric: holdMetric, Unreachable: true},
	}
	slices.SortFunc(want, compareRoutes)
	got, err := plat.Routes()
	if err != nil {
		t.Fatal(err)
	}
	slices.SortFunc(got, compareRoutes)
	if !slices.Equal(got, want) {
		t.Fatalf("the table holds\n%v\nwant\n%v", got, want)
	}
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if stats := reconciler.Stats(); stats.Added != 0 || stats.Removed != 0 {
		t.Errorf("a second pass added %d routes and removed %d", stats.Added, stats.Removed)
	}
	if err := reconciler.withdraw(); err != nil {
		t.Fatal(err)
	}
	if got, err := plat.Routes(); err != nil || len(got) != 0 {
		t.Fatalf("after withdrawal the table holds %v (err %v)", got, err)
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
