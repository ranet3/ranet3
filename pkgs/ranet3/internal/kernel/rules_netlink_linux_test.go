// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

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
			Rule{Family: family, action: actionNop, Priority: 5190},
			Rule{Family: family, FWMark: 0x72, action: actionGoto, target: 5190, Priority: 5100},
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
	exact := Rule{Family: FamilyIPv6, FWMark: 0x72, Table: 254, Priority: 5600}
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
	rt.Overlay = []schema.Prefix{schema.MustPrefix("3fff::/20"), schema.MustPrefix("203.0.113.0/24")}
	routes := netstack.NewRouteTable()
	routes.Set(netip.Prefix{}, prefix("3fff:1::/48"), netstack.Local)
	routes.Set(netip.Prefix{}, prefix("192.0.2.0/24"), netstack.Local)
	routes.Set(netip.Prefix{}, prefix("203.0.113.5/32"), netstack.Assigned)
	reconciler := newReconciler(tbl.Normalized(), rt, nil, routes, plat)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	want := derivedRules(DefaultTable, rt.Overlay, []netip.Prefix{prefix("3fff:1::/48"), prefix("192.0.2.0/24"), prefix("203.0.113.5/32")}, exitView{})
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

// otherRule is a rule of another program's protocol, written with action, and
// with no priority where pref is false, so the kernel gives it one
type otherRule struct {
	rule   Rule
	action uint8
	pref   bool
}

// writeOtherRule adds or deletes rule as kind says
func writeOtherRule(t *testing.T, conn *nlConn, kind uint16, other otherRule) {
	t.Helper()
	full := (&netlinkPlatform{table: Table{Proto: unix.RTPROT_BOOT}}).ruleMessage(other.rule)
	body := slices.Clone(full[:sizeofFibRuleHdr])
	body[7] = other.action
	for attr, value := range (nlMessage{Data: full}).attributes(sizeofFibRuleHdr) {
		if attr == unix.FRA_PRIORITY && !other.pref || attr == unix.FRA_TABLE && other.action != unix.FR_ACT_TO_TBL {
			continue
		}
		body = putAttr(body, attr, value)
	}
	flags := uint16(unix.NLM_F_ACK)
	if kind == unix.RTM_NEWRULE {
		flags |= unix.NLM_F_CREATE | unix.NLM_F_EXCL
	}
	if _, err := conn.execute(kind, flags, body); err != nil {
		t.Fatalf("write %s as action %d: %v", other.rule, other.action, err)
	}
}

// foreignTable is a platform writing another program's routes into table id out
// of the device of index
func foreignTable(conn *nlConn, id schema.TableID, index uint32) *netlinkPlatform {
	return &netlinkPlatform{table: Table{ID: id, Proto: unix.RTPROT_BOOT}, index: index, conn: conn,
		occupied: map[Route]bool{}, refused: map[Route]bool{}}
}

// A pass finds taken exactly what another program's rules ahead of the mesh's
// take, as the kernel answers each lookup in both families.
func TestNetlinkLookupsReportAnotherProgramsRuleAhead(t *testing.T) {
	const device, uplink, other = "ranetahead0", "ranetup0", "ranetother0"
	plat := rootRulePlatform(t, device)
	conn, err := dialNetlink()
	if err != nil {
		t.Fatalf("dial rtnetlink: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	setLinkFlags(t, conn, plat.index, unix.IFF_UP)
	indexes := map[string]uint32{}
	for _, name := range []string{uplink, other} {
		if err := createLink(conn, name, "dummy"); err != nil {
			t.Fatalf("create the dummy %s: %v", name, err)
		}
		link, err := conn.link(0, name)
		if err != nil {
			t.Fatal(err)
		}
		setLinkFlags(t, conn, link.index, unix.IFF_UP)
		indexes[name] = link.index
	}
	defaults := []Route{{Destination: prefix("0.0.0.0/0")}, {Destination: prefix("::/0"), Metric: defaultIPv6Metric}}
	for _, route := range defaults {
		if err := foreignTable(conn, schema.TableMain, indexes[uplink]).AddRoute(route); err != nil {
			t.Fatalf("install main's %s: %v", route, err)
		}
	}

	tbl, rt := platformFor(device)
	tbl.Addresses = prefixes(prefix("192.0.2.1/32"), prefix("3fff::1/128"))
	tbl = tbl.Normalized()
	rt.Overlay = prefixes(prefix("192.0.2.0/24"), prefix("3fff::/20"))
	peers := []netip.Addr{addr("203.0.113.70"), addr("2001:db8:400::7")}
	endpoints := peers
	rt.Endpoints = func() []netip.Addr { return endpoints }
	routes := netstack.NewRouteTable()
	for _, live := range []string{"192.0.2.5/32", "3fff:0:5::5/128", "203.0.113.64/26", "2001:db8:400::/48"} {
		routes.Set(netip.Prefix{}, prefix(live), nil)
	}
	addresses, err := resolveAddresses(tbl, nil)
	if err != nil {
		t.Fatal(err)
	}
	reconciler := newReconciler(tbl, rt, addresses, routes, plat)

	// pass reconciles and gives each lookup it found taken, as its family, address and answer
	pass := func(arm string) []string {
		t.Helper()
		if err := reconciler.reconcile(); err != nil {
			t.Fatalf("%s: the pass failed: %v", arm, err)
		}
		lookups := reconciler.Stats().Lookups
		t.Logf("%s: %+v", arm, lookups)
		if len(lookups) != 2+len(endpoints) {
			t.Errorf("%s: the pass asked %+v, want both holds and every live endpoint", arm, lookups)
		}
		var taken []string
		for _, lookup := range lookups {
			if lookup.Taken {
				taken = append(taken, fmt.Sprintf("%s %s %s", lookup.Family, lookup.Address, lookup.Answer))
			}
		}
		return taken
	}
	expect := func(arm string, want ...string) {
		t.Helper()
		if got := pass(arm); !slices.Equal(got, want) {
			t.Errorf("%s: taken %q, want %q", arm, got, want)
		}
	}
	both := func(rule func(family Family, overlay schema.Prefix) otherRule) []otherRule {
		return []otherRule{rule(FamilyIPv4, schema.MustPrefix("192.0.2.0/24")), rule(FamilyIPv6, schema.MustPrefix("3fff::/20"))}
	}
	add := func(rules []otherRule) {
		t.Helper()
		for _, rule := range rules {
			writeOtherRule(t, conn, unix.RTM_NEWRULE, rule)
		}
	}
	del := func(rules []otherRule) {
		t.Helper()
		for _, rule := range rules {
			writeOtherRule(t, conn, unix.RTM_DELRULE, rule)
		}
	}
	route := func(kind uint16, id schema.TableID, routes ...Route) {
		t.Helper()
		table := foreignTable(conn, id, indexes[other])
		for _, route := range routes {
			write := table.AddRoute
			if kind == unix.RTM_DELROUTE {
				write = table.DelRoute
			}
			if err := write(route); err != nil {
				t.Fatalf("write %s in table %d: %v", route, id, err)
			}
		}
	}
	// priorities is where the kernel put the rules of protocol boot, by family
	priorities := func() []string {
		t.Helper()
		dumped, err := DumpRules()
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, rule := range dumped {
			if rule.Protocol == unix.RTPROT_BOOT {
				out = append(out, fmt.Sprintf("%s %d", rule.Family, rule.Priority))
			}
		}
		return out
	}
	const (
		held4  = "ipv4 192.0.2.2 "
		held6  = "ipv6 3fff::2 "
		mesh4  = "ipv4 203.0.113.70 table 200 dev " + device
		mesh6  = "ipv6 2001:db8:400::7 table 200 dev " + device
		other4 = " dev " + other
	)

	// the hold refuses the overlay's lookup and main answers the marked one
	expect("P0")

	wg := both(func(family Family, _ schema.Prefix) otherRule {
		return otherRule{rule: Rule{Family: family, invert: true, FWMark: 51820, Table: 51820}, action: unix.FR_ACT_TO_TBL}
	})
	wg = append(wg, both(func(family Family, _ schema.Prefix) otherRule {
		return otherRule{rule: Rule{Family: family, Table: schema.TableMain, suppress: SuppressUpTo(0)}, action: unix.FR_ACT_TO_TBL}
	})...)
	route(unix.RTM_NEWROUTE, 51820, defaults...)
	add(wg)
	if got, want := priorities(), []string{"ipv4 5098", "ipv4 5099", "ipv6 5098", "ipv6 5099"}; !slices.Equal(slices.Sorted(slices.Values(got)), want) {
		t.Errorf("W: wg-quick's rules landed at %v, want %v", got, want)
	}
	expect("W", held4+"table 51820"+other4, held6+"table 51820"+other4)
	del(wg)

	held, err := plat.Rules()
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range held {
		if err := plat.DelRule(rule); err != nil {
			t.Fatal(err)
		}
	}
	add(wg)
	if got, want := priorities(), []string{"ipv4 32764", "ipv4 32765", "ipv6 32764", "ipv6 32765"}; !slices.Equal(slices.Sorted(slices.Values(got)), want) {
		t.Errorf("W0: wg-quick's rules landed at %v, want %v", got, want)
	}
	expect("W0")
	del(wg)
	route(unix.RTM_DELROUTE, 51820, defaults...)

	tailscale := func(base uint32) []otherRule {
		var rules []otherRule
		for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
			marked := Rule{Family: family, FWMark: 0x80000, FWMask: 0xff0000}
			main, fallback, unreachable := marked, marked, marked
			main.Priority, main.Table = base+10, schema.TableMain
			fallback.Priority, fallback.Table = base+30, schema.TableDefault
			unreachable.Priority = base + 50
			rules = append(rules,
				otherRule{rule: main, action: unix.FR_ACT_TO_TBL, pref: true},
				otherRule{rule: fallback, action: unix.FR_ACT_TO_TBL, pref: true},
				otherRule{rule: unreachable, action: unix.FR_ACT_UNREACHABLE, pref: true},
				otherRule{rule: Rule{Family: family, Priority: base + 70, Table: 52}, action: unix.FR_ACT_TO_TBL, pref: true},
			)
		}
		return rules
	}
	tailnet := []Route{{Destination: prefix("100.64.0.0/10")}, {Destination: prefix("fd7a:115c:a1e0::/48"), Metric: defaultIPv6Metric}}
	route(unix.RTM_NEWROUTE, 52, tailnet...)
	add(tailscale(1300))
	expect("T1300 (a)")
	route(unix.RTM_DELROUTE, 52, tailnet...)
	route(unix.RTM_NEWROUTE, 52, defaults...)
	expect("T1300 (b)", held4+"table 52"+other4, held6+"table 52"+other4)
	del(tailscale(1300))
	add(tailscale(5200))
	expect("T5200")
	del(tailscale(5200))
	route(unix.RTM_DELROUTE, 52, defaults...)

	gotoAt := func(priority, target uint32) []otherRule {
		return both(func(family Family, _ schema.Prefix) otherRule {
			return otherRule{rule: Rule{Family: family, Priority: priority, action: actionGoto, target: target}, action: unix.FR_ACT_GOTO, pref: true}
		})
	}
	refusing := func(action uint8) []otherRule {
		return both(func(family Family, overlay schema.Prefix) otherRule {
			return otherRule{rule: Rule{Family: family, Priority: 5050, To: overlay}, action: action, pref: true}
		})
	}
	for _, arm := range []struct {
		name  string
		rules []otherRule
		want  []string
	}{
		// past 5110 alone the lookup still ends at 5420 in the mesh's table
		{"G", gotoAt(1000, priorityOverlayEnd), nil},
		{"G-g", slices.Concat(gotoAt(1000, priorityOverlayEnd), gotoAt(5300, priorityMeshEnd)), []string{held4 + "table main dev " + uplink, held6 + "table main dev " + uplink}},
		{"M", gotoAt(5300, priorityMesh), []string{mesh4, mesh6}},
		{"E prohibit", refusing(unix.FR_ACT_PROHIBIT), []string{held4 + "a refusal (permission denied)", held6 + "a refusal (permission denied)"}},
		{"E unreachable", refusing(unix.FR_ACT_UNREACHABLE), []string{held4 + "a refusal (network is unreachable)", held6 + "a refusal (network is unreachable)"}},
		{"E blackhole", refusing(unix.FR_ACT_BLACKHOLE), []string{held4 + "a refusal (invalid argument)", held6 + "a refusal (invalid argument)"}},
	} {
		add(arm.rules)
		expect(arm.name, arm.want...)
		del(arm.rules)
	}

	// with a default in the mesh's table, which 5420 suppresses, a goto to 5420
	// sends only the endpoints a longer route of it holds into the tun
	endpoints = []netip.Addr{addr("198.51.100.77"), addr("203.0.113.70"), addr("2001:db8:a::77"), addr("2001:db8:400::7")}
	for _, route := range defaults {
		routes.Set(netip.Prefix{}, route.Destination, nil)
	}
	add(gotoAt(5300, priorityMesh))
	expect("X1", mesh4, mesh6)
	del(gotoAt(5300, priorityMesh))

	// with nothing longer than the defaults in the mesh's table, a lookup of it
	// for the mark sends every endpoint into the tun
	for _, live := range []string{"203.0.113.64/26", "2001:db8:400::/48"} {
		routes.Remove(netip.Prefix{}, prefix(live))
	}
	marked := both(func(family Family, _ schema.Prefix) otherRule {
		return otherRule{rule: Rule{Family: family, Priority: 5050, FWMark: schema.UnderlayMark, Table: tbl.ID}, action: unix.FR_ACT_TO_TBL, pref: true}
	})
	add(marked)
	byDefault := " table 200 dev " + device
	expect("X5", "ipv4 198.51.100.77"+byDefault, "ipv4 203.0.113.70"+byDefault, "ipv6 2001:db8:a::77"+byDefault, "ipv6 2001:db8:400::7"+byDefault)
	del(marked)
	for _, route := range defaults {
		routes.Remove(netip.Prefix{}, route.Destination)
	}

	// a goto to 5410 meets main first, which answers the endpoints it holds an
	// on-link route for out of the uplink and passes the rest on to 5420
	lan := []Route{{Destination: prefix("198.51.100.0/24")}, {Destination: prefix("2001:db8:a::/64"), Metric: defaultIPv6Metric}}
	for _, route := range lan {
		if err := foreignTable(conn, schema.TableMain, indexes[uplink]).AddRoute(route); err != nil {
			t.Fatalf("install main's %s: %v", route, err)
		}
	}
	for _, live := range []string{"198.51.100.64/26", "203.0.113.64/26", "2001:db8:a::/48", "2001:db8:400::/48"} {
		routes.Set(netip.Prefix{}, prefix(live), nil)
	}
	expect("X4 without the goto")
	add(gotoAt(5300, priorityMain))
	expect("X4", mesh4, mesh6)
	del(gotoAt(5300, priorityMain))
	for _, live := range []string{"198.51.100.64/26", "2001:db8:a::/48"} {
		routes.Remove(netip.Prefix{}, prefix(live))
	}
	for _, route := range lan {
		if err := foreignTable(conn, schema.TableMain, indexes[uplink]).DelRoute(route); err != nil {
			t.Fatalf("delete main's %s: %v", route, err)
		}
	}
	endpoints = peers

	holds := []Route{
		{Destination: prefix("192.0.2.0/24"), Unreachable: true, Metric: holdMetric},
		{Destination: prefix("3fff::/20"), Unreachable: true, Metric: holdMetric},
	}
	route(unix.RTM_NEWROUTE, 300, holds...)
	lookups := both(func(family Family, overlay schema.Prefix) otherRule {
		return otherRule{rule: Rule{Family: family, Priority: 5050, To: overlay, Table: 300}, action: unix.FR_ACT_TO_TBL, pref: true}
	})
	add(lookups)
	// another program's unreachable route refuses the packet as the hold does
	expect("E 300")
	del(lookups)
	route(unix.RTM_DELROUTE, 300, holds...)

	expect("P0 again")
	if err := reconciler.withdraw(); err != nil {
		t.Fatal(err)
	}

	// with prefixes assigned, main answers the rest of each out of the tun: the
	// overlay's lookup asks outside them where the hold has room, and the
	// underlay's that leaves through the tun is taken whatever table answers
	tbl.Addresses = prefixes(prefix("192.0.2.1/24"), prefix("3fff::1/64"))
	if addresses, err = resolveAddresses(tbl, nil); err != nil {
		t.Fatal(err)
	}
	endpoints = []netip.Addr{addr("192.0.2.5"), addr("3fff::5")}
	routes.Set(netip.Prefix{}, prefix("3fff::5/128"), nil)
	reconciler = newReconciler(tbl, rt, addresses, routes, plat)
	onTun := " table main dev " + device
	expect("X2", "ipv4 192.0.2.5"+onTun, "ipv6 3fff::5"+onTun)
	route(unix.RTM_NEWROUTE, 51820, defaults...)
	add(wg)
	expect("X2 under wg-quick", "ipv6 3fff:0:0:1:: table 51820"+other4, "ipv4 192.0.2.5"+onTun, "ipv6 3fff::5"+onTun)
	del(wg)
	route(unix.RTM_DELROUTE, 51820, defaults...)
	if err := reconciler.withdraw(); err != nil {
		t.Fatal(err)
	}
}
