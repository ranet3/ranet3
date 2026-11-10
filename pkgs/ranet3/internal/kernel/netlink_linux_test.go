// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"encoding/binary"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/netnstest"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/schema"
)

// This test speaks to a real kernel. It refuses to run anywhere but inside a
// network namespace it created itself and proved empty, because the code under
// test writes routes and addresses, and the machine running the suite is
// usually on the mesh it is being written for.
func TestNetlinkPlatformInNetworkNamespace(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real netlink path needs root on linux")
	}
	netnstest.EnterEmpty(t)

	conn, err := dialNetlink()
	if err != nil {
		t.Fatalf("dial rtnetlink: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	const device = "ranettest0"
	createTUN(t, device)
	tun, err := conn.link(0, device)
	if err != nil {
		t.Fatalf("look up %s: %v", device, err)
	}
	setLinkFlags(t, conn, tun.index, unix.IFF_UP)

	tbl, rt := platformFor(device)
	opened, err := newPlatform(tbl, rt)
	if err != nil {
		t.Fatalf("open the netlink platform: %v", err)
	}
	t.Cleanup(func() { _ = opened.Close() })
	plat := opened.(*netlinkPlatform)

	if routes, err := plat.Routes(); err != nil || len(routes) != 0 {
		t.Fatalf("a fresh table holds %v (err %v)", routes, err)
	}

	// an address of each family on the tun, which reads back as assigned
	local4, local6 := prefix("10.99.0.1/32"), prefix("3fff:a:1::1/128")
	for _, address := range []netip.Prefix{local4, local6} {
		if err := plat.AddAddr(address); err != nil {
			t.Fatalf("assign %s: %v", address, err)
		}
	}
	assigned, err := plat.Addrs()
	if err != nil {
		t.Fatalf("list addresses: %v", err)
	}
	for _, address := range []netip.Prefix{local4, local6} {
		if !slices.Contains(assigned, address) {
			t.Fatalf("%s is missing from %v", address, assigned)
		}
	}

	// IPv6 carries the kernel's own default metric explicitly, so a dump
	// reports back exactly the route that was installed.
	want := []Route{
		{Destination: prefix("10.0.0.0/8")},
		{Destination: prefix("::/0"), Source: prefix("3fff:a:1::/48"), Metric: defaultIPv6Metric},
		{Destination: prefix("3fff:a::/36"), Metric: defaultIPv6Metric},
	}
	slices.SortFunc(want, compareRoutes)
	for _, route := range want {
		if err := plat.AddRoute(route); err != nil {
			if route.Source.IsValid() && (errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EOPNOTSUPP)) {
				t.Fatalf("source-specific route %s rejected, is CONFIG_IPV6_SUBTREES set: %v", route, err)
			}
			t.Fatalf("install %s: %v", route, err)
		}
	}
	if got, err := plat.Routes(); err != nil || !slices.Equal(got, want) {
		t.Fatalf("table holds %v, want %v (err %v)", got, want, err)
	}

	// an exclusive install must report a collision even if the route is ours,
	// so a race after the dump cannot be counted as a successful addition
	for _, route := range want {
		if err := plat.AddRoute(route); !errors.Is(err, errRouteSkipped) {
			t.Fatalf("reinstall %s: got %v, want the route reported as not installed", route, err)
		}
	}
	if got, _ := plat.Routes(); !slices.Equal(got, want) {
		t.Fatalf("a repeated install changed the table to %v", got)
	}

	// Ownership: neither another protocol in this table nor this protocol in
	// another table may show up in a dump, because anything that does is on
	// the delete list at withdrawal.
	other := &netlinkPlatform{
		table: Table{ID: DefaultTable, Proto: DefaultProtocol + 1}, rt: Runtime{Interface: device},
		index: plat.index, conn: plat.conn,
	}
	elsewhere := &netlinkPlatform{
		table: Table{ID: DefaultTable + 1, Proto: DefaultProtocol}, rt: Runtime{Interface: device},
		index: plat.index, conn: plat.conn,
	}
	foreign := Route{Destination: prefix("198.51.100.0/24")}
	aside := Route{Destination: prefix("203.0.113.0/24")}
	if err := other.AddRoute(foreign); err != nil {
		t.Fatalf("install a foreign route: %v", err)
	}
	if err := elsewhere.AddRoute(aside); err != nil {
		t.Fatalf("install a route in another table: %v", err)
	}
	if got, _ := plat.Routes(); !slices.Equal(got, want) {
		t.Fatalf("dump picked up routes of other owners: %v", got)
	}
	// the kernel filters the dumps itself
	// the other protocol's route reaches only the census
	// the other table's route reaches neither dump
	recorder := &replyRecorder{netlinkConn: plat.conn}
	filtered := &netlinkPlatform{table: plat.table, rt: plat.rt, index: plat.index, conn: recorder,
		occupied: map[Route]bool{}, refused: map[Route]bool{}}
	if got, err := filtered.Routes(); err != nil || !slices.Equal(got, want) {
		t.Fatalf("the filtered dump read %v (err %v), want %v", got, err, want)
	}
	if len(recorder.replies) != len(want) {
		t.Errorf("the dump carried %d routes for the %d of ours", len(recorder.replies), len(want))
	}
	recorder.replies = nil
	if writers, err := filtered.foreignWriters(); err != nil || !slices.Equal(writers, []string{protocolLabel(DefaultProtocol + 1)}) {
		t.Errorf("the census read %v (err %v), want the other protocol in this table alone", writers, err)
	}
	if len(recorder.replies) != len(want)+1 {
		t.Errorf("the census dump carried %d routes, want the %d in this table", len(recorder.replies), len(want)+1)
	}

	// A notification for this table has to reach the monitor, because the reconcile
	// loop has nothing else to tell it that somebody edited the table.
	drain(plat.Notify())
	if err := plat.AddRoute(Route{Destination: prefix("192.0.2.0/24")}); err != nil {
		t.Fatalf("install a route to wake the monitor: %v", err)
	}
	select {
	case <-plat.Notify():
	case <-time.After(waitBudget):
		t.Fatal("no route notification arrived")
	}
	if err := plat.DelRoute(Route{Destination: prefix("192.0.2.0/24")}); err != nil {
		t.Fatalf("remove the route: %v", err)
	}

	// A delete removes exactly one route and is idempotent, so a reconcile
	// that races the kernel does not fail on the second attempt.
	victim := Route{Destination: prefix("3fff:a::/36"), Metric: defaultIPv6Metric}
	for range 2 {
		if err := plat.DelRoute(victim); err != nil {
			t.Fatalf("remove %s: %v", victim, err)
		}
	}
	remaining := slices.DeleteFunc(slices.Clone(want), func(route Route) bool { return route == victim })
	if got, _ := plat.Routes(); !slices.Equal(got, remaining) {
		t.Fatalf("table holds %v, want %v", got, remaining)
	}

	for _, route := range remaining {
		if err := plat.DelRoute(route); err != nil {
			t.Fatalf("remove %s: %v", route, err)
		}
	}
	if got, _ := plat.Routes(); len(got) != 0 {
		t.Fatalf("table still holds %v", got)
	}
	if got, _ := other.Routes(); !slices.Equal(got, []Route{foreign}) {
		t.Fatalf("the foreign route did not survive, table holds %v", got)
	}
	if got, _ := elsewhere.Routes(); !slices.Equal(got, []Route{aside}) {
		t.Fatalf("the other table did not survive, it holds %v", got)
	}

	if err := plat.DelAddr(local4); err != nil {
		t.Fatalf("remove %s: %v", local4, err)
	}
	if assigned, _ := plat.Addrs(); slices.Contains(assigned, local4) {
		t.Fatalf("%s survived removal: %v", local4, assigned)
	}
}

func TestNetlinkReportsOccupiedRoute(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("the real netlink path needs root on linux")
	}
	netnstest.EnterEmpty(t)
	conn, err := dialNetlink()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	// the namespace's own loopback needs no optional link driver
	const device = "lo"
	lo, err := conn.link(0, device)
	if err != nil {
		t.Fatal(err)
	}
	setLinkFlags(t, conn, lo.index, unix.IFF_UP)
	tbl, rt := platformFor(device)
	opened, err := newPlatform(tbl, rt)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = opened.Close() })
	plat := opened.(*netlinkPlatform)
	tbl.Proto++
	foreign := &netlinkPlatform{table: tbl, rt: rt, index: lo.index, conn: conn}
	announced := Route{Destination: prefix("198.51.100.0/24")}
	if err := foreign.AddRoute(announced); err != nil {
		t.Fatal(err)
	}
	for attempt := range 2 {
		if err := plat.AddRoute(announced); !errors.Is(err, errRouteSkipped) {
			t.Errorf("attempt %d reported %v, want the foreign route reported as not installed", attempt, err)
		}
	}
	if got, err := plat.Routes(); err != nil || len(got) != 0 {
		t.Fatalf("refused route appeared owned: %v, error %v", got, err)
	}
	if got, err := foreign.Routes(); err != nil || !slices.Equal(got, []Route{announced}) {
		t.Fatalf("foreign route changed: %v, error %v", got, err)
	}
}

// a reload against a real kernel, the tun's addresses IPv4 alone
// a new overlay moves the rule that sends it to the table
// then the tun is renumbered
// each takes the one pass that follows it
func TestNetlinkReloadRenumbersTheTunAndMovesTheRules(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real netlink path needs root on linux")
	}
	netnstest.EnterEmpty(t)
	conn, err := dialNetlink()
	if err != nil {
		t.Fatalf("dial rtnetlink: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	const device = "ranetreload0"
	createTUN(t, device)
	tun, err := conn.link(0, device)
	if err != nil {
		t.Fatal(err)
	}
	setLinkFlags(t, conn, tun.index, unix.IFF_UP)

	first, second, third := prefix("10.99.0.1/32"), prefix("10.99.0.2/32"), prefix("10.99.0.3/32")
	before, after := []schema.Prefix{schema.MustPrefix("203.0.113.0/24")}, []schema.Prefix{schema.MustPrefix("198.51.100.0/24")}
	mesh := netstack.NewRouteTable()
	mesh.Set(netip.Prefix{}, prefix("10.0.0.0/8"), nil)
	r, err := New(Table{Addresses: prefixes(first, second)}, Runtime{Interface: device, Overlay: before}, mesh)
	if err != nil {
		t.Fatalf("start the reconciler: %v", err)
	}
	t.Cleanup(func() { _ = r.plat.Close() })
	plat := r.plat.(*netlinkPlatform)
	step := func(next Table, overlay []schema.Prefix) {
		t.Helper()
		if err := r.SetTable(next, overlay, nil); err != nil {
			t.Fatalf("the reload was refused: %v", err)
		}
		if !r.adopt() {
			t.Fatal("an accepted reload handed the loop nothing")
		}
		if err := r.reconcile(); err != nil {
			t.Fatalf("the pass after the reload: %v", err)
		}
	}
	// a dump of a family this kernel lacks answers with the other one's entries, so each is read as a set
	holds := func(step string, addresses []netip.Prefix, route Route, overlay []schema.Prefix) {
		t.Helper()
		assigned, err := plat.Addrs()
		if err != nil {
			t.Fatalf("%s: list addresses: %v", step, err)
		}
		routes, err := plat.Routes()
		if err != nil {
			t.Fatalf("%s: list routes: %v", step, err)
		}
		rules, err := plat.Rules()
		if err != nil {
			t.Fatalf("%s: list rules: %v", step, err)
		}
		got := slices.Compact(slices.SortedFunc(slices.Values(slices.DeleteFunc(assigned, func(p netip.Prefix) bool { return !p.Addr().Is4() })), comparePrefixes))
		if want := slices.SortedFunc(slices.Values(addresses), comparePrefixes); !slices.Equal(got, want) {
			t.Errorf("%s: the tun carries %v, want %v", step, got, want)
		}
		routes = slices.DeleteFunc(routes, func(route Route) bool { return route.Metric == holdMetric })
		if got := slices.Compact(slices.SortedFunc(slices.Values(routes), compareRoutes)); !slices.Equal(got, []Route{route}) {
			t.Errorf("%s: the table holds %v beside the holds, want %s", step, got, route)
		}
		if got, want := slices.Compact(sortedByText(rules)), sortedByText(derivedRules(DefaultTable, overlay, nil, exitView{})); !slices.Equal(got, want) {
			t.Errorf("%s: the rules are %v, want %v", step, got, want)
		}
	}
	if err := r.reconcile(); err != nil {
		t.Fatalf("the first pass: %v", err)
	}
	holds("the first pass", []netip.Prefix{first, second}, Route{Destination: prefix("10.0.0.0/8")}, before)

	step(Table{Addresses: prefixes(first, second)}, after)
	holds("a new overlay", []netip.Prefix{first, second}, Route{Destination: prefix("10.0.0.0/8")}, after)

	step(Table{Addresses: prefixes(second, third)}, after)
	holds("a renumbered tun", []netip.Prefix{second, third}, Route{Destination: prefix("10.0.0.0/8")}, after)

	if err := r.withdraw(nil); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if assigned, _ := plat.Addrs(); slices.ContainsFunc(assigned, func(p netip.Prefix) bool { return p.Addr().Is4() }) {
		t.Errorf("the withdrawal left %v on the tun", assigned)
	}
	if routes, _ := plat.Routes(); len(routes) != 0 {
		t.Errorf("the withdrawal left %v in the table", routes)
	}
	if rules, _ := plat.Rules(); len(rules) != 0 {
		t.Errorf("the withdrawal left %v", rules)
	}
}

// a route the mesh carries for exactly an overlay prefix goes in at the
// kernel's default priority beside the overlay's hold of it, and a lookup
// inside the prefix takes the route, in each family
func TestNetlinkRouteOfAnOverlayPrefixWinsOverItsHold(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real netlink path needs root on linux")
	}
	netnstest.EnterEmpty(t)
	conn, err := dialNetlink()
	if err != nil {
		t.Fatalf("dial rtnetlink: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	const device = "ranethold0"
	createTUN(t, device)
	tun, err := conn.link(0, device)
	if err != nil {
		t.Fatal(err)
	}
	setLinkFlags(t, conn, tun.index, unix.IFF_UP)

	overlay := []schema.Prefix{schema.MustPrefix("192.0.2.0/24"), schema.MustPrefix("2001:db8:1::/48")}
	mesh := netstack.NewRouteTable()
	for _, entry := range overlay {
		mesh.Set(netip.Prefix{}, entry.Prefix, nil)
	}
	r, err := New(Table{Addresses: prefixes(prefix("198.51.100.1/32"), prefix("2001:db8:a::1/128"))}, Runtime{Interface: device, Overlay: overlay}, mesh)
	if err != nil {
		t.Fatalf("start the reconciler: %v", err)
	}
	t.Cleanup(func() { _ = r.plat.Close() })
	if err := r.reconcile(); err != nil {
		t.Fatalf("the first pass: %v", err)
	}
	routes, err := r.plat.Routes()
	if err != nil {
		t.Fatal(err)
	}
	want := []Route{
		{Destination: prefix("192.0.2.0/24")},
		{Destination: prefix("192.0.2.0/24"), Metric: ^uint32(0), Unreachable: true},
		{Destination: prefix("2001:db8:1::/48"), Metric: 1024},
		{Destination: prefix("2001:db8:1::/48"), Metric: ^uint32(0), Unreachable: true},
	}
	slices.SortFunc(want, compareRoutes)
	if !slices.Equal(routes, want) {
		t.Fatalf("the table holds %v, want %v", routes, want)
	}
	for _, entry := range overlay {
		inside := entry.Addr().Next()
		got, err := RouteGet(netip.Addr{}, inside, "")
		if err != nil || got.Prefix != entry.Prefix || got.Table != DefaultTable || got.Type != "unicast" || !slices.Equal(got.NextHops, []NextHop{{Device: device}}) {
			t.Errorf("a lookup of %s answered %+v (err %v), want the route of %s out of %s", inside, got, err, entry, device)
		}
	}
	if err := r.withdraw(nil); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
}

// a reload renumbering the tun's only IPv4 address leaves another writer's IPv4 routes out of the tun in place
// linux flushes every IPv4 route out of a device that loses its last IPv4 address, so the new address goes on before the old one comes off
// a new prefix length goes on beside the old one, since linux keys an IPv4 address by its length as well
// a new address within the subnet goes on as a secondary, which the tun promotes once the primary comes off
// an IPv6 address given another length is replaced in place, since linux keys it by address alone
// the pass after the reload then moves only what the reload changed
func TestNetlinkReloadRenumberingTheOnlyAddressKeepsAnotherWritersRoutes(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real netlink path needs root on linux")
	}
	first, second := prefix("10.99.0.1/32"), prefix("10.99.0.2/32")
	subnet, renumbered := prefix("10.99.0.1/24"), prefix("10.99.0.2/24")
	host6, subnet6 := prefix("3fff:a::1/128"), prefix("3fff:a::1/64")
	for name, renumber := range map[string]struct {
		start, next    Table
		want           netip.Prefix
		added, removed string
		// promote_secondaries is off on the tun before the reconciler starts
		noPromotion bool
	}{
		"another address":       {Table{Addresses: prefixes(first)}, Table{Addresses: prefixes(second)}, second, "0", "0", false},
		"another prefix length": {Table{Addresses: prefixes(first)}, Table{Addresses: prefixes(subnet)}, subnet, "0", "0", false},
		"within the subnet with promote_secondaries off": {
			Table{Addresses: prefixes(subnet)}, Table{Addresses: prefixes(renumbered)}, renumbered, "0", "0", true},
		"another IPv6 prefix length": {Table{Addresses: prefixes(host6)}, Table{Addresses: prefixes(subnet6)}, subnet6, "0", "0", false},
	} {
		t.Run(name, func(t *testing.T) {
			netnstest.EnterEmpty(t)
			conn, err := dialNetlink()
			if err != nil {
				t.Fatalf("dial rtnetlink: %v", err)
			}
			t.Cleanup(func() { _ = conn.Close() })
			const device = "ranetrenumber0"
			createTUN(t, device)
			tun, err := conn.link(0, device)
			if err != nil {
				t.Fatal(err)
			}
			setLinkFlags(t, conn, tun.index, unix.IFF_UP)
			if renumber.noPromotion {
				if err := os.WriteFile("/proc/sys/net/ipv4/conf/"+device+"/promote_secondaries", []byte("0"), 0); err != nil {
					t.Fatal(err)
				}
			}
			meshRoute, foreign := prefix("10.0.0.0/8"), []Route{{Destination: prefix("192.0.2.0/24")}, {Destination: prefix("198.51.100.0/24")}}
			if renumber.want.Addr().Is6() {
				// linux gives an IPv6 route without a metric 1024
				meshRoute, foreign = prefix("3fff:b::/48"), []Route{{Destination: prefix("2001:db8:1::/48"), Metric: 1024}, {Destination: prefix("2001:db8:2::/48"), Metric: 1024}}
			}
			mesh := netstack.NewRouteTable()
			mesh.Set(netip.Prefix{}, meshRoute, nil)
			bus := events.New()
			r, err := New(renumber.start, Runtime{Interface: device, Events: bus}, mesh)
			if err != nil {
				t.Fatalf("start the reconciler: %v", err)
			}
			t.Cleanup(func() { _ = r.plat.Close() })
			if err := r.reconcile(); err != nil {
				t.Fatalf("the first pass: %v", err)
			}
			// one in the reconciler's table under another protocol, and one in main as networkd writes it
			others := []struct {
				writer *netlinkPlatform
				route  Route
			}{
				{&netlinkPlatform{table: Table{ID: DefaultTable, Proto: 99}, rt: r.rt, index: tun.index, conn: conn}, foreign[0]},
				{&netlinkPlatform{table: Table{ID: schema.TableMain, Proto: protocolStatic}, rt: r.rt, index: tun.index, conn: conn}, foreign[1]},
			}
			for _, other := range others {
				if err := other.writer.AddRoute(other.route); err != nil {
					t.Fatalf("another writer in %s: %v", other.writer.where(other.writer.table), err)
				}
			}

			reload(t, r, renumber.next)
			for _, other := range others {
				if got, err := other.writer.Routes(); err != nil || !slices.Equal(got, []Route{other.route}) {
					t.Errorf("another writer in %s holds %v after the reload (err %v), want %s", other.writer.where(other.writer.table), got, err, other.route)
				}
			}
			assigned, err := r.plat.Addrs()
			if err != nil {
				t.Fatal(err)
			}
			if got := slices.DeleteFunc(assigned, func(p netip.Prefix) bool {
				return p.Addr().Is4() != renumber.want.Addr().Is4() || p.Addr().IsLinkLocalUnicast()
			}); !slices.Equal(got, []netip.Prefix{renumber.want}) {
				t.Errorf("the tun carries %v after the reload, want %s", got, renumber.want)
			}
			passes := bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "kernel.pass" }, 0)
			if len(passes) == 0 {
				t.Fatal("no pass was recorded")
			}
			if got := passes[len(passes)-1].Attrs; got["added"] != renumber.added || got["removed"] != renumber.removed {
				t.Errorf("the pass after the reload was recorded with added=%s removed=%s, want added=%s removed=%s", got["added"], got["removed"], renumber.added, renumber.removed)
			}
		})
	}
}

// a dump whose reply or end carries NLM_F_DUMP_INTR comes back as errDumpInterrupted with none of its replies, and one that carries it
// nowhere comes back whole
func TestCollectRefusesAnInterruptedDump(t *testing.T) {
	reply := func(flags uint16) nlMessage {
		return nlMessage{Kind: unix.RTM_NEWADDR, Flags: unix.NLM_F_MULTI | flags, Seq: 1, Pid: 1, Data: []byte{1, 2, 3, 4}}
	}
	done := func(flags uint16) nlMessage {
		return nlMessage{Kind: unix.NLMSG_DONE, Flags: unix.NLM_F_MULTI | flags, Seq: 1, Pid: 1, Data: make([]byte, 4)}
	}
	for name, arm := range map[string]struct {
		messages    []nlMessage
		interrupted bool
	}{
		"the flag on a reply":       {[]nlMessage{reply(0), reply(unix.NLM_F_DUMP_INTR), done(0)}, true},
		"the flag on the end alone": {[]nlMessage{reply(0), reply(0), done(unix.NLM_F_DUMP_INTR)}, true},
		"the flag nowhere":          {[]nlMessage{reply(0), reply(0), done(0)}, false},
	} {
		got, err := collect(1, 1, func() ([]nlMessage, error) { return arm.messages, nil })
		switch {
		case arm.interrupted && (err != errDumpInterrupted || got != nil):
			t.Errorf("%s: the dump read as %d replies and %v, want none and %v", name, len(got), err, errDumpInterrupted)
		case !arm.interrupted && (err != nil || len(got) != 2):
			t.Errorf("%s: the dump read as %d replies and %v, want both", name, len(got), err)
		}
	}
}

// a dump a change interrupts twice and leaves whole on the third ask comes back whole, one it interrupts three times is refused after
// the third ask, and a keyed request a change interrupts or a dump that fails otherwise is asked once
func TestInterruptedDumpIsAskedAgain(t *testing.T) {
	for name, arm := range map[string]struct {
		flags       uint16
		interrupted int
		failure     error
		asks        int
		want        error
	}{
		"a dump interrupted twice":       {flags: unix.NLM_F_DUMP, interrupted: 2, asks: 3},
		"a dump interrupted three times": {flags: unix.NLM_F_DUMP, interrupted: 3, asks: 3, want: errDumpInterrupted},
		"a keyed request interrupted":    {interrupted: 1, asks: 1, want: errDumpInterrupted},
		"a dump that fails otherwise":    {flags: unix.NLM_F_DUMP, failure: unix.ENOBUFS, asks: 1, want: unix.ENOBUFS},
	} {
		asks := 0
		got, err := dumpAgainIfInterrupted(arm.flags, func() ([]nlMessage, error) {
			asks++
			if arm.failure != nil {
				return nil, arm.failure
			}
			seq, flags := uint32(asks), uint16(0)
			if asks <= arm.interrupted {
				flags = unix.NLM_F_DUMP_INTR
			}
			messages := []nlMessage{
				{Kind: unix.RTM_NEWADDR, Flags: unix.NLM_F_MULTI | flags, Seq: seq, Pid: 1, Data: []byte{1, 2, 3, 4}},
				{Kind: unix.NLMSG_DONE, Flags: unix.NLM_F_MULTI, Seq: seq, Pid: 1, Data: make([]byte, 4)},
			}
			return collect(seq, 1, func() ([]nlMessage, error) { return messages, nil })
		})
		if asks != arm.asks {
			t.Errorf("%s: asked %d times, want %d", name, asks, arm.asks)
		}
		switch {
		case arm.want != nil && (!errors.Is(err, arm.want) || got != nil):
			t.Errorf("%s: read as %d replies and %v, want none and %v", name, len(got), err, arm.want)
		case arm.want == nil && (err != nil || len(got) != 1):
			t.Errorf("%s: read as %d replies and %v, want the whole dump", name, len(got), err)
		}
	}
}

// dumpedAddresses is how many addresses a test dumps while another address comes and goes, more than one datagram of a dump holds
// interruptedDumps is how many dumps it takes
// churnBiteDumps is how many dumps a test takes at most waiting for its churn to interrupt one
const dumpedAddresses, interruptedDumps, churnBiteDumps = 512, 100, 1000

// an address dump that another address coming and going keeps interrupting comes back whole, with no reply the kernel flagged, or as
// errDumpInterrupted, and never as a table that may miss or repeat an entry
func TestAddressDumpUnderChurnIsWholeOrRefused(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real netlink path needs root on linux")
	}
	netnstest.EnterEmpty(t)
	conn, err := dialNetlink()
	if err != nil {
		t.Fatalf("dial rtnetlink: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	const dumpedName, churnName = "ranetdump0", "ranetchurn0"
	createTUN(t, dumpedName)
	createTUN(t, churnName)
	dumped, err := conn.link(0, dumpedName)
	if err != nil {
		t.Fatal(err)
	}
	churned, err := conn.link(0, churnName)
	if err != nil {
		t.Fatal(err)
	}
	setLinkFlags(t, conn, dumped.index, unix.IFF_UP)
	setLinkFlags(t, conn, churned.index, unix.IFF_UP)
	addDumpedAddresses(t, conn, dumped.index)
	churnAddress(t, churned.index, prefix("192.0.2.1/32"))

	body := make([]byte, unix.SizeofIfAddrmsg)
	body[0] = unix.AF_INET
	awaitInterruptedDump(t, conn, unix.RTM_GETADDR, body)
	refused := 0
	for range interruptedDumps {
		replies, err := conn.execute(unix.RTM_GETADDR, unix.NLM_F_DUMP, body)
		if errors.Is(err, errDumpInterrupted) {
			refused++
			continue
		}
		if err != nil {
			t.Fatalf("dump the addresses: %v", err)
		}
		held := 0
		for _, reply := range replies {
			if reply.Flags&unix.NLM_F_DUMP_INTR != 0 {
				t.Fatal("a dump came back with a reply the kernel flagged as interrupted")
			}
			if reply.Kind == unix.RTM_NEWADDR && len(reply.Data) >= unix.SizeofIfAddrmsg && binary.NativeEndian.Uint32(reply.Data[4:]) == dumped.index {
				held++
			}
		}
		if held != dumpedAddresses {
			t.Fatalf("a dump that came back whole holds %d of the %d addresses", held, dumpedAddresses)
		}
	}
	if refused == 0 {
		t.Fatalf("none of %d dumps was interrupted, so the churn proved nothing", interruptedDumps)
	}
	t.Logf("%d of %d dumps were interrupted", refused, interruptedDumps)
}

// the reconciler reads the tun's addresses whole every time while another device's addresses keep changing, since its dumps name
// the tun and the kernel never flags a dump of one device interrupted
func TestNetlinkReadsTheTunsAddressesWhileAnotherDeviceChurns(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real netlink path needs root on linux")
	}
	netnstest.EnterEmpty(t)
	conn, err := dialNetlink()
	if err != nil {
		t.Fatalf("dial rtnetlink: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	const device, churnName = "ranetaddrs0", "ranetchurn0"
	createTUN(t, device)
	tun, err := conn.link(0, device)
	if err != nil {
		t.Fatal(err)
	}
	if err := createLink(conn, churnName, "dummy"); err != nil {
		t.Fatalf("create the dummy %s: %v", churnName, err)
	}
	churned, err := conn.link(0, churnName)
	if err != nil {
		t.Fatal(err)
	}
	setLinkFlags(t, conn, tun.index, unix.IFF_UP)
	setLinkFlags(t, conn, churned.index, unix.IFF_UP)
	plat := &netlinkPlatform{index: tun.index, conn: conn}
	held := []netip.Prefix{prefix("192.0.2.1/32"), prefix("2001:db8::1/128")}
	for _, address := range held {
		if err := plat.AddAddr(address); err != nil {
			t.Fatalf("assign %s: %v", address, err)
		}
	}
	addDumpedAddresses(t, conn, churned.index)
	churnAddress(t, churned.index, prefix("192.0.2.100/32"))

	for read := range interruptedDumps {
		addresses, err := plat.Addrs()
		if err != nil {
			t.Fatalf("read %d of the tun's addresses failed: %v", read+1, err)
		}
		for _, address := range held {
			if !slices.Contains(addresses, address) {
				t.Fatalf("read %d of the tun's addresses holds %v, not %s", read+1, addresses, address)
			}
		}
	}
}

// the kernel ends a dump naming a tun it no longer holds on ENODEV, which the reconciler reads as a tun holding no address, so
// its withdraw after the tun closed releases nothing and returns no error
func TestNetlinkReadsATunTheKernelNoLongerHoldsAsEmpty(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real netlink path needs root on linux")
	}
	netnstest.EnterEmpty(t)
	conn, err := dialNetlink()
	if err != nil {
		t.Fatalf("dial rtnetlink: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	const device = "ranetclosed0"
	createTUN(t, device)
	tun, err := conn.link(0, device)
	if err != nil {
		t.Fatal(err)
	}
	setLinkFlags(t, conn, tun.index, unix.IFF_UP)
	plat := &netlinkPlatform{index: tun.index, conn: conn}
	if err := plat.AddAddr(prefix("192.0.2.1/32")); err != nil {
		t.Fatalf("assign 192.0.2.1/32: %v", err)
	}
	body := make([]byte, unix.SizeofIfInfomsg)
	binary.NativeEndian.PutUint32(body[4:], tun.index)
	if _, err := conn.execute(unix.RTM_DELLINK, unix.NLM_F_ACK, body); err != nil {
		t.Fatalf("delete %s: %v", device, err)
	}
	if addresses, err := plat.Addrs(); err != nil || len(addresses) != 0 {
		t.Errorf("the read of a tun the kernel no longer holds is %v and %v, want no addresses and no error", addresses, err)
	}
}

// addDumpedAddresses puts dumpedAddresses IPv4 host addresses on the device of index
func addDumpedAddresses(t *testing.T, conn *nlConn, index uint32) {
	t.Helper()
	add := uint16(unix.NLM_F_CREATE | unix.NLM_F_EXCL | unix.NLM_F_ACK)
	for i := range dumpedAddresses {
		block := [4]byte{198, 51, 100, byte(i)}
		if i >= 256 {
			block = [4]byte{203, 0, 113, byte(i)}
		}
		if _, err := conn.execute(unix.RTM_NEWADDR, add, hostAddrMessage(index, netip.PrefixFrom(netip.AddrFrom4(block), 32))); err != nil {
			t.Fatalf("address %d: %v", i, err)
		}
	}
}

// churnAddress adds address to the device of index and takes it off again, without a pause, until the test ends
func churnAddress(t *testing.T, index uint32, address netip.Prefix) {
	t.Helper()
	add := uint16(unix.NLM_F_CREATE | unix.NLM_F_EXCL | unix.NLM_F_ACK)
	message := hostAddrMessage(index, address)
	churn(t, func(conn *nlConn) {
		_, _ = conn.execute(unix.RTM_NEWADDR, add, message)
		_, _ = conn.execute(unix.RTM_DELADDR, unix.NLM_F_ACK, message)
	})
}

// churn runs step over a socket of its own, again and again without a pause, until the test ends
func churn(t *testing.T, step func(conn *nlConn)) {
	t.Helper()
	conn, err := dialNetlink()
	if err != nil {
		t.Fatal(err)
	}
	stop, stopped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		defer func() { _ = conn.Close() }()
		for {
			select {
			case <-stop:
				return
			default:
			}
			step(conn)
		}
	}()
	t.Cleanup(func() {
		close(stop)
		<-stopped
	})
}

// awaitInterruptedDump takes dumps of kind with body until the kernel flags one as interrupted, at most churnBiteDumps of them,
// so a test counts only once its churn bites
func awaitInterruptedDump(t *testing.T, conn *nlConn, kind uint16, body []byte) {
	t.Helper()
	for range churnBiteDumps {
		replies, err := conn.request(kind, unix.NLM_F_DUMP, body)
		if errors.Is(err, errDumpInterrupted) || slices.ContainsFunc(replies, func(reply nlMessage) bool { return reply.Flags&unix.NLM_F_DUMP_INTR != 0 }) {
			return
		}
		if err != nil {
			t.Fatalf("dump: %v", err)
		}
	}
	t.Fatalf("the churn interrupted none of %d dumps, so it proved nothing", churnBiteDumps)
}

func createTUN(t *testing.T, name string) {
	t.Helper()
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Skipf("no /dev/net/tun: %v", err)
	}
	// the device lives as long as the descriptor, so it outlives the test by
	// nothing at all.
	t.Cleanup(func() { _ = unix.Close(fd) })
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		t.Fatalf("build an ifreq for %s: %v", name, err)
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		t.Fatalf("create tun %s: %v", name, err)
	}
}

func setLinkFlags(t testing.TB, conn *nlConn, index uint32, flags uint32) {
	t.Helper()
	body := make([]byte, unix.SizeofIfInfomsg)
	binary.NativeEndian.PutUint32(body[4:], index)
	binary.NativeEndian.PutUint32(body[8:], flags)
	binary.NativeEndian.PutUint32(body[12:], flags)
	if _, err := conn.execute(unix.RTM_NEWLINK, unix.NLM_F_ACK, body); err != nil {
		t.Fatalf("set flags on link %d: %v", index, err)
	}
}

// createLink is test scaffolding, not part of the reconciler: the daemon never
// creates a link through netlink.
func createLink(conn *nlConn, name, kind string) error {
	info := putAttrString(nil, unix.IFLA_INFO_KIND, kind)
	body := make([]byte, unix.SizeofIfInfomsg)
	body = putAttrString(body, unix.IFLA_IFNAME, name)
	body = putAttr(body, unix.IFLA_LINKINFO, info)
	flags := uint16(unix.NLM_F_CREATE | unix.NLM_F_EXCL | unix.NLM_F_ACK)
	_, err := conn.execute(unix.RTM_NEWLINK, flags, body)
	return err
}

// replyRecorder keeps every reply a request drew, the messages the kernel sent before any decoding filtered them
type replyRecorder struct {
	netlinkConn
	replies []nlMessage
}

func (r *replyRecorder) execute(kind, flags uint16, body []byte) ([]nlMessage, error) {
	replies, err := r.netlinkConn.execute(kind, flags, body)
	r.replies = append(r.replies, replies...)
	return replies, err
}

func drain(signal <-chan struct{}) {
	for {
		select {
		case <-signal:
		default:
			return
		}
	}
}

// a dump the kernel ends early still ends at NLMSG_DONE, with the errno it ended on as that message's payload
// a rule dump for a family with no rules engine ends that way on its first call, with no privileges and nothing written
func TestExecuteReportsTheErrnoADumpEndedOn(t *testing.T) {
	conn, err := dialNetlink()
	if err != nil {
		t.Fatalf("dial rtnetlink: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	rules := make([]byte, sizeofFibRuleHdr)
	rules[0] = unix.AF_BRIDGE
	if replies, err := conn.execute(unix.RTM_GETRULE, unix.NLM_F_DUMP, rules); !errors.Is(err, unix.EAFNOSUPPORT) || replies != nil {
		t.Errorf("a rule dump the kernel ended on EAFNOSUPPORT read as %d replies and %v", len(replies), err)
	}
	// the socket is still in step, so the next request is answered as its own
	routes := make([]byte, unix.SizeofRtMsg)
	routes[0] = unix.AF_INET
	if _, err := conn.execute(unix.RTM_GETROUTE, unix.NLM_F_DUMP, routes); err != nil {
		t.Errorf("a dump after the one the kernel ended early failed: %v", err)
	}
}

// The RFC 8966 section 3.5.4 hold has to reach the kernel as a route that
// answers with an error, naming no output device, and has to come back from a
// dump the same way or every pass would delete and reinstall it.
func TestNetlinkHoldsRetractedPrefix(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real netlink path needs root on linux")
	}
	netnstest.EnterEmpty(t)
	conn, err := dialNetlink()
	if err != nil {
		t.Fatalf("dial rtnetlink: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	const device = "ranethold0"
	createTUN(t, device)
	tun, err := conn.link(0, device)
	if err != nil {
		t.Fatal(err)
	}
	setLinkFlags(t, conn, tun.index, unix.IFF_UP)
	plat := &netlinkPlatform{
		table: Table{ID: DefaultTable, Proto: DefaultProtocol}, rt: Runtime{Interface: device},
		index:    tun.index,
		conn:     conn,
		occupied: map[Route]bool{}, refused: map[Route]bool{},
	}

	// An explicit metric, the way the reconciler always sets one: a zero
	// RTA_PRIORITY makes the kernel substitute its own default, 1024 for
	// IPv6, and the dump would then never match what was asked for.
	held := Route{Destination: prefix("2001:db8:1::/48"), Unreachable: true, Metric: defaultIPv6Metric}
	if err := plat.AddRoute(held); err != nil {
		t.Fatalf("install the hold: %v", err)
	}
	got, err := plat.Routes()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []Route{held}) {
		t.Fatalf("the table holds %v, want %v", got, []Route{held})
	}
	// It converges, so a pass does not delete and reinstall it forever.
	if add, del := diffRoutes([]Route{held}, got, nil); len(add) != 0 || len(del) != 0 {
		t.Fatalf("an installed hold did not converge: add %v, delete %v", add, del)
	}
	if err := plat.DelRoute(held); err != nil {
		t.Fatalf("withdraw the hold: %v", err)
	}
	if got, err := plat.Routes(); err != nil || len(got) != 0 {
		t.Fatalf("the hold outlived its withdrawal: %v, error %v", got, err)
	}
}

// The policy engine against a real kernel, beside the rule tests of
// rules_netlink_linux_test.go and monitor_linux_test.go. An encoder alone
// proves the bytes and not that the kernel takes them: FRA_PROTOCOL is the
// whole ownership story and a kernel that ignored it would hand back none of
// this reconciler's rules, which it would never withdraw.
func TestNetlinkRulesInNetworkNamespace(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real netlink path needs root on linux")
	}
	netnstest.EnterEmpty(t)

	conn, err := dialNetlink()
	if err != nil {
		t.Fatalf("dial rtnetlink: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	const device = "ranettest0"
	createTUN(t, device)
	tbl, rt := platformFor(device)
	opened, err := newPlatform(tbl, rt)
	if err != nil {
		t.Fatalf("open the netlink platform: %v", err)
	}
	t.Cleanup(func() { _ = opened.Close() })
	plat := opened.(*netlinkPlatform)

	// The kernel's own three rules carry no FRA_PROTOCOL of ours, so a fresh
	// namespace reads back empty however many rules it holds.
	if rules, err := plat.Rules(); err != nil || len(rules) != 0 {
		t.Fatalf("a fresh namespace reads back %v (err %v), want none of ours", rules, err)
	}

	want := []Rule{
		{Family: FamilyIPv4, To: schema.MustPrefix("203.0.113.0/24"), Table: DefaultTable, Priority: 100},
		{Family: FamilyIPv6, From: schema.MustPrefix("3fff:b::/48"), Table: DefaultTable, Priority: 150},
		{Family: FamilyIPv4, FWMark: 0x72, Table: 254, Priority: 40},
		{Family: FamilyIPv6, FWMark: 0x72, Table: 254, Priority: 40},
		// one on a device that exists and one on a device that does not yet, which the kernel holds detached
		{Family: FamilyIPv6, IIF: device, Table: 254, Priority: 60},
		{Family: FamilyIPv4, IIF: device + "e", Table: 254, Priority: 60},
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
	slices.SortFunc(got, func(a, b Rule) int { return strings.Compare(a.String(), b.String()) })
	sorted := slices.Clone(want)
	slices.SortFunc(sorted, func(a, b Rule) int { return strings.Compare(a.String(), b.String()) })
	if !slices.Equal(got, sorted) {
		t.Fatalf("the kernel holds %v, want %v", got, sorted)
	}

	// A rule written by somebody else is invisible here, which is the property
	// the whole delete path rests on.
	foreign := plat.ruleMessage(Rule{Family: FamilyIPv4, To: schema.MustPrefix("192.0.2.0/24"), Table: DefaultTable, Priority: 101})
	foreign = replaceProtocol(t, foreign, unix.RTPROT_STATIC)
	if _, err := conn.execute(unix.RTM_NEWRULE, unix.NLM_F_CREATE|unix.NLM_F_EXCL|unix.NLM_F_ACK, foreign); err != nil {
		t.Fatalf("install another writer's rule: %v", err)
	}
	after, err := plat.Rules()
	if err != nil {
		t.Fatalf("list rules: %v", err)
	}
	if len(after) != len(want) {
		t.Fatalf("another writer's rule reads back as ours: %v", after)
	}

	for _, rule := range want {
		if err := plat.DelRule(rule); err != nil {
			t.Fatalf("delete %s: %v", rule, err)
		}
		// A second delete is success, as it has to be for a pass racing its
		// own notification.
		if err := plat.DelRule(rule); err != nil {
			t.Fatalf("deleting %s twice: %v", rule, err)
		}
	}
	if rules, err := plat.Rules(); err != nil || len(rules) != 0 {
		t.Fatalf("after withdrawal the kernel holds %v (err %v)", rules, err)
	}
}
