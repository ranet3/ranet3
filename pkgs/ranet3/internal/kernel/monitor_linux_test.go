// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/netlink"
	"ranet3.com/pkgs/ranet3/internal/netnstest"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/schema"
)

// ruleRestoreBudget is how soon a deleted rule of the reconciler's is back
// the periodic sweep alone takes DefaultReconcileInterval
const ruleRestoreBudget = time.Second

// ownPort is the port of the socket a test's reconciler writes routes through, and otherPort another writer's
const (
	ownPort   = 4000
	otherPort = 4001
)

// the monitor wakes on a deleted rule carrying the reconciler's protocol and on nothing else about rules
// another writer's rule comes and goes without a pass, and a rule the reconciler adds itself is already in place
func TestRouteMonitorWakesOnlyOnADeletedRuleItOwns(t *testing.T) {
	plat, _ := writePlatform(t)
	wakesOn := reconcilerWakes(uint32(plat.table.ID), plat.table.Proto, plat.index, ownPort)
	owned := plat.ruleMessage(Rule{Family: FamilyIPv4, FWMark: 0x72, Table: schema.TableMain, Priority: 40})
	for name, arm := range map[string]struct {
		kind uint16
		body []byte
		want bool
	}{
		"its own rule deleted":           {unix.RTM_DELRULE, owned, true},
		"its own rule added":             {unix.RTM_NEWRULE, owned, false},
		"another writer's rule deleted":  {unix.RTM_DELRULE, replaceProtocol(t, owned, unix.RTPROT_STATIC), false},
		"a rule without a protocol gone": {unix.RTM_DELRULE, stripProtocol(t, owned), false},
	} {
		if got := wakesOn(netlink.Message{Kind: arm.kind, Data: arm.body}); got != arm.want {
			t.Errorf("%s: the monitor woke %v, want %v", name, got, arm.want)
		}
	}
}

// the monitor wakes on an address added to the tun or taken off it, whoever wrote it, and on no other link's
func TestRouteMonitorWakesOnTheTunsAddresses(t *testing.T) {
	plat, _ := writePlatform(t)
	wakesOn := reconcilerWakes(uint32(plat.table.ID), plat.table.Proto, plat.index, ownPort)
	tun := plat.addrMessage(netip.MustParsePrefix("192.0.2.1/32"))
	other := slices.Clone(tun)
	binary.NativeEndian.PutUint32(other[4:], plat.index+1)
	for name, arm := range map[string]struct {
		kind uint16
		body []byte
		want bool
	}{
		"an address added to the tun":       {unix.RTM_NEWADDR, tun, true},
		"an address taken off the tun":      {unix.RTM_DELADDR, tun, true},
		"an address added to another link":  {unix.RTM_NEWADDR, other, false},
		"an address taken off another link": {unix.RTM_DELADDR, other, false},
		"an address message cut short":      {unix.RTM_NEWADDR, tun[:4], false},
	} {
		if got := wakesOn(netlink.Message{Kind: arm.kind, Data: arm.body}); got != arm.want {
			t.Errorf("%s: the monitor woke %v, want %v", name, got, arm.want)
		}
	}
}

// the monitor wakes on a route of its table and on a deleted rule of its protocol that a socket other than the one the reconciler
// writes through wrote, the kernel's own changes among them, which carry port 0, and on the tun's addresses whichever socket wrote them
func TestRouteMonitorWakesOnARouteOnlyWhereAnotherSocketWroteIt(t *testing.T) {
	plat, _ := writePlatform(t)
	wakesOn := reconcilerWakes(uint32(plat.table.ID), plat.table.Proto, plat.index, ownPort)
	elsewhere, _ := writePlatform(t)
	elsewhere.table.ID = plat.table.ID + 1
	for _, route := range []Route{{Destination: prefix("2001:db8:1::/48"), Metric: 1024}, {Destination: prefix("192.0.2.0/24"), Metric: 1024}} {
		added, deleted := plat.routeMessage(route, false), plat.routeMessage(route, true)
		for name, arm := range map[string]struct {
			kind uint16
			port uint32
			body []byte
			want bool
		}{
			"its own route added":                    {unix.RTM_NEWROUTE, ownPort, added, false},
			"its own route deleted":                  {unix.RTM_DELROUTE, ownPort, deleted, false},
			"a route the kernel added":               {unix.RTM_NEWROUTE, 0, added, true},
			"a route the kernel deleted":             {unix.RTM_DELROUTE, 0, deleted, true},
			"another writer's route added":           {unix.RTM_NEWROUTE, otherPort, added, true},
			"another writer's route deleted":         {unix.RTM_DELROUTE, otherPort, deleted, true},
			"another table's route deleted":          {unix.RTM_DELROUTE, otherPort, elsewhere.routeMessage(route, true), false},
			"its own rule deleted by its socket":     {unix.RTM_DELRULE, ownPort, plat.ruleMessage(Rule{Family: FamilyIPv4, FWMark: 0x72, Table: schema.TableMain, Priority: 40}), false},
			"its own rule deleted by another socket": {unix.RTM_DELRULE, otherPort, plat.ruleMessage(Rule{Family: FamilyIPv4, FWMark: 0x72, Table: schema.TableMain, Priority: 40}), true},
			"its own rule deleted by the kernel":     {unix.RTM_DELRULE, 0, plat.ruleMessage(Rule{Family: FamilyIPv4, FWMark: 0x72, Table: schema.TableMain, Priority: 40}), true},
			"a tun address its socket added":         {unix.RTM_NEWADDR, ownPort, plat.addrMessage(prefix("192.0.2.1/32")), true},
			"a tun address its socket took off":      {unix.RTM_DELADDR, ownPort, plat.addrMessage(prefix("192.0.2.1/32")), true},
		} {
			if got := wakesOn(netlink.Message{Kind: arm.kind, Pid: arm.port, Data: arm.body}); got != arm.want {
				t.Errorf("%s, %s: the monitor woke %v, want %v", route.Destination, name, got, arm.want)
			}
		}
	}
}

// a datagram the monitor cannot parse and an overflow each wake it, where a datagram holding only a route of its own socket's does not
func TestRouteMonitorWakesOnWhatItCannotReadPastItsOwnRoute(t *testing.T) {
	plat, _ := writePlatform(t)
	source := newScriptedSource(nil)
	monitor := startMonitor("scripted", source, reconcilerWakes(uint32(plat.table.ID), plat.table.Proto, plat.index, ownPort))
	t.Cleanup(func() { _ = monitor.Close() })
	own := fromPort(notification(unix.RTM_NEWROUTE, plat.routeMessage(Route{Destination: prefix("2001:db8:1::/48"), Metric: 1024}, false)), ownPort)
	source.queue <- scriptedRead{datagram: own}
	// read, then given monitorQuiet to wake
	waitFor(t, func() bool { return source.reads.Load() == 1 })
	time.Sleep(monitorQuiet)
	select {
	case <-monitor.signal:
		t.Fatal("a route written through the reconciler's own socket woke the monitor")
	default:
	}
	runsPast := fromPort(notification(unix.RTM_NEWROUTE, nil), ownPort)
	binary.NativeEndian.PutUint32(runsPast, uint32(2*len(runsPast)))
	source.queue <- scriptedRead{datagram: runsPast}
	awaitWake(t, monitor.signal, "a datagram whose length runs past its end")
	source.queue <- scriptedRead{err: unix.ENOBUFS}
	awaitWake(t, monitor.signal, "an overflow")
}

// monitorQuiet is how long a test waits to see that a datagram handed on woke nothing
const monitorQuiet = 50 * time.Millisecond

// fromPort is datagram with the port of its first message's header set to port
func fromPort(datagram []byte, port uint32) []byte {
	binary.NativeEndian.PutUint32(datagram[12:], port)
	return datagram
}

// notification is one datagram holding one netlink message of kind with body
func notification(kind uint16, body []byte) []byte {
	datagram := make([]byte, unix.SizeofNlMsghdr+len(body))
	binary.NativeEndian.PutUint32(datagram, uint32(len(datagram)))
	binary.NativeEndian.PutUint16(datagram[4:], kind)
	copy(datagram[unix.SizeofNlMsghdr:], body)
	return datagram
}

// the monitor reads its socket through readNotifications: an error wakes it, the notification after the error and a datagram that
// does not parse each wake it again, and Close ends the backoff two errors in a row leave it in, its goroutine with it
func TestRouteMonitorReadsOnAndClosesWhilePaused(t *testing.T) {
	source := newScriptedSource(nil)
	monitor := startMonitor("scripted", source, func(message netlink.Message) bool { return message.Kind == unix.RTM_NEWADDR })
	t.Cleanup(func() { _ = monitor.Close() })
	source.queue <- scriptedRead{err: unix.EMSGSIZE}
	awaitWake(t, monitor.signal, "EMSGSIZE")
	source.queue <- scriptedRead{datagram: notification(unix.RTM_NEWADDR, hostAddrMessage(2, prefix("192.0.2.10/24")))}
	awaitWake(t, monitor.signal, "an address after the error")
	runsPast := notification(unix.RTM_NEWADDR, nil)
	binary.NativeEndian.PutUint32(runsPast, uint32(2*len(runsPast)))
	source.queue <- scriptedRead{datagram: runsPast}
	awaitWake(t, monitor.signal, "a datagram whose length runs past its end")
	source.queue <- scriptedRead{err: unix.EMSGSIZE}
	source.queue <- scriptedRead{err: unix.EMSGSIZE}
	waitFor(t, func() bool { return source.reads.Load() == 5 })
	awaitClose(t, monitor.Close)
	select {
	case <-monitor.done:
	default:
		t.Error("the monitor's goroutine still runs after Close returned")
	}
}

// addressWakeBudget is how soon a pass follows another writer's address on the tun
// the periodic sweep alone takes DefaultReconcileInterval
const addressWakeBudget = time.Second

// in mode 2 another writer's overlay address of either family on the tun brings the family's catch-all for the host in, and taking it
// off takes it out, each on a pass the address's own notification wakes, long before the periodic sweep
func TestNetlinkFollowsAnotherWritersAddressOnTheTun(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("the real netlink path needs root on linux")
	}
	netnstest.EnterEmpty(t)
	conn, err := dialNetlink()
	if err != nil {
		t.Fatalf("dial rtnetlink: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	const device = "ranetaddr0"
	createTUN(t, device)

	bus := events.New()
	overlay := []schema.Prefix{schema.MustPrefix("192.0.2.0/24"), schema.MustPrefix("3fff::/20")}
	r, err := New(Table{}.WithMode(&ExitMode{}), Runtime{Interface: device, Overlay: overlay, Events: bus, Sessions: func() int { return 1 }}, netstack.NewRouteTable())
	if err != nil {
		t.Fatalf("start the reconciler: %v", err)
	}
	plat := r.plat.(*netlinkPlatform)
	// read through a socket of the test's own, since the loop owns the platform's
	catchAll := func() []string {
		replies, err := conn.execute(unix.RTM_GETRULE, unix.NLM_F_DUMP, make([]byte, sizeofFibRuleHdr))
		if err != nil {
			t.Fatalf("dump rules: %v", err)
		}
		var out []string
		for _, reply := range replies {
			if rule, ok := plat.decodeRule(reply); ok && rule.Priority == priorityCatchAll {
				out = append(out, string(rule.Family)+" iif "+rule.IIF)
			}
		}
		slices.Sort(out)
		return out
	}
	trigger := func() string {
		passes := bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "kernel.pass" }, 0)
		if len(passes) == 0 {
			return ""
		}
		return passes[len(passes)-1].Attrs["trigger"]
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("the reconciler stopped with %v", err)
		}
	})
	waitFor(t, func() bool { return trigger() == "start" })
	if got := catchAll(); len(got) != 0 {
		t.Fatalf("with no overlay address on the tun the catch-all reads %v, want none", got)
	}

	v4, v6 := netip.MustParsePrefix("192.0.2.1/32"), netip.MustParsePrefix("3fff::1/128")
	for _, step := range []struct {
		what    string
		kind    uint16
		address netip.Prefix
		want    []string
	}{
		{"another writer's IPv4 overlay address added", unix.RTM_NEWADDR, v4, []string{"ipv4 iif lo"}},
		{"the IPv4 address taken off", unix.RTM_DELADDR, v4, nil},
		{"another writer's IPv6 overlay address added", unix.RTM_NEWADDR, v6, []string{"ipv6 iif lo"}},
		{"the IPv6 address taken off", unix.RTM_DELADDR, v6, nil},
	} {
		flags := uint16(unix.NLM_F_ACK)
		if step.kind == unix.RTM_NEWADDR {
			flags |= unix.NLM_F_CREATE | unix.NLM_F_EXCL
		}
		if _, err := conn.execute(step.kind, flags, plat.addrMessage(step.address)); err != nil {
			t.Fatalf("%s: %v", step.what, err)
		}
		changed := time.Now()
		waitFor(t, func() bool { return slices.Equal(catchAll(), step.want) && trigger() == "kernel" })
		if took := time.Since(changed); took > addressWakeBudget {
			t.Errorf("%s: the catch-all followed in %s, want at most %s", step.what, took, addressWakeBudget)
		}
	}
}

// systemd-networkd deletes every rule it did not ask for whenever it configures a link
// the reconciler puts its own back within the settle window and one pass, long before the periodic sweep
func TestNetlinkRestoresADeletedRuleWithinASecond(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("the real netlink path needs root on linux")
	}
	netnstest.EnterEmpty(t)
	conn, err := dialNetlink()
	if err != nil {
		t.Fatalf("dial rtnetlink: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	const device = "ranetrule0"
	createTUN(t, device)

	// the rules derived from an overlay of each family
	overlay := []schema.Prefix{schema.MustPrefix("198.18.0.0/15"), schema.MustPrefix("3fff::/20")}
	installed := derivedRules(DefaultTable, overlay, nil, exitView{})
	r, err := New(Table{}, Runtime{Interface: device, Overlay: overlay}, netstack.NewRouteTable())
	if err != nil {
		t.Fatalf("start the reconciler: %v", err)
	}
	plat := r.plat.(*netlinkPlatform)
	// read through a socket of the test's own, since the loop owns the platform's
	holds := func(rule Rule) func() bool {
		return func() bool {
			replies, err := conn.execute(unix.RTM_GETRULE, unix.NLM_F_DUMP, make([]byte, sizeofFibRuleHdr))
			if err != nil {
				t.Fatalf("dump rules: %v", err)
			}
			return slices.ContainsFunc(replies, func(reply netlink.Message) bool {
				got, ok := plat.decodeRule(reply)
				return ok && got == rule
			})
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("the reconciler stopped with %v", err)
		}
	})
	for _, rule := range installed {
		waitFor(t, holds(rule))
	}

	for _, rule := range installed {
		if _, err := conn.execute(unix.RTM_DELRULE, unix.NLM_F_ACK, plat.ruleMessage(rule)); err != nil {
			t.Fatalf("delete %s as networkd would: %v", rule, err)
		}
		deleted := time.Now()
		waitFor(t, holds(rule))
		if took := time.Since(deleted); took > ruleRestoreBudget {
			t.Errorf("the deleted rule %s took %s to come back, want at most %s", rule, took, ruleRestoreBudget)
		}
	}
}

// passCounter is the reconciler's own platform counting its passes, each of which lists the table once, and failing the next
// writes of a route a test names
type passCounter struct {
	*netlinkPlatform
	lists atomic.Int64
	mu    sync.Mutex
	fail  map[netip.Prefix]int
}

func (p *passCounter) Routes() ([]Route, error) {
	p.lists.Add(1)
	return p.netlinkPlatform.Routes()
}

func (p *passCounter) AddRoute(route Route) error {
	p.mu.Lock()
	failing := p.fail[route.Destination] > 0
	if failing {
		p.fail[route.Destination]--
	}
	p.mu.Unlock()
	if failing {
		return fmt.Errorf("write %s: %w", route.Destination, unix.ENOBUFS)
	}
	return p.netlinkPlatform.AddRoute(route)
}

// failNext fails the next times writes of a route to destination
func (p *passCounter) failNext(destination netip.Prefix, times int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.fail[destination] = times
}

// secondPassWindow is how long after a pass's write a pass its own notification woke would have run, its settle window
// and the pass with room for a loaded machine
const secondPassWindow = 4 * settleDelay

// routeRestoreBudget is how soon a route of the reconciler's that another writer deletes is back, the settle window and
// one pass, where the periodic pass the test sets takes an hour
const routeRestoreBudget = time.Second

// routeRetryBudget is how soon a route whose write failed is written again, the first retry of the backoff after the
// settle window and the pass that failed
const routeRetryBudget = 3 * minRetryInterval

// countedReconciler runs a reconciler on a tun named device in a network namespace of the test's own, with an hour between
// its periodic passes, on a platform counting its passes, and answers whether the reconciler's table holds a route to a
// destination, read through a socket of the test's own
func countedReconciler(t *testing.T, device string) (*passCounter, *netstack.RouteTable, *nlConn, func(netip.Prefix) bool) {
	t.Helper()
	netnstest.EnterEmpty(t)
	conn, err := dialNetlink()
	if err != nil {
		t.Fatalf("dial rtnetlink: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	createTUN(t, device)
	if err := netnstest.BringUp(device); err != nil {
		t.Fatal(err)
	}
	overlay := []schema.Prefix{schema.MustPrefix("198.18.0.0/15"), schema.MustPrefix("3fff::/20")}
	routes := netstack.NewRouteTable()
	r, err := New(Table{Reconcile: schema.Duration(time.Hour)}, Runtime{Interface: device, Overlay: overlay}, routes)
	if err != nil {
		t.Fatalf("start the reconciler: %v", err)
	}
	counter := &passCounter{netlinkPlatform: r.plat.(*netlinkPlatform), fail: map[netip.Prefix]int{}}
	r.use(counter)
	holds := func(destination netip.Prefix) bool {
		family := uint8(unix.AF_INET6)
		if destination.Addr().Is4() {
			family = unix.AF_INET
		}
		body := make([]byte, unix.SizeofRtMsg)
		body[0] = family
		body = netlink.PutAttrU32(body, unix.RTA_TABLE, uint32(counter.table.ID))
		replies, err := conn.execute(unix.RTM_GETROUTE, unix.NLM_F_DUMP, body)
		if err != nil {
			t.Fatalf("dump the table: %v", err)
		}
		return slices.ContainsFunc(replies, func(reply netlink.Message) bool {
			route, ok := counter.decodeRoute(reply)
			return ok && route.Destination == destination
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("the reconciler stopped with %v", err)
		}
	})
	<-r.FirstPass()
	return counter, routes, conn, holds
}

// each route the reconciler writes or deletes takes one pass, its own notification waking none after it
func TestNetlinkRouteChangeRunsOnePass(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("the real netlink path needs root on linux")
	}
	counter, routes, _, holds := countedReconciler(t, "ranetpass0")
	time.Sleep(secondPassWindow)
	for _, step := range []struct {
		destination netip.Prefix
		add         bool
	}{{prefix("2001:db8:1::/48"), true}, {prefix("192.0.2.0/24"), true}, {prefix("2001:db8:1::/48"), false}, {prefix("192.0.2.0/24"), false}} {
		before := counter.lists.Load()
		if step.add {
			routes.Set(netip.Prefix{}, step.destination, nil)
		} else {
			routes.Remove(netip.Prefix{}, step.destination)
		}
		waitFor(t, func() bool { return holds(step.destination) == step.add })
		time.Sleep(secondPassWindow)
		if passes := counter.lists.Load() - before; passes != 1 {
			t.Errorf("a route to %s, added %t, took %d passes, want 1", step.destination, step.add, passes)
		}
	}
}

// another writer's delete of a route of the reconciler's wakes the pass that writes it back, long before the periodic one
func TestNetlinkRestoresAnotherWritersDeletedRouteWithinASecond(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("the real netlink path needs root on linux")
	}
	counter, routes, conn, holds := countedReconciler(t, "ranetroute0")
	for _, destination := range []netip.Prefix{prefix("2001:db8:1::/48"), prefix("192.0.2.0/24")} {
		routes.Set(netip.Prefix{}, destination, nil)
		waitFor(t, func() bool { return holds(destination) })
		if _, err := conn.execute(unix.RTM_DELROUTE, unix.NLM_F_ACK, counter.routeMessage(Route{Destination: destination}, true)); err != nil {
			t.Fatalf("delete %s as another writer: %v", destination, err)
		}
		deleted := time.Now()
		waitFor(t, func() bool { return holds(destination) })
		if took := time.Since(deleted); took > routeRestoreBudget {
			t.Errorf("the deleted route to %s took %s to come back, want at most %s", destination, took, routeRestoreBudget)
		}
	}
}

// a route write the kernel refuses fails its pass, whose retry writes it, alone and beside a route whose write lands
func TestNetlinkRetriesAFailedRouteWrite(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("the real netlink path needs root on linux")
	}
	counter, routes, _, holds := countedReconciler(t, "ranetretry0")
	for _, step := range []struct {
		failing, beside netip.Prefix
	}{{failing: prefix("2001:db8:1::/48")}, {failing: prefix("2001:db8:2::/48"), beside: prefix("2001:db8:3::/48")}} {
		counter.failNext(step.failing, 1)
		changed := time.Now()
		routes.Set(netip.Prefix{}, step.failing, nil)
		if step.beside.IsValid() {
			routes.Set(netip.Prefix{}, step.beside, nil)
		}
		waitFor(t, func() bool { return holds(step.failing) })
		if took := time.Since(changed); took > routeRetryBudget {
			t.Errorf("the route to %s whose write failed took %s to be written, want at most %s", step.failing, took, routeRetryBudget)
		}
		if step.beside.IsValid() && !holds(step.beside) {
			t.Errorf("the route to %s beside it is not written", step.beside)
		}
	}
}
