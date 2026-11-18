// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/egress"
	meshkernel "ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/netlink"
	"ranet3.com/pkgs/ranet3/internal/netnstest"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/sadr"
	"ranet3.com/pkgs/ranet3/schema"
)

const (
	// orderStand is how long the reconciler's waiting writes stand before a
	// second datagram shows the state lasts
	orderStand = time.Second
	// orderHold is how long a held pass waits before its read
	orderHold = time.Second
	// orderWait bounds the wait for a route to land or a datagram to come
	// out of the tun
	orderWait = 10 * time.Second
	// orderQuiet is how long a datagram that must stay out is waited for
	orderQuiet = 300 * time.Millisecond
	// orderPoll is how often a wait looks
	orderPoll = 2 * time.Millisecond
	// orderFailing is how many passes a phase that runs with the filter
	// failing has fail, more than run within orderWait
	orderFailing = 100
)

// orderBackend is the real nftables backend with the failures and the hold a
// phase arms before a learn
type orderBackend struct {
	borderBackend
	failRules, failFill atomic.Int32
	holdRules           atomic.Int64
}

// orderTake takes one of n, reporting whether there was one
func orderTake(n *atomic.Int32) bool {
	for {
		v := n.Load()
		if v <= 0 {
			return false
		}
		if n.CompareAndSwap(v, v-1) {
			return true
		}
	}
}

func (b *orderBackend) Rules(rules []BorderRule, sets borderSets) (chainReadback, error) {
	if d := b.holdRules.Swap(0); d > 0 {
		time.Sleep(time.Duration(d))
	}
	if orderTake(&b.failRules) {
		return chainReadback{}, fmt.Errorf("dump rules: %w", netlink.ErrDumpInterrupted)
	}
	return b.borderBackend.Rules(rules, sets)
}

func (b *orderBackend) Fill(rules []BorderRule, was, sets borderSets) error {
	if orderTake(&b.failFill) {
		return unix.ENOBUFS
	}
	return b.borderBackend.Fill(rules, was, sets)
}

// heldSource is the route source as a reconciler whose route writes wait
// reads it: while held, each Snapshot hands the one read before the hold, so
// the reconciler keeps the routes it wrote and tells the filter it holds
// them, as it tells a delete the kernel refused. A stall stops the next
// Snapshot until it is let go. report is the routes the reconciler's last
// report named.
type heldSource struct {
	meshkernel.RouteSource
	held   atomic.Bool
	stall  atomic.Pointer[orderStall]
	mu     sync.Mutex
	last   []sadr.Route[*netstack.Peer]
	report []meshkernel.Route
}

// orderStall stops one Snapshot: the Snapshot closes entered as it comes,
// then waits until open is closed
type orderStall struct{ entered, open chan struct{} }

func (s *heldSource) Snapshot() []sadr.Route[*netstack.Peer] {
	if stall := s.stall.Swap(nil); stall != nil {
		close(stall.entered)
		<-stall.open
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.held.Load() {
		s.last = s.RouteSource.Snapshot()
	}
	return s.last
}

func (s *heldSource) Installed(routes []meshkernel.Route) {
	s.mu.Lock()
	s.report = slices.Clone(routes)
	s.mu.Unlock()
	if sink, ok := s.RouteSource.(meshkernel.InstalledSink); ok {
		sink.Installed(routes)
	}
}

const (
	orderTun     = "r3omesh"
	orderUplink  = "r3oup"
	orderForward = "r3ofw"
)

var (
	// orderStranger is a host beyond the uplink, outside the overlay and every
	// class
	orderStranger = netip.MustParseAddr("192.0.2.2")
	// orderForwarded is a host on orderForward, outside the overlay and every
	// class
	orderForwarded = netip.MustParseAddr("198.51.100.130")
)

// orderLab is an exit's antispoof filter over the real backend and its route
// reconciler over the filter's route source, in a namespace of their own, with
// a tun standing for the uplink a stranger's datagrams arrive on, and in
// cap.exit's mode one standing for a link forward expands to
type orderLab struct {
	t                 *testing.T
	ns                *netnstest.Thread
	mesh, up, forward int
	be                *orderBackend
	filter            *BorderFilter
	source            *heldSource
	router            *meshkernel.Reconciler
	table             meshkernel.Table
	overlay           []schema.Prefix
	routes            *netstack.RouteTable
	peer              *netstack.Peer
}

// startOrderLab starts the lab with classes, the filter's sets derived from
// the mesh's table on each pass as the node derives them
func startOrderLab(t *testing.T, classes []egress.Class) *orderLab {
	t.Helper()
	return startOrderLabIn(t, classes, false)
}

// startOrderLabIn starts the lab as startOrderLab does, and where exit is
// true runs the node in cap.exit's mode with orderForward a link forward
// expands to, the host's network read as the uplink, its default and that link
func startOrderLabIn(t *testing.T, classes []egress.Class, exit bool) *orderLab {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("the real nftables path and a tun need root on linux")
	}
	lab := &orderLab{t: t, ns: netnstest.StartThread(t), routes: netstack.NewRouteTable(), peer: &netstack.Peer{ID: "example/router"}}
	lab.table = meshkernel.Table{Addresses: []schema.Prefix{schema.MustPrefix("203.0.113.1/32")}}
	uplink := netip.MustParsePrefix("192.0.2.1/24")
	runtime := meshkernel.Runtime{Interface: orderTun}
	if exit {
		lab.table = lab.table.WithMode(&meshkernel.ExitMode{Forward: []string{orderForward}, Fallback: meshkernel.FallbackUplink})
		uplink = netip.MustParsePrefix("192.0.2.1/25")
		network := meshkernel.NetworkState{IPv4: meshkernel.NetworkFamily{
			Default:   meshkernel.DefaultRoute{Interface: orderUplink, Gateway: netip.MustParseAddr("192.0.2.126")},
			Addresses: []netip.Addr{uplink.Addr(), netip.MustParseAddr("198.51.100.129")},
			Links: []meshkernel.Link{
				{Name: orderForward, Prefixes: []netip.Prefix{netip.MustParsePrefix("198.51.100.129/25")}},
				{Name: orderUplink, Prefixes: []netip.Prefix{uplink}},
			},
		}}
		runtime.Sessions = func() int { return 1 }
		runtime.Network = func() meshkernel.NetworkState { return network }
	}
	lab.overlay = []schema.Prefix{schema.MustPrefix("203.0.113.0/24")}
	runtime.Overlay = lab.overlay
	cfg := &egress.Border{Overlay: lab.overlay}
	rt := egress.BorderRuntime{Tun: orderTun, Inside: []string{orderTun, "lo"}, Routes: lab.routes.Changes(), Sets: orderSets(classes, lab.routes)}
	if err := lab.ns.Do(func() error {
		lab.mesh, lab.up = benchOpenTun(t, orderTun), benchOpenTun(t, orderUplink)
		files := map[string]string{
			"/proc/sys/net/ipv4/ip_forward":                         "1",
			"/proc/sys/net/ipv4/conf/all/rp_filter":                 "0",
			"/proc/sys/net/ipv4/conf/" + orderUplink + "/rp_filter": "0",
		}
		if exit {
			lab.forward = benchOpenTun(t, orderForward)
			files["/proc/sys/net/ipv4/conf/"+orderForward+"/rp_filter"] = "0"
		}
		for path, value := range files {
			if err := os.WriteFile(path, []byte(value), 0o644); err != nil {
				return err
			}
		}
		nl, err := netnstest.OpenNetlink()
		if err != nil {
			return err
		}
		defer nl.Close()
		if err := nl.AddAddresses(orderUplink, uplink); err != nil {
			return err
		}
		if exit {
			if err := nl.AddAddresses(orderForward, netip.MustParsePrefix("198.51.100.129/25")); err != nil {
				return err
			}
		}
		inner, err := newBorderBackend(cfg, rt)
		if err != nil {
			return err
		}
		lab.be = &orderBackend{borderBackend: inner}
		if lab.filter, err = startBorderFilter(cfg, rt, lab.be); err != nil {
			return err
		}
		lab.source = &heldSource{RouteSource: lab.filter.Routes(lab.routes)}
		lab.router, err = meshkernel.New(lab.table, runtime, lab.source)
		if err != nil {
			return errors.Join(err, lab.filter.Close())
		}
		return nil
	}); err != nil {
		t.Fatalf("start the filter and the reconciler: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	borderDone, routeDone := make(chan error, 1), make(chan error, 1)
	go func() { borderDone <- lab.filter.Run(ctx) }()
	go func() { routeDone <- lab.router.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-routeDone; err != nil {
			t.Errorf("the reconciler: %v", err)
		}
		if err := <-borderDone; err != nil {
			t.Errorf("the antispoof filter: %v", err)
		}
	})
	select {
	case <-lab.router.FirstPass():
	case <-time.After(orderWait):
		t.Fatal("the first route pass did not end")
	}
	return lab
}

// entryDrops is the chain entry's IPv4 drops, read now
func (l *orderLab) entryDrops() uint64 {
	l.t.Helper()
	var debug egress.BorderDebug
	if err := l.ns.Do(func() error {
		debug = l.filter.Debug()
		return nil
	}); err != nil {
		l.t.Fatal(err)
	}
	for _, chain := range debug.Chains {
		for _, rule := range chain.Rules {
			if rule.Spec == "drop ipv4 entering the mesh" {
				return rule.Packets
			}
		}
	}
	l.t.Fatalf("no drop ipv4 entering the mesh rule in the debug read %+v", debug)
	return 0
}

// send has the stranger send one datagram to host and reports whether it came
// out of the mesh tun and how far the chain entry's drops moved
func (l *orderLab) send(host netip.Addr) (entered bool, dropped uint64) {
	l.t.Helper()
	return l.sendFrom(l.up, orderStranger, host)
}

// sendFrom sends as send does, the datagram from source arriving on the tun
// link stands for
func (l *orderLab) sendFrom(link int, source, host netip.Addr) (entered bool, dropped uint64) {
	l.t.Helper()
	buf := make([]byte, 2048)
	drain(l.mesh, buf)
	before := l.entryDrops()
	packet := benchUDP(source, host)
	if _, err := unix.Write(link, packet); err != nil {
		l.t.Fatal(err)
	}
	for deadline := time.Now().Add(orderQuiet); time.Now().Before(deadline) && !entered; time.Sleep(orderPoll) {
		n, err := unix.Read(l.mesh, buf)
		if err != nil && !errors.Is(err, unix.EAGAIN) {
			l.t.Fatal(err)
		}
		// forwarding moves the TTL and the header's checksum alone
		entered = err == nil && n == len(packet) && bytes.Equal(buf[16:20], packet[16:20]) && bytes.Equal(buf[20:n], packet[20:])
	}
	return entered, l.entryDrops() - before
}

// installed is how many routes into the tun the reconciler's last report
// held, its holds left out
func (l *orderLab) installed() int {
	l.source.mu.Lock()
	defer l.source.mu.Unlock()
	n := 0
	for _, route := range l.source.report {
		if !route.Unreachable && !route.Throw && !route.Cover {
			n++
		}
	}
	return n
}

// holds reports whether the reconciler's last report held a hold at destination
func (l *orderLab) holds(destination netip.Prefix) bool {
	l.source.mu.Lock()
	defer l.source.mu.Unlock()
	return slices.ContainsFunc(l.source.report, func(route meshkernel.Route) bool { return route.Unreachable && route.Destination == destination })
}

// awaitInstalled waits until the reconciler's last pass left want routes installed
func (l *orderLab) awaitInstalled(what string, want int) {
	l.t.Helper()
	for deadline := time.Now().Add(orderWait); l.installed() != want; time.Sleep(orderPoll) {
		if time.Now().After(deadline) {
			l.t.Fatalf("%s: the reconciler holds %d routes, want %d", what, l.installed(), want)
		}
	}
}

// passNow has the filter run a pass that reads, as a reload wakes one where a
// change of the table alone may move no set, waits for it to end and reports
// whether it left the filter ready
func (l *orderLab) passNow(what string) bool {
	l.t.Helper()
	since := time.Now()
	if err := l.filter.SetConfig(l.filter.Capability()); err != nil {
		l.t.Fatal(err)
	}
	for deadline := time.Now().Add(orderWait); !l.filter.Stats().At.After(since); time.Sleep(orderPoll) {
		if time.Now().After(deadline) {
			l.t.Fatalf("%s: no pass of the filter's ended", what)
		}
	}
	return l.filter.Stats().Ready
}

// learnRead learns lan while a pass of the reconciler, which a reload wakes
// at once, waits at its read of the source, arming the backend before the
// learn, and lets the pass read on as the learn lands: the reconciler reads
// the source the moment the LAN comes, as with no settle
func (l *orderLab) learnRead(lan netip.Prefix, arm func(*orderBackend)) {
	l.t.Helper()
	stall := &orderStall{entered: make(chan struct{}), open: make(chan struct{})}
	defer close(stall.open)
	l.source.stall.Store(stall)
	if err := l.router.SetTable(l.table, l.overlay, nil); err != nil {
		l.t.Fatal(err)
	}
	select {
	case <-stall.entered:
	case <-time.After(orderWait):
		l.source.stall.Store(nil)
		l.t.Fatal("no pass of the reconciler came to read the source")
	}
	arm(l.be)
	l.routes.Set(netip.Prefix{}, lan, l.peer)
}

// awaitHold waits until the reconciler's last report holds a hold at
// destination
func (l *orderLab) awaitHold(what string, destination netip.Prefix) {
	l.t.Helper()
	if !l.holdWithin(destination) {
		l.t.Fatalf("%s: the reconciler reports no hold at %s within %v", what, destination, orderWait)
	}
}

// holdWithin reports whether the reconciler's report comes to hold a hold at
// destination within orderWait
func (l *orderLab) holdWithin(destination netip.Prefix) bool {
	for deadline := time.Now().Add(orderWait); !l.holds(destination); time.Sleep(orderPoll) {
		if time.Now().After(deadline) {
			return false
		}
	}
	return true
}

// orderNoneBlock is an exit's none class outside the overlay, and
// orderOutside a LAN outside every class
var (
	orderNoneBlock = netip.MustParsePrefix("198.51.100.0/25")
	orderOutside   = netip.MustParsePrefix("198.51.100.192/26")
)

// orderBlockClasses is the classes of an exit whose none class is orderNoneBlock
func orderBlockClasses() []egress.Class {
	return []egress.Class{{From: schema.PrefixFrom(orderNoneBlock), To: egress.Translation{None: true}}}
}

// At an exit whose none class covers a block, the route to a LAN another node
// comes to advertise inside the block enters the kernel only once a pass of the
// antispoof filter has written the none set without it. With no fault the
// route lands and a stranger's datagram meets the chain entry. After one failed
// read, after one failed fill, over a pass held past the reconciler's settle,
// and over a held pass while a pass of the reconciler reads the source the
// moment the LAN comes, as with no settle, the datagram sent once the
// reconciler reports the hold at the LAN's key and before the pass that writes
// the set meets that hold and stays out of the tun, the filter reading ready
// in the two held phases, and the one sent once the route landed meets
// the chain entry. While the filter fails, a LAN outside every class lands beside
// one inside the class that stays out, and the removal of a LAN lands too.
func TestTUNEntryRoutesALearnedLANOnlyOnceItsNoneSetIsWritten(t *testing.T) {
	lab := startOrderLab(t, orderBlockClasses())
	want := lab.installed()
	hold := func(b *orderBackend) { b.holdRules.Store(int64(orderHold)) }
	for _, phase := range []struct {
		name string
		lan  netip.Prefix
		arm  func(*orderBackend)
		// held is a phase whose filter reads ready, read one whose reconciler reads the source at the learn
		held, read bool
	}{
		{name: "no fault", lan: netip.MustParsePrefix("198.51.100.0/28")},
		{name: "one failed read", lan: netip.MustParsePrefix("198.51.100.16/28"), arm: func(b *orderBackend) { b.failRules.Store(1) }},
		{name: "one failed fill", lan: netip.MustParsePrefix("198.51.100.32/28"), arm: func(b *orderBackend) { b.failFill.Store(1) }},
		{name: "a pass held past the settle", lan: netip.MustParsePrefix("198.51.100.48/28"), arm: hold, held: true},
		{name: "a pass held, the reconciler reading at the learn", lan: netip.MustParsePrefix("198.51.100.96/28"), arm: hold, held: true, read: true},
	} {
		host := phase.lan.Addr().Next()
		start := time.Now()
		if phase.arm != nil {
			if phase.read {
				lab.learnRead(phase.lan, phase.arm)
				// the wait for the reconciler's pass is no part of the phase
				start = time.Now()
			} else {
				phase.arm(lab.be)
				lab.routes.Set(netip.Prefix{}, phase.lan, lab.peer)
			}
			lab.awaitHold(phase.name, phase.lan)
			ready := lab.filter.Stats().Ready
			held := lab.installed()
			entered, dropped := lab.send(host)
			t.Logf("%s: at %v the reconciler held %d routes (%d before the learn) and a hold at the LAN, the filter ready %v, the stranger's datagram to %s entered the tun %v, the chain entry dropped %d",
				phase.name, time.Since(start), held, want, ready, host, entered, dropped)
			if entered || dropped != 0 || held != want {
				t.Errorf("%s: before the pass writing the none set, want no entry, no drop and no new route", phase.name)
			}
			if phase.held && !ready {
				t.Errorf("%s: the filter read not ready, want the held pass to keep it ready", phase.name)
			}
		} else {
			lab.routes.Set(netip.Prefix{}, phase.lan, lab.peer)
		}
		want++
		lab.awaitInstalled(phase.name, want)
		entered, dropped := lab.send(host)
		t.Logf("%s: the route landed by %v, then the datagram entered the tun %v, the chain entry dropped %d", phase.name, time.Since(start), entered, dropped)
		if entered || dropped != 1 {
			t.Errorf("%s: once the route landed, want no entry and one drop", phase.name)
		}
	}

	// a LAN inside the class beside it, so the pass the two wake reads and fails
	inside := netip.MustParsePrefix("198.51.100.64/28")
	lab.be.failRules.Store(orderFailing)
	start := time.Now()
	lab.routes.Set(netip.Prefix{}, inside, lab.peer)
	lab.routes.Set(netip.Prefix{}, orderOutside, lab.peer)
	lab.awaitInstalled("the LAN outside every class", want+1)
	lab.awaitHold("the LAN inside the class", inside)
	ready := lab.filter.Stats().Ready
	outEntered, outDropped := lab.send(orderOutside.Addr().Next())
	inEntered, inDropped := lab.send(inside.Addr().Next())
	t.Logf("while the filter fails (ready %v): at %v the datagram to the LAN outside every class entered the tun %v, the chain entry dropped %d, and the one to the LAN inside the class entered %v, dropped %d",
		ready, time.Since(start), outEntered, outDropped, inEntered, inDropped)
	if ready || outEntered || outDropped != 1 || inEntered || inDropped != 0 {
		t.Error("with the filter failing, want it not ready, one drop outside every class and nothing inside the class")
	}

	first := netip.MustParsePrefix("198.51.100.0/28")
	start = time.Now()
	lab.routes.Remove(netip.Prefix{}, first)
	lab.awaitInstalled("the removed LAN's route", want)
	ready = lab.filter.Stats().Ready
	entered, dropped := lab.send(first.Addr().Next())
	t.Logf("a removed LAN while the filter fails (ready %v): at %v the datagram entered the tun %v, the chain entry dropped %d", ready, time.Since(start), entered, dropped)
	if ready || entered || dropped != 0 {
		t.Error("a LAN removed while the filter fails: want the filter not ready, no entry and no drop")
	}
	lab.be.failRules.Store(0)
}

// At an exit with no none class, the route to a LAN another node comes to
// advertise lands while the antispoof filter fails: a stranger's datagram sent
// once it landed meets the chain entry
func TestTUNEntryRoutesEveryLANOfAnExitWithNoNoneClass(t *testing.T) {
	lab := startOrderLab(t, nil)
	lab.be.failRules.Store(orderFailing)
	// a reload wakes a pass that reads, where a change of the table alone moves no set here
	if err := lab.filter.SetConfig(lab.filter.Capability()); err != nil {
		t.Fatal(err)
	}
	lan := netip.MustParsePrefix("198.51.100.16/28")
	before := lab.installed()
	start := time.Now()
	lab.routes.Set(netip.Prefix{}, lan, lab.peer)
	lab.awaitInstalled("the LAN's route", before+1)
	ready := lab.filter.Stats().Ready
	entered, dropped := lab.send(lan.Addr().Next())
	t.Logf("no none class, the filter failing (ready %v): at %v the datagram to %s entered the tun %v, the chain entry dropped %d", ready, time.Since(start), lan, entered, dropped)
	if ready || entered || dropped != 1 {
		t.Error("with no none class and the filter failing, want the filter not ready, no entry and one drop")
	}
}

// At an exit whose none class covers a block, a LAN whose entry leaves the
// mesh's table with no hold and comes back, from another node, while the
// reconciler still has its route in the kernel, is not reached by a
// stranger's datagram: the none set leaves the LAN's addresses out while the
// reconciler says its route is there, so the chain entry drops the datagram. It
// holds with the filter's passes failing from the removal's pass on, with the
// LAN back before the reconciler's pass after the settle, and with the
// reconciler's writes waiting, so the route stays in the kernel as long as
// they wait and the reconciler reports it there. The waiting writes stand in
// for a delete the kernel refuses, which no phase here has: the reconciler
// reports such a route there as it reports a route it kept. Each fails where
// the route was not in the kernel as the datagram went. Once the writes go on
// the route goes, and the next pass puts the addresses back.
func TestTUNEntryKeepsALANThatComesBackOutWhileItsRouteIsThere(t *testing.T) {
	for _, waiting := range []bool{false, true} {
		t.Run(map[bool]string{false: "the reconciler's pass after the settle", true: "the reconciler's writes waiting"}[waiting], func(t *testing.T) {
			lab := startOrderLab(t, orderBlockClasses())
			before := lab.installed()
			lan := netip.MustParsePrefix("198.51.100.16/28")
			host := lan.Addr().Next()
			lab.routes.Set(netip.Prefix{}, lan, lab.peer)
			lab.awaitInstalled("the LAN's route", before+1)
			lab.source.held.Store(waiting)
			start := time.Now()
			lab.routes.Remove(netip.Prefix{}, lan)
			if !lab.passNow("a pass after the removal") {
				t.Fatal("the pass after the removal left the filter not ready")
			}
			lab.be.failRules.Store(orderFailing)
			lab.routes.Set(netip.Prefix{}, lan, &netstack.Peer{ID: "example/other"})
			there, entered, dropped := lab.sendRouted(host, before+1)
			if !there {
				t.Fatal("setup: the LAN's route left the kernel before the datagram went")
			}
			t.Logf("the LAN back from another node %v after its removal, its route in the kernel: the stranger's datagram to %s entered the tun %v, the chain entry dropped %d", time.Since(start), host, entered, dropped)
			if entered || dropped != 1 {
				t.Error("the LAN back: want no entry and one drop")
			}
			if waiting {
				time.Sleep(orderStand)
				entered, dropped = lab.send(host)
				t.Logf("with the reconciler's writes waiting %v on, the reconciler holding %d routes: the datagram entered the tun %v, the chain entry dropped %d", time.Since(start), lab.installed(), entered, dropped)
				if entered || dropped != 1 {
					t.Error("the LAN back while the route's delete waits: want no entry and one drop")
				}
			}
			lab.be.failRules.Store(0)
			lab.source.held.Store(false)
			lab.routes.Remove(netip.Prefix{}, lan)
			lab.awaitInstalled("the route's removal", before)
			for deadline := time.Now().Add(orderWait); !lab.noneAdmits(host); time.Sleep(orderPoll) {
				if time.Now().After(deadline) {
					t.Fatalf("once the route went no pass put %s back into the none set", host)
				}
			}
		})
	}
}

// noneAdmits reports whether the none set the filter's last pass asked for holds address
func (l *orderLab) noneAdmits(address netip.Addr) bool {
	return slices.ContainsFunc(l.filter.Stats().Sets, func(reading egress.BorderSetReading) bool {
		return strings.HasPrefix(reading.Name, noneSet) && holdsAddress(reading.Elements, address)
	})
}

// A wider learned route that stays in the kernel after its entry left the
// mesh's table, the reconciler's writes waiting as in the test above, keeps a
// narrower LAN inside it out of a stranger's reach when the narrower one comes
// to be advertised with the filter failing: the none set leaves the wider
// route's addresses out while the reconciler says it is there, so the chain entry
// drops the datagram. It fails where the wider route was not in the kernel as
// the datagram went.
func TestTUNEntryKeepsALANInsideAWiderRouteThatIsStillThereOut(t *testing.T) {
	lab := startOrderLab(t, orderBlockClasses())
	before := lab.installed()
	wide, narrow := netip.MustParsePrefix("198.51.100.0/26"), netip.MustParsePrefix("198.51.100.16/28")
	host := narrow.Addr().Next()
	lab.routes.Set(netip.Prefix{}, wide, lab.peer)
	lab.awaitInstalled("the wider route", before+1)
	lab.source.held.Store(true)
	start := time.Now()
	lab.routes.Remove(netip.Prefix{}, wide)
	if !lab.passNow("a pass after the wider route's removal") {
		t.Fatal("the pass after the removal left the filter not ready")
	}
	lab.be.failRules.Store(orderFailing)
	lab.routes.Set(netip.Prefix{}, narrow, lab.peer)
	there, entered, dropped := lab.sendRouted(host, before+1)
	if !there {
		t.Fatal("setup: with the reconciler's writes waiting the wider route left the kernel before the datagram went")
	}
	t.Logf("the narrower LAN learned %v after the wider one's removal, the wider route in the kernel: the stranger's datagram to %s entered the tun %v, the chain entry dropped %d", time.Since(start), host, entered, dropped)
	if entered || dropped != 1 {
		t.Error("a narrower LAN learned: want no entry and one drop")
	}
	lab.be.failRules.Store(0)
	lab.source.held.Store(false)
}

// sendRouted sends as send does, and reports whether the reconciler held the
// count of routes with both before the datagram went and after
func (l *orderLab) sendRouted(host netip.Addr, with int) (there, entered bool, dropped uint64) {
	l.t.Helper()
	before := l.installed() == with
	entered, dropped = l.send(host)
	return before && l.installed() == with, entered, dropped
}

// In cap.exit's mode with a forwarded link and the mesh's default installed,
// a LAN inside the none class learned while the antispoof filter fails gets a
// hold at its key, so a datagram from a host on the forwarded link toward the
// LAN, sent once the reconciler reports the hold, takes no route into the tun
// by the mesh's default. Once the filter writes, the LAN's route lands and the
// datagram meets the chain entry.
func TestTUNEntryKeepsAForwardedDatagramOutOfAHeldLAN(t *testing.T) {
	lab := startOrderLabIn(t, orderBlockClasses(), true)
	before := lab.installed()
	lab.routes.Set(netip.Prefix{}, netip.MustParsePrefix("0.0.0.0/0"), lab.peer)
	lab.awaitInstalled("the mesh's default", before+1)
	// a host past the uplink's link, which only the mesh's default reaches from the forwarded link
	entered, dropped := lab.sendFrom(lab.forward, orderForwarded, netip.MustParseAddr("192.0.2.200"))
	if entered || dropped != 1 {
		t.Fatalf("setup: a forwarded datagram toward no class entered the tun %v and the chain entry dropped %d, want it to meet the chain entry by the mesh's default", entered, dropped)
	}
	lan := netip.MustParsePrefix("198.51.100.16/28")
	host := lan.Addr().Next()
	if !lab.passNow("a pass before the learn") {
		t.Fatal("setup: the pass before the learn left the filter not ready")
	}
	lab.be.failRules.Store(orderFailing)
	start := time.Now()
	lab.routes.Set(netip.Prefix{}, lan, lab.peer)
	// with no hold by orderWait the datagram goes all the same, to show where it lands
	holding := lab.holdWithin(lan)
	entered, dropped = lab.sendFrom(lab.forward, orderForwarded, host)
	t.Logf("%v after the learn, the reconciler reporting a hold at %s %v: the forwarded datagram to %s entered the tun %v, the chain entry dropped %d", time.Since(start), lan, holding, host, entered, dropped)
	if !holding || entered {
		t.Error("with the filter failing, want a hold at the LAN and the forwarded datagram out of the tun")
	}
	lab.be.failRules.Store(0)
	lab.awaitInstalled("the LAN's route once the filter writes", before+2)
	entered, dropped = lab.sendFrom(lab.forward, orderForwarded, host)
	if entered || dropped != 1 {
		t.Errorf("once the LAN's route landed the forwarded datagram entered the tun %v and the chain entry dropped %d, want one drop", entered, dropped)
	}
}

// A reload that takes a LAN's addresses out of the overlay, whose pass fails,
// has the reconciler put a hold in place of the LAN's route, so a stranger's
// datagram to the LAN meets the hold and takes no route into the tun
func TestTUNEntryTakesARouteOutAtAReloadThatMakesItALAN(t *testing.T) {
	lab := startOrderLab(t, []egress.Class{{From: schema.MustPrefix("203.0.113.0/25"), To: egress.Translation{None: true}}})
	before := lab.installed()
	lan := netip.MustParsePrefix("203.0.113.64/28")
	host := lan.Addr().Next()
	lab.routes.Set(netip.Prefix{}, lan, lab.peer)
	lab.awaitInstalled("the route inside the overlay", before+1)
	lab.be.failRules.Store(orderFailing)
	start := time.Now()
	if err := lab.filter.SetConfig(egress.Border{Overlay: []schema.Prefix{schema.MustPrefix("203.0.113.0/26")}}); err != nil {
		t.Fatal(err)
	}
	lab.awaitInstalled("the route after the reload", before)
	ready, holding := lab.filter.Stats().Ready, lab.holds(lan)
	entered, dropped := lab.send(host)
	t.Logf("the route went %v after the reload, the filter ready %v, a hold at the LAN %v: the stranger's datagram to %s entered the tun %v, the chain entry dropped %d", time.Since(start), ready, holding, host, entered, dropped)
	if ready || !holding || entered {
		t.Error("after a reload that made the route a LAN and whose pass fails: want the filter not ready, a hold at the LAN and no entry")
	}
}
