// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package userspace

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/wireguard/tun"
)

const (
	// exitWait bounds every wait for the exit's goroutines
	exitWait = 5 * time.Second
	// fakeReads is the reads of a fake lane's batch, a tun's batch on linux
	fakeReads = 64
)

// fakeMesh is the lanes a test hands the exit, recording what each lane laid
// and answered
type fakeMesh struct {
	reads int
	done  chan struct{}
	// answerGate, where set, holds every Answer until it closes, and fillGate
	// holds every Fill once it has laid its packets until the mesh closes
	answerGate chan struct{}
	fillGate   bool
	// laidTo, where set, takes each packet a lane laid as it is laid
	laidTo func(raw []byte)
	// session, where set, names the session each address sits behind, and
	// every address sits behind one otherwise
	session func(netip.Addr) int
	// mtu, where set, is the MTU each lane reports, and a session's otherwise
	mtu int
	// unrecorded, where set, keeps no packet a lane laid and lays each batch
	// into the lane's one slab, so a measurement's memory and time are the
	// exit's and not the record's
	unrecorded bool

	mu      sync.Mutex
	lanes   []*fakeLane
	laid    [][]byte
	answers []fakeAnswer
}

type fakeAnswer struct {
	offending []byte
	kind      netstack.ExitAnswer
	mtu       int
}

func newFakeMesh() *fakeMesh { return &fakeMesh{reads: fakeReads, done: make(chan struct{})} }

func (m *fakeMesh) OpenLane() Lane {
	l := &fakeLane{m: m}
	m.mu.Lock()
	m.lanes = append(m.lanes, l)
	m.mu.Unlock()
	return l
}

// closeMesh closes the mesh as Mesh.Close does for its lanes
func (m *fakeMesh) closeMesh() { close(m.done) }

func (m *fakeMesh) laidPackets() [][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([][]byte(nil), m.laid...)
}

func (m *fakeMesh) answered() []fakeAnswer {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]fakeAnswer(nil), m.answers...)
}

// openLanes counts the lanes opened and not given back
func (m *fakeMesh) openLanes() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	open := 0
	for _, l := range m.lanes {
		if !l.closed {
			open++
		}
	}
	return open
}

type fakeLane struct {
	m      *fakeMesh
	closed bool
	// slab and reads are the batch an unrecorded mesh's lane lays into
	slab  []byte
	reads []tun.ReadPacket
}

func (l *fakeLane) Fill(fill func(slab []byte, reads []tun.ReadPacket) int) bool {
	select {
	case <-l.m.done:
		return false
	default:
	}
	slab, reads := l.slab, l.reads
	if !l.m.unrecorded || slab == nil {
		slab, reads = make([]byte, 2*65535), make([]tun.ReadPacket, l.m.reads)
	}
	if l.m.unrecorded {
		l.slab, l.reads = slab, reads
	}
	n := fill(slab, reads)
	if !l.m.unrecorded {
		l.m.mu.Lock()
		for _, r := range reads[:n] {
			l.m.laid = append(l.m.laid, bytes.Clone(slab[r.Offset:r.Offset+r.Size]))
		}
		l.m.mu.Unlock()
	}
	if l.m.laidTo != nil {
		for _, r := range reads[:n] {
			l.m.laidTo(slab[r.Offset : r.Offset+r.Size])
		}
	}
	if l.m.fillGate {
		<-l.m.done
		return false
	}
	return true
}

func (l *fakeLane) Answer(offending []byte, kind netstack.ExitAnswer, mtu int) bool {
	if l.m.answerGate != nil {
		<-l.m.answerGate
	}
	l.m.mu.Lock()
	defer l.m.mu.Unlock()
	l.m.answers = append(l.m.answers, fakeAnswer{bytes.Clone(offending), kind, mtu})
	return true
}

func (l *fakeLane) MTU(netip.Addr, netip.Addr) int {
	if l.m.mtu != 0 {
		return l.m.mtu
	}
	return 1420
}

func (l *fakeLane) SameSession(_, a, b netip.Addr) bool {
	return l.m.session == nil || l.m.session(a) == l.m.session(b)
}

func (l *fakeLane) Done() <-chan struct{} { return l.m.done }

func (l *fakeLane) Close() {
	l.m.mu.Lock()
	defer l.m.mu.Unlock()
	l.closed = true
}

// fakePlatform is a platform whose link uplink0 reaches every address of the
// families it routes and each address in reaches, holding the addresses in
// held, and whose other link holds those in beside, which a socket scoped to
// uplink0 sends from none of. Its Prepare refuses every socket, so no dial
// leaves the host unless a test readies its own.
type fakePlatform struct {
	routes4, routes6      bool
	reaches, held, beside []netip.Addr
}

func (p *fakePlatform) platform() Platform {
	return Platform{
		Prepare: func(string, netip.AddrPort, syscall.RawConn) error { return syscall.ENETUNREACH },
		Route: func(address netip.Addr) (Link, bool, error) {
			if address.Is4() && p.routes4 || address.Is6() && p.routes6 || slices.Contains(p.reaches, address) {
				return Link{Name: "uplink0", MTU: 1500}, true, nil
			}
			return Link{}, false, nil
		},
		Held: func(address netip.Addr, link string) bool {
			return (link == "" || link == "uplink0") && slices.Contains(p.held, address) || link == "" && slices.Contains(p.beside, address)
		},
	}
}

// testLimits are limits small enough for a test and above every floor
func testLimits() Limits {
	return Limits{Budget: 64 << 20, From: FromGoLimit, Flows: 64, Connections: 16, Dials: 8, TimeWait: 16, Window: stackWindow, Lanes: 1 << 20, Link: 1 << 20}
}

// exitConfig is an exit node's capability over both families
func exitConfig() egress.Egress {
	return egress.Egress{Advertise: []schema.Prefix{schema.MustPrefix("0.0.0.0/0"), schema.MustPrefix("::/0")}}
}

// readyCall is one call of the Ready hook
type readyCall struct{ v4, v6, serves bool }

// exitHarness is an exit over a fake mesh and platform, with the hooks'
// calls recorded
type exitHarness struct {
	exit *Exit
	mesh *fakeMesh

	mu         sync.Mutex
	ready      []readyCall
	republish  int
	cancel     context.CancelFunc
	runErr     chan error
	runStarted bool
}

func newExitHarness(t *testing.T, mesh *fakeMesh, p *fakePlatform) *exitHarness {
	t.Helper()
	h := &exitHarness{mesh: mesh, runErr: make(chan error, 1)}
	rt := Runtime{Mesh: mesh, Platform: p.platform(), Limits: testLimits(), MeshAddresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}
	rt.Ready = func(v4, v6, serves bool) {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.ready = append(h.ready, readyCall{v4, v6, serves})
	}
	rt.Republish = func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.republish++
	}
	x, err := New(exitConfig(), rt)
	if err != nil {
		t.Fatal(err)
	}
	h.exit = x
	t.Cleanup(func() {
		if h.runStarted {
			h.stopRun(t)
			return
		}
		if err := x.Close(); err != nil {
			t.Errorf("close: %s", err)
		}
	})
	return h
}

// run starts Run and waits for its first pass to name a family ready
func (h *exitHarness) run(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel, h.runStarted = cancel, true
	go func() { h.runErr <- h.exit.Run(ctx) }()
	h.waitFor(t, "a family ready", func() bool { return len(h.readyCalls()) != 0 })
}

// stopRun ends Run and waits for it to return
func (h *exitHarness) stopRun(t *testing.T) {
	t.Helper()
	if !h.runStarted {
		return
	}
	h.runStarted = false
	h.cancel()
	select {
	case err := <-h.runErr:
		if err != nil {
			t.Errorf("run: %s", err)
		}
	case <-time.After(exitWait):
		t.Fatalf("run did not return within %s of its context ending", exitWait)
	}
}

func (h *exitHarness) readyCalls() []readyCall {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]readyCall(nil), h.ready...)
}

func (h *exitHarness) waitFor(t *testing.T, what string, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(exitWait)
	for !done() {
		if time.Now().After(deadline) {
			t.Fatalf("no %s within %s", what, exitWait)
		}
		time.Sleep(time.Millisecond)
	}
}

// frames is each packet as a session hands it to Egress, TUNHeadroom bytes
// ahead of it
func frames(packets ...[]byte) [][]byte {
	out := make([][]byte, 0, len(packets))
	for _, raw := range packets {
		out = append(out, append(make([]byte, netstack.TUNHeadroom), raw...))
	}
	return out
}

// New refuses what the userspace exit cannot carry, before it builds
// anything, each in words naming what this build's exit lacks
func TestNewRefusesWhatTheExitCannotCarry(t *testing.T) {
	p := &fakePlatform{routes4: true, routes6: true}
	rt := Runtime{Mesh: newFakeMesh(), Platform: p.platform(), Limits: testLimits()}
	none := exitConfig()
	none.Translate = []egress.Class{{From: schema.MustPrefix("192.0.2.0/25"), To: egress.Translation{None: true}}}
	withReturn := exitConfig()
	withReturn.Return = true
	subnet := exitConfig()
	subnet.Advertise = append(subnet.Advertise, schema.MustPrefix("198.51.100.0/24"))
	noPrepare := rt
	noPrepare.Platform.Prepare = nil
	noMesh := rt
	noMesh.Mesh = nil
	noRoute := rt
	noRoute.Platform.Route = nil
	noHeld := rt
	noHeld.Platform.Held = nil
	noFlows := rt
	noFlows.Limits.Flows = 0
	smallWindow := rt
	smallWindow.Limits.Window = 1024
	for _, c := range []struct {
		name string
		cfg  egress.Egress
		rt   Runtime
		want string
	}{
		{"a class of none", none, rt, "translates 192.0.2.0/25 with none, and the exit this build carries opens its own sockets"},
		{"return", withReturn, rt, "return is set, and the exit this build carries ends each connection a leaf opens"},
		{"a subnet", subnet, rt, "advertises 198.51.100.0/24, a subnet, and this build's exit carries only defaults"},
		{"no prepare", exitConfig(), noPrepare, "given no Prepare"},
		{"no mesh", exitConfig(), noMesh, "given no mesh"},
		{"no route lookup", exitConfig(), noRoute, "no route or held address lookup"},
		{"no held lookup", exitConfig(), noHeld, "no route or held address lookup"},
		{"no flows", exitConfig(), noFlows, "limit of flows is 0"},
		{"a window below a tcp buffer", exitConfig(), smallWindow, "window of 1024 bytes"},
		{"nothing to serve", egress.Egress{}, rt, "advertise is empty and no segment here delivers to egress"},
	} {
		t.Run(c.name, func(t *testing.T) {
			x, err := New(c.cfg, c.rt)
			if err == nil {
				_ = x.Close()
				t.Fatal("taken")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("refused with %q, want it to say %q", err, c.want)
			}
		})
	}
	t.Run("a default and its halves", func(t *testing.T) {
		cfg := exitConfig()
		cfg.Advertise = append(cfg.Advertise, schema.MustPrefix("0.0.0.0/1"), schema.MustPrefix("128.0.0.0/1"))
		x, err := New(cfg, rt)
		if err != nil {
			t.Fatal(err)
		}
		if err := x.Close(); err != nil {
			t.Error(err)
		}
	})
}

// A segment no endpoint holds draws the stack's reset, which the pump lays
// into a lane as a tun read lays a packet, and Run's end reports both families
// not ready, publishes nothing and gives every lane back
func TestSegmentNoEndpointHoldsComesBackAsResetThroughALane(t *testing.T) {
	mesh := newFakeMesh()
	h := newExitHarness(t, mesh, &fakePlatform{routes4: true, routes6: true})
	h.run(t)
	if got := h.readyCalls(); got[len(got)-1] != (readyCall{true, true, true}) {
		t.Fatalf("ready calls %v, want both families ready and serving last", got)
	}
	if got := h.exit.Announce(); len(got) != 2 {
		t.Errorf("announced %v, want both defaults", got)
	}
	for _, family := range []struct{ leaf, server netip.Addr }{{leaf4, server4}, {leaf6, server6}} {
		leaf, server := netip.AddrPortFrom(family.leaf, 40000), netip.AddrPortFrom(family.server, 80)
		h.exit.Egress(frames(tcpSegment(leaf, server, 1000, 1, tcpACK, nil)), nil)
		h.waitFor(t, "reset toward "+leaf.String(), func() bool {
			for _, raw := range mesh.laidPackets() {
				if p, ok := parse(raw); ok && p.protocol == protoTCP && p.flags&tcpRST != 0 && netip.AddrPortFrom(p.dst, p.dstPort) == leaf && netip.AddrPortFrom(p.src, p.srcPort) == server {
					return true
				}
			}
			return false
		})
	}
	h.stopRun(t)
	if got := h.readyCalls(); got[len(got)-1] != (readyCall{}) {
		t.Errorf("ready calls %v, want none ready last", got)
	}
	if got := h.exit.Announce(); len(got) != 0 {
		t.Errorf("announced %v after Run's end", got)
	}
	if open := mesh.openLanes(); open != 0 {
		t.Errorf("%d lanes not given back after Run's end", open)
	}
}

// What a lane's judgment refuses is answered through the lane, from this node
// and of the judgment's kind, and reaches no stack
func TestLaneAnswersWhatItsJudgmentRefuses(t *testing.T) {
	mesh := newFakeMesh()
	h := newExitHarness(t, mesh, &fakePlatform{routes4: true, routes6: true})
	h.run(t)
	refused := [][]byte{
		ip4(leaf4, server4, protoUDP, 1, 0, 1, make([]byte, 8)),
		ipPacket(leaf6, server6, protoUncarried, make([]byte, 8)),
		tcpSegment(netip.AddrPortFrom(leaf4, 40000), netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), 22), 1000, 0, tcpSYN, nil),
	}
	h.exit.Egress(frames(refused...), nil)
	h.waitFor(t, "an answer to each", func() bool { return len(mesh.answered()) == len(refused) })
	kinds := map[netstack.ExitAnswer]int{}
	for _, a := range mesh.answered() {
		kinds[a.kind]++
	}
	if kinds[netstack.ExitExpired] != 1 || kinds[netstack.ExitProhibited] != 2 {
		t.Errorf("answered %v, want one expired and two prohibited", kinds)
	}
	time.Sleep(stackSettle)
	if laid := mesh.laidPackets(); len(laid) != 0 {
		t.Errorf("a refused packet reached the stack, which sent %d packets", len(laid))
	}
}

// A family is ready while a link outside the mesh routes its prefixes and the
// host holds its classes' addresses where a socket scoped to that link sends
// from them, and the egress SIDs are served while every family so routed is
// ready
func TestReadinessFollowsTheRoutesAndTheHeldAddresses(t *testing.T) {
	class := netip.MustParseAddr("198.51.100.9")
	for _, c := range []struct {
		name     string
		platform fakePlatform
		want     readyCall
		why      string
	}{
		{"both routed", fakePlatform{routes4: true, routes6: true, held: []netip.Addr{class}}, readyCall{true, true, true}, ""},
		{"ipv6 not routed", fakePlatform{routes4: true, held: []netip.Addr{class}}, readyCall{true, false, true}, "no link outside the mesh reaches 8000:: for ::/0"},
		{"the class address not held", fakePlatform{routes4: true, routes6: true}, readyCall{false, true, false},
			"this host does not hold 198.51.100.9, an address cap.egress translate names"},
		{"the class address held on another link", fakePlatform{routes4: true, routes6: true, beside: []netip.Addr{class}}, readyCall{false, true, false},
			"this host does not hold 198.51.100.9, an address cap.egress translate names, on uplink0, the link this host reaches 0.0.0.0/0 by"},
	} {
		t.Run(c.name, func(t *testing.T) {
			mesh := newFakeMesh()
			rt := Runtime{Mesh: mesh, Platform: c.platform.platform(), Limits: testLimits()}
			var calls []readyCall
			var mu sync.Mutex
			rt.Ready = func(v4, v6, serves bool) {
				mu.Lock()
				defer mu.Unlock()
				calls = append(calls, readyCall{v4, v6, serves})
			}
			cfg := exitConfig()
			cfg.Translate = []egress.Class{{From: schema.MustPrefix("0.0.0.0/0"), To: egress.Translation{Addr: class}}}
			x, err := New(cfg, rt)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- x.Run(ctx) }()
			deadline := time.Now().Add(exitWait)
			for x.Status().PassAt.IsZero() && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			status := x.Status()
			cancel()
			if err := <-done; err != nil {
				t.Error(err)
			}
			if got := (readyCall{status.Ready4, status.Ready6, false}); got.v4 != c.want.v4 || got.v6 != c.want.v6 {
				t.Errorf("ready %v, want %v", got, c.want)
			}
			if status.Unready != c.why {
				t.Errorf("unready %q, want %q", status.Unready, c.why)
			}
			mu.Lock()
			defer mu.Unlock()
			if c.want != (readyCall{}) && (len(calls) == 0 || calls[0] != c.want) {
				t.Errorf("ready calls %v, want %v first", calls, c.want)
			}
		})
	}
}

// A family is carried out by a route outside the mesh where any prefix it
// reads is so routed, judged over every prefix whichever fails first, so a
// family routed in part withdraws the egress SIDs while it is not ready in
// either order of its prefixes. Why it is not ready names the first prefix
// that fails, and a pass looks each prefix up once at most
func TestReadinessJudgesEveryPrefixForItsRouteWhicheverFailsFirst(t *testing.T) {
	low, high := schema.MustPrefix("0.0.0.0/1"), schema.MustPrefix("128.0.0.0/1")
	// the addresses readAddress reads for low and high
	lowRead, highRead := netip.MustParseAddr("64.0.0.0"), netip.MustParseAddr("192.0.0.0")
	lowUnrouted := "no link outside the mesh reaches 64.0.0.0 for 0.0.0.0/1"
	highUnrouted := "no link outside the mesh reaches 192.0.0.0 for 128.0.0.0/1"
	for _, c := range []struct {
		name    string
		order   []schema.Prefix
		reaches []netip.Addr
		carried bool
		why     string
	}{
		{"the unrouted prefix first", []schema.Prefix{low, high}, []netip.Addr{highRead}, true, lowUnrouted},
		{"the routed prefix first", []schema.Prefix{high, low}, []netip.Addr{highRead}, true, lowUnrouted},
		{"the other prefix routed", []schema.Prefix{high, low}, []netip.Addr{lowRead}, true, highUnrouted},
		{"neither routed", []schema.Prefix{low, high}, nil, false, lowUnrouted},
		{"neither routed, the other order", []schema.Prefix{high, low}, nil, false, highUnrouted},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := fakePlatform{routes6: true, reaches: c.reaches}
			platform := p.platform()
			var lookups atomic.Int64
			route := platform.Route
			platform.Route = func(address netip.Addr) (Link, bool, error) {
				if address.Is4() {
					lookups.Add(1)
				}
				return route(address)
			}
			rt := Runtime{Mesh: newFakeMesh(), Platform: platform, Limits: testLimits()}
			var calls []readyCall
			var mu sync.Mutex
			rt.Ready = func(v4, v6, serves bool) {
				mu.Lock()
				defer mu.Unlock()
				calls = append(calls, readyCall{v4, v6, serves})
			}
			cfg := egress.Egress{Advertise: append(slices.Clone(c.order), schema.MustPrefix("::/0"))}
			x, err := New(cfg, rt)
			if err != nil {
				t.Fatal(err)
			}
			ready, routed, why := x.readiness(egress.FamilyIPv4)
			if ready || routed != c.carried || why != c.why {
				t.Errorf("readiness ready %t, routed %t, why %q, want not ready, routed %t, why %q", ready, routed, why, c.carried, c.why)
			}
			if n := lookups.Load(); n > int64(len(c.order)) {
				t.Errorf("%d route lookups for %d prefixes, want one each at most", n, len(c.order))
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- x.Run(ctx) }()
			deadline := time.Now().Add(exitWait)
			for x.Status().PassAt.IsZero() && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			status := x.Status()
			cancel()
			if err := <-done; err != nil {
				t.Error(err)
			}
			if status.PassAt.IsZero() {
				t.Fatalf("no pass within %s", exitWait)
			}
			if status.Ready4 || !status.Ready6 || status.Unready != c.why {
				t.Errorf("status ready %t and %t, unready %q, want ipv6 alone ready and unready %q", status.Ready4, status.Ready6, status.Unready, c.why)
			}
			// the SIDs are served while every family carried out is ready
			want := readyCall{false, true, !c.carried}
			mu.Lock()
			defer mu.Unlock()
			if len(calls) == 0 || calls[0] != want {
				t.Errorf("ready calls %v, want %v first", calls, want)
			}
		})
	}
}

// Egress never waits on a lane: with a worker held inside an answer, a
// session's call returns at once, and what the lanes cannot hold, past their
// bytes or past a worker's queue, is dropped and counted
func TestEgressReturnsWhileALaneIsBlocked(t *testing.T) {
	for _, c := range []struct {
		name  string
		lanes int64
	}{{"past the lanes' bytes", testLimits().Lanes}, {"past a worker's queue", 1 << 40}} {
		t.Run(c.name, func(t *testing.T) { egressReturnsWhileALaneIsBlocked(t, c.lanes) })
	}
}

func egressReturnsWhileALaneIsBlocked(t *testing.T, lanes int64) {
	mesh := newFakeMesh()
	mesh.answerGate = make(chan struct{})
	h := newExitHarness(t, mesh, &fakePlatform{routes4: true, routes6: true})
	t.Cleanup(func() { close(mesh.answerGate) })
	h.exit.rt.Limits.Lanes = lanes
	h.run(t)
	expired := ip4(leaf4, server4, protoUDP, 1, 0, 1, make([]byte, 8))
	batch := make([][]byte, 0, 64)
	for range cap(batch) {
		batch = append(batch, frames(expired)[0])
	}
	sent := 0
	returned := make(chan struct{})
	go func() {
		defer close(returned)
		for range 2 * workerQueuePackets / len(batch) * len(h.exit.workers) {
			h.exit.Egress(batch, nil)
			sent += len(batch)
		}
	}()
	select {
	case <-returned:
	case <-time.After(exitWait):
		t.Fatalf("Egress waited on a blocked lane for %s", exitWait)
	}
	if dropped := h.exit.counts.laneDropped.Load(); dropped == 0 {
		t.Errorf("%d packets to a blocked lane, none dropped", sent)
	}
	if held := h.exit.laneHeld.Load(); held > h.exit.rt.Limits.Lanes {
		t.Errorf("the lanes hold %d bytes past their bound of %d", held, h.exit.rt.Limits.Lanes)
	}
}

// The mesh closing while the pump holds a batch and the workers wait ends
// every lane's goroutine and gives every lane back, and Run then ends as
// asked, with packets still queued
func TestMeshClosingUnderARunningExitEndsItsLanes(t *testing.T) {
	mesh := newFakeMesh()
	mesh.fillGate = true
	h := newExitHarness(t, mesh, &fakePlatform{routes4: true, routes6: true})
	h.run(t)
	h.exit.Egress(frames(tcpSegment(netip.AddrPortFrom(leaf4, 40000), netip.AddrPortFrom(server4, 80), 1000, 1, tcpACK, nil)), nil)
	h.waitFor(t, "the pump's batch", func() bool { return len(mesh.laidPackets()) != 0 })
	mesh.closeMesh()
	h.waitFor(t, "every lane given back", func() bool { return mesh.openLanes() == 0 })
	h.exit.Egress(frames(tcpSegment(netip.AddrPortFrom(leaf4, 40001), netip.AddrPortFrom(server4, 80), 1000, 1, tcpACK, nil)), nil)
	h.stopRun(t)
}

// SetEnabled(false) reports both families not ready, publishes nothing and
// takes nothing more from the sessions, and SetEnabled(true) restores it
func TestWithdrawnExitTakesNothing(t *testing.T) {
	mesh := newFakeMesh()
	h := newExitHarness(t, mesh, &fakePlatform{routes4: true, routes6: true})
	h.run(t)
	h.exit.SetEnabled(false)
	h.waitFor(t, "both families withdrawn", func() bool {
		calls := h.readyCalls()
		return calls[len(calls)-1] == readyCall{}
	})
	if got := h.exit.Announce(); len(got) != 0 {
		t.Errorf("announced %v while withdrawn", got)
	}
	segment := tcpSegment(netip.AddrPortFrom(leaf4, 40000), netip.AddrPortFrom(server4, 80), 1000, 1, tcpACK, nil)
	dropped := h.exit.counts.laneDropped.Load()
	h.exit.Egress(frames(segment), nil)
	time.Sleep(stackSettle)
	if laid := mesh.laidPackets(); len(laid) != 0 {
		t.Errorf("a withdrawn exit carried a segment, laying %d packets", len(laid))
	}
	if got := h.exit.counts.laneDropped.Load(); got != dropped+1 {
		t.Errorf("dropped %d of the one packet taken while withdrawn", got-dropped)
	}
	h.exit.SetEnabled(true)
	h.waitFor(t, "both families ready again", func() bool {
		calls := h.readyCalls()
		return calls[len(calls)-1] == readyCall{true, true, true}
	})
	h.exit.Egress(frames(segment), nil)
	h.waitFor(t, "the reset once enabled again", func() bool { return len(mesh.laidPackets()) != 0 })
}

// Close closes Raw of an exit whose Run never ran, once however often it is
// called, and hands back Raw's error from the first
func TestCloseClosesRawOnce(t *testing.T) {
	p := &fakePlatform{routes4: true, routes6: true}
	raw := &fakeRaw{closeErr: errRawClosed}
	rt := Runtime{Mesh: newFakeMesh(), Platform: p.platform(), Limits: testLimits()}
	rt.Platform.Raw = raw
	x, err := New(exitConfig(), rt)
	if err != nil {
		t.Fatal(err)
	}
	if err := x.Close(); !errors.Is(err, errRawClosed) {
		t.Errorf("close: %v, want Raw's error", err)
	}
	if err := x.Close(); err != nil || raw.closed != 1 {
		t.Errorf("second close %v with Raw closed %d times, want nothing more", err, raw.closed)
	}
}

var errRawClosed = errors.New("raw closed")

// fakeRaw records each packet sent through it, and closes with closeErr
type fakeRaw struct {
	closeErr error

	mu     sync.Mutex
	sent   [][]byte
	closed int
}

func (r *fakeRaw) Send(packet []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent = append(r.sent, bytes.Clone(packet))
	return nil
}

func (r *fakeRaw) sentSoFar() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([][]byte(nil), r.sent...)
}

func (r *fakeRaw) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed++
	return r.closeErr
}
