// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin

package transport

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/logtest"
)

// fakeLinks stands in for the host's own routing. Every test here drives the
// binding from it rather than from a real link change, because moving a
// machine between wifi and a dock is not something a test can do.
type fakeLinks struct {
	mu     sync.Mutex
	index  int
	err    error
	signal chan struct{}
}

func newFakeLinks(index int) *fakeLinks {
	return &fakeLinks{index: index, signal: make(chan struct{}, 1)}
}

func (f *fakeLinks) DefaultInterface() (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.index, f.err
}

func (f *fakeLinks) Changed() <-chan struct{} { return f.signal }

// move is the host's default route arriving on another interface.
func (f *fakeLinks) move(index int, err error) {
	f.mu.Lock()
	f.index, f.err = index, err
	f.mu.Unlock()
	select {
	case f.signal <- struct{}{}:
	default:
	}
}

// boundInterface reads back what the kernel holds, so the tests assert on the
// socket rather than on the bookkeeping beside it.
func boundInterface(t *testing.T, socket *darwinSocket) int {
	t.Helper()
	level, option := socket.boundInterfaceOption()
	var index int
	var readErr error
	if err := socket.raw.Control(func(fd uintptr) {
		index, readErr = unix.GetsockoptInt(int(fd), level, option)
	}); err != nil {
		t.Fatal(err)
	}
	if readErr != nil {
		t.Fatal(readErr)
	}
	return index
}

// twoInterfaces is the loopback and one other link this host really has, so a
// rebind moves between two indices the kernel will accept.
func twoInterfaces(t *testing.T) (first, second int) {
	t.Helper()
	devices, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, device := range devices {
		if device.Flags&net.FlagLoopback != 0 {
			first = device.Index
			continue
		}
		if second == 0 && device.Flags&net.FlagUp != 0 {
			second = device.Index
		}
	}
	if first == 0 || second == 0 {
		t.Skip("this host has no loopback and a second live interface to move between")
	}
	return first, second
}

// waitFor polls until the socket carries index, because the rebind happens on
// the hub's own goroutine and a link change carries no acknowledgment.
func waitFor(t *testing.T, bind *darwinBind, index int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if boundInterface(t, bind.v4) == index && boundInterface(t, bind.v6) == index {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("the socket did not reach interface %d: udp4 on %d, udp6 on %d",
		index, boundInterface(t, bind.v4), boundInterface(t, bind.v6))
}

// Both families have to be bound. A node with one socket on the host's own
// interface and the other following the forwarding table reaches half its
// peers, and the half it loses is whichever family an exit announced into.
func TestUnderlayBindingReachesBothFamilies(t *testing.T) {
	index, _ := twoInterfaces(t)
	hub, err := NewHub(":0", Underlay{Bind: true}, Runtime{Links: newFakeLinks(index)})
	if err != nil {
		t.Fatalf("open a bound hub: %v", err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	bind := hub.bind.(*darwinBind)
	if got := boundInterface(t, bind.v4); got != index {
		t.Errorf("the udp4 socket is bound to %d, want %d", got, index)
	}
	if got := boundInterface(t, bind.v6); got != index {
		t.Errorf("the udp6 socket is bound to %d, want %d", got, index)
	}
	if !hub.UnderlayReady() {
		t.Error("a bound hub reports its underlay is not where it should be")
	}
}

// A link change moves the option on the descriptor that is already open. The
// alternative, reopening, would drop every SA on the node to follow a change
// no peer ever saw, so the port has to survive the move.
func TestUnderlayRebindsWithoutReplacingTheSocket(t *testing.T) {
	first, second := twoInterfaces(t)
	links := newFakeLinks(first)
	hub, err := NewHub(":0", Underlay{Bind: true}, Runtime{Links: links})
	if err != nil {
		t.Fatalf("open a bound hub: %v", err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	bind := hub.bind.(*darwinBind)
	port := hub.LocalAddr().(*net.UDPAddr).Port
	v4, v6 := bind.v4.conn, bind.v6.conn

	links.move(second, nil)
	waitFor(t, bind, second)

	if got := hub.LocalAddr().(*net.UDPAddr).Port; got != port {
		t.Errorf("the hub moved from port %d to %d, so every SA on it went with it", port, got)
	}
	if bind.v4.conn != v4 || bind.v6.conn != v6 {
		t.Error("the sockets were replaced rather than rebound")
	}
}

// A laptop that boots with no network has no default route to bind to. That is
// an ordinary morning rather than a failure, so the hub opens, but what it must
// not do is report the underlay as being where the configuration says, because
// the reconciler reads that before it hands the machine's traffic to the mesh.
func TestUnderlayStaysUnboundUntilTheHostHasADefaultRoute(t *testing.T) {
	index, _ := twoInterfaces(t)
	links := newFakeLinks(0)
	links.move(0, errors.New("no default route"))
	hub, err := NewHub(":0", Underlay{Bind: true}, Runtime{Links: links})
	if err != nil {
		t.Fatalf("a hub on a host with no default route was refused: %v", err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	bind := hub.bind.(*darwinBind)
	if got := boundInterface(t, bind.v4); got != 0 {
		t.Errorf("the udp4 socket was bound to %d with no default route to read", got)
	}
	if hub.UnderlayReady() {
		t.Fatal("an unbound socket reported that the underlay is where it should be")
	}

	links.move(index, nil)
	waitFor(t, bind, index)
	// Polled rather than read once: the socket carries the option before the
	// hub records where it is, because the reachability probe runs between
	// the two, and that probe is two connect calls rather than nothing.
	if !waitReady(t, hub) {
		t.Error("the underlay bound and still reports that it is not where it should be")
	}
}

// waitReady polls until the hub says its underlay is where it should be.
func waitReady(t *testing.T, hub *Hub) bool {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if hub.UnderlayReady() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

// A default route that disappears leaves the binding where it is. Unbinding
// would hand the socket back to the forwarding table for the length of the
// gap, and that table may hold a default out of our own tun.
func TestUnderlayKeepsItsBindingWhenTheDefaultRouteGoes(t *testing.T) {
	index, _ := twoInterfaces(t)
	links := newFakeLinks(index)
	hub, err := NewHub(":0", Underlay{Bind: true}, Runtime{Links: links})
	if err != nil {
		t.Fatalf("open a bound hub: %v", err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	bind := hub.bind.(*darwinBind)

	links.move(0, errors.New("no default route"))
	// Nothing acknowledges a change that is meant to do nothing, so this is a
	// deliberate wait rather than a poll: the failure it is looking for is the
	// socket being unbound, which would happen promptly if it happened.
	time.Sleep(100 * time.Millisecond)
	if got := boundInterface(t, bind.v4); got != index {
		t.Errorf("the udp4 socket moved to %d when the host lost its default route", got)
	}
	if got := boundInterface(t, bind.v6); got != index {
		t.Errorf("the udp6 socket moved to %d when the host lost its default route", got)
	}
}

// The reachability probe runs on every binding, so it has to answer for both
// families without reaching for the wrong one: netip.Addr.As4 panics on an
// IPv6 address, and this runs on the goroutine that follows link changes.
func TestBoundReachProbeAnswersForBothFamilies(t *testing.T) {
	index, _ := twoInterfaces(t)
	for _, probe := range offLinkProbes {
		// Whether the host can reach them is the host's business. What is
		// asserted is that asking does not panic and does not come back with
		// something that is not a routing answer.
		err := reachesWhenBound(index, probe)
		t.Logf("interface %d to %s: %v", index, probe, err)
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			// A sandbox that forbids the syscall is not the host answering
			// about a route, so there is nothing here to assert against. The
			// nix darwin builder refuses a connect to anything off the loopback
			// even with __darwinAllowLocalNetworking.
			t.Skipf("this sandbox will not let a socket ask about %s: %v", probe, err)
		}
		if err != nil && !errors.Is(err, unix.ENETUNREACH) && !errors.Is(err, unix.EHOSTUNREACH) &&
			!errors.Is(err, unix.EADDRNOTAVAIL) && !errors.Is(err, unix.ENETDOWN) {
			t.Errorf("probing %s answered %v, which is not a routing answer", probe, err)
		}
	}
}

// lockedLog is a log sink two goroutines may use. The link follower reports
// from its own, and a test watching for that report reads while it writes, so
// the plain buffer the rest of this package captures into would be a race.
type lockedLog struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (l *lockedLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *lockedLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func (l *lockedLog) Reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buf.Reset()
}

func captureBoundReachLogs(t *testing.T) *lockedLog {
	t.Helper()
	logs := &lockedLog{}
	logtest.SetDefault(t, slog.New(slog.NewTextHandler(logs, nil)))
	return logs
}

// answering replaces the probe with one the test decides, per family, and puts
// the real one back afterward.
func answering(t *testing.T, reaches map[bool]error) {
	t.Helper()
	previous := boundReachProbe
	t.Cleanup(func() { boundReachProbe = previous })
	boundReachProbe = func(_ int, target netip.Addr) error { return reaches[target.Is4()] }
}

// An unreachable socket is reported rather than refused, so the report is the
// whole of what this mechanism does and every rule it holds is a rule about
// what it says.
//
// Warning per family would warn on every single-stack uplink, which is an
// ordinary host and not a fault, so the report is made only where neither
// family can get off the link. And the two messages differ, because an
// interface whose routing this node manages, which may or may not hold a
// default it wrote, is a different thing to go looking at than one whose
// routing nothing here writes. The routed detail claims no write, since
// routed says only that Runtime.Routes prepared the interface.
func TestBoundReachIsReportedOnlyWhenNeitherFamilyWorks(t *testing.T) {
	unreach := unix.ENETUNREACH
	for name, test := range map[string]struct {
		reaches map[bool]error
		index   int
		routed  bool
		want    string
		detail  string
	}{
		"neither family reaches, and nothing wrote that interface's routing": {
			reaches: map[bool]error{true: unreach, false: unreach},
			index:   7,
			want:    "cannot reach off",
			detail:  "nothing here writes that interface's routing, so give it a default scoped to it, route -n add -net 0.0.0.0/0 <next hop> -ifscope <interface>",
		},
		"neither family reaches on an interface this node prepared": {
			reaches: map[bool]error{true: unreach, false: unreach},
			index:   7, routed: true,
			want:   "still cannot reach off",
			detail: "this node writes a default scoped to that interface only for a family whose zero address an unscoped route out of another interface holds or is about to hold, so see which route a lookup scoped to it finds, route -n get [-inet6] -ifscope <interface> <probe>",
		},
		"only IPv6 reaches, which is an ordinary IPv6-only uplink": {
			reaches: map[bool]error{true: unreach},
			index:   7,
		},
		"only IPv4 reaches, which is an ordinary IPv4-only uplink": {
			reaches: map[bool]error{false: unreach},
			index:   7,
		},
		"both reach": {reaches: map[bool]error{}, index: 7},
		// Zero is the socket that was never bound, so the forwarding table is
		// answering for it as it does for every other socket on the machine.
		"an unbound socket": {
			reaches: map[bool]error{true: unreach, false: unreach},
			index:   0,
		},
	} {
		t.Run(name, func(t *testing.T) {
			answering(t, test.reaches)
			logs := captureBoundReachLogs(t)
			reportBoundReach(test.index, test.routed)
			got := logs.String()
			switch {
			case test.want == "" && got != "":
				t.Errorf("nothing was wrong and the report reads %s", got)
			case test.want == "":
			case !strings.Contains(got, test.want):
				t.Errorf("the report reads %s, want it to say %q", got, test.want)
			}
			if test.want == "" {
				return
			}
			if !strings.Contains(got, "detail="+strconv.Quote(test.detail)) {
				t.Errorf("the report reads %s, want its detail to be %q", got, test.detail)
			}
			// Both probes named, since an operator reading this has to know
			// which destinations were asked about.
			for _, probe := range offLinkProbes {
				if !strings.Contains(got, probe.String()) {
					t.Errorf("the report does not name the probe %s: %s", probe, got)
				}
			}
			// And the other message is not the one that was made.
			other := "still cannot reach off"
			if test.routed {
				other = `msg="transport bound the underlay socket to an interface it cannot reach off"`
			}
			if strings.Contains(got, other) {
				t.Errorf("the report says %q as well, so routed decides nothing: %s", other, got)
			}
		})
	}
}

// The report is made where the socket is bound, on both paths that bind one:
// the first binding at startup, which is the one a node starting next to the
// default a previous run installed depends on, and every rebind the link
// follower makes afterward.
func TestBindingReportsWhatTheSocketCanReach(t *testing.T) {
	first, second := twoInterfaces(t)
	answering(t, map[bool]error{true: unix.ENETUNREACH, false: unix.ENETUNREACH})

	logs := captureBoundReachLogs(t)
	links := newFakeLinks(first)
	hub, err := NewHub(":0", Underlay{Bind: true}, Runtime{Links: links})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	if got := logs.String(); !strings.Contains(got, "cannot reach off") {
		t.Errorf("the first binding said nothing about a socket that reaches nothing: %s", got)
	}

	logs.Reset()
	links.move(second, nil)
	waitFor(t, hub.bind.(*darwinBind), second)
	deadline := time.Now().Add(2 * time.Second)
	for !strings.Contains(logs.String(), "cannot reach off") && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := logs.String(); !strings.Contains(got, "cannot reach off") {
		t.Errorf("the rebind said nothing about a socket that reaches nothing: %s", got)
	}
}

// Binding needs something to say which interface to bind to. A caller that
// asks for it and supplies nothing gets an error rather than a socket that
// silently follows the forwarding table.
func TestBindingWithoutALinkSourceIsRefused(t *testing.T) {
	if _, err := NewHub(":0", Underlay{Bind: true}, Runtime{}); err == nil {
		t.Fatal("a hub asked to bind with no link source was opened anyway")
	}
}

// A hub that was never asked to bind reports its underlay ready, because
// nothing was asked of it. Otherwise every linux node and every node that
// leaves the block out would hold its announced default back forever.
func TestUnboundUnderlayReportsReady(t *testing.T) {
	hub, err := NewHub(":0", Underlay{}, Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	if !hub.UnderlayReady() {
		t.Error("a hub that was never asked to bind reports that it is not where it should be")
	}
	if got := hub.bind.(*darwinBind); boundInterface(t, got.v4) != 0 {
		t.Error("a hub that was never asked to bind set IP_BOUND_IF anyway")
	}
}

// recordingRoutes stands in for Runtime.Routes, which on darwin writes a
// default scoped to the interface a socket is bound to while a family needs
// one. It records the order of every call against the interface the socket
// was on at the time, because the order is the property under test.
type recordingRoutes struct {
	hub *Hub
	mu  sync.Mutex
	at  []string
}

func (r *recordingRoutes) note(what string, index int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	bound := 0
	if r.hub != nil {
		r.hub.mu.Lock()
		bound = r.hub.boundTo
		r.hub.mu.Unlock()
	}
	r.at = append(r.at, fmt.Sprintf("%s %d while bound to %d", what, index, bound))
}

func (r *recordingRoutes) Prepare(index int) error { r.note("prepare", index); return nil }
func (r *recordingRoutes) Settle(index int) error  { r.note("settle", index); return nil }

func (r *recordingRoutes) calls() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.at)
}

// A move makes the interface the socket is going to usable before the socket
// moves onto it, and clears the one it left only after. On this platform a
// bound socket still reads the shared forwarding table, so a socket on an
// interface whose scoped default has already gone reaches nothing at all
// while a family needed that default.
func TestUnderlayPreparesAnInterfaceBeforeBindingToIt(t *testing.T) {
	first, second := twoInterfaces(t)
	links := newFakeLinks(first)
	routes := &recordingRoutes{}
	hub, err := NewHub(":0", Underlay{Bind: true}, Runtime{Links: links, Routes: routes})
	if err != nil {
		t.Fatalf("open a bound hub: %v", err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	routes.mu.Lock()
	routes.hub = hub
	routes.mu.Unlock()
	bind := hub.bind.(*darwinBind)

	links.move(second, nil)
	waitFor(t, bind, second)
	// The settle after the move is the last call, and a poll can read the
	// list between the bind and it.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && len(routes.calls()) < 4 {
		time.Sleep(5 * time.Millisecond)
	}

	calls := routes.calls()
	if len(calls) < 4 {
		t.Fatalf("the move made %v, want a prepare and a settle for each interface", calls)
	}
	// The opening pair is on the interface the socket was born on, and the
	// hub's own binding happened inside the listen hook, so the first prepare
	// reads as bound to nothing.
	if want := fmt.Sprintf("prepare %d while bound to 0", first); calls[0] != want {
		t.Errorf("the first call was %q, want %q", calls[0], want)
	}
	// The move: prepared while still on the old interface, settled once on
	// the new one. Either half in the other order is a window with no route.
	if want := fmt.Sprintf("prepare %d while bound to %d", second, first); calls[2] != want {
		t.Errorf("the move prepared as %q, want %q", calls[2], want)
	}
	if want := fmt.Sprintf("settle %d while bound to %d", second, second); calls[3] != want {
		t.Errorf("the move settled as %q, want %q", calls[3], want)
	}
}

// A prepare that fails stops the move. Binding onto an interface whose routing
// could not be written is the outage the ordering exists to avoid, so the
// socket stays where it is and the failure is reported.
func TestUnderlayStaysPutWhenAnInterfaceCannotBePrepared(t *testing.T) {
	first, second := twoInterfaces(t)
	links := newFakeLinks(first)
	refusing := &refusingRoutes{}
	hub, err := NewHub(":0", Underlay{Bind: true}, Runtime{Links: links, Routes: refusing})
	if err != nil {
		t.Fatalf("open a bound hub: %v", err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	bind := hub.bind.(*darwinBind)

	refusing.refuse.Store(true)
	links.move(second, nil)
	// Nothing acknowledges a move that is meant not to happen, so this waits
	// rather than polling: the failure it looks for is the socket moving.
	time.Sleep(200 * time.Millisecond)
	if got := boundInterface(t, bind.v4); got != first {
		t.Errorf("the socket moved to %d although its routing could not be written", got)
	}

	// And it follows the next notification once the routing can be written.
	refusing.refuse.Store(false)
	links.move(second, nil)
	waitFor(t, bind, second)
}

// refusingRoutes fails Prepare on demand.
type refusingRoutes struct{ refuse atomic.Bool }

func (r *refusingRoutes) Prepare(int) error {
	if r.refuse.Load() {
		return errors.New("the routing could not be written")
	}
	return nil
}

func (r *refusingRoutes) Settle(int) error { return nil }

// failingRoutes fails Settle on demand, which is the path that used to leave
// both sockets open on the port for the life of the process.
type failingRoutes struct{ settle atomic.Bool }

func (r *failingRoutes) Prepare(int) error { return nil }
func (r *failingRoutes) Settle(int) error {
	if r.settle.Load() {
		return errors.New("the record could not be settled")
	}
	return nil
}

// A hub that fails on the way up has to leave nothing behind. Settle runs
// after the sockets are open, so returning without closing them held the port
// until the process exited and the next attempt on it answered EADDRINUSE.
func TestFailedSettleLeavesNoSocketOnThePort(t *testing.T) {
	index, _ := twoInterfaces(t)
	// A fixed port, so the second attempt asks for the one the first would
	// have leaked rather than for whatever is free.
	probe, err := NewHub(":0", Underlay{}, Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	_ = probe.Close()

	routes := &failingRoutes{}
	routes.settle.Store(true)
	address := fmt.Sprintf(":%d", port)
	if _, err := NewHub(address, Underlay{Bind: true},
		Runtime{Links: newFakeLinks(index), Routes: routes}); err == nil {
		t.Fatal("a hub whose settle failed was returned anyway")
	}
	// The port has to be free again, which it is only if both sockets closed.
	again, err := NewHub(address, Underlay{}, Runtime{})
	if err != nil {
		t.Fatalf("the port is still held after a failed settle: %v", err)
	}
	_ = again.Close()
}

// A move that fails partway puts both families back where they were. One on
// each interface reaches half this node's peers, and recording the index it
// did not reach makes UnderlayReady answer from a value nothing holds.
func TestPartialRebindLeavesBothFamiliesWhereTheyWere(t *testing.T) {
	first, _ := twoInterfaces(t)
	hub, err := NewHub(":0", Underlay{Bind: true}, Runtime{Links: newFakeLinks(first)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	bind := hub.bind.(*darwinBind)
	if got := boundInterface(t, bind.v4); got != first {
		t.Fatalf("the hub opened on interface %d, want %d", got, first)
	}

	// The v6 half refuses while the v4 half has already moved, which is the
	// half-finished move. It is injected because the kernel will not produce
	// one: every index it refuses, it refuses for both families, measured.
	_, second := twoInterfaces(t)
	bind.v6.bindOption = func(int) error { return errors.New("the option was refused") }
	t.Cleanup(func() { bind.v6.bindOption = nil })
	if err := hub.BindUnderlay(second); err == nil {
		t.Fatal("a move whose second family refused reported success")
	}
	if got := boundInterface(t, bind.v4); got != first {
		t.Errorf("the udp4 socket was left on %d after a failed move, want %d", got, first)
	}
	if got := boundInterface(t, bind.v6); got != first {
		t.Errorf("the udp6 socket was left on %d after a failed move, want %d", got, first)
	}
	if hub.UnderlayReady() {
		t.Error("a hub that could not complete a move reports its underlay ready")
	}
}

// dontFragmentSet reads back whether the kernel sets DF on the socket's datagrams
func dontFragmentSet(t *testing.T, socket *darwinSocket) bool {
	t.Helper()
	level, option := dontFragmentOption(socket.ipv6)
	var value int
	var readErr error
	if err := socket.raw.Control(func(fd uintptr) { value, readErr = unix.GetsockoptInt(int(fd), level, option) }); err != nil {
		t.Fatal(err)
	}
	if readErr != nil {
		t.Fatal(readErr)
	}
	return value != 0
}

// openMuxes opens a hub and a mux to each of addresses at port 4500
func openMuxes(t *testing.T, addresses ...string) (*Hub, []*Mux) {
	t.Helper()
	hub, err := NewHub(":0", Underlay{}, Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	var muxes []*Mux
	for _, address := range addresses {
		mux, err := hub.NewMux(net.ParseIP(address), 4500)
		if err != nil {
			t.Fatal(err)
		}
		muxes = append(muxes, mux)
	}
	return hub, muxes
}

// both sockets set DF on every datagram from the open
// a mux letting its IPv4 sends fragment clears it on the IPv4 socket until the last such mux stops, and every IPv4 mux reads that it sends without DF meanwhile
// an IPv6 mux fragments its own datagrams alone, the IPv6 socket keeping DF and only that mux reading that it sends without it
func TestSocketsSendWithDontFragment(t *testing.T) {
	hub, muxes := openMuxes(t, "127.0.0.1", "127.0.0.2", "::1", "::2")
	bind := hub.bind.(*darwinBind)
	v4, v4b, v6, v6b := muxes[0], muxes[1], muxes[2], muxes[3]
	for _, step := range []struct {
		name string
		act  func() error
		// sockets is whether the IPv4 and the IPv6 socket set DF
		sockets [2]bool
		// muxes holds each mux's reading of its own sends
		muxes [4]bool
	}{
		{"nothing fragments", func() error { return nil }, [2]bool{true, true}, [4]bool{true, true, true, true}},
		{"an IPv4 mux fragments", func() error { return v4.Fragment(true) }, [2]bool{false, true}, [4]bool{false, false, true, true}},
		{"another IPv4 mux fragments", func() error { return v4b.Fragment(true) }, [2]bool{false, true}, [4]bool{false, false, true, true}},
		{"the first IPv4 mux stops", func() error { return v4.Fragment(false) }, [2]bool{false, true}, [4]bool{false, false, true, true}},
		{"the last IPv4 mux stops", func() error { return v4b.Fragment(false) }, [2]bool{true, true}, [4]bool{true, true, true, true}},
		{"an IPv6 mux fragments", func() error { return v6.Fragment(true) }, [2]bool{true, true}, [4]bool{true, true, false, true}},
		{"it closes", v6.Close, [2]bool{true, true}, [4]bool{true, true, true, true}},
	} {
		if err := step.act(); err != nil {
			t.Fatalf("%s: %v", step.name, err)
		}
		if got := [2]bool{dontFragmentSet(t, bind.v4), dontFragmentSet(t, bind.v6)}; got != step.sockets {
			t.Errorf("%s: the IPv4 and IPv6 sockets set DF %v, want %v", step.name, got, step.sockets)
		}
		if got := [4]bool{v4.DontFragment(), v4b.DontFragment(), v6.DontFragment(), v6b.DontFragment()}; got != step.muxes {
			t.Errorf("%s: the muxes read that they send with DF %v, want %v", step.name, got, step.muxes)
		}
	}
}

// the path MTU of an unbound socket is the MTU of the interface the route to the peer leaves by
func TestPathMTUIsTheRoutedInterfaceMTU(t *testing.T) {
	_, muxes := openMuxes(t, "127.0.0.1", "::1")
	loopback, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Fatal(err)
	}
	for _, mux := range muxes {
		if got, err := mux.PathMTU(); err != nil || got != loopback.MTU {
			t.Errorf("the path MTU to %s reads %d, %v, want lo0's %d", mux.Endpoint(), got, err, loopback.MTU)
		}
	}
}

// the path MTU of a bound socket is the MTU of the interface it is bound to
// the interface the host routes the peer through plays no part
// the hub binds a live interface other than lo0, as the binding tests open theirs
// the peer is 127.0.0.1, which the host routes through lo0
func TestPathMTUOfABoundSocketIsTheBoundInterfaceMTU(t *testing.T) {
	loopbackIndex, index := twoInterfaces(t)
	loopback, err := net.InterfaceByIndex(loopbackIndex)
	if err != nil {
		t.Fatal(err)
	}
	link, err := net.InterfaceByIndex(index)
	if err != nil {
		t.Fatal(err)
	}
	if link.MTU == loopback.MTU {
		t.Skipf("%s carries the MTU of %s, %d, so a read of either looks the same", link.Name, loopback.Name, link.MTU)
	}
	hub, err := NewHub(":0", Underlay{Bind: true}, Runtime{Links: newFakeLinks(index)})
	if err != nil {
		t.Fatalf("open a bound hub: %v", err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	mux, err := hub.NewMux(net.ParseIP("127.0.0.1"), 4500)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := mux.PathMTU(); err != nil || got != link.MTU {
		t.Errorf("the path MTU to %s from a hub bound to %s reads %d, %v, want %s's %d rather than the %d of %s",
			mux.Endpoint(), link.Name, got, err, link.Name, link.MTU, loopback.MTU, loopback.Name)
	}
}

// the path MTU of an endpoint pinned to a link-local address is the MTU of the interface the pin names, the one the request arrived on
// lo0 holds fe80::1, and the pin names it on another live interface, as a link that shares the address would
func TestPathMTUOfALinkLocalPinIsItsInterfaceMTU(t *testing.T) {
	loopbackIndex, index := twoInterfaces(t)
	loopback, err := net.InterfaceByIndex(loopbackIndex)
	if err != nil {
		t.Fatal(err)
	}
	link, err := net.InterfaceByIndex(index)
	if err != nil {
		t.Fatal(err)
	}
	if link.MTU == loopback.MTU {
		t.Skipf("%s carries the MTU of %s, %d, so a read of either looks the same", link.Name, loopback.Name, link.MTU)
	}
	hub, err := NewHub(":0", Underlay{}, Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	pin := netip.MustParseAddr("fe80::1")
	mux, err := hub.NewMuxTo(pinnedEndpoint(netip.MustParseAddrPort("[::1]:4500"), pin, index))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := mux.PathMTU(); err != nil || got != link.MTU {
		t.Errorf("the path MTU of %s pinned to %s on %s reads %d, %v, want %s's %d rather than the %d of %s",
			mux.Endpoint(), pin, link.Name, got, err, link.Name, link.MTU, loopback.MTU, loopback.Name)
	}
}

const (
	// fethNear and fethFar are the feth pair a test makes, numbered past any a host keeps
	fethNear = "feth7700"
	fethFar  = "feth7701"
	// fethMTU is the near feth's MTU, the largest IP packet a send through it carries
	fethMTU = 1400
	// dadWait bounds the wait for a feth's IPv6 addresses to finish duplicate address detection
	dadWait = 5 * time.Second
	// dadPoll is how often the wait looks
	dadPoll = 50 * time.Millisecond
)

// requireHostNet skips a test that changes the host's interfaces to make what unless the run is root and asks for it
func requireHostNet(t *testing.T, what string) {
	t.Helper()
	if os.Getenv("RANET3_DARWIN_NETTEST") != "1" {
		t.Skipf("set RANET3_DARWIN_NETTEST=1 and run as root to make %s", what)
	}
	if os.Geteuid() != 0 {
		t.Skipf("RANET3_DARWIN_NETTEST=1 but this process is not root, and %s needs root", what)
	}
}

func hostCommand(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
		t.Fatalf("%s: %v: %s", strings.Join(args, " "), err, out)
	}
}

// fethPath makes a feth pair whose near end carries fethMTU and an address of each family
// it points two neighbors of each family at the far end, where a datagram to one leaves through the near end and reaches no host
func fethPath(t *testing.T) {
	t.Helper()
	for _, name := range []string{fethNear, fethFar} {
		hostCommand(t, "ifconfig", name, "create")
		t.Cleanup(func() { _ = exec.Command("ifconfig", name, "destroy").Run() })
	}
	hostCommand(t, "ifconfig", fethNear, "peer", fethFar)
	hostCommand(t, "ifconfig", fethNear, "mtu", strconv.Itoa(fethMTU))
	hostCommand(t, "ifconfig", fethNear, "inet", "192.0.2.1/24", "up")
	hostCommand(t, "ifconfig", fethNear, "inet6", "2001:db8:f::1", "prefixlen", "64")
	hostCommand(t, "ifconfig", fethFar, "up")
	far, err := net.InterfaceByName(fethFar)
	if err != nil {
		t.Fatal(err)
	}
	for _, neighbor := range []string{"192.0.2.9", "192.0.2.10"} {
		hostCommand(t, "arp", "-s", neighbor, far.HardwareAddr.String())
	}
	for _, neighbor := range []string{"2001:db8:f::9", "2001:db8:f::10"} {
		hostCommand(t, "ndp", "-s", neighbor, far.HardwareAddr.String())
	}
	waitDAD(t, fethNear)
}

// waitDAD waits until no IPv6 address of the interface name is tentative
func waitDAD(t *testing.T, name string) {
	t.Helper()
	for deadline := time.Now().Add(dadWait); ; time.Sleep(dadPoll) {
		out, err := exec.Command("ifconfig", name).CombinedOutput()
		if err != nil {
			t.Fatalf("ifconfig %s: %v: %s", name, err, out)
		}
		if !strings.Contains(string(out), "tentative") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("an IPv6 address on %s stayed tentative for %s: %s", name, dadWait, out)
		}
	}
}

// farFrames reads the frames that cross to the far feth through a bpf device attached to it
type farFrames struct {
	fd     int
	buffer []byte
}

// bpfBuffer is the bpf buffer a test asks for, which holds every frame of a send
const bpfBuffer = 1 << 16

// watchFar attaches a bpf device to the far feth, which sees every frame the near feth hands across
// a read returns the frames that arrived so far and never waits for more
func watchFar(t *testing.T) *farFrames {
	t.Helper()
	fd := -1
	for i := 0; fd < 0; i++ {
		opened, err := unix.Open(fmt.Sprintf("/dev/bpf%d", i), unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		switch {
		case err == nil:
			fd = opened
		case !errors.Is(err, unix.EBUSY):
			t.Fatalf("open a bpf device: %v", err)
		}
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	// the buffer is sized before the device attaches, which fixes it
	if err := unix.IoctlSetPointerInt(fd, unix.BIOCSBLEN, bpfBuffer); err != nil {
		t.Fatalf("size the bpf buffer: %v", err)
	}
	// struct ifreq is the interface's name and a union of 16 bytes
	request := make([]byte, unix.IFNAMSIZ+16)
	copy(request, fethFar)
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), unix.BIOCSETIF, uintptr(unsafe.Pointer(&request[0]))); errno != 0 {
		t.Fatalf("attach bpf to %s: %v", fethFar, errno)
	}
	if err := unix.IoctlSetPointerInt(fd, unix.BIOCIMMEDIATE, 1); err != nil {
		t.Fatalf("hand each frame over as it arrives: %v", err)
	}
	size, err := unix.IoctlGetInt(fd, unix.BIOCGBLEN)
	if err != nil {
		t.Fatalf("read the bpf buffer's size: %v", err)
	}
	return &farFrames{fd: fd, buffer: make([]byte, size)}
}

// crossed reads the far feth for whole UDP datagrams of size bytes from port to 4500, from the address from where it is valid
// it reads until want of them crossed or budget passed
// it reports how many crossed
func (f *farFrames) crossed(t *testing.T, port, size, want int, from netip.Addr, budget time.Duration) int {
	t.Helper()
	got := 0
	for deadline := time.Now().Add(budget); got < want && time.Now().Before(deadline); {
		n, err := unix.Read(f.fd, f.buffer)
		if errors.Is(err, unix.EAGAIN) {
			time.Sleep(pollInterval)
			continue
		}
		if err != nil {
			t.Fatalf("read the frames that crossed to %s: %v", fethFar, err)
		}
		// each frame follows its bpf_hdr and the next header starts on a word
		for frames := f.buffer[:n]; len(frames) >= unix.SizeofBpfHdr; {
			captured := int(binary.NativeEndian.Uint32(frames[unsafe.Offsetof(unix.BpfHdr{}.Caplen):]))
			header := int(binary.NativeEndian.Uint16(frames[unsafe.Offsetof(unix.BpfHdr{}.Hdrlen):]))
			if header+captured > len(frames) {
				break
			}
			if payload, source := udpDatagram(frames[header:header+captured], port); payload == size && (!from.IsValid() || source == from) {
				got++
			}
			frames = frames[min(len(frames), (header+captured+unix.BPF_ALIGNMENT-1)&^(unix.BPF_ALIGNMENT-1)):]
		}
	}
	return got
}

// the wait for each far neighbor's path to carry a datagram
const (
	// pathWait bounds the wait for one neighbor
	// darwin has lost the first IPv6 datagrams to the far feth for several seconds after fethPath returned
	pathWait = 30 * time.Second
	// pathResend is how long the wait looks for a datagram before it sends another
	pathResend = 250 * time.Millisecond
)

// carried sends a datagram through each mux until one crosses to the far feth, as leftFrom does from any source
// each mux's datagram has a size of its own from 64 bytes
// crossed tells datagrams apart by size alone
// no step sends a datagram of those sizes
// a send that fails counts as one that never crossed
func (f *farFrames) carried(t *testing.T, port int, muxes []*Mux) {
	t.Helper()
	for i, mux := range muxes {
		probe := make([]byte, 64+i)
		f.leftFrom(t, port, len(probe), netip.Addr{}, func() error { return mux.SendESPBatch([][]byte{probe}) })
	}
}

// the ethertypes of IPv4 and IPv6
const (
	etherIPv4 = 0x0800
	etherIPv6 = 0x86dd
)

// udpDatagram is the payload size and the IP source of the whole UDP datagram from port to 4500 that an ethernet frame carries
// the size is -1 for any other frame, a fragment among them
func udpDatagram(frame []byte, port int) (int, netip.Addr) {
	if len(frame) < 14 {
		return -1, netip.Addr{}
	}
	packet := frame[14:]
	var udp []byte
	var source netip.Addr
	switch binary.BigEndian.Uint16(frame[12:]) {
	case etherIPv4:
		// a fragment sets more fragments or an offset, the bits below DF
		if len(packet) < 20 || packet[9] != unix.IPPROTO_UDP || binary.BigEndian.Uint16(packet[6:])&0x3fff != 0 {
			return -1, netip.Addr{}
		}
		source = netip.AddrFrom4([4]byte(packet[12:16]))
		udp = packet[min(len(packet), int(packet[0]&0x0f)*4):]
	case etherIPv6:
		// a fragment carries a fragment header ahead of UDP
		if len(packet) < 40 || packet[6] != unix.IPPROTO_UDP {
			return -1, netip.Addr{}
		}
		source = netip.AddrFrom16([16]byte(packet[8:24]))
		udp = packet[40:]
	default:
		return -1, netip.Addr{}
	}
	if len(udp) < 8 || int(binary.BigEndian.Uint16(udp)) != port || binary.BigEndian.Uint16(udp[2:]) != 4500 {
		return -1, netip.Addr{}
	}
	return int(binary.BigEndian.Uint16(udp[4:])) - 8, source
}

// through a feth whose MTU is 1400, both families refuse a datagram past it, and the send reports the interface's MTU once the datagrams within it went
// a mux letting its sends fragment sends the longer datagram in fragments
// an IPv4 mux fragments the whole IPv4 socket, another IPv4 mux sending it in fragments too, and an IPv6 mux fragments its own datagrams alone
// every send carries the longer datagram between two that fill the feth under the family's headers
// both of those cross to the far feth, the one after a refused datagram too
// the steps begin once a datagram to each far neighbor crossed
func TestDarwinRefusesWhatTheInterfaceCannotCarry(t *testing.T) {
	requireHostNet(t, "a feth pair")
	fethPath(t)
	hub, muxes := openMuxes(t, "192.0.2.9", "192.0.2.10", "2001:db8:f::9", "2001:db8:f::10")
	port := hub.LocalAddr().(*net.UDPAddr).Port
	far := watchFar(t)
	far.carried(t, port, muxes)
	v4, v6 := muxes[0], muxes[2]
	for _, mux := range muxes {
		if got, err := mux.PathMTU(); err != nil || got != fethMTU {
			t.Fatalf("the path MTU to %s reads %d, %v, want the feth's %d", mux.Endpoint(), got, err, fethMTU)
		}
	}
	// 1500 bytes of UDP payload fit the feth under neither family's headers
	long := make([]byte, 1500)
	for _, step := range []struct {
		name string
		act  func() error
		// refused is which muxes have the long datagram refused and reported rather than sent in fragments
		refused [4]bool
	}{
		{"nothing fragments", func() error { return nil }, [4]bool{true, true, true, true}},
		{"an IPv4 mux fragments", func() error { return v4.Fragment(true) }, [4]bool{false, false, true, true}},
		{"it stops and an IPv6 mux fragments", func() error {
			return errors.Join(v4.Fragment(false), v6.Fragment(true))
		}, [4]bool{true, true, false, true}},
		{"that stops too", func() error { return v6.Fragment(false) }, [4]bool{true, true, true, true}},
	} {
		if err := step.act(); err != nil {
			t.Fatalf("%s: %v", step.name, err)
		}
		for i, mux := range muxes {
			// the largest datagram the feth carries under the outer IP and UDP headers
			largest := fethMTU - 40 - 8
			if mux.Endpoint().AddrPort().Addr().Is4() {
				largest = fethMTU - 20 - 8
			}
			filling := make([]byte, largest)
			err := mux.SendESPBatch([][]byte{filling, long, filling})
			report, ok := err.(*PathMTUError)
			switch {
			case step.refused[i] && (!ok || *report != (PathMTUError{Endpoint: mux.Endpoint(), MTU: fethMTU})):
				t.Errorf("%s: the send to %s answered %v, want the report of its %d byte interface alone", step.name, mux.Endpoint(), err, fethMTU)
			case !step.refused[i] && err != nil:
				t.Errorf("%s: the send to %s answered %v, want every datagram sent", step.name, mux.Endpoint(), err)
			}
			if got := mux.DontFragment(); got != step.refused[i] {
				t.Errorf("%s: the mux to %s reads that it sends with DF %v, want %v", step.name, mux.Endpoint(), got, step.refused[i])
			}
			if got := far.crossed(t, port, largest, 2, netip.Addr{}, arrivalBudget); got != 2 {
				t.Errorf("%s: %d of the send's two datagrams of %d bytes to %s crossed to the far feth, want both", step.name, got, largest, mux.Endpoint())
			}
		}
	}
}

// hostAddress is an address of the family ipv6 names on an interface of this host that is up and broadcasts
func hostAddress(t *testing.T, ipv6 bool) netip.Addr {
	t.Helper()
	links, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, link := range links {
		if link.Flags&net.FlagUp == 0 || link.Flags&net.FlagBroadcast == 0 || link.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, err := link.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			prefix, ok := address.(*net.IPNet)
			if !ok {
				continue
			}
			if addr, ok := netip.AddrFromSlice(prefix.IP); ok {
				if addr = addr.Unmap(); addr.Is6() == ipv6 && addr.IsGlobalUnicast() {
					return addr
				}
			}
		}
	}
	t.Skipf("this host holds no address of the family on an interface that is up, IPv6 %v", ipv6)
	return netip.Addr{}
}

// loopbackLinkLocal is lo0's link-local IPv6 address, zoned by lo0
func loopbackLinkLocal(t *testing.T) (netip.Addr, int) {
	t.Helper()
	loopback, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Fatal(err)
	}
	addresses, err := loopback.Addrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range addresses {
		if prefix, ok := address.(*net.IPNet); ok && prefix.IP.IsLinkLocalUnicast() && prefix.IP.To4() == nil {
			local, _ := netip.AddrFromSlice(prefix.IP)
			return local.WithZone(loopback.Name), loopback.Index
		}
	}
	t.Skip("lo0 holds no link-local IPv6 address")
	return netip.Addr{}, 0
}

// receivedControl is the control message XNU hands a socket of the family ipv6 names with a datagram that reached dst on interface index
func receivedControl(ipv6 bool, dst netip.Addr, index int) []byte {
	level, kind, size := unix.IPPROTO_IP, unix.IP_RECVPKTINFO, unix.SizeofInet4Pktinfo
	if ipv6 {
		level, kind, size = unix.IPPROTO_IPV6, unix.IPV6_PKTINFO, unix.SizeofInet6Pktinfo
	}
	control := make([]byte, unix.CmsgSpace(size))
	header := (*unix.Cmsghdr)(unsafe.Pointer(&control[0]))
	header.Level, header.Type = int32(level), int32(kind)
	header.SetLen(unix.CmsgLen(size))
	data := unsafe.Pointer(&control[unix.CmsgLen(0)])
	if ipv6 {
		info := (*unix.Inet6Pktinfo)(data)
		info.Addr, info.Ifindex = dst.As16(), uint32(index)
	} else {
		info := (*unix.Inet4Pktinfo)(data)
		info.Addr, info.Ifindex = dst.As4(), uint32(index)
	}
	return control
}

// sentPin is the source address and interface a send's control message names, and whether it lets the datagram fragment
func sentPin(control []byte) (source netip.Addr, index int, fragments bool, err error) {
	messages, err := unix.ParseSocketControlMessage(control)
	if err != nil {
		return netip.Addr{}, 0, false, err
	}
	for _, m := range messages {
		switch {
		case m.Header.Level == unix.IPPROTO_IP && m.Header.Type == unix.IP_PKTINFO && len(m.Data) == unix.SizeofInet4Pktinfo:
			info := (*unix.Inet4Pktinfo)(unsafe.Pointer(&m.Data[0]))
			source, index = netip.AddrFrom4(info.Spec_dst), int(info.Ifindex)
		case m.Header.Level == unix.IPPROTO_IPV6 && m.Header.Type == unix.IPV6_PKTINFO && len(m.Data) == unix.SizeofInet6Pktinfo:
			info := (*unix.Inet6Pktinfo)(unsafe.Pointer(&m.Data[0]))
			source, index = netip.AddrFrom16(info.Addr), int(info.Ifindex)
		case m.Header.Level == unix.IPPROTO_IPV6 && m.Header.Type == unix.IPV6_DONTFRAG && len(m.Data) == 4:
			fragments = binary.NativeEndian.Uint32(m.Data) == 0
		default:
			return netip.Addr{}, 0, false, fmt.Errorf("a send carries a control message of level %d and type %d", m.Header.Level, m.Header.Type)
		}
	}
	return source, index, fragments, nil
}

// markedRequest is an IKE request under pairTestIKESPI behind the non-ESP marker, as a peer sends it to the hub's port
func markedRequest() []byte {
	request := make([]byte, 28)
	binary.BigEndian.PutUint64(request, pairTestIKESPI)
	return withMarker(request)
}

// replyLeavesFrom has a client at client connected to reached on the hub's port send a request, which the hub answers through the endpoint it arrived with
// a connected socket takes datagrams from the address it connected to alone, so the answer reaches the client only from reached
// darwin routes the answer to client by lo0, whose own address it takes for the source of a send that names none
func replyLeavesFrom(t *testing.T, network string, client, reached netip.Addr) {
	t.Helper()
	hub, err := NewHub(":0", Underlay{}, Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	unclaimed := hub.Listen()
	to := netip.AddrPortFrom(reached, hub.port)
	conn, err := net.DialUDP(network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(client, 0)), net.UDPAddrFromAddrPort(to))
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		t.Skipf("this sandbox will not let a socket at %s connect to %s: %v", client, to, err)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := conn.Write(markedRequest()); err != nil {
		t.Fatalf("a request from %s to %s: %v", client, to, err)
	}
	var first Unclaimed
	select {
	case first = <-unclaimed:
	case <-time.After(arrivalBudget):
		t.Fatalf("the request from %s to %s never reached the hub", client, to)
	}
	mux, err := hub.NewMuxTo(first.Endpoint)
	if err != nil {
		t.Fatal(err)
	}
	answer := []byte("answer")
	if err := mux.SendIKETo(answer, first.Endpoint); err != nil {
		t.Fatalf("the answer to %s: %v", first.Endpoint, err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(arrivalBudget)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("the answer to a request that reached %s never arrived on a socket connected to it, so it left from another address: %v", to, err)
	}
	if got := buf[:n]; !bytes.Equal(got, withMarker(answer)) {
		t.Fatalf("the client read %q, want the answer", got)
	}
}

// an IPv4 answer leaves from the address its request reached, the host's own here, rather than the 127.0.0.1 the route to the client picks
// RFC 7296 section 2.11: "It MUST specify the address and port at which the request was received as the source address and port in the response."
func TestDarwinReplyLeavesFromTheAddressTheRequestReached(t *testing.T) {
	replyLeavesFrom(t, "udp4", netip.MustParseAddr("127.0.0.1"), hostAddress(t, false))
}

// an IPv6 answer leaves from the address its request reached rather than the ::1 the route to the client picks
// lo0's link-local address names lo0 in the answer's pin, and the host's own global address names no interface
func TestDarwinReplyLeavesFromTheAddressTheRequestReachedOverIPv6(t *testing.T) {
	loopback := netip.MustParseAddr("::1")
	t.Run("link-local", func(t *testing.T) {
		reached, _ := loopbackLinkLocal(t)
		replyLeavesFrom(t, "udp6", loopback, reached)
	})
	t.Run("global", func(t *testing.T) { replyLeavesFrom(t, "udp6", loopback, hostAddress(t, true)) })
}

// a listener reads the address each datagram reached, and the endpoint of an IKE datagram is pinned to it
// an ESP datagram gets no endpoint, which the hub reads for nothing
func TestDarwinReceiverPinsIKEAlone(t *testing.T) {
	for i, family := range []struct{ network, loopback string }{{"udp4", "127.0.0.1"}, {"udp6", "::1"}} {
		t.Run(family.network, func(t *testing.T) {
			opened, receivers, port, err := listenPacketBind(0, 0, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = opened.Close() })
			bind := opened.(*darwinBind)
			if bind.v4 == nil || bind.v6 == nil {
				t.Fatal("the bind opened one family alone")
			}
			socket := []*darwinSocket{bind.v4, bind.v6}[i]
			if err := socket.conn.SetReadDeadline(time.Now().Add(arrivalBudget)); err != nil {
				t.Fatal(err)
			}
			peer := listenPeer(t, family.network, family.loopback)
			at := peer.LocalAddr().(*net.UDPAddr).AddrPort()
			loopback := netip.MustParseAddr(family.loopback)
			esp := binary.BigEndian.AppendUint32(nil, pairTestSPI)
			ike := markedRequest()
			for _, datagram := range [][]byte{esp, ike} {
				if _, err := peer.WriteToUDPAddrPort(datagram, netip.AddrPortFrom(loopback, port)); err != nil {
					t.Fatal(err)
				}
			}
			bufs, sizes, endpoints, records := make([][]byte, 1), make([]int, 1), make([]Endpoint, 1), make([]receiveRecord, 1)
			for _, datagram := range [][]byte{esp, ike} {
				endpoints[0] = &darwinEndpoint{}
				if n, refused, err := receivers[i](bufs, sizes, endpoints, records); n != 1 || refused != 0 || err != nil {
					t.Fatalf("a read answered %d datagrams, %d refused and %v", n, refused, err)
				}
				if got := bufs[0][:sizes[0]]; !bytes.Equal(got, datagram) {
					t.Fatalf("the listener read %x, want %x", got, datagram)
				}
				if len(datagram) == len(esp) {
					if endpoints[0] != nil {
						t.Errorf("an ESP datagram came with the endpoint %v", endpoints[0])
					}
					continue
				}
				ep, ok := endpoints[0].(*darwinEndpoint)
				if !ok || ep.pin() == nil || ep.source != loopback || ep.index != 0 || ep.AddrPort() != netip.AddrPortFrom(at.Addr().Unmap(), at.Port()) {
					t.Errorf("an IKE datagram from %s to %s came with %#v, want one pinned to %s", at, loopback, endpoints[0], loopback)
				}
			}
		})
	}
}

// the record of each datagram, ESP and IKE alike, holds the address and port it came from, here two peers on two ports of one address
func TestDarwinReceiveRecordCarriesEachDatagramsSource(t *testing.T) {
	for i, family := range []struct{ network, loopback string }{{"udp4", "127.0.0.1"}, {"udp6", "::1"}} {
		t.Run(family.network, func(t *testing.T) {
			opened, receivers, port, err := listenPacketBind(0, 0, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = opened.Close() })
			bind := opened.(*darwinBind)
			if bind.v4 == nil || bind.v6 == nil {
				t.Fatal("the bind opened one family alone")
			}
			if err := []*darwinSocket{bind.v4, bind.v6}[i].conn.SetReadDeadline(time.Now().Add(arrivalBudget)); err != nil {
				t.Fatal(err)
			}
			loopback := netip.MustParseAddr(family.loopback)
			var sent []netip.AddrPort
			for _, datagram := range [][]byte{binary.BigEndian.AppendUint32(nil, pairTestSPI), markedRequest()} {
				for range 2 {
					peer := listenPeer(t, family.network, family.loopback)
					if _, err := peer.WriteToUDPAddrPort(datagram, netip.AddrPortFrom(loopback, port)); err != nil {
						t.Fatal(err)
					}
					at := peer.LocalAddr().(*net.UDPAddr).AddrPort()
					sent = append(sent, netip.AddrPortFrom(at.Addr().Unmap(), at.Port()))
				}
			}
			bufs, sizes, endpoints, records := make([][]byte, 1), make([]int, 1), make([]Endpoint, 1), make([]receiveRecord, 1)
			for _, from := range sent {
				records[0] = receiveRecord{}
				if n, refused, err := receivers[i](bufs, sizes, endpoints, records); n != 1 || refused != 0 || err != nil {
					t.Fatalf("a read answered %d datagrams, %d refused and %v", n, refused, err)
				}
				if records[0].source != from {
					t.Errorf("a datagram from %s came with the source %v", from, records[0].source)
				}
			}
		})
	}
}

// an IPv4 answer names the address its request reached in ipi_spec_dst and leaves ipi_ifindex 0, whatever interface the request arrived on
// XNU takes a nonzero ipi_ifindex over ipi_spec_dst and IP_BOUND_IF, which would drop the source and move the answer off the bound underlay
// an IPv6 answer names the interface for a link-local source alone, which needs its zone
func TestDarwinPinKeepsTheBoundScope(t *testing.T) {
	from := netip.MustParseAddrPort("198.51.100.1:4500")
	for _, test := range []struct {
		reached string
		ipv6    bool
		index   int
	}{
		{reached: "192.0.2.7"},
		{reached: "2001:db8::7", ipv6: true},
		{reached: "fe80::7", ipv6: true, index: 7},
	} {
		reached := netip.MustParseAddr(test.reached)
		ep, err := (&darwinSocket{ipv6: test.ipv6}).replyEndpoint(from, receivedControl(test.ipv6, reached, 7))
		if err != nil {
			t.Fatalf("a request that reached %s on interface 7: %v", reached, err)
		}
		source, index, fragments, err := sentPin(ep.sendControl())
		if err != nil || source != reached || index != test.index || fragments {
			t.Errorf("the answer to a request that reached %s on interface 7 names %s at interface %d, fragmenting %v, %v, want %s at interface %d",
				reached, source, index, fragments, err, reached, test.index)
		}
	}
}

// an IKE datagram whose control message names no destination gets no endpoint, since its answer could not name the address it reached
func TestDarwinReceiverRefusesAnIKEDatagramWithoutItsDestination(t *testing.T) {
	from := netip.MustParseAddrPort("198.51.100.1:4500")
	if ep, err := (&darwinSocket{}).replyEndpoint(from, nil); err == nil {
		t.Errorf("no control message gave the endpoint %v, want a refusal", ep)
	}
}

// the receiver counts a datagram whose control message the kernel cut short as refused and drops it, IKE and ESP alike, and hands on the datagram after them
// SO_TIMESTAMP cuts it in both families: ip_savecontrol and ip6_savecontrol_v4 queue the timestamp ahead of the packet info, which copyout_control then cuts and flags MSG_CTRUNC
// SO_TIMESTAMP_MONOTONIC's 8 octets leave the IPv4 packet info whole and less of the buffer than a message header for the TOS, so the control data parses and only MSG_CTRUNC says the outer ECN field is unknown
func TestDarwinReceiverDropsADatagramWhoseControlMessageWasCut(t *testing.T) {
	for _, family := range []struct {
		name, network, loopback string
		ipv6                    bool
		option                  int
	}{
		{"udp4", "udp4", "127.0.0.1", false, unix.SO_TIMESTAMP},
		{"udp6", "udp6", "::1", true, unix.SO_TIMESTAMP},
		{"udp4 monotonic", "udp4", "127.0.0.1", false, unix.SO_TIMESTAMP_MONOTONIC},
	} {
		t.Run(family.name, func(t *testing.T) {
			opened, receivers, port, err := listenPacketBind(0, 0, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = opened.Close() })
			bind := opened.(*darwinBind)
			i := 0
			if family.ipv6 {
				i = 1
			}
			socket := []*darwinSocket{bind.v4, bind.v6}[i]
			if socket == nil {
				t.Skipf("the bind opened no %s socket", family.network)
			}
			timestamp := func(on int) {
				t.Helper()
				var setErr error
				if err := socket.raw.Control(func(fd uintptr) { setErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, family.option, on) }); err != nil || setErr != nil {
					t.Fatalf("set the timestamp option %#x to %d: %v, %v", family.option, on, err, setErr)
				}
			}
			if err := socket.conn.SetReadDeadline(time.Now().Add(arrivalBudget)); err != nil {
				t.Fatal(err)
			}
			peer := listenPeer(t, family.network, family.loopback)
			to := netip.AddrPortFrom(netip.MustParseAddr(family.loopback), port)
			esp := binary.BigEndian.AppendUint32(nil, pairTestSPI)
			after := binary.BigEndian.AppendUint32(nil, pairTestSPI+1)
			// the kernel builds a datagram's control message as it queues it, so the two sent while timestamps are on carry one and the third does not
			timestamp(1)
			for _, datagram := range [][]byte{markedRequest(), esp} {
				if _, err := peer.WriteToUDPAddrPort(datagram, to); err != nil {
					t.Fatal(err)
				}
			}
			bufs, sizes, endpoints, records := make([][]byte, 1), make([]int, 1), make([]Endpoint, 1), make([]receiveRecord, 1)
			for _, what := range []string{"an IKE datagram", "an ESP datagram"} {
				if n, refused, err := receivers[i](bufs, sizes, endpoints, records); n != 0 || refused != 1 || err != nil {
					t.Fatalf("the read of %s whose control message was cut answered %d datagrams, %d refused and %v, want it refused", what, n, refused, err)
				}
			}
			timestamp(0)
			if _, err := peer.WriteToUDPAddrPort(after, to); err != nil {
				t.Fatal(err)
			}
			n, refused, err := receivers[i](bufs, sizes, endpoints, records)
			if n != 1 || refused != 0 || err != nil || !bytes.Equal(bufs[0][:sizes[0]], after) || endpoints[0] != nil {
				t.Fatalf("the read after them answered %d datagrams, %d refused and %v, %x with %v, want the ESP datagram %x alone", n, refused, err, bufs[0][:sizes[0]], endpoints[0], after)
			}
		})
	}
}

// an answer pinned to an address the host lost goes from the kernel's choice of source, and every send to the endpoint does from then on
// the path MTU of such an endpoint is that of the route
// once the host holds the address again, a fresh request that reaches it moves the session back onto it
// the hub records the fallback once, with the errno darwin refused the pin with
// the test adds an address to lo0, has a request reach it and removes it before the answer
func TestDarwinReplyFromAGoneSourceFallsBack(t *testing.T) {
	requireHostNet(t, "an lo0 alias")
	for _, family := range []struct {
		network, loopback, alias string
		add, remove              []string
	}{
		{"udp4", "127.0.0.1", "127.0.0.77", []string{"ifconfig", "lo0", "alias", "127.0.0.77", "up"}, []string{"ifconfig", "lo0", "-alias", "127.0.0.77"}},
		{"udp6", "::1", "2001:db8:77::1", []string{"ifconfig", "lo0", "inet6", "2001:db8:77::1", "prefixlen", "128", "alias"}, []string{"ifconfig", "lo0", "inet6", "2001:db8:77::1", "-alias"}},
	} {
		t.Run(family.network, func(t *testing.T) {
			events := &eventLog{}
			hub, err := NewHub(":0", Underlay{}, Runtime{Events: events.record})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = hub.Close() })
			unclaimed := hub.Listen()
			hostCommand(t, family.add...)
			t.Cleanup(func() { _ = exec.Command(family.remove[0], family.remove[1:]...).Run() })
			waitDAD(t, "lo0")
			alias, loopback := netip.MustParseAddr(family.alias), netip.MustParseAddr(family.loopback)
			client := listenPeer(t, family.network, family.loopback)
			if _, err := client.WriteToUDPAddrPort(markedRequest(), netip.AddrPortFrom(alias, hub.port)); err != nil {
				t.Fatal(err)
			}
			var first Unclaimed
			select {
			case first = <-unclaimed:
			case <-time.After(arrivalBudget):
				t.Fatalf("the request to %s never reached the hub", alias)
			}
			ep := first.Endpoint.(*darwinEndpoint)
			if ep.pin() == nil || ep.source != alias {
				t.Fatalf("the request to %s arrived with an endpoint pinned %v to %s", alias, ep.pin() != nil, ep.source)
			}
			hostCommand(t, family.remove...)
			mux, err := hub.NewMuxTo(ep)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := mux.PathMTU(); err != nil {
				t.Errorf("the path MTU to %s pinned to %s the host no longer holds: %v", ep, alias, err)
			}
			for i := range 2 {
				answer := fmt.Appendf(nil, "answer %d", i)
				if err := mux.SendIKETo(answer, ep); err != nil {
					t.Fatalf("answer %d, pinned to %s the host no longer holds, was not sent from another address: %v", i, alias, err)
				}
				if from := readFrom(t, client, withMarker(answer)); from != netip.AddrPortFrom(loopback, hub.port) {
					t.Errorf("answer %d arrived from %s, want the kernel's choice %s", i, from, netip.AddrPortFrom(loopback, hub.port))
				}
			}
			if !ep.unpinned.Load() {
				t.Error("the endpoint still names the gone source")
			}
			got := events.recorded()
			t.Logf("the hub recorded %q", got)
			if want := "transport.endpoint.unpinned endpoint=" + ep.String() + " errno="; len(got) != 1 || !strings.HasPrefix(got[0], want) {
				t.Errorf("the hub recorded %q, want one line starting %q", got, want)
			}
			hostCommand(t, family.add...)
			waitDAD(t, "lo0")
			if _, err := client.WriteToUDPAddrPort(markedRequest(), netip.AddrPortFrom(alias, hub.port)); err != nil {
				t.Fatal(err)
			}
			var again Unclaimed
			select {
			case again = <-unclaimed:
			case <-time.After(arrivalBudget):
				t.Fatalf("the request to %s, held again, never reached the hub", alias)
			}
			if !mux.AdoptEndpoint(again.Endpoint) {
				t.Errorf("a fresh request to %s, which the host holds again, left the session on the kernel's choice", alias)
			}
			back := []byte("answer from the address held again")
			if err := mux.SendIKE(back); err != nil {
				t.Fatal(err)
			}
			if from := readFrom(t, client, withMarker(back)); from != netip.AddrPortFrom(alias, hub.port) {
				t.Errorf("the answer after %s came back arrived from %s, want %s", alias, from, netip.AddrPortFrom(alias, hub.port))
			}
		})
	}
}

// leftFrom sends with send, again every pathResend, until a datagram of size from port crosses to the far feth from source, or from anywhere for an invalid source
// it fails the test when none does within pathWait
func (f *farFrames) leftFrom(t *testing.T, port, size int, source netip.Addr, send func() error) {
	t.Helper()
	start := time.Now()
	for tries := 1; ; tries++ {
		err := send()
		if f.crossed(t, port, size, 1, source, pathResend) > 0 {
			t.Logf("a datagram of %d bytes crossed to %s at try %d, %s after the first", size, fethFar, tries, time.Since(start).Round(time.Millisecond))
			return
		}
		if time.Since(start) >= pathWait {
			t.Fatalf("none of %d datagrams of %d bytes crossed to %s from %s within %s, the last send answering %v", tries, size, fethFar, source, pathWait, err)
		}
	}
}

// pinPaths are the peers pinDetour routes, each off both feths' subnets
// pin is the near feth's address, and farAddress the far feth's, which the host picks for a send to peer that names no source
var pinPaths = []struct {
	name, family            string
	peer, pin, farAddress   netip.Addr
	farGateway, nearGateway string
	header                  int
}{
	{"IPv4", "-inet", netip.MustParseAddr("203.0.113.20"), netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.18.0.1"), "198.18.0.9", "192.0.2.9", 20},
	{"IPv6", "-inet6", netip.MustParseAddr("2001:db8:20::20"), netip.MustParseAddr("2001:db8:f::1"), netip.MustParseAddr("2001:db8:e::1"), "2001:db8:e::9", "2001:db8:f::9", 40},
}

// pinDetour makes the feth pair, gives the far feth an address of each family and a gateway resolving to the near feth, and routes each of pinPaths' peers by the far feth
// where scoped, it also routes each peer by the near feth in a route scoped to it, as a scoped default does for a utun or PPP service
// the far feth's bpf device sees a datagram leaving either feth
func pinDetour(t *testing.T, scoped bool) {
	t.Helper()
	fethPath(t)
	near, err := net.InterfaceByName(fethNear)
	if err != nil {
		t.Fatal(err)
	}
	hostCommand(t, "ifconfig", fethFar, "inet", "198.18.0.1/24")
	hostCommand(t, "ifconfig", fethFar, "inet6", "2001:db8:e::1", "prefixlen", "64")
	waitDAD(t, fethFar)
	hostCommand(t, "arp", "-s", "198.18.0.9", near.HardwareAddr.String())
	hostCommand(t, "ndp", "-s", "2001:db8:e::9", near.HardwareAddr.String())
	for _, path := range pinPaths {
		peer := path.peer.String()
		hostCommand(t, "route", "-n", "add", path.family, "-host", peer, path.farGateway)
		t.Cleanup(func() { _ = exec.Command("route", "-n", "delete", path.family, "-host", peer).Run() })
		if scoped {
			hostCommand(t, "route", "-n", "add", path.family, "-host", peer, path.nearGateway, "-ifscope", fethNear)
			t.Cleanup(func() {
				_ = exec.Command("route", "-n", "delete", path.family, "-host", peer, "-ifscope", fethNear).Run()
			})
		}
	}
}

// a pinned send leaves by the interface that holds its pin, the near feth of fethMTU, where the host routes the peer by the far feth, which carries 1500
// so a pinned endpoint's path MTU and the report of a datagram refused for its size name the near feth's MTU
// ip_output scopes the lookup of a send naming its source to the interface holding that source, which here holds a scoped route to the peer
func TestDarwinPinnedPathMTUIsThePinsInterface(t *testing.T) {
	requireHostNet(t, "a feth pair")
	pinDetour(t, true)
	for _, path := range pinPaths {
		t.Run(path.name, func(t *testing.T) {
			hub, err := NewHub(":0", Underlay{}, Runtime{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = hub.Close() })
			ep := pinnedEndpoint(netip.AddrPortFrom(path.peer, 4500), path.pin, 0)
			mux, err := hub.NewMuxTo(ep)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := mux.PathMTU(); err != nil || got != fethMTU {
				t.Errorf("the path MTU of %s pinned to %s reads %d, %v, want the near feth's %d", ep, path.pin, got, err, fethMTU)
			}
			err = hub.bind.Send([][]byte{make([]byte, fethMTU-path.header-8+1)}, ep)
			if report, ok := err.(*PathMTUError); !ok || *report != (PathMTUError{Endpoint: ep, MTU: fethMTU}) {
				t.Errorf("a send to %s pinned to %s one byte past the near feth answered %v, want the report of its %d alone", ep, path.pin, err, fethMTU)
			}
		})
	}
}

// a pinned answer whose pin's interface holds no route to the peer goes from the kernel's choice of source, by the route the host holds
// the session's path MTU is then that route's interface's, the far feth's
// a fresh request that reaches the same pin within unroutedHold is the same destination, so it moves nothing and the session's next send does not try the pin again
// the hub records the fallback once, naming the EHOSTUNREACH darwin refuses such a send with
func TestDarwinReplyWithNoRouteFromThePinFallsBack(t *testing.T) {
	requireHostNet(t, "a feth pair")
	pinDetour(t, false)
	far, err := net.InterfaceByName(fethFar)
	if err != nil {
		t.Fatal(err)
	}
	frames := watchFar(t)
	for _, path := range pinPaths {
		t.Run(path.name, func(t *testing.T) {
			events := &eventLog{}
			hub, err := NewHub(":0", Underlay{}, Runtime{Events: events.record})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = hub.Close() })
			peer := netip.AddrPortFrom(path.peer, 4500)
			ep := pinnedEndpoint(peer, path.pin, 0)
			mux, err := hub.NewMuxTo(ep)
			if err != nil {
				t.Fatal(err)
			}
			answer := make([]byte, 100)
			if err := hub.bind.Send([][]byte{answer}, ep); err != nil {
				t.Fatalf("an answer to %s pinned to %s, whose interface holds no route there, was not sent from another address: %v", ep, path.pin, err)
			}
			if !ep.unpinned.Load() {
				t.Error("the endpoint still names a pin its interface holds no route from")
			}
			frames.leftFrom(t, int(hub.port), len(answer), path.farAddress, func() error { return hub.bind.Send([][]byte{answer}, ep) })
			if got, err := mux.PathMTU(); err != nil || got != far.MTU {
				t.Errorf("the path MTU of %s, which fell back from %s, reads %d, %v, want the far feth's %d", ep, path.pin, got, err, far.MTU)
			}
			for i := range 3 {
				if mux.AdoptEndpoint(pinnedEndpoint(peer, path.pin, 0)) {
					t.Errorf("fresh request %d from %s to %s, which holds no route back, moved the session", i, peer, path.pin)
				}
				if err := mux.SendIKE([]byte("answer")); err != nil {
					t.Fatal(err)
				}
			}
			want := fmt.Sprintf("transport.endpoint.unpinned endpoint=%s errno=EHOSTUNREACH", ep)
			if got := events.recorded(); !slices.Equal(got, []string{want}) {
				t.Errorf("the hub recorded %q, want %q", got, want)
			}
		})
	}
}

// a session whose pin fell back after EHOSTUNREACH stays on the kernel's choice while unroutedHold lasts, through a fresh request to the pin once it routes again
// after the hold, a fresh request to the pin moves the session back onto it, and its ESP leaves from the pin
// the hub records the fallback once
// the test deletes the pin's scoped route and adds it back, as configd withdraws and restores a service's scoped default while its address stays
func TestDarwinSessionReturnsToAPinThatRoutesAgain(t *testing.T) {
	requireHostNet(t, "a feth pair")
	pinDetour(t, true)
	frames := watchFar(t)
	for i, path := range pinPaths {
		t.Run(path.name, func(t *testing.T) {
			events := &eventLog{}
			hub, err := NewHub(":0", Underlay{}, Runtime{Events: events.record})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = hub.Close() })
			peer := netip.AddrPortFrom(path.peer, 4500)
			ep := pinnedEndpoint(peer, path.pin, 0)
			mux, err := hub.NewMuxTo(ep)
			if err != nil {
				t.Fatal(err)
			}
			// each step's ESP has a size of its own, past the other family's
			sentFrom := func(step int, source netip.Addr) {
				t.Helper()
				size := 200 + 300*i + step
				frames.leftFrom(t, int(hub.port), size, source, func() error { return mux.SendESP(make([]byte, size)) })
			}
			sentFrom(0, path.pin)
			hostCommand(t, "route", "-n", "delete", path.family, "-host", path.peer.String(), "-ifscope", fethNear)
			sentFrom(1, path.farAddress)
			if ep.unroutedUntil.Load() == nil {
				t.Fatalf("premise: a send pinned to %s, whose scoped route is gone, did not fall back for want of a route", path.pin)
			}
			hostCommand(t, "route", "-n", "add", path.family, "-host", path.peer.String(), path.nearGateway, "-ifscope", fethNear)
			if mux.AdoptEndpoint(pinnedEndpoint(peer, path.pin, 0)) {
				t.Errorf("a fresh request to %s within the hold moved the session", path.pin)
			}
			sentFrom(2, path.farAddress)
			ep.unroutedUntil.Store(new(time.Now()))
			if !mux.AdoptEndpoint(pinnedEndpoint(peer, path.pin, 0)) {
				t.Errorf("a fresh request to %s after the hold left the session on the kernel's choice", path.pin)
			}
			sentFrom(3, path.pin)
			want := fmt.Sprintf("transport.endpoint.unpinned endpoint=%s errno=EHOSTUNREACH", ep)
			if got := events.recorded(); !slices.Equal(got, []string{want}) {
				t.Errorf("the hub recorded %q, want %q", got, want)
			}
		})
	}
}

// a send whose pinned try and unpinned resend are both refused keeps the pin and records nothing, so a later send tries the pin again
// a reject ARP entry for the pin's gateway, which stands for one whose ARP failed, has darwin refuse both with EHOSTUNREACH
// once the gateway answers again, sends leave from the pin
func TestDarwinSendRefusedWithAndWithoutThePinKeepsIt(t *testing.T) {
	requireHostNet(t, "a feth pair")
	pinDetour(t, true)
	far, err := net.InterfaceByName(fethFar)
	if err != nil {
		t.Fatal(err)
	}
	frames := watchFar(t)
	path := pinPaths[0]
	hostCommand(t, "arp", "-d", path.nearGateway)
	hostCommand(t, "arp", "-s", path.nearGateway, far.HardwareAddr.String(), "reject")
	t.Cleanup(func() { _ = exec.Command("arp", "-d", path.nearGateway).Run() })
	events := &eventLog{}
	hub, err := NewHub(":0", Underlay{}, Runtime{Events: events.record})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	ep := pinnedEndpoint(netip.AddrPortFrom(path.peer, 4500), path.pin, 0)
	err = hub.bind.Send([][]byte{make([]byte, 100)}, ep)
	// a write that names no source is a sendto, and one carrying the pin a sendmsg
	if call, ok := errors.AsType[*os.SyscallError](err); !ok || call.Syscall != "sendto" || !errors.Is(err, unix.EHOSTUNREACH) {
		t.Fatalf("premise: a send pinned to %s, whose gateway rejects, answered %v, want the resend's EHOSTUNREACH", path.pin, err)
	}
	if ep.pin() == nil || ep.unroutedUntil.Load() != nil {
		t.Errorf("a send refused with and without its pin %s dropped the pin, fallen back for want of a route %v", path.pin, ep.unroutedUntil.Load() != nil)
	}
	hostCommand(t, "arp", "-d", path.nearGateway)
	hostCommand(t, "arp", "-s", path.nearGateway, far.HardwareAddr.String())
	frames.leftFrom(t, int(hub.port), 101, path.pin, func() error { return hub.bind.Send([][]byte{make([]byte, 101)}, ep) })
	if got := events.recorded(); len(got) != 0 {
		t.Errorf("the hub recorded %q, want nothing", got)
	}
}

// unpinnedSends is how many sends TestDarwinRefusedSendWithoutAPinIsTriedOnce counts, enough that a stray message of the process cannot double them
const unpinnedSends = 16

// messagesSent is the count of sends this process made, which sosend raises on every call before the protocol can refuse it
func messagesSent(t *testing.T) int64 {
	t.Helper()
	var usage unix.Rusage
	if err := unix.Getrusage(unix.RUSAGE_SELF, &usage); err != nil {
		t.Fatalf("read this process's resource usage: %v", err)
	}
	return usage.Msgsnd
}

// a send to an endpoint with no pin that darwin refuses with an errno a pinned send falls back on is one call, and records nothing
// udp_output and udp6_output refuse a datagram to port 0 with EADDRNOTAVAIL
func TestDarwinRefusedSendWithoutAPinIsTriedOnce(t *testing.T) {
	for _, loopback := range []string{"127.0.0.1", "::1"} {
		events := &eventLog{}
		hub, err := NewHub(":0", Underlay{}, Runtime{Events: events.record})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = hub.Close() })
		ep := &darwinEndpoint{addr: netip.AddrPortFrom(netip.MustParseAddr(loopback), 0)}
		before := messagesSent(t)
		for range unpinnedSends {
			if err := hub.bind.Send([][]byte{make([]byte, 64)}, ep); !errors.Is(err, unix.EADDRNOTAVAIL) {
				t.Fatalf("premise: a send to %s answered %v, want EADDRNOTAVAIL", ep, err)
			}
		}
		sent := messagesSent(t) - before
		if sent < unpinnedSends {
			t.Fatalf("premise: %d sends to %s, each refused, counted %d calls, want one or more each", unpinnedSends, ep, sent)
		}
		if sent >= 2*unpinnedSends {
			t.Errorf("%d sends to %s, each refused, made %d calls, want one each", unpinnedSends, ep, sent)
		}
		if got := events.recorded(); len(got) != 0 || ep.pin() != nil {
			t.Errorf("sends to %s with no pin recorded %q, and it holds a pin %v", ep, got, ep.pin() != nil)
		}
	}
}

// after darwin refuses a pinned datagram for its size, the datagrams of the send that fit still leave from the pin
// the pin is the near feth's address the host does not pick for the neighbor, so a datagram that names no source leaves from the other
func TestDarwinDatagramsAfterASizeRefusalLeaveFromThePin(t *testing.T) {
	requireHostNet(t, "a feth pair")
	fethPath(t)
	hostCommand(t, "ifconfig", fethNear, "inet", "192.0.2.5", "netmask", "255.255.255.255", "alias")
	hostCommand(t, "ifconfig", fethNear, "inet6", "2001:db8:f::5", "prefixlen", "64", "alias")
	waitDAD(t, fethNear)
	frames := watchFar(t)
	for _, family := range []struct {
		name      string
		neighbor  netip.Addr
		addresses []netip.Addr
		header    int
	}{
		{"IPv4", netip.MustParseAddr("192.0.2.9"), []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.5")}, 20},
		{"IPv6", netip.MustParseAddr("2001:db8:f::9"), []netip.Addr{netip.MustParseAddr("2001:db8:f::1"), netip.MustParseAddr("2001:db8:f::5")}, 40},
	} {
		t.Run(family.name, func(t *testing.T) {
			peer := netip.AddrPortFrom(family.neighbor, 4500)
			conn, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(peer))
			if err != nil {
				t.Fatal(err)
			}
			chosen := conn.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Unmap()
			_ = conn.Close()
			index := slices.Index(family.addresses, chosen)
			if index < 0 {
				t.Fatalf("the host sends to %s from %s, want one of %v", peer, chosen, family.addresses)
			}
			pin := family.addresses[1-index]
			hub, err := NewHub(":0", Underlay{}, Runtime{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = hub.Close() })
			ep := pinnedEndpoint(peer, pin, 0)
			frames.leftFrom(t, int(hub.port), 64, pin, func() error { return hub.bind.Send([][]byte{make([]byte, 64)}, ep) })
			largest := fethMTU - family.header - 8
			filling := make([]byte, largest)
			err = hub.bind.Send([][]byte{filling, make([]byte, 1500), filling}, ep)
			if report, ok := err.(*PathMTUError); !ok || *report != (PathMTUError{Endpoint: ep, MTU: fethMTU}) {
				t.Errorf("a send to %s pinned to %s answered %v, want the report of the near feth's %d alone", ep, pin, err, fethMTU)
			}
			if got := frames.crossed(t, int(hub.port), largest, 2, pin, arrivalBudget); got != 2 {
				t.Errorf("%d of the send's two datagrams of %d bytes to %s left from the pin %s, want both, where the host picks %s", got, largest, peer, pin, chosen)
			}
		})
	}
}
