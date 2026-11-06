// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package kernel

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/route"
	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/schema"
)

// The tests in this file run the kill switch and the overlay holds against
// the real kernel: a reconciler on a test utun M in mode 2 with fallback =
// "none" writes the rejects and the holds on lo0, and the Mac's own sends are
// made at them. While a reconciler holds the switch the Mac's unbound traffic
// beyond its connected networks is refused for a few seconds.

const (
	// killHelperEnv runs the test binary as the crash helper, which holds the
	// switch with a reconciler of its own until it is killed
	killHelperEnv = "RANET3_DARWIN_SWITCH_HELPER"
	// killReady bounds the wait for the helper to hold the switch, and for a
	// running reconciler's first pass
	killReady = 15 * time.Second
	// killHelperLife bounds a helper that is never killed
	killHelperLife = time.Minute
	// killGone bounds the wait for a killed helper's utun and the end of a
	// test's table, and killPoll is how often a wait looks again
	killGone = 5 * time.Second
	killPoll = 5 * time.Millisecond
	// killConnectWait is how long a TCP connect toward a documentation target
	// is given before it counts as left
	killConnectWait = 300 * time.Millisecond
	// killQuiet is longer than a running reconciler takes to settle after the
	// wakes of its own writes, and killWake is how long a reject another
	// writer deleted may take to be written again, well inside the minute
	// between periodic passes
	killQuiet = time.Second
	killWake  = 2 * time.Second
	// killPort is the port every datagram and connect here goes to
	killPort = 9
)

var (
	// killOverlay holds M's addresses in its first prefix of each family, and
	// its second prefix of each family is where the carve-out arm puts a
	// link's connected network
	killOverlay   = prefixes(prefix("198.51.100.0/24"), prefix("2001:db8:bb::/48"), prefix("192.0.2.128/25"), prefix("2001:db8:cc::/48"))
	killAddresses = prefixes(prefix("198.51.100.1/24"), prefix("2001:db8:bb::1/64"))
	// killTargets lie under a member of each family's cover and inside no
	// prefix of the overlay
	killTargets = []netip.Addr{netip.MustParseAddr("203.0.113.7"), netip.MustParseAddr("2001:db8:ff::7")}
	// killUnannounced is an address of each family's first overlay prefix that
	// no route announces and M does not hold
	killUnannounced = []netip.Addr{netip.MustParseAddr("198.51.100.77"), netip.MustParseAddr("2001:db8:bb:ff::77")}
	// killCarved is a link's address on each family's second overlay prefix,
	// the whole prefix its connected network, and killCarvedTarget an address
	// inside each
	killCarved       = []netip.Prefix{prefix("192.0.2.129/25"), prefix("2001:db8:cc::1/48")}
	killCarvedTarget = []netip.Addr{netip.MustParseAddr("192.0.2.130"), netip.MustParseAddr("2001:db8:cc::2")}
	// killOther is the addresses of a second test utun standing in for
	// another program, outside every overlay prefix
	killOther = []netip.Prefix{prefix("192.0.2.1/32"), prefix("2001:db8:dd::1/64")}
	// killEndpoint is a peer's endpoint the underlay sends to
	killEndpoint = netip.MustParseAddr("192.0.2.9")
	// killFull is a full-length prefix of each family, which the full-length
	// helper's overlay holds beside killOverlay and its mesh announces
	killFull        = []netip.Prefix{prefix("198.18.0.77/32"), prefix("2001:db8:ee::77/128")}
	killFullOverlay = slices.Concat(killOverlay, prefixes(killFull...))
)

// killHelperPlain and killHelperFull are killHelperEnv's values for the helper
// that holds the switch and for the full-length helper, which runs under
// fallback = "uplink" so no reject refuses a send at killFull
const (
	killHelperPlain = "1"
	killHelperFull  = "full"
)

// killRig is a reconciler on M, a test utun standing in for ranet3's, in mode
// 2 over killOverlay with M's addresses written, a route source holding both
// zero routes, a session count the test sets and a clock it moves
type killRig struct {
	name      string
	index     int
	fd        int
	table     *netstack.RouteTable
	reconcile *Reconciler
	live      atomic.Int64
	clock     atomic.Int64
	// stopped says the test stopped or closed the reconciler itself, or
	// handed it to Run, which does both
	stopped bool
}

// killRigOptions name what one test changes about the rig
type killRigOptions struct {
	fallback  Fallback
	live      int64
	network   func() NetworkState
	selection bool
	// overlay is the rig's overlay, killOverlay where nil
	overlay []schema.Prefix
}

func newKillRig(t *testing.T, options killRigOptions) *killRig {
	t.Helper()
	name, fd := createUTUNWithFD(t)
	setInterfaceUp(t, name)
	rig := &killRig{name: name, index: interfaceIndex(t, name), fd: fd, table: netstack.NewRouteTable()}
	rig.live.Store(options.live)
	rig.clock.Store(time.Now().UnixNano())
	overlay := killOverlay
	if options.overlay != nil {
		overlay = options.overlay
	}
	runtime := Runtime{
		Interface: name,
		Overlay:   overlay,
		Sessions:  func() int { return int(rig.live.Load()) },
		Network:   options.network,
	}
	if options.selection {
		runtime.Selection = openTestSelection(t, nil, name)
	}
	table := Table{
		ID: DefaultTable, Proto: DefaultProtocol, Addresses: killAddresses,
		Reconcile: schema.Duration(time.Minute), CaptureGrace: schema.Duration(MinCaptureGrace),
	}
	reconciler, err := New(table.WithMode(&ExitMode{Fallback: options.fallback}), runtime, rig.table)
	if err != nil {
		t.Fatal(err)
	}
	reconciler.now = func() time.Time { return time.Unix(0, rig.clock.Load()) }
	rig.reconcile = reconciler
	for _, zero := range defaultPrefixes {
		rig.table.Set(netip.Prefix{}, zero, nil)
	}
	t.Cleanup(func() {
		if !rig.stopped {
			_ = reconciler.withdraw(nil)
			_ = reconciler.plat.Close()
		}
	})
	return rig
}

func (rig *killRig) pass(t *testing.T, step string) {
	t.Helper()
	if err := rig.reconcile.reconcile(); err != nil {
		t.Fatalf("%s: %v", step, err)
	}
}

// later moves the rig's clock by d
func (rig *killRig) later(d time.Duration) { rig.clock.Add(int64(d)) }

// stop withdraws the reconciler as an operator's stop does
func (rig *killRig) stop(t *testing.T) {
	t.Helper()
	rig.stopped = true
	if err := rig.reconcile.withdraw(nil); err != nil {
		t.Errorf("the stop: %v", err)
	}
	_ = rig.reconcile.plat.Close()
}

// leave closes the reconciler and withdraws nothing, so its rejects and holds
// stay on lo0 as a crash leaves them
func (rig *killRig) leave() {
	rig.stopped = true
	_ = rig.reconcile.Close()
}

// TestDarwinSwitchCrashHelper holds the switch for TestDarwinSwitchOutlivesACrash,
// which runs the test binary again to start it and kills it with SIGKILL, or
// as the full-length helper announces killFull for
// TestDarwinFullLengthHoldOutlivesACrash. It skips anywhere else.
func TestDarwinSwitchCrashHelper(t *testing.T) {
	mode := os.Getenv(killHelperEnv)
	if mode != killHelperPlain && mode != killHelperFull {
		t.Skip("run only as the crash helper of TestDarwinSwitchOutlivesACrash or TestDarwinFullLengthHoldOutlivesACrash")
	}
	requireNetTest(t)
	full := mode == killHelperFull
	options := killRigOptions{fallback: FallbackNone, live: 1}
	if full {
		options = killRigOptions{fallback: FallbackUplink, live: 1, overlay: killFullOverlay}
	}
	rig := newKillRig(t, options)
	if full {
		for _, key := range killFull {
			rig.table.Set(netip.Prefix{}, key, nil)
		}
	}
	rig.pass(t, "the helper's pass")
	if got := switchReads(rig.reconcile); !full && got != string(FallbackPassing) {
		t.Fatalf("the helper's switch is %s, want passing", got)
	}
	fmt.Printf("switch helper ready %s %d\n", rig.name, rig.index)
	time.Sleep(killHelperLife)
}

// A reconciler with a live session puts each zero route in as the halves of
// its members out of M, both families' rejects and the holds on lo0, and
// reports the switch passing: an unbound lookup of each target ends at a half
// on M and an unbound datagram comes out of M. An unbound send to an overlay address no
// route announces is refused at its hold. A link whose connected network is
// a prefix of the overlay carves it, so no hold goes in there and that link
// carries the prefix's traffic. Another program's route inside a hold reads as
// taken, and its removal ends it. With the session gone past the capture's
// grace no half is left, every unbound send beyond the connected networks is
// refused with ENETUNREACH and the switch reports holding. The stop removes
// the rejects and the holds.
func TestDarwinSwitchPassesThenHolds(t *testing.T) {
	requireNetTest(t)
	killLeavesTheHost(t)
	loopback := interfaceIndex(t, Loopback)
	carved, _ := createFeth(t)
	for _, step := range [][]string{
		{"up"},
		{"inet", killCarved[0].String(), "alias"},
		{"inet6", killCarved[1].Addr().String(), "prefixlen", fmt.Sprint(killCarved[1].Bits()), "alias"},
	} {
		if err := ifconfig(carved, step...)(); err != nil {
			t.Fatalf("give %s its connected networks: %v", carved, err)
		}
	}
	waitHoleDAD(t, carved)
	carvedIndex := interfaceIndex(t, carved)
	network := NetworkState{
		IPv4: NetworkFamily{Links: []Link{{Name: carved, Prefixes: killCarved[:1]}}},
		IPv6: NetworkFamily{Links: []Link{{Name: carved, Prefixes: killCarved[1:]}}},
	}
	rig := newKillRig(t, killRigOptions{fallback: FallbackNone, live: 1, network: func() NetworkState { return network }})
	rig.pass(t, "the first pass")
	waitHoleDAD(t, rig.name)
	held, carvedKeys := overlayKeys(killOverlay[:2]), overlayKeys(killOverlay[2:])

	t.Run("passing", func(t *testing.T) {
		killHalvesOn(t, rig.index, true)
		loops := killLoops(t, loopback)
		killLoopsHold(t, loops, rejectKeys, true, "reject")
		killLoopsHold(t, loops, held, true, "hold")
		if got := switchReads(rig.reconcile); got != string(FallbackPassing) {
			t.Errorf("the switch is %s, want passing", got)
		}
		for _, target := range killTargets {
			if got := askRoute(t, target, 0); got != rig.index {
				t.Errorf("an unbound RTM_GET for %s answers interface %d, want M's %d", target, got, rig.index)
			}
			if !arrivesUnbound(t, rig.fd, target) {
				t.Errorf("an unbound datagram to %s did not come out of M", target)
			}
		}
	})

	t.Run("the hold", func(t *testing.T) {
		for _, target := range killUnannounced {
			if got := askRoute(t, target, 0); got != loopback {
				t.Errorf("an unbound RTM_GET for %s answers interface %d, want lo0's %d", target, got, loopback)
			}
			for _, kind := range []string{"UDP", "TCP"} {
				if err := killSend(t, kind, target, killBinding{}); !errors.Is(err, unix.ENETUNREACH) {
					t.Errorf("an unbound %s send to %s answers %v, want ENETUNREACH", kind, target, err)
				}
			}
		}
	})

	t.Run("the carve-out", func(t *testing.T) {
		if stats := rig.reconcile.Stats(); stats.Skipped != 0 {
			t.Errorf("the pass skipped %d routes, want none", stats.Skipped)
		}
		killLoopsHold(t, killLoops(t, loopback), carvedKeys, false, "hold")
		for _, target := range killCarvedTarget {
			if got := askRoute(t, target, 0); got != carvedIndex {
				t.Errorf("an unbound RTM_GET for %s answers interface %d, want %s's %d", target, got, carved, carvedIndex)
			}
			if err := killSend(t, "UDP", target, killBinding{}); err != nil {
				t.Errorf("an unbound datagram to %s answers %v, want it sent", target, err)
			}
		}
	})

	t.Run("the lookup", func(t *testing.T) {
		lookups := rig.reconcile.Stats().Lookups
		if len(lookups) != len(held) || slices.ContainsFunc(lookups, func(l Lookup) bool { return l.Taken }) {
			t.Fatalf("the pass asked %+v, want one lookup of each hold, none taken", lookups)
		}
		other, destroy := destroyableUTUN(t)
		setInterfaceUp(t, other)
		otherIndex := interfaceIndex(t, other)
		for _, address := range killOther {
			if err := (runningKernel{}).Assign(true, other, address); err != nil {
				t.Fatalf("assign %s to %s: %v", address, other, err)
			}
		}
		sock := killSocket(t)
		var taking []netip.Prefix
		for _, lookup := range lookups {
			inside := netip.PrefixFrom(lookup.Address, lookup.Prefix.Bits()+1).Masked()
			if err := killOut(sock, unix.RTM_ADD, otherIndex, inside); err != nil {
				t.Fatalf("add %s out of %s: %v", inside, other, err)
			}
			taking = append(taking, inside)
		}
		rig.pass(t, "the pass with another program's routes inside the holds")
		for _, lookup := range rig.reconcile.Stats().Lookups {
			if !lookup.Taken || !strings.Contains(lookup.Answer, other) {
				t.Errorf("the lookup of %s inside %s reads %+v, want it taken by %s", lookup.Address, lookup.Prefix, lookup, other)
			}
		}
		for _, inside := range taking {
			if err := killOut(sock, unix.RTM_DELETE, otherIndex, inside); err != nil {
				t.Errorf("delete %s out of %s: %v", inside, other, err)
			}
		}
		rig.pass(t, "the pass after those routes went")
		if lookups := rig.reconcile.Stats().Lookups; len(lookups) != len(held) || slices.ContainsFunc(lookups, func(l Lookup) bool { return l.Taken }) {
			t.Errorf("the pass after another program's routes went asked %+v, want none taken", lookups)
		}
		if err := destroy(); err != nil {
			t.Errorf("destroy %s: %v", other, err)
		}
	})

	t.Run("holding", func(t *testing.T) {
		rig.live.Store(0)
		rig.pass(t, "the pass that finds the session gone")
		rig.later(2 * MinCaptureGrace)
		rig.pass(t, "the pass after the grace")
		killHalvesOn(t, rig.index, false)
		loops := killLoops(t, loopback)
		killLoopsHold(t, loops, rejectKeys, true, "reject")
		killLoopsHold(t, loops, held, true, "hold")
		if got := switchReads(rig.reconcile); got != string(FallbackHolding) {
			t.Errorf("the switch is %s, want holding", got)
		}
		for _, target := range killTargets {
			for _, kind := range []string{"ICMP", "UDP", "TCP"} {
				if err := killSend(t, kind, target, killBinding{}); !errors.Is(err, unix.ENETUNREACH) {
					t.Errorf("an unbound %s send to %s answers %v, want ENETUNREACH", kind, target, err)
				}
			}
		}
	})

	rig.stop(t)
	loops := killLoops(t, loopback)
	killLoopsHold(t, loops, rejectKeys, false, "reject")
	killLoopsHold(t, loops, overlayKeys(killOverlay), false, "hold")
}

// SIGKILL of the helper takes its utun and every route out of it, and leaves
// the rejects and the holds on lo0. Every unbound ICMP, UDP and TCP send to a
// target is then refused with ENETUNREACH, as an unbound send to an overlay
// address no route announces is while the helper lives and after. A socket
// bound to U's address or scoped to U, the interface the host's own default
// of the family leaves by, passes the rejects over, but an IPv4 TCP connect
// bound to U's address, which is refused. The underlay's two sends
// leave by U. A second reconciler with the switch takes the rejects and the
// holds over with no warning, and one under fallback = "uplink" deletes the
// rejects and at its stop the holds.
func TestDarwinSwitchOutlivesACrash(t *testing.T) {
	requireNetTest(t)
	killLeavesTheHost(t)
	loopback := interfaceIndex(t, Loopback)
	u4, _, err := lookupDefault(runningKernel{}, 0, netip.IPv4Unspecified())
	if err != nil {
		t.Skipf("this host has no IPv4 default to fall back on: %v", err)
	}
	underlay := []int{u4, hostDefault6(t, 0)}
	sources := []netip.Addr{killSourceOf(t, underlay[0], true), killSourceOf(t, underlay[1], false)}
	for i, source := range sources {
		if !source.IsValid() {
			t.Fatalf("U at %d holds no address of the family of %s", underlay[i], killTargets[i])
		}
	}
	holder, name, index := killStartHelper(t, killHelperPlain)
	held := overlayKeys(killOverlay)
	unannounced := func(state string) {
		t.Helper()
		for i, target := range killUnannounced {
			if err := killSend(t, "UDP", target, killBinding{}); !errors.Is(err, unix.ENETUNREACH) {
				t.Errorf("%s, an unbound datagram to %s answers %v, want ENETUNREACH", state, target, err)
			}
			if err := killSend(t, "UDP", target, killBinding{source: sources[i]}); err != nil {
				t.Errorf("%s, a datagram to %s bound to U's %s answers %v, want it sent", state, target, sources[i], err)
			}
		}
	}
	unannounced("with the helper alive")

	killHelper(t, holder, name, index)
	loops := killLoops(t, loopback)
	killLoopsHold(t, loops, rejectKeys, true, "reject")
	killLoopsHold(t, loops, held, true, "hold")
	for i, target := range killTargets {
		for _, kind := range []string{"ICMP", "UDP", "TCP"} {
			if err := killSend(t, kind, target, killBinding{}); !errors.Is(err, unix.ENETUNREACH) {
				t.Errorf("after the kill, an unbound %s send to %s answers %v, want ENETUNREACH", kind, target, err)
			}
			for _, binding := range []killBinding{{source: sources[i]}, {index: underlay[i]}} {
				err := killSend(t, kind, target, binding)
				refused := target.Is4() && kind == "TCP" && binding.source.IsValid()
				switch {
				case refused && !errors.Is(err, unix.ENETUNREACH):
					t.Errorf("after the kill, a %s send to %s %s answers %v, want ENETUNREACH as measured", kind, target, binding, err)
				case !refused && kind == "TCP" && errors.Is(err, unix.ENETUNREACH), !refused && kind != "TCP" && err != nil:
					t.Errorf("after the kill, a %s send to %s %s answers %v, want it to leave by U", kind, target, binding, err)
				}
			}
		}
	}
	unannounced("after the kill")
	if got := askRoute(t, killEndpoint, u4); got != u4 {
		t.Errorf("RTM_GET for the endpoint %s scoped to U answers interface %d, want %d", killEndpoint, got, u4)
	}
	if err := killPacketInfo(killEndpoint, u4); err != nil {
		t.Errorf("a datagram to the endpoint %s with packet info naming U answers %v, want it sent", killEndpoint, err)
	}
	if err := killSend(t, "UDP", killEndpoint, killBinding{index: u4}); err != nil {
		t.Errorf("a datagram to the endpoint %s scoped to U answers %v, want it sent", killEndpoint, err)
	}

	logs := captureKernelLogs(t)
	second := newKillRig(t, killRigOptions{fallback: FallbackNone})
	second.pass(t, "the takeover's pass")
	if warned := killWarnings(logs.String()); len(warned) > 0 {
		t.Errorf("the takeover warned:\n%s", strings.Join(warned, "\n"))
	}
	if got := switchReads(second.reconcile); got != string(FallbackHolding) {
		t.Errorf("the takeover's switch is %s, want holding", got)
	}
	second.leave()
	loops = killLoops(t, loopback)
	killLoopsHold(t, loops, rejectKeys, true, "reject")
	killLoopsHold(t, loops, held, true, "hold")

	third := newKillRig(t, killRigOptions{fallback: FallbackUplink})
	third.pass(t, "the pass under uplink")
	loops = killLoops(t, loopback)
	killLoopsHold(t, loops, rejectKeys, false, "reject")
	killLoopsHold(t, loops, held, true, "hold")
	third.stop(t)
	killLoopsHold(t, killLoops(t, loopback), held, false, "hold")
}

// At a full-length overlay prefix the mesh announces, M's route goes in as a
// host route beside the hold on lo0, and an unbound send there ends at M's
// route while the helper lives. SIGKILL takes M's route and leaves the hold,
// which then refuses an unbound send there with ENETUNREACH. The helper runs
// under fallback = "uplink", so no reject of the switch's refuses it.
func TestDarwinFullLengthHoldOutlivesACrash(t *testing.T) {
	requireNetTest(t)
	killLeavesTheHost(t)
	loopback := interfaceIndex(t, Loopback)
	holder, name, index := killStartHelper(t, killHelperFull)
	killLoopsHold(t, killLoops(t, loopback), killFull, true, "hold")
	for _, full := range killFull {
		target := full.Addr()
		if got := askRoute(t, target, 0); got != index {
			t.Errorf("while the helper lives an unbound RTM_GET for %s answers interface %d, want M's %d", target, got, index)
		}
		if err := killSend(t, "UDP", target, killBinding{}); err != nil {
			t.Errorf("while the helper lives an unbound datagram to %s answers %v, want it sent into M", target, err)
		}
	}

	killHelper(t, holder, name, index)
	killLoopsHold(t, killLoops(t, loopback), killFull, true, "hold")
	for _, full := range killFull {
		for _, kind := range []string{"UDP", "TCP"} {
			if err := killSend(t, kind, full.Addr(), killBinding{}); !errors.Is(err, unix.ENETUNREACH) {
				t.Errorf("after the kill, an unbound %s send to %s answers %v, want ENETUNREACH at the hold", kind, full.Addr(), err)
			}
		}
	}
}

// A reconciler under Run with the mesh routing a full-length prefix of the
// overlay in each family and an IPv6 /128 outside it reads its own host routes
// back, the IPv6 ones marked RTF_LLINFO by XNU, so its passes settle with
// none skipped and none runs after. Once the mesh withdraws them each leaves
// the utun and the hold beneath the overlay's refuses an unbound send again.
func TestDarwinRunReadsItsHostRoutesBack(t *testing.T) {
	requireNetTest(t)
	killLeavesTheHost(t)
	name, _ := createUTUNWithFD(t)
	setInterfaceUp(t, name)
	index := interfaceIndex(t, name)
	routed := append(slices.Clone(killFull), prefix("2001:db8:dd::5/128"))
	mesh := netstack.NewRouteTable()
	table := Table{ID: DefaultTable, Proto: DefaultProtocol, Addresses: killAddresses, Reconcile: schema.Duration(time.Minute)}
	reconciler, err := New(table, Runtime{Interface: name, Overlay: killFullOverlay}, mesh)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range routed {
		mesh.Set(netip.Prefix{}, key, nil)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- reconciler.Run(ctx) }()
	running := true
	t.Cleanup(func() {
		if running {
			cancel()
			<-done
		}
	})
	select {
	case <-reconciler.FirstPass():
	case <-time.After(killReady):
		t.Fatalf("the reconciler's first pass did not end within %s", killReady)
	}
	passes := []Stats{reconciler.Stats()}
	for deadline := time.Now().Add(2 * killQuiet); time.Now().Before(deadline); time.Sleep(killPoll) {
		if stats := reconciler.Stats(); !stats.At.Equal(passes[len(passes)-1].At) {
			passes = append(passes, stats)
		}
	}
	for i, stats := range passes {
		if stats.Skipped != 0 || stats.Err != "" {
			t.Errorf("pass %d skipped %d routes with err %q, want none", i, stats.Skipped, stats.Err)
		}
	}
	if last := passes[len(passes)-1]; time.Since(last.At) < killQuiet || len(passes) > 3 {
		t.Errorf("%d passes ran in %s from the first, the last at %s, want the passes settled within %s", len(passes), 2*killQuiet, last.At.Format(time.StampMilli), killQuiet)
	}
	for _, key := range routed {
		if !modeHolds(modeRowsOn(t, index), key, false) {
			t.Errorf("M holds no route at %s unscoped", key)
		}
	}

	for _, key := range routed {
		mesh.Remove(netip.Prefix{}, key)
	}
	left := routed
	for deadline := time.Now().Add(killWake); len(left) > 0 && time.Now().Before(deadline); time.Sleep(killPoll) {
		rows := modeRowsOn(t, index)
		left = slices.DeleteFunc(slices.Clone(routed), func(key netip.Prefix) bool { return !modeHolds(rows, key, false) })
	}
	if len(left) > 0 {
		t.Errorf("M still holds %v %s after the mesh withdrew them", left, killWake)
	}
	loopback := interfaceIndex(t, Loopback)
	for _, full := range killFull {
		if got := askRoute(t, full.Addr(), 0); got != loopback {
			t.Errorf("after the withdrawal an unbound RTM_GET for %s answers interface %d, want lo0's %d at the hold", full.Addr(), got, loopback)
		}
	}
	cancel()
	running = false
	if err := <-done; err != nil {
		t.Errorf("the stop: %v", err)
	}
}

// A running reconciler holding the switch wakes on another writer's delete of
// a reject or a hold on lo0 and writes each again within one wake, long before
// the periodic pass a minute out. No exit is live, so no capture's grace wakes
// a pass either. Its stop removes the rejects and the holds.
func TestDarwinSwitchWritesADeletedRejectAgainAtOnce(t *testing.T) {
	requireNetTest(t)
	killLeavesTheHost(t)
	loopback := interfaceIndex(t, Loopback)
	rig := newKillRig(t, killRigOptions{fallback: FallbackNone})
	rig.stopped = true
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- rig.reconcile.Run(ctx) }()
	running := true
	t.Cleanup(func() {
		if running {
			cancel()
			<-done
		}
	})
	select {
	case <-rig.reconcile.FirstPass():
	case <-time.After(killReady):
		t.Fatalf("the reconciler's first pass did not end within %s", killReady)
	}
	time.Sleep(killQuiet)
	if got := switchReads(rig.reconcile); got != string(FallbackHolding) {
		t.Fatalf("the switch is %s, want holding", got)
	}
	loops := killLoops(t, loopback)
	killLoopsHold(t, loops, rejectKeys, true, "reject")
	killLoopsHold(t, loops, overlayKeys(killOverlay), true, "hold")

	deleted := []netip.Prefix{prefix("128.0.0.0/1"), prefix("8000::/1"), overlayKeys(killOverlay)[0]}
	sock := killSocket(t)
	began := time.Now()
	for _, key := range deleted {
		message, err := loopMessage(unix.RTM_DELETE, key)
		if err == nil {
			err = sock.WriteRoute(message)
		}
		if err != nil {
			t.Fatalf("delete the route at %s: %v", key, err)
		}
	}
	back := false
	for deadline := began.Add(killWake); !back && time.Now().Before(deadline); time.Sleep(killPoll) {
		loops := killLoops(t, loopback)
		back = !slices.ContainsFunc(deleted, func(key netip.Prefix) bool { _, ok := loops[key]; return !ok })
	}
	if !back {
		t.Errorf("the routes at %v another writer deleted on lo0 were not written again within %s", deleted, killWake)
	}

	cancel()
	running = false
	if err := <-done; err != nil {
		t.Errorf("the stop: %v", err)
	}
	loops = killLoops(t, loopback)
	killLoopsHold(t, loops, rejectKeys, false, "reject")
	killLoopsHold(t, loops, overlayKeys(killOverlay), false, "hold")
}

// The start with no reconciler deletes the rejects and the holds a reconciler
// that ended without its stop left on lo0.
func TestDarwinStartWithNoReconcilerDeletesWhatACrashLeft(t *testing.T) {
	requireNetTest(t)
	killLeavesTheHost(t)
	loopback := interfaceIndex(t, Loopback)
	rig := newKillRig(t, killRigOptions{fallback: FallbackNone, live: 1})
	rig.pass(t, "the pass")
	rig.leave()
	loops := killLoops(t, loopback)
	killLoopsHold(t, loops, rejectKeys, true, "reject")
	killLoopsHold(t, loops, overlayKeys(killOverlay), true, "hold")
	DeleteFallback(killOverlay)
	loops = killLoops(t, loopback)
	killLoopsHold(t, loops, rejectKeys, false, "reject")
	killLoopsHold(t, loops, overlayKeys(killOverlay), false, "hold")
}

// U2, a second test utun, holds a route at one half of a member of each
// family, a host route longer than /0, and the mesh announces a route at the
// same key, which row L6 scopes beneath it. Under the switch the member goes
// in as its other half alone, the half at the mesh's key withheld, and with
// the switch off as the member whole beside the mesh's scoped route. No pass
// skips a route.
func TestDarwinSwitchWithholdsAHalfBeneathAHostRoute(t *testing.T) {
	requireNetTest(t)
	killLeavesTheHost(t)
	loopback := interfaceIndex(t, Loopback)
	members := []netip.Prefix{prefix("128.0.0.0/1"), prefix("8000::/1")}
	u2Name, _ := createUTUNWithFD(t)
	setInterfaceUp(t, u2Name)
	u2 := interfaceIndex(t, u2Name)
	for _, address := range killOther {
		if err := (runningKernel{}).Assign(true, u2Name, address); err != nil {
			t.Fatalf("assign %s to %s: %v", address, u2Name, err)
		}
	}
	waitHoleDAD(t, u2Name)
	sock := killSocket(t)
	for _, member := range members {
		host := halves(member)[0]
		if err := killOut(sock, unix.RTM_ADD, u2, host); err != nil {
			t.Fatalf("add %s out of U2: %v", host, err)
		}
		t.Cleanup(func() {
			if err := killOut(sock, unix.RTM_DELETE, u2, host); err != nil && !gone(err) {
				t.Errorf("the route %s out of U2 was left behind: %v", host, err)
			}
		})
	}
	rig := newKillRig(t, killRigOptions{fallback: FallbackNone, live: 1, selection: true})
	for _, member := range members {
		rig.table.Set(netip.Prefix{}, halves(member)[0], nil)
	}
	for _, switched := range []bool{true, false} {
		if !switched {
			if err := rig.reconcile.SetTable(rig.reconcile.Table().WithMode(&ExitMode{Fallback: FallbackUplink}), killOverlay, nil); err != nil {
				t.Fatal(err)
			}
			if !rig.reconcile.adopt() {
				t.Fatal("the reload to uplink was not taken")
			}
		}
		for pass := range 2 {
			rig.pass(t, fmt.Sprintf("pass %d with the switch asked for %v", pass, switched))
			if stats := rig.reconcile.Stats(); stats.Skipped != 0 {
				t.Errorf("pass %d with the switch asked for %v skipped %d routes, want none", pass, switched, stats.Skipped)
			}
		}
		routes, err := rig.reconcile.plat.Routes()
		if err != nil {
			t.Fatal(err)
		}
		at := func(key netip.Prefix) []Route {
			return slices.DeleteFunc(slices.Clone(routes), func(r Route) bool { return r.Destination != key })
		}
		loops := killLoops(t, loopback)
		for _, member := range members {
			split := halves(member)
			if got := at(split[0]); len(got) != 1 || got[0].Cover || !got[0].Scoped {
				t.Errorf("with the switch asked for %v M holds %v at %s, want the mesh's route scoped alone", switched, got, split[0])
			}
			whole, other := at(member), at(split[1])
			if switched && (len(whole) != 0 || len(other) != 1 || !other[0].Cover || other[0].Scoped) {
				t.Errorf("under the switch M holds %v at %s and %v at %s, want nothing and the other half unscoped", whole, member, other, split[1])
			}
			if !switched && (len(whole) != 1 || !whole[0].Cover || whole[0].Scoped || len(other) != 0) {
				t.Errorf("with the switch off M holds %v at %s and %v at %s, want the member unscoped and nothing", whole, member, other, split[1])
			}
			if _, ok := loops[member]; ok != switched {
				t.Errorf("with the switch asked for %v lo0 holds a reject at %s %v", switched, member, ok)
			}
		}
	}
	rig.stop(t)
}

// killLeavesTheHost reads the host's table and defaults, and once every later
// cleanup of the test has run deletes any reject on lo0 at the switch's keys
// and the overlay's that an arm left, scoped or not, and then waits for the
// table and the defaults to be as they were, but for ARP, NDP and cloned rows
func killLeavesTheHost(t *testing.T) {
	t.Helper()
	loopback := interfaceIndex(t, Loopback)
	defaults := defaultRoutesOnHost(t)
	table := hostRows(t)
	t.Cleanup(func() {
		var gone, added []string
		same := false
		for deadline := time.Now().Add(killGone); ; time.Sleep(killPoll) {
			same = sameDefaults(defaults, defaultRoutesOnHost(t))
			gone, added = rowsDiff(table, hostRows(t))
			if same && len(gone) == 0 && len(added) == 0 || time.Now().After(deadline) {
				break
			}
		}
		if !same {
			t.Error("the host's default routes changed over the test")
		}
		if len(gone) > 0 || len(added) > 0 {
			t.Errorf("the host's table differs from the one before the test\ngone:  %q\nadded: %q", gone, added)
		}
	})
	t.Cleanup(func() { killSweep(t, loopback) })
}

// killSweep deletes each reject on lo0 at a key of the switch's or the
// overlay's, the scoped ones by their scope, since RTM_DELETE finds a scoped
// route only under its interface
func killSweep(t *testing.T, loopback int) {
	t.Helper()
	sock, err := routeSocket(runningKernel{})
	if err != nil {
		t.Errorf("open a routing socket to delete what an arm left: %v", err)
		return
	}
	defer sock.Close()
	keys := slices.Concat(rejectKeys, overlayKeys(killFullOverlay))
	for _, rm := range dumpedRoutes(t) {
		destination, ok := dumpedPrefix(rm)
		if !ok || rm.Index != loopback || rm.Flags&unix.RTF_REJECT == 0 || !slices.Contains(keys, destination) {
			continue
		}
		message, err := loopMessage(unix.RTM_DELETE, destination)
		if err == nil && rm.Flags&unix.RTF_IFSCOPE != 0 {
			message.Flags, message.Index = message.Flags|unix.RTF_IFSCOPE, loopback
		}
		if err == nil {
			err = sock.WriteRoute(message)
		}
		if err != nil && !gone(err) {
			t.Errorf("delete the reject at %s an arm left: %v", destination, err)
		}
	}
}

// killLoops is each key lo0 holds a route of the rejects' shape at
func killLoops(t *testing.T, loopback int) map[netip.Prefix]bool {
	t.Helper()
	loops, err := loopRows(runningKernel{}, loopback)
	if err != nil {
		t.Fatal(err)
	}
	return loops
}

// killLoopsHold checks that loops holds a route at each of keys, or at none
func killLoopsHold(t *testing.T, loops map[netip.Prefix]bool, keys []netip.Prefix, want bool, what string) {
	t.Helper()
	for _, key := range keys {
		if _, ok := loops[key]; ok != want {
			t.Errorf("lo0 holds a %s at %s %v, want %v", what, key, ok, want)
		}
	}
}

// killHalvesOn checks that the interface at index holds both halves of every
// member of the cover unscoped and no member whole, or no half at all
func killHalvesOn(t *testing.T, index int, want bool) {
	t.Helper()
	rows := modeRowsOn(t, index)
	for _, member := range rejectKeys {
		if modeHolds(rows, member, false) {
			t.Errorf("M holds the member %s whole beside its reject", member)
		}
		for _, half := range halves(member) {
			if got := modeHolds(rows, half, false); got != want {
				t.Errorf("M holds the half %s unscoped %v, want %v", half, got, want)
			}
		}
	}
}

// killWarnings is each record at WARN among the JSON records of logs
func killWarnings(logs string) []string {
	var out []string
	for line := range strings.Lines(logs) {
		if strings.Contains(line, `"level":"WARN"`) {
			out = append(out, strings.TrimSpace(line))
		}
	}
	return out
}

// killStartHelper runs the test binary again as the crash helper of mode,
// killHelperEnv's value, and waits for its reconciler's first pass, killing it
// when the test ends
func killStartHelper(t *testing.T, mode string) (*exec.Cmd, string, int) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("find the test binary: %v", err)
	}
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	helper := exec.Command(self, "-test.run=^TestDarwinSwitchCrashHelper$", "-test.count=1")
	helper.Env = append(os.Environ(), killHelperEnv+"="+mode)
	helper.Stdout, helper.Stderr = write, write
	if err := helper.Start(); err != nil {
		_ = read.Close()
		_ = write.Close()
		t.Fatalf("start the helper: %v", err)
	}
	_ = write.Close()
	t.Cleanup(func() {
		_ = helper.Process.Kill()
		_ = helper.Wait()
		_ = read.Close()
	})
	lines := make(chan string, 64)
	go func() {
		defer close(lines)
		scanner := bufio.NewScanner(read)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
	}()
	var said []string
	deadline := time.After(killReady)
	for {
		select {
		case line, ok := <-lines:
			if !ok {
				t.Fatalf("the helper exited before it held the switch: %q", said)
			}
			said = append(said, line)
			var name string
			var index int
			if _, err := fmt.Sscanf(line, "switch helper ready %s %d", &name, &index); err == nil {
				return helper, name, index
			}
		case <-deadline:
			t.Fatalf("the helper did not hold the switch within %s: %q", killReady, said)
		}
	}
}

// killHelper kills the helper with SIGKILL and waits for its utun and every
// route out of it to go
func killHelper(t *testing.T, helper *exec.Cmd, name string, index int) {
	t.Helper()
	if err := helper.Process.Kill(); err != nil {
		t.Fatalf("kill the helper: %v", err)
	}
	_ = helper.Wait()
	for deadline := time.Now().Add(killGone); ; time.Sleep(killPoll) {
		if _, err := net.InterfaceByIndex(index); err != nil && len(modeRowsOn(t, index)) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s or its routes outlived the helper by %s", name, killGone)
		}
	}
}

func killSocket(t *testing.T) rtSocket {
	t.Helper()
	sock, err := routeSocket(runningKernel{})
	if err != nil {
		t.Fatalf("open a routing socket: %v", err)
	}
	t.Cleanup(func() { _ = sock.Close() })
	return sock
}

// killOut writes one unscoped route out of the interface at index, as another
// program's route there
func killOut(sock rtSocket, kind, index int, destination netip.Prefix) error {
	mask, ok := prefixMask(destination)
	if !ok {
		return fmt.Errorf("%s has no netmask", destination)
	}
	addrs := make([]route.Addr, unix.RTAX_MAX)
	addrs[unix.RTAX_DST] = routeAddr(destination.Addr())
	addrs[unix.RTAX_GATEWAY] = &route.LinkAddr{Index: index}
	addrs[unix.RTAX_NETMASK] = routeAddr(mask)
	return sock.WriteRoute(&route.RouteMessage{Type: kind, Flags: unix.RTF_UP | unix.RTF_STATIC, Index: index, Addrs: addrs})
}

// killSourceOf is an address of the family on the interface at index that is
// not link-local, invalid where it holds none
func killSourceOf(t *testing.T, index int, is4 bool) netip.Addr {
	t.Helper()
	for _, address := range addressesOf(t, index) {
		if address.Is4() == is4 && !address.IsLinkLocalUnicast() {
			return address
		}
	}
	return netip.Addr{}
}

// killBinding ties a send's socket to the uplink: bound to its address where
// source is valid, scoped to its index with IP_BOUND_IF or IPV6_BOUND_IF where
// index is nonzero, and neither where both are zero
type killBinding struct {
	source netip.Addr
	index  int
}

func (b killBinding) String() string {
	switch {
	case b.source.IsValid():
		return "bound to U's " + b.source.String()
	case b.index != 0:
		return fmt.Sprintf("scoped to U at %d", b.index)
	}
	return "unbound"
}

// killSend opens one socket of kind, ICMP, UDP or TCP, toward target, ties it
// as binding says, connects it and sends one echo or datagram where kind
// carries one. It is the error the connect or the send met, nil where the send
// went or a TCP connect had no answer within killConnectWait, and a socket
// that cannot be set up fails the test.
func killSend(t *testing.T, kind string, target netip.Addr, binding killBinding) error {
	t.Helper()
	v6 := target.Is6()
	domain, sockType, protocol, port := unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP, killPort
	level, option := unix.IPPROTO_IP, unix.IP_BOUND_IF
	if v6 {
		domain, level, option = unix.AF_INET6, unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF
	}
	payload := []byte("switch test")
	switch kind {
	case "ICMP":
		protocol, port, payload = unix.IPPROTO_ICMP, 0, killEcho(v6)
		if v6 {
			protocol = unix.IPPROTO_ICMPV6
		}
	case "TCP":
		sockType, protocol = unix.SOCK_STREAM, unix.IPPROTO_TCP
	}
	fd, err := unix.Socket(domain, sockType, protocol)
	if err != nil {
		t.Fatalf("open a %s socket toward %s: %v", kind, target, err)
	}
	defer unix.Close(fd)
	switch {
	case binding.source.IsValid():
		if err := unix.Bind(fd, killSockaddr(binding.source, 0)); err != nil {
			t.Fatalf("bind a %s socket to %s: %v", kind, binding.source, err)
		}
	case binding.index != 0:
		if err := unix.SetsockoptInt(fd, level, option, binding.index); err != nil {
			t.Fatalf("scope a %s socket to %d: %v", kind, binding.index, err)
		}
	}
	to := killSockaddr(target, port)
	if kind == "TCP" {
		return killConnect(t, fd, to)
	}
	if err := unix.Connect(fd, to); err != nil {
		return err
	}
	_, err = unix.Write(fd, payload)
	return err
}

// killConnect connects fd without blocking and waits killConnectWait for an
// answer, which a documentation target never gives
func killConnect(t *testing.T, fd int, to unix.Sockaddr) error {
	t.Helper()
	if err := unix.SetNonblock(fd, true); err != nil {
		t.Fatal(err)
	}
	if err := unix.Connect(fd, to); !errors.Is(err, unix.EINPROGRESS) {
		return err
	}
	ready := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
	n, err := unix.Poll(ready, int(killConnectWait.Milliseconds()))
	for errors.Is(err, unix.EINTR) {
		n, err = unix.Poll(ready, int(killConnectWait.Milliseconds()))
	}
	if err != nil {
		t.Fatalf("wait for a connect: %v", err)
	}
	if n == 0 {
		return nil
	}
	code, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
	if err != nil {
		t.Fatalf("read a connect's answer: %v", err)
	}
	if code != 0 {
		return unix.Errno(code)
	}
	return nil
}

// killPacketInfo sends one datagram as the underlay's shared socket does,
// unconnected with the packet info naming index
func killPacketInfo(target netip.Addr, index int) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	control := (&ipv4.ControlMessage{IfIndex: index}).Marshal()
	_, err = unix.SendmsgN(fd, []byte("switch test"), control, killSockaddr(target, killPort), 0)
	return err
}

func killSockaddr(address netip.Addr, port int) unix.Sockaddr {
	if address.Is4() {
		return &unix.SockaddrInet4{Addr: address.As4(), Port: port}
	}
	return &unix.SockaddrInet6{Addr: address.As16(), Port: port}
}

// killEcho is an ICMP or ICMPv6 echo request with no data. The kernel sums an
// ICMPv6 message itself.
func killEcho(v6 bool) []byte {
	echo := []byte{8, 0, 0, 0, 0x52, 0x33, 0, 1}
	if v6 {
		echo[0] = 128
		return echo
	}
	var sum uint32
	for i := 0; i < len(echo); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(echo[i:]))
	}
	for sum > 0xffff {
		sum = sum>>16 + sum&0xffff
	}
	binary.BigEndian.PutUint16(echo[2:], ^uint16(sum))
	return echo
}
