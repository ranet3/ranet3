// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel_test

import (
	"context"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/egress/egresstest"
	"ranet3.com/pkgs/ranet3/internal/netnstest"
	"ranet3.com/pkgs/ranet3/schema"
)

const (
	// debugSweep is a sweep no test outlasts, so a counter that moves after the
	// first pass moves without one
	debugSweep = time.Hour
	// debugBusySweep is a sweep short enough that one pass follows another
	// while a test reads, and debugPasses the passes such a test reads across,
	// each seen by a poll of heldPoll
	debugBusySweep = time.Millisecond
	debugPasses    = 20
	// debugReaders is how many goroutines read at once
	debugReaders = 2
)

// debugExit is the kernel exit translating 0.0.0.0/0 in a namespace of its own
// with sweep, whose uplink up0 routes 203.0.113.0/24 and whose loopback holds
// its mesh address, and the exit's debug read. Its Run is the caller's.
func debugExit(t *testing.T, sweep time.Duration) (exit egress.Exit, debug func() egress.ExitDebug, host *netnstest.Thread, mesh netip.Addr) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	host = netnstest.StartThread(t)
	mesh = netip.MustParseAddr("192.0.2.1")
	if err := host.Do(func() error {
		netlink, err := netnstest.OpenNetlink()
		if err != nil {
			return err
		}
		defer netlink.Close()
		kind := netnstest.Attr(unix.IFLA_LINKINFO, netnstest.Attr(unix.IFLA_INFO_KIND, netnstest.CString("dummy")))
		if err := netlink.Request(unix.RTM_NEWLINK, unix.NLM_F_CREATE|unix.NLM_F_EXCL, slices.Concat(netnstest.IfInfo(0, 0), netnstest.Attr(unix.IFLA_IFNAME, netnstest.CString("up0")), kind)); err != nil {
			return err
		}
		if err := netnstest.BringUp("up0"); err != nil {
			return err
		}
		if err := netlink.AddAddresses("up0", netip.MustParsePrefix("198.51.100.2/24")); err != nil {
			return err
		}
		if err := netlink.AddAddresses("lo", netip.PrefixFrom(mesh, 32)); err != nil {
			return err
		}
		up, err := net.InterfaceByName("up0")
		if err != nil {
			return err
		}
		return netlink.RouteVia(up.Index, netip.MustParsePrefix("203.0.113.0/24"), netip.Addr{})
	}); err != nil {
		t.Fatalf("make the uplink: %v", err)
	}
	cfg := egress.Egress{Advertise: []schema.Prefix{schema.MustPrefix("0.0.0.0/0")}, Sweep: schema.Duration(sweep)}
	exit = newKernelExit(t, egresstest.Host{Do: host.Do, TUN: "ranet0", Write: func([][]byte) {}, Mesh: []netip.Addr{mesh}}, cfg, egress.Hooks{})
	debugged, ok := exit.(interface{ Debug() egress.ExitDebug })
	if !ok {
		t.Fatal("the kernel exit answers no debug read")
	}
	return exit, debugged.Debug, host, mesh
}

// runDebugExit runs exit until the test ends or stop is called, which waits
// for Run to return and reports its error, and waits for its first pass
func runDebugExit(t *testing.T, exit egress.Exit) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- exit.Run(ctx) }()
	stop = sync.OnceFunc(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("stop the exit: %v", err)
		}
	})
	t.Cleanup(stop)
	for deadline := time.Now().Add(heldWait); exit.Status().PassAt.IsZero(); time.Sleep(heldPoll) {
		if time.Now().After(deadline) {
			t.Fatalf("no pass within %s", heldWait)
		}
	}
	return stop
}

// awaitPasses waits for debugPasses passes of exit to follow the last one,
// each with no error
func awaitPasses(t *testing.T, exit egress.Exit) {
	t.Helper()
	passes, last := 0, exit.Status().PassAt
	for deadline := time.Now().Add(heldWait); passes < debugPasses && time.Now().Before(deadline); time.Sleep(heldPoll) {
		status := exit.Status()
		if status.Err != "" {
			t.Errorf("a pass failed: %s", status.Err)
		}
		if !status.PassAt.Equal(last) {
			passes, last = passes+1, status.PassAt
		}
	}
	if passes < debugPasses {
		t.Errorf("%d passes ran within %s, want %d", passes, heldWait, debugPasses)
	}
}

// readDebug calls debug from debugReaders goroutines, each in a loop until
// the returned function is called, which answers each read error by the reads
// that answered it, no error under ""
func readDebug(debug func() egress.ExitDebug) (stop func() map[string]int) {
	var mu sync.Mutex
	errs := map[string]int{}
	done := make(chan struct{})
	var readers sync.WaitGroup
	for range debugReaders {
		readers.Go(func() {
			for {
				select {
				case <-done:
					return
				default:
				}
				read := debug()
				mu.Lock()
				errs[read.ReadErr]++
				mu.Unlock()
			}
		})
	}
	return func() map[string]int {
		close(done)
		readers.Wait()
		return errs
	}
}

// A datagram this host sends from its mesh address out of its uplink crosses
// the rule translating that address, and a debug read finds the rule's
// counter moved while the last pass, and Status with it, still reads none
func TestDebugReadsARulesCounterWithoutAPass(t *testing.T) {
	exit, debug, host, mesh := debugExit(t, debugSweep)
	runDebugExit(t, exit)
	pass := exit.Status()
	if err := host.Do(func() error {
		conn, err := net.DialUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(mesh, 0)), net.UDPAddrFromAddrPort(netip.MustParseAddrPort("203.0.113.9:9")))
		if err != nil {
			return err
		}
		defer conn.Close()
		_, err = conn.Write([]byte("a flow"))
		return err
	}); err != nil {
		t.Fatalf("send from the mesh address: %v", err)
	}
	read := debug()
	spec := "local via ranet0 ipv4 from 192.0.2.1/32 masquerade"
	at := slices.IndexFunc(read.Rules, func(rule egress.RuleReading) bool { return rule.Spec == spec })
	if read.ReadErr != "" || at < 0 || !read.Rules[at].Held || read.Rules[at].Counter != "flows" || read.Rules[at].Packets != 1 {
		t.Fatalf("the debug read holds %q and the rules %+v, want %s held with 1 flow", read.ReadErr, read.Rules, spec)
	}
	if now := exit.Status(); !now.PassAt.Equal(pass.PassAt) || now.Rules == nil || now.Rules.Flows != 0 {
		t.Fatalf("a pass ran or counted the flow: %v then %v, %+v", pass.PassAt, now.PassAt, now.Rules)
	}
}

// Two readers read the exit's rules at once while one pass follows another,
// each read and each pass with no error: a read takes no socket a pass writes
// through, and no reader the socket another reads through
func TestDebugReadsBesidePassesAndAnotherReader(t *testing.T) {
	exit, debug, _, _ := debugExit(t, debugBusySweep)
	runDebugExit(t, exit)
	stop := readDebug(debug)
	awaitPasses(t, exit)
	if errs := stop(); errs[""] == 0 || len(errs) != 1 {
		t.Errorf("the reads answered %v by their read error, want every one read", errs)
	}
}

// Reads go on while the exit stops and after Run has returned, which closed
// the backend's sockets: each reads the rules or answers the error a read
// after the stop answers, which names no descriptor Close released
func TestDebugReadsAcrossTheExitsStop(t *testing.T) {
	exit, debug, _, _ := debugExit(t, debugBusySweep)
	stopExit := runDebugExit(t, exit)
	stopReads := readDebug(debug)
	awaitPasses(t, exit)
	stopExit()
	errs := stopReads()
	after := debug()
	if after.ReadErr == "" || strings.Contains(after.ReadErr, syscall.EBADF.Error()) {
		t.Fatalf("a debug read after Run returned answers %q, want the error of a stopped exit", after.ReadErr)
	}
	for err, reads := range errs {
		if err != "" && err != after.ReadErr {
			t.Errorf("%d reads across the stop answered %q, want the rules or %q", reads, err, after.ReadErr)
		}
	}
}
