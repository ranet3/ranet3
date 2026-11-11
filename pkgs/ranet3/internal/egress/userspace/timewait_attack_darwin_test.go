// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package userspace

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/egress"
)

const (
	// the window leaves half its ports to the host while the exit holds its half
	timewaitAttackWindow = 2048
	// the run spans a slot's lifetime and the refill after its release
	timewaitAttackRun = 60 * time.Second
	// the pause limits the load of the host's independent connects
	timewaitAttackProbeEvery = 250 * time.Millisecond
	// pacing bounds refused SYN traffic without slowing admitted connections
	timewaitAttackRefusalPause = time.Millisecond
	// the control limits how long the unbounded exit can starve the host
	timewaitAttackControl = 8 * time.Second
	// the finite sample keeps starvation observations inside the short control
	timewaitAttackControlProbes = 5
	// the backstop restores even if the test's own progress stops
	timewaitAttackRestoreAfter = 120 * time.Second
	// the detached restore outlives the in-process backstop and its writes
	timewaitAttackOutsideWait = timewaitAttackRestoreAfter + timewaitOutsideMargin
	// this opt-in isolates a host-wide setting change from other test runs
	timewaitAttackEnvironment = "RANET3_TIMEWAIT_ATTACK"
	// the original range must leave ample room once the control restores it
	timewaitAttackRangeFactor = 4
	// spare descriptors leave room for the listener, relay and host probes
	timewaitAttackDescriptorSlack = 512
	// a host connect cannot consume the remaining control stretch indefinitely
	timewaitAttackProbeWait = 2 * time.Second
	// the control samples starvation without extending it through a long pause
	timewaitAttackControlGap = 100 * time.Millisecond
	// the pass leaves time for probes and restoration inside the control bound
	timewaitAttackControlTail = 3 * time.Second
	// cleanup and the control share the time outside the bounded attack
	timewaitAttackExtra = 25 * time.Second
	// each restoration write has its own allowance even if its peer fails
	timewaitAttackWriteWait = time.Second
	// work stops early enough to attempt both restoration writes before the cap
	timewaitAttackRestoreBudget = 2 * timewaitAttackWriteWait
	// table reads observe the window without bind probes that hasten collection
	timewaitAttackTableEvery = time.Second
	// progress logs do not put per-connection output on the attack's path
	timewaitAttackReportEvery = 5 * time.Second
	// a stopped exit must leave no attack socket before the control starts
	timewaitAttackDrainWait = 5 * time.Second
	// the registrar gets an extra pass after the exit's reservation margin
	timewaitAttackSettleSlack = time.Second
)

// an occupied host permits a skip, unlike a failed or blind table read
var errTimewaitAttackNoWindow = errors.New("no unoccupied window exists in the automatic range")

// counts retain no address or port belonging to another program
type timewaitAttackCounts struct {
	rows, timewait, other, free int
}

// concurrent readers publish errors as well as counts so a lost sample cannot hide a failure
type timewaitAttackReadings struct {
	counts             timewaitAttackCounts
	maximum            int
	good, bad          uint64
	errProbe, errTable error
	failureCounts      timewaitAttackCounts
	errEvidence        error
	errRepeat          error
}

// the monitor owns only the two independent observations, never the attack worker
type timewaitAttackMonitor struct {
	mu       sync.Mutex
	readings timewaitAttackReadings
	cancel   context.CancelFunc
	ready    chan struct{}
	workers  sync.WaitGroup
}

// the test asserts that a leaf-first attack leaves the host able to connect only with the bound.
// a detached process restores the range even if this process dies or stays stopped
func TestHostPortBoundPreservesUnboundConnectsUnderALeafFirstAttack(t *testing.T) {
	if _, set := os.LookupEnv(timewaitAttackEnvironment); !set {
		t.Skipf("%s is unset. Set it to permit a temporary host-wide port range change", timewaitAttackEnvironment)
	}
	if os.Geteuid() != 0 {
		t.Skip("root is required to narrow and restore the host's automatic port range")
	}
	timewaitCheckPendingRestore(t)
	first, err := unix.SysctlUint32(timewaitRangeFirst)
	if err != nil {
		t.Fatalf("setup: cannot read the automatic range's first port: %v", err)
	}
	last, err := unix.SysctlUint32(timewaitRangeLast)
	if err != nil {
		t.Fatalf("setup: cannot read the automatic range's last port: %v", err)
	}
	low, high := int(min(first, last)), int(max(first, last))
	if low < 1 || high > 65535 {
		t.Fatalf("setup: invalid automatic range %d..%d", first, last)
	}
	if high-low+1 < timewaitMinimumRange {
		t.Fatalf("setup: automatic range %d..%d needs at least %d ports to exclude another interrupted test's narrowed range", first, last, timewaitMinimumRange)
	}
	if high-low+1 < timewaitAttackRangeFactor*timewaitAttackWindow {
		t.Skipf("the automatic range must hold at least %d ports", timewaitAttackRangeFactor*timewaitAttackWindow)
	}
	msl, err := xnuMSL()
	if err != nil {
		t.Fatalf("setup: cannot read the MSL: %v", err)
	}
	if msl > timewaitMaxMSL {
		t.Skipf("an MSL at most %s is required, got %s", timewaitMaxMSL, msl)
	}
	bound := timewaitAttackWindow / 2
	var descriptors unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &descriptors); err != nil {
		t.Fatalf("setup: cannot read the descriptor limit: %v", err)
	}
	if descriptors.Cur < uint64(bound+timewaitAttackDescriptorSlack) {
		t.Skipf("the soft descriptor limit is %d, need at least %d", descriptors.Cur, bound+timewaitAttackDescriptorSlack)
	}
	loopback := netip.AddrFrom4([4]byte{127, 0, 0, 1})
	server := tcpServer(t, loopback, readsToTheEnd)
	probeServer := tcpServer(t, loopback, readsToTheEnd)
	rows, err := timewaitAttackRows(context.Background())
	if err != nil {
		t.Fatalf("setup: the host's TCP table is not readable: %v", err)
	}
	base, err := timewaitAttackChooseWindow(rows, server, probeServer, low, high)
	if err != nil {
		if errors.Is(err, errTimewaitAttackNoWindow) {
			t.Skipf("attack cannot start: %v", err)
		}
		t.Fatalf("setup: attack cannot start: %v", err)
	}
	t.Logf("attack: original range %d..%d, window %d..%d, MSL %s, bound %d", first, last, base, base+timewaitAttackWindow-1, msl, bound)

	verdict := "undecided: setup did not complete"
	t.Cleanup(func() {
		if t.Failed() && verdict == "the bound held under the attack and the control starved the window" {
			verdict = "undecided: setup cleanup failed"
		}
		t.Logf("attack: verdict: %s", verdict)
	})
	narrow, restore := timewaitAttackArmRestore(t, int(first), int(last))
	narrowedAt := time.Now()
	workDeadline := narrowedAt.Add(timewaitAttackRun + timewaitAttackExtra - timewaitAttackRestoreBudget)
	ctx, stopWatch := timewaitAttackWatch(context.Background(), workDeadline, restore)
	defer func() {
		if err := restore(false); err != nil {
			verdict = "undecided: restoring the automatic range failed"
			t.Errorf("attack: restore: %v", err)
		}
		stopWatch()
	}()
	fail := func(class, format string, args ...any) {
		t.Helper()
		verdict = class + ": " + fmt.Sprintf(format, args...)
		if err := restore(false); err != nil {
			t.Errorf("attack: restore: %v", err)
		}
		t.Fatalf("attack: %s", verdict)
	}
	check := func() {
		if ctx.Err() != nil {
			fail("undecided", "setup: narrowed stretch reaches its %s bound including restoration", timewaitAttackRun+timewaitAttackExtra)
		}
	}
	if err := narrow(base); err != nil {
		fail("undecided", "setup: narrowing the automatic range: %v", err)
	}
	check()

	h := timewaitAttackHarness(t, true)
	status := h.x.Status()
	host := status.Flows.Host
	if host == nil || host.Bound != bound {
		fail("undecided", "setup: the exit did not read the narrowed range, host hold %v, want bound %d", host, bound)
	}
	if status.Flows.Limits.Flows < 2*timewaitAttackWindow || status.FlowsPerSource <= bound {
		fail("undecided", "setup: Flows %d and source share %d do not isolate the host bound", status.Flows.Limits.Flows, status.FlowsPerSource)
	}
	t.Logf("attack: with bound starts at %s, Flows %d, source share %d, Held %d, Ports %d, Bound %d", time.Since(narrowedAt), status.Flows.Limits.Flows, status.FlowsPerSource, host.Held, host.Ports, host.Bound)
	// held slots can outlive their TIME_WAIT rows by a sweep and the margin
	func() {
		start := time.Now()
		end := start.Add(timewaitAttackRun)
		phaseCtx, cancel := context.WithDeadline(ctx, end.Add(exitWait))
		defer cancel()
		timewaitAttackDialDeadline(h, phaseCtx)
		monitor := timewaitAttackStartMonitor(t, phaseCtx, server, probeServer, base, start)
		var syns, admitted, refused uint64
		ended := false
		defer func() {
			monitor.stop()
			if !ended {
				t.Logf("attack: with bound ends at %s, SYNs %d, admitted %d, refused %d, refusal rate %.1f/s", time.Since(narrowedAt), syns, admitted, refused, float64(refused)/time.Since(start).Seconds())
			}
		}()
		var firstSlot time.Time
		lastSweep, lastReport := start, start
		reached, fell, rose, lowHeld := false, false, false, 0
		observe := func() {
			host = h.x.Status().Flows.Host
			if host == nil || host.Bound != bound {
				fail("undecided", "setup: the exit's host bound changed during the attack")
			}
			reached = reached || host.Ports == bound
			rose = rose || fell && host.Held > lowHeld
		}
		pump := func() {
			check()
			reading := monitor.snapshot()
			if reading.maximum > bound+1 {
				fail("the bound did not hold", "the table shows %d attack rows, above bound %d plus one", reading.maximum, bound)
			}
			if reading.errTable != nil {
				fail("undecided", "setup: read the attack table: %v", reading.errTable)
			}
			if reading.errProbe != nil {
				firstOutcome := timewaitError(reading.errProbe)
				if !errors.Is(reading.errProbe, unix.EADDRNOTAVAIL) {
					fail("undecided", "host probe failed with %s, not port starvation", firstOutcome)
				}
				// block without sending SYNs until evidence is stored or restoration is due
				select {
				case <-monitor.ready:
				case <-ctx.Done():
				}
				check()
				reading = monitor.snapshot()
				counts := reading.failureCounts
				repeatOutcome := timewaitError(reading.errRepeat)
				if reading.errEvidence != nil {
					fail("undecided", "setup: read evidence for probe %s: %v, repeat probe %s", firstOutcome, reading.errEvidence, repeatOutcome)
				}
				switch {
				case counts.rows > bound:
					fail("the bound did not hold", "probe %s, attack rows %d exceed bound %d, repeat probe %s", firstOutcome, counts.rows, bound, repeatOutcome)
				case counts.free == 0:
					fail("undecided", "setup: other programs filled the free half, probe %s, attack rows %d, other rows %d, free ports %d, repeat probe %s", firstOutcome, counts.rows, counts.other, counts.free, repeatOutcome)
				case errors.Is(reading.errRepeat, unix.EADDRNOTAVAIL):
					fail("the claim failed against the margin", "probe %s and repeat probe %s with attack rows %d within bound %d, other rows %d and %d ports without a table row", firstOutcome, repeatOutcome, counts.rows, bound, counts.other, counts.free)
				case reading.errRepeat == nil:
					fail("undecided", "probe %s was momentary and the repeat succeeded, attack rows %d, other rows %d, free ports %d", firstOutcome, counts.rows, counts.other, counts.free)
				default:
					fail("undecided", "probe %s followed by repeat probe %s, attack rows %d, other rows %d, free ports %d", firstOutcome, repeatOutcome, counts.rows, counts.other, counts.free)
				}
			}
			now := time.Now()
			if now.Sub(lastSweep) >= mappingSweep {
				observe()
				before := host.Held
				h.advance(now.Sub(lastSweep))
				lastSweep = now
				observe()
				if !fell && !firstSlot.IsZero() && now.Sub(firstSlot) >= 2*msl+reservationMargin && host.Held < before {
					fell, lowHeld = true, host.Held
				}
			}
			if now.Sub(lastReport) >= timewaitAttackReportEvery {
				observe()
				t.Logf("attack: at %s, SYNs %d, admitted %d, refused %d, Held %d, Ports %d, Bound %d, attack rows %d, TIME_WAIT %d, other rows %d, probes succeeded %d, failed %d", now.Sub(start), syns, admitted, refused, host.Held, host.Ports, host.Bound, reading.counts.rows, reading.counts.timewait, reading.counts.other, reading.good, reading.bad)
				lastReport = now
			}
		}
		for time.Now().Before(end) {
			pump()
			leaf := netip.AddrPortFrom(leaf4, uint16(base+int(syns%timewaitAttackWindow)))
			syns++
			reason, err := timewaitAttackConnection(t, phaseCtx, h, leaf, server, pump)
			if err != nil {
				fail("undecided", "setup: attack connection failed: %v", err)
			}
			if reason != "" {
				// the answer lane records separately from packet batches, so discard its copies
				h.mesh.mu.Lock()
				clear(h.mesh.answers)
				h.mesh.answers = h.mesh.answers[:0]
				h.mesh.mu.Unlock()
				refused++
				if reason != reasonHostPorts {
					fail("undecided", "setup: SYN refused for %q rather than the host-port bound", reason)
				}
				if !reached {
					observe()
				}
				if err := timewaitWait(phaseCtx, time.Now().Add(timewaitAttackRefusalPause)); err != nil {
					fail("undecided", "setup: refusal pacing reaches the phase deadline: %v", err)
				}
				continue
			}
			admitted++
			if firstSlot.IsZero() {
				firstSlot = time.Now()
			}
			if fell && !rose {
				observe()
			}
		}
		monitor.stop()
		pump()
		observe()
		reading := monitor.snapshot()
		t.Logf("attack: with bound ends at %s, SYNs %d, admitted %d, refused %d, refusal rate %.1f/s, Held %d, Ports %d, Bound %d, probes succeeded %d, failed %d, maximum attack rows %d", time.Since(narrowedAt), syns, admitted, refused, float64(refused)/time.Since(start).Seconds(), host.Held, host.Ports, host.Bound, reading.good, reading.bad, reading.maximum)
		ended = true
		// independent connects are the claim, not an inference from the held count
		if reading.good == 0 || reading.bad != 0 {
			fail("undecided", "setup: the bounded run has no clean series of successful host probes")
		}
		// reaching the limit and refusing only there shows the attack exercised the bound
		if refused == 0 || !reached {
			fail("undecided", "setup: the attack did not reach and exercise the host-port bound")
		}
		for reason, count := range h.refusals() {
			if count != 0 && reason != reasonHostPorts {
				fail("undecided", "setup: refusal count %d has reason %q", count, reason)
			}
		}
		// the table independently bounds host sockets even when status counts other phases
		if reading.maximum > bound+1 {
			fail("the bound did not hold", "maximum attack rows %d exceed bound %d plus one", reading.maximum, bound)
		}
		// a release followed by a refill proves the sweep and margin act during the run
		if !fell || !rose {
			fail("undecided", "setup: held slots did not fall and rise after their first lifetime, fell %t, rose %t", fell, rose)
		}
	}()
	if err := timewaitAttackClose(ctx, h); err != nil {
		fail("undecided", "setup: close the bounded exit: %v", err)
	}
	drainCtx, stopDrain := context.WithTimeout(ctx, timewaitAttackDrainWait)
	for {
		counts, err := timewaitAttackTable(drainCtx, server, probeServer, base)
		if err != nil {
			stopDrain()
			fail("undecided", "setup: read the bounded exit's drain: %v", err)
		}
		if counts.rows == 0 {
			break
		}
		if err := timewaitWait(drainCtx, time.Now().Add(timewaitAttackTableEvery)); err != nil {
			stopDrain()
			fail("undecided", "setup: %d attack rows remain after the exit's close", counts.rows)
		}
	}
	stopDrain()
	if err := timewaitWait(ctx, time.Now().Add(reservationMargin+timewaitAttackSettleSlack)); err != nil {
		fail("undecided", "setup: no time for the post-close margin: %v", err)
	}
	if err := timewaitAttackProbe(ctx, probeServer); err != nil {
		fail("undecided", "setup: host probe after the bounded exit's close: %s", timewaitError(err))
	}
	check()

	control := timewaitAttackHarness(t, false)
	if control.x.Status().Flows.Host != nil {
		fail("undecided", "setup: the control still has a host hold")
	}
	controlStart := time.Now()
	controlEnded := false
	defer func() {
		if !controlEnded {
			t.Logf("attack: control ends at %s", time.Since(narrowedAt))
		}
	}()
	t.Logf("attack: control starts at %s", controlStart.Sub(narrowedAt))
	controlCtx, stopControl := timewaitAttackWatch(ctx, controlStart.Add(timewaitAttackControl-timewaitAttackRestoreBudget), restore)
	defer stopControl()
	passCtx, stopPass := context.WithDeadline(controlCtx, controlStart.Add(timewaitAttackControl-timewaitAttackControlTail))
	timewaitAttackDialDeadline(control, passCtx)
	attempted, completed, failed := 0, 0, 0
	for i := 0; i < timewaitAttackWindow && passCtx.Err() == nil; i++ {
		check()
		attempted++
		reason, err := timewaitAttackConnection(t, passCtx, control, netip.AddrPortFrom(leaf4, uint16(base+i)), server, check)
		if reason != "" || err != nil {
			failed++
		} else {
			completed++
		}
	}
	stopPass()
	if err := timewaitAttackClose(controlCtx, control); err != nil {
		fail("undecided", "setup: close the control exit: %v", err)
	}
	starved := false
	for i := range timewaitAttackControlProbes {
		if controlCtx.Err() != nil {
			fail("undecided", "setup: the control reaches its %s bound including restoration", timewaitAttackControl)
		}
		err := timewaitAttackProbe(controlCtx, probeServer)
		t.Logf("attack: control probe %d at %s: %s", i+1, time.Since(controlStart), timewaitError(err))
		starved = starved || errors.Is(err, unix.EADDRNOTAVAIL)
		if i+1 < timewaitAttackControlProbes {
			if err := timewaitWait(controlCtx, time.Now().Add(timewaitAttackControlGap)); err != nil {
				fail("undecided", "setup: control probe spacing reaches its deadline")
			}
		}
	}
	counts, err := timewaitAttackTable(controlCtx, server, probeServer, base)
	if err != nil {
		fail("undecided", "setup: read the control table: %v", err)
	}
	t.Logf("attack: control table: TIME_WAIT %d, other rows %d, free ports %d", counts.timewait, counts.other, counts.free)
	if controlCtx.Err() != nil {
		fail("undecided", "setup: the control exhausted its observation time before restoration")
	}
	if err := restore(false); err != nil {
		fail("undecided", "setup: restore after the control: %v", err)
	}
	restoredAt := time.Now()
	stopControl()
	if restoredAt.Sub(controlStart) > timewaitAttackControl || restoredAt.Sub(narrowedAt) > timewaitAttackRun+timewaitAttackExtra {
		fail("undecided", "setup: control or narrowed-stretch deadline passed during restoration")
	}
	t.Logf("attack: control ends at %s, attempted %d, completed %d, failed %d, TIME_WAIT left under the restored range %d", restoredAt.Sub(narrowedAt), attempted, completed, failed, counts.timewait)
	controlEnded = true
	if err := timewaitAttackProbe(context.Background(), probeServer); err != nil {
		fail("undecided", "setup: host probe after restoring the range: %s", timewaitError(err))
	}
	t.Log("attack: host probe after restoring the range: success")
	// starvation in the control establishes that the bounded attack could have harmed the host
	if !starved {
		fail("undecided", "the control showed no EADDRNOTAVAIL, with %d window ports free in the table", counts.free)
	}
	verdict = "the bound held under the attack and the control starved the window"
}

// gaps between occupied endpoints find a window without scanning or binding candidate ports
func timewaitAttackChooseWindow(rows [][]string, server, probe netip.AddrPort, low, high int) (int, error) {
	var occupied []int
	listens, probes := false, false
	serverEnd, probeEnd := tableEnd(server), tableEnd(probe)
	for _, row := range rows {
		listens = listens || row[3] == serverEnd && row[5] == "LISTEN"
		probes = probes || row[3] == probeEnd && row[5] == "LISTEN"
		port, err := timewaitTablePort(row[3])
		if err != nil {
			return 0, err
		}
		if port >= low && port <= high {
			occupied = append(occupied, port)
		}
	}
	if !listens || !probes {
		return 0, errors.New("the host's TCP table is not readable by this user, its own listeners are missing")
	}
	slices.Sort(occupied)
	base := low
	for _, port := range occupied {
		if port-base >= timewaitAttackWindow {
			return base, nil
		}
		base = max(base, port+1)
	}
	if high-base+1 >= timewaitAttackWindow {
		return base, nil
	}
	return 0, errTimewaitAttackNoWindow
}

// callers share the table parser but retain their own deadline and skip or failure policy
func timewaitAttackRows(parent context.Context) ([][]string, error) {
	ctx, cancel := context.WithTimeout(parent, netstatWait)
	defer cancel()
	rows, _, err := timewaitTableRows(ctx)
	return rows, err
}

// the same snapshot proves visibility and counts unique occupied ports as well as socket rows
func timewaitAttackTable(parent context.Context, server, probe netip.AddrPort, base int) (timewaitAttackCounts, error) {
	var counts timewaitAttackCounts
	rows, err := timewaitAttackRows(parent)
	if err != nil {
		return counts, err
	}
	var occupied [timewaitAttackWindow]bool
	listens, probes := false, false
	serverEnd, probeEnd := tableEnd(server), tableEnd(probe)
	for _, fields := range rows {
		listens = listens || fields[3] == serverEnd && fields[5] == "LISTEN"
		probes = probes || fields[3] == probeEnd && fields[5] == "LISTEN"
		port, err := timewaitTablePort(fields[3])
		if err != nil {
			return counts, err
		}
		if port < base || port >= base+timewaitAttackWindow {
			continue
		}
		occupied[port-base] = true
		if fields[4] == serverEnd {
			counts.rows++
			if fields[5] == "TIME_WAIT" {
				counts.timewait++
			}
		} else {
			counts.other++
		}
	}
	if !listens || !probes {
		return counts, errors.New("the host TCP table went blind, an own listener is missing")
	}
	for _, used := range occupied {
		if !used {
			counts.free++
		}
	}
	return counts, nil
}

// successful probes reset their sockets so the observer leaves no TIME_WAIT behind
func timewaitAttackProbe(parent context.Context, server netip.AddrPort) error {
	ctx, cancel := context.WithTimeout(parent, timewaitAttackProbeWait)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp4", server.String())
	if err != nil {
		return err
	}
	defer conn.Close()
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return errors.New("the probe did not return a TCP socket")
	}
	return tcp.SetLinger(0)
}

// source and flow limits leave only the host-port bound able to refuse a sequential SYN
func timewaitAttackHarness(t *testing.T, bounded bool) *relayHarness {
	t.Helper()
	h := newRelayHarness(t, func(rt *Runtime, cfg *egress.Egress) {
		cfg.FlowsPerSource = timewaitAttackWindow + 1
		rt.Limits.Flows = 2 * timewaitAttackWindow
		rt.Platform.hostSockets = nil
		if bounded {
			rt.Platform.hostSockets = xnuHostSockets()
		}
	})
	allowLoopback(t, h.x.stack)
	if h.x.tcp.holds != nil {
		// holds born between sweeps must not inherit the harness's last tick
		h.x.tcp.holds.now = time.Now
	}
	return h
}

// the relay's own dial inherits the phase deadline, not just the packet observer's wait
func timewaitAttackDialDeadline(h *relayHarness, ctx context.Context) {
	h.x.tcp.mu.Lock()
	defer h.x.tcp.mu.Unlock()
	ctx, cancel := context.WithCancel(ctx)
	previousCancel := h.x.tcp.cancel
	h.x.tcp.ctx = ctx
	h.x.tcp.cancel = func() {
		cancel()
		previousCancel()
	}
}

// failed control connections return to the caller instead of ending the pass through the window
func timewaitAttackConnection(t *testing.T, parent context.Context, h *relayHarness, leaf, server netip.AddrPort, pump func()) (string, error) {
	t.Helper()
	if reason := h.syn(t, leaf, server); reason != "" {
		h.drainLaid()
		return reason, nil
	}
	ctx, cancel := context.WithTimeout(parent, exitWait)
	defer cancel()
	wait := func(syn bool) (sent, error) {
		for ctx.Err() == nil {
			pump()
			if pkt := h.x.link.poll(); pkt != nil {
				view := pkt.ToView()
				p, ok := parse(view.AsSlice())
				view.Release()
				h.x.link.release(pkt)
				if ok && p.protocol == protoTCP && netip.AddrPortFrom(p.dst, p.dstPort) == leaf {
					if p.flags&tcpRST != 0 {
						return sent{}, errors.New("the relay reset the leaf connection")
					}
					if syn && p.flags == tcpSYN|tcpACK || !syn && p.flags&tcpFIN != 0 {
						return p, nil
					}
				}
			}
			if syn && h.x.tcp.held()[1] == 0 {
				return sent{}, errors.New("the relay dial ended without a handshake")
			}
			runtime.Gosched()
		}
		return sent{}, ctx.Err()
	}
	p, err := wait(true)
	if err == nil {
		c := leafConn{leaf: leaf, server: server, seq: leafISN + 1, ack: p.seq + 1}
		if !h.x.link.deliver(tcpSegment(leaf, server, c.seq, c.ack, tcpACK, nil)) || !h.x.link.deliver(tcpSegment(leaf, server, c.seq, c.ack, tcpACK|tcpFIN, nil)) {
			err = errors.New("the link refused the leaf's handshake or FIN")
		} else {
			c.seq++
			p, err = wait(false)
			if err == nil && !h.x.link.deliver(tcpSegment(leaf, server, c.seq, p.seq+uint32(p.payload)+1, tcpACK, nil)) {
				err = errors.New("the link refused the leaf's final ACK")
			}
		}
	}
	for h.x.tcp.held()[1] != 0 && ctx.Err() == nil {
		pump()
		runtime.Gosched()
	}
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	return "", err
}

// close shares the caller's deadline so cleanup cannot keep the window pinned through a control timeout
func timewaitAttackClose(parent context.Context, h *relayHarness) error {
	ctx, cancel := context.WithTimeout(parent, exitWait)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- h.x.Close() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// the probe and table readers run independently so a slow table command cannot postpone a host probe
func timewaitAttackStartMonitor(t *testing.T, parent context.Context, server, probe netip.AddrPort, base int, start time.Time) *timewaitAttackMonitor {
	t.Helper()
	ctx, cancel := context.WithCancel(parent)
	m := &timewaitAttackMonitor{cancel: cancel, ready: make(chan struct{})}
	m.workers.Add(2)
	go func() {
		defer m.workers.Done()
		// every return wakes the worker, including the final pump after monitor.stop
		defer close(m.ready)
		for ctx.Err() == nil {
			err := timewaitAttackProbe(ctx, probe)
			if ctx.Err() != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
				return
			}
			m.mu.Lock()
			if err == nil {
				m.readings.good++
			} else {
				m.readings.bad++
				m.readings.errProbe = err
			}
			m.mu.Unlock()
			if errors.Is(err, unix.EADDRNOTAVAIL) {
				counts, errTable := timewaitAttackTable(ctx, server, probe, base)
				errRepeat := timewaitAttackProbe(ctx, probe)
				m.mu.Lock()
				m.readings.failureCounts = counts
				m.readings.errEvidence = errTable
				m.readings.errRepeat = errRepeat
				m.mu.Unlock()
			}
			if err != nil || timewaitWait(ctx, time.Now().Add(timewaitAttackProbeEvery)) != nil {
				return
			}
		}
	}()
	go func() {
		defer m.workers.Done()
		ticker := time.NewTicker(timewaitAttackTableEvery)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			counts, err := timewaitAttackTable(ctx, server, probe, base)
			if ctx.Err() != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
				return
			}
			m.mu.Lock()
			m.readings.counts, m.readings.errTable = counts, err
			m.readings.maximum = max(m.readings.maximum, counts.rows)
			m.mu.Unlock()
			if err != nil {
				return
			}
			t.Logf("attack: table at %s: attack rows %d, TIME_WAIT %d, other rows %d", time.Since(start), counts.rows, counts.timewait, counts.other)
		}
	}()
	return m
}

// a snapshot keeps counters and the first failed observation consistent across the worker's reads
func (m *timewaitAttackMonitor) snapshot() timewaitAttackReadings {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.readings
}

// cancellation interrupts host waits, and joining prevents observations after the phase ends
func (m *timewaitAttackMonitor) stop() {
	m.cancel()
	m.workers.Wait()
}

// a stalled setting write cannot consume its peer's allowance, and readback catches clamping
func timewaitAttackWrite(name string, value int) error {
	ctx, cancel := context.WithTimeout(context.Background(), timewaitAttackWriteWait)
	defer cancel()
	if err := exec.CommandContext(ctx, "/usr/sbin/sysctl", "-w", fmt.Sprintf("%s=%d", name, value)).Run(); err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	got, err := unix.SysctlUint32(name)
	if err != nil {
		return fmt.Errorf("read back %s: %w", name, err)
	}
	if got != uint32(value) {
		return fmt.Errorf("read back %s: got %d, want %d", name, got, value)
	}
	return nil
}

// narrowing and restoration share a lock so a signal cannot leave a late narrowing write behind
func timewaitAttackArmRestore(t *testing.T, first, last int) (func(int) error, func(bool) error) {
	t.Helper()
	timewaitCheckDeadline(t, timewaitAttackRestoreAfter, timewaitAttackRestoreBudget)
	restoreBy := time.Now().Add(timewaitAttackRestoreAfter)
	outside := timewaitStartOutsideRestore(t, first, last, timewaitAttackOutsideWait)
	var mu sync.Mutex
	finished := false
	restore := func(stderr bool) error {
		mu.Lock()
		defer mu.Unlock()
		finished = true
		return outside.finish(t, stderr, errors.Join(timewaitAttackWrite(timewaitRangeFirst, first), timewaitAttackWrite(timewaitRangeLast, last)))
	}
	narrow := func(base int) error {
		timewaitCheckDeadline(t, timewaitAttackRestoreAfter, timewaitAttackRestoreBudget)
		mu.Lock()
		defer mu.Unlock()
		if finished || !time.Now().Before(restoreBy) {
			return errors.New("restoration already starts")
		}
		a, b := base, base+timewaitAttackWindow-1
		if first > last {
			a, b = b, a
		}
		if err := outside.check(); err != nil {
			return err
		}
		if err := timewaitAttackWrite(timewaitRangeFirst, a); err != nil {
			return err
		}
		if !time.Now().Before(restoreBy) {
			return errors.New("restoration bound passes before narrowing completes")
		}
		return timewaitAttackWrite(timewaitRangeLast, b)
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, unix.SIGINT, unix.SIGTERM, unix.SIGHUP, unix.SIGQUIT)
	timer := time.NewTimer(time.Until(restoreBy))
	stop, done := make(chan struct{}), make(chan struct{})
	t.Cleanup(func() {
		if err := restore(false); err != nil {
			t.Errorf("attack: restore automatic range: %v", err)
		}
		timer.Stop()
		signal.Stop(signals)
		close(stop)
		<-done
	})
	go func() {
		defer close(done)
		var reason string
		var received os.Signal
		select {
		case received = <-signals:
			reason = received.String()
		case <-timer.C:
			reason = "restoration backstop"
		case <-stop:
			return
		}
		err := restore(true)
		fmt.Fprintf(os.Stderr, "attack: verdict: undecided: %s, restore automatic range: %v\n", reason, err)
		timewaitExitSignal(received)
	}()
	return narrow, restore
}

// deadline restoration runs independently of the worker, leaving room for both sysctl writes
func timewaitAttackWatch(parent context.Context, deadline time.Time, restore func(bool) error) (context.Context, func()) {
	ctx, cancel := context.WithDeadline(parent, deadline)
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		select {
		case <-ctx.Done():
			if err := restore(true); err != nil {
				fmt.Fprintf(os.Stderr, "attack: deadline restore failed: %v\n", err)
			}
		case <-stop:
		}
	}()
	return ctx, sync.OnceFunc(func() {
		close(stop)
		<-done
		cancel()
	})
}
