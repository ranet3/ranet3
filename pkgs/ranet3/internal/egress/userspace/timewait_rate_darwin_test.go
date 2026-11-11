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
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/egress"
)

const (
	// this opt-in keeps leaf-first host socket holds out of the other measurements
	timewaitRateEnvironment = "RANET3_TIMEWAIT_RATE"
	// this is the most sockets a run leaves in TIME_WAIT on the host at once
	timewaitRateConnections = 1024
	// an even pair count gives each kind the first position equally often
	timewaitRatePairs = 4
	// the automatic range keeps room for the host while the measurement runs
	timewaitRateRangeFactor = 16
	// this preferred block stays below the usual automatic range
	timewaitRateLeafBase = 30000
	// the block must remain usable without elevated privileges
	timewaitRateUnprivileged = 1024
	// slow runs stop opening connections rather than failing for their rate
	timewaitRateRunWait = 14 * time.Second
	// prompt removal distinguishes exit aborts from natural TIME_WAIT expiry
	timewaitRateAbortWait = 3 * time.Second
	// natural expiry needs room for the collector after the socket's lifetime
	timewaitRateDrainWait = 15 * time.Second
	// host-table polling stays outside the connection timing and avoids a busy loop
	timewaitRatePoll = time.Second
	// the cap includes initial equalization and every post-close window.
	// each run budgets its opening span, an unfinished connection, table checks
	// and exit close. the outer allowances cover initial setup and final cleanup.
	timewaitRateWholeWait = netstatWait + (2*timewaitRatePairs+1)*(2*timewaitMaxMSL+timewaitRateDrainWait) +
		2*timewaitRatePairs*(3*netstatWait+timewaitRateRunWait+4*exitWait) + exitWait
)

// a missing listener distinguishes a blind table from an empty TIME_WAIT count
var errTimewaitRateBlindTable = errors.New("host TCP table went blind: the server's LISTEN row is missing")

// complete runs carry the deferred close cost as well as their connection-span rate
type timewaitRateSample struct {
	rate               float64
	spanAndCloseMicros float64
	cpuMicros          float64
	cpuOK              bool
	closeCPUMicros     float64
	closeCPUOK         bool
	pair               int
	firstInPair        bool
}

// the test measures the relay's leaf-first connections a second on macOS with the bound on host ports and without it
func TestBenchLeafFirstConnectionRateWithAndWithoutHostPortBounds(t *testing.T) {
	if _, set := os.LookupEnv(timewaitRateEnvironment); !set {
		t.Skipf("%s is unset. Set it to enable the leaf-first connection-rate measurement", timewaitRateEnvironment)
	}
	started := time.Now()
	wholeDeadline := started.Add(timewaitRateWholeWait)
	first, err := unix.SysctlUint32("net.inet.ip.portrange.first")
	if err != nil {
		t.Fatalf("bench: setup: read the automatic range's first port: %v", err)
	}
	last, err := unix.SysctlUint32("net.inet.ip.portrange.last")
	if err != nil {
		t.Fatalf("bench: setup: read the automatic range's last port: %v", err)
	}
	low, high := int(min(first, last)), int(max(first, last))
	// the range guard limits this measurement's share even on a narrowed host
	if low < 1 || high > 65535 || high-low+1 < timewaitRateRangeFactor*timewaitRateConnections {
		t.Skipf("bench: automatic range %d..%d must contain at least %d ports", first, last, timewaitRateRangeFactor*timewaitRateConnections)
	}
	leafFirst := min(timewaitRateLeafBase, low-timewaitRateConnections)
	leafLast := leafFirst + timewaitRateConnections - 1
	// staying below the automatic range avoids pinning the host's automatic ports
	if leafFirst < timewaitRateUnprivileged || leafLast >= low {
		t.Skipf("bench: no unprivileged block of %d leaf ports below automatic range %d..%d", timewaitRateConnections, low, high)
	}
	msl, err := xnuMSL()
	if err != nil {
		t.Fatalf("bench: setup: read the host MSL: %v", err)
	}
	if msl <= 0 || msl > timewaitMaxMSL {
		t.Skipf("bench: MSL %s must be positive and at most %s to fit the whole-test bound %s", msl, timewaitMaxMSL, timewaitRateWholeWait)
	}
	t.Logf("bench: automatic range %d..%d, leaf block %d..%d, MSL %s, connections per run %d", first, last, leafFirst, leafLast, msl, timewaitRateConnections)

	var outsideBlock atomic.Uint64
	server := tcpServer(t, netip.AddrFrom4([4]byte{127, 0, 0, 1}), func(conn *net.TCPConn) {
		peer, ok := conn.RemoteAddr().(*net.TCPAddr)
		if !ok || peer.Port < leafFirst || peer.Port > leafLast {
			// a raced bind may fall back to an automatic port. reset it before FIN
			// rather than letting this measurement leave that port in TIME_WAIT.
			outsideBlock.Add(1)
			_ = conn.SetLinger(0)
			_ = conn.Close()
			return
		}
		readsToTheEnd(conn)
	})
	if time.Since(started) > netstatWait {
		t.Fatalf("bench: setup: initial setup exceeds %s", netstatWait)
	}
	var boundedStorage, plainStorage [timewaitRatePairs]timewaitRateSample
	boundedSamples, plainSamples := boundedStorage[:0], plainStorage[:0]
	runsFinished, summarized := 0, false
	defer func() {
		if !summarized && runsFinished != 0 {
			timewaitRateSummaries(t, boundedSamples, plainSamples)
		}
	}()
	timewaitRateIdle(t, "initial setup", time.Now(), msl, wholeDeadline)
	for pair := range timewaitRatePairs {
		boundedFirst := pair%2 == 0
		for position, bounded := range [...]bool{boundedFirst, !boundedFirst} {
			kind := "without bound"
			if bounded {
				kind = "with bound"
			}
			if !time.Now().Before(timewaitRateLatestStart(wholeDeadline, msl)) {
				t.Logf("bench: whole-test bound %s leaves no room for another connection and its cleanup. No further run starts", timewaitRateWholeWait)
				return
			}
			before, rows, err := timewaitRateTable(server, wholeDeadline)
			if err != nil {
				if runsFinished == 0 && errors.Is(err, errTimewaitRateBlindTable) {
					t.Skip("bench: the host's TCP table is not readable by this user. The measurement runs as root")
				}
				t.Fatalf("bench: setup: read pre-run host TIME_WAIT table: %v", err)
			}
			if runsFinished == 0 {
				timewaitRateCheckBlock(t, rows, leafFirst, leafLast)
			}
			// only a test that starts no run can skip for an occupied server tuple
			if before != 0 {
				if runsFinished == 0 {
					timewaitRateGuard(t, before)
					t.Skipf("bench: pair %d %s cannot start with %d TIME_WAIT sockets toward its server", pair+1, kind, before)
				}
				timewaitRateSummaries(t, boundedSamples, plainSamples)
				summarized = true
				timewaitRateGuard(t, before)
				t.Fatalf("bench: setup: pair %d %s cannot start with %d TIME_WAIT sockets toward its server. No further run starts", pair+1, kind, before)
			}
			if !time.Now().Before(timewaitRateLatestStart(wholeDeadline, msl)) {
				t.Logf("bench: whole-test bound %s leaves no room after the pre-run table read. No further run starts", timewaitRateWholeWait)
				return
			}
			var sample timewaitRateSample
			var complete bool
			if !t.Run(fmt.Sprintf("pair_%d/%s", pair+1, strings.ReplaceAll(kind, " ", "_")), func(t *testing.T) {
				sample, complete = timewaitRateRun(t, server, leafFirst, pair+1, bounded, position == 0, msl, wholeDeadline, &outsideBlock)
			}) {
				t.Fatal("bench: setup: a run or its cleanup failed. No further run starts")
			}
			runsFinished++
			if complete {
				if bounded {
					boundedSamples = append(boundedSamples, sample)
				} else {
					plainSamples = append(plainSamples, sample)
				}
			}
		}
	}
}

// no harness sweep runs, so held sockets reach the separately timed exit close
func timewaitRateRun(t *testing.T, server netip.AddrPort, leafFirst, pair int, bounded, firstInPair bool, msl time.Duration, wholeDeadline time.Time, outsideBlock *atomic.Uint64) (timewaitRateSample, bool) {
	t.Helper()
	runDeadline := timewaitRateEarlier(timewaitRateLatestStart(wholeDeadline, msl), time.Now().Add(timewaitRateRunWait))
	kind := "without bound"
	var platform *hostSockets
	if bounded {
		kind, platform = "with bound", xnuHostSockets()
	}
	position := "second"
	if firstInPair {
		position = "first"
	}
	h := newRelayHarness(t, func(rt *Runtime, cfg *egress.Egress) {
		cfg.FlowsPerSource = timewaitRateConnections + 1
		rt.Platform.hostSockets = platform
		// hostPortsOf halves Flows, so a live connection fits beside every hold
		rt.Limits.Flows = 2 * (timewaitRateConnections + 1)
	})
	allowLoopback(t, h.x.stack)
	status := h.x.Status()
	hostBound := 0
	if (status.Flows.Host != nil) != bounded {
		t.Fatal("bench: setup: the status's host hold does not match the run's kind")
	}
	if bounded {
		hostBound = status.Flows.Host.Bound
	}
	t.Logf("bench: pair %d %s (%s in pair): source share %d, Flows %d, HostPorts %d", pair, kind, position, status.FlowsPerSource, status.Flows.Limits.Flows, hostBound)
	// the measurement admits every hold plus one live connection, without refusals from sizing
	if status.FlowsPerSource < timewaitRateConnections+1 || status.Flows.Limits.Flows < timewaitRateConnections+1 || bounded && hostBound < timewaitRateConnections+1 {
		t.Fatal("bench: setup: the exit's limits do not admit every held slot plus one open connection")
	}
	attempted, done, tableAtEnd := 0, 0, -1
	var firstSYN, spanStart, lastClosed time.Time
	// the span sums the time before and after the middle table check, excluding
	// that check and its diagnostic log from both kinds' connection rates
	var elapsed time.Duration
	// span CPU includes the test's own waiting loop and the middle table check
	// and log for both kinds, but excludes the child command's CPU via RUSAGE_SELF
	var cpuStart time.Duration
	var cpuStartOK bool
	finishSpan := func(at time.Time) {
		if !spanStart.IsZero() && at.After(spanStart) {
			elapsed += at.Sub(spanStart)
		}
		spanStart = time.Time{}
	}
	var rate float64
	reported := false
	report := func() {
		if reported {
			return
		}
		reported = true
		finishSpan(time.Now())
		if done != 0 && elapsed > 0 {
			rate = float64(done) / elapsed.Seconds()
		}
		var refused uint64
		for _, count := range h.refusals() {
			refused += count
		}
		failed := max(attempted-done-int(refused), 0)
		tableResult := "not read"
		if tableAtEnd >= 0 {
			tableResult = strconv.Itoa(tableAtEnd)
		}
		extent := "complete run"
		if done != timewaitRateConnections {
			extent = "short run excluded from medians"
		}
		t.Logf("bench: pair %d %s (%s in pair): %s, connections done %d, time %s, rate %.1f connections/s, refused %d, failed otherwise %d, TIME_WAIT at run end %s", pair, kind, position, extent, done, elapsed, rate, refused, failed, tableResult)
		// a refusal or failed connection invalidates the sized, sequential workload
		if refused != 0 || failed != 0 || outsideBlock.Load() != 0 {
			t.Errorf("bench: setup: pair %d %s: refused %d, failed otherwise %d, host sockets outside the leaf block %d", pair, kind, refused, failed, outsideBlock.Load())
		}
	}
	defer report()
	middleRead := false
	for i := range timewaitRateConnections {
		if !time.Now().Before(runDeadline) {
			break
		}
		leaf := netip.AddrPortFrom(leaf4, uint16(leafFirst+i))
		if i == 0 {
			cpuStart, cpuStartOK = timewaitRateCPU(t, "span start")
			firstSYN = time.Now()
			spanStart = firstSYN
		}
		attempted++
		conn := timewaitRateOpen(t, h, leaf, server, wholeDeadline)
		timewaitRateCloseFirst(t, h, &conn, wholeDeadline)
		timewaitRateWaitConnections(t, h, wholeDeadline)
		lastClosed = time.Now()
		done++
		if !middleRead && (done == timewaitRateConnections/2 || lastClosed.Sub(firstSYN) >= timewaitRateRunWait/2) {
			finishSpan(lastClosed)
			count := timewaitRateCount(t, server, wholeDeadline)
			t.Logf("bench: pair %d %s: middle guard after %d connections: TIME_WAIT %d", pair, kind, done, count)
			middleRead = true
			spanStart = time.Now()
		}
	}
	finishSpan(lastClosed)
	cpuEnd, cpuEndOK := timewaitRateCPU(t, "span end")
	// the end table read has its own command deadline, even after a short run
	tableAtEnd = timewaitRateCount(t, server, wholeDeadline)
	report()
	// a held slot can cover any phase, so the host table must independently show
	// every completed connection in TIME_WAIT for either kind of run
	badTable := tableAtEnd != done
	if badTable {
		t.Logf("bench: setup: pair %d %s: host table shows %d TIME_WAIT sockets at run end, want %d completed connections", pair, kind, tableAtEnd, done)
	}
	badHeld := false
	host := h.x.Status().Flows.Host
	if (host != nil) != bounded {
		t.Fatal("bench: setup: the run-end host hold does not match the run's kind")
	}
	if bounded {
		held := host.Held
		t.Logf("bench: pair %d %s: held slots before close %d", pair, kind, held)
		// no sweep releases a completed connection's held slot during this run
		badHeld = held != done
		if badHeld {
			t.Logf("bench: setup: pair %d %s: held %d slots, want %d", pair, kind, held, done)
		}
	}
	// closing the exit before draining ends its holds and precedes every later run
	cpuBeforeClose, cpuBeforeCloseOK := timewaitRateCPU(t, "before exit close")
	closeStart := time.Now()
	closeWithin(t, h.x)
	closed := time.Now()
	closeElapsed := closed.Sub(closeStart)
	cpuAfterClose, cpuAfterCloseOK := timewaitRateCPU(t, "after exit close")
	sample := timewaitRateSample{rate: rate, pair: pair, firstInPair: firstInPair}
	if done != 0 {
		divisor := float64(done) * float64(time.Microsecond)
		sample.spanAndCloseMicros = float64(elapsed+closeElapsed) / divisor
		spanCPU, closeCPU := "unavailable", "unavailable"
		if cpuStartOK && cpuEndOK {
			spanCPU = fmt.Sprintf("%.3f microseconds/connection", float64(cpuEnd-cpuStart)/divisor)
		}
		sample.closeCPUOK = cpuBeforeCloseOK && cpuAfterCloseOK
		if sample.closeCPUOK {
			sample.closeCPUMicros = float64(cpuAfterClose-cpuBeforeClose) / divisor
			closeCPU = fmt.Sprintf("%.3f microseconds/connection", sample.closeCPUMicros)
		}
		sample.cpuOK = cpuStartOK && cpuEndOK && cpuBeforeCloseOK && cpuAfterCloseOK
		if sample.cpuOK {
			sample.cpuMicros = float64(cpuEnd-cpuStart+cpuAfterClose-cpuBeforeClose) / divisor
		}
		t.Logf("bench: pair %d %s (%s in pair): exit close %.3f microseconds/connection, span plus close %.3f microseconds/connection, span process user+system CPU %s, close process user+system CPU %s", pair, kind, position, float64(closeElapsed)/divisor, sample.spanAndCloseMicros, spanCPU, closeCPU)
	} else {
		t.Logf("bench: pair %d %s (%s in pair): exit close %s, per-connection wall and CPU costs unavailable because no connection completed", pair, kind, position, closeElapsed)
	}
	if t.Failed() {
		t.Fatal("bench: setup: run accounting or exit close failed. No further run starts")
	}
	drainDeadline := timewaitRateEarlier(wholeDeadline, closed.Add(2*msl+timewaitRateDrainWait))
	if bounded {
		count := timewaitRateWaitEmpty(t, server, timewaitRateEarlier(drainDeadline, closed.Add(timewaitRateAbortWait)), tableAtEnd, pair, kind, "after exit close")
		t.Logf("bench: pair %d %s: after exit close TIME_WAIT last observed %d, elapsed %s", pair, kind, count, time.Since(closed))
		// aborting the held sockets must remove their TIME_WAITs promptly
		if count != 0 {
			t.Logf("bench: pair %d %s: close reading: %d TIME_WAIT sockets remain after %s. Waiting for the host before stopping", pair, kind, count, timewaitRateAbortWait)
			count = timewaitRateWaitEmpty(t, server, drainDeadline, count, pair, kind, "after slow exit close")
			if count != 0 {
				t.Fatalf("bench: setup: pair %d %s: drain bound reached with %d TIME_WAIT sockets left. No further run starts", pair, kind, count)
			}
			t.Fatalf("bench: setup: pair %d %s: TIME_WAIT did not empty within %s of exit close", pair, kind, timewaitRateAbortWait)
		}
	} else {
		count := timewaitRateWaitEmpty(t, server, drainDeadline, tableAtEnd, pair, kind, "after plain close")
		// the next run cannot add sockets while any of this run's TIME_WAITs remain
		if count != 0 {
			t.Fatalf("bench: setup: pair %d %s: drain bound reached with %d TIME_WAIT sockets left. No further run starts", pair, kind, count)
		}
	}
	if badTable {
		t.Fatalf("bench: setup: pair %d %s: run-end TIME_WAIT count %d differs from completed connection count %d. No further run starts", pair, kind, tableAtEnd, done)
	}
	if badHeld {
		t.Fatal("bench: setup: held-slot count differs from the completed connection count")
	}
	timewaitRateIdle(t, "exit close", closed, msl, wholeDeadline)
	return sample, done == timewaitRateConnections
}

// a common post-close window includes draining, so an early abort cannot advance the next start
func timewaitRateIdle(t *testing.T, origin string, since time.Time, msl time.Duration, wholeDeadline time.Time) {
	t.Helper()
	window := 2*msl + timewaitRateDrainWait
	until := timewaitRateEarlier(since.Add(window), wholeDeadline)
	time.Sleep(max(time.Until(until), 0))
	t.Logf("bench: idle window after %s: elapsed %s, target %s", origin, time.Since(since), window)
}

// process-wide user and system CPU include server and runtime work as well as
// the relay, and a missing resource reading is unavailable rather than a failed rate
func timewaitRateCPU(t *testing.T, when string) (time.Duration, bool) {
	t.Helper()
	var usage unix.Rusage
	if err := unix.Getrusage(unix.RUSAGE_SELF, &usage); err != nil {
		t.Logf("bench: process CPU at %s is unavailable: %v", when, err)
		return 0, false
	}
	user := time.Duration(usage.Utime.Sec)*time.Second + time.Duration(usage.Utime.Usec)*time.Microsecond
	system := time.Duration(usage.Stime.Sec)*time.Second + time.Duration(usage.Stime.Usec)*time.Microsecond
	return user + system, true
}

// reserving the last connection's phase waits, table checks, exit close and drain
// keeps slow runs inside the whole-test cap
func timewaitRateLatestStart(wholeDeadline time.Time, msl time.Duration) time.Time {
	return wholeDeadline.Add(-(4*exitWait + 2*netstatWait + 2*msl + timewaitRateDrainWait))
}

// the handshake uses the harness's SYN admission and ACK delivery without its
// fixed-sleep packet wait, leaving the relay's path and kernel work in the reading
func timewaitRateOpen(t *testing.T, h *relayHarness, leaf, server netip.AddrPort, wholeDeadline time.Time) leafConn {
	t.Helper()
	deadline := timewaitRateEarlier(wholeDeadline, time.Now().Add(exitWait))
	if reason := h.syn(t, leaf, server); reason != "" {
		t.Fatalf("bench: setup: the exit refused the connection past %s", reason)
	}
	p := timewaitRateWaitLaid(t, h, leaf, deadline, "SYN-ACK", func(p sent) bool {
		return p.flags == tcpSYN|tcpACK
	})
	c := leafConn{leaf: leaf, server: server, seq: leafISN + 1, ack: p.seq + 1}
	if !h.x.link.deliver(tcpSegment(leaf, server, c.seq, c.ack, tcpACK, nil)) {
		t.Fatal("bench: setup: the link refused the leaf's ACK")
	}
	return c
}

// sending the leaf's FIN first makes the host the active closer
func timewaitRateCloseFirst(t *testing.T, h *relayHarness, c *leafConn, wholeDeadline time.Time) {
	t.Helper()
	deadline := timewaitRateEarlier(wholeDeadline, time.Now().Add(exitWait))
	if !h.x.link.deliver(tcpSegment(c.leaf, c.server, c.seq, c.ack, tcpACK|tcpFIN, nil)) {
		t.Fatal("bench: setup: the link refused the leaf's FIN")
	}
	c.seq++
	p := timewaitRateWaitLaid(t, h, c.leaf, deadline, "FIN", func(p sent) bool {
		return p.flags&tcpFIN != 0
	})
	c.ack = p.seq + uint32(p.payload) + 1
	if !h.x.link.deliver(tcpSegment(c.leaf, c.server, c.seq, c.ack, tcpACK, nil)) {
		t.Fatal("bench: setup: the link refused the leaf's final ACK")
	}
}

// parsed fields own no packet storage, so the view and packet can be released
// before returning without copying bytes
func timewaitRateWaitLaid(t *testing.T, h *relayHarness, leaf netip.AddrPort, deadline time.Time, what string, match func(sent) bool) sent {
	t.Helper()
	for time.Now().Before(deadline) {
		if pkt := h.x.link.poll(); pkt != nil {
			view := pkt.ToView()
			p, ok := parse(view.AsSlice())
			view.Release()
			h.x.link.release(pkt)
			if ok && p.protocol == protoTCP && netip.AddrPortFrom(p.dst, p.dstPort) == leaf && match(p) {
				return p
			}
		}
		runtime.Gosched()
	}
	t.Fatalf("bench: setup: no %s toward the leaf within its %s wait", what, exitWait)
	return sent{}
}

// the relay's zero connection count follows its hold accounting, so the next
// SYN cannot overlap an open connection or race a slot still being counted.
// this wait takes the relay and flows locks. both end paths take the flows lock
// once, but the bound accounts its hold before the connection decrement while the
// plain path releases its flow under the relay lock, so polling can tilt the reading.
func timewaitRateWaitConnections(t *testing.T, h *relayHarness, wholeDeadline time.Time) {
	t.Helper()
	deadline := timewaitRateEarlier(wholeDeadline, time.Now().Add(exitWait))
	for h.x.tcp.held()[1] != 0 {
		if !time.Now().Before(deadline) {
			t.Fatalf("bench: setup: relay connections do not reach zero within %s", exitWait)
		}
		runtime.Gosched()
	}
}

// complete-run samples survive a later guard failure and keep deferred close
// costs beside the rate, with short runs excluded from every median
func timewaitRateSummaries(t *testing.T, boundedSamples, plainSamples []timewaitRateSample) {
	t.Helper()
	var rateMedians, wallMedians, cpuMedians, closeCPUMedians [2]float64
	var cpuCounts, closeCPUCounts [2]int
	for k, kind := range []struct {
		name    string
		samples []timewaitRateSample
	}{{"with bound", boundedSamples}, {"without bound", plainSamples}} {
		if len(kind.samples) == 0 {
			t.Logf("bench: %s: no complete runs for a median", kind.name)
			continue
		}
		var rateStorage, spanStorage, wallStorage, cpuStorage, closeCPUStorage [timewaitRatePairs]float64
		rates, spans := rateStorage[:len(kind.samples)], spanStorage[:len(kind.samples)]
		walls, cpus := wallStorage[:len(kind.samples)], cpuStorage[:0]
		closeCPUs := closeCPUStorage[:0]
		for i, sample := range kind.samples {
			rates[i], spans[i] = sample.rate, 1e6/sample.rate
			walls[i] = sample.spanAndCloseMicros
			if sample.cpuOK {
				cpus = append(cpus, sample.cpuMicros)
			}
			if sample.closeCPUOK {
				closeCPUs = append(closeCPUs, sample.closeCPUMicros)
			}
		}
		slices.Sort(rates)
		slices.Sort(spans)
		slices.Sort(walls)
		slices.Sort(cpus)
		slices.Sort(closeCPUs)
		rateMedians[k], wallMedians[k] = timewaitRateMedian(rates), timewaitRateMedian(walls)
		spread := "no spread can be read from one complete run"
		if len(kind.samples) > 1 {
			spread = fmt.Sprintf("lowest/highest %.1f/%.1f connections/s and %.3f/%.3f microseconds/connection", rates[0], rates[len(rates)-1], spans[0], spans[len(spans)-1])
		}
		t.Logf("bench: %s: %d complete runs on one machine, median %.1f connections/s and %.3f microseconds/connection, %s", kind.name, len(kind.samples), rateMedians[k], timewaitRateMedian(spans), spread)
		cpuCounts[k], closeCPUCounts[k] = len(cpus), len(closeCPUs)
		if len(cpus) != 0 {
			cpuMedians[k] = timewaitRateMedian(cpus)
		}
		if len(closeCPUs) != 0 {
			closeCPUMedians[k] = timewaitRateMedian(closeCPUs)
		}
		t.Logf("bench: %s: span plus close wall %s, combined process CPU %s. The span's CPU includes the test's own waiting loop", kind.name, timewaitRateDistribution(walls), timewaitRateDistribution(cpus))
		t.Logf("bench: %s: exit-close process CPU %s. This is the exit's close CPU, including aborts, held-slot release and teardown with the bound, and teardown alone without it", kind.name, timewaitRateDistribution(closeCPUs))
	}
	if len(boundedSamples) != 0 && len(plainSamples) != 0 {
		t.Logf("bench: complete-run median rate with/without ratio %.3f. Below 1 is a rate cost of the bound", rateMedians[0]/rateMedians[1])
		cpuRatio := "unavailable"
		if cpuCounts[0] != 0 && cpuCounts[1] != 0 && cpuMedians[1] != 0 {
			cpuRatio = fmt.Sprintf("%.3f", cpuMedians[0]/cpuMedians[1])
		}
		t.Logf("bench: span plus close median with/without ratios: wall %.3f, combined process CPU %s. Above 1 is a time cost of the bound. The span's CPU includes the test's own waiting loop", wallMedians[0]/wallMedians[1], cpuRatio)
		closeDifference := "unavailable"
		if closeCPUCounts[0] != 0 && closeCPUCounts[1] != 0 {
			closeDifference = fmt.Sprintf("%+.3f microseconds/connection", closeCPUMedians[0]-closeCPUMedians[1])
		}
		t.Logf("bench: exit-close process CPU median difference with-minus-without %s. This compares exit close CPU: aborts, held-slot release and teardown with the bound, teardown alone without it", closeDifference)
	}
	t.Log("bench: span plus close counts the bound's per-connection path steps and its aborts and held-slot releases at exit close. It leaves out the daemon's sweeps that abort and release holds and kernel work outside the process's threads. Every dial's socket readying is in both kinds, so their difference leaves its cost out. It also counts exit teardown, which the daemon does not pay per connection. Rate alone leaves the kind with the bound its aborts out")
	if len(boundedSamples) > 1 && len(plainSamples) > 1 {
		t.Log("bench: the smallest difference these runs on one machine can show is their observed spread")
	} else {
		t.Log("bench: no between-kind spread-based resolution can be read unless each kind has at least two complete runs")
	}
	t.Log("bench: the reading's floor includes the connection-count wait's relay and flows locks. Both end paths take the flows lock once. The bound accounts its hold before the connection decrement, while the plain path releases its flow under the relay lock. Every dial's socket readying is common to both kinds, so their difference leaves its cost out")
	timewaitRateOrderSummaries(t, boundedSamples, plainSamples)
}

// matching complete pairs keeps missing or short partners out of order comparisons
func timewaitRateOrderSummaries(t *testing.T, boundedSamples, plainSamples []timewaitRateSample) {
	t.Helper()
	type pairDifference struct {
		pair   int
		micros float64
	}
	var storage [2][timewaitRatePairs / 2]pairDifference
	differences := [2][]pairDifference{storage[0][:0], storage[1][:0]}
	for _, bounded := range boundedSamples {
		for _, plain := range plainSamples {
			if bounded.pair != plain.pair {
				continue
			}
			order := 0
			if !bounded.firstInPair {
				order = 1
			}
			differences[order] = append(differences[order], pairDifference{pair: bounded.pair, micros: bounded.spanAndCloseMicros - plain.spanAndCloseMicros})
			break
		}
	}
	t.Logf("bench: order comparison uses %d/%d complete pairs on one machine", len(differences[0])+len(differences[1]), timewaitRatePairs)
	for order, position := range [...]string{"first", "second"} {
		values := differences[order]
		if len(values) == 0 {
			t.Logf("bench: bound ran %s: 0/%d complete pairs. Paired span plus close difference unavailable", position, timewaitRatePairs/2)
			continue
		}
		slices.SortFunc(values, func(a, b pairDifference) int { return a.pair - b.pair })
		var pairs strings.Builder
		for i, value := range values {
			if i != 0 {
				pairs.WriteString(", ")
			}
			fmt.Fprintf(&pairs, "pair %d %+.3f", value.pair, value.micros)
		}
		t.Logf("bench: bound ran %s: %d/%d complete pairs, paired span plus close difference with-minus-without: %s microseconds/connection. Positive is a wall-time cost of the bound", position, len(values), timewaitRatePairs/2, pairs.String())
	}
	t.Log("bench: bound-first pairs follow bounded closes or initial setup with no expiry wait. Bound-second pairs follow plain closes with expiry and table polling. Both runs of a pair share that preceding condition, so a gap between positions is not an order effect alone. Use the within-pair differences")
}

// missing samples and single-run resolution stay explicit instead of becoming a zero spread
func timewaitRateDistribution(sorted []float64) string {
	if len(sorted) == 0 {
		return "unavailable (0 complete-run samples)"
	}
	center := fmt.Sprintf("%d complete-run samples, median %.3f microseconds/connection", len(sorted), timewaitRateMedian(sorted))
	if len(sorted) == 1 {
		return center + ", no spread can be read"
	}
	return fmt.Sprintf("%s, lowest/highest %.3f/%.3f microseconds/connection", center, sorted[0], sorted[len(sorted)-1])
}

// averaging the middle pair also handles partial results with an even sample count
func timewaitRateMedian(sorted []float64) float64 {
	middle := len(sorted) / 2
	if len(sorted)%2 == 0 {
		return (sorted[middle-1] + sorted[middle]) / 2
	}
	return sorted[middle]
}

// this uses the independent host table path, with the caller's shorter deadline
// as well as the command bound, so a final poll cannot overrun a drain
func timewaitRateTable(server netip.AddrPort, deadline time.Time) (int, [][]string, error) {
	ctx, cancel := context.WithDeadline(context.Background(), timewaitRateEarlier(deadline, time.Now().Add(netstatWait)))
	defer cancel()
	rows, _, err := timewaitTableRows(ctx)
	if err != nil {
		return 0, nil, err
	}
	end := tableEnd(server)
	count, listening := 0, false
	for _, fields := range rows {
		if fields[3] == end && fields[5] == "LISTEN" {
			listening = true
		}
		if fields[4] == end && fields[5] == "TIME_WAIT" {
			count++
		}
	}
	if !listening {
		return -1, nil, errTimewaitRateBlindTable
	}
	return count, rows, nil
}

// a privileged reuse bind can share another user's port, so the first snapshot must exclude it
func timewaitRateCheckBlock(t *testing.T, rows [][]string, first, last int) {
	t.Helper()
	occupied := 0
	for _, fields := range rows {
		port, err := timewaitTablePort(fields[3])
		if err != nil {
			t.Fatalf("bench: setup: read leaf block occupancy: %v", err)
		}
		if port >= first && port <= last {
			occupied++
		}
	}
	if occupied != 0 {
		t.Skipf("bench: leaf block %d..%d has %d sockets in the host TCP table", first, last, occupied)
	}
}

// this guard applies to every table read, not just a run's final count
func timewaitRateGuard(t *testing.T, count int) {
	t.Helper()
	// exceeding the fixed workload means the test is accumulating unintended sockets
	if count > timewaitRateConnections {
		t.Fatalf("bench: setup: host table shows %d TIME_WAIT sockets toward the server, above the guard %d. No further run starts", count, timewaitRateConnections)
	}
}

// a failed table read cannot be treated as an empty host table
func timewaitRateCount(t *testing.T, server netip.AddrPort, deadline time.Time) int {
	t.Helper()
	count, _, err := timewaitRateTable(server, deadline)
	if err != nil {
		t.Fatalf("bench: setup: read host TIME_WAIT table: %v", err)
	}
	timewaitRateGuard(t, count)
	return count
}

// polling after the exit closes keeps natural expiry outside the timed span,
// while retaining the last count if the final command reaches the deadline
func timewaitRateWaitEmpty(t *testing.T, server netip.AddrPort, deadline time.Time, last, pair int, kind, when string) int {
	t.Helper()
	started := time.Now()
	defer func() {
		t.Logf("bench: pair %d %s: wait %s took %s, TIME_WAIT left %d", pair, kind, when, time.Since(started), last)
	}()
	for time.Now().Before(deadline) {
		count, _, err := timewaitRateTable(server, deadline)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) && !time.Now().Before(deadline) {
				break
			}
			t.Fatalf("bench: setup: read host table while waiting %s: %v, last TIME_WAIT count %d", when, err, last)
		}
		timewaitRateGuard(t, count)
		last = count
		if count == 0 {
			return 0
		}
		time.Sleep(min(timewaitRatePoll, max(time.Until(deadline), 0)))
	}
	return last
}

// shorter caller deadlines take precedence over individual command or step waits
func timewaitRateEarlier(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
