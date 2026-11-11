// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package userspace

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const (
	// the collector's lazy pass after TIME_WAIT expiry is not covered by the exit's margin.
	timewaitReserveLazyWait = 11 * time.Second
	// capping the socket lifetime keeps the observations and drains within their bounds
	timewaitMaxMSL = 15 * time.Second
	// a stalled server cannot consume another arm's observation allowance
	timewaitReserveSocketWait = 5 * time.Second
	// the observation wait permits readings beyond the exit's held-port margin.
	timewaitReserveObservationWait = 20 * time.Second
	// subsecond samples resolve prompt BSD bind reuse while limiting collector work.
	timewaitReserveProbeInterval = 250 * time.Millisecond
	timewaitReserveHoldInterval  = time.Second
	timewaitReserveKernelWait    = 15 * time.Second
	// socket waits cover every connection, but only the bind arms need observation
	// and probe spacing. three arms allow a TIME_WAIT lifetime, one allows
	// collector delay, and an extra observation wait covers scheduling and setup.
	timewaitReserveWholeWait = 5*2*timewaitReserveSocketWait +
		4*(timewaitReserveObservationWait+2*timewaitReserveProbeInterval) +
		6*timewaitMaxMSL + timewaitReserveKernelWait + timewaitReserveObservationWait
)

// the server reads through the client's FIN and closes without sending data.
// a wildcard BSD bind without reuse reads whether the port is available to the
// host's own BSD automatic binds and unbound connects, without changing settings.
// it does not read the registrar reference that refuses a Skywalk flow.
func TestTimeWaitPortsBecomeAvailableAfterTheirSocketsEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), timewaitReserveWholeWait)
	defer cancel()
	value := os.Getenv("RANET3_TIMEWAIT_SERVER")
	if value == "" {
		t.Skip("RANET3_TIMEWAIT_SERVER is unset. A remote IPv4 address:port that reads through FIN and closes without sending is required")
	}
	server, err := netip.ParseAddrPort(value)
	if err != nil || !server.Addr().Is4() || !server.Addr().IsGlobalUnicast() || server.Addr().IsLoopback() || server.Port() == 0 {
		t.Skip("RANET3_TIMEWAIT_SERVER lacks a remote IPv4 address:port with a nonzero port")
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatalf("setup: read the host's addresses: %s", timewaitError(err))
	}
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err != nil {
			t.Fatal("setup: cannot parse a host interface address")
		}
		if prefix.Addr().Unmap() == server.Addr() {
			t.Skip("a remote server is required and the configured address belongs to this host")
		}
	}
	msl, err := unix.SysctlUint32("net.inet.tcp.msl")
	if err != nil {
		t.Fatalf("setup: read net.inet.tcp.msl: %v", err)
	}
	mslDuration := time.Duration(msl) * time.Millisecond
	t.Logf("net.inet.tcp.msl: %d ms", msl)
	if mslDuration <= 0 || mslDuration > timewaitMaxMSL {
		t.Fatalf("setup: MSL is %s, want positive and at most %s", mslDuration, timewaitMaxMSL)
	}
	lifetime := 2 * mslDuration
	var lastProbe time.Time
	for _, arm := range []struct {
		name        string
		hold        bool
		kernelClose bool
		linger      bool
		readLinger  bool
	}{
		{name: "linger without the exemption", readLinger: true},
		{name: "ended at once", linger: true},
		{name: "ended after the hold", hold: true, linger: true},
		{name: "ended after the kernel's close", kernelClose: true, linger: true},
		{name: "closed plainly"},
	} {
		timewaitReserveArm(t, ctx, server, lifetime, arm.name, arm.hold, arm.kernelClose, arm.linger, arm.readLinger, &lastProbe)
	}
	if err := timewaitWait(ctx, time.Now()); err != nil {
		t.Fatalf("reading: observation cut short: whole-test bound %s: %v", timewaitReserveWholeWait, err)
	}
}

func timewaitReserveArm(t *testing.T, ctx context.Context, server netip.AddrPort, lifetime time.Duration, name string, hold, kernelClose, linger, readLinger bool, lastProbe *time.Time) {
	t.Helper()
	observing := false
	failSetup := func(format string, args ...any) {
		t.Helper()
		if observing && ctx.Err() != nil {
			t.Fatalf("reading: %s: observation cut short by whole-test bound %s: %v", name, timewaitReserveWholeWait, ctx.Err())
		}
		t.Fatalf("setup: %s: %s", name, fmt.Sprintf(format, args...))
	}
	wait := func(until time.Time) {
		t.Helper()
		if err := timewaitWait(ctx, until); err != nil {
			failSetup("whole-test bound %s: %v", timewaitReserveWholeWait, err)
		}
	}
	wait(time.Now())
	port := 0
	dialer := net.Dialer{
		Timeout: timewaitReserveSocketWait,
		Control: func(_, _ string, raw syscall.RawConn) error {
			var socketErr error
			if err := raw.Control(func(fd uintptr) {
				socketErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
				if socketErr != nil {
					return
				}
				if linger {
					// the kernel refuses options after both halves shut down without this exemption
					if err := prepareHostSocket(int(fd)); err != nil {
						socketErr = fmt.Errorf("prepare host socket: %w", err)
						return
					}
				}
				if socketErr = unix.Bind(int(fd), &unix.SockaddrInet4{}); socketErr != nil {
					return
				}
				local, err := unix.Getsockname(int(fd))
				if err != nil {
					socketErr = fmt.Errorf("getsockname: %w", err)
					return
				}
				address, ok := local.(*unix.SockaddrInet4)
				if !ok || address.Port == 0 {
					socketErr = fmt.Errorf("getsockname: want an assigned IPv4 port, got %T", local)
					return
				}
				port = address.Port
			}); err != nil {
				return err
			}
			return socketErr
		},
	}
	conn, err := dialer.DialContext(ctx, "tcp4", server.String())
	if err != nil {
		failSetup("reuse bind(0) and connect within %s: %s", timewaitReserveSocketWait, timewaitError(err))
	}
	stopClose := context.AfterFunc(ctx, func() { conn.Close() })
	defer func() {
		stopClose()
		conn.Close()
	}()
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		failSetup("connect returned %T, want *net.TCPConn", conn)
	}
	deadline := time.Now().Add(timewaitReserveSocketWait)
	if wholeDeadline, ok := ctx.Deadline(); ok && wholeDeadline.Before(deadline) {
		deadline = wholeDeadline
	}
	if err := tcp.SetDeadline(deadline); err != nil {
		failSetup("port %d: set socket deadline: %s", port, timewaitError(err))
	}
	if err := tcp.CloseWrite(); err != nil {
		failSetup("port %d: shutdown write side: %s", port, timewaitError(err))
	}
	var data [1]byte
	if n, err := tcp.Read(data[:]); n != 0 || err != io.EOF {
		failSetup("port %d: read server FIN within %s: got %d bytes and %s, want EOF without data", port, timewaitReserveSocketWait, n, timewaitError(err))
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		failSetup("port %d: access connection descriptor: %s", port, timewaitError(err))
	}
	state, err := xnuState(raw)
	seen := time.Now()
	if err != nil {
		failSetup("port %d: read TCP_CONNECTION_INFO: %s", port, timewaitError(err))
	}
	if state != hostTimeWait {
		failSetup("port %d: %s, want TIME_WAIT", port, timewaitStateReading(raw))
	}
	t.Logf("%s: port %d: TIME_WAIT seen with descriptor open", name, port)
	observing = true
	if readLinger {
		err := tcp.SetLinger(0)
		wait(time.Now())
		result := "succeeded"
		if err != nil {
			result = timewaitResult(err, port)
		}
		t.Logf("%s: port %d: SetLinger(0) without SONPX_SETOPTSHUT: %s", name, port, result)
		// the exit needs the exemption because the unprepared socket refuses this option with EINVAL
		if !errors.Is(err, unix.EINVAL) {
			t.Errorf("reading: %s: port %d: SetLinger(0) without SONPX_SETOPTSHUT returned %s, want EINVAL", name, port, result)
		}
		if err == nil {
			// a successful option needs undoing so this arm still closes plainly.
			if err := tcp.SetLinger(-1); err != nil {
				failSetup("port %d: disable linger for plain close: %s", port, timewaitResult(err, port))
			}
		}
		if err := tcp.Close(); err != nil {
			failSetup("port %d: close socket plainly: %s", port, timewaitError(err))
		}
		return
	}
	readState := func() (bool, string) {
		state, err := xnuState(raw)
		wait(time.Now())
		if err != nil {
			return false, timewaitResult(err, port)
		}
		if state == hostTimeWait {
			return true, ""
		}
		return false, timewaitStateReading(raw)
	}
	probes := 0
	defer func() { t.Logf("%s: port %d: probes: %d", name, port, probes) }()
	probe := func() (time.Time, error) {
		t.Helper()
		wait(lastProbe.Add(timewaitReserveProbeInterval))
		bindErr, err := timewaitReserveProbe(port)
		at := time.Now()
		*lastProbe = at
		probes++
		if err != nil {
			failSetup("port %d: probe: %v", port, err)
		}
		if bindErr != nil && !timewaitAddressError(bindErr) {
			failSetup("port %d: probe returned %s, not an address-in-use kind of failure", port, timewaitResult(bindErr, port))
		}
		wait(at)
		return at, bindErr
	}
	at, before := probe()
	t.Logf("%s: port %d: before ending socket: %s, since TIME_WAIT: %s", name, port, timewaitResult(before, port), at.Sub(seen))
	// a successful pre-close BSD bind cannot show that this socket refuses the port.
	if before == nil {
		failSetup("port %d: the BSD bind without reuse succeeds with the descriptor open in TIME_WAIT. The arm cannot see the pin", port)
	}
	if hold || kernelClose {
		previous := timewaitResult(before, port)
		holdUntil := seen.Add(lifetime)
		if kernelClose {
			holdUntil = holdUntil.Add(timewaitReserveKernelWait)
		}
		stateChanged := false
		for next := seen.Add(timewaitReserveHoldInterval); next.Before(holdUntil); {
			wait(next)
			if !time.Now().Before(holdUntil) {
				break
			}
			at, outcome := probe()
			result := timewaitResult(outcome, port)
			if result != previous {
				t.Logf("%s: port %d: descriptor held: %s, since TIME_WAIT: %s", name, port, result, at.Sub(seen))
				previous = result
			}
			if kernelClose {
				inTimeWait, result := readState()
				if !inTimeWait {
					stateChanged = true
					stateAt := time.Now()
					at, outcome := probe()
					t.Logf("%s: port %d: TCP_CONNECTION_INFO leaves TIME_WAIT: %s, since TIME_WAIT: %s, BSD bind after the state change with descriptor held: %s, probe since TIME_WAIT: %s", name, port, result, stateAt.Sub(seen), timewaitResult(outcome, port), at.Sub(seen))
					break
				}
			}
			next = at.Add(timewaitReserveHoldInterval)
		}
		if !stateChanged {
			wait(holdUntil)
			if kernelClose {
				failSetup("port %d: TCP_CONNECTION_INFO never leaves TIME_WAIT within %s. BSD bind succeeds at the last held-descriptor probe: %t", port, lifetime+timewaitReserveKernelWait, previous == timewaitResult(nil, port))
			}
		}
	}
	// spacing before close permits an immediate post-close probe without a burst,
	// including across arm boundaries and after the final held-descriptor probe.
	wait(lastProbe.Add(timewaitReserveProbeInterval))
	if linger {
		if err := tcp.SetLinger(0); err != nil {
			wait(time.Now())
			t.Errorf("reading: %s: port %d: SetLinger(0) with SONPX_SETOPTSHUT: %s", name, port, timewaitResult(err, port))
			return
		}
		result := timewaitStateReading(raw)
		wait(time.Now())
		t.Logf("%s: port %d: TCP_CONNECTION_INFO right before linger-zero close: %s, since TIME_WAIT: %s", name, port, result, time.Since(seen))
	}
	if err := tcp.Close(); err != nil {
		failSetup("port %d: close socket: %s", port, timewaitError(err))
	}
	ended := time.Now()
	observeUntil := ended.Add(timewaitReserveObservationWait)
	wantBy := ended.Add(reservationMargin)
	if !linger {
		observeUntil = seen.Add(lifetime + timewaitReserveObservationWait)
		wantBy = seen.Add(lifetime + timewaitReserveLazyWait)
	}
	var firstFree, lastRefused time.Time
	previous := ""
	postProbes := 0
	for {
		at, outcome := probe()
		postProbes++
		result := timewaitResult(outcome, port)
		if result != previous {
			if linger {
				t.Logf("%s: port %d: after ending socket: %s, since close: %s", name, port, result, at.Sub(ended))
			} else {
				t.Logf("%s: port %d: after ending socket: %s, since close: %s, since TIME_WAIT: %s", name, port, result, at.Sub(ended), at.Sub(seen))
			}
			previous = result
		}
		if outcome == nil {
			firstFree = at
			break
		}
		lastRefused = at
		next := at.Add(timewaitReserveProbeInterval)
		if next.After(observeUntil) {
			wait(observeUntil)
			break
		}
		wait(next)
	}
	summaryNote := ""
	if !linger {
		// each probe's close schedules collector work, so this is not idle-host timing.
		summaryNote = ". This is a probed host's release time, not an idle host's"
	}
	if firstFree.IsZero() {
		t.Logf("%s: port %d: summary: BSD bind still refused at %s after close. Observation ends at %s after close%s", name, port, lastRefused.Sub(ended), observeUntil.Sub(ended), summaryNote)
	} else if postProbes == 1 {
		t.Logf("%s: port %d: summary: BSD bind never observed refused after close. First bind at %s%s", name, port, firstFree.Sub(ended), summaryNote)
	} else {
		// sampling brackets release rather than claiming an exact kernel timestamp.
		t.Logf("%s: port %d: summary: BSD bind refused through %s after close. First bind at %s after close%s", name, port, lastRefused.Sub(ended), firstFree.Sub(ended), summaryNote)
	}
	if linger {
		// a BSD bind without reuse must not remain refused beyond the exit's margin.
		// a late successful sample alone does not prove the port stayed refused.
		if firstFree.IsZero() || firstFree.After(observeUntil) || lastRefused.After(wantBy) {
			t.Errorf("reading: %s: port %d: BSD bind without reuse is refused past %s after close or not observed free within the observation. Last refused at %s, first bind at %s", name, port, reservationMargin, timewaitSampleTime(lastRefused, ended), timewaitSampleTime(firstFree, ended))
		}
	} else {
		// the control must show a post-close pin to measure ordinary TIME_WAIT.
		if postProbes == 1 && !firstFree.IsZero() {
			t.Errorf("reading: %s: port %d: first BSD bind without reuse succeeds at %s after plain close. The control did not show the pin", name, port, firstFree.Sub(ended))
		}
		// ordinary expiry permits BSD binds after its lifetime and the lazy collector pass,
		// without treating a successful sample's polling delay as continued refusal.
		if firstFree.IsZero() || firstFree.After(observeUntil) || lastRefused.After(wantBy) {
			t.Errorf("reading: %s: port %d: BSD bind without reuse is refused past twice MSL plus the %s lazy collector bound (%s since TIME_WAIT) or not observed free within the observation. Last refused at %s, first bind at %s", name, port, timewaitReserveLazyWait, lifetime+timewaitReserveLazyWait, timewaitSampleTime(lastRefused, seen), timewaitSampleTime(firstFree, seen))
		}
	}
}

// the probe never connects, so closing a successful bind leaves no TIME_WAIT.
func timewaitReserveProbe(port int) (bindErr, setupErr error) {
	fd, err := timewaitSocket(false)
	if err != nil {
		return nil, fmt.Errorf("open plain socket: %w", err)
	}
	bindErr = unix.Bind(fd, &unix.SockaddrInet4{Port: port})
	if err := unix.Close(fd); err != nil {
		return bindErr, fmt.Errorf("close probe socket: %w", err)
	}
	return bindErr, nil
}

// timers keep sample spacing inside the caller's deadline without spinning
func timewaitWait(ctx context.Context, until time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	left := time.Until(until)
	if left <= 0 {
		return nil
	}
	timer := time.NewTimer(left)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return ctx.Err()
	}
}

// an absent sample must not look like a zero-duration observation
func timewaitSampleTime(at, origin time.Time) string {
	if at.IsZero() {
		return "never observed"
	}
	return at.Sub(origin).String()
}
