// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package userspace

import (
	"context"
	"encoding/binary"
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
	timewaitRegistrarSysctl = "kern.skywalk.stats.netns"
	// two lazy passes cover disposal when the close's fast pass gives up and an idle host needs another pass.
	timewaitRegistrarLazyWait        = 22 * time.Second
	timewaitRegistrarSocketWait      = 5 * time.Second
	timewaitRegistrarReadWait        = 5 * time.Second
	timewaitRegistrarObservationWait = 20 * time.Second
	timewaitRegistrarPlainWait       = 25 * time.Second
	timewaitRegistrarKernelWait      = 22 * time.Second
	// observation extends past the lazy allowance so a late reference can be seen.
	timewaitRegistrarLazyObservationWait = timewaitRegistrarLazyWait + timewaitRegistrarReadWait
	// subsecond samples resolve disposal without creating sockets that wake the collector.
	timewaitRegistrarReadInterval = 250 * time.Millisecond
	timewaitRegistrarHoldInterval = time.Second
	// table growth retries share the read deadline and sampling cadence.
	timewaitRegistrarReadAttempts = 3
	// each arm allows socket waits, a pre-close read, a final read and spacing.
	// the initial read and scheduling slack sit outside the arms' observation bounds.
	timewaitRegistrarWholeWait = 3*(2*timewaitRegistrarSocketWait+2*timewaitRegistrarReadWait+2*timewaitRegistrarReadInterval) +
		timewaitRegistrarObservationWait + timewaitRegistrarLazyObservationWait + 4*timewaitMaxMSL + timewaitRegistrarKernelWait +
		timewaitRegistrarPlainWait + timewaitRegistrarReadWait + timewaitRegistrarObservationWait
	// the native layouts include alignment padding after their fields.
	timewaitRegistrarHeaderSize = 32
	timewaitRegistrarRecordSize = 32
	// bitsets count distinct port numbers across namespaces without retaining addresses.
	timewaitRegistrarPortWords = (1 << 16) / 64
)

type timewaitRegistrarCounts struct {
	bsd        uint64
	skywalk    uint64
	listener   uint64
	filter     uint64
	namespaces uint64
}

func (counts timewaitRegistrarCounts) String() string {
	return fmt.Sprintf("BSD=%d Skywalk=%d listener=%d packet-filter=%d namespaces=%d", counts.bsd, counts.skywalk, counts.listener, counts.filter, counts.namespaces)
}

type timewaitRegistrarSnapshot struct {
	counts       timewaitRegistrarCounts
	skywalkPorts uint64
	bsdPorts     uint64
}

// registrar reads leave the collector undisturbed by bind-probe socket closes.
// the dump contains other programs' addresses and ports, so only aggregate totals
// and the current arm's own port counts reach the log.
func TestTimeWaitRegistrarReferencesDisappearAfterTheirSocketsEnd(t *testing.T) {
	value := os.Getenv("RANET3_TIMEWAIT_SERVER")
	if value == "" {
		t.Skip("RANET3_TIMEWAIT_SERVER is unset. A remote IPv4 address:port that reads through FIN and closes without sending is required")
	}
	server, err := netip.ParseAddrPort(value)
	if err != nil || !server.Addr().Is4() || !server.Addr().IsGlobalUnicast() || server.Addr().IsLoopback() || server.Port() == 0 {
		t.Skip("RANET3_TIMEWAIT_SERVER lacks a remote IPv4 address:port with a nonzero port")
	}
	if os.Geteuid() != 0 {
		t.Skip("root is required to read the port registrar")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timewaitRegistrarWholeWait)
	defer cancel()
	initial, err := timewaitRegistrarRead(ctx, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.ENOTSUP) {
			t.Skipf("the kernel has no registrar to read through %s: %s", timewaitRegistrarSysctl, timewaitError(err))
		}
		t.Fatalf("setup: initial registrar read: %v", err)
	}
	lastRead := time.Now()
	t.Logf("registrar TCP ports with a Skywalk reference: %d", initial.skywalkPorts)
	t.Logf("registrar TCP ports with a BSD reference: %d", initial.bsdPorts)

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
		t.Fatalf("setup: read net.inet.tcp.msl: %s", timewaitError(err))
	}
	mslDuration := time.Duration(msl) * time.Millisecond
	t.Logf("net.inet.tcp.msl: %d ms", msl)
	if mslDuration <= 0 || mslDuration > timewaitMaxMSL {
		t.Fatalf("setup: MSL is %s, want positive and at most %s", mslDuration, timewaitMaxMSL)
	}
	for _, arm := range []struct {
		name        string
		kernelClose bool
		linger      bool
	}{
		{"ended at once", false, true},
		{"ended after the kernel's close", true, true},
		{"closed plainly", false, false},
	} {
		timewaitRegistrarArm(t, ctx, server, 2*mslDuration, arm.name, arm.kernelClose, arm.linger, &lastRead)
	}
	if err := ctx.Err(); err != nil {
		t.Fatalf("reading: observation cut short by whole-test bound %s: %v", timewaitRegistrarWholeWait, err)
	}
}

func timewaitRegistrarArm(t *testing.T, ctx context.Context, server netip.AddrPort, lifetime time.Duration, name string, kernelClose, linger bool, lastRead *time.Time) {
	t.Helper()
	observing := false
	failSetup := func(format string, args ...any) {
		t.Helper()
		if observing && ctx.Err() != nil {
			t.Fatalf("reading: %s: observation cut short by whole-test bound %s: %v", name, timewaitRegistrarWholeWait, ctx.Err())
		}
		t.Fatalf("setup: %s: %s", name, fmt.Sprintf(format, args...))
	}
	wait := func(until time.Time) {
		t.Helper()
		if err := timewaitWait(ctx, until); err != nil {
			failSetup("whole-test bound %s: %v", timewaitRegistrarWholeWait, err)
		}
	}
	wait(time.Now())
	port := 0
	dialer := net.Dialer{
		Timeout: timewaitRegistrarSocketWait,
		Control: func(_, _ string, raw syscall.RawConn) error {
			var socketErr error
			if err := raw.Control(func(fd uintptr) {
				socketErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
				if socketErr != nil {
					return
				}
				if linger {
					// the kernel refuses options after both halves shut down without this exemption
					socketErr = prepareHostSocket(int(fd))
					if socketErr != nil {
						return
					}
				}
				if socketErr = unix.Bind(int(fd), &unix.SockaddrInet4{}); socketErr != nil {
					return
				}
				local, err := unix.Getsockname(int(fd))
				if err != nil {
					socketErr = err
					return
				}
				address, ok := local.(*unix.SockaddrInet4)
				if !ok || address.Port == 0 {
					socketErr = errors.New("getsockname does not return an assigned IPv4 port")
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
		failSetup("reuse bind(0), socket options and connect within %s: %s", timewaitRegistrarSocketWait, timewaitError(err))
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
	deadline := time.Now().Add(timewaitRegistrarSocketWait)
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
		failSetup("port %d: read server FIN within %s: got %d bytes and %s, want EOF without data", port, timewaitRegistrarSocketWait, n, timewaitError(err))
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
	observing = true
	readings := 0
	summary := "reading ends before socket close"
	defer func() {
		t.Logf("%s: port %d: readings: %d", name, port, readings)
		t.Logf("%s: port %d: summary: %s. Another program's socket on the same port would add a reference this test cannot tell from its own", name, port, summary)
	}()
	read := func() (time.Time, timewaitRegistrarCounts) {
		t.Helper()
		wait(lastRead.Add(timewaitRegistrarReadInterval))
		snapshot, err := timewaitRegistrarRead(ctx, uint16(port))
		at := time.Now()
		*lastRead = at
		readings++
		if err != nil {
			failSetup("port %d: registrar read: %v", port, err)
		}
		wait(at)
		return at, snapshot.counts
	}
	at, before := read()
	t.Logf("%s: port %d: before ending socket: %s, since TIME_WAIT: %s", name, port, before, at.Sub(seen))
	// without a BSD reference before close, this table cannot track the socket's disposal.
	if before.bsd == 0 {
		failSetup("port %d: no BSD reference with the descriptor open in TIME_WAIT. The arm cannot track this socket", port)
	}
	if kernelClose {
		holdUntil := seen.Add(lifetime + timewaitRegistrarKernelWait)
		previous := before
		stateChanged := false
		for next := at.Add(timewaitRegistrarHoldInterval); next.Before(holdUntil); {
			wait(next)
			if !time.Now().Before(holdUntil) {
				break
			}
			state, err := xnuState(raw)
			stateAt := time.Now()
			at, counts := read()
			if counts != previous {
				t.Logf("%s: port %d: descriptor held: %s, since TIME_WAIT: %s", name, port, counts, at.Sub(seen))
				previous = counts
			}
			if err != nil || state != hostTimeWait {
				result := timewaitError(err)
				if err == nil {
					result = timewaitStateReading(raw)
				}
				t.Logf("%s: port %d: TCP_CONNECTION_INFO leaves TIME_WAIT: %s, since TIME_WAIT: %s, registrar at %s: %s", name, port, result, stateAt.Sub(seen), at.Sub(seen), counts)
				stateChanged = true
				break
			}
			next = at.Add(timewaitRegistrarHoldInterval)
		}
		if !stateChanged {
			wait(holdUntil)
			summary = fmt.Sprintf("reading did not happen because TCP_CONNECTION_INFO never leaves TIME_WAIT within %s. Last held counts: %s", lifetime+timewaitRegistrarKernelWait, previous)
			failSetup("port %d: %s", port, summary)
		}
	}
	// spacing before close preserves an immediate post-close read without a burst.
	wait(lastRead.Add(timewaitRegistrarReadInterval))
	if linger {
		if err := tcp.SetLinger(0); err != nil {
			wait(time.Now())
			summary = "linger-zero close is not read because SetLinger(0) fails"
			t.Errorf("reading: %s: port %d: SetLinger(0) with SONPX_SETOPTSHUT: %s", name, port, timewaitError(err))
			return
		}
	}
	if err := tcp.Close(); err != nil {
		failSetup("port %d: close socket: %s", port, timewaitError(err))
	}
	ended := time.Now()
	summary = "post-close observation ends without a disposal reading"
	observeUntil := ended.Add(timewaitRegistrarObservationWait)
	if kernelClose {
		observeUntil = ended.Add(timewaitRegistrarLazyObservationWait)
	}
	if !linger {
		observeUntil = seen.Add(lifetime + timewaitRegistrarPlainWait)
	}
	var firstAbsent, lastPresent time.Time
	var previous timewaitRegistrarCounts
	postReadings := 0
	for {
		at, counts := read()
		postReadings++
		if postReadings == 1 || counts != previous {
			if linger {
				t.Logf("%s: port %d: after ending socket: %s, since close: %s", name, port, counts, at.Sub(ended))
			} else {
				t.Logf("%s: port %d: after ending socket: %s, since close: %s, since TIME_WAIT: %s", name, port, counts, at.Sub(ended), at.Sub(seen))
			}
			previous = counts
		}
		if counts.bsd == 0 {
			firstAbsent = at
			break
		}
		lastPresent = at
		next := at.Add(timewaitRegistrarReadInterval)
		if next.After(observeUntil) {
			wait(observeUntil)
			break
		}
		wait(next)
	}
	if firstAbsent.IsZero() {
		summary = fmt.Sprintf("a BSD reference still stands at %s after close. Observation ends at %s after close", lastPresent.Sub(ended), observeUntil.Sub(ended))
	} else if lastPresent.IsZero() {
		summary = fmt.Sprintf("no BSD reference is observed after close. First absent reading at %s", firstAbsent.Sub(ended))
	} else {
		// the two samples bracket disposal without assigning it a kernel timestamp.
		summary = fmt.Sprintf("a BSD reference stands through %s after close. First absent reading at %s after close", lastPresent.Sub(ended), firstAbsent.Sub(ended))
	}
	if linger {
		bound, boundName := reservationMargin, "exit's reservation margin"
		if kernelClose {
			bound, boundName = timewaitRegistrarLazyWait, "lazy collector bound"
		}
		// a reference past the arm's bound disproves it, but a late absent sample alone does not.
		if firstAbsent.IsZero() || lastPresent.After(ended.Add(bound)) {
			t.Errorf("reading: %s: port %d: BSD reference exceeds the %s %s or remains at observation end. Last present at %s, first absent at %s", name, port, bound, boundName, timewaitSampleTime(lastPresent, ended), timewaitSampleTime(firstAbsent, ended))
		}
	} else {
		// the control must retain a BSD reference after close to show TIME_WAIT tracking.
		if lastPresent.IsZero() {
			t.Errorf("reading: %s: port %d: no BSD reference after plain close. The control does not show TIME_WAIT tracking", name, port)
		}
		// idle collector passes need the full observation allowance, not the abort margin.
		if firstAbsent.IsZero() {
			t.Errorf("reading: %s: port %d: BSD reference remains at observation end, %s since TIME_WAIT", name, port, time.Since(seen))
		}
	}
}

// the parser walks records, not the port range, and discards every address.
// port zero requests only distinct-port totals for the initial privacy-safe log.
func timewaitRegistrarParse(data []byte, port uint16) (timewaitRegistrarSnapshot, error) {
	var snapshot timewaitRegistrarSnapshot
	var skywalkSeen, bsdSeen [timewaitRegistrarPortWords]uint64
	for offset := 0; offset < len(data); {
		if len(data)-offset < timewaitRegistrarHeaderSize {
			return snapshot, fmt.Errorf("offset %d: incomplete namespace header", offset)
		}
		header := data[offset : offset+timewaitRegistrarHeaderSize]
		if header[16] != 0 && header[16] != 4 && header[16] != 16 {
			return snapshot, fmt.Errorf("offset %d: unsupported namespace address length", offset+16)
		}
		protocol := header[17]
		records := binary.NativeEndian.Uint32(header[20:24])
		offset += timewaitRegistrarHeaderSize
		if uint64(records) > uint64((len(data)-offset)/timewaitRegistrarRecordSize) {
			return snapshot, fmt.Errorf("offset %d: namespace record count exceeds remaining reply", offset-timewaitRegistrarHeaderSize+20)
		}
		holdsPort := false
		for range records {
			record := data[offset : offset+timewaitRegistrarRecordSize]
			if binary.NativeEndian.Uint16(record[2:4]) != 0 {
				return snapshot, fmt.Errorf("offset %d: unexpected port range in namespace record", offset+2)
			}
			offset += timewaitRegistrarRecordSize
			if protocol != unix.IPPROTO_TCP {
				continue
			}
			recordPort := binary.NativeEndian.Uint16(record[0:2])
			if port != 0 && recordPort != port {
				continue
			}
			skywalk := binary.NativeEndian.Uint32(record[4:8])
			bsd := binary.NativeEndian.Uint32(record[8:12])
			if port == 0 {
				word, bit := recordPort/64, uint64(1)<<(recordPort%64)
				if skywalk != 0 && skywalkSeen[word]&bit == 0 {
					skywalkSeen[word] |= bit
					snapshot.skywalkPorts++
				}
				if bsd != 0 && bsdSeen[word]&bit == 0 {
					bsdSeen[word] |= bit
					snapshot.bsdPorts++
				}
				continue
			}
			holdsPort = true
			snapshot.counts.skywalk += uint64(skywalk)
			snapshot.counts.bsd += uint64(bsd)
			snapshot.counts.filter += uint64(binary.NativeEndian.Uint32(record[12:16]))
			snapshot.counts.listener += uint64(binary.NativeEndian.Uint32(record[16:20]))
		}
		if holdsPort {
			snapshot.counts.namespaces++
		}
	}
	return snapshot, nil
}

func timewaitRegistrarRead(ctx context.Context, port uint16) (timewaitRegistrarSnapshot, error) {
	var empty timewaitRegistrarSnapshot
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	readCtx, cancel := context.WithTimeout(ctx, timewaitRegistrarReadWait)
	defer cancel()
	type reply struct {
		snapshot timewaitRegistrarSnapshot
		err      error
	}
	// sysctl has no deadline argument. the buffered reply lets the worker finish
	// and leave after the caller stops waiting.
	ready := make(chan reply, 1)
	go func() {
		for attempt := 1; ; attempt++ {
			if err := readCtx.Err(); err != nil {
				ready <- reply{err: err}
				return
			}
			data, err := unix.SysctlRaw(timewaitRegistrarSysctl)
			if errors.Is(err, unix.ENOMEM) && attempt < timewaitRegistrarReadAttempts {
				if err := timewaitWait(readCtx, time.Now().Add(timewaitRegistrarReadInterval)); err != nil {
					ready <- reply{err: err}
					return
				}
				continue
			}
			if err != nil {
				ready <- reply{err: fmt.Errorf("read %s: %w", timewaitRegistrarSysctl, err)}
				return
			}
			snapshot, err := timewaitRegistrarParse(data, port)
			ready <- reply{snapshot, err}
			return
		}
	}()
	select {
	case <-readCtx.Done():
		return empty, fmt.Errorf("registrar read within %s: %w", timewaitRegistrarReadWait, readCtx.Err())
	case result := <-ready:
		if err := readCtx.Err(); err != nil {
			return empty, fmt.Errorf("registrar read within %s: %w", timewaitRegistrarReadWait, err)
		}
		return result.snapshot, result.err
	}
}
