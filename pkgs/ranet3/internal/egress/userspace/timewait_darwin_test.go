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
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const (
	// timewaitPortCount keeps the host's automatic range to four occupied ports.
	timewaitPortCount = 4
	// timewaitSocketWait bounds the four TIME_WAIT connections together.
	timewaitSocketWait = 5 * time.Second
	// timewaitConnectWait bounds both unbound connect readings together.
	timewaitConnectWait = 3 * time.Second
	// timewaitCommandWait bounds each sysctl or netstat invocation.
	timewaitCommandWait = 2 * time.Second
	// timewaitNarrowWait bounds the narrowed stretch with command and socket waits.
	// the command term allows two narrowing writes, netstat, two restore writes
	// and their cleanup repeat. the socket terms allow the four setup connections
	// and both connect readings.
	timewaitNarrowWait = 7*timewaitCommandWait + timewaitSocketWait + timewaitConnectWait
	// the in-process backstop restores even if the test goroutine stalls
	timewaitRestoreWait = 60 * time.Second
	// the outside restore leaves room for both in-process writes and scheduling
	timewaitOutsideMargin = 4 * timewaitCommandWait
	// the detached process outlives the in-process backstop and its writes
	timewaitOutsideWait = timewaitRestoreWait + timewaitOutsideMargin
	// an interrupted test's narrowed range must never become the original range
	timewaitMinimumRange = 8192
	// timewaitRangeFirst names the first automatic port, not the high-port range.
	timewaitRangeFirst = "net.inet.ip.portrange.first"
	// timewaitRangeLast names the last automatic port in the same range.
	timewaitRangeLast = "net.inet.ip.portrange.last"
)

// all child state and the pending record share this lock across restore paths
var timewaitPendingRestore struct {
	sync.Mutex
	outside *timewaitOutsideRestore
}

// a reaped leader must never supply a process group ID for another signal
type timewaitOutsideRestore struct {
	process                 *os.Process
	started                 time.Time
	after                   time.Duration
	status                  unix.WaitStatus
	reaped, killed, retired bool
	errRelease              error
}

// the test narrows the whole host's automatic range, so other programs compete
// for its four ports. the server accepts, reads through the client's FIN, then
// closes without sending data. the Mac holds TIME_WAIT as the active closer,
// and a remote peer keeps the port's other end off this host.
// a detached process restores the range even if this process dies or stays stopped
func TestTimeWaitRefusesItsPortsToAutomaticBindsAndUnboundConnects(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root is required to narrow and restore the host's automatic port range")
	}
	var servers [2]netip.AddrPort
	for i, name := range []string{"RANET3_TIMEWAIT_SERVER", "RANET3_TIMEWAIT_OTHER"} {
		value := os.Getenv(name)
		if value == "" {
			if i == 0 {
				t.Skipf("%s is unset and a remote IPv4 address:port that reads through FIN and closes without sending is required", name)
			}
			continue
		}
		server, err := netip.ParseAddrPort(value)
		if err != nil || !server.Addr().Is4() || !server.Addr().IsGlobalUnicast() || server.Addr().IsLoopback() || server.Port() == 0 {
			t.Skipf("%s lacks a remote IPv4 address:port with a nonzero port", name)
		}
		servers[i] = server
	}
	timewaitCheckPendingRestore(t)
	if servers[1] == servers[0] {
		t.Fatal("setup: RANET3_TIMEWAIT_OTHER must differ from RANET3_TIMEWAIT_SERVER in address or port")
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
		for _, server := range servers {
			if server.IsValid() && prefix.Addr().Unmap() == server.Addr() {
				t.Skip("a remote server is required and the configured address belongs to this host")
			}
		}
	}

	msl, err := unix.SysctlUint32("net.inet.tcp.msl")
	if err != nil {
		t.Fatalf("setup: read net.inet.tcp.msl: %v", err)
	}
	t.Logf("net.inet.tcp.msl: %d ms", msl)
	if lifetime := 2 * time.Duration(msl) * time.Millisecond; lifetime <= timewaitNarrowWait {
		t.Fatalf("setup: twice the MSL is %s, want longer than the %s narrowed bound", lifetime, timewaitNarrowWait)
	}
	first, err := unix.SysctlUint32(timewaitRangeFirst)
	if err != nil {
		t.Fatalf("setup: read %s: %v", timewaitRangeFirst, err)
	}
	last, err := unix.SysctlUint32(timewaitRangeLast)
	if err != nil {
		t.Fatalf("setup: read %s: %v", timewaitRangeLast, err)
	}
	low, high := int(min(first, last)), int(max(first, last))
	if low < 1 || high > 65535 || high-low+1 < timewaitMinimumRange {
		t.Fatalf("setup: automatic range %d..%d needs at least %d ports to exclude another interrupted test's narrowed range", first, last, timewaitMinimumRange)
	}
	// one candidate window avoids scanning the host's range or opening many sockets.
	base := high - timewaitPortCount + 1
	if err := timewaitProbeWindow(base); err != nil {
		t.Fatalf("setup: probe window %d..%d: %v", base, high, err)
	}
	timewaitCheckDeadline(t, timewaitRestoreWait, 2*timewaitCommandWait)
	restoreBy := time.Now().Add(timewaitRestoreWait)
	outside := timewaitStartOutsideRestore(t, int(first), int(last), timewaitOutsideWait)

	// restoration and narrowing share a lock so a signal cannot restore between
	// the two writes and leave the second narrowing write behind it.
	var rangeMu sync.Mutex
	finished := false
	restore := func(stderr bool) error {
		rangeMu.Lock()
		defer rangeMu.Unlock()
		finished = true
		// both writes run even if the first fails and another restore may run safely.
		return outside.finish(t, stderr, errors.Join(timewaitSetPort(timewaitRangeFirst, int(first)), timewaitSetPort(timewaitRangeLast, int(last))))
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, unix.SIGINT, unix.SIGTERM, unix.SIGHUP, unix.SIGQUIT)
	timer := time.NewTimer(time.Until(restoreBy))
	stop := make(chan struct{})
	stopped := make(chan struct{})
	t.Cleanup(func() {
		err := restore(false)
		timer.Stop()
		signal.Stop(signals)
		close(stop)
		<-stopped
		if err != nil {
			t.Errorf("restore automatic port range: %v", err)
		}
	})
	go func() {
		defer close(stopped)
		var reason string
		var received os.Signal
		select {
		case received = <-signals:
			reason = received.String()
		case <-timer.C:
			reason = fmt.Sprintf("%s restoration bound", timewaitRestoreWait)
		case <-stop:
			return
		}
		err := restore(true)
		fmt.Fprintf(os.Stderr, "TIME_WAIT test: %s, restore automatic port range: %v\n", reason, err)
		timewaitExitSignal(received)
	}()
	failSetup := func(format string, args ...any) {
		t.Helper()
		if err := restore(false); err != nil {
			t.Errorf("restore automatic port range: %v", err)
		}
		t.Fatalf("setup: "+format, args...)
	}
	timewaitCheckDeadline(t, timewaitRestoreWait, 2*timewaitCommandWait)
	err = func() error {
		rangeMu.Lock()
		defer rangeMu.Unlock()
		if finished || !time.Now().Before(restoreBy) {
			return errors.New("restoration has already started")
		}
		windowFirst, windowLast := base, high
		if first > last {
			windowFirst, windowLast = windowLast, windowFirst
		}
		if err := outside.check(); err != nil {
			return err
		}
		if err := timewaitSetPort(timewaitRangeFirst, windowFirst); err != nil {
			return err
		}
		if !time.Now().Before(restoreBy) {
			return errors.New("restoration bound passes before narrowing completes")
		}
		return timewaitSetPort(timewaitRangeLast, windowLast)
	}()
	if err != nil {
		failSetup("narrow automatic range: %v", err)
	}
	socketDeadline := time.Now().Add(timewaitSocketWait)
	for i := 0; i < timewaitPortCount; i++ {
		if err := timewaitCloseFromHost(servers[0], base+i, socketDeadline); err != nil {
			failSetup("leave port %d in TIME_WAIT: %v", base+i, err)
		}
	}
	counts, err := timewaitCountPorts(base)
	if err != nil {
		failSetup("count host TIME_WAIT sockets: %v", err)
	}
	total := 0
	for _, count := range counts {
		total += count
	}
	t.Logf("time-wait sockets: %d", total)
	for i, count := range counts {
		if count != 1 {
			failSetup("port %d has %d host TIME_WAIT sockets, want one on each of the four ports (total %d)", base+i, count, total)
		}
	}

	readBind := func(reading string, port int, reuse, wantSuccess bool) {
		t.Helper()
		fd, err := timewaitSocket(reuse)
		if err != nil {
			failSetup("%s: open socket: %v", reading, err)
		}
		defer unix.Close(fd)
		bindErr := unix.Bind(fd, &unix.SockaddrInet4{Port: port})
		gotPort, err := timewaitLocalPort(fd)
		if err != nil {
			failSetup("%s: read local port: %v", reading, err)
		}
		got := timewaitResult(bindErr, gotPort)
		t.Logf("%s: %s", reading, got)
		if wantSuccess {
			if bindErr != nil || gotPort == 0 || (port != 0 && gotPort != port) {
				t.Errorf("premise: %s: got %s, want a successful bind to the requested port", reading, got)
			}
			return
		}
		if bindErr == nil {
			t.Errorf("premise: %s: got %s, want automatic port allocation to fail", reading, got)
		} else if !timewaitAddressError(bindErr) {
			failSetup("%s: got %s, not an address-allocation failure", reading, got)
		}
	}
	readBind("plain bind(0) with every range port in TIME_WAIT", 0, false, false)
	// port zero still uses the wildcard automatic-port scan with SO_REUSEADDR,
	// so the premise excludes reuse bind(0), not just plain bind(0).
	readBind("reuse bind(0) with every range port in TIME_WAIT", 0, true, false)
	readConnect := func(reading string, server netip.AddrPort, deadline time.Time) {
		t.Helper()
		fd, err := timewaitSocket(false)
		if err != nil {
			failSetup("%s: open socket: %v", reading, err)
		}
		started := time.Now()
		// a policy can hand the flow to a network extension, returning EINPROGRESS
		// before any port is taken. the reading waits for the outcome and reads
		// the local port on both sides of the wait.
		connectErr := unix.Connect(fd, &unix.SockaddrInet4{Addr: server.Addr().As4(), Port: int(server.Port())})
		immediate := timewaitResult(connectErr, 0)
		connected := false
		if connectErr == nil {
			immediate, connected = timewaitConnectPeer(fd)
		}
		peerMissing := connectErr == nil && !connected
		firstPort, err := timewaitLocalPort(fd)
		if err != nil {
			unix.Close(fd)
			got := fmt.Sprintf("immediate %s, final unavailable, local port unavailable, wait %s, getsockname: %v", immediate, time.Since(started), err)
			t.Logf("%s: %s", reading, got)
			if connected {
				t.Errorf("premise: %s: %s, want refusal without connecting", reading, got)
				return
			}
			failSetup("%s: undecided, %s", reading, got)
		}
		port := firstPort
		finalErr := connectErr
		final := immediate
		pending := false
		var outcomeErr error
		if firstPort == 0 && (connectErr == nil || errors.Is(connectErr, unix.EINPROGRESS)) {
			finalErr, pending, outcomeErr = timewaitAwaitConnect(fd, deadline)
			switch {
			case outcomeErr != nil:
				final = "unavailable"
			case pending:
				final = "pending"
			case finalErr == nil:
				var hasPeer bool
				final, hasPeer = timewaitConnectPeer(fd)
				connected = connected || hasPeer
				peerMissing = peerMissing || !hasPeer
			default:
				final = timewaitResult(finalErr, 0)
			}
			port, err = timewaitLocalPort(fd)
			if err != nil {
				port = -1
				outcomeErr = errors.Join(outcomeErr, fmt.Errorf("read final local port: %w", err))
			}
		}
		// closing before logging or restoration stops any connect that gets a port.
		unix.Close(fd)
		waited := time.Since(started)
		if outcomeErr != nil {
			final += fmt.Sprintf(" (observation error: %v)", outcomeErr)
		}
		localPort := strconv.Itoa(port)
		if port < 0 {
			localPort = "unavailable"
		}
		got := fmt.Sprintf("immediate %s, final %s, local port %d -> %s, wait %s", immediate, final, firstPort, localPort, waited)
		t.Logf("%s: %s", reading, got)
		switch {
		case firstPort > 0 || port > 0 || connected:
			t.Errorf("premise: %s: %s, want refusal without allocating a port or connecting", reading, got)
		case outcomeErr != nil || pending || peerMissing || !timewaitAddressError(finalErr):
			failSetup("%s: undecided, %s", reading, got)
		}
	}
	connectDeadline := time.Now().Add(timewaitConnectWait)
	readConnect("unbound connect with every range port in TIME_WAIT", servers[0], connectDeadline)
	if servers[1].IsValid() {
		readConnect("unbound connect to another destination", servers[1], connectDeadline)
	} else {
		t.Log("unbound connect to another destination: not taken (RANET3_TIMEWAIT_OTHER is unset)")
	}
	readBind(fmt.Sprintf("reuse bind(%d) over its TIME_WAIT", base), base, true, true)
	if err := restore(false); err != nil {
		t.Fatalf("restore automatic port range before the final reading: %v", err)
	}
	readBind("plain bind(0) after restoring the range", 0, false, true)
}

// timewaitSetPort uses the full sysctl path because unix exposes no darwin
// sysctl setter, and reads the value back to detect clamping as well as errors.
func timewaitSetPort(name string, value int) error {
	ctx, cancel := context.WithTimeout(context.Background(), timewaitCommandWait)
	defer cancel()
	output, err := exec.CommandContext(ctx, "/usr/sbin/sysctl", "-w", fmt.Sprintf("%s=%d", name, value)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("set %s=%d: %w (%s)", name, value, err, strings.TrimSpace(string(output)))
	}
	got, err := unix.SysctlUint32(name)
	if err != nil {
		return fmt.Errorf("read back %s: %w", name, err)
	}
	if got != uint32(value) {
		return fmt.Errorf("set %s=%d: read back %d", name, value, got)
	}
	return nil
}

// timewaitSocket opens an IPv4 TCP socket without binding it and uses nonblocking
// mode so the connect readings can share a deadline through poll.
func timewaitSocket(reuse bool) (int, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_TCP)
	if err != nil {
		return -1, err
	}
	unix.CloseOnExec(fd)
	if err = unix.SetNonblock(fd, true); err == nil && reuse {
		err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	}
	if err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

// timewaitProbeWindow holds all four plain wildcard binds together, then closes
// them without connecting, so this check creates no TIME_WAIT sockets.
func timewaitProbeWindow(base int) error {
	for i := 0; i < timewaitPortCount; i++ {
		fd, err := timewaitSocket(false)
		if err != nil {
			return fmt.Errorf("open probe socket: %w", err)
		}
		defer unix.Close(fd)
		if err := unix.Bind(fd, &unix.SockaddrInet4{Port: base + i}); err != nil {
			return fmt.Errorf("plain bind(%d): %w", base+i, err)
		}
	}
	return nil
}

// timewaitCloseFromHost sends FIN first and checks the socket's state before
// closing its descriptor. the server sends no data and closes after that FIN.
func timewaitCloseFromHost(server netip.AddrPort, port int, deadline time.Time) error {
	dialer := net.Dialer{
		Deadline: deadline,
		Control: func(_, _ string, raw syscall.RawConn) error {
			var socketErr error
			if err := raw.Control(func(fd uintptr) {
				socketErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
				if socketErr == nil {
					socketErr = unix.Bind(int(fd), &unix.SockaddrInet4{Port: port})
				}
			}); err != nil {
				return err
			}
			return socketErr
		},
	}
	conn, err := dialer.Dial("tcp4", server.String())
	if err != nil {
		return fmt.Errorf("reuse bind and connect: %s", timewaitError(err))
	}
	defer conn.Close()
	if err := conn.SetDeadline(deadline); err != nil {
		return fmt.Errorf("set connection deadline: %s", timewaitError(err))
	}
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return fmt.Errorf("connect returned %T, want *net.TCPConn", conn)
	}
	if err := tcp.CloseWrite(); err != nil {
		return fmt.Errorf("shutdown write side: %s", timewaitError(err))
	}
	var data [1]byte
	if n, err := tcp.Read(data[:]); n != 0 || err != io.EOF {
		return fmt.Errorf("read server FIN: got %d bytes and %s, want EOF without data", n, timewaitError(err))
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		return fmt.Errorf("access connection descriptor: %s", timewaitError(err))
	}
	state, err := xnuState(raw)
	if err != nil {
		return fmt.Errorf("read TCP_CONNECTION_INFO: %s", timewaitError(err))
	}
	if state != hostTimeWait {
		return fmt.Errorf("%s, want TIME_WAIT", timewaitStateReading(raw))
	}
	return nil
}

// diagnostics preserve numbers that xnuState folds into hostFinWait for FIN_WAIT_1
// and FIN_WAIT_2, and into hostOther for LISTEN, SYN_SENT, SYN_RECEIVED,
// ESTABLISHED, CLOSE_WAIT and unknown states
func timewaitRawState(raw syscall.RawConn) (int, error) {
	var info *unix.TCPConnectionInfo
	var errOption error
	if err := raw.Control(func(fd uintptr) {
		info, errOption = unix.GetsockoptTCPConnectionInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_CONNECTION_INFO)
	}); err != nil {
		return 0, err
	}
	if errOption != nil {
		return 0, errOption
	}
	return int(info.State), nil
}

// a failed diagnostic read must not look like a raw state of zero
func timewaitStateReading(raw syscall.RawConn) string {
	state, err := timewaitRawState(raw)
	if err != nil {
		return "raw TCP_CONNECTION_INFO read failed: " + timewaitError(err)
	}
	return fmt.Sprintf("raw TCP_CONNECTION_INFO state %d", state)
}

// timewaitCountPorts reads the host's socket table independently of the closed
// descriptors and counts IPv4 sockets on each local port across all addresses.
func timewaitCountPorts(base int) ([timewaitPortCount]int, error) {
	var counts [timewaitPortCount]int
	ctx, cancel := context.WithTimeout(context.Background(), timewaitCommandWait)
	defer cancel()
	rows, _, err := timewaitTableRows(ctx)
	if err != nil {
		return counts, fmt.Errorf("netstat: %w", err)
	}
	for _, fields := range rows {
		if fields[0] != "tcp4" || fields[5] != "TIME_WAIT" {
			continue
		}
		port, err := timewaitTablePort(fields[3])
		if err != nil {
			return counts, err
		}
		if port >= base && port < base+timewaitPortCount {
			counts[port-base]++
		}
	}
	return counts, nil
}

// timewaitConnectPeer confirms only IPv4 peers and describes missing peers or
// other address families so either caller can report an undecided reading.
func timewaitConnectPeer(fd int) (result string, connected bool) {
	peer, err := unix.Getpeername(fd)
	if err != nil {
		return fmt.Sprintf("ready without an error and without a peer (getpeername: %s)", timewaitResult(err, 0)), false
	}
	if _, ok := peer.(*unix.SockaddrInet4); !ok {
		return fmt.Sprintf("a peer of another family was returned (Go type %T)", peer), false
	}
	return "IPv4 peer connected", true
}

// timewaitAwaitConnect waits for readiness and reads SO_ERROR within the shared
// deadline. a zero error still needs the caller's peer check.
// an interrupted poll keeps that deadline and a timeout leaves the result pending.
func timewaitAwaitConnect(fd int, deadline time.Time) (outcome error, pending bool, err error) {
	poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
	for {
		left := time.Until(deadline)
		if left <= 0 {
			return nil, true, nil
		}
		n, err := unix.Poll(poll, int((left+time.Millisecond-1)/time.Millisecond))
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return nil, false, fmt.Errorf("poll connect: %w", err)
		}
		if n == 0 {
			return nil, true, nil
		}
		code, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
		if err != nil {
			return nil, false, fmt.Errorf("read SO_ERROR: %w", err)
		}
		if code != 0 {
			return syscall.Errno(code), false, nil
		}
		return nil, false, nil
	}
}

// timewaitAddressError accepts allocation exhaustion without pinning which of
// the two address errnos a bind or implicit bind returns on this kernel.
func timewaitAddressError(err error) bool {
	return errors.Is(err, unix.EADDRINUSE) || errors.Is(err, unix.EADDRNOTAVAIL)
}

// timewaitResult keeps each reading to a port or a symbolic errno.
func timewaitResult(err error, port int) string {
	if err == nil {
		return fmt.Sprintf("port %d", port)
	}
	return timewaitError(err)
}

// network errors can embed addresses, so diagnostics expose only errno or error kind
func timewaitError(err error) string {
	if err == nil {
		return "success"
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		if name := unix.ErrnoName(errno); name != "" {
			return name
		}
		return fmt.Sprintf("errno %d", errno)
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return "deadline exceeded"
	}
	if errors.Is(err, io.EOF) {
		return "EOF"
	}
	if errors.Is(err, net.ErrClosed) {
		return "socket closed"
	}
	return fmt.Sprintf("error of type %T", err)
}

// the caller owns the deadline and receives no command output in an error
func timewaitTableRows(ctx context.Context) ([][]string, []string, error) {
	out, err := exec.CommandContext(ctx, netstat, "-an", "-p", "tcp").Output()
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		return nil, nil, err
	}
	var rows [][]string
	var lines []string
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 6 && strings.HasPrefix(fields[0], "tcp") {
			rows = append(rows, fields)
			lines = append(lines, line)
		}
	}
	return rows, lines, nil
}

// only the port is retained from an endpoint, and malformed rows never expose host addresses
func timewaitTablePort(end string) (int, error) {
	separator := strings.LastIndexByte(end, '.')
	if separator < 0 {
		return 0, errors.New("a TCP row has no local port")
	}
	part := end[separator+1:]
	if part == "*" {
		return 0, nil
	}
	port, err := strconv.Atoi(part)
	if err != nil || port < 0 || port > 65535 {
		return 0, errors.New("a TCP row has an invalid local port")
	}
	return port, nil
}

// a returned address family is checked before any port is read
func timewaitLocalPort(fd int) (int, error) {
	local, err := unix.Getsockname(fd)
	if err != nil {
		return 0, err
	}
	address, ok := local.(*unix.SockaddrInet4)
	if !ok {
		return 0, fmt.Errorf("getsockname returned %T, want an IPv4 address", local)
	}
	return address.Port, nil
}

// the binary's alarm must leave room for the last in-process restore and both writes
func timewaitCheckDeadline(t *testing.T, backstop, writes time.Duration) {
	t.Helper()
	if deadline, set := t.Deadline(); set {
		left, needed := time.Until(deadline), backstop+writes
		if left < needed {
			t.Fatalf("setup: test deadline has %.3f seconds left, need %.3f seconds before narrowing. Pass -timeout 0 or increase -timeout to leave more than %.3f seconds for this test", left.Seconds(), needed.Seconds(), needed.Seconds())
		}
	}
}

// the caller holds the shared lock so registration cannot race another test's check
func timewaitPendingRestoreError() error {
	if outside := timewaitPendingRestore.outside; outside != nil {
		if err := outside.wait(unix.WNOHANG); err != nil {
			return fmt.Errorf("a wait on the outside restore of an earlier test in this run failed: %w", err)
		}
		if outside.reaped {
			return fmt.Errorf("a restore of an earlier test in this run ended without a successful retire: %w", outside.exitedError())
		}
		return fmt.Errorf("a restore of an earlier test in this run is still pending. Its outside write time is %s (%s after its start)", outside.started.Add(outside.after).Format(time.RFC3339Nano), outside.after)
	}
	return nil
}

// a partial failed restore can leave a range that passes the size floor
func timewaitCheckPendingRestore(t *testing.T) {
	t.Helper()
	timewaitPendingRestore.Lock()
	err := timewaitPendingRestoreError()
	timewaitPendingRestore.Unlock()
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
}

// a separate session survives the binary and terminal without retaining their streams.
// the leader stays unreaped until its group is killed or a wait finds it exited.
func timewaitStartOutsideRestore(t *testing.T, first, last int, after time.Duration) *timewaitOutsideRestore {
	t.Helper()
	timewaitPendingRestore.Lock()
	defer timewaitPendingRestore.Unlock()
	if err := timewaitPendingRestoreError(); err != nil {
		t.Fatalf("setup: %v", err)
	}
	null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("setup: open null device for outside restore: %v", err)
	}
	defer null.Close()
	const script = `/bin/sleep "$1"
/usr/sbin/sysctl -w "net.inet.ip.portrange.first=$2"
/usr/sbin/sysctl -w "net.inet.ip.portrange.last=$3"
`
	seconds := strconv.FormatInt(int64((after+time.Second-1)/time.Second), 10)
	args := []string{"/bin/sh", "-c", script, "timewait-restore", seconds, strconv.Itoa(first), strconv.Itoa(last)}
	started := time.Now()
	process, err := os.StartProcess("/bin/sh", args, &os.ProcAttr{
		Env:   []string{},
		Dir:   "/",
		Files: []*os.File{null, null, null},
		Sys:   &syscall.SysProcAttr{Setsid: true},
	})
	if err != nil {
		t.Fatalf("setup: start outside restore before narrowing: %v", err)
	}
	outside := &timewaitOutsideRestore{process: process, started: started, after: after}
	timewaitPendingRestore.outside = outside
	return outside
}

// the shared lock serializes this sole wait mechanism and its cached terminal status.
// releasing the process handle after reaping avoids a second wait through another API.
func (outside *timewaitOutsideRestore) wait(options int) error {
	if outside.reaped {
		return outside.errRelease
	}
	var status unix.WaitStatus
	var pid int
	var err error
	for {
		pid, err = unix.Wait4(outside.process.Pid, &status, options, nil)
		if !errors.Is(err, unix.EINTR) {
			break
		}
	}
	if err != nil {
		return fmt.Errorf("wait for outside restore: %w", err)
	}
	if pid == 0 {
		return nil
	}
	if !status.Exited() && !status.Signaled() {
		return fmt.Errorf("outside restore wait returns a nonterminal status %d", status)
	}
	outside.status = status
	outside.reaped = true
	outside.errRelease = outside.process.Release()
	return outside.errRelease
}

// only a normal successful shell exit proves that its write path completed
func (outside *timewaitOutsideRestore) exitedError() error {
	if outside.status.Exited() && outside.status.ExitStatus() == 0 {
		return errors.New("outside restore already exited and has already written the range")
	}
	if outside.status.Signaled() {
		return fmt.Errorf("outside restore already exited with signal %s (%d) and may already have written the range", outside.status.Signal(), outside.status.Signal())
	}
	return fmt.Errorf("outside restore already exited with status %d and may already have written the range", outside.status.ExitStatus())
}

// signal zero cannot distinguish a waiting child from an unreaped exited child
func (outside *timewaitOutsideRestore) check() error {
	timewaitPendingRestore.Lock()
	defer timewaitPendingRestore.Unlock()
	if err := outside.wait(unix.WNOHANG); err != nil {
		return err
	}
	if outside.reaped {
		return outside.exitedError()
	}
	return nil
}

// a failed write leaves the child alone, but only a successful nonblocking wait
// permits an armed claim. a wait failure keeps the pending record for later tests.
func (outside *timewaitOutsideRestore) finish(t *testing.T, stderr bool, errWrites error) (err error) {
	t.Helper()
	timewaitPendingRestore.Lock()
	defer timewaitPendingRestore.Unlock()
	if outside.retired {
		return errWrites
	}
	report := ""
	defer func() {
		if err != nil {
			if report != "" {
				report += ". "
			}
			report += strings.ReplaceAll(err.Error(), "\n", " | ")
		}
		line := fmt.Sprintf("outside restore: %s, observed %s after its start", report, time.Since(outside.started))
		if stderr {
			fmt.Fprintln(os.Stderr, line)
		} else {
			t.Log(line)
		}
	}()
	if err := outside.wait(unix.WNOHANG); err != nil {
		return errors.Join(errWrites, err)
	}
	if !outside.reaped {
		if errWrites != nil && !outside.killed {
			return fmt.Errorf("outside restore remains armed and writes %s after its start: %w", outside.after, errWrites)
		}
		if !outside.killed {
			errKill := unix.Kill(-outside.process.Pid, unix.SIGKILL)
			if errKill != nil {
				if err := outside.wait(unix.WNOHANG); err != nil {
					return errors.Join(errKill, err)
				}
				if !outside.reaped {
					return fmt.Errorf("outside restore remains armed and writes %s after its start, cannot stop its process group: %w", outside.after, errKill)
				}
			} else {
				outside.killed = true
			}
		}
		if !outside.reaped {
			if err := outside.wait(0); err != nil {
				return err
			}
		}
	}
	if !outside.killed || !outside.status.Signaled() || outside.status.Signal() != unix.SIGKILL {
		return errors.Join(errWrites, outside.exitedError())
	}
	report = fmt.Sprintf("still waiting, ended by the test's kill, wait signal %s (%d)", outside.status.Signal(), outside.status.Signal())
	if errWrites != nil {
		return errWrites
	}
	outside.retired = true
	timewaitPendingRestore.outside = nil
	return nil
}

// the default quit action must finish its dump rather than race an explicit exit
func timewaitExitSignal(received os.Signal) {
	if received == unix.SIGQUIT {
		signal.Reset(unix.SIGQUIT)
		if err := unix.Kill(os.Getpid(), unix.SIGQUIT); err == nil {
			select {}
		} else {
			fmt.Fprintf(os.Stderr, "TIME_WAIT test: resend SIGQUIT: %v\n", err)
		}
	}
	os.Exit(1)
}
