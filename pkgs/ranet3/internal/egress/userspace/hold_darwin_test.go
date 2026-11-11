// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package userspace

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/egress"
)

const (
	// holdServer names a server off the host, address and port, that reads
	// to the client's FIN and closes, which the leaf-first cases then dial in
	// place of a loopback server of the test's own
	holdServer = "RANET3_HOLD_SERVER"
	// netstat is the host's program the cases read the TCP table through,
	// netstatWait bounds one run of it, and tableWait a wait for the table
	// to show a count
	netstat     = "/usr/sbin/netstat"
	netstatWait = 5 * time.Second
	tableWait   = 2 * time.Second
	// holdBench names a measurement to run, as the package's other benches
	// are named
	holdBench = "RANET3_EXIT_BENCH"
)

// netstatRefused is whether err is the host's refusal to start netstat at
// all, as the nix build's sandbox refuses it
func netstatRefused(err error) bool {
	var start *os.PathError
	return errors.As(err, &start) && start.Op == "fork/exec" && start.Path == netstat && errors.Is(start.Err, syscall.EPERM)
}

// tableRows is the host's TCP table from netstat, a path that is not the
// exit's own, each row that names an end in a TCP state as its fields with
// the line. Where the host refuses to start netstat the case skips, and any
// other failure of netstat fails it.
func tableRows(t *testing.T) (rows [][]string, lines []string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), netstatWait)
	defer cancel()
	out, err := exec.CommandContext(ctx, netstat, "-an", "-p", "tcp").Output()
	if netstatRefused(err) {
		t.Skipf("the host refuses to start netstat, so its TCP table cannot be read here: %v", err)
	}
	if err != nil {
		t.Fatalf("netstat: %v", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if fields := strings.Fields(line); len(fields) >= 6 && strings.HasPrefix(fields[0], "tcp") {
			rows, lines = append(rows, fields), append(lines, line)
		}
	}
	return rows, lines
}

// tableEnd is end as netstat writes it
func tableEnd(end netip.AddrPort) string {
	return end.Addr().Unmap().String() + "." + strconv.Itoa(int(end.Port()))
}

// readableTable skips the case where netstat run as this user lists not even
// a loopback listener of the case's own, as on a Mac whose login user's
// netstat lists no TCP row at all where root's lists them: the table is not
// readable by this user there, and the case runs as root
func readableTable(t *testing.T) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("no loopback to listen on: %v", err)
	}
	defer listener.Close()
	own := tableEnd(listener.Addr().(*net.TCPAddr).AddrPort())
	rows, _ := tableRows(t)
	for _, fields := range rows {
		if fields[3] == own && fields[5] == "LISTEN" {
			return
		}
	}
	t.Skipf("netstat lists %d TCP rows and none for this case's own listener on %s: the host's TCP table is not readable by this user, and the case runs as root", len(rows), own)
}

// timeWaitLines is the host's TCP sockets in TIME_WAIT whose remote end is
// server, from the host's table
func timeWaitLines(t *testing.T, server netip.AddrPort) []string {
	t.Helper()
	remote := tableEnd(server)
	rows, all := tableRows(t)
	var lines []string
	for i, fields := range rows {
		if fields[4] == remote && fields[5] == "TIME_WAIT" {
			lines = append(lines, all[i])
		}
	}
	return lines
}

// waitTable waits until the host's table shows want TIME_WAITs toward
// server, and fails with what it shows otherwise
func waitTable(t *testing.T, server netip.AddrPort, want int, when string) {
	t.Helper()
	deadline := time.Now().Add(tableWait)
	for {
		lines := timeWaitLines(t, server)
		if len(lines) == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s the host holds %d sockets in TIME_WAIT toward %s, want %d:\n%s", when, len(lines), server, want, strings.Join(lines, "\n"))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// darwinHoldHarness is a hold harness on XNU's own bound, and the server
// the leaf-first cases dial: the one holdServer names, which the harness's
// Prepare then readies, else a loopback server of the test's own. Its cases
// read the host's table, so it skips where this user cannot read it.
func darwinHoldHarness(t *testing.T) (*relayHarness, netip.AddrPort) {
	t.Helper()
	readableTable(t)
	return darwinHarnessOn(t, xnuHostSockets())
}

// darwinHarnessOn is darwinHoldHarness bounding the host ports through
// platform, none where it is nil
func darwinHarnessOn(t *testing.T, platform *hostSockets) (*relayHarness, netip.AddrPort) {
	t.Helper()
	h, _, _ := holdHarness(t, platform)
	if named := os.Getenv(holdServer); named != "" {
		server, err := netip.ParseAddrPort(named)
		if err != nil {
			t.Fatalf("%s=%q: %v", holdServer, named, err)
		}
		h.mu.Lock()
		h.reach = server.Addr()
		h.mu.Unlock()
		return h, server
	}
	return h, tcpServer(t, netip.MustParseAddr("127.0.0.1"), readsToTheEnd)
}

// timeWaitPair is a loopback connection whose client end closed first and
// reads TIME_WAIT, readied by prepareHostSocket, and the server's address.
// unready closes the readying off with a flag of 0 before the connection
// closes, so the socket is as one never readied.
func timeWaitPair(t *testing.T, unready bool) (*net.TCPConn, netip.AddrPort) {
	t.Helper()
	conn, server := hostPair(t)
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	if unready {
		var set error
		var npx [8]byte
		binary.NativeEndian.PutUint32(npx[4:8], sonpxSetOptShut)
		if err := raw.Control(func(fd uintptr) {
			set = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_NP_EXTENSIONS, string(npx[:]))
		}); err != nil || set != nil {
			t.Fatalf("SO_NP_EXTENSIONS: %v %v", err, set)
		}
	}
	if err := conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err := peerSaw(server, exitWait); !errors.Is(err, io.EOF) {
		t.Fatalf("the server read %v, want the client's FIN", err)
	}
	_ = server.Close()
	deadline := time.Now().Add(exitWait)
	for {
		state, err := xnuState(raw)
		if err != nil {
			t.Fatal(err)
		}
		if state == hostTimeWait {
			return conn, server.LocalAddr().(*net.TCPAddr).AddrPort()
		}
		if time.Now().After(deadline) {
			t.Fatalf("the client's socket reads state %d, want TIME_WAIT", state)
		}
		time.Sleep(time.Millisecond)
	}
}

// XNU refuses the linger of 0 on a socket in TIME_WAIT, shut both ways, with
// EINVAL, and takes it on one prepareHostSocket readied, whose close then
// ends the TIME_WAIT in the host's table
func TestPreparedSocketTakesTheLingerOfZeroInTimeWait(t *testing.T) {
	readableTable(t)
	plain, _ := timeWaitPair(t, true)
	if err := plain.SetLinger(0); !errors.Is(err, syscall.EINVAL) {
		t.Errorf("a socket in TIME_WAIT without SONPX_SETOPTSHUT took the linger with %v, want EINVAL", err)
	}
	prepared, server := timeWaitPair(t, false)
	waitTable(t, server, 1, "before the abort")
	if err := abortSocket(prepared); err != nil {
		t.Fatalf("a socket in TIME_WAIT with SONPX_SETOPTSHUT refused the linger of 0: %v", err)
	}
	waitTable(t, server, 0, "after the abort")
}

// heldMSL is the MSL the harness's hold read
func heldMSL(h *relayHarness) time.Duration {
	return time.Duration(h.x.tcp.holds.msl.Load())
}

// The exit holds a slot for every socket of its own that XNU keeps in
// TIME_WAIT, counted by the server's address and port in the host's own
// table. With six connections open from two sources a seventh is refused past
// the host ports. Once one source's three closed first, the table shows three
// TIME_WAITs and the status three held beside three open, six of six, and once
// the other three closed, six, which still refuse a seventh. One source's four
// leaf-first closes refuse its fifth as share held. A server-first close
// and a reset leave none and hold nothing past the next sweep. Twice the MSL
// on the exit's clock aborts the four, which the table shows gone at once,
// with no abort refused, while their slots stay the margin, and past it a new
// connection is admitted. Close aborts every socket the hold keeps.
func TestHostTimeWaitIsHeldAndAbortedOnTheExitsClock(t *testing.T) {
	third, fourth := netip.MustParseAddr("192.0.2.3"), netip.MustParseAddr("192.0.2.4")
	t.Run("host ports", func(t *testing.T) {
		h, server := darwinHoldHarness(t)
		var first, second []*leafConn
		for i := range 3 {
			first = append(first, h.open(t, netip.AddrPortFrom(leaf4, uint16(43100+i)), server))
			second = append(second, h.open(t, netip.AddrPortFrom(third, uint16(43110+i)), server))
		}
		seventh := netip.AddrPortFrom(fourth, 43120)
		if reason := h.syn(t, seventh, server); reason != reasonHostPorts {
			t.Fatalf("with six connections open a seventh was refused past %q, want %q", reason, reasonHostPorts)
		}
		for _, c := range first {
			h.closeFirst(t, c)
		}
		h.waitConnections(t, 3)
		waitTable(t, server, 3, "after three leaf-first closes")
		status := h.x.Status().Flows
		if got := status.Host; got == nil || *got != (egress.HostHold{Held: 3, Ports: 6, Bound: 6}) {
			t.Errorf("with three held and three open the status counts %+v, want 3 held and 6 host ports of 6", got)
		}
		if flows, held := sourceHeld(status, leaf4); flows != 3 || held != 3 {
			t.Errorf("the status gives %s %d flows with %d held, want 3 with 3", leaf4, flows, held)
		}
		for _, c := range second {
			h.closeFirst(t, c)
		}
		h.waitConnections(t, 0)
		waitTable(t, server, 6, "after six leaf-first closes")
		if held := h.x.flows.heldCount(); held != 6 {
			t.Errorf("after six leaf-first closes %d slots are held, want 6", held)
		}
		if reason := h.syn(t, seventh, server); reason != reasonHostPorts {
			t.Errorf("with six held a seventh was refused past %q, want %q", reason, reasonHostPorts)
		}
	})
	t.Run("share held", func(t *testing.T) {
		h, server := darwinHoldHarness(t)
		for i := range 4 {
			h.closeFirst(t, h.open(t, netip.AddrPortFrom(leaf4, uint16(43200+i)), server))
		}
		h.waitConnections(t, 0)
		waitTable(t, server, 4, "after four leaf-first closes")
		if reason := h.syn(t, netip.AddrPortFrom(leaf4, 43204), server); reason != reasonShareHeld {
			t.Errorf("a source holding four was refused past %q, want %q", reason, reasonShareHeld)
		}
	})
	t.Run("server first and reset", func(t *testing.T) {
		h, _ := darwinHoldHarness(t)
		loopback := netip.MustParseAddr("127.0.0.1")
		serverFirst := tcpServer(t, loopback, sendsAndCloses)
		resetNow := make(chan struct{})
		resetting := tcpServer(t, loopback, resetsOn(resetNow))
		h.closeAfter(t, h.open(t, netip.AddrPortFrom(leaf4, 43300), serverFirst))
		h.open(t, netip.AddrPortFrom(leaf4, 43301), resetting)
		close(resetNow)
		h.waitConnections(t, 0)
		h.advance(mappingSweep)
		if held := h.x.tcp.held(); held != [3]int{} || h.x.flows.heldCount() != 0 {
			t.Errorf("a sweep after a server-first close and a reset the relay holds %v and %d slots, want none", held, h.x.flows.heldCount())
		}
		for _, server := range []netip.AddrPort{serverFirst, resetting} {
			if lines := timeWaitLines(t, server); len(lines) != 0 {
				t.Errorf("the host holds sockets in TIME_WAIT toward %s:\n%s", server, strings.Join(lines, "\n"))
			}
		}
	})
	t.Run("on the exit's clock", func(t *testing.T) {
		h, server := darwinHoldHarness(t)
		for i := range 4 {
			h.closeFirst(t, h.open(t, netip.AddrPortFrom(leaf4, uint16(43400+i)), server))
		}
		h.waitConnections(t, 0)
		waitTable(t, server, 4, "after four leaf-first closes")
		h.advance(2 * heldMSL(h))
		if kept := heldConns(h.x.tcp.holds); len(kept) != 0 {
			t.Errorf("at the hold's end the hold still keeps %d sockets, whose aborts the host refused", len(kept))
		}
		waitTable(t, server, 0, "at once after twice the MSL on the exit's clock")
		h.advance(reservationMargin - time.Second)
		next := netip.AddrPortFrom(leaf4, 43404)
		if reason := h.syn(t, next, server); reason != reasonShareHeld {
			t.Fatalf("short of the margin past the aborts a new flow was refused past %q, want %q", reason, reasonShareHeld)
		}
		h.advance(2 * time.Second)
		h.closeFirst(t, h.open(t, next, server))
		h.waitConnections(t, 0)
	})
	t.Run("close", func(t *testing.T) {
		h, server := darwinHoldHarness(t)
		for i := range 3 {
			h.closeFirst(t, h.open(t, netip.AddrPortFrom(leaf4, uint16(43500+i)), server))
		}
		h.waitConnections(t, 0)
		waitTable(t, server, 3, "after three leaf-first closes")
		closeWithin(t, h.x)
		waitTable(t, server, 0, "after Close")
	})
}

// lastAckServer is a loopback server of the test's own, and the one
// connection it accepts
func lastAckServer(t *testing.T) (netip.AddrPort, <-chan *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("no loopback to serve on: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan *net.TCPConn, 1)
	go func() {
		if conn, err := listener.AcceptTCP(); err == nil {
			accepted <- conn
		}
	}()
	return listener.Addr().(*net.TCPAddr).AddrPort(), accepted
}

// socketInt is conn's socket-level option, as the host reads it: SO_RCVBUF
// or SO_SNDBUF a buffer's size, SO_NREAD the bytes its receive buffer holds,
// SO_NWRITE those its send buffer holds, sent and unacknowledged or unsent
func socketInt(t *testing.T, conn *net.TCPConn, option int) int {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var n int
	var read error
	if err := raw.Control(func(fd uintptr) { n, read = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, option) }); err != nil || read != nil {
		t.Fatalf("read socket option %#x: %v %v", option, err, read)
	}
	return n
}

// lastAck is one connection whose host socket reads LAST_ACK, with bytes the
// host cannot send behind the server's closed window: the server closes first
// and reads nothing, and the leaf writes in steps of a segment, each handed
// whole to the host's socket or to the server's receive buffer before the
// next, until the host's socket holds bytes that stay unsent across stuck,
// then closes. The sizes come from the host, which grows a socket's buffers
// as it likes: the leaf writes to most at the outside, and the case fails
// with what the host read where the host sent it all. It returns the harness,
// the server's end, the socket the end step keeps and the bytes written.
func lastAck(t *testing.T, leafPort uint16) (*relayHarness, *net.TCPConn, *net.TCPConn, int) {
	t.Helper()
	const (
		segment = 16 << 10
		// most is twice the largest receive buffer XNU grows a socket's to
		most  = 16 << 20
		stuck = 200 * time.Millisecond
	)
	h, _, _ := holdHarness(t, xnuHostSockets())
	server, accepted := lastAckServer(t)
	c := h.open(t, netip.AddrPortFrom(leaf4, leafPort), server)
	var conn *net.TCPConn
	select {
	case conn = <-accepted:
	case <-time.After(exitWait):
		t.Fatal("the server accepted no connection")
	}
	t.Cleanup(func() { _ = conn.Close() })
	flow := listedFlow(t, h)
	if err := conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	c.ack = h.stackFIN(t, c)
	sizes := func() string {
		return fmt.Sprintf("the server's receive buffer is %d bytes holding %d, the host's send buffer %d holding %d, the leaf wrote %d",
			socketInt(t, conn, unix.SO_RCVBUF), socketInt(t, conn, unix.SO_NREAD), socketInt(t, flow.conn, unix.SO_SNDBUF), socketInt(t, flow.conn, unix.SO_NWRITE), int(c.seq-leafISN-1))
	}
	payload := bytes.Repeat([]byte{'x'}, segment)
	for written := 0; ; written += segment {
		if socketInt(t, flow.conn, unix.SO_NWRITE) > 0 {
			time.Sleep(stuck)
			if socketInt(t, flow.conn, unix.SO_NWRITE) > 0 {
				break
			}
		}
		if written >= most {
			t.Fatalf("the host sent every byte the leaf wrote, up to %d: %s", most, sizes())
		}
		h.x.link.deliver(tcpSegment(c.leaf, c.server, c.seq, c.ack, tcpACK|tcpPSH, payload))
		c.seq += segment
		deadline := time.Now().Add(exitWait)
		for socketInt(t, conn, unix.SO_NREAD)+socketInt(t, flow.conn, unix.SO_NWRITE) < written+segment {
			if time.Now().After(deadline) {
				t.Fatalf("the relay handed the host's socket short of what the leaf wrote: %s", sizes())
			}
			time.Sleep(time.Millisecond)
		}
	}
	t.Logf("before the leaf's close %s", sizes())
	written := int(c.seq - leafISN - 1)
	h.x.link.deliver(tcpSegment(c.leaf, c.server, c.seq, c.ack, tcpACK|tcpFIN, nil))
	h.waitConnections(t, 0)
	kept := heldConns(h.x.tcp.holds)
	if len(kept) != 1 {
		t.Fatalf("the end step keeps %d sockets with %d slots, want the one", len(kept), h.x.flows.heldCount())
	}
	if state, err := h.x.tcp.holds.state(kept[0]); err != nil || state != hostLastAck {
		t.Fatalf("the host's socket reads state %d (%v), want LAST_ACK: %s", state, err, sizes())
	}
	return h, conn, kept[0], written
}

// A server that closes first and then reads nothing leaves the host's socket
// in LAST_ACK once the leaf writes more than the server's receive buffer takes
// and closes: its last bytes and its FIN wait behind the server's closed
// window. The end step keeps the socket and its slot, every sweep past twice
// the MSL and the margin keeps them, and nothing resets the server, which then
// reads every byte the leaf wrote and the end. The next sweep after the host
// reads the socket closed releases the slot, with no margin. The exit's stop
// aborts such a socket, with the host taking the linger of 0, and gives its
// slot back.
func TestLastAckKeepsItsSlotUntilTheServerAcknowledges(t *testing.T) {
	t.Run("acknowledged", func(t *testing.T) {
		h, conn, kept, written := lastAck(t, 43700)
		for elapsed := time.Duration(0); elapsed <= 2*heldMSL(h)+reservationMargin+mappingSweep; elapsed += mappingSweep {
			h.advance(mappingSweep)
		}
		if got, held := phases(h.x.tcp.holds), h.x.flows.heldCount(); !slices.Equal(got, []holdPhase{holdWatch}) || held != 1 || len(heldConns(h.x.tcp.holds)) != 1 {
			t.Fatalf("past twice the MSL and the margin the hold keeps %v with %d slots, want the socket watched with 1", got, held)
		}
		_ = conn.SetReadDeadline(time.Now().Add(exitWait))
		read, err := io.Copy(io.Discard, conn)
		if err != nil || read != int64(written) {
			t.Fatalf("the server read %d bytes and then %v, want %d and the end", read, err, written)
		}
		deadline := time.Now().Add(exitWait)
		for {
			state, err := h.x.tcp.holds.state(kept)
			if err != nil {
				t.Fatal(err)
			}
			if state == hostClosed {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("once the server read to the end the host's socket reads state %d, want closed", state)
			}
			time.Sleep(time.Millisecond)
		}
		h.advance(mappingSweep)
		if held := h.x.flows.heldCount(); held != 0 || listed(h.x.tcp.holds) != 0 {
			t.Errorf("the sweep after the host read the socket closed holds %d slots, want none and no margin", held)
		}
	})
	t.Run("stop", func(t *testing.T) {
		h, conn, kept, _ := lastAck(t, 43701)
		aborts, aborted := 0, errors.New("no abort")
		h.x.tcp.holds.abort = func(conn *net.TCPConn) error {
			aborts++
			aborted = abortSocket(conn)
			return aborted
		}
		closeWithin(t, h.x)
		if aborts != 1 || aborted != nil {
			t.Errorf("the stop made %d aborts of the socket in LAST_ACK, the last returning %v, want 1 the host took", aborts, aborted)
		}
		if err := stillOpen(kept); err == nil {
			t.Error("the stop left the socket in LAST_ACK open")
		}
		if held := h.x.flows.heldCount(); held != 0 {
			t.Errorf("after the stop %d slots are held, want none", held)
		}
		// what the server reads past its full window, a reset where it took
		// the abort's, for the record of what XNU did
		_ = conn.SetReadDeadline(time.Now().Add(peerWait))
		read, err := io.Copy(io.Discard, conn)
		t.Logf("after the stop the server read %d bytes and then %v", read, err)
	})
}

// the heap and the descriptors one held TIME_WAIT costs, against perFlow:
// what the exit holds with six sockets held after leaf-first closes, three
// from each of two sources within the harness's share of 4, less what it
// holds once their hold and margin have passed on the exit's clock, beside
// the same two reads of an exit that holds nothing
func TestBenchBytesPerHeldTimeWait(t *testing.T) {
	if os.Getenv(holdBench) == "" {
		t.Skipf("%s names no measurement", holdBench)
	}
	const held = 6
	sources := [2]netip.Addr{leaf4, other4}
	measure := func(platform *hostSockets) (heap int64, files int) {
		h, server := darwinHarnessOn(t, platform)
		for i := range held {
			h.closeFirst(t, h.open(t, netip.AddrPortFrom(sources[i%2], uint16(43600+i)), server))
		}
		h.waitConnections(t, 0)
		heapHeld, filesHeld := liveHeap(), openFiles(t)
		h.advance(2 * xnuDefaultMSL(t))
		h.advance(reservationMargin)
		if n := h.x.flows.heldCount(); n != 0 {
			t.Fatalf("%d slots held past the hold and the margin", n)
		}
		heapFreed, filesFreed := liveHeap(), openFiles(t)
		closeWithin(t, h.x)
		return (int64(heapHeld) - int64(heapFreed)) / held, (filesHeld - filesFreed) / held
	}
	heap, files := measure(xnuHostSockets())
	baseHeap, baseFiles := measure(nil)
	t.Logf("bench: per held time_wait %d bytes of heap and %d descriptors over %d held, with no hold %d bytes and %d descriptors, perFlow %d", heap, files, held, baseHeap, baseFiles, perFlow)
}

// xnuDefaultMSL is the host's MSL, which an exit that holds nothing does not
// read
func xnuDefaultMSL(t *testing.T) time.Duration {
	t.Helper()
	msl, err := xnuMSL()
	if err != nil {
		t.Fatal(err)
	}
	return msl
}

// liveHeap is the live heap after a collection
func liveHeap() uint64 {
	runtime.GC()
	runtime.GC()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return stats.HeapAlloc
}

// openFiles is the descriptors the process holds
func openFiles(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/dev/fd")
	if err != nil {
		t.Fatalf("read the descriptors: %v", err)
	}
	return len(entries)
}
