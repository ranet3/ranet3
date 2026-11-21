// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package userspace

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/netnstest"
)

// A leaf's connection is ended in the stack and dialed again toward the
// server through Prepare: bytes cross both ways whole, the leaf's half close
// reaches the server while the server still sends, no copy buffer is held
// while the connection idles, and once both ends close the exit holds nothing
// of it, its mapping among them
func TestLeafConnectionIsRelayedBothWaysThroughPrepare(t *testing.T) {
	r := newLeafRig(t, func(rt Runtime) (*Exit, error) { return New(exitConfig(), rt) })
	payload := make([]byte, 1<<20)
	for i := range payload {
		payload[i] = byte(rand.Uint32())
	}
	for _, family := range []struct {
		name         string
		leaf, server netip.Addr
	}{{"ipv4", rigLeaf4.Addr(), rigServer4.Addr()}, {"ipv6", rigLeaf6.Addr(), rigServer6.Addr()}} {
		t.Run(family.name, func(t *testing.T) {
			received := make(chan []byte, 1)
			server := r.listen(family.server, 7, func(conn net.Conn) {
				defer conn.Close()
				in := bufio.NewReader(conn)
				if line, err := in.ReadString('\n'); err != nil || line != "ping\n" {
					received <- nil
					return
				}
				if _, err := conn.Write([]byte("pong\n")); err != nil {
					received <- nil
					return
				}
				rest, err := io.ReadAll(in)
				if err != nil {
					received <- nil
					return
				}
				received <- rest
				_, _ = conn.Write(rest)
			})
			r.mu.Lock()
			r.prepared = nil
			r.mu.Unlock()
			conn, err := r.dial(netip.AddrPortFrom(family.leaf, 0), server, rigSettle)
			if err != nil {
				t.Fatalf("dial %s: %v", server, err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(exitWait))
			if _, err := conn.Write([]byte("ping\n")); err != nil {
				t.Fatal(err)
			}
			reply := make([]byte, len("pong\n"))
			if _, err := io.ReadFull(conn, reply); err != nil || string(reply) != "pong\n" {
				t.Fatalf("read %q: %v, want pong", reply, err)
			}
			waitFor(t, "every copy buffer back while the connection idles", func() bool { return r.exit.tcp.copies.out.Load() == 0 })
			if _, err := conn.Write(payload); err != nil {
				t.Fatal(err)
			}
			if err := conn.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			echoed, err := io.ReadAll(conn)
			if err != nil {
				t.Fatalf("read after the half close: %v", err)
			}
			select {
			case got := <-received:
				if !bytes.Equal(got, payload) {
					t.Errorf("the server received %d bytes, want the leaf's %d whole", len(got), len(payload))
				}
			case <-time.After(exitWait):
				t.Fatal("the server saw no end of the leaf's bytes")
			}
			if !bytes.Equal(echoed, payload) {
				t.Errorf("the leaf received %d bytes after its half close, want the server's %d whole", len(echoed), len(payload))
			}
			waitFor(t, "the connection's counts given back", func() bool { return r.exit.tcp.held() == [3]int{} })
			waitFor(t, "the connection's mapping ended", func() bool {
				r.exit.tcp.mappings.mu.Lock()
				defer r.exit.tcp.mappings.mu.Unlock()
				return len(r.exit.tcp.mappings.byInside) == 0 && len(r.exit.tcp.mappings.byOutside) == 0
			})
			if out := r.exit.tcp.copies.out.Load(); out != 0 {
				t.Errorf("%d copy buffers held once the connection closed", out)
			}
			r.mu.Lock()
			prepared := slices.Clone(r.prepared)
			r.mu.Unlock()
			if len(prepared) == 0 || slices.ContainsFunc(prepared, func(to netip.AddrPort) bool { return to != server }) {
				t.Errorf("Prepare readied sockets toward %v, want each toward %s", prepared, server)
			}
		})
	}
}

// The exit's stop resets each connection it relays toward the leaf and toward
// the server, and once the exit is enabled again a new connection is dialed
// and relayed
func TestWithdrawalResetsEachRelayedConnection(t *testing.T) {
	r := newLeafRig(t, func(rt Runtime) (*Exit, error) { return New(exitConfig(), rt) })
	ended := make(chan error, 2)
	server := r.listen(rigServer4.Addr(), 9, func(conn net.Conn) {
		defer conn.Close()
		if _, err := conn.Write([]byte("ready\n")); err != nil {
			ended <- err
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(exitWait))
		_, err := io.Copy(io.Discard, conn)
		ended <- err
	})
	leaf := netip.AddrPortFrom(rigLeaf4.Addr(), 0)
	conn, err := r.dial(leaf, server, rigSettle)
	if err != nil {
		t.Fatalf("dial %s: %v", server, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(exitWait))
	ready := make([]byte, len("ready\n"))
	if _, err := io.ReadFull(conn, ready); err != nil {
		t.Fatalf("read %q: %v", ready, err)
	}
	r.exit.SetEnabled(false)
	if _, err := io.ReadAll(conn); !errors.Is(err, syscall.ECONNRESET) {
		t.Errorf("the leaf read %v once the exit stopped, want a reset", err)
	}
	select {
	case err := <-ended:
		if !errors.Is(err, syscall.ECONNRESET) {
			t.Errorf("the server read %v once the exit stopped, want a reset", err)
		}
	case <-time.After(exitWait):
		t.Fatal("the server's connection outlived the exit's stop")
	}
	waitFor(t, "the connection's counts given back", func() bool { return r.exit.tcp.held() == [3]int{} })
	r.exit.SetEnabled(true)
	waitFor(t, "the exit taking again", r.exit.taking.Load)
	again, err := r.dial(leaf, server, rigSettle)
	if err != nil {
		t.Fatalf("dial %s once enabled again: %v", server, err)
	}
	defer again.Close()
	_ = again.SetDeadline(time.Now().Add(exitWait))
	if _, err := io.ReadFull(again, ready); err != nil {
		t.Errorf("read once enabled again: %v", err)
	}
}

// A connection the dial opened watches no ICMP errors once it is open, so
// Linux takes an error about it as a soft error that ends nothing (RFC 5382
// REQ-10). A socket still watching would read the error as its errno, which
// the relay takes for the connection's end.
func TestDialedConnectionWatchesNoErrors(t *testing.T) {
	for _, c := range []struct {
		leaf, loopback netip.Addr
		level, option  int
	}{
		{leaf4, netip.MustParseAddr("127.0.0.1"), syscall.IPPROTO_IP, syscall.IP_RECVERR},
		{leaf6, netip.IPv6Loopback(), syscall.IPPROTO_IPV6, syscall.IPV6_RECVERR},
	} {
		t.Run(c.loopback.String(), func(t *testing.T) {
			listener, err := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(netip.AddrPortFrom(c.loopback, 0)))
			if err != nil {
				t.Skipf("no loopback to dial: %v", err)
			}
			defer listener.Close()
			p := &fakePlatform{}
			x := &Exit{rt: Runtime{Platform: p.platform()}}
			x.rt.Platform.Prepare = func(string, netip.AddrPort, syscall.RawConn) error { return nil }
			conn, _, failure := (&tcpRelay{x: x}).dial(context.Background(), netip.AddrPortFrom(c.leaf, 0), listener.Addr().(*net.TCPAddr).AddrPort())
			if conn == nil {
				t.Fatalf("dial: %v", failure.err)
			}
			defer conn.Close()
			raw, err := conn.SyscallConn()
			if err != nil {
				t.Fatal(err)
			}
			var watching int
			var read error
			if err := raw.Control(func(fd uintptr) { watching, read = syscall.GetsockoptInt(int(fd), c.level, c.option) }); err != nil {
				t.Fatal(err)
			}
			if read != nil {
				t.Fatal(read)
			}
			if watching != 0 {
				t.Error("the open connection watches its ICMP errors, so one about it would end it")
			}
		})
	}
}

// A port the host gives a new mapping that another mapping holds on the same
// address, as one whose sockets closed before its release does, fails the
// bind and leaves the table as it was, and the port is the new endpoint's once
// that mapping is released. One on another address is no other endpoint's. The
// host is made to give the port by IP_LOCAL_PORT_RANGE, Linux 6.3's range of
// one socket's own. It runs in a network namespace of its own where one can be
// made (inOwnNetwork).
func TestHostsPortAMappingHoldsIsRefused(t *testing.T) {
	if !inOwnNetwork(t) {
		return
	}
	loopback, second := netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.2")
	for _, c := range []struct {
		name    string
		held    netip.Addr
		refused bool
	}{
		{"on the dial's address", loopback, true},
		{"on another address", second, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			port := freeTCPPort(t, loopback)
			first, other := tcpInside{netip.AddrPortFrom(leaf4, port), c.held}, tcpInside{netip.AddrPortFrom(other4, port), loopback}
			var mappings tcpMappings
			closed, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			held, err := mappings.bind(closed, first)
			if err != nil {
				t.Fatalf("bind for %s on %s: %v", first.leaf, c.held, err)
			}
			_ = unix.Close(closed)
			given := func() int {
				fd := tcpSocket(t)
				if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_LOCAL_PORT_RANGE, int(port)<<16|int(port)); errors.Is(err, unix.ENOPROTOOPT) {
					t.Skipf("this kernel gives no socket a port range of its own: %v", err)
				} else if err != nil {
					t.Fatal(err)
				}
				return fd
			}
			m, err := mappings.bind(given(), other)
			mappings.mu.Lock()
			kept := mappings.byInside[first] == held && mappings.byOutside[held.outside] == held && held.sockets == 1
			entries := len(mappings.byInside) + len(mappings.byOutside)
			mappings.mu.Unlock()
			if !kept {
				t.Errorf("%s's mapping on %s is no longer the table's once %s bound", first.leaf, held.outside, other.leaf)
			}
			if !c.refused {
				if err != nil || m.outside != netip.AddrPortFrom(loopback, port) {
					t.Errorf("bind for %s on %s: %+v, %v, want a mapping on %s:%d", other.leaf, loopback, m, err, loopback, port)
				}
				return
			}
			if !errors.Is(err, errPortHeld) || entries != 2 {
				t.Fatalf("bind for %s given port %d, which %s's mapping holds: %+v, %v, the table %d entries, want %v and the 2 entries of %s's mapping", other.leaf, port, first.leaf, m, err, entries, errPortHeld, first.leaf)
			}
			mappings.release(held)
			if m, err := mappings.bind(given(), other); err != nil || m.outside != netip.AddrPortFrom(loopback, port) {
				t.Errorf("bind for %s once %s's mapping ended: %+v, %v, want a mapping on %s:%d", other.leaf, first.leaf, m, err, loopback, port)
			}
		})
	}
}

// A class naming another address may take the port of a live mapping under
// auto on its own address, a new mapping's and a one-off socket's both, and
// that ends nothing: the live mapping stays the table's, its next socket binds
// its endpoint, and no other inside endpoint leaves from that endpoint. The
// host is made to give that port by IP_LOCAL_PORT_RANGE. It runs in a network
// namespace of its own where one can be made (inOwnNetwork).
func TestAnotherClassLeavesALiveAutoMappingAlone(t *testing.T) {
	if !inOwnNetwork(t) {
		return
	}
	loopback, second, third := netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("127.0.0.3")
	servers := acceptingServers(t, 2)
	port := freeTCPPort(t, loopback)
	// under auto toward a server whose route picks loopback
	auto := tcpInside{netip.AddrPortFrom(leaf4, port), loopback}
	// a leaf port of 0 takes the port the host gives
	classed := tcpInside{netip.AddrPortFrom(other4, 0), second}
	other := tcpInside{netip.AddrPortFrom(netip.MustParseAddr("203.0.113.9"), port), loopback}
	var mappings tcpMappings
	live := tcpSocket(t)
	m, err := mappings.bind(live, auto)
	if err != nil || m.outside != netip.AddrPortFrom(loopback, port) {
		t.Fatalf("bind for %s under auto: %+v, %v, want a mapping on %s:%d", auto.leaf, m, err, loopback, port)
	}
	if err := unix.Connect(live, sockaddrOf(servers[0])); err != nil {
		t.Fatalf("connect %s: %v", servers[0], err)
	}
	ranged := func() int {
		fd := tcpSocket(t)
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_LOCAL_PORT_RANGE, int(port)<<16|int(port)); errors.Is(err, unix.ENOPROTOOPT) {
			t.Skipf("this kernel gives no socket a port range of its own: %v", err)
		} else if err != nil {
			t.Fatal(err)
		}
		return fd
	}
	if theirs, err := mappings.bind(ranged(), classed); err != nil || theirs.outside != netip.AddrPortFrom(second, port) {
		t.Fatalf("bind for %s on %s with the host's range at %d alone: %+v, %v, want a mapping on %s:%d", classed.leaf, second, port, theirs, err, second, port)
	}
	if err := unix.Bind(ranged(), sockaddrOf(netip.AddrPortFrom(third, 0))); err != nil {
		t.Fatalf("a one-off socket on %s with the host's range at %d alone: %v", third, port, err)
	}
	theirs, err := mappings.bind(tcpSocket(t), other)
	if err != nil {
		t.Fatalf("bind for %s on %s: %v", other.leaf, loopback, err)
	}
	if theirs.outside == m.outside {
		t.Errorf("%s took %s, the endpoint %s's live connection leaves from", other.leaf, theirs.outside, auto.leaf)
	}
	next, err := mappings.bind(tcpSocket(t), auto)
	if err != nil || next != m || m.outside != netip.AddrPortFrom(loopback, port) {
		t.Errorf("%s's next socket under auto: %+v, %v, want its live mapping on %s:%d", auto.leaf, next, err, loopback, port)
	}
	mappings.mu.Lock()
	defer mappings.mu.Unlock()
	if mappings.byInside[auto] != m || mappings.byOutside[m.outside] != m {
		t.Errorf("%s's live mapping on %s is no longer the table's", auto.leaf, m.outside)
	}
}

// Under auto, with the routes toward two servers picking two source addresses,
// each connection of one inside endpoint leaves from its own route's source,
// on the leaf's port on each where free, under a mapping for each address, so
// no connection leaves under another route's source, and a later connection
// toward either server leaves from that address's mapping
func TestMappingUnderAutoIsKeptForEachRoutesSource(t *testing.T) {
	h, prefixes := twoAddressesHeld(t)
	r := &tcpRelay{x: h.x}
	leaf := netip.AddrPortFrom(leaf4, freeTCPPort(t, prefixes[0].Addr()))
	var mappings [2]*tcpMapping
	for _, which := range []string{"first", "next"} {
		for i, prefix := range prefixes {
			server := acceptingServerOn(t, prefix.Addr().Next().Next())
			conn, m, failure := r.dial(context.Background(), leaf, server)
			if conn == nil {
				t.Fatalf("dial from %s toward %s: %v", leaf, server, failure.err)
			}
			t.Cleanup(func() { _ = conn.Close() })
			t.Cleanup(func() { r.mappings.release(m) })
			local := conn.LocalAddr().(*net.TCPAddr).AddrPort()
			want := netip.AddrPortFrom(prefix.Addr(), leaf.Port())
			if netip.AddrPortFrom(local.Addr().Unmap(), local.Port()) != want || m == nil || m.outside != want {
				t.Errorf("the %s dial from %s toward %s left from %s under mapping %+v, want %s, its route's source at the leaf's port", which, leaf, server, local, m, want)
			}
			if which == "first" {
				mappings[i] = m
			} else if m != mappings[i] {
				t.Errorf("the dial from %s toward %s again took mapping %+v, want the one on %s", leaf, server, m, want)
			}
		}
	}
	if mappings[0] == mappings[1] {
		t.Errorf("connections from %s toward servers routed by %s and %s share mapping %+v", leaf, prefixes[0].Addr(), prefixes[1].Addr(), mappings[0])
	}
}

// acceptingServerOn is a server on address, closing every connection it
// accepts
func acceptingServerOn(t *testing.T, address netip.Addr) netip.AddrPort {
	t.Helper()
	server, err := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(netip.AddrPortFrom(address, 0)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	go func() {
		for {
			conn, err := server.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	return server.Addr().(*net.TCPAddr).AddrPort()
}

// A listener of the host's holding SO_REUSEADDR binds and listens on a port a
// mapping's connected socket holds, which Linux lets it beside a socket that
// is not listening, and then refuses the mapping's next bind of the port, so
// that connection leaves from a port the host gives, for that connection
// alone, and the mapping holds on for its live connection
func TestConnectionWhoseMappingsPortAHostListenerTookLeavesFromAnotherPort(t *testing.T) {
	servers := acceptingServers(t, 2)
	x := dialingExit(t, egress.Egress{}, func(string, netip.AddrPort, syscall.RawConn) error { return nil })
	r := &tcpRelay{x: x}
	leaf := netip.AddrPortFrom(leaf4, freeTCPPort(t, servers[0].Addr()))
	conn, m, failure := r.dial(context.Background(), leaf, servers[0])
	if conn == nil {
		t.Fatalf("dial from %s toward %s: %v", leaf, servers[0], failure.err)
	}
	defer conn.Close()
	defer r.mappings.release(m)
	listener := tcpSocket(t)
	if err := unix.SetsockoptInt(listener, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		t.Fatal(err)
	}
	if err := unix.Bind(listener, sockaddrOf(netip.AddrPortFrom(netip.IPv4Unspecified(), m.outside.Port()))); err != nil {
		t.Fatalf("a listener of the host's on port %d beside the mapping's socket: %v", m.outside.Port(), err)
	}
	if err := unix.Listen(listener, 1); err != nil {
		t.Fatalf("listen on port %d beside the mapping's socket: %v", m.outside.Port(), err)
	}
	again, held, failure := r.dial(context.Background(), leaf, servers[1])
	if again == nil {
		t.Fatalf("dial from %s toward %s once a listener took its port: %v", leaf, servers[1], failure.err)
	}
	defer again.Close()
	r.mappings.release(held)
	if local := again.LocalAddr().(*net.TCPAddr).AddrPort(); local.Port() == m.outside.Port() || held != nil {
		t.Errorf("the dial toward %s left from %s with mapping %+v, want a one-off port other than %d", servers[1], local, held, m.outside.Port())
	}
	r.mappings.mu.Lock()
	defer r.mappings.mu.Unlock()
	if r.mappings.byInside[m.inside] != m || m.sockets != 1 {
		t.Errorf("the mapping is no longer the table's or holds %d sockets, want its live connection's 1", m.sockets)
	}
}

// A server's response and FIN reach the leaf whole and the connection closes
// cleanly, though ICMP host unreachables about the exit's socket toward the
// server came while the exit still held bytes for the leaf, before the relay
// read the server's FIN and once it watches the socket past it: Linux keeps
// the error as the connection's soft error, which ends nothing. For each of
// five connections the test reads the first error back through SO_ERROR,
// which shows Linux took it and clears it, then sends it again before the
// relay reads the FIN, and once more after. The leaf's endpoint holds bytes
// its closed window keeps from the leaf while the watch starts, so a watch
// that took the error for the connection's end would reset the leaf before
// them. It runs as root of a network namespace made for the process alone
// (claim), since it sends ICMP errors of its own.
func TestServersCloseReachesTheLeafPastASoftError(t *testing.T) {
	claim(t)
	const size = 112 << 10
	loopback := netip.MustParseAddr("127.0.0.1")
	h := newRelayHarness(t, nil)
	allowLoopback(t, h.x.stack)
	for i := range 5 {
		sniff, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_TCP)
		if err != nil {
			t.Skipf("no raw socket for this process: %v", err)
		}
		server := tcpServer(t, loopback, func(conn *net.TCPConn) {
			_, _ = conn.Write(make([]byte, size))
			_ = conn.CloseWrite()
			_ = conn.SetReadDeadline(time.Now().Add(exitWait))
			_, _ = io.Copy(io.Discard, conn)
			_ = conn.Close()
		})
		c := h.open(t, netip.AddrPortFrom(leaf4, uint16(43050+i)), server)
		f := listedFlow(t, h)
		local := f.conn.LocalAddr().(*net.TCPAddr).AddrPort()
		seq := sentSequence(t, sniff, local, server)
		_ = unix.Close(sniff)
		// the leaf acknowledges nothing yet, so the relay holds bytes for it
		// while the host's socket takes the server's FIN
		deadline := time.Now().Add(exitWait)
		for {
			info, unread, _, err := socketInfo(f.conn)
			if err != nil {
				t.Fatal(err)
			}
			if info.State == linuxCloseWait && unread > 0 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("connection %d: the host's socket is in state %d with %d bytes unread, want CLOSE-WAIT with bytes the relay has not read", i, info.State, unread)
			}
			time.Sleep(time.Millisecond)
		}
		icmpErrorAbout(t, 3, 1, local, server, seq)
		if errno := syscall.Errno(socketErrno(t, f.conn)); errno != syscall.EHOSTUNREACH {
			t.Fatalf("connection %d: the host's socket holds error %v after the host unreachable, want it soft as EHOSTUNREACH", i, errno)
		}
		icmpErrorAbout(t, 3, 1, local, server, seq)
		// the leaf takes the response through a narrow window until the relay
		// has read to the server's FIN and shut the leaf's endpoint, then
		// closes its window, so the endpoint holds the rest of the response
		start := c.ack
		for tcp.EndpointState(f.ep.State()) == tcp.StateEstablished {
			raw := h.waitLaid(t, "the response toward the leaf", func(raw []byte) bool {
				p, ok := parse(raw)
				return ok && p.protocol == protoTCP && netip.AddrPortFrom(p.dst, p.dstPort) == c.leaf && (p.payload > 0 || p.flags&tcpRST != 0)
			})
			p, _ := parse(raw)
			if p.flags&tcpRST != 0 {
				t.Fatalf("connection %d: the response reset after %d of %d bytes", i, c.ack-start, size)
			}
			if p.seq == c.ack {
				c.ack += uint32(p.payload)
			}
			h.x.link.deliver(leafSegment(c.leaf, c.server, c.seq, c.ack, tcpACK, 8<<10, nil))
		}
		h.x.link.deliver(leafSegment(c.leaf, c.server, c.seq, c.ack, tcpACK, 0, nil))
		// the relay watches the host's socket once it shut the leaf's endpoint
		time.Sleep(10 * time.Millisecond)
		icmpErrorAbout(t, 3, 1, local, server, seq)
		closingResponse(t, h, c, make([]byte, size-int(c.ack-start)))
		h.x.link.deliver(tcpSegment(c.leaf, c.server, c.seq, c.ack, tcpACK|tcpFIN, nil))
		h.waitConnections(t, 0)
		f.ending.Lock()
		wasReset := f.wasReset
		f.ending.Unlock()
		if wasReset {
			t.Fatalf("connection %d: the exit reset its connection toward the server", i)
		}
	}
}

// An ICMP error about a dial's connection that comes after its connect and
// before the dial closes its error queue, which the socket takes as its errno,
// ends nothing once the queue is closed: the close returns no error, and
// neither connectionFailed nor peek takes the connection for ended, while the
// server sends nothing yet nor once its bytes and FIN have come, which a read
// then takes whole. It runs as root of a network namespace made for the
// process alone (claim), since it sends ICMP errors of its own.
func TestErrorBeforeTheDialsQueueClosesEndsNothing(t *testing.T) {
	claim(t)
	loopback4 := netip.MustParseAddr("127.0.0.1")
	for _, c := range []struct {
		name       string
		kind, code byte
		loopback   netip.Addr
	}{
		{"IPv4 host unreachable", 3, 1, loopback4},
		{"IPv4 time exceeded", 11, 0, loopback4},
		{"IPv6 address unreachable", 1, 3, netip.IPv6Loopback()},
	} {
		t.Run(c.name, func(t *testing.T) {
			const size = 1000
			send := make(chan struct{})
			sent := sync.OnceFunc(func() { close(send) })
			t.Cleanup(sent)
			server := tcpServer(t, c.loopback, func(conn *net.TCPConn) {
				select {
				case <-send:
				case <-time.After(exitWait):
				}
				_, _ = conn.Write(make([]byte, size))
				_ = conn.CloseWrite()
				_ = conn.SetReadDeadline(time.Now().Add(exitWait))
				_, _ = io.Copy(io.Discard, conn)
				_ = conn.Close()
			})
			fd, local, seq, queue := queuedConnection(t, server)
			icmpErrorAbout(t, c.kind, c.code, local, server, seq)
			waitErrno(t, fd)
			if err := queue.close(); err != nil {
				t.Fatalf("the queue's close returned %v for a connection the host keeps open", err)
			}
			if connectionFailed(uintptr(fd)) {
				t.Error("connectionFailed takes the open connection for ended before the server sends")
			}
			if err := peek(uintptr(fd)); !errors.Is(err, unix.EAGAIN) {
				t.Errorf("peek on the open connection holding nothing returned %v, want EAGAIN", err)
			}
			sent()
			waitFor(t, "CLOSE-WAIT past the server's FIN", func() bool { return tcpState(t, fd) == linuxCloseWait })
			if connectionFailed(uintptr(fd)) {
				t.Error("connectionFailed takes the connection for ended past the server's FIN")
			}
			if err := peek(uintptr(fd)); err != nil {
				t.Errorf("peek past the server's bytes and FIN returned %v, want them", err)
			}
			if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1}); err != nil {
				t.Fatal(err)
			}
			got, buf := 0, make([]byte, size)
			for {
				n, err := unix.Read(fd, buf)
				if err != nil {
					t.Fatalf("read past %d of %d bytes: %v", got, size, err)
				}
				if n == 0 {
					break
				}
				got += n
			}
			if got != size {
				t.Errorf("read %d of %d bytes before the end", got, size)
			}
		})
	}
}

// A server's reset that ends a dial's connection before the dial closes its
// error queue, after an ICMP error about it the socket took as its errno, is
// what the close returns, since the socket no longer holds it. It runs as
// root of a network namespace made for the process alone (claim), since it
// sends ICMP errors of its own.
func TestResetBeforeTheDialsQueueClosesIsWhatTheCloseReturns(t *testing.T) {
	claim(t)
	resetNow := make(chan struct{})
	resetServer := sync.OnceFunc(func() { close(resetNow) })
	t.Cleanup(resetServer)
	server := tcpServer(t, netip.MustParseAddr("127.0.0.1"), resetsOn(resetNow))
	fd, local, seq, queue := queuedConnection(t, server)
	icmpErrorAbout(t, 3, 1, local, server, seq)
	waitErrno(t, fd)
	resetServer()
	waitClosed(t, fd)
	if err := queue.close(); !errors.Is(err, unix.ECONNRESET) {
		t.Errorf("the queue's close returned %v for a connection the server reset, want ECONNRESET", err)
	}
}

// The close of a dial's error queue returns the errno of a server's reset that
// ended the connection after an ICMP error the socket kept as its soft errno,
// its option off, though a take of the errno hands the soft errno over where
// the socket holds no other. It runs as root of a network namespace made for
// the process alone (claim), since it sends ICMP errors of its own.
func TestResetAfterASoftErrorIsWhatTheCloseReturns(t *testing.T) {
	claim(t)
	loopback4 := netip.MustParseAddr("127.0.0.1")
	for _, c := range []struct {
		name       string
		kind, code byte
		loopback   netip.Addr
	}{
		{"IPv4 host unreachable", 3, 1, loopback4},
		{"IPv4 time exceeded", 11, 0, loopback4},
		{"IPv6 administratively prohibited", 1, 1, netip.IPv6Loopback()},
	} {
		t.Run(c.name, func(t *testing.T) {
			resetNow := make(chan struct{})
			resetServer := sync.OnceFunc(func() { close(resetNow) })
			t.Cleanup(resetServer)
			server := tcpServer(t, c.loopback, resetsOn(resetNow))
			fd, local, seq, queue := queuedConnection(t, server)
			level, option := unix.IPPROTO_IP, unix.IP_RECVERR
			if c.loopback.Is6() {
				level, option = unix.IPPROTO_IPV6, unix.IPV6_RECVERR
			}
			if err := unix.SetsockoptInt(fd, level, option, 0); err != nil {
				t.Fatal(err)
			}
			icmpErrorAbout(t, c.kind, c.code, local, server, seq)
			// the handler leaves no sign of a soft errno to wait on
			time.Sleep(50 * time.Millisecond)
			if polled(fd)&unix.POLLERR != 0 {
				t.Fatal("the ICMP error left the socket's errno with its option off")
			}
			resetServer()
			waitClosed(t, fd)
			if err := queue.close(); !errors.Is(err, unix.ECONNRESET) {
				t.Errorf("the queue's close returned %v for a connection the server reset, want ECONNRESET", err)
			}
		})
	}
}

// The close of a dial's error queue returns EPIPE, the errno of a server's
// reset after its FIN, where the server's bytes, FIN and reset all reached the
// dial's socket before the close
func TestResetAfterBytesAndFINBeforeTheDialsQueueClosesIsWhatTheCloseReturns(t *testing.T) {
	server := tcpServer(t, netip.MustParseAddr("127.0.0.1"), func(conn *net.TCPConn) {
		_, _ = conn.Write(make([]byte, 1000))
		_ = conn.CloseWrite()
		_ = conn.SetLinger(0)
		_ = conn.Close()
	})
	fd, _, _, queue := queuedConnection(t, server)
	waitClosed(t, fd)
	if err := queue.close(); !errors.Is(err, unix.EPIPE) {
		t.Errorf("the queue's close returned %v for a connection whose server sent bytes, a FIN and a reset, want EPIPE", err)
	}
}

// The close of a dial's error queue returns the errno of a server's reset that
// came after the close took an errno an ICMPv6 administratively prohibited left
// on the live connection, EACCES, and before the close read the state. The
// test makes that order through the queue's taken. It runs as root of a
// network namespace made for the process alone (claim), since it sends ICMP
// errors of its own.
func TestResetAfterTheCloseTookALiveErrnoIsWhatItReturns(t *testing.T) {
	claim(t)
	resetNow := make(chan struct{})
	resetServer := sync.OnceFunc(func() { close(resetNow) })
	t.Cleanup(resetServer)
	server := tcpServer(t, netip.IPv6Loopback(), resetsOn(resetNow))
	fd, local, seq, queue := queuedConnection(t, server)
	icmpErrorAbout(t, 1, 1, local, server, seq)
	waitErrno(t, fd)
	queue.taken = func() {
		resetServer()
		waitClosed(t, fd)
	}
	if ended := queue.close(); !errors.Is(ended, unix.ECONNRESET) {
		t.Errorf("the close returned %v after the server's reset, want ECONNRESET", ended)
	}
}

// A connection the server reset after the dial's connect returned and before
// the dial read its error queue fails the dial: the leaf's SYN is answered
// with a reset, the server took that one connection alone, and the mapping
// tables and the admission's charges hold nothing once the dial is answered.
// The test makes that order through the relay's connected.
func TestResetBeforeTheDialReadsItsQueueResetsTheLeafAtItsSYN(t *testing.T) {
	h := newRelayHarness(t, nil)
	allowLoopback(t, h.x.stack)
	resetNow := make(chan struct{})
	resetServer := sync.OnceFunc(func() { close(resetNow) })
	t.Cleanup(resetServer)
	var accepted atomic.Int32
	resets := resetsOn(resetNow)
	server := tcpServer(t, netip.MustParseAddr("127.0.0.1"), func(conn *net.TCPConn) {
		accepted.Add(1)
		resets(conn)
	})
	state := make(chan uint8, 2)
	h.x.tcp.connected = func(conn *net.TCPConn) {
		resetServer()
		state <- stateOnceClosed(conn, exitWait)
	}
	leaf := netip.AddrPortFrom(leaf4, 43050)
	if reason := h.syn(t, leaf, server); reason != "" {
		t.Fatalf("the SYN was refused past %s", reason)
	}
	select {
	case s := <-state:
		if s != unix.BPF_TCP_CLOSE {
			t.Fatalf("the dial's connection is in state %d after the server's reset, want closed", s)
		}
	case <-time.After(exitWait):
		t.Fatal("the dial reached no connection")
	}
	answer := h.waitLaid(t, "the answer toward the leaf", func(raw []byte) bool {
		p, ok := parse(raw)
		return ok && p.protocol == protoTCP && netip.AddrPortFrom(p.dst, p.dstPort) == leaf
	})
	if p, _ := parse(answer); p.flags&tcpRST == 0 {
		t.Errorf("the leaf's SYN was answered with flags %#x, want a reset", p.flags)
	}
	h.waitConnections(t, 0)
	if held := h.x.tcp.held(); held != [3]int{} {
		t.Errorf("the relay holds dials, connections and flows %v once the dial failed, want none", held)
	}
	if n := accepted.Load(); n != 1 {
		t.Errorf("the server took %d connections, want the dial's one", n)
	}
	mappings := &h.x.tcp.mappings
	mappings.mu.Lock()
	defer mappings.mu.Unlock()
	if inside, outside := len(mappings.byInside), len(mappings.byOutside); inside != 0 || outside != 0 {
		t.Errorf("the mapping tables hold %d entries by inside endpoint and %d by outside endpoint once the dial failed, want none", inside, outside)
	}
}

// A connection that was established and then ended, whose error queue's close
// returned an errno portTaken reads, fails the dial with that errno and is not
// dialed again from another port: the leaf's SYN is answered with a reset, the
// server took that one connection alone, and the mapping tables and the
// admission's charges hold nothing once the dial is answered. The test makes
// by hand, through the relay's connected, the state a timeout's end after a
// soft errno or the error queue's dequeue over a reset's errno leaves. With the
// option off, an ICMPv6 administratively prohibited about the connection stays
// its soft errno, EACCES. The server then resets, and the test takes the
// reset's errno, so the close's take reads EACCES of a closed connection. It
// runs as root of a network namespace made for the process alone (claim),
// since it sends ICMP errors of its own, toward a server on the rig's address
// on loopback, since the stack carries no leaf's segment toward ::1.
func TestEndedConnectionWhoseCloseReturnsAPortTakenErrnoIsNotDialedAgain(t *testing.T) {
	claim(t)
	serversOnce.Do(func() { serversErr = addServers() })
	if serversErr != nil {
		t.Fatalf("address the servers on loopback: %v", serversErr)
	}
	h := newRelayHarness(t, nil)
	h.reach = rigServer6.Addr()
	resetNow := make(chan struct{})
	resetServer := sync.OnceFunc(func() { close(resetNow) })
	t.Cleanup(resetServer)
	var accepted atomic.Int32
	resets := resetsOn(resetNow)
	server := tcpServer(t, rigServer6.Addr(), func(conn *net.TCPConn) {
		accepted.Add(1)
		resets(conn)
	})
	sniff, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_TCP)
	if err != nil {
		t.Skipf("no raw socket for this process: %v", err)
	}
	defer unix.Close(sniff)
	connected := make(chan *net.TCPConn, 2)
	resume := make(chan struct{})
	resumeDial := sync.OnceFunc(func() { close(resume) })
	t.Cleanup(resumeDial)
	h.x.tcp.connected = func(conn *net.TCPConn) {
		connected <- conn
		<-resume
	}
	leaf := netip.AddrPortFrom(leaf6, 43060)
	if reason := h.syn(t, leaf, server); reason != "" {
		t.Fatalf("the SYN was refused past %s", reason)
	}
	var conn *net.TCPConn
	select {
	case conn = <-connected:
	case <-time.After(exitWait):
		t.Fatal("the dial reached no connection")
	}
	fd := descriptorOf(t, conn)
	local := conn.LocalAddr().(*net.TCPAddr).AddrPort()
	seq := sentSequence(t, sniff, local, server)
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_RECVERR, 0); err != nil {
		t.Fatal(err)
	}
	icmpErrorAbout(t, 1, 1, local, server, seq)
	// the handler leaves no sign of a soft errno to wait on
	time.Sleep(50 * time.Millisecond)
	resetServer()
	waitClosed(t, fd)
	if errno := socketErrno(t, conn); unix.Errno(errno) != unix.ECONNRESET {
		t.Fatalf("the server's reset left %v on the socket, want ECONNRESET", unix.Errno(errno))
	}
	resumeDial()
	answer := h.waitLaid(t, "the answer toward the leaf", func(raw []byte) bool {
		p, ok := parse(raw)
		return ok && p.protocol == protoTCP && netip.AddrPortFrom(p.dst, p.dstPort) == leaf
	})
	if p, _ := parse(answer); p.flags&tcpRST == 0 {
		t.Errorf("the leaf's SYN was answered with flags %#x, want a reset", p.flags)
	}
	// a second try reaches connected before the dial returns, so before the answer
	if again := len(connected); again != 0 {
		t.Errorf("the dial connected again after its first connection ended, %d more, want none", again)
	}
	h.waitConnections(t, 0)
	if held := h.x.tcp.held(); held != [3]int{} {
		t.Errorf("the relay holds dials, connections and flows %v once the dial failed, want none", held)
	}
	if n := accepted.Load(); n != 1 {
		t.Errorf("the server took %d connections, want the dial's one", n)
	}
	mappings := &h.x.tcp.mappings
	mappings.mu.Lock()
	defer mappings.mu.Unlock()
	if inside, outside := len(mappings.byInside), len(mappings.byOutside); inside != 0 || outside != 0 {
		t.Errorf("the mapping tables hold %d entries by inside endpoint and %d by outside endpoint once the dial failed, want none", inside, outside)
	}
}

// descriptorOf is conn's descriptor, which stays conn's while conn is open
func descriptorOf(t *testing.T, conn *net.TCPConn) int {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	fd := -1
	if err := raw.Control(func(d uintptr) { fd = int(d) }); err != nil {
		t.Fatal(err)
	}
	return fd
}

// stateOnceClosed is the state TCP_INFO reports of conn's connection once it
// is closed, or as it stands once within passes. A goroutine other than the
// test's waits through it, since no wait there may end the test.
func stateOnceClosed(conn *net.TCPConn, within time.Duration) uint8 {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0
	}
	var state uint8
	deadline := time.Now().Add(within)
	_ = raw.Control(func(fd uintptr) {
		for {
			if info, err := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO); err == nil {
				state = info.State
			}
			if state == unix.BPF_TCP_CLOSE || time.Now().After(deadline) {
				return
			}
			time.Sleep(time.Millisecond)
		}
	})
	return state
}

// A leaf that answers nothing after its FIN, so that its endpoint gives the
// connection up for a timeout, which leaves it in the error state, reaches
// the server as a reset. Its keepalive probes, one unanswered, end it.
func TestLeafsTimeoutAfterItsFINReachesTheServer(t *testing.T) {
	h := newRelayHarness(t, nil)
	allowLoopback(t, h.x.stack)
	server, readFIN := readsToTheFIN(t)
	c := h.open(t, netip.AddrPortFrom(leaf4, 43012), server)
	f := listedFlow(t, h)
	h.x.link.deliver(tcpSegment(c.leaf, c.server, c.seq, c.ack, tcpACK|tcpFIN, nil))
	conn := readFIN()
	idle, interval := tcpip.KeepaliveIdleOption(10*time.Millisecond), tcpip.KeepaliveIntervalOption(10*time.Millisecond)
	if err := f.ep.SetSockOptInt(tcpip.KeepaliveCountOption, 1); err != nil {
		t.Fatal(err)
	}
	if err := f.ep.SetSockOpt(&interval); err != nil {
		t.Fatal(err)
	}
	if err := f.ep.SetSockOpt(&idle); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "error on the server's socket after the leaf's endpoint timed out", func() bool { return socketErrno(t, conn) != 0 })
	h.waitConnections(t, 0)
}

const (
	// ownNetwork marks the run of a test in a process of its own, in a user
	// and network namespace of its own
	ownNetwork = "RANET3_OWN_NETWORK"
	// ownNetworkRefused, set by a test of inOwnNetwork alone, has it take the
	// new namespace for one not made, as a host that allows no user namespace
	// refuses it
	ownNetworkRefused = "RANET3_OWN_NETWORK_REFUSED"
	// ownNetworkClaimRefused, set by a test of inOwnNetwork alone, has the
	// claim of a process's namespace refused as a builder like CI's refuses
	// it, the loopback's bringing up refused with EPERM (claimProcess)
	ownNetworkClaimRefused = "RANET3_OWN_NETWORK_CLAIM_REFUSED"
	// ownNetworkBody, set by TestInOwnNetworkRunsInPlaceOnlyWhereItHasNone
	// alone, makes that test the body it runs, which passes, fails or skips
	// as it reads
	ownNetworkBody = "RANET3_OWN_NETWORK_BODY"
	// ownNetworkProbe, set by TestInOwnNetworkRunsInPlaceOnlyWhereItHasNone
	// alone, makes that test the probe of what this host gives
	ownNetworkProbe = "RANET3_OWN_NETWORK_PROBE"
	// unusableExit is the exit status by which a child tells its parent that
	// its namespace was made and refused a step the test needs, a status no
	// test binary ends with otherwise
	unusableExit = 77
)

// claimProcess is netnstest.ClaimProcess, or where ownNetworkClaimRefused is
// set the refusal a builder like CI's gives a process in a user namespace of
// its own, wrapped as BringUp wraps the kernel's
func claimProcess() (skip string, err error) {
	if os.Getenv(ownNetworkClaimRefused) != "" {
		return "", fmt.Errorf("bring lo up: %w", unix.EPERM)
	}
	return netnstest.ClaimProcess()
}

// inOwnNetwork reports whether t runs in a network namespace of its own, with
// its loopback up and no socket in it but the test's, or in place. Outside one
// it runs t again in a process of its own in a new user and network namespace,
// takes that run's end for t's, and reports false. Where it cannot have one,
// since the namespace is not made, or is made and its claim is refused for
// want of a permission, as a host's security module refuses the capabilities
// of a user namespace an unprivileged process made, it logs which and reports
// true, so t runs in place, in the namespace it shares, as it ran before it
// had one. The child tells the second case by unusableExit alone. Any other
// end of the child is t's, a failure or a skip of the test's own. A test needs
// it that binds on 127.0.0.2 or 127.0.0.3 a port freeTCPPort found free on
// 127.0.0.1 alone, since in a namespace it shares a socket of another process,
// or a connection of an earlier test of the binary in TIME_WAIT, may hold that
// port there.
func inOwnNetwork(t *testing.T) bool {
	t.Helper()
	if os.Getenv(ownNetwork) != "" {
		claimOnce.Do(func() { claimSkip, claimErr = claimProcess() })
		refused := claimErr
		if errors.Is(refused, unix.EPERM) || errors.Is(refused, unix.EACCES) {
			_, _ = os.Stderr.WriteString(unusableMark + refused.Error() + "\n")
			os.Exit(unusableExit)
		}
		claim(t)
		return true
	}
	cmd := childOf(t)
	cmd.Env = append(os.Environ(), ownNetwork+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}
	var out []byte
	err := errors.New(ownNetworkRefused + " is set")
	if os.Getenv(ownNetworkRefused) == "" {
		out, err = cmd.CombinedOutput()
	}
	var exit *exec.ExitError
	switch {
	case err != nil && !errors.As(err, &exit):
		t.Logf("no network namespace of its own was made (%v), so the test runs in place", err)
		return true
	case exit != nil && exit.ExitCode() == unusableExit:
		_, why, _ := bytes.Cut(out, []byte(unusableMark))
		t.Logf("a network namespace of its own was made and is not usable (%s), so the test runs in place", bytes.TrimSpace(why))
		return true
	case err != nil:
		t.Fatalf("the run in a network namespace of its own ended with %v:\n%s", err, out)
	case bytes.Contains(out, []byte("--- SKIP: "+t.Name()+" ")):
		t.Skipf("the run in a network namespace of its own skipped:\n%s", out)
	case !bytes.Contains(out, []byte("--- PASS: "+t.Name()+" ")):
		t.Fatalf("the run in a network namespace of its own passed no %s:\n%s", t.Name(), out)
	}
	return false
}

// unusableMark heads the line by which a child says what refused its claim
const unusableMark = "claim of the namespace refused: "

// inOwnNetwork runs a test in place where the namespace is not made, or is
// made and not usable, and says which, and nowhere else: a failure or a skip
// of the test is its own wherever it runs. What this host gives is read by a
// probe of the test's own, a child in the same namespaces that reports its
// claim, and not from inOwnNetwork. The test runs itself again whole with the
// claim of every child refused, as a builder like CI's refuses it.
func TestInOwnNetworkRunsInPlaceOnlyWhereItHasNone(t *testing.T) {
	const notMade, notUsable = "no network namespace of its own was made", "a network namespace of its own was made and is not usable"
	const claimHeld, claimRefused = "the probe's claim held", "the probe's claim was refused"
	if os.Getenv(ownNetworkProbe) != "" {
		claimOnce.Do(func() { claimSkip, claimErr = claimProcess() })
		switch {
		case claimErr == nil && claimSkip == "":
			t.Log(claimHeld)
		case errors.Is(claimErr, unix.EPERM) || errors.Is(claimErr, unix.EACCES):
			t.Log(claimRefused)
		default:
			t.Fatalf("the probe's claim ended with %q and %v", claimSkip, claimErr)
		}
		return
	}
	if body := os.Getenv(ownNetworkBody); body != "" {
		if !inOwnNetwork(t) {
			return
		}
		ns, err := os.Readlink("/proc/thread-self/ns/net")
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("the body ran in %s", ns)
		switch body {
		case "fail":
			t.Error("the body fails, as asked")
		case "skip":
			t.Skip("the body skips, as asked")
		}
		return
	}
	here, err := os.Readlink("/proc/thread-self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	// gives is the case this host names for a test that wants a usable
	// namespace, empty where it gives one, as the probe finds it
	probe := childOf(t)
	probe.Env = append(os.Environ(), ownNetworkProbe+"=1")
	probe.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}
	found, err := probe.CombinedOutput()
	var gives string
	switch _, exited := err.(*exec.ExitError); {
	case err != nil && !exited:
		gives = notMade
	case err == nil && bytes.Contains(found, []byte(claimHeld)):
	case err == nil && bytes.Contains(found, []byte(claimRefused)):
		gives = notUsable
	default:
		t.Fatalf("the probe ended with %v:\n%s", err, found)
	}
	t.Logf("the probe, a child in the same namespaces, finds the case %q", gives)
	// refusedSaid is the whole line inOwnNetwork logs where the claim is
	// refused as ownNetworkClaimRefused refuses it, naming the refusal alone
	refusedSaid := notUsable + " (bring lo up: " + unix.EPERM.Error() + "), so the test runs in place\n"
	for _, c := range []struct {
		name, body, env string
		// said is the case inOwnNetwork names where it runs the test in place,
		// empty where it runs it in a child, on a host that gives a usable
		// namespace
		said, end string
	}{
		{"made and usable", "pass", "", "", "PASS"},
		{"made and usable, failing", "fail", "", "", "FAIL"},
		{"made and usable, skipping", "skip", "", "", "SKIP"},
		{"not made", "pass", ownNetworkRefused, notMade, "PASS"},
		{"not made, failing", "fail", ownNetworkRefused, notMade, "FAIL"},
		{"made and not usable", "pass", ownNetworkClaimRefused, notUsable, "PASS"},
		{"made and not usable, failing", "fail", ownNetworkClaimRefused, notUsable, "FAIL"},
		{"made and not usable, skipping", "skip", ownNetworkClaimRefused, notUsable, "SKIP"},
	} {
		cmd := childOf(t)
		cmd.Env = append(os.Environ(), ownNetworkBody+"="+c.body)
		if c.env != "" {
			cmd.Env = append(cmd.Env, c.env+"=1")
		}
		out, err := cmd.CombinedOutput()
		if _, exited := err.(*exec.ExitError); err != nil && !exited {
			t.Fatal(err)
		}
		// where this host gives no usable namespace, or makes none, the run in
		// place stands for a row that wants one
		want := c.said
		if want == "" || gives == notMade && want == notUsable {
			want = gives
		}
		said := ""
		for _, s := range []string{notMade, notUsable} {
			if bytes.Contains(out, []byte(s)) {
				said = s
			}
		}
		// the run's own end, at the start of a line, and not a child's it quotes
		end := bytes.Contains(append([]byte("\n"), out...), []byte("\n--- "+c.end+": "+t.Name()+" ")) && (err == nil) == (c.end != "FAIL")
		inPlace := bytes.Contains(out, []byte("the body ran in "+here+"\n"))
		if c.env == ownNetworkClaimRefused && !bytes.Contains(out, []byte(": "+refusedSaid)) {
			t.Errorf("%s: logged no line %q:\n%s", c.name, refusedSaid, out)
		}
		if said != want || !end || inPlace != (want != "") {
			t.Errorf("%s: said %q, ended %s %t, ran in place %t, want %q, true and %t, the probe's case %q:\n%s", c.name, said, c.end, end, inPlace, want, want != "", gives, out)
		}
	}
	if os.Getenv(ownNetworkClaimRefused) != "" {
		return
	}
	cmd := childOf(t)
	cmd.Env = append(os.Environ(), ownNetworkClaimRefused+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil || !bytes.Contains(append([]byte("\n"), out...), []byte("\n--- PASS: "+t.Name()+" ")) {
		t.Errorf("with the claim of every child refused, as a builder like CI's refuses it, the test ended with %v:\n%s", err, out)
	}
}

// TestMain readies the loopback the package's servers listen on before any
// test runs, so that no test depends on another having brought it up: where the
// process is root and the loopback is down, as unshare -rn leaves it, it claims
// the namespace as claim does, and it leaves an up loopback as it is
func TestMain(m *testing.M) {
	if lo, err := net.InterfaceByName("lo"); os.Getuid() == 0 && err == nil && lo.Flags&net.FlagUp == 0 {
		claimOnce.Do(func() { claimSkip, claimErr = claimProcess() })
	}
	m.Run()
}

// queuedConnection is a socket connected to server with its error queue on,
// as a dial's is between its connect and the queue's close, with its local
// endpoint and the sequence number its next segment takes
func queuedConnection(t *testing.T, server netip.AddrPort) (fd int, local netip.AddrPort, seq uint32, queue *errorQueue) {
	t.Helper()
	family := unix.AF_INET
	if server.Addr().Is6() {
		family = unix.AF_INET6
	}
	sniff, err := unix.Socket(family, unix.SOCK_RAW, unix.IPPROTO_TCP)
	if err != nil {
		t.Skipf("no raw socket for this process: %v", err)
	}
	defer unix.Close(sniff)
	fd, err = unix.Socket(family, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	queue = &errorQueue{}
	if err := queue.open(fd, server); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = queue.close() })
	if err := unix.Connect(fd, sockaddrOf(server)); err != nil {
		t.Fatal(err)
	}
	sa, err := unix.Getsockname(fd)
	if err != nil {
		t.Fatal(err)
	}
	local = sockaddrPort(sa)
	return fd, local, sentSequence(t, sniff, local, server), queue
}

// polled is the events a poll of fd returns at once
func polled(fd int) int16 {
	fds := []unix.PollFd{{Fd: int32(fd)}}
	_, _ = unix.Poll(fds, 0)
	return fds[0].Revents
}

// waitErrno waits for an ICMP error to leave its errno on fd's socket
func waitErrno(t *testing.T, fd int) {
	t.Helper()
	waitFor(t, "errno the ICMP error left on the socket", func() bool { return polled(fd)&unix.POLLERR != 0 })
}

// waitClosed waits for the server's reset to close fd's connection
func waitClosed(t *testing.T, fd int) {
	t.Helper()
	waitFor(t, "the connection's close on the server's reset", func() bool { return tcpState(t, fd) == unix.BPF_TCP_CLOSE })
}

// tcpState is the state TCP_INFO reports of fd's connection
func tcpState(t *testing.T, fd int) uint8 {
	t.Helper()
	info, err := unix.GetsockoptTCPInfo(fd, unix.IPPROTO_TCP, unix.TCP_INFO)
	if err != nil {
		t.Fatal(err)
	}
	return info.State
}

// linuxCloseWait is Linux's TCP_CLOSE_WAIT, a state TCP_INFO reports
const linuxCloseWait = 8

// sentSequence is the sequence number of the first segment from local's port
// toward server's that sniff, a raw TCP socket of their family, holds, past
// the SYN where it is one. A raw IPv6 socket hands a segment without its
// header.
func sentSequence(t *testing.T, sniff int, local, server netip.AddrPort) uint32 {
	t.Helper()
	if err := unix.SetsockoptTimeval(sniff, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1<<16)
	for {
		n, _, err := unix.Recvfrom(sniff, buf, 0)
		if err != nil {
			t.Fatalf("no segment from %s toward %s: %v", local, server, err)
		}
		segment := buf[:n]
		if local.Addr().Is4() && n > 0 {
			segment = buf[min(n, int(buf[0]&0x0f)*4):n]
		}
		if len(segment) < 20 || binary.BigEndian.Uint16(segment[0:2]) != local.Port() || binary.BigEndian.Uint16(segment[2:4]) != server.Port() {
			continue
		}
		seq := binary.BigEndian.Uint32(segment[4:8])
		if segment[13]&tcpSYN != 0 {
			return seq + 1
		}
		return seq
	}
}

// icmpErrorAbout sends local's host an ICMP error of kind and code quoting a
// segment from local toward server at seq, as a router on a failing path does
func icmpErrorAbout(t *testing.T, kind, code byte, local, server netip.AddrPort, seq uint32) {
	t.Helper()
	quote := tcpSegment(local, server, seq, 0, tcpACK, nil)
	message := []byte{kind, code, 0, 0, 0, 0, 0, 0}
	family, protocol := unix.AF_INET, unix.IPPROTO_ICMP
	if local.Addr().Is6() {
		// Linux sums the ICMPv6 message a raw socket sends
		family, protocol = unix.AF_INET6, unix.IPPROTO_ICMPV6
		message = append(message, quote...)
	} else {
		message = append(message, quote[:28]...)
		binary.BigEndian.PutUint16(message[2:4], fold(sum(0, message)))
	}
	fd, err := unix.Socket(family, unix.SOCK_RAW, protocol)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.Sendto(fd, message, 0, sockaddrOf(netip.AddrPortFrom(local.Addr(), 0))); err != nil {
		t.Fatal(err)
	}
}

// tcpSocket is an IPv4 TCP socket, closed as t ends where nothing closed it
// before
func tcpSocket(t *testing.T) int {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	return fd
}
