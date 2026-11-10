// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package userspace

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"slices"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/egress"
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
			r.waitFor(t, "every copy buffer back while the connection idles", func() bool { return r.exit.tcp.copies.out.Load() == 0 })
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
			r.waitFor(t, "the connection's counts given back", func() bool { return r.exit.tcp.held() == [3]int{} })
			r.waitFor(t, "the connection's mapping ended", func() bool {
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

// Withdrawing the exit resets each connection it relays toward the leaf and
// toward the server, and once the exit is enabled again a new connection is
// dialed and relayed
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
		t.Errorf("the leaf read %v once the exit withdrew, want a reset", err)
	}
	select {
	case err := <-ended:
		if !errors.Is(err, syscall.ECONNRESET) {
			t.Errorf("the server read %v once the exit withdrew, want a reset", err)
		}
	case <-time.After(exitWait):
		t.Fatal("the server's connection outlived the withdrawal")
	}
	r.waitFor(t, "the connection's counts given back", func() bool { return r.exit.tcp.held() == [3]int{} })
	r.exit.SetEnabled(true)
	r.waitFor(t, "the exit taking again", r.exit.taking.Load)
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

// waitFor waits for done within exitWait
func (r *leafRig) waitFor(t *testing.T, what string, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(exitWait)
	for !done() {
		if time.Now().After(deadline) {
			t.Fatalf("no %s within %s", what, exitWait)
		}
		time.Sleep(time.Millisecond)
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
// one socket's own.
func TestHostsPortAMappingHoldsIsRefused(t *testing.T) {
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
// host is made to give that port by IP_LOCAL_PORT_RANGE.
func TestAnotherClassLeavesALiveAutoMappingAlone(t *testing.T) {
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
