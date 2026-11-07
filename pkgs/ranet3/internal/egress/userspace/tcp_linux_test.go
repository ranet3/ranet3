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
)

// A leaf's connection is ended in the stack and dialed again toward the
// server through Prepare: bytes cross both ways whole, the leaf's half close
// reaches the server while the server still sends, no copy buffer is held
// while the connection idles, and once both ends close the exit holds nothing
// of it
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
			conn, failure := (&tcpRelay{x: x}).dial(context.Background(), netip.AddrPortFrom(c.leaf, 0), listener.Addr().(*net.TCPAddr).AddrPort())
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
