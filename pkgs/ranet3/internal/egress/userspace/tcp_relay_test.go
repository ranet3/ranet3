// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package userspace

import (
	"io"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/egress"
)

// A leaf's SYN sent again while its dial runs is taken without a second
// admission, since the stack's forwarder hands no second request for it, and
// once the dial fails every count is back and the exit stops
func TestSYNAgainWhileDialingIsAdmittedOnce(t *testing.T) {
	release := make(chan struct{})
	released := sync.OnceFunc(func() { close(release) })
	h := newRelayHarness(t, func(rt *Runtime, _ *egress.Egress) {
		rt.Platform.Prepare = func(_ string, to netip.AddrPort, _ syscall.RawConn) error {
			if !to.IsValid() {
				return nil
			}
			<-release
			return syscall.ENETUNREACH
		}
	})
	t.Cleanup(released)
	leaf, server := netip.AddrPortFrom(leaf4, 43020), netip.AddrPortFrom(server4, 80)
	for range 2 {
		if reason := h.syn(t, leaf, server); reason != "" {
			t.Fatalf("the SYN was refused past %s", reason)
		}
	}
	if held := h.x.tcp.held(); held != [3]int{1, 1, 1} {
		t.Errorf("the relay holds dials, connections and flows %v for one SYN sent twice, want 1 each", held)
	}
	released()
	h.waitConnections(t, 0)
	if held := h.x.tcp.held(); held != [3]int{} {
		t.Errorf("the relay holds dials, connections and flows %v once the dial failed, want none", held)
	}
}

// A dial that completes after the relay's withdraw resets the leaf and the
// server rather than relaying a connection withdraw did not list
func TestDialDoneAfterWithdrawalResetsBothEnds(t *testing.T) {
	h := newRelayHarness(t, nil)
	allowLoopback(t, h.x.stack)
	accepted := make(chan *net.TCPConn, 1)
	server := tcpServer(t, netip.MustParseAddr("127.0.0.1"), func(conn *net.TCPConn) { accepted <- conn })
	leaf := netip.AddrPortFrom(leaf4, 43030)
	if reason := h.syn(t, leaf, server); reason != "" {
		t.Fatalf("the SYN was refused past %s", reason)
	}
	synAck := h.waitLaid(t, "the SYN-ACK toward the leaf", func(raw []byte) bool {
		p, ok := parse(raw)
		return ok && p.protocol == protoTCP && p.flags == tcpSYN|tcpACK && netip.AddrPortFrom(p.dst, p.dstPort) == leaf
	})
	h.x.tcp.withdraw()
	p, _ := parse(synAck)
	h.x.link.deliver(tcpSegment(leaf, server, leafISN+1, p.seq+1, tcpACK, nil))
	h.waitLaid(t, "the reset toward the leaf", func(raw []byte) bool {
		p, ok := parse(raw)
		return ok && p.resetToward(leaf)
	})
	var conn *net.TCPConn
	select {
	case conn = <-accepted:
	case <-time.After(exitWait):
		t.Fatal("the server accepted no connection")
	}
	defer conn.Close()
	if err := peerSaw(conn, exitWait); !reset(err) {
		t.Errorf("the server read %v, want a reset", err)
	}
	h.waitConnections(t, 0)
}

// The leaf's endpoint of a relayed connection has keepalives on
func TestRelayedLeafEndpointKeepsAlive(t *testing.T) {
	h := newRelayHarness(t, nil)
	allowLoopback(t, h.x.stack)
	server := tcpServer(t, netip.MustParseAddr("127.0.0.1"), readsToTheEnd)
	h.open(t, netip.AddrPortFrom(leaf4, 43040), server)
	if !listedFlow(t, h).ep.SocketOptions().GetKeepAlive() {
		t.Error("the leaf's endpoint has keepalives off")
	}
}

// A server's reset after its FIN reaches the leaf as a reset while the leaf,
// which acknowledged the FIN, sends nothing more, and the connection ends
func TestServersResetAfterItsFINReachesTheLeaf(t *testing.T) {
	h := newRelayHarness(t, nil)
	allowLoopback(t, h.x.stack)
	resetNow := make(chan struct{})
	resets := resetsOn(resetNow)
	server := tcpServer(t, netip.MustParseAddr("127.0.0.1"), func(conn *net.TCPConn) {
		_ = conn.CloseWrite()
		resets(conn)
	})
	c := h.open(t, netip.AddrPortFrom(leaf4, 43000), server)
	c.ack = h.stackFIN(t, c)
	h.x.link.deliver(tcpSegment(c.leaf, c.server, c.seq, c.ack, tcpACK, nil))
	close(resetNow)
	h.waitLaid(t, "the reset toward the leaf after the server's FIN", func(raw []byte) bool {
		p, ok := parse(raw)
		return ok && p.resetToward(c.leaf)
	})
	h.waitConnections(t, 0)
}

// A leaf's reset after its FIN reaches the server as a reset while the
// server, which read the FIN, sends nothing, and the connection ends
func TestLeafsResetAfterItsFINReachesTheServer(t *testing.T) {
	h := newRelayHarness(t, nil)
	allowLoopback(t, h.x.stack)
	server, readFIN := readsToTheFIN(t)
	c := h.open(t, netip.AddrPortFrom(leaf4, 43010), server)
	h.x.link.deliver(tcpSegment(c.leaf, c.server, c.seq, c.ack, tcpACK|tcpFIN, nil))
	c.seq++
	conn := readFIN()
	h.x.link.deliver(tcpSegment(c.leaf, c.server, c.seq, c.ack, tcpRST|tcpACK, nil))
	waitFor(t, "error on the server's socket after the leaf's reset", func() bool { return socketErrno(t, conn) != 0 })
	h.waitConnections(t, 0)
}

// readsToTheFIN is a loopback server that reads each connection to the
// client's FIN and keeps it open, and a wait for the connection whose FIN it
// read, closed as t ends
func readsToTheFIN(t *testing.T) (netip.AddrPort, func() *net.TCPConn) {
	finished := make(chan *net.TCPConn, 1)
	server := tcpServer(t, netip.MustParseAddr("127.0.0.1"), func(conn *net.TCPConn) {
		_ = conn.SetReadDeadline(time.Now().Add(exitWait))
		_, _ = io.Copy(io.Discard, conn)
		finished <- conn
	})
	return server, func() *net.TCPConn {
		t.Helper()
		select {
		case conn := <-finished:
			t.Cleanup(func() { _ = conn.Close() })
			return conn
		case <-time.After(exitWait):
			t.Fatal("the server read no FIN")
			return nil
		}
	}
}
