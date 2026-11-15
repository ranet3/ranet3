// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package userspace

import (
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

// isResetToward picks a reset the exit sends toward leaf
func isResetToward(leaf netip.AddrPort) func([]byte) bool {
	return func(raw []byte) bool {
		p, ok := parse(raw)
		return ok && p.protocol == protoTCP && p.flags&tcpRST != 0 && netip.AddrPortFrom(p.dst, p.dstPort) == leaf
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
	h.waitLaid(t, "the reset toward the leaf after the server's FIN", isResetToward(c.leaf))
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
