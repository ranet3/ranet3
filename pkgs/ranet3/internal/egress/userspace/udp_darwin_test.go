// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package userspace

import (
	"encoding/binary"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// A datagram sent after an ICMP error left its errno on its destination's
// socket reaches its server: XNU fails the write with the error's errno
// (sosendcheck hands so_error and clears it), which may as well be one of the
// host's own, so the send writes it once more, and nothing is counted as the
// host's own or as failed by pending errors. The error is a port unreachable
// handed through a raw ICMP or ICMPv6 socket, quoting the first datagram as
// the destination's socket sent it, on a socket no reader takes so_error from.
// The error itself reaches the exit through its ICMP socket, which no reader
// of this test runs, from loopback is relayed as nothing, and from a router
// the mesh carries reaches the leaf:
// TestServersErrorFromLoopbackIsNotRelayedThroughTheICMPSocket shows both.
// Root alone opens the raw socket.
func TestDatagramLeavesPastAnErrorsErrno(t *testing.T) {
	for _, loopback := range []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.IPv6Loopback()} {
		t.Run(loopback.String(), func(t *testing.T) {
			domain, protocol, kind, code := unix.AF_INET6, unix.IPPROTO_ICMPV6, byte(1), byte(4)
			var at unix.Sockaddr = &unix.SockaddrInet6{Addr: loopback.As16()}
			if loopback.Is4() {
				domain, protocol, kind, code = unix.AF_INET, unix.IPPROTO_ICMP, 3, 3
				at = &unix.SockaddrInet4{Addr: loopback.As4()}
			}
			fd, err := unix.Socket(domain, unix.SOCK_RAW, protocol)
			if err != nil {
				t.Skipf("no raw ICMP socket for the test: %v", err)
			}
			defer unix.Close(fd)
			h := newRelayHarness(t, nil)
			h.x.rt.Platform.Prepare = func(string, netip.AddrPort, syscall.RawConn) error { return nil }
			server := loopbackServer(t, loopback)
			to := serverAt(server)
			conn, err := h.x.udp.connect(0, loopback, to)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			dst := &destination{to: to, conn: conn}
			leaf := netip.AddrPortFrom(leaf4, freeUDPPort(t, leaf4))
			if loopback.Is6() {
				leaf = netip.AddrPortFrom(leaf6, freeUDPPort(t, leaf6))
			}
			payload := []byte("before the error")
			first := udpDatagram(leaf, to, payload)
			d, _ := readDatagram(first)
			if refused, _ := h.x.udp.send(first, d, dst, false); refused {
				t.Fatal("the first datagram was refused")
			}
			readDatagramFrom(t, server, payload)

			message := append([]byte{kind, code, 0, 0, 0, 0, 0, 0}, udpDatagram(serverAt(conn), to, payload)...)
			if loopback.Is4() {
				binary.BigEndian.PutUint16(message[2:4], fold(sum(0, message)))
			}
			if err := unix.Sendto(fd, message, 0, at); err != nil {
				t.Fatalf("send the port unreachable: %v", err)
			}
			// so_error makes the socket readable, and the server sends it
			// nothing
			if !readable(t, conn) {
				t.Fatal("the port unreachable left no errno on the destination's socket")
			}

			unsent, pending := h.count(false, reasonUnsent), h.count(false, reasonPending)
			next := udpDatagram(leaf, to, []byte("after the error"))
			dn, _ := readDatagram(next)
			if refused, closed := h.x.udp.send(next, dn, dst, false); refused || closed {
				t.Errorf("the send past the error's errno reported refused %t closed %t, want neither", refused, closed)
			}
			readDatagramFrom(t, server, dn.payload())
			if unsent, pending := h.count(false, reasonUnsent)-unsent, h.count(false, reasonPending)-pending; unsent != 0 || pending != 0 {
				t.Errorf("counted %d datagrams unsent and %d failed by pending errors, want none", unsent, pending)
			}
		})
	}
}

// readable is whether conn's socket turns readable within exitWait, polled
// without reading it
func readable(t *testing.T, conn *net.UDPConn) bool {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	ready := false
	for start := time.Now(); !ready && time.Since(start) < exitWait; time.Sleep(time.Millisecond) {
		if err := raw.Control(func(fd uintptr) {
			fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
			n, err := unix.Poll(fds, 0)
			ready = err == nil && n == 1 && fds[0].Revents&unix.POLLIN != 0
		}); err != nil {
			t.Fatal(err)
		}
	}
	return ready
}
