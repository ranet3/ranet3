// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package userspace

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// A server's error about a leaf's datagram, which XNU queues on no socket the
// exit reads, reaches the exit through its ICMP socket and ends neither the
// mapping nor its socket toward the server. Over IPv6's loopback alone, the
// one address a test of no namespace holds, and loopback is a source the mesh
// refuses, so the error reaches the leaf as nothing, which the window below
// watches for. The same error about another program's socket on the host,
// drawn after it, reaches no leaf and is counted: XNU carries both through
// the loopback in turn and the socket's reader takes them in turn, so that
// count shows the exit's error reached the reader before the window. The
// same error from a router the mesh carries, handed to the reader, reaches
// the leaf from the router. The IPv4 quote is read below.
func TestServersErrorFromLoopbackIsNotRelayedThroughTheICMPSocket(t *testing.T) {
	server := netip.IPv6Loopback()
	live := loopbackServer(t, server)
	closed := netip.AddrPortFrom(server, freeUDPPort(t, server))
	h := newRelayHarness(t, nil)
	leaf := netip.AddrPortFrom(leaf6, freeUDPPort(t, leaf6))
	datagram := udpDatagram(leaf, closed, []byte("to a port no socket holds"))
	before := h.count(false, reasonNotOurs)
	h.x.udp.take(datagram, false)
	other, err := net.DialUDP("udp6", nil, net.UDPAddrFromAddrPort(closed))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, err := other.Write([]byte("another program's")); err != nil {
		t.Fatal(err)
	}
	_ = other.SetReadDeadline(time.Now().Add(exitWait))
	if _, err := other.Read(make([]byte, 64)); !icmpErrno(err) {
		t.Fatalf("the other socket read %v, want the port unreachable's errno", err)
	}
	deadline := time.Now().Add(exitWait)
	for h.count(false, reasonNotOurs) == before && time.Now().Before(deadline) {
		time.Sleep(layPoll)
	}
	if h.count(false, reasonNotOurs) == before {
		t.Fatal("the error about another program's socket was not counted, so nothing shows the server's error reached the exit")
	}
	h.noneLaid(t, "a packet for an error from loopback", exitWait/10, func([]byte) bool { return true })
	port, ok := h.mappingOf(leaf)
	if !ok {
		t.Fatal("the error ended the leaf's mapping")
	}
	if !destinationLive(h.x, leaf, closed) {
		t.Error("the error ended the mapping's socket toward the server")
	}
	h.x.udp.take(udpDatagram(leaf, serverAt(live), []byte("after the error")), false)
	if from := readDatagramFrom(t, live, []byte("after the error")); from.Port() != port {
		t.Errorf("the datagram after the error left from port %d, want the mapping's %d", from.Port(), port)
	}

	// the same error handed to the reader directly, many times over, so the
	// messages of other programs the socket reads meanwhile cannot stand in
	// for its count
	h.x.icmp.mu.Lock()
	unbound := h.x.icmp.families[1].sockets[netip.Addr{}]
	h.x.icmp.mu.Unlock()
	if unbound == nil {
		t.Fatal("no IPv6 socket bound to no address")
	}
	message := append([]byte{1, 4, 0, 0, 0, 0, 0, 0}, udpDatagram(other.LocalAddr().(*net.UDPAddr).AddrPort(), closed, []byte("another program's"))...)
	const handed = 64
	before = h.count(false, reasonNotOurs)
	for range handed {
		h.x.icmp.take(unbound, message, server)
	}
	if got := h.count(false, reasonNotOurs) - before; got < handed {
		t.Errorf("counted %d of the %d errors about another program's socket handed to the reader", got, handed)
	}
	if pkt := h.x.link.poll(); pkt != nil {
		t.Errorf("laid a packet of %d bytes toward a leaf for another program's error handed to the reader", pkt.Size())
		h.x.link.release(pkt)
	}

	// the port unreachable from a router the mesh carries, quoting the
	// datagram as the mapping's socket sent it, as the reader would read it
	router := netip.MustParseAddr("2001:db8:2::1")
	h.x.icmp.take(unbound, append([]byte{1, 4, 0, 0, 0, 0, 0, 0}, udpDatagram(h.mappingsOf(leaf)[0].external(), closed, []byte("to a port no socket holds"))...), router)
	laid := h.waitLaid(t, "the router's error", func(raw []byte) bool {
		p, ok := parse(raw)
		return ok && p.protocol == protoICMPv6
	})
	if p, _ := parse(laid); p.src != router || p.dst != leaf6 || p.kind != 1 || p.code != 4 {
		t.Errorf("relayed %s, want port unreachable from %s to %s", p, router, leaf6)
	}
	if quote := laid[40+8:]; !bytes.Equal(quote, datagram) {
		t.Errorf("quoted %x, want the leaf's datagram %x", quote, datagram)
	}
}

// XNU takes the quote the exit builds of a leaf's datagram, where it knows
// every field and where two datagrams differed in every field it then zeroes,
// options and extension headers left out and the UDP length claiming the
// payload quoted: a port unreachable quoting it, handed through a raw ICMP
// socket to a UDP socket of the host's connected as the leaf's was, fails the
// socket's next read with ECONNREFUSED, since XNU finds the socket by the
// quote's addresses and ports alone. Root alone opens the raw socket.
func TestXNUTakesTheQuoteOfADatagramWhoseFieldsDiffered(t *testing.T) {
	for _, loopback := range []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.IPv6Loopback()} {
		for _, differed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s differed %t", loopback, differed), func(t *testing.T) {
				domain, protocol, kind, code := unix.AF_INET6, unix.IPPROTO_ICMPV6, byte(1), byte(4)
				var to unix.Sockaddr = &unix.SockaddrInet6{Addr: loopback.As16()}
				if loopback.Is4() {
					domain, protocol, kind, code = unix.AF_INET, unix.IPPROTO_ICMP, 3, 3
					to = &unix.SockaddrInet4{Addr: loopback.As4()}
				}
				fd, err := unix.Socket(domain, unix.SOCK_RAW, protocol)
				if err != nil {
					t.Skipf("no raw ICMP socket for the test: %v", err)
				}
				defer unix.Close(fd)
				server := netip.AddrPortFrom(loopback, freeUDPPort(t, loopback))
				conn, err := net.DialUDP(udpNetwork(loopback), nil, net.UDPAddrFromAddrPort(server))
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				leaf := serverAt(conn)
				payload := []byte("the leaf's datagram")
				sent := [][]byte{leafDatagram(leaf, server, payload, 1)}
				if differed {
					longer := udpMessage(leaf, server, bytes.Repeat([]byte{0x77}, 40))
					var other []byte
					if loopback.Is4() {
						other = ip4(loopback, loopback, protoUDP, 2, 0x4000, 1, longer)
						other[1] = 0xb8
						other = withOptions(other, 4)
					} else {
						other = ip6(loopback, loopback, ipv6DestinationOptions, 1, append([]byte{protoUDP, 0, 1, 4, 0, 0, 0, 0}, longer...))
						binary.BigEndian.PutUint32(other[0:4], 6<<28|0xb8<<20|0x12345)
					}
					sent = append(sent, other)
				}
				dst := &destination{to: server}
				for _, raw := range sent {
					d, ok := readDatagram(raw)
					if !ok {
						t.Fatalf("the test's datagram %x does not read", raw)
					}
					dst.keep(raw, d)
				}
				every := fieldClass | fieldIdent | fieldFragment | fieldHops | fieldOptions | fieldLength | fieldChecksum
				if loopback.Is6() {
					every = fieldClass | fieldFlow | fieldHops | fieldOptions | fieldLength | fieldChecksum
				}
				if want := map[bool]fields{false: 0, true: every}[differed]; dst.varied != want {
					t.Fatalf("the datagrams differed in %08b, want %08b", dst.varied, want)
				}
				message := append(append([]byte{kind, code, 0, 0, 0, 0, 0, 0}, dst.quote(0, payload, false)...), payload...)
				if loopback.Is4() {
					binary.BigEndian.PutUint16(message[2:4], fold(sum(0, message)))
				}
				if err := unix.Sendto(fd, message, 0, to); err != nil {
					t.Fatalf("send the port unreachable: %v", err)
				}
				_ = conn.SetReadDeadline(time.Now().Add(exitWait))
				if _, err := conn.Read(make([]byte, 64)); !errors.Is(err, syscall.ECONNREFUSED) {
					t.Errorf("the socket read %v, want ECONNREFUSED", err)
				}
			})
		}
	}
}

// XNU hands an ICMP socket an IPv4 error's quote with its total length in
// the host's byte order, and the quote is read whole all the same, its
// header checksum checked with that length turned back: the port unreachable
// about a datagram of the test's own names its socket and the closed port it
// went to
func TestQuotedIPv4ErrorIsReadAsXNUHandsIt(t *testing.T) {
	loopback := netip.MustParseAddr("127.0.0.1")
	closed := netip.AddrPortFrom(loopback, freeUDPPort(t, loopback))
	icmp, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_ICMP)
	if err != nil {
		t.Skipf("no ICMP datagram socket for the test: %v", err)
	}
	defer unix.Close(icmp)
	timeout := unix.NsecToTimeval(exitWait.Nanoseconds())
	if err := unix.SetsockoptTimeval(icmp, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout); err != nil {
		t.Fatal(err)
	}
	sender, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(closed))
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	local := serverAt(sender)
	payload := []byte("to a port no socket holds")
	if _, err := sender.Write(payload); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
	for {
		n, _, err := unix.Recvfrom(icmp, buf, 0)
		if err != nil {
			t.Fatalf("read no port unreachable: %v", err)
		}
		if n < 20 || n < int(buf[0]&0x0f)*4+8 {
			continue
		}
		message := buf[int(buf[0]&0x0f)*4 : n]
		header := int(message[8]&0x0f) * 4
		if message[0] != 3 || header < 20 || len(message) < 8+header+4 ||
			binary.BigEndian.Uint16(message[8+header:]) != local.Port() || binary.BigEndian.Uint16(message[8+header+2:]) != closed.Port() {
			continue
		}
		t.Logf("the quoted total length as XNU hands it: %#04x", binary.BigEndian.Uint16(message[8+2:]))
		t.Logf("the quoted header checksum as XNU hands it: %#04x", binary.BigEndian.Uint16(message[8+10:]))
		// lo0 leaves the IPv4 header checksum to an offload that never runs,
		// so the quote of a loopback datagram holds none: the test writes the
		// one the header holds with the datagram's own length in network
		// order, and leaves the length as XNU hands it
		quoted := slices.Clone(message[8 : 8+header])
		binary.BigEndian.PutUint16(quoted[2:4], uint16(header+8+len(payload)))
		binary.BigEndian.PutUint16(quoted[10:12], 0)
		binary.BigEndian.PutUint16(message[8+10:], fold(sum(0, quoted)))
		q, reason := readQuotedError(message, false, loopback, nil)
		if reason != "" || q.from != local || q.to != closed || q.kind != 3 || q.code != 3 || q.protocol != protoUDP {
			t.Errorf("read %+v, %q, want port unreachable from %s to %s", q, reason, local, closed)
		}
		return
	}
}

// An error the ICMP socket reads about a TCP segment reaches the dial whose
// socket sent it from the quoted address and port toward the quoted server,
// the first alone, and no dial once the dial closed. One quoting another
// port reaches none.
func TestDialErrorReachesItsDialAlone(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("no loopback to dial: %v", err)
	}
	defer listener.Close()
	server := listener.Addr().(*net.TCPAddr).AddrPort()
	conn, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	local := conn.LocalAddr().(*net.TCPAddr).AddrPort()
	h := newRelayHarness(t, nil)
	queue := h.x.icmp.queue()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var opened error
	if err := raw.Control(func(fd uintptr) { opened = queue.open(int(fd), server) }); err != nil || opened != nil {
		t.Fatalf("open the dial's queue: %v %v", err, opened)
	}
	quoting := func(from netip.AddrPort, code byte) quotedError {
		return quotedError{icmpError: icmpError{offender: netip.MustParseAddr("198.51.100.1"), kind: 3, code: code}, protocol: protoTCP, from: from, to: server}
	}
	if h.x.icmp.dials.take(quoting(netip.AddrPortFrom(local.Addr(), local.Port()+1), 1)) {
		t.Error("an error quoting another port reached the dial")
	}
	if !h.x.icmp.dials.take(quoting(local, 1)) || !h.x.icmp.dials.take(quoting(local, 3)) {
		t.Fatal("the errors quoting the dial's socket reached no dial")
	}
	if got, ok := queue.read(syscall.EHOSTUNREACH); !ok || got.code != 1 {
		t.Errorf("the dial read %+v %t, want the first error, code 1", got, ok)
	}
	queue.close()
	if h.x.icmp.dials.take(quoting(local, 1)) {
		t.Error("an error reached the dial once it closed")
	}
	h.x.icmp.dials.mu.Lock()
	left := len(h.x.icmp.dials.queues[server])
	h.x.icmp.dials.mu.Unlock()
	if left != 0 {
		t.Errorf("%d queues still held toward the server once the dial closed, want none", left)
	}
	// a later dial's descriptor takes the lowest number free, the closed
	// one's, and its error reaches it alone
	again := h.x.icmp.queue()
	if err := raw.Control(func(fd uintptr) { opened = again.open(int(fd), server) }); err != nil || opened != nil {
		t.Fatalf("open the later dial's queue: %v %v", err, opened)
	}
	defer again.close()
	if !h.x.icmp.dials.take(quoting(local, 1)) {
		t.Fatal("the error quoting the later dial's socket reached no dial")
	}
	if got, ok := again.read(nil); !ok || got.code != 1 {
		t.Errorf("the later dial read %+v %t, want the error, code 1", got, ok)
	}
}

// A dial the server refuses fails with the refusal at once, while the reader
// of the family's ICMP socket bound to no address waits on it. The dial reads
// that socket itself for an error an ICMP message may have caused. A read
// that waited for the reader's lock held the dial, and the leaf's answer and
// Close with it, past the socket's next message, which the reader takes first.
// The family's socket is the test's own here, whose read lock a waiting read
// holds for the test's span whatever messages arrive, and such a read holds
// the dial past the test's wait every time.
func TestRefusedDialFailsWhileTheICMPSocketWaits(t *testing.T) {
	for _, c := range []struct {
		name           string
		leaf, loopback netip.Addr
	}{
		{"ipv4", leaf4, netip.MustParseAddr("127.0.0.1")},
		{"ipv6", leaf6, netip.IPv6Loopback()},
	} {
		t.Run(c.name, func(t *testing.T) {
			// a port no socket holds, so the server's stack resets the dial
			listener, err := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(netip.AddrPortFrom(c.loopback, 0)))
			if err != nil {
				t.Skipf("no loopback to dial: %v", err)
			}
			closed := listener.Addr().(*net.TCPAddr).AddrPort()
			_ = listener.Close()
			h := newRelayHarness(t, nil)
			h.x.icmp.mu.Lock()
			f := h.x.icmp.families[family(c.loopback.Is6())]
			unbound := f.sockets[netip.Addr{}]
			h.x.icmp.mu.Unlock()
			if unbound == nil {
				t.Fatalf("no %s socket bound to no address: %v", c.name, f.err)
			}
			waitOnUnbound(t, h, c.loopback.Is6())
			failed := make(chan dialFailure, 1)
			go func() {
				conn, _, failure := h.x.tcp.dial(context.Background(), netip.AddrPortFrom(c.leaf, 0), closed)
				if conn != nil {
					_ = conn.Close()
				}
				failed <- failure
			}()
			select {
			case failure := <-failed:
				if !errors.Is(failure.err, syscall.ECONNREFUSED) || failure.caused {
					t.Errorf("the dial to the closed %s failed with %v, an ICMP error %t, want ECONNREFUSED and none", closed, failure.err, failure.caused)
				}
			case <-time.After(exitWait):
				t.Fatalf("the dial to the closed %s had not failed after %s", closed, exitWait)
			}
		})
	}
}

// waitOnUnbound puts an ICMP datagram socket of the test's own in place of
// h's socket of ipv6's family bound to no address, with a read waiting in it
// that holds its read lock until the test ends. The read's function blocks
// inside RawConn.Read, so no message the socket receives releases the lock, as
// one reaching the exit's own socket would release its reader's for a moment.
// At the end the read returns, h's socket is put back and the test's closed.
func waitOnUnbound(t *testing.T, h *relayHarness, ipv6 bool) {
	t.Helper()
	domain, protocol := unix.AF_INET, unix.IPPROTO_ICMP
	if ipv6 {
		domain, protocol = unix.AF_INET6, unix.IPPROTO_ICMPV6
	}
	fd, err := unix.Socket(domain, unix.SOCK_DGRAM, protocol)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		t.Fatal(err)
	}
	waiting := &icmpSocket{ipv6: ipv6, file: os.NewFile(uintptr(fd), "icmp")}
	if waiting.raw, err = waiting.file.SyscallConn(); err != nil {
		_ = waiting.file.Close()
		t.Fatal(err)
	}
	held, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- waiting.raw.Read(func(uintptr) bool {
			close(held)
			<-release
			return true
		})
	}()
	select {
	case <-held:
	case err := <-done:
		_ = waiting.file.Close()
		t.Fatalf("the waiting read returned before it held the lock: %v", err)
	}
	h.x.icmp.mu.Lock()
	sockets := h.x.icmp.families[family(ipv6)].sockets
	own := sockets[netip.Addr{}]
	sockets[netip.Addr{}] = waiting
	h.x.icmp.mu.Unlock()
	t.Cleanup(func() {
		close(release)
		<-done
		h.x.icmp.mu.Lock()
		sockets[netip.Addr{}] = own
		h.x.icmp.mu.Unlock()
		_ = waiting.file.Close()
	})
}
