// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package userspace

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/underlay"
)

// echoFamilies is each family's leaf, another leaf and the loopback address
// darwin holds
var echoFamilies = []struct {
	name                string
	leaf, other, server netip.Addr
}{
	{"ipv4", leaf4, other4, netip.MustParseAddr("127.0.0.1")},
	{"ipv6", leaf6, other6, netip.IPv6Loopback()},
}

// A reply longer than the buffer it is read into is reported too large, so
// the mapping's reader drops it whole rather than carry it cut, and one that
// fits is read whole
func TestEchoReplyTooLargeForItsBufferIsRefused(t *testing.T) {
	var out atomic.Int64
	b := replyBuffer{headroom: largeBuffer - 99, out: &out}
	defer b.give()
	e := &echoSocket{replies: make(chan echoReply, 1), done: make(chan struct{})}
	e.replies <- echoReply{message: make([]byte, 100), from: netip.IPv6Loopback()}
	if _, _, err := e.receive(&b); !errors.Is(err, errEchoTooLarge) {
		t.Errorf("a reply of 100 bytes into 99 read %v, want errEchoTooLarge", err)
	}
	e.replies <- echoReply{message: make([]byte, 99), from: netip.IPv6Loopback()}
	if n, _, err := e.receive(&b); err != nil || n != 99 {
		t.Errorf("a reply of 99 bytes into 99 read %d, %v, want it whole", n, err)
	}
}

// A mapping's receive holds no pooled buffer while it waits for a reply, and
// takes one when a reply is there to move
func TestEchoSocketTakesItsBufferOnlyForAReply(t *testing.T) {
	var out atomic.Int64
	b := replyBuffer{headroom: 40, out: &out}
	defer b.give()
	e := &echoSocket{replies: make(chan echoReply, 1), done: make(chan struct{})}
	read := make(chan error, 1)
	go func() {
		_, _, err := e.receive(&b)
		read <- err
	}()
	time.Sleep(50 * time.Millisecond)
	if got := out.Load(); got != 0 {
		t.Errorf("a receive waiting for a reply holds %d pooled buffers, want none", got)
	}
	e.replies <- echoReply{message: make([]byte, 8), from: netip.IPv6Loopback()}
	if err := <-read; err != nil {
		t.Fatal(err)
	}
	if got := out.Load(); got != 1 {
		t.Errorf("the reply moved through %d pooled buffers, want one", got)
	}
}

// A mapping's queue toward its leaf holds at most perFlow bytes of replies,
// the share Within gives a mapping, or one reply alone of any size, and takes
// more once its reader has taken what it held
func TestEchoQueueHoldsAMappingsShareOrOneReply(t *testing.T) {
	e := &echoSocket{replies: make(chan echoReply, echoReplies), done: make(chan struct{})}
	from := netip.IPv6Loopback()
	if !e.enqueue(make([]byte, largeBuffer-40), from) {
		t.Fatal("an empty queue refused one reply of the largest size")
	}
	if e.enqueue(make([]byte, 64), from) {
		t.Fatal("a queue holding past perFlow took another reply")
	}
	var out atomic.Int64
	b := replyBuffer{headroom: 40, out: &out}
	if _, _, err := e.receive(&b); err != nil {
		t.Fatal(err)
	}
	b.give()
	taken := 0
	for e.enqueue(make([]byte, 1024), from) {
		taken++
	}
	if taken != perFlow/1024 {
		t.Errorf("took %d replies of 1024 bytes, want the %d perFlow holds", taken, perFlow/1024)
	}
}

// A leaf's echo goes out with the leaf's identifier where no other mapping of
// the exit holds it, and another leaf's on the same identifier with one the
// exit picks, each reply coming back to its own leaf with the leaf's
// identifier at the host's TTL or hop limit. XNU hands every ICMP socket every
// echo reply: the replies to another socket's echo running beside them,
// on an identifier no mapping holds, reach no leaf and are counted, and so is
// a reply on a mapping's identifier from an address the mapping never sent to.
func TestEchoTakesOnlyItsOwnReplies(t *testing.T) {
	for _, family := range echoFamilies {
		t.Run(family.name, func(t *testing.T) {
			h := newRelayHarness(t, nil)
			h.x.SetHopLimits(hostTTL, hostHopLimit)
			const id, foreign = 0x5151, 0x7272
			stranger := strangerEcho(t, family.server)
			for seq, leaf := range []netip.Addr{family.leaf, family.other, family.leaf} {
				payload := fmt.Appendf(nil, "echo %d", seq)
				stranger.ping(t, foreign, uint16(seq))
				h.x.echo.take(ipPacket(leaf, family.server, icmpProtocol(leaf), echoRequest(leaf, family.server, id, uint16(seq), payload)))
				reply := h.waitLaid(t, fmt.Sprintf("reply %d to %s", seq, leaf), func(raw []byte) bool {
					if p, ok := parse(raw); ok && p.dst == leaf && p.protocol == icmpProtocol(leaf) && binary.BigEndian.Uint16(raw[len(raw)-len(payload)-4:]) != id {
						t.Errorf("laid %s toward the leaf, a reply on another identifier", p)
					}
					return isEchoReply(raw, family.server, leaf, id, uint16(seq), payload)
				})
				if got := hopsOf(reply); got != hostHops(leaf) {
					t.Errorf("reply %d laid at %d, want the host's %d", seq, got, hostHops(leaf))
				}
			}
			h.x.echo.mu.Lock()
			mine, theirs := h.x.echo.mappings[echoKey{family.leaf, id}], h.x.echo.mappings[echoKey{family.other, id}]
			h.x.echo.mu.Unlock()
			if mine == nil || theirs == nil {
				t.Fatalf("the leaf's mapping %t and the other's %t, want one each", mine != nil, theirs != nil)
			}
			if got := boundIdentifier(t, mine.socket); got != id {
				t.Errorf("the leaf's mapping holds identifier %d, want the leaf's %d, which no other mapping held", got, id)
			}
			if got := boundIdentifier(t, theirs.socket); got == id || got == foreign {
				t.Errorf("the other leaf's mapping holds identifier %d, which another socket's echo or the first mapping holds", got)
			}
			deadline := time.Now().Add(exitWait)
			for h.count(false, reasonNotOurs) < 3 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if got := h.count(false, reasonNotOurs); got < 3 {
				t.Errorf("counted %d messages as not the exit's, want at least the stranger's 3 replies", got)
			}
			// a reply on the leaf's identifier from an address its mapping never
			// sent to, read by the socket bound to no address
			elsewhere, index, message := netip.MustParseAddr("192.0.2.9"), 0, append(make([]byte, 20), 0, 0, 0, 0, id>>8, id&0xff, 0, 9)
			message[0] = 0x45
			if family.server.Is6() {
				elsewhere, index, message = netip.MustParseAddr("2001:db8:4::9"), 1, message[20:]
				message[0] = 129
			}
			h.x.icmp.mu.Lock()
			unbound := h.x.icmp.families[index].sockets[netip.Addr{}]
			h.x.icmp.mu.Unlock()
			if unbound == nil {
				t.Fatal("no socket bound to no address")
			}
			before := h.count(false, reasonNotOurs)
			h.x.icmp.take(unbound, message, elsewhere)
			if h.count(false, reasonNotOurs) == before {
				t.Errorf("a reply on the leaf's identifier from %s, where its mapping never sent, was not counted", elsewhere)
			}
			if pkt := h.x.link.poll(); pkt != nil {
				t.Errorf("laid a packet of %d bytes toward a leaf past the replies", pkt.Size())
				h.x.link.release(pkt)
			}
		})
	}
}

// openEcho gives a mapping the identifier it asks for only where no other
// mapping of the family holds it, and one the exit picks where one does. The
// relay never asks for one another mapping holds (`mapping`), so this reads
// openEcho's own check directly.
func TestEchoSocketGivesAHeldIdentifierAnother(t *testing.T) {
	for _, family := range echoFamilies {
		t.Run(family.name, func(t *testing.T) {
			h := newRelayHarness(t, nil)
			const id = 0x5353
			ipv6 := family.server.Is6()
			first, err := h.x.icmp.openEcho(ipv6, netip.Addr{}, id, family.server)
			if err != nil {
				t.Fatalf("open the first mapping: %v", err)
			}
			defer first.close()
			second, err := h.x.icmp.openEcho(ipv6, netip.Addr{}, id, family.server)
			if err != nil {
				t.Fatalf("open the second mapping: %v", err)
			}
			defer second.close()
			if got, _ := first.identifier(); got != id {
				t.Errorf("the first mapping holds identifier %d, want the %d it asked for, which no mapping held", got, id)
			}
			if got, _ := second.identifier(); got == id || got == 0 {
				t.Errorf("the second mapping holds identifier %d, want one the exit picks, not the first mapping's %d", got, id)
			}
		})
	}
}

// Each family's ICMP socket is narrowed with ICMP6_FILTER to echo replies and
// the error types 1 to 4, so no echo request or neighbor discovery message is
// read
func TestICMPv6SocketReadsOnlyEchoRepliesAndErrors(t *testing.T) {
	h := newRelayHarness(t, nil)
	h.x.icmp.mu.Lock()
	socket := h.x.icmp.families[1].sockets[netip.Addr{}]
	h.x.icmp.mu.Unlock()
	if socket == nil {
		t.Fatalf("no ICMPv6 socket: %v", h.x.icmp.families[1].err)
	}
	var filter *unix.ICMPv6Filter
	var err error
	if controlErr := socket.raw.Control(func(fd uintptr) {
		filter, err = unix.GetsockoptICMPv6Filter(int(fd), unix.IPPROTO_ICMPV6, unix.ICMP6_FILTER)
	}); controlErr != nil || err != nil {
		t.Fatalf("read the filter: %v %v", controlErr, err)
	}
	passes := func(kind uint8) bool { return filter.Filt[kind>>5]&(1<<(kind&31)) != 0 }
	for kind := range 256 {
		want := kind >= 1 && kind <= 4 || kind == 129
		if got := passes(uint8(kind)); got != want {
			t.Errorf("type %d passes %t, want %t", kind, got, want)
		}
	}
}

// An echo socket is scoped by Prepare toward each destination it sends to,
// again only where the destination changes, so each request leaves by the
// link the platform names for its own destination, and a destination the
// platform routes by no link is refused before anything is sent. The scope is
// the one underlay.Bound sets, read back.
func TestEchoSocketIsScopedTowardEachDestination(t *testing.T) {
	loopback, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Skipf("no lo0: %v", err)
	}
	// the test's goroutine alone opens and sends, so Prepare runs on it alone
	var scoped []netip.AddrPort
	bound := underlay.Bound(func(address netip.Addr) (int, uint64) {
		if address.IsLoopback() {
			return loopback.Index, 1
		}
		return 0, 0
	})
	h := newRelayHarness(t, func(rt *Runtime, _ *egress.Egress) {
		rt.Platform.Prepare = func(network string, to netip.AddrPort, raw syscall.RawConn) error {
			scoped = append(scoped, to)
			return bound(network, to, raw)
		}
	})
	unrouted := map[bool]netip.Addr{false: netip.MustParseAddr("192.0.2.77"), true: netip.MustParseAddr("2001:db8:4::77")}
	for _, family := range echoFamilies {
		t.Run(family.name, func(t *testing.T) {
			ipv6 := family.server.Is6()
			e, err := h.x.icmp.openEcho(ipv6, netip.Addr{}, 0x6161, family.server)
			if err != nil {
				t.Fatal(err)
			}
			defer e.close()
			request := echoRequest(family.leaf, family.server, 0x6161, 1, []byte("scoped"))
			scoped = scoped[:0]
			for _, to := range []netip.Addr{family.server, family.server, unrouted[ipv6], family.server} {
				err := e.send(request, to)
				if routed := to.IsLoopback(); routed != (err == nil) {
					t.Errorf("send toward %s: %v, want it sent %t", to, err, routed)
				}
			}
			want := []netip.AddrPort{netip.AddrPortFrom(family.server, 0), netip.AddrPortFrom(unrouted[ipv6], 0), netip.AddrPortFrom(family.server, 0)}
			if !slices.Equal(scoped, want) {
				t.Errorf("Prepare scoped the socket toward %v, want %v", scoped, want)
			}
			level, option := unix.IPPROTO_IP, unix.IP_BOUND_IF
			if ipv6 {
				level, option = unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF
			}
			var index int
			if controlErr := e.socket.raw.Control(func(fd uintptr) { index, err = unix.GetsockoptInt(int(fd), level, option) }); controlErr != nil || err != nil {
				t.Fatalf("read the scope: %v %v", controlErr, err)
			}
			if index != loopback.Index {
				t.Errorf("the socket is scoped to interface %d, want lo0's %d", index, loopback.Index)
			}
		})
	}
}

// stranger is another program's ICMP datagram socket, whose echo the exit
// sees the replies to
type stranger struct {
	fd int
	to unix.Sockaddr
}

// strangerEcho is an ICMP datagram socket of the test's own toward server,
// closed with t
func strangerEcho(t *testing.T, server netip.Addr) *stranger {
	t.Helper()
	domain, protocol := unix.AF_INET, unix.IPPROTO_ICMP
	var to unix.Sockaddr
	if server.Is6() {
		domain, protocol, to = unix.AF_INET6, unix.IPPROTO_ICMPV6, &unix.SockaddrInet6{Addr: server.As16()}
	} else {
		to = &unix.SockaddrInet4{Addr: server.As4()}
	}
	fd, err := unix.Socket(domain, unix.SOCK_DGRAM, protocol)
	if err != nil {
		t.Skipf("no ICMP datagram socket for the test: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	timeout := unix.NsecToTimeval(exitWait.Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout); err != nil {
		t.Fatal(err)
	}
	return &stranger{fd: fd, to: to}
}

// ping sends an echo request on id and seq and waits for its reply on the
// stranger's own socket, which XNU hands the exit's as well
func (s *stranger) ping(t *testing.T, id, seq uint16) {
	t.Helper()
	request := make([]byte, 8+len("stranger"))
	request[0] = 8
	if _, ok := s.to.(*unix.SockaddrInet6); ok {
		request[0] = 128
	}
	binary.BigEndian.PutUint16(request[4:6], id)
	binary.BigEndian.PutUint16(request[6:8], seq)
	copy(request[8:], "stranger")
	if request[0] == 8 {
		binary.BigEndian.PutUint16(request[2:4], fold(sum(0, request)))
	}
	if err := unix.Sendto(s.fd, request, 0, s.to); err != nil {
		t.Fatalf("the stranger's echo: %v", err)
	}
	buf := make([]byte, 1500)
	for {
		n, _, err := unix.Recvfrom(s.fd, buf, 0)
		if err != nil {
			t.Fatalf("the stranger read no reply: %v", err)
		}
		message := buf[:n]
		if _, ok := s.to.(*unix.SockaddrInet4); ok && n >= 20 {
			message = buf[int(buf[0]&0x0f)*4 : n]
		}
		if len(message) >= 8 && (message[0] == 0 || message[0] == 129) && binary.BigEndian.Uint16(message[4:6]) == id && binary.BigEndian.Uint16(message[6:8]) == seq {
			return
		}
	}
}
