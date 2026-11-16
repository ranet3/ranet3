// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package userspace

import (
	"bytes"
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
	"ranet3.com/pkgs/ranet3/internal/netstack"
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
			elsewhere := netip.MustParseAddr("192.0.2.9")
			if family.server.Is6() {
				elsewhere = netip.MustParseAddr("2001:db8:4::9")
			}
			before := h.count(false, reasonNotOurs)
			h.x.icmp.take(h.unboundICMP(t, family.server.Is6()), unboundReply(elsewhere, id, 9, nil), elsewhere)
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

// A mapping takes replies from the echoDestinations its requests were last
// sent toward: a request toward one it holds makes that one the latest, so the
// one a new destination drops is the one its requests went toward longest ago
func TestEchoSocketKeepsTheDestinationsItsRequestsWentTowardLast(t *testing.T) {
	at := func(i int) netip.Addr { return netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)}) }
	e := &echoSocket{}
	for i := range echoDestinations {
		e.record(at(i))
	}
	e.record(at(0))
	e.record(at(echoDestinations))
	for i := range echoDestinations + 1 {
		if want := i != 1; e.sentTo(at(i)) != want {
			t.Errorf("a reply from %s taken %t, want %t: the requests went toward the first again before a new one, which drops the second", at(i), !want, want)
		}
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

// An echo socket is scoped by Prepare toward each request's destination
// before each send, so each request leaves by the link the platform names for
// its destination at that send: a selection that moves to another link at one
// destination moves the next request's scope with it, and a destination the
// platform names no link for, from the start or since, is refused before
// anything is sent. The scope is the one underlay.Bound sets, read back.
func TestEchoSocketIsScopedTowardEachDestination(t *testing.T) {
	loopback, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Skipf("no lo0: %v", err)
	}
	other := 0
	if ifs, err := net.Interfaces(); err == nil {
		for _, ifi := range ifs {
			if ifi.Index != loopback.Index && ifi.Flags&net.FlagUp != 0 {
				other = ifi.Index
				break
			}
		}
	}
	// the test's goroutine alone opens and sends, so Prepare runs on it alone,
	// and selected is the link the selection names for a loopback address
	var scoped []netip.AddrPort
	selected := loopback.Index
	bound := underlay.Bound(func(address netip.Addr) (int, uint64) {
		if address.IsLoopback() {
			return selected, 1
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
			selected = loopback.Index
			ipv6 := family.server.Is6()
			e, err := h.x.icmp.openEcho(ipv6, netip.Addr{}, 0x6161, family.server)
			if err != nil {
				t.Fatal(err)
			}
			defer e.close()
			scope := func() int {
				level, option := unix.IPPROTO_IP, unix.IP_BOUND_IF
				if ipv6 {
					level, option = unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF
				}
				var index int
				var err error
				if controlErr := e.socket.raw.Control(func(fd uintptr) { index, err = unix.GetsockoptInt(int(fd), level, option) }); controlErr != nil || err != nil {
					t.Fatalf("read the scope: %v %v", controlErr, err)
				}
				return index
			}
			request := echoRequest(family.leaf, family.server, 0x6161, 1, []byte("scoped"))
			scoped = scoped[:0]
			sends := []netip.Addr{family.server, family.server, unrouted[ipv6], family.server}
			for _, to := range sends {
				err := e.send(request, to)
				if routed := to.IsLoopback(); routed != (err == nil) {
					t.Errorf("send toward %s: %v, want it sent %t", to, err, routed)
				}
			}
			var want []netip.AddrPort
			for _, to := range sends {
				want = append(want, netip.AddrPortFrom(to, 0))
			}
			if !slices.Equal(scoped, want) {
				t.Errorf("Prepare scoped the socket toward %v, want %v, one for each send", scoped, want)
			}
			if got := scope(); got != loopback.Index {
				t.Errorf("the socket is scoped to interface %d, want lo0's %d", got, loopback.Index)
			}
			if other != 0 {
				// the loopback by another link may be refused, and the scope
				// is set before the send either way
				selected = other
				_ = e.send(request, family.server)
				if got := scope(); got != other {
					t.Errorf("the socket is scoped to interface %d after the selection moved to %d at %s, want the new one", got, other, family.server)
				}
			}
			selected = 0
			if err := e.send(request, family.server); !errors.Is(err, unix.ENETUNREACH) {
				t.Errorf("a request to %s after the selection named no link for it: %v, want ENETUNREACH", family.server, err)
			}
		})
	}
}

// A mapping whose earlier request left keeps that request's time through the
// next one, refused once the selection stopped naming a link for their
// destination
func TestEchoMappingKeepsItsTimePastARequestAfterTheSelectionWent(t *testing.T) {
	loopback, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Skipf("no lo0: %v", err)
	}
	var selected atomic.Int64
	bound := underlay.Bound(func(netip.Addr) (int, uint64) { return int(selected.Load()), 1 })
	h := newRelayHarness(t, func(rt *Runtime, _ *egress.Egress) { rt.Platform.Prepare = bound })
	for _, family := range echoFamilies {
		t.Run(family.name, func(t *testing.T) {
			selected.Store(int64(loopback.Index))
			const id = 0x6565
			payload := []byte("selection")
			h.x.echo.take(ipPacket(family.leaf, family.server, icmpProtocol(family.leaf), echoRequest(family.leaf, family.server, id, 1, payload)))
			h.waitLaid(t, "the reply to the first request", func(raw []byte) bool { return isEchoReply(raw, family.server, family.leaf, id, 1, payload) })
			selected.Store(0)
			before := h.count(false, reasonEchoUnsent)
			h.x.echo.take(ipPacket(family.leaf, family.server, icmpProtocol(family.leaf), echoRequest(family.leaf, family.server, id, 2, payload)))
			if got := h.count(false, reasonEchoUnsent) - before; got != 1 {
				t.Fatalf("counted %d requests unsent after the selection went, want 1", got)
			}
			h.advance(mappingSweep)
			h.x.echo.mu.Lock()
			live := h.x.echo.mappings[echoKey{family.leaf, id}] != nil
			h.x.echo.mu.Unlock()
			if !live {
				t.Error("the mapping ended at the next pass, want it kept by the request that left")
			}
		})
	}
}

// An echo request toward a destination the underlay names no link for is
// refused by the exit itself, its Prepare failing with ENETUNREACH before
// anything leaves: it is counted as echo unsent and answered as one no route
// reaches, the request quoted, and the mapping it opened ends at the next
// pass with its flow given back
func TestEchoRequestToADestinationWithNoLinkIsAnsweredNoRoute(t *testing.T) {
	bound := underlay.Bound(func(netip.Addr) (int, uint64) { return 0, 0 })
	h := newRelayHarness(t, func(rt *Runtime, _ *egress.Egress) { rt.Platform.Prepare = bound })
	var requests [][]byte
	for _, family := range echoFamilies {
		raw := ipPacket(family.leaf, family.server, icmpProtocol(family.leaf), echoRequest(family.leaf, family.server, 0x6464, 1, []byte("no link")))
		requests = append(requests, raw)
		h.x.echo.take(raw)
	}
	if got := h.count(false, reasonEchoUnsent); got != uint64(len(echoFamilies)) {
		t.Errorf("counted %d requests unsent, want 1 in each family", got)
	}
	answers := h.mesh.answered()
	if len(answers) != len(requests) {
		t.Fatalf("answered %d requests, want each of the %d", len(answers), len(requests))
	}
	for i, answer := range answers {
		if answer.kind != netstack.ExitNoRoute || !bytes.Equal(answer.offending, requests[i]) {
			t.Errorf("answer %d is kind %d or about another packet, want request %d answered as no route", i, answer.kind, i)
		}
	}
	opened, _ := h.echoHeld()
	h.advance(mappingSweep)
	if left, open := h.echoHeld(); opened != len(echoFamilies) || left != 0 || open != 0 {
		t.Errorf("%d mappings opened, %d left and %d flows held after the next pass, want 1 opened in each family and none left", opened, left, open)
	}
}

// A reply from the destination of a request the exit refused, its underlay
// naming no link toward it, goes to the leaf and keeps the mapping echoIdle
// from it: the destination is recorded before the send, so a reply on the
// mapping's identifier from there is the mapping's, read here as the socket
// bound to no address reads it
func TestEchoReplyFromTheDestinationOfARefusedRequestIsTaken(t *testing.T) {
	bound := underlay.Bound(func(netip.Addr) (int, uint64) { return 0, 0 })
	h := newRelayHarness(t, func(rt *Runtime, _ *egress.Egress) { rt.Platform.Prepare = bound })
	refused := map[bool]netip.Addr{false: netip.MustParseAddr("192.0.2.77"), true: netip.MustParseAddr("2001:db8:4::77")}
	for _, family := range echoFamilies {
		t.Run(family.name, func(t *testing.T) {
			ipv6 := family.server.Is6()
			to := refused[ipv6]
			const id = 0x6969
			unsent := h.count(false, reasonEchoUnsent)
			h.x.echo.take(ipPacket(family.leaf, to, icmpProtocol(family.leaf), echoRequest(family.leaf, to, id, 1, []byte("refused"))))
			h.x.echo.mu.Lock()
			m := h.x.echo.mappings[echoKey{family.leaf, id}]
			h.x.echo.mu.Unlock()
			if m == nil || h.count(false, reasonEchoUnsent) != unsent+1 {
				t.Fatalf("the mapping is open %t and the request counted unsent %t, want both", m != nil, h.count(false, reasonEchoUnsent) == unsent+1)
			}
			h.x.icmp.take(h.unboundICMP(t, ipv6), unboundReply(to, m.outside.id, 9, []byte("a reply")), to)
			h.waitLaid(t, "the reply toward the leaf", func(raw []byte) bool { return isEchoReply(raw, to, family.leaf, id, 9, []byte("a reply")) })
			h.endsAt(t, h.now().Add(echoIdle))
		})
	}
}

// An echo request scoped to a link that holds no route to its destination is
// answered over IPv6 alone: the selection names lo0 for every destination,
// and lo0 holds no route to a documentation address. Over IPv6 XNU refuses
// the send with EHOSTUNREACH, and the request is counted and answered as one
// no route reaches, quoted. Over IPv4 XNU sends it, so the exit counts
// nothing and the leaf hears nothing. What XNU gives each family is read
// first on a send of the test's own, and named where it is another.
func TestEchoRequestOnALinkWithNoRouteIsAnsweredNoRouteOverIPv6Alone(t *testing.T) {
	loopback, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Skipf("no lo0: %v", err)
	}
	bound := underlay.Bound(func(netip.Addr) (int, uint64) { return loopback.Index, 1 })
	h := newRelayHarness(t, func(rt *Runtime, _ *egress.Egress) { rt.Platform.Prepare = bound })
	unrouted := map[bool]netip.Addr{false: netip.MustParseAddr("192.0.2.77"), true: netip.MustParseAddr("2001:db8:4::77")}
	refusal := map[bool]error{false: nil, true: unix.EHOSTUNREACH}
	for _, family := range echoFamilies {
		t.Run(family.name, func(t *testing.T) {
			ipv6 := family.server.Is6()
			to := unrouted[ipv6]
			message := echoRequest(family.leaf, to, 0x6767, 1, []byte("routed nowhere"))
			e, err := h.x.icmp.openEcho(ipv6, netip.Addr{}, 0x6868, to)
			if err != nil {
				t.Fatal(err)
			}
			met := e.send(message, to)
			_ = e.close()
			if errors.Is(met, unix.EPERM) {
				t.Skipf("the host refuses this process a send off the loopback with %v, as the nix build's sandbox refuses it, so what XNU does with a send scoped to lo0 toward %s is not read here", met, to)
			}
			t.Logf("XNU met a send scoped to lo0 toward %s with %v", to, met)
			if want := refusal[ipv6]; !errors.Is(met, want) {
				t.Fatalf("XNU met a send scoped to lo0 toward %s with %v, want %v", to, met, want)
			}
			raw := ipPacket(family.leaf, to, icmpProtocol(family.leaf), message)
			answered, unsent := len(h.mesh.answered()), h.count(false, reasonEchoUnsent)
			h.x.echo.take(raw)
			answers, counted := h.mesh.answered()[answered:], h.count(false, reasonEchoUnsent)-unsent
			if met == nil {
				if len(answers) != 0 || counted != 0 {
					t.Errorf("answered %v and counted %d unsent where XNU sent the request, want neither", answers, counted)
				}
				return
			}
			if len(answers) != 1 || answers[0].kind != netstack.ExitNoRoute || !bytes.Equal(answers[0].offending, raw) || counted != 1 {
				t.Errorf("answered %v and counted %d unsent after XNU refused the send with %v, want the request counted once and answered as no route", answers, counted, met)
			}
		})
	}
}

// onEchoHost is a function that runs another where this process's echo
// sockets open, which on darwin is anywhere
func onEchoHost(*testing.T) func(func()) {
	return func(f func()) { f() }
}

// readyLoopback readies nothing on darwin, where the host's loopback is up
// and this process's echo sockets open
func readyLoopback(*testing.T) {}

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

// unboundICMP is the socket of h's exit bound to no address in the family
// ipv6 names, which reads every echo reply of the family
func (h *relayHarness) unboundICMP(t *testing.T, ipv6 bool) *icmpSocket {
	t.Helper()
	h.x.icmp.mu.Lock()
	defer h.x.icmp.mu.Unlock()
	socket := h.x.icmp.families[family(ipv6)].sockets[netip.Addr{}]
	if socket == nil {
		t.Fatal("no socket bound to no address")
	}
	return socket
}

// unboundReply is an echo reply from from on id as an ICMP socket of from's
// family reads it: over IPv4 behind an IP header of 20 bytes, which XNU hands
// the socket, and over IPv6 alone. Its checksum is left 0, which the exit
// computes again.
func unboundReply(from netip.Addr, id, seq uint16, payload []byte) []byte {
	reply := append(binary.BigEndian.AppendUint16(binary.BigEndian.AppendUint16([]byte{0, 0, 0, 0}, id), seq), payload...)
	if from.Is6() {
		reply[0] = 129
		return reply
	}
	return append([]byte{0x45, 19: 0}, reply...)
}
