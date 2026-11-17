// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package userspace

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/netnstest"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/nftables"
)

// pathMTU is loopback's MTU while a test holds a path narrower than the
// leaf's session
const pathMTU = 1300

// twoPrefixes are the two prefixes twoAddressesHeld gives loopback, whose
// routes pick each prefix's address toward the rest of it
var twoPrefixes = [2]netip.Prefix{netip.MustParsePrefix("198.51.100.1/25"), netip.MustParsePrefix("198.51.100.129/25")}

// rigFamily is one family's addresses of the rig: the leaf's, and three
// servers' on loopback
type rigFamily struct {
	name    string
	leaf    netip.Addr
	servers [3]netip.Addr
}

var rigFamilies = []rigFamily{
	{"ipv4", rigLeaf4.Addr(), [3]netip.Addr{rigServer4.Addr(), rigOthers4[0].Addr(), rigOthers4[1].Addr()}},
	{"ipv6", rigLeaf6.Addr(), [3]netip.Addr{rigServer6.Addr(), rigOthers6[0].Addr(), rigOthers6[1].Addr()}},
}

// A leaf's datagrams to two servers leave the exit from one port, the leaf's
// own where free, on the address each server's route picks (RFC 4787 REQ-1
// from each address, REQ-3). Each server's reply reaches the
// leaf's socket from that server, as does a datagram from another port of an
// address the leaf sent to, and none from an address it never sent to
// (REQ-8). Every socket the relay opened passed Prepare: the route probe
// toward each server, the one that only receives with no destination of each
// address the servers' routes pick, and each server's own.
func TestLeafDatagramsAreRelayedThroughPrepare(t *testing.T) {
	r := newLeafRig(t, func(rt Runtime) (*Exit, error) { return New(exitConfig(), rt) })
	for _, family := range rigFamilies {
		t.Run(family.name, func(t *testing.T) {
			r.mu.Lock()
			r.prepared = nil
			r.mu.Unlock()
			a, b, stranger := r.server(t, family.servers[0]), r.server(t, family.servers[1]), r.server(t, family.servers[2])
			beside := r.server(t, family.servers[0])
			port := freeUDPPort(t, family.leaf)
			leaf := r.leafSocket(t, netip.AddrPortFrom(family.leaf, port), nil)
			outside := map[*net.UDPConn]netip.AddrPort{}
			for _, server := range []*net.UDPConn{a, b} {
				payload := []byte("to " + serverAt(server).String())
				if _, err := leaf.WriteToUDPAddrPort(payload, serverAt(server)); err != nil {
					t.Fatal(err)
				}
				from := readDatagramFrom(t, server, payload)
				if from.Port() != port {
					t.Errorf("%s read the leaf's datagram from %s, want from the leaf's port %d", serverAt(server), from, port)
				}
				outside[server] = from
			}
			for _, server := range []*net.UDPConn{a, b, beside} {
				to := outside[server]
				if server == beside {
					to = outside[a]
				}
				payload := []byte("from " + serverAt(server).String())
				if _, err := server.WriteToUDPAddrPort(payload, to); err != nil {
					t.Fatal(err)
				}
				if from := readDatagramFrom(t, leaf, payload); from != serverAt(server) {
					t.Errorf("the leaf read %s's datagram from %s", serverAt(server), from)
				}
			}
			filtered := countOf(r.exit, false, reasonFiltered)
			if _, err := stranger.WriteToUDPAddrPort([]byte("unasked"), outside[a]); err != nil {
				t.Fatal(err)
			}
			waitFor(t, "the stranger's datagram dropped as filtered", func() bool { return countOf(r.exit, false, reasonFiltered) > filtered })
			if _, err := a.WriteToUDPAddrPort([]byte("after"), outside[a]); err != nil {
				t.Fatal(err)
			}
			if got, from := readNext(t, leaf); string(got) != "after" {
				t.Errorf("the leaf read %q from %s, want the server's datagram after the stranger's, the stranger's never", got, from)
			}
			r.mu.Lock()
			prepared := slices.Clone(r.prepared)
			r.mu.Unlock()
			var want []netip.AddrPort
			routes := map[netip.Addr]bool{}
			for _, server := range []*net.UDPConn{a, b} {
				want = append(want, serverAt(server))
				if route := routeAddress(t, serverAt(server)); !routes[route] {
					routes[route] = true
					want = append(want, netip.AddrPort{})
				}
				want = append(want, serverAt(server))
			}
			if !slices.Equal(prepared, want) {
				t.Errorf("Prepare readied sockets toward %v, want %v", prepared, want)
			}
		})
	}
}

// A leaf's datagram with DF that the path to its server cannot carry whole is
// answered too big at the path's MTU from the exit and reaches no server, and
// one the leaf lets be fragmented reaches the server whole (RFC 4787 REQ-13).
// The refusal for its size is not counted as one of the host's own.
// A whole IPv6 datagram counts as one with DF, since no router fragments
// IPv6, and one the leaf fragmented itself is fragmented again.
func TestDatagramWithDFIsAnsweredTooBigPastThePath(t *testing.T) {
	r := newLeafRig(t, func(rt Runtime) (*Exit, error) { return New(exitConfig(), rt) })
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := netnstest.SetLinkMTU(lo.Index, pathMTU); err != nil {
		t.Fatalf("narrow loopback to %d: %v", pathMTU, err)
	}
	t.Cleanup(func() {
		if err := netnstest.SetLinkMTU(lo.Index, lo.MTU); err != nil {
			t.Errorf("restore loopback's MTU of %d: %v", lo.MTU, err)
		}
	})
	for _, family := range rigFamilies {
		t.Run(family.name, func(t *testing.T) {
			server := r.server(t, family.servers[0])
			whole := r.leafSocket(t, netip.AddrPortFrom(family.leaf, 0), func(fd int) error {
				if family.leaf.Is4() {
					return unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO)
				}
				return nil
			})
			payload := bytes.Repeat([]byte{0xdf}, pathMTU+50)
			answered := len(r.mesh.answered())
			if _, err := whole.WriteToUDPAddrPort(payload, serverAt(server)); err != nil {
				t.Fatal(err)
			}
			waitFor(t, "an answer to the datagram past the path", func() bool { return len(r.mesh.answered()) > answered })
			if answer := r.mesh.answered()[answered]; answer.kind != netstack.ExitTooBig || answer.mtu != pathMTU {
				t.Errorf("answered %v at %d, want too big at the path's %d", answer.kind, answer.mtu, pathMTU)
			}
			if got := countOf(r.exit, false, reasonUnsent); got != 0 {
				t.Errorf("counted %d datagrams unsent, want none, the one past the path refused for its size", got)
			}
			if _, err := whole.WriteToUDPAddrPort([]byte("fits"), serverAt(server)); err != nil {
				t.Fatal(err)
			}
			if got, from := readNext(t, server); string(got) != "fits" {
				t.Errorf("the server read %d bytes from %s, want the datagram that fits, the one past the path never", len(got), from)
			}

			size, set := pathMTU+50, func(fd int) error {
				return unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DONT)
			}
			if family.leaf.Is6() {
				size, set = leafMTU+100, nil
			}
			fragmented := r.leafSocket(t, netip.AddrPortFrom(family.leaf, 0), set)
			payload = bytes.Repeat([]byte{0xf7}, size)
			if _, err := fragmented.WriteToUDPAddrPort(payload, serverAt(server)); err != nil {
				t.Fatal(err)
			}
			if got, from := readNext(t, server); !bytes.Equal(got, payload) {
				t.Errorf("the server read %d bytes from %s, want the %d the leaf let be fragmented", len(got), from, len(payload))
			}
		})
	}
}

// An IPv6 datagram reaches its server whole within the path's MTU, and past it
// leaves in fragments only where its leaf sent it in fragments: one the leaf
// sent whole, behind no extension header, a destination options header or a
// hop-by-hop options header, is answered too big at the path's MTU quoting it
// as the leaf sent it, and reaches no server, as a router answers one (RFC
// 8200 section 4.5, RFC 4443 section 3.2)
func TestIPv6DatagramIsFragmentedOnlyWhereItsLeafFragmentedIt(t *testing.T) {
	onLoopback(t, rigServer6)
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := netnstest.SetLinkMTU(lo.Index, pathMTU); err != nil {
		t.Fatalf("narrow loopback to %d: %v", pathMTU, err)
	}
	t.Cleanup(func() {
		if err := netnstest.SetLinkMTU(lo.Index, lo.MTU); err != nil {
			t.Errorf("restore loopback's MTU of %d: %v", lo.MTU, err)
		}
	})
	h := newRelayHarness(t, nil)
	h.x.rt.Platform.Prepare = func(string, netip.AddrPort, syscall.RawConn) error { return nil }
	server := rigLoopbackServer(t, rigServer6.Addr())
	// an options header holding one PadN option, followed by UDP
	options := []byte{protoUDP, 0, 1, 4, 0, 0, 0, 0}
	for _, c := range []struct {
		name       string
		next       byte
		fragmented bool
	}{
		{"no extension header", protoUDP, false},
		{"destination options", ipv6DestinationOptions, false},
		{"hop-by-hop options", 0, false},
		{"fragments the leaf made", ipv6Fragment, true},
	} {
		for _, size := range []int{pathMTU - 300, pathMTU + 50} {
			t.Run(fmt.Sprintf("%s of %d bytes", c.name, size), func(t *testing.T) {
				leaf := netip.AddrPortFrom(leaf6, freeUDPPort(t, leaf6))
				payload := bytes.Repeat([]byte{byte(size)}, size)
				message := udpMessage(leaf, serverAt(server), payload)
				var packets [][]byte
				switch c.next {
				case protoUDP:
					packets = [][]byte{ip6(leaf6, rigServer6.Addr(), protoUDP, 64, message)}
				case ipv6Fragment:
					packets = fragments(leaf6, rigServer6.Addr(), protoUDP, 7, message, 512)
				default:
					packets = [][]byte{ip6(leaf6, rigServer6.Addr(), c.next, 64, append(bytes.Clone(options), message...))}
				}
				answered := len(h.mesh.answered())
				for _, raw := range packets {
					h.x.handle(h.lane, raw)
				}
				if 40+len(message) <= pathMTU || c.fragmented {
					readDatagramFrom(t, server, payload)
					if answers := h.mesh.answered()[answered:]; len(answers) != 0 {
						t.Errorf("answered %v, want the datagram carried alone", answers)
					}
					return
				}
				answers := h.mesh.answered()[answered:]
				if len(answers) != 1 || answers[0].kind != netstack.ExitTooBig || answers[0].mtu != pathMTU || !bytes.Equal(answers[0].offending, packets[0]) {
					t.Errorf("answered %v, want one too big at the path's %d quoting the leaf's packet", answers, pathMTU)
				}
				_ = server.SetReadDeadline(time.Now().Add(stackSettle))
				buf := make([]byte, 1<<16)
				if n, _, err := server.ReadFromUDPAddrPort(buf); err == nil {
					t.Errorf("the server read %d bytes, want nothing of the datagram past the path", n)
				}
			})
		}
	}
}

// A destination's socket told of an ICMP error keeps reading whatever errno
// the host hands the error as: after a destination unreachable of code 1
// (EHOSTUNREACH), 5 (EOPNOTSUPP) or 8 (ENONET) about the leaf's datagram, the
// server's reply still reaches the leaf (RFC 4787 REQ-12)
func TestDestinationReadsOnPastEveryReceiveError(t *testing.T) {
	onLoopback(t, rigServer4)
	h := newRelayHarness(t, nil)
	h.x.rt.Platform.Prepare = func(string, netip.AddrPort, syscall.RawConn) error { return nil }
	for _, code := range []byte{1, 5, 8} {
		t.Run(fmt.Sprintf("code %d", code), func(t *testing.T) {
			server := rigLoopbackServer(t, rigServer4.Addr())
			leaf := netip.AddrPortFrom(leaf4, freeUDPPort(t, leaf4))
			payload := []byte("before the error")
			h.x.udp.take(udpDatagram(leaf, serverAt(server), payload), false)
			outside := readDatagramFrom(t, server, payload)
			sendICMP(t, outside.Addr(), leafRefusal(serverAt(server).Addr(), outside.Addr(), 3, code, udpDatagram(outside, serverAt(server), payload))[20:])
			h.waitLaid(t, "relayed error", func(raw []byte) bool {
				p, ok := parse(raw)
				return ok && p.protocol == 1 && p.kind == 3 && p.code == code
			})
			reply := []byte("after the error")
			if _, err := server.WriteToUDPAddrPort(reply, outside); err != nil {
				t.Fatal(err)
			}
			h.waitLaid(t, "reply after the error", func(raw []byte) bool { return isDatagram(raw, serverAt(server), leaf, reply) })
		})
	}
}

// tooBigServer4 and tooBigServer6 are servers' addresses on loopback that no
// test but TestDatagramLeavesPastAPendingError sends to, whose too bigs
// teach the namespace a path MTU toward them that outlives the test
var (
	tooBigServer4 = netip.MustParsePrefix("203.0.113.40/32")
	tooBigServer6 = netip.MustParsePrefix("2001:db8:3::40/128")
)

// An ICMP error about a datagram that left, pending on its destination's
// socket, which no reader drains, fails no later datagram: by the time the
// next send returns, the datagram has reached its server after two writes,
// the error has reached the leaf where the socket queued it, and nothing is
// counted as the host's own or as failed by pending errors. So with a
// Fragmentation Needed or a Packet Too Big, whose EMSGSIZE a datagram that
// fits the narrower path meets with DF, the datagram past the path then still
// answered too big at the path's MTU (RFC 4787 REQ-13, RFC 1191, RFC 8201),
// with a destination unreachable of code 3 (ECONNREFUSED), 5 (EOPNOTSUPP) or
// 8 (ENONET), and with a port unreachable whose queue entry the kernel
// dropped since replies filled the socket's receive buffer, its errno pending
// all the same (sock_queue_err_skb). The too bigs go to servers of their own,
// since the path MTU each teaches the namespace stays past the test.
func TestDatagramLeavesPastAPendingError(t *testing.T) {
	onLoopback(t, rigServer4, rigServer6, tooBigServer4, tooBigServer6)
	h := newRelayHarness(t, nil)
	h.x.rt.Platform.Prepare = func(string, netip.AddrPort, syscall.RawConn) error { return nil }
	unreachable := func(code byte) func(*net.UDPConn, *net.UDPConn, []byte) {
		return func(conn, server *net.UDPConn, left []byte) {
			sendICMP(t, serverAt(conn).Addr(), leafRefusal(serverAt(server).Addr(), serverAt(conn).Addr(), 3, code, left)[20:])
		}
	}
	for _, c := range []struct {
		name         string
		source, leaf netip.Addr
		first        int
		dontFragment bool
		raise        func(conn, server *net.UDPConn, left []byte)
		// mtu is the path's past a too big, and queued whether the socket
		// queues the error
		mtu    int
		queued bool
	}{
		{"ipv4 too big", tooBigServer4.Addr(), leaf4, 1400, true, func(conn, _ *net.UDPConn, left []byte) { tooBig(t, serverAt(conn).Addr(), 1000, left) }, 1000, true},
		{"ipv6 too big", tooBigServer6.Addr(), leaf6, 1400, true, func(conn, _ *net.UDPConn, left []byte) { tooBig(t, serverAt(conn).Addr(), 1280, left) }, 1280, true},
		{"code 3", rigServer4.Addr(), leaf4, 5, false, unreachable(3), 0, true},
		{"code 5", rigServer4.Addr(), leaf4, 5, false, unreachable(5), 0, true},
		{"code 8", rigServer4.Addr(), leaf4, 5, false, unreachable(8), 0, true},
		{"queue entry dropped", rigServer4.Addr(), leaf4, 5, false, func(conn, server *net.UDPConn, left []byte) {
			if err := onSocket(conn, func(fd int) error { return unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 1) }); err != nil {
				t.Fatal(err)
			}
			for range 3 {
				if _, err := server.WriteToUDPAddrPort(make([]byte, 1000), serverAt(conn)); err != nil {
					t.Fatal(err)
				}
			}
			time.Sleep(stackSettle)
			unreachable(3)(conn, server, left)
		}, 0, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			server := rigLoopbackServer(t, c.source)
			to := serverAt(server)
			conn, err := h.x.udp.connect(0, c.source, to)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			dst := &destination{to: to, conn: conn}
			leaf := netip.AddrPortFrom(c.leaf, freeUDPPort(t, c.leaf))
			first := udpDatagram(leaf, to, bytes.Repeat([]byte{0xb1}, c.first))
			d, _ := readDatagram(first)
			if refused, _ := h.x.udp.send(first, d, dst, c.dontFragment); refused {
				t.Fatal("the first datagram was refused")
			}
			readDatagramFrom(t, server, d.payload())
			c.raise(conn, server, udpDatagram(serverAt(conn), to, d.payload()))
			for start := time.Now(); !pendingError(conn); time.Sleep(time.Millisecond) {
				if time.Since(start) > exitWait {
					t.Fatal("no error pending on the destination's socket")
				}
			}

			next := udpDatagram(leaf, to, []byte("fits the path"))
			dn, _ := readDatagram(next)
			answered := len(h.mesh.answered())
			h.drainLaid()
			failures := countFailures(t, h, asQueued)
			refused, closed := h.x.udp.send(next, dn, dst, c.dontFragment)
			if refused || closed || *failures != 1 {
				t.Errorf("the send past the pending error reported refused %t closed %t after %d failed writes, want neither after 1", refused, closed, *failures)
			}
			if pkt := h.x.link.poll(); (pkt != nil) != c.queued {
				t.Errorf("the pending error had reached the leaf %t when the send returned, want %t", pkt != nil, c.queued)
			} else if pkt != nil {
				h.x.link.release(pkt)
			}
			readDatagramFrom(t, server, dn.payload())
			if got := h.count(false, reasonUnsent) + h.count(false, reasonPending); got != 0 {
				t.Errorf("counted %d datagrams unsent or failed by pending errors, want none", got)
			}
			if answers := h.mesh.answered()[answered:]; len(answers) != 0 {
				t.Errorf("answered %v about the datagram that fits the path", answers)
			}
			if c.mtu == 0 {
				return
			}
			if refused, _ := h.x.udp.send(first, d, dst, true); refused {
				t.Fatal("the datagram past the path was refused as one of the host's own")
			}
			if answers := h.mesh.answered()[answered:]; len(answers) != 1 || answers[0].kind != netstack.ExitTooBig || answers[0].mtu != c.mtu || !bytes.Equal(answers[0].offending, first) {
				t.Errorf("answered %v, want one too big at the path's %d quoting the datagram past it", answers, c.mtu)
			}
		})
	}
}

// A datagram the host refuses for a reason of its own, the route toward its
// server made unreachable, is written twice, counted unsent and reported
// refused, never counted as failed by pending errors, though the host hands
// EHOSTUNREACH as it would for an ICMP error
func TestDatagramTheHostRefusesIsWrittenTwice(t *testing.T) {
	r := newGoneRig(t)
	to := serverAt(r.both)
	if got := r.send(t, r.both, "left"); got.Addr() != r.gone.Addr() {
		t.Fatalf("the server read the datagram from %s, want %s", got, r.gone.Addr())
	}
	dst := r.h.mappingsOf(r.leaf)[0].destinations[to]
	unreachable(t, netip.PrefixFrom(to.Addr(), 32))
	raw := udpDatagram(r.leaf, to, []byte("refused"))
	d, _ := readDatagram(raw)
	failures := countFailures(t, r.h, asQueued)
	refused, closed := r.h.x.udp.send(raw, d, dst, false)
	if !refused || closed || *failures != 2 {
		t.Errorf("the send the host refused reported refused %t closed %t after %d failed writes, want refused after 2", refused, closed, *failures)
	}
	if unsent, pending := r.h.count(false, reasonUnsent), r.h.count(false, reasonPending); unsent != 1 || pending != 0 {
		t.Errorf("counted %d datagrams unsent and %d failed by pending errors, want 1 and 0", unsent, pending)
	}
}

// A datagram toward a server the host's own firewall rejects in its output
// path, which fails the write with EPERM and queues the reject's ICMP error on
// the socket, is written once, counted unsent and reported refused, and the
// leaf is told of the one error that write raised, none counted as no flow of
// the exit's: in both families, the writes counted by the rule's own counter,
// three datagrams each sent apart, with the rule written once a first
// datagram left and with it written before the destination's first datagram.
// A datagram past the first may fail its first write before the rule, on the
// errno of an error the kernel queued past an earlier write's drain, and is
// written again, so the failed writes are three to five, and the rule's
// counter alone shows each datagram written once past it. The last two cases
// queue such an error past the first datagram's drain (queueLate), which the
// leaf is told of too. Root alone writes the rule (rejectUDP).
func TestDatagramTheHostsFirewallRejectsIsWrittenOnce(t *testing.T) {
	for _, c := range []struct {
		name      string
		server    netip.Prefix
		leaf      netip.Addr
		proto     uint8
		sentFirst bool
		late      bool
	}{
		{"ipv4 past a datagram that left", rigServer4, leaf4, unix.NFPROTO_IPV4, true, false},
		{"ipv6 past a datagram that left", rigServer6, leaf6, unix.NFPROTO_IPV6, true, false},
		{"ipv4 from the first datagram", rigServer4, leaf4, unix.NFPROTO_IPV4, false, false},
		{"ipv6 from the first datagram", rigServer6, leaf6, unix.NFPROTO_IPV6, false, false},
		{"ipv4 with an error queued past the first one's drain", rigServer4, leaf4, unix.NFPROTO_IPV4, false, true},
		{"ipv6 with an error queued past the first one's drain", rigServer6, leaf6, unix.NFPROTO_IPV6, false, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			onLoopback(t, c.server)
			h := newRelayHarness(t, nil)
			h.x.rt.Platform.Prepare = func(string, netip.AddrPort, syscall.RawConn) error { return nil }
			server := rigLoopbackServer(t, c.server.Addr())
			to := serverAt(server)
			conn, err := h.x.udp.connect(0, c.server.Addr(), to)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			dst := &destination{to: to, conn: conn}
			leaf := netip.AddrPortFrom(c.leaf, freeUDPPort(t, c.leaf))
			if c.sentFirst {
				first := udpDatagram(leaf, to, []byte("before the rule"))
				d, _ := readDatagram(first)
				if refused, _ := h.x.udp.send(first, d, dst, false); refused {
					t.Fatal("the first datagram was refused")
				}
				readDatagramFrom(t, server, d.payload())
			}
			rejected := rejectUDP(t, c.proto, to, 0)

			const datagrams = 3
			h.drainLaid()
			notOurs := h.count(false, reasonNotOurs)
			failures := countFailures(t, h, asQueued)
			for i := range datagrams {
				next := udpDatagram(leaf, to, []byte{byte('a' + i)})
				dn, _ := readDatagram(next)
				if refused, closed := h.x.udp.send(next, dn, dst, false); !refused || closed {
					t.Errorf("the send the firewall rejected reported refused %t closed %t, want refused", refused, closed)
				}
				time.Sleep(stackSettle)
				if c.late && i == 0 {
					queueLate(t, conn, to)
				}
			}
			errs, least := datagrams, datagrams
			if c.late {
				errs, least = datagrams+1, datagrams+1
			}
			if past := rejected(); past != datagrams || *failures < least || *failures > 2*datagrams-1 {
				t.Errorf("%d datagrams took %d writes past the rule and %d failed writes, want %d past the rule and %d to %d failed", datagrams, past, *failures, datagrams, least, 2*datagrams-1)
			}
			if unsent, pending := h.count(false, reasonUnsent), h.count(false, reasonPending); unsent != datagrams || pending != 0 {
				t.Errorf("counted %d datagrams unsent and %d failed by pending errors, want %d and 0", unsent, pending, datagrams)
			}
			if told := len(relayedErrors(h, dst, errs)); told != errs {
				t.Errorf("the leaf was told of %d errors, want the %d the rejected writes raised and any queued late", told, errs)
			}
			if got := h.count(false, reasonNotOurs) - notOurs; got != 0 {
				t.Errorf("counted %d of the rejects' errors as no flow of the exit's, want none", got)
			}
		})
	}
}

// The error the host's firewall raises about a datagram it refused reaches
// the leaf quoting that datagram's own UDP length, the IP length that
// follows and its whole payload, where its socket sent a datagram of another
// length: one of UDP length 108, which the rule rejects, refused past one of
// 14 that left, and in the other order refused before it, in both families.
// Linux's queue hands the refused datagram's payload and no UDP header. Root
// alone writes the rule (rejectUDP).
func TestRefusedDatagramsErrorQuotesItsOwnLength(t *testing.T) {
	for _, c := range []struct {
		name      string
		server    netip.Prefix
		leaf      netip.Addr
		proto     uint8
		sentFirst bool
	}{
		{"ipv4 refused past a shorter datagram that left", rigServer4, leaf4, unix.NFPROTO_IPV4, true},
		{"ipv6 refused past a shorter datagram that left", rigServer6, leaf6, unix.NFPROTO_IPV6, true},
		{"ipv4 refused before a shorter datagram left", rigServer4, leaf4, unix.NFPROTO_IPV4, false},
		{"ipv6 refused before a shorter datagram left", rigServer6, leaf6, unix.NFPROTO_IPV6, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			onLoopback(t, c.server)
			h := newRelayHarness(t, nil)
			h.x.rt.Platform.Prepare = func(string, netip.AddrPort, syscall.RawConn) error { return nil }
			server := rigLoopbackServer(t, c.server.Addr())
			to := serverAt(server)
			conn, err := h.x.udp.connect(0, c.server.Addr(), to)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			dst := &destination{to: to, conn: conn}
			leaf := netip.AddrPortFrom(c.leaf, freeUDPPort(t, c.leaf))
			short, long := []byte("leaves"), bytes.Repeat([]byte{0x6c}, 100)
			rejectUDP(t, c.proto, to, uint16(8+len(long)))
			h.drainLaid()
			send := func(payload []byte, refused bool) {
				t.Helper()
				raw := udpDatagram(leaf, to, payload)
				d, _ := readDatagram(raw)
				if got, closed := h.x.udp.send(raw, d, dst, false); got != refused || closed {
					t.Fatalf("the send of %d octets of payload reported refused %t closed %t, want refused %t", len(payload), got, closed, refused)
				}
				if !refused {
					readDatagramFrom(t, server, payload)
				}
			}
			if c.sentFirst {
				send(short, false)
			}
			send(long, true)
			if !c.sentFirst {
				send(short, false)
			}
			told := relayedErrors(h, dst, 1)
			if len(told) != 1 {
				t.Fatalf("the leaf was told of %d errors, want the one the rejected write raised", len(told))
			}
			header := ipHeader(c.leaf.Is6())
			quote := quoteOf(told[0])
			if udp, ip := quotedLengths(quote, header); udp != 8+len(long) || ip != header+8+len(long) || !bytes.Equal(quote[header+8:], long) {
				t.Errorf("the error about the refused datagram quotes UDP length %d, IP length %d and %d octets of payload, want %d, %d and its %d", udp, ip, len(quote)-header-8, 8+len(long), header+8+len(long), len(long))
			}
		})
	}
}

// relayedErrors are the ICMP errors laid toward a leaf about dst's datagrams
// until want of them are laid or exitWait passes, the errors dst's socket
// queued relayed as its reader would. The host may queue its firewall's
// error after the failed write's own drain, since the error comes back
// through loopback and the kernel may take it in later, and the test's
// destination has no reader.
func relayedErrors(h *relayHarness, dst *destination, want int) [][]byte {
	var told [][]byte
	for deadline := time.Now().Add(exitWait); ; time.Sleep(time.Millisecond) {
		dst.mu.Lock()
		h.x.udp.relayErrors(dst)
		dst.mu.Unlock()
		for raw := h.laid(); raw != nil; raw = h.laid() {
			if p, ok := parse(raw); ok && (p.protocol == protoICMP || p.protocol == protoICMPv6) {
				told = append(told, raw)
			}
		}
		if len(told) >= want || !time.Now().Before(deadline) {
			return told
		}
	}
}

// queueLate sends a port unreachable about a datagram of conn, the socket
// toward to, through a raw socket, and returns once conn holds it pending:
// an error queued past a failed write's drain, as the kernel may queue a
// reject's error under load
func queueLate(t *testing.T, conn *net.UDPConn, to netip.AddrPort) {
	t.Helper()
	from := serverAt(conn)
	message := []byte{3, 3, 0, 0, 0, 0, 0, 0}
	if from.Addr().Is6() {
		message = []byte{1, 4, 0, 0, 0, 0, 0, 0}
	}
	sendICMP(t, from.Addr(), append(message, udpDatagram(from, to, []byte{'a'})...))
	for deadline := time.Now().Add(exitWait); !pendingError(conn); time.Sleep(time.Millisecond) {
		if !time.Now().Before(deadline) {
			t.Fatalf("no error pending on the socket toward %s within %s", to, exitWait)
		}
	}
}

// rejectUDP writes a rule into the host's output path that rejects as
// administratively prohibited each UDP datagram of family proto toward to,
// of UDP length length alone where length is not 0, and takes it out at the
// test's end. It returns the count of datagrams the rule rejected so far.
// The test skips where the kernel has not loaded a module the rule needs,
// which it never asks the kernel to load.
func rejectUDP(t *testing.T, proto uint8, to netip.AddrPort, length uint16) func() uint64 {
	t.Helper()
	var missing []string
	for _, module := range []string{"nf_tables", "nft_reject_inet", "nf_reject_ipv4", "nf_reject_ipv6"} {
		if _, err := os.Stat("/sys/module/" + module); err != nil {
			missing = append(missing, module)
		}
	}
	if len(missing) != 0 {
		t.Skipf("the kernel has not loaded %v, which the reject rule needs", missing)
	}
	nft, err := nftables.Dial()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nft.Close() })
	chain := nftables.Chain{Table: "reject", Name: "output", Type: "filter", Hook: unix.NF_INET_LOCAL_OUT}
	match := slices.Concat(
		nftables.NFProto(proto),
		nftables.DestinationPrefix(netip.PrefixFrom(to.Addr(), to.Addr().BitLen())),
		nftables.MetaCompareValue(unix.NFT_META_L4PROTO, unix.NFT_CMP_EQ, []byte{unix.IPPROTO_UDP}),
		[][]byte{nftables.TransportLoad(2, 2), nftables.Expression("cmp", nftables.Compare(unix.NFT_CMP_EQ, binary.BigEndian.AppendUint16(nil, to.Port())))},
	)
	if length != 0 {
		match = append(match, nftables.TransportLoad(4, 2), nftables.Expression("cmp", nftables.Compare(unix.NFT_CMP_EQ, binary.BigEndian.AppendUint16(nil, length))))
	}
	rule, err := chain.Rule(unix.NFPROTO_INET, "reject the server's port", append(match, nftables.Expression("counter", nil), nftables.RejectICMPX(unix.NFT_REJECT_ICMPX_ADMIN_PROHIBITED)))
	if err != nil {
		t.Fatal(err)
	}
	if err := nft.Batch([]nftables.Request{nftables.NewTable(unix.NFPROTO_INET, chain.Table), chain.Create(unix.NFPROTO_INET), rule}); err != nil {
		t.Fatalf("write the reject rule: %v", err)
	}
	t.Cleanup(func() { _ = nft.Batch([]nftables.Request{nftables.DeleteTable(unix.NFPROTO_INET, chain.Table)}) })
	return func() uint64 {
		t.Helper()
		rules, err := nftables.TableRules(nft, unix.NFPROTO_INET, chain.Table)
		if err != nil || len(rules) != 1 {
			t.Fatalf("read the reject rule back: %d rules, %v", len(rules), err)
		}
		return rules[0].Packets
	}
}

// A reply past the largest receive window, an IPv6 jumbogram (RFC 2675) that
// a link of an MTU past 65575 bytes carries and Linux hands a UDP socket, is
// dropped and counted as truncated, and the destination reads on: the
// server's next reply reaches the leaf. The jumbogram is laid on loopback
// through a packet socket, since the host's routes cap what its IP sockets
// send at 65575 bytes.
func TestJumbogramReplyIsDroppedAsTruncated(t *testing.T) {
	onLoopback(t, rigServer6)
	h := newRelayHarness(t, nil)
	h.x.rt.Platform.Prepare = func(string, netip.AddrPort, syscall.RawConn) error { return nil }
	server := rigLoopbackServer(t, rigServer6.Addr())
	leaf := netip.AddrPortFrom(leaf6, freeUDPPort(t, leaf6))
	h.x.udp.take(udpDatagram(leaf, serverAt(server), []byte("opens")), false)
	outside := readDatagramFrom(t, server, []byte("opens"))
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}

	// a hop-by-hop header holding the jumbo payload option ahead of a UDP
	// datagram whose length field is 0 (RFC 2675 section 4), whose payload
	// fills the largest receive window
	payload := bytes.Repeat([]byte{0x6a}, datagramBuffer)
	udp := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:2], serverAt(server).Port())
	binary.BigEndian.PutUint16(udp[2:4], outside.Port())
	copy(udp[8:], payload)
	binary.BigEndian.PutUint16(udp[6:8], fold(sum(pseudo(serverAt(server).Addr(), outside.Addr(), protoUDP, len(udp)), udp)))
	jumbo := make([]byte, 40+8, 40+8+len(udp))
	jumbo[0], jumbo[6], jumbo[7] = 6<<4, 0, 64
	src, dst := serverAt(server).Addr().As16(), outside.Addr().As16()
	copy(jumbo[8:24], src[:])
	copy(jumbo[24:40], dst[:])
	jumbo[40], jumbo[41], jumbo[42], jumbo[43] = protoUDP, 0, 0xc2, 4
	binary.BigEndian.PutUint32(jumbo[44:48], uint32(8+len(udp)))
	jumbo = append(jumbo, udp...)
	if err := netnstest.SetLinkMTU(lo.Index, len(jumbo)); err != nil {
		t.Fatalf("widen loopback to %d: %v", len(jumbo), err)
	}
	t.Cleanup(func() {
		if err := netnstest.SetLinkMTU(lo.Index, lo.MTU); err != nil {
			t.Errorf("restore loopback's MTU of %d: %v", lo.MTU, err)
		}
	})
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_IPV6)))
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	truncated := h.count(false, reasonTruncated)
	if err := unix.Sendto(fd, jumbo, 0, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_IPV6), Ifindex: lo.Index}); err != nil {
		t.Fatalf("send the jumbogram of %d bytes: %v", len(jumbo), err)
	}
	for start := time.Now(); h.count(false, reasonTruncated) == truncated; time.Sleep(time.Millisecond) {
		if time.Since(start) > exitWait {
			t.Fatalf("no jumbogram counted truncated within %s", exitWait)
		}
	}
	reply := []byte("after the jumbogram")
	if _, err := server.WriteToUDPAddrPort(reply, outside); err != nil {
		t.Fatal(err)
	}
	h.waitLaid(t, "reply after the jumbogram", func(raw []byte) bool { return isDatagram(raw, serverAt(server), leaf, reply) })
}

// tooBig sends to a Fragmentation Needed or a Packet Too Big at mtu quoting
// datagram, as a router on the path sends it
func tooBig(t *testing.T, to netip.Addr, mtu int, datagram []byte) {
	t.Helper()
	message := append([]byte{3, 4, 0, 0, 0, 0, 0, 0}, datagram[:20+8]...)
	binary.BigEndian.PutUint16(message[6:8], uint16(mtu))
	if to.Is6() {
		message = append([]byte{2, 0, 0, 0, 0, 0, 0, 0}, datagram[:40+8]...)
		binary.BigEndian.PutUint32(message[4:8], uint32(mtu))
	}
	sendICMP(t, to, message)
}

// htons is v in network byte order as a packet socket's protocol field holds
// it in memory
func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}

// pendingError is whether conn's socket shows an error, pending or queued,
// read without taking it
func pendingError(conn *net.UDPConn) bool {
	var pending bool
	_ = onSocket(conn, func(fd int) error {
		fds := []unix.PollFd{{Fd: int32(fd)}}
		n, err := unix.Poll(fds, 0)
		pending = err == nil && n == 1 && fds[0].Revents&unix.POLLERR != 0
		return nil
	})
	return pending
}

// The worst mix of flows, each a UDP mapping's first destination holding the
// mapping's receiving socket and its own connected one, keeps the exit's
// descriptors within the process's limit less the node's daemonFiles: Within
// holds Flows to what those descriptors hold at flowFiles each, and the flow
// past it is refused for the total
func TestWorstMixOfFlowsKeepsTheNodesDescriptors(t *testing.T) {
	const files = daemonFiles + 2*24
	limits, err := Within(Memory{GoLimit: 32 << 20}, files)
	if err != nil {
		t.Fatal(err)
	}
	h := newRelayHarness(t, func(rt *Runtime, _ *egress.Egress) { rt.Limits = limits })
	server := loopbackServer(t, netip.MustParseAddr("127.0.0.1"))
	before := openFiles(t)
	for i := range limits.Flows + 6 {
		leaf := netip.AddrPortFrom(leaf4, uint16(40000+i))
		h.x.udp.take(udpDatagram(leaf, serverAt(server), []byte("one destination")), false)
	}
	if held := openFiles(t) - before; held > files-daemonFiles {
		t.Errorf("%d flows hold %d descriptors, past the %d the process's limit leaves past the node's %d", limits.Flows, held, files-daemonFiles, daemonFiles)
	}
	if got := h.count(true, reasonTotal); got != 6 {
		t.Errorf("refused %d flows for the total, want the 6 past Flows %d", got, limits.Flows)
	}
}

// The exit's stop ends every mapping and gives back its flows, and once the
// exit is enabled again a datagram opens a mapping anew
func TestWithdrawalEndsEveryMapping(t *testing.T) {
	r := newLeafRig(t, func(rt Runtime) (*Exit, error) { return New(exitConfig(), rt) })
	server := r.server(t, rigServer4.Addr())
	leaf := r.leafSocket(t, netip.AddrPortFrom(rigLeaf4.Addr(), 0), nil)
	if _, err := leaf.WriteToUDPAddrPort([]byte("before"), serverAt(server)); err != nil {
		t.Fatal(err)
	}
	readDatagramFrom(t, server, []byte("before"))
	r.exit.SetEnabled(false)
	waitFor(t, "every mapping ended", func() bool {
		r.exit.udp.mu.RLock()
		defer r.exit.udp.mu.RUnlock()
		return len(r.exit.udp.mappings) == 0 && len(r.exit.udp.ports) == 0
	})
	r.exit.flows.mu.Lock()
	open := r.exit.flows.open
	r.exit.flows.mu.Unlock()
	if open != 0 {
		t.Errorf("%d flows held once the exit stopped", open)
	}
	r.exit.SetEnabled(true)
	waitFor(t, "the exit taking again", r.exit.taking.Load)
	if _, err := leaf.WriteToUDPAddrPort([]byte("after"), serverAt(server)); err != nil {
		t.Fatal(err)
	}
	readDatagramFrom(t, server, []byte("after"))
}

// A leaf's port below 1024 that another socket holds maps to a port below
// 1024, RFC 4787 REQ-3 (a): the first of the lowPortSearch ports below 1024
// after it that the host holds free, 1023 followed by 1, and one the host
// gives once every one of them is held
func TestMappingKeepsALowPortLowWithinItsSearch(t *testing.T) {
	claim(t)
	const leafPort = 1020
	next := func(port uint16) uint16 {
		if port == 1023 {
			return 1
		}
		return port + 1
	}
	for _, c := range []struct {
		name string
		// held is how many ports from the leaf's on other sockets hold
		held int
		low  bool
	}{
		{"the last port of the search free", lowPortSearch, true},
		{"every port of the search held", lowPortSearch + 1, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			port := uint16(leafPort)
			for range c.held {
				holder, err := net.ListenUDP("udp4", &net.UDPAddr{Port: int(port)})
				if err != nil {
					t.Fatalf("hold port %d: %v", port, err)
				}
				t.Cleanup(func() { _ = holder.Close() })
				port = next(port)
			}
			p := &fakePlatform{}
			x := &Exit{rt: Runtime{Platform: p.platform()}}
			x.rt.Platform.Prepare = func(string, netip.AddrPort, syscall.RawConn) error { return nil }
			conn, err := newUDPRelay(x).listen(netip.AddrPortFrom(rigLeaf4.Addr(), leafPort), netip.IPv4Unspecified())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			got := uint16(conn.LocalAddr().(*net.UDPAddr).Port)
			switch {
			case c.low && got != port:
				t.Errorf("the mapping of port %d took %d with %d ports held, want %d, the first free one", leafPort, got, c.held, port)
			case !c.low && got < 1024:
				t.Errorf("the mapping of port %d took %d with every port of its search held, want one the host gives", leafPort, got)
			}
		})
	}
}

// server is a UDP socket at address, on this namespace's loopback
func (r *leafRig) server(t *testing.T, address netip.Addr) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP(udpNetwork(address), net.UDPAddrFromAddrPort(netip.AddrPortFrom(address, 0)))
	if err != nil {
		t.Fatalf("a server at %s: %v", address, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// leafSocket is a UDP socket of the leaf's at local, opened in the leaf's
// namespace, set run on its descriptor before it binds where given
func (r *leafRig) leafSocket(t *testing.T, local netip.AddrPort, set func(fd int) error) *net.UDPConn {
	t.Helper()
	var conn *net.UDPConn
	err := r.leaf.Do(func() error {
		var config net.ListenConfig
		if set != nil {
			config.Control = func(_, _ string, raw syscall.RawConn) error {
				var setErr error
				if err := raw.Control(func(fd uintptr) { setErr = set(int(fd)) }); err != nil {
					return err
				}
				return setErr
			}
		}
		pc, err := config.ListenPacket(context.Background(), udpNetwork(local.Addr()), local.String())
		if err != nil {
			return err
		}
		conn = pc.(*net.UDPConn)
		return nil
	})
	if err != nil {
		t.Fatalf("a leaf socket at %s: %v", local, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// readNext is the next datagram conn reads within exitWait, and where it came
// from
func readNext(t *testing.T, conn *net.UDPConn) ([]byte, netip.AddrPort) {
	t.Helper()
	buf := make([]byte, 1<<16)
	_ = conn.SetReadDeadline(time.Now().Add(exitWait))
	n, from, err := conn.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatalf("%s read no datagram: %v", serverAt(conn), err)
	}
	return buf[:n], netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
}

// With the host holding two addresses of one family, two leaves whose
// mappings leave from one address each, under auto by their routes or under
// two classes, hairpin to each other from each one's own mapping's address and
// port (RFC 4787 REQ-9 (a)), the sender holding none on the address its
// datagram went to, and each passes the other's filter once both have sent to
// the address the other leaves from: the first datagram of the punch is
// filtered, and every later one each way reaches its leaf from the other
// mapping's address, as from outside. A leaf's error about one reaches the
// sender from the address the sender sent to, the target's (RFC 5508 REQ-7
// (a)), and one quoting the sender's port at the target's address, which the
// sender never leaves from, is dropped.
func TestHairpinComesFromTheSendersOwnAddress(t *testing.T) {
	for _, classes := range []bool{false, true} {
		name := map[bool]string{false: "auto", true: "two classes"}[classes]
		t.Run(name, func(t *testing.T) {
			h, addresses := twoAddressesHeld(t)
			listener := netip.AddrPortFrom(leaf4, freeUDPPort(t, leaf4))
			sender := netip.AddrPortFrom(other4, freeUDPPort(t, other4))
			if classes {
				translate := append(classed(addresses[0].Addr()).Translate, classed(addresses[1].Addr()).Translate...)
				translate[0].From.Prefix, translate[1].From.Prefix = netip.PrefixFrom(listener.Addr(), 32), netip.PrefixFrom(sender.Addr(), 32)
				h.x.cfg.Translate = translate
			}
			toListener, toSender := openFrom(t, h, listener, addresses[0]), openFrom(t, h, sender, addresses[1])
			laid := punch(t, h, sender, toSender, listener, toListener)
			h.x.handle(h.lane, leafRefusal(listener.Addr(), toSender.Addr(), 3, 3, laid))
			out := h.waitLaid(t, "the listener's error to the sender", func(raw []byte) bool {
				p, ok := parse(raw)
				return ok && p.protocol == protoICMP && p.dst == sender.Addr()
			})
			checkServerError(t, out, toListener, sender, 3, 3, []byte("goes through"))
			forger := netip.AddrPortFrom(leaf4.Next(), freeUDPPort(t, leaf4))
			openFrom(t, h, forger, addresses[0])
			before := h.count(false, reasonLeafErrorUnmapped)
			quoted := udpDatagram(netip.AddrPortFrom(toListener.Addr(), toSender.Port()), forger, []byte("never sent"))
			h.x.handle(h.lane, leafRefusal(forger.Addr(), toListener.Addr(), 3, 3, quoted))
			if got := h.count(false, reasonLeafErrorUnmapped) - before; got != 1 {
				t.Errorf("dropped %d errors as about no datagram a mapping delivered, want the one quoting the sender's port at %s, which it never leaves from", got, toListener.Addr())
			}
		})
	}
}

// punch has sender and listener, which their peers know at toSender and
// toListener, hairpin to each other through the lane: the sender's first
// datagram is filtered, the listener's answer reaches the sender from
// toListener, and the sender's next reaches the listener from toSender, which
// punch returns as laid
func punch(t *testing.T, h *relayHarness, sender, toSender, listener, toListener netip.AddrPort) []byte {
	t.Helper()
	filtered := h.count(false, reasonFiltered)
	h.x.handle(h.lane, udpDatagram(sender, toListener, []byte("punches")))
	if got := h.count(false, reasonFiltered) - filtered; got != 1 {
		t.Fatalf("filtered %d hairpinned datagrams, want the first of the punch", got)
	}
	h.x.handle(h.lane, udpDatagram(listener, toSender, []byte("answers")))
	h.waitLaid(t, "the listener's datagram, from "+toListener.String(), func(raw []byte) bool {
		return isDatagram(raw, toListener, sender, []byte("answers"))
	})
	h.x.handle(h.lane, udpDatagram(sender, toListener, []byte("goes through")))
	return h.waitLaid(t, "the sender's datagram, from "+toSender.String(), func(raw []byte) bool {
		return isDatagram(raw, toSender, listener, []byte("goes through"))
	})
}

// twoAddressesHeld is a relay harness in this namespace, which holds the two
// prefixes it returns on loopback and readies every socket. Loopback takes
// each prefix as local, so a socket toward a server inside one leaves from
// that prefix's address.
func twoAddressesHeld(t *testing.T) (*relayHarness, [2]netip.Prefix) {
	t.Helper()
	prefixes := twoPrefixes
	onLoopback(t, prefixes[:]...)
	// New starts no goroutine, so nothing reads the platform while it changes
	h := newRelayHarness(t, nil)
	holdOnly(&h.x.rt, prefixes[0].Addr(), prefixes[1].Addr())
	h.x.rt.Platform.Prepare = func(string, netip.AddrPort, syscall.RawConn) error { return nil }
	return h, prefixes
}

// onLoopback claims this namespace, gives loopback the rig's servers as a leaf
// rig does, once in the process, so that no rig built later finds one of them
// there before it, and gives loopback each of prefixes it does not hold yet
func onLoopback(t *testing.T, prefixes ...netip.Prefix) {
	t.Helper()
	claim(t)
	serversOnce.Do(func() { serversErr = addServers() })
	if serversErr != nil {
		t.Fatalf("address the servers on loopback: %v", serversErr)
	}
	if err := netnstest.BringUp("lo"); err != nil {
		t.Fatal(err)
	}
	netlink, err := netnstest.OpenNetlink()
	if err != nil {
		t.Fatal(err)
	}
	defer netlink.Close()
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	for _, prefix := range prefixes {
		if err := netlink.AddAddress(lo.Index, prefix); err != nil && err != unix.EEXIST {
			t.Fatal(err)
		}
	}
}

// rigLoopbackServer is a UDP socket at address on the loopback the test
// brought up in its own namespace (onLoopback), and fails the test, never
// skips it, where that loopback carries no datagram to it within exitWait.
// An address just added may carry nothing for a moment, so the socket sends
// itself a new probe every 10 ms until one arrives, and is handed over once
// it read the last probe it sent, the probes before it read or lost.
func rigLoopbackServer(t *testing.T, address netip.Addr) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP(udpNetwork(address), net.UDPAddrFromAddrPort(netip.AddrPortFrom(address, 0)))
	if err != nil {
		t.Fatalf("a server at %s: %v", address, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	buf := make([]byte, 64)
	for i, deadline := 0, time.Now().Add(exitWait); ; i++ {
		probe := fmt.Appendf(nil, "loopback probe %d", i)
		_, err := conn.WriteToUDPAddrPort(probe, serverAt(conn))
		if err != nil {
			time.Sleep(10 * time.Millisecond)
		}
		for err == nil {
			_ = conn.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
			var n int
			if n, err = conn.Read(buf); err == nil && bytes.Equal(buf[:n], probe) {
				_ = conn.SetReadDeadline(time.Time{})
				return conn
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the loopback of %s, which the test brought up, carries no datagram within %v: %v", address, exitWait, err)
		}
	}
}

// openFrom opens leaf's mapping toward a server inside prefix and is the
// address and port it left from, failing t where that is not prefix's address
func openFrom(t *testing.T, h *relayHarness, leaf netip.AddrPort, prefix netip.Prefix) netip.AddrPort {
	t.Helper()
	server, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(prefix.Addr().Next().Next(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	h.x.udp.take(udpDatagram(leaf, serverAt(server), []byte("opens a mapping")), false)
	outside := readDatagramFrom(t, server, []byte("opens a mapping"))
	if outside.Addr() != prefix.Addr() {
		t.Fatalf("the mapping of %s left from %s, want %s", leaf, outside, prefix.Addr())
	}
	return outside
}

// Under auto, with the host's routes toward two servers leaving by two links,
// each holding an address of its own, a leaf's datagram toward each server
// leaves by that server's link from the link's own address at the leaf's
// port, as the far end of each link reads it there, under a mapping on each
// address. Neither mapping ends at the other's destination, and each server's
// reply reaches the leaf through its own.
func TestMappingUnderAutoLeavesEachLinkFromItsOwnAddress(t *testing.T) {
	claim(t)
	far := netnstest.StartThread(t)
	links := []struct {
		name, peer string
		here, far  netip.Prefix
	}{
		{"a0", "b0", netip.MustParsePrefix("203.0.113.1/26"), netip.MustParsePrefix("203.0.113.2/26")},
		{"a1", "b1", netip.MustParsePrefix("203.0.113.65/26"), netip.MustParsePrefix("203.0.113.66/26")},
	}
	servers := make([]*net.UDPConn, len(links))
	for i, link := range links {
		servers[i] = veth(t, far, link.name, link.peer, []netip.Prefix{link.here}, link.far, 1)[0]
	}
	h := newRelayHarness(t, nil)
	holdOnly(&h.x.rt, links[0].here.Addr(), links[1].here.Addr())
	h.x.rt.Platform.Prepare = func(string, netip.AddrPort, syscall.RawConn) error { return nil }
	leaf := netip.AddrPortFrom(leaf4, freeUDPPortOn(t, links[0].here.Addr(), links[1].here.Addr()))
	for i, server := range servers {
		payload := []byte("to the server beyond " + links[i].name)
		h.x.udp.take(udpDatagram(leaf, serverAt(server), payload), false)
		if got, want := readDatagramFrom(t, server, payload), netip.AddrPortFrom(links[i].here.Addr(), leaf.Port()); got != want {
			t.Errorf("%s carried the leaf's datagram from %s, want %s, its own address at the leaf's port", links[i].name, got, want)
		}
	}
	if mappings := h.mappingsOf(leaf); len(mappings) != len(links) {
		t.Errorf("%s holds %d mappings, want one on each link's address", leaf, len(mappings))
	}
	for i, server := range servers {
		payload := []byte("from the server beyond " + links[i].name)
		if _, err := server.WriteToUDPAddrPort(payload, netip.AddrPortFrom(links[i].here.Addr(), leaf.Port())); err != nil {
			t.Fatal(err)
		}
		h.waitLaid(t, "reply from beyond "+links[i].name, func(raw []byte) bool { return isDatagram(raw, serverAt(server), leaf, payload) })
	}
}

// veth makes the veth pair of name here, holding each of addresses, and peer in
// far's namespace, holding there, and is count servers at there's address on
// peer
func veth(t *testing.T, far *netnstest.Thread, name, peer string, addresses []netip.Prefix, there netip.Prefix, count int) []*net.UDPConn {
	t.Helper()
	here, err := netnstest.OpenNetlink()
	if err != nil {
		t.Fatal(err)
	}
	defer here.Close()
	if err := here.AddVeth(name, peer, 0, far.Path); err != nil {
		t.Fatalf("a veth pair %s and %s: %v", name, peer, err)
	}
	t.Cleanup(func() { _ = netnstest.DelLink(name) })
	if err := here.AddAddresses(name, addresses...); err != nil {
		t.Fatal(err)
	}
	servers := make([]*net.UDPConn, 0, count)
	t.Cleanup(func() {
		for _, server := range servers {
			_ = server.Close()
		}
	})
	if err := far.Do(func() error {
		netlink, err := netnstest.OpenNetlink()
		if err != nil {
			return err
		}
		defer netlink.Close()
		if err := netlink.AddAddresses(peer, there); err != nil {
			return err
		}
		for range count {
			server, err := onLink(there.Addr(), peer)
			if err != nil {
				return err
			}
			servers = append(servers, server)
		}
		return nil
	}); err != nil {
		t.Fatalf("servers on %s at the far end of %s: %v", peer, name, err)
	}
	return servers
}

// onLink is a UDP socket at address that reads only what arrives on link
func onLink(address netip.Addr, link string) (*net.UDPConn, error) {
	conn, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(address, 0)))
	if err != nil {
		return nil, err
	}
	if err := onSocket(conn, func(fd int) error { return unix.BindToDevice(fd, link) }); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// goneRig is a veth link holding gone and kept, whose far end holds an address
// inside both, so the host's route toward it leaves from gone by the longer
// prefix until gone is taken off, and one inside kept alone, toward which the
// route leaves from kept. The harness's platform holds what this namespace
// holds.
type goneRig struct {
	h            *relayHarness
	gone, kept   netip.Prefix
	both, keptBy *net.UDPConn
	leaf         netip.AddrPort
}

func newGoneRig(t *testing.T) *goneRig {
	t.Helper()
	claim(t)
	far := netnstest.StartThread(t)
	r := &goneRig{gone: netip.MustParsePrefix("203.0.113.1/26"), kept: netip.MustParsePrefix("203.0.113.5/25")}
	r.both = veth(t, far, "g0", "h0", []netip.Prefix{r.gone, r.kept}, netip.MustParsePrefix("203.0.113.2/25"), 1)[0]
	alone := netip.MustParsePrefix("203.0.113.70/25")
	if err := far.Do(func() error {
		netlink, err := netnstest.OpenNetlink()
		if err != nil {
			return err
		}
		defer netlink.Close()
		if err := netlink.AddAddresses("h0", alone); err != nil {
			return err
		}
		r.keptBy, err = onLink(alone.Addr(), "h0")
		return err
	}); err != nil {
		t.Fatalf("a server at %s on h0: %v", alone.Addr(), err)
	}
	t.Cleanup(func() { _ = r.keptBy.Close() })
	r.h = newRelayHarness(t, nil)
	r.h.x.rt.Platform.Held = namespaceHolds
	r.h.x.rt.Platform.Prepare = func(string, netip.AddrPort, syscall.RawConn) error { return nil }
	r.leaf = netip.AddrPortFrom(leaf4, freeUDPPortOn(t, r.gone.Addr(), r.kept.Addr()))
	return r
}

// send has the leaf send payload to server, and is where server read it from
func (r *goneRig) send(t *testing.T, server *net.UDPConn, payload string) netip.AddrPort {
	t.Helper()
	r.h.x.udp.take(udpDatagram(r.leaf, serverAt(server), []byte(payload)), false)
	return readDatagramFrom(t, server, []byte(payload))
}

// takeOff takes gone off the link
func (r *goneRig) takeOff(t *testing.T) {
	t.Helper()
	netlink, err := netnstest.OpenNetlink()
	if err != nil {
		t.Fatal(err)
	}
	defer netlink.Close()
	link, err := net.InterfaceByName("g0")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.DelAddress(link.Index, r.gone); err != nil {
		t.Fatalf("take %s off g0: %v", r.gone, err)
	}
}

// Under auto a mapping whose address the host gave up ends at the first
// datagram its socket then refuses, which is counted, and the leaf's mapping
// on the address the host still holds lives on with its destination. The next
// datagram toward the same server leaves from that address under that
// mapping, as the route read again picks it, and holds the one flow beside
// the mapping's first.
func TestMappingWhoseAddressTheHostGaveUpEndsAtItsNextSendAlone(t *testing.T) {
	r := newGoneRig(t)
	if got, want := r.send(t, r.keptBy, "to kept"), netip.AddrPortFrom(r.kept.Addr(), r.leaf.Port()); got != want {
		t.Fatalf("the server beyond %s alone read the datagram from %s, want %s", r.kept, got, want)
	}
	if got := r.send(t, r.both, "to both"); got.Addr() != r.gone.Addr() {
		t.Fatalf("the server inside both prefixes read the datagram from %s, want %s", got, r.gone.Addr())
	}
	mappings := r.h.mappingsOf(r.leaf)
	if len(mappings) != 2 {
		t.Fatalf("%s holds %d mappings, want one on each address", r.leaf, len(mappings))
	}
	kept, gone := mappings[0], mappings[1]
	r.takeOff(t)
	r.h.x.udp.take(udpDatagram(r.leaf, serverAt(r.both), []byte("refused")), false)
	if got := r.h.count(false, reasonUnsent); got != 1 {
		t.Errorf("counted %d datagrams unsent, want the one the socket on %s refused", got, r.gone.Addr())
	}
	if !ended(gone) || !slices.Equal(r.h.mappingsOf(r.leaf), []*mapping{kept}) {
		t.Fatalf("the mapping on %s ended %t, and %s holds %v, want it ended and the one on %s alone", r.gone.Addr(), ended(gone), r.leaf, r.h.mappingsOf(r.leaf), r.kept.Addr())
	}
	if got, want := r.send(t, r.both, "after"), kept.external(); got != want {
		t.Errorf("the server inside both prefixes read the next datagram from %s, want %s, the mapping on the address the route picks now", got, want)
	}
	kept.mu.RLock()
	held := len(kept.destinations)
	kept.mu.RUnlock()
	if !slices.Equal(r.h.mappingsOf(r.leaf), []*mapping{kept}) || held != 2 {
		t.Errorf("%s holds %v with %d destinations on %s, want the mapping on %s alone with both", r.leaf, r.h.mappingsOf(r.leaf), held, r.kept.Addr(), r.kept.Addr())
	}
	r.h.x.flows.mu.Lock()
	defer r.h.x.flows.mu.Unlock()
	if open := r.h.x.flows.open; open != 2 {
		t.Errorf("%d flows held, want one for each destination", open)
	}
}

// Under auto a mapping whose send the host refuses while it still holds the
// mapping's address, the route toward the server made unreachable, lives on:
// the datagram is counted unsent, and the mapping keeps its destination
func TestMappingWhoseAddressTheHostHoldsLivesPastARefusedSend(t *testing.T) {
	r := newGoneRig(t)
	if got := r.send(t, r.both, "left"); got.Addr() != r.gone.Addr() {
		t.Fatalf("the server read the datagram from %s, want %s", got, r.gone.Addr())
	}
	m := r.h.mappingsOf(r.leaf)[0]
	unreachable(t, netip.PrefixFrom(serverAt(r.both).Addr(), 32))
	r.h.x.udp.take(udpDatagram(r.leaf, serverAt(r.both), []byte("refused")), false)
	if got := r.h.count(false, reasonUnsent); got != 1 {
		t.Errorf("counted %d datagrams unsent, want the one the unreachable route refused", got)
	}
	if ended(m) || !slices.Equal(r.h.mappingsOf(r.leaf), []*mapping{m}) {
		t.Errorf("the mapping on %s, which the host holds, ended %t, want it kept", r.gone.Addr(), ended(m))
	}
}

// unreachable routes to as unreachable in the main table until the test ends,
// so a send toward it fails while the host keeps every address it holds
func unreachable(t *testing.T, to netip.Prefix) {
	t.Helper()
	netlink, err := netnstest.OpenNetlink()
	if err != nil {
		t.Fatal(err)
	}
	defer netlink.Close()
	header := []byte{unix.AF_INET, byte(to.Bits()), 0, 0, unix.RT_TABLE_MAIN, unix.RTPROT_BOOT, unix.RT_SCOPE_UNIVERSE, unix.RTN_UNREACHABLE, 0, 0, 0, 0}
	route := slices.Concat(header, netnstest.Attr(unix.RTA_DST, to.Addr().AsSlice()))
	if err := netlink.Request(unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_EXCL, route); err != nil {
		t.Fatalf("route %s unreachable: %v", to, err)
	}
	t.Cleanup(func() {
		netlink, err := netnstest.OpenNetlink()
		if err != nil {
			t.Error(err)
			return
		}
		defer netlink.Close()
		if err := netlink.Request(unix.RTM_DELROUTE, 0, route); err != nil {
			t.Errorf("remove the unreachable route to %s: %v", to, err)
		}
	})
}

// Under a class naming an address the host then gives up, a leaf that keeps
// sending sees each datagram counted unsent and its mapping end by its timer,
// timed from the last datagram that left, as a mapping with no datagram out
func TestMappingOnAClassAddressTheHostGaveUpEndsByItsTimer(t *testing.T) {
	r := newGoneRig(t)
	r.h.x.cfg.Translate = classed(r.gone.Addr()).Translate
	if got := r.send(t, r.both, "left"); got.Addr() != r.gone.Addr() {
		t.Fatalf("the server read the datagram from %s, want %s, the class's", got, r.gone.Addr())
	}
	m := r.h.mappingsOf(r.leaf)[0]
	r.takeOff(t)
	const tries = 4
	for i := range tries {
		r.h.advance(time.Minute)
		r.h.x.udp.take(udpDatagram(r.leaf, serverAt(r.both), []byte("refused")), false)
		if ended(m) {
			t.Fatalf("the mapping ended %d minutes after the last datagram that left, before its timer", i+1)
		}
	}
	if got := r.h.count(false, reasonUnsent); got != tries {
		t.Errorf("counted %d datagrams unsent, want each of the %d refused", got, tries)
	}
	r.h.advance(mappingTimeout - tries*time.Minute + time.Second)
	if !ended(m) {
		t.Errorf("the mapping lives %s past the last datagram that left", mappingTimeout+time.Second)
	}
}

// TestMappingsAreTheModels' property with servers whose routes pick two
// addresses of loopback's, so a leaf's destinations take a mapping on each
func TestMappingsAreTheModelsAcrossTwoRoutesAddresses(t *testing.T) {
	onLoopback(t, twoPrefixes[:]...)
	first, second := twoPrefixes[0].Addr().Next().Next(), twoPrefixes[1].Addr().Next().Next()
	mappingsAreTheModels(t, []netip.Addr{first, first.Next(), second}, second.Next(), func(rt *Runtime) {
		holdOnly(rt, twoPrefixes[0].Addr(), twoPrefixes[1].Addr())
		rt.Platform.Prepare = func(string, netip.AddrPort, syscall.RawConn) error { return nil }
	})
}

// sendICMP sends message, an ICMP or ICMPv6 message, to to through a raw
// socket of to's family, its checksum written here for ICMP and by the kernel
// for ICMPv6
func sendICMP(t *testing.T, to netip.Addr, message []byte) {
	t.Helper()
	family, protocol := unix.AF_INET6, unix.IPPROTO_ICMPV6
	var at unix.Sockaddr = &unix.SockaddrInet6{Addr: to.As16()}
	if to.Is4() {
		family, protocol, at = unix.AF_INET, unix.IPPROTO_ICMP, &unix.SockaddrInet4{Addr: to.As4()}
		message[2], message[3] = 0, 0
		checksum := fold(sum(0, message))
		message[2], message[3] = byte(checksum>>8), byte(checksum)
	}
	fd, err := unix.Socket(family, unix.SOCK_RAW|unix.SOCK_CLOEXEC, protocol)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.Sendto(fd, message, 0, at); err != nil {
		t.Fatalf("send an ICMP message toward %s: %v", to, err)
	}
}

// A datagram with DF past its path, whose socket the host refuses with
// EMSGSIZE for its size alone, is written once, answered too big at the
// path's MTU and recorded with its length: with the queue as the kernel
// leaves it, and with the queue answering that an error came with the
// failure, as a too big queued ahead of the datagram would, since the
// datagram's size past the path still holds
func TestDatagramPastThePathIsWrittenOnce(t *testing.T) {
	onLoopback(t, rigServer4)
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	server := rigLoopbackServer(t, rigServer4.Addr())
	if err := netnstest.SetLinkMTU(lo.Index, pathMTU); err != nil {
		t.Fatalf("narrow loopback to %d: %v", pathMTU, err)
	}
	t.Cleanup(func() {
		if err := netnstest.SetLinkMTU(lo.Index, lo.MTU); err != nil {
			t.Errorf("restore loopback's MTU of %d: %v", lo.MTU, err)
		}
	})
	h := newRelayHarness(t, nil)
	h.x.rt.Platform.Prepare = func(string, netip.AddrPort, syscall.RawConn) error { return nil }
	to := serverAt(server)
	for _, c := range []struct {
		name    string
		drained func(queued bool) bool
	}{
		{"queue as the kernel leaves it", asQueued},
		{"queue answering an error came", func(bool) bool { return true }},
	} {
		t.Run(c.name, func(t *testing.T) {
			writes := countFailures(t, h, c.drained)
			conn, err := h.x.udp.connect(0, rigServer4.Addr(), to)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			dst := &destination{to: to, conn: conn}
			big := udpDatagram(netip.AddrPortFrom(leaf4, freeUDPPort(t, leaf4)), to, bytes.Repeat([]byte{0xb2}, pathMTU))
			d, _ := readDatagram(big)
			answered := len(h.mesh.answered())
			h.x.udp.send(big, d, dst, true)
			if *writes != 1 {
				t.Errorf("the datagram past the path took %d writes, want 1", *writes)
			}
			// the path's MTU is the kernel's for the socket, which an earlier
			// test's too big toward the same address may have lowered past the
			// loopback's
			mtu, err := socketPathMTU(conn, false)
			if err != nil || mtu > pathMTU {
				t.Fatalf("the socket's path MTU reads %d, %v, want at most the loopback's %d", mtu, err, pathMTU)
			}
			if answers := h.mesh.answered()[answered:]; len(answers) != 1 || answers[0].kind != netstack.ExitTooBig || answers[0].mtu != mtu {
				t.Errorf("answered %v, want one too big at the path's %d", answers, mtu)
			}
			if dst.ipLen == 0 || dst.longest != uint16(len(d.udp)) {
				t.Errorf("the datagram that did not leave was recorded with %d bytes of IP header and UDP length %d, want its own %d", dst.ipLen, dst.longest, len(d.udp))
			}
		})
	}
}

// A datagram each of whose writes fails while its socket's queue answers that
// an ICMP error came with the failure is written 4 times and no more, the
// cap that holds the lane's worker for a server that keeps the socket's errno
// set, counted as failed by pending errors, never as the host's own, and
// reported not refused. The queue's answer is the test's, so no ICMP error is
// sent: the route toward the server is unreachable, each write failing at
// once, and the answer turns false past 6 drains, so a send past the cap ends
// too, with more writes than 4. Each failed write is drained once, which
// counts the writes.
func TestDatagramIsWrittenNoMoreThanFourTimes(t *testing.T) {
	r := newGoneRig(t)
	to := serverAt(r.both)
	if got := r.send(t, r.both, "left"); got.Addr() != r.gone.Addr() {
		t.Fatalf("the server read the datagram from %s, want %s", got, r.gone.Addr())
	}
	dst := r.h.mappingsOf(r.leaf)[0].destinations[to]
	unreachable(t, netip.PrefixFrom(to.Addr(), 32))
	var writes *int
	writes = countFailures(t, r.h, func(bool) bool { return *writes <= 6 })
	raw := udpDatagram(r.leaf, to, []byte("past every pending error"))
	d, _ := readDatagram(raw)
	unsent, pending := r.h.count(false, reasonUnsent), r.h.count(false, reasonPending)
	refused, closed := r.h.x.udp.send(raw, d, dst, false)
	if refused || closed || *writes != 4 {
		t.Errorf("the send reported refused %t closed %t after %d writes, want neither after 4", refused, closed, *writes)
	}
	if unsent, pending := r.h.count(false, reasonUnsent)-unsent, r.h.count(false, reasonPending)-pending; unsent != 0 || pending != 1 {
		t.Errorf("counted %d datagrams unsent and %d failed by pending errors, want 0 and 1", unsent, pending)
	}
}

// countFailures counts the failed writes of h's sends until the test ends,
// since failed drains the socket's queue once past each, and has answer give
// failed whether the queue held an error, from what it held
func countFailures(t *testing.T, h *relayHarness, answer func(queued bool) bool) *int {
	t.Helper()
	failures := 0
	h.x.udp.drained = func(queued bool) bool {
		failures++
		return answer(queued)
	}
	t.Cleanup(func() { h.x.udp.drained = nil })
	return &failures
}

// asQueued answers whether the queue held an error as the kernel left it
func asQueued(queued bool) bool { return queued }

// A datagram whose socket refuses the DF setting is not written, and is
// counted unsent and reported refused, and the next datagram that asks the
// same setting is refused alike, since a failed setting is asked again: an
// IPv6 datagram's on a destination's IPv4 socket, which Linux refuses the
// IPv6 option. No write is made, and only a write fills the destination's
// record (keep), so the record stays empty. Nothing left, so the
// destination's deadline stays where it was. The socket is bound to no
// address, so the test needs no loopback.
func TestDatagramWhoseDFSettingFailsIsNotWritten(t *testing.T) {
	h := newRelayHarness(t, nil)
	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	to := netip.AddrPortFrom(server6, 4000)
	dst := &destination{to: to, conn: conn}
	raw := udpDatagram(netip.AddrPortFrom(leaf6, 40000), to, []byte("never written"))
	d, ok := readDatagram(raw)
	if !ok {
		t.Fatal("the test's datagram does not read")
	}
	unsent := h.count(false, reasonUnsent)
	const deadline = 12345
	dst.deadline.Store(deadline)
	for i := range 2 {
		if refused, closed := h.x.udp.send(raw, d, dst, true); !refused || closed {
			t.Errorf("send %d reported refused %t closed %t, want refused", i+1, refused, closed)
		}
		if got := dst.deadline.Load(); got != deadline {
			t.Errorf("send %d left the destination's deadline at %d, want %d where it was", i+1, got, deadline)
		}
	}
	if got := h.count(false, reasonUnsent) - unsent; got != 2 {
		t.Errorf("counted %d datagrams unsent, want both", got)
	}
	if dst.ipLen != 0 {
		t.Error("the destination recorded a datagram, so one was written")
	}
}
