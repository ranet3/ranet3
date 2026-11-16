// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package userspace

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
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
)

// An echo request's checksum is checked on both of the relay's paths, the
// lane's for a request whole and the stack's for one in fragments: a bad one
// is dropped and counted before any socket is readied. IPv6's stack drops a
// bad checksum itself before its handler, so that arm counts nothing of the
// relay's and readies nothing either. A good one reaches its mapping's socket,
// which the harness refuses, or the host where it gives this process none.
func TestEchoChecksumIsCheckedOnBothPaths(t *testing.T) {
	for _, family := range []struct {
		name         string
		leaf, server netip.Addr
	}{{"ipv4", leaf4, server4}, {"ipv6", leaf6, server6}} {
		refused := echoRefused(family.leaf.Is6())
		for _, bad := range []bool{false, true} {
			for _, fragmented := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s bad %t fragmented %t", family.name, bad, fragmented), func(t *testing.T) {
					h := newRelayHarness(t, nil)
					h.refuseAll = true
					size := 100
					if fragmented {
						size = 3000
					}
					message := echoRequest(family.leaf, family.server, 7, 1, bytes.Repeat([]byte{9}, size))
					if bad {
						message[2] ^= 0x5a
					}
					protocol := icmpProtocol(family.leaf)
					packets := [][]byte{ipPacket(family.leaf, family.server, protocol, message)}
					if fragmented {
						packets = fragments(family.leaf, family.server, protocol, 9, message, 1200)
					}
					for _, raw := range packets {
						h.x.handle(h.lane, raw)
					}
					prepared, dropped := h.preparedSoFar(), h.count(false, reasonICMPChecksum)
					switch {
					case !bad && refused:
						if len(prepared) != 0 || dropped != 0 || h.count(true, reasonEchoSocket) != 1 {
							t.Errorf("readied %v, dropped %d for the checksum and refused %d for the echo socket, want the host's one refusal", prepared, dropped, h.count(true, reasonEchoSocket))
						}
					case !bad:
						if want := []netip.AddrPort{netip.AddrPortFrom(family.server, 0)}; !slices.Equal(prepared, want) || h.count(true, reasonSocket) != 1 {
							t.Errorf("readied %v and refused %d for the socket, want the mapping's socket toward %s readied once", prepared, h.count(true, reasonSocket), family.server)
						}
					case family.leaf.Is6() && fragmented:
						if len(prepared) != 0 || dropped != 0 {
							t.Errorf("readied %v and dropped %d for the checksum, want nothing of the relay's", prepared, dropped)
						}
					default:
						if len(prepared) != 0 || dropped != 1 {
							t.Errorf("readied %v and dropped %d for the checksum, want nothing readied and one dropped", prepared, dropped)
						}
					}
				})
			}
		}
	}
}

// An echo mapping's socket holds the leaf's identifier where the host holds
// it free, and sends to every destination from it (RFC 5508 REQ-1a). Each
// reply comes back to the leaf from its server with the leaf's identifier and
// a checksum the exit computed, at the host's TTL or hop limit, its sequence
// number and data untouched.
// Another leaf with the same identifier has a mapping of its own on another
// identifier, and its replies come back with its own.
func TestEchoIsRelayedFromTheLeafsIdentifier(t *testing.T) {
	for _, family := range []struct {
		name        string
		leaf, other netip.Addr
		servers     []netip.Addr
	}{
		{"ipv4", leaf4, other4, []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.2")}},
		{"ipv6", leaf6, other6, []netip.Addr{netip.IPv6Loopback()}},
	} {
		t.Run(family.name, func(t *testing.T) {
			for _, server := range family.servers {
				_ = loopbackServer(t, server)
			}
			h := newRelayHarness(t, nil)
			h.x.SetHopLimits(hostTTL, hostHopLimit)
			id := freeIdentifiers(t, family.leaf.Is6(), 1)[0]
			seq := uint16(0)
			for _, ping := range []struct{ leaf, server netip.Addr }{
				{family.leaf, family.servers[0]}, {family.leaf, family.servers[len(family.servers)-1]}, {family.other, family.servers[0]},
			} {
				seq++
				payload := fmt.Appendf(nil, "echo %d", seq)
				h.x.echo.take(ipPacket(ping.leaf, ping.server, icmpProtocol(ping.leaf), echoRequest(ping.leaf, ping.server, id, seq, payload)))
				reply := h.waitLaid(t, fmt.Sprintf("reply %d from %s to %s", seq, ping.server, ping.leaf), func(raw []byte) bool {
					return isEchoReply(raw, ping.server, ping.leaf, id, seq, payload)
				})
				if got := hopsOf(reply); got != hostHops(ping.leaf) {
					t.Errorf("reply %d laid at %d, want the host's %d", seq, got, hostHops(ping.leaf))
				}
			}
			h.x.echo.mu.Lock()
			mine, theirs, n := h.x.echo.mappings[echoKey{family.leaf, id}], h.x.echo.mappings[echoKey{family.other, id}], len(h.x.echo.mappings)
			h.x.echo.mu.Unlock()
			if mine == nil || theirs == nil || n != 2 {
				t.Fatalf("%d mappings, the leaf's %t and the other's %t, want one each", n, mine != nil, theirs != nil)
			}
			if got := boundIdentifier(t, mine.socket); got != id {
				t.Errorf("the leaf's mapping took identifier %d for the leaf's %d, which the host held free", got, id)
			}
			if got := boundIdentifier(t, theirs.socket); got == id {
				t.Errorf("both leaves' mappings hold identifier %d", id)
			}
		})
	}
}

// An echo mapping under a class naming an address sends from that address,
// and under auto from the one the route to the server picks, its reply coming
// back to the leaf either way
func TestEchoLeavesFromTheAddressOfTheLeafsClass(t *testing.T) {
	server := netip.MustParseAddr("127.0.0.1")
	for _, c := range []struct {
		name string
		cfg  egress.Egress
		want netip.Addr
	}{
		{"auto", egress.Egress{}, netip.IPv4Unspecified()},
		{"an address", classed(netip.MustParseAddr("127.0.0.2")), netip.MustParseAddr("127.0.0.2")},
	} {
		t.Run(c.name, func(t *testing.T) {
			_ = loopbackServer(t, server)
			id := freeIdentifiers(t, false, 1)[0]
			h := newRelayHarness(t, nil)
			h.x.cfg.Translate = c.cfg.Translate
			h.x.echo.take(ipPacket(leaf4, server, protoICMP, echoRequest(leaf4, server, id, 1, []byte("from a class"))))
			h.waitLaid(t, "reply", func(raw []byte) bool { return isEchoReply(raw, server, leaf4, id, 1, []byte("from a class")) })
			h.x.echo.mu.Lock()
			m := h.x.echo.mappings[echoKey{leaf4, id}]
			h.x.echo.mu.Unlock()
			var sa unix.Sockaddr
			var err error
			if controlErr := m.socket.raw.Control(func(fd uintptr) { sa, err = unix.Getsockname(int(fd)) }); controlErr != nil || err != nil {
				t.Fatalf("the mapping's socket's address: %v %v", controlErr, err)
			}
			if got := sockaddrPort(sa).Addr(); got != c.want {
				t.Errorf("the mapping's socket is bound to %s, want %s", got, c.want)
			}
		})
	}
}

// An echo socket the platform refuses, as Android refuses one to an app
// outside ping_group_range, is answered administratively prohibited from the
// exit and counted, and opens no mapping and holds no flow
func TestRefusedEchoSocketIsAnsweredProhibited(t *testing.T) {
	for _, refusal := range []syscall.Errno{syscall.EACCES, syscall.EPERM} {
		t.Run(refusal.Error(), func(t *testing.T) {
			h := newRelayHarness(t, func(rt *Runtime, _ *egress.Egress) {
				rt.Platform.Prepare = func(string, netip.AddrPort, syscall.RawConn) error { return refusal }
			})
			raw := ipPacket(leaf4, server4, protoICMP, echoRequest(leaf4, server4, 7, 1, []byte("refused")))
			h.x.echo.take(raw)
			answers := h.mesh.answered()
			if len(answers) != 1 || answers[0].kind != netstack.ExitProhibited || !bytes.Equal(answers[0].offending, raw) {
				t.Errorf("answered %v, want administratively prohibited quoting the request", answers)
			}
			if got := h.count(true, reasonEchoSocket); got != 1 {
				t.Errorf("refused %d for the echo socket, want 1", got)
			}
			if n, open := h.echoHeld(); n != 0 || open != 0 {
				t.Errorf("%d mappings and %d flows after the refusal, want none", n, open)
			}
		})
	}
}

// An echo request the host refuses to send for a reason no destination
// unreachable names is dropped and counted as echo unsent and answered
// nothing, and the mapping it opened ends at the next pass with its flow
// given back: over IPv4 the loopback network's broadcast address, whose route
// the up loopback holds in any namespace and which the host refuses with
// EACCES to a socket without SO_BROADCAST, and over IPv6 a link-local
// multicast one, which it refuses with EINVAL to a socket that names no
// interface
func TestEchoRequestTheHostRefusesIsCounted(t *testing.T) {
	host := onEchoHost(t)
	for _, c := range []struct {
		name     string
		leaf, to netip.Addr
	}{
		{"ipv4 broadcast", leaf4, netip.MustParseAddr("127.255.255.255")},
		{"ipv6 link-local multicast", leaf6, netip.MustParseAddr("ff02::1")},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newRelayHarness(t, func(rt *Runtime, _ *egress.Egress) {
				rt.Platform.Prepare = func(string, netip.AddrPort, syscall.RawConn) error { return nil }
			})
			host(func() {
				h.x.echo.take(ipPacket(c.leaf, c.to, icmpProtocol(c.leaf), echoRequest(c.leaf, c.to, 7, 1, []byte("refused"))))
			})
			if got := h.count(false, reasonEchoUnsent); got != 1 {
				t.Errorf("counted %d requests unsent, want 1", got)
			}
			if answers := h.mesh.answered(); len(answers) != 0 {
				t.Errorf("answered %v, want nothing", answers)
			}
			opened, _ := h.echoHeld()
			h.advance(mappingSweep)
			if left, open := h.echoHeld(); opened != 1 || left != 0 || open != 0 {
				t.Errorf("%d mappings opened, %d left and %d flows held after the next pass, want 1 opened and none left", opened, left, open)
			}
		})
	}
}

// An echo request the host refuses to send since no route leads to its
// destination, ENETUNREACH, or since the route that matches it cannot deliver
// to its host, EHOSTUNREACH, is counted as echo unsent and answered as one no
// route reaches, in each family, quoting the request as the leaf sent it
// though another leaf's mapping holds its identifier and its own sends with
// another: the mappings' sockets open in echoSpace's namespace, whose one
// route past the loopback's is an unreachable one
func TestEchoRequestTheHostFindsNoWayForIsAnswered(t *testing.T) {
	space := echoSpace(t)
	unreachable := map[bool]netip.Prefix{false: netip.MustParsePrefix("198.51.100.0/24"), true: netip.MustParsePrefix("2001:db8:5::/48")}
	err := space.Do(func() error {
		netlink, err := netnstest.OpenNetlink()
		if err != nil {
			return err
		}
		defer netlink.Close()
		for _, to := range unreachable {
			family := byte(unix.AF_INET6)
			if to.Addr().Is4() {
				family = unix.AF_INET
			}
			header := []byte{family, byte(to.Bits()), 0, 0, unix.RT_TABLE_MAIN, unix.RTPROT_BOOT, unix.RT_SCOPE_UNIVERSE, unix.RTN_UNREACHABLE, 0, 0, 0, 0}
			if err := netlink.Request(unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_EXCL, slices.Concat(header, netnstest.Attr(unix.RTA_DST, to.Addr().AsSlice()))); err != nil {
				return fmt.Errorf("route %s unreachable: %w", to, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("make the namespace: %v", err)
	}
	for _, c := range []struct {
		name            string
		leaf, other, to netip.Addr
	}{
		{"ipv4 no route", leaf4, other4, netip.MustParseAddr("192.0.2.77")},
		{"ipv6 no route", leaf6, other6, netip.MustParseAddr("2001:db8:4::77")},
		{"ipv4 unreachable route", leaf4, other4, unreachable[false].Addr().Next()},
		{"ipv6 unreachable route", leaf6, other6, unreachable[true].Addr().Next()},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newRelayHarness(t, func(rt *Runtime, _ *egress.Egress) {
				rt.Platform.Prepare = func(string, netip.AddrPort, syscall.RawConn) error { return nil }
			})
			const id = 7
			holder := ipPacket(c.other, c.to, icmpProtocol(c.other), echoRequest(c.other, c.to, id, 1, []byte("holds the identifier")))
			raw := ipPacket(c.leaf, c.to, icmpProtocol(c.leaf), echoRequest(c.leaf, c.to, id, 1, []byte("no way")))
			sent := bytes.Clone(raw)
			// a mapping's socket opens on the thread that takes its request, so in
			// the namespace
			_ = space.Do(func() error {
				h.x.echo.take(holder)
				h.x.echo.take(raw)
				return nil
			})
			if refused := h.count(true, reasonEchoSocket); refused != 0 {
				t.Fatalf("refused %d for the echo socket, want the namespace to give one", refused)
			}
			h.x.echo.mu.Lock()
			m := h.x.echo.mappings[echoKey{c.leaf, id}]
			h.x.echo.mu.Unlock()
			if m == nil || m.outside.id == id {
				t.Fatalf("the leaf's mapping is open %t, want it open sending with another identifier than the other leaf's %d", m != nil, id)
			}
			if got := h.count(false, reasonEchoUnsent); got != 2 {
				t.Errorf("counted %d requests unsent, want both leaves' 2", got)
			}
			if answers := h.mesh.answered(); len(answers) != 2 || answers[1].kind != netstack.ExitNoRoute || !bytes.Equal(answers[1].offending, sent) {
				t.Errorf("answered %v, want the leaf's request answered as no route, quoted as the leaf sent it", answers)
			}
		})
	}
}

// Two requests of one leaf and identifier in flight together, as a leaf that
// pings two destinations with one identifier has them on two workers, leave
// the mapping the time of the one that left, whatever the host refused beside
// it and whichever send ends first, and a mapping neither left from ends at
// the first pass once both ended. No pass ends a mapping while a send on it
// is in flight. The host refuses 127.255.255.255 with EACCES and sends to
// 127.0.0.1, which echoSpace leaves unanswered.
func TestEchoMappingLastsFromTheRequestThatLeft(t *testing.T) {
	space := echoSpace(t)
	refused, sent := netip.MustParseAddr("127.255.255.255"), netip.MustParseAddr("127.0.0.1")
	for _, c := range []struct {
		name string
		to   [2]netip.Addr
		// ends is the order the two sends end in
		ends [2]int
	}{
		{"opener refused, its refusal ending first", [2]netip.Addr{refused, sent}, [2]int{0, 1}},
		{"opener refused, the other send ending first", [2]netip.Addr{refused, sent}, [2]int{1, 0}},
		{"both refused", [2]netip.Addr{refused, refused}, [2]int{0, 1}},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newRelayHarness(t, nil)
			var raws [2][]byte
			var requests [2]echoQuery
			var mappings [2]*echoMapping
			for i, to := range c.to {
				raws[i] = ipPacket(leaf4, to, protoICMP, echoRequest(leaf4, to, 7, uint16(i+1), []byte("in flight")))
				requests[i], _ = readEcho(raws[i])
				var reason string
				_ = space.Do(func() error {
					mappings[i], reason = h.x.echo.mapping(requests[i])
					return nil
				})
				if mappings[i] == nil {
					t.Fatalf("request %d's mapping was refused for %s", i+1, reason)
				}
			}
			h.advance(0)
			left := h.now()
			for _, i := range c.ends {
				h.x.echo.send(raws[i], requests[i], mappings[i])
			}
			unsent := uint64(2)
			if c.to[1] == sent {
				unsent = 1
			}
			if mappings[0] != mappings[1] || h.count(false, reasonEchoUnsent) != unsent || h.count(true, reasonWithdrawn) != 0 {
				t.Fatalf("one mapping %t, %d counted unsent and %d refused as withdrawn, want one mapping and %d unsent alone", mappings[0] == mappings[1], h.count(false, reasonEchoUnsent), h.count(true, reasonWithdrawn), unsent)
			}
			if c.to[1] == sent {
				h.endsAt(t, left.Add(echoIdle))
				return
			}
			h.advance(mappingSweep)
			if live, open := h.echoHeld(); live != 0 || open != 0 {
				t.Errorf("%d mappings and %d flows after the first pass once both were refused, want none", live, open)
			}
		})
	}
}

// A mapping a request left on keeps that request's time through a later
// request the host refuses, and ends echoIdle after the one that left with
// its flow given back
func TestEchoMappingKeepsTheTimeOfARequestThatLeftPastARefusal(t *testing.T) {
	space := echoSpace(t)
	h := newRelayHarness(t, nil)
	take := func(to netip.Addr, seq uint16) {
		raw := ipPacket(leaf4, to, protoICMP, echoRequest(leaf4, to, 7, seq, []byte("kept")))
		_ = space.Do(func() error {
			h.x.echo.take(raw)
			return nil
		})
	}
	left := h.now()
	take(netip.MustParseAddr("127.0.0.1"), 1)
	h.advance(10 * time.Second)
	take(netip.MustParseAddr("127.255.255.255"), 2)
	if got := h.count(false, reasonEchoUnsent); got != 1 {
		t.Fatalf("counted %d requests unsent, want the second alone", got)
	}
	h.endsAt(t, left.Add(echoIdle))
}

// A mapping's time moves only on: a request that read the clock before
// another left and stores its time after that one's keeps the later time, so
// the mapping lasts echoIdle from the later request. The first request's
// read of the clock sends the second whole, ten seconds on, before it returns.
func TestEchoMappingTimeMovesOnlyOn(t *testing.T) {
	space := echoSpace(t)
	h := newRelayHarness(t, nil)
	to := netip.MustParseAddr("127.0.0.1")
	var raws [2][]byte
	var requests [2]echoQuery
	var m *echoMapping
	for i := range raws {
		raws[i] = ipPacket(leaf4, to, protoICMP, echoRequest(leaf4, to, 7, uint16(i+1), []byte("on")))
		requests[i], _ = readEcho(raws[i])
		_ = space.Do(func() error {
			m, _ = h.x.echo.mapping(requests[i])
			return nil
		})
	}
	if m == nil {
		t.Fatal("the mapping was refused")
	}
	armed := true
	h.x.echo.now = func() time.Time {
		read := h.now()
		if armed {
			armed = false
			h.advance(10 * time.Second)
			h.x.echo.send(raws[1], requests[1], m)
		}
		return read
	}
	h.x.echo.send(raws[0], requests[0], m)
	if got := h.count(false, reasonEchoUnsent); got != 0 {
		t.Fatalf("counted %d requests unsent, want both to leave", got)
	}
	h.endsAt(t, h.now().Add(echoIdle))
}

// A pass as a request leaves ends no mapping: send moves the mapping's time
// before it lowers its count of the sends in flight, so a pass run from the
// clock send reads that time from finds the request still in flight
func TestEchoMappingOutlivesAPassAsItsRequestLeaves(t *testing.T) {
	space := echoSpace(t)
	h := newRelayHarness(t, nil)
	to := netip.MustParseAddr("127.0.0.1")
	armed := true
	h.x.echo.now = func() time.Time {
		now := h.now()
		if armed {
			armed = false
			h.x.echo.expire(now.Add(2 * echoIdle))
		}
		return now
	}
	left := h.now()
	_ = space.Do(func() error {
		h.x.echo.take(ipPacket(leaf4, to, protoICMP, echoRequest(leaf4, to, 7, 1, []byte("leaving"))))
		return nil
	})
	if unsent, refused := h.count(false, reasonEchoUnsent), h.count(true, reasonEchoSocket); unsent != 0 || refused != 0 {
		t.Fatalf("counted %d unsent and refused %d for the echo socket, want the request to leave", unsent, refused)
	}
	h.endsAt(t, left.Add(echoIdle))
}

// A reply that comes in to a mapping no request left from goes to the leaf
// and keeps the mapping echoIdle from it, as a request that left would: the
// host refuses the leaf's request to 127.255.255.255, and a raw socket of the
// namespace sends an echo reply on the mapping's identifier from 127.0.0.1,
// which the kernel hands the mapping's socket whatever its source
func TestEchoReplyKeepsAMappingNoRequestLeftFrom(t *testing.T) {
	space := echoSpace(t)
	h := newRelayHarness(t, nil)
	refused, from := netip.MustParseAddr("127.255.255.255"), netip.MustParseAddr("127.0.0.1")
	const id = 7
	_ = space.Do(func() error {
		h.x.echo.take(ipPacket(leaf4, refused, protoICMP, echoRequest(leaf4, refused, id, 1, []byte("refused"))))
		return nil
	})
	h.x.echo.mu.Lock()
	m := h.x.echo.mappings[echoKey{leaf4, id}]
	h.x.echo.mu.Unlock()
	if unsent := h.count(false, reasonEchoUnsent); m == nil || unsent != 1 {
		t.Fatalf("the mapping is open %t and %d requests counted unsent, want it open and its request refused", m != nil, unsent)
	}
	reply := echoRequest(from, from, m.outside.id, 9, []byte("a reply"))
	reply[0] = 0
	binary.BigEndian.PutUint16(reply[2:4], 0)
	binary.BigEndian.PutUint16(reply[2:4], fold(sum(0, reply)))
	err := space.Do(func() error {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_ICMP)
		if err != nil {
			return err
		}
		defer unix.Close(fd)
		return unix.Sendto(fd, reply, 0, &unix.SockaddrInet4{Addr: from.As4()})
	})
	if err != nil {
		t.Fatalf("send the reply: %v", err)
	}
	h.waitLaid(t, "the reply toward the leaf", func(raw []byte) bool { return isEchoReply(raw, from, leaf4, id, 9, []byte("a reply")) })
	h.endsAt(t, h.now().Add(echoIdle))
}

// An ICMP message from a leaf that is neither an echo request nor an error,
// as an extended echo request of RFC 8335, is dropped and counted as no echo
// on the lane's path, where the stack would drop it uncounted, and opens no
// mapping
func TestQueryNoEchoIsDroppedAndCountedOnTheLanesPath(t *testing.T) {
	h := newRelayHarness(t, nil)
	for _, c := range []struct {
		leaf, server netip.Addr
		kind         byte
	}{{leaf4, server4, 42}, {leaf6, server6, 160}} {
		message := echoRequest(c.leaf, c.server, 7, 1, []byte("an extended echo request"))
		message[0] = c.kind
		h.x.handle(h.lane, ipPacket(c.leaf, c.server, icmpProtocol(c.leaf), message))
	}
	if got := h.count(false, reasonNotEcho); got != 2 {
		t.Errorf("counted %d dropped as no echo, want both extended echo requests", got)
	}
	h.x.echo.mu.Lock()
	n := len(h.x.echo.mappings)
	h.x.echo.mu.Unlock()
	if n != 0 {
		t.Errorf("%d echo mappings after the drops, want none", n)
	}
}

// Echo mappings waiting for a reply hold no pooled buffer: a mapping's reader
// takes one only once its socket is readable, and gives it back once the
// reply has moved, so an idle mapping costs no 64 KiB against Within's
// perFlow
func TestIdleEchoMappingsHoldNoBuffer(t *testing.T) {
	server := netip.MustParseAddr("127.0.0.1")
	_ = loopbackServer(t, server)
	h := newRelayHarness(t, nil)
	ids := freeIdentifiers(t, false, 8)
	for i, id := range ids {
		h.x.echo.take(ipPacket(leaf4, server, icmpProtocol(leaf4), echoRequest(leaf4, server, id, 1, []byte("idle"))))
		h.waitLaid(t, fmt.Sprintf("reply %d", i), func(raw []byte) bool {
			return isEchoReply(raw, server, leaf4, id, 1, []byte("idle"))
		})
	}
	deadline := time.Now().Add(exitWait)
	for h.x.echo.out.Load() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("%d of %d idle echo mappings hold a pooled buffer", h.x.echo.out.Load(), len(ids))
		}
		time.Sleep(time.Millisecond)
	}
	h.x.echo.mu.Lock()
	n := len(h.x.echo.mappings)
	h.x.echo.mu.Unlock()
	if n != len(ids) {
		t.Errorf("%d echo mappings, want the %d idle ones", n, len(ids))
	}
}

// An IPv6 echo reply longer than the buffer it is read into past the leaf's
// header is dropped and counted, never carried cut with a checksum over what
// is left: the loopback answers a request of the largest ICMPv6 message
func TestEchoReplyTooLargeForItsBufferIsDropped(t *testing.T) {
	server := netip.IPv6Loopback()
	_ = loopbackServer(t, server)
	h := newRelayHarness(t, nil)
	id := freeIdentifiers(t, true, 1)[0]
	h.x.echo.take(ipPacket(leaf6, server, icmpProtocol(leaf6), echoRequest(leaf6, server, id, 1, make([]byte, 1<<16-1-8))))
	deadline := time.Now().Add(exitWait)
	for h.count(false, reasonEchoTooLarge) == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("no reply dropped as too large within %s, %d packets laid", exitWait, len(h.mesh.laidPackets()))
		}
		time.Sleep(10 * time.Millisecond)
	}
	for _, raw := range h.mesh.laidPackets() {
		if p, ok := parse(raw); ok && p.dst == leaf6 {
			t.Errorf("laid %s toward the leaf, want nothing", p)
		}
	}
}

// An echo mapping ends a minute after its last request out or reply in (RFC
// 5508 REQ-2), and gives its flow back
func TestEchoMappingEndsAMinuteAfterItsLastEcho(t *testing.T) {
	server := netip.MustParseAddr("127.0.0.1")
	_ = loopbackServer(t, server)
	h := newRelayHarness(t, nil)
	id := freeIdentifiers(t, false, 1)[0]
	ping := func(seq uint16) {
		payload := fmt.Appendf(nil, "echo %d", seq)
		h.x.echo.take(ipPacket(leaf4, server, protoICMP, echoRequest(leaf4, server, id, seq, payload)))
		h.waitLaid(t, fmt.Sprintf("reply %d", seq), func(raw []byte) bool { return isEchoReply(raw, server, leaf4, id, seq, payload) })
	}
	live := func() bool {
		h.x.echo.mu.Lock()
		defer h.x.echo.mu.Unlock()
		return h.x.echo.mappings[echoKey{leaf4, id}] != nil
	}
	ping(1)
	h.advance(59 * time.Second)
	if !live() {
		t.Fatal("the mapping ended 59 seconds after its last echo")
	}
	ping(2)
	h.advance(59 * time.Second)
	if !live() {
		t.Fatal("the mapping ended 59 seconds after an echo that kept it")
	}
	h.advance(2 * time.Second)
	if live() {
		t.Error("the mapping outlived a minute with no echo")
	}
	h.x.flows.mu.Lock()
	defer h.x.flows.mu.Unlock()
	if h.x.flows.open != 0 {
		t.Errorf("%d flows held once the mapping ended", h.x.flows.open)
	}
}

// A fragmented echo request in either family toward a server the leaf holds
// a TCP connection to reaches the relay once, through the stack's ICMP
// handler, draws the server's one reply toward the leaf, and nothing of
// gVisor's own. Its one mapping holds the identifier the leaf's kernel gave.
func TestFragmentedEchoWithATCPFlowOpenReachesTheRelayOnce(t *testing.T) {
	r := newLeafRig(t, func(rt Runtime) (*Exit, error) { return New(exitConfig(), rt) })
	r.allowEcho(t)
	for _, family := range rigFamilies {
		t.Run(family.name, func(t *testing.T) {
			server := r.listen(family.servers[0], 7, func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(io.Discard, conn)
			})
			conn, err := r.dial(netip.AddrPortFrom(family.leaf, 0), server, rigSettle)
			if err != nil {
				t.Fatalf("dial %s: %v", server, err)
			}
			defer conn.Close()
			if _, err := conn.Write([]byte("held open\n")); err != nil {
				t.Fatal(err)
			}
			stats := r.exit.stack.Stats().ICMP
			sent := stats.V4.PacketsSent.EchoReply.Value() + stats.V6.PacketsSent.EchoReply.Value()
			received := stats.V4.PacketsReceived.EchoRequest.Value() + stats.V6.PacketsReceived.EchoRequest.Value()
			ping := r.leafEcho(t, family.leaf.Is6())
			payload := bytes.Repeat([]byte{0xec}, leafMTU+200)
			message := make([]byte, 8+len(payload))
			message[0] = 8
			if family.leaf.Is6() {
				message[0] = 128
			}
			binary.BigEndian.PutUint16(message[6:8], 1)
			copy(message[8:], payload)
			var to unix.Sockaddr
			if family.leaf.Is6() {
				to = &unix.SockaddrInet6{Addr: server.Addr().As16()}
			} else {
				to = &unix.SockaddrInet4{Addr: server.Addr().As4()}
			}
			if err := unix.Sendto(ping, message, 0, to); err != nil {
				t.Fatalf("the leaf's echo to %s: %v", server.Addr(), err)
			}
			buf := make([]byte, 1<<16)
			n, _, err := unix.Recvfrom(ping, buf, 0)
			if err != nil {
				t.Fatalf("the leaf read no reply: %v", err)
			}
			if n != len(message) || binary.BigEndian.Uint16(buf[6:8]) != 1 || !bytes.Equal(buf[8:n], payload) {
				t.Errorf("the leaf read %d bytes, sequence %d, want the reply of %d bytes to sequence 1", n, binary.BigEndian.Uint16(buf[6:8]), len(message))
			}
			if got := stats.V4.PacketsSent.EchoReply.Value() + stats.V6.PacketsSent.EchoReply.Value(); got != sent {
				t.Errorf("gVisor sent %d echo replies of its own", got-sent)
			}
			if got := stats.V4.PacketsReceived.EchoRequest.Value() + stats.V6.PacketsReceived.EchoRequest.Value(); got != received+1 {
				t.Errorf("the stack took %d echo requests, want the one it reassembled", got-received)
			}
			bound, err := unix.Getsockname(ping)
			if err != nil {
				t.Fatal(err)
			}
			id := sockaddrPort(bound).Port()
			var mine []*echoMapping
			r.exit.echo.mu.Lock()
			for key, m := range r.exit.echo.mappings {
				if key.leaf == family.leaf {
					mine = append(mine, m)
				}
			}
			r.exit.echo.mu.Unlock()
			if len(mine) != 1 {
				t.Fatalf("%d echo mappings of %s, want one", len(mine), family.leaf)
			}
			if got := boundIdentifier(t, mine[0].socket); mine[0].key.id != id || got != id {
				t.Errorf("the mapping of identifier %d holds %d, want the leaf's %d, which this namespace held free", mine[0].key.id, got, id)
			}
		})
	}
}

// allowEcho lets this process's group open an ICMP datagram socket in this
// namespace and the leaf's
func (r *leafRig) allowEcho(t *testing.T) {
	t.Helper()
	if err := allowEchoSockets(); err != nil {
		t.Fatalf("allow echo sockets here: %v", err)
	}
	if err := r.leaf.Do(allowEchoSockets); err != nil {
		t.Fatalf("allow echo sockets in the leaf's namespace: %v", err)
	}
}

// allowEchoSockets lets this process's group open an ICMP datagram socket in
// the network namespace of the calling thread, which a new namespace lets no
// group open. The range names only groups the user namespace maps.
func allowEchoSockets() error {
	group := os.Getegid()
	return os.WriteFile("/proc/sys/net/ipv4/ping_group_range", fmt.Appendf(nil, "%d %d\n", group, group), 0o644)
}

// echoSpace is a network namespace of the test's own on a thread of its own,
// its loopback up, where this process's echo sockets open and the host
// answers no echo request, so a request that left draws no reply. It needs
// root, as unshare -rn gives.
func echoSpace(t *testing.T) *netnstest.Thread {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("a network namespace of its own needs root on linux, as unshare -rn gives")
	}
	space := netnstest.StartThread(t)
	err := space.Do(func() error {
		if err := allowEchoSockets(); err != nil {
			return err
		}
		for _, ignore := range []string{"/proc/sys/net/ipv4/icmp_echo_ignore_all", "/proc/sys/net/ipv6/icmp/echo_ignore_all"} {
			if err := os.WriteFile(ignore, []byte("1\n"), 0o644); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("make the namespace: %v", err)
	}
	return space
}

// onEchoHost is a function that runs another where this process's echo
// sockets open: in echoSpace's namespace where the process is root, as the
// root suite runs it, and in the test's own otherwise, the test skipping
// where that gives none
func onEchoHost(t *testing.T) func(func()) {
	t.Helper()
	if os.Getuid() == 0 {
		space := echoSpace(t)
		return func(f func()) {
			_ = space.Do(func() error {
				f()
				return nil
			})
		}
	}
	if echoRefused(false) || echoRefused(true) {
		t.Skip("no echo socket for this process")
	}
	return func(f func()) { f() }
}

// leafEcho is an ICMP datagram socket of the leaf's, opened in its namespace,
// whose reads wait at most exitWait
func (r *leafRig) leafEcho(t *testing.T, ipv6 bool) int {
	t.Helper()
	family, protocol := unix.AF_INET, unix.IPPROTO_ICMP
	if ipv6 {
		family, protocol = unix.AF_INET6, unix.IPPROTO_ICMPV6
	}
	var fd int
	err := r.leaf.Do(func() error {
		var err error
		fd, err = unix.Socket(family, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, protocol)
		return err
	})
	if err != nil {
		t.Fatalf("the leaf's echo socket: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	timeout := unix.NsecToTimeval(exitWait.Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout); err != nil {
		t.Fatal(err)
	}
	return fd
}

// freeIdentifiers is n distinct identifiers no ICMP datagram socket of the
// family holds now
func freeIdentifiers(t *testing.T, ipv6 bool, n int) []uint16 {
	t.Helper()
	var ids []uint16
	var held []*echoSocket
	defer func() {
		for _, s := range held {
			_ = s.close()
		}
	}()
	for range n {
		s, err := openEcho(ipv6, netip.Addr{}, 0, func(string, syscall.RawConn) error { return nil })
		if err != nil {
			t.Skipf("no echo socket for this process: %v", err)
		}
		held = append(held, s)
		ids = append(ids, boundIdentifier(t, s))
	}
	return ids
}

// echoRefused is whether the host gives this process no ICMP datagram socket
// of the family, as a new namespace gives none
func echoRefused(ipv6 bool) bool {
	s, err := openEcho(ipv6, netip.Addr{}, 0, func(string, syscall.RawConn) error { return nil })
	if err != nil {
		return true
	}
	_ = s.close()
	return false
}
