// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package userspace

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

// quotedMessage is an ICMP error of kind and code with rest after its
// checksum, quoting the first quoted bytes of datagram, an IPv4 one with the
// quoted header's total length written in the host's byte order as XNU hands
// it, its checksum still the one sent
func quotedMessage(kind, code byte, rest uint32, datagram []byte, quoted int) []byte {
	message := binary.BigEndian.AppendUint32([]byte{kind, code, 0, 0}, rest)
	quote := bytes.Clone(datagram[:quoted])
	if quote[0]>>4 == 4 {
		binary.NativeEndian.PutUint16(quote[2:4], binary.BigEndian.Uint16(quote[2:4]))
	}
	return append(message, quote...)
}

// An error an ICMP socket reads is matched by the protocol, the addresses and
// the ports of the datagram it quotes, whatever the quoted IPv4 total length
// claims: XNU hands it in the host's order, and a claim past the quote is not
// read either. The quoted IPv4 header's checksum is checked with that field
// written back in network order, and a damaged one is counted. A too big
// carries the message's MTU, or the route's where the message carries none,
// and a parameter problem its pointer. Any other message, a quote of a
// fragment past the first or of another protocol, is no error of the exit's.
func TestQuotedErrorIsReadWhateverItsIPv4LengthClaims(t *testing.T) {
	outside4, server := netip.MustParseAddrPort("198.51.100.17:40000"), netip.MustParseAddrPort("203.0.113.9:4000")
	outside6, server6 := netip.MustParseAddrPort("[2001:db8:1::1]:40000"), netip.MustParseAddrPort("[2001:db8::9]:4000")
	router4, router6 := netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("2001:db8:2::1")
	payload := bytes.Repeat([]byte{0xab}, 64)
	datagram4, datagram6 := udpDatagram(outside4, server, payload), udpDatagram(outside6, server6, payload)
	routeMTU := func(netip.Addr) int { return 1280 }
	type want struct {
		reason           string
		from, to         netip.AddrPort
		kind, code       byte
		info             uint32
		prefix, protocol int
	}
	claiming := bytes.Clone(datagram4)
	binary.BigEndian.PutUint16(claiming[2:4], 0xfff0)
	binary.BigEndian.PutUint16(claiming[10:12], 0)
	binary.BigEndian.PutUint16(claiming[10:12], fold(sum(0, claiming[:20])))
	damaged := bytes.Clone(datagram4)
	damaged[8]--
	fragment := bytes.Clone(datagram4)
	binary.BigEndian.PutUint16(fragment[6:8], 3)
	binary.BigEndian.PutUint16(fragment[10:12], 0)
	binary.BigEndian.PutUint16(fragment[10:12], fold(sum(0, fragment[:20])))
	segment := tcpSegment(outside4, server, 1, 0, tcpSYN, nil)
	echo := ipPacket(outside4.Addr(), server.Addr(), protoICMP, echoRequest(outside4.Addr(), server.Addr(), 7, 1, nil))
	for _, c := range []struct {
		name    string
		message []byte
		ipv6    bool
		want    want
	}{
		{"ipv4 too big with its mtu", quotedMessage(3, 4, 1400, datagram4, 20+8+16), false, want{"", outside4, server, 3, 4, 1400, 16, protoUDP}},
		{"ipv4 too big with no mtu", quotedMessage(3, 4, 0, datagram4, 20+8), false, want{"", outside4, server, 3, 4, 1280, 0, protoUDP}},
		{"ipv4 length claiming past the quote", quotedMessage(11, 0, 0, claiming, 20+8), false, want{"", outside4, server, 11, 0, 0, 0, protoUDP}},
		{"ipv4 parameter problem", quotedMessage(12, 0, 9<<24, datagram4, 20+8), false, want{"", outside4, server, 12, 0, 9, 0, protoUDP}},
		{"ipv4 tcp", quotedMessage(3, 1, 0, segment, 20+8), false, want{"", outside4, server, 3, 1, 0, 0, protoTCP}},
		{"ipv4 damaged quoted header", quotedMessage(3, 3, 0, damaged, 20+8), false, want{reason: reasonQuotedChecksum}},
		{"ipv4 fragment past the first", quotedMessage(3, 3, 0, fragment, 20+8), false, want{reason: reasonNotOurs}},
		{"ipv4 quote short of the ports", quotedMessage(3, 3, 0, datagram4, 20+2), false, want{reason: reasonNotOurs}},
		{"ipv4 redirect", quotedMessage(5, 1, 0, datagram4, 20+8), false, want{reason: reasonNotOurs}},
		{"ipv4 echo reply", []byte{0, 0, 0, 0, 0, 1, 0, 1}, false, want{reason: reasonNotOurs}},
		{"ipv4 quoting icmp", quotedMessage(3, 1, 0, echo, 20+8), false, want{reason: reasonNotOurs}},
		{"ipv6 unreachable", quotedMessage(1, 4, 0, datagram6, 40+8+16), true, want{"", outside6, server6, 1, 4, 0, 16, protoUDP}},
		{"ipv6 too big", quotedMessage(2, 0, 1280, datagram6, 40+8), true, want{"", outside6, server6, 2, 0, 1280, 0, protoUDP}},
		{"ipv6 parameter problem", quotedMessage(4, 0, 42, datagram6, 40+8), true, want{"", outside6, server6, 4, 0, 42, 0, protoUDP}},
		{"ipv6 echo reply", []byte{129, 0, 0, 0, 0, 1, 0, 1}, true, want{reason: reasonNotOurs}},
		{"ipv6 quote short of the ports", quotedMessage(1, 4, 0, datagram6, 40+2), true, want{reason: reasonNotOurs}},
	} {
		t.Run(c.name, func(t *testing.T) {
			router := router4
			if c.ipv6 {
				router = router6
			}
			q, reason := readQuotedError(c.message, c.ipv6, router, routeMTU)
			if reason != c.want.reason {
				t.Fatalf("read as %q, want %q", reason, c.want.reason)
			}
			if reason != "" {
				return
			}
			got := want{"", q.from, q.to, q.kind, q.code, q.info, len(q.prefix), int(q.protocol)}
			if got != c.want || q.offender != router {
				t.Errorf("read %+v from %s, want %+v from %s", got, q.offender, c.want, router)
			}
		})
	}
}

// An error an ICMP socket reads about a UDP datagram reaches the leaf of the
// mapping whose socket toward the quoted server sent it from the quoted
// address and port, from the error's offender at the host's TTL or hop limit
// and quoting the leaf's own datagram. One quoting another address at the mapping's port, a port no
// mapping holds, a server the mapping never sent to, or TCP is about no
// socket of the mapping's.
func TestQuotedErrorReachesOnlyTheLeafOfTheSocketItQuotes(t *testing.T) {
	for _, family := range []struct {
		name                        string
		leaf, server, router, other netip.Addr
		kind, code                  byte
	}{
		{"ipv4", leaf4, netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("198.51.100.1"), other4, 3, 1},
		{"ipv6", leaf6, netip.IPv6Loopback(), netip.MustParseAddr("2001:db8:2::1"), other6, 1, 3},
	} {
		t.Run(family.name, func(t *testing.T) {
			server := loopbackServer(t, family.server)
			h := newRelayHarness(t, nil)
			leaf := netip.AddrPortFrom(family.leaf, freeUDPPort(t, family.leaf))
			h.x.udp.take(udpDatagram(leaf, serverAt(server), []byte("request")), false)
			outside := readDatagramFrom(t, server, []byte("request"))
			quoting := func(from, to netip.AddrPort, protocol byte) quotedError {
				return quotedError{icmpError: icmpError{offender: family.router, kind: family.kind, code: family.code}, protocol: protocol, from: from, to: to}
			}
			for _, other := range []struct {
				name string
				q    quotedError
			}{
				{"another address at the mapping's port", quoting(netip.AddrPortFrom(family.other, outside.Port()), serverAt(server), protoUDP)},
				{"a port no mapping holds", quoting(netip.AddrPortFrom(outside.Addr(), outside.Port()+1), serverAt(server), protoUDP)},
				{"a server never sent to", quoting(outside, netip.AddrPortFrom(family.server, serverAt(server).Port()+1), protoUDP)},
				{"tcp", quoting(outside, serverAt(server), protoTCP)},
			} {
				if h.x.udp.relayQuoted(other.q) {
					t.Errorf("%s: an error quoting %s to %s taken as the mapping's", other.name, other.q.from, other.q.to)
				}
			}
			h.x.SetHopLimits(hostTTL, hostHopLimit)
			if !h.x.udp.relayQuoted(quoting(outside, serverAt(server), protoUDP)) {
				t.Fatal("the error quoting the mapping's socket was not taken")
			}
			laid := h.waitLaid(t, "the error", func(pkt []byte) bool {
				p, ok := parse(pkt)
				return ok && p.src == family.router && p.dst == family.leaf && p.kind == family.kind && p.code == family.code
			})
			if got := hopsOf(laid); got != hostHops(family.leaf) {
				t.Errorf("laid the error at %d, want the host's %d", got, hostHops(family.leaf))
			}
		})
	}
}
