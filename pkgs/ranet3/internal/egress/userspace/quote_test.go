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
// a parameter problem its pointer, and a quoted UDP header its length. Where
// an RFC 4884 extension follows the quote, the quote ends where the
// message's length attribute says. Any other
// message, a quote of a fragment past the first or of another protocol, is no
// error of the exit's.
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
		// length is a UDP datagram's
		length uint16
	}
	udp4, udp6 := binary.BigEndian.Uint16(datagram4[24:26]), binary.BigEndian.Uint16(datagram6[44:46])
	// extended is message with its quote padded to the 128 octets of an
	// RFC 4884 extension's original datagram field, an extension header and
	// one object after it
	extended := func(message []byte) []byte {
		padded := append(bytes.Clone(message), make([]byte, 8+128-len(message))...)
		return append(padded, 2<<4, 0, 0, 0, 0, 8, 2, 1, 0, 0, 0, 1)
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
		{"ipv4 too big with its mtu", quotedMessage(3, 4, 1400, datagram4, 20+8+16), false, want{"", outside4, server, 3, 4, 1400, 16, protoUDP, udp4}},
		{"ipv4 too big with no mtu", quotedMessage(3, 4, 0, datagram4, 20+8), false, want{"", outside4, server, 3, 4, 1280, 0, protoUDP, udp4}},
		{"ipv4 length claiming past the quote", quotedMessage(11, 0, 0, claiming, 20+8), false, want{"", outside4, server, 11, 0, 0, 0, protoUDP, udp4}},
		{"ipv4 parameter problem", quotedMessage(12, 0, 9<<24, datagram4, 20+8), false, want{"", outside4, server, 12, 0, 9, 0, protoUDP, udp4}},
		{"ipv4 tcp", quotedMessage(3, 1, 0, segment, 20+8), false, want{"", outside4, server, 3, 1, 0, 0, protoTCP, 0}},
		{"ipv4 unreachable with an extension", extended(quotedMessage(3, 3, 128/4<<16, datagram4, len(datagram4))), false, want{"", outside4, server, 3, 3, 0, 128 - 28, protoUDP, udp4}},
		{"ipv4 length attribute short of 128 octets", append(quotedMessage(3, 3, 64/4<<16, datagram4, len(datagram4)), 0, 0, 0, 0), false, want{"", outside4, server, 3, 3, 0, 64 + 4, protoUDP, udp4}},
		{"ipv4 damaged quoted header", quotedMessage(3, 3, 0, damaged, 20+8), false, want{reason: reasonQuotedChecksum}},
		{"ipv4 fragment past the first", quotedMessage(3, 3, 0, fragment, 20+8), false, want{reason: reasonNotOurs}},
		{"ipv4 quote short of the ports", quotedMessage(3, 3, 0, datagram4, 20+2), false, want{reason: reasonNotOurs}},
		{"ipv4 redirect", quotedMessage(5, 1, 0, datagram4, 20+8), false, want{reason: reasonNotOurs}},
		{"ipv4 echo reply", []byte{0, 0, 0, 0, 0, 1, 0, 1}, false, want{reason: reasonNotOurs}},
		{"ipv4 quoting icmp", quotedMessage(3, 1, 0, echo, 20+8), false, want{reason: reasonNotOurs}},
		{"ipv6 unreachable", quotedMessage(1, 4, 0, datagram6, 40+8+16), true, want{"", outside6, server6, 1, 4, 0, 16, protoUDP, udp6}},
		{"ipv6 unreachable with an extension", extended(quotedMessage(1, 4, 128/8<<24, datagram6, len(datagram6))), true, want{"", outside6, server6, 1, 4, 0, 128 - 48, protoUDP, udp6}},
		{"ipv6 too big", quotedMessage(2, 0, 1280, datagram6, 40+8), true, want{"", outside6, server6, 2, 0, 1280, 0, protoUDP, udp6}},
		{"ipv6 parameter problem", quotedMessage(4, 0, 42, datagram6, 40+8), true, want{"", outside6, server6, 4, 0, 42, 0, protoUDP, udp6}},
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
			got := want{"", q.from, q.to, q.kind, q.code, q.info, len(q.prefix), int(q.protocol), 0}
			if q.protocol == protoUDP {
				got.length = q.length
			}
			if got != c.want || q.offender != router {
				t.Errorf("read %+v from %s, want %+v from %s", got, q.offender, c.want, router)
			}
		})
	}
}

// A destination's first datagram, then 16 of other sizes, then one with the
// first's payload under another identification: an error about the first,
// with the quoted UDP length or with none, reaches the leaf quoting the
// first's addresses, ports and payload, with no identification or checksum
// of another datagram's, since the run carried neither alike, and its own
// UDP length where the error quotes it. An error whose quoted UDP length is
// shorter than a UDP header is dropped and counted.
func TestErrorAfterARunQuotesNoOtherDatagramsFields(t *testing.T) {
	server := loopbackServer(t, netip.MustParseAddr("127.0.0.1"))
	h := newRelayHarness(t, nil)
	leaf := netip.AddrPortFrom(leaf4, freeUDPPort(t, leaf4))
	payload := []byte("same payload")
	first := leafDatagram(leaf, serverAt(server), payload, 1)
	h.x.udp.take(first, false)
	outside := readDatagramFrom(t, server, payload)
	for i := range 16 {
		other := bytes.Repeat([]byte{0x5a}, 40+i)
		h.x.udp.take(leafDatagram(leaf, serverAt(server), other, uint16(i+2)), false)
		readDatagramFrom(t, server, other)
	}
	h.x.udp.take(leafDatagram(leaf, serverAt(server), payload, 100), false)
	readDatagramFrom(t, server, payload)
	e := icmpError{offender: netip.MustParseAddr("198.51.100.1"), kind: 3, code: 3}
	for _, length := range []uint16{uint16(8 + len(payload)), 0} {
		h.drainLaid()
		if length == 0 {
			dst := h.mappingsOf(leaf)[0].destinations[serverAt(server)]
			dst.mu.Lock()
			h.x.udp.relay(dst, e, 0, payload, false)
			dst.mu.Unlock()
		} else if !h.x.udp.relayQuoted(quotedError{icmpError: e, protocol: protoUDP, from: outside, to: serverAt(server), length: length, prefix: payload}) {
			t.Fatal("the error about the first datagram was not taken as the mapping's")
		}
		quote := h.nextLaid(t, "the error about the first datagram")[20+8:]
		want := bytes.Clone(first)
		binary.BigEndian.PutUint16(want[4:6], 0)
		binary.BigEndian.PutUint16(want[20+6:20+8], 0)
		binary.BigEndian.PutUint16(want[10:12], 0)
		binary.BigEndian.PutUint16(want[10:12], fold(sum(0, want[:20])))
		if !bytes.Equal(quote, want) {
			t.Errorf("the error quoting UDP length %d quotes %x, want %x, the first's with no identification or checksum", length, quote, want)
		}
	}
	before := h.count(false, reasonQuotedLength)
	if !h.x.udp.relayQuoted(quotedError{icmpError: e, protocol: protoUDP, from: outside, to: serverAt(server), length: 7, prefix: payload}) {
		t.Fatal("the error quoting UDP length 7 was not taken as the mapping's")
	}
	if got := h.count(false, reasonQuotedLength) - before; got != 1 {
		t.Errorf("counted %d errors quoting UDP length 7, want 1", got)
	}
	if pkt := h.x.link.poll(); pkt != nil {
		h.x.link.release(pkt)
		t.Error("the error quoting UDP length 7 reached the leaf")
	}
}

// mapped registers a mapping of leaf on outside holding dst, a destination
// toward dst.to, and returns what takes it out
func (h *relayHarness) mapped(leaf, outside netip.AddrPort, dst *destination) func() {
	m := &mapping{leaf: leaf, source: outside.Addr(), port: outside.Port(), destinations: map[netip.AddrPort]*destination{dst.to: dst}}
	h.x.udp.mu.Lock()
	h.x.udp.ports[outside] = m
	h.x.udp.mu.Unlock()
	return func() {
		h.x.udp.mu.Lock()
		delete(h.x.udp.ports, outside)
		h.x.udp.mu.Unlock()
	}
}

// ipHeader is the length of an IP header with no options or extension
// headers, an IPv6 one where ipv6
func ipHeader(ipv6 bool) int {
	if ipv6 {
		return 40
	}
	return 20
}

// quoteOf is the part of laid, an ICMP error toward a leaf, past its outer IP
// header and the eight octets of its ICMP header
func quoteOf(laid []byte) []byte {
	return laid[ipHeader(laid[0]>>4 == 6)+8:]
}

// quotedLengths is the UDP length and the IP length quote claims, an IPv4 or
// IPv6 header of header octets and a UDP header
func quotedLengths(quote []byte, header int) (udp, ip int) {
	udp = int(binary.BigEndian.Uint16(quote[header+4 : header+6]))
	if quote[0]>>4 == 6 {
		return udp, ipHeader(true) + int(binary.BigEndian.Uint16(quote[4:6]))
	}
	return udp, int(binary.BigEndian.Uint16(quote[2:4]))
}

// An error an ICMP socket reads about a destination whose three datagrams
// carried UDP lengths of 60, 48 and 72 octets, in that order, so that neither
// end is the first's, is relayed where it quotes a length in the range from
// the shortest to the longest, as the page states: those two and 61, which no
// datagram carried, the quote's IP length the header's and that UDP length. It
// is dropped and counted where it quotes 47, 73 or 65535, outside the range,
// so no IP length wraps: with and without 40 octets of IPv4 options or 16 of
// IPv6 extension headers, which every datagram carried.
func TestErrorQuotingALengthOutsideTheDestinationsRangeIsDropped(t *testing.T) {
	h := newRelayHarness(t, nil)
	for _, c := range []struct {
		name                  string
		leaf, server, outside netip.AddrPort
		options               int
		router                netip.Addr
		kind, code            byte
	}{
		{"ipv4", netip.AddrPortFrom(leaf4, 40000), netip.MustParseAddrPort("203.0.113.9:4000"), netip.MustParseAddrPort("198.51.100.17:40000"), 0, netip.MustParseAddr("198.51.100.1"), 3, 3},
		{"ipv4 with 40 octets of options", netip.AddrPortFrom(leaf4, 40001), netip.MustParseAddrPort("203.0.113.9:4000"), netip.MustParseAddrPort("198.51.100.17:40001"), 40, netip.MustParseAddr("198.51.100.1"), 3, 3},
		{"ipv6", netip.AddrPortFrom(leaf6, 40000), netip.MustParseAddrPort("[2001:db8::9]:4000"), netip.MustParseAddrPort("[2001:db8:1::1]:40000"), 0, netip.MustParseAddr("2001:db8:2::1"), 1, 4},
		{"ipv6 with 16 octets of extension headers", netip.AddrPortFrom(leaf6, 40001), netip.MustParseAddrPort("[2001:db8::9]:4000"), netip.MustParseAddrPort("[2001:db8:1::1]:40001"), 16, netip.MustParseAddr("2001:db8:2::1"), 1, 4},
	} {
		t.Run(c.name, func(t *testing.T) {
			dst := &destination{to: c.server}
			defer h.mapped(c.leaf, c.outside, dst)()
			for _, size := range []int{52, 40, 64} {
				raw := udpDatagram(c.leaf, c.server, bytes.Repeat([]byte{0x41}, size))
				if c.options > 0 {
					raw = withOptions(raw, c.options)
				}
				d, ok := readDatagram(raw)
				if !ok {
					t.Fatalf("the test's datagram %x does not read", raw)
				}
				dst.keep(raw, d)
			}
			header := int(dst.ipLen)
			for _, length := range []uint16{47, 48, 61, 72, 73, 65535} {
				h.drainLaid()
				dropped := h.count(false, reasonQuotedLength)
				q := quotedError{icmpError: icmpError{offender: c.router, kind: c.kind, code: c.code}, protocol: protoUDP, from: c.outside, to: c.server, length: length}
				if !h.x.udp.relayQuoted(q) {
					t.Fatalf("the error quoting UDP length %d was not taken as the mapping's", length)
				}
				laid := h.laid()
				if length < 48 || length > 72 {
					if got := h.count(false, reasonQuotedLength) - dropped; got != 1 || laid != nil {
						t.Errorf("the error quoting UDP length %d was counted %d times and laid %t, want counted once and dropped", length, got, laid != nil)
					}
					continue
				}
				if laid == nil {
					t.Fatalf("the error quoting UDP length %d reached no leaf", length)
				}
				if udp, ip := quotedLengths(quoteOf(laid), header); udp != int(length) || ip != header+int(length) {
					t.Errorf("the error quoting UDP length %d quotes UDP length %d and IP length %d, want %d and %d", length, udp, ip, length, header+int(length))
				}
			}
		})
	}
}

// A destination keeps 60 bytes of its first datagram's IP header and its 8
// bytes of UDP header, the 68 bytes of headers the limits page states: an
// IPv4 header with 40 bytes of options and an IPv6 one with 16 bytes of
// extension headers are quoted whole, and an IPv6 one with 24 bytes of them,
// 64 in all, is quoted as its fixed header alone
func TestDestinationKeepsSixtyEightBytesOfHeaders(t *testing.T) {
	if room := len(destination{}.ip) + len(destination{}.udp); room != 68 {
		t.Errorf("a destination has room for %d bytes of headers, the page states 68", room)
	}
	for _, c := range []struct {
		name    string
		server  netip.Addr
		leaf    netip.Addr
		options int
		kept    bool
	}{
		{"ipv4 with 40 bytes of options", netip.MustParseAddr("127.0.0.1"), leaf4, 40, true},
		{"ipv6 with 16 bytes of extension headers", netip.IPv6Loopback(), leaf6, 16, true},
		{"ipv6 with 24 bytes of extension headers", netip.IPv6Loopback(), leaf6, 24, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			server := loopbackServer(t, c.server)
			h := newRelayHarness(t, nil)
			leaf := netip.AddrPortFrom(c.leaf, freeUDPPort(t, c.leaf))
			payload := []byte("behind options")
			plain := udpDatagram(leaf, serverAt(server), payload)
			first := withOptions(plain, c.options)
			h.x.udp.take(first, false)
			readDatagramFrom(t, server, payload)
			dst := h.mappingsOf(leaf)[0].destinations[serverAt(server)]
			e := icmpError{offender: netip.MustParseAddr("198.51.100.1"), kind: 3, code: 1}
			headers := 20 + 8
			if c.leaf.Is6() {
				e, headers = icmpError{offender: netip.MustParseAddr("2001:db8:2::1"), kind: 1, code: 4}, 40+8
			}
			h.drainLaid()
			dst.mu.Lock()
			kept := int(dst.ipLen) + len(dst.udp)
			h.x.udp.relay(dst, e, 0, payload, false)
			dst.mu.Unlock()
			quote := h.nextLaid(t, "the error")[headers:]
			want, wantKept := first, len(first)-len(payload)
			if !c.kept {
				want, wantKept = plain, 40+8
			}
			if kept != wantKept || !bytes.Equal(quote, want) {
				t.Errorf("kept %d bytes of headers, want %d, and quotes %x, want %x", kept, wantKept, quote, want)
			}
		})
	}
}

// withOptions puts size bytes of options past raw's IP header: IPv4
// no-operation options, or an IPv6 destination options header padded with
// PadN
func withOptions(raw []byte, size int) []byte {
	options := make([]byte, size)
	at := 40
	if raw[0]>>4 == 4 {
		at = 20
		for i := range options {
			options[i] = 1
		}
	} else {
		options[0], options[1] = protoUDP, byte(size/8-1)
		options[2], options[3] = 1, byte(size-4)
	}
	out := append(append(bytes.Clone(raw[:at]), options...), raw[at:]...)
	if at == 20 {
		out[0] = 4<<4 | byte(len(options)+20)/4
		binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
		binary.BigEndian.PutUint16(out[10:12], 0)
		binary.BigEndian.PutUint16(out[10:12], fold(sum(0, out[:at+size])))
		return out
	}
	out[6] = 60
	binary.BigEndian.PutUint16(out[4:6], uint16(len(out)-40))
	return out
}

// An error an ICMP socket reads about a UDP datagram reaches the leaf of the
// mapping whose socket toward the quoted server sent it from the quoted
// address and port, from the error's offender at the host's TTL or hop limit
// and quoting the leaf's own datagram. One quoting another address at the
// mapping's port, a port no mapping holds, a server the mapping never sent
// to, or TCP is about no socket of the mapping's.
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
				return quotedError{icmpError: icmpError{offender: family.router, kind: family.kind, code: family.code}, protocol: protocol, from: from, to: to, length: uint16(8 + len("request"))}
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

// leafDatagram is an IP packet from leaf to server holding a UDP datagram of
// payload, an IPv4 one with identification id
func leafDatagram(leaf, server netip.AddrPort, payload []byte, id uint16) []byte {
	message := udpMessage(leaf, server, payload)
	if leaf.Addr().Is6() {
		return ip6(leaf.Addr(), server.Addr(), protoUDP, 64, message)
	}
	return ip4(leaf.Addr(), server.Addr(), protoUDP, id, 0, 64, message)
}

// An error on a destination's socket that has sent nothing is about no
// datagram of the exit's: it reaches no leaf and is counted
func TestErrorOnASocketThatSentNothingIsCounted(t *testing.T) {
	h := newRelayHarness(t, nil)
	dst := &destination{to: netip.MustParseAddrPort("203.0.113.9:4000")}
	before := h.count(false, reasonNotOurs)
	dst.mu.Lock()
	h.x.udp.relay(dst, icmpError{offender: netip.MustParseAddr("198.51.100.1"), kind: 3, code: 3}, 0, []byte("a payload"), false)
	dst.mu.Unlock()
	if got := h.count(false, reasonNotOurs) - before; got != 1 {
		t.Errorf("counted %d errors about no datagram of the exit's, want 1", got)
	}
	if pkt := h.x.link.poll(); pkt != nil {
		t.Errorf("laid a packet of %d bytes toward a leaf for an error about no datagram", pkt.Size())
		h.x.link.release(pkt)
	}
}

// An RFC 4884 length attribute names the original datagram field where the
// message holds the whole field, up to its last octet, and names none where
// the field would pass the message's end by one octet
func TestExtensionLengthCoversTheMessageToItsEnd(t *testing.T) {
	for _, c := range []struct {
		name  string
		ipv6  bool
		kind  byte
		unit  int
		field int
	}{
		{"ipv4", false, 3, 4, 128},
		{"ipv6", true, 1, 8, 128},
	} {
		t.Run(c.name, func(t *testing.T) {
			for _, size := range []int{8 + c.field, 8 + c.field - 1} {
				message := make([]byte, size)
				message[0] = c.kind
				if c.ipv6 {
					message[4] = byte(c.field / c.unit)
				} else {
					message[5] = byte(c.field / c.unit)
				}
				want := 0
				if size == 8+c.field {
					want = c.field
				}
				if got := original(message, c.ipv6); got != want {
					t.Errorf("a message of %d octets whose attribute names %d: original %d, want %d", size, c.field, got, want)
				}
			}
		})
	}
}
