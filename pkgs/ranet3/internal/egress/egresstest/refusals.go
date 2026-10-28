// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package egresstest

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"
)

// icmpNotCarried is RFC 5508 section 7's REQ-10c, which IPv4 alone has: a NAT
// SHOULD NOT support Source Quench or Information Request and Reply. The
// leaf's quench quoting the server's datagram and its information request
// reach the server not at all, and the server's quench to the leaf's mapping
// reaches the leaf not at all, while an echo still crosses.
func (r *rows) icmpNotCarried(t *testing.T) {
	to := netip.AddrPortFrom(r.family.Server, quenchPort)
	from := netip.AddrPortFrom(r.family.Leaf, leafQuenchPort)
	server := r.listenUDP(t, to)
	leaf := r.bindUDP(t, from)
	opened := []byte("opens the mapping over " + r.family.Name)
	mapping := receiveFrom(t, udpReader(server), opened, func() { _, _ = leaf.WriteToUDPAddrPort(opened, to) })
	icmp := r.serverIP(t, syscall.IPPROTO_ICMP, r.family.Server)

	quench := message{kind4: 4}
	out := []struct {
		what string
		sent []byte
	}{
		{"the leaf's source quench", icmpError(r.family.Leaf, r.family.Server, quench, datagram(to, from, leafTTL, []byte("the server's datagram")))},
		{"the leaf's information request", query(r.family.Leaf, r.family.Server, 15, 0, informationID, []byte("an information request"))},
	}
	for _, step := range out {
		r.exit.hand([][]byte{step.sent})
		if readsICMP(icmp, step.sent[headerLength(step.sent)]) {
			t.Errorf("the server read %s, which the exit does not carry", step.what)
		}
	}

	back := len(r.network.Back())
	in := icmpError(r.family.Server, mapping.Addr(), quench, datagram(mapping, to, leafTTL, opened))
	if _, err := icmp.WriteToIP(in[headerLength(in):], &net.IPAddr{IP: mapping.Addr().AsSlice()}); err != nil {
		t.Fatalf("send the server's source quench to %s: %v", mapping, err)
	}
	time.Sleep(quietPeriod)
	for _, packet := range r.network.Back()[back:] {
		if p, ok := parse(packet); ok && p.protocol == syscall.IPPROTO_ICMP && len(p.payload) > 0 && p.payload[0] == 4 {
			t.Errorf("the server's source quench to the leaf's mapping %s reached the leaf from %s", mapping, p.src)
		}
	}
	r.echoTo(t, r.family.Server, quenchEchoID)
}

// readsICMP is whether the server reads an ICMP message of type kind within
// quietPeriod
func readsICMP(icmp *net.IPConn, kind byte) bool {
	buf := make([]byte, readSize)
	for by := time.Now().Add(quietPeriod); ; {
		n, _, err := ipReader(icmp)(buf, by)
		if err != nil {
			return false
		}
		if n > 0 && buf[0] == kind {
			return true
		}
	}
}

// checksummed is RFC 6888 REQ-1 for the protocols whose checksum covers the
// addresses, which a NAT carrying them has to rewrite: a DCCP-Request of RFC
// 4340 section 5.2 and a UDP-Lite datagram of RFC 3828, each covering all of
// itself and valid. Under none the server reads each from the leaf's own
// address, valid, and its answer, a DCCP-Response of section 5.3 or a
// UDP-Lite datagram, reaches the leaf as the server sent it, the UDP-Lite one
// unless the arm declares UDP-Lite unanswered. Under a class that translates
// the server never reads one whose checksum fails for the addresses it reads
// it from: it reads it valid from the class's address, or reads nothing while
// each answer about it is an administratively prohibited from an address of
// the exit, at least one of them arriving unless the arm declares the refusal
// of IPv4 DCCP or of UDP-Lite unanswered, and none where it does.
func (r *rows) checksummed(t *testing.T) {
	for _, p := range []struct {
		name            string
		protocol        byte
		port            uint16
		request, answer func(from, to netip.AddrPort) []byte
		// unanswered is the limit an arm declares where it refuses the protocol
		// with no answer, which holds in IPv6 too where inIPv6 is set and drops
		// the reply into the mesh under none too where dropsReply is
		unanswered         Limit
		inIPv6, dropsReply bool
	}{
		{"dccp", 33, leafDCCPPort, dccpRequest, dccpResponse, UnansweredIPv4DCCP, false, false},
		{"udp-lite", 136, leafUDPLitePort, udpLite, udpLite, UnansweredUDPLite, true, true},
	} {
		t.Run(p.name, func(t *testing.T) {
			raw := r.serverIP(t, int(p.protocol), r.family.Server)
			to := netip.AddrPortFrom(r.family.Server, checksummedPort)
			leaf := netip.AddrPortFrom(r.family.Leaf, p.port)
			sent := p.request(leaf, to)
			transport := sent[headerLength(sent):]
			declared, unanswered := r.limits[p.unanswered]
			unanswered = unanswered && (p.inIPv6 || !r.v6())
			if unanswered {
				t.Logf("declared in %s: %s", declared.Row, declared.Reason)
			}
			back := len(r.network.Back())
			var from netip.Addr
			var read []byte
			arrived := func(by time.Time) bool {
				buf := make([]byte, readSize)
				for {
					n, address, err := ipReader(raw)(buf, by)
					if err != nil {
						return false
					}
					// past the ports and the checksum, which a translation rewrites
					if n == len(transport) && bytes.Equal(buf[8:n], transport[8:]) {
						from, read = address.Addr(), buf[:n]
						return true
					}
				}
			}
			if r.class == None {
				until(func() { r.exit.hand([][]byte{sent}) }, arrived)
			} else {
				// a refusal answers each packet, so one is sent
				r.exit.hand([][]byte{sent})
				arrived(time.Now().Add(quietPeriod))
			}
			valid := read != nil && checksum(from, to.Addr(), p.protocol, read) == 0
			if r.class == None {
				if read == nil || from != r.family.Leaf || !valid {
					t.Fatalf("under none the server read the %s packet from %s with a valid checksum %v, want it from the leaf's own %s, valid", p.name, from, valid, r.family.Leaf)
				}
				if unanswered && p.dropsReply {
					return
				}
				answer := p.answer(to, leaf)
				answer = answer[headerLength(answer):]
				if !r.await(func() { _, _ = raw.WriteToIP(answer, &net.IPAddr{IP: leaf.Addr().AsSlice()}) }, func(packet []byte) bool {
					a, ok := parse(packet)
					return ok && a.protocol == p.protocol && a.src == to.Addr() && a.dst == leaf.Addr() && bytes.Equal(a.payload, answer)
				}) {
					t.Errorf("under none the server's %s answer to the leaf's %s reached the leaf not at all", p.name, leaf)
				}
				return
			}
			switch {
			case read != nil && !valid:
				t.Errorf("the server read the %s packet from %s with a checksum that fails for the addresses it read it from", p.name, from)
			case read != nil && from != r.seen():
				t.Errorf("the server read the %s packet from %s, want %s", p.name, from, r.seen())
			case read != nil:
				return
			}
			answers := 0
			for _, packet := range r.network.Back()[back:] {
				a, ok := readAnswer(packet)
				if !ok || !quotes(a.quote, sent) {
					continue
				}
				answers++
				if !a.is(r.v6(), prohibited) || !r.fromExit(a.from) {
					t.Errorf("the %s packet the exit refused was answered with type %d code %d from %s, want administratively prohibited from the exit", p.name, a.kind, a.code, a.from)
				}
			}
			switch {
			case answers == 0 && !unanswered:
				t.Errorf("the server read no %s packet and no answer about it came back, only %s", p.name, answersIn(r.network.Back()[back:]))
			case answers > 0 && unanswered:
				t.Errorf("the arm declares the %s refusal unanswered, and %d answers about it came back", p.name, answers)
			}
		})
	}
}

// dccpRequest is a DCCP-Request from from to to, RFC 4340 section 5.2, of
// service code 0
func dccpRequest(from, to netip.AddrPort) []byte { return dccp(from, to, 0, make([]byte, 4)) }

// dccpResponse is a DCCP-Response from from to to, RFC 4340 section 5.3,
// acknowledging sequence number 1, of service code 0
func dccpResponse(from, to netip.AddrPort) []byte {
	// the acknowledgement number subheader of section 5.1, its 48-bit number
	// ending at the eighth octet, then the service code
	rest := make([]byte, 12)
	rest[7] = 1
	return dccp(from, to, 1, rest)
}

// dccp is a DCCP packet of type kind from from to to, a generic header of RFC
// 4340 section 5.1 with extended sequence numbers and sequence number 1 ahead
// of rest, its checksum covering all of it, CsCov 0 of section 9.2
func dccp(from, to netip.AddrPort, kind byte, rest []byte) []byte {
	packet := append(make([]byte, 16, 16+len(rest)), rest...)
	binary.BigEndian.PutUint16(packet[0:], from.Port())
	binary.BigEndian.PutUint16(packet[2:], to.Port())
	// data offset in 32-bit words, then the type with X set, then the low octet
	// of the 48-bit sequence number
	packet[4], packet[8], packet[15] = byte(len(packet)/4), kind<<1|1, 1
	binary.BigEndian.PutUint16(packet[6:], checksum(from.Addr(), to.Addr(), 33, packet))
	return ipPacket(from.Addr(), to.Addr(), 33, leafTTL, packet)
}

// udpLite is a UDP-Lite datagram from from to to, RFC 3828 section 3.1, its
// checksum coverage 0, which covers all of it
func udpLite(from, to netip.AddrPort) []byte {
	lite := make([]byte, 8, 32)
	binary.BigEndian.PutUint16(lite[0:], from.Port())
	binary.BigEndian.PutUint16(lite[2:], to.Port())
	lite = append(lite, "a udp-lite datagram"...)
	sum := checksum(from.Addr(), to.Addr(), 136, lite)
	if sum == 0 {
		// a computed zero is sent as all ones, section 3.1
		sum = 0xffff
	}
	binary.BigEndian.PutUint16(lite[6:], sum)
	return ipPacket(from.Addr(), to.Addr(), 136, leafTTL, lite)
}
