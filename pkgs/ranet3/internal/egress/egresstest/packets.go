// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package egresstest

import (
	"bytes"
	"encoding/binary"
	"math"
	"net/netip"
	"slices"
	"syscall"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"ranet3.com/pkgs/ranet3/internal/packet"
)

// ipPacket is an IP packet from src to dst carrying payload of protocol, with
// hops as its TTL or hop limit and, over IPv4, DF set
func ipPacket(src, dst netip.Addr, protocol, hops byte, payload []byte) []byte {
	if src.Is4() {
		header := make([]byte, 20, 20+len(payload))
		header[0] = 0x45
		binary.BigEndian.PutUint16(header[2:], uint16(20+len(payload)))
		binary.BigEndian.PutUint16(header[6:], 0x4000)
		header[8], header[9] = hops, protocol
		copy(header[12:], src.AsSlice())
		copy(header[16:], dst.AsSlice())
		binary.BigEndian.PutUint16(header[10:], ^uint16(packet.Sum(0, header)))
		return append(header, payload...)
	}
	header := make([]byte, 40, 40+len(payload))
	header[0] = 0x60
	binary.BigEndian.PutUint16(header[4:], uint16(len(payload)))
	header[6], header[7] = protocol, hops
	copy(header[8:], src.AsSlice())
	copy(header[24:], dst.AsSlice())
	return append(header, payload...)
}

// datagram is a UDP datagram from from to to carrying payload, with hops as its TTL or hop limit
func datagram(from, to netip.AddrPort, hops byte, payload []byte) []byte {
	udp := make([]byte, 8, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:], from.Port())
	binary.BigEndian.PutUint16(udp[2:], to.Port())
	binary.BigEndian.PutUint16(udp[4:], uint16(8+len(payload)))
	udp = append(udp, payload...)
	sum := checksum(from.Addr(), to.Addr(), syscall.IPPROTO_UDP, udp)
	if sum == 0 {
		// RFC 768 sends a computed zero as all ones, zero meaning no checksum
		sum = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:], sum)
	return ipPacket(from.Addr(), to.Addr(), syscall.IPPROTO_UDP, hops, udp)
}

// sized is a datagram from from to to whose packet is size bytes long
func sized(from, to netip.AddrPort, size int) []byte {
	header := 28
	if from.Addr().Is6() {
		header = 48
	}
	return datagram(from, to, leafTTL, bytes.Repeat([]byte{'m'}, size-header))
}

// echo is an echo request from src to dst under id, carrying data
func echo(src, dst netip.Addr, id uint16, data []byte) []byte {
	return query(src, dst, byte(ipv4.ICMPTypeEcho), byte(ipv6.ICMPTypeEchoRequest), id, data)
}

// query is an ICMP query from src to dst of type kind4 over IPv4 and kind6
// over IPv6, under id, carrying data
func query(src, dst netip.Addr, kind4, kind6 byte, id uint16, data []byte) []byte {
	message := make([]byte, 8, 8+len(data))
	binary.BigEndian.PutUint16(message[4:], id)
	binary.BigEndian.PutUint16(message[6:], 1)
	message = append(message, data...)
	if src.Is4() {
		message[0] = kind4
		binary.BigEndian.PutUint16(message[2:], ^uint16(packet.Sum(0, message)))
		return ipPacket(src, dst, syscall.IPPROTO_ICMP, leafTTL, message)
	}
	message[0] = kind6
	binary.BigEndian.PutUint16(message[2:], checksum(src, dst, syscall.IPPROTO_ICMPV6, message))
	return ipPacket(src, dst, syscall.IPPROTO_ICMPV6, leafTTL, message)
}

// icmpError is the error m from src to dst carrying quote, the start of the
// packet it answers
func icmpError(src, dst netip.Addr, m message, quote []byte) []byte {
	message := append(make([]byte, 8, 8+len(quote)), quote...)
	if src.Is4() {
		message[0], message[1] = m.kind4, m.code4
		binary.BigEndian.PutUint16(message[2:], ^uint16(packet.Sum(0, message)))
		return ipPacket(src, dst, syscall.IPPROTO_ICMP, leafTTL, message)
	}
	message[0], message[1] = m.kind6, m.code6
	binary.BigEndian.PutUint16(message[2:], checksum(src, dst, syscall.IPPROTO_ICMPV6, message))
	return ipPacket(src, dst, syscall.IPPROTO_ICMPV6, leafTTL, message)
}

// segment is a TCP segment from from to to with seq, ack and flags, carrying
// payload, in a header of RFC 9293 section 3.1 with no options
func segment(from, to netip.AddrPort, seq, ack uint32, flags byte, payload []byte) []byte {
	tcp := make([]byte, 20, 20+len(payload))
	binary.BigEndian.PutUint16(tcp[0:], from.Port())
	binary.BigEndian.PutUint16(tcp[2:], to.Port())
	binary.BigEndian.PutUint32(tcp[4:], seq)
	binary.BigEndian.PutUint32(tcp[8:], ack)
	tcp[12], tcp[13] = 5<<4, flags
	binary.BigEndian.PutUint16(tcp[14:], math.MaxUint16)
	tcp = append(tcp, payload...)
	binary.BigEndian.PutUint16(tcp[16:], checksum(from.Addr(), to.Addr(), syscall.IPPROTO_TCP, tcp))
	return ipPacket(from.Addr(), to.Addr(), syscall.IPPROTO_TCP, leafTTL, tcp)
}

// checksum is the checksum of segment, whose own checksum field reads zero,
// under the pseudo header of RFC 768 or of RFC 8200 section 8.1
func checksum(src, dst netip.Addr, protocol byte, segment []byte) uint16 {
	pseudo := slices.Concat(src.AsSlice(), dst.AsSlice())
	if src.Is4() {
		pseudo = binary.BigEndian.AppendUint16(append(pseudo, 0, protocol), uint16(len(segment)))
	} else {
		pseudo = append(binary.BigEndian.AppendUint32(pseudo, uint32(len(segment))), 0, 0, 0, protocol)
	}
	return ^uint16(packet.Sum(packet.Sum(0, pseudo), segment))
}

// parsed is an IP packet's addresses, its protocol and what it carries, the
// fixed header alone read for IPv6, since no packet of the rows carries an
// extension header
type parsed struct {
	src, dst netip.Addr
	protocol byte
	payload  []byte
}

func parse(raw []byte) (parsed, bool) {
	whole, version := packet.Payload(raw)
	switch version {
	case 4:
		return parsed{netip.AddrFrom4([4]byte(whole[12:16])), netip.AddrFrom4([4]byte(whole[16:20])), whole[9], whole[headerLength(whole):]}, true
	case 6:
		return parsed{netip.AddrFrom16([16]byte(whole[8:24])), netip.AddrFrom16([16]byte(whole[24:40])), whole[6], whole[40:]}, true
	}
	return parsed{}, false
}

// answer is an ICMP or ICMPv6 error toward the leaf: who sent it, its type and
// code, the MTU it carries and the start of the packet it answers
type answer struct {
	from       netip.Addr
	kind, code byte
	mtu        int
	quote      []byte
}

// readAnswer reads raw as an ICMP or ICMPv6 error
func readAnswer(raw []byte) (answer, bool) {
	p, ok := parse(raw)
	if !ok || len(p.payload) < 8 {
		return answer{}, false
	}
	a := answer{from: p.src, kind: p.payload[0], code: p.payload[1], quote: p.payload[8:]}
	switch {
	case p.protocol == syscall.IPPROTO_ICMP && (a.kind == byte(ipv4.ICMPTypeDestinationUnreachable) || a.kind == byte(ipv4.ICMPTypeTimeExceeded)):
		// RFC 1191 section 4 puts the next hop's MTU in the low half of the word after the checksum
		a.mtu = int(binary.BigEndian.Uint16(p.payload[6:]))
		return a, true
	case p.protocol == syscall.IPPROTO_ICMPV6 && a.kind < 128:
		// RFC 4443 section 2.1 numbers every error below 128, and section 3.2
		// puts Packet Too Big's MTU in the word after the checksum
		a.mtu = int(binary.BigEndian.Uint32(p.payload[4:]))
		return a, true
	}
	return answer{}, false
}

// is reports whether a is m in the family v6 says
func (a answer) is(v6 bool, m message) bool {
	if v6 {
		return a.kind == m.kind6 && a.code == m.code6
	}
	return a.kind == m.kind4 && a.code == m.code4
}

// quotes reports whether quote, the start of a packet an error carries back,
// holds what RFC 5508 REQ-4 a has a NAT put back of sent, and only that: the
// addresses, the protocol and the transport header, as much of it as the
// quote carries and at least the eight octets RFC 792 quotes
func quotes(quote, sent []byte) bool {
	q, okQuote := quoted(quote)
	s, okSent := quoted(sent)
	if !okQuote || !okSent || q.src != s.src || q.dst != s.dst || q.protocol != s.protocol {
		return false
	}
	n := min(len(q.payload), transportLength(s))
	return n >= 8 && len(s.payload) >= n && bytes.Equal(q.payload[:n], s.payload[:n])
}

// quoted is parse for the start of a packet, which a quote may cut short of
// the length its header gives
func quoted(raw []byte) (parsed, bool) {
	switch {
	case len(raw) >= 20 && raw[0]>>4 == 4 && headerLength(raw) >= 20 && len(raw) >= headerLength(raw):
		return parsed{netip.AddrFrom4([4]byte(raw[12:16])), netip.AddrFrom4([4]byte(raw[16:20])), raw[9], raw[headerLength(raw):]}, true
	case len(raw) >= 40 && raw[0]>>4 == 6:
		return parsed{netip.AddrFrom16([16]byte(raw[8:24])), netip.AddrFrom16([16]byte(raw[24:40])), raw[6], raw[40:]}, true
	}
	return parsed{}, false
}

func transportLength(p parsed) int {
	if p.protocol == syscall.IPPROTO_TCP && len(p.payload) > 12 {
		return int(p.payload[12]>>4) * 4
	}
	return 8
}

func headerLength(raw []byte) int {
	if raw[0]>>4 == 4 {
		return int(raw[0]&0x0f) * 4
	}
	return 40
}

func ports(quote []byte) (protocol byte, src, dst uint16, ok bool) {
	q, ok := quoted(quote)
	if !ok || len(q.payload) < 4 {
		return 0, 0, 0, false
	}
	return q.protocol, binary.BigEndian.Uint16(q.payload), binary.BigEndian.Uint16(q.payload[2:]), true
}

// withoutDF is the IPv4 packet raw with DF clear, which a router fragments
// where it would answer raw too big
func withoutDF(raw []byte) []byte {
	out := slices.Clone(raw)
	out[6] &^= 0x40
	out[10], out[11] = 0, 0
	binary.BigEndian.PutUint16(out[10:], ^uint16(packet.Sum(0, out[:headerLength(out)])))
	return out
}
