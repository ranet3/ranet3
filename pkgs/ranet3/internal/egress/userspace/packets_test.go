// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package userspace

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// The tests' packets, written byte by byte so they share no code with what
// they test. The addresses are the documentation ranges'.
var (
	leaf4   = netip.MustParseAddr("192.0.2.2")
	server4 = netip.MustParseAddr("203.0.113.5")
	other4  = netip.MustParseAddr("198.51.100.7")
	leaf6   = netip.MustParseAddr("2001:db8:1::2")
	server6 = netip.MustParseAddr("2001:db8:3::5")
	other6  = netip.MustParseAddr("2001:db8:4::7")
)

const (
	protoICMP   = 1
	protoTCP    = 6
	protoUDP    = 17
	protoICMPv6 = 58
	// protoUncarried is a protocol number for experiments, RFC 3692, which
	// the exit carries no flow of
	protoUncarried = 253
	// ipv6Fragment and ipv6DestinationOptions are IPv6 extension headers
	ipv6Fragment           = 44
	ipv6DestinationOptions = 60

	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpRST = 0x04
	tcpPSH = 0x08
	tcpACK = 0x10
)

// sum adds b to the internet checksum's running sum, RFC 1071
func sum(running uint32, b []byte) uint32 {
	for i := 0; i+1 < len(b); i += 2 {
		running += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		running += uint32(b[len(b)-1]) << 8
	}
	return running
}

// fold is the checksum a running sum makes
func fold(running uint32) uint16 {
	for running>>16 != 0 {
		running = running&0xffff + running>>16
	}
	return ^uint16(running)
}

// pseudo is the running sum of the pseudo header of a transport message of
// length bytes from src to dst
func pseudo(src, dst netip.Addr, protocol byte, length int) uint32 {
	running := sum(sum(0, src.AsSlice()), dst.AsSlice())
	return running + uint32(protocol) + uint32(length)
}

// ip4 is an IPv4 packet with a header of 20 bytes, its checksum set. fragment
// is the flags and offset field.
func ip4(src, dst netip.Addr, protocol byte, id, fragment uint16, ttl byte, payload []byte) []byte {
	b := make([]byte, 20+len(payload))
	b[0] = 4<<4 | 5
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	binary.BigEndian.PutUint16(b[4:6], id)
	binary.BigEndian.PutUint16(b[6:8], fragment)
	b[8], b[9] = ttl, protocol
	copy(b[12:16], src.AsSlice())
	copy(b[16:20], dst.AsSlice())
	binary.BigEndian.PutUint16(b[10:12], fold(sum(0, b[:20])))
	copy(b[20:], payload)
	return b
}

// ip6 is an IPv6 packet whose first next header is next
func ip6(src, dst netip.Addr, next, hops byte, payload []byte) []byte {
	b := make([]byte, 40+len(payload))
	b[0] = 6 << 4
	binary.BigEndian.PutUint16(b[4:6], uint16(len(payload)))
	b[6], b[7] = next, hops
	copy(b[8:24], src.AsSlice())
	copy(b[24:40], dst.AsSlice())
	copy(b[40:], payload)
	return b
}

// ipPacket is an unfragmented packet of src's family, with a TTL or hop limit
// of 64
func ipPacket(src, dst netip.Addr, protocol byte, payload []byte) []byte {
	if src.Is4() {
		return ip4(src, dst, protocol, 1, 0, 64, payload)
	}
	return ip6(src, dst, protocol, 64, payload)
}

// fragments cuts payload, a transport message of protocol, into fragments of
// at most size bytes of it each, a multiple of 8 but the last
func fragments(src, dst netip.Addr, protocol byte, id uint16, payload []byte, size int) [][]byte {
	var out [][]byte
	for offset := 0; offset < len(payload); offset += size {
		end := min(offset+size, len(payload))
		more := uint16(0)
		if end < len(payload) {
			more = 1
		}
		if src.Is4() {
			out = append(out, ip4(src, dst, protocol, id, more<<13|uint16(offset/8), 64, payload[offset:end]))
			continue
		}
		header := make([]byte, 8)
		header[0] = protocol
		binary.BigEndian.PutUint16(header[2:4], uint16(offset)|more)
		binary.BigEndian.PutUint32(header[4:8], uint32(id))
		out = append(out, ip6(src, dst, ipv6Fragment, 64, append(header, payload[offset:end]...)))
	}
	return out
}

// tcpSegment is an IP packet holding a TCP segment with no option, its
// checksum set
func tcpSegment(src, dst netip.AddrPort, seq, ack uint32, flags byte, payload []byte) []byte {
	b := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(b[0:2], src.Port())
	binary.BigEndian.PutUint16(b[2:4], dst.Port())
	binary.BigEndian.PutUint32(b[4:8], seq)
	binary.BigEndian.PutUint32(b[8:12], ack)
	b[12], b[13] = 5<<4, flags
	binary.BigEndian.PutUint16(b[14:16], 65535)
	copy(b[20:], payload)
	binary.BigEndian.PutUint16(b[16:18], fold(sum(pseudo(src.Addr(), dst.Addr(), protoTCP, len(b)), b)))
	return ipPacket(src.Addr(), dst.Addr(), protoTCP, b)
}

// echoRequest is an ICMP or ICMPv6 echo request from src to dst, its checksum
// set, unwrapped
func echoRequest(src, dst netip.Addr, id, seq uint16, payload []byte) []byte {
	b := make([]byte, 8+len(payload))
	b[0] = 8
	if src.Is6() {
		b[0] = 128
	}
	binary.BigEndian.PutUint16(b[4:6], id)
	binary.BigEndian.PutUint16(b[6:8], seq)
	copy(b[8:], payload)
	running := sum(0, b)
	if src.Is6() {
		running += pseudo(src, dst, protoICMPv6, len(b))
	}
	binary.BigEndian.PutUint16(b[2:4], fold(running))
	return b
}

// icmpProtocol is the ICMP protocol of address's family
func icmpProtocol(address netip.Addr) byte {
	if address.Is4() {
		return protoICMP
	}
	return protoICMPv6
}

// sent is one packet as a test reads it
type sent struct {
	src, dst         netip.Addr
	protocol         byte
	srcPort, dstPort uint16
	// seq, ack and flags are a TCP segment's, and kind and code an ICMP
	// message's
	seq, ack   uint32
	flags      byte
	kind, code byte
	payload    int
}

// parse reads raw, one IPv4 or IPv6 packet with no extension header
func parse(raw []byte) (sent, bool) {
	var p sent
	var body []byte
	switch {
	case len(raw) >= 20 && raw[0]>>4 == 4:
		header := int(raw[0]&0x0f) * 4
		if len(raw) < header {
			return p, false
		}
		p.src, p.dst = netip.AddrFrom4([4]byte(raw[12:16])), netip.AddrFrom4([4]byte(raw[16:20]))
		p.protocol, body = raw[9], raw[header:]
	case len(raw) >= 40 && raw[0]>>4 == 6:
		p.src, p.dst = netip.AddrFrom16([16]byte(raw[8:24])), netip.AddrFrom16([16]byte(raw[24:40]))
		p.protocol, body = raw[6], raw[40:]
	default:
		return p, false
	}
	switch p.protocol {
	case protoTCP:
		if len(body) < 20 {
			return p, false
		}
		p.srcPort, p.dstPort = binary.BigEndian.Uint16(body[0:2]), binary.BigEndian.Uint16(body[2:4])
		p.seq, p.ack = binary.BigEndian.Uint32(body[4:8]), binary.BigEndian.Uint32(body[8:12])
		p.flags, p.payload = body[13], len(body)-int(body[12]>>4)*4
	case protoUDP:
		if len(body) < 8 {
			return p, false
		}
		p.srcPort, p.dstPort, p.payload = binary.BigEndian.Uint16(body[0:2]), binary.BigEndian.Uint16(body[2:4]), len(body)-8
	case protoICMP, protoICMPv6:
		if len(body) < 8 {
			return p, false
		}
		p.kind, p.code, p.payload = body[0], body[1], len(body)-8
	}
	return p, true
}

func (p sent) String() string {
	switch p.protocol {
	case protoTCP:
		return fmt.Sprintf("tcp %s > %s flags %#02x payload %d", netip.AddrPortFrom(p.src, p.srcPort), netip.AddrPortFrom(p.dst, p.dstPort), p.flags, p.payload)
	case protoUDP:
		return fmt.Sprintf("udp %s > %s payload %d", netip.AddrPortFrom(p.src, p.srcPort), netip.AddrPortFrom(p.dst, p.dstPort), p.payload)
	case protoICMP, protoICMPv6:
		return fmt.Sprintf("icmp %s > %s type %d code %d", p.src, p.dst, p.kind, p.code)
	}
	return fmt.Sprintf("protocol %d %s > %s", p.protocol, p.src, p.dst)
}
