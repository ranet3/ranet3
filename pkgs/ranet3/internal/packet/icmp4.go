// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package packet

import (
	"encoding/binary"
	"math/bits"
	"net/netip"
)

// the ICMP errors of RFC 792 and RFC 1812 a router answers a packet it does not forward with
const (
	icmpProtocol = 1
	// icmpHeaderLen is the type, the code, the checksum and the four octets each message uses its own way
	icmpHeaderLen = 8
	// the error messages, which no ICMP error answers
	icmpUnreachable      = 3
	icmpSourceQuench     = 4
	icmpRedirect         = 5
	icmpTimeExceeded     = 11
	icmpParameterProblem = 12
	// the codes of destination unreachable, RFC 1812 section 5.2.7.1
	icmpNetUnreachable      = 0
	icmpHostUnreachable     = 1
	icmpFragmentationNeeded = 4
	icmpProhibited          = 13
	// icmpTTLExceeded is the code of time exceeded in transit
	icmpTTLExceeded = 0
	// maxErrorDatagram is the most an error comes to with its IP header, RFC 1812 section 4.3.2.3
	maxErrorDatagram = 576
	// internetControl is precedence 6, which RFC 1812 section 4.3.2.5 gives every ICMP error but source quench
	internetControl = 0xc0
	// typeOfService is the TOS field RFC 1349 puts between the precedence and the last bit, which section 4.3.2.5 has an error copy
	typeOfService = 0x1e
)

// LimitedBroadcast is { -1, -1 } of RFC 1812 section 4.2.2.11, which no router forwards, section 5.3.5.1
var LimitedBroadcast = netip.AddrFrom4([4]byte{255, 255, 255, 255})

// TimeExceeded answers an IPv4 packet whose TTL ran out in transit, RFC 1812 section 5.3.1, from source with ttl, and allow is icmpError's
func TimeExceeded(offending []byte, source netip.Addr, ttl uint8, allow func() bool) []byte {
	return icmpError(offending, source, ttl, icmpTimeExceeded, icmpTTLExceeded, 0, allow)
}

// NetUnreachable answers an IPv4 packet for a network no route reaches, RFC 1812 section 5.2.7.1 code 0, from source with ttl, and allow is icmpError's
func NetUnreachable(offending []byte, source netip.Addr, ttl uint8, allow func() bool) []byte {
	return icmpError(offending, source, ttl, icmpUnreachable, icmpNetUnreachable, 0, allow)
}

// HostUnreachable answers an IPv4 packet for a host no route reaches where other hosts of its network may be reachable
// RFC 1812 section 5.2.7.1 code 1, from source with ttl, and allow is icmpError's
func HostUnreachable(offending []byte, source netip.Addr, ttl uint8, allow func() bool) []byte {
	return icmpError(offending, source, ttl, icmpUnreachable, icmpHostUnreachable, 0, allow)
}

// Prohibited answers an IPv4 packet this node does not forward by its policy, RFC 1812 section 5.2.7.1 code 13, from source with ttl, and allow is icmpError's
func Prohibited(offending []byte, source netip.Addr, ttl uint8, allow func() bool) []byte {
	return icmpError(offending, source, ttl, icmpUnreachable, icmpProhibited, 0, allow)
}

// FragmentationNeeded answers an IPv4 packet with DF that is larger than the next link carries, RFC 1191 section 4
// mtu is that link's, carried as the next-hop MTU, source the address the answer comes from with ttl, and allow is icmpError's
func FragmentationNeeded(offending []byte, source netip.Addr, ttl uint8, mtu int, allow func() bool) []byte {
	return icmpError(offending, source, ttl, icmpUnreachable, icmpFragmentationNeeded, uint32(uint16(mtu)), allow)
}

// ParameterProblem answers an IPv4 packet whose header this node cannot read, RFC 1812 section 4.3.3.5, from source with ttl, and allow is icmpError's
// pointer names the octet at fault, counted from the header's first
func ParameterProblem(offending []byte, source netip.Addr, ttl uint8, pointer int, allow func() bool) []byte {
	return icmpError(offending, source, ttl, icmpParameterProblem, 0, uint32(pointer)<<24, allow)
}

// icmpError answers offending with one ICMP error of kind and code from source, rest being the second word of its header
// ttl is the fixed TTL RFC 1812 section 4.2.2.9 has be configurable, which a node takes from its host's default
// the answer quotes as much of the datagram as RFC 1812 section 4.3.2.3 lets it without passing 576 bytes
// it goes with DF, an atomic datagram, whose zero identification RFC 6864 allows
// it returns nil for anything but one whole IPv4 packet whose header HeaderValid passes, for a source that is not one host
// for a TTL of 0, which section 4.2.2.9 has no router originate, for a packet section 4.3.2.7 lets no error answer, and for one allow refuses
// allow is called once the packet is one an error may answer and before anything is built
func icmpError(offending []byte, source netip.Addr, ttl, kind, code byte, rest uint32, allow func() bool) []byte {
	if ttl == 0 || Version(offending) != 4 || !HeaderValid(offending) || !SingleHost(source) || !answerable(offending) || !allow() {
		return nil
	}
	quoted := min(len(offending), maxErrorDatagram-ipv4HeaderLen-icmpHeaderLen)
	out := make([]byte, ipv4HeaderLen+icmpHeaderLen+quoted)
	out[0] = 4<<4 | ipv4HeaderLen/4
	out[1] = internetControl | offending[1]&typeOfService
	binary.BigEndian.PutUint16(out[2:], uint16(len(out)))
	binary.BigEndian.PutUint16(out[6:], dontFragment)
	out[8] = ttl
	out[9] = icmpProtocol
	from := source.As4()
	copy(out[12:16], from[:])
	copy(out[16:20], offending[12:16])
	putHeaderChecksum(out[:ipv4HeaderLen])
	message := out[ipv4HeaderLen:]
	message[0], message[1] = kind, code
	binary.BigEndian.PutUint32(message[4:], rest)
	copy(message[icmpHeaderLen:], offending[:quoted])
	binary.BigEndian.PutUint16(message[2:], ^uint16(Sum(0, message)))
	return out
}

// answerable is RFC 1812 section 4.3.2.7, the rules that keep one packet from turning into many
// no error answers an ICMP error, a fragment but the first, a datagram whose source is not one host,
// or one sent to a multicast group or the limited broadcast, which every receiver would answer alike
func answerable(offending []byte) bool {
	if binary.BigEndian.Uint16(offending[6:8])&fragmentOffset != 0 {
		return false
	}
	destination := netip.AddrFrom4([4]byte(offending[16:20]))
	if !SingleHost(netip.AddrFrom4([4]byte(offending[12:16]))) || destination.IsMulticast() || destination == LimitedBroadcast {
		return false
	}
	headerLen := int(offending[0]&0x0f) * 4
	if offending[9] != icmpProtocol || len(offending) == headerLen {
		return true
	}
	switch offending[headerLen] {
	case icmpUnreachable, icmpSourceQuench, icmpRedirect, icmpTimeExceeded, icmpParameterProblem:
		return false
	}
	return true
}

// SingleHost reports whether an IPv4 address names one host, which a multicast group and the networks special names do not
// and so whether an ICMPv4 error may come from it
func SingleHost(address netip.Addr) bool {
	return address.Is4() && !address.IsMulticast() && !special(address)
}

// special reports whether an IPv4 address lies on this network, network 0, on loopback, network 127, or in class E, the limited broadcast with it
// which RFC 1122 section 3.2.1.3 and RFC 1812 section 5.3.7 give meanings other than one host
func special(address netip.Addr) bool {
	first := address.As4()[0]
	return first == 0 || first == 127 || first >= 240
}

// Sum adds the one's complement sum of b, RFC 1071, to carrying and folds the carries back in
// an odd length counts a zero byte after the last, and only the last part of a sum may have one
// an IP checksum is the complement of the sum over what it covers
func Sum(carrying uint32, b []byte) uint32 {
	for i := 0; i+1 < len(b); i += 2 {
		carrying += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		carrying += uint32(b[len(b)-1]) << 8
	}
	for carrying>>16 != 0 {
		carrying = carrying&0xffff + carrying>>16
	}
	return carrying
}

// putHeaderChecksum writes the checksum of header, a whole IPv4 header, over what its checksum field held
func putHeaderChecksum(header []byte) {
	binary.BigEndian.PutUint16(header[10:], 0)
	binary.BigEndian.PutUint16(header[10:], ^uint16(Sum(0, header)))
}

// AdjustChecksum is checksum once a 16 bit field it covers moved from one value to another, RFC 1624 section 3's equation 3
// whose sum of three 16 bit words two folds bring under 16 bits
// a field at an odd offset straddles two of the 16 bit words the checksum adds up, which take its bytes swapped
func AdjustChecksum(checksum, from, to uint16, odd bool) uint16 {
	if odd {
		from, to = bits.ReverseBytes16(from), bits.ReverseBytes16(to)
	}
	sum := uint32(^checksum) + uint32(^from) + uint32(to)
	sum = sum&0xffff + sum>>16
	sum = sum&0xffff + sum>>16
	return ^uint16(sum)
}
