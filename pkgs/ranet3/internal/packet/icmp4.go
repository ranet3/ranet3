// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package packet

import (
	"encoding/binary"
	"net/netip"
)

// the ICMP of RFC 792 that answers an IPv4 packet with DF too large for the next link
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
	// icmpFragmentationNeeded is the code of destination unreachable for a datagram DF kept whole
	icmpFragmentationNeeded = 4
	// quotedData is the 64 bits of the offending datagram's data an error quotes after its header
	quotedData = 8
	// internetControl is precedence 6, which RFC 1812 section 4.3.2.5 gives every ICMP error but source quench
	internetControl = 0xc0
	// defaultTTL is the time to live RFC 1700 recommends
	defaultTTL = 64
)

// FragmentationNeeded answers an IPv4 packet with DF that is larger than the next link carries, RFC 1191 section 4
// mtu is that link's, carried as the next-hop MTU, and source the address the answer comes from
// the answer quotes the packet's header and the first 8 bytes of its data
// it goes with DF, an atomic datagram, whose zero identification RFC 6864 allows
// it reports false for anything but one whole IPv4 packet, for a source that is not one host
// and for a packet RFC 1122 section 3.2.2 lets no error answer
func FragmentationNeeded(offending []byte, source netip.Addr, mtu int) ([]byte, bool) {
	if Version(offending) != 4 || !singleHost(source) || !answerable(offending) {
		return nil, false
	}
	headerLen := int(offending[0]&0x0f) * 4
	quoted := min(len(offending), headerLen+quotedData)
	out := make([]byte, ipv4HeaderLen+icmpHeaderLen+quoted)
	out[0] = 4<<4 | ipv4HeaderLen/4
	out[1] = internetControl
	binary.BigEndian.PutUint16(out[2:], uint16(len(out)))
	binary.BigEndian.PutUint16(out[6:], dontFragment)
	out[8] = defaultTTL
	out[9] = icmpProtocol
	from := source.As4()
	copy(out[12:16], from[:])
	copy(out[16:20], offending[12:16])
	binary.BigEndian.PutUint16(out[10:], ^uint16(Sum(0, out[:ipv4HeaderLen])))
	message := out[ipv4HeaderLen:]
	message[0], message[1] = icmpUnreachable, icmpFragmentationNeeded
	binary.BigEndian.PutUint16(message[6:], uint16(mtu))
	copy(message[icmpHeaderLen:], offending[:quoted])
	binary.BigEndian.PutUint16(message[2:], ^uint16(Sum(0, message)))
	return out, true
}

// answerable is RFC 1122 section 3.2.2, the rules that keep one packet from turning into many
// no error answers an ICMP error, a fragment but the first, a datagram whose source is not one host,
// or one sent to a multicast group or the limited broadcast, which every receiver would answer alike
func answerable(offending []byte) bool {
	if binary.BigEndian.Uint16(offending[6:8])&fragmentOffset != 0 {
		return false
	}
	destination := netip.AddrFrom4([4]byte(offending[16:20]))
	if !singleHost(netip.AddrFrom4([4]byte(offending[12:16]))) || destination.IsMulticast() || destination.As4() == [4]byte{255, 255, 255, 255} {
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

// singleHost reports whether an IPv4 address names one host
// RFC 1122 section 3.2.1.3 gives this network, loopback, multicast and class E, the limited broadcast with it, other meanings
func singleHost(address netip.Addr) bool {
	if !address.Is4() {
		return false
	}
	first := address.As4()[0]
	return first != 0 && !address.IsLoopback() && !address.IsMulticast() && first < 240
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
