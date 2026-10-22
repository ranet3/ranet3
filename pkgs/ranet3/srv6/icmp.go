// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package srv6

import (
	"encoding/binary"
	"net/netip"

	"ranet3.com/pkgs/ranet3/internal/packet"
)

// This file builds the ICMPv6 errors RFC 8986's pseudocode answers a refused
// packet with, rather than dropping it in silence. It takes bytes and returns
// bytes like the rest of the package: whether an answer is sent at all, and
// how often, is the dataplane's to decide.
//
// Without these a converted waypoint is invisible to traceroute, where a node
// still running seg6local answers through ip6_forward, so a fleet migrating
// node by node loses the tool it debugs paths with one node at a time.

const (
	// icmpv6Next is the protocol number of the header these messages carry.
	icmpv6Next = 58
	// The two messages RFC 8986 calls for, RFC 4443 sections 3.3 and 3.4, each
	// with the one code this node uses.
	icmpTimeExceeded     = 3
	icmpHopLimitInTranst = 0
	icmpParameterProblem = 4
	icmpErroneousHeader  = 0
	// icmpPacketTooBig is RFC 4443 section 3.2, whose one code is 0 and whose four octets carry the MTU
	icmpPacketTooBig = 2
	// icmpRedirect is RFC 4861 section 4.5, informational by its type and still one RFC 4443 section 2.4 (e.2) lets no error answer
	icmpRedirect = 137
	// icmpHeaderLen is the type, the code, the checksum and the four octets
	// the three messages use differently.
	icmpHeaderLen = 8
	// segmentsLeftInHeader is where Segments Left sits inside a routing header,
	// which findRouting says where to find.
	segmentsLeftInHeader = 3
)

// TimeExceeded answers a packet whose hop limit ran out at this node, RFC 4443
// section 3.3. source is the segment the packet was addressed to, which is the
// address a router answers an expired packet from. allow is icmpError's.
func TimeExceeded(offending []byte, source netip.Addr, allow func() bool) []byte {
	return icmpError(offending, source, icmpTimeExceeded, icmpHopLimitInTranst, 0, allow)
}

// ParameterProblem answers a routing header this node will not act on, RFC
// 4443 section 3.4, pointing at the Segments Left field that RFC 8986 section
// 4.1 S10 names. allow is icmpError's.
func ParameterProblem(offending []byte, source netip.Addr, allow func() bool) []byte {
	if len(offending) < ipv6HeaderLen {
		return nil
	}
	// The pointer names a field, so a packet whose routing header cannot be
	// found is one this answer has nothing to point at.
	offset, err := findRouting(offending)
	if err != nil {
		return nil
	}
	return icmpError(offending, source, icmpParameterProblem, icmpErroneousHeader, uint32(offset+segmentsLeftInHeader), allow)
}

// PacketTooBig answers a packet larger than the next link carries, RFC 4443 section 3.2, with that link's mtu
// source is the address the answer comes from, and allow is icmpError's
func PacketTooBig(offending []byte, source netip.Addr, mtu int, allow func() bool) []byte {
	return icmpError(offending, source, icmpPacketTooBig, 0, uint32(mtu), allow)
}

// icmpError builds one message carrying as much of the offending packet as
// fits, RFC 4443 section 3.3: enough that the whole reply stays inside the
// IPv6 minimum MTU, so it reaches the sender without fragmenting.
//
// It returns nil for a packet no error may answer, which keeps one message
// from becoming many, and for one allow refuses. allow is called once the
// packet is one an error may answer and before anything is built.
func icmpError(offending []byte, source netip.Addr, kind, code uint8, pointer uint32, allow func() bool) []byte {
	if !Usable(source) || !answerable(offending) || !allow() {
		return nil
	}
	destination := netip.AddrFrom16([16]byte(offending[8:24]))
	quoted := min(len(offending), MinimumIPv6MTU-ipv6HeaderLen-icmpHeaderLen)
	body := make([]byte, icmpHeaderLen+quoted)
	body[0], body[1] = kind, code
	binary.BigEndian.PutUint32(body[4:], pointer)
	copy(body[icmpHeaderLen:], offending[:quoted])

	out := make([]byte, ipv6HeaderLen+len(body))
	out[0] = 0x60
	binary.BigEndian.PutUint16(out[4:], uint16(len(body)))
	out[6] = icmpv6Next
	out[7] = DefaultHopLimit
	copy(out[8:], addr16(source))
	copy(out[24:], addr16(destination))
	copy(out[ipv6HeaderLen:], body)
	binary.BigEndian.PutUint16(out[ipv6HeaderLen+2:], icmpChecksum(source, destination, body))
	return out
}

// answerable is RFC 4443 section 2.4 (e): the rules that stop one refused
// packet turning into many. An ICMPv6 error may not answer another or a
// redirect, and it may not answer anything addressed to or sent from more than
// one interface, since every receiver would answer the same packet.
//
// Packet Too Big refuses a multicast destination as well, departing from the
// first exception of (e.3), since the dataplane answers from the packet's
// destination, which for a group is no address an answer may come from, and
// the mesh routes no multicast.
//
// The link-layer cases (e.4) and (e.5) cannot arise, because every packet
// reaching here was read off the tun or decrypted out of a unicast ESP session
// with one peer, and neither has a link layer.
func answerable(offending []byte) bool {
	if len(offending) < ipv6HeaderLen || offending[0]>>4 != 6 {
		return false
	}
	from := netip.AddrFrom16([16]byte(offending[8:24]))
	to := netip.AddrFrom16([16]byte(offending[24:40]))
	if from.IsUnspecified() || from.IsMulticast() || to.IsMulticast() {
		return false
	}
	return !carriesUnanswerable(offending)
}

// carriesUnanswerable reports whether offending is an ICMPv6 error or a redirect, which RFC 4443 section 2.4 (e.1) and (e.2) let no error answer
// the walk steps over each extension header in any order but ESP, which hides what follows it, and a fragment other than the first, which holds no upper-layer header, as the kernel's ipv6_skip_exthdr does
// the upper-layer header is the last of the maxExtensionHeaders headers it reads, so an error behind maxExtensionHeaders extension headers or more is answered, departing from (e.1)
// since refusing at the bound would withhold the answers RFC 4443 sections 3.2 and 3.3 require from a packet not shown to be an error
// an ICMPv6 header cut short before its type counts as an error, as the kernel's is_ineligible reads one, and every other end of the walk shows none
func carriesUnanswerable(offending []byte) bool {
	next, offset := offending[6], ipv6HeaderLen
	for range maxExtensionHeaders {
		switch next {
		case icmpv6Next:
			// a type below 128 is an error message, RFC 4443 section 2.1
			return len(offending) <= offset || offending[offset] < 128 || offending[offset] == icmpRedirect
		case nextHeaderFragment:
			// the fragment offset is the field's top 13 bits, RFC 8200 section 4.5
			if len(offending) < offset+4 || binary.BigEndian.Uint16(offending[offset+2:])>>3 != 0 {
				return false
			}
		case nextHeaderHopByHop, nextHeaderRouting, nextHeaderDestOpts, nextHeaderAuth:
		default:
			return false
		}
		var ok bool
		if next, offset, ok = stepExtension(offending, next, offset); !ok {
			return false
		}
	}
	return false
}

// icmpChecksum is the RFC 4443 section 2.3 checksum over the pseudo-header of
// RFC 8200 section 8.1 and the message.
func icmpChecksum(source, destination netip.Addr, body []byte) uint16 {
	var pseudo [40]byte
	copy(pseudo[0:], addr16(source))
	copy(pseudo[16:], addr16(destination))
	binary.BigEndian.PutUint32(pseudo[32:], uint32(len(body)))
	pseudo[39] = icmpv6Next

	return ^uint16(packet.Sum(packet.Sum(0, pseudo[:]), body))
}
