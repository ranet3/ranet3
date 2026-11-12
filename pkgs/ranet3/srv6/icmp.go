// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package srv6

import (
	"encoding/binary"
	"net/netip"

	"ranet3.com/pkgs/ranet3/internal/packet"
)

// This file builds the ICMPv6 errors a router answers a packet it does not
// forward with, among them those RFC 8986's pseudocode answers a refused
// segment with, rather than dropping it in silence. It takes bytes and returns
// bytes like the rest of the package: whether an answer is sent at all, and
// how often, is the dataplane's to decide.
//
// Without these a converted waypoint is invisible to traceroute, where a node
// still running seg6local answers through ip6_forward, so a fleet migrating
// node by node loses the tool it debugs paths with one node at a time.

const (
	// icmpv6Next is the protocol number of the header these messages carry.
	icmpv6Next = 58
	// The two messages RFC 8986 calls for, RFC 4443 sections 3.3 and 3.4, with
	// the codes this node uses: Parameter Problem's erroneous header field and
	// unrecognized Next Header type, RFC 8986 section 4.1.1's SR upper-layer
	// header error, and the extension header too big and too many extension
	// headers RFC 8883 sections 2.3 and 2.5 answer a processing limit with.
	icmpTimeExceeded      = 3
	icmpHopLimitInTransit = 0
	icmpParameterProblem  = 4
	icmpErroneousHeader   = 0
	icmpUnrecognizedNext  = 1
	icmpUpperLayer        = 4
	icmpHeaderTooBig      = 6
	icmpTooManyHeaders    = 8
	// icmpPacketTooBig is RFC 4443 section 3.2, whose one code is 0 and whose four octets carry the MTU
	icmpPacketTooBig = 2
	// icmpRedirect is RFC 4861 section 4.5, informational by its type and still one RFC 4443 section 2.4 (e.2) lets no error answer
	icmpRedirect = 137
	// icmpUnreachable is RFC 4443 section 3.1, with the three codes a router forwarding a packet answers with
	icmpUnreachable = 1
	icmpNoRoute     = 0
	icmpProhibited  = 1
	icmpBeyondScope = 2
	// icmpHeaderLen is the type, the code, the checksum and the four octets
	// each message uses its own way.
	icmpHeaderLen = 8
)

// TimeExceeded answers a packet whose hop limit ran out at this node, RFC 4443
// section 3.3, from source. allow is icmpError's.
func TimeExceeded(offending []byte, source netip.Addr, allow func() bool) []byte {
	return icmpError(offending, source, icmpTimeExceeded, icmpHopLimitInTransit, 0, allow)
}

// ParameterProblem answers a header field this node will not act on, RFC 4443
// section 3.4, with the code and the pointer refusal names, from source. allow
// is icmpError's.
//
// A refusal of RFC 8883 section 2.5's code 8 lies past the headers the error
// search of every answer steps past, so its own search steps past as many as
// maxEdgeHeaders. It is answered where that search ends within them, at any
// end searchError names, without finding an ICMPv6 error or a Redirect, and
// dropped where the search ends unfinished or finds one, by RFC 4443 section
// 2.4 (e.1) and (e.2).
func ParameterProblem(offending []byte, source netip.Addr, refusal *Refusal, allow func() bool) []byte {
	if refusal.Code == icmpTooManyHeaders && len(offending) >= ipv6HeaderLen {
		if unanswerable, reached := searchError(offending, maxEdgeHeaders); unanswerable || !reached {
			return nil
		}
	}
	return icmpError(offending, source, icmpParameterProblem, refusal.Code, uint32(refusal.Pointer), allow)
}

// PacketTooBig answers a packet larger than the next link carries, RFC 4443 section 3.2, with that link's mtu
// source is the address the answer comes from, and allow is icmpError's
func PacketTooBig(offending []byte, source netip.Addr, mtu int, allow func() bool) []byte {
	return icmpError(offending, source, icmpPacketTooBig, 0, uint32(mtu), allow)
}

// NoRoute answers a packet no entry of the forwarding table carries, RFC 4443 section 3.1 code 0, from source, and allow is icmpError's
func NoRoute(offending []byte, source netip.Addr, allow func() bool) []byte {
	return icmpError(offending, source, icmpUnreachable, icmpNoRoute, 0, allow)
}

// Prohibited answers a packet this node does not forward by its policy, RFC 4443 section 3.1 code 1, from source, and allow is icmpError's
func Prohibited(offending []byte, source netip.Addr, allow func() bool) []byte {
	return icmpError(offending, source, icmpUnreachable, icmpProhibited, 0, allow)
}

// Unreachable answers a packet with destination unreachable of code, any of RFC 4443 section 3.1's, from source at the hop limit hops
// an exit relaying a server's or a router's error to the leaf it is about sends it from that offender with the offender's code, and allow is icmpError's
func Unreachable(offending []byte, source netip.Addr, hops, code uint8, allow func() bool) []byte {
	return withHopLimit(icmpError(offending, source, icmpUnreachable, code, 0, allow), hops)
}

// Relayed is an ICMPv6 error of kind and code from source at the hop limit hops quoting quote, rest being the four octets after its checksum
// quote is a packet's header and the part of what followed it the error carries, whose payload length may claim more than quote holds
// as RFC 4443 section 2.4 (c)'s quote of a long packet does: an exit relaying a server's or a router's error about a leaf's packet quotes it so
// it returns nil where icmpError would, the error held within the minimum MTU as icmpError holds it
func Relayed(quote []byte, source netip.Addr, hops, kind, code uint8, rest uint32) []byte {
	return withHopLimit(icmpError(quote, source, kind, code, rest, func() bool { return true }), hops)
}

// withHopLimit sets out's hop limit to hops where out is a packet, which no checksum covers
func withHopLimit(out []byte, hops uint8) []byte {
	if out != nil {
		out[7] = hops
	}
	return out
}

// BeyondScope answers a packet whose destination lies past the scope of its source, RFC 4443 section 3.1 code 2, from source, and allow is icmpError's
// a link-local source with a wider destination, which no router forwards off its link
func BeyondScope(offending []byte, source netip.Addr, allow func() bool) []byte {
	return icmpError(offending, source, icmpUnreachable, icmpBeyondScope, 0, allow)
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
// its search steps past as many extension headers as walk does, so it reads every header a SID acts on
// and an error behind more is answered, departing from (e.1), since refusing at the bound would withhold the answers RFC 4443 sections 3.2 and 3.3 require from a packet not shown to be an error
func carriesUnanswerable(offending []byte) bool {
	unanswerable, _ := searchError(offending, maxExtensionHeaders)
	return unanswerable
}

// searchError steps through the extension headers of offending, past at most steps of them, to its upper-layer header
// it reports whether that header is an ICMPv6 error or a redirect, and whether the search reached it
// it steps past each extension header in any order but ESP, which hides what follows it, and a fragment other than the first, which holds no upper-layer header, as the kernel's ipv6_skip_exthdr does
// an ICMPv6 header cut short before its type counts as an error, as the kernel's is_ineligible reads one, and every other end of the search shows none
func searchError(offending []byte, steps int) (unanswerable, reached bool) {
	next, offset := offending[6], ipv6HeaderLen
	for stepped := 0; ; stepped++ {
		switch next {
		case icmpv6Next:
			// a type below 128 is an error message, RFC 4443 section 2.1
			return len(offending) <= offset || offending[offset] < 128 || offending[offset] == icmpRedirect, true
		case nextHeaderFragment:
			// the fragment offset is the field's top 13 bits, RFC 8200 section 4.5
			if len(offending) < offset+4 || binary.BigEndian.Uint16(offending[offset+2:])>>3 != 0 {
				return false, true
			}
		}
		step, following, end := stepHeader(offending, next, offset)
		switch {
		case step == stepUpper:
			return false, true
		case stepped == steps:
			return false, false
		case step == stepShort:
			return false, true
		case step == stepLong:
			// the header following starts past the packet's end, an ICMPv6 header among them cut short before its type
			return following == icmpv6Next, true
		}
		next, offset = following, end
	}
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
