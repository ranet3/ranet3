// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

// Package srv6 implements segment routing over IPv6 in userspace: the routing
// header of [RFC 8754], H.Encaps of [RFC 8986] section 5.1, and the two
// endpoint behaviors a mesh needs, End, a waypoint that forwards to the next
// segment, and End.DT46, an exit that strips the outer header and delivers
// what was inside.
//
// Nothing here touches a socket, a route table or a kernel. Every entry point
// takes bytes and returns bytes, so a process that already carries the packet
// acts on the header itself, identically on every platform and under a test
// that needs no privileges. That is the reason to reach for this rather than
// linux's seg6local: darwin has no segment routing at all, and a
// NEPacketTunnelProvider or a VpnService is handed a tun and a list of routes
// and never sees a forwarding table.
//
// # What a caller uses
//
// Four entry points, one per direction a packet takes.
//
//   - Sending. [AppendEncapsulated] appends an inner packet behind an outer
//     IPv6 header and a routing header to a buffer the caller owns, and
//     [Encapsulate] returns the same bytes in a buffer of their own.
//     [Overhead] sizes the result beforehand and [CheckPath] refuses a path
//     before anything is built from it.
//   - Receiving, for a segment this node answers for. [NewLocalTable] takes
//     the [Segment] list and the overlay every SID admits an outer source
//     from, and [LocalTable.Handle] returns a [Result] saying whether to pass
//     the packet on untouched, forward it to the [Result.Next] segment,
//     deliver the [Result.Inner] packet to the mesh or out of it to egress,
//     or drop it. [End] and [Decap] are End and End.DT46 on their own.
//   - Choosing. [NewSteerTable] takes the [Steer] list and [SteerTable.Lookup]
//     answers which [Policy], if any, one of this node's own packets takes.
//   - Entering. [WalkEdge] reads a packet entering the domain from outside it
//     for a routing header the domain's edge refuses, and [LocalTable.Holds]
//     names a SID of this node's.
//
// A nil [LocalTable] or [SteerTable] answers for nothing rather than panicking,
// which is the node configuring no segment routing, so a caller never has to
// ask first.
//
// [Segments] is the serialized form of both tables together, carrying yaml,
// json and toml tags and validating itself, and [Segments.Tables] builds the
// pair from it. Its scalars come from
// [ranet3.com/pkgs/ranet3/schema].
//
// [TimeExceeded] and [ParameterProblem] build the ICMPv6 errors RFC 8986's
// pseudocode answers a refused packet with, which is how a waypoint stays
// visible to traceroute.
// [ParameterProblem] takes its code and pointer from the [Refusal] an
// [End] or a [Decap] returns. Whether such an answer is sent, and how often,
// stays with the caller.
//
// # What it does not read
//
// [End] and [Decap] read no option of a hop-by-hop or destination options
// header. A fragment of a larger packet is dropped rather than reassembled.
//
// [RFC 8754]: https://www.rfc-editor.org/rfc/rfc8754
// [RFC 8986]: https://www.rfc-editor.org/rfc/rfc8986
package srv6

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"slices"
)

const (
	// ipv6HeaderLen is the fixed IPv6 header, RFC 8200 section 3, and
	// ipv4HeaderLen the shortest IPv4 one, RFC 791 section 3.1.
	ipv6HeaderLen = 40
	ipv4HeaderLen = 20
	// srhFixedLen is the routing header before its first segment.
	srhFixedLen = 8
	// addrLen is one segment.
	addrLen = 16

	// Next Header values, from the IANA protocol registry. Routing is the
	// SRH's own, and the two below it announce an encapsulated inner packet.
	nextHeaderRouting = 43
	// The kinds RFC 8200 section 4.1's order puts ahead of a routing header,
	// and the fragment header, whose packet walk proceeds past only as an
	// atomic fragment.
	nextHeaderHopByHop = 0
	nextHeaderDestOpts = 60
	nextHeaderFragment = 44
	extensionUnit      = 8
	// maxExtensionHeaders bounds the extension headers walk and carriesUnanswerable step past in one packet, so a sender sets no cost per packet past it
	maxExtensionHeaders = 8
	// maxEdgeHeaders bounds the extension headers WalkEdge steps past in a packet entering the mesh, and the error search of a packet walk refuses past maxExtensionHeaders
	// it is at least maxExtensionHeaders, so the edge steps past every header a SID's walk does
	maxEdgeHeaders = 16
	// nextHeaderAuth is the authentication header of RFC 4302, which may sit
	// between the routing header and the upper-layer header.
	nextHeaderAuth = 51
	// The extension headers of the IANA registry RFC 8200 section 4 points to
	// that walk does not process: Mobility, HIP, Shim6, and the two of RFC 3692
	// for experiments. ESP is not among them: End and End.DT46 do not process
	// it either, and walk returns it as the upper-layer header.
	nextHeaderMobility = 135
	nextHeaderHIP      = 139
	nextHeaderShim6    = 140
	nextHeaderTesting1 = 253
	nextHeaderTesting2 = 254
	// The fields a refusal points at: the IPv6 header's Payload Length and Next
	// Header, RFC 8200 section 3, and a routing header's Routing Type, Segments
	// Left and Last Entry, RFC 8754 section 2.
	payloadLengthInIPv6  = 4
	nextHeaderInIPv6     = 6
	routingTypeInHeader  = 2
	segmentsLeftInHeader = 3
	lastEntryInHeader    = 4
	// NextHeaderIPv4 and NextHeaderIPv6 name what H.Encaps put inside, which
	// an End.DT46 has to read to know which stack to deliver to.
	NextHeaderIPv4 = 4
	NextHeaderIPv6 = 41

	// routingTypeSegment is Routing Type 4, the SRH, RFC 8754 section 2.
	routingTypeSegment = 4

	// MinimumIPv6MTU is RFC 8200 section 5: "IPv6 requires that every link in
	// the Internet have an MTU of 1280 octets or greater." A device steering
	// through a list is refused below it, and an ICMP error stays inside it so
	// it reaches the sender without fragmenting.
	MinimumIPv6MTU = 1280

	// MaxSegments bounds a segment list this node builds or acts on, so the
	// 16 bytes each segment puts in front of every packet are this node's
	// choice rather than a peer's.
	MaxSegments = 16
)

var (
	// ErrNotSegmentRouted is returned for a packet with no SRH, which is the
	// ordinary case on a mesh where most traffic is not steered.
	ErrNotSegmentRouted = errors.New("srv6: packet carries no segment routing header")
	// ErrHopLimit is the refusal RFC 8986 section 4.1 S06 answers with a Time
	// Exceeded, which TimeExceeded builds.
	ErrHopLimit = errors.New("srv6: the hop limit reached zero at this waypoint")
	// errFragment is a fragment of a larger packet, which RFC 8200 section 4.5
	// leaves to reassembly at the destination, and a SID drops. The header of
	// an atomic fragment is one walk proceeds past.
	errFragment = errors.New("srv6: a fragment of a larger packet, which this node does not reassemble")
)

// Refusal is a header field that keeps a packet from being processed, which
// RFC 4443 section 3.4 answers with a Parameter Problem of Code pointing at
// the octet Pointer of the packet.
type Refusal struct {
	Code    uint8
	Pointer int
	what    string
}

func (r *Refusal) Error() string {
	return fmt.Sprintf("srv6: %s, parameter problem code %d at octet %d", r.what, r.Code, r.Pointer)
}

func refuse(code uint8, pointer int, what string) *Refusal {
	return &Refusal{Code: code, Pointer: pointer, what: what}
}

// Encapsulate is H.Encaps, RFC 8986 section 5.1: it puts inner inside a new
// IPv6 packet whose destination is the first segment of path and whose routing
// header carries the rest.
//
// path is in the order the packet visits, so a caller writes the waypoints and
// then the exit, and this reverses them for the wire.
//
// The inner packet is not modified. RFC 8986 section 5.1 S05 decrements its
// hop limit and this does not, matching __seg6_do_srh_encap: a
// packet read off the tun was either originated here, where a host must not
// decrement, or already forwarded into the tun by the kernel, where it
// already was. Decrementing again would charge it twice for one hop.
func Encapsulate(inner []byte, source netip.Addr, path []netip.Addr) ([]byte, error) {
	return AppendEncapsulated(nil, inner, source, path)
}

// AppendEncapsulated appends to dst the packet Encapsulate returns, copying inner once
// a refusal returns dst as it was
func AppendEncapsulated(dst, inner []byte, source netip.Addr, path []netip.Addr) ([]byte, error) {
	if err := CheckPath(source, path); err != nil {
		return dst, err
	}
	return appendEncapsulated(dst, inner, source, path)
}

// appendEncapsulated is AppendEncapsulated for a source and a path CheckPath
// has taken, which a Policy's constructor checks once rather than a packet at a time
func appendEncapsulated(dst, inner []byte, source netip.Addr, path []netip.Addr) ([]byte, error) {
	innerNext, err := innerNextHeader(inner)
	if err != nil {
		return dst, err
	}
	// The outer payload length is 16 bits and counts the routing header as
	// well, so a packet that would overflow it is refused rather than sent
	// with a length that has wrapped.
	if payload := srhFixedLen + addrLen*len(path) + len(inner); payload > 0xffff {
		return dst, fmt.Errorf("srv6: %d bytes behind %d segments is more than an IPv6 payload length can carry", len(inner), len(path))
	}
	overhead, start := Overhead(len(path)), len(dst)
	dst = slices.Grow(dst, overhead+len(inner))[:start+overhead+len(inner)]
	copy(dst[start+overhead:], inner)
	writeOuter(dst[start:start+overhead], dst[start+overhead:], innerNext, source, path)
	return dst, nil
}

// Overhead is the bytes an encapsulation puts in front of a packet for a path
// of n segments, which a tunnel takes off its own MTU so the dataplane keeps
// being handed packets that still fit once the header is there.
func Overhead(segments int) int {
	return ipv6HeaderLen + srhFixedLen + addrLen*segments
}

// CheckPath refuses a segment list and a tunnel source this node will not
// encapsulate with, so a configuration is rejected when it is read rather than
// when the first packet matches it.
func CheckPath(source netip.Addr, path []netip.Addr) error {
	if len(path) == 0 {
		return errors.New("srv6: a segment list needs at least one segment")
	}
	if len(path) > MaxSegments {
		return fmt.Errorf("srv6: %d segments is more than the %d this node will build", len(path), MaxSegments)
	}
	if !Usable(source) {
		return fmt.Errorf("srv6: tunnel source %s cannot address a segment routed packet", source)
	}
	for _, segment := range path {
		if !Usable(segment) {
			return fmt.Errorf("srv6: segment %s cannot address a segment routed packet", segment)
		}
	}
	return nil
}

// Usable reports whether an address can be a segment or a tunnel source. A
// zone is local to one host and never reaches the wire, a v4-mapped address
// cannot appear in an IPv6 destination, and neither the unspecified address
// nor a multicast group is somewhere a packet can be forwarded to.
func Usable(address netip.Addr) bool {
	return address.Is6() && !address.Is4In6() && address.Zone() == "" &&
		!address.IsUnspecified() && !address.IsMulticast()
}

// writeOuter fills a header of exactly Overhead(len(path)) bytes in front of
// inner, whose next header innerNext names. Its caller has already checked
// everything, so it cannot fail and never reports.
//
// Every byte of the header is assigned rather than left as it was found:
// AppendEncapsulated hands this the bytes an earlier packet left in a buffer
// its caller keeps, so anything skipped here would go on the wire as a
// fragment of that packet.
func writeOuter(out, inner []byte, innerNext uint8, source netip.Addr, path []netip.Addr) {
	// __seg6_do_srh_encap copies the traffic class, the flow label and the hop
	// limit out of an IPv6 inner packet, the behavior seg6_flowlabel 0 names
	// and its default. Matching it keeps a packet this node steers and
	// one a kernel headend steers the same bytes, and stops an encapsulation
	// handing a packet a hop budget its own header had already spent.
	hopLimit := uint8(DefaultHopLimit)
	if innerNext == NextHeaderIPv6 {
		hopLimit = inner[7]
	}
	last := uint8(len(path) - 1)
	srhLen := srhFixedLen + addrLen*len(path)

	if innerNext == NextHeaderIPv6 {
		// Version, traffic class and flow label together, since the inner
		// packet's version nibble is already 6.
		copy(out[:4], inner[:4])
	} else {
		// RFC 6040 section 4.1's normal mode: "copying the two-bit ECN field of the incoming IP header", the low bits of the TOS octet, into the low bits of the traffic class
		out[0], out[1] = 0x60, (inner[1]&0b11)<<4
		binary.BigEndian.PutUint16(out[2:], 0)
	}
	binary.BigEndian.PutUint16(out[4:], uint16(srhLen+len(inner)))
	out[6] = nextHeaderRouting
	out[7] = hopLimit
	copy(out[8:], addr16(source))
	// The outer destination is the first segment of the path, which the wire's
	// list holds last, at the index Segments Left names.
	copy(out[24:], addr16(path[0]))

	srh := out[ipv6HeaderLen:]
	srh[0] = innerNext
	// Hdr Ext Len counts 8-octet units after the first eight octets, so a list
	// of n segments is 2n.
	srh[1] = uint8(2 * len(path))
	srh[2] = routingTypeSegment
	srh[3] = last // Segments Left starts at the last index
	srh[4] = last // Last Entry is that index too
	srh[5], srh[6], srh[7] = 0, 0, 0
	// the wire holds the path backward, written in place so a packet allocates nothing
	for i, segment := range path {
		copy(srh[srhFixedLen+addrLen*(len(path)-1-i):], addr16(segment))
	}
}

// DefaultHopLimit is the outer budget an IPv4 inner packet gets, since its TTL
// is not an IPv6 hop limit to copy. It takes 64, the hop limit linux gives the
// packets it sends (IPV6_DEFAULT_HOPLIMIT), rather than a mesh-sized number,
// so a segment list that loops dies at the same count anything else does.
const DefaultHopLimit = 64

// segmentsLeft is the Segments Left of the SRH at srh, whose Hdr Ext Len lies
// within raw, once it is checked as RFC 8754 section 4.3.1.1 checks it with
// segments left: Last Entry within Hdr Ext Len and Segments Left at most Last
// Entry+1, either refused with code 0 at Segments Left. A list past the cap of
// MaxSegments is a header past this node's processing limit, refused with
// RFC 8883 section 2.3's code 6 at the header's first octet.
//
// Last Entry gives the segment count, and RFC 8754 section 2.1 puts any TLVs
// after the list: they are present exactly when Hdr Ext Len is greater than
// (Last Entry+1)*2, and the same section requires a type this node does not
// recognize to be ignored rather than refused. So the segments have to fit
// and everything past them is somebody else's. RFC 8754 section 4.1.1 lets a
// source leave out the segment the destination address already carries, so a
// Segments Left of Last Entry+1 is a reduced header rather than an error.
func segmentsLeft(raw []byte, srh int) (uint8, error) {
	left, count, extLen := raw[srh+segmentsLeftInHeader], int(raw[srh+lastEntryInHeader])+1, int(raw[srh+1])
	if 2*count > extLen {
		return 0, refuse(icmpErroneousHeader, srh+segmentsLeftInHeader, "a routing header's last entry needs more segments than its length holds")
	}
	if int(left) > count {
		return 0, refuse(icmpErroneousHeader, srh+segmentsLeftInHeader, "a routing header's segments left is past its last entry")
	}
	if count > MaxSegments {
		return 0, refuse(icmpHeaderTooBig, srh, "a routing header holds more segments than this node acts on")
	}
	return left, nil
}

// walk reads the extension headers of raw, an IPv6 packet of at least its
// fixed header, to the first one a SID acts on: an SRH with segments left at
// srh, or the upper-layer header next at upper where srh is 0. It proceeds
// past the headers RFC 8200 section 4 has a node proceed past, and refuses
// any other with the Parameter Problem RFC 8200, RFC 4443 section 3.4 and RFC
// 8883 give it, a fragment of a larger packet being errFragment. A Fragment
// header the packet ends inside is refused at the IPv6 Payload Length, since
// the header has no length field of its own.
//
// It steps past at most maxExtensionHeaders headers, so a sender sets no cost
// per packet past them. One more it would step past is refused with RFC 8883
// section 2.5's code 8 at its first octet, and any other header in that place
// is met as in the places before it.
func walk(raw []byte) (srh, upper int, next byte, err error) {
	next, offset, field := raw[6], ipv6HeaderLen, nextHeaderInIPv6
	for steps := 0; ; steps++ {
		step, following, end := stepHeader(raw, next, offset)
		switch step {
		case stepUpper:
			switch next {
			case nextHeaderMobility, nextHeaderHIP, nextHeaderShim6, nextHeaderTesting1, nextHeaderTesting2:
				return 0, 0, 0, refuse(icmpUnrecognizedNext, field, "an extension header of a kind this node does not process")
			}
			return 0, offset, next, nil
		case stepShort:
			return 0, 0, 0, refuse(icmpErroneousHeader, payloadLengthInIPv6, "the packet ends inside an extension header's length")
		case stepLong:
			if next == nextHeaderFragment {
				return 0, 0, 0, refuse(icmpErroneousHeader, payloadLengthInIPv6, "the packet ends inside a fragment header")
			}
			return 0, 0, 0, refuse(icmpErroneousHeader, offset+1, "an extension header runs past the packet's end")
		case stepFragment:
			return 0, 0, 0, errFragment
		}
		switch next {
		case nextHeaderHopByHop:
			if offset != ipv6HeaderLen {
				return 0, 0, 0, refuse(icmpUnrecognizedNext, field, "a hop-by-hop options header past the first place")
			}
		case nextHeaderRouting:
			if raw[offset+segmentsLeftInHeader] != 0 {
				if raw[offset+routingTypeInHeader] == routingTypeSegment {
					return offset, 0, 0, nil
				}
				return 0, 0, 0, refuse(icmpErroneousHeader, offset+routingTypeInHeader, "a routing header of a type this node does not process with segments left")
			}
		}
		if steps == maxExtensionHeaders {
			return 0, 0, 0, refuse(icmpTooManyHeaders, offset, "more extension headers than this node steps past")
		}
		next, offset, field = following, end, offset
	}
}

// stepping names the kind of header stepHeader finds
type stepping uint8

const (
	// stepPast is an extension header within the packet, which a walk may step past to the one following it
	stepPast stepping = iota
	// stepUpper is a header of a kind stepHeader does not read, the upper-layer header or an extension header no walk steps past
	stepUpper
	// stepFragment is the Fragment header, within the packet, of a fragment of a larger packet
	stepFragment
	// stepShort is a header the packet ends inside before its length, and stepLong one running past the packet's end
	stepShort
	stepLong
)

// stepHeader reads the header of kind at offset in raw, as walk and the error search step through one, for what it is, the header following it and where that one starts
// the kinds it reads are those RFC 8200 section 4 has a node proceed past, the hop-by-hop options, destination options, routing and authentication headers
// and the Fragment header, whose packet section 4.5 has processed as a whole where it is an atomic fragment
func stepHeader(raw []byte, kind byte, offset int) (step stepping, following byte, end int) {
	switch kind {
	case nextHeaderHopByHop, nextHeaderDestOpts, nextHeaderRouting, nextHeaderAuth, nextHeaderFragment:
	default:
		return stepUpper, 0, 0
	}
	following, end, ok := StepExtension(raw, kind, offset)
	switch {
	case !ok:
		return stepShort, 0, 0
	case end > len(raw):
		return stepLong, following, end
	case kind == nextHeaderFragment && !atomicFragment(raw, offset):
		return stepFragment, following, end
	}
	return stepPast, following, end
}

// atomicFragment reports the Fragment header at offset, whose 8 octets raw
// holds, as an atomic fragment's, RFC 8200 section 4.5: its Fragment Offset's
// 13 bits and its M flag all 0.
func atomicFragment(raw []byte, offset int) bool {
	return binary.BigEndian.Uint16(raw[offset+2:])&0xfff9 == 0
}

// StepExtension reads the extension header of type kind at offset, RFC 8200
// section 4, for the header that follows it and where that one starts. It
// reads only the octets that say so, and reports false when the packet ends
// before them, so the start it gives may lie past the packet's end.
func StepExtension(raw []byte, kind byte, offset int) (next byte, end int, ok bool) {
	if len(raw) < offset+2 {
		return 0, 0, false
	}
	switch kind {
	case nextHeaderFragment:
		end = offset + extensionUnit
	case nextHeaderAuth:
		// RFC 4302 section 2.2 counts AH in 4-octet units, less 2
		end = offset + 4*(2+int(raw[offset+1]))
	default:
		end = offset + extensionUnit*(1+int(raw[offset+1]))
	}
	return raw[offset], end, true
}

// End is the waypoint behavior of RFC 8986 section 4.1: the packet is not
// changed except that it moves on to the next segment. It returns the address
// the packet now goes to, having rewritten the destination and the counter in
// place.
//
// The hop limit is decremented, RFC 8986 section 4.1 S12, which bounds a
// segment list that points back at an earlier node.
//
// It acts on the SRH with segments left that walk finds, and checks it in
// section 4.1's order: the hop limit, S05 to S07, before Last Entry and
// Segments Left, S08 to S11. A packet with no such SRH reaches its upper-layer
// header, which a waypoint SID's local configuration allows none of, so it is
// refused with code 4 at that header, section 4.1.1 S04.
func End(raw []byte) (netip.Addr, error) {
	next, _, err := waypoint(raw)
	return next, err
}

// waypoint is End, reporting as well where the SRH it acted on starts in raw
func waypoint(raw []byte) (netip.Addr, int, error) {
	if len(raw) < ipv6HeaderLen || raw[0]>>4 != 6 {
		return netip.Addr{}, 0, ErrNotSegmentRouted
	}
	srh, upper, _, err := walk(raw)
	if err != nil {
		return netip.Addr{}, 0, err
	}
	if srh == 0 {
		return netip.Addr{}, 0, refuse(icmpUpperLayer, upper, "End reached an upper-layer header, which a waypoint SID does not process")
	}
	if raw[7] <= 1 {
		return netip.Addr{}, 0, ErrHopLimit
	}
	left, err := segmentsLeft(raw, srh)
	if err != nil {
		return netip.Addr{}, 0, err
	}
	raw[7]--
	raw[srh+segmentsLeftInHeader] = left - 1
	segment := srh + srhFixedLen + addrLen*int(left-1)
	copy(raw[24:40], raw[segment:segment+addrLen])
	return netip.AddrFrom16([16]byte(raw[24:40])), srh, nil
}

// AtLocalInterface is RFC 8754 section 4.3.2 for the SRH at srh in raw, a packet whose destination is an address of this node that is no SID
// it is nil at segments left 0, where the node goes on to the next header, and otherwise the Parameter Problem, code 0, at the Routing Type that section answers with
func AtLocalInterface(raw []byte, srh int) *Refusal {
	if raw[srh+segmentsLeftInHeader] == 0 {
		return nil
	}
	return refuse(icmpErroneousHeader, srh+routingTypeInHeader, "a routing header with segments left at an address of this node that is no SID")
}

// Decap is the exit behavior of RFC 8986 section 4.8, End.DT46: the outer IPv6
// header and the routing header are removed and what was inside is returned,
// with the next-header value that says which family it is.
//
// An exit is keyed on the upper-layer header rather than on a routing header,
// which is why a packet carrying none is delivered rather than refused: a
// reduced encapsulation of a one-segment policy puts that segment in the
// destination address and writes no SRH at all, and the kernel's own
// decap_and_validate accepts it the same way.
//
// It returns a slice of raw rather than a copy, because the caller is the
// dataplane and the buffer is already its own. The slice is raw's tail, behind
// at least the 40 bytes of the fixed header, which a caller holding raw may
// write the packet's next framing into. The two-table half of the RFC's
// End.DT46, choosing a lookup table per family, is the caller's: this package
// takes bytes and returns bytes.
//
// The upper-layer header is the one walk finds, behind every header it
// proceeds past, and an SRH with segments left is refused with code 0 at its
// Segments Left, section 4.8 S02 to S04. An upper-layer header other than IPv4
// or IPv6 is refused with code 4 at it, S09 to S10 and section 4.1.1 S04, and
// a packet behind one of the two that is not of its version, or shorter than
// that version's header, with code 0 at its first octet, RFC 4443 section 3.4.
// So family, the Next Header, is always the inner packet's version.
func Decap(raw []byte) (inner []byte, family uint8, err error) {
	if len(raw) < ipv6HeaderLen || raw[0]>>4 != 6 {
		return nil, 0, ErrNotSegmentRouted
	}
	srh, upper, next, err := walk(raw)
	if err != nil {
		return nil, 0, err
	}
	if srh != 0 {
		return nil, 0, refuse(icmpErroneousHeader, srh+segmentsLeftInHeader, "an exit was reached with segments still to go")
	}
	inner = raw[upper:]
	version, shortest := byte(6), ipv6HeaderLen
	switch next {
	case NextHeaderIPv6:
	case NextHeaderIPv4:
		version, shortest = 4, ipv4HeaderLen
	default:
		return nil, 0, refuse(icmpUpperLayer, upper, "an exit delivers only an encapsulated IPv4 or IPv6 packet")
	}
	if len(inner) < shortest || inner[0]>>4 != version {
		return nil, 0, refuse(icmpErroneousHeader, upper, "the octets behind an exit's next header are no packet of its version")
	}
	return inner, next, nil
}

// innerNextHeader is the protocol number announcing what an encapsulation is
// carrying, read from the packet itself rather than taken on trust from the
// caller: the two disagreeing is a packet an exit refuses to deliver, found
// one hop too late to say anything useful about it.
//
// A packet too short to hold the header its version claims is refused here,
// which lets writeOuter read the fields it copies.
func innerNextHeader(inner []byte) (uint8, error) {
	if len(inner) == 0 {
		return 0, errors.New("srv6: nothing to encapsulate")
	}
	switch version := inner[0] >> 4; version {
	case 4:
		if len(inner) < ipv4HeaderLen {
			return 0, fmt.Errorf("srv6: %d bytes is shorter than the IPv4 header it claims to be", len(inner))
		}
		return NextHeaderIPv4, nil
	case 6:
		if len(inner) < ipv6HeaderLen {
			return 0, fmt.Errorf("srv6: %d bytes is shorter than the IPv6 header it claims to be", len(inner))
		}
		return NextHeaderIPv6, nil
	default:
		return 0, fmt.Errorf("srv6: the packet to encapsulate is IP version %d", version)
	}
}

func addr16(address netip.Addr) []byte {
	raw := address.As16()
	return raw[:]
}
