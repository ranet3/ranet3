// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package srv6

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"net/netip"
	"slices"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// usableAddresses draws addresses CheckPath takes as a segment or a source.
func usableAddresses() hegel.Generator[netip.Addr] {
	return hegel.Filter(hegel.IPAddresses().IPv6(), Usable)
}

// usablePaths draws a segment list CheckPath accepts, one to MaxSegments long.
func usablePaths() hegel.Generator[[]netip.Addr] {
	return hegel.Composite(func(tc hegel.TestCase) []netip.Addr {
		count := hegel.Draw(tc, pbt.Spanning(1, MaxSegments))
		return hegel.Draw(tc, hegel.Lists(usableAddresses()).MinSize(count).MaxSize(count))
	})
}

// payloads draws up to limit bytes, the length drawn first so that sizes
// spread over the whole range rather than staying as short as byte strings
// are drawn by default.
func payloads(tc hegel.TestCase, limit int) string {
	size := hegel.Draw(tc, pbt.Spanning(0, limit))
	return string(hegel.Draw(tc, hegel.Binary(size, size)))
}

// hopLimits draws a hop limit, with 0 and 1, which a waypoint refuses to
// forward at, 2, the last it forwards at, and 255 drawn outright.
func hopLimits() hegel.Generator[uint8] {
	return hegel.OneOf(hegel.SampledFrom([]uint8{0, 1, 2, 255}), hegel.Integers[uint8](0, 255))
}

// innerPackets draws a packet an encapsulation accepts, up to 1500 bytes and
// built by innerV4 and innerV6Hops as the table tests build theirs, with the
// header fields H.Encaps copies onto the outer header drawn as well: the
// traffic class, the flow label and the hop limit of an IPv6 packet. The TOS
// and the TTL of an IPv4 one are drawn too, of which it copies the ECN field
// of the TOS alone.
func innerPackets() hegel.Generator[[]byte] {
	return hegel.Composite(func(tc hegel.TestCase) []byte {
		if hegel.Draw(tc, hegel.Booleans()) {
			raw := innerV4(payloads(tc, 1500-ipv4HeaderLen))
			raw[1] = hegel.Draw(tc, pbt.Spanning[byte](0, 0xff))
			raw[8] = hegel.Draw(tc, hopLimits())
			return raw
		}
		raw := innerV6Hops(payloads(tc, 1500-ipv6HeaderLen), hegel.Draw(tc, hopLimits()))
		binary.BigEndian.PutUint32(raw, 6<<28|hegel.Draw(tc, pbt.Spanning[uint32](0, 1<<28-1)))
		return raw
	})
}

// mostly draws from usual seven times in eight, and from rare otherwise.
func mostly[T any](usual, rare hegel.Generator[T]) hegel.Generator[T] {
	return hegel.Composite(func(tc hegel.TestCase) T {
		if hegel.Draw(tc, hegel.WeightedBooleans(1.0/8)) {
			return hegel.Draw(tc, rare)
		}
		return hegel.Draw(tc, usual)
	})
}

// mangledPackets draws a well formed encapsulation, walked some way along its
// path and sometimes put behind extension headers, and then left whole or
// damaged in one of three ways: a few bytes of its headers overwritten, its
// tail cut off, or one header's length octet made to claim other than the
// header holds. Bytes drawn whole almost never get past the version and next
// header checks, and these reach every branch of the chain walk, the routing
// header read and the exit.
func mangledPackets() hegel.Generator[[]byte] {
	return hegel.Composite(func(tc hegel.TestCase) []byte {
		inner := hegel.Draw(tc, innerPackets())
		raw, err := Encapsulate(inner, hegel.Draw(tc, usableAddresses()), hegel.Draw(tc, usablePaths()))
		if err != nil {
			tc.Errorf("a packet and a path drawn to be accepted were refused: %v", err)
		}
		for range hegel.Draw(tc, hegel.Integers(0, MaxSegments)) {
			if _, err := End(raw); err != nil {
				break
			}
		}
		// Hop-by-hop and destination options headers in front of the
		// routing header, each pointing on to the next: mostly one or two,
		// and now and then the most walk steps past in front of it or one
		// more than that, with the odd fragment header among them, which ends
		// the walk wherever it sits. lengths is where each header's length
		// octet sits, the routing header's first.
		chain := hegel.OneOf(hegel.Integers(0, 2), hegel.SampledFrom([]int{maxExtensionHeaders, maxExtensionHeaders + 1}))
		lengths := []int{ipv6HeaderLen + 1}
		for range hegel.Draw(tc, chain) {
			kind := hegel.Draw(tc, hegel.SampledFrom([]byte{nextHeaderHopByHop, nextHeaderDestOpts}))
			if hegel.Draw(tc, hegel.WeightedBooleans(1.0/8)) {
				kind = nextHeaderFragment
			}
			units := hegel.Draw(tc, hegel.Integers(0, 2))
			header := hegel.Draw(tc, hegel.Binary(extensionUnit*(1+units), extensionUnit*(1+units)))
			header[0], header[1] = raw[6], byte(units)
			raw = slices.Concat(raw[:ipv6HeaderLen], header, raw[ipv6HeaderLen:])
			raw[6] = kind
			for i := range lengths {
				lengths[i] += len(header)
			}
			lengths = append(lengths, ipv6HeaderLen+1)
		}
		binary.BigEndian.PutUint16(raw[4:], uint16(len(raw)-ipv6HeaderLen))
		// The damage stays in the headers, the bytes the parsers read, rather
		// than in the inner packet that is most of the packet. A length
		// octet claims anything up to the 255 units it can say, those two ends
		// half the time, and 255 runs past the end of any packet. That is an
		// extension header's octet where there is one, since a header in
		// front of the routing header claiming more than the packet holds is
		// one the walk has to refuse rather than follow.
		headers := len(raw) - len(inner)
		switch hegel.Draw(tc, hegel.Integers(0, 4)) {
		case 1:
			for range hegel.Draw(tc, hegel.Integers(1, 4)) {
				raw[hegel.Draw(tc, hegel.Integers(0, headers-1))] = hegel.Draw(tc, hegel.Integers[byte](0, 255))
			}
		case 2:
			raw = raw[:hegel.Draw(tc, pbt.Spanning(0, headers))]
		case 3, 4:
			at := lengths[0]
			if len(lengths) > 1 && hegel.Draw(tc, hegel.WeightedBooleans(3.0/4)) {
				at = hegel.Draw(tc, hegel.SampledFrom(lengths[1:]))
			}
			raw[at] = hegel.Draw(tc, hegel.OneOf(hegel.SampledFrom([]byte{0, 255}), hegel.Integers[byte](0, 255)))
		}
		return raw
	})
}

// lyingLengths draws an encapsulation behind none, one or two extension
// headers, one of whose length octets, the routing header's own among them,
// claims a length the packet may not hold. The claim is drawn from 0 to 255,
// and half the time from the four lengths at the end of the packet: the
// header ending one unit short of it, at or just inside it, and one and two
// units past it. Those are where walk decides between a header it can read
// and one it must refuse, and mangledPackets reaches them only now and then. Where there is an extension header, the one in
// front of the routing header is the one lying in at least half the draws,
// since only its length carries the walk on to the routing header.
func lyingLengths() hegel.Generator[[]byte] {
	return hegel.Composite(func(tc hegel.TestCase) []byte {
		inner := hegel.Draw(tc, innerPackets())
		raw, err := Encapsulate(inner, hegel.Draw(tc, usableAddresses()), hegel.Draw(tc, usablePaths()))
		if err != nil {
			tc.Errorf("a packet and a path drawn to be accepted were refused: %v", err)
		}
		// starts is where each header begins, the routing header's first
		starts := []int{ipv6HeaderLen}
		for range hegel.Draw(tc, hegel.Integers(0, 2)) {
			header := make([]byte, extensionUnit)
			header[0], header[2], header[3] = raw[6], 1, 4 // a PadN filling it
			raw = slices.Concat(raw[:ipv6HeaderLen], header, raw[ipv6HeaderLen:])
			raw[6] = hegel.Draw(tc, hegel.SampledFrom([]byte{nextHeaderHopByHop, nextHeaderDestOpts}))
			for i := range starts {
				starts[i] += extensionUnit
			}
			starts = append(starts, ipv6HeaderLen)
		}
		binary.BigEndian.PutUint16(raw[4:], uint16(len(raw)-ipv6HeaderLen))
		start := hegel.Draw(tc, hegel.SampledFrom(starts))
		if len(starts) > 1 && hegel.Draw(tc, hegel.Booleans()) {
			start = starts[1]
		}
		// the units after a header's first that would end it at the packet's end
		fits := (len(raw)-start)/extensionUnit - 1
		var near []byte
		for _, units := range []int{fits - 1, fits, fits + 1, fits + 2} {
			if units >= 0 && units <= 255 {
				near = append(near, byte(units))
			}
		}
		claim := hegel.Integers[byte](0, 255)
		if len(near) > 0 && hegel.Draw(tc, hegel.Booleans()) {
			claim = hegel.SampledFrom(near)
		}
		raw[start+1] = hegel.Draw(tc, claim)
		return raw
	})
}

// boundaryFields draws a well formed encapsulation, walked some way along its
// path, with one routing header field set just past what it says of itself:
// Segments Left one past Last Entry, which a reduced header carries, or two
// past it, Hdr Ext Len one unit short of its segments, or Last Entry one
// segment past what that length holds. Otherwise Segments Left is set to zero
// and the packet cut where the routing header ends, an exit with nothing after
// the header to deliver. Segments Left takes two draws in five, since only the
// second of its two values is one End refuses. An encapsulation writes the
// value on the near side of each edge, so every other shape draws those, and
// damage drawn anywhere in a header lands on the far ones only by luck.
func boundaryFields() hegel.Generator[[]byte] {
	return hegel.Composite(func(tc hegel.TestCase) []byte {
		inner := hegel.Draw(tc, innerPackets())
		raw, err := Encapsulate(inner, hegel.Draw(tc, usableAddresses()), hegel.Draw(tc, usablePaths()))
		if err != nil {
			tc.Errorf("a packet and a path drawn to be accepted were refused: %v", err)
		}
		for range hegel.Draw(tc, hegel.Integers(0, MaxSegments)) {
			if _, err := End(raw); err != nil {
				break
			}
		}
		srh := raw[ipv6HeaderLen:]
		lastEntry, units := int(srh[4]), int(srh[1])
		switch hegel.Draw(tc, hegel.Integers(0, 4)) {
		case 0, 1:
			srh[3] = byte(lastEntry + hegel.Draw(tc, hegel.Integers(1, 2)))
		case 2:
			srh[1] = byte(units - 1)
		case 3:
			srh[4] = byte(units / 2)
		default:
			srh[3] = 0
			raw = raw[:ipv6HeaderLen+srhFixedLen+extensionUnit*units]
		}
		return raw
	})
}

// End and Decap read bytes a peer chose, and a waypoint or an exit runs them
// on every packet addressed to one of its segments, so no input may make them
// panic: each answers with an error or with a value inside the packet it was
// given. An SRH walk finds lies whole inside the packet, since End indexes the
// packet by its segments and carriedPacket reads past its length. The ICMP
// answers to a refused packet read the same bytes and are held to the same.
// Every one of them is handed the packet with no capacity past its length, so
// reading past its end panics here, where in a dataplane buffer it would read
// whatever followed the packet.
func TestEndAndDecapNeverPanicOnArbitraryBytes(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		raw := slices.Clip(hegel.Draw(ht, hegel.OneOf(
			hegel.Composite(func(tc hegel.TestCase) []byte { return []byte(payloads(tc, 1500)) }),
			mangledPackets(),
			lyingLengths(),
			boundaryFields(),
		)))

		if len(raw) >= ipv6HeaderLen && raw[0]>>4 == 6 {
			if srh, _, _, err := walk(raw); err == nil && srh != 0 && (srh < ipv6HeaderLen || srh+srhFixedLen+extensionUnit*int(raw[srh+1]) > len(raw)) {
				ht.Fatalf("walk found an SRH at %d claiming %d units in a %d byte packet", srh, raw[srh+1], len(raw))
			}
		}
		_, endErr := End(slices.Clip(bytes.Clone(raw)))
		inner, family, decapErr := Decap(slices.Clip(bytes.Clone(raw)))
		if decapErr == nil {
			if len(inner) == 0 || family != NextHeaderIPv4 && family != NextHeaderIPv6 {
				ht.Fatalf("Decap delivered %d bytes of family %d", len(inner), family)
			}
		}
		from := addr("3fff:b:0:106::2")
		TimeExceeded(raw, from, always)
		// a refusal points into the packet, or just past it at an upper-layer header the packet ends before
		for _, err := range []error{endErr, decapErr} {
			if refusal, ok := errors.AsType[*Refusal](err); ok {
				if refusal.Pointer < 0 || refusal.Pointer > len(raw) {
					ht.Fatalf("%v points at %d of a %d byte packet", refusal, refusal.Pointer, len(raw))
				}
				ParameterProblem(raw, from, refusal, always)
			}
		}
	})
}

// laidHeader is one extension header of a packet the walk's model lays out, RFC 8200 section 4: its kind, the octets it takes, and the byte its body is filled with
// hop-by-hop, routing and destination options take 8 octets and 8 more for each unit of their length octet, sections 4.3, 4.4 and 4.6
// an authentication header takes 8 octets and 4 more for each unit of its length octet, RFC 4302 section 2.2, and a fragment header 8, its second octet reserved, section 4.5
type laidHeader struct {
	kind   byte
	octets int
	fill   byte
	// more is a fragment header's M flag, its offset being 0
	more bool
}

// laidPacket is an IPv6 packet as the walk's model lays it out: the extension headers after the fixed header, what ends their chain, and where the packet is cut
type laidPacket struct {
	headers []laidHeader
	// last is the protocol the last header names: 58 for an ICMPv6 message of type icmp, 44 for a fragment header at offset later, which holds an ICMPv6 error, or 59, 50 or another
	last  byte
	icmp  byte
	later uint16
	// length is how much of the packet is kept
	length int
}

// whole lays out every byte of the packet, and starts gives where each header begins and then where the item ending the chain does
func (p laidPacket) whole() (raw []byte, starts []int) {
	raw = make([]byte, 40, 40+8*len(p.headers))
	raw[0], raw[7] = 0x60, 64
	copy(raw[8:], addr16(addr("3fff:a::1")))
	copy(raw[24:], addr16(addr("3fff:b::2")))
	raw[6] = p.last
	for i, h := range p.headers {
		if i == 0 {
			raw[6] = h.kind
		}
		header := bytes.Repeat([]byte{h.fill}, h.octets)
		header[0] = p.last
		if i+1 < len(p.headers) {
			header[0] = p.headers[i+1].kind
		}
		switch h.kind {
		case 44:
			// offset 0, and the reserved octet and bits keep the fill, which section 4.5 has a reader ignore
			header[2], header[3] = 0, h.fill&0x06
			if h.more {
				header[3] |= 1
			}
		case 51:
			header[1] = byte(h.octets/4 - 2)
		default:
			header[1] = byte(h.octets/8 - 1)
		}
		starts = append(starts, len(raw))
		raw = append(raw, header...)
	}
	starts = append(starts, len(raw))
	switch p.last {
	case 58:
		raw = append(raw, p.icmp, 0, 0, 0, 0, 0, 0, 0)
	case 44:
		later := []byte{58, 0, 0, 0, 0, 0, 0, 7, 1, 0, 0, 0, 0, 0, 0, 0}
		binary.BigEndian.PutUint16(later[2:], p.later<<3)
		raw = append(raw, later...)
	case 59:
	default:
		raw = append(raw, 0, 0, 0, 1, 0, 0, 0, 1)
	}
	binary.BigEndian.PutUint16(raw[4:], uint16(len(raw)-40))
	return raw, starts
}

// refused is the model's verdict on a packet of length octets: the search steps past 8 extension headers at most, so it reaches the item ending the chain only behind 8 or fewer
// it steps over a laid header only when the packet holds the octets saying what follows, the first 2, and the first 4 of a fragment header, whose offset they hold
// and it refuses only an ICMPv6 message it reaches whose type is an error's, below 128, or a redirect's, 137, or which the packet ends before the type of
func (p laidPacket) refused() bool {
	const steps = 8
	if len(p.headers) > steps {
		return false
	}
	start := 40
	for _, h := range p.headers {
		says := 2
		if h.kind == 44 {
			says = 4
		}
		if p.length < start+says {
			return false
		}
		start += h.octets
	}
	return p.last == 58 && (p.length <= start || p.icmp < 128 || p.icmp == 137)
}

// laidKinds are the extension headers the walk steps over, hop-by-hop, routing, destination options, AH, and a fragment header at offset 0
var laidKinds = []byte{0, 43, 60, 51, 44}

// laid is a header of kind taking the octets units of its length octet give it
// a fragment header has no length octet, and the parity of units gives its M flag
func laid(kind byte, units int, fill byte) laidHeader {
	switch kind {
	case 44:
		return laidHeader{kind: kind, octets: 8, fill: fill, more: units%2 == 1}
	case 51:
		return laidHeader{kind: kind, octets: 4 * (units + 2), fill: fill}
	}
	return laidHeader{kind: kind, octets: 8 * (units + 1), fill: fill}
}

// checkLaid holds Time Exceeded and Packet Too Big for p to the model: each is built exactly when the model refuses nothing, asking allow once then and never otherwise
func checkLaid(tb testing.TB, p laidPacket) {
	tb.Helper()
	raw, _ := p.whole()
	p.length = min(p.length, len(raw))
	offending := slices.Clip(raw[:p.length])
	sid := addr("3fff:b:0:106::2")
	for name, build := range map[string]func(allow func() bool) []byte{
		"time exceeded":  func(allow func() bool) []byte { return TimeExceeded(offending, sid, allow) },
		"packet too big": func(allow func() bool) []byte { return PacketTooBig(offending, sid, MinimumIPv6MTU, allow) },
	} {
		asked := 0
		answer := build(func() bool { asked++; return true })
		if want := !p.refused(); (answer != nil) != want || (asked == 1) != want || asked > 1 {
			tb.Fatalf("%s for %d octets of a packet laid out as %+v was built %t asking allow %d times, the model answers %t", name, p.length, p, answer != nil, asked, want)
		}
	}
}

// any chain of the headers the walk steps over, in any order and with lengths across their whole range, ending in an ICMPv6 message of any type, a later fragment, no next header, ESP or another protocol
// and cut anywhere or near where a header starts, gets Time Exceeded and Packet Too Big exactly when the model of its layout finds no ICMPv6 error or redirect, RFC 4443 section 2.4 (e.1) and (e.2)
// every ICMPv6 type behind each kind of header, every length of each, every cut through each and its ICMPv6 header, and chains of each as long as the search steps past and either side, are tried first, which meets each in every run
func TestSearchRefusesExactlyWhatTheModelFindsAnError(t *testing.T) {
	for _, kind := range laidKinds {
		for icmp := range 256 {
			checkLaid(t, laidPacket{headers: []laidHeader{laid(kind, 0, 0xff)}, last: 58, icmp: byte(icmp), length: math.MaxInt})
		}
		for units := range 256 {
			for _, icmp := range []byte{1, 128} {
				checkLaid(t, laidPacket{headers: []laidHeader{laid(kind, units, 0xff)}, last: 58, icmp: icmp, length: math.MaxInt})
			}
		}
		for units := range 2 {
			p := laidPacket{headers: []laidHeader{laid(kind, units, 0xff)}, last: 58, icmp: 128}
			raw, _ := p.whole()
			for p.length = 40; p.length <= len(raw); p.length++ {
				checkLaid(t, p)
			}
		}
		for count := 7; count <= 10; count++ {
			for _, icmp := range []byte{1, 128} {
				checkLaid(t, laidPacket{headers: slices.Repeat([]laidHeader{laid(kind, 0, 0xff)}, count), last: 58, icmp: icmp, length: math.MaxInt})
			}
		}
	}
	pbt.Check(t, func(ht *hegel.T) {
		p := laidPacket{
			last: hegel.Draw(ht, hegel.SampledFrom([]byte{58, 58, 58, 44, 59, 50, 6, 17, 41})),
			// any type, and often one at the edge of the errors or the redirect
			icmp:   hegel.Draw(ht, hegel.OneOf(pbt.Spanning[byte](0, 255), hegel.SampledFrom([]byte{127, 128, 136, 137, 138}))),
			later:  hegel.Draw(ht, pbt.Spanning[uint16](1, 1<<13-1)),
			length: math.MaxInt,
		}
		// mostly a few headers, and often as many as the search steps past or more
		for range hegel.Draw(ht, hegel.OneOf(pbt.Spanning(0, 3), hegel.SampledFrom([]int{7, 8, 9, 10}))) {
			kind := hegel.Draw(ht, hegel.SampledFrom(laidKinds))
			p.headers = append(p.headers, laid(kind, hegel.Draw(ht, pbt.Spanning(0, 255)), hegel.Draw(ht, hegel.Integers[byte](0, 255))))
		}
		// half the packets are cut a few octets past where a header or the item ending the chain starts, where the walk decides between reading on and stopping
		if hegel.Draw(ht, hegel.Booleans()) {
			_, starts := p.whole()
			p.length = hegel.Draw(ht, hegel.SampledFrom(starts)) + hegel.Draw(ht, pbt.Spanning(0, 4))
		}
		checkLaid(ht, p)
	})
}

// chainHeader is one extension header of a packet the SIDs' model lays out, RFC 8200 section 4
// units is the length octet of a hop-by-hop, destination options, routing or authentication header, routing and left a routing header's type and segments left
// and offset and more a fragment header's Fragment Offset and M flag
type chainHeader struct {
	kind          byte
	units         int
	routing, left byte
	offset        uint16
	more          bool
}

// octets is the size of h, 8 octets and 8 more a unit, an authentication header's 8 and 4 more a unit by RFC 4302 section 2.2, and a fragment header's 8, section 4.5
func (h chainHeader) octets() int {
	switch h.kind {
	case 44:
		return 8
	case 51:
		return 4 * (h.units + 2)
	}
	return 8 * (h.units + 1)
}

// chainPacket is a packet the SIDs' model lays out: its extension headers, the protocol ending their chain, and how much of it is kept
type chainPacket struct {
	headers []chainHeader
	last    byte
	length  int
}

// the segments an SRH with segments left carries in the model, in wire order
var chainSegments = []netip.Addr{addr("3fff:b:0:506::1"), addr("3fff:b:0:406::1")}

// bytes lays the packet out to 3fff:b:0:206::1 at hop limit 64, and gives where each header starts and then where the item ending the chain does
// an SRH with segments left holds the two chainSegments and a Last Entry of 1, and an IPv6 or IPv4 packet ends the chain where last names one
func (p chainPacket) bytes() (raw []byte, starts []int) {
	raw = make([]byte, 40)
	raw[0], raw[7] = 0x60, 64
	copy(raw[8:], addr16(addr("3fff:a::1")))
	copy(raw[24:], addr16(addr("3fff:b:0:206::1")))
	raw[6] = p.last
	for i, h := range p.headers {
		if i == 0 {
			raw[6] = h.kind
		}
		header := make([]byte, h.octets())
		header[0] = p.last
		if i+1 < len(p.headers) {
			header[0] = p.headers[i+1].kind
		}
		switch h.kind {
		case 44:
			binary.BigEndian.PutUint16(header[2:], h.offset<<3)
			if h.more {
				header[3] |= 1
			}
		case 43:
			header[1], header[2], header[3] = byte(h.units), h.routing, h.left
			if h.routing == 4 && h.left != 0 {
				header[4] = 1
				copy(header[8:], addr16(chainSegments[0]))
				copy(header[24:], addr16(chainSegments[1]))
			}
		default:
			header[1] = byte(h.units)
		}
		starts = append(starts, len(raw))
		raw = append(raw, header...)
	}
	starts = append(starts, len(raw))
	switch p.last {
	case 41:
		raw = append(raw, innerV6("payload")...)
	case 4:
		raw = append(raw, innerV4("payload")...)
	default:
		raw = append(raw, 0, 0, 0, 1, 0, 0, 0, 1)
	}
	raw = raw[:min(p.length, len(raw))]
	binary.BigEndian.PutUint16(raw[4:], uint16(len(raw)-40))
	return raw, starts
}

// chainVerdict names the end the model has a SID's walk meet: a Parameter Problem of code at pointer, a fragment of a larger packet, an SRH with segments left at srh, or else the upper-layer header next at upper
type chainVerdict struct {
	refused    bool
	code       uint8
	pointer    int
	fragment   bool
	srh, upper int
	next       byte
}

// model walks p's headers as RFC 8200 section 4, RFC 8754 section 4.3.1.1 and RFC 8883 section 2.5 have a SID walk them, in the order they come
// section 4: a node proceeds past a header it processes, and answers code 1 at "the offset of the unrecognized value" for a kind it does not, Mobility, HIP, Shim6, 253 and 254 among them
// section 4.1: a hop-by-hop options header comes only "immediately after the IPv6 header", and code 1 at the Next Header naming it answers one anywhere else
// section 4.4 and RFC 8754 section 4.3.1.1: a routing header at segments left 0 is passed, an SRH with segments left is the one acted on, and another type with segments left is code 0 at its Routing Type
// section 4.5: an atomic fragment's header is passed, and any other fragment waits for reassembly
// RFC 4443 section 3.4: a header the packet ends inside is code 0, at its length, or at the IPv6 Payload Length where the packet ends before that or the header is a fragment header, which has none
// RFC 8883 section 2.5: past 8 extension headers, the limit, code 8 at "the first octet of the first extension header that is beyond the limit"
func (p chainPacket) model(starts []int) chainVerdict {
	refuse := func(code uint8, pointer int) chainVerdict {
		return chainVerdict{refused: true, code: code, pointer: pointer}
	}
	naming := 6
	for i, h := range p.headers {
		start := starts[i]
		switch {
		case p.length < start+2:
			return refuse(0, 4)
		case p.length < start+h.octets() && h.kind == 44:
			return refuse(0, 4)
		case p.length < start+h.octets():
			return refuse(0, start+1)
		case h.kind == 0 && i > 0:
			return refuse(1, naming)
		case h.kind == 43 && h.left != 0 && h.routing == 4:
			return chainVerdict{srh: start}
		case h.kind == 43 && h.left != 0:
			return refuse(0, start+2)
		case h.kind == 44 && (h.offset != 0 || h.more):
			return chainVerdict{fragment: true}
		case i == 8:
			return refuse(8, start)
		}
		naming = start
	}
	switch p.last {
	case 135, 139, 140, 253, 254:
		return refuse(1, naming)
	}
	return chainVerdict{upper: starts[len(starts)-1], next: p.last}
}

// chainKinds are the extension headers the model lays out, hop-by-hop, destination options, AH, routing and fragment headers
var chainKinds = []byte{0, 60, 51, 43, 44}

// checkChain holds End and Decap on p to the model
// End forwards to the segment an SRH with segments left names and refuses an upper-layer header with code 4 at it, RFC 8986 section 4.1.1 S04
// and Decap refuses the SRH with code 0 at its Segments Left, delivers an IPv4 or IPv6 packet whole behind the chain, and answers code 4 or code 0 at it otherwise, section 4.8
func checkChain(tb testing.TB, p chainPacket) {
	tb.Helper()
	raw, starts := p.bytes()
	p.length = len(raw)
	want := p.model(starts)
	holds := func(err error, want chainVerdict) bool {
		if want.fragment {
			return errors.Is(err, errFragment)
		}
		return refusedWith(err, want.code, want.pointer)
	}
	endWant, decapWant := want, want
	switch {
	case want.refused || want.fragment:
	case want.srh != 0:
		decapWant = chainVerdict{refused: true, code: 0, pointer: want.srh + 3}
	default:
		endWant = chainVerdict{refused: true, code: 4, pointer: want.upper}
		decapWant = chainVerdict{}
		inner := raw[want.upper:]
		switch {
		case want.next != 4 && want.next != 41:
			decapWant = chainVerdict{refused: true, code: 4, pointer: want.upper}
		case want.next == 4 && (len(inner) < 20 || inner[0]>>4 != 4), want.next == 41 && (len(inner) < 40 || inner[0]>>4 != 6):
			decapWant = chainVerdict{refused: true, code: 0, pointer: want.upper}
		}
	}
	next, err := End(bytes.Clone(raw))
	if endWant.srh != 0 {
		segment := chainSegments[raw[endWant.srh+3]-1]
		if err != nil || next != segment {
			tb.Fatalf("End on %+v returned %v, %v, want a forward to %v", p, next, err, segment)
		}
	} else if !holds(err, endWant) {
		tb.Fatalf("End on %+v returned %v, want %+v", p, err, endWant)
	}
	inner, _, err := Decap(raw)
	if decapWant.refused || decapWant.fragment {
		if !holds(err, decapWant) {
			tb.Fatalf("Decap on %+v returned %v, want %+v", p, err, decapWant)
		}
	} else if err != nil || !bytes.Equal(inner, raw[want.upper:]) {
		tb.Fatalf("Decap on %+v returned %d octets, %v, want the packet at %d", p, len(inner), err, want.upper)
	}
}

// chainHeaders draws an extension header of any of chainKinds: lengths across their range, a routing header of any type and segments left, an SRH with segments left holding two segments, and a fragment at any offset and M, an atomic one half the time
func chainHeaders() hegel.Generator[chainHeader] {
	return hegel.Composite(func(tc hegel.TestCase) chainHeader {
		h := chainHeader{kind: hegel.Draw(tc, hegel.SampledFrom(chainKinds)), units: hegel.Draw(tc, hegel.OneOf(pbt.Spanning(0, 3), pbt.Spanning(0, 255)))}
		switch h.kind {
		case 43:
			h.routing = hegel.Draw(tc, hegel.OneOf(hegel.SampledFrom([]byte{0, 2, 3, 4, 4, 253}), hegel.Integers[byte](0, 255)))
			h.left = hegel.Draw(tc, hegel.OneOf(hegel.SampledFrom([]byte{0, 0, 1}), hegel.Integers[byte](0, 255)))
			if h.routing == 4 && h.left != 0 {
				h.units, h.left = 4, 1+h.left%2
			}
		case 44:
			if hegel.Draw(tc, hegel.Booleans()) {
				h.offset, h.more = hegel.Draw(tc, pbt.Spanning[uint16](0, 1<<13-1)), hegel.Draw(tc, hegel.Booleans())
			}
		}
		return h
	})
}

// the walk at End and at Decap meets every chain of hop-by-hop, destination options, AH, routing and fragment headers as the model of RFC 8200 section 4, RFC 8754 section 4.3.1.1 and RFC 8883 section 2.5 has it
// in any order and with lengths across their range, a hop-by-hop header in any place, routing headers of any type and segments left, fragments at any offset and M
// ending in an IPv6 or IPv4 packet, another protocol, ESP, an ICMPv6 message or a kind the walk does not process, and cut anywhere or near where a header starts
// chains of 6 to 9 headers of each kind, about the limit of 8 the walk steps past, ending in each protocol and in an SRH at segments left 0 or 1, are tried first, which meets each in every run
func TestWalkMeetsEveryChainAsTheModelHasIt(t *testing.T) {
	lasts := []byte{41, 4, 6, 17, 59, 50, 58, 135, 139, 140, 253, 254}
	for _, kind := range chainKinds {
		for count := 6; count <= 9; count++ {
			chain := slices.Repeat([]chainHeader{{kind: kind}}, count)
			for _, last := range lasts {
				checkChain(t, chainPacket{headers: chain, last: last, length: math.MaxInt})
			}
			for _, left := range []byte{0, 1} {
				srh := chainHeader{kind: 43, units: 4, routing: 4, left: left}
				checkChain(t, chainPacket{headers: append(slices.Clone(chain), srh), last: 41, length: math.MaxInt})
			}
		}
	}
	pbt.Check(t, func(ht *hegel.T) {
		p := chainPacket{last: hegel.Draw(ht, hegel.SampledFrom(lasts)), length: math.MaxInt}
		// mostly a few headers, and often as many as the walk steps past and either side
		for range hegel.Draw(ht, hegel.OneOf(pbt.Spanning(0, 3), hegel.SampledFrom([]int{6, 7, 8, 9}))) {
			p.headers = append(p.headers, hegel.Draw(ht, chainHeaders()))
		}
		// half the packets are cut anywhere, most of them a few octets past where a header or the item ending the chain starts
		if hegel.Draw(ht, hegel.Booleans()) {
			raw, starts := p.bytes()
			p.length = hegel.Draw(ht, pbt.Spanning(40, len(raw)))
			if hegel.Draw(ht, hegel.WeightedBooleans(3.0/4)) {
				p.length = hegel.Draw(ht, hegel.SampledFrom(starts)) + hegel.Draw(ht, pbt.Spanning(0, 4))
			}
		}
		checkChain(ht, p)
	})
}

// A packet encapsulated over any path this node accepts reads back as that
// path: the SRH sits behind the fixed header, where walk finds it with segments
// left or, for a path of one segment, proceeds past it to the inner packet, its
// segments read back in the order the packet visits them, with the first one
// active and on the outer header, and the inner packet follows the routing
// header byte for byte. Each
// waypoint then moves it to the next
// segment, writing that segment into the outer destination, until the exit
// hands back the inner packet and its family, as the tail of the outer packet
// rather than a copy of it. The outer header copies the
// traffic class, the flow label and the hop limit of an IPv6 inner packet, and
// of an IPv4 one the ECN field of its TOS alone and not its TTL, so a walk
// stops with ErrHopLimit exactly where the inner IPv6 budget runs out, and
// nowhere else.
// A reversal or an offset wrong in any one of these sends traffic through the
// waypoints in the wrong order, or delivers something other than what was
// sent.
func TestEncapsulationReadsBackAsItsPath(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		inner := hegel.Draw(ht, innerPackets())
		source := hegel.Draw(ht, usableAddresses())
		path := hegel.Draw(ht, usablePaths())

		raw, err := Encapsulate(inner, source, path)
		if err != nil {
			ht.Fatalf("Encapsulate refused %d bytes over %v: %v", len(inner), path, err)
		}
		// a path of one segment is at segments left 0, which walk proceeds past to the inner packet
		srh, upper, _, err := walk(raw)
		if err != nil || len(path) > 1 && srh != ipv6HeaderLen || len(path) == 1 && upper != Overhead(1) {
			ht.Fatalf("walk found the SRH at %d and the upper-layer header at %d, %v, for a path of %d", srh, upper, err, len(path))
		}
		// the SRH's segments, in the order the packet visits them, the reverse of the wire's
		count := int(raw[ipv6HeaderLen+lastEntryInHeader]) + 1
		read := make([]netip.Addr, 0, count)
		for i := count - 1; i >= 0; i-- {
			at := ipv6HeaderLen + srhFixedLen + addrLen*i
			read = append(read, netip.AddrFrom16([16]byte(raw[at:at+addrLen])))
		}
		left := int(raw[ipv6HeaderLen+segmentsLeftInHeader])
		// an IPv4 packet's ECN field, the low bits of its TOS octet, goes to the low bits of the traffic class, RFC 6040 section 4.1's normal mode
		family, hops, word := uint8(NextHeaderIPv4), uint8(DefaultHopLimit), []byte{0x60, (inner[1] & 0b11) << 4, 0, 0}
		if inner[0]>>4 == 6 {
			family, hops, word = NextHeaderIPv6, inner[7], inner[:4]
		}
		switch active := ipv6HeaderLen + srhFixedLen + addrLen*left; {
		case !slices.Equal(read, path):
			ht.Fatalf("the path read back as %v, want %v", read, path)
		case left != len(path)-1:
			ht.Fatalf("segments left is %d for a path of %d", left, len(path))
		case netip.AddrFrom16([16]byte(raw[active:active+addrLen])) != path[0]:
			ht.Fatalf("the active segment is %v, want %v", netip.AddrFrom16([16]byte(raw[active:active+addrLen])), path[0])
		case raw[ipv6HeaderLen] != family || raw[ipv6HeaderLen+routingTypeInHeader] != routingTypeSegment:
			ht.Fatalf("the routing header of type %d announces %d, want an SRH announcing %d", raw[ipv6HeaderLen+routingTypeInHeader], raw[ipv6HeaderLen], family)
		case netip.AddrFrom16([16]byte(raw[24:40])) != path[0] || netip.AddrFrom16([16]byte(raw[8:24])) != source:
			ht.Fatalf("the outer header runs from %v to %v", netip.AddrFrom16([16]byte(raw[8:24])), netip.AddrFrom16([16]byte(raw[24:40])))
		case int(binary.BigEndian.Uint16(raw[4:])) != len(raw)-ipv6HeaderLen || raw[7] != hops:
			ht.Fatalf("the outer header carries payload length %d and hop limit %d, want %d and %d",
				binary.BigEndian.Uint16(raw[4:]), raw[7], len(raw)-ipv6HeaderLen, hops)
		case !bytes.Equal(raw[:4], word):
			ht.Fatalf("the outer header opens with %x, want %x", raw[:4], word)
		case !bytes.Equal(raw[ipv6HeaderLen+srhFixedLen+addrLen*count:], inner):
			ht.Fatal("the bytes after the routing header are not the inner packet")
		}

		for step, want := range path[1:] {
			before := raw[7]
			next, err := End(raw)
			if before <= 1 {
				if !errors.Is(err, ErrHopLimit) {
					ht.Fatalf("waypoint %d with hop limit %d returned %v, %v, want ErrHopLimit", step, before, next, err)
				}
				return
			}
			destination := netip.AddrFrom16([16]byte(raw[24:40]))
			if err != nil || next != want || raw[7] != before-1 || destination != next {
				ht.Fatalf("waypoint %d returned %v, %v, leaving destination %v and hop limit %d, want %v and %d",
					step, next, err, destination, raw[7], want, before-1)
			}
		}
		delivered, got, err := Decap(raw)
		if err != nil || got != family || !bytes.Equal(delivered, inner) {
			ht.Fatalf("the exit delivered %d bytes of family %d, %v, want the %d byte inner packet of family %d",
				len(delivered), got, err, len(inner), family)
		}
		// the dataplane writes the delivered packet's tun framing into the outer header in front of it
		if &delivered[len(delivered)-1] != &raw[len(raw)-1] {
			ht.Fatal("the exit delivered the inner packet outside the tail of the outer one")
		}
	})
}

// AppendEncapsulated appends to a buffer holding bytes of its own, with room
// past them that an earlier packet left filled, the bytes Encapsulate returns:
// Overhead bytes of header and then the inner packet. The buffer is filled with
// a byte the expected header does not contain, so a header byte left as it was
// found shows up as a difference, rather than going on the wire as a stray
// fragment of whatever the buffer held. A buffer with room for the result is
// written in place, the bytes before it stay, and a refusal of what
// Encapsulate refuses hands the buffer back as it was.
func TestAppendEncapsulatedWritesWhatEncapsulateReturns(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		// mostly what both accept, and now and then what both refuse
		inner := hegel.Draw(ht, mostly(innerPackets(), hegel.Binary(0, 64)))
		source := hegel.Draw(ht, mostly(usableAddresses(), hegel.Generator[netip.Addr](hegel.IPAddresses())))
		path := hegel.Draw(ht, mostly(usablePaths(), hegel.Lists(hegel.IPAddresses()).MaxSize(MaxSegments+1)))
		prefix := hegel.Draw(ht, pbt.Spanning(0, 64))
		// the room past the buffer's bytes, now and then too little for the result
		room := Overhead(len(path)) + len(inner) + hegel.Draw(ht, pbt.Spanning(0, 64))
		if hegel.Draw(ht, hegel.WeightedBooleans(1.0/8)) {
			room = hegel.Draw(ht, pbt.Spanning(0, Overhead(len(path))+len(inner)-1))
		}

		want, wantErr := Encapsulate(inner, source, path)
		fill := hegel.Draw(ht, hegel.Integers[byte](0, 255))
		if wantErr == nil {
			header := want[:Overhead(len(path))]
			for tries := 0; bytes.IndexByte(header, fill) >= 0; tries++ {
				ht.Assume(tries < 256)
				fill++
			}
		}
		dst := bytes.Repeat([]byte{fill}, prefix+room)[:prefix]

		got, err := AppendEncapsulated(dst, inner, source, path)
		switch {
		case wantErr != nil:
			if err == nil || len(got) != prefix || cap(got) != cap(dst) {
				ht.Fatalf("AppendEncapsulated answered %d bytes and %v where Encapsulate refused with %v", len(got), err, wantErr)
			}
		case err != nil:
			ht.Fatalf("AppendEncapsulated refused what Encapsulate wrote: %v", err)
		case len(want) != Overhead(len(path))+len(inner) || !bytes.Equal(want[Overhead(len(path)):], inner):
			ht.Fatalf("Encapsulate returned %d bytes that are not %d of header and the %d byte packet", len(want), Overhead(len(path)), len(inner))
		case len(got) != prefix+len(want) || !bytes.Equal(got[prefix:], want):
			ht.Fatalf("AppendEncapsulated wrote\n%x\nwhere Encapsulate returned\n%x", got[prefix:], want)
		case bytes.Count(got[:prefix], []byte{fill}) != prefix:
			ht.Fatal("AppendEncapsulated changed the bytes the buffer held before it")
		case room >= len(want) && &got[:1][0] != &dst[:1][0]:
			ht.Fatalf("AppendEncapsulated moved the result out of a buffer with %d bytes of room for its %d", room, len(want))
		}
	})
}
