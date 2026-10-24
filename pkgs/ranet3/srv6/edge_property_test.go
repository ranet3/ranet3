// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package srv6

import (
	"encoding/binary"
	"math"
	"slices"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// edgeRead are the hop-by-hop, routing and destination options headers the model's walk reads, edgeBound how many of them at most
// and edgeForwarded the routing types RFC 7045 section 2.1 has it forward
var (
	edgeRead      = []byte{0, 43, 60}
	edgeForwarded = []byte{2, 3, 253, 254}
)

const edgeBound = 16

// edge is the model's verdict on the walk of a packet entering the mesh, of p.length octets, RFC 8200 section 4
// the walk reads the edgeRead headers, edgeBound at most, and stops at the first header of any other kind or at what ends the chain
// a header it reads that the packet ends inside is invalid, the one past the bound it would read is invalid, and a routing header of a type outside edgeForwarded is refused
// on a pass it gives the header the walk stopped at and where that header starts
func (p laidPacket) edge() (EdgeVerdict, byte, int) {
	start := ipv6HeaderLen
	for i, h := range p.headers {
		switch {
		case !slices.Contains(edgeRead, h.kind):
			return EdgePass, h.kind, start
		case i == edgeBound || p.length < start+h.octets:
			return EdgeInvalid, h.kind, start
		case h.kind == 43 && !slices.Contains(edgeForwarded, h.fill):
			return EdgeRoutingHeader, h.kind, start
		}
		start += h.octets
	}
	return EdgePass, p.last, start
}

// checkEdgeLaid holds WalkEdge on p, cut to p.length octets, to the model
func checkEdgeLaid(tb testing.TB, p laidPacket) {
	tb.Helper()
	raw, _ := p.whole()
	p.length = min(p.length, len(raw))
	verdict, next, offset := WalkEdge(slices.Clip(raw[:p.length]))
	if wantVerdict, wantNext, wantOffset := p.edge(); verdict != wantVerdict || next != wantNext || offset != wantOffset {
		tb.Fatalf("the walk over %d octets of a packet laid out as %+v gave verdict %d at next header %d offset %d, the model %d at %d offset %d", p.length, p, verdict, next, offset, wantVerdict, wantNext, wantOffset)
	}
}

// edgeLasts end a laid packet's chain: a TCP, UDP or ICMPv6 header, no next header, ESP, a later fragment, AH, or an encapsulated IPv4 or IPv6 packet
var edgeLasts = []byte{6, 17, 58, 59, 50, 44, 51, 4, 41}

// edgeKinds are the headers a laid chain holds, the three the walk reads and the two that stop it, a fragment header at offset 0 and AH
var edgeKinds = slices.Concat(edgeRead, []byte{44, 51})

// any chain of hop-by-hop, routing and destination options headers, with fragment and authentication headers among them, every routing type and any length
// cut anywhere or near where a header starts, is walked as the model of RFC 8200 section 4 with RFC 7045 section 2.1's routing types walks it
// every routing type behind each kind of header, every length of each, every cut through a short chain, and chains of the headers the walk reads from one short of its bound to two past it are tried first, which meets each in every run
func TestEdgeWalkFollowsTheModelOfTheChain(t *testing.T) {
	for _, kind := range edgeKinds {
		for routing := range 256 {
			checkEdgeLaid(t, laidPacket{headers: []laidHeader{laid(kind, 0, 2), laid(43, 0, byte(routing))}, last: 17, length: math.MaxInt})
			checkEdgeLaid(t, laidPacket{headers: []laidHeader{laid(43, 0, byte(routing)), laid(kind, 0, 2)}, last: 17, length: math.MaxInt})
		}
		for units := range 256 {
			checkEdgeLaid(t, laidPacket{headers: []laidHeader{laid(kind, units, 2)}, last: 41, length: math.MaxInt})
		}
		p := laidPacket{headers: []laidHeader{laid(kind, 1, 2), laid(43, 0, 2)}, last: 6}
		raw, _ := p.whole()
		for p.length = ipv6HeaderLen; p.length <= len(raw); p.length++ {
			checkEdgeLaid(t, p)
		}
	}
	for count := edgeBound - 1; count <= edgeBound+2; count++ {
		var headers []laidHeader
		for i := range count {
			headers = append(headers, laid(edgeRead[i%len(edgeRead)], 0, 253))
		}
		checkEdgeLaid(t, laidPacket{headers: headers, last: 17, length: math.MaxInt})
		checkEdgeLaid(t, laidPacket{headers: slices.Repeat([]laidHeader{laid(43, 0, 2)}, count), last: 17, length: math.MaxInt})
	}
	pbt.Check(t, func(ht *hegel.T) {
		p := laidPacket{last: hegel.Draw(ht, hegel.SampledFrom(edgeLasts)), later: 1, length: math.MaxInt}
		// mostly a few headers, and often as many as the walk reads, one fewer or more
		for range hegel.Draw(ht, hegel.OneOf(pbt.Spanning(0, 3), hegel.SampledFrom([]int{edgeBound - 1, edgeBound, edgeBound + 1, edgeBound + 2}))) {
			kind := hegel.Draw(ht, mostly(hegel.SampledFrom(edgeRead), hegel.SampledFrom(edgeKinds)))
			// a routing type the walk forwards mostly, so a chain reaches the bound, and now and then any of the 256
			routing := hegel.Draw(ht, mostly(hegel.SampledFrom(edgeForwarded), pbt.Spanning[byte](0, 255)))
			p.headers = append(p.headers, laid(kind, hegel.Draw(ht, mostly(pbt.Spanning(0, 2), pbt.Spanning(0, 255))), routing))
		}
		// half the packets are cut a few octets past where a header or the item ending the chain starts, where the walk decides between reading on and stopping
		if hegel.Draw(ht, hegel.Booleans()) {
			_, starts := p.whole()
			p.length = hegel.Draw(ht, hegel.SampledFrom(starts)) + hegel.Draw(ht, pbt.Spanning(0, extensionUnit))
		}
		checkEdgeLaid(ht, p)
	})
}

// decapsulable draws a packet an End.DT46 may decapsulate: an encapsulation through any path walked to its last segment, or an IPv4 or IPv6 packet behind the fixed header alone
// either now and then behind hop-by-hop and destination options headers, and a quarter of the time mangled as the parsers' properties mangle a packet
func decapsulable() hegel.Generator[[]byte] {
	return hegel.Composite(func(tc hegel.TestCase) []byte {
		if hegel.Draw(tc, hegel.WeightedBooleans(1.0/4)) {
			return hegel.Draw(tc, hegel.OneOf(mangledPackets(), lyingLengths(), boundaryFields()))
		}
		inner := hegel.Draw(tc, innerPackets())
		var raw []byte
		if hegel.Draw(tc, hegel.Booleans()) {
			var err error
			if raw, err = Encapsulate(inner, hegel.Draw(tc, usableAddresses()), hegel.Draw(tc, usablePaths())); err != nil {
				tc.Errorf("a packet and a path drawn to be accepted were refused: %v", err)
			}
			for {
				if _, err := End(raw); err != nil {
					break
				}
			}
		} else {
			family, _ := innerNextHeader(inner)
			raw = make([]byte, ipv6HeaderLen, ipv6HeaderLen+len(inner))
			raw[0], raw[6], raw[7] = 0x60, family, 64
			copy(raw[8:], addr16(hegel.Draw(tc, usableAddresses())))
			copy(raw[24:], addr16(hegel.Draw(tc, usableAddresses())))
			raw = append(raw, inner...)
		}
		for range hegel.Draw(tc, hegel.Integers(0, 2)) {
			header := []byte{raw[6], 0, 1, 4, 0, 0, 0, 0}
			raw = slices.Concat(raw[:ipv6HeaderLen], header, raw[ipv6HeaderLen:])
			raw[6] = hegel.Draw(tc, hegel.SampledFrom([]byte{nextHeaderHopByHop, nextHeaderDestOpts}))
		}
		binary.BigEndian.PutUint16(raw[4:], uint16(len(raw)-ipv6HeaderLen))
		return raw
	})
}

// every packet Decap hands back an inner packet for is one the walk refuses, or one it walks to that inner packet, its family as the next header and its start as the offset
// so an inner packet a SID of another node would decapsulate never passes the walk unread, RFC 8754 section 5.1 level 1
func TestEdgeWalkReachesEveryInnerPacketAnExitDecapsulates(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		raw := slices.Clip(hegel.Draw(ht, decapsulable()))
		if len(raw) < ipv6HeaderLen || raw[0]>>4 != 6 {
			return
		}
		inner, family, err := Decap(raw)
		if err != nil {
			return
		}
		if verdict, next, offset := WalkEdge(raw); verdict == EdgePass && (next != family || offset != len(raw)-len(inner)) {
			ht.Fatalf("Decap delivers the %d octets of family %d behind octet %d, and the walk passed the packet at next header %d offset %d", len(inner), family, len(raw)-len(inner), next, offset)
		}
	})
}
