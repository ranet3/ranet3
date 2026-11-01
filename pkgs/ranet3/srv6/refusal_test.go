// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package srv6

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"
	"testing"
)

// refusedWith reports whether err is a Refusal of code pointing at pointer
func refusedWith(err error, code uint8, pointer int) bool {
	refusal, ok := errors.AsType[*Refusal](err)
	return ok && refusal.Code == code && refusal.Pointer == pointer
}

// refusal is the code and the pointer a case wants
type refusal struct {
	code    uint8
	pointer int
}

// chained is an IPv6 packet to 3fff:b:0:206::1 at hop limit hops, its fixed header naming first and followed by parts, each naming the next in its first octet
func chained(hops uint8, first byte, parts ...[]byte) []byte {
	raw := slices.Concat(append([][]byte{make([]byte, ipv6HeaderLen)}, parts...)...)
	raw[0], raw[6], raw[7] = 0x60, first, hops
	binary.BigEndian.PutUint16(raw[4:], uint16(len(raw)-ipv6HeaderLen))
	copy(raw[8:], addr16(addr("3fff:b:0:100::1")))
	copy(raw[24:], addr16(addr("3fff:b:0:206::1")))
	return raw
}

// srh is an SRH naming next at segments left, its segments in wire order
func srh(next, left byte, segments ...netip.Addr) []byte {
	header := []byte{next, byte(2 * len(segments)), routingTypeSegment, left, byte(len(segments) - 1), 0, 0, 0}
	for _, segment := range segments {
		header = append(header, addr16(segment)...)
	}
	return header
}

// routing is a routing header of kind naming next at segments left, of 8 octets
func routing(next, kind, left byte) []byte { return []byte{next, 0, kind, left, 0, 0, 0, 0} }

// atomic is the fragment header of a whole packet naming next, its Fragment Offset and M flag 0, RFC 8200 section 4.5
func atomic(next byte) []byte { return []byte{next, 0, 0, 0, 0, 0, 0, 7} }

// lastFragment is the fragment header of the last fragment of a larger packet naming next, its Fragment Offset 1 and its M flag 0
func lastFragment(next byte) []byte { return []byte{next, 0, 0, 1 << 3, 0, 0, 0, 7} }

// destinationOptions is count destination options headers of 8 octets, the last naming next
func destinationOptions(count int, next byte) [][]byte {
	chain := make([][]byte, count)
	for i := range chain {
		chain[i] = options(nextHeaderDestOpts)
	}
	chain[count-1][0] = next
	return chain
}

// RFC 8986 section 4.8 S05: "Proceed to process the next header in the packet", and S02 and S06 "Remove the outer IPv6 header with all its extension headers"
// RFC 8200 section 4.4: "If Segments Left is zero, the node must ignore the Routing header and proceed to process the next header in the packet"
// section 4.5, a fragment with "both the Fragment Offset field and the M flag" zero "should be processed as a fully reassembled packet"
// section 4.1: "IPv6 nodes must accept and attempt to process extension headers in any order and occurring any number of times in the same packet"
// so End.DT46 delivers the inner packet behind each header it proceeds past, an SRH at segments left 0 whose Last Entry runs past its length among them
// and behind 7 destination options headers and an SRH, the 8th, the most extension headers walk steps past
// a fragment of a larger packet, the first or the last, waits for a reassembly neither End nor the exit does
func TestExitDeliversBehindEveryHeaderItProceedsPast(t *testing.T) {
	sid := addr("3fff:b:0:206::1")
	v6, v4 := innerV6("payload"), innerV4("payload")
	broken := srh(NextHeaderIPv6, 0, sid)
	broken[lastEntryInHeader] = 3
	for _, c := range []struct {
		name  string
		raw   []byte
		inner []byte
	}{
		{"an ipv6 packet behind hop-by-hop with no routing header", chained(64, nextHeaderHopByHop, options(NextHeaderIPv6), v6), v6},
		{"an ipv4 packet behind destination options with no routing header", chained(64, nextHeaderDestOpts, options(NextHeaderIPv4), v4), v4},
		{"behind a routing header of type 2 at segments left 0", chained(64, nextHeaderRouting, routing(NextHeaderIPv6, 2, 0), v6), v6},
		{"behind a routing header of type 200 at segments left 0", chained(64, nextHeaderRouting, routing(NextHeaderIPv4, 200, 0), v4), v4},
		{"behind destination options after the SRH", chained(64, nextHeaderRouting, srh(nextHeaderDestOpts, 0, sid), options(NextHeaderIPv6), v6), v6},
		{"behind an authentication header after the SRH", chained(64, nextHeaderRouting, srh(nextHeaderAuth, 0, sid), authentication(NextHeaderIPv4), v4), v4},
		{"behind an atomic fragment after the SRH", chained(64, nextHeaderRouting, srh(nextHeaderFragment, 0, sid), atomic(NextHeaderIPv6), v6), v6},
		{"behind an atomic fragment with no routing header", chained(64, nextHeaderFragment, atomic(NextHeaderIPv4), v4), v4},
		{"behind an SRH at segments left 0 whose Last Entry runs past its length", chained(64, nextHeaderRouting, broken, v6), v6},
		{"behind 7 destination options headers and an SRH, the 8th", chained(64, nextHeaderDestOpts, append(destinationOptions(7, nextHeaderRouting), srh(NextHeaderIPv6, 0, sid), v6)...), v6},
	} {
		inner, family, err := Decap(c.raw)
		want := uint8(NextHeaderIPv6)
		if c.inner[0]>>4 == 4 {
			want = NextHeaderIPv4
		}
		if err != nil || family != want || !bytes.Equal(inner, c.inner) {
			t.Errorf("%s: Decap returned %d octets of family %d, %v, want the inner packet", c.name, len(inner), family, err)
		}
	}
	for name, raw := range map[string][]byte{
		"a first fragment behind the SRH":        chained(64, nextHeaderRouting, srh(nextHeaderFragment, 0, sid), fragment(NextHeaderIPv6, 0), v6),
		"a last fragment behind the SRH":         chained(64, nextHeaderRouting, srh(nextHeaderFragment, 0, sid), lastFragment(NextHeaderIPv6), v6),
		"a last fragment with no routing header": chained(64, nextHeaderFragment, lastFragment(NextHeaderIPv6), v6),
	} {
		if _, err := End(bytes.Clone(raw)); !errors.Is(err, errFragment) {
			t.Errorf("%s: End returned %v, want errFragment", name, err)
		}
		if _, _, err := Decap(raw); !errors.Is(err, errFragment) {
			t.Errorf("%s: Decap returned %v, want errFragment", name, err)
		}
	}
}

// each refusal End and End.DT46 answer, with the code and the pointer of its RFC
// RFC 8986 section 4.8 S03 and section 4.1 S10: code 0 "and Pointer set to the Segments Left field"
// section 4.1.1 S04: code 4 "and Pointer set to the offset of the Upper-Layer header", which End.DT46's S10 reaches for any header but IPv4 and IPv6, and End for every one
// RFC 8200 section 4.4: "If Segments Left is non-zero, the node must discard the packet and send an ICMP Parameter Problem, Code 0, message to the packet's Source Address, pointing to the unrecognized Routing Type"
// section 4: code 1 at "the offset of the unrecognized value", and "The same action should be taken if a node encounters a Next Header value of zero in any header other than an IPv6 header"
// RFC 4443 section 3.4: a node that "finds a problem with a field in the IPv6 header or extension headers such that it cannot complete processing the packet" SHOULD answer, "indicating the type and location of the problem"
// RFC 8883 section 2.3: code 6 "when a node discards a packet because the size of an extension header exceeds its processing limit", pointing at "the first octet in the extension header that exceeds the limit"
// section 2.5: code 8 for "an extension header chain that exceeds a limit on the number of extension headers", pointing at "the first octet of the first extension header that is beyond the limit"
func TestEndAndExitRefuseEachHeaderAtItsField(t *testing.T) {
	sid, next := addr("3fff:b:0:206::1"), addr("3fff:b:0:506::1")
	v6, v4, udp := innerV6("payload"), innerV4("payload"), make([]byte, 8)
	afterSRH := ipv6HeaderLen + srhFixedLen + addrLen
	tooMany := make([]netip.Addr, MaxSegments+1)
	for i := range tooMany {
		tooMany[i] = next
	}
	pastLength := srh(NextHeaderIPv6, 1, next, sid)
	pastLength[lastEntryInHeader] = 5
	// ninth is where the 9th extension header of a chain of destination options starts, the first beyond walk's limit of 8
	ninth := ipv6HeaderLen + extensionUnit*maxExtensionHeaders
	// atLeft is the code 0 at the Segments Left of an SRH right behind the fixed header
	atLeft := &refusal{0, ipv6HeaderLen + segmentsLeftInHeader}
	both := func(r refusal) [2]*refusal { return [2]*refusal{&r, &r} }
	for _, c := range []struct {
		name string
		raw  []byte
		// want is End's refusal and then the exit's, nil for one the case does not ask
		want [2]*refusal
	}{
		{"an exit reached with segments left", chained(64, nextHeaderRouting, srh(NextHeaderIPv6, 1, next, sid), v6), [2]*refusal{nil, atLeft}},
		{"udp behind the SRH", chained(64, nextHeaderRouting, srh(17, 0, sid), udp), both(refusal{4, afterSRH})},
		{"udp behind destination options after the SRH", chained(64, nextHeaderRouting, srh(nextHeaderDestOpts, 0, sid), options(17), udp), both(refusal{4, afterSRH + 8})},
		{"an echo request with no routing header", chained(64, icmpv6Next, message(128)), both(refusal{4, ipv6HeaderLen})},
		{"udp behind hop-by-hop with no routing header", chained(64, nextHeaderHopByHop, options(17), udp), both(refusal{4, ipv6HeaderLen + 8})},
		{"a routing header of type 0 with segments left", chained(64, nextHeaderRouting, routing(NextHeaderIPv6, 0, 1), v6), both(refusal{0, ipv6HeaderLen + routingTypeInHeader})},
		{"a routing header of type 200 with segments left behind hop-by-hop", chained(64, nextHeaderHopByHop, options(nextHeaderRouting), routing(NextHeaderIPv6, 200, 1), v6), both(refusal{0, ipv6HeaderLen + 8 + routingTypeInHeader})},
		{"hop-by-hop behind destination options", chained(64, nextHeaderDestOpts, options(nextHeaderHopByHop), options(nextHeaderRouting), srh(NextHeaderIPv6, 1, next, sid), v6), both(refusal{1, ipv6HeaderLen})},
		{"an SRH naming hop-by-hop next", chained(64, nextHeaderRouting, srh(nextHeaderHopByHop, 0, sid), options(NextHeaderIPv6), v6), both(refusal{1, ipv6HeaderLen})},
		{"a mobility header on the walk", chained(64, nextHeaderDestOpts, options(nextHeaderMobility), options(nextHeaderRouting), srh(NextHeaderIPv6, 1, next, sid), v6), both(refusal{1, ipv6HeaderLen})},
		{"an experimental header first", chained(64, nextHeaderTesting2, options(nextHeaderRouting), srh(NextHeaderIPv6, 1, next, sid), v6), both(refusal{1, nextHeaderInIPv6})},
		{"a header running past the packet", chained(64, nextHeaderDestOpts, []byte{nextHeaderRouting, 40, 0, 0, 0, 0, 0, 0}), both(refusal{0, ipv6HeaderLen + 1})},
		{"a packet ending one octet into a header", chained(64, nextHeaderDestOpts, []byte{nextHeaderRouting}), both(refusal{0, payloadLengthInIPv6})},
		{"a packet ending inside a fragment header", chained(64, nextHeaderFragment, []byte{NextHeaderIPv6, 0, 0, 0}), both(refusal{0, payloadLengthInIPv6})},
		{"a 9th destination options header", chained(64, nextHeaderDestOpts, append(destinationOptions(9, nextHeaderRouting), srh(NextHeaderIPv6, 1, next, sid), v6)...), both(refusal{8, ninth})},
		{"an SRH at segments left 0 as the 9th header", chained(64, nextHeaderDestOpts, append(destinationOptions(8, nextHeaderRouting), srh(NextHeaderIPv6, 0, sid), v6)...), both(refusal{8, ninth})},
		{"a mobility header as the 9th header", chained(64, nextHeaderDestOpts, append(destinationOptions(8, nextHeaderMobility), options(NextHeaderIPv6), v6)...), both(refusal{1, ninth - extensionUnit})},
		{"a list of 17 segments with segments left", chained(64, nextHeaderRouting, srh(NextHeaderIPv6, 1, tooMany...), v6), [2]*refusal{{6, ipv6HeaderLen}, atLeft}},
		{"a Last Entry past its length with segments left", chained(64, nextHeaderRouting, pastLength, v6), [2]*refusal{atLeft, atLeft}},
		{"a Segments Left past the Last Entry of 2 segments", chained(64, nextHeaderRouting, srh(NextHeaderIPv6, 3, next, sid), v6), [2]*refusal{atLeft, atLeft}},
		{"an ipv4 packet behind next header 41", chained(64, nextHeaderRouting, srh(NextHeaderIPv6, 0, sid), v4), [2]*refusal{{4, afterSRH}, {0, afterSRH}}},
		{"an ipv6 packet behind next header 4", chained(64, nextHeaderRouting, srh(NextHeaderIPv4, 0, sid), v6), [2]*refusal{nil, {0, afterSRH}}},
		{"an ipv6 header cut short", chained(64, nextHeaderRouting, srh(NextHeaderIPv6, 0, sid), v6[:30]), [2]*refusal{nil, {0, afterSRH}}},
		{"nothing behind next header 4", chained(64, nextHeaderRouting, srh(NextHeaderIPv4, 0, sid)), [2]*refusal{nil, {0, afterSRH}}},
	} {
		if want := c.want[0]; want != nil {
			if _, err := End(bytes.Clone(c.raw)); !refusedWith(err, want.code, want.pointer) {
				t.Errorf("%s: End returned %v, want code %d at %d", c.name, err, want.code, want.pointer)
			}
		}
		if want := c.want[1]; want != nil {
			if _, _, err := Decap(bytes.Clone(c.raw)); !refusedWith(err, want.code, want.pointer) {
				t.Errorf("%s: Decap returned %v, want code %d at %d", c.name, err, want.code, want.pointer)
			}
		}
	}
}

// RFC 8986 section 4.1 checks the hop limit, S05 to S07, before Last Entry and Segments Left, S08 to S11, so a packet out of hops gets Time Exceeded however its list is malformed
// and RFC 8754 section 4.3.1.1 reads Last Entry only with segments left, so End at segments left 0 reaches the upper-layer header past a Last Entry running past its length
func TestEndChecksTheHopLimitFirstAndLastEntryOnlyWithSegmentsLeft(t *testing.T) {
	sid, next := addr("3fff:b:0:206::1"), addr("3fff:b:0:506::1")
	v6 := innerV6("payload")
	pastLength := srh(NextHeaderIPv6, 1, next, sid)
	pastLength[lastEntryInHeader] = 5
	pastLeft := srh(NextHeaderIPv6, 3, next, sid)
	tooMany := make([]netip.Addr, MaxSegments+1)
	for i := range tooMany {
		tooMany[i] = next
	}
	for name, header := range map[string][]byte{
		"a Last Entry past its length":     pastLength,
		"a Segments Left past Last Entry":  pastLeft,
		"a list of 17 segments":            srh(NextHeaderIPv6, 1, tooMany...),
		"a well formed list of 2 segments": srh(NextHeaderIPv6, 1, next, sid),
	} {
		if _, err := End(chained(1, nextHeaderRouting, header, v6)); !errors.Is(err, ErrHopLimit) {
			t.Errorf("%s at hop limit 1: End returned %v, want ErrHopLimit", name, err)
		}
	}
	broken := srh(NextHeaderIPv6, 0, sid)
	broken[lastEntryInHeader] = 3
	if _, err := End(chained(64, nextHeaderRouting, broken, v6)); !refusedWith(err, icmpUpperLayer, ipv6HeaderLen+srhFixedLen+addrLen) {
		t.Errorf("End at segments left 0 with a Last Entry past its length returned %v, want code 4 at the inner packet", err)
	}
}

// RFC 8200 section 4.1 has a node accept extension headers "in any order and occurring any number of times", and RFC 8986 section 4.1 S02 to S03 proceed past an SRH at segments left 0
// so End acts on an SRH behind an authentication header, behind an atomic fragment, and behind a routing header at segments left 0, an SRH or another type
// and on one behind 8 destination options headers, the most walk steps past, the SRH being the 9th header and one walk acts on rather than steps past
func TestEndActsOnTheSRHBehindEveryHeaderItProceedsPast(t *testing.T) {
	sid, next := addr("3fff:b:0:206::1"), addr("3fff:b:0:506::1")
	v6 := innerV6("payload")
	active := srh(NextHeaderIPv6, 1, next, sid)
	for name, raw := range map[string][]byte{
		"behind an authentication header":             chained(64, nextHeaderAuth, authentication(nextHeaderRouting), active, v6),
		"behind an atomic fragment":                   chained(64, nextHeaderFragment, atomic(nextHeaderRouting), active, v6),
		"behind an SRH at segments left 0":            chained(64, nextHeaderRouting, srh(nextHeaderRouting, 0, addr("3fff:b:0:906::1")), active, v6),
		"behind a routing header of type 2 at left 0": chained(64, nextHeaderRouting, routing(nextHeaderRouting, 2, 0), active, v6),
		"behind 8 destination options headers":        chained(64, nextHeaderDestOpts, append(destinationOptions(8, nextHeaderRouting), active, v6)...),
	} {
		got, err := End(raw)
		if err != nil || got != next || netip.AddrFrom16([16]byte(raw[24:40])) != next || raw[7] != 63 {
			t.Errorf("%s: End returned %s, %v, the destination %s at hop limit %d, want %s at 63", name, got, err, netip.AddrFrom16([16]byte(raw[24:40])), raw[7], next)
		}
	}
}
