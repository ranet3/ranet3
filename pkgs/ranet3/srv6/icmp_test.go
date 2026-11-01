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

// always lets every answer out, for a test of what an answer holds
func always() bool { return true }

// behindRouting is segmentRouted's packet with what follows its routing header replaced by headers destination options headers and then an ICMPv6 message of kind
func behindRouting(t *testing.T, headers int, kind byte) []byte {
	t.Helper()
	var tail [][]byte
	for range headers {
		tail = append(tail, options(nextHeaderDestOpts))
	}
	if headers == 0 {
		return afterRouting(t, icmpv6Next, message(kind))
	}
	tail[len(tail)-1][0] = icmpv6Next
	return afterRouting(t, nextHeaderDestOpts, append(tail, message(kind))...)
}

// afterRouting is segmentRouted's packet with what follows its routing header, right behind the fixed header, replaced by the headers of tail, the first of which next names
func afterRouting(t *testing.T, next byte, tail ...[]byte) []byte {
	t.Helper()
	raw := segmentRouted(t)
	offset := ipv6HeaderLen
	end := offset + srhFixedLen + extensionUnit*int(raw[offset+1])
	raw = append(raw[:end:end], slices.Concat(tail...)...)
	raw[offset] = next
	binary.BigEndian.PutUint16(raw[4:], uint16(len(raw)-ipv6HeaderLen))
	return raw
}

// withHopByHop is raw with a hop-by-hop header between its fixed header and the header after it
func withHopByHop(raw []byte) []byte {
	out := slices.Concat(raw[:ipv6HeaderLen], options(raw[6]), raw[ipv6HeaderLen:])
	out[6] = nextHeaderHopByHop
	binary.BigEndian.PutUint16(out[4:], uint16(len(out)-ipv6HeaderLen))
	return out
}

// options is a hop-by-hop or destination options header of 8 octets naming next, one PadN option filling it, RFC 8200 section 4.2
func options(next byte) []byte { return []byte{next, 0, 1, 4, 0, 0, 0, 0} }

// fragment is a fragment header naming next at offset, in 8-octet units, with M set, RFC 8200 section 4.5
func fragment(next byte, offset uint16) []byte {
	header := []byte{next, 0, 0, 0, 0, 0, 0, 7}
	binary.BigEndian.PutUint16(header[2:], offset<<3|1)
	return header
}

// authentication is an AH of 24 octets naming next, an SPI, a sequence number and a 12 octet ICV, its length 4 by RFC 4302 section 2.2
func authentication(next byte) []byte {
	return append([]byte{next, 4, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1}, make([]byte, 12)...)
}

// message is an ICMPv6 message of kind, its 8 octet header and nothing behind it
func message(kind byte) []byte { return []byte{kind, 0, 0, 0, 0, 0, 0, 0} }

// expiring is a packet steered through two segments with hop limit 1 and front destination options headers in front of its routing header
// End refuses it with ErrHopLimit, as the End SID it reaches does
func expiring(t *testing.T, front int) []byte {
	t.Helper()
	path := []netip.Addr{addr("3fff:b:0:206::2"), addr("3fff:b:0:506::1")}
	raw, err := Encapsulate(innerV6("payload"), addr("3fff:b:0:100::1"), path)
	if err != nil {
		t.Fatal(err)
	}
	chain := make([][]byte, front)
	for i := range chain {
		chain[i] = options(nextHeaderDestOpts)
	}
	if front > 0 {
		chain[front-1][0] = raw[6]
		raw = slices.Concat(raw[:ipv6HeaderLen], slices.Concat(chain...), raw[ipv6HeaderLen:])
		raw[6] = nextHeaderDestOpts
	}
	raw[7] = 1
	binary.BigEndian.PutUint16(raw[4:], uint16(len(raw)-ipv6HeaderLen))
	if _, err := End(bytes.Clone(raw)); !errors.Is(err, ErrHopLimit) {
		t.Fatalf("End refused %d headers in front of the routing header with %v, want ErrHopLimit", front, err)
	}
	return raw
}

// The checksum is the one field a receiver drops the packet over, and it is
// computed here by hand. This sums the finished message the way a receiver
// does, over the same pseudo-header: a correct message sums to zero, which is
// the check RFC 4443 section 2.3 has the receiver make.
func TestTimeExceededChecksumsAsAReceiverVerifiesIt(t *testing.T) {
	sid := addr("3fff:b:0:106::2")
	offending := segmentRouted(t)
	answer := TimeExceeded(offending, sid, always)
	if answer == nil {
		t.Fatal("a packet that expired here was not answered")
	}
	if answer[6] != icmpv6Next || answer[ipv6HeaderLen] != icmpTimeExceeded || answer[ipv6HeaderLen+1] != 0 {
		t.Fatalf("the answer is next header %d type %d code %d", answer[6], answer[ipv6HeaderLen], answer[ipv6HeaderLen+1])
	}
	if got := netip.AddrFrom16([16]byte(answer[8:24])); got != sid {
		t.Errorf("the answer is sent from %s, want the segment it was addressed to", got)
	}
	if got := netip.AddrFrom16([16]byte(answer[24:40])); got != netip.AddrFrom16([16]byte(offending[8:24])) {
		t.Errorf("the answer is addressed to %s", got)
	}
	body := answer[ipv6HeaderLen:]
	if got := verify(sid, netip.AddrFrom16([16]byte(answer[24:40])), body); got != 0 {
		t.Errorf("a receiver sums the message to %#04x, want zero", got)
	}
	// The sender matches the error to its own packet by the quoted bytes, and
	// the whole message has to reach it without fragmenting.
	if len(answer) > MinimumIPv6MTU {
		t.Errorf("the answer is %d bytes, over the %d byte minimum", len(answer), MinimumIPv6MTU)
	}
	if string(body[icmpHeaderLen:]) != string(offending) {
		t.Error("the answer does not quote the packet it is about")
	}
}

// A packet quoted at the minimum MTU is truncated rather than dropped, and the
// message still verifies, which is the odd-length path through the checksum.
func TestLargeOffendingPacketIsQuotedUpToTheMinimumMTU(t *testing.T) {
	sid := addr("3fff:b:0:106::2")
	offending := append(segmentRouted(t), make([]byte, 2000)...)
	binary.BigEndian.PutUint16(offending[4:], uint16(len(offending)-ipv6HeaderLen))
	answer := ParameterProblem(offending, sid, &Refusal{Code: icmpErroneousHeader, Pointer: ipv6HeaderLen + segmentsLeftInHeader}, always)
	if answer == nil {
		t.Fatal("a header this node refused was not answered")
	}
	if len(answer) != MinimumIPv6MTU {
		t.Errorf("the answer is %d bytes, want it filled to %d", len(answer), MinimumIPv6MTU)
	}
	if got := verify(sid, netip.AddrFrom16([16]byte(answer[24:40])), answer[ipv6HeaderLen:]); got != 0 {
		t.Errorf("a receiver sums the message to %#04x, want zero", got)
	}
	if pointer := binary.BigEndian.Uint32(answer[ipv6HeaderLen+4:]); pointer != ipv6HeaderLen+segmentsLeftInHeader {
		t.Errorf("the pointer is %d, want the segments left field at %d", pointer, ipv6HeaderLen+segmentsLeftInHeader)
	}
}

// RFC 4443 section 2.4 (e) names what an error may not answer. Every one of
// these turns one refused packet into many, which is the reason the rule
// exists and the reason a segment routing node is a good place to break it.
// No error this package builds answers one, and none asks the rate limit an
// answer would draw from.
//
// The search finds an ICMPv6 error or a redirect behind every header it steps
// over, and the packets it shows no error in are answered by every error,
// each asking the rate limit once: an informational message, a later
// fragment, no next header, ESP or another protocol, a header the packet ends
// inside the octets the search reads of, and a chain past the headers the
// search steps past.
func TestNoErrorAnswersWhatWouldMultiply(t *testing.T) {
	sid := addr("3fff:b:0:106::2")
	damaged := func(damage func(raw []byte)) []byte {
		raw := segmentRouted(t)
		damage(raw)
		return raw
	}
	// the routing header of segmentRouted's two segments ends here
	end := ipv6HeaderLen + srhFixedLen + addrLen*2
	runningPast := func(raw []byte) []byte {
		raw[end+1] = 200
		return raw
	}
	const anError = icmpTimeExceeded
	for _, c := range []struct {
		name      string
		offending []byte
		answered  bool
	}{
		{"a source that is no single node", damaged(func(raw []byte) { copy(raw[8:], addr16(addr("::"))) }), false},
		{"a multicast source", damaged(func(raw []byte) { copy(raw[8:], addr16(addr("ff02::1"))) }), false},
		{"a multicast destination", damaged(func(raw []byte) { copy(raw[24:], addr16(addr("ff02::1"))) }), false},
		{"another icmp error", behindRouting(t, 0, anError), false},
		{"an icmp error behind destination options after the routing header", behindRouting(t, 1, anError), false},
		{"an icmp error behind hop-by-hop in front of the routing header", withHopByHop(behindRouting(t, 0, anError)), false},
		{"an icmp error behind a first fragment", afterRouting(t, nextHeaderFragment, fragment(icmpv6Next, 0), message(anError)), false},
		{"an icmp error behind an authentication header", afterRouting(t, nextHeaderAuth, authentication(icmpv6Next), message(anError)), false},
		{"an icmp error behind a first fragment and destination options", afterRouting(t, nextHeaderFragment, fragment(nextHeaderDestOpts, 0), options(icmpv6Next), message(anError)), false},
		{"an icmp error behind 7 extension headers", behindRouting(t, maxExtensionHeaders-2, anError), false},
		{"an icmp error behind 8 extension headers, the most the search steps past", behindRouting(t, maxExtensionHeaders-1, anError), false},
		{"a redirect", behindRouting(t, 0, icmpRedirect), false},
		{"a redirect behind destination options", behindRouting(t, 2, icmpRedirect), false},
		{"an icmpv6 header with no type", behindRouting(t, 0, 128)[:end], false},
		{"an icmpv6 header behind a header the packet ends inside", behindRouting(t, 1, 128)[:end+4], false},
		{"an icmpv6 header behind a header running past the end of the packet", runningPast(behindRouting(t, 1, 128)), false},
		{"a packet shorter than a header", []byte{0x60}, false},

		{"an echo request", behindRouting(t, 0, 128), true},
		{"an echo request behind destination options", behindRouting(t, 1, 128), true},
		{"an echo request behind 8 extension headers", behindRouting(t, maxExtensionHeaders-1, 128), true},
		{"an echo request behind hop-by-hop", withHopByHop(behindRouting(t, 0, 128)), true},
		{"an echo request behind a first fragment", afterRouting(t, nextHeaderFragment, fragment(icmpv6Next, 0), message(128)), true},
		{"an echo request behind an authentication header", afterRouting(t, nextHeaderAuth, authentication(icmpv6Next), message(128)), true},
		{"an icmp error behind a later fragment", afterRouting(t, nextHeaderFragment, fragment(icmpv6Next, 1), message(anError)), true},
		{"no next header", afterRouting(t, 59), true},
		{"esp", afterRouting(t, 50, make([]byte, 16)), true},
		{"udp", afterRouting(t, 17, make([]byte, 8)), true},
		{"an extension header the packet ends inside the octets the walk reads of", behindRouting(t, 1, anError)[:end+1], true},
		{"a fragment header the packet ends before the offset of", afterRouting(t, nextHeaderFragment, fragment(icmpv6Next, 0), message(anError))[:end+3], true},
		{"an extension header behind one running past the end of the packet", runningPast(behindRouting(t, 2, anError)), true},
		{"an icmp error behind 9 extension headers, past what the search steps past", behindRouting(t, maxExtensionHeaders, anError), true},
	} {
		for _, builder := range errorBuilders {
			asked := 0
			answer := builder.build(c.offending, sid, func() bool { asked++; return true })
			if (answer != nil) != c.answered || (asked == 1) != c.answered || asked > 1 {
				t.Errorf("%s for %s was built %t asking the rate limit %d times, want built %t", builder.name, c.name, answer != nil, asked, c.answered)
			}
		}
	}
}

// RFC 4443 section 2.4 (e.1): "An ICMPv6 error message MUST NOT be originated as a result of receiving ... An ICMPv6 error message."
// End refuses an ICMPv6 error behind 8 extension headers with code 4 at it, which the search of every answer reaches, so it goes unanswered
// a code 8 refusal lies past that search, so its own steps past as many as 16 extension headers
// and it is answered where that one ends within them without finding an error or a redirect, at an upper-layer header, at ESP or at a fragment other than the first
// TCP behind 9 or 16 headers, an echo request or ESP behind 9, and an ICMPv6 error behind a later fragment behind 9, are answered with code 8 at the 9th header
// and an ICMPv6 error behind 9, or TCP behind 17, goes unanswered
func TestBoundRefusalIsAnsweredOnlyWhereTheSearchFindsNoError(t *testing.T) {
	sid, tcp := addr("3fff:b:0:206::1"), make([]byte, 20)
	behind := func(headers int, last byte, upper []byte) []byte {
		chain := make([][]byte, headers)
		for i := range chain {
			chain[i] = options(nextHeaderDestOpts)
		}
		chain[headers-1][0] = last
		return chained(64, nextHeaderDestOpts, append(chain, upper)...)
	}
	ninth := ipv6HeaderLen + extensionUnit*maxExtensionHeaders
	for _, c := range []struct {
		name     string
		raw      []byte
		want     refusal
		answered bool
	}{
		{"an icmp error behind 8 headers", behind(8, icmpv6Next, message(icmpTimeExceeded)), refusal{icmpUpperLayer, ninth}, false},
		{"tcp behind 9 headers", behind(9, 6, tcp), refusal{icmpTooManyHeaders, ninth}, true},
		{"tcp behind 16 headers", behind(16, 6, tcp), refusal{icmpTooManyHeaders, ninth}, true},
		{"an echo request behind 9 headers", behind(9, icmpv6Next, message(128)), refusal{icmpTooManyHeaders, ninth}, true},
		{"esp behind 9 headers", behind(9, 50, make([]byte, 16)), refusal{icmpTooManyHeaders, ninth}, true},
		{"an icmp error behind a later fragment behind 9 headers", behind(9, nextHeaderFragment, slices.Concat(fragment(icmpv6Next, 1), message(icmpTimeExceeded))), refusal{icmpTooManyHeaders, ninth}, true},
		{"an icmp error behind 9 headers", behind(9, icmpv6Next, message(icmpTimeExceeded)), refusal{icmpTooManyHeaders, ninth}, false},
		{"tcp behind 17 headers", behind(17, 6, tcp), refusal{icmpTooManyHeaders, ninth}, false},
	} {
		_, err := End(bytes.Clone(c.raw))
		got, ok := errors.AsType[*Refusal](err)
		if !ok || got.Code != c.want.code || got.Pointer != c.want.pointer {
			t.Fatalf("%s: End returned %v, want code %d at %d", c.name, err, c.want.code, c.want.pointer)
		}
		answer := ParameterProblem(c.raw, sid, got, always)
		if (answer != nil) != c.answered {
			t.Errorf("%s: the code %d refusal was answered %t, want %t", c.name, got.Code, answer != nil, c.answered)
			continue
		}
		if answer != nil && (answer[ipv6HeaderLen+1] != c.want.code || binary.BigEndian.Uint32(answer[ipv6HeaderLen+4:]) != uint32(c.want.pointer)) {
			t.Errorf("%s: the answer carries code %d pointer %d, want %d at %d", c.name, answer[ipv6HeaderLen+1], binary.BigEndian.Uint32(answer[ipv6HeaderLen+4:]), c.want.code, c.want.pointer)
		}
	}
}

// a segment End refuses for its hop limit gets Time Exceeded behind as many headers in front of its routing header as walk steps past
// the search then steps past its routing header too, or ends there unfinished, and answers what lies past it
func TestExpiredSegmentIsAnsweredBehindEveryHeaderWalkStepsPast(t *testing.T) {
	for front := range maxExtensionHeaders + 1 {
		raw := expiring(t, front)
		if TimeExceeded(raw, netip.AddrFrom16([16]byte(raw[24:40])), always) == nil {
			t.Errorf("a segment with %d headers in front of its routing header got no Time Exceeded", front)
		}
	}
}

// a packet to a multicast group gets no Packet Too Big, even from a unicast source, departing from RFC 4443 section 3.2, which has one sent
// the dataplane would answer from the group, and the mesh routes no multicast
func TestPacketTooBigToAGroupIsRefusedDepartingFromRFC4443(t *testing.T) {
	raw := segmentRouted(t)
	copy(raw[24:], addr16(addr("ff0e::1")))
	asked := false
	if answer := PacketTooBig(raw, addr("3fff:b:0:106::2"), MinimumIPv6MTU, func() bool { asked = true; return true }); answer != nil || asked {
		t.Errorf("a packet to a group got Packet Too Big %t, and allow was asked %t", answer != nil, asked)
	}
}

// each builder asks allow once for a packet an error may answer, and builds nothing when allow refuses
// it asks nothing about a packet it would not answer, so a rate limit behind allow spends nothing on one
func TestBuildersAskAllowOnlyBeforeAnAnswer(t *testing.T) {
	sid := addr("3fff:b:0:106::2")
	for _, builder := range errorBuilders {
		for _, allowed := range []bool{true, false} {
			asked := 0
			answer := builder.build(segmentRouted(t), sid, func() bool { asked++; return allowed })
			if asked != 1 || (answer != nil) != allowed {
				t.Errorf("%s asked allow %d times and built %t with allow saying %t, want once and %t", builder.name, asked, answer != nil, allowed, allowed)
			}
		}
		for what, refused := range map[string]struct {
			offending []byte
			source    netip.Addr
		}{
			"an answer from a multicast group": {segmentRouted(t), addr("ff02::1")},
			"another icmp error":               {behindRouting(t, 0, icmpTimeExceeded), sid},
		} {
			asked := false
			if answer := builder.build(refused.offending, refused.source, func() bool { asked = true; return true }); answer != nil || asked {
				t.Errorf("%s for %s was built %t, and allow was asked %t", builder.name, what, answer != nil, asked)
			}
		}
	}
}

// errorBuilder is one of the errors this package answers with and the type and code it writes
type errorBuilder struct {
	name       string
	kind, code byte
	build      func(offending []byte, source netip.Addr, allow func() bool) []byte
}

// errorBuilders are every ICMPv6 error this package builds, packet too big carrying 1280
var errorBuilders = []errorBuilder{
	{"time exceeded", 3, 0, TimeExceeded},
	{"parameter problem", 4, 0, func(raw []byte, source netip.Addr, allow func() bool) []byte {
		return ParameterProblem(raw, source, &Refusal{Code: icmpErroneousHeader, Pointer: ipv6HeaderLen + segmentsLeftInHeader}, allow)
	}},
	{"packet too big", 2, 0, func(raw []byte, source netip.Addr, allow func() bool) []byte {
		return PacketTooBig(raw, source, MinimumIPv6MTU, allow)
	}},
	{"no route to destination", 1, 0, NoRoute},
	{"communication administratively prohibited", 1, 1, Prohibited},
	{"beyond scope of source address", 1, 2, BeyondScope},
}

// verify sums a finished message the way a receiver does, with the checksum
// field in place rather than zeroed. A correct message comes back zero,
// whatever the length parity, which is the test RFC 4443 section 2.3 has the
// receiver make.
func verify(source, destination netip.Addr, body []byte) uint16 {
	return icmpChecksum(source, destination, body)
}
