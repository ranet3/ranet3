// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package babel

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"testing"
	"time"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// routeSaid is a route as updateTLVs is handed it, which comes out as a
// Router-Id TLV and the Update behind it.
type routeSaid struct {
	key      routeKey
	adv      advertisement
	interval time.Duration
}

type nextHopSaid struct{ address netip.Addr }

type ackReqSaid struct{ nonce, interval uint16 }

// ackSaid is the Ack this node answers a request with, given the two Opaque
// octets the request carried, which RFC 8966 section 4.6.4 has it echo: "Set
// to the Opaque value of the Acknowledgment Request that prompted this
// Acknowledgment".
type ackSaid struct{ opaque [2]byte }

// paddingSaid is a Pad1 at length zero and a PadN of that many zeros
// otherwise, which carry nothing and are dropped on the way in.
type paddingSaid struct{ length int }

// said is one thing a speaker says to a neighbor: a Hello, an IHU, a route, a
// request and so on, kept as the value it was built from so that what the
// far end decodes can be held against it.
type said struct{ value any }

// GoString spells each drawn value out in a failure, with prefixes and
// addresses written as text rather than shown as the internals of netip.
func (s said) GoString() string {
	switch v := s.value.(type) {
	case routeSaid:
		return fmt.Sprintf("route %v from %v, router-id %x seqno %d metric %d, every %v",
			v.key.dest, v.key.source, v.adv.routerID, v.adv.seqno, v.adv.metric, v.interval)
	case nextHopSaid:
		return fmt.Sprintf("next hop %v", v.address)
	case ackReqSaid:
		return fmt.Sprintf("ack request %d every %d", v.nonce, v.interval)
	case ackSaid:
		return fmt.Sprintf("ack echoing %x", v.opaque)
	case paddingSaid:
		return fmt.Sprintf("padding %d", v.length)
	}
	return fmt.Sprintf("%T%+v", s.value, s.value)
}

// tlvs gives the TLVs the speaker writes for it.
func (s said) tlvs() []RawTLV {
	switch v := s.value.(type) {
	case Hello:
		return []RawTLV{EncodeHello(v)}
	case IHU:
		return []RawTLV{EncodeIHU(v)}
	case routeSaid:
		return updateTLVs(v.key, v.adv, v.interval)
	case nextHopSaid:
		return []RawTLV{EncodeNextHop(v.address.AsSlice())}
	case RouteRequest:
		return []RawTLV{EncodeRouteRequest(v)}
	case SeqnoRequest:
		return []RawTLV{EncodeSeqnoRequest(v)}
	case ackReqSaid:
		return []RawTLV{EncodeAckReq(v.nonce, v.interval)}
	case ackSaid:
		// as the receive path answers one: the request decoded, then the
		// Ack encoded from what it decoded to
		nonce, err := DecodeAckReq([]byte{0, 0, v.opaque[0], v.opaque[1], 0, 0})
		if err != nil {
			panic(fmt.Sprintf("a request carrying %x was refused: %v", v.opaque, err))
		}
		return []RawTLV{EncodeAck(nonce)}
	case paddingSaid:
		if v.length == 0 {
			return []RawTLV{{Type: TLVPad1}}
		}
		return []RawTLV{{Type: TLVPadN, Body: make([]byte, v.length)}}
	}
	panic(fmt.Sprintf("nothing writes %T", s.value))
}

// heard decodes what arrived for s, the TLVs tlvs wrote less any padding, and
// reports where it differs from what was said. Updates go through one prefix
// decoder for the whole packet, as on the receive path.
func (s said) heard(got []RawTLV, prefixes *PrefixDecoder) error {
	switch v := s.value.(type) {
	case Hello:
		hello, err := DecodeHello(got[0].Body)
		if err != nil || hello != v {
			return fmt.Errorf("decoded as %+v, %v", hello, err)
		}
	case IHU:
		ihu, address, err := DecodeIHU(got[0].Body)
		if err != nil || ihu != v || address != nil {
			return fmt.Errorf("decoded as %+v for %v, %v", ihu, address, err)
		}
	case routeSaid:
		id, ignore, err := DecodeRouterID(got[0].Body)
		if err != nil || ignore || id != v.adv.routerID {
			return fmt.Errorf("its router-id decoded as %x, ignore %v, %v", id, ignore, err)
		}
		update, err := prefixes.Decode(got[1].Body)
		want := Update{
			AE: updateAE(v.key.dest), Plen: v.key.dest.Bits(), Prefix: net.IP(v.key.dest.Addr().AsSlice()),
			Interval: uint16(v.interval / (10 * time.Millisecond)), Seqno: v.adv.seqno, Metric: v.adv.metric,
			SourcePrefix: v.key.source,
		}
		if err != nil || !reflect.DeepEqual(update, want) {
			return fmt.Errorf("its update decoded as %+v, %v, want %+v", update, err, want)
		}
	case nextHopSaid:
		// The encoder takes a net.IP, whose IPv4 and v4-mapped spellings
		// are one address, and names the family the way To4 does.
		sent := net.IP(v.address.AsSlice())
		ae := AEIPv6
		if sent.To4() != nil {
			ae = AEIPv4
		}
		address, gotAE, ignore, err := DecodeNextHop(got[0].Body)
		if err != nil || ignore || gotAE != ae || !address.Equal(sent) {
			return fmt.Errorf("decoded as %v under AE %d, ignore %v, %v", address, gotAE, ignore, err)
		}
	case RouteRequest:
		request, err := DecodeRouteRequest(got[0].Body)
		if err != nil || request != v {
			return fmt.Errorf("decoded as %+v, %v", request, err)
		}
	case SeqnoRequest:
		request, err := DecodeSeqnoRequest(got[0].Body)
		if err != nil || request != v {
			return fmt.Errorf("decoded as %+v, %v", request, err)
		}
	case ackReqSaid:
		nonce, err := DecodeAckReq(got[0].Body)
		if err != nil || nonce != v.nonce {
			return fmt.Errorf("decoded as nonce %d, %v", nonce, err)
		}
	case ackSaid:
		if !bytes.Equal(got[0].Body, v.opaque[:]) {
			return fmt.Errorf("arrived as %x, where the request carried %x", got[0].Body, v.opaque)
		}
	}
	return nil
}

// maskedPrefixes draws a masked prefix over addresses, from the default route
// to a single host.
func maskedPrefixes(addresses hegel.Generator[netip.Addr]) hegel.Generator[netip.Prefix] {
	return hegel.Composite(func(tc hegel.TestCase) netip.Prefix {
		address := hegel.Draw(tc, addresses)
		return netip.PrefixFrom(address, hegel.Draw(tc, pbt.Spanning(0, address.BitLen()))).Masked()
	})
}

// routeKeys draws a key the speaker could hold: a masked destination of either
// family, and either no source or a masked one of the same family at least one
// bit long, the keys originatedKey and the receive path both leave.
func routeKeys() hegel.Generator[routeKey] {
	return hegel.Composite(func(tc hegel.TestCase) routeKey {
		key := routeKey{dest: hegel.Draw(tc, maskedPrefixes(hegel.IPAddresses()))}
		if hegel.Draw(tc, hegel.Booleans()) {
			addresses := hegel.IPAddresses().IPv6()
			if key.dest.Addr().Is4() {
				addresses = hegel.IPAddresses().IPv4()
			}
			source := hegel.Draw(tc, addresses)
			key.source = netip.PrefixFrom(source, hegel.Draw(tc, pbt.Spanning(1, source.BitLen()))).Masked()
		}
		return key
	})
}

// learnedKeys are the keys a request names. The receive path only learns a
// destination that names a route, which leaves out a v4-mapped one under AE 2,
// and the request decoder refuses one for the same reason.
func learnedKeys() hegel.Generator[routeKey] {
	return hegel.Filter(routeKeys(), func(key routeKey) bool { return !key.dest.Addr().Is4In6() })
}

func uint16s() hegel.Generator[uint16] { return pbt.Spanning[uint16](0, 0xffff) }

func uint32s() hegel.Generator[uint32] { return pbt.Spanning[uint32](0, 0xffffffff) }

// routeSaids draws a route as the speaker advertises it, every update
// interval Config.Validate allows, 10ms to maxInterval, among them.
func routeSaids() hegel.Generator[said] {
	return hegel.Composite(func(tc hegel.TestCase) said {
		route := routeSaid{key: hegel.Draw(tc, routeKeys()),
			interval: hegel.Draw(tc, pbt.Spanning(10*time.Millisecond, maxInterval))}
		copy(route.adv.routerID[:], hegel.Draw(tc, hegel.Binary(8, 8)))
		route.adv.seqno, route.adv.metric = hegel.Draw(tc, uint16s()), hegel.Draw(tc, uint16s())
		return said{route}
	})
}

// saids draws one thing a speaker says, any of the TLVs this package encodes.
func saids() hegel.Generator[said] {
	return hegel.Composite(func(tc hegel.TestCase) said {
		switch hegel.Draw(tc, hegel.Integers(0, 9)) {
		case 0:
			hello := Hello{Seqno: hegel.Draw(tc, uint16s()), Interval: hegel.Draw(tc, uint16s()),
				Unicast: hegel.Draw(tc, hegel.Booleans()), HasTS: hegel.Draw(tc, hegel.Booleans())}
			if hello.HasTS {
				hello.TxTS = hegel.Draw(tc, uint32s())
			}
			return said{hello}
		case 1:
			ihu := IHU{RxCost: hegel.Draw(tc, uint16s()), Interval: hegel.Draw(tc, uint16s()),
				HasTS: hegel.Draw(tc, hegel.Booleans())}
			if ihu.HasTS {
				ihu.OriginTS = hegel.Draw(tc, uint32s())
				ihu.ReceiveTS = hegel.Draw(tc, uint32s())
			}
			return said{ihu}
		case 2, 3:
			return hegel.Draw(tc, routeSaids())
		case 4:
			return said{nextHopSaid{hegel.Draw(tc, hegel.IPAddresses())}}
		case 5:
			if hegel.Draw(tc, hegel.WeightedBooleans(1.0/4)) {
				return said{RouteRequest{AE: AEWildcard}}
			}
			key := hegel.Draw(tc, learnedKeys())
			// RFC 9229 section 2.3 keeps a request for an IPv4 prefix on AE
			// 1, and the decoder takes AE 4 as well
			ae := aeFor(key.dest)
			if ae == AEIPv4 && hegel.Draw(tc, hegel.Booleans()) {
				ae = AEIPv4ViaIPv6
			}
			return said{RouteRequest{AE: ae, Prefix: key.dest, SourcePrefix: key.source}}
		case 6:
			key := hegel.Draw(tc, learnedKeys())
			request := SeqnoRequest{AE: aeFor(key.dest), Prefix: key.dest, SourcePrefix: key.source,
				Seqno: hegel.Draw(tc, uint16s()), HopCount: hegel.Draw(tc, pbt.Spanning[uint8](0, 255))}
			copy(request.RouterID[:], hegel.Draw(tc, hegel.Binary(8, 8)))
			return said{request}
		case 7:
			return said{ackReqSaid{hegel.Draw(tc, uint16s()), hegel.Draw(tc, uint16s())}}
		case 8:
			return said{ackSaid{[2]byte(hegel.Draw(tc, hegel.Binary(2, 2)))}}
		}
		return said{paddingSaid{hegel.Draw(tc, tlvLengths())}}
	})
}

// tlvLengths draws the length of a TLV body: mostly the short ones the
// protocol uses, and now and then 0 or 255, the two a length octet ends at.
func tlvLengths() hegel.Generator[int] {
	return hegel.Composite(func(tc hegel.TestCase) int {
		if hegel.Draw(tc, hegel.WeightedBooleans(1.0/4)) {
			return hegel.Draw(tc, hegel.SampledFrom([]int{0, 255}))
		}
		return hegel.Draw(tc, hegel.Integers(0, 40))
	})
}

// linkLocals draws an address in fe80::/64, which every babel packet here is
// sent from.
func linkLocals() hegel.Generator[netip.Addr] {
	return hegel.Map(hegel.Binary(8, 8), func(id []byte) netip.Addr {
		address := [16]byte{0xfe, 0x80}
		copy(address[8:], id)
		return netip.AddrFrom16(address)
	})
}

// Every TLV the speaker writes reaches a neighbor as the value it was built
// from: framed into one packet among others, wrapped in the IPv6 and UDP
// headers the tunnel carries, then taken apart and decoded the way the receive
// path does. Each of them is something a neighbor acts on, a cost, a route, a
// sequence number or a request to answer, and BIRD reads the same bytes, so
// one that decodes as anything else is a mesh where two nodes disagree about
// what was said. Padding is dropped on the way in and carries nothing.
func TestEveryTLVTheSpeakerWritesDecodesBackToItself(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		sent := hegel.Draw(ht, hegel.Lists(saids()).MinSize(1).MaxSize(24))
		from, local := hegel.Draw(ht, linkLocals()), hegel.Draw(ht, linkLocals())
		to := multicastGroup
		if hegel.Draw(ht, hegel.Booleans()) {
			to = local
		}

		var tlvs, kept []RawTLV
		for _, s := range sent {
			for _, tlv := range s.tlvs() {
				tlvs = append(tlvs, tlv)
				if tlv.Type != TLVPad1 && tlv.Type != TLVPadN {
					kept = append(kept, tlv)
				}
			}
		}
		payload := EncodePacket(tlvs)
		src, got, err := parsePacket(buildPacket(from, to, payload), local)
		if err != nil || src != from || !bytes.Equal(got, payload) {
			ht.Fatalf("the packet from %v to %v came back from %v with %d of %d payload bytes: %v",
				from, to, src, len(got), len(payload), err)
		}
		heard, err := DecodePacket(got)
		if err != nil {
			ht.Fatalf("the packet of %d TLVs was refused: %v", len(tlvs), err)
		}
		if !slices.EqualFunc(heard, kept, func(a, b RawTLV) bool { return a.Type == b.Type && bytes.Equal(a.Body, b.Body) }) {
			ht.Fatalf("the packet framed %v and came apart as %v", kept, heard)
		}
		var prefixes PrefixDecoder
		for _, s := range sent {
			n := 0
			for _, tlv := range s.tlvs() {
				if tlv.Type != TLVPad1 && tlv.Type != TLVPadN {
					n++
				}
			}
			if err := s.heard(heard[:n], &prefixes); err != nil {
				ht.Fatalf("%#v %v", s, err)
			}
			heard = heard[n:]
		}
	})
}

// framedTLVs draws TLVs of every type the receive path decodes and of some it
// does not, each with a body drawn whole, so every decoder meets bytes no
// encoder would write.
func framedTLVs() hegel.Generator[[]byte] {
	return hegel.Composite(func(tc hegel.TestCase) []byte {
		tlvs := hegel.Draw(tc, hegel.Lists(hegel.Composite(func(tc hegel.TestCase) RawTLV {
			size := hegel.Draw(tc, tlvLengths())
			return RawTLV{Type: TLVType(hegel.Draw(tc, hegel.Integers(0, 12))), Body: hegel.Draw(tc, hegel.Binary(size, size))}
		})).MaxSize(16))
		return EncodePacket(tlvs)
	})
}

// addressed draws a payload holding every TLV type whose body carries an
// address, IHU, Next Hop, Update and both requests, under every address
// encoding RFC 8966 and RFC 9229 define and the one past them, each cut at a
// drawn length. The encoding decides how much of the body is read as an
// address, and the speaker writes only some of these pairs, so drawn bytes
// would almost never reach the rest.
func addressed() hegel.Generator[[]byte] {
	fixed := []struct {
		tlv    TLVType
		length int // the octets in front of the address
	}{{TLVIHU, 6}, {TLVNextHop, 2}, {TLVUpdate, 10}, {TLVRouteRequest, 2}, {TLVSeqnoRequest, 14}}
	return hegel.Composite(func(tc hegel.TestCase) []byte {
		var tlvs []RawTLV
		for _, f := range fixed {
			for ae := AEWildcard; ae <= AEIPv4ViaIPv6+1; ae++ {
				// room for the longest address and a sub-TLV after it
				full := f.length + 16 + 8
				body := hegel.Draw(tc, hegel.Binary(full, full))
				body[0] = ae
				tlvs = append(tlvs, RawTLV{Type: f.tlv, Body: body[:hegel.Draw(tc, pbt.Spanning(0, full))]})
			}
		}
		return EncodePacket(tlvs)
	})
}

// compressed draws runs of Updates leaning on the prefix compression of RFC
// 8966 section 4.6.9. Under each address encoding that has it, a full update
// with the prefix flag sets the prefix the ones after it may leave the front
// of out, and those then claim a prefix length and an omitted count from zero
// to past what the address holds. Half the lengths are the address's width or
// one past it, and half the counts the octets the length covers or one past
// them, the pairs the decoder has to tell apart. Each sends the octets its
// claim leaves to send, as a sender would, so the decoder reads every claim
// through to the prefix it builds, and now and then fewer.
func compressed() hegel.Generator[[]byte] {
	return hegel.Composite(func(tc hegel.TestCase) []byte {
		var tlvs []RawTLV
		for _, ae := range []uint8{AEIPv4, AEIPv6, AEIPv4ViaIPv6} {
			addresses := hegel.IPAddresses().IPv4()
			if ae == AEIPv6 {
				addresses = hegel.IPAddresses().IPv6()
			}
			first := hegel.Draw(tc, maskedPrefixes(addresses))
			width := first.Addr().BitLen()
			tlvs = append(tlvs, EncodeUpdate(Update{AE: ae, Plen: first.Bits(), Interval: 100, Prefix: first.Addr().AsSlice()}))
			for range hegel.Draw(tc, hegel.Integers(1, 3)) {
				plen := hegel.Draw(tc, hegel.OneOf(hegel.SampledFrom([]int{width, width + 1}), pbt.Spanning(0, width+8)))
				covered := prefixByteLen(plen)
				omitted := hegel.Draw(tc, hegel.OneOf(hegel.SampledFrom([]int{covered, covered + 1}), pbt.Spanning(0, width/8+2)))
				size := max(0, covered-omitted)
				sent := hegel.Draw(tc, hegel.Binary(size, size))
				if hegel.Draw(tc, hegel.WeightedBooleans(1.0/4)) {
					sent = sent[:hegel.Draw(tc, hegel.Integers(0, size))]
				}
				body := []byte{ae, hegel.Draw(tc, hegel.Integers[byte](0, 255)), byte(plen), byte(omitted), 0, 100, 0, 0, 0, 1}
				tlvs = append(tlvs, RawTLV{Type: TLVUpdate, Body: append(body, sent...)})
			}
		}
		return EncodePacket(tlvs)
	})
}

// misframed sets one length in a framed payload to exactly the bytes after it
// or one more: the packet's Body Length, or the Length octet of one of its
// TLVs. Each is read before what it bounds, and a bound off by one there reads
// a byte past the packet, where encoded lengths are exact and damage drawn
// anywhere almost never lands one past.
func misframed(tc hegel.TestCase, raw []byte) []byte {
	if len(raw) < headerLen {
		return raw
	}
	// where each TLV's Length octet sits that can claim one past the end, a
	// TLV close enough to the end, found the way decodeTLVFrames walks
	var lengths []int
	for at := headerLen; at+1 < len(raw); {
		if raw[at] == byte(TLVPad1) {
			at++
			continue
		}
		if len(raw)-(at+2)+1 <= 255 {
			lengths = append(lengths, at+1)
		}
		at += 2 + int(raw[at+1])
	}
	past := hegel.Draw(tc, hegel.Integers(0, 1))
	if len(lengths) == 0 || hegel.Draw(tc, hegel.WeightedBooleans(1.0/3)) {
		binary.BigEndian.PutUint16(raw[2:4], uint16(len(raw)-headerLen+past))
		return raw
	}
	at := hegel.Draw(tc, hegel.SampledFrom(lengths))
	raw[at] = byte(len(raw) - (at + 1) + past)
	return raw
}

// written draws a packet the speaker could write with some of its TLVs
// damaged, a few bytes of a body overwritten or its tail cut off, and now and
// then a byte of the framing overwritten as well. A damaged TLV still framed
// right reaches its decoder, where bytes drawn whole are mostly turned away by
// the framing or the address encoding first. Half the writes land in the first
// four octets of a body, which hold the address encoding, the flags, the
// prefix length and the omitted count of every TLV that has them, and half
// the TLVs are routes, so an update often follows another of its family whose
// prefix the omitted count refers back to.
func written() hegel.Generator[[]byte] {
	return hegel.Composite(func(tc hegel.TestCase) []byte {
		var tlvs []RawTLV
		for _, s := range hegel.Draw(tc, hegel.Lists(hegel.OneOf(saids(), routeSaids())).MinSize(1).MaxSize(8)) {
			for _, tlv := range s.tlvs() {
				if len(tlv.Body) > 0 && hegel.Draw(tc, hegel.Booleans()) {
					for range hegel.Draw(tc, hegel.Integers(1, 3)) {
						at := hegel.Draw(tc, hegel.OneOf(hegel.Integers(0, min(3, len(tlv.Body)-1)), hegel.Integers(0, len(tlv.Body)-1)))
						tlv.Body[at] = hegel.Draw(tc, hegel.Integers[byte](0, 255))
					}
				}
				if hegel.Draw(tc, hegel.WeightedBooleans(1.0/4)) {
					tlv.Body = tlv.Body[:hegel.Draw(tc, hegel.Integers(0, len(tlv.Body)))]
				}
				tlvs = append(tlvs, tlv)
			}
		}
		raw := EncodePacket(tlvs)
		if hegel.Draw(tc, hegel.WeightedBooleans(1.0/4)) {
			raw[hegel.Draw(tc, hegel.Integers(0, len(raw)-1))] = hegel.Draw(tc, hegel.Integers[byte](0, 255))
		}
		return raw
	})
}

// decodeEvery takes a payload apart and decodes each TLV in it the way the
// receive path does, with one prefix decoder for the packet. The payload and
// every body are handed over with no capacity past their length, so a decoder
// reading past the end of what it was given panics here, where on the receive
// path it would read whatever the buffer held after it.
func decodeEvery(payload []byte) {
	tlvs, err := DecodePacket(slices.Clip(payload))
	if err != nil {
		return
	}
	var prefixes PrefixDecoder
	for _, tlv := range tlvs {
		tlv.Body = slices.Clip(tlv.Body)
		switch tlv.Type {
		case TLVHello:
			_, _ = DecodeHello(tlv.Body)
		case TLVIHU:
			_, _, _ = DecodeIHU(tlv.Body)
		case TLVNextHop:
			_, _, _, _ = DecodeNextHop(tlv.Body)
		case TLVRouterID:
			_, _, _ = DecodeRouterID(tlv.Body)
		case TLVUpdate:
			_, _ = prefixes.Decode(tlv.Body)
		case TLVAckReq:
			_, _ = DecodeAckReq(tlv.Body)
		case TLVRouteRequest:
			_, _ = DecodeRouteRequest(tlv.Body)
		case TLVSeqnoRequest:
			_, _ = DecodeSeqnoRequest(tlv.Body)
		}
	}
}

// The packet parser runs on bytes a neighbor chose, inline with every packet
// that reaches the speaker, so nothing it is handed may panic it: the IPv6
// and UDP envelope, the babel framing and each TLV decoder answer with an
// error or a value. The payloads are bytes drawn whole, with and without a
// babel header in front, TLVs whose bodies are drawn whole, every TLV that
// carries an address under every address encoding, runs of compressed
// updates, and packets the speaker writes with bytes overwritten. Half of
// them have one length misframed, and each is sent in a well formed envelope
// or a damaged one, so the decoders are reached rather than stopped at the
// checksum.
func TestPacketParserNeverPanicsOnArbitraryBytes(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		// up to what a 1500 byte packet leaves after its two headers
		const most = 1500 - ipv6HeaderLen - udpHeaderLen
		drawn := func(tc hegel.TestCase, limit int) []byte {
			size := hegel.Draw(tc, pbt.Spanning(0, limit))
			return hegel.Draw(tc, hegel.Binary(size, size))
		}
		var payload []byte
		switch hegel.Draw(ht, hegel.Integers(0, 7)) {
		case 0, 1:
			payload = hegel.Draw(ht, written())
		case 2, 3:
			payload = hegel.Draw(ht, addressed())
		case 4, 5:
			payload = hegel.Draw(ht, compressed())
		case 6:
			payload = hegel.Draw(ht, framedTLVs())
		default:
			if hegel.Draw(ht, hegel.Booleans()) {
				payload = drawn(ht, most)
				break
			}
			body := drawn(ht, most-headerLen)
			payload = append([]byte{Magic, Version, byte(len(body) >> 8), byte(len(body))}, body...)
		}
		if hegel.Draw(ht, hegel.Booleans()) {
			payload = misframed(ht, payload)
		}
		local := hegel.Draw(ht, linkLocals())
		raw := buildPacket(hegel.Draw(ht, linkLocals()), multicastGroup, payload)
		for range hegel.Draw(ht, hegel.Integers(0, 2)) {
			raw[hegel.Draw(ht, hegel.Integers(0, ipv6HeaderLen+udpHeaderLen-1))] = hegel.Draw(ht, hegel.Integers[byte](0, 255))
		}
		if hegel.Draw(ht, hegel.WeightedBooleans(1.0/8)) {
			raw = raw[:hegel.Draw(ht, hegel.Integers(0, len(raw)))]
		}
		raw = slices.Clip(raw)

		isBabelPacket(raw)
		if _, carried, err := parsePacket(raw, local); err == nil {
			decodeEvery(carried)
		}
		decodeEvery(payload)
	})
}
