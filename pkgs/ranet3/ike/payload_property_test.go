// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ike

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// withEdges draws from gen half the time and one of edges the rest. A run
// draws the same 200 cases every time, so an edge a property depends on is
// named here rather than left to the sample to reach. gen comes first so a
// failure shrinks within it rather than to whichever edge is listed first.
func withEdges[T any](gen hegel.Generator[T], edges ...T) hegel.Generator[T] {
	return hegel.OneOf(gen, hegel.SampledFrom(edges))
}

// drawBytes draws up to most bytes, with no bytes, most bytes and any other
// given lengths among the edges. The length is drawn on its own, since a byte
// string the engine sizes itself rarely reaches a few hundred bytes.
func drawBytes(tc hegel.TestCase, most int, edges ...int) []byte {
	size := hegel.Draw(tc, withEdges(hegel.Integers(0, most), append([]int{0, most}, edges...)...))
	return hegel.Draw(tc, hegel.Binary(size, size))
}

// drawBody draws a payload body, with the lengths either side of the one
// where the payload's length field first needs its high byte among the edges.
func drawBody(tc hegel.TestCase) []byte {
	return drawBytes(tc, 300, 255-genericPayloadHeaderLen, 256-genericPayloadHeaderLen)
}

// chainTypes are the payload types a chain can carry before its end. Zero
// ends a chain, and SK has to be the last payload of a message.
var chainTypes = withEdges(
	hegel.Filter(hegel.Integers[PayloadType](1, 255), func(t PayloadType) bool { return t != PayloadSK }),
	1, PayloadSK-1, PayloadSK+1, 255)

// innerTypes are the payload types the chain inside SK can carry, where only
// zero, which ends it, is out.
var innerTypes = withEdges(hegel.Integers[PayloadType](1, 255), 1, PayloadSK, 255)

// drawPayloads draws up to most payloads of the given types.
func drawPayloads(tc hegel.TestCase, types hegel.Generator[PayloadType], most int) []RawPayload {
	count := hegel.Draw(tc, withEdges(hegel.Integers(0, most), 0, most))
	payloads := make([]RawPayload, count)
	for i := range payloads {
		kind := hegel.Draw(tc, types)
		critical := hegel.Draw(tc, hegel.Booleans())
		payloads[i] = RawPayload{Type: kind, Critical: critical, Body: drawBody(tc)}
	}
	return payloads
}

// samePayloads compares two payload lists by what is on the wire, so an empty
// body and a nil one are the same body.
func samePayloads(a, b []RawPayload) bool {
	return slices.EqualFunc(a, b, func(x, y RawPayload) bool {
		return x.Type == y.Type && x.Critical == y.Critical && bytes.Equal(x.Body, y.Body)
	})
}

// drawOctet draws any octet, zero and 0xff among the edges.
func drawOctet[T ~uint8](tc hegel.TestCase, edges ...T) T {
	return hegel.Draw(tc, withEdges(hegel.Integers[T](0, 255), append([]T{0, 255}, edges...)...))
}

// drawHeader draws a header in the one version this package speaks, every
// field at zero and at its largest among the edges. Next Payload and Length
// are drawn too, though a message works both out itself.
func drawHeader(tc hegel.TestCase) Header {
	spiI := hegel.Draw(tc, withEdges(hegel.Integers[uint64](0, math.MaxUint64), 0, math.MaxUint64))
	spiR := hegel.Draw(tc, withEdges(hegel.Integers[uint64](0, math.MaxUint64), 0, math.MaxUint64))
	next := drawOctet[PayloadType](tc)
	exchange := drawOctet(tc, IKE_SA_INIT, INFORMATIONAL)
	flags := drawOctet(tc, FlagInitiator, FlagResponse)
	messageID := hegel.Draw(tc, withEdges(hegel.Integers[uint32](0, math.MaxUint32), 0, math.MaxUint32))
	length := hegel.Draw(tc, withEdges(hegel.Integers[uint32](0, math.MaxUint32), 0, math.MaxUint32))
	return Header{
		SPIInitiator: spiI, SPIResponder: spiR, NextPayload: next,
		MajorVersion: 2, ExchangeType: exchange, Flags: flags,
		MessageID: messageID, Length: length,
	}
}

// Every field of the fixed header reads back as it was written, the flag
// octet's reserved bits included, since a responder correlates and answers by
// these fields.
func TestHeaderRoundTrips(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		want := drawHeader(ht)
		got, err := decodeHeader(want.encode())
		if err != nil {
			ht.Fatalf("decodeHeader refused %+v: %v", want, err)
		}
		if *got != want {
			ht.Fatalf("decodeHeader read %+v back as %+v", want, *got)
		}
	})
}

// A message reads back as the header and payloads it was built from, in their
// order, with Next Payload pointing at the first payload and Length the size
// of the whole. Payloads of types this package never names are carried as they
// are, since section 2.5 of RFC 7296 has a node skip what it does not know
// unless the critical bit says otherwise. A message may end in an SK payload.
func TestMessageRoundTrips(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		m := Message{Header: drawHeader(ht), Payloads: drawPayloads(ht, chainTypes, 6)}
		endsInSK := hegel.Draw(ht, hegel.Booleans())
		if endsInSK {
			m.Payloads = append(m.Payloads, RawPayload{Type: PayloadSK, Body: drawBody(ht)})
		}
		raw := m.Encode()
		got, err := DecodeMessage(raw)
		if err != nil {
			ht.Fatalf("DecodeMessage refused %x: %v", raw, err)
		}
		want := m.Header
		want.NextPayload, want.Length = PayloadNone, uint32(len(raw))
		if len(m.Payloads) > 0 {
			want.NextPayload = m.Payloads[0].Type
		}
		if got.Header != want {
			ht.Fatalf("DecodeMessage read the header back as %+v, want %+v", got.Header, want)
		}
		if !samePayloads(got.Payloads, m.Payloads) {
			ht.Fatalf("DecodeMessage read the payloads back as %+v, want %+v", got.Payloads, m.Payloads)
		}
	})
}

// The chain inside an SK payload reads back as written. Here any type but
// zero may appear anywhere, SK among them, because nothing follows the chain
// but the padding.
func TestPayloadChainRoundTrips(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		want := drawPayloads(ht, innerTypes, 6)
		first := PayloadNone
		if len(want) > 0 {
			first = want[0].Type
		}
		got, err := decodePayloadChain(first, encodePayloadChain(want))
		if err != nil {
			ht.Fatalf("decodePayloadChain refused %+v: %v", want, err)
		}
		if !samePayloads(got, want) {
			ht.Fatalf("decodePayloadChain read %+v back as %+v", want, got)
		}
	})
}

// drawTransform draws a transform of any type, ID and key length, a key
// length of zero, which writes no attribute at all, among the edges. A
// transform the encoder writes never carries an attribute it could not parse,
// so UnsupportedAttributes stays false.
func drawTransform(tc hegel.TestCase) Transform {
	kind := drawOctet(tc, TransEncr, TransESN)
	id := hegel.Draw(tc, withEdges(hegel.Integers[uint16](0, math.MaxUint16), 0, math.MaxUint16))
	bits := hegel.Draw(tc, withEdges(hegel.Integers[uint16](0, math.MaxUint16), 0, 128, 256, math.MaxUint16))
	return Transform{Type: kind, ID: id, KeyLengthBits: bits}
}

// drawProposal draws a proposal of any number, protocol and SPI, holding any
// transforms. The edges are no transform and the most, and the SPI sizes of
// IKE, of ESP and of an IKE rekey.
func drawProposal(tc hegel.TestCase) Proposal {
	var p Proposal
	p.Number = drawOctet[uint8](tc, 1)
	p.Protocol = drawOctet(tc, ProtoIKE, ProtoESP)
	p.SPI = drawBytes(tc, 16, 4, 8)
	transforms := hegel.Draw(tc, withEdges(hegel.Integers(0, 8), 0, 8))
	for range transforms {
		p.Transforms = append(p.Transforms, drawTransform(tc))
	}
	return p
}

// drawProposals draws up to four proposals, none and four among the edges.
func drawProposals(tc hegel.TestCase) []Proposal {
	count := hegel.Draw(tc, withEdges(hegel.Integers(0, 4), 0, 4))
	proposals := make([]Proposal, count)
	for i := range proposals {
		proposals[i] = drawProposal(tc)
	}
	return proposals
}

// An SA payload reads back as the proposals and transforms it was built from,
// in their order, with every key length attribute intact. The order is the
// offer's preference, and a key length that came back different would select
// a different cipher than the one offered.
func TestSARoundTrips(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		want := drawProposals(ht)
		got, err := DecodeSA(EncodeSA(want))
		if err != nil {
			ht.Fatalf("DecodeSA refused %+v: %v", want, err)
		}
		same := slices.EqualFunc(got, want, func(x, y Proposal) bool {
			return x.Number == y.Number && x.Protocol == y.Protocol &&
				bytes.Equal(x.SPI, y.SPI) && slices.Equal(x.Transforms, y.Transforms)
		})
		if !same {
			ht.Fatalf("DecodeSA read %+v back as %+v", want, got)
		}
	})
}

// drawSelector draws a selector of either address family, with its addresses
// in the width the type names, the lowest and highest address of the family
// and every port and protocol at zero and at its largest among the edges.
func drawSelector(tc hegel.TestCase) TrafficSelector {
	addresses := withEdges[netip.Addr](hegel.IPAddresses().IPv4(),
		netip.IPv4Unspecified(), netip.AddrFrom4([4]byte{255, 255, 255, 255}))
	kind := hegel.Draw(tc, hegel.SampledFrom([]uint8{TS_IPV4_ADDR_RANGE, TS_IPV6_ADDR_RANGE}))
	if kind == TS_IPV6_ADDR_RANGE {
		addresses = withEdges[netip.Addr](hegel.IPAddresses().IPv6(),
			netip.IPv6Unspecified(), netip.AddrFrom16([16]byte{
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			}))
	}
	protocol := drawOctet[uint8](tc)
	startPort := hegel.Draw(tc, withEdges(hegel.Integers[uint16](0, math.MaxUint16), 0, math.MaxUint16))
	endPort := hegel.Draw(tc, withEdges(hegel.Integers[uint16](0, math.MaxUint16), 0, math.MaxUint16))
	start := hegel.Draw(tc, addresses)
	end := hegel.Draw(tc, addresses)
	return TrafficSelector{
		Type: kind, Protocol: protocol, StartPort: startPort, EndPort: endPort,
		StartAddr: net.IP(start.AsSlice()), EndAddr: net.IP(end.AsSlice()),
	}
}

// A TS payload reads back as the selectors it was built from, each address in
// the width its type names, which is the width isFullRangeSelectors compares.
func TestTrafficSelectorsRoundTrip(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		count := hegel.Draw(ht, withEdges(hegel.Integers(0, 4), 0, 4))
		want := make([]TrafficSelector, count)
		for i := range want {
			want[i] = drawSelector(ht)
		}
		got, err := DecodeTS(EncodeTS(want))
		if err != nil {
			ht.Fatalf("DecodeTS refused %+v: %v", want, err)
		}
		// slices.Equal rather than net.IP.Equal, which would fold a 4-in-6
		// address onto its IPv4 form and so pass a selector of the wrong width
		same := slices.EqualFunc(got, want, func(x, y TrafficSelector) bool {
			return x.Type == y.Type && x.Protocol == y.Protocol &&
				x.StartPort == y.StartPort && x.EndPort == y.EndPort &&
				slices.Equal(x.StartAddr, y.StartAddr) && slices.Equal(x.EndAddr, y.EndAddr)
		})
		if !same {
			ht.Fatalf("DecodeTS read %+v back as %+v", want, got)
		}
	})
}

// A notify reads back with its protocol, SPI, type and data as written. A
// peer acts on the type, and the data carries cookies, NAT detection hashes
// and the group INVALID_KE_PAYLOAD asks for. The edges include the last
// error type and the first status type, where section 3.10.1 splits them.
func TestNotifyRoundTrips(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		protocol := drawOctet(ht, ProtoESP)
		kind := hegel.Draw(ht, withEdges(hegel.Integers[NotifyType](0, math.MaxUint16), 0, 16383, 16384, math.MaxUint16))
		want := Notify{Protocol: protocol, SPI: drawBytes(ht, 16, 4, 8), Type: kind, Data: drawBody(ht)}
		got, err := DecodeNotify(EncodeNotify(want))
		if err != nil {
			ht.Fatalf("DecodeNotify refused %+v: %v", want, err)
		}
		if got.Protocol != want.Protocol || got.Type != want.Type ||
			!bytes.Equal(got.SPI, want.SPI) || !bytes.Equal(got.Data, want.Data) {
			ht.Fatalf("DecodeNotify read %+v back as %+v", want, got)
		}
	})
}

// A KE payload reads back as the group and public value it was built from,
// the two the shared secret is computed over. The edges include the
// public value sizes of X25519, P-256 and P-384.
func TestKERoundTrips(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		group := hegel.Draw(ht, withEdges(hegel.Integers[uint16](0, math.MaxUint16), 0, DH_CURVE25519, math.MaxUint16))
		public := drawBytes(ht, 300, 32, 64, 96)
		gotGroup, gotPublic, err := DecodeKE(EncodeKE(group, public))
		if err != nil {
			ht.Fatalf("DecodeKE refused group %d with %x: %v", group, public, err)
		}
		if gotGroup != group || !bytes.Equal(gotPublic, public) {
			ht.Fatalf("DecodeKE read group %d with %x back as group %d with %x", group, public, gotGroup, gotPublic)
		}
	})
}

// A nonce reads back as itself, since both nonces enter SKEYSEED and the
// signed octets byte for byte. The edges include the shortest and longest
// nonce section 3.9 allows.
func TestNonceRoundTrips(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		nonce := drawBytes(ht, 300, 16, 256)
		if got := DecodeNonce(EncodeNonce(nonce)); !bytes.Equal(got, nonce) {
			ht.Fatalf("DecodeNonce read %x back as %x", nonce, got)
		}
	})
}

// drawName draws one string of an identity, with the lengths where a DER
// length moves from one octet to the long form and from one length octet to
// two among the edges.
func drawName(tc hegel.TestCase) string {
	return string(drawBytes(tc, 300, 127, 128, 255, 256))
}

// An ID payload reads back as its type and data, and an identity this end
// asserts reads back as the same name through the RDNSequence inside it, at
// any length its three strings take. The name selects which key verifies
// AUTH.
func TestIdentityRoundTrips(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		idType := drawOctet(ht, ID_DER_ASN1_DN)
		data := drawBody(ht)
		gotType, gotData, err := DecodeID(EncodeID(idType, data))
		if err != nil {
			ht.Fatalf("DecodeID refused type %d with %x: %v", idType, data, err)
		}
		if gotType != idType || !bytes.Equal(gotData, data) {
			ht.Fatalf("DecodeID read type %d with %x back as type %d with %x", idType, data, gotType, gotData)
		}

		organization, commonName, serialNumber := drawName(ht), drawName(ht), drawName(ht)
		want := Identity{Organization: organization, CommonName: commonName, SerialNumber: serialNumber}
		got, err := identityFromID(want.encodeID())
		if err != nil {
			ht.Fatalf("identityFromID refused %q: %v", want, err)
		}
		if got != want {
			ht.Fatalf("identityFromID read %q back as %q", want, got)
		}
	})
}

// A Delete payload reads back as the protocol and SPIs it was built from: an
// IKE delete with none, and a Child SA delete with any number of four octet
// SPIs, none among them. A delete that read back short would leave a Child SA
// installed that the peer has torn down.
func TestDeleteRoundTrips(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		protocol := hegel.Draw(ht, hegel.SampledFrom([]ProtocolID{ProtoIKE, ProtoAH, ProtoESP}))
		want := Delete{Protocol: protocol}
		if protocol != ProtoIKE {
			count := hegel.Draw(ht, withEdges(hegel.Integers(0, 8), 0, 1, 8))
			for range count {
				want.SPIs = append(want.SPIs, hegel.Draw(ht, hegel.Binary(4, 4)))
			}
		}
		got, err := DecodeDelete(EncodeDelete(want))
		if err != nil {
			ht.Fatalf("DecodeDelete refused %+v: %v", want, err)
		}
		if got.Protocol != want.Protocol || !slices.EqualFunc(got.SPIs, want.SPIs, bytes.Equal) {
			ht.Fatalf("DecodeDelete read %+v back as %+v", want, got)
		}
	})
}

// An AUTH payload this end builds verifies under the matching public key, for
// any key and any signed octets: the method, the Ed25519 AlgorithmIdentifier
// and the signature all read back as they were written.
func TestAuthVerifiesWhatItSigned(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		seed := hegel.Draw(ht, hegel.Binary(ed25519.SeedSize, ed25519.SeedSize))
		private := ed25519.NewKeyFromSeed(seed)
		signed := drawBytes(ht, 600)
		body := BuildAuth(private, signed)
		if err := VerifyAuth(private.Public().(ed25519.PublicKey), signed, body); err != nil {
			ht.Fatalf("VerifyAuth refused %x over %x: %v", body, signed, err)
		}
	})
}

// skSuite is one AEAD suite an IKE SA can negotiate, as SASuite spells it.
type skSuite struct {
	id, bits uint16
}

// skSuites is every suite aeadParams takes, ChaCha20-Poly1305 under both key
// lengths it may be named with.
var skSuites = []skSuite{
	{ENCR_AES_GCM_16, 128}, {ENCR_AES_GCM_16, 192}, {ENCR_AES_GCM_16, 256},
	{ENCR_CHACHA20_POLY1305, 0}, {ENCR_CHACHA20_POLY1305, 256},
}

// An encrypted message reads back as what it was built from: the header, the
// cleartext payloads ahead of SK, and, once SK decrypts under the same key,
// the payloads inside it, for every suite, any key and IV, and any payloads.
// Everything after IKE_SA_INIT travels this way.
func TestSKRoundTrips(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		drawn := hegel.Draw(ht, hegel.SampledFrom(skSuites))
		suite := SASuite{EncrID: drawn.id, EncrKeyBits: drawn.bits}
		params, err := aeadParams(suite.EncrID, suite.EncrKeyBits)
		if err != nil {
			ht.Fatal(err)
		}
		key := hegel.Draw(ht, hegel.Binary(params.KeyLen+params.SaltLen, params.KeyLen+params.SaltLen))
		iv := hegel.Draw(ht, hegel.Binary(params.IVLen, params.IVLen))
		header := drawHeader(ht)
		cleartext := drawPayloads(ht, chainTypes, 2)
		inner := drawPayloads(ht, innerTypes, 4)

		raw, err := encryptMessageIV(suite, key, header, cleartext, inner, iv)
		if err != nil {
			ht.Fatalf("encryptMessageIV refused %+v: %v", suite, err)
		}
		m, err := DecodeMessage(raw)
		if err != nil {
			ht.Fatalf("DecodeMessage refused the encrypted message %x: %v", raw, err)
		}
		want := header
		want.NextPayload, want.Length = PayloadSK, uint32(len(raw))
		if len(cleartext) > 0 {
			want.NextPayload = cleartext[0].Type
		}
		if m.Header != want {
			ht.Fatalf("DecodeMessage read the header back as %+v, want %+v", m.Header, want)
		}
		if len(m.Payloads) == 0 || m.Payloads[len(m.Payloads)-1].Type != PayloadSK ||
			!samePayloads(m.Payloads[:len(m.Payloads)-1], cleartext) {
			ht.Fatalf("DecodeMessage read the outer payloads back as %+v, want %+v and then SK", m.Payloads, cleartext)
		}
		got, err := DecryptMessage(suite, key, raw, m)
		if err != nil {
			ht.Fatalf("DecryptMessage refused what was encrypted under the same key: %v", err)
		}
		if !samePayloads(got, inner) {
			ht.Fatalf("DecryptMessage read %+v back as %+v", inner, got)
		}
	})
}

// returns runs decode on b and says what went wrong, if anything did: what
// decode reported, or the panic it raised.
func returns(decode func([]byte) string, b []byte) (problem string) {
	defer func() {
		if r := recover(); r != nil {
			problem = fmt.Sprintf("panicked: %v", r)
		}
	}()
	return decode(b)
}

// withLength is b with the header's length field set to the size of b, when
// b is long enough to have one, so DecodeMessage goes on to the payloads.
func withLength(b []byte) []byte {
	if len(b) < HeaderLen {
		return b
	}
	b = slices.Clone(b)
	binary.BigEndian.PutUint32(b[24:28], uint32(len(b)))
	return b
}

// encodingKinds are the encodings encodingOf writes: one for each payload this
// package decodes, the offers, answer and selectors it sends itself, which the
// selection behind the SA and TS decoders reads, an answer whose SPI is too
// short, and encodings with one length field misstated. Every case draws one
// of each, so no kind depends on the sample reaching it.
var encodingKinds = []string{
	"message", "chain", "SA", "IKE offer", "ESP offer", "ESP answer", "short ESP SPI",
	"misstated SPI Size", "misstated proposal length", "misstated transform length",
	"TS", "full range selectors", "notify", "delete", "KE", "identity", "AUTH",
	"misstated AUTH algorithm length",
}

// misstate draws a value to write into a length field: one of edges, the
// values where a bound check that is off by one would let a wrong length
// through, or anything from 0 to largest. Each edge is clamped into the field.
// A length field is one byte or two among many, so damage seldom reaches the
// one that matters, and seldom with exactly the wrong value.
func misstate(tc hegel.TestCase, largest int, edges ...int) int {
	generators := []hegel.Generator[int]{hegel.Integers(0, largest)}
	for _, edge := range edges {
		generators = append(generators, hegel.Just(min(max(edge, 0), largest)))
	}
	return hegel.Draw(tc, hegel.OneOf(generators...))
}

// encodingOf draws an encoding of the given kind as this package writes it.
func encodingOf(tc hegel.TestCase, kind string) []byte {
	var b []byte
	switch kind {
	case "message":
		m := Message{Header: drawHeader(tc), Payloads: drawPayloads(tc, chainTypes, 4)}
		endsInSK := hegel.Draw(tc, hegel.Booleans())
		if endsInSK {
			// either side of a whole IV, and of an IV with its ICV
			m.Payloads = append(m.Payloads, RawPayload{Type: PayloadSK, Body: drawBytes(tc, 64, 7, 8, 23, 24)})
		}
		b = m.Encode()
	case "chain":
		b = encodePayloadChain(drawPayloads(tc, innerTypes, 4))
	case "SA":
		b = EncodeSA(drawProposals(tc))
	case "IKE offer":
		b = EncodeSA([]Proposal{ikeProposal()})
	case "ESP offer":
		b = EncodeSA([]Proposal{espProposal(hegel.Draw(tc, hegel.Binary(4, 4)))})
	case "ESP answer":
		answer := espProposal(hegel.Draw(tc, hegel.Binary(4, 4)))
		answer.Transforms = []Transform{answer.Transforms[0], {Type: TransESN, ID: ESN_NO}}
		b = EncodeSA([]Proposal{answer})
	case "short ESP SPI":
		// an answer of the right shape whose SPI is shorter than four octets,
		// which the Child SA selection has to refuse before it reads one
		answer := espProposal(drawBytes(tc, 3))
		answer.Transforms = []Transform{answer.Transforms[0], {Type: TransESN, ID: ESN_NO}}
		b = EncodeSA([]Proposal{answer})
	case "misstated SPI Size":
		// either side of the SPI the proposal carries, and the rest of the
		// proposal and one past it
		b = EncodeSA([]Proposal{drawProposal(tc)})
		spi, rest := int(b[6]), len(b)-8
		b[6] = byte(misstate(tc, 0xff, spi-1, spi+1, rest, rest+1))
	case "misstated proposal length":
		// the shortest proposal there is and one under it, and either side of
		// this one's length, which is all the bytes there are
		b = EncodeSA([]Proposal{drawProposal(tc)})
		length := int(binary.BigEndian.Uint16(b[2:4]))
		binary.BigEndian.PutUint16(b[2:4], uint16(misstate(tc, 0xffff, 7, 8, length-1, length+1)))
	case "misstated transform length":
		// the first transform's, at the shortest transform there is and one
		// under it, either side of its own length, and the bytes left in the
		// proposal from where it starts and one past them
		p := drawProposal(tc)
		p.Transforms = append(p.Transforms, drawTransform(tc))
		b = EncodeSA([]Proposal{p})
		at := 8 + len(p.SPI)
		length, rest := int(binary.BigEndian.Uint16(b[at+2:at+4])), len(b)-at
		binary.BigEndian.PutUint16(b[at+2:at+4], uint16(misstate(tc, 0xffff, 7, 8, length-1, length+1, rest, rest+1)))
	case "full range selectors":
		b = fullRangeSelectors()
	case "TS":
		count := hegel.Draw(tc, withEdges(hegel.Integers(0, 3), 0, 3))
		selectors := make([]TrafficSelector, count)
		for i := range selectors {
			selectors[i] = drawSelector(tc)
		}
		b = EncodeTS(selectors)
	case "notify":
		kind := hegel.Draw(tc, withEdges(hegel.Integers[NotifyType](0, math.MaxUint16), 0, math.MaxUint16))
		b = EncodeNotify(Notify{SPI: drawBytes(tc, 8, 4), Type: kind, Data: drawBytes(tc, 64)})
	case "delete":
		protocol := hegel.Draw(tc, hegel.SampledFrom([]ProtocolID{ProtoIKE, ProtoAH, ProtoESP}))
		d := Delete{Protocol: protocol}
		if protocol != ProtoIKE {
			count := hegel.Draw(tc, withEdges(hegel.Integers(0, 4), 0, 4))
			for range count {
				d.SPIs = append(d.SPIs, hegel.Draw(tc, hegel.Binary(4, 4)))
			}
		}
		b = EncodeDelete(d)
	case "KE":
		group := hegel.Draw(tc, withEdges(hegel.Integers[uint16](0, math.MaxUint16), 0, math.MaxUint16))
		b = EncodeKE(group, drawBytes(tc, 96, 32, 64))
	case "identity":
		organization, commonName, serialNumber := drawName(tc), drawName(tc), drawName(tc)
		b = Identity{Organization: organization, CommonName: commonName, SerialNumber: serialNumber}.encodeID()
	case "misstated AUTH algorithm length":
		// either side of the AlgorithmIdentifier's own length, and the bytes
		// after the length octet and one past them
		seed := hegel.Draw(tc, hegel.Binary(ed25519.SeedSize, ed25519.SeedSize))
		b = BuildAuth(ed25519.NewKeyFromSeed(seed), drawBytes(tc, 64))
		length, rest := int(b[4]), len(b)-5
		b[4] = byte(misstate(tc, 0xff, length-1, length+1, rest, rest+1))
	default:
		seed := hegel.Draw(tc, hegel.Binary(ed25519.SeedSize, ed25519.SeedSize))
		b = BuildAuth(ed25519.NewKeyFromSeed(seed), drawBytes(tc, 64))
	}
	return b
}

// damages lists what damage may do to an encoding: overwrite one byte, move one
// byte up or down by one, which is an off by one in whatever field it lands
// in, cut the end off, or add bytes after it.
var damages = []string{"overwrite", "nudge", "cut", "extend"}

// damage changes a copy of b up to three times. Random bytes stop at the first
// length field they get wrong, and a datagram that is almost right reaches the
// checks behind it. The edges are the first and last byte for an overwrite or
// a nudge, and for a cut, everything, the last byte, or nothing.
func damage(tc hegel.TestCase, b []byte) []byte {
	b = slices.Clone(b)
	count := hegel.Draw(tc, withEdges(hegel.Integers(0, 3), 0, 1, 3))
	for range count {
		change := hegel.Draw(tc, hegel.SampledFrom(damages))
		switch {
		case change == "overwrite" && len(b) > 0:
			at := hegel.Draw(tc, withEdges(hegel.Integers(0, len(b)-1), 0, len(b)-1))
			b[at] = drawOctet[byte](tc)
		case change == "nudge" && len(b) > 0:
			at := hegel.Draw(tc, withEdges(hegel.Integers(0, len(b)-1), 0, len(b)-1))
			b[at] += hegel.Draw(tc, hegel.SampledFrom([]byte{1, 0xff}))
		case change == "cut" && len(b) > 0:
			b = b[:hegel.Draw(tc, withEdges(hegel.Integers(0, len(b)), 0, len(b)-1, len(b)))]
		default:
			b = append(b, drawBytes(tc, 16, 1)...)
		}
	}
	return b
}

// Every decoder this package runs on bytes a peer sent returns, with an error
// or with a value, and none of them panics: the header, the message and its
// payload chain, the chain inside SK, SA proposals and their transforms along
// with the selection that reads them, traffic selectors, notify, delete, KE,
// nonce, identity and AUTH. A panic on a datagram would take the node down
// from anywhere on the network. Each case tries arbitrary bytes up to 4096
// long, with the lengths either side of a whole header among their edges, and
// an encoding of each of those payloads with a few bytes damaged. It tries both
// again as a message with its length field set to its size, which hands the
// payload walker chains its length check would refuse. It tries every way each
// encoding can be cut short, and the encoding whole, since every length field
// is a place where a datagram cut short can make a decoder read past the end.
// Some encodings misstate one length field on purpose, at the values where a
// bound check off by one would let it through.
func TestDecodersReturnOnArbitraryBytes(t *testing.T) {
	signer := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	public := signer.Public().(ed25519.PublicKey)
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128}
	key := make([]byte, 16+4)
	pbt.Check(t, func(ht *hegel.T) {
		arbitrary := drawBytes(ht, 4096, HeaderLen-1, HeaderLen, HeaderLen+genericPayloadHeaderLen)
		first := drawOctet(ht, PayloadSK)
		// input is a byte string and the kind of encoding it was cut from,
		// whose decoders it goes to, or no kind for every decoder
		type input struct {
			bytes []byte
			kind  string
		}
		inputs := []input{{arbitrary, ""}, {withLength(arbitrary), ""}}
		for _, kind := range encodingKinds {
			valid := encodingOf(ht, kind)
			damaged := damage(ht, valid)
			inputs = append(inputs, input{damaged, ""}, input{withLength(damaged), ""})
			for n := 0; n <= len(valid); n++ {
				inputs = append(inputs, input{valid[:n], kind})
			}
		}

		// reads names the encodings whose cuts a decoder is given, and
		// arbitrary and damaged bytes go to every decoder
		sa := []string{"SA", "IKE offer", "ESP offer", "ESP answer", "short ESP SPI",
			"misstated SPI Size", "misstated proposal length", "misstated transform length"}
		selectors := []string{"TS", "full range selectors"}
		decoders := []struct {
			name   string
			reads  []string
			decode func([]byte) string
		}{
			{"decodeHeader", []string{"message"}, func(b []byte) string {
				if h, err := decodeHeader(b); err == nil && h == nil {
					return "returned neither a header nor an error"
				}
				return ""
			}},
			{"DecodeMessage", []string{"message"}, func(b []byte) string {
				m, err := DecodeMessage(b)
				if err == nil && m == nil {
					return "returned neither a message nor an error"
				}
				if err == nil && m.find(PayloadSK) != nil {
					_, _ = DecryptMessage(suite, key, b, m)
				}
				return ""
			}},
			{"decodePayloadChain", []string{"chain"}, func(b []byte) string { _, _ = decodePayloadChain(first, b); return "" }},
			{"decodeMessagePlaintext", []string{"chain"}, func(b []byte) string { _, _ = decodeMessagePlaintext(first, b); return "" }},
			{"DecodeSA", sa, func(b []byte) string { _, _ = DecodeSA(b); return "" }},
			{"decodeProposal", sa, func(b []byte) string { _, _, _, _ = decodeProposal(b); return "" }},
			{"decodeTransform", sa, func(b []byte) string { _, _, _, _ = decodeTransform(b); return "" }},
			{"selectIKEProposal", sa, func(b []byte) string { _, _, _ = selectIKEProposal(b, DH_CURVE25519); return "" }},
			{"decodeChildProposal", sa, func(b []byte) string { _, _, _, _ = decodeChildProposal(b, nil); return "" }},
			{"selectChildRequestProposal", sa, func(b []byte) string {
				_, _ = selectChildRequestProposal(b, nil, DH_CURVE25519)
				return ""
			}},
			{"DecodeTS", selectors, func(b []byte) string { _, _ = DecodeTS(b); return "" }},
			{"isFullRangeSelectors", selectors, func(b []byte) string { _ = isFullRangeSelectors(b); return "" }},
			{"DecodeNotify", []string{"notify"}, func(b []byte) string { _, _ = DecodeNotify(b); return "" }},
			{"DecodeDelete", []string{"delete"}, func(b []byte) string { _, _ = DecodeDelete(b); return "" }},
			{"DecodeKE", []string{"KE"}, func(b []byte) string { _, _, _ = DecodeKE(b); return "" }},
			{"DecodeNonce", nil, func(b []byte) string { _ = DecodeNonce(b); return "" }},
			{"DecodeID", []string{"identity"}, func(b []byte) string { _, _, _ = DecodeID(b); return "" }},
			{"identityFromID", []string{"identity"}, func(b []byte) string { _, _ = identityFromID(b); return "" }},
			{"DecodeIdentityDN", []string{"identity"}, func(b []byte) string { _, _, _, _ = DecodeIdentityDN(b); return "" }},
			{"derAttribute", []string{"identity"}, func(b []byte) string { _, _, _ = derAttribute(b); return "" }},
			{"VerifyAuth", []string{"AUTH", "misstated AUTH algorithm length"}, func(b []byte) string {
				_ = VerifyAuth(public, nil, b)
				return ""
			}},
		}

		// the decoders run on a goroutine of their own, which marks each call
		// before making it, and this one watches the mark
		var at atomic.Int64
		at.Store(-1)
		done := make(chan string, 1)
		go func() {
			for i, in := range inputs {
				// a read past the end has to panic here rather than reach
				// spare capacity behind a cut, an append or a truncation
				b := slices.Clip(in.bytes)
				if in.kind == "message" && len(b) >= HeaderLen {
					// a cut message that kept its length field would be
					// refused unread, so the field follows the cut
					binary.BigEndian.PutUint32(b[24:28], uint32(len(b)))
				}
				for d, decoder := range decoders {
					if in.kind != "" && !slices.Contains(decoder.reads, in.kind) {
						continue
					}
					at.Store(int64(i*len(decoders) + d))
					if problem := returns(decoder.decode, b); problem != "" {
						done <- fmt.Sprintf("%s on %x: %s", decoder.name, b, problem)
						return
					}
				}
			}
			done <- ""
		}()
		watch := time.NewTicker(100 * time.Millisecond)
		defer watch.Stop()
		mark, since := at.Load(), time.Now()
		for {
			select {
			case problem := <-done:
				if problem != "" {
					ht.Fatalf("%s", problem)
				}
				return
			case <-watch.C:
				if now := at.Load(); now != mark {
					mark, since = now, time.Now()
				} else if mark >= 0 && time.Since(since) > time.Second {
					// a decoder still in one call a second later ends the
					// run, the way go test's own timeout does, but naming the
					// decoder and the input, since failing the case for hegel
					// to shrink would leave one stuck goroutine running per
					// case it tried, and a decoder that allocates as it loops
					// would fill memory within seconds
					in, decoder := inputs[mark/int64(len(decoders))], decoders[mark%int64(len(decoders))]
					hung := fmt.Sprintf("%s: %s on %x did not return within a second", t.Name(), decoder.name, slices.Clip(in.bytes))
					go func() { panic(hung) }()
					select {}
				}
			}
		}
	})
}
