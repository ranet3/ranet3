// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-License-Identifier: MIT

package ike

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"reflect"
	"slices"
	"testing"
)

func TestDecodeMessageRejectsInvalidDeclaredExtent(t *testing.T) {
	for _, length := range []uint32{0, HeaderLen - 1, HeaderLen + 1} {
		raw := make([]byte, HeaderLen)
		binary.BigEndian.PutUint32(raw[24:28], length)
		if _, err := DecodeMessage(raw); err == nil {
			t.Fatalf("DecodeMessage accepted declared length %d for %d-byte packet", length, len(raw))
		}
	}
}

// RFC 7296 section 3.1: "An Encrypted payload MUST be the last payload in a packet and an Encrypted payload MUST NOT contain another Encrypted payload."
// a payload after SK belongs to no chain of the message, which is refused
// the SK payload carries a Delete, so its Next Payload field names the chain inside and not the end of the message
func TestDecodeMessageRefusesAPayloadAfterSK(t *testing.T) {
	inner := []RawPayload{{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoIKE})}}
	raw, err := encryptMessageIV(SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128}, make([]byte, 16+4), Header{}, nil, inner, make([]byte, 8))
	if err != nil {
		t.Fatal(err)
	}
	// an empty payload ending a chain
	raw = append(raw, 0, 0, 0, 4)
	binary.BigEndian.PutUint32(raw[24:28], uint32(len(raw)))
	if _, err := DecodeMessage(raw); err == nil {
		t.Fatal("DecodeMessage took a payload after SK")
	}
}

// RFC 7296 section 3.1: "An Encrypted payload MUST be the last payload in a packet and an Encrypted payload MUST NOT contain another Encrypted payload."
// an SK payload inside SK, alone, first, between two others or last, is refused once SK decrypts
func TestDecryptMessageRefusesAnSKPayloadInsideAnother(t *testing.T) {
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128}
	key := make([]byte, 16+4)
	nested := RawPayload{Type: PayloadSK, Body: make([]byte, 24)}
	deletion := RawPayload{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoIKE})}
	for placement, inner := range map[string][]RawPayload{
		"alone":   {nested},
		"first":   {nested, deletion},
		"between": {deletion, nested, deletion},
		"last":    {deletion, nested},
	} {
		raw, err := encryptMessageIV(suite, key, Header{}, nil, inner, make([]byte, 8))
		if err != nil {
			t.Fatal(err)
		}
		m, err := DecodeMessage(raw)
		if err != nil {
			t.Fatalf("the message with an SK payload %s inside SK does not decode: %v", placement, err)
		}
		if got, err := DecryptMessage(suite, key, raw, m); err == nil {
			t.Errorf("DecryptMessage took %+v, an SK payload %s inside SK", got, placement)
		}
	}
}

func TestDecodeMessageRejectsTrailingPayloadBytes(t *testing.T) {
	raw := (&Header{Length: HeaderLen + 1}).encode()
	raw = append(raw, 0)
	if _, err := DecodeMessage(raw); err == nil {
		t.Fatal("DecodeMessage accepted bytes after an empty payload chain")
	}
}

// RFC 7296 section 3.2 on the critical bit: "MUST be ignored by the recipient if the recipient understands the payload type code."
// section 2.5: "If the critical flag is set and the payload type is unrecognized, the message MUST be rejected"
// section 2.5: "If the critical flag is not set and the payload type is unsupported, that payload MUST be ignored."
func TestOnlyACriticalPayloadOfAnUnsupportedTypeIsRefused(t *testing.T) {
	for _, payloadType := range []PayloadType{PayloadSA, PayloadCERT, PayloadCERTREQ, PayloadNonce, PayloadV, PayloadSK, PayloadCP, PayloadEAP} {
		if unsupported, found := firstUnsupportedCritical([]RawPayload{{Type: payloadType, Critical: true}}); found {
			t.Errorf("refused a message marking payload type %d critical, a type this end understands", unsupported)
		}
	}
	// the types on either side of those RFC 7296 defines, and one of the range kept for private use
	for _, payloadType := range []PayloadType{32, 49, 250} {
		if unsupported, found := firstUnsupportedCritical(nil, []RawPayload{{Type: PayloadSA, Critical: true}, {Type: payloadType, Critical: true}}); !found || unsupported != payloadType {
			t.Errorf("found payload type %d (%v) in a message marking payload type %d critical, a type this end does not support", unsupported, found, payloadType)
		}
		if unsupported, found := firstUnsupportedCritical([]RawPayload{{Type: payloadType}}); found {
			t.Errorf("refused a message carrying payload type %d unmarked", unsupported)
		}
	}
}

// RFC 7296 section 2.5: "Also, for forward compatibility, all fields marked RESERVED MUST be set to zero by an implementation running version 2.0, and their content MUST be ignored by an implementation running version 2.0"
// each RESERVED field of the payloads this end builds is zero, and a payload with every bit of those fields set reads as the one sent
func TestReservedFieldsAreSentAsZeroAndIgnored(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed := []byte("octets the AUTH payload signs")
	sa := EncodeSA([]Proposal{ikeProposal()})
	// the proposal's octet after Last Substruc, then the two of each transform after its Last Substruc and its Transform Type
	saReserved := []int{1}
	for at := 8 + int(sa[6]); at < len(sa); at += int(binary.BigEndian.Uint16(sa[at+2 : at+4])) {
		saReserved = append(saReserved, at+1, at+5)
	}
	unsupported := []RawPayload{{Type: PayloadType(250), Body: []byte{1}}}
	for _, payload := range []struct {
		name     string
		sent     []byte
		reserved []int
		mask     byte
		read     func([]byte) (any, error)
	}{
		{"payload chain", encodePayloadChain(unsupported), []int{1}, 0x7f, func(b []byte) (any, error) { return decodePayloadChain(unsupported[0].Type, b) }},
		{"message", (&Message{Payloads: unsupported}).Encode(), []int{HeaderLen + 1}, 0x7f, func(b []byte) (any, error) {
			message, err := DecodeMessage(b)
			if err != nil {
				return nil, err
			}
			return message.Payloads, nil
		}},
		{"SA payload", sa, saReserved, 0xff, func(b []byte) (any, error) { return DecodeSA(b) }},
		{"KE payload", EncodeKE(DH_CURVE25519, make([]byte, 32)), []int{2, 3}, 0xff, func(b []byte) (any, error) {
			group, data, err := DecodeKE(b)
			return []any{group, data}, err
		}},
		{"ID payload", EncodeID(ID_DER_ASN1_DN, []byte{0x30, 0x00}), []int{1, 2, 3}, 0xff, func(b []byte) (any, error) {
			idType, data, err := DecodeID(b)
			return []any{idType, data}, err
		}},
		{"AUTH payload", BuildAuth(private, signed), []int{1, 2, 3}, 0xff, func(b []byte) (any, error) { return nil, VerifyAuth(public, signed, b) }},
		{"TS payload", EncodeTS([]TrafficSelector{FullRangeV4(), FullRangeV6()}), []int{1, 2, 3}, 0xff, func(b []byte) (any, error) { return DecodeTS(b) }},
	} {
		for _, at := range payload.reserved {
			if bits := payload.sent[at] & payload.mask; bits != 0 {
				t.Errorf("the %s is sent with RESERVED bits %#x at octet %d", payload.name, bits, at)
			}
		}
		want, err := payload.read(payload.sent)
		if err != nil {
			t.Fatalf("the %s this end sends does not read: %v", payload.name, err)
		}
		set := slices.Clone(payload.sent)
		for _, at := range payload.reserved {
			set[at] |= payload.mask
		}
		if got, err := payload.read(set); err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("the %s with its RESERVED bits set reads as %v (%v), want %v", payload.name, got, err, want)
		}
	}

	// the SK payload's header is associated data, so the one with its RESERVED bits set is sealed after they are set
	suite, key := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128}, make([]byte, 20)
	inner := []RawPayload{{Type: PayloadNonce, Body: make([]byte, 32)}}
	sealed, err := EncryptMessage(suite, key, Header{}, nil, inner)
	if err != nil {
		t.Fatal(err)
	}
	if bits := sealed[HeaderLen+1] & 0x7f; bits != 0 {
		t.Errorf("the SK payload is sent with RESERVED bits %#x", bits)
	}
	set := sealedEdited(t, suite, key, Header{}, inner, func(aad []byte) { aad[HeaderLen+1] |= 0x7f })
	message, err := DecodeMessage(set)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := DecryptMessage(suite, key, set, message); err != nil || !samePayloads(got, inner) {
		t.Errorf("the SK payload with its RESERVED bits set reads as %v (%v), want %v", got, err, inner)
	}
}

func payloadTypes(payloads []RawPayload) []PayloadType {
	types := make([]PayloadType, len(payloads))
	for i, payload := range payloads {
		types[i] = payload.Type
	}
	return types
}

// samePayloads compares two payload lists by what is on the wire, so an empty
// body and a nil one are the same body.
func samePayloads(a, b []RawPayload) bool {
	return slices.EqualFunc(a, b, func(x, y RawPayload) bool {
		return x.Type == y.Type && x.Critical == y.Critical && bytes.Equal(x.Body, y.Body)
	})
}

func TestIKEContextAllocatesUniqueIVs(t *testing.T) {
	context := &ikeContext{suite: SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128}}
	key := make([]byte, 20)
	first, err := context.encrypt(key, Header{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := context.encrypt(key, Header{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	firstIV := first[HeaderLen+genericPayloadHeaderLen : HeaderLen+genericPayloadHeaderLen+8]
	secondIV := second[HeaderLen+genericPayloadHeaderLen : HeaderLen+genericPayloadHeaderLen+8]
	if string(firstIV) == string(secondIV) {
		t.Fatalf("reused IKE IV %x", firstIV)
	}
}
