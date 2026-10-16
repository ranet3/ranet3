// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-License-Identifier: MIT

package ike

import (
	"encoding/binary"
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

func TestResponsePayloadsRejectCriticalFlag(t *testing.T) {
	for _, payloadType := range []PayloadType{PayloadSA, PayloadType(250)} {
		if err := validateResponseCriticalFlags([]RawPayload{{Type: payloadType, Critical: true}}); err == nil {
			t.Fatalf("accepted critical response payload type %d", payloadType)
		}
	}
	if err := validateResponseCriticalFlags([]RawPayload{{Type: PayloadType(250)}}); err != nil {
		t.Fatalf("rejected ignorable noncritical response payload: %v", err)
	}
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
