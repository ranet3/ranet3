// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

package ike

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"net"
	"slices"
	"strings"
	"testing"
	"time"
)

func encodedChildProposal(encryption Transform) []byte {
	return EncodeSA([]Proposal{{
		Number: 1, Protocol: ProtoESP, SPI: []byte{1, 2, 3, 4},
		Transforms: []Transform{encryption, {Type: TransESN, ID: ESN_NO}},
	}})
}

func TestDecodeChildProposalNormalizesChaChaKeyLength(t *testing.T) {
	offered := espProposal(nil).Transforms
	_, got, _, err := decodeChildProposal(encodedChildProposal(Transform{Type: TransEncr, ID: ENCR_CHACHA20_POLY1305}), offered)
	if err != nil {
		t.Fatal(err)
	}
	if got.KeyLengthBits != 256 {
		t.Fatalf("key length normalized to %d, want 256", got.KeyLengthBits)
	}
	attributed := Transform{Type: TransEncr, ID: ENCR_CHACHA20_POLY1305, KeyLengthBits: 256}
	if _, _, _, err := decodeChildProposal(encodedChildProposal(attributed), append(offered, attributed)); err == nil {
		t.Fatal("accepted Key Length attribute for fixed-length ChaCha20-Poly1305")
	}
}

func TestDecodeChildProposalRejectsInvalidShape(t *testing.T) {
	tests := []Proposal{
		{Number: 2, Protocol: ProtoESP, SPI: []byte{1, 2, 3, 4}, Transforms: []Transform{{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128}, {Type: TransESN, ID: ESN_NO}}},
		{Number: 1, Protocol: ProtoIKE, SPI: []byte{1, 2, 3, 4}, Transforms: []Transform{{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128}, {Type: TransESN, ID: ESN_NO}}},
		{Number: 1, Protocol: ProtoESP, SPI: []byte{0, 0, 0, 0}, Transforms: []Transform{{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128}, {Type: TransESN, ID: ESN_NO}}},
		{Number: 1, Protocol: ProtoESP, SPI: []byte{1, 2, 3, 4}, Transforms: []Transform{{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128}, {Type: TransESN, ID: ESN_YES}}},
		{Number: 1, Protocol: ProtoESP, SPI: []byte{1, 2, 3, 4}, Transforms: []Transform{{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 192}, {Type: TransESN, ID: ESN_NO}}},
	}
	for _, proposal := range tests {
		if _, _, _, err := decodeChildProposal(EncodeSA([]Proposal{proposal}), espProposal(nil).Transforms); err == nil {
			t.Fatalf("accepted invalid proposal %+v", proposal)
		}
	}
}

func TestSelectChildRekeyProposalSkipsAttributedTransform(t *testing.T) {
	want := ChildSA{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128}
	proposal := Proposal{
		Number: 1, Protocol: ProtoESP, SPI: []byte{1, 2, 3, 4},
		Transforms: []Transform{
			{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128},
			{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128},
			{Type: TransESN, ID: ESN_NO},
		},
	}
	raw := addUnknownTVAttributeToFirstTransform(EncodeSA([]Proposal{proposal}))
	selection, err := selectChildRequestProposal(raw, Suites{}.rekeyChoice(want), Suites{}.kexEntries(), 0)
	if err != nil {
		t.Fatal(err)
	}
	selected := selection.encryption
	if selected.UnsupportedAttributes || selected.ID != want.EncrID || selected.KeyLengthBits != want.EncrKeyBits {
		t.Fatalf("selected transform = %#v", selected)
	}
}

func TestDecodeChildExchangePayloadsRejectsDuplicates(t *testing.T) {
	payloads := []RawPayload{
		{Type: PayloadSA, Body: encodedChildProposal(Transform{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128})},
		{Type: PayloadNonce, Body: EncodeNonce(make([]byte, 32))},
		{Type: PayloadTSi, Body: fullRangeSelectors()},
		{Type: PayloadTSr, Body: fullRangeSelectors()},
	}
	if _, err := decodeChildExchangePayloads(payloads, PRF_HMAC_SHA2_256); err != nil {
		t.Fatalf("refused the exchange before it carried a second Nonce payload: %v", err)
	}
	payloads = append(payloads, RawPayload{Type: PayloadNonce, Body: EncodeNonce(make([]byte, 32))})
	if _, err := decodeChildExchangePayloads(payloads, PRF_HMAC_SHA2_256); err == nil {
		t.Fatal("accepted a second Nonce payload")
	}
}

// RFC 7296 section 3.2 on the critical bit: "MUST be ignored by the recipient if the recipient understands the payload type code."
// a Child SA exchange marking every payload critical, a Delete it does not take among them, decodes as one marking none
func TestDecodeChildExchangePayloadsIgnoresTheCriticalBit(t *testing.T) {
	payloads := []RawPayload{
		{Type: PayloadSA, Critical: true, Body: encodedChildProposal(Transform{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128})},
		{Type: PayloadNonce, Critical: true, Body: EncodeNonce(make([]byte, 32))},
		{Type: PayloadTSi, Critical: true, Body: fullRangeSelectors()},
		{Type: PayloadTSr, Critical: true, Body: fullRangeSelectors()},
		{Type: PayloadD, Critical: true, Body: EncodeDelete(Delete{Protocol: ProtoESP, SPIs: [][]byte{{0, 0, 0, 9}}})},
	}
	if _, err := decodeChildExchangePayloads(payloads, PRF_HMAC_SHA2_256); err != nil {
		t.Fatalf("refused a Child SA exchange marking every payload critical: %v", err)
	}
}

func TestDecodeChildNegotiationResponseHandlesNotifyOnlyError(t *testing.T) {
	_, err := decodeChildNegotiationResponse([]RawPayload{{
		Type: PayloadN,
		Body: EncodeNotify(Notify{Type: N_TEMPORARY_FAILURE}),
	}}, PRF_HMAC_SHA2_256)
	if err == nil || !strings.Contains(err.Error(), "rejected: notify type 43") {
		t.Fatalf("notify-only response error = %v", err)
	}
}

// RFC 7296 section 3.10.1: "An implementation receiving a Notify payload with one of these types that it does not recognize in a response MUST assume that the corresponding request has failed entirely."
// section 3.10.1: "Notify payloads with status types MAY be added to any message and MUST be ignored if not recognized."
// a whole Child SA answer beside an error notify of a type nothing assigns is a rejection naming it, and beside a status notify of a type nothing assigns is taken
func TestDecodeChildNegotiationResponseTakesAnErrorNotifyItDoesNotRecognizeAsARejection(t *testing.T) {
	answer := func(notify RawPayload) []RawPayload {
		return []RawPayload{
			notify,
			{Type: PayloadSA, Body: encodedChildProposal(Transform{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128})},
			{Type: PayloadNonce, Body: EncodeNonce(make([]byte, 32))},
			{Type: PayloadTSi, Body: fullRangeSelectors()},
			{Type: PayloadTSr, Body: fullRangeSelectors()},
		}
	}
	_, err := decodeChildNegotiationResponse(answer(unrecognizedError), PRF_HMAC_SHA2_256)
	if rejected, ok := errors.AsType[*rejectedError](err); !ok || rejected.notify.Type != 8191 {
		t.Errorf("the answer carrying error notify type 8191 decoded with %v, want a rejection naming it", err)
	}
	if _, err := decodeChildNegotiationResponse(answer(unrecognizedStatus), PRF_HMAC_SHA2_256); err != nil {
		t.Errorf("the answer carrying status notify type 40000 was refused: %v", err)
	}
}

func TestValidateFullRangeSelectors(t *testing.T) {
	want := fullRangeSelectors()
	if err := validateFullRangeSelectors(&RawPayload{Body: want}, &RawPayload{Body: want}); err != nil {
		t.Fatal(err)
	}
	narrow := EncodeTS([]TrafficSelector{FullRangeV4()})
	if err := validateFullRangeSelectors(&RawPayload{Body: narrow}, &RawPayload{Body: want}); err == nil {
		t.Fatal("accepted narrowed traffic selectors")
	}
}

// RFC 7296 section 2.10: a nonce "MUST be at least 128 bits in size, and MUST
// be at least half the key size of the negotiated pseudorandom function". The
// second half was missing, so a 16 byte nonce was taken under HMAC-SHA2-384,
// whose preferred key size is 48.
func TestNonceLengthFollowsTheNegotiatedPRF(t *testing.T) {
	for _, test := range []struct {
		prf    uint16
		length int
		want   bool
	}{
		{PRF_HMAC_SHA2_256, 15, false},
		{PRF_HMAC_SHA2_256, 16, true},
		{PRF_HMAC_SHA2_384, 16, false},
		{PRF_HMAC_SHA2_384, 23, false},
		{PRF_HMAC_SHA2_384, 24, true},
		{PRF_HMAC_SHA2_384, 257, false},
	} {
		if got := validNonceFor(make([]byte, test.length), test.prf); got != test.want {
			t.Errorf("a %d byte nonce under PRF %d was accepted=%v, want %v", test.length, test.prf, got, test.want)
		}
	}
	// RFC 7296 section 3.9: "The size of the Nonce Data MUST be between 16 and 256 octets, inclusive."
	// validNonce holds it alone, so it holds under a PRF whose half key is shorter than 16 octets too
	for length, want := range map[int]bool{15: false, 16: true, 256: true, 257: false} {
		if got := validNonce(make([]byte, length)); got != want {
			t.Errorf("a %d byte nonce was accepted=%v, want %v", length, got, want)
		}
	}
}

// a peer spelling out INTEG NONE alongside an AEAD cipher does it on every proposal it sends
// so the Child SA selector takes it as the IKE one does
// RFC 7296 section 2.7: "The accepted cryptographic suite MUST contain exactly one transform of each type included in the proposal."
func TestIntegNoneIsTakenAndEchoedOnEveryProposal(t *testing.T) {
	integ := Transform{Type: TransInteg, ID: INTEG_NONE}
	esp := func(extra ...Transform) []byte {
		spi := []byte{0, 0, 0, 9}
		return EncodeSA([]Proposal{{Number: 1, Protocol: ProtoESP, SPI: spi, Transforms: append([]Transform{
			{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 256},
			{Type: TransESN, ID: ESN_NO},
		}, extra...)}})
	}
	selection, err := selectChildRequestProposal(esp(integ), Suites{}.espCiphers(), Suites{}.kexEntries(), 0)
	if err != nil {
		t.Fatalf("a Child SA proposal naming INTEG NONE was refused: %v", err)
	}
	if selection.integ != integ {
		t.Errorf("the selection kept %+v, so the answer cannot carry it back", selection.integ)
	}
	// this end's own offer names no integrity transform
	// and an answer to it holds only the types the offer named
	if _, _, _, err := decodeChildProposal(esp(integ), espProposal(nil).Transforms); err == nil {
		t.Error("an answer to this end's offer named a transform type the offer did not")
	}

	// every cipher this end lists is combined mode
	// so an integrity algorithm has no key here
	unusable := Transform{Type: TransInteg, ID: 12}
	if _, err := selectChildRequestProposal(esp(unusable), Suites{}.espCiphers(), Suites{}.kexEntries(), 0); err == nil {
		t.Error("a Child SA proposal naming a real integrity algorithm was accepted")
	}
	if _, _, _, err := decodeChildProposal(esp(unusable), espProposal(nil).Transforms); err == nil {
		t.Error("decoding a Child SA proposal naming a real integrity algorithm succeeded")
	}
}

// RFC 7296 section 3.3.6: "if the responder receives a transform that it does not understand, or one that contains a Transform Attribute it does not understand, it MUST consider this transform unacceptable" and "other transforms with the same Transform Type are processed as usual."
func TestUnusableChildIntegrityAlternativeDoesNotRefuseTheProposal(t *testing.T) {
	spi := []byte{0, 0, 0, 7}
	base := []Transform{
		{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 256},
		{Type: TransESN, ID: ESN_NO},
	}
	none := Transform{Type: TransInteg, ID: INTEG_NONE}
	unusable := Transform{Type: TransInteg, ID: 12}

	body := EncodeSA([]Proposal{{Number: 1, Protocol: ProtoESP, SPI: spi,
		Transforms: append(slices.Clone(base), unusable, none)}})
	selection, err := selectChildRequestProposal(body, Suites{}.espCiphers(), Suites{}.kexEntries(), 0)
	if err != nil {
		t.Fatalf("an offer naming an integrity algorithm alongside NONE was refused: %v", err)
	}
	if selection.integ != none {
		t.Errorf("the answer carries integrity transform %v, want the NONE the offer included", selection.integ)
	}

	onlyUnusable := EncodeSA([]Proposal{{Number: 1, Protocol: ProtoESP, SPI: spi,
		Transforms: append(slices.Clone(base), unusable)}})
	if _, err := selectChildRequestProposal(onlyUnusable, Suites{}.espCiphers(), Suites{}.kexEntries(), 0); err == nil {
		t.Error("an offer whose every integrity alternative is unusable was accepted")
	}
	pair := EncodeSA([]Proposal{
		{Number: 1, Protocol: ProtoESP, SPI: spi, Transforms: append(slices.Clone(base), unusable)},
		{Number: 2, Protocol: ProtoESP, SPI: spi, Transforms: slices.Clone(base)},
	})
	if selection, err := selectChildRequestProposal(pair, Suites{}.espCiphers(), Suites{}.kexEntries(), 0); err != nil || selection.proposal.Number != 2 {
		t.Errorf("the second proposal was not considered: %v, %v", selection.proposal.Number, err)
	}
}

// RFC 7296 section 3.3.6: "The initiator of an exchange MUST check that the accepted offer is consistent with one of its proposals, and if not MUST terminate the exchange."
// an unoffered DH transform is the costly case
// the responder would mean perfect forward secrecy this end never derives
func TestChildAnswerIsCheckedAgainstWhatThisEndOffered(t *testing.T) {
	spi := []byte{0, 0, 0, 9}
	base := []Transform{
		{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 256},
		{Type: TransESN, ID: ESN_NO},
	}
	answer := func(extra ...Transform) []byte {
		return EncodeSA([]Proposal{{Number: 1, Protocol: ProtoESP, SPI: spi,
			Transforms: append(slices.Clone(base), extra...)}})
	}
	offered := espProposal(nil).Transforms
	for name, extra := range map[string][]Transform{
		"the shape the offer asks for": nil,
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := decodeChildProposal(answer(extra...), offered); err != nil {
				t.Errorf("a conforming answer was refused: %v", err)
			}
		})
	}
	for name, extra := range map[string][]Transform{
		"dh none":                  {{Type: TransDH, ID: 0}},
		"a real dh group":          {{Type: TransDH, ID: DH_CURVE25519}},
		"integ none spelled out":   {{Type: TransInteg, ID: INTEG_NONE}},
		"integ none with key bits": {{Type: TransInteg, ID: INTEG_NONE, KeyLengthBits: 128}},
		"dh and integ none":        {{Type: TransDH, ID: 0}, {Type: TransInteg, ID: INTEG_NONE}},
		"a repeated type":          {{Type: TransESN, ID: ESN_NO}},
		"an unknown type":          {{Type: TransformType(15), ID: 1}},
		"an integ algorithm":       {{Type: TransInteg, ID: 12}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := decodeChildProposal(answer(extra...), offered); err == nil {
				t.Error("an answer naming what the offer did not was accepted")
			}
		})
	}
}

// an answer leaving out a type the offer included is refused as much as one adding a type
func TestChildAnswerMissingAnOfferedTypeIsRefused(t *testing.T) {
	spi := []byte{0, 0, 0, 9}
	for name, transforms := range map[string][]Transform{
		"no esn":    {{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 256}},
		"no cipher": {{Type: TransESN, ID: ESN_NO}},
	} {
		t.Run(name, func(t *testing.T) {
			answer := EncodeSA([]Proposal{{Number: 1, Protocol: ProtoESP, SPI: spi, Transforms: transforms}})
			_, _, _, err := decodeChildProposal(answer, espProposal(nil).Transforms)
			if err == nil || !strings.Contains(err.Error(), "incomplete Child SA proposal") {
				t.Errorf("an answer without every offered type got %v, want it refused as incomplete", err)
			}
		})
	}
}

// This is a drift guard on the offer, not a test of the reader: the reader
// knows two transform types, and a type added to espProposal has to be added
// to it in the same change, or every answer to the new offer is refused as
// inconsistent and no Child SA is ever established. Stated here rather than as
// a permissive default that would accept a value the reader does nothing
// with.
func TestEspProposalOffersNoTypeTheAnswerReaderRefuses(t *testing.T) {
	for _, transform := range espProposal([]byte{0, 0, 0, 1}).Transforms {
		switch transform.Type {
		case TransEncr, TransESN:
		default:
			t.Fatalf("espProposal offers transform type %d, which decodeChildProposal refuses: "+
				"an answer carries one transform of each type the offer included, RFC 7296 section 2.7",
				transform.Type)
		}
	}
}

// a responder answering a peer's offer echoes each type the offer named, DH and INTEG among them
// RFC 7296 section 2.7: "The accepted cryptographic suite MUST contain exactly one transform of each type included in the proposal."
func TestResponderEchoesEveryTypeTheOfferNamed(t *testing.T) {
	spi := []byte{0, 0, 0, 9}
	base := []Transform{
		{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 256},
		{Type: TransESN, ID: ESN_NO},
	}
	none := Transform{Type: TransInteg, ID: INTEG_NONE}
	for name, extra := range map[string][]Transform{
		"dh none":       {{Type: TransDH, ID: 0}},
		"pfs":           {{Type: TransDH, ID: DH_CURVE25519}},
		"integ none":    {none},
		"dh and integ":  {{Type: TransDH, ID: 0}, none},
		"pfs and integ": {{Type: TransDH, ID: DH_CURVE25519}, none},
	} {
		t.Run(name, func(t *testing.T) {
			offer := EncodeSA([]Proposal{{Number: 1, Protocol: ProtoESP, SPI: spi,
				Transforms: append(slices.Clone(base), extra...)}})
			keGroup := uint16(0)
			for _, transform := range extra {
				if transform.Type == TransDH {
					keGroup = transform.ID
				}
			}
			selection, err := selectChildRequestProposal(offer, Suites{}.espCiphers(), Suites{}.kexEntries(), keGroup)
			if err != nil {
				t.Fatalf("the offer was refused: %v", err)
			}
			child := responderChild{number: selection.proposal.Number,
				encryption: selection.encryption, dh: selection.dh, integ: selection.integ}
			for _, want := range extra {
				if !slices.Contains(child.proposal(spi).Transforms, want) {
					t.Errorf("the answer is %v, which drops %v", child.proposal(spi).Transforms, want)
				}
			}
		})
	}
}

// RFC 7296 section 2.8: "Note that, when rekeying, the new Child SA SHOULD NOT have different Traffic Selectors and algorithms than the old one."
// a rekey offers the cipher of the SA it replaces alone while esp cipher holds it
// and it reads every answer a responder can build from that offer
func TestRekeyOffersOnlyTheCipherItsAnswerReaderWillTake(t *testing.T) {
	spi := []byte{0, 0, 0, 5}
	for _, old := range []ChildSA{
		{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 256},
		{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128},
		{EncrID: ENCR_CHACHA20_POLY1305},
	} {
		offer := espRekeyProposal(spi, old)
		ciphers := 0
		for _, transform := range offer.Transforms {
			if transform.Type != TransEncr {
				continue
			}
			ciphers++
			if transform.ID != old.EncrID || transform.KeyLengthBits != old.EncrKeyBits {
				t.Errorf("the rekey offer names %v, which its own answer reader refuses", transform)
			}
		}
		if ciphers != 1 {
			t.Errorf("the rekey offer names %d ciphers, want the one the answer may carry", ciphers)
		}
		selection, err := selectChildRequestProposal(EncodeSA([]Proposal{offer}), Suites{}.espCiphers(), Suites{}.kexEntries(), 0)
		if err != nil {
			t.Fatalf("the rekey offer was refused: %v", err)
		}
		child := responderChild{number: selection.proposal.Number,
			encryption: selection.encryption, dh: selection.dh, integ: selection.integ}
		if _, _, _, err := decodeChildProposal(EncodeSA([]Proposal{child.proposal(spi)}), offer.Transforms); err != nil {
			t.Errorf("an answer built from the rekey offer was refused: %v", err)
		}
	}
	// the initial offer names every listed cipher
	// no old SA holds the answer to one
	ciphers := 0
	for _, transform := range espProposal(spi).Transforms {
		if transform.Type == TransEncr {
			ciphers++
		}
	}
	if ciphers != 3 {
		t.Errorf("the initial offer names %d ciphers, want every one this end has", ciphers)
	}
}

// a rekey answer naming a cipher other than the one the SA being replaced uses is refused
// an answer to the initial offer naming it is taken
func TestRekeyAnswerWithAnotherCipherIsRefused(t *testing.T) {
	old := ChildSA{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128}
	for name, encryption := range map[string]Transform{
		"a longer key":   {Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 256},
		"another cipher": {Type: TransEncr, ID: ENCR_CHACHA20_POLY1305},
	} {
		t.Run(name, func(t *testing.T) {
			answer := encodedChildProposal(encryption)
			if _, _, _, err := decodeChildProposal(answer, espProposal(nil).Transforms); err != nil {
				t.Fatalf("the answer was refused with no SA to hold it to: %v", err)
			}
			_, _, _, err := decodeChildProposal(answer, espRekeyProposal(nil, old).Transforms)
			if err == nil || !strings.Contains(err.Error(), "selected an unoffered transform") {
				t.Errorf("a rekey answer of %v for an SA keyed with %v got %v, want it refused", encryption, old, err)
			}
		})
	}
}

// RFC 7296 section 1.3: "There are two octets of data associated with this notification: the accepted Diffie-Hellman group number in big endian order."
// a notify without them tells a peer its group is wrong and not which one to use
// so every site sending one carries them
func TestEveryInvalidKENotifyNamesAGroup(t *testing.T) {
	// a Child SA offer naming a group its absent KE payload is not in draws the notify
	spi := []byte{0, 0, 0, 3}
	offer := EncodeSA([]Proposal{{Number: 1, Protocol: ProtoESP, SPI: spi, Transforms: []Transform{
		{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 256},
		{Type: TransESN, ID: ESN_NO},
		{Type: TransDH, ID: DH_CURVE25519},
	}}})
	_, err := selectChildRequestProposal(offer, Suites{}.espCiphers(), Suites{}.kexEntries(), 0)
	var wrongGroup *invalidKEError
	if !errors.As(err, &wrongGroup) {
		t.Fatalf("an offer naming a group this end did not use reported %v", err)
	}
	if wrongGroup.group != DH_CURVE25519 {
		t.Errorf("the error names group %d, want the one the offer asked for", wrongGroup.group)
	}
	// all three sites build the notify data with invalidKENotifyData
	notify, err := DecodeNotify(EncodeNotify(Notify{Type: N_INVALID_KE_PAYLOAD,
		Data: invalidKENotifyData(wrongGroup.group)}))
	if err != nil {
		t.Fatal(err)
	}
	if len(notify.Data) != 2 || binary.BigEndian.Uint16(notify.Data) != DH_CURVE25519 {
		t.Errorf("the notify carries %v, which no initiator can retry from", notify.Data)
	}
	if group, ok := preferredGroupFromNotify(notify); !ok || group != DH_CURVE25519 {
		t.Errorf("an initiator reading that notify got %d, %v", group, ok)
	}
}

// preferredGroupFromNotify spells out what an initiator does with the data,
// so the two halves are checked against each other.
func preferredGroupFromNotify(n Notify) (uint16, bool) {
	if n.Type != N_INVALID_KE_PAYLOAD || len(n.Data) < 2 {
		return 0, false
	}
	return binary.BigEndian.Uint16(n.Data), true
}

// wantInvalidKE fails a test whose answer is not INVALID_KE_PAYLOAD
// with the two octets of group as its data
func wantInvalidKE(t *testing.T, answer Notify, group uint16) {
	t.Helper()
	if got, ok := preferredGroupFromNotify(answer); !ok || len(answer.Data) != 2 || got != group {
		t.Errorf("answered notify %d with data %x, want INVALID_KE_PAYLOAD naming group %d", answer.Type, answer.Data, group)
	}
}

// an IKE_SA_INIT whose KE is in a group its offer leaves out
// is told the offered group to retry in
func TestIKESAInitKEOutsideItsOfferIsAnsweredWithTheGroup(t *testing.T) {
	h := newResponderHarness(t, nil)
	mux, err := h.initiator.NewMux(net.ParseIP("127.0.0.1"), h.remotePort)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mux.Close() })
	spiI := randUint64Nonzero()
	if err := mux.RegisterIKE(spiI); err != nil {
		t.Fatal(err)
	}
	// encodeTestSAInit writes its KE in X25519
	offer := Proposal{Number: 1, Protocol: ProtoIKE, Transforms: []Transform{
		{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 256},
		{Type: TransPRF, ID: PRF_HMAC_SHA2_256},
		{Type: TransDH, ID: DH_ECP_256},
	}}
	request := encodeTestSAInit(t, spiI, bytes.Repeat([]byte{1}, 32), offer, nil)
	reply := statelessAnswer(t, mux, request, "a KE outside the offer drew no answer")
	wantInvalidKE(t, firstTestNotify(t, reply), DH_ECP_256)
}

// a peer's Child SA rekey whose KE is in a group its offer leaves out
// is told the offered group to retry in and keeps the Child SA it has
func TestPeerChildRekeyKEOutsideItsOfferIsAnsweredWithTheGroup(t *testing.T) {
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	ctx := &ikeContext{suite: suite, spiI: 11, spiR: 12, skD: bytes.Repeat([]byte{1}, 32),
		skei: bytes.Repeat([]byte{2}, 20), sker: bytes.Repeat([]byte{3}, 20), responder: true}
	old := ChildSA{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, LocalSPI: 21, RemoteSPI: 22}
	s := &Session{current: ctx, Child: old}
	offer := espProposal(binary.BigEndian.AppendUint32(nil, 32))
	offer.Transforms = append(offer.Transforms, Transform{Type: TransDH, ID: DH_ECP_256})
	// group 14 is MODP 2048, which this end has no code for
	raw, err := s.handleChildRekey(ctx, 0, []RawPayload{
		{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_REKEY_SA, Protocol: ProtoESP, SPI: binary.BigEndian.AppendUint32(nil, old.RemoteSPI)})},
		{Type: PayloadSA, Body: EncodeSA([]Proposal{offer})},
		{Type: PayloadNonce, Body: bytes.Repeat([]byte{4}, 32)},
		{Type: PayloadKE, Body: EncodeKE(14, bytes.Repeat([]byte{5}, 32))},
		{Type: PayloadTSi, Body: fullRangeSelectors()},
		{Type: PayloadTSr, Body: fullRangeSelectors()},
	})
	if err != nil {
		t.Fatal(err)
	}
	message, err := DecodeMessage(raw.whole)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := DecryptMessage(suite, ctx.localEncryptionKey(), raw.whole, message)
	if err != nil {
		t.Fatal(err)
	}
	payload := findType(inner, PayloadN)
	if payload == nil {
		t.Fatalf("the answer carried no notify: %v", inner)
	}
	notify, err := DecodeNotify(payload.Body)
	if err != nil {
		t.Fatal(err)
	}
	wantInvalidKE(t, notify, DH_ECP_256)
	if s.currentChild().LocalSPI != old.LocalSPI {
		t.Error("a refused rekey replaced the Child SA")
	}
}

// a peer's rekey answered INVALID_KE_PAYLOAD and retried at once in the group asked for is taken
// the limit on peer rekeys counts the rekeys this end runs a key exchange for
// so one whose KE fails the exchange, answered INVALID_SYNTAX, has taken it, and a next request at once draws TEMPORARY_FAILURE
// RFC 7296 section 1.3: "In the case of such a rejection, the CREATE_CHILD_SA exchange fails, and the initiator will probably retry the exchange with a Diffie-Hellman proposal and KEi in the group that the responder gave in the INVALID_KE_PAYLOAD Notify payload."
func TestPeerRekeyRetriedInTheGroupItWasAskedForIsTaken(t *testing.T) {
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256, DHGroup: DH_CURVE25519}
	old := ChildSA{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, LocalSPI: 21, RemoteSPI: 22}
	ke := func(group uint16) RawPayload {
		dh, err := GenerateDH(group)
		if err != nil {
			t.Fatal(err)
		}
		return RawPayload{Type: PayloadKE, Body: EncodeKE(group, dh.PublicBytes())}
	}
	// an X25519 public value of zeros is a low order point no exchange completes with
	failing := RawPayload{Type: PayloadKE, Body: EncodeKE(DH_CURVE25519, make([]byte, 32))}
	// each offer names p256 and x25519
	// and the default kex list puts x25519 first
	rekeyChild := func(ke RawPayload) []RawPayload {
		return []RawPayload{
			{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_REKEY_SA, Protocol: ProtoESP, SPI: binary.BigEndian.AppendUint32(nil, old.RemoteSPI)})},
			{Type: PayloadSA, Body: EncodeSA([]Proposal{{Number: 1, Protocol: ProtoESP, SPI: binary.BigEndian.AppendUint32(nil, 32), Transforms: []Transform{encrAES128, esnNone, dhP256, dhX25519}}})},
			{Type: PayloadNonce, Body: EncodeNonce(bytes.Repeat([]byte{4}, 32))},
			ke,
			{Type: PayloadTSi, Body: fullRangeSelectors()},
			{Type: PayloadTSr, Body: fullRangeSelectors()},
		}
	}
	rekeyIKE := func(ke RawPayload) []RawPayload {
		return []RawPayload{
			{Type: PayloadSA, Body: EncodeSA([]Proposal{{Number: 1, Protocol: ProtoIKE, SPI: binary.BigEndian.AppendUint64(nil, 0x2122232425262728), Transforms: []Transform{encrAES128, prfSHA256, dhP256, dhX25519}}})},
			{Type: PayloadNonce, Body: EncodeNonce(bytes.Repeat([]byte{4}, 32))},
			ke,
		}
	}
	for name, test := range map[string]struct {
		ike     bool
		request func(ke RawPayload) []RawPayload
	}{
		"a Child SA rekey": {false, rekeyChild},
		"an IKE SA rekey":  {true, rekeyIKE},
	} {
		// answer has a fresh session answer requests in turn and returns the answers' payloads
		answer := func(t *testing.T, requests ...[]RawPayload) [][]RawPayload {
			mux, _ := lifecycleMuxes(t)
			ctx := &ikeContext{suite: suite, spiI: 11, spiR: 12, skD: bytes.Repeat([]byte{1}, 32),
				skei: bytes.Repeat([]byte{2}, 20), sker: bytes.Repeat([]byte{3}, 20), responder: true}
			s := &Session{mux: mux, current: ctx, Child: old, rechecks: make(chan struct{}, 1)}
			s.SetChildHandler(func(ChildSA) error { return nil })
			handle := s.handleChildRekey
			if test.ike {
				handle = s.handleIKERekey
			}
			answers := make([][]RawPayload, 0, len(requests))
			for i, request := range requests {
				raw, err := handle(ctx, uint32(i), request)
				// an INVALID_SYNTAX answer returns why, which ends the IKE SA once dispatch has sent it
				if _, refused := errors.AsType[invalidSyntaxSent](err); err != nil && !refused {
					t.Fatal(err)
				}
				answers = append(answers, sealedAnswer(t, ctx, raw.whole))
			}
			return answers
		}
		t.Run(name+" retried after INVALID_KE_PAYLOAD", func(t *testing.T) {
			answers := answer(t, test.request(ke(DH_ECP_256)), test.request(ke(DH_CURVE25519)))
			payload := findType(answers[0], PayloadN)
			if payload == nil {
				t.Fatalf("a KE in p256 was answered %v, want INVALID_KE_PAYLOAD", answers[0])
			}
			notify, err := DecodeNotify(payload.Body)
			if err != nil {
				t.Fatal(err)
			}
			wantInvalidKE(t, notify, DH_CURVE25519)
			if findType(answers[1], PayloadSA) == nil {
				t.Errorf("the retry in the group asked for was answered notify %d, want the SA", notifyIn(t, answers[1]))
			}
		})
		t.Run(name+" after one whose key exchange failed", func(t *testing.T) {
			answers := answer(t, test.request(failing), test.request(ke(DH_CURVE25519)))
			if got := notifyIn(t, answers[0]); got != N_INVALID_SYNTAX {
				t.Errorf("a KE no exchange completes with was answered notify %d, want INVALID_SYNTAX", got)
			}
			if got := notifyIn(t, answers[1]); got != N_TEMPORARY_FAILURE {
				t.Errorf("a rekey at once after one this end ran a key exchange for was answered notify %d, want TEMPORARY_FAILURE", got)
			}
		})
	}
}

// a peer's Child SA rekey offering NONE beside a group ike kex left out, with its KE in that group
// is answered in NONE without a KE payload
// RFC 7296 section 3.3.6: "If one of the proposals offered is for the Diffie-Hellman group of NONE, and the responder selects that Diffie-Hellman group, then it MUST ignore the initiator's KE payload and omit the KE payload from the response."
func TestPeerChildRekeyOfferingNONEIsAnsweredWithoutAKE(t *testing.T) {
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	ctx := &ikeContext{suite: suite, spiI: 11, spiR: 12, skD: bytes.Repeat([]byte{1}, 32),
		skei: bytes.Repeat([]byte{2}, 20), sker: bytes.Repeat([]byte{3}, 20), responder: true}
	old := ChildSA{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, LocalSPI: 21, RemoteSPI: 22}
	lists := suitesOf(t, Crypto{IKE: IKESuites{Kex: []string{"p256"}}})
	mux, _ := lifecycleMuxes(t)
	s := &Session{mux: mux, current: ctx, Child: old, suites: func() Suites { return lists }, rechecks: make(chan struct{}, 1)}
	s.SetChildHandler(func(ChildSA) error { return nil })
	dh, err := GenerateDH(DH_CURVE25519)
	if err != nil {
		t.Fatal(err)
	}
	offer := espProposal(binary.BigEndian.AppendUint32(nil, 32))
	offer.Transforms = append(offer.Transforms, Transform{Type: TransDH, ID: DH_CURVE25519}, Transform{Type: TransDH})
	raw, err := s.handleChildRekey(ctx, 0, []RawPayload{
		{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_REKEY_SA, Protocol: ProtoESP, SPI: binary.BigEndian.AppendUint32(nil, old.RemoteSPI)})},
		{Type: PayloadSA, Body: EncodeSA([]Proposal{offer})},
		{Type: PayloadNonce, Body: bytes.Repeat([]byte{4}, 32)},
		{Type: PayloadKE, Body: EncodeKE(DH_CURVE25519, dh.PublicBytes())},
		{Type: PayloadTSi, Body: fullRangeSelectors()},
		{Type: PayloadTSr, Body: fullRangeSelectors()},
	})
	if err != nil {
		t.Fatal(err)
	}
	answer := sealedAnswer(t, ctx, raw.whole)
	sa := findType(answer, PayloadSA)
	if sa == nil {
		t.Fatalf("the rekey was answered %v, want a Child SA", answer)
	}
	proposals, err := DecodeSA(sa.Body)
	if err != nil || len(proposals) != 1 || !slices.Contains(proposals[0].Transforms, Transform{Type: TransDH}) {
		t.Errorf("the answer holds %+v, %v, want the group NONE", proposals, err)
	}
	if findType(answer, PayloadKE) != nil {
		t.Error("an answer in the group NONE carried a KE payload")
	}
}

// an IKE_AUTH Child SA proposal whose Diffie-Hellman type offers only groups is unacceptable
// so a later proposal is taken, one offering NONE beside a group takes NONE
// and an offer of nothing else is refused with this end's AUTH and NO_PROPOSAL_CHOSEN
// RFC 7296 section 1.2: "Thus, the SA payloads in the IKE_AUTH exchange cannot contain Transform Type 4 (Diffie-Hellman group) with any value other than NONE."
// RFC 7296 section 3.3.6: "Responders MUST select a single complete set of parameters from the offers (or reject all offers if none are acceptable)."
func TestIKEAuthChildProposalNamingOnlyGroupsIsUnacceptable(t *testing.T) {
	grouped := espProposal([]byte{0, 0, 0, 9})
	grouped.Transforms = append(grouped.Transforms, dhX25519, dhP256)
	withNone := espProposal([]byte{0, 0, 0, 9})
	withNone.Transforms = append(withNone.Transforms, dhX25519, Transform{Type: TransDH})
	plain := espProposal([]byte{0, 0, 0, 9})
	h := newResponderHarness(t, nil)
	for name, test := range map[string]struct {
		offer []Proposal
		// taken is the number of the proposal the answer takes, zero where it refuses them all
		taken uint8
		dh    Transform
	}{
		"a proposal naming only groups":                        {[]Proposal{grouped}, 0, Transform{}},
		"a proposal naming only groups before another":         {[]Proposal{grouped, plain}, 2, Transform{}},
		"a proposal naming NONE beside a group":                {[]Proposal{withNone}, 1, Transform{Type: TransDH}},
		"a proposal naming only groups before one naming NONE": {[]Proposal{grouped, withNone}, 2, Transform{Type: TransDH}},
	} {
		t.Run(name, func(t *testing.T) {
			offer := slices.Clone(test.offer)
			for i := range offer {
				offer[i].Number = uint8(i + 1)
			}
			inner, err := answerIKEAuth(t, h, Suites{}, offer...)
			if findType(inner, PayloadAUTH) == nil {
				t.Fatalf("the answer carried %v, %v, want this end's AUTH", inner, err)
			}
			if (err == nil) != (test.taken != 0) {
				t.Errorf("the responder's IKE_AUTH ended with %v", err)
			}
			if got := takenProposal(t, inner); got != test.taken {
				t.Fatalf("the answer took proposal %d, want %d", got, test.taken)
			}
			if test.taken == 0 {
				return
			}
			proposals, err := DecodeSA(findType(inner, PayloadSA).Body)
			if err != nil {
				t.Fatal(err)
			}
			var dh Transform
			for _, transform := range proposals[0].Transforms {
				if transform.Type == TransDH {
					dh = transform
				}
			}
			if dh != test.dh {
				t.Errorf("the answer took %+v, want %+v", dh, test.dh)
			}
		})
	}
}

// a Child SA proposal naming SPI zero is refused at IKE_AUTH and at CREATE_CHILD_SA
// and a proposal after it in the same offer is taken
// RFC 3948 section 1: "An IKE implementation supporting this protocol specification MUST NOT use the ESP SPI field zero for ESP packets."
func TestChildSAProposalNamingSPIZeroIsRefused(t *testing.T) {
	zero, valid := espProposal([]byte{0, 0, 0, 0}), espProposal([]byte{0, 0, 0, 9})
	valid.Number = 2
	old := ChildSA{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, LocalSPI: 21, RemoteSPI: 22}
	h := newResponderHarness(t, nil)
	for name, test := range map[string]struct {
		offer []Proposal
		// taken is the number of the proposal the answer takes
		// zero where it refuses them all
		taken uint8
	}{
		"a proposal naming SPI zero alone":          {[]Proposal{zero}, 0},
		"a proposal naming SPI zero before another": {[]Proposal{zero, valid}, valid.Number},
	} {
		t.Run(name+" at IKE_AUTH", func(t *testing.T) {
			inner, err := answerIKEAuth(t, h, Suites{}, test.offer...)
			if (err == nil) != (test.taken != 0) {
				t.Errorf("the responder's IKE_AUTH ended with %v", err)
			}
			if got := takenProposal(t, inner); got != test.taken {
				t.Errorf("the answer took proposal %d, want %d", got, test.taken)
			}
		})
		t.Run(name+" at CREATE_CHILD_SA", func(t *testing.T) {
			mux, _ := lifecycleMuxes(t)
			ctx := &ikeContext{suite: SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}, spiI: 11, spiR: 12,
				skD: bytes.Repeat([]byte{1}, 32), skei: bytes.Repeat([]byte{2}, 20), sker: bytes.Repeat([]byte{3}, 20), responder: true}
			s := &Session{mux: mux, current: ctx, Child: old, rechecks: make(chan struct{}, 1)}
			s.SetChildHandler(func(ChildSA) error { return nil })
			raw, err := s.handleChildRekey(ctx, 0, []RawPayload{
				{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_REKEY_SA, Protocol: ProtoESP, SPI: binary.BigEndian.AppendUint32(nil, old.RemoteSPI)})},
				{Type: PayloadSA, Body: EncodeSA(test.offer)},
				{Type: PayloadNonce, Body: bytes.Repeat([]byte{4}, 32)},
				{Type: PayloadTSi, Body: fullRangeSelectors()},
				{Type: PayloadTSr, Body: fullRangeSelectors()},
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := takenProposal(t, sealedAnswer(t, ctx, raw.whole)); got != test.taken {
				t.Errorf("the answer took proposal %d, want %d", got, test.taken)
			}
			child := s.currentChild()
			switch {
			case test.taken == 0 && child.LocalSPI != old.LocalSPI:
				t.Errorf("a refused rekey replaced the Child SA with %+v", child)
			case test.taken != 0 && child.RemoteSPI != binary.BigEndian.Uint32(valid.SPI):
				t.Errorf("the rekey left the Child SA sending under SPI %d, want the SPI of the proposal it took", child.RemoteSPI)
			}
		})
	}
}

// a Child SA proposal carrying a Transform Type this end does not understand is unacceptable
// so is one carrying a PRF, a type of an IKE SA's proposal alone, and one without ESN, a type every ESP proposal carries
// and a proposal after any of them in the same offer is taken
// RFC 7296 section 3.3.6: "If the responder receives a proposal that contains a Transform Type it does not understand, or a proposal that is missing a mandatory Transform Type, it MUST consider this proposal unacceptable" and "other proposals in the same SA payload are processed as usual."
func TestChildSAProposalOfAnUnknownTypeOrWithoutESNIsUnacceptable(t *testing.T) {
	unknown := espProposal([]byte{0, 0, 0, 8})
	unknown.Transforms = append(unknown.Transforms, Transform{Type: TransformType(15), ID: 1})
	withPRF := espProposal([]byte{0, 0, 0, 8})
	withPRF.Transforms = append(withPRF.Transforms, prfSHA256)
	withoutESN := espProposal([]byte{0, 0, 0, 8})
	withoutESN.Transforms = slices.DeleteFunc(withoutESN.Transforms, func(t Transform) bool { return t.Type == TransESN })
	valid := espProposal([]byte{0, 0, 0, 9})
	valid.Number = 2
	for name, unusable := range map[string]Proposal{"a type it does not understand": unknown, "a PRF": withPRF, "no ESN": withoutESN} {
		if _, err := selectChildRequestProposal(EncodeSA([]Proposal{unusable}), Suites{}.espCiphers(), Suites{}.kexEntries(), 0); err == nil {
			t.Errorf("a proposal with %s was taken", name)
		}
		selection, err := selectChildRequestProposal(EncodeSA([]Proposal{unusable, valid}), Suites{}.espCiphers(), Suites{}.kexEntries(), 0)
		if err != nil || selection.proposal.Number != valid.Number {
			t.Errorf("an offer of a proposal with %s and another was answered with proposal %d, %v, want the other", name, selection.proposal.Number, err)
		}
	}
}

// a Child SA proposal whose only ESN carries an attribute this end does not understand or a key length is unacceptable, as is one whose only integrity transform is a NONE carrying such an attribute
// and a proposal after it in the same offer is taken
// RFC 7296 section 3.3.6: "if the responder receives a transform that it does not understand, or one that contains a Transform Attribute it does not understand, it MUST consider this transform unacceptable"
func TestChildSAProposalWhoseESNOrIntegrityNONECarriesAnAttributeIsUnacceptable(t *testing.T) {
	valid := espProposal([]byte{0, 0, 0, 9})
	valid.Number = 2
	for name, test := range map[string]struct {
		first Transform
		// attributed is whether first carries an attribute this end does not understand
		attributed bool
	}{
		"an ESN carrying an attribute this end does not understand":        {first: esnNone, attributed: true},
		"an ESN carrying a key length":                                     {first: Transform{Type: TransESN, ID: ESN_NO, KeyLengthBits: 128}},
		"an INTEG NONE carrying an attribute this end does not understand": {first: Transform{Type: TransInteg, ID: INTEG_NONE}, attributed: true},
	} {
		t.Run(name, func(t *testing.T) {
			unusable := espProposal([]byte{0, 0, 0, 8})
			unusable.Transforms = append([]Transform{test.first}, slices.DeleteFunc(unusable.Transforms, func(t Transform) bool { return t.Type == test.first.Type })...)
			for _, offer := range [][]Proposal{{unusable}, {unusable, valid}} {
				body := EncodeSA(offer)
				if test.attributed {
					body = addUnknownTVAttributeToFirstTransform(body)
				}
				selection, err := selectChildRequestProposal(body, Suites{}.espCiphers(), Suites{}.kexEntries(), 0)
				switch {
				case len(offer) == 1 && err == nil:
					t.Errorf("a proposal with %s was taken", name)
				case len(offer) == 2 && (err != nil || selection.proposal.Number != valid.Number):
					t.Errorf("an offer of a proposal with %s and another was answered with proposal %d, %v, want the other", name, selection.proposal.Number, err)
				}
			}
		})
	}
}

// takenProposal is the number of the proposal an answer's SA payload takes
// zero for an answer refusing every proposal with NO_PROPOSAL_CHOSEN
func takenProposal(t testing.TB, answer []RawPayload) uint8 {
	t.Helper()
	sa := findType(answer, PayloadSA)
	if sa == nil {
		if got := notifyIn(t, answer); got != N_NO_PROPOSAL_CHOSEN {
			t.Errorf("the answer carried no SA payload and notify %d, want NO_PROPOSAL_CHOSEN", got)
		}
		return 0
	}
	proposals, err := DecodeSA(sa.Body)
	if err != nil || len(proposals) != 1 {
		t.Fatalf("the answer's SA payload holds %+v, %v, want one proposal", proposals, err)
	}
	return proposals[0].Number
}

// answerIKEAuth has a session of h's responder, reading lists, answer an IKE_AUTH from testorg/client:2 whose SA payload holds children
// it returns the answer's payloads and the error the responder's IKE_AUTH ended with
func answerIKEAuth(t testing.TB, h *responderHarness, lists Suites, children ...Proposal) ([]RawPayload, error) {
	t.Helper()
	// the session's SPI routes the request to this mux ahead of the harness's Serve
	mux, err := h.responder.cfg.Hub.NewMux(net.IPv4(127, 0, 0, 1), h.initiator.LocalAddr().(*net.UDPAddr).Port)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	peer, err := h.initiator.NewMux(net.IPv4(127, 0, 0, 1), h.remotePort)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()

	spiI, spiR := randUint64Nonzero(), randUint64Nonzero()
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	ctx := &ikeContext{suite: suite, spiI: spiI, spiR: spiR, responder: true,
		skD: bytes.Repeat([]byte{1}, 32), skei: bytes.Repeat([]byte{2}, 20), sker: bytes.Repeat([]byte{3}, 20),
		skpi: bytes.Repeat([]byte{4}, 32), skpr: bytes.Repeat([]byte{5}, 32)}
	s := &Session{mux: mux, current: ctx, suites: func() Suites { return lists }}
	if err := mux.RegisterIKE(spiI); err != nil {
		t.Fatal(err)
	}
	if err := peer.RegisterIKE(spiI); err != nil {
		t.Fatal(err)
	}

	// two stand-ins for the IKE_SA_INIT messages the AUTH payloads sign
	message1, message2 := []byte("the IKE_SA_INIT request"), []byte("the IKE_SA_INIT response")
	ni, nr := bytes.Repeat([]byte{6}, 32), bytes.Repeat([]byte{7}, 32)
	idi := idBody("testorg/client:2")
	header := Header{SPIInitiator: spiI, SPIResponder: spiR, ExchangeType: IKE_AUTH, Flags: FlagInitiator, MessageID: 1}
	request, err := EncryptMessage(suite, ctx.skei, header, nil, []RawPayload{
		{Type: PayloadIDi, Body: idi},
		{Type: PayloadAUTH, Body: BuildAuth(h.private, concat(message1, nr, prf(suite.PRFID, ctx.skpi, idi)))},
		{Type: PayloadSA, Body: EncodeSA(children)},
		{Type: PayloadTSi, Body: fullRangeSelectors()},
		{Type: PayloadTSr, Body: fullRangeSelectors()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := peer.SendIKE(request); err != nil {
		t.Fatal(err)
	}
	_, created, authErr := s.completeResponderAuth(h.responder, message1, message2, ni, nr, time.Now().Add(answerBudget))
	if !created {
		t.Errorf("an IKE_AUTH that authenticates left the IKE SA uncreated, with %v", authErr)
	}
	raw, err := peer.RecvIKEUntil(time.Now().Add(answerBudget))
	if err != nil {
		t.Fatalf("no IKE_AUTH answer: %v", err)
	}
	message, err := DecodeMessage(raw)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := DecryptMessage(suite, ctx.sker, raw, message)
	if err != nil {
		t.Fatal(err)
	}
	return inner, authErr
}

// an IKE_AUTH whose Child SA offer is refused ends with the error that kept its answer from going, where the answer cannot be sealed or, for a request in fragments, cannot be cut
// the IV space of the responder's key runs out at the answer's seal or at its first fragment
func TestRefusedIKEAuthWhoseAnswerCannotGoEndsWithTheAnswersError(t *testing.T) {
	h := newResponderHarness(t, nil)
	for name, test := range map[string]struct {
		// used is the IVs the responder's key used before the answer
		used uint64
		// cut is the octets of plaintext in each fragment of the request, zero for the request whole
		cut int
	}{
		"an answer that cannot be sealed": {math.MaxUint64, 0},
		"an answer that cannot be cut":    {math.MaxUint64 - 1, 100},
	} {
		t.Run(name, func(t *testing.T) {
			mux, err := h.responder.cfg.Hub.NewMux(net.IPv4(127, 0, 0, 1), h.initiator.LocalAddr().(*net.UDPAddr).Port)
			if err != nil {
				t.Fatal(err)
			}
			defer mux.Close()
			peer, err := h.initiator.NewMux(net.IPv4(127, 0, 0, 1), h.remotePort)
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			spiI, spiR := randUint64Nonzero(), randUint64Nonzero()
			suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
			ctx := &ikeContext{suite: suite, spiI: spiI, spiR: spiR, responder: true,
				skD: bytes.Repeat([]byte{1}, 32), skei: bytes.Repeat([]byte{2}, 20), sker: bytes.Repeat([]byte{3}, 20),
				skpi: bytes.Repeat([]byte{4}, 32), skpr: bytes.Repeat([]byte{5}, 32)}
			ctx.sendIV.Store(test.used)
			s := &Session{mux: mux, current: ctx, suites: func() Suites { return Suites{} }, fragments: test.cut > 0, pathMTU: noPathMTU}
			if err := mux.RegisterIKE(spiI); err != nil {
				t.Fatal(err)
			}
			message1, message2 := []byte("the IKE_SA_INIT request"), []byte("the IKE_SA_INIT response")
			ni, nr := bytes.Repeat([]byte{6}, 32), bytes.Repeat([]byte{7}, 32)
			idi := idBody("testorg/client:2")
			header := Header{SPIInitiator: spiI, SPIResponder: spiR, ExchangeType: IKE_AUTH, Flags: FlagInitiator, MessageID: 1}
			inner := []RawPayload{
				{Type: PayloadIDi, Body: idi},
				{Type: PayloadAUTH, Body: BuildAuth(h.private, concat(message1, nr, prf(suite.PRFID, ctx.skpi, idi)))},
				{Type: PayloadSA, Body: EncodeSA([]Proposal{espProposal([]byte{0, 0, 0, 0})})},
				{Type: PayloadTSi, Body: fullRangeSelectors()},
				{Type: PayloadTSr, Body: fullRangeSelectors()},
			}
			var request [][]byte
			if test.cut > 0 {
				request = cutInto(t, suite, ctx.skei, header, inner, test.cut)
			} else {
				raw, err := EncryptMessage(suite, ctx.skei, header, nil, inner)
				if err != nil {
					t.Fatal(err)
				}
				request = [][]byte{raw}
			}
			for _, datagram := range request {
				if err := peer.SendIKE(datagram); err != nil {
					t.Fatal(err)
				}
			}
			_, created, err := s.completeResponderAuth(h.responder, message1, message2, ni, nr, time.Now().Add(answerBudget))
			if created || err == nil || !strings.Contains(err.Error(), "IV space exhausted") {
				t.Errorf("an IKE_AUTH in %d datagrams whose refusal could not go ended with %v and created %v, want the IV space's error and no IKE SA", len(request), err, created)
			}
		})
	}
}
