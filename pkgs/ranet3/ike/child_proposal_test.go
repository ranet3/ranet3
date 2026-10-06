// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

package ike

import (
	"bytes"
	"encoding/binary"
	"errors"
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
	want := ChildSA{EncrID: ENCR_CHACHA20_POLY1305, EncrKeyBits: 256}
	_, got, _, err := decodeChildProposal(encodedChildProposal(Transform{Type: TransEncr, ID: ENCR_CHACHA20_POLY1305}), &want)
	if err != nil {
		t.Fatal(err)
	}
	if got.KeyLengthBits != 256 {
		t.Fatalf("key length normalized to %d, want 256", got.KeyLengthBits)
	}
	if _, _, _, err := decodeChildProposal(encodedChildProposal(Transform{Type: TransEncr, ID: ENCR_CHACHA20_POLY1305, KeyLengthBits: 256}), &want); err == nil {
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
		if _, _, _, err := decodeChildProposal(EncodeSA([]Proposal{proposal}), nil); err == nil {
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
	selection, err := selectChildRequestProposal(raw, &want, 0)
	if err != nil {
		t.Fatal(err)
	}
	selected := selection.encryption
	if selected.UnsupportedAttributes || selected.ID != want.EncrID || selected.KeyLengthBits != want.EncrKeyBits {
		t.Fatalf("selected transform = %#v", selected)
	}
}

func TestDecodeChildExchangePayloadsRejectsDuplicatesAndCriticalUnknowns(t *testing.T) {
	base := []RawPayload{
		{Type: PayloadSA, Body: encodedChildProposal(Transform{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128})},
		{Type: PayloadNonce, Body: []byte{1}},
		{Type: PayloadTSi, Body: []byte{0, 0, 0, 0}},
		{Type: PayloadTSr, Body: []byte{0, 0, 0, 0}},
	}
	for _, extra := range []RawPayload{
		{Type: PayloadNonce, Body: []byte{2}},
		{Type: PayloadType(250), Critical: true},
	} {
		payloads := append(append([]RawPayload(nil), base...), extra)
		if _, err := decodeChildExchangePayloads(payloads, PRF_HMAC_SHA2_256); err == nil {
			t.Fatalf("accepted invalid extra payload %+v", extra)
		}
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
}

// A peer that spells out INTEG NONE alongside an AEAD cipher does it on every
// proposal it sends, not only the IKE_SA_INIT one. Taking it there and
// refusing it on the Child SA bundled into IKE_AUTH kills the handshake one
// message after the exchange that was just made to work, and refusing it on an
// IKE rekey leaves such a peer established and unable to rekey from its own
// side. RFC 7296 section 2.7 then requires the answer to carry it back.
func TestIntegNoneIsTakenAndEchoedOnEveryProposal(t *testing.T) {
	integ := Transform{Type: TransInteg, ID: INTEG_NONE}
	esp := func(extra ...Transform) []byte {
		spi := []byte{0, 0, 0, 9}
		return EncodeSA([]Proposal{{Number: 1, Protocol: ProtoESP, SPI: spi, Transforms: append([]Transform{
			{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 256},
			{Type: TransESN, ID: ESN_NO},
		}, extra...)}})
	}
	selection, err := selectChildRequestProposal(esp(integ), nil, 0)
	if err != nil {
		t.Fatalf("a Child SA proposal naming INTEG NONE was refused: %v", err)
	}
	if selection.integ != integ {
		t.Errorf("the selection kept %+v, so the answer cannot carry it back", selection.integ)
	}
	// The other direction is not the same rule. decodeChildProposal reads the
	// answer to this end's own offer, which names no integrity transform, and
	// section 2.7 makes the answer a subset of the offer. See its own doc.
	if _, _, _, err := decodeChildProposal(esp(integ), nil); err == nil {
		t.Error("an answer to this end's offer named a transform type the offer did not")
	}

	// And an integrity transform there is no key for is still refused, because
	// every cipher this implementation offers is combined mode.
	unusable := Transform{Type: TransInteg, ID: 12}
	if _, err := selectChildRequestProposal(esp(unusable), nil, 0); err == nil {
		t.Error("a Child SA proposal naming a real integrity algorithm was accepted")
	}
	if _, _, _, err := decodeChildProposal(esp(unusable), nil); err == nil {
		t.Error("decoding a Child SA proposal naming a real integrity algorithm succeeded")
	}
}

// The Child SA selector draws the same line as the IKE one: RFC 7296 §3.3.6
// makes an integrity algorithm this end has no key for one unacceptable
// transform, and "other transforms with the same Transform Type are processed
// as usual", so an offer naming one alongside NONE still has an answer.
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
	selection, err := selectChildRequestProposal(body, nil, 0)
	if err != nil {
		t.Fatalf("an offer naming an integrity algorithm alongside NONE was refused: %v", err)
	}
	if selection.integ != none {
		t.Errorf("the answer carries integrity transform %v, want the NONE the offer included", selection.integ)
	}

	onlyUnusable := EncodeSA([]Proposal{{Number: 1, Protocol: ProtoESP, SPI: spi,
		Transforms: append(slices.Clone(base), unusable)}})
	if _, err := selectChildRequestProposal(onlyUnusable, nil, 0); err == nil {
		t.Error("an offer whose every integrity alternative is unusable was accepted")
	}
	pair := EncodeSA([]Proposal{
		{Number: 1, Protocol: ProtoESP, SPI: spi, Transforms: append(slices.Clone(base), unusable)},
		{Number: 2, Protocol: ProtoESP, SPI: spi, Transforms: slices.Clone(base)},
	})
	if selection, err := selectChildRequestProposal(pair, nil, 0); err != nil || selection.proposal.Number != 2 {
		t.Errorf("the second proposal was not considered: %v, %v", selection.proposal.Number, err)
	}
}

// decodeChildProposal is the initiator reading the answer to its own offer,
// which is espProposal. RFC 7296 section 3.3.6 has it "check that the accepted
// offer is consistent with one of its proposals, and if not MUST terminate the
// exchange", and section 2.7 says consistent is "exactly one transform of each
// type included in the proposal". So a conforming answer carries the types
// espProposal carries, and an unoffered DH transform is the dangerous case:
// the responder would mean perfect forward secrecy, this end derives without
// it, and the Child SA it installs carries nothing.
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
	for name, extra := range map[string][]Transform{
		"the shape the offer asks for": nil,
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := decodeChildProposal(answer(extra...), nil); err != nil {
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
		"an unknown type":          {{Type: TransformType(9), ID: 1}},
		"an integ algorithm":       {{Type: TransInteg, ID: 12}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := decodeChildProposal(answer(extra...), nil); err == nil {
				t.Error("an answer naming what the offer did not was accepted")
			}
		})
	}
}

// One of each type the offer included rules out an answer that leaves a type
// out as much as one that adds a type, and RFC 7296 section 3.3.3 makes both
// of the types espProposal names mandatory for ESP.
func TestChildAnswerMissingAnOfferedTypeIsRefused(t *testing.T) {
	spi := []byte{0, 0, 0, 9}
	for name, transforms := range map[string][]Transform{
		"no esn":    {{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 256}},
		"no cipher": {{Type: TransESN, ID: ESN_NO}},
	} {
		t.Run(name, func(t *testing.T) {
			answer := EncodeSA([]Proposal{{Number: 1, Protocol: ProtoESP, SPI: spi, Transforms: transforms}})
			_, _, _, err := decodeChildProposal(answer, nil)
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

// The responder answering somebody else's offer is the other direction, and it
// does echo a type it was offered: a peer that names DH or INTEG gets it back,
// RFC 7296 section 2.7. selectChildRequestProposal builds that, and it is not
// what decodeChildProposal above reads.
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
			selection, err := selectChildRequestProposal(offer, nil, keGroup)
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

// decodeChildProposal holds a rekey answer to the cipher the SA being replaced
// already uses, so the rekey offer has to ask for that one alone. Offering all
// three asks a question this end refuses the answer to: RFC 7296 section 2.7
// lets the responder take any transform in the proposal, and a peer whose
// preference order changed between the initial exchange and the rekey answers
// within the offer and is turned down.
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
		// Every answer a responder may build from that offer is one this end
		// reads, which is the property the two halves have to agree on.
		selection, err := selectChildRequestProposal(EncodeSA([]Proposal{offer}), nil, 0)
		if err != nil {
			t.Fatalf("the rekey offer was refused: %v", err)
		}
		child := responderChild{number: selection.proposal.Number,
			encryption: selection.encryption, dh: selection.dh, integ: selection.integ}
		if _, _, _, err := decodeChildProposal(EncodeSA([]Proposal{child.proposal(spi)}), &old); err != nil {
			t.Errorf("an answer built from the rekey offer was refused: %v", err)
		}
	}
	// The initial offer still names all three, because there is no old SA to
	// hold the answer to.
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

// The other half of the test above: a rekey answer naming a cipher other than
// the one the SA being replaced uses is refused, though the initial offer
// names it and an answer to that offer would be taken.
func TestRekeyAnswerWithAnotherCipherIsRefused(t *testing.T) {
	old := ChildSA{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128}
	for name, encryption := range map[string]Transform{
		"a longer key":   {Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 256},
		"another cipher": {Type: TransEncr, ID: ENCR_CHACHA20_POLY1305},
	} {
		t.Run(name, func(t *testing.T) {
			answer := encodedChildProposal(encryption)
			if _, _, _, err := decodeChildProposal(answer, nil); err != nil {
				t.Fatalf("the answer was refused with no SA to hold it to: %v", err)
			}
			_, _, _, err := decodeChildProposal(answer, &old)
			if err == nil || !strings.Contains(err.Error(), "changed encryption transform") {
				t.Errorf("a rekey answer of %v for an SA keyed with %v got %v, want it refused", encryption, old, err)
			}
		})
	}
}

// RFC 7296 section 1.3 gives INVALID_KE_PAYLOAD "two octets of data
// associated with this notification: the accepted Diffie-Hellman group number
// in big endian order", and has the initiator retry in the group the responder
// gave. A notify without them tells a peer its group is wrong and not which
// one to use, so its retry is a guess. Every site that sends one has to carry
// them.
func TestEveryInvalidKENotifyNamesAGroup(t *testing.T) {
	// A Child SA offer whose DH group this end does not have, which draws
	// the notify from the selector all three sites read.
	spi := []byte{0, 0, 0, 3}
	offer := EncodeSA([]Proposal{{Number: 1, Protocol: ProtoESP, SPI: spi, Transforms: []Transform{
		{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 256},
		{Type: TransESN, ID: ESN_NO},
		{Type: TransDH, ID: DH_CURVE25519},
	}}})
	_, err := selectChildRequestProposal(offer, nil, 0)
	var wrongGroup *invalidKEError
	if !errors.As(err, &wrongGroup) {
		t.Fatalf("an offer naming a group this end did not use reported %v", err)
	}
	if wrongGroup.group != DH_CURVE25519 {
		t.Errorf("the error names group %d, want the one the offer asked for", wrongGroup.group)
	}
	// And the data every site puts in the notify names it. All three build it
	// here, so this is the property rather than a sample of one site.
	notify, err := DecodeNotify(EncodeNotify(Notify{Type: N_INVALID_KE_PAYLOAD,
		Data: invalidKENotifyData(wrongGroup.group)}))
	if err != nil {
		t.Fatal(err)
	}
	if len(notify.Data) != 2 || binary.BigEndian.Uint16(notify.Data) != DH_CURVE25519 {
		t.Errorf("the notify carries %v, which no initiator can retry from", notify.Data)
	}
	// The initiator reads it back as the group to come back with.
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
	message, err := DecodeMessage(raw)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := DecryptMessage(suite, ctx.localEncryptionKey(), raw, message)
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

// an IKE_AUTH whose Child SA offer names a group
// is answered with this end's AUTH and the offered group it would take
func TestIKEAuthChildOfferNamingAGroupIsAnsweredWithTheGroup(t *testing.T) {
	h := newResponderHarness(t, nil)
	// the session's SPI routes the request to this mux ahead of the harness's Serve
	mux, err := h.responder.cfg.Hub.NewMux(net.IPv4(127, 0, 0, 1), h.initiator.LocalAddr().(*net.UDPAddr).Port)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mux.Close() })
	peer, err := h.initiator.NewMux(net.IPv4(127, 0, 0, 1), h.remotePort)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { peer.Close() })

	const spiI, spiR = 0x2122232425262728, 0x3132333435363738
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	ctx := &ikeContext{suite: suite, spiI: spiI, spiR: spiR, responder: true,
		skD: bytes.Repeat([]byte{1}, 32), skei: bytes.Repeat([]byte{2}, 20), sker: bytes.Repeat([]byte{3}, 20),
		skpi: bytes.Repeat([]byte{4}, 32), skpr: bytes.Repeat([]byte{5}, 32)}
	s := &Session{mux: mux, current: ctx}
	if err := mux.RegisterIKE(spiI); err != nil {
		t.Fatal(err)
	}
	if err := peer.RegisterIKE(spiI); err != nil {
		t.Fatal(err)
	}

	// two stand-ins for the IKE_SA_INIT messages the AUTH payloads sign
	message1, message2 := []byte("the IKE_SA_INIT request"), []byte("the IKE_SA_INIT response")
	ni, nr := bytes.Repeat([]byte{6}, 32), bytes.Repeat([]byte{7}, 32)
	idi := Identity{Organization: "testorg", CommonName: "client", SerialNumber: "2"}.encodeID()
	child := espProposal([]byte{0, 0, 0, 9})
	child.Transforms = append(child.Transforms, Transform{Type: TransDH, ID: DH_ECP_256})
	header := Header{SPIInitiator: spiI, SPIResponder: spiR, ExchangeType: IKE_AUTH, Flags: FlagInitiator, MessageID: 1}
	request, err := EncryptMessage(suite, ctx.skei, header, nil, []RawPayload{
		{Type: PayloadIDi, Body: idi},
		{Type: PayloadAUTH, Body: BuildAuth(h.private, concat(message1, nr, prf(suite.PRFID, ctx.skpi, idi)))},
		{Type: PayloadSA, Body: EncodeSA([]Proposal{child})},
		{Type: PayloadTSi, Body: fullRangeSelectors()},
		{Type: PayloadTSr, Body: fullRangeSelectors()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := peer.SendIKE(request); err != nil {
		t.Fatal(err)
	}
	if _, err := s.completeResponderAuth(h.responder, message1, message2, ni, nr, time.Now().Add(answerBudget)); err == nil {
		t.Fatal("an IKE_AUTH Child SA offer naming a group was taken")
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
	if findType(inner, PayloadAUTH) == nil {
		t.Fatal("the answer carried no AUTH, which means the exchange ended before the Child SA")
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
}
