// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

package ike

import (
	"encoding/binary"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func addUnknownTVAttributeToFirstTransform(raw []byte) []byte {
	transformOffset := 8 + int(raw[6])
	transformLength := int(binary.BigEndian.Uint16(raw[transformOffset+2 : transformOffset+4]))
	insertAt := transformOffset + transformLength
	unknown := []byte{0x80, 0x0f, 0, 1}
	withAttribute := make([]byte, 0, len(raw)+len(unknown))
	withAttribute = append(withAttribute, raw[:insertAt]...)
	withAttribute = append(withAttribute, unknown...)
	withAttribute = append(withAttribute, raw[insertAt:]...)
	binary.BigEndian.PutUint16(withAttribute[2:4], uint16(len(withAttribute)))
	binary.BigEndian.PutUint16(withAttribute[transformOffset+2:transformOffset+4], uint16(transformLength+len(unknown)))
	return withAttribute
}

func TestSuiteFromProposalRequiresExactOfferSelection(t *testing.T) {
	valid := Proposal{Number: 1, Protocol: ProtoIKE, Transforms: []Transform{
		{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128},
		{Type: TransPRF, ID: PRF_HMAC_SHA2_256},
		{Type: TransDH, ID: DH_CURVE25519},
	}}
	offered := ikeProposal().Transforms
	if _, err := suiteFromProposal(valid, offered); err != nil {
		t.Fatal(err)
	}
	for _, extra := range []Transform{
		{Type: TransInteg, ID: 12},
		{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 192},
		{Type: TransformType(9), ID: 1},
	} {
		invalid := valid
		invalid.Transforms = append(append([]Transform(nil), valid.Transforms...), extra)
		if _, err := suiteFromProposal(invalid, offered); err == nil {
			t.Fatalf("accepted invalid selected transform %+v", extra)
		}
	}
	// RFC 7296 section 2.7: "The responder MUST choose a single suite, which may be any subset of the SA proposal following the rules below."
	// this end's offer names no integrity transform
	// so an answer naming one is inconsistent with it whatever its value
	echoed := valid
	echoed.Transforms = append(append([]Transform(nil), valid.Transforms...), Transform{Type: TransInteg, ID: INTEG_NONE})
	if _, err := suiteFromProposal(echoed, offered); err == nil {
		t.Error("an answer naming a transform type this end never offered was accepted")
	}
}

func TestDecodeSARejectsInconsistentNestedFraming(t *testing.T) {
	valid := EncodeSA([]Proposal{{Number: 1, Protocol: ProtoIKE, Transforms: []Transform{{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128}}}})
	for name, mutate := range map[string]func([]byte){
		"proposal marker":  func(raw []byte) { raw[0] = 1 },
		"transform marker": func(raw []byte) { raw[8] = 1 },
		"transform count":  func(raw []byte) { raw[7] = 2 },
		"trailing data":    func(raw []byte) { raw[0] = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			raw := append([]byte(nil), valid...)
			if name == "trailing data" {
				raw = append(raw, 0)
			} else {
				mutate(raw)
			}
			if _, err := DecodeSA(raw); err == nil {
				t.Fatal("DecodeSA accepted inconsistent framing")
			}
		})
	}
}

func TestUnknownTransformAttributeMakesOnlyTransformUnacceptable(t *testing.T) {
	proposal := Proposal{Number: 1, Protocol: ProtoIKE, Transforms: []Transform{
		{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 256},
		{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128},
		{Type: TransPRF, ID: PRF_HMAC_SHA2_256},
		{Type: TransDH, ID: DH_CURVE25519},
	}}
	withAttribute := addUnknownTVAttributeToFirstTransform(EncodeSA([]Proposal{proposal}))

	decoded, err := DecodeSA(withAttribute)
	if err != nil {
		t.Fatal(err)
	}
	if !decoded[0].Transforms[0].UnsupportedAttributes {
		t.Fatal("unknown attribute was silently discarded")
	}
	lists := Suites{}
	chosen, _, ok := chooseIKE(decoded, lists.ikeCiphers(), lists.rekeyPRFs(PRF_HMAC_SHA2_256), lists.kexGroups(), DH_CURVE25519)
	if !ok || chosen.suite.EncrKeyBits != 128 || chosen.transforms[0].KeyLengthBits != 128 {
		t.Fatalf("selection did not skip attributed transform: selected=%#v suite=%#v", chosen.transforms, chosen.suite)
	}

	selectedResponse := decoded[0]
	selectedResponse.Transforms = []Transform{decoded[0].Transforms[0], decoded[0].Transforms[2], decoded[0].Transforms[3]}
	if _, err := suiteFromProposal(selectedResponse, ikeProposal().Transforms); err == nil {
		t.Fatal("initiator accepted selected transform with unknown attribute")
	}
}

func TestIKERekeyProposalRejectsUnexpectedTransformType(t *testing.T) {
	base := []Transform{
		{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128},
		{Type: TransPRF, ID: PRF_HMAC_SHA2_256},
		{Type: TransDH, ID: DH_CURVE25519},
	}
	lists := Suites{}
	rekey := func(p Proposal) (ikeChoice, bool) {
		chosen, _, ok := chooseIKE([]Proposal{p}, lists.ikeCiphers(), lists.rekeyPRFs(PRF_HMAC_SHA2_256), lists.kexGroups(), DH_CURVE25519)
		return chosen, ok
	}
	unknown := Proposal{Number: 1, Protocol: ProtoIKE,
		Transforms: append(slices.Clone(base), Transform{Type: TransformType(9), ID: 1})}
	if _, ok := rekey(unknown); ok {
		t.Fatal("accepted IKE rekey proposal with unexpected transform type")
	}
	// every cipher this end lists is combined mode
	// so an integrity algorithm has no key here
	unusable := Proposal{Number: 1, Protocol: ProtoIKE,
		Transforms: append(slices.Clone(base), Transform{Type: TransInteg, ID: 12})}
	if _, ok := rekey(unusable); ok {
		t.Fatal("accepted an integrity transform there is no key for")
	}
	// selectIKEProposal takes INTEG NONE on the initial exchange
	// so refusing it here would leave such a peer unable to rekey from its own side
	// RFC 7296 section 2.7: "The accepted cryptographic suite MUST contain exactly one transform of each type included in the proposal."
	integ := Transform{Type: TransInteg, ID: INTEG_NONE}
	none := Proposal{Number: 1, Protocol: ProtoIKE, Transforms: append(slices.Clone(base), integ)}
	chosen, ok := rekey(none)
	if !ok {
		t.Fatal("a rekey proposal naming INTEG NONE was refused")
	}
	if !slices.Contains(chosen.transforms, integ) {
		t.Errorf("the answer is %v, which drops a transform type the offer included", chosen.transforms)
	}
}

// a proposal for another protocol than the exchange negotiates is unacceptable at each responder
// so the proposal after it is the one answered
// RFC 7296 section 2.7: "If a proposal is accepted, the SA response MUST contain the same protocol."
// RFC 7296 section 3.3.6: "If there are multiple proposals, the responder MUST choose a single proposal."
func TestProposalOfAnotherProtocolIsUnacceptable(t *testing.T) {
	ikeTransforms := []Transform{encrAES128, prfSHA256, dhX25519}
	t.Run("at IKE_SA_INIT", func(t *testing.T) {
		body := EncodeSA([]Proposal{
			{Number: 1, Protocol: ProtoESP, Transforms: ikeTransforms},
			{Number: 2, Protocol: ProtoIKE, Transforms: ikeTransforms},
		})
		selected, _, err := selectIKEProposal(body, DH_CURVE25519, Suites{})
		if err != nil || selected.Number != 2 {
			t.Errorf("an ESP proposal ahead of an IKE one was answered with proposal %d, %v, want 2", selected.Number, err)
		}
	})
	t.Run("at IKE_AUTH and CREATE_CHILD_SA", func(t *testing.T) {
		body := EncodeSA([]Proposal{
			{Number: 1, Protocol: ProtoAH, SPI: []byte{0, 0, 0, 9}, Transforms: []Transform{encrAES128, esnNone}},
			{Number: 2, Protocol: ProtoESP, SPI: []byte{0, 0, 0, 9}, Transforms: []Transform{encrAES128, esnNone}},
		})
		selection, err := selectChildRequestProposal(body, Suites{}.espCiphers(), Suites{}.kexGroups(), 0, groupOptional)
		if err != nil || selection.proposal.Number != 2 {
			t.Errorf("an AH proposal ahead of an ESP one was answered with proposal %d, %v, want 2", selection.proposal.Number, err)
		}
	})
	t.Run("at an IKE SA rekey", func(t *testing.T) {
		mux, _ := lifecycleMuxes(t)
		s := answeringSession(t, mux, SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256, DHGroup: DH_CURVE25519},
			ChildSA{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, LocalSPI: 21, RemoteSPI: 22}, 0, Suites{})
		proposals := []Proposal{{Transforms: ikeTransforms}, {Transforms: ikeTransforms}}
		request := peerRekeyOf(t, s, true, proposals, DH_CURVE25519)
		proposals[0].Protocol = ProtoESP
		request[0].Body = EncodeSA(proposals)
		answer := answerPeerRekey(t, s, true, request)
		if answer.proposal.Number != 2 || answer.proposal.Protocol != ProtoIKE {
			t.Errorf("an ESP proposal ahead of an IKE one was answered %+v, want proposal 2 of IKE", answer)
		}
	})
}

func TestSupportsIdentitySignatureHash(t *testing.T) {
	identity := make([]byte, 2)
	binary.BigEndian.PutUint16(identity, HashIdentity)
	payloads := []RawPayload{{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_SIGNATURE_HASH_ALGORITHMS, Data: identity})}}
	if ok, err := supportsSignatureHash(payloads, HashIdentity); err != nil || !ok {
		t.Fatalf("identity support = %v, %v", ok, err)
	}
	if ok, err := supportsSignatureHash(nil, HashIdentity); err != nil || ok {
		t.Fatalf("missing notification = %v, %v", ok, err)
	}
}

// The error tells the peer which group to come back with, so it has to name
// it.
func TestInvalidKEErrorNamesGroup(t *testing.T) {
	message := (&invalidKEError{group: DH_CURVE25519}).Error()
	if !strings.Contains(message, strconv.Itoa(int(DH_CURVE25519))) {
		t.Errorf("the error reads %q and does not name group %d", message, DH_CURVE25519)
	}
}

// RFC 7296 section 3.3.6: "if the responder receives a transform that it does not understand, or one that contains a Transform Attribute it does not understand, it MUST consider this transform unacceptable" and "other transforms with the same Transform Type are processed as usual."
// a peer with non-AEAD ciphers too offers its integrity algorithms alongside NONE in the one proposal
// and both ends can still run that proposal
func TestUnusableIntegrityAlternativeDoesNotRefuseTheProposal(t *testing.T) {
	base := []Transform{
		{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 256},
		{Type: TransPRF, ID: PRF_HMAC_SHA2_256},
		{Type: TransDH, ID: DH_CURVE25519},
	}
	none := Transform{Type: TransInteg, ID: INTEG_NONE}
	unusable := Transform{Type: TransInteg, ID: 12}
	withBoth := append(slices.Clone(base), unusable, none)

	body := EncodeSA([]Proposal{{Number: 1, Protocol: ProtoIKE, Transforms: withBoth}})
	selected, _, err := selectIKEProposal(body, DH_CURVE25519, Suites{})
	if err != nil {
		t.Fatalf("an offer naming an integrity algorithm alongside NONE was refused: %v", err)
	}
	if !slices.Contains(selected.Transforms, none) {
		t.Errorf("the answer is %v, which names no integrity transform of the type the offer included", selected.Transforms)
	}
	if slices.Contains(selected.Transforms, unusable) {
		t.Errorf("the answer is %v, which takes an integrity algorithm there is no key for", selected.Transforms)
	}

	lists := Suites{}
	rekey := func(p Proposal) (ikeChoice, bool) {
		chosen, _, ok := chooseIKE([]Proposal{p}, lists.ikeCiphers(), lists.rekeyPRFs(PRF_HMAC_SHA2_256), lists.kexGroups(), DH_CURVE25519)
		return chosen, ok
	}
	rekeySelected, ok := rekey(Proposal{Number: 1, Protocol: ProtoIKE, Transforms: withBoth})
	if !ok {
		t.Fatal("the same offer was refused on rekey, so a peer this end established cannot rekey from its own side")
	}
	if !slices.Contains(rekeySelected.transforms, none) || slices.Contains(rekeySelected.transforms, unusable) {
		t.Errorf("the rekey answer is %v", rekeySelected.transforms)
	}

	// a proposal whose every alternative of one type is unacceptable holds no complete set of parameters
	onlyUnusable := EncodeSA([]Proposal{{Number: 1, Protocol: ProtoIKE, Transforms: append(slices.Clone(base), unusable)}})
	if _, _, err := selectIKEProposal(onlyUnusable, DH_CURVE25519, Suites{}); err == nil {
		t.Error("an offer whose every integrity alternative is unusable was accepted")
	}
	if _, ok := rekey(Proposal{Number: 1, Protocol: ProtoIKE, Transforms: append(slices.Clone(base), unusable)}); ok {
		t.Error("a rekey offer whose every integrity alternative is unusable was accepted")
	}
	// RFC 7296 section 3.3.6: "other proposals in the same SA payload are processed as usual"
	pair := EncodeSA([]Proposal{
		{Number: 1, Protocol: ProtoIKE, Transforms: append(slices.Clone(base), unusable)},
		{Number: 2, Protocol: ProtoIKE, Transforms: slices.Clone(base)},
	})
	if selected, _, err := selectIKEProposal(pair, DH_CURVE25519, Suites{}); err != nil || selected.Number != 2 {
		t.Errorf("the second proposal was not considered: %v, %v", selected.Number, err)
	}
}
