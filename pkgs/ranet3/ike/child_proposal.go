// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

package ike

import (
	"encoding/binary"
	"fmt"
	"slices"
)

func fullRangeSelectors() []byte {
	return EncodeTS([]TrafficSelector{FullRangeV4(), FullRangeV6()})
}

func validateFullRangeSelectors(tsi, tsr *RawPayload) error {
	if tsi == nil || tsr == nil {
		return fmt.Errorf("ike: Child SA exchange is missing traffic selectors")
	}
	if !isFullRangeSelectors(tsi.Body) {
		return fmt.Errorf("ike: unsupported initiator traffic selectors")
	}
	if !isFullRangeSelectors(tsr.Body) {
		return fmt.Errorf("ike: unsupported responder traffic selectors")
	}
	return nil
}

// Selector order and reserved bytes do not change the negotiated policy.
// Still require exactly one unrestricted selector for each address family.
func isFullRangeSelectors(body []byte) bool {
	selectors, err := DecodeTS(body)
	if err != nil || len(selectors) != 2 {
		return false
	}
	var v4, v6 bool
	for _, selector := range selectors {
		var expected TrafficSelector
		switch selector.Type {
		case TS_IPV4_ADDR_RANGE:
			if v4 {
				return false
			}
			v4, expected = true, FullRangeV4()
		case TS_IPV6_ADDR_RANGE:
			if v6 {
				return false
			}
			v6, expected = true, FullRangeV6()
		default:
			return false
		}
		// slices.Equal rather than net.IP.Equal: DecodeTS has already fixed the
		// width to the selector type, and net.IP.Equal would fold a 4-in-6
		// address onto its IPv4 form, which is a different selector on the
		// wire and must not compare equal to one.
		if selector.Protocol != 0 || selector.StartPort != 0 || selector.EndPort != 0xffff ||
			!slices.Equal(selector.StartAddr, expected.StartAddr) || !slices.Equal(selector.EndAddr, expected.EndAddr) {
			return false
		}
	}
	return v4 && v6
}

type childExchangePayloads struct {
	sa, nonce, ke, tsi, tsr *RawPayload
	notifies                []Notify
}

func decodeChildExchangePayloads(payloads []RawPayload, prfID uint16) (childExchangePayloads, error) {
	out, err := parseChildExchangePayloads(payloads)
	if err != nil {
		return childExchangePayloads{}, err
	}
	if err := validateCompleteChildExchange(out, prfID); err != nil {
		return childExchangePayloads{}, err
	}
	return out, nil
}

func parseChildExchangePayloads(payloads []RawPayload) (childExchangePayloads, error) {
	var out childExchangePayloads
	setUnique := func(dst **RawPayload, payload *RawPayload) error {
		if *dst != nil {
			return fmt.Errorf("ike: duplicate payload type %d in Child SA exchange", payload.Type)
		}
		*dst = payload
		return nil
	}
	for i := range payloads {
		payload := &payloads[i]
		var err error
		switch payload.Type {
		case PayloadSA:
			err = setUnique(&out.sa, payload)
		case PayloadNonce:
			err = setUnique(&out.nonce, payload)
		case PayloadTSi:
			err = setUnique(&out.tsi, payload)
		case PayloadTSr:
			err = setUnique(&out.tsr, payload)
		case PayloadN:
			notify, decodeErr := DecodeNotify(payload.Body)
			if decodeErr != nil {
				return childExchangePayloads{}, decodeErr
			}
			out.notifies = append(out.notifies, notify)
		case PayloadKE:
			err = setUnique(&out.ke, payload)
		}
		if err != nil {
			return childExchangePayloads{}, err
		}
	}
	return out, nil
}

func validateCompleteChildExchange(payloads childExchangePayloads, prfID uint16) error {
	if payloads.sa == nil || payloads.nonce == nil || payloads.tsi == nil || payloads.tsr == nil ||
		!validNonceFor(payloads.nonce.Body, prfID) {
		return fmt.Errorf("ike: incomplete Child SA exchange")
	}
	return nil
}

// validNonce is RFC 7296 section 2.10 without its second half: "Nonces used in
// IKEv2 MUST be randomly chosen, MUST be at least 128 bits in size, and MUST
// be at least half the key size of the negotiated pseudorandom function."
// This much a responder can check on an IKE_SA_INIT request, where the nonce
// arrives alongside the proposals the PRF is still to be chosen from.
func validNonce(nonce []byte) bool { return len(nonce) >= 16 && len(nonce) <= 256 }

// validNonceFor adds the second half, for every exchange whose PRF is settled.
// The PRFs here are HMAC constructions, whose preferred key size is their
// output size, so a 16 byte nonce is short for HMAC-SHA2-384.
func validNonceFor(nonce []byte, prfID uint16) bool {
	return validNonce(nonce) && len(nonce) >= PRFOutputLen(prfID)/2
}

func canonicalEncryptionTransform(t Transform) (Transform, error) {
	if t.Type != TransEncr {
		return Transform{}, fmt.Errorf("ike: expected an encryption transform")
	}
	if t.UnsupportedAttributes {
		return Transform{}, fmt.Errorf("ike: encryption transform has unsupported attributes")
	}
	if t.ID == ENCR_CHACHA20_POLY1305 && t.KeyLengthBits != 0 {
		return Transform{}, fmt.Errorf("ike: ChaCha20-Poly1305 has a fixed key length")
	}
	if _, err := aeadParams(t.ID, t.KeyLengthBits); err != nil {
		return Transform{}, err
	}
	if t.ID == ENCR_CHACHA20_POLY1305 {
		t.KeyLengthBits = 256
	}
	return t, nil
}

// decodeChildProposal reads the one ESP proposal answering this end's offer of offered, in IKE_AUTH or in a CREATE_CHILD_SA it started
// RFC 7296 section 3.3.6: "The initiator of an exchange MUST check that the accepted offer is consistent with one of its proposals, and if not MUST terminate the exchange."
// RFC 7296 section 2.7: "The accepted cryptographic suite MUST contain exactly one transform of each type included in the proposal."
// RFC 7296 section 1.2: "the SA payloads in the IKE_AUTH exchange cannot contain Transform Type 4 (Diffie-Hellman group) with any value other than NONE."
// an offer names a cipher and ESN alone
// so an answer naming any other type is refused
// a DH group among them would key the SA from a key exchange this end never ran
func decodeChildProposal(body []byte, offered []Transform) (Proposal, Transform, uint32, error) {
	props, err := DecodeSA(body)
	if err != nil || len(props) != 1 {
		return Proposal{}, Transform{}, 0, fmt.Errorf("ike: invalid Child SA proposal")
	}
	p := props[0]
	if p.Number != 1 || p.Protocol != ProtoESP || len(p.SPI) != 4 {
		return Proposal{}, Transform{}, 0, fmt.Errorf("ike: invalid Child SA proposal shape")
	}
	remoteSPI := binary.BigEndian.Uint32(p.SPI)
	if remoteSPI == 0 {
		return Proposal{}, Transform{}, 0, fmt.Errorf("ike: Child SA proposal has a zero SPI")
	}
	var encryption Transform
	var haveEncryption, haveESN bool
	for _, transform := range p.Transforms {
		switch transform.Type {
		case TransEncr:
			if haveEncryption {
				return Proposal{}, Transform{}, 0, fmt.Errorf("ike: Child SA proposal has duplicate encryption transforms")
			}
			if !slices.Contains(offered, transform) {
				return Proposal{}, Transform{}, 0, fmt.Errorf("ike: Child SA proposal selected an unoffered transform")
			}
			encryption, err = canonicalEncryptionTransform(transform)
			if err != nil {
				return Proposal{}, Transform{}, 0, err
			}
			haveEncryption = true
		case TransESN:
			if haveESN || transform.ID != ESN_NO || transform.KeyLengthBits != 0 || transform.UnsupportedAttributes {
				return Proposal{}, Transform{}, 0, fmt.Errorf("ike: Child SA proposal has an unsupported ESN transform")
			}
			haveESN = true
		default:
			return Proposal{}, Transform{}, 0, fmt.Errorf("ike: Child SA proposal has transform type %d", transform.Type)
		}
	}
	if !haveEncryption || !haveESN {
		return Proposal{}, Transform{}, 0, fmt.Errorf("ike: incomplete Child SA proposal")
	}
	return p, encryption, remoteSPI, nil
}

type childProposalSelection struct {
	proposal   Proposal
	encryption Transform
	dh         Transform
	// integ is the integrity transform the offer carried, or the zero value
	// when it carried none. RFC 7296 section 2.7 wants one transform of every
	// type the offer included back in the answer, and the only one this
	// implementation can take is NONE.
	integ     Transform
	remoteSPI uint32
}

type invalidKEError struct{ group uint16 }

// invalidKENotifyData is the notification data every INVALID_KE_PAYLOAD
// carries. RFC 7296 section 1.3: "There are two octets of data associated with
// this notification: the accepted Diffie-Hellman group number in big endian
// order", and the same section has the initiator retry "with a Diffie-Hellman
// proposal and KEi in the group that the responder gave". A notify without
// them says the group is wrong and not which one to use, so the retry is a
// guess. Section 3.10.1's own entry for the type is "See Sections 1.2 and
// 1.3."
func invalidKENotifyData(group uint16) []byte {
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, group)
	return data
}

func (e *invalidKEError) Error() string {
	return fmt.Sprintf("ike: peer must use DH group %d", e.group)
}

// selectChildRequestProposal answers a Child SA offer from ciphers and groups, each in this end's order, as chooseIKE answers an IKE SA offer
// rule tells chooseGroup whether the answer may go without a group
func selectChildRequestProposal(body []byte, ciphers, groups []Transform, keGroup uint16, rule groupRule) (childProposalSelection, error) {
	props, err := DecodeSA(body)
	if err != nil {
		return childProposalSelection{}, fmt.Errorf("ike: invalid Child SA proposal")
	}
	var met []childProposalSelection
	var offers [][]Transform
	for _, p := range props {
		// a proposal's SPI is the one the ESP packets this end sends the peer would carry
		// RFC 3948 section 2.1: "The SPI field in the ESP header MUST NOT be a zero value."
		if p.Number == 0 || p.Protocol != ProtoESP || len(p.SPI) != 4 || binary.BigEndian.Uint32(p.SPI) == 0 {
			continue
		}
		var integ Transform
		var haveESN, haveInteg, offeredInteg, unacceptable bool
		for _, transform := range p.Transforms {
			switch transform.Type {
			case TransEncr, TransDH:
			case TransESN:
				if !haveESN && transform.ID == ESN_NO && transform.KeyLengthBits == 0 && !transform.UnsupportedAttributes {
					haveESN = true
				}
			case TransInteg:
				// RFC 7296 section 3.3.6: "if the responder receives a transform that it does not understand, or one that contains a Transform Attribute it does not understand, it MUST consider this transform unacceptable" and "other transforms with the same Transform Type are processed as usual."
				offeredInteg = true
				if !haveInteg && transform.ID == INTEG_NONE && !transform.UnsupportedAttributes {
					integ = transform
					haveInteg = true
				}
			default:
				// RFC 7296 section 3.3.6: "If the responder receives a proposal that contains a Transform Type it does not understand, or a proposal that is missing a mandatory Transform Type, it MUST consider this proposal unacceptable" and "other proposals in the same SA payload are processed as usual."
				unacceptable = true
			}
		}
		cipher, haveCipher := choose(ciphers, p.Transforms)
		if unacceptable || offeredInteg && !haveInteg || !haveCipher || !haveESN {
			continue
		}
		encryption, err := canonicalEncryptionTransform(cipher)
		if err != nil {
			return childProposalSelection{}, err
		}
		met = append(met, childProposalSelection{proposal: p, encryption: encryption, integ: integ, remoteSPI: binary.BigEndian.Uint32(p.SPI)})
		offers = append(offers, p.Transforms)
	}
	at, dh, retry, ok := chooseGroup(offers, groups, keGroup, rule)
	if retry != 0 {
		return childProposalSelection{}, &invalidKEError{retry}
	}
	if !ok {
		return childProposalSelection{}, fmt.Errorf("ike: no acceptable Child SA proposal")
	}
	chosen := met[at]
	chosen.dh = dh
	return chosen, nil
}
