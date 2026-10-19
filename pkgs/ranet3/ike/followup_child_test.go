// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ike

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

// childOffer is a peer's proposal of a Child SA under AES-GCM with a 128-bit key, keyed by X25519 and ML-KEM-768
var childOffer = []Transform{encrAES128, dhX25519, {Type: TransADDKE1, ID: ML_KEM_768}}

// newPeerChildRekey is a peer's rekey of s's Child SA, or its creation of one where s holds none, offering transforms and ESN_NO in one proposal, with its KE payload in X25519, Ni ni and the full ranges as traffic selectors
func newPeerChildRekey(t testing.TB, s *Session, transforms []Transform, ni []byte) (*peerRekey, []RawPayload) {
	t.Helper()
	dh, err := GenerateDH(DH_CURVE25519)
	if err != nil {
		t.Fatal(err)
	}
	p := &peerRekey{dh: dh, ni: ni, espI: randUint32Nonzero()}
	request := []RawPayload{
		{Type: PayloadSA, Body: EncodeSA([]Proposal{{Number: 1, Protocol: ProtoESP, SPI: binary.BigEndian.AppendUint32(nil, p.espI), Transforms: slices.Concat(transforms, []Transform{esnNone})}})},
		{Type: PayloadNonce, Body: EncodeNonce(ni)},
		{Type: PayloadKE, Body: EncodeKE(DH_CURVE25519, dh.PublicBytes())},
		{Type: PayloadTSi, Body: fullRangeSelectors()},
		{Type: PayloadTSr, Body: fullRangeSelectors()},
	}
	if child := s.currentChild(); child.RemoteSPI != 0 {
		rekey := Notify{Type: N_REKEY_SA, Protocol: ProtoESP, SPI: binary.BigEndian.AppendUint32(nil, child.RemoteSPI)}
		request = append([]RawPayload{{Type: PayloadN, Body: EncodeNotify(rekey)}}, request...)
	}
	return p, request
}

// childKeys is the initiator's and the responder's key of the Child SA the peer's chain makes under old, an IKE SA of HMAC-SHA2-384, each octets long, computed with crypto/hmac
// RFC 9370 section 2.2.4: "KEYMAT = prf+ (SK_d, SK(0) | Ni | Nr | SK(1) |  ... SK(n))"
// RFC 7296 section 2.17: "All keys for SAs carrying data from the initiator to the responder are taken before SAs going from the responder to the initiator."
func (p *peerRekey) childKeys(old *ikeContext, each int) (initiator, responder []byte) {
	stream := modelPRFPlus(sha512.New384, old.skD, concat(slices.Concat([][]byte{p.shared, p.ni, p.nr}, p.secrets)...), 2*each)
	return stream[:each], stream[each:]
}

// installed reports whether s holds the Child SA the peer's chain or rekey made, of AES-GCM with a 128-bit key
func (p *peerRekey) installed(s *Session) bool {
	got := s.currentChild()
	return got.EncrID == ENCR_AES_GCM_16 && got.EncrKeyBits == 128 && got.LocalSPI == p.espR && got.RemoteSPI == p.espI
}

// RFC 9370 Appendix A.3's offer made for a Child SA, with ML-KEM-768 for PQ_KEM_2, ML-KEM-1024 for PQ_KEM_5, ML-KEM-512 for PQ_KEM_1 and a private use ID for PQ_KEM_6, which this end lacks, in a peer's rekey of the Child SA and in its creation of one
// the CREATE_CHILD_SA answer and the first IKE_FOLLOWUP_KE answer each carry a link of their own, the last answer none, and the Child SA is installed only at that last exchange, keyed by every secret of the chain
// RFC 9370 section 2.2.4: "With multiple key exchanges, the SAs are not yet created when the CREATE_CHILD_SA is completed. Instead, they would be created only after the series of IKE_FOLLOWUP_KE exchanges is finished."
// RFC 9370 section 2.2.4: "KEYMAT = prf+ (SK_d, SK(0) | Ni | Nr | SK(1) |  ... SK(n))"
func TestChildSAChainOfAppendixA3AsResponder(t *testing.T) {
	const mlkem512, private = 35, 1025
	for name, rekey := range map[string]bool{"a rekey of the Child SA": true, "a creation of the Child SA": false} {
		t.Run(name, func(t *testing.T) {
			s, _ := answeringChain(t, modelSuite, Suites{kex: []kexEntry{entry768And1024}})
			if !rekey {
				s.Child = ChildSA{}
			}
			old, ctx := s.currentChild(), s.current
			offer := slices.Concat([]Transform{encrAES128, dhX25519}, addkeOf(TransADDKE1, mlkem512, ML_KEM_768), addkeOf(TransADDKE1+1, ML_KEM_1024, private, 0))
			p, request := newPeerChildRekey(t, s, offer, drawnOctets(t, 32))
			answer := p.rekey(t, s.handleChildRekey, ctx, request)
			sa := findType(answer, PayloadSA)
			if sa == nil {
				t.Fatalf("the responder answered %v, want an SA", payloadTypes(answer))
			}
			proposals, err := DecodeSA(sa.Body)
			if want := slices.Concat([]Transform{encrAES128, esnNone, dhX25519}, addkeOf(TransADDKE1, ML_KEM_768), addkeOf(TransADDKE1+1, ML_KEM_1024)); err != nil || len(proposals) != 1 || !slices.Equal(proposals[0].Transforms, want) {
				t.Fatalf("the responder answered %+v, %v, want %+v", proposals, err, want)
			}
			link1 := p.link
			if findType(answer, PayloadTSi) == nil || findType(answer, PayloadTSr) == nil || len(link1) != followupLinkLen {
				t.Fatalf("the CREATE_CHILD_SA answer carries %v with the link %x, want TSi, TSr and a link of %d octets", payloadTypes(answer), link1, followupLinkLen)
			}
			first, err := p.followup(t, s, ctx, ML_KEM_768, link1)
			if err != nil || len(first) != 2 || first[0].Type != PayloadKE || len(p.link) != followupLinkLen || bytes.Equal(p.link, link1) {
				t.Fatalf("the first IKE_FOLLOWUP_KE drew %v with the link %x, %v, want KEr and a link of its own", payloadTypes(first), p.link, err)
			}
			if got := s.currentChild(); got.LocalSPI != old.LocalSPI {
				t.Fatal("the responder installed the Child SA before the last IKE_FOLLOWUP_KE")
			}
			last, err := p.followup(t, s, ctx, ML_KEM_1024, p.link)
			if err != nil || len(last) != 1 || last[0].Type != PayloadKE {
				t.Fatalf("the last IKE_FOLLOWUP_KE drew %v, %v, want KEr alone", payloadTypes(last), err)
			}
			// AES-GCM with a 128-bit key takes 16 octets of key and 4 of salt
			initiator, responder := p.childKeys(ctx, 16+4)
			if got := s.currentChild(); !p.installed(s) || !bytes.Equal(got.InboundKey, initiator) || !bytes.Equal(got.OutboundKey, responder) {
				t.Errorf("the responder holds the Child SA of SPIs %08x and %08x, want %08x and %08x keyed by the chain of Appendix A.3", got.LocalSPI, got.RemoteSPI, p.espR, p.espI)
			}
			if got := s.Suite().ESP(); got != "aes128gcm/x25519+mlkem768+mlkem1024" {
				t.Errorf("the Child SA is named %s, want its entry after its cipher", got)
			}
			if retiring := s.retiringChild(); retiring.LocalSPI != old.LocalSPI {
				t.Errorf("the responder retires the Child SA of SPI %08x, want %08x", retiring.LocalSPI, old.LocalSPI)
			}
		})
	}
}

// a peer's rekey of a Child SA whose KE payload is in the group of the SA's entry is answered in that whole entry while the offer and kex hold it, ahead of an entry kex lists first
// so a Child SA of x25519+mlkem768 keeps ML-KEM-768 and opens a chain, and one of x25519 alone runs none and is replaced at once
// with the KE payload in another group the order of kex decides, so a Child SA of p256+mlkem768 is replaced in x25519 rather than drawing INVALID_KE_PAYLOAD for p256
// RFC 7296 section 2.8: "Note that, when rekeying, the new Child SA SHOULD NOT have different Traffic Selectors and algorithms than the old one."
func TestPeerChildSARekeyKeepsTheEntryOfTheSAItReplaces(t *testing.T) {
	for name, test := range map[string]struct {
		entry kexEntry
		kex   []kexEntry
		chain bool
	}{
		"a Child SA of x25519+mlkem768 under kex listing x25519 first": {entry768, []kexEntry{entryX25519, entry768}, true},
		"a Child SA of x25519 under kex listing x25519+mlkem768 first": {entryX25519, []kexEntry{entry768, entryX25519}, false},
		"a Child SA of p256+mlkem768 under a KE payload in x25519":     {kexEntry{group: DH_ECP_256, additions: [addkeTypes]uint16{ML_KEM_768}}, []kexEntry{entryX25519, {group: DH_ECP_256, additions: [addkeTypes]uint16{ML_KEM_768}}}, false},
	} {
		t.Run(name, func(t *testing.T) {
			s, _ := answeringChain(t, chainSuite, Suites{kex: test.kex})
			s.childKex = keyedEntry{spi: s.Child.LocalSPI, entry: test.entry}
			p, request := newPeerChildRekey(t, s, []Transform{encrAES128, dhX25519, dhP256, {Type: TransADDKE1, ID: ML_KEM_768}, {Type: TransADDKE1}}, drawnOctets(t, 32))
			answer := p.rekey(t, s.handleChildRekey, s.current, request)
			if findType(answer, PayloadSA) == nil {
				t.Fatalf("the rekey drew %v, want it taken", payloadTypes(answer))
			}
			if test.chain {
				if len(p.link) != followupLinkLen || p.installed(s) {
					t.Errorf("the rekey drew the link %x and installed the Child SA is %v, want a link of %d octets and the Child SA left to the chain", p.link, p.installed(s), followupLinkLen)
				}
				return
			}
			if p.link != nil || !p.installed(s) || s.Suite().ESPKex != "x25519" {
				t.Errorf("the rekey drew the link %x and left the Child SA in %s, want no link and the Child SA replaced in x25519", p.link, s.Suite().ESP())
			}
		})
	}
}

// an IKE_FOLLOWUP_KE of a peer's Child SA chain whose key fails the checks of FIPS 203 section 7.2 is answered INVALID_SYNTAX, which ends the IKE SA without a Delete, and recorded as ike.kex.rejected
// draft-ietf-ipsecme-ikev2-mlkem-09 section 2.2: "If the checks fail, the responder MUST reject the initiator's improper public key and SHOULD send a Notify payload of type INVALID_SYNTAX as a response to the request to prevent resource exhaustion or denial of service risks."
func TestBadKeyInAChildChainIsAnsweredInvalidSyntax(t *testing.T) {
	s, events := answeringChain(t, chainSuite, chainLists)
	ctx := s.current
	peer, request := newPeerChildRekey(t, s, childOffer, drawnOctets(t, 32))
	peer.rekey(t, s.handleChildRekey, ctx, request)
	_, key := modelKEM(t, ML_KEM_768)
	raw, err := s.handleFollowup(ctx, 0, []RawPayload{{Type: PayloadKE, Body: EncodeKE(ML_KEM_768, key[:len(key)-1])}, linkPayload(peer.link)})
	if _, ending := errors.AsType[invalidSyntaxSent](err); !ending || raw == nil || !notified(sealedAnswer(t, ctx, raw), N_INVALID_SYNTAX, nil) {
		t.Errorf("the IKE_FOLLOWUP_KE drew an answer ending the IKE SA %v, %v, want INVALID_SYNTAX", ending, err)
	}
	if peer.installed(s) {
		t.Error("a refused IKE_FOLLOWUP_KE installed the Child SA")
	}
	rejected := slices.DeleteFunc(events.recorded(), func(line string) bool { return !strings.HasPrefix(line, "ike.kex.rejected ") })
	if want := []string{"ike.kex.rejected > exchange=IKE_FOLLOWUP_KE method=mlkem768 side=key"}; !slices.Equal(rejected, want) {
		t.Errorf("the session recorded %q, want %q", rejected, want)
	}
}

// an INFORMATIONAL beside a peer's open Child SA chain, empty or deleting the Child SA the chain would replace, is answered as ever and leaves the chain open
// RFC 7296 section 2.1: "Once the IKE SA is set up, either end of the Security Association may initiate requests at any time, and there can be many requests and responses "in flight" at any given moment."
func TestRequestsDuringAPeersChildChainAreAnsweredAsUsual(t *testing.T) {
	s, _ := answeringChain(t, chainSuite, chainLists)
	ctx := s.current
	peer, request := newPeerChildRekey(t, s, childOffer, drawnOctets(t, 32))
	peer.rekey(t, s.handleChildRekey, ctx, request)
	answeredAsUsual(t, s, ctx)
	if s.chainKind() == "" {
		t.Fatal("a request beside the chain ended it")
	}
	if answer, err := peer.followup(t, s, ctx, ML_KEM_768, peer.link); err != nil || len(answer) != 1 || answer[0].Type != PayloadKE {
		t.Fatalf("the IKE_FOLLOWUP_KE drew %v, %v, want KEr alone", payloadTypes(answer), err)
	}
	if !peer.installed(s) {
		t.Error("the responder does not hold the Child SA of the chain")
	}
}

// a peer's rekey of the IKE SA while its Child SA chain is open, and its creation or rekey of the Child SA while its IKE SA chain is open, are answered TEMPORARY_FAILURE and leave the open chain
// RFC 7296 section 2.25.1: "If a peer receives a request to rekey the IKE SA, and it is currently creating, rekeying, or closing a Child SA of that IKE SA, it SHOULD reply with TEMPORARY_FAILURE."
// RFC 7296 section 2.25.2: "If a peer receives a request to create or rekey a Child SA when it is currently rekeying the IKE SA, it SHOULD reply with TEMPORARY_FAILURE."
func TestRekeyOfTheOtherSADuringAPeersChainDrawsTemporaryFailure(t *testing.T) {
	t.Run("an IKE SA rekey during a Child SA chain", func(t *testing.T) {
		s, _ := answeringChain(t, chainSuite, chainLists)
		ctx := s.current
		chain, request := newPeerChildRekey(t, s, childOffer, drawnOctets(t, 32))
		chain.rekey(t, s.handleChildRekey, ctx, request)
		for _, offer := range [][]Transform{hybridOffer, classicalOffer} {
			crossing, request := newPeerRekey(t, offer, drawnOctets(t, 32))
			if refused := crossing.rekey(t, s.handleIKERekey, ctx, request); !notified(refused, N_TEMPORARY_FAILURE, nil) {
				t.Errorf("a peer's IKE SA rekey offering %+v during its Child SA chain drew %v, want TEMPORARY_FAILURE", offer, payloadTypes(refused))
			}
		}
		if answer, err := chain.followup(t, s, ctx, ML_KEM_768, chain.link); err != nil || findType(answer, PayloadKE) == nil {
			t.Fatalf("the chain's IKE_FOLLOWUP_KE drew %v, %v, want KEr", payloadTypes(answer), err)
		}
		if current, _ := s.contexts(); current != ctx || !chain.installed(s) {
			t.Error("the session does not hold the IKE SA it had and the Child SA of the chain")
		}
	})
	t.Run("a Child SA rekey during an IKE SA chain", func(t *testing.T) {
		s, _ := answeringChain(t, chainSuite, chainLists)
		ctx := s.current
		chain, request := newPeerRekey(t, hybridOffer, drawnOctets(t, 32))
		chain.rekey(t, s.handleIKERekey, ctx, request)
		for _, offer := range [][]Transform{childOffer, {encrAES128, dhX25519}} {
			crossing, request := newPeerChildRekey(t, s, offer, drawnOctets(t, 32))
			if refused := crossing.rekey(t, s.handleChildRekey, ctx, request); !notified(refused, N_TEMPORARY_FAILURE, nil) {
				t.Errorf("a peer's Child SA rekey offering %+v during its IKE SA chain drew %v, want TEMPORARY_FAILURE", offer, payloadTypes(refused))
			}
		}
		if answer, err := chain.followup(t, s, ctx, ML_KEM_768, chain.link); err != nil || findType(answer, PayloadKE) == nil {
			t.Fatalf("the chain's IKE_FOLLOWUP_KE drew %v, %v, want KEr", payloadTypes(answer), err)
		}
		if current, _ := s.contexts(); current.spiI != chain.spiI || s.currentChild().LocalSPI != 21 {
			t.Error("the session does not hold the IKE SA of the chain and the Child SA it had")
		}
	})
}

// a peer's Child SA chain is dropped once followupWait passes and by the peer's next rekey of the Child SA, each recorded as ike.followup.dropped of the Child SA
// RFC 9370 section 2.2.4: "The responder MUST handle this situation gracefully and delete the associated state if it does not receive the next expected IKE_FOLLOWUP_KE request after some reasonable period of time."
func TestPeerChildChainIsDroppedAtFollowupWaitAndByTheNextRekey(t *testing.T) {
	s, events := answeringChain(t, chainSuite, chainLists)
	ctx := s.current
	expired, request := newPeerChildRekey(t, s, childOffer, drawnOctets(t, 32))
	expired.rekey(t, s.handleChildRekey, ctx, request)
	s.expireChain(time.Now().Add(followupWait))
	if s.chainKind() != "" {
		t.Fatal("the chain was kept past followupWait")
	}
	// each rekey comes sooner than the limit on a peer's rekeys allows, so each starts it over
	s.lastPeerChildRekey.Store(0)
	superseded, request := newPeerChildRekey(t, s, childOffer, drawnOctets(t, 32))
	superseded.rekey(t, s.handleChildRekey, ctx, request)
	s.lastPeerChildRekey.Store(0)
	last, request := newPeerChildRekey(t, s, childOffer, drawnOctets(t, 32))
	last.rekey(t, s.handleChildRekey, ctx, request)
	dropped := slices.DeleteFunc(events.recorded(), func(line string) bool { return !strings.HasPrefix(line, "ike.followup.dropped ") })
	if want := []string{"ike.followup.dropped > sa=child reason=expired", "ike.followup.dropped > sa=child reason=superseded"}; !slices.Equal(dropped, want) {
		t.Errorf("the session recorded %q, want %q", dropped, want)
	}
	for _, chain := range []*peerRekey{expired, superseded} {
		if answer, err := chain.followup(t, s, ctx, ML_KEM_768, chain.link); err != nil || !notified(answer, N_STATE_NOT_FOUND, nil) {
			t.Errorf("the dropped chain's IKE_FOLLOWUP_KE drew %v, %v, want STATE_NOT_FOUND", payloadTypes(answer), err)
		}
	}
	if answer, err := last.followup(t, s, ctx, ML_KEM_768, last.link); err != nil || findType(answer, PayloadKE) == nil || !last.installed(s) {
		t.Errorf("the last chain's IKE_FOLLOWUP_KE drew %v, %v, want KEr and its Child SA installed", payloadTypes(answer), err)
	}
}

// an ESP proposal in IKE_AUTH that requires an additional key exchange is skipped though kex holds an entry running it, since IKE_AUTH runs no key exchange
// RFC 7296 section 1.2: "Thus, the SA payloads in the IKE_AUTH exchange cannot contain Transform Type 4 (Diffie-Hellman group) with any value other than NONE."
// RFC 9370 section 2.2.3: "This exchange is the standard IKE exchange, as described in [RFC7296], with the modification of AUTH payload calculation described in [RFC9242]."
func TestIKEAuthChildSARunsNoAdditionalKeyExchangeUnderAJoinedEntry(t *testing.T) {
	h := newResponderHarness(t, nil)
	required := Proposal{Number: 1, Protocol: ProtoESP, SPI: []byte{0, 0, 0, 9}, Transforms: []Transform{encrAES256, esnNone, {Type: TransADDKE1, ID: ML_KEM_768}}}
	plain := Proposal{Number: 2, Protocol: ProtoESP, SPI: []byte{0, 0, 0, 10}, Transforms: []Transform{encrAES256, esnNone}}
	inner, _ := answerIKEAuth(t, h, Suites{kex: []kexEntry{entry768}}, required, plain)
	sa := findType(inner, PayloadSA)
	if sa == nil {
		t.Fatalf("IKE_AUTH drew %v, want proposal 2", payloadTypes(inner))
	}
	proposals, err := DecodeSA(sa.Body)
	if err != nil || len(proposals) != 1 || proposals[0].Number != 2 || slices.ContainsFunc(proposals[0].Transforms, func(transform Transform) bool { return additional(transform.Type) }) {
		t.Errorf("IKE_AUTH answered %+v, %v, want proposal 2 with no ADDKE type", proposals, err)
	}
}

// a peer's Child SA chain answered after this end's IKE SA rekey checked for an open chain and before it recorded itself collides with no rekey of the IKE SA, so this end's rekey replaces the SA though its exchange holds the lowest nonce
// RFC 9370 section 2.2.4: "In a nutshell, IKEv2 follows the rule that, in the case of simultaneous rekeying, if two identical new IKE SAs (or two pairs of Child SAs) are created, then one of them should be deleted."
func TestPeerChildChainAnsweredAsThisEndsIKESARekeyStartsCollidesWithNone(t *testing.T) {
	lowest, above, answered := bytes.Repeat([]byte{0}, 32), bytes.Repeat([]byte{4}, 32), bytes.Repeat([]byte{6}, 32)
	s, _ := initiatingSession(t, classicalSuite, Suites{ikeCipher: []Transform{encrAES128}, kex: []kexEntry{entryX25519, entry768}})
	old := s.current
	peer, request := newPeerChildRekey(t, s, childOffer, above)
	var crossing []byte
	var crossingErr error
	drawn := 0
	s.ikeRekeyNonce = func(n []byte) error {
		// RekeyIKE draws its Ni once its check for an open chain passed
		if drawn++; drawn == 1 {
			crossing, crossingErr = s.handleChildRekey(old, 0, request)
		}
		copy(n, lowest)
		return nil
	}
	done := rekeying(s)
	create := requested(t, s, done, CREATE_CHILD_SA)
	if crossingErr != nil {
		t.Fatalf("the peer's Child SA creation ended the IKE SA: %v", crossingErr)
	}
	if peer.read(t, sealedAnswer(t, old, crossing)); peer.link == nil {
		t.Fatal("the peer's Child SA creation drew no link")
	}
	answer, answering := answerRekey(t, create.inner, 0, nil, answered)
	create.result <- requestResult{inner: answer}
	deletion := requested(t, s, done, INFORMATIONAL)
	if deletion.context != old || findType(deletion.inner, PayloadD) == nil {
		t.Errorf("the request after the answer carries %v, want the Delete of the old SA", payloadTypes(deletion.inner))
	}
	deletion.result <- requestResult{}
	if err := ended(t, s, done); err != nil {
		t.Fatal(err)
	}
	if current, _ := s.contexts(); current.spiI != answering.spiI || current.spiR != answering.spiR {
		t.Error("the session is not current on the SA of its own rekey")
	}
}
