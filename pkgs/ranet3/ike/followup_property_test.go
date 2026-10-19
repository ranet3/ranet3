// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package ike

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"hash"
	"slices"
	"strings"
	"testing"
	"time"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// rekeyKeyInputs holds the drawn inputs a rekey with additional key exchanges derives its keys from
type rekeyKeyInputs struct {
	prfID      uint16
	newHash    func() hash.Hash
	skD        []byte
	shared     []byte
	ni, nr     []byte
	additional [][]byte
}

func drawnRekeyKeyInputs(ht *hegel.T) rekeyKeyInputs {
	in := rekeyKeyInputs{prfID: PRF_HMAC_SHA2_256, newHash: sha256.New}
	if hegel.Draw(ht, hegel.Booleans()) {
		in.prfID, in.newHash = PRF_HMAC_SHA2_384, sha512.New384
	}
	in.skD = hegel.Draw(ht, hegel.Binary(in.newHash().Size(), in.newHash().Size()))
	in.shared = hegel.Draw(ht, hegel.Binary(32, 97))
	in.ni, in.nr = hegel.Draw(ht, hegel.Binary(16, 64)), hegel.Draw(ht, hegel.Binary(16, 64))
	// an ML-KEM shared secret is 32 octets
	for range hegel.Draw(ht, pbt.Spanning(0, addkeTypes)) {
		in.additional = append(in.additional, hegel.Draw(ht, hegel.Binary(32, 32)))
	}
	return in
}

// the chained secrets of RFC 9370 section 2.2.4, SK(0) | Ni | Nr | SK(1) | ... SK(n), written one after another in that order
func (in rekeyKeyInputs) chained() []byte {
	var chain bytes.Buffer
	chain.Write(in.shared)
	chain.Write(in.ni)
	chain.Write(in.nr)
	for _, secret := range in.additional {
		chain.Write(secret)
	}
	return chain.Bytes()
}

// the keys of an IKE SA rekey with additional key exchanges equal the chain RFC 9370 and RFC 7296 give, computed with crypto/hmac
// RFC 9370 section 2.2.4: "SKEYSEED = prf(SK_d, SK(0) | Ni | Nr | SK(1) | ... SK(n))"
// RFC 7296 section 2.18: "SK_d, SK_ai, SK_ar, SK_ei, and SK_er are computed from SKEYSEED as specified in Section 2.14, using SPIi, SPIr, Ni, and Nr from the new exchange, and using the new IKE SA's PRF."
func TestRekeyedIKEKeysFollowTheChainOfRFC9370(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		in := drawnRekeyKeyInputs(ht)
		suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: hegel.Draw(ht, hegel.SampledFrom([]uint16{128, 256})), PRFID: in.prfID}
		spiI, spiR := hegel.Draw(ht, hegel.Integers[uint64](1, 1<<63)), hegel.Draw(ht, hegel.Integers[uint64](1, 1<<63))
		keys, err := DeriveRekeyedIKEKeys(in.prfID, in.skD, suite, in.shared, in.ni, in.nr, spiI, spiR, in.additional...)
		if err != nil {
			ht.Fatal(err)
		}
		mac := hmac.New(in.newHash, in.skD)
		mac.Write(in.chained())
		var spis [16]byte
		binary.BigEndian.PutUint64(spis[:8], spiI)
		binary.BigEndian.PutUint64(spis[8:], spiR)
		want := modelKeys(in.newHash, mac.Sum(nil), concat(in.ni, in.nr, spis[:]), int(suite.EncrKeyBits)/8+4)
		got := [5][]byte{keys.SKd, keys.SKei, keys.SKer, keys.SKpi, keys.SKpr}
		if !slices.EqualFunc(got[:], want[:], bytes.Equal) {
			ht.Fatalf("a rekey with %d additional key exchanges derived %x, the chain %x", len(in.additional), got, want)
		}
	})
}

// the KEYMAT of a Child SA made with additional key exchanges equals the chain RFC 9370 and RFC 7296 give, computed with crypto/hmac
// RFC 9370 section 2.2.4: "KEYMAT = prf+ (SK_d, SK(0) | Ni | Nr | SK(1) |  ... SK(n))"
// RFC 7296 section 2.17: "All keys for SAs carrying data from the initiator to the responder are taken before SAs going from the responder to the initiator."
func TestChildKeymatFollowsTheChainOfRFC9370(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		in := drawnRekeyKeyInputs(ht)
		encrID, bits := ENCR_AES_GCM_16, hegel.Draw(ht, hegel.SampledFrom([]uint16{128, 256}))
		each := int(bits)/8 + 4
		if hegel.Draw(ht, hegel.Booleans()) {
			encrID, bits, each = ENCR_CHACHA20_POLY1305, 256, 32+4
		}
		initiator, responder, err := childSAKeymat(in.prfID, in.skD, in.shared, in.ni, in.nr, encrID, bits, in.additional...)
		if err != nil {
			ht.Fatal(err)
		}
		want := modelPRFPlus(in.newHash, in.skD, in.chained(), 2*each)
		if !bytes.Equal(initiator, want[:each]) || !bytes.Equal(responder, want[each:]) {
			ht.Fatalf("a Child SA with %d additional key exchanges took %x and %x, the chain %x", len(in.additional), initiator, responder, want)
		}
	})
}

// an answer to an IKE SA rekey is taken only as the single choice of one proposal of the offer, with a nonzero SPI, Nr long enough for the PRF, a KE payload in the request's group, and a link exactly where the choice runs additional key exchanges
// every mutation of such an answer is refused, and refused as the end of the IKE SA exactly where it selects an additional key exchange or carries a link, since the peer may then hold a chain waiting on this end
// RFC 7296 section 3.3.6: "The initiator of an exchange MUST check that the accepted offer is consistent with one of its proposals, and if not MUST terminate the exchange."
// RFC 9370 section 2.2.1: "If this happens in the CREATE_CHILD_SA exchange, then the initiator MAY delete the IKE SA over which the invalid message was received by sending a Delete payload."
func TestIKERekeyAnswerIsTakenOnlyAsTheSingleChoiceOfAnOfferedProposal(t *testing.T) {
	groups := []uint16{DH_CURVE25519, DH_ECP_384, DH_ECP_256}
	pbt.Check(t, func(ht *hegel.T) {
		lists := Suites{kex: drawnEntries(ht, false)}
		entries := lists.kexEntries()
		current := entries[hegel.Draw(ht, hegel.Integers(0, len(entries)-1))]
		prf := hegel.Draw(ht, hegel.SampledFrom([]uint16{PRF_HMAC_SHA2_256, PRF_HMAC_SHA2_384}))
		old := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 256, PRFID: prf, DHGroup: current.group, Additions: current.additions}
		offer := lists.ikeRekeyProposals(binary.BigEndian.AppendUint64(nil, randUint64Nonzero()), old, current.group)
		proposal := offer[hegel.Draw(ht, hegel.Integers(0, len(offer)-1))]
		var chosen []Transform
		for _, kind := range []TransformType{TransEncr, TransPRF} {
			var of []Transform
			for _, transform := range proposal.Transforms {
				if transform.Type == kind {
					of = append(of, transform)
				}
			}
			chosen = append(chosen, of[hegel.Draw(ht, hegel.Integers(0, len(of)-1))])
		}
		var group uint16
		for _, transform := range proposal.Transforms {
			if transform.Type == TransDH {
				group = transform.ID
			}
			if transform.Type == TransDH || additional(transform.Type) {
				chosen = append(chosen, transform)
			}
		}
		var entry kexEntry
		for _, e := range entries {
			if slices.Equal(entryProposalKex(e), kexOf(proposal)) {
				entry = e
			}
		}
		mine, err := GenerateDH(group)
		if err != nil {
			ht.Fatal(err)
		}
		theirs, err := GenerateDH(group)
		if err != nil {
			ht.Fatal(err)
		}
		shared, err := mine.SharedSecret(theirs.PublicBytes())
		if err != nil {
			ht.Fatal(err)
		}
		var link []byte
		if !entry.classical() {
			link = hegel.Draw(ht, hegel.Binary(1, 32))
		}
		nonce := hegel.Draw(ht, hegel.Binary(32, 64))
		spiR := hegel.Draw(ht, hegel.Integers[uint64](1, 1<<63))
		sa := &Proposal{Number: proposal.Number, Protocol: ProtoIKE, SPI: binary.BigEndian.AppendUint64(nil, spiR), Transforms: chosen}
		ke := EncodeKE(group, theirs.PublicBytes())
		answer := func(sa *Proposal, nonce, ke, link []byte) []RawPayload {
			var payloads []RawPayload
			if sa != nil {
				payloads = append(payloads, RawPayload{Type: PayloadSA, Body: EncodeSA([]Proposal{*sa})})
			}
			payloads = append(payloads, RawPayload{Type: PayloadNonce, Body: EncodeNonce(nonce)}, RawPayload{Type: PayloadKE, Body: ke})
			if link != nil {
				payloads = append(payloads, linkPayload(link))
			}
			return payloads
		}
		got, err := readIKERekeyAnswer(answer(sa, nonce, ke, link), offer, group, mine)
		if err != nil || got.suite.entry() != entry || got.suite.PRFID != prf || got.suite.EncrID != chosen[0].ID || got.suite.EncrKeyBits != chosen[0].KeyLengthBits ||
			got.spiR != spiR || !bytes.Equal(got.nonce, nonce) || !bytes.Equal(got.shared, shared) || !bytes.Equal(got.link, link) {
			ht.Fatalf("the single choice %+v of proposal %+v with the link %x read as %+v, %v, want entry %+v", sa, proposal, link, got, err, entry)
		}

		mutated := *sa
		mutated.Transforms = slices.Clone(sa.Transforms)
		mutatedSA, mutatedNonce, mutatedKE, mutatedLink := &mutated, nonce, ke, link
		switch hegel.Draw(ht, pbt.Spanning(0, 11)) {
		case 0:
			if len(offer) == 1 {
				return
			}
			others := slices.DeleteFunc(slices.Clone(offer), func(p Proposal) bool { return p.Number == proposal.Number })
			mutated.Number = others[hegel.Draw(ht, hegel.Integers(0, len(others)-1))].Number
		case 1:
			i := hegel.Draw(ht, hegel.Integers(0, len(mutated.Transforms)-1))
			mutated.Transforms = slices.Delete(mutated.Transforms, i, i+1)
		case 2:
			i := hegel.Draw(ht, hegel.Integers(0, len(mutated.Transforms)-1))
			mutated.Transforms = slices.Insert(mutated.Transforms, i, mutated.Transforms[i])
		case 3:
			mutated.Transforms = append(mutated.Transforms, hegel.Draw(ht, hegel.SampledFrom([]Transform{
				{Type: TransInteg, ID: INTEG_NONE}, {Type: TransESN, ID: ESN_NO}, {Type: TransformType(15), ID: 1},
				{Type: TransADDKE7, ID: 0}, {Type: TransADDKE7, ID: ML_KEM_768},
			})))
		case 4:
			i := hegel.Draw(ht, hegel.Integers(0, len(mutated.Transforms)-1))
			mutated.Transforms[i].ID = hegel.Draw(ht, hegel.SampledFrom([]uint16{0, 1, ENCR_AES_GCM_16 + 1, DH_ECP_256 - 1, ML_KEM_768 - 1}))
			if mutated.Transforms[i] == sa.Transforms[i] {
				return
			}
		case 5:
			if entry.classical() {
				return
			}
			// a second ADDKE type running a method the answer runs already
			mutated.Transforms = append(mutated.Transforms, Transform{Type: TransADDKE1 + TransformType(len(entry.added())), ID: entry.added()[0]})
		case 6:
			mutated.Protocol = ProtoESP
		case 7:
			if mutatedLink == nil {
				mutatedLink = hegel.Draw(ht, hegel.Binary(0, 32))
			} else {
				mutatedLink = nil
			}
		case 8:
			mutatedNonce = nonce[:8]
		case 9:
			other := hegel.Draw(ht, hegel.SampledFrom(slices.DeleteFunc(slices.Clone(groups), func(g uint16) bool { return g == group })))
			pair, err := GenerateDH(other)
			if err != nil {
				ht.Fatal(err)
			}
			mutatedKE = EncodeKE(other, pair.PublicBytes())
		case 10:
			mutated.SPI = make([]byte, 8)
		case 11:
			mutatedSA = nil
		}
		taken, err := readIKERekeyAnswer(answer(mutatedSA, mutatedNonce, mutatedKE, mutatedLink), offer, group, mine)
		if err == nil {
			ht.Fatalf("the answer %+v with the nonce %x and the link %x to the offer %+v was taken as %+v", mutatedSA, mutatedNonce, mutatedLink, offer, taken)
		}
		// the model: an answer chains once it carries a link or any ADDKE type of its SA payload names a method
		chains := mutatedLink != nil
		if mutatedSA != nil {
			for _, transform := range mutatedSA.Transforms {
				chains = chains || transform.Type >= TransADDKE1 && transform.Type <= TransADDKE7 && transform.ID != 0
			}
		}
		if _, ending := errors.AsType[*saEnding](err); ending != chains {
			ht.Fatalf("the answer %+v with the link %x was refused with %v, ending the IKE SA %v, want %v", mutatedSA, mutatedLink, err, ending, chains)
		}
	})
}

// a peer's rekeys of the IKE SA and the Child SA and its IKE_FOLLOWUP_KE exchanges, in any order beside other requests and the passing of time, are answered as a model of the chain RFC 9370 section 2.2.4 gives
// an IKE SA rekey keeping the SA's additional key exchanges, and any Child SA rekey, is answered with a link where it runs any, and replaces its SA at once where it runs none
// an IKE_FOLLOWUP_KE echoing the open chain's link is answered with the next method's ciphertext, a new link while methods remain, and the new SA once none remain
// any other IKE_FOLLOWUP_KE draws STATE_NOT_FOUND, a rekey of the SA the open chain makes or followupWait passing drops the chain, each recorded with the SA and the reason, and a rekey of the other SA draws TEMPORARY_FAILURE and leaves the chain
// a Delete of the Child SA is answered with the Delete of this end's half and leaves the chain, and the peer then makes a Child SA from scratch
// RFC 9370 section 2.2.4: "If the responder receives an IKE_FOLLOWUP_KE message for which it does not have a key exchange state, it MUST send back a new error type notification called "STATE_NOT_FOUND"."
// RFC 7296 section 2.25.1: "If a peer receives a request to rekey the IKE SA, and it is currently creating, rekeying, or closing a Child SA of that IKE SA, it SHOULD reply with TEMPORARY_FAILURE."
func TestPeerChainsAreAnsweredAsTheModelOfTheChain(t *testing.T) {
	mux, _ := lifecycleMuxes(t)
	entry1024And768 := kexEntry{group: DH_CURVE25519, additions: [addkeTypes]uint16{ML_KEM_1024, ML_KEM_768}}
	// the model's entries, each with the methods of its additional key exchanges in the order they run
	entries := []struct {
		entry   kexEntry
		methods []uint16
	}{{entryX25519, nil}, {entry768, []uint16{ML_KEM_768}}, {entry768And1024, []uint16{ML_KEM_768, ML_KEM_1024}}, {entry1024And768, []uint16{ML_KEM_1024, ML_KEM_768}}}
	// leavesOut holds each pair of the SA's entry and a rekey's entry where the rekey runs without one of the SA's methods, which the lists holding the SA's entry refuse
	// RFC 9370 section 2.2.1: "With these semantics, note that ADDKE Transform Types are not associated with any particular type of key exchange and do not have any Transform IDs that are specific per Transform Type IANA registry."
	// RFC 9370 section 4: "The ordering of the additional key exchanges should not matter in general, as only the final shared secret is of interest."
	// so a method that moves to another ADDKE type is kept, and x25519+mlkem768+mlkem1024 and x25519+mlkem1024+mlkem768 each keep the other
	leavesOut := map[[2]int]bool{{1, 0}: true, {2, 0}: true, {2, 1}: true, {3, 0}: true, {3, 1}: true}
	lists := Suites{ikeCipher: []Transform{encrAES128}}
	for _, e := range entries {
		lists.kex = append(lists.kex, e.entry)
	}
	offering := func(base []Transform, at int) []Transform {
		offer := slices.Clone(base)
		for n, method := range entries[at].methods {
			offer = append(offer, Transform{Type: TransADDKE1 + TransformType(n), ID: method})
		}
		return offer
	}
	child := ChildSA{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, LocalSPI: 21, RemoteSPI: 22}
	pbt.Check(t, func(ht *hegel.T) {
		// the model: the IKE SA's entry, drawn so that a rekey dropping an addition can meet the first step, whether the session holds a Child SA, and the open chain's SA, entry, peer and methods left, none open where peer is nil
		current, offered := hegel.Draw(ht, hegel.Integers(0, len(entries)-1)), 0
		held := true
		suite := classicalSuite
		suite.Additions = entries[current].entry.additions
		s := answeringSession(ht, mux, suite, child, 0, lists)
		events := &recorder{}
		s.events = events.record
		var peer *peerRekey
		var kind string
		var left int
		// drops holds the sa and reason attributes of each chain dropped
		var drops []string
		// links holds the link of each chain that ended, which no later IKE_FOLLOWUP_KE may reach
		var links [][]byte
		// replaced checks the SA was replaced by the one the peer's rekey made in the entry at index at, and has the peer delete the SA it replaced
		replaced := func(old *ikeContext, by *peerRekey, at int) {
			suite := classicalSuite
			suite.Additions = entries[at].entry.additions
			now, retained := s.contexts()
			if now == old || retained != old || now.suite != suite || now.spiI != by.spiI || !sameKeys(now, by.keys(ht, old, suite)) {
				ht.Fatalf("the session is current on an SA in %+v and retains the old one is %v, want the SA of %+v the peer's rekey made", now.suite, retained == old, entries[at].entry)
			}
			header := Header{SPIInitiator: old.spiI, SPIResponder: old.spiR, ExchangeType: INFORMATIONAL}
			if _, err := s.handleRequest(old, &header, nil, []RawPayload{{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoIKE})}}); err != nil {
				ht.Fatalf("the peer's Delete of the replaced SA ended the session: %v", err)
			}
			current = at
		}
		// replacedChild checks the Child SA was made by the peer's rekey or creation in the entry at index at, and has the peer delete the Child SA it replaced where the session held one, which every later rekey would wait on
		replacedChild := func(by *peerRekey, at int) {
			ctx := s.current
			initKey, respKey, err := childSAKeymat(ctx.suite.PRFID, ctx.skD, by.shared, by.ni, by.nr, ENCR_AES_GCM_16, 128, by.secrets...)
			if err != nil {
				ht.Fatal(err)
			}
			got := s.currentChild()
			if !by.installed(s) || !bytes.Equal(got.InboundKey, initKey) || !bytes.Equal(got.OutboundKey, respKey) || s.Suite().ESPKex != kexName(entries[at].entry) {
				ht.Fatalf("the session holds the Child SA of SPIs %08x and %08x in %s, want the Child SA of %+v the peer's rekey made", got.LocalSPI, got.RemoteSPI, s.Suite().ESP(), entries[at].entry)
			}
			if held {
				header := Header{SPIInitiator: ctx.spiI, SPIResponder: ctx.spiR, ExchangeType: INFORMATIONAL}
				deleted := Delete{Protocol: ProtoESP, SPIs: [][]byte{binary.BigEndian.AppendUint32(nil, s.retiringChild().RemoteSPI)}}
				if _, err := s.handleRequest(ctx, &header, nil, []RawPayload{{Type: PayloadD, Body: EncodeDelete(deleted)}}); err != nil || s.retiringChild().LocalSPI != 0 {
					ht.Fatalf("the peer's Delete of the replaced Child SA ended the session with %v or left it retiring", err)
				}
			}
			held = true
		}
		for range hegel.Draw(ht, pbt.Spanning(1, 12)) {
			ctx := s.current
			switch hegel.Draw(ht, hegel.Integers(0, 7)) {
			case 0:
				at := hegel.Draw(ht, hegel.Integers(0, len(entries)-1))
				// the steps come faster than the limit on a peer's rekeys allows, so each starts it over
				s.lastPeerIKERekey.Store(0)
				next, request := newPeerRekey(ht, offering(classicalOffer, at), hegel.Draw(ht, hegel.Binary(32, 32)))
				answer := next.rekey(ht, s.handleIKERekey, ctx, request)
				// the peer's rekey of the Child SA runs until its chain ends
				if peer != nil && kind == "child" {
					if !notified(answer, N_TEMPORARY_FAILURE, nil) {
						ht.Fatalf("an IKE SA rekey during a Child SA chain drew %v, want TEMPORARY_FAILURE", payloadTypes(answer))
					}
					break
				}
				// a rekey of the IKE SA ends the peer's last one, whatever its own answer
				if peer != nil {
					drops, links, peer = append(drops, "sa=ike reason=superseded"), append(links, peer.link), nil
				}
				switch {
				// while the lists hold the SA's entry, a rekey keeps each of its additional key exchanges
				case leavesOut[[2]int{current, at}]:
					if !notified(answer, N_NO_PROPOSAL_CHOSEN, nil) {
						ht.Fatalf("a rekey into %+v of an SA of %+v drew %v, want NO_PROPOSAL_CHOSEN", entries[at].entry, entries[current].entry, payloadTypes(answer))
					}
				case len(entries[at].methods) == 0:
					if findType(answer, PayloadSA) == nil || next.link != nil {
						ht.Fatalf("a rekey into %+v drew %v with the link %x, want it taken with no link", entries[at].entry, payloadTypes(answer), next.link)
					}
					replaced(ctx, next, at)
				default:
					if findType(answer, PayloadSA) == nil || len(next.link) != followupLinkLen {
						ht.Fatalf("a rekey into %+v drew %v with the link %x, want it taken with a link of %d octets", entries[at].entry, payloadTypes(answer), next.link, followupLinkLen)
					}
					if now, _ := s.contexts(); now != ctx {
						ht.Fatal("a rekey with additional key exchanges replaced the SA at its CREATE_CHILD_SA")
					}
					peer, kind, offered, left = next, "ike", at, len(entries[at].methods)
				}
			case 1:
				if peer == nil {
					if answer, err := (&peerRekey{}).followup(ht, s, ctx, ML_KEM_768, hegel.Draw(ht, hegel.Binary(0, 16))); err != nil || !notified(answer, N_STATE_NOT_FOUND, nil) {
						ht.Fatalf("an IKE_FOLLOWUP_KE with no chain open drew %v, %v, want STATE_NOT_FOUND", payloadTypes(answer), err)
					}
					continue
				}
				methods := entries[offered].methods
				method, previous := methods[len(methods)-left], peer.link
				answer, err := peer.followup(ht, s, ctx, method, previous)
				if left--; left > 0 {
					if err != nil || findType(answer, PayloadKE) == nil || len(peer.link) != followupLinkLen || bytes.Equal(peer.link, previous) {
						ht.Fatalf("an IKE_FOLLOWUP_KE with methods to follow drew %v with the link %x, %v, want KEr and a new link", payloadTypes(answer), peer.link, err)
					}
					continue
				}
				if err != nil || len(answer) != 1 || answer[0].Type != PayloadKE {
					ht.Fatalf("the last IKE_FOLLOWUP_KE drew %v, %v, want KEr alone", payloadTypes(answer), err)
				}
				links = append(links, previous)
				if kind == "child" {
					replacedChild(peer, offered)
				} else {
					replaced(ctx, peer, offered)
				}
				peer = nil
			case 2:
				link := hegel.Draw(ht, hegel.Binary(followupLinkLen, followupLinkLen))
				if len(links) > 0 && hegel.Draw(ht, hegel.Booleans()) {
					link = hegel.Draw(ht, hegel.SampledFrom(links))
				}
				if answer, err := (&peerRekey{}).followup(ht, s, ctx, ML_KEM_768, link); err != nil || !notified(answer, N_STATE_NOT_FOUND, nil) {
					ht.Fatalf("an IKE_FOLLOWUP_KE with a link no chain holds drew %v, %v, want STATE_NOT_FOUND", payloadTypes(answer), err)
				}
			case 3:
				header := Header{SPIInitiator: ctx.spiI, SPIResponder: ctx.spiR, ExchangeType: INFORMATIONAL}
				raw, err := s.handleRequest(ctx, &header, nil, nil)
				if err != nil || len(sealedAnswer(ht, ctx, raw)) != 0 {
					ht.Fatalf("an empty INFORMATIONAL drew an error %v or a payload", err)
				}
			case 4:
				s.expireChain(time.Now().Add(followupWait))
				if peer != nil {
					drops, links, peer = append(drops, "sa="+kind+" reason=expired"), append(links, peer.link), nil
				}
			case 5:
				s.expireChain(time.Now())
			case 6:
				at := hegel.Draw(ht, hegel.Integers(0, len(entries)-1))
				s.lastPeerChildRekey.Store(0)
				next, request := newPeerChildRekey(ht, s, offering([]Transform{encrAES128, dhX25519}, at), hegel.Draw(ht, hegel.Binary(32, 32)))
				answer := next.rekey(ht, s.handleChildRekey, ctx, request)
				// the peer's rekey of the IKE SA runs until its chain ends
				if peer != nil && kind == "ike" {
					if !notified(answer, N_TEMPORARY_FAILURE, nil) {
						ht.Fatalf("a Child SA rekey during an IKE SA chain drew %v, want TEMPORARY_FAILURE", payloadTypes(answer))
					}
					break
				}
				if peer != nil {
					drops, links, peer = append(drops, "sa=child reason=superseded"), append(links, peer.link), nil
				}
				if findType(answer, PayloadSA) == nil {
					ht.Fatalf("a Child SA rekey into %+v drew %v, want it taken", entries[at].entry, payloadTypes(answer))
				}
				if len(entries[at].methods) == 0 {
					if next.link != nil {
						ht.Fatalf("a Child SA rekey into %+v drew the link %x, want none", entries[at].entry, next.link)
					}
					replacedChild(next, at)
					break
				}
				if len(next.link) != followupLinkLen || next.installed(s) {
					ht.Fatalf("a Child SA rekey into %+v drew the link %x and installed the Child SA is %v, want a link of %d octets and the Child SA left to the chain", entries[at].entry, next.link, next.installed(s), followupLinkLen)
				}
				peer, kind, offered, left = next, "child", at, len(entries[at].methods)
			case 7:
				if !held {
					break
				}
				// the peer deletes the Child SA, which leaves any chain open, and its next Child SA request makes one from scratch
				deleting := s.currentChild()
				header := Header{SPIInitiator: ctx.spiI, SPIResponder: ctx.spiR, ExchangeType: INFORMATIONAL}
				deleted := Delete{Protocol: ProtoESP, SPIs: [][]byte{binary.BigEndian.AppendUint32(nil, deleting.RemoteSPI)}}
				raw, err := s.handleRequest(ctx, &header, nil, []RawPayload{{Type: PayloadD, Body: EncodeDelete(deleted)}})
				if err != nil {
					ht.Fatalf("the peer's Delete of the Child SA ended the session: %v", err)
				}
				var answered Delete
				if payload := findType(sealedAnswer(ht, ctx, raw), PayloadD); payload != nil {
					answered, err = DecodeDelete(payload.Body)
				}
				if err != nil || answered.Protocol != ProtoESP || len(answered.SPIs) != 1 || binary.BigEndian.Uint32(answered.SPIs[0]) != deleting.LocalSPI || s.currentChild().LocalSPI != 0 {
					ht.Fatalf("the peer's Delete of the Child SA of SPIs %08x and %08x drew %+v, %v, want the Delete of this end's half and the Child SA gone", deleting.LocalSPI, deleting.RemoteSPI, answered, err)
				}
				held = false
			}
			want := ""
			if peer != nil {
				want = kind
			}
			if got := s.chainKind(); got != want {
				ht.Fatalf("the session holds a chain of %q, the model of %q", got, want)
			}
			var dropped []string
			for _, line := range events.recorded() {
				if attrs, ok := strings.CutPrefix(line, "ike.followup.dropped > "); ok {
					dropped = append(dropped, attrs)
				}
			}
			if !slices.Equal(dropped, drops) {
				ht.Fatalf("the session dropped chains as %q, the model %q", dropped, drops)
			}
		}
	})
}
