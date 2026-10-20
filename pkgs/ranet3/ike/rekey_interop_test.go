// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

package ike

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestPeerChildRekeyWithPFS(t *testing.T) {
	for _, group := range []uint16{DH_CURVE25519, DH_ECP_256, DH_ECP_384} {
		for _, responder := range []bool{false, true} {
			t.Run(fmt.Sprintf("group=%d/responder=%t", group, responder), func(t *testing.T) {
				mux, _ := lifecycleMuxes(t)
				suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
				ctx := &ikeContext{suite: suite, spiI: 11, spiR: 12, skD: bytes.Repeat([]byte{1}, 32),
					skei: bytes.Repeat([]byte{2}, 20), sker: bytes.Repeat([]byte{3}, 20), responder: responder}
				old := ChildSA{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, LocalSPI: 21, RemoteSPI: 22}
				s := &Session{mux: mux, current: ctx, Child: old}
				dh, err := GenerateDH(group)
				if err != nil {
					t.Fatal(err)
				}
				ni := bytes.Repeat([]byte{4}, 32)
				proposal := espProposal(binary.BigEndian.AppendUint32(nil, 32))
				proposal.Transforms = append(proposal.Transforms, Transform{Type: TransDH, ID: group})
				// RFC 7296 section 2.5: "implementations MUST NOT reject as invalid a message with those payloads in any other order."
				// so the request has them in reverse
				// section 3.10.1: "Unrecognized error types in a request and status types in a request or response MUST be ignored, and they should be logged."
				// so it carries one of each besides
				raw, err := s.handleChildRekey(ctx, 0, []RawPayload{
					{Type: PayloadTSr, Body: fullRangeSelectors()},
					{Type: PayloadTSi, Body: fullRangeSelectors()},
					{Type: PayloadKE, Body: EncodeKE(group, dh.PublicBytes())},
					{Type: PayloadNonce, Body: ni},
					{Type: PayloadSA, Body: EncodeSA([]Proposal{proposal})},
					{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_REKEY_SA, Protocol: ProtoESP, SPI: binary.BigEndian.AppendUint32(nil, old.RemoteSPI)})},
					unrecognizedError,
					unrecognizedStatus,
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
				// section 2.5: "implementations SHOULD send the payloads defined in this specification in the order shown in the figures in Sections 1 and 2"
				// the figure of section 1.3.3: "HDR, SK {SA, Nr, [KEr,] TSi, TSr}"
				if got, want := payloadTypes(inner), []PayloadType{PayloadSA, PayloadNonce, PayloadKE, PayloadTSi, PayloadTSr}; !slices.Equal(got, want) {
					t.Errorf("the rekey answer carries payload types %v, want %v", got, want)
				}
				payloads, err := decodeChildExchangePayloads(inner, PRF_HMAC_SHA2_256)
				if err != nil || payloads.ke == nil {
					t.Fatalf("invalid PFS response: %v, %v", inner, err)
				}
				gotGroup, public, err := DecodeKE(payloads.ke.Body)
				if err != nil || gotGroup != group {
					t.Fatalf("response KE group = %d, %v", gotGroup, err)
				}
				selected, err := DecodeSA(payloads.sa.Body)
				if err != nil || len(selected) != 1 {
					t.Fatalf("response proposal = %v, %v", selected, err)
				}
				var selectedDH uint16
				for _, transform := range selected[0].Transforms {
					if transform.Type == TransDH {
						selectedDH = transform.ID
					}
				}
				if selectedDH != group {
					t.Fatalf("selected DH group = %d, want %d", selectedDH, group)
				}
				shared, err := dh.SharedSecret(public)
				if err != nil {
					t.Fatal(err)
				}
				// Derive from the peer's DH secret, independently of the Child
				// helper. Keys follow the exchange initiator, not the IKE role.
				keymat := prfPlus(suite.PRFID, ctx.skD, concat(shared, ni, payloads.nonce.Body), 40)
				child := s.currentChild()
				if !bytes.Equal(child.InboundKey, keymat[:20]) || !bytes.Equal(child.OutboundKey, keymat[20:]) {
					t.Fatal("Child SA keys do not match peer PFS derivation")
				}
				if child.RemoteSPI != 32 || child.LocalSPI == old.LocalSPI || s.retiringChild().LocalSPI != old.LocalSPI {
					t.Fatal("Child SA overlap was not preserved")
				}
			})
		}
	}
}

func TestChildProposalDHSelection(t *testing.T) {
	for _, tc := range []struct {
		name       string
		groups     []uint16
		ke, want   uint16
		retryGroup uint16
	}{
		{"match KE", []uint16{DH_CURVE25519, DH_ECP_256}, DH_CURVE25519, DH_CURVE25519, 0},
		{"KE after the first listed group", []uint16{DH_ECP_256, DH_CURVE25519}, DH_ECP_256, 0, DH_CURVE25519},
		{"retry unsupported KE", []uint16{DH_ECP_256}, 14, 0, DH_ECP_256},
		{"retry missing KE", []uint16{DH_ECP_256}, 0, 0, DH_ECP_256},
		{"explicit NONE without KE", []uint16{DH_ECP_256, 0}, 0, 0, 0},
		{"explicit NONE beside an unsupported KE", []uint16{DH_ECP_256, 0}, 14, 0, DH_ECP_256},
		{"no PFS", nil, 0, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proposal := espProposal([]byte{1, 2, 3, 4})
			for _, group := range tc.groups {
				proposal.Transforms = append(proposal.Transforms, Transform{Type: TransDH, ID: group})
			}
			selected, err := selectChildRequestProposal(EncodeSA([]Proposal{proposal}), Suites{}.espCiphers(), Suites{}.kexEntries(), tc.ke)
			if tc.retryGroup != 0 {
				var invalid *invalidKEError
				if !errors.As(err, &invalid) || invalid.group != tc.retryGroup {
					t.Fatalf("selection error = %v, want retry group %d", err, tc.retryGroup)
				}
			} else if err != nil || selected.dh.ID != tc.want {
				t.Fatalf("selected group = %d, %v; want %d", selected.dh.ID, err, tc.want)
			}
		})
	}
}

func TestIKERekeyProposalKeepsPRF(t *testing.T) {
	for _, prf := range []uint16{PRF_HMAC_SHA2_256, PRF_HMAC_SHA2_384} {
		offer := Suites{}.ikeRekeyProposals(nil, SASuite{PRFID: prf, DHGroup: DH_CURVE25519}, DH_CURVE25519)
		if len(offer) != len(Suites{}.kexEntries()) {
			t.Fatalf("offered %d proposals, want one for each of %d kex entries", len(offer), len(Suites{}.kexEntries()))
		}
		for _, proposal := range offer {
			var count int
			for _, transform := range proposal.Transforms {
				if transform.Type == TransPRF {
					count++
					if transform.ID != prf {
						t.Fatalf("proposal %d offered PRF %d, want %d", proposal.Number, transform.ID, prf)
					}
				}
			}
			if count != 1 {
				t.Fatalf("proposal %d offered %d PRFs, want 1", proposal.Number, count)
			}
		}
		lists := Suites{}
		chosen, _, ok := chooseIKE([]Proposal{ikeProposal()}, lists.ikeCiphers(), lists.rekeyPRFs(prf), lists.rekeyEntries(kexEntry{group: DH_CURVE25519}, DH_CURVE25519), DH_CURVE25519)
		if !ok || chosen.suite.PRFID != prf {
			t.Fatalf("selected PRF %d, want %d", chosen.suite.PRFID, prf)
		}
	}
}

// an answer to this end's IKE SA rekey that chooses a PRF the rekey offer left out
// is refused and leaves the SA it would have replaced current
func TestRekeyIKERefusesAPRFItsOfferLeftOut(t *testing.T) {
	mux, _ := lifecycleMuxes(t)
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	old := &ikeContext{suite: suite, spiI: 11, spiR: 12, skD: make([]byte, 32), skei: make([]byte, 20), sker: make([]byte, 20)}
	s := &Session{mux: mux, current: old, requests: make(chan *localRequest, 1)}
	done := make(chan error, 1)
	go func() { done <- s.RekeyIKE() }()
	request := <-s.requests
	dh, err := GenerateDH(DH_CURVE25519)
	if err != nil {
		t.Fatal(err)
	}
	answer := Proposal{Number: 1, Protocol: ProtoIKE, SPI: binary.BigEndian.AppendUint64(nil, 22), Transforms: []Transform{
		{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128},
		{Type: TransPRF, ID: PRF_HMAC_SHA2_384},
		{Type: TransDH, ID: DH_CURVE25519},
	}}
	request.result <- requestResult{inner: []RawPayload{
		{Type: PayloadSA, Body: EncodeSA([]Proposal{answer})},
		// a nonce long enough for HMAC-SHA2-384
		// leaves the refusal to the offer check
		{Type: PayloadNonce, Body: bytes.Repeat([]byte{1}, 32)},
		{Type: PayloadKE, Body: EncodeKE(DH_CURVE25519, dh.PublicBytes())},
	}}
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "unoffered transform 2/6") {
			t.Errorf("RekeyIKE returned %v, want the answer's PRF refused by name", err)
		}
	case next := <-s.requests:
		next.result <- requestResult{err: errors.New("nothing answers past the rekey")}
		t.Fatalf("RekeyIKE installed the answer and asked for exchange %d next, then returned %v", next.exchange, <-done)
	}
	if current, _ := s.contexts(); current != old {
		t.Error("a refused rekey answer replaced the IKE SA")
	}
}

// RFC 7296 section 2.18: "Therefore, implementations MUST perform a new Diffie-Hellman exchange when rekeying the IKE SA."
// and: "This means that a successful exchange rekeying the IKE SA always includes the KEi/KEr payloads."
// an answer to this end's IKE SA rekey that carries no KE payload is refused and leaves the SA it would have replaced current
func TestRekeyIKERefusesAnAnswerWithoutAKeyExchange(t *testing.T) {
	mux, _ := lifecycleMuxes(t)
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	old := &ikeContext{suite: suite, spiI: 11, spiR: 12, skD: make([]byte, 32), skei: make([]byte, 20), sker: make([]byte, 20)}
	s := &Session{mux: mux, current: old, requests: make(chan *localRequest, 1)}
	done := make(chan error, 1)
	go func() { done <- s.RekeyIKE() }()
	request := <-s.requests
	answer := Proposal{Number: 1, Protocol: ProtoIKE, SPI: binary.BigEndian.AppendUint64(nil, 22), Transforms: []Transform{
		{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128},
		{Type: TransPRF, ID: PRF_HMAC_SHA2_256},
		{Type: TransDH, ID: DH_CURVE25519},
	}}
	request.result <- requestResult{inner: []RawPayload{
		{Type: PayloadSA, Body: EncodeSA([]Proposal{answer})},
		{Type: PayloadNonce, Body: bytes.Repeat([]byte{1}, 32)},
	}}
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "incomplete IKE SA rekey response") {
			t.Errorf("RekeyIKE returned %v, want the answer refused as incomplete", err)
		}
	case next := <-s.requests:
		next.result <- requestResult{err: errors.New("nothing answers past the rekey")}
		t.Fatalf("RekeyIKE installed the answer and asked for exchange %d next, then returned %v", next.exchange, <-done)
	}
	if current, _ := s.contexts(); current != old {
		t.Error("a refused rekey answer replaced the IKE SA")
	}
}

// RFC 7296 section 3.9: "Nonce values MUST NOT be reused."
// section 2.6.1 gives the IKE_SA_INIT retry after INVALID_KE_PAYLOAD as "HDR(A,0), N(COOKIE), SAi1, KEi', Ni -->", the nonce of the attempt that failed
// each IKE SA rekey draws its own nonce, and its retry in the group an INVALID_KE_PAYLOAD names sends the nonce of the attempt that failed, from which no key was derived
func TestEachIKESARekeyDrawsItsOwnNonceAndItsRetryKeepsIt(t *testing.T) {
	mux, _ := lifecycleMuxes(t)
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	s := &Session{mux: mux, current: &ikeContext{suite: suite, spiI: 11, spiR: 12, skD: make([]byte, 32), skei: make([]byte, 20), sker: make([]byte, 20)},
		requests: make(chan *localRequest, 1)}
	nonceOf := func(request *localRequest) []byte {
		t.Helper()
		nonce := findType(request.inner, PayloadNonce)
		if nonce == nil {
			t.Fatalf("the IKE SA rekey request carries %v and no nonce", payloadTypes(request.inner))
		}
		return DecodeNonce(nonce.Body)
	}
	var nonces [][]byte
	for range 2 {
		done := make(chan error, 1)
		go func() { done <- s.RekeyIKE() }()
		first := <-s.requests
		nonce := nonceOf(first)
		nonces = append(nonces, nonce)
		first.result <- requestResult{inner: []RawPayload{{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_INVALID_KE_PAYLOAD, Data: invalidKENotifyData(DH_ECP_256)})}}}
		retry := <-s.requests
		if again := nonceOf(retry); !bytes.Equal(again, nonce) {
			t.Errorf("the retry in the group INVALID_KE_PAYLOAD named sent nonce %x, want the failed attempt's %x", again, nonce)
		}
		retry.result <- requestResult{inner: []RawPayload{{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_NO_PROPOSAL_CHOSEN})}}}
		if err := <-done; err == nil {
			t.Fatal("RekeyIKE took an answer of NO_PROPOSAL_CHOSEN")
		}
	}
	if bytes.Equal(nonces[0], nonces[1]) {
		t.Errorf("two IKE SA rekeys sent the same nonce %x", nonces[0])
	}
}

// RFC 7296 section 3.10.1: "An implementation receiving a Notify payload with one of these types that it does not recognize in a response MUST assume that the corresponding request has failed entirely."
// section 3.10.1: "Notify payloads with status types MAY be added to any message and MUST be ignored if not recognized."
// an answer to this end's IKE SA rekey carrying a whole SA beside an error notify of a type nothing assigns is a rejection that leaves the old SA current, and one carrying it beside a status notify of a type nothing assigns replaces the old SA
func TestRekeyIKETakesAnErrorNotifyItDoesNotRecognizeAsARejection(t *testing.T) {
	// answered starts a rekey and answers it with notify beside a whole SA
	answered := func(t *testing.T, notify RawPayload) (*Session, *ikeContext, <-chan error) {
		mux, _ := lifecycleMuxes(t)
		suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
		old := &ikeContext{suite: suite, spiI: 11, spiR: 12, skD: make([]byte, 32), skei: make([]byte, 20), sker: make([]byte, 20)}
		s := &Session{mux: mux, current: old, requests: make(chan *localRequest, 1)}
		done := make(chan error, 1)
		go func() { done <- s.RekeyIKE() }()
		request := <-s.requests
		dh, err := GenerateDH(DH_CURVE25519)
		if err != nil {
			t.Fatal(err)
		}
		answer := Proposal{Number: 1, Protocol: ProtoIKE, SPI: binary.BigEndian.AppendUint64(nil, 22), Transforms: []Transform{
			{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128},
			{Type: TransPRF, ID: PRF_HMAC_SHA2_256},
			{Type: TransDH, ID: DH_CURVE25519},
		}}
		request.result <- requestResult{inner: []RawPayload{
			notify,
			{Type: PayloadSA, Body: EncodeSA([]Proposal{answer})},
			{Type: PayloadNonce, Body: bytes.Repeat([]byte{1}, 32)},
			{Type: PayloadKE, Body: EncodeKE(DH_CURVE25519, dh.PublicBytes())},
		}}
		return s, old, done
	}
	t.Run("error", func(t *testing.T) {
		s, old, done := answered(t, unrecognizedError)
		select {
		case err := <-done:
			if rejected, ok := errors.AsType[*rejectedError](err); !ok || rejected.notify.Type != 8191 {
				t.Errorf("RekeyIKE returned %v, want a rejection naming notify type 8191", err)
			}
		case next := <-s.requests:
			next.result <- requestResult{err: errors.New("nothing answers past the rekey")}
			t.Fatalf("RekeyIKE installed the answer and asked for exchange %d next, then returned %v", next.exchange, <-done)
		}
		if current, _ := s.contexts(); current != old {
			t.Error("a rejected rekey answer replaced the IKE SA")
		}
	})
	t.Run("status", func(t *testing.T) {
		s, old, done := answered(t, unrecognizedStatus)
		select {
		case err := <-done:
			t.Fatalf("RekeyIKE returned %v without deleting the SA it replaced", err)
		case next := <-s.requests:
			// the Delete of the old IKE SA
			next.result <- requestResult{}
		}
		if err := <-done; err != nil {
			t.Errorf("RekeyIKE returned %v, want the answer taken", err)
		}
		if current, _ := s.contexts(); current == old {
			t.Error("the rekey answer carrying a status notify left the old IKE SA current")
		}
	})
}

func TestPeerRekeyDefersConflictingTransition(t *testing.T) {
	for _, state := range []string{"local Child rekey", "Child retirement", "local IKE rekey", "old IKE SA", "replaced IKE SA"} {
		t.Run(state, func(t *testing.T) {
			ctx := &ikeContext{suite: SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128}, skei: make([]byte, 20)}
			s := &Session{current: ctx}
			handle := s.handleIKERekey
			switch state {
			case "local Child rekey":
				s.childRekeying.Store(true)
			case "Child retirement":
				s.retiring.LocalSPI = 1
			case "local IKE rekey":
				s.localRekey = &ikeRekey{old: ctx}
				handle = s.handleChildRekey
			case "old IKE SA":
				s.current = new(ikeContext)
				handle = s.handleChildRekey
			// RFC 7296 section 2.8.2: "it SHOULD return TEMPORARY_FAILURE because it is an IKE SA that it is currently trying to close (whether or not it has already sent the delete notification for the SA)."
			case "replaced IKE SA":
				s.current, s.old = new(ikeContext), ctx
			}
			raw, err := handle(ctx, 0, nil)
			if err != nil {
				t.Fatal(err)
			}
			message, err := DecodeMessage(raw)
			if err != nil {
				t.Fatal(err)
			}
			inner, err := DecryptMessage(ctx.suite, ctx.skei, raw, message)
			if err != nil || len(inner) != 1 || inner[0].Type != PayloadN {
				t.Fatalf("response = %v, %v", inner, err)
			}
			notify, err := DecodeNotify(inner[0].Body)
			if err != nil || notify.Type != N_TEMPORARY_FAILURE {
				t.Fatalf("notify = %v, %v", notify, err)
			}
		})
	}
}

// while this end rekeys the IKE SA, a peer's Delete of a Child SA is answered as usual, with the Delete of the SA's other half
func TestChildSADeleteDuringAnIKESARekeyIsAnsweredWithItsDelete(t *testing.T) {
	child := ChildSA{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, LocalSPI: 0x10203040, RemoteSPI: 0x50607080}
	s := newRekeyableSession(t, child)
	s.current.skei, s.current.sker = make([]byte, 20), make([]byte, 20)
	s.localRekey = &ikeRekey{old: s.current}
	inner := crossingDelete(t, s, child.RemoteSPI)
	if len(inner) != 1 || inner[0].Type != PayloadD {
		t.Fatalf("the Child SA Delete was answered with %v, want a Delete payload", inner)
	}
	deleted, err := DecodeDelete(inner[0].Body)
	if err != nil || deleted.Protocol != ProtoESP || len(deleted.SPIs) != 1 || binary.BigEndian.Uint32(deleted.SPIs[0]) != child.LocalSPI {
		t.Errorf("the answer deletes %+v (%v), want ESP SPI %08x", deleted, err, child.LocalSPI)
	}
}

// RFC 7296 section 2.8: "After the new equivalent IKE SA is created, the initiator deletes the old IKE SA, and the Delete payload to delete itself MUST be the last request sent over the old IKE SA."
// a Child SA exchange queued on an IKE SA that has since been replaced is refused before it takes a Message ID or goes out
func TestQueuedChildRequestDoesNotUseRetiredIKE(t *testing.T) {
	mux, _ := lifecycleMuxes(t)
	replaced := testContext()
	s := &Session{mux: mux, current: new(ikeContext)}
	_, err := s.startRequest(&localRequest{exchange: CREATE_CHILD_SA, context: replaced})
	if err == nil {
		t.Fatal("started CREATE_CHILD_SA on a replaced IKE SA")
	}
	if replaced.nextLocalMID != 0 {
		t.Errorf("the refused exchange took Message ID %d of the replaced IKE SA", replaced.nextLocalMID-1)
	}
}

// The rate limit has to sit in handleChildRekey, before the Diffie-Hellman and
// the keymat, the work a peer rekeying in a loop is really asking us to
// spend.
func TestHandleChildRekeyRefusesSecondRekeyInSameInterval(t *testing.T) {
	mux, _ := lifecycleMuxes(t)
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	ctx := &ikeContext{suite: suite, spiI: 11, spiR: 12, skD: bytes.Repeat([]byte{1}, 32),
		skei: bytes.Repeat([]byte{2}, 20), sker: bytes.Repeat([]byte{3}, 20)}
	old := ChildSA{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, LocalSPI: 21, RemoteSPI: 22}
	s := &Session{mux: mux, current: ctx, Child: old, started: time.Now()}

	rekey := func(msgID uint32, remoteSPI uint32) []RawPayload {
		raw, err := s.handleChildRekey(ctx, msgID, []RawPayload{
			{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_REKEY_SA, Protocol: ProtoESP, SPI: binary.BigEndian.AppendUint32(nil, remoteSPI)})},
			{Type: PayloadSA, Body: EncodeSA([]Proposal{espProposal(binary.BigEndian.AppendUint32(nil, 32))})},
			{Type: PayloadNonce, Body: bytes.Repeat([]byte{4}, 32)},
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
		return inner
	}

	if notify := findType(rekey(0, old.RemoteSPI), PayloadN); notify != nil {
		decoded, _ := DecodeNotify(notify.Body)
		t.Fatalf("the first peer rekey was refused with notify type %d", decoded.Type)
	}
	// Clear the retirement the first rekey left outstanding, which would
	// refuse the second on its own and hide what this test is about.
	s.childMu.Lock()
	s.retiring = ChildSA{}
	s.childMu.Unlock()

	// The replacement is now current, so the second names it and is refused
	// only because it is too soon.
	next := s.currentChild()
	notify := findType(rekey(1, next.RemoteSPI), PayloadN)
	if notify == nil {
		t.Fatal("a second peer rekey in the same interval was accepted")
	}
	decoded, err := DecodeNotify(notify.Body)
	if err != nil || decoded.Type != N_TEMPORARY_FAILURE {
		t.Fatalf("second rekey answered with notify %v, %v, want TEMPORARY_FAILURE", decoded, err)
	}
}

// ChaCha20-Poly1305 carries no KEY_LENGTH attribute, and the CREATE_CHILD_SA
// response path has its own copy of the rule that suppresses it.
func TestChaChaChildRekeyResponseEchoesNoKeyLength(t *testing.T) {
	mux, _ := lifecycleMuxes(t)
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	ctx := &ikeContext{suite: suite, spiI: 11, spiR: 12, skD: bytes.Repeat([]byte{1}, 32),
		skei: bytes.Repeat([]byte{2}, 20), sker: bytes.Repeat([]byte{3}, 20)}
	// A rekey keeps the cipher, so the SA being replaced has to be the one
	// whose response encoding is under test.
	old := ChildSA{EncrID: ENCR_CHACHA20_POLY1305, EncrKeyBits: 256, LocalSPI: 21, RemoteSPI: 22}
	s := &Session{mux: mux, current: ctx, Child: old, started: time.Now()}

	// Offered the way a conformant peer offers a fixed-key cipher: no Key
	// Length attribute at all.
	proposal := Proposal{
		Number: 1, Protocol: ProtoESP, SPI: binary.BigEndian.AppendUint32(nil, 32),
		Transforms: []Transform{{Type: TransEncr, ID: ENCR_CHACHA20_POLY1305}, {Type: TransESN, ID: ESN_NO}},
	}
	raw, err := s.handleChildRekey(ctx, 0, []RawPayload{
		{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_REKEY_SA, Protocol: ProtoESP, SPI: binary.BigEndian.AppendUint32(nil, old.RemoteSPI)})},
		{Type: PayloadSA, Body: EncodeSA([]Proposal{proposal})},
		{Type: PayloadNonce, Body: bytes.Repeat([]byte{4}, 32)},
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
	payloads, err := decodeChildExchangePayloads(inner, PRF_HMAC_SHA2_256)
	if err != nil {
		t.Fatalf("the rekey was refused rather than answered: %v, %v", inner, err)
	}
	// RFC 7296 section 3.4: "If none of the proposals in that SA payload specifies a Diffie-Hellman group, the KE payload MUST NOT be present."
	if payloads.ke != nil {
		t.Error("the answer to a rekey offering no Diffie-Hellman group carries a KE payload")
	}
	selected, err := DecodeSA(payloads.sa.Body)
	if err != nil || len(selected) != 1 {
		t.Fatalf("response proposal = %v, %v", selected, err)
	}
	for _, transform := range selected[0].Transforms {
		if transform.Type == TransEncr && transform.KeyLengthBits != 0 {
			t.Errorf("the rekey response offered ChaCha20-Poly1305 with Key Length %d, which RFC 7296 section 3.3.5 forbids",
				transform.KeyLengthBits)
		}
	}
}

// The Child path's half of the same rule. A local failure installing the
// replacement is not the peer's fault and not a reason to lose the IKE SA that
// carried the exchange. RFC 7296 section 1.3.1 is explicit that "A failed
// attempt to create a Child SA SHOULD NOT tear down the IKE SA". Returning an
// error instead sends Run down the teardown path.
func TestLocalFailureAnsweringAChildRekeyIsTemporary(t *testing.T) {
	mux, _ := lifecycleMuxes(t)
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	ctx := &ikeContext{suite: suite, spiI: 11, spiR: 12, skD: bytes.Repeat([]byte{1}, 32),
		skei: bytes.Repeat([]byte{2}, 20), sker: bytes.Repeat([]byte{3}, 20)}
	old := ChildSA{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, LocalSPI: 21, RemoteSPI: 22}
	s := &Session{mux: mux, current: ctx, Child: old, started: time.Now()}
	// The dataplane refusing the replacement is the shape this actually takes:
	// the SA is negotiated and cannot be installed here.
	s.SetChildHandler(func(ChildSA) error { return errors.New("the dataplane is gone") })

	raw, err := s.handleChildRekey(ctx, 0, []RawPayload{
		{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_REKEY_SA, Protocol: ProtoESP,
			SPI: binary.BigEndian.AppendUint32(nil, old.RemoteSPI)})},
		{Type: PayloadSA, Body: EncodeSA([]Proposal{espProposal(binary.BigEndian.AppendUint32(nil, 32))})},
		{Type: PayloadNonce, Body: bytes.Repeat([]byte{4}, 32)},
		{Type: PayloadTSi, Body: fullRangeSelectors()},
		{Type: PayloadTSr, Body: fullRangeSelectors()},
	})
	if err != nil {
		t.Fatalf("a local failure was returned as an error, which Run turns into a teardown: %v", err)
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
		t.Fatal("a local failure answered with a whole SA")
	}
	notify, err := DecodeNotify(payload.Body)
	if err != nil {
		t.Fatal(err)
	}
	if notify.Type != N_TEMPORARY_FAILURE {
		t.Errorf("the answer is notify type %d, want TEMPORARY_FAILURE", notify.Type)
	}
}
