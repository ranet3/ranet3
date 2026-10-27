// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package ike

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/internal/bubble"
	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// the answers a peer may send, every transform this end names and the ones near them it must refuse
var (
	answerCiphers = []Transform{encrAES256, encrAES128, encrChaCha,
		{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 192},
		{Type: TransEncr, ID: ENCR_AES_GCM_16},
		{Type: TransEncr, ID: ENCR_CHACHA20_POLY1305, KeyLengthBits: 256}}
	answerPRFs = []Transform{prfSHA384, prfSHA256, {Type: TransPRF, ID: 7}}
)

// answerOf draws one transform of an answer, from expected half the time and from every otherwise
func answerOf(tc hegel.TestCase, expected, every []Transform) Transform {
	if hegel.Draw(tc, hegel.Booleans()) {
		return hegel.Draw(tc, hegel.SampledFrom(expected))
	}
	return hegel.Draw(tc, hegel.SampledFrom(every))
}

// namedAll is the transform of each name
func namedAll(names []string) []Transform {
	out := make([]Transform, len(names))
	for i, name := range names {
		out[i] = transformOf(name)
	}
	return out
}

// drawnCrypto draws the four lists
func drawnCrypto(tc hegel.TestCase) Crypto {
	return Crypto{
		IKE: IKESuites{Cipher: pbt.List(tc, everyCipher), PRF: pbt.List(tc, everyPRF), Kex: pbt.List(tc, everyKex)},
		ESP: ESPSuites{Cipher: pbt.List(tc, everyCipher)},
	}
}

// written is list, or every where the list is left out
func written(list, every []string) []string {
	if list == nil {
		return every
	}
	return list
}

// transformOf is the transform the lists name name by
func transformOf(name string) Transform {
	for _, table := range [][]suiteName{cipherNames, prfNames, kexNames} {
		for _, entry := range table {
			if entry.name == name {
				return entry.transform
			}
		}
	}
	panic("no transform is named " + name)
}

// ahead is list with name first where list holds it
func ahead(list []string, name string) []string {
	if !slices.Contains(list, name) {
		return list
	}
	return slices.Concat([]string{name}, slices.DeleteFunc(slices.Clone(list), func(other string) bool { return other == name }))
}

// offered is one proposal of a peer's offer by the names of its transforms
type offered struct {
	ciphers, prfs, groups []string
	// none is the group NONE among the groups
	none bool
	// unknown is a transform of a type no exchange takes
	unknown bool
}

// answered is how a model or a session answered an offer
// refused is NO_PROPOSAL_CHOSEN, retry names the group INVALID_KE_PAYLOAD asks for, and number is the proposal taken
// group is none for NONE and empty for an answer without a group
type answered struct {
	refused            bool
	retry              string
	number             int
	cipher, prf, group string
}

// a peer's rekey is answered as RFC 7296 and this end's lists have it, the model below stating the rule over the drawn names alone
// the proposals that count are those this end's lists meet in every type but the group, a proposal with a transform of an unknown type never does
// an IKE SA rekey keeps the PRF, so only a proposal holding the SA's PRF while ike prf holds it counts
// a Child SA's cipher is the one it runs while esp cipher holds it and the proposal offers it, else the first of esp cipher the proposal holds
// the group is the first of ike kex any counted proposal holds, the SA's own first where the KE payload is in it and kex holds it
// the first counted proposal holding it is answered, and a KE payload in another group is asked to come back in it
// a Child SA's proposal may offer NONE or no group, which is taken ahead of every group without a KE payload and behind every group with one
// RFC 7296 section 3.3.4: "The implementation MUST reject SA proposals that are not authorized by these IKE suite controls."
// RFC 7296 section 2.8: "Note that, when rekeying, the new Child SA SHOULD NOT have different Traffic Selectors and algorithms than the old one."
func TestPeerRekeyIsAnsweredByTheListsOrRefused(t *testing.T) {
	mux, _ := lifecycleMuxes(t)
	pbt.Check(t, func(ht *hegel.T) {
		ike := hegel.Draw(ht, hegel.Booleans())
		lists := drawnCrypto(ht)
		ciphers, prfs, groups := written(lists.IKE.Cipher, everyCipher), written(lists.IKE.PRF, everyPRF), written(lists.IKE.Kex, everyKex)
		esp := written(lists.ESP.Cipher, everyCipher)
		prf := hegel.Draw(ht, hegel.SampledFrom(everyPRF))
		group := hegel.Draw(ht, hegel.SampledFrom(everyKex))
		childCipher := hegel.Draw(ht, hegel.SampledFrom(everyCipher))
		// empty for a Child SA SK_d alone keyed
		childGroup := hegel.Draw(ht, hegel.SampledFrom(slices.Concat([]string{""}, everyKex)))
		offer := make([]offered, hegel.Draw(ht, pbt.Spanning(1, 3)))
		for i := range offer {
			offer[i].ciphers = pbt.Subset(ht, everyCipher, 1, len(everyCipher))
			if ike {
				offer[i].prfs = pbt.Subset(ht, everyPRF, 1, len(everyPRF))
				offer[i].groups = pbt.Subset(ht, everyKex, 1, len(everyKex))
			} else {
				offer[i].groups = pbt.List(ht, everyKex)
				offer[i].none = hegel.Draw(ht, hegel.WeightedBooleans(1.0/4))
			}
			offer[i].unknown = hegel.Draw(ht, hegel.WeightedBooleans(1.0/8))
		}
		ke := hegel.Draw(ht, hegel.SampledFrom(everyKex))
		// half the time the KE payload is in a group of kex drawn by its place, the last as often as the first
		if hegel.Draw(ht, hegel.Booleans()) {
			ke = groups[hegel.Draw(ht, pbt.Spanning(0, len(groups)-1))]
		}
		if !ike && hegel.Draw(ht, hegel.WeightedBooleans(1.0/3)) {
			ke = ""
		}
		// a peer keeping the group of the SA it rekeys sends its KE payload in that group
		if ke != "" && hegel.Draw(ht, hegel.WeightedBooleans(1.0/2)) {
			if ike {
				group = ke
			} else {
				childGroup = ke
			}
		}
		// a Child SA's own group listed behind the first is drawn outright, so every run meets it answered ahead of kex order
		if !ike && len(groups) > 1 && hegel.Draw(ht, pbt.Spanning(0, 3)) == 0 {
			ke = groups[hegel.Draw(ht, pbt.Spanning(1, len(groups)-1))]
			childGroup = ke
			offer[0] = offered{ciphers: []string{esp[hegel.Draw(ht, pbt.Spanning(0, len(esp)-1))]}, groups: slices.Clone(groups)}
		}

		var want answered
		cipherOrder := ciphers
		if !ike {
			cipherOrder = ahead(esp, childCipher)
		}
		var counted []int
		for i, p := range offer {
			if p.unknown || firstShared(cipherOrder, p.ciphers, nil) == "" || ike && !(slices.Contains(prfs, prf) && slices.Contains(p.prfs, prf)) {
				continue
			}
			counted = append(counted, i)
		}
		withoutGroup := func() bool {
			for _, i := range counted {
				if offer[i].none || len(offer[i].groups) == 0 {
					want = answered{number: i + 1, cipher: firstShared(cipherOrder, offer[i].ciphers, nil)}
					if offer[i].none {
						want.group = "none"
					}
					return true
				}
			}
			return false
		}
		own := group
		if !ike {
			own = childGroup
		}
		order := groups
		if own == ke {
			order = ahead(groups, own)
		}
		decided := !ike && ke == "" && withoutGroup()
		for _, g := range order {
			if decided {
				break
			}
			for _, i := range counted {
				if !slices.Contains(offer[i].groups, g) {
					continue
				}
				decided = true
				if g != ke {
					want = answered{retry: g}
				} else {
					want = answered{number: i + 1, cipher: firstShared(cipherOrder, offer[i].ciphers, nil), group: g}
				}
				break
			}
		}
		if !decided && !(!ike && withoutGroup()) {
			want = answered{refused: true}
		}
		if ike && !want.refused && want.retry == "" {
			want.prf = prf
		}

		var proposals []Proposal
		for _, p := range offer {
			var transforms []Transform
			for _, name := range slices.Concat(p.ciphers, p.prfs, p.groups) {
				transforms = append(transforms, transformOf(name))
			}
			if p.none {
				transforms = append(transforms, Transform{Type: TransDH})
			}
			if !ike {
				transforms = append(transforms, esnNone)
			}
			if p.unknown {
				transforms = append(transforms, Transform{Type: TransformType(15), ID: 1})
			}
			proposals = append(proposals, Proposal{Transforms: transforms})
		}
		var keGroup, childGroupID uint16
		if ke != "" {
			keGroup = transformOf(ke).ID
		}
		if childGroup != "" {
			childGroupID = transformOf(childGroup).ID
		}
		cipher := transformOf(childCipher)
		s := answeringSession(ht, mux, SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: transformOf(prf).ID, DHGroup: transformOf(group).ID},
			ChildSA{EncrID: cipher.ID, EncrKeyBits: cipher.KeyLengthBits, LocalSPI: 21, RemoteSPI: 22}, childGroupID, suitesOf(ht, lists))
		answer := answerPeerRekey(ht, s, ike, peerRekeyOf(ht, s, ike, proposals, keGroup))
		var got answered
		switch {
		case answer.notify.Type == N_NO_PROPOSAL_CHOSEN:
			got.refused = true
		case answer.notify.Type == N_INVALID_KE_PAYLOAD:
			retry, _ := preferredGroupFromNotify(answer.notify)
			got.retry = transformName(Transform{Type: TransDH, ID: retry})
		case answer.notify.Type != 0:
			ht.Fatalf("the rekey was answered with notify %d", answer.notify.Type)
		default:
			got.number = int(answer.proposal.Number)
			for _, transform := range answer.proposal.Transforms {
				switch {
				case transform == Transform{Type: TransDH}:
					got.group = "none"
				case transform.Type == TransDH:
					got.group = transformName(transform)
				case transform.Type == TransEncr:
					got.cipher = transformName(transform)
				case transform.Type == TransPRF:
					got.prf = transformName(transform)
				}
			}
		}
		if got != want {
			ht.Fatalf("an offer of %+v with its KE payload in %q was answered %+v, want %+v", offer, ke, got, want)
		}
	})
}

// an IKE SA rekey this end starts offers its lists with the PRF the SA keeps, its KE payload in the SA's group while kex holds it and in kex's first otherwise
// it sends nothing once ike prf left out the SA's PRF
// and it takes an answer only in transforms its offer holds and in the group of its KE payload
// RFC 7296 section 3.3.6: "The initiator of an exchange MUST check that the accepted offer is consistent with one of its proposals, and if not MUST terminate the exchange."
func TestOwnIKESARekeyOffersTheListsAndTakesOnlyWhatTheyOffer(t *testing.T) {
	mux, _ := lifecycleMuxes(t)
	pbt.Check(t, func(ht *hegel.T) {
		lists := drawnCrypto(ht)
		ciphers, prfs, groups := written(lists.IKE.Cipher, everyCipher), written(lists.IKE.PRF, everyPRF), written(lists.IKE.Kex, everyKex)
		prf := hegel.Draw(ht, hegel.SampledFrom(everyPRF))
		group := hegel.Draw(ht, hegel.SampledFrom(everyKex))
		ctx := &ikeContext{suite: SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: transformOf(prf).ID, DHGroup: transformOf(group).ID},
			spiI: randUint64Nonzero(), spiR: randUint64Nonzero(), skD: make([]byte, 32), skei: make([]byte, 20), sker: make([]byte, 20)}
		// a kex list left out leads with x25519+mlkem768, whose rekey runs IKE_FOLLOWUP_KE after it, so a rekey here offers each classical key exchange alone in its place
		suites := suitesOf(ht, lists)
		if lists.IKE.Kex == nil {
			suites.kex = classicalLists.kex
		}
		s := &Session{mux: mux, current: ctx, requests: make(chan *localRequest, 1), suites: func() Suites { return suites }}
		done := make(chan error, 1)
		go func() { done <- s.RekeyIKE() }()
		next := func() *localRequest {
			select {
			case request := <-s.requests:
				return request
			case err := <-done:
				ht.Fatalf("the rekey ended with %v before its request", err)
			case <-time.After(answerBudget):
				ht.Fatal("the rekey sent nothing")
			}
			return nil
		}
		if !slices.Contains(prfs, prf) {
			select {
			case err := <-done:
				if !errors.Is(err, ErrPRFUnlisted) {
					ht.Fatalf("a rekey of an SA whose PRF ike prf left out ended with %v", err)
				}
			case request := <-s.requests:
				request.result <- requestResult{err: errors.New("nothing answers")}
				ht.Fatalf("a rekey of an SA whose PRF ike prf left out sent exchange %d", request.exchange)
			}
			return
		}
		request := next()
		sa, ke := findType(request.inner, PayloadSA), findType(request.inner, PayloadKE)
		if sa == nil || ke == nil {
			ht.Fatalf("the rekey request carried %v", request.inner)
		}
		keGroup := groups[0]
		if slices.Contains(groups, group) {
			keGroup = group
		}
		// RFC 7296 section 3.4: "SHOULD match the Diffie-Hellman group in the first group in the first proposal, if such exists."
		// one proposal for each group, numbered in that order
		proposals, err := DecodeSA(sa.Body)
		if err != nil || len(proposals) != len(groups) {
			ht.Fatalf("the rekey offered %+v, %v, want one proposal for each of %q", proposals, err, groups)
		}
		var gotOffer, wantOffer []string
		for i, offered := range ahead(groups, keGroup) {
			wantOffer = append(wantOffer, slices.Concat(ciphers, []string{prf, offered})...)
			if proposals[i].Number != uint8(i+1) {
				ht.Fatalf("proposal %d of the rekey offer is numbered %d", i+1, proposals[i].Number)
			}
			for _, transform := range proposals[i].Transforms {
				gotOffer = append(gotOffer, transformName(transform))
			}
		}
		if !slices.Equal(gotOffer, wantOffer) {
			ht.Fatalf("lists %+v offered %q to rekey an SA in %s and %s, want %q", lists, gotOffer, prf, group, wantOffer)
		}
		if got, _, err := DecodeKE(ke.Body); err != nil || transformName(Transform{Type: TransDH, ID: got}) != keGroup {
			ht.Fatalf("lists holding kex %q sent the KE payload of a rekey of an SA in %s in group %d, %v, want %s", groups, group, got, err, keGroup)
		}

		cipher := answerOf(ht, namedAll(ciphers), answerCiphers)
		answerPRF := answerOf(ht, []Transform{transformOf(prf)}, answerPRFs)
		// half the time the answer's SA payload names a group other than the KE payload this end sent
		others := namedAll(slices.DeleteFunc(slices.Clone(everyKex), func(name string) bool { return name == keGroup }))
		answerGroup := answerOf(ht, []Transform{transformOf(keGroup)}, others)
		// and apart from that, its KE payload names this end's group half the time, else its SA payload's or any
		answerKE := transformOf(keGroup)
		if hegel.Draw(ht, hegel.Booleans()) {
			answerKE = answerOf(ht, []Transform{answerGroup}, namedAll(everyKex))
		}
		// an answer as offered but in a cipher ike cipher left out, drawn outright
		if left := slices.DeleteFunc(slices.Clone(everyCipher), func(name string) bool { return slices.Contains(ciphers, name) }); len(left) > 0 && hegel.Draw(ht, pbt.Spanning(0, 3)) == 0 {
			cipher = transformOf(left[hegel.Draw(ht, pbt.Spanning(0, len(left)-1))])
			answerPRF, answerGroup, answerKE = transformOf(prf), transformOf(keGroup), transformOf(keGroup)
		}
		take := slices.Contains(proposals[0].Transforms, cipher) && answerPRF == transformOf(prf) && transformName(answerGroup) == keGroup && answerKE == answerGroup
		dh, err := GenerateDH(answerKE.ID)
		if err != nil {
			ht.Fatal(err)
		}
		request.result <- requestResult{inner: []RawPayload{
			{Type: PayloadSA, Body: EncodeSA([]Proposal{{Number: 1, Protocol: ProtoIKE, SPI: binary.BigEndian.AppendUint64(nil, randUint64Nonzero()),
				Transforms: []Transform{cipher, answerPRF, answerGroup}}})},
			{Type: PayloadNonce, Body: bytes.Repeat([]byte{1}, 32)},
			{Type: PayloadKE, Body: EncodeKE(answerKE.ID, dh.PublicBytes())},
		}}
		if take {
			// the Delete of the SA the rekey replaced
			next().result <- requestResult{}
		}
		select {
		case err := <-done:
			if took := err == nil; took != take {
				ht.Fatalf("an answer in %+v, %+v and %+v with its KE payload in %d to an offer of %q with its KE payload in %s ended the rekey with %v", cipher, answerPRF, answerGroup, answerKE.ID, gotOffer, keGroup, err)
			}
		case request := <-s.requests:
			request.result <- requestResult{err: errors.New("nothing answers")}
			ht.Fatalf("an answer in %+v, %+v and %+v to an offer of %q was followed by exchange %d", cipher, answerPRF, answerGroup, gotOffer, request.exchange)
		}
		if current, _ := s.contexts(); (current != ctx) != take {
			ht.Fatalf("an answer the rekey took is %v, and the session runs the SA it replaced is %v", take, current == ctx)
		}
	})
}

// an IKE SA rekey of an SA whose group kex holds only in an entry with additional key exchanges sends its KE payload in that group
// and offers that entry first, with the other entries after it
// RFC 7296 section 3.4: "This Diffie-Hellman Group Num MUST match a Diffie-Hellman group specified in a proposal in the SA payload that is sent in the same message, and SHOULD match the Diffie-Hellman group in the first group in the first proposal, if such exists."
// RFC 9370 section 2.2.4: "If the initiator includes any ADDKE Transform Types in the SA payload (along with Transform Type 4), and if the responder agrees to perform additional key exchanges, then the additional key exchanges are performed in a series of new IKE_FOLLOWUP_KE exchanges that follow the CREATE_CHILD_SA exchange."
func TestOwnIKESARekeyOfAGroupOnlyAJoinedEntryHoldsOffersThatEntryFirst(t *testing.T) {
	mux, _ := lifecycleMuxes(t)
	lists := Suites{kex: []kexEntry{{group: DH_CURVE25519, additions: [addkeTypes]uint16{ML_KEM_768}}, {group: DH_ECP_384}}}
	ctx := &ikeContext{suite: SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256, DHGroup: DH_CURVE25519},
		spiI: randUint64Nonzero(), spiR: randUint64Nonzero(), skD: make([]byte, 32), skei: make([]byte, 20), sker: make([]byte, 20)}
	s := &Session{mux: mux, current: ctx, requests: make(chan *localRequest, 1), suites: func() Suites { return lists }}
	done := make(chan error, 1)
	go func() { done <- s.RekeyIKE() }()
	var request *localRequest
	select {
	case request = <-s.requests:
	case err := <-done:
		t.Fatalf("the rekey ended with %v before its request", err)
	case <-time.After(answerBudget):
		t.Fatal("the rekey sent nothing")
	}
	sa, ke := findType(request.inner, PayloadSA), findType(request.inner, PayloadKE)
	request.result <- requestResult{err: errors.New("nothing answers")}
	<-done
	if sa == nil || ke == nil {
		t.Fatalf("the rekey request carried %v", request.inner)
	}
	if group, _, err := DecodeKE(ke.Body); err != nil || group != DH_CURVE25519 {
		t.Errorf("the KE payload is in group %d, %v, want %d", group, err, DH_CURVE25519)
	}
	proposals, err := DecodeSA(sa.Body)
	if err != nil || len(proposals) != 2 {
		t.Fatalf("the rekey offered %+v, %v, want one proposal for each entry", proposals, err)
	}
	if kex := kexOf(proposals[0]); !slices.Equal(kex, []Transform{dhX25519, {Type: TransADDKE1, ID: ML_KEM_768}}) {
		t.Errorf("proposal 1 offers the key exchanges %+v, want x25519 joined by ML-KEM-768", kex)
	}
	if kex := kexOf(proposals[1]); !slices.Equal(kex, []Transform{dhP384}) {
		t.Errorf("proposal 2 offers the key exchanges %+v, want p384 alone", kex)
	}
}

// an SA is unlisted once the lists leave out one of its transforms, a Child SA's group counting where a key exchange of its own keyed it
// and the IKE SA is replaced rather than rekeyed once they leave out its PRF
func TestUnlistedNamesEachSAOutsideTheLists(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		lists := drawnCrypto(ht)
		cipher := hegel.Draw(ht, hegel.SampledFrom(everyCipher))
		prf := hegel.Draw(ht, hegel.SampledFrom(everyPRF))
		group := hegel.Draw(ht, hegel.SampledFrom(everyKex))
		childCipher := hegel.Draw(ht, hegel.SampledFrom(everyCipher))
		childGroup := hegel.Draw(ht, hegel.SampledFrom(slices.Concat([]string{""}, everyKex)))
		haveChild := hegel.Draw(ht, hegel.WeightedBooleans(3.0/4))

		ikeOut := !slices.Contains(written(lists.IKE.Cipher, everyCipher), cipher) || !slices.Contains(written(lists.IKE.PRF, everyPRF), prf) ||
			!slices.Contains(written(lists.IKE.Kex, everyKex), group)
		var wantIKE, wantChild string
		if ikeOut {
			wantIKE = cipher + "/" + prf + "/" + group
		}
		if haveChild && (!slices.Contains(written(lists.ESP.Cipher, everyCipher), childCipher) || childGroup != "" && !slices.Contains(written(lists.IKE.Kex, everyKex), childGroup)) {
			wantChild = childCipher
			if childGroup != "" {
				wantChild += "/" + childGroup
			}
		}
		wantPRF := !slices.Contains(written(lists.IKE.PRF, everyPRF), prf)

		encr := transformOf(cipher)
		child := ChildSA{}
		var childGroupID uint16
		if haveChild {
			wire := transformOf(childCipher)
			child = ChildSA{EncrID: wire.ID, EncrKeyBits: wire.KeyLengthBits, LocalSPI: 21, RemoteSPI: 22}
			if childGroup != "" {
				childGroupID = transformOf(childGroup).ID
			}
		}
		suites := suitesOf(ht, lists)
		s := &Session{current: &ikeContext{suite: SASuite{EncrID: encr.ID, EncrKeyBits: encr.KeyLengthBits, PRFID: transformOf(prf).ID, DHGroup: transformOf(group).ID}},
			Child: child, childKex: keyedEntry{spi: child.LocalSPI, entry: kexEntry{group: childGroupID}}, suites: func() Suites { return suites }}
		gotChild, gotIKE, gotPRF := s.unlisted()
		if gotChild != wantChild || gotIKE != wantIKE || gotPRF != wantPRF {
			ht.Fatalf("lists %+v found the Child SA %q, the IKE SA %q and its PRF %v unlisted, want %q, %q and %v", lists, gotChild, gotIKE, gotPRF, wantChild, wantIKE, wantPRF)
		}
	})
}

// a reload rekeys each live SA holding a cipher or a group the lists left out, the IKE SA first, and replaces an IKE SA holding a PRF they left out
// and leaves an SA they hold every transform of
// the rekeyed SA runs what a peer listing every name answers the new offer with
func TestReloadRekeysOrReplacesWhatItLeftOut(t *testing.T) {
	bubble.Run(testReloadRekeysOrReplacesWhatItLeftOut)(t)
}

func testReloadRekeysOrReplacesWhatItLeftOut(t *testing.T) {
	h := newResponderHarness(t, nil)
	pbt.Check(t, func(ht *hegel.T) {
		before, after := drawnCrypto(ht), drawnCrypto(ht)
		dialed := &recorder{}
		var lists atomic.Pointer[Suites]
		first := suitesOf(ht, before)
		lists.Store(&first)
		cfg := h.peerConfig()
		cfg.Suites = func() Suites { return *lists.Load() }
		cfg.Events = dialed.record
		ctx, cancel := context.WithTimeout(context.Background(), answerBudget)
		var runs sync.WaitGroup
		defer runs.Wait()
		defer cancel()
		initiator, err := InitiateContext(ctx, cfg)
		if err != nil {
			ht.Fatalf("lists %+v failed the handshake: %v", before, err)
		}
		defer initiator.Mux().Close()
		var responder *Session
		select {
		case responder = <-h.sessions:
			<-h.identities
		case <-ctx.Done():
			ht.Fatal("the responder handed over no session")
		}
		defer responder.Mux().Close()
		initiatorRun := make(chan error, 1)
		runs.Go(func() { initiatorRun <- initiator.Run(ctx) })
		runs.Go(func() { _ = responder.Run(ctx) })
		// the responder lists every cipher and prf and each classical key exchange, so each SA runs the first of its order the dialing lists hold
		sa := Suite{
			IKECipher: firstShared(nil, before.IKE.Cipher, everyCipher), IKEPRF: firstShared(nil, before.IKE.PRF, everyPRF),
			IKEKex: firstShared(nil, before.IKE.Kex, everyKex), ESPCipher: firstShared(nil, before.ESP.Cipher, everyCipher),
		}
		// the initiator's Run answers a rekey the responder starts after the check Run makes when it starts
		if err := responder.RekeyChild(); err != nil {
			ht.Fatal(err)
		}
		next := suitesOf(ht, after)
		lists.Store(&next)
		gone, ended := settledRecheck(ht, initiator, initiatorRun)
		prfOut := !slices.Contains(written(after.IKE.PRF, everyPRF), sa.IKEPRF)
		ikeOut := !slices.Contains(written(after.IKE.Cipher, everyCipher), sa.IKECipher) || !slices.Contains(written(after.IKE.Kex, everyKex), sa.IKEKex)
		childOut := !slices.Contains(written(after.ESP.Cipher, everyCipher), sa.ESPCipher)
		var unlisted []string
		for _, line := range dialed.recorded() {
			if strings.HasPrefix(line, "ike.suite.unlisted ") {
				unlisted = append(unlisted, line)
			}
		}
		ikeLine := "ike.suite.unlisted " + dialedPair + " sa=ike suite=" + sa.IKE()
		switch {
		case prfOut:
			if !slices.Equal(unlisted, []string{ikeLine + " action=replace"}) {
				ht.Fatalf("a reload from %+v to %+v recorded %q, want the IKE SA replaced", before, after, unlisted)
			}
			if !gone {
				select {
				case ended = <-initiatorRun:
				case <-time.After(answerBudget):
					ht.Fatal("the session replacing its IKE SA did not end")
				}
			}
			if !errors.Is(ended, ErrPRFUnlisted) {
				ht.Fatalf("the session replacing its IKE SA ended with %v", ended)
			}
			return
		case gone:
			ht.Fatalf("a reload from %+v to %+v ended the session with %v", before, after, ended)
		case ikeOut:
			if len(unlisted) == 0 || unlisted[0] != ikeLine+" action=rekey" {
				ht.Fatalf("a reload from %+v to %+v recorded %q, want the IKE SA rekeyed", before, after, unlisted)
			}
			kex := sa.IKEKex
			if !slices.Contains(written(after.IKE.Kex, everyKex), kex) {
				kex = firstShared(nil, after.IKE.Kex, everyKex)
			}
			awaitRecorded(ht, dialed, "ike.rekey.completed "+dialedPair+" sa=ike suite="+firstShared(nil, after.IKE.Cipher, everyCipher)+"/"+sa.IKEPRF+"/"+kex)
		case childOut:
			if len(unlisted) == 0 || unlisted[0] != "ike.suite.unlisted "+dialedPair+" sa=child suite="+sa.ESPCipher+" action=rekey" {
				ht.Fatalf("a reload from %+v to %+v recorded %q, want the Child SA rekeyed", before, after, unlisted)
			}
		default:
			if len(unlisted) != 0 {
				ht.Fatalf("a reload from %+v to %+v holding every transform of the SAs recorded %q", before, after, unlisted)
			}
		}
		if childOut {
			childLine := "ike.suite.unlisted " + dialedPair + " sa=child suite=" + sa.ESPCipher + " action=rekey"
			// a check once the IKE SA's rekey ended marks the Child SA where the rekey's end has not
			if ikeOut {
				if gone, ended := settledRecheck(ht, initiator, initiatorRun); gone {
					ht.Fatalf("a reload from %+v to %+v ended the session with %v after the IKE SA's rekey", before, after, ended)
				}
			}
			if !slices.Contains(dialed.recorded(), childLine) {
				ht.Fatalf("a reload from %+v to %+v recorded %q, want the Child SA rekeyed", before, after, dialed.recorded())
			}
			awaitRecorded(ht, dialed, "ike.rekey.completed "+dialedPair+" sa=child suite="+firstShared(nil, after.ESP.Cipher, everyCipher))
		}
	})
}

// an initiator takes an IKE_SA_INIT answer only in transforms its offer holds and in the group of its KE payload, and refuses every other
// a Child SA answer it takes only in a cipher its offer holds, the cipher of the SA a rekey replaces alone while esp cipher holds it
// key lengths count, so an AES-GCM answer without one, one of a length the lists do not name, and a ChaCha20-Poly1305 answer with one are refused
// RFC 7296 section 3.3.6: "The initiator of an exchange MUST check that the accepted offer is consistent with one of its proposals, and if not MUST terminate the exchange."
func TestInitiatorTakesOnlyAnAnswerItsListsOffer(t *testing.T) {
	peer := listenPeer(t)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	_, local, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	remote, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pbt.Check(t, func(ht *hegel.T) {
		lists := drawnCrypto(ht)
		suites := suitesOf(ht, lists)

		old := transformOf(hegel.Draw(ht, hegel.SampledFrom(everyCipher)))
		rekey := hegel.Draw(ht, hegel.Booleans())
		esp := written(lists.ESP.Cipher, everyCipher)
		childOffer := suites.espProposal([]byte{0, 0, 0, 9})
		if rekey {
			childOffer = suites.espRekeyProposal([]byte{0, 0, 0, 9}, ChildSA{EncrID: old.ID, EncrKeyBits: old.KeyLengthBits})
			if slices.Contains(esp, transformName(old)) {
				esp = []string{transformName(old)}
			}
		}
		childAnswer := hegel.Draw(ht, hegel.SampledFrom(answerCiphers))
		_, encr, _, err := decodeChildProposal(EncodeSA([]Proposal{{Number: 1, Protocol: ProtoESP, SPI: []byte{0, 0, 0, 7}, Transforms: []Transform{childAnswer, esnNone}}}), childOffer.Transforms)
		if took := err == nil; took != slices.Contains(esp, transformName(childAnswer)) {
			ht.Fatalf("a Child SA answer in %+v to an offer of %q was taken as %+v, %v", childAnswer, esp, encr, err)
		}

		hub, err := testNetwork(t).NewHub()
		if err != nil {
			ht.Fatal(err)
		}
		defer hub.Close()
		ctx, cancel := context.WithTimeout(context.Background(), answerBudget)
		defer cancel()
		initiated := make(chan error, 1)
		go func() {
			session, err := InitiateContext(ctx, PeerConfig{
				Local: identity.MustParse("testorg/client:2"), LocalPrivateKey: local,
				Remote: identity.MustParse("testorg/server:1"), RemotePublicKey: remote,
				RemoteAddr: peerAddr.IP, RemotePort: peerAddr.Port, Hub: hub,
				Suites: func() Suites { return suites },
			})
			if err == nil {
				session.Mux().Close()
			}
			initiated <- err
		}()
		buf := make([]byte, 4096)
		// read is the next IKE request the initiator sends of exchange, false once the peer socket's deadline passed
		read := func(exchange ExchangeType) (*Message, *net.UDPAddr, bool) {
			for {
				n, from, err := peer.ReadFromUDP(buf)
				if err != nil {
					return nil, nil, false
				}
				if n <= NonESPMarkerLen {
					continue
				}
				if request, err := DecodeMessage(buf[NonESPMarkerLen:n]); err == nil && request.Header.ExchangeType == exchange && !request.Header.IsResponse() {
					return request, from, true
				}
			}
		}
		_ = peer.SetReadDeadline(time.Now().Add(answerBudget))
		request, from, ok := read(IKE_SA_INIT)
		if !ok {
			ht.Fatal("no IKE_SA_INIT request arrived")
		}
		offer := suites.ikeProposals(suites.kexEntries()[0].group)
		if sa := request.find(PayloadSA); sa == nil || !bytes.Equal(sa.Body, EncodeSA(offer)) {
			ht.Fatalf("the initiator offered %+v, want its lists", sa)
		}
		keGroup := transformOf(written(lists.IKE.Kex, everyKex)[0])
		cipher := answerOf(ht, namedAll(written(lists.IKE.Cipher, everyCipher)), answerCiphers)
		prf := answerOf(ht, namedAll(written(lists.IKE.PRF, everyPRF)), answerPRFs)
		group := answerOf(ht, []Transform{keGroup}, namedAll(everyKex))
		// the answer's KE payload may name another group than its SA payload
		answerKE := answerOf(ht, []Transform{keGroup}, namedAll(everyKex))
		// an answer as offered but in a cipher or PRF the lists left out, drawn outright
		ciphersLeft := slices.DeleteFunc(slices.Clone(everyCipher), func(name string) bool { return slices.Contains(written(lists.IKE.Cipher, everyCipher), name) })
		prfsLeft := slices.DeleteFunc(slices.Clone(everyPRF), func(name string) bool { return slices.Contains(written(lists.IKE.PRF, everyPRF), name) })
		if left := slices.Concat(ciphersLeft, prfsLeft); len(left) > 0 && hegel.Draw(ht, pbt.Spanning(0, 3)) == 0 {
			cipher, prf = transformOf(written(lists.IKE.Cipher, everyCipher)[0]), transformOf(written(lists.IKE.PRF, everyPRF)[0])
			if outside := transformOf(left[hegel.Draw(ht, pbt.Spanning(0, len(left)-1))]); outside.Type == TransEncr {
				cipher = outside
			} else {
				prf = outside
			}
			group, answerKE = keGroup, keGroup
		}
		// the answer names proposal 1, the one in the KE payload's group, and leaves out the ADDKE transform proposal 1 of a kex list left out holds
		take := slices.Contains(offer[0].Transforms, cipher) && slices.Contains(offer[0].Transforms, prf) && group == keGroup && answerKE == group &&
			!slices.ContainsFunc(offer[0].Transforms, func(t Transform) bool { return additional(t.Type) })
		dh, err := GenerateDH(answerKE.ID)
		if err != nil {
			ht.Fatal(err)
		}
		answer := (&Message{
			Header: Header{SPIInitiator: request.Header.SPIInitiator, SPIResponder: randUint64Nonzero(), ExchangeType: IKE_SA_INIT, Flags: FlagResponse},
			Payloads: []RawPayload{
				{Type: PayloadSA, Body: EncodeSA([]Proposal{{Number: 1, Protocol: ProtoIKE, Transforms: []Transform{cipher, prf, group}}})},
				{Type: PayloadKE, Body: EncodeKE(answerKE.ID, dh.PublicBytes())},
				{Type: PayloadNonce, Body: EncodeNonce(bytes.Repeat([]byte{7}, 32))},
				{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_SIGNATURE_HASH_ALGORITHMS, Data: binary.BigEndian.AppendUint16(nil, HashIdentity)})},
			},
		}).Encode()
		if _, err := peer.WriteToUDP(withNonESPMarker(answer), from); err != nil {
			ht.Fatal(err)
		}
		// an initiator that took the answer goes on to IKE_AUTH
		authed := make(chan bool, 1)
		go func() {
			_, _, ok := read(IKE_AUTH)
			authed <- ok
		}()
		var took bool
		select {
		case err := <-initiated:
			if err == nil {
				ht.Fatal("the initiator built a session from an answer nothing authenticated")
			}
			_ = peer.SetReadDeadline(time.Now())
			<-authed
		case took = <-authed:
			hub.Close()
			<-initiated
		}
		if took != take {
			ht.Fatalf("an answer in %+v, %+v and %+v with its KE payload in %d to an offer of %+v with its KE payload in %d was taken %v, want %v", cipher, prf, group, answerKE.ID, offer, keGroup.ID, took, take)
		}
	})
}
