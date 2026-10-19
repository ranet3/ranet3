// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ike

import (
	"slices"
	"testing"
)

// a peer's proposal whose ADDKE types each offer NONE, or that leaves one out, is answered with NONE written out for each type it holds
// in IKE_AUTH, in a rekey of the Child SA and in a rekey of an IKE SA whose key exchange ran alone
// one requiring an additional key exchange is skipped, since this end runs none there, and NO_PROPOSAL_CHOSEN answers an offer of nothing else
// RFC 7296 section 2.7: "The accepted cryptographic suite MUST contain exactly one transform of each type included in the proposal."
// RFC 9370 section 2.2.1: "The responder MUST treat all of the omitted ADDKE transforms as if they were proposed with Transform ID NONE."
func TestEachADDKETypeIsAnsweredNoneOrItsProposalIsSkipped(t *testing.T) {
	addke := func(t TransformType, ids ...uint16) []Transform {
		var transforms []Transform
		for _, id := range ids {
			transforms = append(transforms, Transform{Type: t, ID: id})
		}
		return transforms
	}
	for name, test := range map[string]struct {
		offered []Transform
		// want is the ADDKE transforms of the answer, nil for a proposal skipped
		want []Transform
	}{
		"ADDKE1 offering NONE alone":                      {addke(TransADDKE1, 0), addke(TransADDKE1, 0)},
		"ADDKE2 offering ML-KEM-768 or NONE, ADDKE5 NONE": {slices.Concat(addke(TransADDKE1+4, 0), addke(TransADDKE1+1, ML_KEM_768, 0)), slices.Concat(addke(TransADDKE1+1, 0), addke(TransADDKE1+4, 0))},
		"ADDKE7 offering NONE then ML-KEM-1024":           {addke(TransADDKE7, 0, ML_KEM_1024), addke(TransADDKE7, 0)},
		"ADDKE1 requiring ML-KEM-768":                     {addke(TransADDKE1, ML_KEM_768), nil},
		"ADDKE3 requiring one of two methods":             {addke(TransADDKE1+2, ML_KEM_768, ML_KEM_1024), nil},
	} {
		for _, exchange := range []struct {
			name string
			base []Transform
			// ike tells a rekey of the IKE SA from one of the Child SA, and auth IKE_AUTH from both
			ike, auth bool
		}{
			{name: "IKE_AUTH", base: []Transform{encrAES256, esnNone}, auth: true},
			{name: "a rekey of the Child SA", base: []Transform{encrAES128, esnNone}},
			{name: "a rekey of the IKE SA", base: []Transform{encrAES128, prfSHA256, dhX25519}, ike: true},
		} {
			t.Run(exchange.name+", "+name, func(t *testing.T) {
				// alone, and ahead of a proposal of the same transforms without the ADDKE types
				for _, beside := range []bool{false, true} {
					offer := []Proposal{{Transforms: slices.Concat(exchange.base, test.offered)}}
					if beside {
						offer = append(offer, Proposal{Transforms: slices.Clone(exchange.base)})
					}
					answer, refused := answerADDKEOffer(t, exchange.auth, exchange.ike, offer)
					switch {
					case test.want == nil && !beside:
						if refused != N_NO_PROPOSAL_CHOSEN {
							t.Errorf("an offer requiring an additional key exchange alone drew %+v and notify %d, want NO_PROPOSAL_CHOSEN", answer, refused)
						}
					case test.want == nil:
						if answer.Number != 2 || slices.ContainsFunc(answer.Transforms, func(transform Transform) bool { return additional(transform.Type) }) {
							t.Errorf("an offer requiring an additional key exchange ahead of one without was answered %+v (%d), want proposal 2 with no ADDKE type", answer, refused)
						}
					default:
						var got []Transform
						for _, transform := range answer.Transforms {
							if additional(transform.Type) {
								got = append(got, transform)
							}
						}
						if answer.Number != 1 || !slices.Equal(got, test.want) {
							t.Errorf("proposal 1 offering %+v was answered %+v (%d), want proposal 1 with %+v", test.offered, answer, refused, test.want)
						}
					}
				}
			})
		}
	}
}

// answerADDKEOffer has a responder answer an offer in IKE_AUTH where auth holds, or in a peer's rekey of the IKE SA or the Child SA
// it returns the proposal of the answer, or the notify it refused with
func answerADDKEOffer(t *testing.T, auth, ike bool, offer []Proposal) (Proposal, NotifyType) {
	t.Helper()
	if auth {
		h := newResponderHarness(t, nil)
		for i := range offer {
			offer[i].Number, offer[i].Protocol, offer[i].SPI = uint8(i+1), ProtoESP, []byte{0, 0, 0, byte(9 + i)}
		}
		inner, _ := answerIKEAuth(t, h, Suites{}, offer...)
		sa := findType(inner, PayloadSA)
		if sa == nil {
			return Proposal{}, notifyIn(t, inner)
		}
		proposals, err := DecodeSA(sa.Body)
		if err != nil || len(proposals) != 1 {
			t.Fatalf("the answer's SA payload holds %+v, %v", proposals, err)
		}
		return proposals[0], 0
	}
	mux, _ := lifecycleMuxes(t)
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256, DHGroup: DH_CURVE25519}
	s := answeringSession(t, mux, suite, ChildSA{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, LocalSPI: 21, RemoteSPI: 22}, 0, Suites{})
	var keGroup uint16
	if ike {
		keGroup = DH_CURVE25519
	}
	answer := answerPeerRekey(t, s, ike, peerRekeyOf(t, s, ike, offer, keGroup))
	return answer.proposal, answer.notify.Type
}

// hybrid is the kex list x25519+mlkem768, p256
var hybrid = Suites{kex: []kexEntry{{group: DH_CURVE25519, additions: [addkeTypes]uint16{ML_KEM_768}}, {group: DH_ECP_256}}}

// kexOf is the key exchange transforms of a proposal in the order it holds them
func kexOf(proposal Proposal) []Transform {
	return slices.DeleteFunc(slices.Clone(proposal.Transforms), func(t Transform) bool { return t.Type != TransDH && !additional(t.Type) })
}

// a CREATE_CHILD_SA runs the entries of one key exchange alone, since this end runs no IKE_FOLLOWUP_KE
// so its own IKE SA rekey offers those, and a peer's rekey or new Child SA requiring an additional key exchange is refused though kex lists the entry
// RFC 9370 section 2.2.4: "If the initiator includes any ADDKE Transform Types in the SA payload (along with Transform Type 4), and if the responder agrees to perform additional key exchanges, then the additional key exchanges are performed in a series of new IKE_FOLLOWUP_KE exchanges that follow the CREATE_CHILD_SA exchange."
func TestRekeyRunsOnlyEntriesOfOneKeyExchange(t *testing.T) {
	offer := hybrid.ikeRekeyProposals([]byte{1, 2, 3, 4, 5, 6, 7, 8}, PRF_HMAC_SHA2_256, DH_ECP_256)
	if len(offer) != 1 || !slices.Equal(kexOf(offer[0]), []Transform{{Type: TransDH, ID: DH_ECP_256}}) {
		t.Errorf("the rekey offer of x25519+mlkem768 and p256 is %+v, want p256 alone", offer)
	}
	mux, _ := lifecycleMuxes(t)
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256, DHGroup: DH_ECP_256}
	s := answeringSession(t, mux, suite, ChildSA{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, LocalSPI: 21, RemoteSPI: 22}, 0, hybrid)
	requiring := []Proposal{{Transforms: []Transform{encrAES128, prfSHA256, dhX25519, {Type: TransADDKE1, ID: ML_KEM_768}}}}
	if answer := answerPeerRekey(t, s, true, peerRekeyOf(t, s, true, requiring, DH_CURVE25519)); answer.notify.Type != N_NO_PROPOSAL_CHOSEN {
		t.Errorf("a peer's rekey requiring x25519+mlkem768 was answered %+v, want NO_PROPOSAL_CHOSEN", answer)
	}
	// a peer's request for the Child SA a session has none of is a rekey's request without REKEY_SA
	fresh := answeringSession(t, mux, suite, ChildSA{}, 0, hybrid)
	requiring = []Proposal{{Transforms: []Transform{encrAES128, esnNone, dhX25519, {Type: TransADDKE1, ID: ML_KEM_768}}}}
	if answer := answerPeerRekey(t, fresh, false, peerRekeyOf(t, fresh, false, requiring, DH_CURVE25519)[1:]); answer.notify.Type != N_NO_PROPOSAL_CHOSEN {
		t.Errorf("a peer's request for a Child SA requiring x25519+mlkem768 was answered %+v, want NO_PROPOSAL_CHOSEN", answer)
	}
}

// an IKE SA is listed while kex holds its whole entry, and a reload changing any part of an entry changes the list
func TestEntriesAreComparedWhole(t *testing.T) {
	classical := Suites{kex: []kexEntry{{group: DH_CURVE25519}, {group: DH_ECP_256}}}
	if got := hybrid.Changed(classical); !slices.Equal(got, []string{"cap.crypto.ike.kex"}) {
		t.Errorf("dropping mlkem768 from x25519+mlkem768 changed %q", got)
	}
	keyed := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 256, PRFID: PRF_HMAC_SHA2_384, DHGroup: DH_CURVE25519, Additions: [addkeTypes]uint16{ML_KEM_768}}
	if !hybrid.holdsIKE(keyed) || classical.holdsIKE(keyed) {
		t.Errorf("an IKE SA of x25519+mlkem768 is held by x25519+mlkem768 %v and by x25519 %v, want true and false", hybrid.holdsIKE(keyed), classical.holdsIKE(keyed))
	}
	keyed.Additions = [addkeTypes]uint16{}
	if hybrid.holdsIKE(keyed) || !classical.holdsIKE(keyed) {
		t.Errorf("an IKE SA of x25519 is held by x25519+mlkem768 %v and by x25519 %v, want false and true", hybrid.holdsIKE(keyed), classical.holdsIKE(keyed))
	}
	// a Child SA's own key exchange is the entry of its group alone
	child := ChildSA{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, LocalSPI: 1}
	if hybrid.holdsChild(child, DH_CURVE25519) || !hybrid.holdsChild(child, DH_ECP_256) {
		t.Errorf("a Child SA keyed in x25519 is held by x25519+mlkem768 %v, one in p256 by p256 %v, want false and true",
			hybrid.holdsChild(child, DH_CURVE25519), hybrid.holdsChild(child, DH_ECP_256))
	}
}

// the responder answers its first kex entry a proposal meets, from the first proposal meeting it, after R304
// the entry's methods sit in the earliest ADDKE types offering them in order, each other type the proposal holds answered NONE, and a type left out counts as NONE
// RFC 9370 section 2.2.1: "The responder MUST treat all of the omitted ADDKE transforms as if they were proposed with Transform ID NONE."
func TestIKEAnswerRunsTheFirstEntryMetInTheEarliestTypes(t *testing.T) {
	type offered struct {
		at  TransformType
		ids []uint16
	}
	proposal := func(group uint16, types ...offered) Proposal {
		transforms := []Transform{encrAES256, prfSHA256, {Type: TransDH, ID: group}}
		for _, of := range types {
			for _, id := range of.ids {
				transforms = append(transforms, Transform{Type: of.at, ID: id})
			}
		}
		return Proposal{Protocol: ProtoIKE, Transforms: transforms}
	}
	hybrid768 := kexEntry{group: DH_CURVE25519, additions: [addkeTypes]uint16{ML_KEM_768}}
	both := kexEntry{group: DH_CURVE25519, additions: [addkeTypes]uint16{ML_KEM_768, ML_KEM_1024}}
	x25519, p256 := kexEntry{group: DH_CURVE25519}, kexEntry{group: DH_ECP_256}
	for name, test := range map[string]struct {
		entries []kexEntry
		offer   []Proposal
		// number is the proposal answered, kex the key exchange transforms of the answer and entry the suite's
		number uint8
		kex    []Transform
		entry  kexEntry
	}{
		"two types offering ML-KEM-768 or NONE": {
			[]kexEntry{hybrid768}, []Proposal{proposal(DH_CURVE25519, offered{TransADDKE1, []uint16{ML_KEM_768, 0}}, offered{TransADDKE1 + 1, []uint16{ML_KEM_768, 0}})},
			1, []Transform{dhX25519, {Type: TransADDKE1, ID: ML_KEM_768}, {Type: TransADDKE1 + 1, ID: 0}}, hybrid768,
		},
		"ML-KEM-768 in ADDKE3 with the types before it left out": {
			[]kexEntry{hybrid768}, []Proposal{proposal(DH_CURVE25519, offered{TransADDKE1 + 2, []uint16{ML_KEM_768}})},
			1, []Transform{dhX25519, {Type: TransADDKE1 + 2, ID: ML_KEM_768}}, hybrid768,
		},
		"NONE alone ahead of the type offering ML-KEM-768": {
			[]kexEntry{hybrid768}, []Proposal{proposal(DH_CURVE25519, offered{TransADDKE1, []uint16{0}}, offered{TransADDKE1 + 1, []uint16{ML_KEM_768}})},
			1, []Transform{dhX25519, {Type: TransADDKE1, ID: 0}, {Type: TransADDKE1 + 1, ID: ML_KEM_768}}, hybrid768,
		},
		"two methods over two types offering both": {
			[]kexEntry{both}, []Proposal{proposal(DH_CURVE25519, offered{TransADDKE1, []uint16{ML_KEM_1024, ML_KEM_768}}, offered{TransADDKE1 + 1, []uint16{ML_KEM_1024, ML_KEM_768}})},
			1, []Transform{dhX25519, {Type: TransADDKE1, ID: ML_KEM_768}, {Type: TransADDKE1 + 1, ID: ML_KEM_1024}}, both,
		},
		"the first entry in a later proposal": {
			[]kexEntry{hybrid768, p256}, []Proposal{proposal(DH_ECP_256), proposal(DH_CURVE25519, offered{TransADDKE1, []uint16{ML_KEM_768}})},
			2, []Transform{dhX25519, {Type: TransADDKE1, ID: ML_KEM_768}}, hybrid768,
		},
		"a proposal without the method meeting the next entry": {
			[]kexEntry{hybrid768, x25519}, []Proposal{proposal(DH_CURVE25519)},
			1, []Transform{dhX25519}, x25519,
		},
	} {
		t.Run(name, func(t *testing.T) {
			for i := range test.offer {
				test.offer[i].Number = uint8(i + 1)
			}
			chosen, retry, ok := chooseIKE(test.offer, []Transform{encrAES256}, []Transform{prfSHA256}, test.entries, DH_CURVE25519)
			var kex []Transform
			for _, transform := range chosen.transforms {
				if transform.Type == TransDH || additional(transform.Type) {
					kex = append(kex, transform)
				}
			}
			if !ok || chosen.offered.Number != test.number || !slices.Equal(kex, test.kex) || chosen.suite.entry() != test.entry {
				t.Errorf("answered proposal %d with %+v into %+v (%v, group %d), want proposal %d with %+v into %+v",
					chosen.offered.Number, kex, chosen.suite.entry(), ok, retry, test.number, test.kex, test.entry)
			}
		})
	}
	// IKE_SA_INIT reads the ADDKE types of a request carrying INTERMEDIATE_EXCHANGE_SUPPORTED, and skips the proposal holding one in a request without
	// RFC 9370 section 2.2.1: "If the IKE_INTERMEDIATE exchange is not negotiated, then the peers MUST treat any ADDKE Transform Types in the IKE_SA_INIT exchange messages as unknown transform types and skip the proposals they appear in."
	t.Run("IKE_SA_INIT", func(t *testing.T) {
		offer := []Proposal{proposal(DH_CURVE25519, offered{TransADDKE1, []uint16{ML_KEM_768}}), proposal(DH_CURVE25519)}
		for i := range offer {
			offer[i].Number = uint8(i + 1)
		}
		lists := Suites{ikeCipher: []Transform{encrAES256}, ikePRF: []Transform{prfSHA256}, kex: []kexEntry{hybrid768, x25519}}
		for _, test := range []struct {
			intermediate bool
			number       uint8
			entry        kexEntry
		}{{false, 2, x25519}, {true, 1, hybrid768}} {
			selected, suite, err := selectIKEProposal(EncodeSA(offer), DH_CURVE25519, lists, test.intermediate)
			if err != nil || selected.Number != test.number || suite.entry() != test.entry {
				t.Errorf("with the notify %v answered proposal %d into %+v (%v), want proposal %d into %+v", test.intermediate, selected.Number, suite.entry(), err, test.number, test.entry)
			}
		}
	})
}
