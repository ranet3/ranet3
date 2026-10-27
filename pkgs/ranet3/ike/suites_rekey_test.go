// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ike

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/internal/bubble"
	"ranet3.com/pkgs/ranet3/transport"
)

var dhP384 = Transform{Type: TransDH, ID: DH_ECP_384}

// answeringSession is a session answering rekeys of an IKE SA in suite and of child, keyed in group, under lists
func answeringSession(t testing.TB, mux *transport.Mux, suite SASuite, child ChildSA, group uint16, lists Suites) *Session {
	t.Helper()
	ctx := &ikeContext{suite: suite, spiI: randUint64Nonzero(), spiR: randUint64Nonzero(), skD: bytes.Repeat([]byte{1}, 32),
		skei: bytes.Repeat([]byte{2}, 20), sker: bytes.Repeat([]byte{3}, 20), responder: true}
	s := &Session{mux: mux, current: ctx, Child: child, childKex: keyedEntry{spi: child.LocalSPI, entry: kexEntry{group: group}},
		suites: func() Suites { return lists }, rechecks: make(chan struct{}, 1), started: time.Now()}
	s.SetChildHandler(func(ChildSA) error { return nil })
	return s
}

// rekeyAnswer is how a session answered a peer's rekey, the notify it refused with or the proposal it took
type rekeyAnswer struct {
	notify   Notify
	proposal Proposal
}

// peerRekeyOf is a peer's rekey of s's IKE SA, or of its Child SA where ike is false, offering proposals with its KE payload in keGroup, zero for none
func peerRekeyOf(t testing.TB, s *Session, ike bool, proposals []Proposal, keGroup uint16) []RawPayload {
	t.Helper()
	for i := range proposals {
		proposals[i].Number = uint8(i + 1)
		proposals[i].Protocol = ProtoESP
		proposals[i].SPI = binary.BigEndian.AppendUint32(nil, randUint32Nonzero())
		if ike {
			proposals[i].Protocol = ProtoIKE
			proposals[i].SPI = binary.BigEndian.AppendUint64(nil, randUint64Nonzero())
		}
	}
	request := []RawPayload{
		{Type: PayloadSA, Body: EncodeSA(proposals)},
		{Type: PayloadNonce, Body: EncodeNonce(bytes.Repeat([]byte{4}, 32))},
	}
	if !ike {
		request = append([]RawPayload{{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_REKEY_SA, Protocol: ProtoESP, SPI: binary.BigEndian.AppendUint32(nil, s.Child.RemoteSPI)})}}, request...)
		request = append(request, RawPayload{Type: PayloadTSi, Body: fullRangeSelectors()}, RawPayload{Type: PayloadTSr, Body: fullRangeSelectors()})
	}
	if keGroup != 0 {
		dh, err := GenerateDH(keGroup)
		if err != nil {
			t.Fatal(err)
		}
		request = append(request, RawPayload{Type: PayloadKE, Body: EncodeKE(keGroup, dh.PublicBytes())})
	}
	return request
}

// answerPeerRekey hands request to s's rekey handler for the IKE SA, or the Child SA where ike is false, and reads the answer
func answerPeerRekey(t testing.TB, s *Session, ike bool, request []RawPayload) rekeyAnswer {
	t.Helper()
	ctx := s.current
	handle := s.handleChildRekey
	if ike {
		handle = s.handleIKERekey
	}
	raw, err := handle(ctx, 0, request)
	if err != nil {
		t.Fatal(err)
	}
	answer := sealedAnswer(t, ctx, raw.whole)
	if sa := findType(answer, PayloadSA); sa != nil {
		proposals, err := DecodeSA(sa.Body)
		if err != nil || len(proposals) != 1 {
			t.Fatalf("the answer's SA payload holds %+v, %v", proposals, err)
		}
		return rekeyAnswer{proposal: proposals[0]}
	}
	payload := findType(answer, PayloadN)
	if payload == nil {
		t.Fatalf("the answer holds neither an SA nor a notify: %v", answer)
	}
	notify, err := DecodeNotify(payload.Body)
	if err != nil {
		t.Fatal(err)
	}
	return rekeyAnswer{notify: notify}
}

// recheck has s check its SAs against the lists in force and returns once it has, or once its Run ended with how it ended
// Run takes one check at a time, so a second is taken only once the first is done
func recheck(t testing.TB, s *Session, run <-chan error) (bool, error) {
	t.Helper()
	for range 2 {
		s.SuitesChanged()
		var ended bool
		var err error
		if !waitUntil(func() bool {
			select {
			case err = <-run:
				ended = true
				return true
			default:
				return len(s.rechecks) == 0
			}
		}) {
			t.Fatal("the session never checked its SAs")
		}
		if ended {
			return true, err
		}
	}
	return false, nil
}

// settledRecheck is recheck for a test in a bubble
// s.rechecks empties once Run takes the check, before Run runs it, so each look first waits for every other goroutine of the bubble to block
func settledRecheck(t testing.TB, s *Session, run <-chan error) (bool, error) {
	t.Helper()
	s.SuitesChanged()
	var ended bool
	var err error
	if !waitUntil(func() bool {
		synctest.Wait()
		select {
		case err = <-run:
			ended = true
			return true
		default:
			return len(s.rechecks) == 0
		}
	}) {
		t.Fatal("the session never checked its SAs")
	}
	return ended, err
}

// groupIn is the Diffie-Hellman transform of an answered proposal, the zero Transform where it holds none
func groupIn(p Proposal) Transform {
	for _, transform := range p.Transforms {
		if transform.Type == TransDH {
			return transform
		}
	}
	return Transform{}
}

// an offer is answered in the first group of this end's kex list that any proposal its lists meet holds
// and the first proposal holding that group decides the other transforms
// a KE payload in another group draws INVALID_KE_PAYLOAD naming that group, though a later proposal holds the KE payload's group
// so IKE_SA_INIT, an IKE SA rekey and a Child SA rekey with a KE payload each follow this end's order across proposals
// RFC 7296 section 1.3: "If the responder selects a proposal using a different Diffie-Hellman group (other than NONE), the responder MUST reject the request and indicate its preferred Diffie-Hellman group in the INVALID_KE_PAYLOAD Notify payload."
func TestOfferIsAnsweredInTheFirstListedGroupAnyProposalHolds(t *testing.T) {
	cases := []struct {
		name string
		// each proposal's ciphers and groups
		proposals [][]Transform
		ke        uint16
		// retry is the group INVALID_KE_PAYLOAD names, zero where the offer is answered
		retry  uint16
		number uint8
		cipher Transform
	}{
		{"a KE payload in a group this end lists after a later proposal's", [][]Transform{{encrAES256, dhP256}, {encrAES256, dhX25519}}, DH_ECP_256, DH_CURVE25519, 0, Transform{}},
		{"a KE payload in the group of a later proposal this end lists first", [][]Transform{{encrAES256, dhP256}, {encrAES256, dhX25519}}, DH_CURVE25519, 0, 2, encrAES256},
		{"proposals holding the same group", [][]Transform{{encrAES128, dhX25519}, {encrAES256, dhX25519}}, DH_CURVE25519, 0, 1, encrAES128},
		{"a proposal holding two ciphers", [][]Transform{{encrChaCha, encrAES256, dhP384, dhX25519}}, DH_CURVE25519, 0, 1, encrAES256},
	}
	with := func(transforms []Transform, more ...Transform) []Transform {
		return slices.Concat(transforms, more)
	}
	t.Run("at IKE_SA_INIT", func(t *testing.T) {
		for _, test := range cases {
			var proposals []Proposal
			for i, transforms := range test.proposals {
				proposals = append(proposals, Proposal{Number: uint8(i + 1), Protocol: ProtoIKE, Transforms: with(transforms, prfSHA384)})
			}
			selected, suite, err := selectIKEProposal(EncodeSA(proposals), test.ke, Suites{}, false)
			if test.retry != 0 {
				if wrong, ok := errors.AsType[*invalidKEError](err); !ok || wrong.group != test.retry {
					t.Errorf("%s: answered %+v, %v, want INVALID_KE_PAYLOAD naming %d", test.name, selected, err, test.retry)
				}
				continue
			}
			if err != nil || selected.Number != test.number || suite.DHGroup != test.ke || !slices.Contains(selected.Transforms, test.cipher) {
				t.Errorf("%s: answered %+v, %v, want proposal %d in %+v and group %d", test.name, selected, err, test.number, test.cipher, test.ke)
			}
		}
	})
	mux, _ := lifecycleMuxes(t)
	for _, ike := range []bool{true, false} {
		site := "at a Child SA rekey"
		if ike {
			site = "at an IKE SA rekey"
		}
		t.Run(site, func(t *testing.T) {
			for _, test := range cases {
				// neither SA was keyed in a group the cases name, so no answer keeps a group
				s := answeringSession(t, mux, SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256, DHGroup: 14},
					ChildSA{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 192, LocalSPI: 21, RemoteSPI: 22}, 0, Suites{})
				var proposals []Proposal
				for _, transforms := range test.proposals {
					more := esnNone
					if ike {
						more = prfSHA256
					}
					proposals = append(proposals, Proposal{Transforms: with(transforms, more)})
				}
				answer := answerPeerRekey(t, s, ike, peerRekeyOf(t, s, ike, proposals, test.ke))
				if test.retry != 0 {
					if group, ok := preferredGroupFromNotify(answer.notify); !ok || group != test.retry {
						t.Errorf("%s: answered %+v, want INVALID_KE_PAYLOAD naming %d", test.name, answer, test.retry)
					}
					continue
				}
				want := test.cipher
				if want.ID == ENCR_CHACHA20_POLY1305 {
					want.KeyLengthBits = 0
				}
				if answer.proposal.Number != test.number || groupIn(answer.proposal).ID != test.ke || !slices.Contains(answer.proposal.Transforms, want) {
					t.Errorf("%s: answered %+v, want proposal %d in %+v and group %d", test.name, answer, test.number, want, test.ke)
				}
			}
		})
	}
}

// a peer's Child SA rekey without a KE payload is answered in a proposal offering NONE or no group, though an earlier proposal offers only groups
// and one whose proposals offer only groups draws INVALID_KE_PAYLOAD naming the first group of kex they hold
// RFC 7296 section 1.3: "The CREATE_CHILD_SA request MAY optionally contain a KE payload for an additional Diffie-Hellman exchange to enable stronger guarantees of forward secrecy for the Child SA."
func TestChildSARekeyWithoutAKEPayloadTakesAProposalWithoutAGroup(t *testing.T) {
	mux, _ := lifecycleMuxes(t)
	grouped := []Transform{encrAES128, dhP256, dhX25519, esnNone}
	for _, test := range []struct {
		name      string
		proposals [][]Transform
		// retry is the group INVALID_KE_PAYLOAD names, zero where the offer is answered
		retry  uint16
		number uint8
		dh     Transform
	}{
		{"a proposal offering only groups before one offering NONE", [][]Transform{grouped, {encrAES128, {Type: TransDH}, esnNone}}, 0, 2, Transform{Type: TransDH}},
		{"a proposal offering only groups before one offering no group", [][]Transform{grouped, {encrAES128, esnNone}}, 0, 2, Transform{}},
		{"proposals offering only groups", [][]Transform{grouped}, DH_CURVE25519, 0, Transform{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := answeringSession(t, mux, SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256, DHGroup: DH_CURVE25519},
				ChildSA{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, LocalSPI: 21, RemoteSPI: 22}, 0, Suites{})
			var proposals []Proposal
			for _, transforms := range test.proposals {
				proposals = append(proposals, Proposal{Transforms: transforms})
			}
			answer := answerPeerRekey(t, s, false, peerRekeyOf(t, s, false, proposals, 0))
			if test.retry != 0 {
				if group, ok := preferredGroupFromNotify(answer.notify); !ok || group != test.retry {
					t.Errorf("answered %+v, want INVALID_KE_PAYLOAD naming %d", answer, test.retry)
				}
				return
			}
			if answer.proposal.Number != test.number || groupIn(answer.proposal) != test.dh {
				t.Errorf("answered %+v, want proposal %d in %+v", answer, test.number, test.dh)
			}
		})
	}
}

// an IKE proposal whose SPI is not the size its exchange gives is unacceptable, and a proposal after it is answered
// RFC 7296 section 3.3.1: "For an initial IKE SA negotiation, this field MUST be zero"
// RFC 7296 section 3.3.1: "it is equal to the size, in octets, of the SPI of the corresponding protocol (8 for IKE, 4 for ESP and AH)."
func TestIKEProposalWithAnSPIOfAnotherSizeIsUnacceptable(t *testing.T) {
	transforms := []Transform{encrAES256, prfSHA384, dhX25519}
	t.Run("at IKE_SA_INIT", func(t *testing.T) {
		withSPI := Proposal{Number: 1, Protocol: ProtoIKE, SPI: bytes.Repeat([]byte{5}, 8), Transforms: transforms}
		if selected, _, err := selectIKEProposal(EncodeSA([]Proposal{withSPI}), DH_CURVE25519, Suites{}, false); err == nil {
			t.Errorf("a proposal with an SPI was answered %+v", selected)
		}
		plain := Proposal{Number: 2, Protocol: ProtoIKE, Transforms: transforms}
		if selected, _, err := selectIKEProposal(EncodeSA([]Proposal{withSPI, plain}), DH_CURVE25519, Suites{}, false); err != nil || selected.Number != 2 {
			t.Errorf("a proposal with an SPI before one without was answered %+v, %v, want proposal 2", selected, err)
		}
	})
	t.Run("at an IKE SA rekey", func(t *testing.T) {
		mux, _ := lifecycleMuxes(t)
		for name, sizes := range map[string][]int{
			"a proposal with a 4-octet SPI alone":          {4},
			"a proposal with a 4-octet SPI before another": {4, 8},
		} {
			s := answeringSession(t, mux, SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_384, DHGroup: DH_CURVE25519},
				ChildSA{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, LocalSPI: 21, RemoteSPI: 22}, 0, Suites{})
			proposals := make([]Proposal, len(sizes))
			for i := range proposals {
				proposals[i].Transforms = transforms
			}
			request := peerRekeyOf(t, s, true, proposals, DH_CURVE25519)
			for i, size := range sizes {
				proposals[i].SPI = bytes.Repeat([]byte{byte(i + 6)}, size)
			}
			request[0].Body = EncodeSA(proposals)
			answer := answerPeerRekey(t, s, true, request)
			want := uint8(len(sizes))
			if len(sizes) == 1 {
				want = 0
			}
			if answer.proposal.Number != want || want == 0 && answer.notify.Type != N_NO_PROPOSAL_CHOSEN {
				t.Errorf("%s: answered %+v, want proposal %d", name, answer, want)
			}
		}
	})
}

// a peer's rekey whose KE payload is in the group of the SA it replaces is answered in that group while the offer and kex hold it
// though kex lists another group the offer holds first
// one whose KE payload is in another group, or of an SA in a group kex left out, is answered in kex's order
// a Child SA keeps its cipher alongside, and one keyed from SK_d alone has no group to keep
// RFC 7296 section 2.8: "Note that, when rekeying, the new Child SA SHOULD NOT have different Traffic Selectors and algorithms than the old one."
func TestPeerRekeyKeepsTheGroupOfTheSAItReplaces(t *testing.T) {
	mux, _ := lifecycleMuxes(t)
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256, DHGroup: DH_ECP_256}
	child := ChildSA{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, LocalSPI: 21, RemoteSPI: 22}
	withoutP256 := suitesOf(t, Crypto{IKE: IKESuites{Kex: []string{"x25519", "p384"}}})
	for _, test := range []struct {
		name  string
		ike   bool
		group uint16
		lists Suites
		ke    uint16
		// retry is the group INVALID_KE_PAYLOAD names, zero where the rekey is answered in the KE payload's group
		retry uint16
	}{
		{"an IKE SA rekey in the SA's group", true, DH_ECP_256, Suites{}, DH_ECP_256, 0},
		{"an IKE SA rekey in a group this end lists first", true, DH_ECP_256, Suites{}, DH_CURVE25519, 0},
		{"an IKE SA rekey in a group this end lists after another the offer holds", true, DH_ECP_256, Suites{}, DH_ECP_384, DH_CURVE25519},
		{"an IKE SA rekey in the SA's group kex left out", true, DH_ECP_256, withoutP256, DH_ECP_256, DH_CURVE25519},
		{"a Child SA rekey in the SA's group", false, DH_ECP_256, Suites{}, DH_ECP_256, 0},
		{"a Child SA rekey in the SA's group kex left out", false, DH_ECP_256, withoutP256, DH_ECP_256, DH_CURVE25519},
		{"a Child SA rekey of an SA SK_d alone keyed", false, 0, Suites{}, DH_ECP_256, DH_CURVE25519},
	} {
		s := answeringSession(t, mux, suite, child, test.group, test.lists)
		kind := esnNone
		if test.ike {
			kind = prfSHA256
		}
		offer := []Proposal{{Transforms: []Transform{encrAES256, encrAES128, kind, dhX25519, dhP384, dhP256}}}
		answer := answerPeerRekey(t, s, test.ike, peerRekeyOf(t, s, test.ike, offer, test.ke))
		if test.retry != 0 {
			if group, ok := preferredGroupFromNotify(answer.notify); !ok || group != test.retry {
				t.Errorf("%s: answered %+v, want INVALID_KE_PAYLOAD naming %d", test.name, answer, test.retry)
			}
			continue
		}
		if got := groupIn(answer.proposal); got.ID != test.ke {
			t.Errorf("%s: answered %+v, want the group %d", test.name, answer, test.ke)
		}
		if !test.ike && !slices.Contains(answer.proposal.Transforms, encrAES128) {
			t.Errorf("%s: answered %+v, want the cipher of the SA it replaces", test.name, answer.proposal)
		}
	}
}

// a peer's IKE SA rekey offering two listed ciphers is answered in the one this end lists first
// RFC 7296 section 2.7: "The responder MUST choose a single suite, which may be any subset of the SA proposal following the rules below."
func TestPeerIKESARekeyIsAnsweredInThisEndsCipherOrder(t *testing.T) {
	mux, _ := lifecycleMuxes(t)
	lists := suitesOf(t, Crypto{IKE: IKESuites{Cipher: []string{"aes256gcm", "chacha20poly1305"}}})
	s := answeringSession(t, mux, SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256, DHGroup: DH_CURVE25519},
		ChildSA{}, 0, lists)
	answer := answerPeerRekey(t, s, true, peerRekeyOf(t, s, true, []Proposal{{Transforms: []Transform{encrChaCha, encrAES256, prfSHA256, dhX25519}}}, DH_CURVE25519))
	if !slices.Contains(answer.proposal.Transforms, encrAES256) {
		t.Errorf("the rekey was answered %+v, want this end's first cipher", answer)
	}
}

// two ends whose kex lists order the groups differently rekey their IKE SA from either end in one exchange each
// and the SA keeps the group its handshake settled
func TestRekeysBetweenEndsOrderingTheGroupsDifferentlyKeepTheGroup(t *testing.T) {
	h := newResponderHarness(t, nil)
	answering := suitesOf(t, Crypto{IKE: IKESuites{Kex: []string{"p256", "x25519"}}})
	h.lists.Store(&answering)
	// each IKE SA numbers its messages from zero
	type request struct {
		fromInitiator bool
		spi           uint64
		mid           uint32
	}
	var mu sync.Mutex
	seen := map[request]bool{}
	sent := map[bool]int{}
	cfg, _ := listedConfig(h, nil)
	initiator, responder, _, _ := dialSuited(t, h, cfg, func(fromInitiator bool, header *Header, _ []byte) bool {
		if header != nil && header.ExchangeType == CREATE_CHILD_SA && !header.IsResponse() {
			mu.Lock()
			if key := (request{fromInitiator, header.SPIInitiator, header.MessageID}); !seen[key] {
				seen[key] = true
				sent[fromInitiator]++
			}
			mu.Unlock()
		}
		return true
	})
	if got := initiator.Suite().IKEKex; got != "p256" {
		t.Fatalf("the handshake settled %s, want the answering end's first group", got)
	}
	for turn := range 3 {
		for _, end := range []struct {
			name            string
			rekeying, other *Session
			fromInitiator   bool
		}{{"answering", responder, initiator, false}, {"dialing", initiator, responder, true}} {
			// the peer rekey limit spaces rekeys a legitimate peer starts minutes apart
			end.other.lastPeerIKERekey.Store(0)
			mu.Lock()
			before := sent[end.fromInitiator]
			mu.Unlock()
			if err := end.rekeying.RekeyIKE(); err != nil {
				t.Fatalf("turn %d: the %s end's rekey: %v", turn, end.name, err)
			}
			mu.Lock()
			requests := sent[end.fromInitiator] - before
			mu.Unlock()
			if requests != 1 {
				t.Errorf("turn %d: the %s end's rekey sent %d CREATE_CHILD_SA requests, want one", turn, end.name, requests)
			}
			if got, peer := initiator.Suite().IKEKex, responder.Suite().IKEKex; got != "p256" || peer != "p256" {
				t.Errorf("turn %d: after the %s end's rekey the IKE SA runs %s and %s, want the group it ran", turn, end.name, got, peer)
			}
		}
	}
}

// an IKE SA rekey this end starts offers the group of its KE payload first, ahead of kex's order
// and so does its retry in the group INVALID_KE_PAYLOAD names
// RFC 7296 section 3.4: "This Diffie-Hellman Group Num MUST match a Diffie-Hellman group specified in a proposal in the SA payload that is sent in the same message, and SHOULD match the Diffie-Hellman group in the first group in the first proposal, if such exists."
func TestIKESARekeyOffersTheGroupOfItsKEPayloadFirst(t *testing.T) {
	mux, _ := lifecycleMuxes(t)
	ctx := &ikeContext{suite: SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256, DHGroup: DH_ECP_256},
		spiI: 11, spiR: 12, skD: make([]byte, 32), skei: make([]byte, 20), sker: make([]byte, 20)}
	s := &Session{mux: mux, current: ctx, requests: make(chan *localRequest, 1), suites: func() Suites { return classicalLists }}
	done := make(chan error, 1)
	go func() { done <- s.RekeyIKE() }()
	offered := func(request *localRequest) (uint16, []Transform) {
		t.Helper()
		sa, ke := findType(request.inner, PayloadSA), findType(request.inner, PayloadKE)
		if sa == nil || ke == nil {
			t.Fatalf("the rekey request carried %v", request.inner)
		}
		proposals, err := DecodeSA(sa.Body)
		if err != nil || len(proposals) == 0 {
			t.Fatalf("the rekey offered %+v, %v", proposals, err)
		}
		group, _, err := DecodeKE(ke.Body)
		if err != nil {
			t.Fatal(err)
		}
		var groups []Transform
		for _, proposal := range proposals {
			for _, transform := range proposal.Transforms {
				if transform.Type == TransDH {
					groups = append(groups, transform)
				}
			}
		}
		return group, groups
	}
	request := <-s.requests
	if group, groups := offered(request); group != DH_ECP_256 || !slices.Equal(groups, []Transform{dhP256, dhX25519, dhP384}) {
		t.Errorf("the rekey sent its KE payload in group %d under the groups %+v, want p256 first", group, groups)
	}
	request.result <- requestResult{inner: []RawPayload{
		{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_INVALID_KE_PAYLOAD, Data: binary.BigEndian.AppendUint16(nil, DH_CURVE25519)})},
	}}
	var retry *localRequest
	select {
	case retry = <-s.requests:
	case err := <-done:
		t.Fatalf("the rekey ended at INVALID_KE_PAYLOAD naming x25519 with %v, want a retry", err)
	}
	if group, groups := offered(retry); group != DH_CURVE25519 || !slices.Equal(groups, []Transform{dhX25519, dhP384, dhP256}) {
		t.Errorf("the retry sent its KE payload in group %d under the groups %+v, want x25519 first", group, groups)
	}
	retry.result <- requestResult{err: errors.New("nothing answers the retry")}
	if err := <-done; err == nil {
		t.Error("a rekey whose retry drew no answer succeeded")
	}
}

// a reload whose lists leave out a live IKE SA's cipher rekeys it once
// and a peer that refuses that rekey leaves the next attempt to the retry timer
func TestRefusedForcedRekeyWaitsForItsRetry(t *testing.T) {
	dialed := &recorder{}
	h := newResponderHarness(t, nil)
	aes256 := suitesOf(t, Crypto{IKE: IKESuites{Cipher: []string{"aes256gcm"}}})
	aes256.kex = classicalLists.kex
	h.lists.Store(&aes256)
	var rekeys atomic.Int32
	cfg, dialing := listedConfig(h, dialed.record)
	initiator, responder, _, _ := dialSuited(t, h, cfg, func(fromInitiator bool, header *Header, _ []byte) bool {
		if fromInitiator && header != nil && header.ExchangeType == CREATE_CHILD_SA && !header.IsResponse() {
			rekeys.Add(1)
		}
		return true
	})
	// the initiator's Run answers a rekey the responder starts after the check Run makes when it starts
	if err := responder.RekeyChild(); err != nil {
		t.Fatal(err)
	}
	aes128 := suitesOf(t, Crypto{IKE: IKESuites{Cipher: []string{"aes128gcm"}}})
	dialing.Store(&aes128)
	initiator.SuitesChanged()
	awaitRecorded(t, dialed, "ike.rekey.failed testorg/client:2>testorg/server:1 sa=ike")
	time.Sleep(quietPeriod)
	if got := rekeys.Load(); got != 1 {
		t.Errorf("the refused rekey was sent %d times before its retry timer, want once", got)
	}
}

// a reload whose lists leave out a live IKE SA's group and its Child SA's cipher rekeys the Child SA
// though the peer refuses the IKE SA's rekey, which leaves the IKE SA to its retry timer
func TestChildSARekeysOnceTheIKESARekeyFailed(t *testing.T) {
	dialed := &recorder{}
	h := newResponderHarness(t, nil)
	x25519 := suitesOf(t, Crypto{IKE: IKESuites{Kex: []string{"x25519"}}})
	h.lists.Store(&x25519)
	cfg, dialing := listedConfig(h, dialed.record)
	initiator, responder, _, _ := dialSuited(t, h, cfg, nil)
	if err := responder.RekeyChild(); err != nil {
		t.Fatal(err)
	}
	next := suitesOf(t, Crypto{IKE: IKESuites{Kex: []string{"p256"}}, ESP: ESPSuites{Cipher: []string{"aes128gcm"}}})
	dialing.Store(&next)
	initiator.SuitesChanged()
	awaitRecorded(t, dialed, "ike.rekey.failed "+dialedPair+" sa=ike")
	awaitRecorded(t, dialed, "ike.rekey.completed "+dialedPair+" sa=child suite=aes128gcm")
	if got := initiator.Suite().IKEKex; got != "x25519" {
		t.Errorf("the IKE SA runs %s, want the group its refused rekey kept", got)
	}
}

// a session deleting its IKE SA for an unlisted PRF starts nothing else while the Delete is unanswered
// neither a second Delete on a later check of its SAs nor a rekey whose timer runs out
func TestReplacementStartsNothingElseWhileItsDeleteIsUnanswered(t *testing.T) {
	dialed := &recorder{}
	h := newResponderHarness(t, nil)
	var deleting, released atomic.Bool
	var rekeysAfter atomic.Int32
	cfg, dialing := listedConfig(h, dialed.record)
	// a Child SA rekey falls due while the Delete waits, a quiet period into the SA and long before its lifetime
	cfg.ChildRekeyInterval, cfg.RekeyMargin = time.Hour, time.Hour-quietPeriod
	cfg.RemotePort = relay(t, h.remotePort, func(fromInitiator bool, header *Header, _ []byte) bool {
		if !fromInitiator || header == nil || header.IsResponse() {
			return true
		}
		switch header.ExchangeType {
		case INFORMATIONAL:
			deleting.Store(true)
			return released.Load()
		case CREATE_CHILD_SA:
			if deleting.Load() {
				rekeysAfter.Add(1)
			}
		}
		return true
	})
	initiator, responder := dialPaused(t, h, cfg)
	runSession(t, responder)
	initiatorRun := runSession(t, initiator)
	sha256Only := suitesOf(t, Crypto{IKE: IKESuites{PRF: []string{"sha256"}}})
	dialing.Store(&sha256Only)
	initiator.SuitesChanged()
	const replace = "ike.suite.unlisted testorg/client:2>testorg/server:1 sa=ike suite=aes256gcm/sha384/x25519 action=replace"
	awaitRecorded(t, dialed, replace)
	if ended, err := recheck(t, initiator, initiatorRun); ended {
		t.Fatalf("the session ended with %v before its Delete was answered", err)
	}
	// the Child SA's rekey timer runs out meanwhile
	time.Sleep(2 * quietPeriod)
	recorded := dialed.recorded()
	if got := strings.Count(strings.Join(recorded, "\n"), replace); got != 1 {
		t.Errorf("the session started %d replacements, want one", got)
	}
	// a rekey started now waits behind the Delete for its request, so only its event shows it
	for _, event := range recorded[slices.Index(recorded, replace)+1:] {
		if strings.HasPrefix(event, "ike.rekey.started ") {
			t.Errorf("the session recorded %q behind its Delete, want no rekey started", event)
		}
	}
	if got := rekeysAfter.Load(); got != 0 {
		t.Errorf("the session sent %d CREATE_CHILD_SA requests behind its Delete, want none", got)
	}
	released.Store(true)
	if err := endedWithin(t, initiatorRun, "dialing"); !errors.Is(err, ErrPRFUnlisted) {
		t.Errorf("the session ended with %v, want its IKE SA deleted for a new handshake", err)
	}
	// a request sent as the session ended reaches the relay after it
	time.Sleep(quietPeriod)
	if got := rekeysAfter.Load(); got != 0 {
		t.Errorf("the session sent %d CREATE_CHILD_SA requests after its Delete, want none", got)
	}
}

// a Child SA a reload left out waits for a rekey under way, and a later check of the SAs meanwhile marks it once
func TestRecheckWhileARekeyRunsMarksAnUnlistedSAOnce(t *testing.T) {
	dialed := &recorder{}
	h := newResponderHarness(t, nil)
	var rekeying, released atomic.Bool
	cfg, dialing := listedConfig(h, dialed.record)
	// the IKE SA's scheduled rekey, due a quiet period into the SA and long before its lifetime, is under way when the lists change
	cfg.IKERekeyInterval, cfg.RekeyMargin = time.Hour, time.Hour-quietPeriod
	cfg.RemotePort = relay(t, h.remotePort, func(fromInitiator bool, header *Header, _ []byte) bool {
		if fromInitiator && header != nil && header.ExchangeType == CREATE_CHILD_SA && !header.IsResponse() {
			rekeying.Store(true)
			return released.Load()
		}
		return true
	})
	initiator, responder := dialPaused(t, h, cfg)
	runSession(t, responder)
	initiatorRun := runSession(t, initiator)
	if !waitUntil(rekeying.Load) {
		t.Fatal("the IKE SA's scheduled rekey never started")
	}
	aes128 := suitesOf(t, Crypto{ESP: ESPSuites{Cipher: []string{"aes128gcm"}}})
	dialing.Store(&aes128)
	for range 2 {
		if ended, err := recheck(t, initiator, initiatorRun); ended {
			t.Fatalf("the session ended with %v", err)
		}
	}
	const unlisted = "ike.suite.unlisted " + dialedPair + " sa=child suite=aes256gcm action=rekey"
	if got := strings.Count(strings.Join(dialed.recorded(), "\n"), unlisted); got != 1 {
		t.Errorf("checks during the IKE SA's rekey marked the Child SA %d times, want once", got)
	}
	released.Store(true)
	awaitRecorded(t, dialed, "ike.rekey.completed "+dialedPair+" sa=child suite=aes128gcm")
}

// a reload during a rekey leaves the SA to that rekey and marks nothing while it runs, and the SA the rekey made is checked against the lists once the rekey has ended
// so an IKE SA rekeyed under the lists from before the reload is marked once and rekeyed again under the new ones
func TestReloadDuringARekeyChecksTheSAItMade(t *testing.T) {
	bubble.Run(testReloadDuringARekeyChecksTheSAItMade)(t)
}

func testReloadDuringARekeyChecksTheSAItMade(t *testing.T) {
	dialed := &recorder{}
	h := newResponderHarness(t, nil)
	var rekeying, released atomic.Bool
	cfg, dialing := listedConfig(h, dialed.record)
	// the IKE SA's scheduled rekey is under way when the lists change, and the next falls due long after the test
	cfg.IKERekeyInterval, cfg.RekeyMargin, cfg.RekeyJitter = time.Hour, 10*time.Minute, 50*time.Minute-time.Millisecond
	// the peer refuses a second rekey within minPeerIKERekeyInterval of the first, and the retry comes after it
	cfg.RekeyRetryInitial, cfg.RekeyRetryMax = 2*minPeerIKERekeyInterval, 2*minPeerIKERekeyInterval
	cfg.RemotePort = relay(t, h.remotePort, func(fromInitiator bool, header *Header, _ []byte) bool {
		if fromInitiator && header != nil && header.ExchangeType == CREATE_CHILD_SA && !header.IsResponse() {
			rekeying.Store(true)
			return released.Load()
		}
		return true
	})
	initiator, responder := dialPaused(t, h, cfg)
	// the first draw puts the scheduled rekey a quiet period into the IKE SA, and every later one is zero
	var drawn atomic.Bool
	initiator.rekeyJitterSource = func(time.Duration) (time.Duration, error) {
		if drawn.CompareAndSwap(false, true) {
			return 50*time.Minute - quietPeriod, nil
		}
		return 0, nil
	}
	runSession(t, responder)
	initiatorRun := runSession(t, initiator)
	if !waitUntil(rekeying.Load) {
		t.Fatal("the IKE SA's scheduled rekey never started")
	}
	aes128 := suitesOf(t, Crypto{IKE: IKESuites{Cipher: []string{"aes128gcm"}}})
	dialing.Store(&aes128)
	if ended, err := settledRecheck(t, initiator, initiatorRun); ended {
		t.Fatalf("the session ended with %v", err)
	}
	released.Store(true)
	completed := "ike.rekey.completed " + dialedPair + " sa=ike suite=aes256gcm/sha384/x25519"
	awaitRecorded(t, dialed, completed)
	awaitRecorded(t, dialed, "ike.rekey.completed "+dialedPair+" sa=ike suite=aes128gcm/sha384/x25519")
	recorded := dialed.recorded()
	unlisted := "ike.suite.unlisted " + dialedPair + " sa=ike suite=aes256gcm/sha384/x25519 action=rekey"
	if got := strings.Count(strings.Join(recorded, "\n"), unlisted); got != 1 || slices.Index(recorded, unlisted) < slices.Index(recorded, completed) {
		t.Errorf("the session recorded %q, want the IKE SA marked unlisted once, after the rekey under way at the reload completed", recorded)
	}
}

// a Child SA a reload left out whose scheduled rekey fell due behind a rekey under way is rekeyed by that schedule, not forced as well
func TestReloadLeavesADueRekeyToItsSchedule(t *testing.T) {
	dialed := &recorder{}
	h := newResponderHarness(t, nil)
	var rekeying, released atomic.Bool
	cfg, dialing := listedConfig(h, dialed.record)
	// the IKE SA's scheduled rekey, due a quiet period into the SA, is under way when the Child SA's falls due a quiet period later, each long before its lifetime
	cfg.IKERekeyInterval, cfg.ChildRekeyInterval, cfg.RekeyMargin = time.Hour, time.Hour+quietPeriod, time.Hour-quietPeriod
	cfg.RemotePort = relay(t, h.remotePort, func(fromInitiator bool, header *Header, _ []byte) bool {
		if fromInitiator && header != nil && header.ExchangeType == CREATE_CHILD_SA && !header.IsResponse() {
			rekeying.Store(true)
			return released.Load()
		}
		return true
	})
	initiator, responder := dialPaused(t, h, cfg)
	runSession(t, responder)
	initiatorRun := runSession(t, initiator)
	if !waitUntil(rekeying.Load) {
		t.Fatal("the IKE SA's scheduled rekey never started")
	}
	// past the Child SA's deadline
	time.Sleep(3 * quietPeriod)
	aes128 := suitesOf(t, Crypto{ESP: ESPSuites{Cipher: []string{"aes128gcm"}}})
	dialing.Store(&aes128)
	if ended, err := recheck(t, initiator, initiatorRun); ended {
		t.Fatalf("the session ended with %v", err)
	}
	released.Store(true)
	awaitRecorded(t, dialed, "ike.rekey.completed "+dialedPair+" sa=child suite=aes128gcm")
	if got := recordedKind(dialed, "ike.suite.unlisted"); got != 0 {
		t.Errorf("a reload forced a rekey that was due already: %q", dialed.recorded())
	}
}

// a reload that leaves out the IKE SA's cipher while the SA's scheduled rekey backs off from a refusal leaves the rekey to its retry
func TestReloadLeavesARekeyBackingOffToItsRetry(t *testing.T) {
	dialed := &recorder{}
	h := newResponderHarness(t, nil)
	cfg, dialing := listedConfig(h, dialed.record)
	// the scheduled rekey falls due a quiet period into the IKE SA, long before its lifetime
	cfg.IKERekeyInterval, cfg.RekeyMargin = time.Hour, time.Hour-quietPeriod
	// the retry falls after the test
	cfg.RekeyRetryInitial, cfg.RekeyRetryMax = answerBudget, answerBudget
	initiator, responder := dialPaused(t, h, cfg)
	// a peer rekey limit that never runs out refuses every IKE SA rekey the initiator starts
	responder.lastPeerIKERekey.Store(int64(100 * answerBudget))
	runSession(t, responder)
	initiatorRun := runSession(t, initiator)
	awaitRecorded(t, dialed, "ike.rekey.failed "+dialedPair+" sa=ike")
	aes128 := suitesOf(t, Crypto{IKE: IKESuites{Cipher: []string{"aes128gcm"}}})
	dialing.Store(&aes128)
	if ended, err := recheck(t, initiator, initiatorRun); ended {
		t.Fatalf("the session ended with %v", err)
	}
	if got := recordedKind(dialed, "ike.suite.unlisted"); got != 0 {
		t.Errorf("a reload forced a rekey backing off from a refusal: %q", dialed.recorded())
	}
}

// a reload that leaves out the suite of an SA the peer's rekey made rekeys that SA at once, though its schedule counted from the SA the peer's rekey replaced
func TestReloadRekeysAnSAThePeerRekeyed(t *testing.T) {
	for _, tc := range []struct {
		sa    string
		lists Crypto
		suite string
	}{
		{"child", Crypto{ESP: ESPSuites{Cipher: []string{"aes128gcm"}}}, "aes128gcm"},
		{"ike", Crypto{IKE: IKESuites{Cipher: []string{"aes128gcm"}}}, "aes128gcm/sha384/x25519"},
	} {
		t.Run(tc.sa, func(t *testing.T) {
			dialed := &recorder{}
			h := newResponderHarness(t, nil)
			cfg, dialing := listedConfig(h, dialed.record)
			// the schedules' own rekeys fall due long after the test
			cfg.ChildRekeyInterval, cfg.IKERekeyInterval, cfg.RekeyMargin = time.Hour, time.Hour, time.Minute
			initiator, responder, _, _ := dialSuited(t, h, cfg, nil)
			rekey := responder.RekeyChild
			if tc.sa == "ike" {
				rekey = responder.RekeyIKE
			}
			if err := rekey(); err != nil {
				t.Fatalf("the peer's rekey failed: %v", err)
			}
			lists := suitesOf(t, tc.lists)
			dialing.Store(&lists)
			// one check, since a second would force the rekey again and hide one the first check's forced rekey dropped
			initiator.SuitesChanged()
			awaitRecorded(t, dialed, "ike.rekey.completed "+dialedPair+" sa="+tc.sa+" suite="+tc.suite)
		})
	}
}

// a reload at both ends leaving out the PRF of their IKE SA sends two Deletes that cross
// and each session ends for a new handshake, so each dialer dials again at once
func TestReloadAtBothEndsEndsEachSessionForANewHandshake(t *testing.T) {
	for run := range 3 {
		h := newResponderHarness(t, nil)
		// the dialing Run holds in the event of the liveness check it starts, so the reload's check and the peer's Delete both come while it is busy
		var hold atomic.Bool
		held, release := make(chan struct{}), make(chan struct{})
		releaseRun := sync.OnceFunc(func() { close(release) })
		events := func(_, _ identity.Identity, kind string, _ ...slog.Attr) {
			if kind == "ike.probe" && hold.CompareAndSwap(true, false) {
				close(held)
				<-release
			}
		}
		cfg, dialing := listedConfig(h, events)
		initiator, responder, initiatorRun, responderRun := dialSuited(t, h, cfg, nil)
		t.Cleanup(releaseRun)
		hold.Store(true)
		initiator.Probe()
		select {
		case <-held:
		case <-time.After(answerBudget):
			t.Fatalf("run %d: the dialing session started no liveness check", run)
		}
		// the answering Run answers the check only after the check it makes when it starts
		if !waitUntil(func() bool { return len(initiator.Mux().IKE()) == 1 }) {
			t.Fatalf("run %d: the answering session did not answer the liveness check", run)
		}
		sha256Only := suitesOf(t, Crypto{IKE: IKESuites{PRF: []string{"sha256"}}})
		h.lists.Store(&sha256Only)
		dialing.Store(&sha256Only)
		initiator.SuitesChanged()
		responder.SuitesChanged()
		// the peer's Delete waits behind the answer, after the reload's check, as a Delete crossing the dialing end's own does
		if !waitUntil(func() bool { return len(initiator.Mux().IKE()) == 2 }) {
			t.Fatalf("run %d: the answering session sent no Delete", run)
		}
		releaseRun()
		if err := endedWithin(t, initiatorRun, "dialing"); !errors.Is(err, ErrPRFUnlisted) {
			t.Errorf("run %d: the dialing session ended with %v, want its IKE SA deleted for a new handshake", run, err)
		}
		if err := endedWithin(t, responderRun, "answering"); !errors.Is(err, ErrPRFUnlisted) {
			t.Errorf("run %d: the answering session ended with %v, want its IKE SA deleted for a new handshake", run, err)
		}
	}
}

const (
	// forcedJitter is the rekey jitter a forced rekey draws its delay within
	forcedJitter = 2 * time.Second
	// forcedDelay is the delay the injected source draws, long enough that a start without it shows
	forcedDelay = 2 * quietPeriod
	// forcedRetry is each retry's delay after a refused forced rekey
	forcedRetry = quietPeriod
	// forcedDue is when a scheduled IKE SA rekey falls due after the SA was made, past the refused rekey and its retry
	forcedDue = 2 * time.Second
	// scheduleSlack is how long after the time its schedule gives a rekey may start, for the timer and Run's loop
	scheduleSlack = time.Second
)

// timedRecorder records into r and keeps when kind first happened in at
func timedRecorder(r *recorder, kind string, at *atomic.Pointer[time.Time]) Recorder {
	return func(local, remote identity.Identity, happened string, attrs ...slog.Attr) {
		r.record(local, remote, happened, attrs...)
		if happened == kind {
			now := time.Now()
			at.CompareAndSwap(nil, &now)
		}
	}
}

// a reload whose lists left out a live SA's cipher rekeys it after a delay the session's jitter source draws within the rekey jitter, as a scheduled rekey's is
// so two ends reloading the same lists at once do not both rekey the SA at once and refuse each other's rekey
// RFC 7296 section 2.8.1: "To reduce the probability of this happening, the timing of rekeying requests SHOULD be jittered (delayed by a random amount of time after the need for rekeying is noticed)."
func TestForcedRekeyWaitsADelayDrawnWithinTheRekeyJitter(t *testing.T) {
	dialed := &recorder{}
	var started atomic.Pointer[time.Time]
	h := newResponderHarness(t, nil)
	cfg, dialing := listedConfig(h, timedRecorder(dialed, "ike.rekey.started", &started))
	cfg.RekeyJitter = forcedJitter
	initiator, responder := dialPaused(t, h, cfg)
	var asked atomic.Int64
	initiator.rekeyJitterSource = func(max time.Duration) (time.Duration, error) {
		asked.Store(int64(max))
		return forcedDelay, nil
	}
	runSession(t, responder)
	initiatorRun := runSession(t, initiator)
	// the initiator's Run answers a rekey the responder starts after the check Run makes when it starts
	if err := responder.RekeyChild(); err != nil {
		t.Fatal(err)
	}
	next := suitesOf(t, Crypto{ESP: ESPSuites{Cipher: []string{"chacha20poly1305", "aes128gcm"}}})
	dialing.Store(&next)
	noticed := time.Now()
	initiator.SuitesChanged()
	// checks of the SAs during the delay draw no second one
	if ended, err := recheck(t, initiator, initiatorRun); ended {
		t.Fatalf("the session ended with %v", err)
	}
	const unlisted = "ike.suite.unlisted " + dialedPair + " sa=child suite=aes256gcm action=rekey"
	awaitRecorded(t, dialed, "ike.rekey.completed "+dialedPair+" sa=child suite=aes128gcm")
	if got := time.Duration(asked.Load()); got != forcedJitter {
		t.Errorf("the delay was drawn within %s, want the rekey jitter %s", got, forcedJitter)
	}
	if waited := started.Load().Sub(noticed); waited < forcedDelay {
		t.Errorf("the forced rekey started %s after the reload, want at least the drawn %s", waited, forcedDelay)
	}
	if got := strings.Count(strings.Join(dialed.recorded(), "\n"), unlisted); got != 1 {
		t.Errorf("the Child SA was marked unlisted %d times, want once", got)
	}
	// the rekey that replaced it leaves the next reload to force a rekey of its own
	// and the peer rekey limit spaces rekeys a legitimate peer starts minutes apart
	responder.lastPeerChildRekey.Store(0)
	chacha := suitesOf(t, Crypto{ESP: ESPSuites{Cipher: []string{"chacha20poly1305"}}})
	dialing.Store(&chacha)
	initiator.SuitesChanged()
	awaitRecorded(t, dialed, "ike.rekey.completed "+dialedPair+" sa=child suite=chacha20poly1305")
}

// a forced rekey the peer refused retries only while the lists still leave out its SA
// once a reload lists the SA again a disabled interval rekeys it no more, and an enabled one rekeys it at the deadline it held before
func TestRefusedForcedRekeyStopsOnceTheListsHoldItsSA(t *testing.T) {
	for _, due := range []time.Duration{0, forcedDue} {
		name := "no interval"
		if due > 0 {
			name = "a scheduled rekey due " + due.String() + " into the SA"
		}
		t.Run(name, func(t *testing.T) {
			dialed := &recorder{}
			var completed atomic.Pointer[time.Time]
			h := newResponderHarness(t, nil)
			aes256 := suitesOf(t, Crypto{IKE: IKESuites{Cipher: []string{"aes256gcm"}}})
			aes256.kex = classicalLists.kex
			h.lists.Store(&aes256)
			cfg, dialing := listedConfig(h, timedRecorder(dialed, "ike.rekey.completed", &completed))
			if due > 0 {
				// the lifetime lies past the test
				cfg.IKERekeyInterval, cfg.RekeyMargin = time.Hour, time.Hour-due
			}
			cfg.RekeyRetryInitial, cfg.RekeyRetryMax = forcedRetry, forcedRetry
			initiator, responder := dialPaused(t, h, cfg)
			// each delay is drawn as zero, so the retry comes forcedRetry after the refusal
			initiator.rekeyJitterSource = func(time.Duration) (time.Duration, error) { return 0, nil }
			established := initiator.current.established
			runSession(t, responder)
			runSession(t, initiator)
			if err := responder.RekeyChild(); err != nil {
				t.Fatal(err)
			}
			aes128 := suitesOf(t, Crypto{IKE: IKESuites{Cipher: []string{"aes128gcm"}}})
			dialing.Store(&aes128)
			initiator.SuitesChanged()
			awaitRecorded(t, dialed, "ike.rekey.failed "+dialedPair+" sa=ike")
			dialing.Store(&Suites{})
			if due == 0 {
				time.Sleep(forcedRetry + quietPeriod)
				if got := recordedKind(dialed, "ike.rekey.completed"); got != 0 {
					t.Errorf("the session rekeyed its IKE SA %d times once the lists held it again, want none: %q", got, dialed.recorded())
				}
				// the refusals it stopped after leave the next reload to force a rekey of its own
				h.lists.Store(&Suites{})
				dialing.Store(&aes128)
				initiator.SuitesChanged()
				awaitRecorded(t, dialed, "ike.rekey.completed "+dialedPair+" sa=ike suite=aes128gcm/sha384/x25519")
				return
			}
			awaitRecorded(t, dialed, "ike.rekey.completed "+dialedPair+" sa=ike suite=aes256gcm/sha384/x25519")
			if at := completed.Load().Sub(established); at < due {
				t.Errorf("the scheduled rekey completed %s after the IKE SA was made, want no sooner than its deadline %s", at, due)
			}
		})
	}
}

// a forced Child SA rekey the peer refused retries only while the lists still leave out the Child SA's cipher
// once a reload lists it again the retry runs no rekey
func TestRefusedForcedChildSARekeyStopsOnceTheListsHoldIt(t *testing.T) {
	dialed := &recorder{}
	h := newResponderHarness(t, nil)
	aes256 := suitesOf(t, Crypto{ESP: ESPSuites{Cipher: []string{"aes256gcm"}}})
	h.lists.Store(&aes256)
	cfg, dialing := listedConfig(h, dialed.record)
	cfg.RekeyRetryInitial, cfg.RekeyRetryMax = forcedRetry, forcedRetry
	initiator, responder := dialPaused(t, h, cfg)
	// each delay is drawn as zero, so the retry comes forcedRetry after the refusal
	initiator.rekeyJitterSource = func(time.Duration) (time.Duration, error) { return 0, nil }
	runSession(t, responder)
	runSession(t, initiator)
	// the initiator's Run answers a rekey the responder starts after the check Run makes when it starts
	if err := responder.RekeyChild(); err != nil {
		t.Fatal(err)
	}
	aes128 := suitesOf(t, Crypto{ESP: ESPSuites{Cipher: []string{"aes128gcm"}}})
	dialing.Store(&aes128)
	initiator.SuitesChanged()
	const started = "ike.rekey.started testorg/client:2>testorg/server:1 sa=child"
	awaitRecorded(t, dialed, "ike.rekey.failed testorg/client:2>testorg/server:1 sa=child")
	dialing.Store(&Suites{})
	time.Sleep(forcedRetry + quietPeriod)
	if got := strings.Count(strings.Join(dialed.recorded(), "\n"), started); got != 1 {
		t.Errorf("the session started %d Child SA rekeys, want the refused one alone once the lists held the Child SA again: %q", got, dialed.recorded())
	}
}

// a forced Child SA rekey whose delay a packet-count rekey overtook starts nothing when that delay runs out, where the Child SA has no interval
// the packet-count rekey made a Child SA the lists hold, which leaves the schedule nothing to run
func TestForcedDelayAPacketCountRekeyOvertookStartsNothing(t *testing.T) {
	dialed := &recorder{}
	h := newResponderHarness(t, nil)
	cfg, dialing := listedConfig(h, dialed.record)
	cfg.RekeyJitter = forcedJitter
	initiator, responder := dialPaused(t, h, cfg)
	if initiator.childRekeyInterval != 0 {
		t.Fatalf("the Child SA rekeys every %s, want no interval", initiator.childRekeyInterval)
	}
	initiator.rekeyJitterSource = func(time.Duration) (time.Duration, error) { return forcedDelay, nil }
	runSession(t, responder)
	initiatorRun := runSession(t, initiator)
	// the initiator's Run answers a rekey the responder starts after the check Run makes when it starts
	if err := responder.RekeyChild(); err != nil {
		t.Fatal(err)
	}
	aes128 := suitesOf(t, Crypto{ESP: ESPSuites{Cipher: []string{"aes128gcm"}}})
	dialing.Store(&aes128)
	initiator.SuitesChanged()
	awaitRecorded(t, dialed, "ike.suite.unlisted "+dialedPair+" sa=child suite=aes256gcm action=rekey")
	forced := time.Now()
	// the peer rekey limit spaces rekeys a legitimate peer starts minutes apart
	responder.lastPeerChildRekey.Store(0)
	if err := initiator.RekeyChildProactively(); err != nil {
		t.Fatal(err)
	}
	awaitRecorded(t, dialed, "ike.rekey.completed "+dialedPair+" sa=child suite=aes128gcm")
	if waited := time.Since(forced); waited >= forcedDelay {
		t.Fatalf("the packet-count rekey completed %s after the reload, past the forced delay of %s", waited, forcedDelay)
	}
	// so a rekey started once the delay ran out would be answered too
	responder.lastPeerChildRekey.Store(0)
	time.Sleep(forcedDelay + 2*quietPeriod)
	select {
	case err := <-initiatorRun:
		t.Fatalf("the session ended with %v", err)
	default:
	}
	if got := strings.Count(strings.Join(dialed.recorded(), "\n"), "ike.rekey.started "+dialedPair+" sa=child"); got != 1 {
		t.Errorf("the session started %d Child SA rekeys, want the packet-count one alone: %q", got, dialed.recorded())
	}
}

// a schedule with no interval that a rekey on another path put back holds nothing for the loop
// a forced delay still running leaves no deadline for the wait and no timer to fall due, and one that fell due leaves no rekey due
// so the wait is never set from a deadline past, which would wake the loop at once on every pass
func TestScheduleWithNoIntervalPutBackHoldsNothingForTheLoop(t *testing.T) {
	s := &Session{}
	far := time.Now().Add(time.Hour)
	t.Run("a forced delay still running", func(t *testing.T) {
		schedule := retryOnly("Child SA", "child", func() error { return nil })
		schedule.forced = true
		schedule.reset(forcedRetry)
		if err := s.rearm(schedule); err != nil {
			t.Fatal(err)
		}
		if !schedule.deadline.IsZero() || schedule.forced {
			t.Errorf("the schedule holds the deadline %v and forced %v, want neither", schedule.deadline, schedule.forced)
		}
		time.Sleep(forcedRetry + quietPeriod)
		if wake := schedule.wake(far, time.Now()); !wake.Equal(far) {
			t.Errorf("the wait takes %v from the schedule once the delay is past, want nothing of it", wake)
		}
		if schedule.poll(); schedule.due {
			t.Error("the forced delay fell due once the schedule was put back")
		}
	})
	t.Run("a forced delay that fell due", func(t *testing.T) {
		schedule := retryOnly("Child SA", "child", func() error { return nil })
		schedule.forced = true
		schedule.reset(0)
		time.Sleep(quietPeriod)
		if schedule.poll(); !schedule.due {
			t.Fatal("the forced delay did not fall due")
		}
		if err := s.rearm(schedule); err != nil {
			t.Fatal(err)
		}
		if next := nextDueRekey([]*rekeySchedule{schedule}, nil); next != nil {
			t.Error("the forced rekey is still due once the schedule was put back")
		}
	})
}

// a forced rekey that falls due once the lists hold its SA again runs nothing, and a rekey due beside it starts at once
// in a quiet session nothing else wakes Run for that rekey before its SA's lifetime
func TestDroppedForcedRekeyLeavesTheRekeyDueBesideItToStart(t *testing.T) {
	dialed := &recorder{}
	h := newResponderHarness(t, nil)
	cfg, dialing := listedConfig(h, dialed.record)
	cfg.IKERekeyInterval, cfg.RekeyMargin = time.Hour, 10*time.Minute
	initiator, responder := dialPaused(t, h, cfg)
	// the IKE SA's scheduled rekey is already due when Run starts
	initiator.current.established = time.Now().Add(-55 * time.Minute)
	// no liveness check falls due, so the session stays quiet
	initiator.dpdEvery, responder.dpdEvery = time.Hour, time.Hour
	// the first draw is the IKE SA's schedule and the second the delay of the Child SA's forced rekey
	// the lists hold the Child SA again by the time that delay, drawn as zero, runs out
	var draws atomic.Int32
	initiator.rekeyJitterSource = func(time.Duration) (time.Duration, error) {
		if draws.Add(1) == 2 {
			dialing.Store(&Suites{})
		}
		return 0, nil
	}
	aes128 := suitesOf(t, Crypto{ESP: ESPSuites{Cipher: []string{"aes128gcm"}}})
	dialing.Store(&aes128)
	runSession(t, responder)
	runSession(t, initiator)
	awaitRecorded(t, dialed, "ike.rekey.started "+dialedPair+" sa=ike")
	recorded := dialed.recorded()
	if !slices.Contains(recorded, "ike.suite.unlisted "+dialedPair+" sa=child suite=aes256gcm action=rekey") {
		t.Errorf("the check Run makes when it starts forced no Child SA rekey: %q", recorded)
	}
	if slices.Contains(recorded, "ike.rekey.started "+dialedPair+" sa=child") {
		t.Errorf("the forced Child SA rekey ran once the lists held the Child SA again: %q", recorded)
	}
}

// a reload forcing a rekey of an SA whose scheduled rekey falls due before the forced delay runs out leaves the rekey to start when its schedule says
// so the rekey keeps the margin before the SA's lifetime, under a rekey jitter above the margin, which Validate accepts, as well
// and a reload listing the SA again first sends it back to its schedule, whose new draw cannot put it past the SA's lifetime less the margin
func TestForcedRekeyStartsNoLaterThanTheRekeyItsScheduleHolds(t *testing.T) {
	for _, c := range []struct {
		name                     string
		interval, margin, jitter time.Duration
		// age is how long the IKE SA has run when Run starts
		age time.Duration
		// draws are the jitter source's in turn: the schedule's, the forced delay's, and the schedule's again once the SA is listed again
		draws  []time.Duration
		listed bool
	}{
		{"jitter above the margin", 6 * time.Second, 1500 * time.Millisecond, 4 * time.Second, 3 * time.Second, []time.Duration{0, 4 * time.Second}, false},
		{"margin above the jitter", time.Hour, 10 * time.Minute, 5 * time.Minute, 50*time.Minute - time.Second, []time.Duration{0, 5 * time.Minute}, false},
		{"listed again before it falls due", time.Hour, 10 * time.Minute, 5 * time.Minute, 50*time.Minute - 2*time.Second, []time.Duration{time.Second, 5 * time.Minute, 0}, true},
		{"listed again under the largest new draw", time.Hour, 10 * time.Minute, 5 * time.Minute, 50*time.Minute - 2*time.Second, []time.Duration{time.Second, 5 * time.Minute, 5 * time.Minute}, true},
	} {
		t.Run(c.name, bubble.Run(func(t *testing.T) {
			dialed := &recorder{}
			var started atomic.Pointer[time.Time]
			h := newResponderHarness(t, nil)
			cfg, dialing := listedConfig(h, timedRecorder(dialed, "ike.rekey.started", &started))
			cfg.IKERekeyInterval, cfg.RekeyMargin, cfg.RekeyJitter = c.interval, c.margin, c.jitter
			initiator, responder := dialPaused(t, h, cfg)
			established := time.Now().Add(-c.age)
			initiator.current.established = established
			// no liveness check falls due, so only the schedule wakes Run
			initiator.dpdEvery, responder.dpdEvery = time.Hour, time.Hour
			var draws atomic.Int32
			initiator.rekeyJitterSource = func(time.Duration) (time.Duration, error) {
				if i := int(draws.Add(1)) - 1; i < len(c.draws) {
					return c.draws[i], nil
				}
				return 0, nil
			}
			runSession(t, responder)
			run := runSession(t, initiator)
			aes128 := suitesOf(t, Crypto{IKE: IKESuites{Cipher: []string{"aes128gcm"}}})
			dialing.Store(&aes128)
			if ended, err := settledRecheck(t, initiator, run); ended {
				t.Fatalf("the session ended with %v", err)
			}
			suite := "aes128gcm/sha384/x25519"
			if c.listed {
				dialing.Store(&Suites{})
				if ended, err := settledRecheck(t, initiator, run); ended {
					t.Fatalf("the session ended with %v", err)
				}
				suite = "aes256gcm/sha384/x25519"
			}
			scheduled := established.Add(c.interval - c.margin - c.draws[0])
			latest := established.Add(c.interval - c.margin)
			for started.Load() == nil && time.Now().Before(latest.Add(scheduleSlack)) {
				time.Sleep(recordPoll)
			}
			at := started.Load()
			if at == nil {
				t.Fatalf("no IKE SA rekey started by %s into the SA, its lifetime less its margin: %q", latest.Sub(established), dialed.recorded())
			}
			if at.Before(scheduled) {
				t.Errorf("the IKE SA rekey started %s into the SA, before its schedule's %s", at.Sub(established), scheduled.Sub(established))
			}
			awaitRecorded(t, dialed, "ike.rekey.completed "+dialedPair+" sa=ike suite="+suite)
			if all := strings.Join(dialed.recorded(), "\n"); strings.Contains(all, "ike.sa.closed "+dialedPair+" sa=ike reason=lifetime") {
				t.Errorf("the IKE SA closed at its lifetime: %s", all)
			}
		}))
	}
}

// a reload during a Child SA rekey this end started outside its schedule, as a packet-count one is, leaves the Child SA to that rekey
// and the Child SA it made is checked against the lists once its outcome is settled, so one made in the cipher the reload left out is rekeyed under the new lists
func TestReloadDuringAPacketCountRekeyChecksTheChildSAItMade(t *testing.T) {
	for _, c := range []struct {
		name  string
		delay time.Duration
	}{
		{"forced delay runs out during the rekey", 0},
		{"forced delay runs out after the rekey", forcedJitter},
	} {
		t.Run(c.name, bubble.Run(func(t *testing.T) {
			dialed := &recorder{}
			h := newResponderHarness(t, nil)
			var rekeying, released atomic.Bool
			cfg, dialing := listedConfig(h, dialed.record)
			// the Child SA's scheduled rekey falls due long after the test
			cfg.ChildRekeyInterval, cfg.RekeyMargin, cfg.RekeyJitter = time.Hour, 10*time.Minute, forcedJitter
			cfg.RekeyRetryInitial, cfg.RekeyRetryMax = forcedRetry, forcedRetry
			cfg.RemotePort = relay(t, h.remotePort, func(fromInitiator bool, header *Header, _ []byte) bool {
				if fromInitiator && header != nil && header.ExchangeType == CREATE_CHILD_SA && !header.IsResponse() {
					rekeying.Store(true)
					return released.Load()
				}
				return true
			})
			initiator, responder := dialPaused(t, h, cfg)
			initiator.rekeyJitterSource = func(time.Duration) (time.Duration, error) { return c.delay, nil }
			initiator.retransmitAfter = 200 * time.Millisecond
			runSession(t, responder)
			run := runSession(t, initiator)
			proactive := make(chan error, 1)
			go func() { proactive <- initiator.RekeyChildProactively() }()
			if !waitUntil(rekeying.Load) {
				t.Fatal("the packet-count rekey never started")
			}
			aes128 := suitesOf(t, Crypto{ESP: ESPSuites{Cipher: []string{"aes128gcm"}}})
			dialing.Store(&aes128)
			if ended, err := settledRecheck(t, initiator, run); ended {
				t.Fatalf("the session ended with %v", err)
			}
			// a forced delay of zero runs out with the rekey still under way
			time.Sleep(quietPeriod)
			released.Store(true)
			if err := <-proactive; err != nil {
				t.Fatalf("the packet-count rekey failed: %v", err)
			}
			awaitRecorded(t, dialed, "ike.rekey.completed "+dialedPair+" sa=child suite=aes256gcm")
			made := time.Now()
			// the rekey jitter bounds the forced delay, and the peer refuses a second Child SA rekey within minPeerChildRekeyInterval of the first
			bound := forcedJitter + minPeerChildRekeyInterval + quietPeriod
			rekeyed := "ike.rekey.completed " + dialedPair + " sa=child suite=aes128gcm"
			for !slices.Contains(dialed.recorded(), rekeyed) {
				if time.Since(made) > bound {
					t.Fatalf("the Child SA made in aes256gcm was not rekeyed under the new lists within %s: %q", bound, dialed.recorded())
				}
				time.Sleep(recordPoll)
			}
		}))
	}
}

// a Child SA reaching its lifetime while the Delete of an IKE SA whose PRF a reload removed is unanswered leaves that Delete the last request the session sends
// RFC 7296 section 2.8: "the Delete payload to delete itself MUST be the last request sent over the old IKE SA."
func TestReplacementPastAChildSALifetimeSendsNoSecondDelete(t *testing.T) {
	dialed := &recorder{}
	h := newResponderHarness(t, nil)
	var released atomic.Bool
	var mu sync.Mutex
	informational := map[uint32]bool{}
	cfg, dialing := listedConfig(h, dialed.record)
	// the Child SA's lifetime falls while the Delete waits, and its scheduled rekey falls due behind the Delete
	cfg.ChildRekeyInterval, cfg.RekeyMargin = 1500*time.Millisecond, 200*time.Millisecond
	cfg.RemotePort = relay(t, h.remotePort, func(fromInitiator bool, header *Header, _ []byte) bool {
		if !fromInitiator || header == nil || header.IsResponse() || header.ExchangeType != INFORMATIONAL {
			return true
		}
		mu.Lock()
		informational[header.MessageID] = true
		mu.Unlock()
		return released.Load()
	})
	initiator, responder := dialPaused(t, h, cfg)
	initiator.rekeyJitterSource = func(time.Duration) (time.Duration, error) { return 0, nil }
	initiator.dpdEvery, responder.dpdEvery = time.Hour, time.Hour
	runSession(t, responder)
	run := runSession(t, initiator)
	sha256Only := suitesOf(t, Crypto{IKE: IKESuites{PRF: []string{"sha256"}}})
	dialing.Store(&sha256Only)
	initiator.SuitesChanged()
	awaitRecorded(t, dialed, "ike.suite.unlisted "+dialedPair+" sa=ike suite=aes256gcm/sha384/x25519 action=replace")
	awaitRecorded(t, dialed, "ike.sa.closed "+dialedPair+" sa=child reason=lifetime")
	released.Store(true)
	if err := endedWithin(t, run, "dialing"); !errors.Is(err, ErrPRFUnlisted) {
		t.Errorf("the session ended with %v, want its IKE SA deleted for a new handshake", err)
	}
	// a request sent as the session ended reaches the relay after it
	time.Sleep(quietPeriod)
	mu.Lock()
	defer mu.Unlock()
	if len(informational) != 1 {
		t.Errorf("the session sent INFORMATIONAL requests under %d Message IDs, want the one Delete", len(informational))
	}
}

// a reload removing the PRF of an IKE SA whose rekey runs past the SA's lifetime replaces the IKE SA once that rekey has ended
// and when the peer refuses the rekey the replacement's Delete goes out on the expired IKE SA as its one Delete
// RFC 7296 section 2.4: "In this case, an IKE endpoint SHOULD send a Delete payload indicating that it has closed the IKE SA unless the other endpoint is no longer responding."
func TestReplacementOfAnIKESAPastItsLifetimeSendsItsDelete(t *testing.T) {
	dialed := &recorder{}
	h := newResponderHarness(t, nil)
	var rekeying, released atomic.Bool
	var mu sync.Mutex
	informational := map[uint32]bool{}
	cfg, dialing := listedConfig(h, dialed.record)
	// the IKE SA's rekey falls due soon after the SA is made
	// and its lifetime ends while the relay holds that rekey
	cfg.IKERekeyInterval, cfg.RekeyMargin = 3*time.Second, 2*time.Second
	cfg.RemotePort = relay(t, h.remotePort, func(fromInitiator bool, header *Header, _ []byte) bool {
		if !fromInitiator || header == nil || header.IsResponse() {
			return true
		}
		switch header.ExchangeType {
		case CREATE_CHILD_SA:
			rekeying.Store(true)
			return released.Load()
		case INFORMATIONAL:
			mu.Lock()
			informational[header.MessageID] = true
			mu.Unlock()
		}
		return true
	})
	initiator, responder := dialPaused(t, h, cfg)
	// the rekey's request is sent again past the lifetime, long before its budget runs out
	initiator.retransmitAfter = 500 * time.Millisecond
	initiator.dpdEvery, responder.dpdEvery = time.Hour, time.Hour
	established := initiator.current.established
	runSession(t, responder)
	run := runSession(t, initiator)
	if !waitUntil(rekeying.Load) {
		t.Fatal("the IKE SA's rekey never started")
	}
	// a peer rekey limit that never runs out refuses the rekey
	responder.lastPeerIKERekey.Store(int64(100 * answerBudget))
	sha256Only := suitesOf(t, Crypto{IKE: IKESuites{PRF: []string{"sha256"}}})
	dialing.Store(&sha256Only)
	initiator.SuitesChanged()
	awaitRecorded(t, dialed, "ike.suite.unlisted "+dialedPair+" sa=ike suite=aes256gcm/sha384/x25519 action=replace")
	time.Sleep(time.Until(established.Add(cfg.IKERekeyInterval + quietPeriod)))
	released.Store(true)
	if err := endedWithin(t, run, "dialing"); !errors.Is(err, ErrPRFUnlisted) {
		t.Errorf("the session ended with %v, want its IKE SA deleted for a new handshake", err)
	}
	if all := strings.Join(dialed.recorded(), "\n"); !strings.Contains(all, "ike.sa.closed "+dialedPair+" sa=ike reason=lifetime") {
		t.Errorf("the IKE SA did not close at its lifetime: %s", all)
	}
	// a request sent as the session ended reaches the relay after it
	time.Sleep(quietPeriod)
	mu.Lock()
	defer mu.Unlock()
	if len(informational) != 1 {
		t.Errorf("the session sent INFORMATIONAL requests under %d Message IDs, want the one Delete", len(informational))
	}
}

// the replacement's Delete of an IKE SA whose PRF a reload removed has the budget of the Delete the lifecycle sends
// and keeps it once a Child SA reaches its lifetime behind it
func TestReplacementDeleteHasTheTeardownBudget(t *testing.T) {
	dialed := &recorder{}
	h := newResponderHarness(t, nil)
	var sent atomic.Int32
	cfg, dialing := listedConfig(h, dialed.record)
	// the Child SA's lifetime falls before the Delete's third send, and its scheduled rekey falls due behind the Delete
	cfg.ChildRekeyInterval, cfg.RekeyMargin = 1500*time.Millisecond, 200*time.Millisecond
	cfg.RemotePort = relay(t, h.remotePort, func(fromInitiator bool, header *Header, _ []byte) bool {
		if fromInitiator && header != nil && !header.IsResponse() && header.ExchangeType == INFORMATIONAL {
			sent.Add(1)
			return false
		}
		return true
	})
	initiator, responder := dialPaused(t, h, cfg)
	initiator.retransmitAfter = time.Second
	initiator.rekeyJitterSource = func(time.Duration) (time.Duration, error) { return 0, nil }
	// the peer counts as alive throughout, which gives an ordinary request the busy budget
	initiator.dpdEvery, responder.dpdEvery = time.Hour, time.Hour
	runSession(t, responder)
	run := runSession(t, initiator)
	sha256Only := suitesOf(t, Crypto{IKE: IKESuites{PRF: []string{"sha256"}}})
	dialing.Store(&sha256Only)
	initiator.SuitesChanged()
	awaitRecorded(t, dialed, "ike.sa.closed "+dialedPair+" sa=child reason=lifetime")
	if err := endedWithin(t, run, "dialing"); !errors.Is(err, ErrPRFUnlisted) {
		t.Errorf("the session ended with %v, want its IKE SA deleted for a new handshake", err)
	}
	if got := sent.Load(); got > teardownRetransmits {
		t.Errorf("the Delete was sent %d times, want at most %d", got, teardownRetransmits)
	}
}
