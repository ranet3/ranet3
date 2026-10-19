// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ike

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// chainSuite is an IKE SA of x25519+mlkem768 under AES-GCM with a 128-bit key and HMAC-SHA2-256
var chainSuite = SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256, DHGroup: DH_CURVE25519, Additions: [addkeTypes]uint16{ML_KEM_768}}

// classicalSuite is chainSuite with no additional key exchange
var classicalSuite = SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256, DHGroup: DH_CURVE25519}

// chainLists holds x25519+mlkem768 ahead of p256, and AES-GCM with a 128-bit key alone, so a rekey of chainSuite offers one proposal
var chainLists = Suites{ikeCipher: []Transform{encrAES128}, kex: []kexEntry{entry768, {group: DH_ECP_256}}}

// hybridOffer and classicalOffer are a peer's proposal of chainSuite and of classicalSuite
var (
	hybridOffer    = []Transform{encrAES128, prfSHA256, dhX25519, {Type: TransADDKE1, ID: ML_KEM_768}}
	classicalOffer = []Transform{encrAES128, prfSHA256, dhX25519}
)

func drawnOctets(t testing.TB, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// chainContext is an IKE SA in suite with keys of its own
func chainContext(t testing.TB, suite SASuite) *ikeContext {
	t.Helper()
	keyLen := int(suite.EncrKeyBits)/8 + 4
	return &ikeContext{suite: suite, spiI: randUint64Nonzero(), spiR: randUint64Nonzero(), skD: drawnOctets(t, 48),
		skei: drawnOctets(t, keyLen), sker: drawnOctets(t, keyLen), established: time.Now()}
}

// initiatingSession is a session of an IKE SA in suite under lists whose requests the test answers in place of Run
func initiatingSession(t *testing.T, suite SASuite, lists Suites) (*Session, *recorder) {
	t.Helper()
	mux, _ := lifecycleMuxes(t)
	events := &recorder{}
	return &Session{mux: mux, current: chainContext(t, suite), requests: make(chan *localRequest, 1), suites: func() Suites { return lists }, events: events.record}, events
}

// answeringChain is a session answering rekeys of an IKE SA in suite under lists, which holds a Child SA of local SPI 21 and remote SPI 22
func answeringChain(t *testing.T, suite SASuite, lists Suites) (*Session, *recorder) {
	t.Helper()
	mux, _ := lifecycleMuxes(t)
	s := answeringSession(t, mux, suite, ChildSA{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, LocalSPI: 21, RemoteSPI: 22}, 0, lists)
	keyLen := int(suite.EncrKeyBits)/8 + 4
	s.current.skei, s.current.sker = drawnOctets(t, keyLen), drawnOctets(t, keyLen)
	events := &recorder{}
	s.events = events.record
	return s, events
}

// rekeying starts s's IKE SA rekey and hands back how it ends
func rekeying(s *Session) <-chan error {
	done := make(chan error, 1)
	go func() { done <- s.RekeyIKE() }()
	return done
}

// drawsInTurn has s draw each of nonces in turn, as the Ni of its own rekey or the Nr of its answer to the peer's, and the last again once they run out
func drawsInTurn(s *Session, nonces ...[]byte) {
	var drawn atomic.Int32
	s.ikeRekeyNonce = func(n []byte) error {
		copy(n, nonces[min(int(drawn.Add(1)), len(nonces))-1])
		return nil
	}
}

// requested is the next request of s's rekey, which must be of exchange
func requested(t *testing.T, s *Session, done <-chan error, exchange ExchangeType) *localRequest {
	t.Helper()
	select {
	case request := <-s.requests:
		if request.exchange != exchange {
			request.result <- requestResult{err: errors.New("not the exchange the test expects")}
			t.Fatalf("the rekey sent exchange %d, want %d", request.exchange, exchange)
		}
		return request
	case err := <-done:
		t.Fatalf("the rekey ended with %v before its exchange %d", err, exchange)
	case <-time.After(answerBudget):
		t.Fatalf("the rekey sent no exchange %d", exchange)
	}
	return nil
}

// ended is how s's rekey ended, which must come with no further request
func ended(t *testing.T, s *Session, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case request := <-s.requests:
		request.result <- requestResult{err: errors.New("not an exchange the test expects")}
		t.Fatalf("the rekey sent exchange %d, want it ended", request.exchange)
	case <-time.After(answerBudget):
		t.Fatal("the rekey never ended")
	}
	return nil
}

// noRequest checks that s's rekey sends nothing for quietPeriod
func noRequest(t *testing.T, s *Session, done <-chan error, why string) {
	t.Helper()
	select {
	case request := <-s.requests:
		request.result <- requestResult{err: errors.New("not an exchange the test expects")}
		t.Fatalf("%s, the rekey sent exchange %d", why, request.exchange)
	case err := <-done:
		t.Fatalf("%s, the rekey ended with %v", why, err)
	case <-time.After(quietPeriod):
	}
}

func offerOf(t *testing.T, request []RawPayload) []Proposal {
	t.Helper()
	sa := findType(request, PayloadSA)
	if sa == nil {
		t.Fatalf("the request carries payload types %v and no SA", payloadTypes(request))
	}
	offer, err := DecodeSA(sa.Body)
	if err != nil {
		t.Fatal(err)
	}
	return offer
}

func notifyAnswer(notifyType NotifyType) []RawPayload {
	return []RawPayload{{Type: PayloadN, Body: EncodeNotify(Notify{Type: notifyType})}}
}

func sameKeys(ctx *ikeContext, keys [5][]byte) bool {
	return slices.EqualFunc([][]byte{ctx.skD, ctx.skei, ctx.sker, ctx.skpi, ctx.skpr}, keys[:], bytes.Equal)
}

func keysOf(keys *IKEKeys) [5][]byte {
	return [5][]byte{keys.SKd, keys.SKei, keys.SKer, keys.SKpi, keys.SKpr}
}

// answerRekey answers request, a CREATE_CHILD_SA rekeying the IKE SA, with the first transform of each type in the offer's proposal at index proposal, a KE payload in the request's group, Nr nr or one drawn where nr is nil, and a link where link is non-nil
func answerRekey(t *testing.T, request []RawPayload, proposal int, link, nr []byte) ([]RawPayload, *peerRekey) {
	t.Helper()
	offer := offerOf(t, request)
	var chosen []Transform
	for _, transform := range offer[proposal].Transforms {
		if !slices.ContainsFunc(chosen, func(c Transform) bool { return c.Type == transform.Type }) {
			chosen = append(chosen, transform)
		}
	}
	ke, nonce := findType(request, PayloadKE), findType(request, PayloadNonce)
	if ke == nil || nonce == nil {
		t.Fatalf("the rekey request carries payload types %v", payloadTypes(request))
	}
	group, public, err := DecodeKE(ke.Body)
	if err != nil {
		t.Fatal(err)
	}
	dh, err := GenerateDH(group)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := dh.SharedSecret(public)
	if err != nil {
		t.Fatal(err)
	}
	if nr == nil {
		nr = drawnOctets(t, 32)
	}
	p := &peerRekey{ni: slices.Clone(nonce.Body), nr: nr, shared: shared, spiI: binary.BigEndian.Uint64(offer[proposal].SPI), spiR: randUint64Nonzero()}
	answer := []RawPayload{
		{Type: PayloadSA, Body: EncodeSA([]Proposal{{Number: offer[proposal].Number, Protocol: ProtoIKE, SPI: binary.BigEndian.AppendUint64(nil, p.spiR), Transforms: chosen}})},
		{Type: PayloadNonce, Body: EncodeNonce(p.nr)},
		{Type: PayloadKE, Body: EncodeKE(group, dh.PublicBytes())},
	}
	if link != nil {
		answer = append(answer, linkPayload(link))
	}
	return answer, p
}

// answerFollowup answers request, an IKE_FOLLOWUP_KE of method, with the ciphertext of its key and a link where link is non-nil
func (p *peerRekey) answerFollowup(t *testing.T, request []RawPayload, method uint16, link []byte) []RawPayload {
	t.Helper()
	key, err := keData(request, method)
	if err != nil {
		t.Fatalf("the IKE_FOLLOWUP_KE request carries no key of method %d: %v", method, err)
	}
	secret, ciphertext := modelEncapsulate(t, method, key)
	p.secrets = append(p.secrets, secret)
	answer := []RawPayload{{Type: PayloadKE, Body: EncodeKE(method, ciphertext)}}
	if link != nil {
		answer = append(answer, linkPayload(link))
	}
	return answer
}

// peerRekey is the peer's end of a rekey with the session under test, as the test plays it: its own rekey of the IKE SA or the Child SA, or its answer to the session's rekey, and what both ends derive the new SA from
type peerRekey struct {
	dh         *DHKeyPair
	ni, nr     []byte
	spiI, spiR uint64
	// espI and espR are the peer's and the session's SPI of the Child SA a Child SA rekey makes
	espI, espR uint32
	shared     []byte
	// link is the one the last answer carried, nil after an answer without one
	link    []byte
	secrets [][]byte
}

// newPeerRekey is a peer's rekey offering transforms, with its KE payload in X25519 and Ni ni
func newPeerRekey(t testing.TB, transforms []Transform, ni []byte) (*peerRekey, []RawPayload) {
	t.Helper()
	dh, err := GenerateDH(DH_CURVE25519)
	if err != nil {
		t.Fatal(err)
	}
	p := &peerRekey{dh: dh, ni: ni, spiI: randUint64Nonzero()}
	return p, []RawPayload{
		{Type: PayloadSA, Body: EncodeSA([]Proposal{{Number: 1, Protocol: ProtoIKE, SPI: binary.BigEndian.AppendUint64(nil, p.spiI), Transforms: transforms}})},
		{Type: PayloadNonce, Body: EncodeNonce(ni)},
		{Type: PayloadKE, Body: EncodeKE(DH_CURVE25519, dh.PublicBytes())},
	}
}

// read takes the responder's SPI, Nr, SK(0) and link from answer where it took the rekey
func (p *peerRekey) read(t testing.TB, answer []RawPayload) {
	t.Helper()
	sa, nonce, ke := findType(answer, PayloadSA), findType(answer, PayloadNonce), findType(answer, PayloadKE)
	if sa == nil || nonce == nil || ke == nil {
		return
	}
	proposals, err := DecodeSA(sa.Body)
	if err != nil || len(proposals) != 1 {
		t.Fatalf("the answer to the peer's rekey chose %+v, %v", proposals, err)
	}
	_, public, err := DecodeKE(ke.Body)
	if err != nil {
		t.Fatal(err)
	}
	if p.shared, err = p.dh.SharedSecret(public); err != nil {
		t.Fatal(err)
	}
	if proposals[0].Protocol == ProtoESP {
		p.espR = binary.BigEndian.Uint32(proposals[0].SPI)
	} else {
		p.spiR = binary.BigEndian.Uint64(proposals[0].SPI)
	}
	p.nr = slices.Clone(nonce.Body)
	if p.link, err = linkOf(answer); err != nil {
		t.Fatal(err)
	}
}

// rekey hands the peer's request on ctx to handle, the session's handler of an IKE SA or a Child SA rekey, and reads the answer
func (p *peerRekey) rekey(t testing.TB, handle func(*ikeContext, uint32, []RawPayload) ([]byte, error), ctx *ikeContext, request []RawPayload) []RawPayload {
	t.Helper()
	raw, err := handle(ctx, 0, request)
	if err != nil {
		t.Fatalf("the peer's rekey ended the IKE SA: %v", err)
	}
	answer := sealedAnswer(t, ctx, raw)
	p.read(t, answer)
	return answer
}

// followupRequest is the peer's IKE_FOLLOWUP_KE of method echoing link, and how it decapsulates the answer
func followupRequest(t testing.TB, method uint16, link []byte) ([]RawPayload, func([]byte) ([]byte, error)) {
	t.Helper()
	decapsulate, key := modelKEM(t, method)
	request := []RawPayload{{Type: PayloadKE, Body: EncodeKE(method, key)}}
	if link != nil {
		request = append(request, linkPayload(link))
	}
	return request, decapsulate
}

// take decapsulates the ciphertext of method an answer carries, and takes its link
func (p *peerRekey) take(t testing.TB, answer []RawPayload, method uint16, decapsulate func([]byte) ([]byte, error)) {
	t.Helper()
	if ke := findType(answer, PayloadKE); ke != nil {
		got, ciphertext, err := DecodeKE(ke.Body)
		if err != nil || got != method {
			t.Fatalf("the IKE_FOLLOWUP_KE answer's KE payload names method %d, want %d: %v", got, method, err)
		}
		secret, err := decapsulate(ciphertext)
		if err != nil {
			t.Fatalf("the answer's ciphertext of %d octets does not decapsulate: %v", len(ciphertext), err)
		}
		p.secrets = append(p.secrets, secret)
		link, err := linkOf(answer)
		if err != nil {
			t.Fatal(err)
		}
		p.link = link
	}
}

// followup runs the peer's IKE_FOLLOWUP_KE of method on ctx, echoing link, and takes the secret and the link of an answer that carries a ciphertext
func (p *peerRekey) followup(t testing.TB, s *Session, ctx *ikeContext, method uint16, link []byte) ([]RawPayload, error) {
	t.Helper()
	request, decapsulate := followupRequest(t, method, link)
	raw, err := s.handleFollowup(ctx, 0, request)
	if raw == nil {
		t.Fatalf("the IKE_FOLLOWUP_KE drew no answer: %v", err)
	}
	answer := sealedAnswer(t, ctx, raw)
	p.take(t, answer, method, decapsulate)
	return answer, err
}

// keys is the new SA's keys as the peer derives them, under old and in suite
func (p *peerRekey) keys(t testing.TB, old *ikeContext, suite SASuite) [5][]byte {
	t.Helper()
	keys, err := DeriveRekeyedIKEKeys(old.suite.PRFID, old.skD, suite, p.shared, p.ni, p.nr, p.spiI, p.spiR, p.secrets...)
	if err != nil {
		t.Fatal(err)
	}
	return keysOf(keys)
}

// appendixA3Keys is the keys of the new SA computed with crypto/hmac from RFC 9370 section 2.2.4 and RFC 7296 sections 2.13, 2.14 and 2.18, under modelSuite
func appendixA3Keys(old *ikeContext, shared, ni, nr []byte, spiI, spiR uint64, secrets [][]byte) [5][]byte {
	skeyseed := modelPRF(old.skD, concat(slices.Concat([][]byte{shared, ni, nr}, secrets)...))
	var spis [16]byte
	binary.BigEndian.PutUint64(spis[:8], spiI)
	binary.BigEndian.PutUint64(spis[8:], spiR)
	return modelKeys(sha512.New384, skeyseed, concat(ni, nr, spis[:]), modelKeyLen)
}

// an IKE SA rekey of an SA of x25519+mlkem768 offers only that entry while the lists hold it, though they hold p256 as well
// the answer's link comes back intact in the IKE_FOLLOWUP_KE that runs ML-KEM-768, and the session holds the old SA and starts no other request of its own until that exchange ends
// the new SA's keys take the ML-KEM-768 secret after the nonces, and it is current from there, before the old SA's Delete
// RFC 9370 section 2.2.4: "The initiator MUST send back this notification intact in the request message of the next IKE_FOLLOWUP_KE exchange."
// RFC 9370 section 2.2.4: "With multiple key exchanges, the SAs are not yet created when the CREATE_CHILD_SA is completed. Instead, they would be created only after the series of IKE_FOLLOWUP_KE exchanges is finished."
func TestHybridIKESARekeyEchoesTheLinkAndSwitchesAfterTheFollowup(t *testing.T) {
	s, events := initiatingSession(t, chainSuite, chainLists)
	old := s.current
	done := rekeying(s)
	create := requested(t, s, done, CREATE_CHILD_SA)
	if offer := offerOf(t, create.inner); len(offer) != 1 || !slices.Equal(kexOf(offer[0]), []Transform{dhX25519, {Type: TransADDKE1, ID: ML_KEM_768}}) {
		t.Errorf("the rekey offered %+v, want x25519+mlkem768 alone", offer)
	}
	if !s.quiet.Load() {
		t.Error("the session left its other requests on while its CREATE_CHILD_SA was out")
	}
	link := []byte("link1, opaque to the initiator")
	answer, peer := answerRekey(t, create.inner, 0, link, nil)
	create.result <- requestResult{inner: answer}

	followup := requested(t, s, done, IKE_FOLLOWUP_KE)
	if got, err := linkOf(followup.inner); err != nil || !bytes.Equal(got, link) {
		t.Errorf("the IKE_FOLLOWUP_KE echoed %q, %v, want %q", got, err, link)
	}
	if followup.context != old {
		t.Error("the IKE_FOLLOWUP_KE runs on another SA than the one the rekey replaces")
	}
	if !s.quiet.Load() {
		t.Error("the session left its other requests on during its IKE_FOLLOWUP_KE")
	}
	if current, _ := s.contexts(); current != old {
		t.Error("the session switched to the new SA before its IKE_FOLLOWUP_KE ended")
	}
	followup.result <- requestResult{inner: peer.answerFollowup(t, followup.inner, ML_KEM_768, nil)}

	deletion := requested(t, s, done, INFORMATIONAL)
	if deletion.context != old || findType(deletion.inner, PayloadD) == nil {
		t.Errorf("the request after the chain carries %v, want the Delete of the old SA", payloadTypes(deletion.inner))
	}
	current, _ := s.contexts()
	if current == old || current.suite != chainSuite || current.spiI != peer.spiI || current.spiR != peer.spiR || !sameKeys(current, peer.keys(t, old, chainSuite)) {
		t.Errorf("the session is current on an SA in %+v, want the one of x25519+mlkem768 its chain made", current.suite)
	}
	deletion.result <- requestResult{}
	if err := ended(t, s, done); err != nil {
		t.Fatal(err)
	}
	if s.quiet.Load() {
		t.Error("the session left its other requests off after its rekey")
	}
	awaitRecorded(t, events, "ike.rekey.completed > sa=ike suite=aes128gcm/sha256/x25519+mlkem768")
}

// RFC 9370 Appendix A.3 with ML-KEM-768 for PQ_KEM_2 and ML-KEM-1024 for PQ_KEM_5: an IKE SA of X25519 alone rekeyed into one of x25519+mlkem768+mlkem1024
// the first IKE_FOLLOWUP_KE runs ML-KEM-768 and echoes link1 of the CREATE_CHILD_SA answer, the second runs ML-KEM-1024 and echoes link2 of the first one's answer
// a send of each from followupWait after the answer before it on is late, the peer free to drop its chain then
// the new SA's keys are SKEYSEED = prf(SK_d, SK(0) | Ni | Nr | SK(1) | SK(2)) through prf+, computed with crypto/hmac
// RFC 9370 section 2.2.4: "The former "Diffie-Hellman Group Num" (now called "Key Exchange Method") field in the KEi(n) and KEr(n) payloads MUST match the n-th negotiated additional key exchange."
func TestIKESARekeyOfAppendixA3AsInitiator(t *testing.T) {
	s, _ := initiatingSession(t, modelSuite, Suites{ikeCipher: []Transform{encrAES256}, kex: []kexEntry{entry768And1024}})
	old := s.current
	done := rekeying(s)
	create := requested(t, s, done, CREATE_CHILD_SA)
	if offer := offerOf(t, create.inner); len(offer) != 1 || !slices.Equal(kexOf(offer[0]), []Transform{dhX25519, {Type: TransADDKE1, ID: ML_KEM_768}, {Type: TransADDKE1 + 1, ID: ML_KEM_1024}}) {
		t.Fatalf("the rekey offered %+v, want x25519+mlkem768+mlkem1024 alone", offer)
	}
	link1, link2 := []byte("link1"), []byte("link2")
	answer, peer := answerRekey(t, create.inner, 0, link1, nil)
	handed := time.Now()
	create.result <- requestResult{inner: answer}
	for _, step := range []struct {
		method       uint16
		echoed, next []byte
	}{{ML_KEM_768, link1, link2}, {ML_KEM_1024, link2, nil}} {
		followup := requested(t, s, done, IKE_FOLLOWUP_KE)
		if len(followup.inner) != 2 || followup.inner[0].Type != PayloadKE || followup.context != old {
			t.Fatalf("the IKE_FOLLOWUP_KE of method %d carries %v, want KEi and the link on the old SA", step.method, payloadTypes(followup.inner))
		}
		if got, err := linkOf(followup.inner); err != nil || !bytes.Equal(got, step.echoed) {
			t.Errorf("the IKE_FOLLOWUP_KE of method %d echoed %q, %v, want %q", step.method, got, err, step.echoed)
		}
		if followup.lateFrom.Before(handed.Add(followupWait)) || followup.lateFrom.After(time.Now().Add(followupWait)) {
			t.Errorf("the IKE_FOLLOWUP_KE of method %d counts its sends late from %s after the answer before it, want followupWait of %s", step.method, followup.lateFrom.Sub(handed), followupWait)
		}
		reply := peer.answerFollowup(t, followup.inner, step.method, step.next)
		handed = time.Now()
		followup.result <- requestResult{inner: reply}
	}
	deletion := requested(t, s, done, INFORMATIONAL)
	current, _ := s.contexts()
	want := appendixA3Keys(old, peer.shared, peer.ni, peer.nr, peer.spiI, peer.spiR, peer.secrets)
	if current == old || current.suite.Additions != entry768And1024.additions || !sameKeys(current, want) {
		t.Errorf("the session is current on an SA in %+v, want x25519+mlkem768+mlkem1024 keyed by the chain of Appendix A.3", current.suite)
	}
	deletion.result <- requestResult{}
	if err := ended(t, s, done); err != nil {
		t.Fatal(err)
	}
}

// RFC 9370 Appendix A.3 as the responder answers it, with ML-KEM-768 for PQ_KEM_2, ML-KEM-1024 for PQ_KEM_5, ML-KEM-512 for PQ_KEM_1 and a private use ID for PQ_KEM_6, which this end lacks
// the CREATE_CHILD_SA answer and the first IKE_FOLLOWUP_KE answer each carry a link of their own, the last answer none, and the SA is not replaced until that last exchange
// RFC 9370 section 2.2.4: "The responder MUST include this notification in a CREATE_CHILD_SA or IKE_FOLLOWUP_KE response message in case the next IKE_FOLLOWUP_KE exchange is expected, filling it with some data that would allow linking the current exchange to the next one."
func TestIKESARekeyOfAppendixA3AsResponder(t *testing.T) {
	const mlkem512, private = 35, 1025
	s, _ := answeringChain(t, modelSuite, Suites{kex: []kexEntry{entry768And1024}})
	ctx := s.current
	p, request := newPeerRekey(t, ikeOffer(addkeOf(TransADDKE1, mlkem512, ML_KEM_768), addkeOf(TransADDKE1+1, ML_KEM_1024, private, 0))[0].Transforms, drawnOctets(t, 32))
	answer := p.rekey(t, s.handleIKERekey, ctx, request)
	proposals, err := DecodeSA(findType(answer, PayloadSA).Body)
	if want := slices.Concat(modelBase, addkeOf(TransADDKE1, ML_KEM_768), addkeOf(TransADDKE1+1, ML_KEM_1024)); err != nil || len(proposals) != 1 || !slices.Equal(proposals[0].Transforms, want) {
		t.Fatalf("the responder answered %+v, %v, want %+v", proposals, err, want)
	}
	link1 := p.link
	if len(link1) != followupLinkLen {
		t.Fatalf("the CREATE_CHILD_SA answer carries the link %x, want %d octets", link1, followupLinkLen)
	}
	first, err := p.followup(t, s, ctx, ML_KEM_768, link1)
	if err != nil || len(first) != 2 || first[0].Type != PayloadKE || len(p.link) != followupLinkLen || bytes.Equal(p.link, link1) {
		t.Fatalf("the first IKE_FOLLOWUP_KE drew %v with the link %x, %v, want KEr and a link of its own", payloadTypes(first), p.link, err)
	}
	if current, _ := s.contexts(); current != ctx {
		t.Fatal("the responder replaced the SA before the last IKE_FOLLOWUP_KE")
	}
	last, err := p.followup(t, s, ctx, ML_KEM_1024, p.link)
	if err != nil || len(last) != 1 || last[0].Type != PayloadKE {
		t.Fatalf("the last IKE_FOLLOWUP_KE drew %v, %v, want KEr alone", payloadTypes(last), err)
	}
	current, retained := s.contexts()
	want := appendixA3Keys(ctx, p.shared, p.ni, p.nr, p.spiI, p.spiR, p.secrets)
	if current == ctx || retained != ctx || current.suite.Additions != entry768And1024.additions || !sameKeys(current, want) {
		t.Errorf("the responder is current on an SA in %+v and retains the old one is %v, want x25519+mlkem768+mlkem1024 keyed by the chain of Appendix A.3", current.suite, retained == ctx)
	}
}

// an answer to an IKE SA rekey that selected an additional key exchange or carried a link, and that this end refuses, ends the IKE SA with a Delete, since the peer may hold a chain waiting on this end
// a classical answer refused so fails the rekey alone, and its schedule retries, an answer whose ADDKE type selects NONE among them
// RFC 9370 section 2.2.1: "If this happens in the CREATE_CHILD_SA exchange, then the initiator MAY delete the IKE SA over which the invalid message was received by sending a Delete payload."
func TestRefusedRekeyAnswerThatChainsEndsTheIKESA(t *testing.T) {
	classicalLists := Suites{ikeCipher: []Transform{encrAES128}, kex: []kexEntry{entryX25519}}
	link := []byte("link1")
	adding := func(addition Transform) func(*testing.T, []RawPayload) {
		return func(t *testing.T, answer []RawPayload) {
			sa := findType(answer, PayloadSA)
			proposals, err := DecodeSA(sa.Body)
			if err != nil {
				t.Fatal(err)
			}
			proposals[0].Transforms = append(proposals[0].Transforms, addition)
			sa.Body = EncodeSA(proposals)
		}
	}
	short := func(t *testing.T, answer []RawPayload) { findType(answer, PayloadNonce).Body = make([]byte, 8) }
	for name, test := range map[string]struct {
		suite  SASuite
		lists  Suites
		link   []byte
		edit   func(*testing.T, []RawPayload)
		ending bool
	}{
		"a duplicate choice in ADDKE1":                 {suite: chainSuite, lists: chainLists, link: link, edit: adding(Transform{Type: TransADDKE1, ID: ML_KEM_768}), ending: true},
		"an additional key exchange and no link":       {suite: chainSuite, lists: chainLists, ending: true},
		"a link and no additional key exchange":        {suite: classicalSuite, lists: classicalLists, link: link, ending: true},
		"an additional key exchange and a short nonce": {suite: chainSuite, lists: chainLists, link: link, edit: short, ending: true},
		"no additional key exchange and a short nonce": {suite: classicalSuite, lists: classicalLists, edit: short},
		"NONE in an ADDKE type the offer left out":     {suite: classicalSuite, lists: classicalLists, edit: adding(Transform{Type: TransADDKE1, ID: 0})},
	} {
		t.Run(name, func(t *testing.T) {
			s, _ := initiatingSession(t, test.suite, test.lists)
			old := s.current
			done := rekeying(s)
			create := requested(t, s, done, CREATE_CHILD_SA)
			answer, _ := answerRekey(t, create.inner, 0, test.link, nil)
			if test.edit != nil {
				test.edit(t, answer)
			}
			create.result <- requestResult{inner: answer}
			err := ended(t, s, done)
			ending, isEnding := errors.AsType[*saEnding](err)
			if err == nil || isEnding != test.ending || isEnding && ending.reason != "rekey answer refused" {
				t.Errorf("the rekey ended with %v, ending the IKE SA is %v, want %v", err, isEnding, test.ending)
			}
			if current, _ := s.contexts(); current != old {
				t.Error("a refused answer replaced the SA")
			}
		})
	}
}

// a ciphertext in the IKE_FOLLOWUP_KE answer that fails the check of FIPS 203 section 7.3, a missing one and one of another method end the IKE SA with a Delete, each recorded as ike.kex.rejected as IKE_INTERMEDIATE records it
// draft-ietf-ipsecme-ikev2-mlkem-09 section 2.2: "If the error occurs in the CREATE_CHILD_SA or IKE_FOLLOWUP_KE exchanges, the initiator MUST delete the existing IKE SA and send a Delete payload in a new INFORMATIONAL exchange for the responder to also remove it."
func TestRejectedFollowupCiphertextEndsTheIKESA(t *testing.T) {
	recut := func(method uint16, cut int) func(t *testing.T, peer *peerRekey, request []RawPayload) []RawPayload {
		return func(t *testing.T, peer *peerRekey, request []RawPayload) []RawPayload {
			answer := peer.answerFollowup(t, request, ML_KEM_768, nil)
			_, ciphertext, err := DecodeKE(answer[0].Body)
			if err != nil {
				t.Fatal(err)
			}
			answer[0].Body = EncodeKE(method, ciphertext[:len(ciphertext)-cut])
			return answer
		}
	}
	for name, reply := range map[string]func(t *testing.T, peer *peerRekey, request []RawPayload) []RawPayload{
		"a ciphertext one octet short": recut(ML_KEM_768, 1),
		"no KE payload":                func(*testing.T, *peerRekey, []RawPayload) []RawPayload { return nil },
		"a KE payload of ML-KEM-1024":  recut(ML_KEM_1024, 0),
	} {
		t.Run(name, func(t *testing.T) {
			s, events := initiatingSession(t, chainSuite, chainLists)
			old := s.current
			done := rekeying(s)
			create := requested(t, s, done, CREATE_CHILD_SA)
			answer, peer := answerRekey(t, create.inner, 0, []byte("link1"), nil)
			create.result <- requestResult{inner: answer}
			followup := requested(t, s, done, IKE_FOLLOWUP_KE)
			followup.result <- requestResult{inner: reply(t, peer, followup.inner)}
			err := ended(t, s, done)
			if ending, ok := errors.AsType[*saEnding](err); !ok || ending.reason != "kex rejected" {
				t.Errorf("the rekey ended with %v, want the IKE SA ended for the rejected exchange", err)
			}
			if current, _ := s.contexts(); current != old {
				t.Error("a rejected exchange replaced the SA")
			}
			rejected := slices.DeleteFunc(events.recorded(), func(line string) bool { return !strings.HasPrefix(line, "ike.kex.rejected ") })
			if want := []string{"ike.kex.rejected > exchange=IKE_FOLLOWUP_KE method=mlkem768 side=ciphertext"}; !slices.Equal(rejected, want) {
				t.Errorf("the session recorded %q, want %q", rejected, want)
			}
		})
	}
}

// an IKE_FOLLOWUP_KE answer that a further exchange follows and that carries no link ends the IKE SA with a Delete, since the peer may hold a chain waiting on this end
// RFC 9370 section 2.2.4: "The responder MUST include this notification in a CREATE_CHILD_SA or IKE_FOLLOWUP_KE response message in case the next IKE_FOLLOWUP_KE exchange is expected, filling it with some data that would allow linking the current exchange to the next one."
func TestFollowupAnswerWithoutTheNextLinkEndsTheIKESA(t *testing.T) {
	s, _ := initiatingSession(t, classicalSuite, Suites{ikeCipher: []Transform{encrAES128}, kex: []kexEntry{entry768And1024}})
	done := rekeying(s)
	create := requested(t, s, done, CREATE_CHILD_SA)
	answer, peer := answerRekey(t, create.inner, 0, []byte("link1"), nil)
	create.result <- requestResult{inner: answer}
	followup := requested(t, s, done, IKE_FOLLOWUP_KE)
	followup.result <- requestResult{inner: peer.answerFollowup(t, followup.inner, ML_KEM_768, nil)}
	err := ended(t, s, done)
	if ending, ok := errors.AsType[*saEnding](err); !ok || ending.reason != "rekey answer refused" {
		t.Errorf("the rekey ended with %v, want the IKE SA ended", err)
	}
}

// a rekey whose IKE_FOLLOWUP_KE draws STATE_NOT_FOUND fails and keeps the old SA, which its schedule rekeys again after its backoff
// the third series in a row to draw it ends the IKE SA with a Delete, and a series that fails otherwise starts the count again
// RFC 9370 section 2.2.4: "If the initiator receives this notification in response to an IKE_FOLLOWUP_KE exchange performing an additional key exchange, it MUST cancel this exchange and MUST treat the whole series of exchanges started from the CREATE_CHILD_SA exchange as having failed."
// RFC 9370 section 2.2.4: "If the initiator continues to receive STATE_NOT_FOUND notifications after several retries, it MUST treat this situation as a fatal error and delete the IKE SA by sending a DELETE payload."
func TestStateNotFoundFailsTheSeriesAndTheThirdInARowEndsTheIKESA(t *testing.T) {
	s, _ := initiatingSession(t, chainSuite, chainLists)
	old := s.current
	notFound, temporary := notifyAnswer(N_STATE_NOT_FOUND), notifyAnswer(N_TEMPORARY_FAILURE)
	for n, step := range []struct {
		answer []RawPayload
		ending bool
	}{{notFound, false}, {notFound, false}, {temporary, false}, {notFound, false}, {notFound, false}, {notFound, true}} {
		done := rekeying(s)
		create := requested(t, s, done, CREATE_CHILD_SA)
		answer, _ := answerRekey(t, create.inner, 0, []byte("link1"), nil)
		create.result <- requestResult{inner: answer}
		followup := requested(t, s, done, IKE_FOLLOWUP_KE)
		followup.result <- requestResult{inner: step.answer}
		err := ended(t, s, done)
		ending, isEnding := errors.AsType[*saEnding](err)
		if err == nil || isEnding != step.ending || isEnding && ending.reason != "state not found" {
			t.Fatalf("series %d ended with %v, ending the IKE SA is %v, want %v", n+1, err, isEnding, step.ending)
		}
		if current, _ := s.contexts(); current != old {
			t.Fatalf("series %d replaced the SA", n+1)
		}
	}
}

// a peer's rekey that crosses this end's, both with additional key exchanges or one of them, is settled on the four nonces before any IKE_FOLLOWUP_KE
// the end whose CREATE_CHILD_SA holds the lowest nonce sends no IKE_FOLLOWUP_KE and deletes the SA its exchange made, where it made one
// and while it waits for the peer's chain it starts no request of its own, the waiting rekey ending once the peer's SA is current
// a peer that sends its IKE_FOLLOWUP_KE all the same after losing is answered TEMPORARY_FAILURE and its chain dropped
// RFC 9370 section 2.2.4: "if additional key exchanges are negotiated in the CREATE_CHILD_SA exchange in which the smallest nonce is used, then, because there is nothing to delete yet, the initiator of this exchange just stops the rekeying process, and it MUST NOT initiate the IKE_FOLLOWUP_KE exchange."
// RFC 7296 section 2.8.2: "The new IKE SA containing the lowest nonce SHOULD be deleted by the node that created it, and the other surviving new IKE SA MUST inherit all the Child SAs."
func TestSimultaneousRekeysWithAdditionalKeyExchanges(t *testing.T) {
	lowest, below, own, answered := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{5}, 32), bytes.Repeat([]byte{6}, 32)
	above := bytes.Repeat([]byte{4}, 32)
	both := Suites{ikeCipher: []Transform{encrAES128}, kex: []kexEntry{entryX25519, entry768}}
	classicalOnly := Suites{ikeCipher: []Transform{encrAES128}, kex: []kexEntry{entryX25519}}
	for name, test := range map[string]struct {
		suite SASuite
		// lists is this end's when its rekey starts, and reloaded where the peer's arrives
		lists, reloaded Suites
		peerOffer       []Transform
		// proposal is the one of this end's offer the peer's answer takes, link its link
		proposal int
		link     []byte
		// peerNonce is the peer's Ni, which is the lowest of the four or above this end's
		peerNonce []byte
	}{
		"both chained, this end's holding the lowest nonce": {suite: chainSuite, lists: chainLists, peerOffer: hybridOffer, link: []byte("link1"), peerNonce: above},
		"both chained, the peer's holding the lowest nonce": {suite: chainSuite, lists: chainLists, peerOffer: hybridOffer, link: []byte("link1"), peerNonce: lowest},
		"this end's classical and holding the lowest nonce, the peer's chained after a reload": {
			suite: classicalSuite, lists: classicalOnly, reloaded: both, peerOffer: hybridOffer, peerNonce: above,
		},
		"this end's chained and holding the lowest nonce, the peer's classical": {
			suite: classicalSuite, lists: both, peerOffer: classicalOffer, proposal: 1, link: []byte("link1"), peerNonce: above,
		},
	} {
		t.Run(name, func(t *testing.T) {
			var lists atomic.Pointer[Suites]
			lists.Store(&test.lists)
			s, events := initiatingSession(t, test.suite, test.lists)
			s.suites = func() Suites { return *lists.Load() }
			drawsInTurn(s, below, own)
			old := s.current
			done := rekeying(s)
			create := requested(t, s, done, CREATE_CHILD_SA)
			if test.reloaded.kex != nil {
				lists.Store(&test.reloaded)
			}
			peer, request := newPeerRekey(t, test.peerOffer, test.peerNonce)
			if answer := peer.rekey(t, s.handleIKERekey, old, request); findType(answer, PayloadSA) == nil {
				t.Fatalf("the peer's rekey drew %v, want it answered", payloadTypes(answer))
			}
			answer, _ := answerRekey(t, create.inner, test.proposal, test.link, answered)
			create.result <- requestResult{inner: answer}
			peerChained, ownChained := peer.link != nil, test.link != nil

			if bytes.Equal(test.peerNonce, lowest) {
				// this end's chain goes on, and the peer's IKE_FOLLOWUP_KE that should not come is refused
				followup := requested(t, s, done, IKE_FOLLOWUP_KE)
				if refused, err := peer.followup(t, s, old, ML_KEM_768, peer.link); err != nil || !notified(refused, N_TEMPORARY_FAILURE, nil) {
					t.Errorf("the losing peer's IKE_FOLLOWUP_KE drew %v, %v, want TEMPORARY_FAILURE", payloadTypes(refused), err)
				}
				awaitRecorded(t, events, "ike.followup.dropped > sa=ike reason=superseded")
				answering := &peerRekey{}
				followup.result <- requestResult{inner: answering.answerFollowup(t, followup.inner, ML_KEM_768, nil)}
				deletion := requested(t, s, done, INFORMATIONAL)
				deletion.result <- requestResult{}
				if err := ended(t, s, done); err != nil {
					t.Fatal(err)
				}
				if current, _ := s.contexts(); current == old || current.spiI == peer.spiI {
					t.Error("the session is not current on the SA of its own rekey, which won")
				}
				if late, err := peer.followup(t, s, old, ML_KEM_768, peer.link); err != nil || !notified(late, N_STATE_NOT_FOUND, nil) {
					t.Errorf("the losing peer's IKE_FOLLOWUP_KE after the rekey drew %v, %v, want STATE_NOT_FOUND", payloadTypes(late), err)
				}
				return
			}

			if !ownChained {
				// the SA this end's classical exchange made goes by this end's Delete
				deletion := requested(t, s, done, INFORMATIONAL)
				if deletion.context == old || deletion.context.spiR != binary.BigEndian.Uint64(offerOf(t, answer)[0].SPI) || findType(deletion.inner, PayloadD) == nil {
					t.Errorf("the request after losing carries %v, want the Delete of the SA this end's exchange made", payloadTypes(deletion.inner))
				}
				deletion.result <- requestResult{}
			}
			if !peerChained {
				// the peer's SA is current already
				if err := ended(t, s, done); err != nil {
					t.Fatal(err)
				}
			} else {
				noRequest(t, s, done, "while it waits for the peer's chain")
				if !s.quiet.Load() {
					t.Error("the session left its other requests on while it waits for the peer's chain")
				}
				if last, err := peer.followup(t, s, old, ML_KEM_768, peer.link); err != nil || findType(last, PayloadKE) == nil {
					t.Fatalf("the peer's IKE_FOLLOWUP_KE drew %v, %v, want KEr", payloadTypes(last), err)
				}
				if err := ended(t, s, done); err != nil {
					t.Fatal(err)
				}
			}
			if current, _ := s.contexts(); current.spiI != peer.spiI || current.spiR != peer.spiR {
				t.Error("the session is not current on the SA of the peer's rekey, which won")
			}
			if s.quiet.Load() {
				t.Error("the session left its other requests off after the peer's SA replaced the old one")
			}
		})
	}
}

// a peer's chain that ends while this end's crossing CREATE_CHILD_SA is still out makes an SA held as the collision's candidate, as a classical rekey's is, and the old SA stays current until this end's answer
// the four nonces then settle it: the peer's SA becomes current where this end's exchange holds the lowest nonce, and the SA of this end's chain where the peer's does, the peer's kept for the peer's Delete
// RFC 7296 section 2.8.2: "The new IKE SA containing the lowest nonce SHOULD be deleted by the node that created it, and the other surviving new IKE SA MUST inherit all the Child SAs."
func TestPeerChainEndingBeforeThisEndsAnswerIsHeldAsTheCollision(t *testing.T) {
	lowest, below, above, own, answered := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{4}, 32), bytes.Repeat([]byte{5}, 32), bytes.Repeat([]byte{6}, 32)
	for name, peerNonce := range map[string][]byte{
		"this end's exchange holding the lowest nonce": above,
		"the peer's exchange holding the lowest nonce": lowest,
	} {
		t.Run(name, func(t *testing.T) {
			s, _ := initiatingSession(t, chainSuite, chainLists)
			drawsInTurn(s, below, own)
			old := s.current
			done := rekeying(s)
			create := requested(t, s, done, CREATE_CHILD_SA)
			peer, request := newPeerRekey(t, hybridOffer, peerNonce)
			if answer := peer.rekey(t, s.handleIKERekey, old, request); peer.link == nil {
				t.Fatalf("the peer's rekey drew %v, want it answered with a link", payloadTypes(answer))
			}
			if last, err := peer.followup(t, s, old, ML_KEM_768, peer.link); err != nil || findType(last, PayloadKE) == nil {
				t.Fatalf("the peer's IKE_FOLLOWUP_KE drew %v, %v, want KEr", payloadTypes(last), err)
			}
			s.stateMu.RLock()
			current, collision := s.current, s.collision
			s.stateMu.RUnlock()
			if current != old || collision == nil || collision.spiI != peer.spiI || collision.spiR != peer.spiR {
				t.Error("the SA of the peer's chain is not held as the collision's candidate beside the old SA, which stays current")
			}
			answer, answering := answerRekey(t, create.inner, 0, []byte("link1"), answered)
			create.result <- requestResult{inner: answer}
			if bytes.Equal(peerNonce, lowest) {
				followup := requested(t, s, done, IKE_FOLLOWUP_KE)
				followup.result <- requestResult{inner: answering.answerFollowup(t, followup.inner, ML_KEM_768, nil)}
				deletion := requested(t, s, done, INFORMATIONAL)
				if deletion.context != old || findType(deletion.inner, PayloadD) == nil {
					t.Errorf("the request after the chain carries %v, want the Delete of the old SA", payloadTypes(deletion.inner))
				}
				deletion.result <- requestResult{}
				if err := ended(t, s, done); err != nil {
					t.Fatal(err)
				}
				s.stateMu.RLock()
				current, kept := s.current, s.collision
				s.stateMu.RUnlock()
				if current.spiI != answering.spiI || current.spiR != answering.spiR {
					t.Error("the session is not current on the SA of its own chain, which won")
				}
				if collision == nil || kept != collision {
					t.Error("the session let go of the peer's SA before the peer's Delete of it")
				}
				return
			}
			if err := ended(t, s, done); err != nil {
				t.Fatal(err)
			}
			if current, _ := s.contexts(); collision == nil || current != collision {
				t.Error("the session is not current on the SA of the peer's chain, which won")
			}
		})
	}
}

// a peer's rekey of the IKE SA while this end's own chain runs is answered TEMPORARY_FAILURE, one with additional key exchanges and one without, and this end's chain goes on
// RFC 9370 section 2.2.4: "a situation may occur when, due to packet loss, one of the peers receives the CREATE_CHILD_SA message requesting the rekey of an SA that is already being rekeyed by this peer (i.e., the CREATE_CHILD_SA exchange initiated by this peer has already been completed, and the series of IKE_FOLLOWUP_KE exchanges is in progress). In this case, a TEMPORARY_FAILURE notification MUST be sent in response to such a request."
func TestPeerRekeyDuringThisEndsChainDrawsTemporaryFailure(t *testing.T) {
	s, _ := initiatingSession(t, chainSuite, chainLists)
	old := s.current
	done := rekeying(s)
	create := requested(t, s, done, CREATE_CHILD_SA)
	answer, peer := answerRekey(t, create.inner, 0, []byte("link1"), nil)
	create.result <- requestResult{inner: answer}
	followup := requested(t, s, done, IKE_FOLLOWUP_KE)
	for _, offer := range [][]Transform{hybridOffer, classicalOffer} {
		crossing, request := newPeerRekey(t, offer, drawnOctets(t, 32))
		if refused := crossing.rekey(t, s.handleIKERekey, old, request); !notified(refused, N_TEMPORARY_FAILURE, nil) {
			t.Errorf("a peer's rekey offering %+v during this end's chain drew %v, want TEMPORARY_FAILURE", offer, payloadTypes(refused))
		}
	}
	followup.result <- requestResult{inner: peer.answerFollowup(t, followup.inner, ML_KEM_768, nil)}
	deletion := requested(t, s, done, INFORMATIONAL)
	deletion.result <- requestResult{}
	if err := ended(t, s, done); err != nil {
		t.Fatal(err)
	}
	if current, _ := s.contexts(); current.spiI != peer.spiI {
		t.Error("the session is not current on the SA its chain made")
	}
}

// this end starts no rekey of either SA while a peer's chain for either is open, and the rekey fails for its schedule to retry after the backoff
// RFC 9370 section 2.2.4: "In this case, a TEMPORARY_FAILURE notification MUST be sent in response to such a request."
// RFC 7296 section 2.25.1: "If a peer receives a request to rekey the IKE SA, and it is currently creating, rekeying, or closing a Child SA of that IKE SA, it SHOULD reply with TEMPORARY_FAILURE."
// RFC 7296 section 2.25.2: "If a peer receives a request to create or rekey a Child SA when it is currently rekeying the IKE SA, it SHOULD reply with TEMPORARY_FAILURE."
func TestNoOwnRekeyWhileAPeersChainIsOpen(t *testing.T) {
	for _, chain := range []string{"ike", "child"} {
		for _, own := range []string{"ike", "child"} {
			t.Run("this end's rekey of the "+own+" SA during the peer's chain of the "+chain+" SA", func(t *testing.T) {
				s, events := answeringChain(t, chainSuite, chainLists)
				s.requests = make(chan *localRequest, 1)
				if chain == "ike" {
					peer, request := newPeerRekey(t, hybridOffer, drawnOctets(t, 32))
					peer.rekey(t, s.handleIKERekey, s.current, request)
				} else {
					peer, request := newPeerChildRekey(t, s, childOffer, drawnOctets(t, 32))
					peer.rekey(t, s.handleChildRekey, s.current, request)
				}
				rekey := s.RekeyIKE
				if own == "child" {
					rekey = s.RekeyChild
				}
				done := make(chan error, 1)
				go func() { done <- rekey() }()
				select {
				case err := <-done:
					if err == nil {
						t.Fatal("this end's rekey succeeded while the peer's chain was open")
					}
				case request := <-s.requests:
					request.result <- requestResult{err: errors.New("not an exchange the test expects")}
					<-done
					t.Fatalf("this end's rekey sent exchange %d while the peer's chain was open", request.exchange)
				case <-time.After(answerBudget):
					t.Fatal("this end's rekey neither failed nor sent a request")
				}
				if got, want := events.recorded(), []string{"ike.rekey.started > sa=" + own, "ike.rekey.failed > sa=" + own}; !slices.Equal(got, want) {
					t.Errorf("the session recorded %q, want %q", got, want)
				}
				if s.chainKind() == "" {
					t.Error("this end's refused rekey ended the peer's chain")
				}
			})
		}
	}
}

// a peer's rekey of an SA of x25519+mlkem768 that leaves ML-KEM-768 out is refused while kex holds that entry, the session having proved the peer runs it
// once the lists leave the entry out, the same rekey is taken with no link
// RFC 9370 section 2.2.4: "If the initiator includes any ADDKE Transform Types in the SA payload (along with Transform Type 4), and if the responder agrees to perform additional key exchanges, then the additional key exchanges are performed in a series of new IKE_FOLLOWUP_KE exchanges that follow the CREATE_CHILD_SA exchange."
func TestPeerRekeyKeepsTheAdditionsWhileTheListsHoldTheEntry(t *testing.T) {
	for name, test := range map[string]struct {
		lists Suites
		taken bool
	}{
		"kex holding x25519+mlkem768 and x25519": {lists: Suites{ikeCipher: []Transform{encrAES128}, kex: []kexEntry{entry768, entryX25519}}},
		"kex holding x25519 alone":               {lists: Suites{ikeCipher: []Transform{encrAES128}, kex: []kexEntry{entryX25519}}, taken: true},
	} {
		t.Run(name, func(t *testing.T) {
			s, _ := answeringChain(t, chainSuite, test.lists)
			ctx := s.current
			peer, request := newPeerRekey(t, classicalOffer, drawnOctets(t, 32))
			answer := peer.rekey(t, s.handleIKERekey, ctx, request)
			current, _ := s.contexts()
			if !test.taken {
				if !notified(answer, N_NO_PROPOSAL_CHOSEN, nil) || current != ctx {
					t.Errorf("the rekey drew %v, want NO_PROPOSAL_CHOSEN and the SA kept", payloadTypes(answer))
				}
				return
			}
			if findType(answer, PayloadSA) == nil || peer.link != nil || current == ctx || current.suite != classicalSuite {
				t.Errorf("the rekey drew %v with the link %x, want it taken into an SA of x25519 with no link", payloadTypes(answer), peer.link)
			}
		})
	}
}

// an IKE_FOLLOWUP_KE that no open chain links is answered STATE_NOT_FOUND, an error that leaves the IKE SA and any chain as they were
// RFC 9370 section 2.2.4: "If the responder receives an IKE_FOLLOWUP_KE message for which it does not have a key exchange state, it MUST send back a new error type notification called "STATE_NOT_FOUND". This is an error notification that is not fatal to the IKE SA. Its Notify Message Type value is 47, its Protocol ID and SPI Size are both set to 0, and the data is empty."
func TestFollowupNoChainLinksDrawsStateNotFound(t *testing.T) {
	s, _ := answeringChain(t, chainSuite, chainLists)
	ctx := s.current
	if answer, err := (&peerRekey{}).followup(t, s, ctx, ML_KEM_768, drawnOctets(t, followupLinkLen)); err != nil || !notified(answer, N_STATE_NOT_FOUND, nil) {
		t.Errorf("an IKE_FOLLOWUP_KE with no chain open drew %v, %v, want STATE_NOT_FOUND", payloadTypes(answer), err)
	}
	peer, request := newPeerRekey(t, hybridOffer, drawnOctets(t, 32))
	peer.rekey(t, s.handleIKERekey, ctx, request)
	for name, link := range map[string][]byte{
		"another link":         drawnOctets(t, followupLinkLen),
		"the link cut short":   peer.link[:followupLinkLen-1],
		"the link lengthened":  append(slices.Clone(peer.link), 0),
		"no link notification": nil,
	} {
		if answer, err := (&peerRekey{}).followup(t, s, ctx, ML_KEM_768, link); err != nil || !notified(answer, N_STATE_NOT_FOUND, nil) {
			t.Errorf("an IKE_FOLLOWUP_KE with %s drew %v, %v, want STATE_NOT_FOUND", name, payloadTypes(answer), err)
		}
	}
	if current, _ := s.contexts(); current != ctx || s.chainKind() == "" {
		t.Fatal("an unlinked IKE_FOLLOWUP_KE ended the chain or replaced the SA")
	}
	if answer, err := peer.followup(t, s, ctx, ML_KEM_768, peer.link); err != nil || findType(answer, PayloadKE) == nil {
		t.Errorf("the linked IKE_FOLLOWUP_KE drew %v, %v, want KEr", payloadTypes(answer), err)
	}
}

// an IKE_FOLLOWUP_KE without a key of the method due that passes the checks of FIPS 203 section 7.2 is answered INVALID_SYNTAX, which ends the IKE SA without a Delete, and a key failing the checks is recorded as ike.kex.rejected
// draft-ietf-ipsecme-ikev2-mlkem-09 section 2.2: "If the checks fail, the responder MUST reject the initiator's improper public key and SHOULD send a Notify payload of type INVALID_SYNTAX as a response to the request to prevent resource exhaustion or denial of service risks."
func TestBadKeyInAFollowupIsAnsweredInvalidSyntax(t *testing.T) {
	for name, test := range map[string]struct {
		ke    func(t *testing.T) []RawPayload
		event string
	}{
		"a key one octet short": {
			ke: func(t *testing.T) []RawPayload {
				_, key := modelKEM(t, ML_KEM_768)
				return []RawPayload{{Type: PayloadKE, Body: EncodeKE(ML_KEM_768, key[:len(key)-1])}}
			},
			event: "ike.kex.rejected > exchange=IKE_FOLLOWUP_KE method=mlkem768 side=key",
		},
		"no KE payload": {ke: func(*testing.T) []RawPayload { return nil }},
		"a key of ML-KEM-1024": {
			ke: func(t *testing.T) []RawPayload {
				_, key := modelKEM(t, ML_KEM_1024)
				return []RawPayload{{Type: PayloadKE, Body: EncodeKE(ML_KEM_1024, key)}}
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, events := answeringChain(t, chainSuite, chainLists)
			ctx := s.current
			peer, request := newPeerRekey(t, hybridOffer, drawnOctets(t, 32))
			peer.rekey(t, s.handleIKERekey, ctx, request)
			raw, err := s.handleFollowup(ctx, 0, append(test.ke(t), linkPayload(peer.link)))
			if _, ending := errors.AsType[invalidSyntaxSent](err); !ending || raw == nil || !notified(sealedAnswer(t, ctx, raw), N_INVALID_SYNTAX, nil) {
				t.Errorf("the IKE_FOLLOWUP_KE drew an answer ending the IKE SA %v, %v, want INVALID_SYNTAX", ending, err)
			}
			if current, _ := s.contexts(); current != ctx {
				t.Error("a refused IKE_FOLLOWUP_KE replaced the SA")
			}
			rejected := slices.DeleteFunc(events.recorded(), func(line string) bool { return !strings.HasPrefix(line, "ike.kex.rejected ") })
			if test.event == "" && len(rejected) != 0 || test.event != "" && !slices.Equal(rejected, []string{test.event}) {
				t.Errorf("the session recorded %q, want %q", rejected, test.event)
			}
		})
	}
}

// an IKE_FOLLOWUP_KE on an IKE SA this end is closing, or on one past its lifetime and so closing as well, is answered TEMPORARY_FAILURE and leaves the chain open
// RFC 7296 section 2.25.2: "If a peer receives a request to rekey an IKE SA that it is currently trying to close, it SHOULD reply with TEMPORARY_FAILURE."
func TestFollowupOnAClosingIKESADrawsTemporaryFailure(t *testing.T) {
	for name, closing := range map[string]func(s *Session, ctx *ikeContext) (callOff func()){
		"an IKE SA this end is closing": func(s *Session, _ *ikeContext) func() {
			s.closing.Store(true)
			return func() { s.closing.Store(false) }
		},
		"an IKE SA past its lifetime": func(s *Session, ctx *ikeContext) func() {
			s.ikeRekeyInterval, ctx.established = rekeyLifetime, time.Now().Add(-rekeyLifetime)
			return func() { s.ikeRekeyInterval = 0 }
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, _ := answeringChain(t, chainSuite, chainLists)
			ctx := s.current
			peer, request := newPeerRekey(t, hybridOffer, drawnOctets(t, 32))
			peer.rekey(t, s.handleIKERekey, ctx, request)
			callOff := closing(s, ctx)
			if answer, err := (&peerRekey{}).followup(t, s, ctx, ML_KEM_768, peer.link); err != nil || !notified(answer, N_TEMPORARY_FAILURE, nil) {
				t.Errorf("an IKE_FOLLOWUP_KE on %s drew %v, %v, want TEMPORARY_FAILURE", name, payloadTypes(answer), err)
			}
			if current, _ := s.contexts(); current != ctx || s.chainKind() == "" {
				t.Fatalf("the IKE_FOLLOWUP_KE refused on %s ended the chain or replaced the SA", name)
			}
			callOff()
			if answer, err := peer.followup(t, s, ctx, ML_KEM_768, peer.link); err != nil || findType(answer, PayloadKE) == nil {
				t.Errorf("the IKE_FOLLOWUP_KE after the close was called off drew %v, %v, want KEr", payloadTypes(answer), err)
			}
		})
	}
}

// a peer's chain is dropped once followupWait passes after the answer that linked it, with ike.followup.dropped
// RFC 9370 section 2.2.4: "The responder MUST handle this situation gracefully and delete the associated state if it does not receive the next expected IKE_FOLLOWUP_KE request after some reasonable period of time."
func TestPeerChainIsDroppedAtFollowupWait(t *testing.T) {
	s, events := answeringChain(t, chainSuite, chainLists)
	ctx := s.current
	opened := time.Now()
	peer, request := newPeerRekey(t, hybridOffer, drawnOctets(t, 32))
	peer.rekey(t, s.handleIKERekey, ctx, request)
	s.expireChain(opened.Add(followupWait - beforeDeadline))
	if s.chainKind() == "" {
		t.Fatal("the chain was dropped before followupWait passed")
	}
	s.expireChain(time.Now().Add(followupWait))
	if s.chainKind() != "" {
		t.Fatal("the chain was kept past followupWait")
	}
	if got, want := events.recorded(), []string{"ike.followup.dropped > sa=ike reason=expired"}; !slices.Equal(got, want) {
		t.Errorf("the session recorded %q, want %q", got, want)
	}
	if answer, err := peer.followup(t, s, ctx, ML_KEM_768, peer.link); err != nil || !notified(answer, N_STATE_NOT_FOUND, nil) {
		t.Errorf("the IKE_FOLLOWUP_KE after the chain was dropped drew %v, %v, want STATE_NOT_FOUND", payloadTypes(answer), err)
	}
}

// each answer that links a further exchange restarts followupWait and draws a link of its own
// RFC 9370 section 2.2.4: "The responder MUST handle this situation gracefully and delete the associated state if it does not receive the next expected IKE_FOLLOWUP_KE request after some reasonable period of time."
func TestEachChainAnswerRestartsFollowupWait(t *testing.T) {
	s, _ := answeringChain(t, classicalSuite, Suites{ikeCipher: []Transform{encrAES128}, kex: []kexEntry{entry768And1024}})
	ctx := s.current
	peer, request := newPeerRekey(t, slices.Concat(classicalOffer, addkeOf(TransADDKE1, ML_KEM_768), addkeOf(TransADDKE1+1, ML_KEM_1024)), drawnOctets(t, 32))
	peer.rekey(t, s.handleIKERekey, ctx, request)
	// the chain has waited most of its time when the first IKE_FOLLOWUP_KE comes
	s.stateMu.Lock()
	s.peerChain.deadline = time.Now().Add(chainWaitCut)
	first := slices.Clone(s.peerChain.link[:])
	s.stateMu.Unlock()
	answered := time.Now()
	if answer, err := peer.followup(t, s, ctx, ML_KEM_768, peer.link); err != nil || findType(answer, PayloadKE) == nil {
		t.Fatalf("the first IKE_FOLLOWUP_KE drew %v, %v, want KEr", payloadTypes(answer), err)
	}
	s.stateMu.RLock()
	deadline, link := s.peerChain.deadline, slices.Clone(s.peerChain.link[:])
	s.stateMu.RUnlock()
	if deadline.Before(answered.Add(followupWait)) {
		t.Errorf("the chain waits until %s after the answer, want followupWait of %s", deadline.Sub(answered), followupWait)
	}
	if bytes.Equal(link, first) || !bytes.Equal(link, peer.link) {
		t.Errorf("the answer linked %x, the chain waits on %x after %x, want a new link the chain waits on", peer.link, link, first)
	}
}

// a peer's chain is superseded by the peer's next rekey of the IKE SA and by the IKE SA it runs on ceasing to be current, and links no IKE_FOLLOWUP_KE from then on
func TestNewPeerRekeySupersedesItsChain(t *testing.T) {
	s, events := answeringChain(t, chainSuite, chainLists)
	ctx := s.current
	first, request := newPeerRekey(t, hybridOffer, drawnOctets(t, 32))
	first.rekey(t, s.handleIKERekey, ctx, request)
	// the second rekey comes sooner than the limit on a peer's rekeys allows, so it starts the limit over
	s.lastPeerIKERekey.Store(0)
	second, request := newPeerRekey(t, hybridOffer, drawnOctets(t, 32))
	second.rekey(t, s.handleIKERekey, ctx, request)
	if got, want := events.recorded(), []string{"ike.followup.dropped > sa=ike reason=superseded"}; !slices.Equal(got, want) {
		t.Errorf("the session recorded %q, want %q", got, want)
	}
	if bytes.Equal(first.link, second.link) {
		t.Error("the second rekey's answer carries the first one's link")
	}
	if answer, err := first.followup(t, s, ctx, ML_KEM_768, first.link); err != nil || !notified(answer, N_STATE_NOT_FOUND, nil) {
		t.Errorf("the superseded chain's IKE_FOLLOWUP_KE drew %v, %v, want STATE_NOT_FOUND", payloadTypes(answer), err)
	}
	if answer, err := second.followup(t, s, ctx, ML_KEM_768, second.link); err != nil || findType(answer, PayloadKE) == nil {
		t.Fatalf("the second chain's IKE_FOLLOWUP_KE drew %v, %v, want KEr", payloadTypes(answer), err)
	}
	if current, _ := s.contexts(); current.spiI != second.spiI || !sameKeys(current, second.keys(t, ctx, chainSuite)) {
		t.Error("the responder is not current on the SA of the second chain")
	}

	replaced, _ := answeringChain(t, chainSuite, chainLists)
	opened := replaced.current
	peer, request := newPeerRekey(t, hybridOffer, drawnOctets(t, 32))
	peer.rekey(t, replaced.handleIKERekey, opened, request)
	next := chainContext(t, chainSuite)
	replaced.stateMu.Lock()
	replaced.current = next
	replaced.stateMu.Unlock()
	for name, ctx := range map[string]*ikeContext{"the SA the chain opened on": opened, "the current SA": next} {
		if answer, err := (&peerRekey{}).followup(t, replaced, ctx, ML_KEM_768, peer.link); err != nil || !notified(answer, N_STATE_NOT_FOUND, nil) {
			t.Errorf("the chain's IKE_FOLLOWUP_KE on %s drew %v, %v, want STATE_NOT_FOUND", name, payloadTypes(answer), err)
		}
	}
	if current, _ := replaced.contexts(); current != next || replaced.chainKind() == "" {
		t.Error("an IKE_FOLLOWUP_KE the chain did not link ended the chain or replaced the SA")
	}
	replacedEvents := &recorder{}
	replaced.events = replacedEvents.record
	replaced.expireChain(time.Now())
	if replaced.chainKind() != "" {
		t.Error("a chain on an IKE SA no longer current was kept")
	}
	if got, want := replacedEvents.recorded(), []string{"ike.followup.dropped > sa=ike reason=superseded"}; !slices.Equal(got, want) {
		t.Errorf("the session recorded %q, want %q", got, want)
	}
}

// an INFORMATIONAL beside a peer's open chain, empty or deleting the Child SA, is answered as ever and leaves the chain open
// RFC 7296 section 2.1: "Once the IKE SA is set up, either end of the Security Association may initiate requests at any time, and there can be many requests and responses "in flight" at any given moment."
func TestRequestsDuringAPeersChainAreAnsweredAsUsual(t *testing.T) {
	s, _ := answeringChain(t, chainSuite, chainLists)
	ctx := s.current
	peer, request := newPeerRekey(t, hybridOffer, drawnOctets(t, 32))
	peer.rekey(t, s.handleIKERekey, ctx, request)
	answeredAsUsual(t, s, ctx)
	if s.chainKind() == "" {
		t.Fatal("a request beside the chain ended it")
	}
	if answer, err := peer.followup(t, s, ctx, ML_KEM_768, peer.link); err != nil || findType(answer, PayloadKE) == nil {
		t.Fatalf("the IKE_FOLLOWUP_KE drew %v, %v, want KEr", payloadTypes(answer), err)
	}
	if current, _ := s.contexts(); current.spiI != peer.spiI || current.suite != chainSuite || !sameKeys(current, peer.keys(t, ctx, chainSuite)) {
		t.Error("the responder is not current on the SA of the chain")
	}
}

// an INFORMATIONAL beside this end's open chain, empty or deleting the Child SA, is answered as ever and leaves the chain open
// RFC 7296 section 2.1: "Once the IKE SA is set up, either end of the Security Association may initiate requests at any time, and there can be many requests and responses "in flight" at any given moment."
func TestRequestsDuringThisEndsChainAreAnsweredAsUsual(t *testing.T) {
	s, _ := initiatingSession(t, chainSuite, chainLists)
	s.Child = ChildSA{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, LocalSPI: 21, RemoteSPI: 22}
	s.SetChildHandler(func(ChildSA) error { return nil })
	old := s.current
	done := rekeying(s)
	create := requested(t, s, done, CREATE_CHILD_SA)
	answer, peer := answerRekey(t, create.inner, 0, []byte("link1"), nil)
	create.result <- requestResult{inner: answer}
	followup := requested(t, s, done, IKE_FOLLOWUP_KE)
	answeredAsUsual(t, s, old)
	followup.result <- requestResult{inner: peer.answerFollowup(t, followup.inner, ML_KEM_768, nil)}
	deletion := requested(t, s, done, INFORMATIONAL)
	if current, _ := s.contexts(); current.spiI != peer.spiI || !sameKeys(current, peer.keys(t, old, chainSuite)) {
		t.Error("the session is not current on the SA of its chain")
	}
	deletion.result <- requestResult{}
	if err := ended(t, s, done); err != nil {
		t.Fatal(err)
	}
}

// answeredAsUsual hands s an empty INFORMATIONAL and one deleting the Child SA of remote SPI 22 on ctx, and checks they are answered empty and with the Delete of local SPI 21
func answeredAsUsual(t *testing.T, s *Session, ctx *ikeContext) {
	t.Helper()
	header := Header{SPIInitiator: ctx.spiI, SPIResponder: ctx.spiR, ExchangeType: INFORMATIONAL, MessageID: 1}
	raw, err := s.handleRequest(ctx, &header, nil, nil)
	if err != nil || len(sealedAnswer(t, ctx, raw)) != 0 {
		t.Errorf("an empty INFORMATIONAL was answered with %v, want an empty answer", err)
	}
	header.MessageID = 2
	raw, err = s.handleRequest(ctx, &header, nil, []RawPayload{{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoESP, SPIs: [][]byte{binary.BigEndian.AppendUint32(nil, 22)}})}})
	if err != nil {
		t.Fatalf("a Delete of the Child SA ended the IKE SA: %v", err)
	}
	payload := findType(sealedAnswer(t, ctx, raw), PayloadD)
	if payload == nil {
		t.Fatal("a Delete of the Child SA drew no Delete")
	}
	deleted, err := DecodeDelete(payload.Body)
	if err != nil || deleted.Protocol != ProtoESP || len(deleted.SPIs) != 1 || binary.BigEndian.Uint32(deleted.SPIs[0]) != 21 {
		t.Errorf("a Delete of the Child SA drew %+v, %v, want the Delete of local SPI 21", deleted, err)
	}
}

// followupWait is the time an initiator retransmitting its IKE_FOLLOWUP_KE as this end does gives it before it deems the IKE SA failed
func TestFollowupWaitIsTheRequestBudget(t *testing.T) {
	var budget time.Duration
	for attempt := 1; attempt <= maxRetransmits; attempt++ {
		budget += retransmitDelay(requestTimeout, attempt)
	}
	if followupWait != budget {
		t.Errorf("followupWait is %s, want the request budget of %s", followupWait, budget)
	}
}

// an initiator waiting on its Delete after IKE_AUTH holds no chain, so it answers an IKE_FOLLOWUP_KE with STATE_NOT_FOUND as Run does with none open, and waits on
// RFC 9370 section 2.2.4: "If the responder receives an IKE_FOLLOWUP_KE message for which it does not have a key exchange state, it MUST send back a new error type notification called "STATE_NOT_FOUND"."
func TestInitiatorClosingAfterAuthAnswersAFollowupWithStateNotFound(t *testing.T) {
	peer, initiator := closingAfterAuth(t)
	done := make(chan error, 1)
	go func() { done <- initiator.deleteAuthenticatedIKE() }()
	peer.read(t)
	header := Header{ExchangeType: IKE_FOLLOWUP_KE, MessageID: 0}
	request, _ := followupRequest(t, ML_KEM_768, drawnOctets(t, followupLinkLen))
	peer.send(t, header, request)
	answer := peer.answer(t)
	if answer.Header.ExchangeType != IKE_FOLLOWUP_KE || answer.Header.MessageID != 0 || !notified(answer.inner, N_STATE_NOT_FOUND, nil) {
		t.Fatalf("the IKE_FOLLOWUP_KE drew exchange %d Message ID %d carrying %v, want STATE_NOT_FOUND at 0", answer.Header.ExchangeType, answer.Header.MessageID, answer.inner)
	}
	if run := runAnswer(t, header, nil, request); !samePayloads(run, answer.inner) {
		t.Errorf("Run answers the IKE_FOLLOWUP_KE with %v, the wait with %v", run, answer.inner)
	}
	waitsOn(t, done)
	peer.send(t, Header{ExchangeType: INFORMATIONAL, Flags: FlagResponse, MessageID: 2}, nil)
	settled(t, done, nil)
}

// chainPeer is the peer of a session whose IKE SA of x25519+mlkem768 was established at established, scripted over a plain socket, the session's Run started by the test
func chainPeer(t *testing.T, established time.Time) (*collisionPeer, *recorder) {
	t.Helper()
	p := newCollisionPeer(t, established)
	p.old.suite = chainSuite
	p.session.suites = func() Suites { return chainLists }
	p.session.rechecks = make(chan struct{}, 1)
	events := &recorder{}
	p.session.events = events.record
	p.addr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: p.session.mux.LocalAddr().(*net.UDPAddr).Port}
	return p, events
}

// request sends the peer's request of exchange at mid on the old SA
func (p *collisionPeer) request(exchange ExchangeType, mid uint32, inner []RawPayload) {
	p.t.Helper()
	raw, err := EncryptMessage(p.old.suite, p.old.sker, Header{SPIInitiator: collisionOldSPIi, SPIResponder: collisionOldSPIr, ExchangeType: exchange, MessageID: mid}, nil, inner)
	if !p.send("the peer's request", raw, err) {
		p.t.FailNow()
	}
}

// reply answers the session's request of exchange at mid on the old SA
func (p *collisionPeer) reply(exchange ExchangeType, mid uint32, inner []RawPayload) {
	p.t.Helper()
	raw, err := EncryptMessage(p.old.suite, p.old.sker, Header{SPIInitiator: collisionOldSPIi, SPIResponder: collisionOldSPIr, ExchangeType: exchange, Flags: FlagResponse, MessageID: mid}, nil, inner)
	if !p.send("the peer's answer", raw, err) {
		p.t.FailNow()
	}
}

// next is the session's next message on the old SA, which must be of exchange and a response where response holds
func (p *collisionPeer) next(what string, exchange ExchangeType, response bool) (*Header, []RawPayload) {
	p.t.Helper()
	message, raw, ok := p.read(what)
	if !ok {
		p.t.FailNow()
	}
	inner, err := DecryptMessage(p.old.suite, p.old.skei, raw, message)
	if err != nil || message.Header.ExchangeType != exchange || message.Header.IsResponse() != response {
		p.t.Fatalf("%s is exchange %d response %v, %v, want exchange %d response %v", what, message.Header.ExchangeType, message.Header.IsResponse(), err, exchange, response)
	}
	return &message.Header, inner
}

// silent reports whether the session sends nothing for d
func (p *collisionPeer) silent(d time.Duration) bool {
	p.t.Helper()
	if err := p.conn.SetReadDeadline(time.Now().Add(d)); err != nil {
		p.t.Fatal(err)
	}
	n, _, err := p.conn.ReadFromUDP(p.buf)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	if err != nil {
		p.t.Fatal(err)
	}
	if header, err := decodeHeader(p.buf[4:n]); err == nil {
		p.t.Logf("the session sent exchange %d response %v at Message ID %d", header.ExchangeType, header.IsResponse(), header.MessageID)
	}
	return false
}

// rekeyDue is when a session's IKE SA was established whose scheduled rekey under rekeyLifetime and rekeyMargin falls due scheduleDue into the test
func rekeyDue() time.Time { return time.Now().Add(scheduleDue - (rekeyLifetime - rekeyMarginOf)) }

// the lifetime and margin of the IKE SA a Run test rekeys on its schedule, the lifetime far past the test
const rekeyLifetime, rekeyMarginOf = time.Hour, time.Hour - time.Second

// the liveness interval of a Run test whose checks fall due within quietPeriod, and of one whose checks never fall due
const dueDPD, noDPD = 20 * time.Millisecond, time.Hour

// the wait a test cuts a peer's chain to, and how long before a chain's deadline a test reads the chain
const chainWaitCut, beforeDeadline = 50 * time.Millisecond, time.Millisecond

// the retransmission timeout of a Run test that waits out the resends of an IKE_FOLLOWUP_KE, the peer's wait scaling with it
const followupRetransmit = 20 * time.Millisecond

// a rekey Run starts whose IKE_FOLLOWUP_KE draws the third STATE_NOT_FOUND in a row ends the IKE SA with the Delete of the teardown, recorded as ike.sa.closed
// RFC 9370 section 2.2.4: "If the initiator continues to receive STATE_NOT_FOUND notifications after several retries, it MUST treat this situation as a fatal error and delete the IKE SA by sending a DELETE payload."
func TestStateNotFoundAtTheLimitDeletesTheIKESA(t *testing.T) {
	p, events := chainPeer(t, rekeyDue())
	s := p.session
	s.ikeRekeyInterval, s.rekeyMargin = rekeyLifetime, rekeyMarginOf
	s.stateNotFounds = stateNotFoundLimit - 1
	run := runSession(t, s)
	header, create := p.next("the rekey", CREATE_CHILD_SA, false)
	answer, _ := answerRekey(t, create, 0, []byte("link1"), nil)
	p.reply(CREATE_CHILD_SA, header.MessageID, answer)
	header, _ = p.next("the IKE_FOLLOWUP_KE", IKE_FOLLOWUP_KE, false)
	p.reply(IKE_FOLLOWUP_KE, header.MessageID, notifyAnswer(N_STATE_NOT_FOUND))
	header, deletion := p.next("the Delete", INFORMATIONAL, false)
	if payload := findType(deletion, PayloadD); payload == nil || header.SPIInitiator != collisionOldSPIi {
		t.Fatalf("the request after the third STATE_NOT_FOUND carries %v on SPI %016x, want the Delete of the IKE SA", payloadTypes(deletion), header.SPIInitiator)
	}
	p.reply(INFORMATIONAL, header.MessageID, nil)
	if err := endedWithin(t, run, "rekeying"); err == nil {
		t.Error("the session outlived the Delete of its IKE SA")
	}
	awaitRecorded(t, events, "ike.sa.closed > sa=ike reason=state not found")
}

// a chain ending as one that ends the IKE SA while the replacement for a PRF the lists left out is under way sends no Delete of its own and records no close
// the replacement's Delete is the last request of the SA
// RFC 7296 section 2.8: "After the new equivalent IKE SA is created, the initiator deletes the old IKE SA, and the Delete payload to delete itself MUST be the last request sent over the old IKE SA."
func TestChainEndingBehindAReplacementSendsNoSecondDelete(t *testing.T) {
	p, events := chainPeer(t, rekeyDue())
	s := p.session
	s.ikeRekeyInterval, s.rekeyMargin = rekeyLifetime, rekeyMarginOf
	s.stateNotFounds = stateNotFoundLimit - 1
	var lists atomic.Pointer[Suites]
	lists.Store(&chainLists)
	s.suites = func() Suites { return *lists.Load() }
	run := runSession(t, s)
	header, create := p.next("the rekey", CREATE_CHILD_SA, false)
	answer, _ := answerRekey(t, create, 0, []byte("link1"), nil)
	p.reply(CREATE_CHILD_SA, header.MessageID, answer)
	header, _ = p.next("the IKE_FOLLOWUP_KE", IKE_FOLLOWUP_KE, false)
	// a reload leaving out the SA's PRF replaces the SA while the chain waits on its answer
	lists.Store(&Suites{ikeCipher: []Transform{encrAES128}, ikePRF: []Transform{prfSHA384}, kex: chainLists.kex})
	s.SuitesChanged()
	awaitRecorded(t, events, "ike.suite.unlisted > sa=ike suite=aes128gcm/sha256/x25519+mlkem768 action=replace")
	p.reply(IKE_FOLLOWUP_KE, header.MessageID, notifyAnswer(N_STATE_NOT_FOUND))
	header, deletion := p.next("the replacement's Delete", INFORMATIONAL, false)
	if findType(deletion, PayloadD) == nil {
		t.Fatalf("the request after the chain carries %v, want the replacement's Delete", payloadTypes(deletion))
	}
	p.reply(INFORMATIONAL, header.MessageID, nil)
	if err := endedWithin(t, run, "rekeying"); !errors.Is(err, ErrPRFUnlisted) {
		t.Errorf("the session ended with %v, want the replacement's end", err)
	}
	if !p.silent(quietPeriod) {
		t.Error("the session sent a request after the replacement's Delete")
	}
	if got := recordedKind(events, "ike.sa.closed"); got != 0 {
		t.Errorf("the session recorded %d closes beside its replacement: %q", got, events.recorded())
	}
}

// Run starts no liveness check while the session is quiet, neither when one falls due nor when one is asked for, and starts the one due once it is not
// strongSwan destroys an IKE SA that takes any other request while it waits for IKE_FOLLOWUP_KE
func TestQuietSessionStartsNoLivenessCheck(t *testing.T) {
	p, _ := chainPeer(t, time.Now())
	s := p.session
	s.dpdEvery = dueDPD
	s.probes = make(chan struct{}, 1)
	s.quiet.Store(true)
	runSession(t, s)
	s.Probe()
	if !p.silent(quietPeriod) {
		t.Fatal("the session sent a request while quiet")
	}
	s.quiet.Store(false)
	header, inner := p.next("the liveness check", INFORMATIONAL, false)
	if len(inner) != 0 {
		t.Errorf("the liveness check carries %v, want nothing", payloadTypes(inner))
	}
	p.reply(INFORMATIONAL, header.MessageID, nil)
}

// Run wakes for the deadline of a peer's chain and drops the chain there, with ike.followup.dropped, so the chain's IKE_FOLLOWUP_KE then draws STATE_NOT_FOUND
// RFC 9370 section 2.2.4: "The responder MUST handle this situation gracefully and delete the associated state if it does not receive the next expected IKE_FOLLOWUP_KE request after some reasonable period of time."
func TestRunDropsThePeersChainAtItsDeadline(t *testing.T) {
	p, events := chainPeer(t, time.Now())
	s := p.session
	// no liveness check wakes Run in the test
	s.dpdEvery = noDPD
	runSession(t, s)
	peer, request := newPeerRekey(t, hybridOffer, drawnOctets(t, 32))
	p.request(CREATE_CHILD_SA, 0, request)
	_, answer := p.next("the answer to the peer's rekey", CREATE_CHILD_SA, true)
	peer.read(t, answer)
	if peer.link == nil {
		t.Fatalf("the answer to the peer's rekey carries %v, want a link", payloadTypes(answer))
	}
	// the wait is cut to a moment from now, which Run reads in the pass after the next exchange
	s.stateMu.Lock()
	s.peerChain.deadline = time.Now().Add(chainWaitCut)
	s.stateMu.Unlock()
	p.request(INFORMATIONAL, 1, nil)
	p.next("the answer to an empty INFORMATIONAL", INFORMATIONAL, true)
	awaitRecorded(t, events, "ike.followup.dropped > sa=ike reason=expired")
	followup, _ := followupRequest(t, ML_KEM_768, peer.link)
	p.request(IKE_FOLLOWUP_KE, 2, followup)
	if _, late := p.next("the answer to the IKE_FOLLOWUP_KE", IKE_FOLLOWUP_KE, true); !notified(late, N_STATE_NOT_FOUND, nil) {
		t.Errorf("the IKE_FOLLOWUP_KE after the deadline drew %v, want STATE_NOT_FOUND", payloadTypes(late))
	}
}

// INVALID_SYNTAX for an IKE_FOLLOWUP_KE ends the IKE SA without a Delete at both ends of the exchange
// the answering end sends it for a key failing the checks of FIPS 203 section 7.2, and the rekeying end takes it in the answer to its own
// RFC 7296 section 2.21.3: "If a peer parsing a request notices that it is badly formatted (after it has passed the message authentication code checks and window checks) and it returns an INVALID_SYNTAX notification, then this error notification is considered fatal in both peers, meaning that the IKE SA is deleted without needing an explicit Delete payload."
func TestInvalidSyntaxForAFollowupEndsTheIKESAWithoutADelete(t *testing.T) {
	t.Run("answering", func(t *testing.T) {
		p, events := chainPeer(t, time.Now())
		run := runSession(t, p.session)
		peer, request := newPeerRekey(t, hybridOffer, drawnOctets(t, 32))
		p.request(CREATE_CHILD_SA, 0, request)
		_, answer := p.next("the answer to the peer's rekey", CREATE_CHILD_SA, true)
		peer.read(t, answer)
		_, key := modelKEM(t, ML_KEM_768)
		p.request(IKE_FOLLOWUP_KE, 1, []RawPayload{{Type: PayloadKE, Body: EncodeKE(ML_KEM_768, key[:len(key)-1])}, linkPayload(peer.link)})
		if _, refused := p.next("the answer to the IKE_FOLLOWUP_KE", IKE_FOLLOWUP_KE, true); !notified(refused, N_INVALID_SYNTAX, nil) {
			t.Fatalf("the IKE_FOLLOWUP_KE with a bad key drew %v, want INVALID_SYNTAX", payloadTypes(refused))
		}
		if err := endedWithin(t, run, "answering"); err == nil {
			t.Error("the session outlived the INVALID_SYNTAX it sent")
		}
		if !p.silent(quietPeriod) {
			t.Error("the session sent a request after its INVALID_SYNTAX")
		}
		awaitRecorded(t, events, "ike.kex.rejected > exchange=IKE_FOLLOWUP_KE method=mlkem768 side=key")
	})
	t.Run("rekeying", func(t *testing.T) {
		p, _ := chainPeer(t, rekeyDue())
		s := p.session
		s.ikeRekeyInterval, s.rekeyMargin = rekeyLifetime, rekeyMarginOf
		run := runSession(t, s)
		header, create := p.next("the rekey", CREATE_CHILD_SA, false)
		answer, _ := answerRekey(t, create, 0, []byte("link1"), nil)
		p.reply(CREATE_CHILD_SA, header.MessageID, answer)
		header, _ = p.next("the IKE_FOLLOWUP_KE", IKE_FOLLOWUP_KE, false)
		p.reply(IKE_FOLLOWUP_KE, header.MessageID, notifyAnswer(N_INVALID_SYNTAX))
		if err := endedWithin(t, run, "rekeying"); !errors.Is(err, errAnsweredInvalidSyntax) {
			t.Errorf("the session ended with %v, want the IKE SA ended by the INVALID_SYNTAX it took", err)
		}
		if !p.silent(quietPeriod) {
			t.Error("the session sent a request after the INVALID_SYNTAX it took")
		}
	})
}

// peerDeletes hands s the peer's Delete of the IKE SA ctx, which s must answer and outlive
func peerDeletes(t *testing.T, s *Session, ctx *ikeContext) {
	t.Helper()
	header := Header{SPIInitiator: ctx.spiI, SPIResponder: ctx.spiR, ExchangeType: INFORMATIONAL, MessageID: 1}
	if _, err := s.handleRequest(ctx, &header, nil, []RawPayload{{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoIKE})}}); err != nil {
		t.Fatalf("the peer's Delete of the IKE SA ended the session: %v", err)
	}
}

// the peer's Delete of the old SA that adopts the SA of its crossing rekey while this end's answer is still out ends this end's rekey, which leaves that SA current
// a classical answer made an SA at the peer, which goes by this end's Delete, and an answer that chains made none, so this end then sends nothing
// RFC 7296 section 2.8.2: "If the peer that did notice the simultaneous rekey gets the delete request from the other peer for the old IKE SA, it knows that the other peer did not detect the simultaneous rekey, and the first peer can forget its own rekey attempt."
func TestPeerDeleteAdoptingItsRekeyEndsThisEndsRekey(t *testing.T) {
	for name, test := range map[string]struct {
		suite     SASuite
		lists     Suites
		peerOffer []Transform
		link      []byte
	}{
		"a classical answer":    {suite: classicalSuite, lists: Suites{ikeCipher: []Transform{encrAES128}, kex: []kexEntry{entryX25519}}, peerOffer: classicalOffer},
		"an answer that chains": {suite: chainSuite, lists: chainLists, peerOffer: hybridOffer, link: []byte("link1")},
	} {
		t.Run(name, func(t *testing.T) {
			s, _ := initiatingSession(t, test.suite, test.lists)
			old := s.current
			done := rekeying(s)
			create := requested(t, s, done, CREATE_CHILD_SA)
			peer, request := newPeerRekey(t, test.peerOffer, drawnOctets(t, 32))
			peer.rekey(t, s.handleIKERekey, old, request)
			if peer.link != nil {
				if last, err := peer.followup(t, s, old, ML_KEM_768, peer.link); err != nil || findType(last, PayloadKE) == nil {
					t.Fatalf("the peer's IKE_FOLLOWUP_KE drew %v, %v, want KEr", payloadTypes(last), err)
				}
			}
			peerDeletes(t, s, old)
			adopted, _ := s.contexts()
			if adopted.spiI != peer.spiI || adopted.spiR != peer.spiR {
				t.Fatal("the peer's Delete of the old SA left the session on another SA than the peer's")
			}
			answer, answering := answerRekey(t, create.inner, 0, test.link, nil)
			create.result <- requestResult{inner: answer}
			if test.link == nil {
				deletion := requested(t, s, done, INFORMATIONAL)
				if deletion.context.spiI != answering.spiI || deletion.context.spiR != answering.spiR || findType(deletion.inner, PayloadD) == nil {
					t.Errorf("the request after the answer carries %v, want the Delete of the SA this end's exchange made", payloadTypes(deletion.inner))
				}
				deletion.result <- requestResult{}
			}
			if err := ended(t, s, done); err != nil {
				t.Fatal(err)
			}
			s.stateMu.RLock()
			current, retained, collision := s.current, s.old, s.collision
			s.stateMu.RUnlock()
			if current != adopted || retained != nil || collision != nil {
				t.Error("this end's rekey moved the session off the SA the peer's Delete left current, or kept an SA beside it")
			}
		})
	}
}

// a peer's rekey answered with a link after this end's rekey checked for an open chain and before it recorded itself is settled on the chain's nonces, as one answered later is
// this end's exchange holds the lowest nonce, so it sends no IKE_FOLLOWUP_KE and waits for the peer's chain, whose last exchange ends this end's rekey
func TestPeerChainAnsweredAsThisEndsRekeyStartsIsSettledOnItsNonces(t *testing.T) {
	below, above, own, answered := bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{4}, 32), bytes.Repeat([]byte{5}, 32), bytes.Repeat([]byte{6}, 32)
	s, _ := initiatingSession(t, chainSuite, chainLists)
	old := s.current
	peer, request := newPeerRekey(t, hybridOffer, above)
	var crossing []byte
	var crossingErr error
	drawn := 0
	s.ikeRekeyNonce = func(n []byte) error {
		drawn++
		if drawn > 1 {
			copy(n, own)
			return nil
		}
		// RekeyIKE draws its Ni once its check for an open chain passed
		crossing, crossingErr = s.handleIKERekey(old, 0, request)
		copy(n, below)
		return nil
	}
	done := rekeying(s)
	create := requested(t, s, done, CREATE_CHILD_SA)
	if crossingErr != nil {
		t.Fatalf("the peer's rekey ended the IKE SA: %v", crossingErr)
	}
	if peer.read(t, sealedAnswer(t, old, crossing)); peer.link == nil {
		t.Fatal("the peer's rekey drew no link")
	}
	answer, _ := answerRekey(t, create.inner, 0, []byte("link1"), answered)
	create.result <- requestResult{inner: answer}
	noRequest(t, s, done, "with its exchange holding the lowest nonce")
	if last, err := peer.followup(t, s, old, ML_KEM_768, peer.link); err != nil || findType(last, PayloadKE) == nil {
		t.Fatalf("the peer's IKE_FOLLOWUP_KE drew %v, %v, want KEr", payloadTypes(last), err)
	}
	if err := ended(t, s, done); err != nil {
		t.Fatal(err)
	}
	if current, _ := s.contexts(); current.spiI != peer.spiI || current.spiR != peer.spiR {
		t.Error("the session is not current on the SA of the peer's chain, which won")
	}
}

// this end's rekey that lost to the peer's chain fails, keeping the SA, once the chain ends without making its SA or once the IKE SA starts to close
// a caller's Delete of the IKE SA then goes out at once, where it would otherwise wait out the chain's deadline behind the rekey
func TestLostRekeyStopsWaitingForThePeersChain(t *testing.T) {
	below, above, own, answered := bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{4}, 32), bytes.Repeat([]byte{5}, 32), bytes.Repeat([]byte{6}, 32)
	for name, end := range map[string]func(s *Session) (deleted <-chan error){
		"the chain dropped at its deadline": func(s *Session) <-chan error {
			s.expireChain(time.Now().Add(followupWait))
			return nil
		},
		"a caller's Delete of the IKE SA": func(s *Session) <-chan error {
			deleted := make(chan error, 1)
			go func() { deleted <- s.DeleteIKE() }()
			return deleted
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, _ := initiatingSession(t, chainSuite, chainLists)
			s.serving.Store(true)
			drawsInTurn(s, below, own)
			old := s.current
			done := rekeying(s)
			create := requested(t, s, done, CREATE_CHILD_SA)
			peer, request := newPeerRekey(t, hybridOffer, above)
			peer.rekey(t, s.handleIKERekey, old, request)
			answer, _ := answerRekey(t, create.inner, 0, []byte("link1"), answered)
			create.result <- requestResult{inner: answer}
			noRequest(t, s, done, "while it waits for the peer's chain")
			deleted := end(s)
			select {
			case err := <-done:
				if err == nil {
					t.Error("the rekey that lost succeeded though the peer's chain made no SA")
				}
			case <-time.After(answerBudget):
				t.Fatal("the rekey that lost went on waiting for the peer's chain")
			}
			if current, _ := s.contexts(); current != old {
				t.Error("the rekey that lost left the session on another SA")
			}
			if s.quiet.Load() {
				t.Error("the session left its other requests off after the rekey that lost ended")
			}
			if deleted == nil {
				return
			}
			deletion := requested(t, s, deleted, INFORMATIONAL)
			if deletion.context != old || findType(deletion.inner, PayloadD) == nil {
				t.Errorf("the request after the rekey carries %v, want the caller's Delete of the IKE SA", payloadTypes(deletion.inner))
			}
			deletion.result <- requestResult{}
			if err := <-deleted; err != nil {
				t.Error(err)
			}
		})
	}
}

// a close Run decides on while this end's rekey that lost waits for the peer's chain ends the wait, so the teardown's Delete goes out at once and not at the chain's deadline
func TestRunClosingWhileALostRekeyWaitsSendsItsDeleteAtOnce(t *testing.T) {
	below, above, own, answered := bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{4}, 32), bytes.Repeat([]byte{5}, 32), bytes.Repeat([]byte{6}, 32)
	p, _ := chainPeer(t, rekeyDue())
	s := p.session
	s.ikeRekeyInterval, s.rekeyMargin = rekeyLifetime, rekeyMarginOf
	s.childFailed = make(chan error, 1)
	drawsInTurn(s, below, own)
	run := runSession(t, s)
	header, create := p.next("the rekey", CREATE_CHILD_SA, false)
	peer, request := newPeerRekey(t, hybridOffer, above)
	p.request(CREATE_CHILD_SA, 0, request)
	_, crossing := p.next("the answer to the peer's rekey", CREATE_CHILD_SA, true)
	if peer.read(t, crossing); peer.link == nil {
		t.Fatalf("the answer to the peer's rekey carries %v, want a link", payloadTypes(crossing))
	}
	answer, _ := answerRekey(t, create, 0, []byte("link1"), answered)
	p.reply(CREATE_CHILD_SA, header.MessageID, answer)
	if !p.silent(quietPeriod) {
		t.Fatal("the session sent a request while its rekey that lost waits for the peer's chain")
	}
	s.ChildFailed(errors.New("the dataplane refused a change"))
	header, deletion := p.next("the teardown's Delete", INFORMATIONAL, false)
	if findType(deletion, PayloadD) == nil {
		t.Fatalf("the request after the close carries %v, want the Delete of the IKE SA", payloadTypes(deletion))
	}
	p.reply(INFORMATIONAL, header.MessageID, nil)
	if err := endedWithin(t, run, "closing"); err == nil {
		t.Error("the session outlived the Delete of its IKE SA")
	}
}

// a peer's rekey answered while this end's own rekey completes its CREATE_CHILD_SA and starts its chain is answered TEMPORARY_FAILURE, one with additional key exchanges and one without, and this end's chain goes on
// the chain starts after the answer first looked at this end's rekey and before it would open the peer's chain or place the peer's SA
// RFC 9370 section 2.2.4: "In this case, a TEMPORARY_FAILURE notification MUST be sent in response to such a request."
func TestPeerRekeyAnsweredAsThisEndsChainStartsDrawsTemporaryFailure(t *testing.T) {
	for name, test := range map[string]struct {
		suite     SASuite
		lists     Suites
		peerOffer []Transform
		// proposal is the one of this end's offer the answer to it takes
		proposal int
	}{
		"a peer's rekey with additional key exchanges": {suite: chainSuite, lists: chainLists, peerOffer: hybridOffer},
		"a peer's classical rekey": {
			suite: classicalSuite, lists: Suites{ikeCipher: []Transform{encrAES128}, kex: []kexEntry{entryX25519, entry768}}, peerOffer: classicalOffer, proposal: 1,
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, _ := initiatingSession(t, test.suite, test.lists)
			// a second mux on the session's hub alone tells an SPI the session holds from one it released
			mux, other := lifecycleMuxes(t)
			s.mux = mux
			old := s.current
			done := rekeying(s)
			create := requested(t, s, done, CREATE_CHILD_SA)
			var followup *localRequest
			var answering *peerRekey
			// the answer to the peer's rekey draws its Nr here
			s.ikeRekeyNonce = func(n []byte) error {
				answer, peer := answerRekey(t, create.inner, test.proposal, []byte("link1"), nil)
				answering = peer
				create.result <- requestResult{inner: answer}
				followup = requested(t, s, done, IKE_FOLLOWUP_KE)
				_, err := rand.Read(n)
				return err
			}
			crossing, request := newPeerRekey(t, test.peerOffer, drawnOctets(t, 32))
			if refused := crossing.rekey(t, s.handleIKERekey, old, request); !notified(refused, N_TEMPORARY_FAILURE, nil) {
				t.Fatalf("the peer's rekey drew %v, want TEMPORARY_FAILURE", payloadTypes(refused))
			}
			s.stateMu.RLock()
			collision := s.collision
			s.stateMu.RUnlock()
			if s.chainKind() != "" || collision != nil {
				t.Error("the peer's refused rekey opened a chain or is held as the collision's candidate")
			}
			if err := other.RegisterIKE(crossing.spiI); err != nil {
				t.Errorf("the peer's refused rekey left its SPI registered: %v", err)
			}
			followup.result <- requestResult{inner: answering.answerFollowup(t, followup.inner, ML_KEM_768, nil)}
			deletion := requested(t, s, done, INFORMATIONAL)
			deletion.result <- requestResult{}
			if err := ended(t, s, done); err != nil {
				t.Fatal(err)
			}
			if current, _ := s.contexts(); current.spiI != answering.spiI || current.spiR != answering.spiR {
				t.Error("the session is not current on the SA its chain made")
			}
		})
	}
}

// an IKE SA rekey keeps the SA's group for its KE payload while an entry it offers has that group, though the lists put an entry of another group first, and leads its offer with that entry
// RFC 7296 section 1.3: "The Diffie-Hellman group of the KEi MUST be an element of the group the initiator expects the responder to accept (additional Diffie-Hellman groups can be proposed)."
func TestIKESARekeyKeepsTheSAsGroupWhileAnOfferedEntryHasIt(t *testing.T) {
	entryP256And768 := kexEntry{group: DH_ECP_256, additions: [addkeTypes]uint16{ML_KEM_768}}
	s, _ := initiatingSession(t, chainSuite, Suites{ikeCipher: []Transform{encrAES128}, kex: []kexEntry{entryP256And768, entry768}})
	done := rekeying(s)
	create := requested(t, s, done, CREATE_CHILD_SA)
	ke := findType(create.inner, PayloadKE)
	if ke == nil {
		t.Fatalf("the rekey request carries payload types %v and no KE", payloadTypes(create.inner))
	}
	group, _, err := DecodeKE(ke.Body)
	offer := offerOf(t, create.inner)
	if err != nil || group != DH_CURVE25519 || len(offer) != 2 || !slices.Equal(kexOf(offer[0]), []Transform{dhX25519, {Type: TransADDKE1, ID: ML_KEM_768}}) {
		t.Errorf("the rekey sent its KE payload in group %d, %v, and offered %+v, want x25519 and x25519+mlkem768 first", group, err, offer)
	}
	create.result <- requestResult{err: errors.New("the test ends the rekey at its request")}
	if err := ended(t, s, done); err == nil {
		t.Error("the rekey succeeded with its request failed")
	}
}

// a peer's rekey that replaces the SA after this end's rekey started and before it read the SA has this end's rekey replace the peer's SA, keyed from that SA's SK_d, and delete it
// RFC 7296 section 2.18: "SKEYSEED for the new IKE SA is computed using SK_d from the existing IKE SA as follows:"
func TestIKESARekeyReplacesThePeersSAMadeAsItStarted(t *testing.T) {
	s, _ := initiatingSession(t, classicalSuite, Suites{ikeCipher: []Transform{encrAES128}, kex: []kexEntry{entryX25519}})
	first := s.current
	peer, request := newPeerRekey(t, classicalOffer, drawnOctets(t, 32))
	var crossing []byte
	var crossingErr error
	drawn := 0
	s.ikeRekeyNonce = func(n []byte) error {
		drawn++
		// RekeyIKE draws its Ni before it reads the SA it rekeys
		if drawn == 1 {
			crossing, crossingErr = s.handleIKERekey(first, 0, request)
		}
		_, err := rand.Read(n)
		return err
	}
	done := rekeying(s)
	create := requested(t, s, done, CREATE_CHILD_SA)
	if crossingErr != nil {
		t.Fatalf("the peer's rekey ended the IKE SA: %v", crossingErr)
	}
	peer.read(t, sealedAnswer(t, first, crossing))
	replaced, _ := s.contexts()
	if replaced.spiI != peer.spiI || replaced.spiR != peer.spiR {
		t.Fatal("the peer's rekey did not replace the SA")
	}
	answer, answering := answerRekey(t, create.inner, 0, nil, nil)
	create.result <- requestResult{inner: answer}
	deletion := requested(t, s, done, INFORMATIONAL)
	if deletion.context != replaced || findType(deletion.inner, PayloadD) == nil {
		t.Errorf("the request after the rekey carries %v, want the Delete of the SA the peer's rekey made", payloadTypes(deletion.inner))
	}
	deletion.result <- requestResult{}
	if err := ended(t, s, done); err != nil {
		t.Fatal(err)
	}
	if current, _ := s.contexts(); !sameKeys(current, answering.keys(t, replaced, classicalSuite)) {
		t.Error("this end's rekey keyed its SA from the SK_d of another SA than the one it replaced")
	}
}

// the rekey backoff of a Run test whose failed series the schedule retries
const followupRetry = 50 * time.Millisecond

// this end's IKE_FOLLOWUP_KE is resent at its Message ID past the peer's wait until answered, with no other request meanwhile
// a STATE_NOT_FOUND answering a send past the wait is not counted toward stateNotFoundLimit, and one answering a send within it is
// RFC 7296 section 2.1: "IKE is a reliable protocol: the initiator MUST retransmit a request until it either receives a corresponding response or deems the IKE SA to have failed."
// RFC 7296 section 2.3: "An IKE endpoint MUST NOT exceed the peer's stated window size for transmitted IKE requests."
func TestFollowupIsResentUntilAnsweredAndALateStateNotFoundIsNotCounted(t *testing.T) {
	p, events := chainPeer(t, rekeyDue())
	s := p.session
	s.ikeRekeyInterval, s.rekeyMargin = rekeyLifetime, rekeyMarginOf
	// no liveness check falls due, so Run counts the peer alive throughout and resends on the busy budget
	s.retransmitAfter, s.dpdEvery = followupRetransmit, noDPD
	s.rekeyRetryInitial, s.rekeyRetryMax = followupRetry, followupRetry
	s.stateNotFounds = stateNotFoundLimit - 1
	run := runSession(t, s)
	header, create := p.next("the rekey", CREATE_CHILD_SA, false)
	answer, _ := answerRekey(t, create, 0, []byte("link1"), nil)
	p.reply(CREATE_CHILD_SA, header.MessageID, answer)
	// the sends within the wait are lost, and the last resend, the first past it, reaches the peer, which dropped the chain
	followup, _ := p.next("the IKE_FOLLOWUP_KE", IKE_FOLLOWUP_KE, false)
	for range maxRetransmits {
		if resent, _ := p.next("a resend of the IKE_FOLLOWUP_KE", IKE_FOLLOWUP_KE, false); resent.MessageID != followup.MessageID {
			t.Fatalf("a resend of the IKE_FOLLOWUP_KE at Message ID %d went at %d", followup.MessageID, resent.MessageID)
		}
	}
	p.reply(IKE_FOLLOWUP_KE, followup.MessageID, notifyAnswer(N_STATE_NOT_FOUND))
	awaitRecorded(t, events, "ike.rekey.failed > sa=ike")
	header, create = p.next("the retried rekey", CREATE_CHILD_SA, false)
	if header.MessageID != followup.MessageID+1 {
		t.Errorf("the retried rekey went at Message ID %d after the IKE_FOLLOWUP_KE answered at %d", header.MessageID, followup.MessageID)
	}
	if got := recordedKind(events, "ike.sa.closed"); got != 0 {
		t.Fatalf("the session recorded %d closes after the late STATE_NOT_FOUND: %q", got, events.recorded())
	}
	answer, _ = answerRekey(t, create, 0, []byte("link1"), nil)
	p.reply(CREATE_CHILD_SA, header.MessageID, answer)
	header, _ = p.next("the retried IKE_FOLLOWUP_KE", IKE_FOLLOWUP_KE, false)
	p.reply(IKE_FOLLOWUP_KE, header.MessageID, notifyAnswer(N_STATE_NOT_FOUND))
	header, deletion := p.next("the Delete", INFORMATIONAL, false)
	if payload := findType(deletion, PayloadD); payload == nil || header.SPIInitiator != collisionOldSPIi {
		t.Fatalf("the request after the STATE_NOT_FOUND within the wait carries %v on SPI %016x, want the Delete of the IKE SA", payloadTypes(deletion), header.SPIInitiator)
	}
	p.reply(INFORMATIONAL, header.MessageID, nil)
	if err := endedWithin(t, run, "rekeying"); err == nil {
		t.Error("the session outlived the Delete of its IKE SA")
	}
	awaitRecorded(t, events, "ike.sa.closed > sa=ike reason=state not found")
}

// an answer is late where its request went out at or past the request's lateFrom, a probe's resend among the sends, and not where every send came before it
func TestAnswerAfterASendPastLateFromIsLate(t *testing.T) {
	for name, probed := range map[string]bool{"every send before lateFrom": false, "a probe's resend past lateFrom": true} {
		t.Run(name, func(t *testing.T) {
			s, _, _ := probedSession(t)
			ctx := s.current
			pending, err := s.startRequest(&localRequest{exchange: IKE_FOLLOWUP_KE, context: ctx, result: make(chan requestResult, 1)})
			if err != nil {
				t.Fatal(err)
			}
			pending.lateFrom = pending.lastSent.Add(time.Nanosecond)
			if probed {
				if _, err := s.probe(pending); err != nil {
					t.Fatal(err)
				}
			}
			result := pending.result
			answer, err := EncryptMessage(ctx.suite, ctx.sker, Header{SPIInitiator: ctx.spiI, SPIResponder: ctx.spiR, ExchangeType: IKE_FOLLOWUP_KE, Flags: FlagResponse, MessageID: pending.msgID}, nil, notifyAnswer(N_STATE_NOT_FOUND))
			if err != nil {
				t.Fatal(err)
			}
			if !s.dispatch(answer, nil, &pending) || pending != nil {
				t.Fatal("the answer was not taken")
			}
			if got := <-result; got.late != probed {
				t.Errorf("the answer is late %v, want %v", got.late, probed)
			}
		})
	}
}

// a refusal of this end's IKE SA rekey adopts only the peer's rekey of the same SA held for it, and only on TEMPORARY_FAILURE
// so the redundant SA of an earlier crossing, kept for the peer's Delete, stays as it is, and so does the peer's SA held for this rekey when another refusal comes
func TestRefusedRekeyAdoptsOnlyThePeersSAHeldForIt(t *testing.T) {
	lists := Suites{ikeCipher: []Transform{encrAES128}, kex: []kexEntry{entryX25519}}
	holds := func(t *testing.T, s *Session, old, collision *ikeContext) {
		t.Helper()
		s.stateMu.RLock()
		defer s.stateMu.RUnlock()
		if s.current != old || s.collision != collision {
			t.Error("the refusal replaced the SA or the collision")
		}
	}
	t.Run("the redundant SA of an earlier crossing", func(t *testing.T) {
		s, _ := initiatingSession(t, classicalSuite, lists)
		old, redundant := s.current, chainContext(t, classicalSuite)
		s.collision = redundant
		done := rekeying(s)
		create := requested(t, s, done, CREATE_CHILD_SA)
		create.result <- requestResult{inner: notifyAnswer(N_TEMPORARY_FAILURE)}
		if err := ended(t, s, done); !rejectedWith(err, N_TEMPORARY_FAILURE) {
			t.Errorf("this end's rekey ended with %v, want TEMPORARY_FAILURE", err)
		}
		holds(t, s, old, redundant)
	})
	t.Run("another refusal", func(t *testing.T) {
		s, _ := initiatingSession(t, classicalSuite, lists)
		old := s.current
		done := rekeying(s)
		create := requested(t, s, done, CREATE_CHILD_SA)
		_, request := newPeerRekey(t, classicalOffer, drawnOctets(t, 32))
		if _, err := s.handleIKERekey(old, 0, request); err != nil {
			t.Fatalf("the peer's rekey ended the IKE SA: %v", err)
		}
		s.stateMu.RLock()
		held := s.collision
		s.stateMu.RUnlock()
		if held == nil {
			t.Fatal("the peer's rekey is not held as the collision")
		}
		create.result <- requestResult{inner: notifyAnswer(N_NO_PROPOSAL_CHOSEN)}
		if err := ended(t, s, done); !rejectedWith(err, N_NO_PROPOSAL_CHOSEN) {
			t.Errorf("this end's rekey ended with %v, want NO_PROPOSAL_CHOSEN", err)
		}
		holds(t, s, old, held)
	})
}

// a refusal of this end's IKE SA rekey ends the rekey with the decision it takes, adopting or not
// so the last IKE_FOLLOWUP_KE of the peer's rekey of the same SA, coming after a decision that adopted nothing, makes the peer's SA current, as the peer makes it on reading the answer
// and a peer rekey of the SA the decision adopted is refused until the peer's Delete of the SA it replaced, as a rekey of any SA that replaced another is
// RFC 9370 section 2.2.4: "In this case, a TEMPORARY_FAILURE notification MUST be sent in response to such a request."
func TestRefusedRekeyEndsAtItsDecision(t *testing.T) {
	// opened is a session whose rekey of its IKE SA old, recorded as RekeyIKE records it before its request, crosses the peer's chained rekey of old, its chain open
	opened := func(t *testing.T) (*Session, *ikeContext, *ikeRekey, *peerRekey) {
		t.Helper()
		s, _ := initiatingSession(t, chainSuite, chainLists)
		old := s.current
		local := &ikeRekey{old: old}
		s.localRekey = local
		peer, request := newPeerRekey(t, hybridOffer, drawnOctets(t, 32))
		raw, err := s.handleIKERekey(old, 0, request)
		if err != nil {
			t.Fatalf("the peer's rekey ended the IKE SA: %v", err)
		}
		if peer.read(t, sealedAnswer(t, old, raw)); peer.link == nil {
			t.Fatal("the peer's rekey drew no link")
		}
		return s, old, local, peer
	}
	refused := refusal("IKE SA rekey", notifyAnswer(N_TEMPORARY_FAILURE))
	t.Run("adopting nothing", func(t *testing.T) {
		s, old, local, peer := opened(t)
		if err := s.refusedIKERekey(local, refused); !rejectedWith(err, N_TEMPORARY_FAILURE) {
			t.Fatalf("this end's rekey ended with %v, want TEMPORARY_FAILURE", err)
		}
		if last, err := peer.followup(t, s, old, ML_KEM_768, peer.link); err != nil || findType(last, PayloadKE) == nil {
			t.Fatalf("the peer's IKE_FOLLOWUP_KE drew %v, %v, want KEr", payloadTypes(last), err)
		}
		if current, _ := s.contexts(); current.spiI != peer.spiI || current.spiR != peer.spiR || !sameKeys(current, peer.keys(t, old, chainSuite)) {
			t.Error("the session is not current on the SA of the peer's rekey, which the peer installed")
		}
		s.stateMu.RLock()
		held := s.collision
		s.stateMu.RUnlock()
		if held != nil {
			t.Error("the peer's SA is held as the collision of a rekey that ended")
		}
		peerDeletes(t, s, old)
	})
	t.Run("adopting the held SA", func(t *testing.T) {
		s, old, local, peer := opened(t)
		if last, err := peer.followup(t, s, old, ML_KEM_768, peer.link); err != nil || findType(last, PayloadKE) == nil {
			t.Fatalf("the peer's IKE_FOLLOWUP_KE drew %v, %v, want KEr", payloadTypes(last), err)
		}
		if err := s.refusedIKERekey(local, refused); err != nil {
			t.Fatalf("this end's rekey ended with %v, want the peer's SA adopted", err)
		}
		adopted, _ := s.contexts()
		if adopted.spiI != peer.spiI || adopted.spiR != peer.spiR {
			t.Fatal("the session is not current on the SA of the peer's rekey")
		}
		// the next rekey comes sooner than the limit on a peer's rekeys allows, so it starts the limit over
		s.lastPeerIKERekey.Store(0)
		_, request := newPeerRekey(t, hybridOffer, drawnOctets(t, 32))
		raw, err := s.handleIKERekey(adopted, 0, request)
		if err != nil {
			t.Fatalf("the peer's next rekey ended the IKE SA: %v", err)
		}
		if answer := sealedAnswer(t, adopted, raw); !notified(answer, N_TEMPORARY_FAILURE, nil) {
			t.Errorf("the peer's rekey of the adopted SA before its Delete of the SA it replaced drew %v, want TEMPORARY_FAILURE", payloadTypes(answer))
		}
		peerDeletes(t, s, old)
	})
}

// a TEMPORARY_FAILURE answering this end's IKE SA rekey while the SA of the peer's rekey, chained or classical, is held as the collision makes that SA current, keyed as the peer keys it, and holds it no longer
// RFC 9370 section 2.2.4: "In this case, a TEMPORARY_FAILURE notification MUST be sent in response to such a request."
func TestRefusedRekeyAdoptsThePeersSAHeldAsTheCollision(t *testing.T) {
	adopts := func(t *testing.T, s *Session, done <-chan error, create *localRequest, old *ikeContext, peer *peerRekey, suite SASuite) {
		t.Helper()
		create.result <- requestResult{inner: notifyAnswer(N_TEMPORARY_FAILURE)}
		if err := ended(t, s, done); err != nil {
			t.Errorf("this end's rekey ended with %v, want the peer's SA adopted", err)
		}
		if current, _ := s.contexts(); current.spiI != peer.spiI || current.spiR != peer.spiR || !sameKeys(current, peer.keys(t, old, suite)) {
			t.Error("the session is not current on the SA of the peer's rekey, which the peer installed")
		}
		s.stateMu.RLock()
		held := s.collision
		s.stateMu.RUnlock()
		if held != nil {
			t.Error("the adopted SA is still held as the collision, which refuses every later peer rekey")
		}
		peerDeletes(t, s, old)
	}
	t.Run("chained", func(t *testing.T) {
		s, _ := initiatingSession(t, chainSuite, chainLists)
		old := s.current
		peer, request := newPeerRekey(t, hybridOffer, drawnOctets(t, 32))
		var crossing []byte
		var crossingErr error
		drawn := 0
		s.ikeRekeyNonce = func(n []byte) error {
			drawn++
			// RekeyIKE draws its Ni before it records its rekey
			if drawn == 1 {
				crossing, crossingErr = s.handleIKERekey(old, 0, request)
			}
			_, err := rand.Read(n)
			return err
		}
		done := rekeying(s)
		create := requested(t, s, done, CREATE_CHILD_SA)
		if crossingErr != nil {
			t.Fatalf("the peer's rekey ended the IKE SA: %v", crossingErr)
		}
		if peer.read(t, sealedAnswer(t, old, crossing)); peer.link == nil {
			t.Fatal("the peer's rekey drew no link")
		}
		if last, err := peer.followup(t, s, old, ML_KEM_768, peer.link); err != nil || findType(last, PayloadKE) == nil {
			t.Fatalf("the peer's IKE_FOLLOWUP_KE drew %v, %v, want KEr", payloadTypes(last), err)
		}
		adopts(t, s, done, create, old, peer, chainSuite)
	})
	t.Run("classical", func(t *testing.T) {
		s, _ := initiatingSession(t, classicalSuite, Suites{ikeCipher: []Transform{encrAES128}, kex: []kexEntry{entryX25519}})
		old := s.current
		done := rekeying(s)
		create := requested(t, s, done, CREATE_CHILD_SA)
		peer, request := newPeerRekey(t, classicalOffer, drawnOctets(t, 32))
		raw, err := s.handleIKERekey(old, 0, request)
		if err != nil {
			t.Fatalf("the peer's rekey ended the IKE SA: %v", err)
		}
		answer := sealedAnswer(t, old, raw)
		if findType(answer, PayloadSA) == nil {
			t.Fatalf("the peer's rekey drew %v, want it answered", payloadTypes(answer))
		}
		peer.read(t, answer)
		adopts(t, s, done, create, old, peer, classicalSuite)
	})
}

// a success answering a resend of the last IKE_FOLLOWUP_KE past the peer's wait completes the rekey on the SA the peer made, keyed as the peer keys it, and the old SA's Delete takes the next Message ID
// RFC 7296 section 2.1: "IKE is a reliable protocol: the initiator MUST retransmit a request until it either receives a corresponding response or deems the IKE SA to have failed."
func TestLateAnswerToTheLastFollowupCompletesTheRekey(t *testing.T) {
	p, events := chainPeer(t, rekeyDue())
	s := p.session
	s.ikeRekeyInterval, s.rekeyMargin = rekeyLifetime, rekeyMarginOf
	// no liveness check falls due, so Run counts the peer alive throughout and resends on the busy budget
	s.retransmitAfter, s.dpdEvery = followupRetransmit, noDPD
	runSession(t, s)
	header, create := p.next("the rekey", CREATE_CHILD_SA, false)
	answer, peer := answerRekey(t, create, 0, []byte("link1"), nil)
	p.reply(CREATE_CHILD_SA, header.MessageID, answer)
	followup, request := p.next("the IKE_FOLLOWUP_KE", IKE_FOLLOWUP_KE, false)
	last := peer.answerFollowup(t, request, ML_KEM_768, nil)
	for range maxRetransmits {
		p.next("a resend of the IKE_FOLLOWUP_KE", IKE_FOLLOWUP_KE, false)
	}
	// RFC 7296 section 2.1: "The responder MUST remember each response until it receives a request whose sequence number is larger than or equal to the sequence number in the response plus its window size"
	p.reply(IKE_FOLLOWUP_KE, followup.MessageID, last)
	header, deletion := p.next("the Delete of the old SA", INFORMATIONAL, false)
	if findType(deletion, PayloadD) == nil || header.SPIInitiator != collisionOldSPIi || header.MessageID != followup.MessageID+1 {
		t.Errorf("the request after the late answer carries %v at Message ID %d on SPI %016x, want the Delete of the old SA at %d", payloadTypes(deletion), header.MessageID, header.SPIInitiator, followup.MessageID+1)
	}
	if current, _ := s.contexts(); current.spiI != peer.spiI || current.spiR != peer.spiR || !sameKeys(current, peer.keys(t, p.old, chainSuite)) {
		t.Error("the session is not current on the SA the peer made, keyed as the peer keys it")
	}
	p.reply(INFORMATIONAL, header.MessageID, nil)
	awaitRecorded(t, events, "ike.rekey.completed > sa=ike suite=aes128gcm/sha256/x25519+mlkem768")
}
