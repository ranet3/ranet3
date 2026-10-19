// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ike

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/transport"
)

// modelPRFPlus is n octets of prf+, written out with crypto/hmac
// RFC 7296 section 2.13: "prf+ (K,S) = T1 | T2 | T3 | T4 | ..." where "T1 = prf (K, S | 0x01)" and "T2 = prf (K, T1 | S | 0x02)"
func modelPRFPlus(newHash func() hash.Hash, key, seed []byte, n int) []byte {
	var stream, last []byte
	for i := byte(1); len(stream) < n; i++ {
		mac := hmac.New(newHash, key)
		mac.Write(concat(last, seed, []byte{i}))
		last = mac.Sum(nil)
		stream = append(stream, last...)
	}
	return stream[:n]
}

// modelKeys is SK_d, SK_ei, SK_er, SK_pi and SK_pr of one generation from its SKEYSEED, under an AEAD cipher whose keys are keyLen octets and which takes no SK_a
func modelKeys(newHash func() hash.Hash, skeyseed, seed []byte, keyLen int) [5][]byte {
	size := newHash().Size()
	stream := modelPRFPlus(newHash, skeyseed, seed, 3*size+2*keyLen)
	take := func(n int) []byte { b := stream[:n]; stream = stream[n:]; return b }
	return [5][]byte{take(size), take(keyLen), take(keyLen), take(size), take(size)}
}

// modelSuite is the IKE SA of every modelled setup, AES-GCM with a 256-bit key, HMAC-SHA2-384 and X25519
var modelSuite = SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 256, PRFID: PRF_HMAC_SHA2_384, DHGroup: DH_CURVE25519}

// modelKeyLen is SK_e of modelSuite, the AES key and its salt
const modelKeyLen = 32 + 4

func modelPRF(key, data []byte) []byte {
	mac := hmac.New(sha512.New384, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// setupModel is one setup under modelSuite as a test computes it from the texts, apart from the code under test
// keys is SK_d, SK_ei, SK_er, SK_pi and SK_pr of the newest generation, and i and r are IntAuth_iN and IntAuth_rN, nil before an IKE_INTERMEDIATE exchange
type setupModel struct {
	ni, nr, spis []byte
	keys         [5][]byte
	i, r         []byte
}

// newSetupModel is generation 0, from the shared secret of IKE_SA_INIT
// RFC 7296 section 2.14: "SKEYSEED = prf(Ni | Nr, g^ir)"
func newSetupModel(ni, nr []byte, spiI, spiR uint64, shared []byte) *setupModel {
	m := &setupModel{ni: ni, nr: nr, spis: binary.BigEndian.AppendUint64(binary.BigEndian.AppendUint64(nil, spiI), spiR)}
	m.keys = modelKeys(sha512.New384, modelPRF(concat(ni, nr), shared), concat(ni, nr, m.spis), modelKeyLen)
	return m
}

// modelChunk is one IKE_INTERMEDIATE message's IntAuth chunk, its octets up to the generic header of the Encrypted payload at offset with both lengths adjusted, then its inner payloads
// RFC 9242 section 3.3.2: "In other words, the Length field in the IKE Header (denoted as Adjusted Length in Figure 1) is set to the sum of the lengths of IntAuth_[i/r]*A and IntAuth_[i/r]*P, and the Payload Length field in the Encrypted payload header (denoted as Adjusted Payload Length in Figure 1) is set to the length of IntAuth_[i/r]*P plus the size of the Encrypted payload header (four octets)."
func modelChunk(raw []byte, offset int, inner []byte) []byte {
	chunk := concat(raw[:offset+4], inner)
	binary.BigEndian.PutUint32(chunk[24:28], uint32(len(chunk)))
	binary.BigEndian.PutUint16(chunk[offset+2:offset+4], uint16(4+len(inner)))
	return chunk
}

// exchanged takes one IKE_INTERMEDIATE exchange into IntAuth under the keys that protected it, then moves to the generation its shared secret makes
// RFC 9242 section 3.3.2: "IntAuth_iN = prf(SK_piN, IntAuth_iN-1 | IntAuth_iNA [| IntAuth_iNP])" and "IntAuth_rN = prf(SK_prN, IntAuth_rN-1 | IntAuth_rNA [| IntAuth_rNP])"
// RFC 9370 section 2.2.2: "SKEYSEED(n) = prf(SK_d(n-1), SK(n) | Ni | Nr)"
func (m *setupModel) exchanged(request, requestInner, response, responseInner, secret []byte) {
	m.i = modelPRF(m.keys[3], concat(m.i, modelChunk(request, HeaderLen, requestInner)))
	m.r = modelPRF(m.keys[4], concat(m.r, modelChunk(response, HeaderLen, responseInner)))
	m.keys = modelKeys(sha512.New384, modelPRF(m.keys[0], concat(secret, m.ni, m.nr)), concat(m.ni, m.nr, m.spis), modelKeyLen)
}

// signed is the octets an end's AUTH covers, from its first message, the other end's nonce, its SK_p and its ID payload's body, with IntAuth at authMID once an IKE_INTERMEDIATE exchange ran
// RFC 7296 section 2.15: "InitiatorSignedOctets = RealMessage1 | NonceRData | MACedIDForI"
// RFC 9242 section 3.3.2: "InitiatorSignedOctets = RealMsg1 | NonceRData | MACedIDForI | IntAuth" and "IntAuth =  IntAuth_iN | IntAuth_rN | IKE_AUTH_MID"
func (m *setupModel) signed(message, nonce, skp, id []byte, authMID uint32) []byte {
	octets := concat(message, nonce, modelPRF(skp, id))
	if m.i != nil {
		octets = concat(octets, m.i, m.r, binary.BigEndian.AppendUint32(nil, authMID))
	}
	return octets
}

// childKeys is the initiator's and the responder's key of the Child SA IKE_AUTH makes, each octets long
// RFC 7296 section 2.17: "KEYMAT = prf+(SK_d, Ni | Nr)"
func (m *setupModel) childKeys(each int) (initiator, responder []byte) {
	stream := modelPRFPlus(sha512.New384, m.keys[0], concat(m.ni, m.nr), 2*each)
	return stream[:each], stream[each:]
}

// modelKEM is a fresh decapsulation key of method from crypto/mlkem, and its encapsulation key's octets
func modelKEM(t testing.TB, method uint16) (func([]byte) ([]byte, error), []byte) {
	t.Helper()
	switch method {
	case ML_KEM_768:
		key, err := mlkem.GenerateKey768()
		if err != nil {
			t.Fatal(err)
		}
		return key.Decapsulate, key.EncapsulationKey().Bytes()
	case ML_KEM_1024:
		key, err := mlkem.GenerateKey1024()
		if err != nil {
			t.Fatal(err)
		}
		return key.Decapsulate, key.EncapsulationKey().Bytes()
	}
	t.Fatalf("no ML-KEM method %d", method)
	return nil, nil
}

// modelEncapsulate is SK(n) and the ciphertext crypto/mlkem makes to key under method
func modelEncapsulate(t testing.TB, method uint16, key []byte) (secret, ciphertext []byte) {
	t.Helper()
	switch method {
	case ML_KEM_768:
		public, err := mlkem.NewEncapsulationKey768(key)
		if err != nil {
			t.Fatalf("the dial's ML-KEM-768 key of %d octets: %v", len(key), err)
		}
		return public.Encapsulate()
	case ML_KEM_1024:
		public, err := mlkem.NewEncapsulationKey1024(key)
		if err != nil {
			t.Fatalf("the dial's ML-KEM-1024 key of %d octets: %v", len(key), err)
		}
		return public.Encapsulate()
	}
	t.Fatalf("no ML-KEM method %d", method)
	return nil, nil
}

func addkeOf(transformType TransformType, ids ...uint16) []Transform {
	var transforms []Transform
	for _, id := range ids {
		transforms = append(transforms, Transform{Type: transformType, ID: id})
	}
	return transforms
}

// modelBase is the transforms of modelSuite but its additions, as an offer and an answer hold them
var modelBase = []Transform{encrAES256, prfSHA384, dhX25519}

// ikeOffer is one proposal of the transforms of modelSuite and those given, numbered 1
func ikeOffer(transforms ...[]Transform) []Proposal {
	return []Proposal{{Number: 1, Protocol: ProtoIKE, Transforms: slices.Concat(append([][]Transform{modelBase}, transforms...)...)}}
}

var (
	entry768        = kexEntry{group: DH_CURVE25519, additions: [addkeTypes]uint16{ML_KEM_768}}
	entry768And1024 = kexEntry{group: DH_CURVE25519, additions: [addkeTypes]uint16{ML_KEM_768, ML_KEM_1024}}
	entryX25519     = kexEntry{group: DH_CURVE25519}
)

// scripted is a scripted initiator's half of a setup with h's responder, every key and IntAuth the model's
type scripted struct {
	t                  *testing.T
	h                  *responderHarness
	mux                *transport.Mux
	model              *setupModel
	spiI, spiR         uint64
	message1, message2 []byte
	answer             *Message
	// cut, where it is set, sends each request in IKE Fragment messages of that many octets of plaintext, sent is the datagrams of the last request and got those of the last message received
	cut  int
	sent [][]byte
	got  [][]byte
	// between, where it is set, runs before the last of a request's two or more datagrams goes
	between func()
}

// openScripted runs IKE_SA_INIT with offer, a KE payload in X25519 and INTERMEDIATE_EXCHANGE_SUPPORTED where notify holds, its Notification Data data
// an answer of a notify alone returns that notify's type and no setup
func openScripted(t *testing.T, h *responderHarness, offer []Proposal, notify bool, data ...byte) (*scripted, NotifyType) {
	t.Helper()
	return openScriptedWith(t, h, offer, nil, notify, data...)
}

// openScriptedWith is openScripted with extra after the notifies of the IKE_SA_INIT request
func openScriptedWith(t *testing.T, h *responderHarness, offer []Proposal, extra []RawPayload, notify bool, data ...byte) (*scripted, NotifyType) {
	t.Helper()
	mux, err := h.initiator.NewMux(net.ParseIP("127.0.0.1"), h.remotePort)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mux.Close() })
	spiI := randUint64Nonzero()
	if err := mux.RegisterIKE(spiI); err != nil {
		t.Fatal(err)
	}
	dh, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ni := make([]byte, nonceLen)
	rand.Read(ni)
	payloads := []RawPayload{
		{Type: PayloadSA, Body: EncodeSA(offer)},
		{Type: PayloadKE, Body: EncodeKE(DH_CURVE25519, dh.PublicKey().Bytes())},
		{Type: PayloadNonce, Body: EncodeNonce(ni)},
		{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_SIGNATURE_HASH_ALGORITHMS, Data: binary.BigEndian.AppendUint16(nil, HashIdentity)})},
	}
	if notify {
		payloads = append(payloads, RawPayload{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_INTERMEDIATE_EXCHANGE_SUPPORTED, Data: data})})
	}
	payloads = append(payloads, extra...)
	message1 := (&Message{Header: Header{SPIInitiator: spiI, ExchangeType: IKE_SA_INIT, Flags: FlagInitiator}, Payloads: payloads}).Encode()
	message2 := statelessAnswer(t, mux, message1, "the responder did not answer IKE_SA_INIT")
	answer, err := DecodeMessage(message2)
	if err != nil {
		t.Fatal(err)
	}
	ke, nonce := answer.find(PayloadKE), answer.find(PayloadNonce)
	if ke == nil || nonce == nil {
		return nil, firstTestNotify(t, message2).Type
	}
	group, public, err := DecodeKE(ke.Body)
	if err != nil || group != DH_CURVE25519 {
		t.Fatalf("the answer's KE payload is in group %d: %v", group, err)
	}
	peer, err := ecdh.X25519().NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := dh.ECDH(peer)
	if err != nil {
		t.Fatal(err)
	}
	spiR := answer.Header.SPIResponder
	return &scripted{t: t, h: h, mux: mux, model: newSetupModel(ni, DecodeNonce(nonce.Body), spiI, spiR, shared),
		spiI: spiI, spiR: spiR, message1: message1, message2: message2, answer: answer}, 0
}

// chose is the transforms of the one proposal of the IKE_SA_INIT answer
func (s *scripted) chose() []Transform {
	s.t.Helper()
	selected, err := DecodeSA(s.answer.find(PayloadSA).Body)
	if err != nil || len(selected) != 1 {
		s.t.Fatalf("the IKE_SA_INIT answer selects %+v: %v", selected, err)
	}
	return selected[0].Transforms
}

// send seals inner as the request of exchange at mid under the newest generation and returns its octets whole
func (s *scripted) send(exchange ExchangeType, mid uint32, inner []RawPayload) []byte {
	s.t.Helper()
	header := Header{SPIInitiator: s.spiI, SPIResponder: s.spiR, ExchangeType: exchange, Flags: FlagInitiator, MessageID: mid}
	raw, err := EncryptMessage(modelSuite, s.model.keys[1], header, nil, inner)
	if err != nil {
		s.t.Fatal(err)
	}
	s.sent = [][]byte{raw}
	if s.cut > 0 {
		s.sent = cutInto(s.t, modelSuite, s.model.keys[1], header, inner, s.cut)
	}
	for i, datagram := range s.sent {
		if i > 0 && i == len(s.sent)-1 && s.between != nil {
			s.between()
		}
		if err := s.mux.SendIKE(datagram); err != nil {
			s.t.Fatal(err)
		}
	}
	return raw
}

// receive is the next message the responder sends past repeats of its IKE_SA_INIT answer, whole or in fragments, opened under the newest generation
// it returns the message's octets through its Encrypted payload's generic header as the message has them whole
func (s *scripted) receive() (Header, []RawPayload, []byte) {
	s.t.Helper()
	s.got = collect(s.t, func() ([]byte, error) { return s.mux.RecvIKEUntil(time.Now().Add(answerBudget)) })
	header, inner, raw, _ := assembled(s.t, modelSuite, s.model.keys[2], s.got)
	return header, inner, raw
}

// silent reports whether the responder sends nothing for quietPeriod
func (s *scripted) silent() bool {
	_, err := s.mux.RecvIKEUntil(time.Now().Add(quietPeriod))
	return err != nil
}

// moved is a mux of the same SPIs on another local port, where the initiator's datagrams come from once its NAT mapping moved
func (s *scripted) moved() *transport.Mux {
	s.t.Helper()
	hub, err := transport.NewHub(":0", transport.Underlay{}, transport.Runtime{})
	if err != nil {
		s.t.Fatal(err)
	}
	s.t.Cleanup(func() { hub.Close() })
	mux, err := hub.NewMux(net.ParseIP("127.0.0.1"), s.h.remotePort)
	if err != nil {
		s.t.Fatal(err)
	}
	s.t.Cleanup(func() { mux.Close() })
	if err := mux.RegisterIKE(s.spiI); err != nil {
		s.t.Fatal(err)
	}
	return mux
}

// intermediate runs IKE_INTERMEDIATE at mid with a fresh key of method and takes the exchange into the model
// it returns the request and the response as sent
func (s *scripted) intermediate(mid uint32, method uint16) (request, response []byte) {
	s.t.Helper()
	decapsulate, key := modelKEM(s.t, method)
	inner := []RawPayload{{Type: PayloadKE, Body: EncodeKE(method, key)}}
	request = s.send(IKE_INTERMEDIATE, mid, inner)
	header, answer, response := s.receive()
	if header.ExchangeType != IKE_INTERMEDIATE || !header.IsResponse() || header.IsInitiator() || header.MessageID != mid {
		s.t.Fatalf("the responder sent exchange %d response %v initiator %v at Message ID %d, want the IKE_INTERMEDIATE response at %d",
			header.ExchangeType, header.IsResponse(), header.IsInitiator(), header.MessageID, mid)
	}
	// RFC 7296 section 2.5: "Payloads sent in IKE response messages MUST NOT have the critical flag set."
	if len(answer) != 1 || answer[0].Type != PayloadKE || answer[0].Critical {
		s.t.Fatalf("the IKE_INTERMEDIATE response at %d carries payload types %v, want one KE payload without the critical flag", mid, payloadTypes(answer))
	}
	got, ciphertext, err := DecodeKE(answer[0].Body)
	if err != nil || got != method {
		s.t.Fatalf("the IKE_INTERMEDIATE response at %d has its KE payload in method %d, want %d: %v", mid, got, method, err)
	}
	secret, err := decapsulate(ciphertext)
	if err != nil {
		s.t.Fatalf("the responder's ciphertext of %d octets does not decapsulate: %v", len(ciphertext), err)
	}
	s.model.exchanged(request, encodePayloadChain(inner), response, encodePayloadChain(answer), secret)
	return request, response
}

// scriptedIDi is the IDi payload body of every scripted initiator
var scriptedIDi = idBody("testorg/client:2")

// authPayloads is the IKE_AUTH request of testorg/client:2 to testorg/server:1, its AUTH over signed
func (s *scripted) authPayloads(signed []byte) []RawPayload {
	return []RawPayload{
		{Type: PayloadIDi, Body: scriptedIDi},
		{Type: PayloadIDr, Body: idBody("testorg/server:1")},
		{Type: PayloadAUTH, Body: BuildAuth(s.h.private, signed)},
		{Type: PayloadSA, Body: EncodeSA([]Proposal{espProposal([]byte{0, 0, 0, 9})})},
		{Type: PayloadTSi, Body: fullRangeSelectors()},
		{Type: PayloadTSr, Body: fullRangeSelectors()},
	}
}

// authenticate sends IKE_AUTH at mid signed with IntAuth at authMID and returns the answer, whose AUTH it checks against the model where the answer carries one
func (s *scripted) authenticate(mid, authMID uint32) (Header, []RawPayload) {
	s.t.Helper()
	s.send(IKE_AUTH, mid, s.authPayloads(s.model.signed(s.message1, s.model.nr, s.model.keys[3], scriptedIDi, authMID)))
	header, answer, _ := s.receive()
	if idr, auth := findType(answer, PayloadIDr), findType(answer, PayloadAUTH); idr != nil && auth != nil {
		if err := VerifyAuth(s.h.public, s.model.signed(s.message2, s.model.ni, s.model.keys[4], idr.Body, authMID), auth.Body); err != nil {
			s.t.Errorf("the responder's AUTH does not verify over the model's octets: %v", err)
		}
	}
	return header, answer
}

// accepted is the session h's responder handed over, checked against the model's last generation, the methods it ran and its IKE_AUTH at authMID
func (s *scripted) accepted(authMID uint32, methods []uint16) *Session {
	s.t.Helper()
	var session *Session
	select {
	case session = <-s.h.sessions:
		<-s.h.identities
	case <-time.After(answerBudget):
		s.t.Fatal("the responder handed over no session")
	}
	s.t.Cleanup(func() { session.Mux().Close() })
	ctx := session.current
	if got := [5][]byte{ctx.skD, ctx.skei, ctx.sker, ctx.skpi, ctx.skpr}; !slices.EqualFunc(got[:], s.model.keys[:], bytes.Equal) {
		s.t.Error("the responder's IKE SA keys are not those of the model's last generation")
	}
	if got := ctx.suite.entry().added(); !slices.Equal(got, methods) {
		s.t.Errorf("the responder's IKE SA ran additions %v, want %v", got, methods)
	}
	if ctx.authMID != authMID || ctx.lastPeerResponseID != authMID || ctx.nextPeerMID != authMID+1 {
		s.t.Errorf("the responder's IKE SA answered IKE_AUTH at %d, last answered %d and waits for %d, want %d, %d and %d",
			ctx.authMID, ctx.lastPeerResponseID, ctx.nextPeerMID, authMID, authMID, authMID+1)
	}
	child := session.currentChild()
	initiatorKey, responderKey := s.model.childKeys(len(child.InboundKey))
	if !bytes.Equal(child.InboundKey, initiatorKey) || !bytes.Equal(child.OutboundKey, responderKey) {
		s.t.Error("the responder's Child SA keys are not KEYMAT from the model's last SK_d")
	}
	return session
}

// the responder answers an offer of additional key exchanges by the entry it lists, NONE in each ADDKE type the entry leaves, and runs an IKE_INTERMEDIATE exchange at Message IDs from 1 for each method it answered
// IKE_AUTH follows at the next Message ID, signed with IntAuth under the keys of the last generation, and its Child SA takes KEYMAT from that generation's SK_d
// an offer it answers NONE in every ADDKE type runs no IKE_INTERMEDIATE exchange, and IKE_AUTH at Message ID 1 signs the octets of RFC 7296
// the offers are RFC 9370 Appendix A.1 and A.2 with HMAC-SHA2-384 for PRF_HMAC_SHA2_512, ML-KEM-768 for PQ_KEM_2, ML-KEM-1024 for PQ_KEM_5, ML-KEM-512 for PQ_KEM_1 and private use IDs for the others, which this end lacks
// RFC 9370 section 2.2.2: "For each additional key exchange agreed to in the IKE_SA_INIT exchange, the initiator and the responder perform an IKE_INTERMEDIATE exchange, as described in [RFC9242]."
// RFC 9242 section 3.2: "The Message ID for the first pair of IKE_AUTH messages is one more than the value used in the last IKE_INTERMEDIATE exchange."
// RFC 9242 section 3.1: "If the responder also supports this exchange, it includes this notification in the response message."
func TestResponderRunsAnExchangeForEachAdditionItAnswers(t *testing.T) {
	const mlkem512, private1, private2, private3 = 35, 1025, 1026, 1027
	appendixA1 := ikeOffer(addkeOf(TransADDKE1, mlkem512, ML_KEM_768, 0), addkeOf(TransADDKE1+1, private1, private2, 0), addkeOf(TransADDKE1+2, ML_KEM_1024, private3, 0))
	appendixA2 := ikeOffer(addkeOf(TransADDKE1, mlkem512, ML_KEM_768, 0), addkeOf(TransADDKE1+1, private1, private2, 0))
	for name, test := range map[string]struct {
		entries []kexEntry
		offer   []Proposal
		answer  []Transform
		methods []uint16
		suite   string
	}{
		"RFC 9370 Appendix A.1 to x25519+mlkem768+mlkem1024": {
			entries: []kexEntry{entry768And1024}, offer: appendixA1,
			answer:  slices.Concat(modelBase, addkeOf(TransADDKE1, ML_KEM_768), addkeOf(TransADDKE1+1, 0), addkeOf(TransADDKE1+2, ML_KEM_1024)),
			methods: []uint16{ML_KEM_768, ML_KEM_1024}, suite: "aes256gcm/sha384/x25519+mlkem768+mlkem1024",
		},
		"RFC 9370 Appendix A.2 to the default lists": {
			offer:  appendixA2,
			answer: slices.Concat(modelBase, addkeOf(TransADDKE1, 0), addkeOf(TransADDKE1+1, 0)),
			suite:  "aes256gcm/sha384/x25519",
		},
		"ML-KEM-768 to x25519+mlkem768": {
			entries: []kexEntry{entry768}, offer: ikeOffer(addkeOf(TransADDKE1, ML_KEM_768)),
			answer:  slices.Concat(modelBase, addkeOf(TransADDKE1, ML_KEM_768)),
			methods: []uint16{ML_KEM_768}, suite: "aes256gcm/sha384/x25519+mlkem768",
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newResponderHarness(t, nil)
			h.lists.Store(&Suites{kex: test.entries})
			s, refused := openScripted(t, h, test.offer, true)
			if s == nil {
				t.Fatalf("the responder refused the offer with notify %d", refused)
			}
			if got := s.chose(); !slices.Equal(got, test.answer) {
				t.Fatalf("the responder answered %+v, want %+v", got, test.answer)
			}
			if !carriesNotify(s.answer, N_INTERMEDIATE_EXCHANGE_SUPPORTED) {
				t.Error("the IKE_SA_INIT answer carries no INTERMEDIATE_EXCHANGE_SUPPORTED")
			}
			var suite SASuite
			for n, method := range test.methods {
				s.intermediate(uint32(n+1), method)
				suite.Additions[n] = method
			}
			authMID := suite.authMID()
			header, answer := s.authenticate(authMID, authMID)
			if header.ExchangeType != IKE_AUTH || !header.IsResponse() || header.MessageID != authMID {
				t.Fatalf("the responder answered IKE_AUTH with exchange %d at Message ID %d, want IKE_AUTH at %d", header.ExchangeType, header.MessageID, authMID)
			}
			if findType(answer, PayloadAUTH) == nil || findType(answer, PayloadSA) == nil {
				t.Fatalf("the IKE_AUTH answer carries payload types %v, want AUTH and the Child SA", payloadTypes(answer))
			}
			if got := s.accepted(authMID, test.methods).Suite().IKE(); got != test.suite {
				t.Errorf("the responder's IKE SA runs %s, want %s", got, test.suite)
			}
		})
	}
}

// an offer whose ADDKE type requires a method no entry runs, or whose request carried no INTERMEDIATE_EXCHANGE_SUPPORTED, draws NO_PROPOSAL_CHOSEN where it offers nothing else
// a proposal skipped so leaves the one beside it answered, with no notify in the answer to a request that carried none
// RFC 9370 Appendix A.4 with ML-KEM-512 and a private use ID for the required PQ_KEM_1 and PQ_KEM_2, and ML-KEM-768 and ML-KEM-1024, which the responder lists, for PQ_KEM_3 and PQ_KEM_4
// RFC 9370 section 2.2.1: "If the IKE_INTERMEDIATE exchange is not negotiated, then the peers MUST treat any ADDKE Transform Types in the IKE_SA_INIT exchange messages as unknown transform types and skip the proposals they appear in."
func TestOfferNoEntryMeetsDrawsNoProposalChosen(t *testing.T) {
	const mlkem512, private1 = 35, 1025
	hybrid := ikeOffer(addkeOf(TransADDKE1, ML_KEM_768))
	beside := append(slices.Clone(hybrid), Proposal{Number: 2, Protocol: ProtoIKE, Transforms: modelBase})
	for name, test := range map[string]struct {
		entries []kexEntry
		offer   []Proposal
		notify  bool
		// answered is the proposal number answered, 0 for the offer refused
		answered uint8
	}{
		"RFC 9370 Appendix A.4": {
			entries: []kexEntry{entry768, {group: DH_CURVE25519, additions: [addkeTypes]uint16{ML_KEM_1024}}, entryX25519},
			offer:   ikeOffer(addkeOf(TransADDKE1, mlkem512, private1), addkeOf(TransADDKE1+1, ML_KEM_768, ML_KEM_1024, 0)), notify: true,
		},
		"an addition the responder lists, without the notify":                              {entries: []kexEntry{entry768}, offer: hybrid},
		"an addition the responder lists, without the notify, beside a classical proposal": {entries: []kexEntry{entry768, entryX25519}, offer: beside, answered: 2},
	} {
		t.Run(name, func(t *testing.T) {
			h := newResponderHarness(t, nil)
			h.lists.Store(&Suites{kex: test.entries})
			s, refused := openScripted(t, h, test.offer, test.notify)
			if test.answered == 0 {
				if s != nil || refused != N_NO_PROPOSAL_CHOSEN {
					t.Fatalf("the offer drew notify %d, want NO_PROPOSAL_CHOSEN", refused)
				}
				return
			}
			if s == nil {
				t.Fatalf("the offer drew notify %d, want proposal %d answered", refused, test.answered)
			}
			selected, err := DecodeSA(s.answer.find(PayloadSA).Body)
			if err != nil || len(selected) != 1 || selected[0].Number != test.answered || !slices.Equal(selected[0].Transforms, modelBase) {
				t.Fatalf("the responder answered %+v (%v), want proposal %d with no ADDKE type", selected, err, test.answered)
			}
			if carriesNotify(s.answer, N_INTERMEDIATE_EXCHANGE_SUPPORTED) {
				t.Error("the answer to a request without INTERMEDIATE_EXCHANGE_SUPPORTED carries it")
			}
		})
	}
}

// the responder answers each IKE_INTERMEDIATE at the next Message ID and drops one at any other, and a bitwise identical repeat of the last draws the response it kept while another at its Message ID draws nothing
// RFC 9242 section 3.2: "Implementations MUST verify that Message IDs in the IKE_INTERMEDIATE messages they receive actually follow this rule."
// RFC 7296 section 2.1: "A retransmission from the initiator MUST be bitwise identical to the original request."
func TestResponderTakesIntermediateExchangesInMessageIDOrder(t *testing.T) {
	h := newResponderHarness(t, nil)
	h.lists.Store(&Suites{kex: []kexEntry{entry768And1024}})
	s, refused := openScripted(t, h, ikeOffer(addkeOf(TransADDKE1, ML_KEM_768), addkeOf(TransADDKE1+1, ML_KEM_1024)), true)
	if s == nil {
		t.Fatalf("the responder refused the offer with notify %d", refused)
	}
	_, key := modelKEM(t, ML_KEM_768)
	for _, mid := range []uint32{2, 0, 3} {
		s.send(IKE_INTERMEDIATE, mid, []RawPayload{{Type: PayloadKE, Body: EncodeKE(ML_KEM_768, key)}})
		if !s.silent() {
			t.Errorf("an IKE_INTERMEDIATE at Message ID %d ahead of the first drew an answer", mid)
		}
	}
	request, response := s.intermediate(1, ML_KEM_768)
	if err := s.mux.SendIKE(request); err != nil {
		t.Fatal(err)
	}
	if again, err := s.mux.RecvIKEUntil(time.Now().Add(answerBudget)); err != nil || !bytes.Equal(again, response) {
		t.Errorf("the repeat of IKE_INTERMEDIATE 1 drew %d octets (%v), want the %d of its response", len(again), err, len(response))
	}
	altered := slices.Clone(request)
	altered[len(altered)-1] ^= 1
	if err := s.mux.SendIKE(altered); err != nil {
		t.Fatal(err)
	}
	if !s.silent() {
		t.Error("a request at Message ID 1 that is not its repeat drew an answer")
	}
	s.intermediate(2, ML_KEM_1024)
	if header, _ := s.authenticate(3, 3); header.ExchangeType != IKE_AUTH || header.MessageID != 3 {
		t.Fatalf("the responder answered exchange %d at Message ID %d, want IKE_AUTH at 3", header.ExchangeType, header.MessageID)
	}
	s.accepted(3, []uint16{ML_KEM_768, ML_KEM_1024})
}

// the responder answers an IKE_INTERMEDIATE and a repeat of it at the address and port they came from, though IKE_SA_INIT came from another, and refuses one there too
// RFC 7296 section 2.11: "MUST respond to the address and port from which the request was received."
func TestResponderAnswersAnIntermediateWhereItCameFrom(t *testing.T) {
	for name, refused := range map[string]bool{"answered": false, "refused": true} {
		t.Run(name, func(t *testing.T) {
			h := newResponderHarness(t, nil)
			h.lists.Store(&Suites{kex: []kexEntry{entry768}})
			s, notify := openScripted(t, h, ikeOffer(addkeOf(TransADDKE1, ML_KEM_768)), true)
			if s == nil {
				t.Fatalf("the responder refused the offer with notify %d", notify)
			}
			// the same SPIs and keys from a second endpoint, where intermediate and receive wait for the response
			origin := s.mux
			s.mux = s.moved()
			if !refused {
				s.intermediate(1, ML_KEM_768)
				// a repeat of the request whole from there draws the answer there, and nothing at the endpoint the IKE SA was set up from
				if err := s.mux.SendIKE(s.sent[0]); err != nil {
					t.Fatal(err)
				}
				if again, err := s.mux.RecvIKEUntil(time.Now().Add(answerBudget)); err != nil || !bytes.Equal(again, s.got[0]) {
					t.Errorf("a repeat of the request from the second endpoint drew %d octets there (%v), want the answer again", len(again), err)
				}
				if _, err := origin.RecvIKEUntil(time.Now().Add(quietPeriod)); err == nil {
					t.Error("a repeat of the request from the second endpoint drew an answer at the first")
				}
				s.authenticate(2, 2)
				s.accepted(2, []uint16{ML_KEM_768})
				return
			}
			s.send(IKE_INTERMEDIATE, 1, []RawPayload{{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_INITIAL_CONTACT})}})
			header, answer, _ := s.receive()
			if header.ExchangeType != IKE_INTERMEDIATE || !header.IsResponse() || header.MessageID != 1 || len(answer) != 1 || answer[0].Type != PayloadN {
				t.Fatalf("the responder sent exchange %d response %v at Message ID %d with payload types %v, want the IKE_INTERMEDIATE response at 1 holding one notify",
					header.ExchangeType, header.IsResponse(), header.MessageID, payloadTypes(answer))
			}
			if got, err := DecodeNotify(answer[0].Body); err != nil || got.Type != N_INVALID_SYNTAX {
				t.Errorf("the refusal of a request without a KE payload holds notify %d (%v), want INVALID_SYNTAX", got.Type, err)
			}
		})
	}
}

// an IKE_AUTH ahead of the last IKE_INTERMEDIATE exchange the answer agreed on, or an IKE_INTERMEDIATE past it, is answered with INVALID_SYNTAX at its Message ID and ends the half-open SA
// RFC 9242 section 3.2: "these exchanges MUST be sequential and MUST all be completed before the IKE_AUTH exchange is initiated."
// RFC 9242 section 5: "Specifications utilizing the Intermediate Exchange MUST NOT allow an unlimited number of these exchanges to take place at the initiator's discretion."
func TestResponderEndsAHandshakeOutOfItsExchangeOrder(t *testing.T) {
	for name, test := range map[string]struct {
		ran      int
		exchange ExchangeType
	}{
		"IKE_AUTH ahead of the IKE_INTERMEDIATE exchange": {0, IKE_AUTH},
		"a second IKE_INTERMEDIATE exchange":              {1, IKE_INTERMEDIATE},
	} {
		t.Run(name, func(t *testing.T) {
			refused := &recorder{}
			h := childRefusedHarness(t, refused.record)
			h.lists.Store(&Suites{kex: []kexEntry{entry768}})
			s, notify := openScripted(t, h, ikeOffer(addkeOf(TransADDKE1, ML_KEM_768)), true)
			if s == nil {
				t.Fatalf("the responder refused the offer with notify %d", notify)
			}
			for n := range test.ran {
				s.intermediate(uint32(n+1), ML_KEM_768)
			}
			mid := uint32(test.ran) + 1
			inner := s.authPayloads(s.model.signed(s.message1, s.model.nr, s.model.keys[3], scriptedIDi, mid))
			if test.exchange == IKE_INTERMEDIATE {
				_, key := modelKEM(t, ML_KEM_768)
				inner = []RawPayload{{Type: PayloadKE, Body: EncodeKE(ML_KEM_768, key)}}
			}
			s.send(test.exchange, mid, inner)
			header, answer, _ := s.receive()
			if header.ExchangeType != test.exchange || !header.IsResponse() || header.MessageID != mid {
				t.Errorf("the responder answered with exchange %d at Message ID %d, want exchange %d at %d", header.ExchangeType, header.MessageID, test.exchange, mid)
			}
			if len(answer) != 1 || answer[0].Type != PayloadN {
				t.Fatalf("the answer carries payload types %v, want one notify", payloadTypes(answer))
			}
			if notify, err := DecodeNotify(answer[0].Body); err != nil || notify.Type != N_INVALID_SYNTAX {
				t.Errorf("the answer holds notify %d (%v), want INVALID_SYNTAX", notify.Type, err)
			}
			awaitHandshakeEnd(t, h, refused, s.spiI)
		})
	}
}

// an IKE_AUTH whose AUTH leaves IntAuth out, carries another IKE_AUTH_MID or takes MACedIDForI under the SK_pi of the generation before the last is answered with AUTHENTICATION_FAILED at its Message ID and ends the half-open SA
// RFC 9242 section 3.3.2: "InitiatorSignedOctets = RealMsg1 | NonceRData | MACedIDForI | IntAuth" and "IntAuth =  IntAuth_iN | IntAuth_rN | IKE_AUTH_MID"
// RFC 9370 section 2.2.2: "Both the initiator and the responder use these updated key values in the next exchange (IKE_INTERMEDIATE or IKE_AUTH)."
func TestResponderRefusesAnAuthOverOtherOctets(t *testing.T) {
	for name, signed := range map[string]func(s *scripted, skpi0 []byte) []byte{
		"the octets of RFC 7296 alone": func(s *scripted, _ []byte) []byte {
			return concat(s.message1, s.model.nr, modelPRF(s.model.keys[3], scriptedIDi))
		},
		"IKE_AUTH_MID 1": func(s *scripted, _ []byte) []byte {
			return s.model.signed(s.message1, s.model.nr, s.model.keys[3], scriptedIDi, 1)
		},
		"MACedIDForI under SK_pi(0)": func(s *scripted, skpi0 []byte) []byte {
			return s.model.signed(s.message1, s.model.nr, skpi0, scriptedIDi, 2)
		},
	} {
		t.Run(name, func(t *testing.T) {
			refused := &recorder{}
			h := childRefusedHarness(t, refused.record)
			h.lists.Store(&Suites{kex: []kexEntry{entry768}})
			s, notify := openScripted(t, h, ikeOffer(addkeOf(TransADDKE1, ML_KEM_768)), true)
			if s == nil {
				t.Fatalf("the responder refused the offer with notify %d", notify)
			}
			skpi0 := s.model.keys[3]
			s.intermediate(1, ML_KEM_768)
			s.send(IKE_AUTH, 2, s.authPayloads(signed(s, skpi0)))
			header, answer, _ := s.receive()
			if header.ExchangeType != IKE_AUTH || !header.IsResponse() || header.MessageID != 2 {
				t.Errorf("the responder answered with exchange %d at Message ID %d, want IKE_AUTH at 2", header.ExchangeType, header.MessageID)
			}
			if len(answer) != 1 || answer[0].Type != PayloadN {
				t.Fatalf("the answer carries payload types %v, want one notify", payloadTypes(answer))
			}
			if got, err := DecodeNotify(answer[0].Body); err != nil || got.Type != N_AUTHENTICATION_FAILED {
				t.Errorf("the answer holds notify %d (%v), want AUTHENTICATION_FAILED", got.Type, err)
			}
			awaitHandshakeEnd(t, h, refused, s.spiI)
		})
	}
}

// an IKE_AUTH after an IKE_INTERMEDIATE exchange whose Child SA offer the responder refuses is answered at its Message ID with AUTH and NO_PROPOSAL_CHOSEN
// the IKE SA that stands then goes with a Delete, the responder's own first request at Message ID 0
// RFC 7296 section 1.2: "If creating the Child SA during the IKE_AUTH exchange fails for some reason, the IKE SA is still created as usual."
func TestResponderAnswersARefusedChildAtTheAuthMessageID(t *testing.T) {
	h := newResponderHarness(t, nil)
	h.lists.Store(&Suites{kex: []kexEntry{entry768}})
	s, notify := openScripted(t, h, ikeOffer(addkeOf(TransADDKE1, ML_KEM_768)), true)
	if s == nil {
		t.Fatalf("the responder refused the offer with notify %d", notify)
	}
	s.intermediate(1, ML_KEM_768)
	inner := s.authPayloads(s.model.signed(s.message1, s.model.nr, s.model.keys[3], scriptedIDi, 2))
	// a Child SA in IKE_AUTH negotiates no key exchange
	child := espProposal([]byte{0, 0, 0, 9})
	child.Transforms = append(child.Transforms, Transform{Type: TransDH, ID: DH_ECP_256})
	findType(inner, PayloadSA).Body = EncodeSA([]Proposal{child})
	s.send(IKE_AUTH, 2, inner)
	header, answer, _ := s.receive()
	if header.ExchangeType != IKE_AUTH || !header.IsResponse() || header.MessageID != 2 {
		t.Fatalf("the responder answered with exchange %d at Message ID %d, want IKE_AUTH at 2", header.ExchangeType, header.MessageID)
	}
	idr, auth, refusal := findType(answer, PayloadIDr), findType(answer, PayloadAUTH), findType(answer, PayloadN)
	if idr == nil || auth == nil || refusal == nil {
		t.Fatalf("the answer carries payload types %v, want IDr, AUTH and a notify", payloadTypes(answer))
	}
	if err := VerifyAuth(s.h.public, s.model.signed(s.message2, s.model.ni, s.model.keys[4], idr.Body, 2), auth.Body); err != nil {
		t.Errorf("the responder's AUTH does not verify over the model's octets: %v", err)
	}
	if got, err := DecodeNotify(refusal.Body); err != nil || got.Type != N_NO_PROPOSAL_CHOSEN {
		t.Errorf("the answer holds notify %d (%v), want NO_PROPOSAL_CHOSEN", got.Type, err)
	}
	header, deleted, _ := s.receive()
	wantIKEDelete(t, header, deleted)
}

// a key failing the checks of FIPS 203 section 7.2 is answered with INVALID_SYNTAX alone, which holds no KE payload, records ike.kex.rejected naming the exchange, the method and the side, and ends the half-open SA
// a KE payload missing or of another method draws INVALID_SYNTAX, and a critical payload of an unknown type UNSUPPORTED_CRITICAL_PAYLOAD naming it, each ending it so and recording no rejection
// draft-ietf-ipsecme-ikev2-mlkem-09 section 2.2: "If the checks fail, the responder MUST reject the initiator's improper public key and SHOULD send a Notify payload of type INVALID_SYNTAX as a response to the request to prevent resource exhaustion or denial of service risks."
// RFC 9370 section 2.2.2: "The former "Diffie-Hellman Group Num" (now called "Key Exchange Method") field in the KEi(n) and KEr(n) payloads MUST match the n-th negotiated additional key exchange."
// RFC 7296 section 2.21.2: "request messages that contain an unsupported critical payload, or where the whole message is malformed (rather than just bad payload contents), MUST be rejected in their entirety, and MUST only lead to an UNSUPPORTED_CRITICAL_PAYLOAD or INVALID_SYNTAX Notification sent as a response."
func TestResponderAnswersAKEPayloadItRefusesWithItsNotifyAlone(t *testing.T) {
	_, key := modelKEM(t, ML_KEM_768)
	_, other := modelKEM(t, ML_KEM_1024)
	// FIPS 203 ByteEncode12 puts the first coefficient in the first octet and the low half of the second
	overQ := slices.Clone(key)
	overQ[0], overQ[1] = 0xff, overQ[1]|0x0f
	ke := func(method uint16, data []byte) RawPayload {
		return RawPayload{Type: PayloadKE, Body: EncodeKE(method, data)}
	}
	const unassigned = PayloadType(200)
	for name, test := range map[string]struct {
		inner  []RawPayload
		notify NotifyType
		data   []byte
		// rejected tells a key refused by its check
		rejected bool
	}{
		"a key with a coefficient of 4095": {inner: []RawPayload{ke(ML_KEM_768, overQ)}, notify: N_INVALID_SYNTAX, rejected: true},
		"a key one octet short":            {inner: []RawPayload{ke(ML_KEM_768, key[:len(key)-1])}, notify: N_INVALID_SYNTAX, rejected: true},
		"a key one octet long":             {inner: []RawPayload{ke(ML_KEM_768, append(slices.Clone(key), 0))}, notify: N_INVALID_SYNTAX, rejected: true},
		"no KE payload":                    {inner: []RawPayload{{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_INITIAL_CONTACT})}}, notify: N_INVALID_SYNTAX},
		"a KE payload of ML-KEM-1024":      {inner: []RawPayload{ke(ML_KEM_1024, other)}, notify: N_INVALID_SYNTAX},
		"two KE payloads":                  {inner: []RawPayload{ke(ML_KEM_768, key), ke(ML_KEM_768, key)}, notify: N_INVALID_SYNTAX},
		"a critical payload of an unassigned type": {inner: []RawPayload{ke(ML_KEM_768, key), {Type: unassigned, Critical: true}},
			notify: N_UNSUPPORTED_CRITICAL_PAYLOAD, data: []byte{byte(unassigned)}},
	} {
		t.Run(name, func(t *testing.T) {
			refused := &recorder{}
			h := childRefusedHarness(t, refused.record)
			h.lists.Store(&Suites{kex: []kexEntry{entry768}})
			s, notify := openScripted(t, h, ikeOffer(addkeOf(TransADDKE1, ML_KEM_768)), true)
			if s == nil {
				t.Fatalf("the responder refused the offer with notify %d", notify)
			}
			s.send(IKE_INTERMEDIATE, 1, test.inner)
			header, answer, _ := s.receive()
			if header.ExchangeType != IKE_INTERMEDIATE || !header.IsResponse() || header.MessageID != 1 {
				t.Errorf("the responder answered with exchange %d at Message ID %d, want IKE_INTERMEDIATE at 1", header.ExchangeType, header.MessageID)
			}
			if len(answer) != 1 || answer[0].Type != PayloadN {
				t.Fatalf("the answer carries payload types %v, want one notify", payloadTypes(answer))
			}
			if got, err := DecodeNotify(answer[0].Body); err != nil || got.Type != test.notify || !bytes.Equal(got.Data, test.data) {
				t.Errorf("the answer holds notify %d with data %x (%v), want %d with %x", got.Type, got.Data, err, test.notify, test.data)
			}
			awaitHandshakeEnd(t, h, refused, s.spiI)
			var rejections []string
			for _, line := range refused.recorded() {
				if strings.HasPrefix(line, "ike.kex.rejected ") {
					rejections = append(rejections, line)
				}
			}
			want := []string(nil)
			if test.rejected {
				want = []string{"ike.kex.rejected > exchange=IKE_INTERMEDIATE method=mlkem768 side=key"}
			}
			if !slices.Equal(rejections, want) {
				t.Errorf("the responder recorded %q, want %q", rejections, want)
			}
		})
	}
}

// keptIntermediate returns the length of the IKE_INTERMEDIATE response of method under cipher and the octets a half-open SA keeps of its last such exchange, that response, the request's digest and IntAuth's two values under prf
func keptIntermediate(t *testing.T, method kemMethod, cipher Transform, prfID uint16) (response, kept int) {
	t.Helper()
	suite := SASuite{EncrID: cipher.ID, EncrKeyBits: cipher.KeyLengthBits, PRFID: prfID}
	params, err := aeadParams(suite.EncrID, suite.EncrKeyBits)
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, params.KeyLen+params.SaltLen)
	ctx := &ikeContext{suite: suite, spiI: 1, spiR: 2, responder: true, skei: key, sker: key}
	sealed, err := (&Session{current: ctx}).response(ctx, 1, IKE_INTERMEDIATE, []RawPayload{{Type: PayloadKE, Body: EncodeKE(method.id, make([]byte, kemSizes[method.id][1]))}})
	if err != nil {
		t.Fatal(err)
	}
	raw := sealed.whole
	// the IKE header, the Encrypted payload's header and IV, the KE payload's header and method, the ciphertext, the Pad Length octet and the ICV
	if want := HeaderLen + genericPayloadHeaderLen + params.IVLen + genericPayloadHeaderLen + 4 + kemSizes[method.id][1] + 1 + params.ICVLen; len(raw) != want {
		t.Errorf("method %d under cipher %d sends a response of %d octets, want %d", method.id, cipher.ID, len(raw), want)
	}
	return len(raw), len(raw) + sha256.Size + 2*len(prf(prfID, nil, nil))
}

// a half-open SA keeps its last IKE_INTERMEDIATE response, the request's digest and IntAuth, so halfOpenLimit of them keep a bounded amount whatever an initiator sends
// the responses are the sizes design section 4.12 counts, from Table 1's KE payloads under AES-GCM, and the cipher of most overhead under the PRF of the longest output bounds the rest
// draft-ietf-ipsecme-ikev2-mlkem-09 section 2.1 Table 1: "ML-KEM-768 | 1192 / 1096 | 36 | 1184 / 1088" and "ML-KEM-1024 | 1576 / 1576 | 37 | 1568 / 1568"
func TestHalfOpenSAsKeepABoundedIntermediateStateEach(t *testing.T) {
	for _, test := range []struct {
		method   uint16
		response int
	}{{ML_KEM_768, 1153}, {ML_KEM_1024, 1633}} {
		method, err := kemOf(test.method)
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := keptIntermediate(t, method, encrAES256, PRF_HMAC_SHA2_384); got != test.response {
			t.Errorf("method %d sends a response of %d octets, want design section 4.12's %d", test.method, got, test.response)
		}
	}
	largest := 0
	for _, method := range kemMethods {
		for _, cipher := range (Suites{}).ikeCiphers() {
			for _, prfID := range []uint16{PRF_HMAC_SHA2_256, PRF_HMAC_SHA2_384} {
				_, kept := keptIntermediate(t, method, cipher, prfID)
				largest = max(largest, kept)
			}
		}
	}
	const ceiling = 512 << 10
	if bound := halfOpenLimit * largest; bound > ceiling {
		t.Errorf("%d half-open SAs keep up to %d octets of IKE_INTERMEDIATE state, %d each, past %d", halfOpenLimit, bound, largest, ceiling)
	}
}

// played is a responder the test plays to one ranet3 dial, every key and IntAuth the model's
type played struct {
	t                  *testing.T
	peer               *net.UDPConn
	from               *net.UDPAddr
	model              *setupModel
	spiI, spiR         uint64
	message1, message2 []byte
	// request is the dial's IKE_SA_INIT request
	request *Message
	// seen is every request read, so a retransmission is passed over
	seen [][]byte
	// dialer is the dial's public key, and key the played responder's
	dialer ed25519.PublicKey
	key    ed25519.PrivateKey
	// forge sends a response under another key ahead of each IKE_INTERMEDIATE response
	forge bool
	// fragments answers IKE_SA_INIT with IKEV2_FRAGMENTATION_SUPPORTED, cut, where it is set, sends each response in IKE Fragment messages of that many octets of plaintext, and last is the datagrams of the last request read
	fragments bool
	cut       int
	last      [][]byte
	cancel    context.CancelFunc
	done      chan struct{}
	session   *Session
	err       error
}

// dialPlayed starts a dial under lists of a responder the test plays, recording into events, and reads its IKE_SA_INIT request
func dialPlayed(t *testing.T, lists Suites, events Recorder) *played {
	t.Helper()
	return dialPlayedWith(t, lists, events, func(*PeerConfig) {})
}

// dialPlayedWith is dialPlayed with the dial's configuration as configure leaves it
func dialPlayedWith(t *testing.T, lists Suites, events Recorder, configure func(*PeerConfig)) *played {
	t.Helper()
	peer := listenPeer(t)
	at := peer.LocalAddr().(*net.UDPAddr)
	dialer, dialerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cfg := PeerConfig{
		Local: identity.MustParse("ranet-test/initiator:1"), LocalPrivateKey: dialerKey,
		Remote: identity.MustParse("ranet-test/responder:2"), RemotePublicKey: public,
		RemoteAddr: at.IP, RemotePort: at.Port,
		Suites: func() Suites { return lists },
		Events: events,
	}
	configure(&cfg)
	p := &played{t: t, peer: peer, dialer: dialer, key: key, done: make(chan struct{})}
	ctx, cancel := context.WithTimeout(context.Background(), answerBudget)
	p.cancel = cancel
	go func() {
		defer close(p.done)
		p.session, p.err = InitiateContext(ctx, cfg)
	}()
	t.Cleanup(func() {
		cancel()
		<-p.done
		if p.session != nil {
			p.session.Mux().Close()
		}
	})
	p.request, p.message1 = p.read(IKE_SA_INIT)
	return p
}

// read is the dial's next request past retransmissions of any before it, which must be of exchange, and its octets
func (p *played) read(exchange ExchangeType) (*Message, []byte) {
	p.t.Helper()
	buf := make([]byte, 65536)
	if err := p.peer.SetReadDeadline(time.Now().Add(answerBudget)); err != nil {
		p.t.Fatal(err)
	}
	for {
		n, from, err := p.peer.ReadFromUDP(buf)
		if err != nil {
			p.t.Fatalf("the dial sent no request of exchange %d: %v", exchange, err)
		}
		raw := slices.Clone(buf[min(n, 4):n])
		if slices.ContainsFunc(p.seen, func(seen []byte) bool { return bytes.Equal(seen, raw) }) {
			continue
		}
		p.seen = append(p.seen, raw)
		message, err := DecodeMessage(raw)
		if err != nil {
			p.t.Fatal(err)
		}
		if message.Header.ExchangeType != exchange {
			p.t.Fatalf("the dial sent exchange %d at Message ID %d, want exchange %d", message.Header.ExchangeType, message.Header.MessageID, exchange)
		}
		p.from = from
		return message, raw
	}
}

// readAll is the datagrams of the dial's next request past retransmissions of any before it, which must be of exchange, the request whole or each of its fragments once
func (p *played) readAll(exchange ExchangeType) [][]byte {
	p.t.Helper()
	p.last = collect(p.t, func() ([]byte, error) {
		_, raw := p.read(exchange)
		return raw, nil
	})
	return p.last
}

// quiet reports whether the dial sends nothing new for quietPeriod
func (p *played) quiet() bool {
	buf := make([]byte, 65536)
	if err := p.peer.SetReadDeadline(time.Now().Add(quietPeriod)); err != nil {
		p.t.Fatal(err)
	}
	for {
		n, _, err := p.peer.ReadFromUDP(buf)
		if err != nil {
			return true
		}
		if raw := buf[min(n, 4):n]; !slices.ContainsFunc(p.seen, func(seen []byte) bool { return bytes.Equal(seen, raw) }) {
			return false
		}
	}
}

// answerSAInit answers IKE_SA_INIT with transforms as proposal number, holding INTERMEDIATE_EXCHANGE_SUPPORTED where notify holds, its Notification Data data
func (p *played) answerSAInit(number uint8, transforms []Transform, notify bool, data ...byte) {
	p.t.Helper()
	ke, nonce := p.request.find(PayloadKE), p.request.find(PayloadNonce)
	if ke == nil || nonce == nil {
		p.t.Fatalf("the IKE_SA_INIT request carries payload types %v", payloadTypes(p.request.Payloads))
	}
	group, public, err := DecodeKE(ke.Body)
	if err != nil || group != DH_CURVE25519 {
		p.t.Fatalf("the IKE_SA_INIT request has its KE payload in group %d: %v", group, err)
	}
	dh, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		p.t.Fatal(err)
	}
	peer, err := ecdh.X25519().NewPublicKey(public)
	if err != nil {
		p.t.Fatal(err)
	}
	shared, err := dh.ECDH(peer)
	if err != nil {
		p.t.Fatal(err)
	}
	nr := make([]byte, nonceLen)
	rand.Read(nr)
	p.spiI, p.spiR = p.request.Header.SPIInitiator, randUint64Nonzero()
	payloads := []RawPayload{
		{Type: PayloadSA, Body: EncodeSA([]Proposal{{Number: number, Protocol: ProtoIKE, Transforms: transforms}})},
		{Type: PayloadKE, Body: EncodeKE(DH_CURVE25519, dh.PublicKey().Bytes())},
		{Type: PayloadNonce, Body: EncodeNonce(nr)},
		{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_SIGNATURE_HASH_ALGORITHMS, Data: binary.BigEndian.AppendUint16(nil, HashIdentity)})},
	}
	if notify {
		payloads = append(payloads, RawPayload{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_INTERMEDIATE_EXCHANGE_SUPPORTED, Data: data})})
	}
	if p.fragments {
		payloads = append(payloads, fragmentationSupported)
	}
	p.message2 = (&Message{Header: Header{SPIInitiator: p.spiI, SPIResponder: p.spiR, ExchangeType: IKE_SA_INIT, Flags: FlagResponse}, Payloads: payloads}).Encode()
	if _, err := p.peer.WriteToUDP(withNonESPMarker(p.message2), p.from); err != nil {
		p.t.Fatal(err)
	}
	p.model = newSetupModel(DecodeNonce(nonce.Body), nr, p.spiI, p.spiR, shared)
}

// send seals inner as the response of exchange at mid under key and returns its octets whole
func (p *played) send(key []byte, exchange ExchangeType, mid uint32, inner []RawPayload) []byte {
	p.t.Helper()
	header := Header{SPIInitiator: p.spiI, SPIResponder: p.spiR, ExchangeType: exchange, Flags: FlagResponse, MessageID: mid}
	raw, err := EncryptMessage(modelSuite, key, header, nil, inner)
	if err != nil {
		p.t.Fatal(err)
	}
	datagrams := [][]byte{raw}
	if p.cut > 0 {
		datagrams = cutInto(p.t, modelSuite, key, header, inner, p.cut)
	}
	for _, datagram := range datagrams {
		if _, err := p.peer.WriteToUDP(withNonESPMarker(datagram), p.from); err != nil {
			p.t.Fatal(err)
		}
	}
	return raw
}

// open is the dial's request of exchange at mid, whole or in fragments, opened under the newest generation, and its octets through its Encrypted payload's generic header as the request has them whole
func (p *played) open(exchange ExchangeType, mid uint32) ([]RawPayload, []byte) {
	p.t.Helper()
	header, inner, raw, _ := assembled(p.t, modelSuite, p.model.keys[1], p.readAll(exchange))
	if header.MessageID != mid || !header.IsInitiator() || header.IsResponse() {
		p.t.Fatalf("the dial sent exchange %d at Message ID %d, initiator %v response %v, want its request at %d", exchange, header.MessageID, header.IsInitiator(), header.IsResponse(), mid)
	}
	return inner, raw
}

// answerIntermediate answers IKE_INTERMEDIATE at mid of method with the ciphertext crypto/mlkem encapsulates to the dial's key, or with what shape makes of it, and takes the exchange into the model
func (p *played) answerIntermediate(mid uint32, method uint16, shape func(ciphertext []byte) []RawPayload) {
	p.t.Helper()
	inner, request := p.open(IKE_INTERMEDIATE, mid)
	if len(inner) != 1 || inner[0].Type != PayloadKE {
		p.t.Fatalf("the IKE_INTERMEDIATE request at %d carries payload types %v, want one KE payload", mid, payloadTypes(inner))
	}
	got, key, err := DecodeKE(inner[0].Body)
	if err != nil || got != method {
		p.t.Fatalf("the IKE_INTERMEDIATE request at %d has its KE payload in method %d, want %d: %v", mid, got, method, err)
	}
	secret, ciphertext := modelEncapsulate(p.t, method, key)
	answer := []RawPayload{{Type: PayloadKE, Body: EncodeKE(method, ciphertext)}}
	if shape != nil {
		answer = shape(ciphertext)
	}
	if p.forge {
		p.send(bytes.Repeat([]byte{7}, modelKeyLen), IKE_INTERMEDIATE, mid, answer)
	}
	response := p.send(p.model.keys[2], IKE_INTERMEDIATE, mid, answer)
	p.model.exchanged(request, encodePayloadChain(inner), response, encodePayloadChain(answer), secret)
}

// playedIDr is the IDr payload body of every played responder
var playedIDr = idBody("ranet-test/responder:2")

// answerAuth takes IKE_AUTH at mid, its AUTH checked over the model's octets with IntAuth at mid, and answers with the played responder's AUTH over signed and a Child SA
// a nil signed is the model's octets
func (p *played) answerAuth(mid uint32, signed []byte) {
	p.t.Helper()
	inner, _ := p.open(IKE_AUTH, mid)
	idi, auth := findType(inner, PayloadIDi), findType(inner, PayloadAUTH)
	if idi == nil || auth == nil {
		p.t.Fatalf("the IKE_AUTH request carries payload types %v", payloadTypes(inner))
	}
	if err := VerifyAuth(p.dialer, p.model.signed(p.message1, p.model.nr, p.model.keys[3], idi.Body, mid), auth.Body); err != nil {
		p.t.Errorf("the dial's AUTH does not verify over the model's octets: %v", err)
	}
	if signed == nil {
		signed = p.model.signed(p.message2, p.model.ni, p.model.keys[4], playedIDr, mid)
	}
	p.send(p.model.keys[2], IKE_AUTH, mid, []RawPayload{
		{Type: PayloadIDr, Body: playedIDr},
		{Type: PayloadAUTH, Body: BuildAuth(p.key, signed)},
		{Type: PayloadSA, Body: EncodeSA([]Proposal{{Number: 1, Protocol: ProtoESP, SPI: []byte{0, 0, 0, 9}, Transforms: []Transform{encrAES128, esnNone}}})},
		{Type: PayloadTSi, Body: fullRangeSelectors()},
		{Type: PayloadTSr, Body: fullRangeSelectors()},
	})
}

// ended is how the dial ended
func (p *played) ended() (*Session, error) {
	p.t.Helper()
	select {
	case <-p.done:
	case <-time.After(answerBudget):
		p.t.Fatal("the dial did not end")
	}
	return p.session, p.err
}

// a dial whose lists hold a + entry asks for IKE_INTERMEDIATE, runs an exchange at Message IDs from 1 for each method the answer agreed on, and signs IKE_AUTH at the next Message ID with IntAuth under the keys of the last generation
// its Child SA takes KEYMAT from that generation's SK_d and its next request takes the Message ID after IKE_AUTH
// an answer of the classical entry runs none, and a dial of classical lists asks for none
// RFC 9370 section 2.2.1: "If the initiator includes any ADDKE Transform Types into the SA payload in the IKE_SA_INIT exchange request message, then it MUST also negotiate the use of the IKE_INTERMEDIATE exchange, as described in [RFC9242] by including an INTERMEDIATE_EXCHANGE_SUPPORTED notification in the same message."
// RFC 9242 section 3.3.1: "Every subsequent IKE_INTERMEDIATE exchange uses the most recently calculated IKE SA keys before this exchange is started."
func TestDialRunsAnExchangeForEachAdditionAgreed(t *testing.T) {
	for name, test := range map[string]struct {
		entries []kexEntry
		number  uint8
		answer  []Transform
		asks    bool
		methods []uint16
		suite   string
	}{
		"x25519+mlkem768": {entries: []kexEntry{entry768}, number: 1, answer: slices.Concat(modelBase, addkeOf(TransADDKE1, ML_KEM_768)),
			asks: true, methods: []uint16{ML_KEM_768}, suite: "aes256gcm/sha384/x25519+mlkem768"},
		"x25519+mlkem768+mlkem1024": {entries: []kexEntry{entry768And1024}, number: 1,
			answer: slices.Concat(modelBase, addkeOf(TransADDKE1, ML_KEM_768), addkeOf(TransADDKE1+1, ML_KEM_1024)),
			asks:   true, methods: []uint16{ML_KEM_768, ML_KEM_1024}, suite: "aes256gcm/sha384/x25519+mlkem768+mlkem1024"},
		"x25519 answered beside x25519+mlkem768": {entries: []kexEntry{entry768, entryX25519}, number: 2, answer: modelBase, asks: true, suite: "aes256gcm/sha384/x25519"},
		"x25519 alone":                           {entries: []kexEntry{entryX25519}, number: 1, answer: modelBase, suite: "aes256gcm/sha384/x25519"},
	} {
		t.Run(name, func(t *testing.T) {
			p := dialPlayed(t, Suites{kex: test.entries}, nil)
			if got := carriesNotify(p.request, N_INTERMEDIATE_EXCHANGE_SUPPORTED); got != test.asks {
				t.Errorf("the IKE_SA_INIT request carries INTERMEDIATE_EXCHANGE_SUPPORTED %v, want %v", got, test.asks)
			}
			p.answerSAInit(test.number, test.answer, test.asks)
			var suite SASuite
			for n, method := range test.methods {
				p.answerIntermediate(uint32(n+1), method, nil)
				suite.Additions[n] = method
			}
			authMID := suite.authMID()
			p.answerAuth(authMID, nil)
			session, err := p.ended()
			if err != nil {
				t.Fatalf("the dial failed: %v", err)
			}
			ctx := session.current
			if got := [5][]byte{ctx.skD, ctx.skei, ctx.sker, ctx.skpi, ctx.skpr}; !slices.EqualFunc(got[:], p.model.keys[:], bytes.Equal) {
				t.Error("the dial's IKE SA keys are not those of the model's last generation")
			}
			if ctx.authMID != authMID || ctx.nextLocalMID != authMID+1 {
				t.Errorf("the dial ran IKE_AUTH at %d and sends its next request at %d, want %d and %d", ctx.authMID, ctx.nextLocalMID, authMID, authMID+1)
			}
			if got := session.Suite().IKE(); got != test.suite {
				t.Errorf("the dial's IKE SA runs %s, want %s", got, test.suite)
			}
			child := session.currentChild()
			initiatorKey, responderKey := p.model.childKeys(len(child.OutboundKey))
			if !bytes.Equal(child.OutboundKey, initiatorKey) || !bytes.Equal(child.InboundKey, responderKey) {
				t.Error("the dial's Child SA keys are not KEYMAT from the model's last SK_d")
			}
		})
	}
}

// a datagram at an IKE_INTERMEDIATE response's Message ID that does not decrypt is passed over, and the dial takes the response after it
func TestDialWaitsPastAnIntermediateResponseThatDoesNotDecrypt(t *testing.T) {
	p := dialPlayed(t, Suites{kex: []kexEntry{entry768}}, nil)
	p.forge = true
	p.answerSAInit(1, slices.Concat(modelBase, addkeOf(TransADDKE1, ML_KEM_768)), true)
	p.answerIntermediate(1, ML_KEM_768, nil)
	p.answerAuth(2, nil)
	if _, err := p.ended(); err != nil {
		t.Fatalf("the dial failed: %v", err)
	}
}

// a dial refuses an answer agreeing on additional key exchanges that carries no INTERMEDIATE_EXCHANGE_SUPPORTED, and sends nothing more
// RFC 9370 section 2.2.1: "If the IKE_INTERMEDIATE exchange is not negotiated, then the peers MUST treat any ADDKE Transform Types in the IKE_SA_INIT exchange messages as unknown transform types and skip the proposals they appear in."
func TestDialRefusesAdditionsAgreedWithoutTheNotify(t *testing.T) {
	p := dialPlayed(t, Suites{kex: []kexEntry{entry768}}, nil)
	p.answerSAInit(1, slices.Concat(modelBase, addkeOf(TransADDKE1, ML_KEM_768)), false)
	if !p.quiet() {
		t.Error("the dial sent another request after an answer it must refuse")
	}
	if _, err := p.ended(); err == nil {
		t.Error("the dial took additions agreed without INTERMEDIATE_EXCHANGE_SUPPORTED")
	}
}

// INTERMEDIATE_EXCHANGE_SUPPORTED carrying Notification Data negotiates the exchange at either end, which reads the notify by its type
// RFC 9242 section 3.1: "Implementations MUST ignore non-empty Notification Data if they don't understand its purpose."
func TestIntermediateNotifyWithDataNegotiatesTheExchange(t *testing.T) {
	data := []byte{0x52, 0x33, 0x00}
	hybrid := slices.Concat(modelBase, addkeOf(TransADDKE1, ML_KEM_768))
	t.Run("responder", func(t *testing.T) {
		h := newResponderHarness(t, nil)
		h.lists.Store(&Suites{kex: []kexEntry{entry768}})
		s, refused := openScripted(t, h, ikeOffer(addkeOf(TransADDKE1, ML_KEM_768)), true, data...)
		if s == nil {
			t.Fatalf("the responder refused a request whose notify carries data with notify %d", refused)
		}
		if got := s.chose(); !slices.Equal(got, hybrid) {
			t.Fatalf("the responder answered %+v, want %+v", got, hybrid)
		}
		if !carriesNotify(s.answer, N_INTERMEDIATE_EXCHANGE_SUPPORTED) {
			t.Error("the IKE_SA_INIT answer carries no INTERMEDIATE_EXCHANGE_SUPPORTED")
		}
		s.intermediate(1, ML_KEM_768)
		if header, _ := s.authenticate(2, 2); header.ExchangeType != IKE_AUTH || header.MessageID != 2 {
			t.Fatalf("the responder answered IKE_AUTH with exchange %d at Message ID %d, want IKE_AUTH at 2", header.ExchangeType, header.MessageID)
		}
		s.accepted(2, []uint16{ML_KEM_768})
	})
	t.Run("dial", func(t *testing.T) {
		p := dialPlayed(t, Suites{kex: []kexEntry{entry768}}, nil)
		p.answerSAInit(1, hybrid, true, data...)
		p.answerIntermediate(1, ML_KEM_768, nil)
		p.answerAuth(2, nil)
		if _, err := p.ended(); err != nil {
			t.Fatalf("the dial refused an answer whose notify carries data: %v", err)
		}
	})
}

// a dial refuses an IKE_INTERMEDIATE response whose KE payload is missing, names another method or holds a ciphertext of another length, records ike.kex.rejected naming the exchange, the method and the ciphertext, and sends neither the next IKE_INTERMEDIATE nor IKE_AUTH
// a response of an error notify, or one marking a payload of an unassigned type critical, fails the dial so and records no rejection
// RFC 7296 section 2.5: "If the critical flag is set and the payload type is unrecognized, the message MUST be rejected"
// draft-ietf-ipsecme-ikev2-mlkem-09 section 2.2: "If the check fails, the initiator MUST reject the ciphertext and MUST fail the exchange, log the error, and stop creating the SA (i.e. not initiate IKE_AUTH or next IKE_INTERMEDIATE)."
// RFC 9242 section 3.4 on the error handling of RFC 7296 sections 2.21.1 and 2.21.2: "these considerations are also applied to the IKE_INTERMEDIATE exchange"
func TestDialRejectsAnIntermediateResponseItCannotTake(t *testing.T) {
	ke := func(method uint16, data []byte) []RawPayload {
		return []RawPayload{{Type: PayloadKE, Body: EncodeKE(method, data)}}
	}
	for name, test := range map[string]struct {
		shape    func(ciphertext []byte) []RawPayload
		rejected bool
	}{
		"a ciphertext one octet short": {func(c []byte) []RawPayload { return ke(ML_KEM_768, c[:len(c)-1]) }, true},
		"a ciphertext one octet long":  {func(c []byte) []RawPayload { return ke(ML_KEM_768, append(c, 0)) }, true},
		"no KE payload": {func([]byte) []RawPayload {
			return []RawPayload{{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_INITIAL_CONTACT})}}
		}, true},
		"a KE payload of ML-KEM-1024": {func([]byte) []RawPayload { return ke(ML_KEM_1024, make([]byte, mlkem.CiphertextSize1024)) }, true},
		"INVALID_SYNTAX": {func([]byte) []RawPayload {
			return []RawPayload{{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_INVALID_SYNTAX})}}
		}, false},
		"a critical payload of an unassigned type beside the KE payload": {func(c []byte) []RawPayload {
			return append(ke(ML_KEM_768, c), RawPayload{Type: PayloadType(200), Critical: true})
		}, false},
	} {
		t.Run(name, func(t *testing.T) {
			dialed := &recorder{}
			p := dialPlayed(t, Suites{kex: []kexEntry{entry768And1024}}, dialed.record)
			p.answerSAInit(1, slices.Concat(modelBase, addkeOf(TransADDKE1, ML_KEM_768), addkeOf(TransADDKE1+1, ML_KEM_1024)), true)
			p.answerIntermediate(1, ML_KEM_768, test.shape)
			if !p.quiet() {
				t.Error("the dial sent another request after a response it refuses")
			}
			if _, err := p.ended(); err == nil {
				t.Fatal("the dial took the response")
			}
			want := 0
			if test.rejected {
				want = 1
				awaitRecorded(t, dialed, "ike.kex.rejected ranet-test/initiator:1>ranet-test/responder:2 exchange=IKE_INTERMEDIATE method=mlkem768 side=ciphertext")
			}
			if got := recordedKind(dialed, "ike.kex.rejected"); got != want {
				t.Errorf("the dial recorded %d rejections, want %d: %q", got, want, dialed.recorded())
			}
		})
	}
}

// a dial refuses a responder's AUTH that leaves IntAuth out, carries another IKE_AUTH_MID or takes MACedIDForR under the SK_pr of the generation before the last
// it says so with AUTHENTICATION_FAILED in an INFORMATIONAL request at the Message ID after IKE_AUTH
// RFC 9242 section 3.3.2: "ResponderSignedOctets = RealMsg2 | NonceIData | MACedIDForR | IntAuth"
// RFC 7296 section 2.21.2: "If the error occurs on the initiator, the notification MAY be returned in a separate INFORMATIONAL exchange, usually with no other payloads."
func TestDialRefusesAResponderAuthOverOtherOctets(t *testing.T) {
	for name, signed := range map[string]func(p *played, skpr0 []byte) []byte{
		"the octets of RFC 7296 alone": func(p *played, _ []byte) []byte {
			return concat(p.message2, p.model.ni, modelPRF(p.model.keys[4], playedIDr))
		},
		"IKE_AUTH_MID 1": func(p *played, _ []byte) []byte {
			return p.model.signed(p.message2, p.model.ni, p.model.keys[4], playedIDr, 1)
		},
		"MACedIDForR under SK_pr(0)": func(p *played, skpr0 []byte) []byte {
			return p.model.signed(p.message2, p.model.ni, skpr0, playedIDr, 2)
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := dialPlayed(t, Suites{kex: []kexEntry{entry768}}, nil)
			p.answerSAInit(1, slices.Concat(modelBase, addkeOf(TransADDKE1, ML_KEM_768)), true)
			skpr0 := p.model.keys[4]
			p.answerIntermediate(1, ML_KEM_768, nil)
			p.answerAuth(2, signed(p, skpr0))
			inner, _ := p.open(INFORMATIONAL, 3)
			if len(inner) != 1 || inner[0].Type != PayloadN {
				t.Fatalf("the INFORMATIONAL request carries payload types %v, want one notify", payloadTypes(inner))
			}
			if got, err := DecodeNotify(inner[0].Body); err != nil || got.Type != N_AUTHENTICATION_FAILED {
				t.Errorf("the INFORMATIONAL request holds notify %d (%v), want AUTHENTICATION_FAILED", got.Type, err)
			}
			p.send(p.model.keys[2], INFORMATIONAL, 3, nil)
			if _, err := p.ended(); err == nil {
				t.Error("the dial took the responder's AUTH")
			}
		})
	}
}

// a cancel while an IKE_INTERMEDIATE exchange waits ends the dial at once and sends nothing more, since only a half-open SA stands at the responder
func TestCancelDuringAnIntermediateExchangeEndsTheDialAtOnce(t *testing.T) {
	p := dialPlayed(t, Suites{kex: []kexEntry{entry768}}, nil)
	p.answerSAInit(1, slices.Concat(modelBase, addkeOf(TransADDKE1, ML_KEM_768)), true)
	p.open(IKE_INTERMEDIATE, 1)
	canceled := time.Now()
	p.cancel()
	if _, err := p.ended(); !errors.Is(err, context.Canceled) {
		t.Errorf("the canceled dial ended with %v, want the cancel", err)
	}
	// a dial past IKE_SA_INIT gives its exchanges canceledAuthWait
	if took := time.Since(canceled); took >= canceledAuthWait/2 {
		t.Errorf("the canceled dial took %s to end", took)
	}
	if !p.quiet() {
		t.Error("the canceled dial sent another request")
	}
}

// two ends listing x25519+mlkem768+mlkem1024 run both exchanges at Message IDs 1 and 2 and IKE_AUTH at 3, and hold the same keys after it
// the dial's next request, a rekey of the Child SA, goes at Message ID 4 and completes
func TestTwoEndsOfTwoAdditionsAgreeOnEveryGeneration(t *testing.T) {
	h := newResponderHarness(t, nil)
	lists := Suites{kex: []kexEntry{entry768And1024, entryX25519}}
	h.lists.Store(&lists)
	var mu sync.Mutex
	var requests []string
	cfg := h.peerConfig()
	cfg.Suites = func() Suites { return lists }
	cfg.RemotePort = relay(t, h.remotePort, func(fromInitiator bool, header *Header, _ []byte) bool {
		if header != nil && fromInitiator && !header.IsResponse() {
			mu.Lock()
			if request := fmtExchange(header); !slices.Contains(requests, request) {
				requests = append(requests, request)
			}
			mu.Unlock()
		}
		return true
	})
	initiator, responder := dialPaused(t, h, cfg)
	for _, s := range []*Session{initiator, responder} {
		t.Cleanup(func() { s.Mux().Close() })
	}
	a, b := initiator.current, responder.current
	if !slices.EqualFunc([][]byte{a.skD, a.skei, a.sker, a.skpi, a.skpr}, [][]byte{b.skD, b.skei, b.sker, b.skpi, b.skpr}, bytes.Equal) {
		t.Error("the two ends hold different IKE SA keys")
	}
	for _, s := range []*Session{initiator, responder} {
		if got := s.Suite().IKE(); got != "aes256gcm/sha384/x25519+mlkem768+mlkem1024" {
			t.Errorf("an end runs %s, want aes256gcm/sha384/x25519+mlkem768+mlkem1024", got)
		}
	}
	runSession(t, initiator)
	runSession(t, responder)
	if err := initiator.RekeyChild(); err != nil {
		t.Fatalf("the Child SA rekey after IKE_AUTH at 3 failed: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	// the old Child SA's Delete may follow
	if want := []string{"IKE_SA_INIT 0", "IKE_INTERMEDIATE 1", "IKE_INTERMEDIATE 2", "IKE_AUTH 3", "CREATE_CHILD_SA 4"}; len(requests) < len(want) || !slices.Equal(requests[:len(want)], want) {
		t.Errorf("the dial sent requests %q, want %q first", requests, want)
	}
}

// fmtExchange names a request by its exchange and Message ID
func fmtExchange(header *Header) string {
	return fmt.Sprintf("%s %d", exchangeName(header.ExchangeType), header.MessageID)
}
