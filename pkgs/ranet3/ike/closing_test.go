// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ike

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/bubble"
	"ranet3.com/pkgs/ranet3/transport"
)

// an initiator whose own Delete is out answers the responder's Delete crossing it as usual and stops waiting for its own answer
// the responder refuses the Child SA and deletes the IKE SA, and its answer to the initiator's Delete is held back, so only the crossing Delete settles the initiator's exchange
func TestInitiatorAnswersTheResponderDeleteCrossingItsOwn(t *testing.T) {
	bubble.Run(testInitiatorAnswersTheResponderDeleteCrossingItsOwn)(t)
}

func testInitiatorAnswersTheResponderDeleteCrossingItsOwn(t *testing.T) {
	refused := &recorder{}
	h := childRefusedHarness(t, refused.record)
	var answer atomic.Pointer[[]byte]
	port := relay(t, h.remotePort, func(fromInitiator bool, header *Header, raw []byte) bool {
		if header == nil || header.ExchangeType != INFORMATIONAL || !header.IsResponse() {
			return true
		}
		if fromInitiator {
			kept := slices.Clone(raw)
			answer.Store(&kept)
			return true
		}
		return false
	})
	mux, err := h.initiator.NewMux(net.ParseIP("127.0.0.1"), port)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mux.Close() })
	held, _ := dialRefusedChild(t, h, mux)
	if header, _, _ := responderMessage(t, mux, held); header.ExchangeType != IKE_AUTH || !header.IsResponse() {
		t.Fatalf("the responder first sent exchange %d response %v, want its IKE_AUTH answer", header.ExchangeType, header.IsResponse())
	}

	held.nextLocalMID = 2
	initiator := &Session{mux: mux, current: held}
	started := time.Now()
	if err := initiator.deleteAuthenticatedIKE(); err != nil {
		t.Fatalf("the initiator's Delete ended with %v, want the responder's crossing Delete to settle it", err)
	}
	if took := time.Since(started); took >= requestTimeout {
		t.Errorf("the initiator waited %s for its own answer, the time of a retransmission", took)
	}
	for deadline := time.Now().Add(answerBudget); answer.Load() == nil; time.Sleep(recordPoll) {
		if time.Now().After(deadline) {
			t.Fatal("the initiator never answered the responder's Delete")
		}
	}
	raw := *answer.Load()
	message, err := DecodeMessage(raw)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := DecryptMessage(held.suite, held.skei, raw, message)
	if err != nil {
		t.Fatal(err)
	}
	if message.Header.MessageID != 0 || len(inner) != 0 {
		t.Errorf("the initiator answered at Message ID %d with %v, want an empty answer at the responder's first Message ID", message.Header.MessageID, inner)
	}
	awaitHandshakeEnd(t, h, refused, held.spiI)
}

// a request that does not close the IKE SA is answered and leaves the initiator waiting for its own answer, a rekey of the IKE SA being answered with TEMPORARY_FAILURE
func TestInitiatorClosingAfterAuthAnswersOtherRequestsAndWaitsOn(t *testing.T) {
	bubble.Run(testInitiatorClosingAfterAuthAnswersOtherRequestsAndWaitsOn)(t)
}

func testInitiatorClosingAfterAuthAnswersOtherRequestsAndWaitsOn(t *testing.T) {
	peer, initiator := closingAfterAuth(t)
	done := make(chan error, 1)
	go func() { done <- initiator.deleteAuthenticatedIKE() }()
	own := peer.read(t)
	if own.Header.MessageID != 2 || own.Header.IsResponse() {
		t.Fatalf("the initiator sent Message ID %d response %v, want its Delete at 2", own.Header.MessageID, own.Header.IsResponse())
	}

	peer.send(t, Header{ExchangeType: INFORMATIONAL, MessageID: 0}, nil)
	if answer := peer.answer(t); answer.Header.MessageID != 0 || len(answer.inner) != 0 {
		t.Fatalf("the liveness check drew Message ID %d carrying %v, want an empty answer at 0", answer.Header.MessageID, answer.inner)
	}
	peer.send(t, Header{ExchangeType: CREATE_CHILD_SA, MessageID: 1}, ikeRekeyRequest(t))
	if answer := peer.answer(t); answer.Header.ExchangeType != CREATE_CHILD_SA || answer.Header.MessageID != 1 || !notified(answer.inner, N_TEMPORARY_FAILURE, nil) {
		t.Fatalf("the IKE SA rekey drew exchange %d Message ID %d carrying %v, want TEMPORARY_FAILURE at 1", answer.Header.ExchangeType, answer.Header.MessageID, answer.inner)
	}
	waitsOn(t, done)
	peer.send(t, Header{ExchangeType: INFORMATIONAL, Flags: FlagResponse, MessageID: 2}, nil)
	settled(t, done, nil)
}

// a session whose own Delete of its IKE SA is out answers a rekey of that IKE SA, or of a Child SA under it, with TEMPORARY_FAILURE and goes on waiting for its answer
func TestSessionClosingItsIKESARefusesRekeysOfIt(t *testing.T) {
	why := errors.New("the reason to delete")
	for _, closer := range []string{"run ending", "DeleteIKE"} {
		t.Run(closer, bubble.Run(func(t *testing.T) {
			peer, s := closingAfterAuth(t)
			s.requests = make(chan *localRequest, 1)
			s.Child = ChildSA{LocalSPI: 0x10203040, RemoteSPI: 0x50607080}
			deleted, finished := make(chan error, 1), make(chan struct{})
			go func() {
				defer close(finished)
				if closer == "run ending" {
					deleted <- s.run(context.Background(), why)
				} else {
					_ = s.Run(context.Background())
				}
			}()
			t.Cleanup(func() {
				s.mux.Close()
				<-finished
			})
			var want error
			if closer == "run ending" {
				want = why
			} else {
				for deadline := time.Now().Add(answerBudget); !s.serving.Load(); time.Sleep(recordPoll) {
					if time.Now().After(deadline) {
						t.Fatal("the session never started serving")
					}
				}
				go func() { deleted <- s.DeleteIKE() }()
			}
			own := peer.read(t)
			if own.Header.ExchangeType != INFORMATIONAL || own.Header.IsResponse() || !deletesIKE(own.inner) {
				t.Fatalf("the session sent exchange %d response %v carrying %v, want its Delete of the IKE SA", own.Header.ExchangeType, own.Header.IsResponse(), own.inner)
			}

			for mid, rekey := range []struct {
				sa    string
				inner []RawPayload
			}{{"IKE", ikeRekeyRequest(t)}, {"Child", childRekeyRequest(s.Child.RemoteSPI)}} {
				peer.send(t, Header{ExchangeType: CREATE_CHILD_SA, MessageID: uint32(mid)}, rekey.inner)
				if answer := peer.answer(t); answer.Header.ExchangeType != CREATE_CHILD_SA || answer.Header.MessageID != uint32(mid) || !notified(answer.inner, N_TEMPORARY_FAILURE, nil) {
					t.Errorf("the %s SA rekey drew exchange %d Message ID %d carrying %v, want TEMPORARY_FAILURE at %d", rekey.sa, answer.Header.ExchangeType, answer.Header.MessageID, answer.inner, mid)
				}
			}
			peer.send(t, Header{ExchangeType: INFORMATIONAL, Flags: FlagResponse, MessageID: own.Header.MessageID}, nil)
			settled(t, deleted, want)
		}))
	}
}

// a rekey of the closing IKE SA that carries a critical payload this end does not support is rejected for that payload, not refused with TEMPORARY_FAILURE, and the initiator waits on
func TestInitiatorClosingAfterAuthRejectsACriticalPayloadBeforeRefusingTheRekey(t *testing.T) {
	bubble.Run(testInitiatorClosingAfterAuthRejectsACriticalPayloadBeforeRefusingTheRekey)(t)
}

func testInitiatorClosingAfterAuthRejectsACriticalPayloadBeforeRefusingTheRekey(t *testing.T) {
	peer, initiator := closingAfterAuth(t)
	done := make(chan error, 1)
	go func() { done <- initiator.deleteAuthenticatedIKE() }()
	own := peer.read(t)

	peer.send(t, Header{ExchangeType: CREATE_CHILD_SA, MessageID: 0}, append(ikeRekeyRequest(t), unsupportedCritical))
	if answer := peer.answer(t); answer.Header.ExchangeType != CREATE_CHILD_SA || answer.Header.MessageID != 0 ||
		!notified(answer.inner, N_UNSUPPORTED_CRITICAL_PAYLOAD, []byte{byte(unsupportedCritical.Type)}) {
		t.Fatalf("the rekey drew exchange %d Message ID %d carrying %v, want UNSUPPORTED_CRITICAL_PAYLOAD for type %d at 0", answer.Header.ExchangeType, answer.Header.MessageID, answer.inner, unsupportedCritical.Type)
	}
	waitsOn(t, done)
	peer.send(t, Header{ExchangeType: INFORMATIONAL, Flags: FlagResponse, MessageID: own.Header.MessageID}, nil)
	settled(t, done, nil)
}

func ikeRekeyRequest(t *testing.T) []RawPayload {
	t.Helper()
	dh, err := GenerateDH(DH_CURVE25519)
	if err != nil {
		t.Fatal(err)
	}
	return []RawPayload{
		{Type: PayloadSA, Body: EncodeSA([]Proposal{ikeRekeyProposal(binary.BigEndian.AppendUint64(nil, 0x2122232425262728), PRF_HMAC_SHA2_256)})},
		{Type: PayloadNonce, Body: EncodeNonce(make([]byte, 32))},
		{Type: PayloadKE, Body: EncodeKE(DH_CURVE25519, dh.PublicBytes())},
	}
}

func childRekeyRequest(remoteSPI uint32) []RawPayload {
	return []RawPayload{
		{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_REKEY_SA, Protocol: ProtoESP, SPI: binary.BigEndian.AppendUint32(nil, remoteSPI)})},
		{Type: PayloadSA, Body: EncodeSA([]Proposal{{
			Number: 1, Protocol: ProtoESP, SPI: binary.BigEndian.AppendUint32(nil, 0x90a0b0c0),
			Transforms: []Transform{{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128}, {Type: TransESN, ID: ESN_NO}},
		}})},
		{Type: PayloadNonce, Body: EncodeNonce(make([]byte, 32))},
		{Type: PayloadTSi, Body: fullRangeSelectors()},
		{Type: PayloadTSr, Body: fullRangeSelectors()},
	}
}

// closingPeer stands in for a responder past IKE_AUTH, on the IKE SA the initiator holds
type closingPeer struct {
	conn *transport.MemoryConn
	held *ikeContext
	to   *net.UDPAddr
}

type closingMessage struct {
	*Message
	inner []RawPayload
	raw   []byte
}

func closingAfterAuth(t *testing.T) (*closingPeer, *Session) {
	t.Helper()
	return closingAfterAuthThrough(t, nil)
}

// pass, where set, sees what goes between the two ends as relay's does
func closingAfterAuthThrough(t *testing.T, pass func(fromInitiator bool, header *Header, raw []byte) bool) (*closingPeer, *Session) {
	t.Helper()
	conn := listenPeer(t)
	addr := conn.LocalAddr().(*net.UDPAddr)
	port := addr.Port
	if pass != nil {
		port = relay(t, addr.Port, pass)
	}
	mux, err := testNetwork(t).Dial(addr.IP, port)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mux.Close() })
	held := &ikeContext{suite: SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256},
		spiI: 0x0102030405060708, spiR: 0x1112131415161718, nextLocalMID: 2, skei: make([]byte, 20), sker: make([]byte, 20)}
	if err := mux.RegisterIKE(held.spiI); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetDeadline(time.Now().Add(answerBudget)); err != nil {
		t.Fatal(err)
	}
	return &closingPeer{conn: conn, held: held}, &Session{mux: mux, current: held}
}

func (p *closingPeer) read(t *testing.T) closingMessage {
	t.Helper()
	buf := make([]byte, 2048)
	n, from, err := p.conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("the initiator sent nothing: %v", err)
	}
	p.to = from
	raw := slices.Clone(buf[4:n])
	message, err := DecodeMessage(raw)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := DecryptMessage(p.held.suite, p.held.skei, raw, message)
	if err != nil {
		t.Fatal(err)
	}
	return closingMessage{message, inner, raw}
}

// answer passes over the initiator's own request, which it retransmits while it waits
func (p *closingPeer) answer(t *testing.T) closingMessage {
	t.Helper()
	for {
		if message := p.read(t); message.Header.IsResponse() {
			return message
		}
	}
}

func (p *closingPeer) send(t *testing.T, header Header, inner []RawPayload) []byte {
	t.Helper()
	header.SPIInitiator, header.SPIResponder = p.held.spiI, p.held.spiR
	raw, err := EncryptMessage(p.held.suite, p.held.sker, header, nil, inner)
	if err != nil {
		t.Fatal(err)
	}
	p.write(t, raw)
	return raw
}

func (p *closingPeer) write(t *testing.T, raw []byte) {
	t.Helper()
	if _, err := p.conn.WriteToUDP(withNonESPMarker(raw), p.to); err != nil {
		t.Fatal(err)
	}
}

// unanswered has the initiator send no answer for quietPeriod, the retransmissions of its own request aside
func (p *closingPeer) unanswered(t *testing.T) {
	t.Helper()
	if err := p.conn.SetReadDeadline(time.Now().Add(quietPeriod)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	for {
		n, _, err := p.conn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		if header, err := decodeHeader(buf[4:n]); err != nil || header.IsResponse() {
			t.Fatalf("the initiator sent %x, want no answer", buf[4:n])
		}
	}
	if err := p.conn.SetReadDeadline(time.Now().Add(answerBudget)); err != nil {
		t.Fatal(err)
	}
}

// a request answered once and retransmitted, its answer lost on the way, draws that answer again bitwise and nothing else, so the next request is answered at the next Message ID and the initiator waits on
func TestInitiatorClosingAfterAuthAnswersARetransmittedRequestWithItsAnswer(t *testing.T) {
	bubble.Run(testInitiatorClosingAfterAuthAnswersARetransmittedRequestWithItsAnswer)(t)
}

func testInitiatorClosingAfterAuthAnswersARetransmittedRequestWithItsAnswer(t *testing.T) {
	var lost atomic.Pointer[[]byte]
	peer, initiator := closingAfterAuthThrough(t, func(fromInitiator bool, header *Header, raw []byte) bool {
		if !fromInitiator || header == nil || !header.IsResponse() || lost.Load() != nil {
			return true
		}
		kept := slices.Clone(raw)
		lost.Store(&kept)
		return false
	})
	done := make(chan error, 1)
	go func() { done <- initiator.deleteAuthenticatedIKE() }()
	own := peer.read(t)
	if own.Header.MessageID != 2 || own.Header.IsResponse() {
		t.Fatalf("the initiator sent Message ID %d response %v, want its Delete at 2", own.Header.MessageID, own.Header.IsResponse())
	}

	request := peer.send(t, Header{ExchangeType: INFORMATIONAL, MessageID: 0}, nil)
	for deadline := time.Now().Add(answerBudget); lost.Load() == nil; time.Sleep(recordPoll) {
		if time.Now().After(deadline) {
			t.Fatal("the initiator never answered the liveness check")
		}
	}
	peer.write(t, request)
	if again := peer.answer(t); !bytes.Equal(again.raw, *lost.Load()) {
		t.Fatalf("the retransmitted liveness check drew %x, want the lost answer %x", again.raw, *lost.Load())
	}
	peer.send(t, Header{ExchangeType: INFORMATIONAL, MessageID: 1}, nil)
	if next := peer.answer(t); next.Header.MessageID != 1 || len(next.inner) != 0 {
		t.Fatalf("the next liveness check drew Message ID %d carrying %v, want an empty answer at 1", next.Header.MessageID, next.inner)
	}
	waitsOn(t, done)
	peer.send(t, Header{ExchangeType: INFORMATIONAL, Flags: FlagResponse, MessageID: own.Header.MessageID}, nil)
	settled(t, done, nil)
}

// RFC 7296 section 2.25.1: "If a peer receives a request to close a Child SA that does not exist, it SHOULD reply without a Delete payload."
// a Delete of a Child SA closes no IKE SA: the initiator answers it without a Delete payload, since the IKE SA it is closing carries no Child SA, and goes on waiting for its own answer
func TestInitiatorClosingAfterAuthAnswersAChildSADeleteAndWaitsOn(t *testing.T) {
	bubble.Run(testInitiatorClosingAfterAuthAnswersAChildSADeleteAndWaitsOn)(t)
}

func testInitiatorClosingAfterAuthAnswersAChildSADeleteAndWaitsOn(t *testing.T) {
	peer, initiator := closingAfterAuth(t)
	done := make(chan error, 1)
	go func() { done <- initiator.deleteAuthenticatedIKE() }()
	own := peer.read(t)

	child := RawPayload{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoESP, SPIs: [][]byte{{0x50, 0x60, 0x70, 0x80}}})}
	peer.send(t, Header{ExchangeType: INFORMATIONAL, MessageID: 0}, []RawPayload{child})
	if answer := peer.answer(t); answer.Header.ExchangeType != INFORMATIONAL || answer.Header.MessageID != 0 || len(answer.inner) != 0 {
		t.Fatalf("the Child SA's Delete drew exchange %d Message ID %d carrying %v, want an empty answer at 0", answer.Header.ExchangeType, answer.Header.MessageID, answer.inner)
	}
	waitsOn(t, done)
	peer.send(t, Header{ExchangeType: INFORMATIONAL, Flags: FlagResponse, MessageID: own.Header.MessageID}, nil)
	settled(t, done, nil)
}

// a Delete at the next Message ID that does not authenticate is no request: the initiator neither answers it nor stops waiting for its own answer, and the peer's next request is still answered at that Message ID
func TestInitiatorClosingAfterAuthIgnoresARequestThatDoesNotAuthenticate(t *testing.T) {
	bubble.Run(testInitiatorClosingAfterAuthIgnoresARequestThatDoesNotAuthenticate)(t)
}

func testInitiatorClosingAfterAuthIgnoresARequestThatDoesNotAuthenticate(t *testing.T) {
	peer, initiator := closingAfterAuth(t)
	done := make(chan error, 1)
	go func() { done <- initiator.deleteAuthenticatedIKE() }()
	own := peer.read(t)

	header := Header{SPIInitiator: peer.held.spiI, SPIResponder: peer.held.spiR, ExchangeType: INFORMATIONAL}
	forged, err := EncryptMessage(peer.held.suite, peer.held.sker, header, nil, deleteIKEPayloads())
	if err != nil {
		t.Fatal(err)
	}
	forged[len(forged)-1] ^= 1
	peer.write(t, forged)
	peer.unanswered(t)
	waitsOn(t, done)
	peer.send(t, Header{ExchangeType: INFORMATIONAL, MessageID: 0}, nil)
	if answer := peer.answer(t); answer.Header.MessageID != 0 || len(answer.inner) != 0 {
		t.Fatalf("the liveness check after the forgery drew Message ID %d carrying %v, want an empty answer at 0", answer.Header.MessageID, answer.inner)
	}
	peer.send(t, Header{ExchangeType: INFORMATIONAL, Flags: FlagResponse, MessageID: own.Header.MessageID}, nil)
	settled(t, done, nil)
}

// an authenticated Delete of the IKE SA outside the window, at a Message ID answered before the last or at one ahead of the next, is neither answered nor acted on, and the answer kept for a retransmission stays the last one sent
func TestInitiatorClosingAfterAuthIgnoresADeleteOutsideTheWindow(t *testing.T) {
	bubble.Run(testInitiatorClosingAfterAuthIgnoresADeleteOutsideTheWindow)(t)
}

func testInitiatorClosingAfterAuthIgnoresADeleteOutsideTheWindow(t *testing.T) {
	peer, initiator := closingAfterAuth(t)
	done := make(chan error, 1)
	go func() { done <- initiator.deleteAuthenticatedIKE() }()
	own := peer.read(t)

	var request []byte
	var kept closingMessage
	for mid := range uint32(2) {
		request = peer.send(t, Header{ExchangeType: INFORMATIONAL, MessageID: mid}, nil)
		if kept = peer.answer(t); kept.Header.MessageID != mid {
			t.Fatalf("the liveness check at Message ID %d drew an answer at %d", mid, kept.Header.MessageID)
		}
	}
	for _, mid := range []uint32{0, 5} {
		peer.send(t, Header{ExchangeType: INFORMATIONAL, MessageID: mid}, deleteIKEPayloads())
		peer.unanswered(t)
		waitsOn(t, done)
	}
	peer.write(t, request)
	if again := peer.answer(t); !bytes.Equal(again.raw, kept.raw) {
		t.Fatalf("the retransmitted liveness check at Message ID 1 drew %x, want its answer %x again", again.raw, kept.raw)
	}
	peer.send(t, Header{ExchangeType: INFORMATIONAL, Flags: FlagResponse, MessageID: own.Header.MessageID}, nil)
	settled(t, done, nil)
}

// unsupportedCritical is a payload of a type no IKEv2 document assigns, its critical flag set
var unsupportedCritical = RawPayload{Type: PayloadType(250), Critical: true, Body: []byte{1}}

// unrecognizedError and unrecognizedStatus are notifies of types no IKEv2 document assigns, the one an error type and the other a status type
var (
	unrecognizedError  = RawPayload{Type: PayloadN, Body: EncodeNotify(Notify{Type: 8191})}
	unrecognizedStatus = RawPayload{Type: PayloadN, Body: EncodeNotify(Notify{Type: 40000})}
)

// a request that authenticates and does not decode is answered INVALID_SYNTAX at its Message ID, which ends the IKE SA at both ends, so the initiator stops waiting for its own answer
func TestInitiatorClosingAfterAuthEndsAtARequestThatDoesNotDecode(t *testing.T) {
	bubble.Run(testInitiatorClosingAfterAuthEndsAtARequestThatDoesNotDecode)(t)
}

func testInitiatorClosingAfterAuthEndsAtARequestThatDoesNotDecode(t *testing.T) {
	peer, initiator := closingAfterAuth(t)
	done := make(chan error, 1)
	go func() { done <- initiator.deleteAuthenticatedIKE() }()
	peer.read(t)

	// a Notify whose stated length is shorter than its own header, then no padding
	header := Header{SPIInitiator: peer.held.spiI, SPIResponder: peer.held.spiR, ExchangeType: INFORMATIONAL}
	malformed, err := encryptMessagePlaintextIV(peer.held.suite, peer.held.sker, header, nil, PayloadN, []byte{0, 0, 0, 3, 0}, make([]byte, 8))
	if err != nil {
		t.Fatal(err)
	}
	peer.write(t, malformed)
	if answer := peer.answer(t); answer.Header.ExchangeType != INFORMATIONAL || answer.Header.MessageID != 0 || !notified(answer.inner, N_INVALID_SYNTAX, nil) {
		t.Fatalf("the malformed request drew exchange %d Message ID %d carrying %v, want INVALID_SYNTAX at 0", answer.Header.ExchangeType, answer.Header.MessageID, answer.inner)
	}
	settled(t, done, nil)
}

// an exchange the wait does not take draws the answer Run gives it, INVALID_SYNTAX, which ends the IKE SA
func TestInitiatorClosingAfterAuthAnswersAnExchangeItDoesNotTakeAsRunDoes(t *testing.T) {
	bubble.Run(testInitiatorClosingAfterAuthAnswersAnExchangeItDoesNotTakeAsRunDoes)(t)
}

func testInitiatorClosingAfterAuthAnswersAnExchangeItDoesNotTakeAsRunDoes(t *testing.T) {
	peer, initiator := closingAfterAuth(t)
	done := make(chan error, 1)
	go func() { done <- initiator.deleteAuthenticatedIKE() }()
	peer.read(t)

	header := Header{ExchangeType: IKE_AUTH, MessageID: 0}
	peer.send(t, header, nil)
	answer := peer.answer(t)
	if answer.Header.ExchangeType != IKE_AUTH || answer.Header.MessageID != 0 || !notified(answer.inner, N_INVALID_SYNTAX, nil) {
		t.Fatalf("the IKE_AUTH request drew exchange %d Message ID %d carrying %v, want INVALID_SYNTAX at 0", answer.Header.ExchangeType, answer.Header.MessageID, answer.inner)
	}
	if run := runAnswer(t, header, nil, nil); !samePayloads(run, answer.inner) {
		t.Errorf("Run answers the IKE_AUTH request with %v, the wait with %v", run, answer.inner)
	}
	settled(t, done, nil)
}

// RFC 7296 section 2.21.3: "After the IKE SA is authenticated, all requests having errors MUST result in a response notifying the other end of the error."
// a Delete payload that does not decode draws the answer Run gives it, INVALID_SYNTAX, which ends the IKE SA, so the initiator stops waiting for its own answer
func TestInitiatorClosingAfterAuthEndsAtADeleteThatDoesNotDecodeAsRunDoes(t *testing.T) {
	bubble.Run(testInitiatorClosingAfterAuthEndsAtADeleteThatDoesNotDecodeAsRunDoes)(t)
}

func testInitiatorClosingAfterAuthEndsAtADeleteThatDoesNotDecodeAsRunDoes(t *testing.T) {
	peer, initiator := closingAfterAuth(t)
	done := make(chan error, 1)
	go func() { done <- initiator.deleteAuthenticatedIKE() }()
	peer.read(t)

	header := Header{ExchangeType: INFORMATIONAL, MessageID: 0}
	inner := []RawPayload{{Type: PayloadD, Body: []byte{byte(ProtoESP)}}}
	peer.send(t, header, inner)
	answer := peer.answer(t)
	if answer.Header.ExchangeType != INFORMATIONAL || answer.Header.MessageID != 0 || !notified(answer.inner, N_INVALID_SYNTAX, nil) {
		t.Fatalf("the Delete that does not decode drew exchange %d Message ID %d carrying %v, want INVALID_SYNTAX at 0", answer.Header.ExchangeType, answer.Header.MessageID, answer.inner)
	}
	if run := runAnswer(t, header, nil, inner); !samePayloads(run, answer.inner) {
		t.Errorf("Run answers the Delete with %v, the wait with %v", run, answer.inner)
	}
	settled(t, done, nil)
}

// a request carrying a critical payload this end does not support, inside SK or in the clear ahead of it, is rejected as Run rejects it, with UNSUPPORTED_CRITICAL_PAYLOAD naming the type, and is not acted on, so the Delete inside it leaves the initiator waiting
// the rejection is the answer kept for its Message ID, and the next request is answered at the next
func TestInitiatorClosingAfterAuthRejectsAnUnsupportedCriticalPayloadAsRunDoes(t *testing.T) {
	deletion := RawPayload{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoIKE})}
	for placement, request := range map[string]struct{ cleartext, inner []RawPayload }{
		"inside SK":    {nil, []RawPayload{deletion, unsupportedCritical}},
		"in the clear": {[]RawPayload{unsupportedCritical}, []RawPayload{deletion}},
	} {
		t.Run(placement, bubble.Run(func(t *testing.T) {
			peer, initiator := closingAfterAuth(t)
			done := make(chan error, 1)
			go func() { done <- initiator.deleteAuthenticatedIKE() }()
			own := peer.read(t)

			header := Header{SPIInitiator: peer.held.spiI, SPIResponder: peer.held.spiR, ExchangeType: INFORMATIONAL, MessageID: 0}
			raw, err := EncryptMessage(peer.held.suite, peer.held.sker, header, request.cleartext, request.inner)
			if err != nil {
				t.Fatal(err)
			}
			peer.write(t, raw)
			answer := peer.answer(t)
			if answer.Header.MessageID != 0 || !notified(answer.inner, N_UNSUPPORTED_CRITICAL_PAYLOAD, []byte{byte(unsupportedCritical.Type)}) {
				t.Fatalf("the request drew Message ID %d carrying %v, want UNSUPPORTED_CRITICAL_PAYLOAD for type %d at 0", answer.Header.MessageID, answer.inner, unsupportedCritical.Type)
			}
			if run := runAnswer(t, header, request.cleartext, request.inner); !samePayloads(run, answer.inner) {
				t.Errorf("Run answers the request with %v, the wait with %v", run, answer.inner)
			}
			peer.write(t, raw)
			if again := peer.answer(t); !bytes.Equal(again.raw, answer.raw) {
				t.Errorf("the retransmitted request drew %x, want the rejection %x again", again.raw, answer.raw)
			}
			peer.send(t, Header{ExchangeType: INFORMATIONAL, MessageID: 1}, nil)
			if next := peer.answer(t); next.Header.MessageID != 1 || len(next.inner) != 0 {
				t.Fatalf("the next liveness check drew Message ID %d carrying %v, want an empty answer at 1", next.Header.MessageID, next.inner)
			}
			waitsOn(t, done)
			peer.send(t, Header{ExchangeType: INFORMATIONAL, Flags: FlagResponse, MessageID: own.Header.MessageID}, nil)
			settled(t, done, nil)
		}))
	}
}

// RFC 7296 section 3.2 on the critical bit: "MUST be ignored by the recipient if the recipient understands the payload type code."
// section 2.5: "If the critical flag is not set and the payload type is unsupported, that payload MUST be ignored."
// a request marking every payload critical, its SK payload and a Vendor ID among them, and adding one of a type nothing assigns unmarked, is answered as Run answers it, and the answer to the initiator's own Delete, marked so and adding the same, settles the wait
func TestInitiatorClosingAfterAuthIgnoresTheCriticalBitOnPayloadsItUnderstands(t *testing.T) {
	bubble.Run(testInitiatorClosingAfterAuthIgnoresTheCriticalBitOnPayloadsItUnderstands)(t)
}

func testInitiatorClosingAfterAuthIgnoresTheCriticalBitOnPayloadsItUnderstands(t *testing.T) {
	peer, initiator := closingAfterAuth(t)
	done := make(chan error, 1)
	go func() { done <- initiator.deleteAuthenticatedIKE() }()
	own := peer.read(t)

	header := Header{SPIInitiator: peer.held.spiI, SPIResponder: peer.held.spiR, ExchangeType: INFORMATIONAL, MessageID: 0}
	inner := []RawPayload{
		{Type: PayloadD, Critical: true, Body: EncodeDelete(Delete{Protocol: ProtoESP, SPIs: [][]byte{{0, 0, 0, 9}}})},
		{Type: PayloadV, Critical: true, Body: []byte("a vendor this end does not know")},
		{Type: PayloadType(250), Body: []byte{1}},
	}
	peer.write(t, sealedEdited(t, peer.held.suite, peer.held.sker, header, inner, criticalSK))
	answer := peer.answer(t)
	if answer.Header.MessageID != 0 || len(answer.inner) != 0 {
		t.Fatalf("the request drew Message ID %d carrying %v, want an empty answer at 0", answer.Header.MessageID, answer.inner)
	}
	if run := runAnswer(t, header, nil, inner); !samePayloads(run, answer.inner) {
		t.Errorf("Run answers the request with %v, the wait with %v", run, answer.inner)
	}
	waitsOn(t, done)
	answered := Header{SPIInitiator: peer.held.spiI, SPIResponder: peer.held.spiR, ExchangeType: INFORMATIONAL, Flags: FlagResponse, MessageID: own.Header.MessageID}
	peer.write(t, sealedEdited(t, peer.held.suite, peer.held.sker, answered, []RawPayload{{Type: PayloadType(250), Body: []byte{1}}}, criticalSK))
	settled(t, done, nil)
}

// RFC 7296 section 2.5: "If the critical flag is set and the payload type is unrecognized, the message MUST be rejected"
// an answer to the initiator's own Delete that carries a critical payload of a type nothing assigns ends the Delete with that refusal
func TestInitiatorClosingAfterAuthRefusesAnAnswerMarkingAnUnsupportedPayloadCritical(t *testing.T) {
	bubble.Run(testInitiatorClosingAfterAuthRefusesAnAnswerMarkingAnUnsupportedPayloadCritical)(t)
}

func testInitiatorClosingAfterAuthRefusesAnAnswerMarkingAnUnsupportedPayloadCritical(t *testing.T) {
	peer, initiator := closingAfterAuth(t)
	done := make(chan error, 1)
	go func() { done <- initiator.deleteAuthenticatedIKE() }()
	own := peer.read(t)
	peer.send(t, Header{ExchangeType: INFORMATIONAL, Flags: FlagResponse, MessageID: own.Header.MessageID}, []RawPayload{unsupportedCritical})
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "marks unsupported payload type 250 critical") {
			t.Errorf("the initiator's Delete ended with %v, want the answer refused for payload type 250", err)
		}
	case <-time.After(answerBudget):
		t.Fatal("the initiator went on waiting for its own answer")
	}
}

// RFC 7296 section 3.10.1: "Unrecognized error types in a request and status types in a request or response MUST be ignored, and they should be logged."
// a request carrying an error notify and a status notify of types nothing assigns is answered empty as Run answers it, and the answer to the initiator's own Delete carrying the status notify settles the wait
func TestInitiatorClosingAfterAuthIgnoresNotifiesItDoesNotRecognize(t *testing.T) {
	bubble.Run(testInitiatorClosingAfterAuthIgnoresNotifiesItDoesNotRecognize)(t)
}

func testInitiatorClosingAfterAuthIgnoresNotifiesItDoesNotRecognize(t *testing.T) {
	peer, initiator := closingAfterAuth(t)
	done := make(chan error, 1)
	go func() { done <- initiator.deleteAuthenticatedIKE() }()
	own := peer.read(t)

	header := Header{ExchangeType: INFORMATIONAL, MessageID: 0}
	inner := []RawPayload{unrecognizedError, unrecognizedStatus}
	peer.send(t, header, inner)
	answer := peer.answer(t)
	if answer.Header.MessageID != 0 || len(answer.inner) != 0 {
		t.Fatalf("the request drew Message ID %d carrying %v, want an empty answer at 0", answer.Header.MessageID, answer.inner)
	}
	if run := runAnswer(t, header, nil, inner); !samePayloads(run, answer.inner) {
		t.Errorf("Run answers the request with %v, the wait with %v", run, answer.inner)
	}
	waitsOn(t, done)
	peer.send(t, Header{ExchangeType: INFORMATIONAL, Flags: FlagResponse, MessageID: own.Header.MessageID}, []RawPayload{unrecognizedStatus})
	settled(t, done, nil)
}

// RFC 7296 section 3.10.1: "An implementation receiving a Notify payload with one of these types that it does not recognize in a response MUST assume that the corresponding request has failed entirely."
// an answer to the initiator's own Delete that carries an error notify of a type nothing assigns ends the Delete with a rejection naming it, and one carrying a notify that does not decode, which may be one, ends it refused
func TestInitiatorClosingAfterAuthTakesAnErrorNotifyInItsAnswerAsTheDeleteFailing(t *testing.T) {
	for name, test := range map[string]struct {
		notify RawPayload
		want   func(error) bool
	}{
		"an error notify": {unrecognizedError, func(err error) bool {
			rejected, ok := errors.AsType[*rejectedError](err)
			return ok && rejected.notify.Type == 8191
		}},
		"a notify that does not decode": {RawPayload{Type: PayloadN, Body: []byte{0}}, func(err error) bool {
			return err != nil && strings.Contains(err.Error(), "short notify payload")
		}},
	} {
		t.Run(name, bubble.Run(func(t *testing.T) {
			peer, initiator := closingAfterAuth(t)
			done := make(chan error, 1)
			go func() { done <- initiator.deleteAuthenticatedIKE() }()
			own := peer.read(t)
			peer.send(t, Header{ExchangeType: INFORMATIONAL, Flags: FlagResponse, MessageID: own.Header.MessageID}, []RawPayload{test.notify})
			select {
			case err := <-done:
				if !test.want(err) {
					t.Errorf("the initiator's Delete ended with %v, want it failed on %s", err, name)
				}
			case <-time.After(answerBudget):
				t.Fatal("the initiator went on waiting for its own answer")
			}
		}))
	}
}

// RFC 7296 section 2.5, which every answer is held to: "Payloads sent in IKE response messages MUST NOT have the critical flag set."
func notified(inner []RawPayload, notifyType NotifyType, data []byte) bool {
	if len(inner) != 1 || inner[0].Type != PayloadN || inner[0].Critical {
		return false
	}
	notify, err := DecodeNotify(inner[0].Body)
	return err == nil && notify.Type == notifyType && bytes.Equal(notify.Data, data)
}

// runAnswer is Run's answer to the request on the IKE SA closingAfterAuth holds, decrypted
func runAnswer(t *testing.T, header Header, cleartext, inner []RawPayload) []RawPayload {
	t.Helper()
	_, s := closingAfterAuth(t)
	header.SPIInitiator, header.SPIResponder = s.current.spiI, s.current.spiR
	response, _ := s.handleRequest(s.current, &header, cleartext, inner)
	if response == nil {
		t.Fatal("Run answers nothing")
	}
	message, err := DecodeMessage(response.whole)
	if err != nil {
		t.Fatalf("Run's answer does not decode: %v", err)
	}
	answer, err := DecryptMessage(s.current.suite, s.current.skei, response.whole, message)
	if err != nil {
		t.Fatal(err)
	}
	return answer
}

func waitsOn(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		t.Fatalf("the initiator stopped waiting for its own answer: %v", err)
	case <-time.After(quietPeriod):
	}
}

// settled has the initiator stop waiting and report want, its IKE SA gone
func settled(t *testing.T, done <-chan error, want error) {
	t.Helper()
	select {
	case err := <-done:
		if !errors.Is(err, want) {
			t.Errorf("the initiator's Delete ended with %v, want %v", err, want)
		}
	case <-time.After(answerBudget):
		t.Fatal("the initiator went on waiting for its own answer")
	}
}
