// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ike

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/bubble"
	"ranet3.com/pkgs/ranet3/transport"
)

// RFC 7296 section 3.10.1: "An implementation receiving a Notify payload with one of these types that it does not recognize in a response MUST assume that the corresponding request has failed entirely."
// the answers here carry unrecognizedError, so every request they answer failed, and each test holds what that failure leaves
var refusingAnswer = requestResult{inner: []RawPayload{unrecognizedError}}

// toldRefusal reports whether one line at level with message was logged, its err the refusal unrecognizedError makes
func toldRefusal(lines *lineRecorder, level slog.Level, message string) bool {
	told := lines.said(level, message, "err")
	if len(told) != 1 {
		return false
	}
	err, _ := told[0].Any().(error)
	rejected, ok := errors.AsType[*rejectedError](err)
	return ok && rejected.notify.Type == 8191
}

func awaitLine(t *testing.T, lines *lineRecorder, level slog.Level, message string) {
	t.Helper()
	for deadline := time.Now().Add(answerBudget); len(lines.said(level, message, "err")) == 0; time.Sleep(recordPoll) {
		if time.Now().After(deadline) {
			t.Fatalf("no line said %q", message)
		}
	}
}

// readOwnRequest reads the next request s sends peer on the IKE SA it holds
func readOwnRequest(t *testing.T, s *Session, peer *transport.MemoryConn) ([]byte, Header, []RawPayload) {
	t.Helper()
	buf := make([]byte, 2048)
	if err := peer.SetReadDeadline(time.Now().Add(answerBudget)); err != nil {
		t.Fatal(err)
	}
	n, _, err := peer.ReadFromUDP(buf)
	if err != nil || n <= NonESPMarkerLen {
		t.Fatalf("the session sent nothing: %d bytes, %v", n, err)
	}
	raw := buf[NonESPMarkerLen:n]
	message, err := DecodeMessage(raw)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := DecryptMessage(s.current.suite, s.current.skei, raw, message)
	if err != nil || message.Header.IsResponse() {
		t.Fatalf("the session sent response %v carrying %v (%v), want a request", message.Header.IsResponse(), inner, err)
	}
	return raw, message.Header, inner
}

// answerOwnRequest has peer answer the request s sent at msgID with inner
func answerOwnRequest(t *testing.T, s *Session, peer *transport.MemoryConn, request Header, inner []RawPayload) {
	t.Helper()
	held := s.current
	answer, err := EncryptMessage(held.suite, held.sker, Header{SPIInitiator: held.spiI, SPIResponder: held.spiR,
		ExchangeType: request.ExchangeType, Flags: FlagResponse, MessageID: request.MessageID}, nil, inner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := peer.WriteToUDP(withNonESPMarker(answer), muxLoopback(s.mux)); err != nil {
		t.Fatal(err)
	}
}

// section 2.4: "Receipt of a fresh cryptographically protected message on an IKE SA or any of its Child SAs ensures liveness of the IKE SA and all of its Child SAs."
// the refused check proves the peer there all the same, and asked for nothing, so its failure changes nothing, and the session tells of it and goes on, its next check at the next Message ID
func TestSessionTellsOfARefusedLivenessCheckAndGoesOn(t *testing.T) {
	bubble.Run(testSessionTellsOfARefusedLivenessCheckAndGoesOn)(t)
}

func testSessionTellsOfARefusedLivenessCheckAndGoesOn(t *testing.T) {
	lines := recordLines(t)
	s, peer, _ := probedSession(t)
	s.started = time.Now().Add(-time.Hour)
	if err := s.mux.RegisterIKE(s.current.spiI); err != nil {
		t.Fatal(err)
	}
	done := runSession(t, s)
	s.Probe()
	check, err := decodeHeader(readRequest(t, s, peer))
	if err != nil {
		t.Fatal(err)
	}
	// the peer last proved itself there as the session started, an hour ago, so only the answer taken as proof brings it back from idle
	s.lastActive.Store(1)
	answerOwnRequest(t, s, peer, *check, refusingAnswer.inner)
	awaitLine(t, lines, slog.LevelWarn, "ike the peer refused a liveness check")
	if !toldRefusal(lines, slog.LevelWarn, "ike the peer refused a liveness check") {
		t.Errorf("the line told %v, want the refusal", lines.said(slog.LevelWarn, "ike the peer refused a liveness check", "err"))
	}
	s.Probe()
	if next, err := decodeHeader(readRequest(t, s, peer)); err != nil || next.MessageID != check.MessageID+1 {
		t.Errorf("the next check went out as %+v (%v), want Message ID %d", next, err, check.MessageID+1)
	}
	if idle := s.Idle(); idle > answerBudget {
		t.Errorf("the peer reads idle for %v after its refusal, want the refusal taken as proof it is there", idle)
	}
	select {
	case err := <-done:
		t.Errorf("the session ended with %v after a refused liveness check", err)
	default:
	}
}

// RFC 7296 section 1.4.1: "Deleting an IKE SA implicitly closes any remaining Child SAs negotiated under it."
// the Delete Run sends as it ends the IKE SA, refused, is told of, and Run ends as it would have
func TestRunTellsOfARefusedDeleteOfTheIKESAAndEnds(t *testing.T) {
	bubble.Run(testRunTellsOfARefusedDeleteOfTheIKESAAndEnds)(t)
}

func testRunTellsOfARefusedDeleteOfTheIKESAAndEnds(t *testing.T) {
	lines := recordLines(t)
	peer, s := closingAfterAuth(t)
	why := errors.New("the IKE SA reached its lifetime")
	done := make(chan error, 1)
	go func() { done <- s.run(context.Background(), why) }()
	own := peer.read(t)
	if own.Header.IsResponse() || !deletesIKE(own.inner) {
		t.Fatalf("the session sent response %v carrying %v, want its Delete of the IKE SA", own.Header.IsResponse(), own.inner)
	}
	peer.send(t, Header{ExchangeType: INFORMATIONAL, Flags: FlagResponse, MessageID: own.Header.MessageID}, refusingAnswer.inner)
	select {
	case err := <-done:
		if err != why {
			t.Errorf("Run ended with %v, want %v", err, why)
		}
	case <-time.After(answerBudget):
		t.Fatal("Run went on after its Delete was answered")
	}
	if !toldRefusal(lines, slog.LevelWarn, "ike the peer refused the Delete that ends the IKE SA") {
		t.Errorf("the lines told %v, want the refusal once", lines.said(slog.LevelWarn, "ike the peer refused the Delete that ends the IKE SA", "err"))
	}
}

// DeleteIKE, refused while Run serves the session, returns the refusal and tells of it
func TestDeleteIKEReturnsTheRefusalAndTellsOfIt(t *testing.T) {
	bubble.Run(testDeleteIKEReturnsTheRefusalAndTellsOfIt)(t)
}

func testDeleteIKEReturnsTheRefusalAndTellsOfIt(t *testing.T) {
	lines := recordLines(t)
	s, peer, _ := probedSession(t)
	// Run puts a request it wakes for back on the queue, which holds one for it
	s.requests = make(chan *localRequest, 1)
	if err := s.mux.RegisterIKE(s.current.spiI); err != nil {
		t.Fatal(err)
	}
	runSession(t, s)
	for deadline := time.Now().Add(answerBudget); !s.serving.Load(); time.Sleep(recordPoll) {
		if time.Now().After(deadline) {
			t.Fatal("Run never served the session")
		}
	}
	deleted := make(chan error, 1)
	go func() { deleted <- s.DeleteIKE() }()
	_, request, inner := readOwnRequest(t, s, peer)
	if request.ExchangeType != INFORMATIONAL || !deletesIKE(inner) {
		t.Fatalf("the session sent exchange %d carrying %v, want its Delete of the IKE SA", request.ExchangeType, inner)
	}
	answerOwnRequest(t, s, peer, request, refusingAnswer.inner)
	select {
	case err := <-deleted:
		if rejected, ok := errors.AsType[*rejectedError](err); !ok || rejected.notify.Type != 8191 {
			t.Errorf("DeleteIKE returned %v, want the refusal", err)
		}
	case <-time.After(answerBudget):
		t.Fatal("DeleteIKE went on waiting after its Delete was answered")
	}
	if !toldRefusal(lines, slog.LevelWarn, "ike the peer refused the Delete that ends the IKE SA") {
		t.Errorf("the lines told %v, want the refusal once", lines.said(slog.LevelWarn, "ike the peer refused the Delete that ends the IKE SA", "err"))
	}
}

// section 2.8: "After the new equivalent IKE SA is created, the initiator deletes the old IKE SA, and the Delete payload to delete itself MUST be the last request sent over the old IKE SA."
// section 2.8.2: "The new IKE SA containing the lowest nonce SHOULD be deleted by the node that created it, and the other surviving new IKE SA MUST inherit all the Child SAs."
// a rekey has taken effect by the time it deletes the SA it replaced, or the one a collision left redundant, so a refusal of that Delete is told of and the rekey stands
func TestRekeyIKETellsOfARefusedDeleteOfAnIKESAItLeaves(t *testing.T) {
	for name, collide := range map[string]bool{"the SA it replaced": false, "the SA a collision left redundant": true} {
		t.Run(name, bubble.Run(func(t *testing.T) {
			lines := recordLines(t)
			mux, _ := lifecycleMuxes(t)
			suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
			old := &ikeContext{suite: suite, spiI: 11, spiR: 12, skD: make([]byte, 32), skei: make([]byte, 20), sker: make([]byte, 20)}
			ones := func(n []byte) error { copy(n, bytes.Repeat([]byte{1}, len(n))); return nil }
			s := &Session{mux: mux, current: old, requests: make(chan *localRequest, 1), suites: func() Suites { return classicalLists }, ikeRekeyNonce: ones}
			done := make(chan error, 1)
			go func() { done <- s.RekeyIKE() }()
			request := <-s.requests
			// a peer rekey crossing this end's, its nonces above this end's ones, which the lowest nonce rule then deletes
			winner := &ikeContext{suite: suite, spiI: 31, spiR: 32, responder: true}
			if collide {
				if err := mux.RegisterIKE(winner.spiI); err != nil {
					t.Fatal(err)
				}
				s.stateMu.Lock()
				s.collision = winner
				s.localRekey.peerNonce, s.localRekey.peerResponseNonce = bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{2}, 32)
				s.stateMu.Unlock()
			}
			dh, err := GenerateDH(DH_CURVE25519)
			if err != nil {
				t.Fatal(err)
			}
			request.result <- requestResult{inner: []RawPayload{
				{Type: PayloadSA, Body: EncodeSA([]Proposal{{Number: 1, Protocol: ProtoIKE, SPI: binary.BigEndian.AppendUint64(nil, 22), Transforms: []Transform{
					{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128}, {Type: TransPRF, ID: PRF_HMAC_SHA2_256}, {Type: TransDH, ID: DH_CURVE25519}}}})},
				{Type: PayloadNonce, Body: bytes.Repeat([]byte{1}, 32)},
				{Type: PayloadKE, Body: EncodeKE(DH_CURVE25519, dh.PublicBytes())},
			}}
			deletion := <-s.requests
			if deletion.exchange != INFORMATIONAL || !deletesIKE(deletion.inner) {
				t.Fatalf("the exchange after the rekey is %d carrying %v, want a Delete of an IKE SA", deletion.exchange, deletion.inner)
			}
			deletion.result <- refusingAnswer
			if err := <-done; err != nil {
				t.Errorf("the rekey failed on a refused Delete, after it took effect: %v", err)
			}
			current, _ := s.contexts()
			message := "ike replaced IKE SA was not deleted by this end"
			if collide {
				message = "ike redundant IKE SA was not deleted by this end"
				if current != winner {
					t.Error("the SA the collision kept is not current")
				}
			} else if current == old {
				t.Error("the replacement is not current")
			}
			if !toldRefusal(lines, slog.LevelInfo, message) {
				t.Errorf("the lines told %v, want the refusal once", lines.said(slog.LevelInfo, message, "err"))
			}
		}))
	}
}

// section 1.4.1: "A node MAY refuse to accept incoming data on half-closed connections but MUST NOT unilaterally close them and reuse the SPIs."
// a refused Delete of a Child SA leaves its pair half closed, and this end tells of it, keeps the SPI the Delete named from every later Child SA of the session, and does not ask again
func TestRefusedChildSADeleteLeavesItsPairHalfClosed(t *testing.T) {
	old := ChildSA{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, LocalSPI: 0x10203040, RemoteSPI: 0x50607080}
	for name, test := range map[string]struct {
		// refuse drives s to the Delete, refuses it, and returns the SPI the Delete named and what the path returned
		refuse  func(t *testing.T, s *Session) (uint32, error)
		failure bool
	}{
		"the SA a rekey replaced": {func(t *testing.T, s *Session) (uint32, error) {
			return old.LocalSPI, driveChildRekey(t, s, old, func(remove *localRequest) { remove.result <- refusingAnswer })
		}, false},
		"the SA the peer made for an answer this end refused": {func(t *testing.T, s *Session) (uint32, error) {
			done := make(chan error, 1)
			go func() { done <- s.RekeyChild() }()
			rekey := <-s.requests
			made := offeredChildSPI(t, rekey.inner)
			rekey.result <- requestResult{inner: []RawPayload{
				{Type: PayloadSA, Body: EncodeSA([]Proposal{{Number: 1, Protocol: ProtoESP, SPI: binary.BigEndian.AppendUint32(nil, old.RemoteSPI+1),
					Transforms: []Transform{{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128}, {Type: TransESN, ID: ESN_NO}}}})},
				{Type: PayloadNonce, Body: EncodeNonce(make([]byte, 32))},
				{Type: PayloadTSi, Body: narrowSelectors()},
				{Type: PayloadTSr, Body: narrowSelectors()},
			}}
			remove := <-s.requests
			if spis := deletedESP(t, remove); !slices.Equal(spis, []uint32{made}) {
				t.Fatalf("the Delete names %08x, want %08x, the SPI the rekey drew", spis, made)
			}
			remove.result <- refusingAnswer
			return made, <-done
		}, true},
		"the replaced SA the peer never deleted": {func(t *testing.T, s *Session) (uint32, error) {
			s.childMu.Lock()
			s.Child, s.retiring, s.retiringBy = ChildSA{LocalSPI: 0x22222222, RemoteSPI: 0x44444444}, old, time.Now()
			s.childMu.Unlock()
			child, ok := s.overdueRetiring(time.Now())
			if !ok {
				t.Fatal("the replaced SA was not handed back at its deadline")
			}
			done := make(chan struct{})
			go func() { defer close(done); s.deleteOverdueChild(child) }()
			remove := <-s.requests
			if spis := deletedESP(t, remove); !slices.Equal(spis, []uint32{old.LocalSPI}) {
				t.Fatalf("the Delete names %08x, want the replaced %08x", spis, old.LocalSPI)
			}
			remove.result <- refusingAnswer
			<-done
			return old.LocalSPI, nil
		}, false},
	} {
		t.Run(name, bubble.Run(func(t *testing.T) {
			lines := recordLines(t)
			s := newRekeyableSession(t, old)
			s.current.skei, s.current.sker = make([]byte, 20), make([]byte, 20)
			spi, err := test.refuse(t, s)
			if failed := err != nil; failed != test.failure {
				t.Errorf("the path returned %v, want failed %v", err, test.failure)
			}
			if retiring := s.retiringChild(); retiring.LocalSPI != 0 {
				t.Errorf("Child SA %08x is still awaiting retirement, want its SAs down", retiring.LocalSPI)
			}
			if err := s.canReplaceChild(spi); err == nil {
				t.Errorf("SPI %08x, which the refused Delete named, can be drawn for a later Child SA", spi)
			}
			told := lines.said(slog.LevelWarn, "ike the peer refused to delete a Child SA, whose pair stays half closed", "spi")
			if len(told) != 1 || told[0].Uint64() != uint64(spi) {
				t.Errorf("the lines told of SPIs %v, want %08x once", told, spi)
			}
			select {
			case again := <-s.requests:
				t.Errorf("exchange %d followed the refused Delete, want none", again.exchange)
			case <-time.After(quietPeriod):
			}
		}))
	}
}

// invalidSyntaxAnswer is the answer of a peer that found this end's request badly formatted
var invalidSyntaxAnswer = []RawPayload{{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_INVALID_SYNTAX})}}

// invalidSyntaxLine is the line this end logs as an IKE SA ends at an INVALID_SYNTAX answer
const invalidSyntaxLine = "ike the peer answered INVALID_SYNTAX, which ends the IKE SA without a Delete"

// closedAtInvalidSyntax counts the events that tell of an IKE SA ended at an INVALID_SYNTAX answer
func closedAtInvalidSyntax(events *recorder) int {
	count := 0
	for _, line := range events.recorded() {
		if strings.HasPrefix(line, "ike.sa.closed ") && strings.HasSuffix(line, " sa=ike reason=invalid syntax") {
			count++
		}
	}
	return count
}

// RFC 7296 section 2.21.3: "If a peer parsing a request notices that it is badly formatted (after it has passed the message authentication code checks and window checks) and it returns an INVALID_SYNTAX notification, then this error notification is considered fatal in both peers, meaning that the IKE SA is deleted without needing an explicit Delete payload."
// whichever of its requests the peer answers so, Run ends at once and sends nothing more, the line and the event say why, and a caller waiting on the request is told the same
func TestSessionEndsWithoutADeleteWhenThePeerAnswersInvalidSyntax(t *testing.T) {
	retiring := ChildSA{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, LocalSPI: 0x10203040, RemoteSPI: 0x50607080}
	ending := errors.New("the IKE SA reached its lifetime")
	for name, test := range map[string]struct {
		// prepare runs before Run starts, and start after it, returning where the caller of the request learns its outcome, nil for a request of Run's own
		prepare func(s *Session)
		start   func(t *testing.T, s *Session) <-chan error
		// ending is the reason Run is already ending the IKE SA for, nil for none
		ending   error
		exchange ExchangeType
		// closing is an IKE SA this end was closing already, whose end Run's own event or the caller of DeleteIKE tells
		closing bool
	}{
		"a liveness check": {
			start:    func(t *testing.T, s *Session) <-chan error { s.Probe(); return nil },
			exchange: INFORMATIONAL,
		},
		"a Child SA rekey": {
			prepare: func(s *Session) { s.Child = retiring },
			start: func(t *testing.T, s *Session) <-chan error {
				done := make(chan error, 1)
				go func() { done <- s.RekeyChild() }()
				return done
			},
			exchange: CREATE_CHILD_SA,
		},
		"an IKE SA rekey": {
			start: func(t *testing.T, s *Session) <-chan error {
				done := make(chan error, 1)
				go func() { done <- s.RekeyIKE() }()
				return done
			},
			exchange: CREATE_CHILD_SA,
		},
		"a Delete of a replaced Child SA the peer never deleted": {
			prepare: func(s *Session) {
				s.Child, s.retiring, s.retiringBy = ChildSA{LocalSPI: 0x22222222, RemoteSPI: 0x44444444}, retiring, time.Now()
			},
			start:    func(t *testing.T, s *Session) <-chan error { return nil },
			exchange: INFORMATIONAL,
		},
		"a Delete of the IKE SA": {
			start: func(t *testing.T, s *Session) <-chan error {
				for deadline := time.Now().Add(answerBudget); !s.serving.Load(); time.Sleep(recordPoll) {
					if time.Now().After(deadline) {
						t.Fatal("Run never served the session")
					}
				}
				done := make(chan error, 1)
				go func() { done <- s.DeleteIKE() }()
				return done
			},
			exchange: INFORMATIONAL,
			closing:  true,
		},
		"the Delete Run sends as it ends the IKE SA": {
			start:    func(t *testing.T, s *Session) <-chan error { return nil },
			ending:   ending,
			exchange: INFORMATIONAL,
			closing:  true,
		},
	} {
		t.Run(name, bubble.Run(func(t *testing.T) {
			lines := recordLines(t)
			s, peer, events := probedSession(t)
			// Run puts a request it wakes for back on the queue, which holds one for it
			s.requests = make(chan *localRequest, 1)
			if err := s.mux.RegisterIKE(s.current.spiI); err != nil {
				t.Fatal(err)
			}
			if test.prepare != nil {
				test.prepare(s)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ran := make(chan error, 1)
			go func() { ran <- s.run(ctx, test.ending) }()
			caller := test.start(t, s)
			_, request, _ := readOwnRequest(t, s, peer)
			if request.ExchangeType != test.exchange {
				t.Fatalf("the session sent exchange %d, want %d", request.ExchangeType, test.exchange)
			}
			answerOwnRequest(t, s, peer, request, invalidSyntaxAnswer)
			want := errAnsweredInvalidSyntax
			if test.ending != nil {
				want = test.ending
			}
			select {
			case err := <-ran:
				if !errors.Is(err, want) {
					t.Errorf("Run ended with %v, want %v", err, want)
				}
			case <-time.After(answerBudget):
				t.Fatal("Run went on after the peer answered INVALID_SYNTAX")
			}
			if caller != nil {
				select {
				case err := <-caller:
					if !errors.Is(err, errAnsweredInvalidSyntax) {
						t.Errorf("the request's caller got %v, want %v", err, errAnsweredInvalidSyntax)
					}
				case <-time.After(answerBudget):
					t.Fatal("the request's caller went on waiting")
				}
			}
			if !s.mux.IsClosed() {
				t.Error("the mux is open after the IKE SA ended")
			}
			buf := make([]byte, 2048)
			if err := peer.SetReadDeadline(time.Now().Add(quietPeriod)); err != nil {
				t.Fatal(err)
			}
			if n, _, err := peer.ReadFromUDP(buf); err == nil {
				t.Errorf("the session sent %d bytes after the peer answered INVALID_SYNTAX, want nothing", n)
			}
			if told := lines.said(slog.LevelWarn, invalidSyntaxLine, "exchange"); len(told) != 1 || told[0].Any() != test.exchange {
				t.Errorf("the lines told of exchanges %v, want %d once", told, test.exchange)
			}
			if got, want := closedAtInvalidSyntax(events), map[bool]int{false: 1, true: 0}[test.closing]; got != want {
				t.Errorf("%d events told of the IKE SA ended at INVALID_SYNTAX, want %d: %v", got, want, events.recorded())
			}
		}))
	}
}

// INVALID_SYNTAX in an answer on the current IKE SA ends it wherever it sits among the answer's notifies: after another error type, after an error type nothing assigns, after a status type nothing assigns and after a notify that does not decode
func TestInvalidSyntaxEndsTheIKESAWhereverItSitsInTheAnswer(t *testing.T) {
	for name, ahead := range map[string]RawPayload{
		"after TEMPORARY_FAILURE":             {Type: PayloadN, Body: EncodeNotify(Notify{Type: N_TEMPORARY_FAILURE})},
		"after an error type nothing assigns": {Type: PayloadN, Body: EncodeNotify(Notify{Type: 8191})},
		"after a status type nothing assigns": {Type: PayloadN, Body: EncodeNotify(Notify{Type: 40000})},
		"after a notify that does not decode": {Type: PayloadN, Body: []byte{0, 0, 0}},
	} {
		t.Run(name, bubble.Run(func(t *testing.T) {
			s, _, _ := probedSession(t)
			ctx := s.current
			pending, err := s.startRequest(&localRequest{exchange: INFORMATIONAL, context: ctx, result: make(chan requestResult, 1)})
			if err != nil {
				t.Fatal(err)
			}
			result := pending.result
			answer, err := EncryptMessage(ctx.suite, ctx.sker, Header{SPIInitiator: ctx.spiI, SPIResponder: ctx.spiR,
				ExchangeType: INFORMATIONAL, Flags: FlagResponse, MessageID: pending.msgID}, nil, append([]RawPayload{ahead}, invalidSyntaxAnswer...))
			if err != nil {
				t.Fatal(err)
			}
			if !s.dispatch(answer, nil, &pending) || pending != nil {
				t.Fatal("the answer was not taken")
			}
			if got := <-result; !s.answeredInvalidSyntax || !errors.Is(got.err, errAnsweredInvalidSyntax) {
				t.Errorf("Run ends %v, and the caller got %v carrying %v, want Run ended and the caller told %v", s.answeredInvalidSyntax, got.err, got.inner, errAnsweredInvalidSyntax)
			}
		}))
	}
}

// an IKE SA a rekey retained is one this end is deleting already, so INVALID_SYNTAX on it deletes it alone, the session goes on with the IKE SA that replaced it, and the request's caller reads the answer as any other refusal
func TestInvalidSyntaxOnARetainedIKESAEndsItAlone(t *testing.T) {
	bubble.Run(testInvalidSyntaxOnARetainedIKESAEndsItAlone)(t)
}

func testInvalidSyntaxOnARetainedIKESAEndsItAlone(t *testing.T) {
	lines := recordLines(t)
	s, _, events := probedSession(t)
	current := s.current
	old := testContext()
	old.spiI, old.spiR = 0x2122232425262728, 0x3132333435363738
	s.old = old
	if err := s.mux.RegisterIKE(old.spiI); err != nil {
		t.Fatal(err)
	}
	pending, err := s.startRequest(&localRequest{exchange: INFORMATIONAL, context: old, inner: deleteIKEPayloads(),
		result: make(chan requestResult, 1)})
	if err != nil {
		t.Fatal(err)
	}
	result := pending.result
	answer, err := EncryptMessage(old.suite, old.sker, Header{SPIInitiator: old.spiI, SPIResponder: old.spiR,
		ExchangeType: INFORMATIONAL, Flags: FlagResponse, MessageID: pending.msgID}, nil, invalidSyntaxAnswer)
	if err != nil {
		t.Fatal(err)
	}
	if !s.dispatch(answer, nil, &pending) || pending != nil {
		t.Fatal("the answer was not taken")
	}
	if s.answeredInvalidSyntax {
		t.Error("INVALID_SYNTAX on the retained IKE SA ended the session")
	}
	if now, retained := s.contexts(); now != current || retained != nil {
		t.Errorf("the session holds current %p and retained %p, want the current IKE SA %p alone", now, retained, current)
	}
	got := <-result
	if rejected, ok := errors.AsType[*rejectedError](refusal("INFORMATIONAL", got.inner)); got.err != nil || !ok || rejected.notify.Type != N_INVALID_SYNTAX {
		t.Errorf("the caller got %v carrying %v, want the answer and its refusal", got.err, got.inner)
	}
	if told := lines.said(slog.LevelWarn, invalidSyntaxLine, "spi"); len(told) != 1 || told[0].Uint64() != old.spiI {
		t.Errorf("the lines told of SPIs %v, want %x once", told, old.spiI)
	}
	if closed := closedAtInvalidSyntax(events); closed != 0 {
		t.Errorf("%d events told of the session's IKE SA ended, want none", closed)
	}
}

// section 2.21.3's "the IKE SA is deleted" names the IKE SA the request came on
// a request on a retained IKE SA that this end answers INVALID_SYNTAX, whether its payload chain or a payload in it does not decode, deletes that IKE SA alone, and the session goes on with the IKE SA that replaced it
func TestInvalidSyntaxThisEndSendsOnARetainedIKESAEndsItAlone(t *testing.T) {
	for name, seal := range map[string]func(old *ikeContext, header Header) ([]byte, error){
		// a payload header whose stated length is shorter than the header itself, then padding
		"a payload chain that does not decode": func(old *ikeContext, header Header) ([]byte, error) {
			return encryptMessagePlaintextIV(old.suite, old.sker, header, nil, PayloadN, []byte{0, 0, 0, 3, 0}, make([]byte, 8))
		},
		"a Delete payload that does not decode": func(old *ikeContext, header Header) ([]byte, error) {
			return EncryptMessage(old.suite, old.sker, header, nil, []RawPayload{{Type: PayloadD, Body: []byte{1}}})
		},
	} {
		t.Run(name, bubble.Run(func(t *testing.T) {
			s, peer, events := probedSession(t)
			current := s.current
			old := testContext()
			old.spiI, old.spiR = 0x2122232425262728, 0x3132333435363738
			s.old = old
			if err := s.mux.RegisterIKE(old.spiI); err != nil {
				t.Fatal(err)
			}
			request, err := seal(old, Header{SPIInitiator: old.spiI, SPIResponder: old.spiR, ExchangeType: INFORMATIONAL})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := peer.WriteToUDP(withNonESPMarker(request), muxLoopback(s.mux)); err != nil {
				t.Fatal(err)
			}
			raw, source, err := s.mux.RecvIKEFromUntil(time.Now().Add(answerBudget))
			if err != nil {
				t.Fatal(err)
			}
			var pending *pendingRequest
			if !s.dispatch(raw, source, &pending) {
				t.Fatal("the request was not taken")
			}
			if s.mux.IsClosed() || s.answeredInvalidSyntax {
				t.Error("INVALID_SYNTAX sent on the retained IKE SA ended the session")
			}
			if now, retained := s.contexts(); now != current || retained != nil {
				t.Errorf("the session holds current %p and retained %p, want the current IKE SA %p alone", now, retained, current)
			}
			if closed := closedAtInvalidSyntax(events); closed != 0 {
				t.Errorf("%d events told of the session's IKE SA ended, want none", closed)
			}
			buf := make([]byte, 2048)
			if err := peer.SetReadDeadline(time.Now().Add(answerBudget)); err != nil {
				t.Fatal(err)
			}
			n, _, err := peer.ReadFromUDP(buf)
			if err != nil || n <= NonESPMarkerLen {
				t.Fatalf("the request drew nothing: %d bytes, %v", n, err)
			}
			answer, err := DecodeMessage(buf[NonESPMarkerLen:n])
			if err != nil {
				t.Fatal(err)
			}
			inner, err := DecryptMessage(old.suite, old.skei, buf[NonESPMarkerLen:n], answer)
			if err != nil || !answer.Header.IsResponse() || answer.Header.SPIInitiator != old.spiI || !notified(inner, N_INVALID_SYNTAX, nil) {
				t.Errorf("the request drew response %v under SPI %x carrying %v (%v), want INVALID_SYNTAX on the retained IKE SA", answer.Header.IsResponse(), answer.Header.SPIInitiator, inner, err)
			}
		}))
	}
}
