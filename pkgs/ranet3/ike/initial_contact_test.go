// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ike

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/internal/bubble"
)

// contactDecision is an InitialContact decision that answers send and keeps whom it was asked about
type contactDecision struct {
	send  bool
	mu    sync.Mutex
	asked []identity.Identity
	on    []*Session
}

func (d *contactDecision) decide(sess *Session, peer identity.Identity) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.asked, d.on = append(d.asked, peer), append(d.on, sess)
	return d.send
}

func (d *contactDecision) askedOnce(t *testing.T, side string, peer identity.Identity, sess *Session) {
	t.Helper()
	d.mu.Lock()
	defer d.mu.Unlock()
	if !slices.Equal(d.asked, []identity.Identity{peer}) || len(d.on) != 1 || d.on[0] != sess {
		t.Errorf("the %s was asked about %v, want once about %s on the session it handed out", side, d.asked, peer)
	}
}

// each end asks its decision once per handshake, about the peer's endpoint, and the other end reads the notice its first IKE_AUTH carried
// so the notice is in the request when this end dials and in the response when the peer dialed
func TestInitialContactRidesTheFirstIKEAuthOfEitherEnd(t *testing.T) {
	for _, dialer := range []bool{false, true} {
		for _, answerer := range []bool{false, true} {
			t.Run(fmt.Sprintf("dialer %t answerer %t", dialer, answerer), bubble.Run(func(t *testing.T) {
				dialing, answering := &contactDecision{send: dialer}, &contactDecision{send: answerer}
				h := newConfiguredResponderHarness(t, map[identity.Identity]Family{identity.MustParse("testorg/server:1"): IPv4}, nil,
					func(cfg *ResponderConfig) { cfg.InitialContact = answering.decide })
				cfg := h.peerConfig()
				cfg.InitialContact = dialing.decide
				ctx, cancel := context.WithTimeout(context.Background(), answerBudget)
				defer cancel()
				initiator, err := InitiateContext(ctx, cfg)
				if err != nil {
					t.Fatal(err)
				}
				defer initiator.Mux().Close()
				responder := <-h.sessions
				defer responder.Mux().Close()
				<-h.identities
				dialing.askedOnce(t, "dialer", cfg.Remote, initiator)
				answering.askedOnce(t, "answerer", cfg.Local, responder)
				if got := responder.InitialContact(); got != dialer {
					t.Errorf("the answering end read INITIAL_CONTACT %t from a request the dialer decided %t", got, dialer)
				}
				if got := initiator.InitialContact(); got != answerer {
					t.Errorf("the dialing end read INITIAL_CONTACT %t from a response the answerer decided %t", got, answerer)
				}
			}))
		}
	}
}

// a session a newer IKE SA's INITIAL_CONTACT ends records why and closes its mux, which takes its Child SAs, and sends the peer no Delete
func TestInitialContactEndsTheSessionWithoutADelete(t *testing.T) {
	bubble.Run(testInitialContactEndsTheSessionWithoutADelete)(t)
}

func testInitialContactEndsTheSessionWithoutADelete(t *testing.T) {
	answered := &recorder{}
	h := newResponderHarness(t, nil, answered.record)
	ctx, cancel := context.WithTimeout(context.Background(), answerBudget)
	defer cancel()
	initiator, err := InitiateContext(ctx, h.peerConfig())
	if err != nil {
		t.Fatal(err)
	}
	responder := <-h.sessions
	<-h.identities
	dialedRun, answeredRun := make(chan error, 1), make(chan error, 1)
	go func() { dialedRun <- initiator.Run(ctx) }()
	go func() { answeredRun <- responder.Run(ctx) }()

	responder.EndAtInitialContact()
	// a second ask while the first is pending does not block, and the session records its end once
	responder.EndAtInitialContact()
	select {
	case err := <-answeredRun:
		if !errors.Is(err, errInitialContact) {
			t.Errorf("the ended session's Run returned %v, want %v", err, errInitialContact)
		}
	case <-time.After(answerBudget):
		t.Fatal("the session the notice ended kept running")
	}
	if !responder.Mux().IsClosed() {
		t.Error("the ended session's mux is open, so its Child SAs still carry ESP")
	}
	if got := endsAtInitialContact(answered); got != 1 {
		t.Errorf("the ended session recorded %d ends at INITIAL_CONTACT among %q, want 1", got, answered.recorded())
	}
	select {
	case err := <-dialedRun:
		t.Fatalf("the peer's session ended with %v, so the end the notice closed sent it something", err)
	case <-time.After(quietPeriod):
	}
}

// endsAtInitialContact counts the ike.sa.closed records of the harness's answered session for INITIAL_CONTACT
func endsAtInitialContact(answered *recorder) int {
	return len(slices.DeleteFunc(answered.recorded(), func(r string) bool {
		return r != "ike.sa.closed testorg/server:1>testorg/client:2 sa=ike reason=initial contact"
	}))
}

// a session that is sending its own Delete when the notice ends it has its end told already, so it records no second one
func TestInitialContactRecordsNothingForASessionAlreadyClosing(t *testing.T) {
	bubble.Run(func(t *testing.T) {
		answered := &recorder{}
		h := newResponderHarness(t, nil, answered.record)
		ctx, cancel := context.WithTimeout(context.Background(), answerBudget)
		defer cancel()
		// the dialing end runs nothing, so the Delete stays unanswered and the session closing
		initiator, err := InitiateContext(ctx, h.peerConfig())
		if err != nil {
			t.Fatal(err)
		}
		defer initiator.Mux().Close()
		responder := <-h.sessions
		<-h.identities
		ran := make(chan error, 1)
		go func() { ran <- responder.Run(ctx) }()
		go func() { _ = responder.DeleteIKE() }()
		synctest.Wait()
		if !responder.closing.Load() {
			t.Fatal("the session is not closing, so this proves nothing")
		}
		responder.EndAtInitialContact()
		select {
		case <-ran:
		case <-time.After(answerBudget):
			t.Fatal("the session the notice ended kept running")
		}
		if got := endsAtInitialContact(answered); got != 0 {
			t.Errorf("the closing session recorded %d ends at INITIAL_CONTACT among %q, want none", got, answered.recorded())
		}
	})(t)
}

// RFC 7296 section 2.4: "receiving parties MAY ignore it in other messages"
// so a notice in the IKE_SA_INIT response is not read
func TestInitialContactInTheIKESAInitResponseIsNotRead(t *testing.T) {
	bubble.Run(func(t *testing.T) {
		s, peer, _, _ := spiSession(t)
		p := newAuthPeer(t)
		response := (&Message{Header: Header{SPIInitiator: s.current.spiI, SPIResponder: s.current.spiR, ExchangeType: IKE_SA_INIT, Flags: FlagResponse},
			Payloads: []RawPayload{{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_INITIAL_CONTACT})}}}).Encode()
		ended := startIKEAuthAfter(s, p, response)
		_, header, _ := readOwnRequest(t, s, peer)
		answerOwnRequest(t, s, peer, header, append(p.authenticatedOver(s, response), childAnswer()[0], childAnswer()[2], childAnswer()[3]))
		if err := <-ended; err != nil {
			t.Fatalf("the IKE_AUTH ended with %v", err)
		}
		if s.InitialContact() {
			t.Error("the dialing end read INITIAL_CONTACT from the IKE_SA_INIT response")
		}
	})(t)
}
