// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

package ike

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/transport"
)

func TestChildNegotiationUsesRequestIKEKeys(t *testing.T) {
	mux, _ := lifecycleMuxes(t)
	old := &ikeContext{suite: SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}, skD: bytes.Repeat([]byte{1}, 32)}
	s := &Session{mux: mux, current: old, requests: make(chan *localRequest)}
	done := make(chan error, 1)
	go func() { done <- s.negotiateChild(nil) }()
	req := <-s.requests
	// A peer IKE rekey can finish before the Child response is processed.
	s.stateMu.Lock()
	s.current = &ikeContext{suite: old.suite, skD: bytes.Repeat([]byte{2}, 32)}
	s.stateMu.Unlock()
	nonce := make([]byte, 32)
	req.result <- requestResult{inner: []RawPayload{
		{Type: PayloadSA, Body: EncodeSA([]Proposal{{Number: 1, Protocol: ProtoESP, SPI: []byte{1, 2, 3, 4}, Transforms: []Transform{{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128}, {Type: TransESN, ID: ESN_NO}}}})},
		{Type: PayloadNonce, Body: nonce},
		{Type: PayloadTSi, Body: fullRangeSelectors()},
		{Type: PayloadTSr, Body: fullRangeSelectors()},
	}}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	wantOut, wantIn, err := ChildSAKeymat(old.suite.PRFID, old.skD, findType(req.inner, PayloadNonce).Body, nonce, ENCR_AES_GCM_16, 128)
	if err != nil {
		t.Fatal(err)
	}
	child := s.currentChild()
	if !bytes.Equal(child.OutboundKey, wantOut) || !bytes.Equal(child.InboundKey, wantIn) {
		t.Fatal("Child SA used the replacement IKE SA's keys instead of its request context")
	}
}

func lifecycleMuxes(t *testing.T) (*transport.Mux, *transport.Mux) {
	t.Helper()
	hub, err := transport.NewHub(":0", transport.Underlay{}, transport.Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { hub.Close() })
	first, err := hub.NewMux(net.IPv4(127, 0, 0, 1), 4500)
	if err != nil {
		t.Fatal(err)
	}
	second, err := hub.NewMux(net.IPv4(127, 0, 0, 1), 4501)
	if err != nil {
		t.Fatal(err)
	}
	return first, second
}

func TestReplaceChildRollsBackSPIRegistration(t *testing.T) {
	mux, other := lifecycleMuxes(t)
	s := &Session{mux: mux}
	s.SetChildHandler(func(ChildSA) error { return errors.New("install failed") })
	child := ChildSA{LocalSPI: 0x10203040}
	if err := s.replaceChild(child); err == nil {
		t.Fatal("replaceChild succeeded after handler failure")
	}
	if err := other.RegisterESP(child.LocalSPI); err != nil {
		t.Fatalf("failed installation retained SPI registration: %v", err)
	}
}

func TestReplaceChildDoesNotReuseInstalledSPI(t *testing.T) {
	for _, draining := range []bool{false, true} {
		mux, other := lifecycleMuxes(t)
		s := &Session{mux: mux}
		if err := mux.RegisterESP(42); err != nil {
			t.Fatal(err)
		}
		if draining {
			s.retired = []childRetirement{{spi: 42}}
		} else {
			s.Child.LocalSPI = 42
		}
		if err := s.replaceChild(ChildSA{LocalSPI: 42}); err == nil {
			t.Fatal("reused an SPI whose inbound keys are still installed")
		}
		if err := other.RegisterESP(42); err == nil {
			t.Fatal("failed replacement released the existing SPI registration")
		}
	}
}

func TestRetireChildPreservesRetryableStateOnFailure(t *testing.T) {
	mux, other := lifecycleMuxes(t)
	old := ChildSA{LocalSPI: 0x10203040, RemoteSPI: 0x50607080}
	if err := mux.RegisterESP(old.LocalSPI); err != nil {
		t.Fatal(err)
	}
	s := &Session{mux: mux, retiring: old}
	s.SetChildRetireHandler(func(uint32) error { return errors.New("remove failed") })
	if err := s.retireChild(old.RemoteSPI); err == nil {
		t.Fatal("retireChild succeeded after handler failure")
	}
	if got := s.retiringChild(); got.LocalSPI != old.LocalSPI || got.RemoteSPI != old.RemoteSPI {
		t.Fatalf("retiring Child SA changed after failure: got %+v, want %+v", got, old)
	}
	if err := other.RegisterESP(old.LocalSPI); err == nil {
		t.Fatal("failed retirement released the inbound SPI")
	}

	s.SetChildRetireHandler(func(uint32) error { return nil })
	if err := s.retireChild(old.RemoteSPI); err != nil {
		t.Fatal(err)
	}
	if err := other.RegisterESP(old.LocalSPI); err != nil {
		t.Fatalf("successful retirement retained SPI registration: %v", err)
	}
}

func TestReplaceChildRejectsOverlappingRetirement(t *testing.T) {
	mux, _ := lifecycleMuxes(t)
	s := &Session{mux: mux, retiring: ChildSA{LocalSPI: 1, RemoteSPI: 2}}
	if err := s.replaceChild(ChildSA{LocalSPI: 3, RemoteSPI: 4}); err == nil {
		t.Fatal("replaceChild replaced an SA while an earlier one was still retiring")
	}
}

func TestRekeyRetirementAllowsQueuedESPToDrain(t *testing.T) {
	for _, peerDelete := range []bool{false, true} {
		mux, other := lifecycleMuxes(t)
		old := ChildSA{LocalSPI: 1, RemoteSPI: 2}
		if err := mux.RegisterESP(old.LocalSPI); err != nil {
			t.Fatal(err)
		}
		s := &Session{mux: mux, retiring: old, childRetireDelay: time.Second}
		removed := false
		s.SetChildRetireHandler(func(spi uint32) error {
			if spi != old.LocalSPI {
				t.Fatalf("retired SPI = %d, want %d", spi, old.LocalSPI)
			}
			removed = true
			return nil
		})
		var err error
		if peerDelete {
			_, err = s.deleteChildren([]uint32{old.RemoteSPI})
		} else {
			err = s.retireChild(old.RemoteSPI)
		}
		if err != nil {
			t.Fatal(err)
		}
		if removed || s.retiringChild().LocalSPI != 0 {
			t.Fatal("retirement removed inbound keys immediately or blocked the next rekey")
		}
		if err := other.RegisterESP(old.LocalSPI); err == nil {
			t.Fatal("inbound SPI was released before queued ESP could drain")
		}
		deadline := s.retired[0].expiresAt
		if err := s.expireRetiredChildren(deadline.Add(-time.Nanosecond)); err != nil || removed {
			t.Fatalf("expired inbound SA too early: %v", err)
		}
		if err := s.expireRetiredChildren(deadline); err != nil || !removed {
			t.Fatalf("did not remove expired inbound SA: %v", err)
		}
		if err := other.RegisterESP(old.LocalSPI); err != nil {
			t.Fatalf("expired inbound SPI is still registered: %v", err)
		}
	}
}

func TestProactiveChildRekeyCoalescesWithRunningExchange(t *testing.T) {
	s := new(Session)
	s.childRekeying.Store(true)
	if err := s.RekeyChildProactively(); err != nil {
		t.Fatalf("proactive rekey did not coalesce: %v", err)
	}
	if err := s.RekeyChild(); err == nil {
		t.Fatal("ordinary rekey did not report the running exchange")
	}
}

func TestChildRekeyGuardSerializesAttempts(t *testing.T) {
	s := &Session{}
	if !s.childRekeying.CompareAndSwap(false, true) {
		t.Fatal("failed to reserve Child rekey")
	}
	if s.childRekeying.CompareAndSwap(false, true) {
		t.Fatal("reserved a second simultaneous Child rekey")
	}
}

func TestChildNotFoundRecoveryCreatesNewChild(t *testing.T) {
	mux, _ := lifecycleMuxes(t)
	old := ChildSA{
		EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128,
		LocalSPI: 0x10203040, RemoteSPI: 0x50607080,
	}
	if err := mux.RegisterESP(old.LocalSPI); err != nil {
		t.Fatal(err)
	}
	s := &Session{
		mux: mux,
		current: &ikeContext{
			suite: SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256},
			skD:   []byte("test child replacement SK_d material"),
		},
		Child:    old,
		requests: make(chan *localRequest),
	}
	var retired uint32
	s.SetChildRetireHandler(func(localSPI uint32) error {
		retired = localSPI
		return nil
	})
	var installed ChildSA
	s.SetChildHandler(func(child ChildSA) error {
		installed = child
		return nil
	})

	done := make(chan error, 1)
	go func() { done <- s.RekeyChild() }()
	first := <-s.requests
	rekeyPayload := findType(first.inner, PayloadN)
	if first.exchange != CREATE_CHILD_SA || rekeyPayload == nil {
		t.Fatalf("first request is not a Child SA rekey: %#v", first.inner)
	}
	rekey, err := DecodeNotify(rekeyPayload.Body)
	if err != nil || rekey.Type != N_REKEY_SA || binary.BigEndian.Uint32(rekey.SPI) != old.LocalSPI {
		t.Fatalf("first REKEY_SA = %#v, %v", rekey, err)
	}
	missingSPI := make([]byte, 4)
	binary.BigEndian.PutUint32(missingSPI, old.LocalSPI)
	first.result <- requestResult{inner: []RawPayload{{
		Type: PayloadN,
		Body: EncodeNotify(Notify{Protocol: ProtoESP, SPI: missingSPI, Type: N_CHILD_SA_NOT_FOUND}),
	}}}

	second := <-s.requests
	if second.exchange != CREATE_CHILD_SA || findType(second.inner, PayloadN) != nil {
		t.Fatalf("replacement request still contains REKEY_SA: %#v", second.inner)
	}
	requestPayloads, err := decodeChildExchangePayloads(second.inner, PRF_HMAC_SHA2_256)
	if err != nil {
		t.Fatalf("invalid replacement request: %v", err)
	}
	proposals, err := DecodeSA(requestPayloads.sa.Body)
	if err != nil || len(proposals) != 1 || len(proposals[0].SPI) != 4 {
		t.Fatalf("invalid replacement proposal: %#v, %v", proposals, err)
	}
	newLocalSPI := binary.BigEndian.Uint32(proposals[0].SPI)
	newRemoteSPI := uint32(0x90a0b0c0)
	remoteSPI := make([]byte, 4)
	binary.BigEndian.PutUint32(remoteSPI, newRemoteSPI)
	second.result <- requestResult{inner: []RawPayload{
		{Type: PayloadSA, Body: EncodeSA([]Proposal{{
			Number: 1, Protocol: ProtoESP, SPI: remoteSPI,
			Transforms: []Transform{{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128}, {Type: TransESN, ID: ESN_NO}},
		}})},
		{Type: PayloadNonce, Body: EncodeNonce(make([]byte, 32))},
		{Type: PayloadTSi, Body: fullRangeSelectors()},
		{Type: PayloadTSr, Body: fullRangeSelectors()},
	}}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if retired != old.LocalSPI {
		t.Fatalf("retired SPI = %08x, want %08x", retired, old.LocalSPI)
	}
	if installed.LocalSPI != newLocalSPI || installed.RemoteSPI != newRemoteSPI {
		t.Fatalf("installed Child SA = %#v", installed)
	}
	if got := s.currentChild(); got.LocalSPI != newLocalSPI || got.RemoteSPI != newRemoteSPI {
		t.Fatalf("current Child SA = %#v", got)
	}
}

// requestMu orders callers queueing work for Run, but it does not order Run
// itself, which allocates Message IDs on its own goroutine. A session closed
// the instant it is established runs both at once, as adopt's
// replace path produces on a simultaneous open.
func TestLocalMessageIDIsNotAllocatedTwiceAtOnce(t *testing.T) {
	mux, _ := lifecycleMuxes(t)
	s := &Session{
		mux: mux,
		current: &ikeContext{
			suite:        SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256},
			skei:         make([]byte, 20),
			sker:         make([]byte, 20),
			nextLocalMID: 2,
		},
		requests: make(chan *localRequest),
	}

	payloads := deleteIKEPayloads()
	seen := make(chan uint32, 64)
	var senders sync.WaitGroup
	for range 8 {
		senders.Go(func() { _ = s.sendUnansweredRequest(payloads) })
		senders.Go(func() {
			pending, err := s.startRequest(&localRequest{exchange: INFORMATIONAL, inner: payloads, result: make(chan requestResult, 1)})
			if err == nil {
				seen <- pending.msgID
			}
		})
	}
	senders.Wait()
	close(seen)

	taken := make(map[uint32]bool)
	for msgID := range seen {
		if taken[msgID] {
			t.Fatalf("Message ID %d was handed to two exchanges", msgID)
		}
		taken[msgID] = true
	}
}

// driveChildRekey runs one Child SA rekey to the point where the replacement
// is installed and the INFORMATIONAL Delete for the old SA is outstanding,
// and answers that Delete with respond.
func driveChildRekey(t *testing.T, s *Session, old ChildSA, respond func(*localRequest)) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- s.RekeyChild() }()

	rekey := <-s.requests
	payloads, err := decodeChildExchangePayloads(rekey.inner, PRF_HMAC_SHA2_256)
	if err != nil {
		t.Fatalf("invalid rekey request: %v", err)
	}
	proposals, err := DecodeSA(payloads.sa.Body)
	if err != nil || len(proposals) != 1 || len(proposals[0].SPI) != 4 {
		t.Fatalf("invalid rekey proposal: %#v, %v", proposals, err)
	}
	remoteSPI := make([]byte, 4)
	binary.BigEndian.PutUint32(remoteSPI, old.RemoteSPI+1)
	rekey.result <- requestResult{inner: []RawPayload{
		{Type: PayloadSA, Body: EncodeSA([]Proposal{{
			Number: 1, Protocol: ProtoESP, SPI: remoteSPI,
			Transforms: []Transform{{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128}, {Type: TransESN, ID: ESN_NO}},
		}})},
		{Type: PayloadNonce, Body: EncodeNonce(make([]byte, 32))},
		{Type: PayloadTSi, Body: fullRangeSelectors()},
		{Type: PayloadTSr, Body: fullRangeSelectors()},
	}}

	remove := <-s.requests
	if remove.exchange != INFORMATIONAL {
		t.Fatalf("second exchange = %d, want INFORMATIONAL", remove.exchange)
	}
	respond(remove)
	return <-done
}

func newRekeyableSession(t *testing.T, old ChildSA) *Session {
	t.Helper()
	mux, _ := lifecycleMuxes(t)
	if err := mux.RegisterESP(old.LocalSPI); err != nil {
		t.Fatal(err)
	}
	s := &Session{
		mux: mux,
		current: &ikeContext{
			suite: SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256},
			skD:   []byte("test child replacement SK_d material"),
		},
		Child:    old,
		requests: make(chan *localRequest),
	}
	s.SetChildHandler(func(ChildSA) error { return nil })
	s.SetChildRetireHandler(func(uint32) error { return nil })
	return s
}

// RFC 7296 section 1.4.1 requires a peer whose own Delete crossed ours to
// answer with no Delete payload at all. Treating that as a failure used to
// leave the replaced SA latched in s.retiring, which locks out every later
// rekey in both directions for the life of the session.
func TestCrossedChildDeleteStillRetiresReplacedSA(t *testing.T) {
	old := ChildSA{
		EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128,
		LocalSPI: 0x10203040, RemoteSPI: 0x50607080,
	}
	s := newRekeyableSession(t, old)
	if err := driveChildRekey(t, s, old, func(remove *localRequest) {
		remove.result <- requestResult{inner: nil}
	}); err != nil {
		t.Fatalf("rekey: %v", err)
	}
	if got := s.retiringChild(); got.LocalSPI != 0 {
		t.Fatalf("Child SA %08x is still awaiting retirement", got.LocalSPI)
	}

	// The session has to stay rekeyable, which is the part a latch broke.
	next := s.currentChild()
	if err := driveChildRekey(t, s, next, func(remove *localRequest) {
		spi := make([]byte, 4)
		binary.BigEndian.PutUint32(spi, next.RemoteSPI)
		remove.result <- requestResult{inner: []RawPayload{
			{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoESP, SPIs: [][]byte{spi}})},
		}}
	}); err != nil {
		t.Fatalf("second rekey: %v", err)
	}
}

// A failed retire exchange has nobody left to send the Delete either, so the
// replaced SA still has to come out of s.retiring.
func TestFailedChildRetireExchangeStillClearsReplacedSA(t *testing.T) {
	old := ChildSA{
		EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128,
		LocalSPI: 0x11223344, RemoteSPI: 0x55667788,
	}
	s := newRekeyableSession(t, old)
	err := driveChildRekey(t, s, old, func(remove *localRequest) {
		remove.result <- requestResult{err: errors.New("peer stopped answering")}
	})
	if err == nil {
		t.Fatal("a failed retire exchange should still be reported")
	}
	if got := s.retiringChild(); got.LocalSPI != 0 {
		t.Fatalf("Child SA %08x is still awaiting retirement after a failed exchange", got.LocalSPI)
	}
}

// A peer chooses when to rekey. Each accepted one retains the SA it replaces
// for the retirement delay, and installing a replacement copies the retained
// set, so an unbounded rate drives that set to the rate times the delay and
// makes every install proportional to it, on the session's own goroutine.
func TestPeerChildRekeysAreRateLimited(t *testing.T) {
	s := &Session{started: time.Now()}
	if !s.allowPeerChildRekey() {
		t.Fatal("the first peer rekey was refused")
	}
	if s.allowPeerChildRekey() {
		t.Error("a second peer rekey was accepted immediately after the first")
	}
	// Backdating the origin the offset is measured from is the same as time
	// passing, and does not make the test wait for it.
	s.started = s.started.Add(-minPeerChildRekeyInterval)
	if !s.allowPeerChildRekey() {
		t.Error("a peer rekey was still refused a whole interval later")
	}
}

// A peer owes a Delete for the Child SA a rekey replaced, and is free not to
// send one. While the replaced SA is still latched, every rekey in both
// directions is refused, so a peer that rekeys once and goes quiet would lock
// the session out of rekeying for its whole life. At the deadline this end
// deletes it under RFC 7296 section 2.4, the answer of a peer that no longer
// has it carries no Delete payload, and its inbound keys then drain like any
// other replaced SA's.
func TestReplacedChildSAThePeerNeverDeletesIsDeletedAtTheDeadline(t *testing.T) {
	mine, _ := lifecycleMuxes(t)
	s := &Session{mux: mine, requests: make(chan *localRequest)}
	replaced := ChildSA{LocalSPI: 0x11111111, RemoteSPI: 0x33333333}
	retired := make(chan uint32, 4)
	s.SetChildRetireHandler(func(spi uint32) error { retired <- spi; return nil })
	if err := mine.RegisterESP(replaced.LocalSPI); err != nil {
		t.Fatal(err)
	}
	s.childMu.Lock()
	s.Child = ChildSA{LocalSPI: 0x22222222, RemoteSPI: 0x44444444}
	s.retiring = replaced
	s.retiringBy = time.Now().Add(retirementDeadline)
	s.childMu.Unlock()

	if _, ok := s.overdueRetiring(time.Now().Add(retirementDeadline - time.Second)); ok {
		t.Fatal("the replaced SA was given up while the peer's Delete could still arrive")
	}
	if when, ok := s.nextRetirement(time.Now()); !ok || when.IsZero() {
		t.Fatal("nothing wakes the control loop to give up on a Delete that is not coming")
	}
	child, ok := s.overdueRetiring(time.Now().Add(retirementDeadline))
	if !ok || child.LocalSPI != replaced.LocalSPI || child.RemoteSPI != replaced.RemoteSPI {
		t.Fatalf("at the deadline the replaced SA handed back is %+v, %v, want %+v", child, ok, replaced)
	}
	if _, ok := s.overdueRetiring(time.Now().Add(retirementDeadline)); ok {
		t.Error("the replaced SA was handed back a second time, so a second Delete for it would follow the first")
	}
	if _, ok := s.nextRetirement(time.Now()); ok {
		t.Error("the control loop still wakes for an SA whose Delete is out, which spins it until the answer")
	}

	done := make(chan struct{})
	go func() { defer close(done); s.deleteOverdueChild(child) }()
	var request *localRequest
	select {
	case request = <-s.requests:
	case <-time.After(answerBudget):
		t.Fatal("no Delete went out for the replaced SA")
	}
	if spis := deletedESP(t, request); request.exchange != INFORMATIONAL || !slices.Equal(spis, []uint32{replaced.LocalSPI}) {
		t.Fatalf("the exchange is %d deleting %08x, want an INFORMATIONAL deleting %08x, the SPI this end receives on", request.exchange, spis, replaced.LocalSPI)
	}
	if s.retiringChild().LocalSPI != replaced.LocalSPI {
		t.Error("the replaced SA was retired before its Delete was answered")
	}
	request.result <- requestResult{}
	<-done
	if s.retiringChild().LocalSPI != 0 {
		t.Error("the replaced SA is still latched after the answer, so every later rekey is refused")
	}
	select {
	case spi := <-retired:
		if spi != replaced.LocalSPI {
			t.Errorf("retired SPI %08x, want the replaced %08x", spi, replaced.LocalSPI)
		}
	default:
		t.Error("the replaced SA's inbound keys were never dropped")
	}

	// the mark goes with the SA, so the SA a later rekey replaces is handed back at its own deadline
	s.childMu.Lock()
	s.retiring, s.retiringBy = ChildSA{LocalSPI: 0x55555555, RemoteSPI: 0x66666666}, time.Now()
	s.childMu.Unlock()
	if _, ok := s.overdueRetiring(time.Now()); !ok {
		t.Error("the SA a later rekey replaced was never handed back, so no Delete would go out for it")
	}
}

// a session left to its own loop sends that Delete once, at the deadline and not before
func TestRunDeletesTheReplacedChildSAAtItsDeadline(t *testing.T) {
	peer, s := closingAfterAuth(t)
	replaced := ChildSA{LocalSPI: 0x11111111, RemoteSPI: 0x33333333}
	s.requests = make(chan *localRequest, 1)
	s.Child, s.retiring = ChildSA{LocalSPI: 0x22222222, RemoteSPI: 0x44444444}, replaced
	if err := s.mux.RegisterESP(replaced.LocalSPI); err != nil {
		t.Fatal(err)
	}
	const wait = 300 * time.Millisecond
	due := time.Now().Add(wait)
	s.retiringBy = due
	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- s.Run(ctx) }()
	defer func() {
		cancel()
		<-runDone
	}()

	deleting := peer.read(t)
	if early := time.Until(due); early > 0 {
		t.Errorf("the Delete went out %s before the deadline", early)
	}
	if spis := deletedESP(t, &localRequest{inner: deleting.inner}); deleting.Header.ExchangeType != INFORMATIONAL || !slices.Equal(spis, []uint32{replaced.LocalSPI}) {
		t.Fatalf("the peer got exchange %d deleting %08x, want an INFORMATIONAL deleting %08x", deleting.Header.ExchangeType, spis, replaced.LocalSPI)
	}
	peer.send(t, Header{ExchangeType: INFORMATIONAL, Flags: FlagResponse, MessageID: deleting.Header.MessageID}, nil)
	for deadline := time.Now().Add(answerBudget); s.retiringChild().LocalSPI != 0; time.Sleep(recordPoll) {
		if time.Now().After(deadline) {
			t.Fatal("the answered Delete left the replaced SA latched")
		}
	}
	if err := peer.conn.SetReadDeadline(time.Now().Add(quietPeriod)); err != nil {
		t.Fatal(err)
	}
	if n, _, err := peer.conn.ReadFromUDP(make([]byte, 2048)); err == nil {
		t.Errorf("the peer got %d more bytes after the answered Delete, want nothing", n)
	}
}

func deletedESP(t *testing.T, request *localRequest) []uint32 {
	t.Helper()
	var spis []uint32
	for _, payload := range request.inner {
		if payload.Type != PayloadD {
			continue
		}
		deleted, err := DecodeDelete(payload.Body)
		if err != nil || deleted.Protocol != ProtoESP {
			t.Fatalf("the request carries Delete %+v (%v), want ESP", deleted, err)
		}
		for _, spi := range deleted.SPIs {
			spis = append(spis, binary.BigEndian.Uint32(spi))
		}
	}
	return spis
}

// RFC 7296 section 1.4.1 has a node answer a Delete that crosses its own for the same SA without a Delete payload for it, and section 2.25.1 asks the same of a Child SA it is trying to close
// this end deletes a replaced SA after the rekey that replaced it and at the deadline, and a peer's Delete for it while either is out is answered empty, the SA retired on this end's own answer
func TestDeleteCrossingThisEndsOwnIsAnsweredWithoutTheSA(t *testing.T) {
	old := ChildSA{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, LocalSPI: 0x10203040, RemoteSPI: 0x50607080}
	for _, tc := range []struct {
		name   string
		delete func(*testing.T, *Session, func(*localRequest)) error
	}{
		{"after the rekey", func(t *testing.T, s *Session, respond func(*localRequest)) error {
			return driveChildRekey(t, s, old, respond)
		}},
		{"at the deadline", func(t *testing.T, s *Session, respond func(*localRequest)) error {
			s.childMu.Lock()
			s.Child, s.retiring, s.retiringBy = ChildSA{LocalSPI: 0x22222222, RemoteSPI: 0x44444444}, old, time.Now()
			s.childMu.Unlock()
			child, ok := s.overdueRetiring(time.Now())
			if !ok {
				t.Fatal("the replaced SA was not handed back at its deadline")
			}
			done := make(chan struct{})
			go func() { defer close(done); s.deleteOverdueChild(child) }()
			respond(<-s.requests)
			<-done
			return nil
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newRekeyableSession(t, old)
			s.current.skei, s.current.sker = make([]byte, 20), make([]byte, 20)
			if err := tc.delete(t, s, func(own *localRequest) {
				if spis := deletedESP(t, own); !slices.Equal(spis, []uint32{old.LocalSPI}) {
					t.Fatalf("this end's Delete names %08x, want the replaced %08x", spis, old.LocalSPI)
				}
				if inner := crossingDelete(t, s, old.RemoteSPI); len(inner) != 0 {
					t.Errorf("the peer's crossing Delete was answered with %v, want no Delete payload", inner)
				}
				if s.retiringChild().LocalSPI != old.LocalSPI {
					t.Error("the peer's crossing Delete retired the SA before this end's own Delete was answered")
				}
				own.result <- requestResult{}
			}); err != nil {
				t.Fatal(err)
			}
			if s.retiringChild().LocalSPI != 0 {
				t.Error("the replaced SA is still latched after this end's Delete was answered")
			}
		})
	}
}

func crossingDelete(t *testing.T, s *Session, remoteSPI uint32) []RawPayload {
	t.Helper()
	ctx := s.currentContext()
	response, err := s.handleRequest(ctx, &Header{ExchangeType: INFORMATIONAL, MessageID: 0}, nil, []RawPayload{
		{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoESP, SPIs: [][]byte{binary.BigEndian.AppendUint32(nil, remoteSPI)}})},
	})
	if err != nil {
		t.Fatal(err)
	}
	message, err := DecodeMessage(response.whole)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := DecryptMessage(ctx.suite, ctx.localEncryptionKey(), response.whole, message)
	if err != nil {
		t.Fatal(err)
	}
	return inner
}

// The exchange completed, so RFC 7296 section 2.8 has the responder holding a
// Child SA whatever this end then makes of the answer. RekeyChild retries on a
// capped backoff, so a rekey this end refuses after the response has to tell
// the peer: without that, every attempt leaves one more SA behind at a peer
// that believes it is carrying traffic.
func TestRefusedRekeyResponseDeletesTheSAItLeftAtThePeer(t *testing.T) {
	mux, _ := lifecycleMuxes(t)
	old := ChildSA{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, LocalSPI: 1, RemoteSPI: 2}
	s := &Session{mux: mux, current: &ikeContext{suite: SASuite{PRFID: PRF_HMAC_SHA2_256}},
		requests: make(chan *localRequest), Child: old, childRetireDelay: time.Second}
	if err := mux.RegisterESP(old.LocalSPI); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.RekeyChild() }()

	rekey := <-s.requests
	// The Delete has to name the SPI this end drew for the replacement, which
	// only the request it just sent carries.
	localSPI := offeredChildSPI(t, rekey.inner)
	remoteSPI := make([]byte, 4)
	binary.BigEndian.PutUint32(remoteSPI, old.RemoteSPI+1)
	// A well-formed proposal, so the SPI the peer installed is known, with
	// selectors this end will not take.
	rekey.result <- requestResult{inner: []RawPayload{
		{Type: PayloadSA, Body: EncodeSA([]Proposal{{
			Number: 1, Protocol: ProtoESP, SPI: remoteSPI,
			Transforms: []Transform{{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128}, {Type: TransESN, ID: ESN_NO}},
		}})},
		{Type: PayloadNonce, Body: EncodeNonce(make([]byte, 32))},
		{Type: PayloadTSi, Body: narrowSelectors()},
		{Type: PayloadTSr, Body: narrowSelectors()},
	}}

	var deleted *localRequest
	select {
	case deleted = <-s.requests:
	case err := <-done:
		t.Fatalf("the rekey returned %v without telling the peer about the SA it installed", err)
	case <-time.After(10 * time.Second):
		t.Fatal("no exchange followed the refusal")
	}
	if deleted.exchange != INFORMATIONAL {
		t.Fatalf("the exchange after the refusal is %d, want the INFORMATIONAL that deletes what the peer installed", deleted.exchange)
	}
	var named []uint32
	for _, p := range deleted.inner {
		if p.Type != PayloadD {
			continue
		}
		d, err := DecodeDelete(p.Body)
		if err != nil {
			t.Fatal(err)
		}
		for _, spi := range d.SPIs {
			named = append(named, binary.BigEndian.Uint32(spi))
		}
	}
	// RFC 7296 section 1.4.1 sends "the SPIs (as they would be expected in the
	// headers of inbound packets) of the SAs to be deleted", so the sender
	// names its own half. Naming the peer's matches nothing at the far end and
	// deletes nothing, so the exchange does none of the work it exists for.
	if len(named) != 1 || named[0] != localSPI {
		t.Errorf("the Delete names %v, want %d, the inbound SPI this end offered", named, localSPI)
	}
	if len(named) == 1 && named[0] == old.RemoteSPI+1 {
		t.Error("the Delete names the peer's inbound SPI, which its own deleteChildren matches against RemoteSPI")
	}
	deleted.result <- requestResult{}
	if err := <-done; err == nil {
		t.Error("the rekey reported success after refusing the answer")
	}
}

// narrowSelectors is a traffic selector pair this end refuses, which makes
// the response above one it turns down after the exchange completed.
func narrowSelectors() []byte {
	return EncodeTS([]TrafficSelector{{Type: TS_IPV4_ADDR_RANGE, EndPort: 0xffff,
		StartAddr: net.IPv4(10, 0, 0, 1).To4(), EndAddr: net.IPv4(10, 0, 0, 1).To4()}})
}

// offeredChildSPI reads the SPI a Child SA request proposes for this end's
// inbound half.
func offeredChildSPI(t *testing.T, inner []RawPayload) uint32 {
	t.Helper()
	payloads, err := decodeChildExchangePayloads(inner, PRF_HMAC_SHA2_256)
	if err != nil {
		t.Fatalf("invalid Child SA request: %v", err)
	}
	proposals, err := DecodeSA(payloads.sa.Body)
	if err != nil || len(proposals) != 1 || len(proposals[0].SPI) != 4 {
		t.Fatalf("invalid Child SA proposal: %#v, %v", proposals, err)
	}
	return binary.BigEndian.Uint32(proposals[0].SPI)
}

// And the rekey this end actually sends carries that one offer, not the
// initial one: espRekeyProposal exists only if the exchange uses it.
//
// Each fixture carries the EncrKeyBits canonicalEncryptionTransform stores, so
// ChaCha20-Poly1305 is 256 here and absent on the wire, which RFC 7296 section
// 3.3.5 requires of a fixed-length-key transform. Comparing the two spellings
// raw drops every cipher and offers ESN alone.
func TestRekeyOnTheWireOffersOneCipher(t *testing.T) {
	for _, installed := range []ChildSA{
		{EncrID: ENCR_CHACHA20_POLY1305, EncrKeyBits: 256, LocalSPI: 1, RemoteSPI: 2},
		{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 256, LocalSPI: 1, RemoteSPI: 2},
		{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, LocalSPI: 1, RemoteSPI: 2},
	} {
		t.Run(fmt.Sprintf("%d/%d", installed.EncrID, installed.EncrKeyBits), func(t *testing.T) {
			wantBits := installed.EncrKeyBits
			if installed.EncrID == ENCR_CHACHA20_POLY1305 {
				wantBits = 0
			}
			mux, _ := lifecycleMuxes(t)
			s := &Session{mux: mux, current: &ikeContext{suite: SASuite{PRFID: PRF_HMAC_SHA2_256}},
				requests: make(chan *localRequest), Child: installed, childRetireDelay: time.Second}
			if err := mux.RegisterESP(installed.LocalSPI); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- s.RekeyChild() }()
			defer func() { <-done }()

			rekey := <-s.requests
			payloads, err := decodeChildExchangePayloads(rekey.inner, PRF_HMAC_SHA2_256)
			if err != nil {
				t.Fatalf("invalid rekey request: %v", err)
			}
			proposals, err := DecodeSA(payloads.sa.Body)
			if err != nil || len(proposals) != 1 {
				t.Fatalf("invalid rekey proposal: %#v, %v", proposals, err)
			}
			var ciphers []Transform
			for _, transform := range proposals[0].Transforms {
				if transform.Type == TransEncr {
					ciphers = append(ciphers, transform)
				}
			}
			if len(ciphers) != 1 || ciphers[0].ID != installed.EncrID || ciphers[0].KeyLengthBits != wantBits {
				t.Errorf("the rekey on the wire offers %v, want only %d with %d key bits", ciphers, installed.EncrID, wantBits)
			}
			rekey.result <- requestResult{err: errors.New("done with this exchange")}
		})
	}
}

// Both ends may decide to close one Child SA at once. The peer's Delete can
// arrive before this end's is out, and deleteChildren then answers it and
// clears the retiring entry, so this end's own exchange comes back to nothing
// left to retire. Reporting that as an error fails the rekey that had already
// succeeded, and the caller then retries a replacement it has.
func TestRetiringAChildTwiceIsNotAFailure(t *testing.T) {
	mux, _ := lifecycleMuxes(t)
	retiring := ChildSA{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, LocalSPI: 7, RemoteSPI: 8}
	s := &Session{mux: mux, retiring: retiring, childRetireDelay: time.Millisecond}
	if err := mux.RegisterESP(retiring.LocalSPI); err != nil {
		t.Fatal(err)
	}
	if err := s.retireChild(retiring.RemoteSPI); err != nil {
		t.Fatalf("the first retirement failed: %v", err)
	}
	if err := s.retireChild(retiring.RemoteSPI); err != nil {
		t.Errorf("retiring an SA the peer's Delete already took reported %v", err)
	}
	// A remote SPI that was never retiring is still an error: the idempotence
	// is about the crossing, not about accepting any SPI at all.
	s.childMu.Lock()
	s.retiring = ChildSA{LocalSPI: 9, RemoteSPI: 10}
	s.childMu.Unlock()
	if err := s.retireChild(99); err == nil {
		t.Error("retiring an SPI no SA is retiring under was accepted")
	}
}

// RFC 7296 section 3.9: "Nonce values MUST NOT be reused."
// a Child SA negotiation here carries no KE, so its keys come from SK_d and the two nonces alone, and two of them that this end starts on one IKE SA send different nonces
func TestEachChildSANegotiationDrawsItsOwnNonce(t *testing.T) {
	mux, _ := lifecycleMuxes(t)
	s := &Session{mux: mux, current: &ikeContext{suite: SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}, skD: bytes.Repeat([]byte{1}, 32)},
		requests: make(chan *localRequest, 1)}
	var nonces [][]byte
	for range 2 {
		done := make(chan error, 1)
		go func() { done <- s.negotiateChild(nil) }()
		request := <-s.requests
		nonce := findType(request.inner, PayloadNonce)
		if nonce == nil {
			request.result <- requestResult{err: errors.New("the request carries no nonce")}
			<-done
			t.Fatalf("the Child SA negotiation carries %v and no nonce", payloadTypes(request.inner))
		}
		nonces = append(nonces, DecodeNonce(nonce.Body))
		request.result <- requestResult{inner: []RawPayload{{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_NO_PROPOSAL_CHOSEN})}}}
		if err := <-done; err == nil {
			t.Fatal("negotiateChild took an answer of NO_PROPOSAL_CHOSEN")
		}
	}
	if bytes.Equal(nonces[0], nonces[1]) {
		t.Errorf("two Child SA negotiations sent the same nonce %x", nonces[0])
	}
}

// RFC 7296 section 3.9: "Nonce values MUST NOT be reused."
// two Child SA rekeys this end answers, each on an IKE SA keyed alike, answer with different nonces
func TestEachChildSAAnswerDrawsItsOwnNonce(t *testing.T) {
	child := ChildSA{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, LocalSPI: 0x10203040, RemoteSPI: 0x50607080}
	var nonces [][]byte
	for range 2 {
		mux, _ := lifecycleMuxes(t)
		ctx := testContext()
		s := &Session{mux: mux, current: ctx, Child: child}
		raw, err := s.handleRequest(ctx, &Header{ExchangeType: CREATE_CHILD_SA, MessageID: 5}, nil, childRekeyRequest(child.RemoteSPI))
		if err != nil {
			t.Fatal(err)
		}
		message, err := DecodeMessage(raw.whole)
		if err != nil {
			t.Fatal(err)
		}
		inner, err := DecryptMessage(ctx.suite, ctx.skei, raw.whole, message)
		if err != nil {
			t.Fatal(err)
		}
		nonce := findType(inner, PayloadNonce)
		if nonce == nil {
			t.Fatalf("the Child SA rekey drew %v and no nonce", payloadTypes(inner))
		}
		nonces = append(nonces, DecodeNonce(nonce.Body))
	}
	if bytes.Equal(nonces[0], nonces[1]) {
		t.Errorf("two Child SA rekeys were answered with the same nonce %x", nonces[0])
	}
}
