// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ike

import (
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/bubble"
)

// a quiet peer's liveness interval falls inside the sends of an unanswered request
const (
	quietRetransmit = 400 * time.Millisecond
	quietDPD        = 500 * time.Millisecond
)

// answeredWithin waits for one exchange a test started to return
func answeredWithin(t *testing.T, done <-chan error, what string) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(answerBudget):
		t.Fatalf("%s did not return", what)
		return nil
	}
}

// stillRunning fails t when run has ended
func stillRunning(t *testing.T, run <-chan error) {
	t.Helper()
	select {
	case err := <-run:
		t.Fatalf("the session ended with %v", err)
	default:
	}
}

// RFC 7296 section 2.8: "An IKE SA so created inherits all of the original IKE SA's Child SAs, and the new IKE SA is used for all control messages needed to maintain those Child SAs."
// the answer to the Delete of the IKE SA a rekey replaced is lost, and the peer, which deleted that SA, answers none of its resends
// so the Delete ends that SA alone after teardownRetransmits sends, the rekey stands, and a Child SA rekey waiting behind it completes over the new IKE SA
func TestUnansweredDeleteOfAReplacedIKESAEndsItAlone(t *testing.T) {
	for name, peer := range map[string]struct{ retransmitAfter, dpdEvery time.Duration }{
		"a quiet peer": {quietRetransmit, quietDPD},
		// a peer that answers at once is busy throughout the sends of a request, since its last answer is far inside the liveness interval
		"a busy peer": {unansweredRetransmit, time.Hour},
	} {
		t.Run(name, func(t *testing.T) {
			lines := recordLines(t)
			h := newResponderHarness(t, nil)
			var replaced atomic.Uint64
			var rekeyed atomic.Bool
			var deletes atomic.Int32
			deleting := make(chan struct{})
			var first sync.Once
			cfg := h.peerConfig()
			cfg.RemotePort = relay(t, h.remotePort, func(fromInitiator bool, header *Header, _ []byte) bool {
				if header == nil {
					return true
				}
				if !fromInitiator && header.IsResponse() && header.ExchangeType == CREATE_CHILD_SA {
					rekeyed.Store(true)
				}
				if !rekeyed.Load() || header.ExchangeType != INFORMATIONAL || header.SPIInitiator != replaced.Load() {
					return true
				}
				if fromInitiator && !header.IsResponse() {
					deletes.Add(1)
					first.Do(func() { close(deleting) })
				}
				return fromInitiator
			})
			initiator, responder := dialPaused(t, h, cfg)
			old := initiator.currentContext()
			replaced.Store(old.spiI)
			initiator.retransmitAfter, initiator.dpdEvery = peer.retransmitAfter, peer.dpdEvery
			responder.dpdEvery = time.Hour
			runSession(t, responder)
			run := runSession(t, initiator)

			ikeDone := make(chan error, 1)
			go func() { ikeDone <- initiator.RekeyIKE() }()
			select {
			case <-deleting:
			case <-time.After(answerBudget):
				t.Fatal("the rekey sent no Delete of the IKE SA it replaced")
			}
			childDone := make(chan error, 1)
			go func() { childDone <- initiator.RekeyChild() }()
			if err := answeredWithin(t, ikeDone, "the IKE SA rekey"); err != nil {
				t.Fatalf("the rekey failed on the Delete of the SA it replaced, after it took effect: %v", err)
			}
			if err := answeredWithin(t, childDone, "the Child SA rekey behind the Delete"); err != nil {
				t.Fatalf("the Child SA rekey behind the Delete failed: %v", err)
			}
			stillRunning(t, run)
			if got := deletes.Load(); got != teardownRetransmits {
				t.Errorf("the Delete of the replaced IKE SA was sent %d times, want %d", got, teardownRetransmits)
			}
			if !initiator.contextRetired(old) {
				t.Error("the session still holds the IKE SA whose Delete went unanswered")
			}
			if told := lines.said(slog.LevelInfo, "ike replaced IKE SA was not deleted by this end", "err"); len(told) != 1 {
				t.Errorf("the unanswered Delete was told %d times, want once", len(told))
			}
		})
	}
}

// RFC 7296 section 2.8.2: "The new IKE SA containing the lowest nonce SHOULD be deleted by the node that created it, and the other surviving new IKE SA MUST inherit all the Child SAs."
// the peer answers none of the sends of the Delete of the redundant IKE SA this end made
// so the Delete ends that SA alone after teardownRetransmits sends, which the session logs, the rekey stands, and a request waiting behind it is answered over the surviving IKE SA
func TestUnansweredDeleteOfARedundantIKESAEndsItAlone(t *testing.T) {
	lines := recordLines(t)
	p := newCollisionPeer(t, time.Now())
	s, suite := p.session, p.old.suite
	s.retransmitAfter, s.dpdEvery = unansweredRetransmit, time.Hour

	var deletes atomic.Int32
	deleting := make(chan struct{})
	p.play(func(p *collisionPeer) {
		// every send of the Delete of the redundant candidate goes unanswered, and the next request is the one waiting behind it
		for {
			request, raw, ok := p.read("the Delete of the redundant candidate or the request behind it")
			if !ok {
				return
			}
			if p.rekeyResend(request) {
				continue
			}
			if request.Header.SPIInitiator == p.localSPIi && request.Header.SPIResponder == collisionLoserSPIr && request.Header.ExchangeType == INFORMATIONAL {
				if deletes.Add(1) == 1 {
					close(deleting)
				}
				continue
			}
			if request.Header.SPIInitiator != collisionPeerSPIi || request.Header.SPIResponder != p.winnerSPIr || request.Header.IsResponse() {
				t.Errorf("the request after the Delete is %+v, want one over the surviving candidate", request.Header)
				return
			}
			if _, err := DecryptMessage(suite, p.winner.SKer, raw, request); err != nil {
				t.Errorf("decrypt the request over the surviving candidate: %v", err)
				return
			}
			raw, err := EncryptMessage(suite, p.winner.SKei, Header{SPIInitiator: collisionPeerSPIi, SPIResponder: p.winnerSPIr, ExchangeType: request.Header.ExchangeType,
				Flags: FlagInitiator | FlagResponse, MessageID: request.Header.MessageID}, nil, nil)
			p.send("the answer over the surviving candidate", raw, err)
			return
		}
	})

	run := runSession(t, s)
	ikeDone := make(chan error, 1)
	go func() { ikeDone <- s.RekeyIKE() }()
	select {
	case <-deleting:
	case <-time.After(answerBudget):
		t.Fatal("the rekey sent no Delete of the redundant candidate")
	}
	behind := make(chan error, 1)
	go func() {
		_, err := s.request(INFORMATIONAL, nil)
		behind <- err
	}()
	if err := answeredWithin(t, ikeDone, "the IKE SA rekey"); err != nil {
		t.Fatalf("the rekey failed on the Delete of its redundant candidate, after the surviving one took effect: %v", err)
	}
	if err := answeredWithin(t, behind, "the request behind the Delete"); err != nil {
		t.Fatalf("the request behind the Delete failed: %v", err)
	}
	stillRunning(t, run)
	if got := deletes.Load(); got != teardownRetransmits {
		t.Errorf("the Delete of the redundant candidate was sent %d times, want %d", got, teardownRetransmits)
	}
	s.stateMu.RLock()
	current, held := s.current, s.collision
	s.stateMu.RUnlock()
	if current.spiI != collisionPeerSPIi || held != nil {
		t.Errorf("after the rekey the session is current on %016x and holds %+v, want the peer's candidate alone", current.spiI, held)
	}
	if told := lines.said(slog.LevelInfo, "ike redundant IKE SA was not deleted by this end", "err"); len(told) != 1 || told[0].Any() == nil {
		t.Errorf("the unanswered Delete was told %d times with the errors %v, want once with its error", len(told), told)
	}
}

// a liveness check outstanding on an IKE SA the peer rekeys goes on over the SA it replaced, which this end keeps until the peer's Delete
// the peer's Delete of that SA and every answer over it are lost, so the check ends that SA alone once its budget is spent, and the session goes on over the SA the peer made
func TestUnansweredLivenessCheckOnAnIKESAThePeerReplacedEndsItAlone(t *testing.T) {
	bubble.Run(testUnansweredLivenessCheckOnAnIKESAThePeerReplacedEndsItAlone)(t)
}

func testUnansweredLivenessCheckOnAnIKESAThePeerReplacedEndsItAlone(t *testing.T) {
	h := newResponderHarness(t, nil)
	var replaced atomic.Uint64
	checking := make(chan struct{})
	var first sync.Once
	cfg := h.peerConfig()
	cfg.RemotePort = relay(t, h.remotePort, func(fromInitiator bool, header *Header, _ []byte) bool {
		if header == nil || header.ExchangeType != INFORMATIONAL || header.SPIInitiator != replaced.Load() {
			return true
		}
		if fromInitiator && !header.IsResponse() {
			first.Do(func() { close(checking) })
		}
		return false
	})
	initiator, responder := dialPaused(t, h, cfg)
	old := initiator.currentContext()
	replaced.Store(old.spiI)
	initiator.retransmitAfter, responder.retransmitAfter = unansweredRetransmit, unansweredRetransmit
	initiator.dpdEvery, responder.dpdEvery = time.Hour, time.Hour
	runSession(t, responder)
	run := runSession(t, initiator)

	initiator.Probe()
	select {
	case <-checking:
	case <-time.After(answerBudget):
		t.Fatal("the probe started no liveness check")
	}
	if err := responder.RekeyIKE(); err != nil {
		t.Fatalf("the peer's rekey failed: %v", err)
	}
	if current := initiator.currentContext(); current == old {
		t.Fatal("the peer's rekey did not replace the IKE SA")
	}
	behind := make(chan error, 1)
	go func() {
		_, err := initiator.request(INFORMATIONAL, nil)
		behind <- err
	}()
	if err := answeredWithin(t, behind, "the request behind the liveness check"); err != nil {
		t.Fatalf("the request behind the liveness check failed: %v", err)
	}
	stillRunning(t, run)
	if !initiator.contextRetired(old) {
		t.Error("the session still holds the IKE SA whose liveness check went unanswered")
	}
}

// RFC 7296 section 2.1: "If the responder receives a retransmitted request for which it has already forgotten the response, it MUST ignore the request"
// so a Delete of the IKE SA the session runs on stops after teardownRetransmits sends from the first, whoever asked for it, while the peer counts as alive
// a replacement whose Delete goes unanswered still ends with ErrPRFUnlisted, which internal/client reads to dial again at once
func TestDeleteOfTheCurrentIKESAHasTheTeardownBudget(t *testing.T) {
	for name, c := range map[string]struct {
		deleteIKE func(t *testing.T, s *Session, dialing *atomic.Pointer[Suites])
		// ended is the error the session ends with, nil where it may end with any
		ended error
	}{
		"a caller's": {deleteIKE: func(t *testing.T, s *Session, _ *atomic.Pointer[Suites]) {
			// before Run serves, DeleteIKE sends once and waits for no answer
			if !waitUntil(s.serving.Load) {
				t.Fatal("Run never served the session")
			}
			if err := s.DeleteIKE(); err == nil {
				t.Error("a Delete nothing answered returned no error")
			}
		}},
		"a replacement": {deleteIKE: func(t *testing.T, s *Session, dialing *atomic.Pointer[Suites]) {
			sha256Only := suitesOf(t, Crypto{IKE: IKESuites{PRF: []string{"sha256"}}})
			dialing.Store(&sha256Only)
			s.SuitesChanged()
		}, ended: ErrPRFUnlisted},
	} {
		t.Run(name, bubble.Run(func(t *testing.T) {
			h := newResponderHarness(t, nil)
			var deletes atomic.Int32
			cfg, dialing := listedConfig(h, nil)
			cfg.RemotePort = relay(t, h.remotePort, func(fromInitiator bool, header *Header, _ []byte) bool {
				if fromInitiator && header != nil && !header.IsResponse() && header.ExchangeType == INFORMATIONAL {
					deletes.Add(1)
					return false
				}
				return true
			})
			initiator, responder := dialPaused(t, h, cfg)
			initiator.retransmitAfter = unansweredRetransmit
			initiator.dpdEvery, responder.dpdEvery = time.Hour, time.Hour
			runSession(t, responder)
			run := runSession(t, initiator)
			c.deleteIKE(t, initiator, dialing)
			if err := endedWithin(t, run, "deleting"); c.ended != nil && !errors.Is(err, c.ended) {
				t.Errorf("the session ended with %v, want %v", err, c.ended)
			}
			if got := deletes.Load(); got != teardownRetransmits {
				t.Errorf("the Delete was sent %d times, want %d", got, teardownRetransmits)
			}
		}))
	}
}

// RFC 7296 section 2.4: "In this case, an IKE endpoint SHOULD send a Delete payload indicating that it has closed the IKE SA unless the other endpoint is no longer responding."
// a Child SA reaches its lifetime while every send of the Delete of the IKE SA a forced rekey replaced is lost
// that Delete ends the replaced SA alone, and the session then sends the Delete of the IKE SA it holds, which the peer answers, and ends with the lifetime's error
func TestLifetimeBehindAnUnansweredDeleteOfAReplacedIKESAStillDeletesTheIKESA(t *testing.T) {
	bubble.Run(testLifetimeBehindAnUnansweredDeleteOfAReplacedIKESAStillDeletesTheIKESA)(t)
}

func testLifetimeBehindAnUnansweredDeleteOfAReplacedIKESAStillDeletesTheIKESA(t *testing.T) {
	h := newResponderHarness(t, nil)
	var replaced atomic.Uint64
	var replacedSent, currentSent atomic.Int32
	cfg, dialing := listedConfig(h, nil)
	// the IKE SA's own schedule lies past the test, the Child SA's rekey falls due behind the IKE SA's, and its lifetime falls while the replaced IKE SA's Delete is out
	cfg.IKERekeyInterval, cfg.ChildRekeyInterval, cfg.RekeyMargin = time.Hour, 2500*time.Millisecond, 200*time.Millisecond
	cfg.RemotePort = relay(t, h.remotePort, func(fromInitiator bool, header *Header, _ []byte) bool {
		if !fromInitiator || header == nil || header.IsResponse() || header.ExchangeType != INFORMATIONAL {
			return true
		}
		if header.SPIInitiator == replaced.Load() {
			replacedSent.Add(1)
			return false
		}
		currentSent.Add(1)
		return true
	})
	initiator, responder := dialPaused(t, h, cfg)
	replaced.Store(initiator.currentContext().spiI)
	initiator.retransmitAfter = time.Second
	initiator.rekeyJitterSource = func(time.Duration) (time.Duration, error) { return 0, nil }
	initiator.dpdEvery, responder.dpdEvery = time.Hour, time.Hour
	runSession(t, responder)
	run := runSession(t, initiator)
	aes128 := suitesOf(t, Crypto{IKE: IKESuites{Cipher: []string{"aes128gcm"}}})
	dialing.Store(&aes128)
	initiator.SuitesChanged()
	if err := endedWithin(t, run, "dialing"); err == nil || !strings.Contains(err.Error(), "the Child SA reached its lifetime") {
		t.Errorf("the session ended with %v, want the Child SA's lifetime", err)
	}
	if got := replacedSent.Load(); got != teardownRetransmits {
		t.Errorf("the Delete of the replaced IKE SA was sent %d times, want %d", got, teardownRetransmits)
	}
	if got := currentSent.Load(); got != 1 {
		t.Errorf("%d INFORMATIONAL requests went out on the IKE SA the rekey made, want its Delete alone", got)
	}
}
