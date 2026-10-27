// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ike

import (
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/bubble"
)

// errRefused is the refusal of the dataplane or the random source a test breaks
var errRefused = errors.New("refused by the test")

// RFC 7296 section 2.4: "In this case, an IKE endpoint SHOULD send a Delete payload indicating that it has closed the IKE SA unless the other endpoint is no longer responding."
// deletedOnFailure has the dialed session end on its local failure with a Delete for the IKE SA, which ends the responder's Run, and record the close for sa
func deletedOnFailure(t *testing.T, pair *refusingPair, sa string) {
	t.Helper()
	err := pair.ended(t, "the session went on after its local failure")
	if !errors.Is(err, errRefused) {
		t.Errorf("the session ended with %v, want its local failure", err)
	}
	want := "ike.sa.closed testorg/client:2>testorg/server:1 sa=" + sa + " reason=local failure"
	got := pair.dialed.recorded()
	closes := slices.DeleteFunc(slices.Clone(got), func(line string) bool { return !strings.HasPrefix(line, "ike.sa.closed ") })
	if !slices.Equal(closes, []string{want}) {
		t.Errorf("the session recorded %q, want one close, %q", got, want)
	}
}

// failingDraws draws no jitter for the first after draws, which the schedules Run sets up take, and refuses every later one
func failingDraws(after int32) func(time.Duration) (time.Duration, error) {
	var drawn atomic.Int32
	return func(time.Duration) (time.Duration, error) {
		if drawn.Add(1) > after {
			return 0, errRefused
		}
		return 0, nil
	}
}

// a Child SA whose keys the dataplane refuses to give up at its lifetime closes the IKE SA with a Delete
// the Delete's answer is held, so the loop wakes for its retransmissions and finds the keys refused again, which records no second close
func TestRefusedWithdrawalAtTheLifetimeDeletesTheIKESA(t *testing.T) {
	bubble.Run(testRefusedWithdrawalAtTheLifetimeDeletesTheIKESA)(t)
}

func testRefusedWithdrawalAtTheLifetimeDeletesTheIKESA(t *testing.T) {
	const lifetime = time.Second
	pair := dialRefusing(t, func(cfg *PeerConfig) {
		cfg.ChildRekeyInterval, cfg.RekeyMargin = lifetime, lifetime-scheduleDue
		cfg.RekeyRetryInitial, cfg.RekeyRetryMax = answerBudget, answerBudget
		cfg.RemotePort = relay(t, cfg.RemotePort, func(fromInitiator bool, header *Header, _ []byte) bool {
			if !fromInitiator && header != nil && header.ExchangeType == INFORMATIONAL && header.IsResponse() {
				time.Sleep(quietPeriod)
			}
			return true
		})
	}, func(initiator, responder *Session) {
		refuseRekeys(initiator, responder)
		initiator.SetChildRetireHandler(func(uint32) error { return errRefused })
		initiator.retransmitAfter = quietPeriod / 3
	})
	deletedOnFailure(t, pair, "child")
}

// a replaced Child SA whose keys the dataplane refuses to give up at its own lifetime closes the IKE SA with a Delete
// the Delete's answer is held, and the lifetime already past does not wake the loop meanwhile, so the dataplane is asked once
func TestRefusedWithdrawalOfAReplacedChildSAIsAskedOnce(t *testing.T) {
	bubble.Run(testRefusedWithdrawalOfAReplacedChildSAIsAskedOnce)(t)
}

func testRefusedWithdrawalOfAReplacedChildSAIsAskedOnce(t *testing.T) {
	const retiringSPI = 0x11111111
	var asked atomic.Int32
	pair := dialRefusing(t, func(cfg *PeerConfig) {
		cfg.ChildRekeyInterval, cfg.RekeyMargin = time.Hour, time.Minute
		cfg.RemotePort = relay(t, cfg.RemotePort, func(fromInitiator bool, header *Header, _ []byte) bool {
			if !fromInitiator && header != nil && header.ExchangeType == INFORMATIONAL && header.IsResponse() {
				time.Sleep(quietPeriod)
			}
			return true
		})
	}, func(initiator, _ *Session) {
		initiator.retiring, initiator.retiringEnds, initiator.retiringBy = ChildSA{LocalSPI: retiringSPI, RemoteSPI: 0x33333333}, time.Now().Add(scheduleDue), time.Now().Add(time.Hour)
		initiator.SetChildRetireHandler(func(spi uint32) error {
			if spi != retiringSPI {
				return nil
			}
			asked.Add(1)
			return errRefused
		})
	})
	deletedOnFailure(t, pair, "child")
	if got := asked.Load(); got != 1 {
		t.Errorf("the dataplane was asked %d times to withdraw the replaced Child SA, want once", got)
	}
}

// a random source that refuses the draw that times the next rekey after a Child SA rekey closes the IKE SA with a Delete
func TestRefusedDrawAfterAChildSARekeyDeletesTheIKESA(t *testing.T) {
	bubble.Run(testRefusedDrawAfterAChildSARekeyDeletesTheIKESA)(t)
}

func testRefusedDrawAfterAChildSARekeyDeletesTheIKESA(t *testing.T) {
	pair := dialRefusing(t, func(cfg *PeerConfig) { cfg.ChildRekeyInterval = time.Hour }, func(initiator, _ *Session) {
		initiator.rekeyJitterSource = failingDraws(1)
	})
	if err := pair.initiator.RekeyChildProactively(); err != nil {
		t.Fatalf("the Child SA rekey failed: %v", err)
	}
	deletedOnFailure(t, pair, "child")
}

// a replaced Child SA the dataplane refuses to retire after this end's Delete for it at the deadline closes the IKE SA with a Delete
func TestRefusedRetirementAfterTheOverdueDeleteDeletesTheIKESA(t *testing.T) {
	bubble.Run(testRefusedRetirementAfterTheOverdueDeleteDeletesTheIKESA)(t)
}

func testRefusedRetirementAfterTheOverdueDeleteDeletesTheIKESA(t *testing.T) {
	pair := dialRefusing(t, func(*PeerConfig) {}, func(initiator, _ *Session) {
		initiator.retiring, initiator.retiringBy = ChildSA{LocalSPI: 0x11111111, RemoteSPI: 0x33333333}, time.Now().Add(scheduleDue)
		initiator.childRetireDelay = 0
		initiator.SetChildRetireHandler(func(uint32) error { return errRefused })
	})
	deletedOnFailure(t, pair, "child")
}

// a failure handed to either end's session closes the IKE SA with a Delete, which ends the other end's Run
func TestChildFailedDeletesTheIKESA(t *testing.T) {
	t.Run("dialed", bubble.Run(func(t *testing.T) {
		pair := dialRefusing(t, func(*PeerConfig) {}, func(*Session, *Session) {})
		pair.initiator.ChildFailed(errRefused)
		deletedOnFailure(t, pair, "child")
	}))
	t.Run("answered", bubble.Run(func(t *testing.T) {
		pair := dialRefusing(t, func(*PeerConfig) {}, func(*Session, *Session) {})
		pair.responder.ChildFailed(errRefused)
		select {
		case err := <-pair.responderDone:
			if !errors.Is(err, errRefused) {
				t.Errorf("the answered session ended with %v, want its local failure", err)
			}
		case <-time.After(answerBudget):
			t.Fatal("the answered session went on after its local failure")
		}
		select {
		case <-pair.initiatorDone:
		case <-time.After(answerBudget):
			t.Fatal("the dialed session still holds the IKE SA, so no Delete for it reached it")
		}
	}))
}

// a failure handed to a session that already holds one Run has not taken returns without waiting for Run, which takes the first
func TestChildFailedNeverBlocks(t *testing.T) {
	s := &Session{childFailed: make(chan error, 1)}
	first := errors.New("the first failure")
	s.ChildFailed(first)
	returned := make(chan struct{})
	go func() {
		s.ChildFailed(errRefused)
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(answerBudget):
		t.Fatal("a second failure waited for Run to take the first")
	}
	if got := <-s.childFailed; got != first {
		t.Errorf("Run takes %v, want the first failure", got)
	}
}

// a random source that refuses the draw that times the next rekey after an IKE SA rekey closes the IKE SA with a Delete
func TestRefusedDrawAfterAnIKESARekeyDeletesTheIKESA(t *testing.T) {
	bubble.Run(testRefusedDrawAfterAnIKESARekeyDeletesTheIKESA)(t)
}

func testRefusedDrawAfterAnIKESARekeyDeletesTheIKESA(t *testing.T) {
	pair := dialRefusing(t, func(cfg *PeerConfig) {
		cfg.IKERekeyInterval, cfg.RekeyMargin = time.Hour, time.Hour-scheduleDue
	}, func(initiator, _ *Session) {
		initiator.rekeyJitterSource = failingDraws(1)
	})
	deletedOnFailure(t, pair, "ike")
}

// a drained Child SA the dataplane refuses to retire closes the IKE SA with a Delete, and is not asked again
func TestRefusedRetirementOfADrainedChildSADeletesTheIKESA(t *testing.T) {
	bubble.Run(testRefusedRetirementOfADrainedChildSADeletesTheIKESA)(t)
}

func testRefusedRetirementOfADrainedChildSADeletesTheIKESA(t *testing.T) {
	var asked atomic.Int32
	pair := dialRefusing(t, func(*PeerConfig) {}, func(initiator, _ *Session) {
		replaced := initiator.Child.LocalSPI
		initiator.childRetireDelay = quietPeriod / 3
		initiator.SetChildRetireHandler(func(spi uint32) error {
			if spi != replaced {
				return nil
			}
			asked.Add(1)
			return errRefused
		})
	})
	if err := pair.initiator.RekeyChild(); err != nil {
		t.Fatalf("the Child SA rekey failed: %v", err)
	}
	deletedOnFailure(t, pair, "child")
	if got := asked.Load(); got != 1 {
		t.Errorf("the dataplane was asked %d times to retire the drained Child SA, want once", got)
	}
}

// a Child SA the peer deletes and the dataplane refuses to close is left out of the answer, and the IKE SA's Delete follows it
func TestRefusedCloseOfAChildSAThePeerDeletedDeletesTheIKESA(t *testing.T) {
	bubble.Run(testRefusedCloseOfAChildSAThePeerDeletedDeletesTheIKESA)(t)
}

func testRefusedCloseOfAChildSAThePeerDeletedDeletesTheIKESA(t *testing.T) {
	pair := dialRefusing(t, func(*PeerConfig) {}, func(initiator, _ *Session) {
		initiator.SetChildRetireHandler(func(uint32) error { return errRefused })
	})
	spi := binary.BigEndian.AppendUint32(nil, pair.initiator.currentChild().RemoteSPI)
	answer, err := pair.responder.request(INFORMATIONAL, []RawPayload{{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoESP, SPIs: [][]byte{spi}})}})
	if err != nil {
		t.Fatalf("the peer's Delete of the Child SA was not answered: %v", err)
	}
	if len(answer) != 0 {
		t.Errorf("the answer carries %d payloads, want none for the Child SA the dataplane kept", len(answer))
	}
	deletedOnFailure(t, pair, "child")
}

// RFC 7296 section 1.4.1: "Normally, the response in the INFORMATIONAL exchange will contain Delete payloads for the paired SAs going in the other direction."
// a peer's Delete naming a replaced Child SA and then the current one, which the dataplane refuses to close, is answered with a Delete payload for the replaced SA it closed
func TestPeerDeleteAnswersTheChildSAClosedBeforeARefusal(t *testing.T) {
	bubble.Run(testPeerDeleteAnswersTheChildSAClosedBeforeARefusal)(t)
}

func testPeerDeleteAnswersTheChildSAClosedBeforeARefusal(t *testing.T) {
	replaced := ChildSA{LocalSPI: 0x11111111, RemoteSPI: 0x33333333}
	pair := dialRefusing(t, func(*PeerConfig) {}, func(initiator, _ *Session) {
		initiator.retiring, initiator.retiringBy = replaced, time.Now().Add(time.Hour)
		initiator.childRetireDelay = 0
		current := initiator.Child.LocalSPI
		initiator.SetChildRetireHandler(func(spi uint32) error {
			if spi == current {
				return errRefused
			}
			return nil
		})
	})
	spis := [][]byte{binary.BigEndian.AppendUint32(nil, replaced.RemoteSPI), binary.BigEndian.AppendUint32(nil, pair.initiator.currentChild().RemoteSPI)}
	answer, err := pair.responder.request(INFORMATIONAL, []RawPayload{{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoESP, SPIs: spis})}})
	if err != nil {
		t.Fatalf("the peer's Delete of the two Child SAs was not answered: %v", err)
	}
	if len(answer) != 1 || answer[0].Type != PayloadD {
		t.Fatalf("the answer carries %v, want one Delete payload", answer)
	}
	deleted, err := DecodeDelete(answer[0].Body)
	if err != nil || deleted.Protocol != ProtoESP || len(deleted.SPIs) != 1 || binary.BigEndian.Uint32(deleted.SPIs[0]) != replaced.LocalSPI {
		t.Errorf("the answer deletes %+v (%v), want the replaced Child SA %08x alone", deleted, err, replaced.LocalSPI)
	}
	deletedOnFailure(t, pair, "child")
}
