// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ike

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/bubble"
)

// refusingPair is a session dialed to the harness responder, with Run going at both ends
type refusingPair struct {
	h             *responderHarness
	initiator     *Session
	responder     *Session
	dialed        *recorder
	initiatorDone chan error
	responderDone chan error
}

// seed sees both sessions before either runs, so what it sets races with nothing
func dialRefusing(t *testing.T, configure func(*PeerConfig), seed func(initiator, responder *Session)) *refusingPair {
	t.Helper()
	pair := &refusingPair{h: newResponderHarness(t, nil), dialed: &recorder{}, initiatorDone: make(chan error, 1), responderDone: make(chan error, 1)}
	cfg := pair.h.peerConfig()
	cfg.Events = pair.dialed.record
	configure(&cfg)
	dial, cancel := context.WithTimeout(context.Background(), answerBudget)
	defer cancel()
	initiator, err := InitiateContext(dial, cfg)
	if err != nil {
		t.Fatal(err)
	}
	pair.initiator, pair.responder = initiator, <-pair.h.sessions
	<-pair.h.identities
	seed(pair.initiator, pair.responder)
	run, stop := context.WithCancel(context.Background())
	var running sync.WaitGroup
	running.Go(func() { pair.responderDone <- pair.responder.Run(run) })
	running.Go(func() { pair.initiatorDone <- pair.initiator.Run(run) })
	t.Cleanup(func() {
		stop()
		running.Wait()
	})
	return pair
}

// seededStreak is a run of refusals begun at since under the IKE SA and the Child SA s holds
func seededStreak(s *Session, since time.Time) temporaryStreak {
	child, _ := s.childEstablishedAt()
	return temporaryStreak{on: s.current, child: child, since: since}
}

// refuseRekeys has the responder answer every rekey with TEMPORARY_FAILURE, as it answers one that finds its own Child SA rekey running
func refuseRekeys(_, responder *Session) { responder.childRekeying.Store(true) }

// in the tests of a failed Child SA exchange the retry backoff starts at retryDelay and doubles, and a scheduled rekey falls due scheduleDue into the session
const (
	retryDelay  = time.Second
	scheduleDue = 300 * time.Millisecond
	// scheduleAhead is where the scheduled rekey falls due in the tests of a schedule another path's rekey resets
	scheduleAhead = time.Second
	// childDue is where the Child SA's scheduled rekey falls due in the test of one that waits on the IKE SA's, which falls due scheduleDue into the session
	childDue = 2 * time.Second
)

// unjittered draws no jitter, so every delay is the one the backoff or the schedule names
func unjittered(time.Duration) (time.Duration, error) { return 0, nil }

// retryDraws draws no jitter and keeps each retry delay the backoff asks it to spread, whose upper half is the bound it is handed
// the schedule's own draws have the configured jitter as their bound, which these tests leave at zero
type retryDraws struct {
	mu     sync.Mutex
	delays []time.Duration
}

func (r *retryDraws) draw(bound time.Duration) (time.Duration, error) {
	if bound > 0 {
		r.mu.Lock()
		r.delays = append(r.delays, 2*bound)
		r.mu.Unlock()
	}
	return 0, nil
}

func (r *retryDraws) drawn() []time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.delays)
}

// childRekeyLines counts what the dialed session recorded of kind for its Child SA
func childRekeyLines(pair *refusingPair, kind string) int {
	line := kind + " testorg/client:2>testorg/server:1 sa=child"
	if kind == "ike.rekey.completed" {
		line += " suite=" + defaultSuite["child"]
	}
	count := 0
	for _, got := range pair.dialed.recorded() {
		if got == line {
			count++
		}
	}
	return count
}

// RFC 7296 section 2.25: "When a peer receives a TEMPORARY_FAILURE notification, it MUST NOT immediately retry the operation" and "it MUST wait so that the sender may complete whatever operation caused the temporary condition."
// a Child SA exchange this end starts that fails holds the next one on every path for the Child SA schedule's retry delay, and the schedule then retries it
// the paths are the schedule, a rekey asked for at once as a sequence space near its end asks for one, which may come as the schedule falls due, and the replacement of a Child SA the peer deleted, and a session with no rekey interval still retries
func TestFailedChildSAExchangeHoldsTheNextOnEveryPath(t *testing.T) {
	for _, tc := range []struct {
		name     string
		interval time.Duration
		margin   time.Duration
		// refuse has the responder refuse the Child SA exchanges until the returned func lets them through
		refuse func(t *testing.T, initiator, responder *Session) func()
		// fail runs the exchange that fails and returns once it has
		fail func(t *testing.T, pair *refusingPair)
	}{
		{"scheduled", time.Hour, time.Hour - scheduleDue, refuseEveryRekey, func(t *testing.T, pair *refusingPair) {
			for deadline := time.Now().Add(answerBudget); childRekeyLines(pair, "ike.rekey.failed") == 0; time.Sleep(recordPoll) {
				if time.Now().After(deadline) {
					t.Fatalf("the scheduled rekey never failed, the session recorded %q", pair.dialed.recorded())
				}
			}
		}},
		{"proactive", time.Hour, 0, refuseEveryRekey, askFailing},
		{"proactive as the schedule falls due", time.Hour, time.Hour - scheduleDue, func(t *testing.T, _, responder *Session) func() {
			// the answer comes once the schedule has fallen due behind the rekey asked for, which the schedule then finds running
			held := time.Now().Add(scheduleDue + quietPeriod)
			return refuseInstalls(responder, held)
		}, askFailing},
		{"replacement", time.Hour, 0, func(t *testing.T, initiator, responder *Session) func() {
			// as RFC 7296 section 1.4.1 lets the peer do, it deleted the Child SA and kept the IKE SA, so the next exchange makes a new one
			for _, end := range []*Session{initiator, responder} {
				if _, err := end.deleteChildren([]uint32{end.Child.RemoteSPI}); err != nil {
					t.Fatal(err)
				}
			}
			return refuseInstalls(responder, time.Time{})
		}, askFailing},
		{"proactive with no interval", 0, 0, refuseEveryRekey, askFailing},
	} {
		t.Run(tc.name, bubble.Run(func(t *testing.T) {
			var allow func()
			draws := &retryDraws{}
			pair := dialRefusing(t, func(cfg *PeerConfig) {
				cfg.ChildRekeyInterval, cfg.RekeyMargin = tc.interval, tc.margin
				cfg.RekeyRetryInitial, cfg.RekeyRetryMax = retryDelay, 4*retryDelay
			}, func(initiator, responder *Session) {
				initiator.rekeyJitterSource = draws.draw
				// no liveness check falls due, so a rekey's end is all that wakes the session to settle it
				initiator.dpdEvery, responder.dpdEvery = time.Hour, time.Hour
				allow = tc.refuse(t, initiator, responder)
			})
			tc.fail(t, pair)
			failed := time.Now()
			if err := pair.initiator.RekeyChildProactively(); err != nil {
				t.Errorf("a rekey asked for right after a failed one returned %v, want it left to the retry", err)
			}
			if err := pair.initiator.RekeyChild(); err == nil {
				t.Error("a rekey run right after a failed one succeeded")
			}
			allow()
			time.Sleep(time.Until(failed.Add(retryDelay / 2)))
			if got := childRekeyLines(pair, "ike.rekey.started"); got != 1 {
				t.Fatalf("%d Child SA rekeys started by half the retry delay after one failed, want only that one, the session recorded %q", got, pair.dialed.recorded())
			}
			for deadline := time.Now().Add(answerBudget); childRekeyLines(pair, "ike.rekey.completed") == 0; time.Sleep(recordPoll) {
				if time.Now().After(deadline) {
					t.Fatalf("the failed rekey was never retried, the session recorded %q", pair.dialed.recorded())
				}
			}
			// each failure is counted once, whatever the schedule's own run made of the moment, so no delay doubles
			if got := draws.drawn(); len(got) == 0 || slices.Max(got) != retryDelay {
				t.Errorf("the backoff drew the retry delays %v, want each the %s a single failure gives", got, retryDelay)
			}
			if child := pair.initiator.currentChild(); child.LocalSPI == 0 || child.RemoteSPI == 0 {
				t.Errorf("after the retry the session holds Child SA %08x/%08x, want one in place", child.LocalSPI, child.RemoteSPI)
			}
			if tc.interval != 0 {
				return
			}
			// with no interval the schedule falls due only to retry, so after the success nothing more starts and the session goes on
			time.Sleep(quietPeriod)
			if got := childRekeyLines(pair, "ike.rekey.started"); got != 2 {
				t.Errorf("%d Child SA rekeys started with no interval, want the failed one and its retry, the session recorded %q", got, pair.dialed.recorded())
			}
			select {
			case err := <-pair.initiatorDone:
				t.Errorf("the session ended after its retry succeeded: %v", err)
			default:
			}
		}))
	}
}

// refuseEveryRekey has the responder answer each rekey with TEMPORARY_FAILURE until the returned func lets them through
func refuseEveryRekey(_ *testing.T, initiator, responder *Session) func() {
	refuseRekeys(initiator, responder)
	return func() { responder.childRekeying.Store(false) }
}

// refuseInstalls has the responder hold each Child SA it would install until held and then refuse it, which it answers with TEMPORARY_FAILURE, until the returned func lets them through
func refuseInstalls(responder *Session, held time.Time) func() {
	var refusing atomic.Bool
	refusing.Store(true)
	responder.SetChildHandler(func(ChildSA) error {
		time.Sleep(time.Until(held))
		if refusing.Load() {
			return errors.New("the responder refuses the Child SA")
		}
		return nil
	})
	return func() { refusing.Store(false) }
}

// askFailing asks for a rekey at once, as internal/client does, and wants it refused
func askFailing(t *testing.T, pair *refusingPair) {
	t.Helper()
	if err := pair.initiator.RekeyChildProactively(); err == nil {
		t.Fatal("a rekey the responder refuses succeeded")
	}
}

// a Child SA rekey that succeeds on any path puts the schedule's next one an interval ahead of the SA it made, as a scheduled success does
func TestChildSARekeySucceedingOnAnyPathResetsTheSchedule(t *testing.T) {
	bubble.Run(testChildSARekeySucceedingOnAnyPathResetsTheSchedule)(t)
}

func testChildSARekeySucceedingOnAnyPathResetsTheSchedule(t *testing.T) {
	pair := dialRefusing(t, func(cfg *PeerConfig) {
		cfg.ChildRekeyInterval, cfg.RekeyMargin = time.Hour, time.Hour-scheduleAhead
	}, func(initiator, _ *Session) { initiator.rekeyJitterSource = unjittered })
	time.Sleep(scheduleAhead / 2)
	if err := pair.initiator.RekeyChildProactively(); err != nil {
		t.Fatalf("the rekey asked for failed: %v", err)
	}
	rekeyed := time.Now()
	// the schedule's own rekey was due scheduleAhead into the session, which this is past
	time.Sleep(time.Until(rekeyed.Add(scheduleAhead * 3 / 4)))
	if got := childRekeyLines(pair, "ike.rekey.started"); got != 1 {
		t.Fatalf("%d Child SA rekeys started by %s after the one asked for, want that one alone, the session recorded %q", got, scheduleAhead*3/4, pair.dialed.recorded())
	}
	for deadline := time.Now().Add(answerBudget); childRekeyLines(pair, "ike.rekey.started") < 2; time.Sleep(recordPoll) {
		if time.Now().After(deadline) {
			t.Fatalf("the schedule never rekeyed the SA the rekey asked for made, the session recorded %q", pair.dialed.recorded())
		}
	}
}

// a rekey the peer starts puts the schedule's next one an interval ahead of the SA it made, as one this end starts does
func TestPeerRekeyResetsTheSchedule(t *testing.T) {
	for _, sa := range []string{"child", "ike"} {
		t.Run(sa, bubble.Run(func(t *testing.T) {
			pair := dialRefusing(t, func(cfg *PeerConfig) {
				if sa == "child" {
					cfg.ChildRekeyInterval = time.Hour
				} else {
					cfg.IKERekeyInterval = time.Hour
				}
				cfg.RekeyMargin = time.Hour - scheduleAhead
			}, func(initiator, _ *Session) { initiator.rekeyJitterSource = unjittered })
			rekey := pair.responder.RekeyChild
			if sa == "ike" {
				rekey = pair.responder.RekeyIKE
			}
			time.Sleep(scheduleAhead / 2)
			if err := rekey(); err != nil {
				t.Fatalf("the peer's rekey failed: %v", err)
			}
			rekeyed := time.Now()
			started := "ike.rekey.started testorg/client:2>testorg/server:1 sa=" + sa
			// the schedule's rekey of the SA the handshake made was due scheduleAhead into the session, which this is past
			time.Sleep(time.Until(rekeyed.Add(scheduleAhead * 3 / 4)))
			if slices.Contains(pair.dialed.recorded(), started) {
				t.Fatalf("the schedule rekeyed the SA the peer's rekey made within %s of it, want %s after it, the session recorded %q", scheduleAhead*3/4, scheduleAhead, pair.dialed.recorded())
			}
			for deadline := time.Now().Add(answerBudget); !slices.Contains(pair.dialed.recorded(), started); time.Sleep(recordPoll) {
				if time.Now().After(deadline) {
					t.Fatalf("the schedule never rekeyed the SA the peer's rekey made, the session recorded %q", pair.dialed.recorded())
				}
			}
		}))
	}
}

// a peer's rekey of the SA a failed rekey backs off from drops the retry, and the schedule's next rekey counts from the peer's SA
func TestPeerRekeyDropsTheRetryOfTheSAItReplaced(t *testing.T) {
	bubble.Run(testPeerRekeyDropsTheRetryOfTheSAItReplaced)(t)
}

func testPeerRekeyDropsTheRetryOfTheSAItReplaced(t *testing.T) {
	var allow func()
	pair := dialRefusing(t, func(cfg *PeerConfig) {
		cfg.ChildRekeyInterval, cfg.RekeyMargin = time.Hour, time.Hour-scheduleAhead
		cfg.RekeyRetryInitial, cfg.RekeyRetryMax = retryDelay, 4*retryDelay
	}, func(initiator, responder *Session) {
		initiator.rekeyJitterSource = unjittered
		initiator.dpdEvery, responder.dpdEvery = time.Hour, time.Hour
		allow = refuseEveryRekey(t, initiator, responder)
	})
	for deadline := time.Now().Add(answerBudget); childRekeyLines(pair, "ike.rekey.failed") == 0; time.Sleep(recordPoll) {
		if time.Now().After(deadline) {
			t.Fatalf("the scheduled rekey never failed, the session recorded %q", pair.dialed.recorded())
		}
	}
	failed := time.Now()
	allow()
	time.Sleep(time.Until(failed.Add(retryDelay / 2)))
	if err := pair.responder.RekeyChild(); err != nil {
		t.Fatalf("the peer's rekey failed: %v", err)
	}
	rekeyed := time.Now()
	// the retry was due retryDelay after the failure, which this is past
	time.Sleep(time.Until(rekeyed.Add(scheduleAhead * 3 / 4)))
	if got := childRekeyLines(pair, "ike.rekey.started"); got != 1 {
		t.Fatalf("%d Child SA rekeys started by %s after the peer's, want the failed one alone, the session recorded %q", got, scheduleAhead*3/4, pair.dialed.recorded())
	}
	for deadline := time.Now().Add(answerBudget); childRekeyLines(pair, "ike.rekey.started") < 2; time.Sleep(recordPoll) {
		if time.Now().After(deadline) {
			t.Fatalf("the schedule never rekeyed the SA the peer's rekey made, the session recorded %q", pair.dialed.recorded())
		}
	}
}

// RFC 7296 section 2.25: "If a peer continues to receive TEMPORARY_FAILURE on the same IKE SA after several minutes, it SHOULD conclude that the state information is out of sync and close the IKE SA."
// a peer's rekey of the SA a refused rekey backs off from ends the refusals, so one refusal of a later rekey on the same IKE SA starts a new run rather than closing it
func TestPeerRekeyEndsTheTemporaryFailureRun(t *testing.T) {
	bubble.Run(testPeerRekeyEndsTheTemporaryFailureRun)(t)
}

func testPeerRekeyEndsTheTemporaryFailureRun(t *testing.T) {
	const lead = 3 * time.Second
	pair := dialRefusing(t, func(cfg *PeerConfig) {
		cfg.ChildRekeyInterval, cfg.RekeyMargin = time.Hour, time.Hour-lead
		cfg.RekeyRetryInitial, cfg.RekeyRetryMax = retryDelay, retryDelay
	}, func(initiator, responder *Session) {
		initiator.rekeyJitterSource = unjittered
		initiator.dpdEvery, responder.dpdEvery = time.Hour, time.Hour
		// the run of refusals began so long ago that the one at the scheduled rekey leaves it open and one past the retry closes it
		initiator.temporary = seededStreak(initiator, time.Now().Add(-temporaryFailureSpan+lead+retryDelay))
		refuseRekeys(initiator, responder)
	})
	for deadline := time.Now().Add(answerBudget); childRekeyLines(pair, "ike.rekey.failed") == 0; time.Sleep(recordPoll) {
		if time.Now().After(deadline) {
			t.Fatalf("the scheduled rekey never failed, the session recorded %q", pair.dialed.recorded())
		}
	}
	failed := time.Now()
	pair.responder.childRekeying.Store(false)
	if err := pair.responder.RekeyChild(); err != nil {
		t.Fatalf("the peer's rekey failed: %v", err)
	}
	// a retry, where one runs, is answered
	time.Sleep(time.Until(failed.Add(retryDelay + retryDelay/2)))
	pair.responder.childRekeying.Store(true)
	// past the rekey the peer's SA gives and its retry
	time.Sleep(time.Until(failed.Add(2*lead + retryDelay)))
	recorded := pair.dialed.recorded()
	if slices.Contains(recorded, "ike.sa.closed "+dialedPair+" sa=child reason=temporary failure") {
		t.Fatalf("one TEMPORARY_FAILURE after the peer's rekey closed the IKE SA, the session recorded %q", recorded)
	}
	if got := childRekeyLines(pair, "ike.rekey.failed"); got < 2 {
		t.Fatalf("%d Child SA rekeys failed, want the scheduled one and one after the peer's rekey, the session recorded %q", got, recorded)
	}
}

// a rekey a reload forced that is refused, and whose SA the peer's rekey then replaces with a listed cipher, as a peer that reloaded the same lists does, ends the run
// since the next refusal is counted under the Child SA the peer made, and so starts a new run rather than closing the IKE SA
func TestPeerRekeyEndsTheTemporaryFailureRunOfAForcedRekey(t *testing.T) {
	bubble.Run(testPeerRekeyEndsTheTemporaryFailureRunOfAForcedRekey)(t)
}

func testPeerRekeyEndsTheTemporaryFailureRunOfAForcedRekey(t *testing.T) {
	// the seeded run's span ends this long after the seed
	const spanLeft = 2 * time.Second
	dialing := new(atomic.Pointer[Suites])
	dialing.Store(&Suites{})
	var seeded time.Time
	pair := dialRefusing(t, func(cfg *PeerConfig) {
		cfg.Suites = func() Suites { return *dialing.Load() }
		cfg.ChildRekeyInterval, cfg.RekeyMargin = time.Hour, time.Minute
		cfg.RekeyRetryInitial, cfg.RekeyRetryMax = retryDelay, retryDelay
	}, func(initiator, responder *Session) {
		initiator.rekeyJitterSource = unjittered
		initiator.dpdEvery, responder.dpdEvery = time.Hour, time.Hour
		seeded = time.Now()
		// the run of refusals began so long ago that the forced rekey's refusal leaves it open and one past spanLeft closes it
		initiator.temporary = seededStreak(initiator, seeded.Add(-temporaryFailureSpan+spanLeft))
		refuseRekeys(initiator, responder)
	})
	aes128 := suitesOf(t, Crypto{ESP: ESPSuites{Cipher: []string{"aes128gcm"}}})
	dialing.Store(&aes128)
	pair.initiator.SuitesChanged()
	for deadline := time.Now().Add(answerBudget); childRekeyLines(pair, "ike.rekey.failed") == 0; time.Sleep(recordPoll) {
		if time.Now().After(deadline) {
			t.Fatalf("the forced rekey never failed, the session recorded %q", pair.dialed.recorded())
		}
	}
	failed := time.Now()
	// the peer's lists leave out the cipher as well, so its rekey makes a Child SA of a listed cipher
	pair.h.lists.Store(&aes128)
	pair.responder.childRekeying.Store(false)
	if err := pair.responder.RekeyChild(); err != nil {
		t.Fatalf("the peer's rekey failed: %v", err)
	}
	pair.responder.childRekeying.Store(true)
	if got := pair.initiator.Suite().ESP(); got != "aes128gcm" {
		t.Fatalf("the peer's rekey made a Child SA of %s, want aes128gcm", got)
	}
	// past the forced rekey's retry and past the seeded run's span
	wake := seeded.Add(spanLeft)
	if retried := failed.Add(retryDelay); retried.After(wake) {
		wake = retried
	}
	time.Sleep(time.Until(wake.Add(retryDelay / 2)))
	if err := pair.initiator.RekeyChildProactively(); err == nil {
		t.Fatal("a rekey the peer refuses succeeded")
	}
	time.Sleep(quietPeriod)
	recorded := pair.dialed.recorded()
	if slices.Contains(recorded, "ike.sa.closed "+dialedPair+" sa=child reason=temporary failure") {
		t.Fatalf("one TEMPORARY_FAILURE after the peer's rekey replaced the SA of the refused forced rekey closed the IKE SA, the session recorded %q", recorded)
	}
	if got := childRekeyLines(pair, "ike.rekey.failed"); got < 2 {
		t.Fatalf("%d Child SA rekeys failed, want the forced one and the one asked for after the peer's rekey, the session recorded %q", got, recorded)
	}
}

// RFC 7296 section 2.25 counts the refusals on the same IKE SA, so the run is the IKE SA's, and a rekey completed on it ends the run whichever end started that rekey
// a peer's Child SA rekey therefore ends a run of refusals of the IKE SA's own rekey, which nothing replaced, and the next refusal starts a new run and closes nothing
// whether the Child SA schedule falls due with the IKE SA's rekey or long after it, as it does once the two SAs were made at different times
func TestPeerChildSARekeyEndsTheTemporaryFailureRunOfTheIKESA(t *testing.T) {
	const lead = 3 * time.Second
	for _, tc := range []struct {
		name  string
		child time.Duration
	}{
		{"child schedule due with the IKE SA's", time.Hour},
		{"child schedule due an hour after the IKE SA's", 2 * time.Hour},
	} {
		t.Run(tc.name, bubble.Run(func(t *testing.T) {
			start := time.Now()
			pair := dialRefusing(t, func(cfg *PeerConfig) {
				cfg.ChildRekeyInterval, cfg.IKERekeyInterval, cfg.RekeyMargin = tc.child, time.Hour, time.Hour-lead
				cfg.RekeyRetryInitial, cfg.RekeyRetryMax = retryDelay, retryDelay
			}, func(initiator, responder *Session) {
				initiator.rekeyJitterSource = unjittered
				initiator.dpdEvery, responder.dpdEvery = time.Hour, time.Hour
				// the run's span ends half a retry delay after the IKE SA's scheduled rekey falls due, so that rekey's retry closes the run unless the peer's Child SA rekey ended it
				initiator.temporary = seededStreak(initiator, time.Now().Add(-temporaryFailureSpan+lead+retryDelay/2))
			})
			time.Sleep(time.Until(start.Add(lead / 3)))
			if err := pair.responder.RekeyChild(); err != nil {
				t.Fatalf("the peer's Child SA rekey failed: %v", err)
			}
			// from here the peer refuses every rekey, the IKE SA's among them
			pair.responder.childRekeying.Store(true)
			time.Sleep(time.Until(start.Add(lead + 2*retryDelay + retryDelay/2)))
			recorded := pair.dialed.recorded()
			for _, sa := range []string{"child", "ike"} {
				if slices.Contains(recorded, "ike.sa.closed "+dialedPair+" sa="+sa+" reason=temporary failure") {
					t.Fatalf("a refusal on the IKE SA after the peer's Child SA rekey closed it, the session recorded %q", recorded)
				}
			}
			ikeFailed := 0
			for _, line := range recorded {
				if line == "ike.rekey.failed "+dialedPair+" sa=ike" {
					ikeFailed++
				}
			}
			if ikeFailed < 2 {
				t.Fatalf("%d IKE SA rekeys failed, want the scheduled one and a retry past the seeded run's span, the session recorded %q", ikeFailed, recorded)
			}
		}))
	}
}

// a peer's Child SA rekey ends the run though a reload then leaves out the cipher of the SA it made, so the rekey the reload forces runs at once on that SA
// and its first refusal past the span of the run the peer's rekey ended starts a new run rather than closing the IKE SA
func TestPeerRekeyEndsTheTemporaryFailureRunBeforeAReloadRekeysItsSA(t *testing.T) {
	bubble.Run(testPeerRekeyEndsTheTemporaryFailureRunBeforeAReloadRekeysItsSA)(t)
}

func testPeerRekeyEndsTheTemporaryFailureRunBeforeAReloadRekeysItsSA(t *testing.T) {
	// the seeded run's span ends this long after the seed
	const spanLeft = 2 * time.Second
	dialing := new(atomic.Pointer[Suites])
	dialing.Store(&Suites{})
	var seeded time.Time
	pair := dialRefusing(t, func(cfg *PeerConfig) {
		cfg.Suites = func() Suites { return *dialing.Load() }
		cfg.ChildRekeyInterval, cfg.RekeyMargin = time.Hour, time.Minute
		cfg.RekeyRetryInitial, cfg.RekeyRetryMax = retryDelay, retryDelay
	}, func(initiator, responder *Session) {
		initiator.rekeyJitterSource = unjittered
		initiator.dpdEvery, responder.dpdEvery = time.Hour, time.Hour
		seeded = time.Now()
		initiator.temporary = seededStreak(initiator, seeded.Add(-temporaryFailureSpan+spanLeft))
	})
	// the streak tells a Child SA by when it was made, so the peer's rekey makes its SA an instant after the one it replaces
	time.Sleep(time.Millisecond)
	if err := pair.responder.RekeyChild(); err != nil {
		t.Fatalf("the peer's rekey failed: %v", err)
	}
	if got := pair.initiator.Suite().ESP(); got == "aes128gcm" {
		t.Fatalf("the peer's rekey made a Child SA of %s, want one the reload leaves out", got)
	}
	time.Sleep(time.Until(seeded.Add(spanLeft + retryDelay/2)))
	// from here the peer refuses every rekey
	pair.responder.childRekeying.Store(true)
	aes128 := suitesOf(t, Crypto{ESP: ESPSuites{Cipher: []string{"aes128gcm"}}})
	dialing.Store(&aes128)
	pair.initiator.SuitesChanged()
	for deadline := time.Now().Add(answerBudget); childRekeyLines(pair, "ike.rekey.failed") == 0; time.Sleep(recordPoll) {
		if time.Now().After(deadline) {
			t.Fatalf("the forced rekey never failed, the session recorded %q", pair.dialed.recorded())
		}
	}
	time.Sleep(quietPeriod)
	recorded := pair.dialed.recorded()
	if slices.Contains(recorded, "ike.sa.closed "+dialedPair+" sa=child reason=temporary failure") {
		t.Fatalf("the first refusal of the forced rekey of the SA the peer's rekey made closed the IKE SA, the session recorded %q", recorded)
	}
}

// a reload makes no exchange and replaces no SA, so a rekey it forces that a second reload calls off before it starts ends no run
// and one refusal past the run's span then closes the IKE SA
func TestReloadEndsNoTemporaryFailureRun(t *testing.T) {
	bubble.Run(testReloadEndsNoTemporaryFailureRun)(t)
}

func testReloadEndsNoTemporaryFailureRun(t *testing.T) {
	// the seeded run's span ends this long after the seed
	const spanLeft = 2 * time.Second
	dialing := new(atomic.Pointer[Suites])
	dialing.Store(&Suites{})
	var seeded time.Time
	pair := dialRefusing(t, func(cfg *PeerConfig) {
		cfg.Suites = func() Suites { return *dialing.Load() }
		cfg.ChildRekeyInterval, cfg.RekeyMargin = time.Hour, time.Minute
		cfg.RekeyJitter = forcedJitter
		cfg.RekeyRetryInitial, cfg.RekeyRetryMax = retryDelay, retryDelay
	}, func(initiator, responder *Session) {
		// a forced rekey waits forcedDelay, and every other draw is none
		initiator.rekeyJitterSource = func(max time.Duration) (time.Duration, error) {
			if max == forcedJitter {
				return forcedDelay, nil
			}
			return 0, nil
		}
		initiator.dpdEvery, responder.dpdEvery = time.Hour, time.Hour
		seeded = time.Now()
		initiator.temporary = seededStreak(initiator, seeded.Add(-temporaryFailureSpan+spanLeft))
		refuseRekeys(initiator, responder)
	})
	aes128 := suitesOf(t, Crypto{ESP: ESPSuites{Cipher: []string{"aes128gcm"}}})
	dialing.Store(&aes128)
	pair.initiator.SuitesChanged()
	const unlisted = "ike.suite.unlisted " + dialedPair + " sa=child suite=aes256gcm action=rekey"
	for deadline := time.Now().Add(answerBudget); !slices.Contains(pair.dialed.recorded(), unlisted); time.Sleep(recordPoll) {
		if time.Now().After(deadline) {
			t.Fatalf("the reload forced no rekey, the session recorded %q", pair.dialed.recorded())
		}
	}
	// the lists hold the Child SA's cipher again before the forced rekey's delay runs out, so its schedule falls due on the SA it counted from
	dialing.Store(&Suites{})
	pair.initiator.SuitesChanged()
	time.Sleep(time.Until(seeded.Add(spanLeft + quietPeriod)))
	if got := childRekeyLines(pair, "ike.rekey.started"); got != 0 {
		t.Fatalf("%d Child SA rekeys started after the second reload listed the cipher again, want none, the session recorded %q", got, pair.dialed.recorded())
	}
	if err := pair.initiator.RekeyChildProactively(); err == nil {
		t.Fatal("a rekey the peer refuses succeeded")
	}
	closed := "ike.sa.closed " + dialedPair + " sa=child reason=temporary failure"
	for deadline := time.Now().Add(answerBudget); !slices.Contains(pair.dialed.recorded(), closed); time.Sleep(recordPoll) {
		if time.Now().After(deadline) {
			t.Fatalf("one refusal past the span of a run only reloads followed did not close the IKE SA, the session recorded %q", pair.dialed.recorded())
		}
	}
}

// a scheduled Child SA rekey that falls due while the IKE SA's rekey runs waits for it, and a Child SA rekey that succeeds meanwhile on another path settles the schedule, so the one that waited does not run after it
// the rekey asked for holds the one request this end has outstanding from before the IKE SA's rekey falls due until after the Child SA's does, as the responder holds its answer until then
func TestChildSARekeySucceedingWhileTheScheduleWaitsDropsItsRun(t *testing.T) {
	pair := dialRefusing(t, func(cfg *PeerConfig) {
		cfg.IKERekeyInterval, cfg.ChildRekeyInterval = time.Hour, time.Hour-scheduleDue+childDue
		cfg.RekeyMargin = time.Hour - scheduleDue
	}, func(initiator, responder *Session) {
		initiator.rekeyJitterSource = unjittered
		initiator.dpdEvery, responder.dpdEvery = time.Hour, time.Hour
		answered := time.Now().Add(childDue + scheduleDue)
		responder.SetChildHandler(func(ChildSA) error {
			time.Sleep(time.Until(answered))
			return nil
		})
	})
	if err := pair.initiator.RekeyChildProactively(); err != nil {
		t.Fatalf("the rekey asked for failed: %v", err)
	}
	rekeyedIKE := "ike.rekey.completed testorg/client:2>testorg/server:1 sa=ike suite=" + defaultSuite["ike"]
	for deadline := time.Now().Add(answerBudget); !slices.Contains(pair.dialed.recorded(), rekeyedIKE); time.Sleep(recordPoll) {
		if time.Now().After(deadline) {
			t.Fatalf("the IKE SA's rekey never completed, the session recorded %q", pair.dialed.recorded())
		}
	}
	// the schedule's next Child SA rekey falls due childDue past the one asked for
	time.Sleep(quietPeriod)
	if got := childRekeyLines(pair, "ike.rekey.started"); got != 1 {
		t.Errorf("%d Child SA rekeys started by %s after the IKE SA's rekey, want the one asked for alone, the session recorded %q", got, quietPeriod, pair.dialed.recorded())
	}
}

// a failed Child SA exchange holds the next one from its end, before Run has settled it on the schedule, so an ask that comes in between does not retry it at once
func TestFailedChildSAExchangeHoldsTheNextBeforeRunSettlesIt(t *testing.T) {
	bubble.Run(testFailedChildSAExchangeHoldsTheNextBeforeRunSettlesIt)(t)
}

func testFailedChildSAExchangeHoldsTheNextBeforeRunSettlesIt(t *testing.T) {
	old := ChildSA{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, LocalSPI: 0x10203040, RemoteSPI: 0x50607080}
	s := newRekeyableSession(t, old)
	done := make(chan error, 1)
	go func() { done <- s.RekeyChild() }()
	rekey := <-s.requests
	rekey.result <- requestResult{inner: []RawPayload{{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_TEMPORARY_FAILURE})}}}
	if err := <-done; err == nil {
		t.Fatal("a rekey the responder refused succeeded")
	}
	// no Run goes here, so nothing settles the failure
	for _, ask := range []struct {
		name string
		run  func() error
		held func(error) bool
	}{
		{"asked for at once", s.RekeyChildProactively, func(err error) bool { return err == nil }},
		{"run by the schedule", s.RekeyChild, func(err error) bool { return err != nil }},
	} {
		asked := make(chan error, 1)
		go func() { asked <- ask.run() }()
		select {
		case request := <-s.requests:
			request.result <- requestResult{err: errors.New("the test ends this exchange")}
			<-asked
			t.Errorf("a rekey %s right after a failed one started an exchange", ask.name)
		case err := <-asked:
			if !ask.held(err) {
				t.Errorf("a rekey %s right after a failed one returned %v", ask.name, err)
			}
		case <-time.After(answerBudget):
			t.Fatalf("a rekey %s right after a failed one never returned", ask.name)
		}
	}
}
