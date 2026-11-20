// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ike

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"ranet3.com/pkgs/ranet3/esp"
	"ranet3.com/pkgs/ranet3/internal/bubble"
	"ranet3.com/pkgs/ranet3/internal/logtest"
	"ranet3.com/pkgs/ranet3/transport"
)

// the times of the tests of a simultaneous IKE SA rekey, on a bubble's clock
const (
	// crossingQuiet is how long the session runs before the responder's first rekey and again after it
	crossingQuiet = busyRequestBudget / 2
	// crossingStep is the wait for every goroutine to act on what the test or the path just did
	crossingStep = time.Second
	// crossingAnswersLost is how long after the crossing the path loses the answers to rekeys, past the 120 s an end held the other's candidate before
	crossingAnswersLost = retainedContextDeadline + 2*time.Second
	// crossingAnswersLostBriefly is how long the path loses them where the crossing must not outlast that 120 s
	crossingAnswersLostBriefly = retainedContextDeadline / 2
	// crossingDecidedWithin bounds the wait for an end whose answers pass to take one, the longest wait between two sends and a step
	crossingDecidedWithin = requestTimeout<<(maxRetransmits-1) + crossingStep
	// crossingMirrorLost is how long past the responder's decision the path loses its answers and its Delete, past the 120 s it keeps the crossed SA after its unanswered Delete
	crossingMirrorLost = retainedContextDeadline + 10*time.Second
	// crossingRefusalLost is how long the path loses the refusal of the initiator's crossing rekey, past the 120 s the refusing end kept the crossed SA before and inside the initiator's resends
	crossingRefusalLost = busyRequestBudget / 2
	// crossingStreakSurvived is the longest loss of that refusal, from the passing of the initiator's request, that lets the initiator take it before the responder's Child SA rekey has drawn TEMPORARY_FAILURE for temporaryFailureSpan at a retry, its retries unjittered
	crossingStreakSurvived = 315 * time.Second
	// crossingStreakEnds loses the initiator's resend that the shorter loss let through, which comes one second after the shorter loss ends, and ends half a second past it so the two never fall on one instant
	crossingStreakEnds = crossingStreakSurvived + 3*time.Second/2
	// crossingLastResend is when the initiator's last resend of its crossing rekey comes after the release, the last of maxRetransmitsWhileBusy sends, 510 s after its first
	crossingLastResend = 508 * time.Second
	// crossingChildAnswersLost is how long the path loses every answer to a rekey sent to the responder from the start of its Child SA rekey, past the 120 s an end keeps a replaced SA after its rekey
	crossingChildAnswersLost = retainedContextDeadline + 6*time.Second
	// crossingSettled is how long after the losses end the test leaves both ends, past every resend budget and every retention
	crossingSettled = busyRequestBudget + retainedContextDeadline
	// crossingESPEvery is how often authenticated ESP passes each way, well inside the liveness interval
	crossingESPEvery = defaultDPDInterval / 4
)

// crossingPacket is the inner packet the test passes under the Child SAs, an IPv4 header between two documentation addresses
var crossingPacket = []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2}

// crossingNonce is a nonce of nonceLen octets of b, so the crossing's four nonces order by b
func crossingNonce(b byte) []byte { return bytes.Repeat([]byte{b}, nonceLen) }

// RFC 7296 section 2.8.2: "The new IKE SA containing the lowest nonce SHOULD be deleted by the node that created it, and the other surviving new IKE SA MUST inherit all the Child SAs."
// section 2.25.2: "it SHOULD reply as usual, and SHOULD prepare to close redundant SAs and move inherited Child SAs later based on the nonces"
// both ends rekey the IKE SA at once, each answering the other's rekey while its own runs, and the path loses every answer to a rekey either way past the 120 s an end held the other's candidate before
// then the answers pass to the initiator first, to the responder first, or to both at once, with the winner set by the nonces
// authenticated ESP flows throughout, so each end resends its rekey for a busy peer's budget
// once every budget has run out, both sessions run on the winner's candidate, both rekeys returned nil, and that SA carries an exchange each way
func TestSimultaneousRekeyWithAnswersLostPastTheCollisionRetentionConverges(t *testing.T) {
	for _, initiatorWins := range []bool{true, false} {
		for _, first := range []string{"initiator", "responder", "both"} {
			winner, reach := "responder", "the "+first+" first"
			if initiatorWins {
				winner = "initiator"
			}
			if first == "both" {
				reach = "both ends at once"
			}
			t.Run(fmt.Sprintf("%s wins and answers reach %s", winner, reach), bubble.Run(func(t *testing.T) {
				testSimultaneousRekeyWithAnswersLostPastTheCollisionRetentionConverges(t, initiatorWins, first)
			}))
		}
	}
}

func testSimultaneousRekeyWithAnswersLostPastTheCollisionRetentionConverges(t *testing.T, initiatorWins bool, first string) {
	c := startCrossing(t, initiatorWins, crossingLosses{toInitiator: true, toResponder: true})
	c.mustHoldCrossing(t)
	time.Sleep(crossingAnswersLost)
	switch first {
	case "initiator":
		c.path.loseAnswers(false, true)
		c.decided(t, c.initiator, "initiator")
	case "responder":
		c.path.loseAnswers(true, false)
		c.decided(t, c.responder, "responder")
	}
	c.path.loseAnswers(false, false)
	time.Sleep(crossingSettled)
	synctest.Wait()
	c.converged(t)
}

// the responder wins a crossing and decides first, since its answer passes, while the path loses its answers to the initiator's resends and its Delete of the crossed SA, for longer than it keeps that SA after its unanswered Delete
// the initiator's resends then draw the answer the responder keeps on the crossed SA for them, and both sessions run on the responder's candidate
func TestSimultaneousRekeyWonWithTheDeleteOfTheCrossedSALostConverges(t *testing.T) {
	bubble.Run(testSimultaneousRekeyWonWithTheDeleteOfTheCrossedSALostConverges)(t)
}

func testSimultaneousRekeyWonWithTheDeleteOfTheCrossedSALostConverges(t *testing.T) {
	c := startCrossing(t, false, crossingLosses{toInitiator: true, staleRequests: true})
	c.decided(t, c.responder, "responder")
	if !c.holdsCandidate(c.responder, c.candidates[0]) {
		t.Fatal("the responder decided holding no candidate of the initiator's, so the rekeys did not cross")
	}
	if held, _ := holdsCrossing(c.initiator, c.nonces[1]); !held {
		t.Fatal("the initiator does not hold the responder's rekey as the collision of its own")
	}
	time.Sleep(crossingMirrorLost)
	c.path.loseAnswers(false, false)
	c.path.loseStaleRequests(false)
	time.Sleep(crossingSettled)
	synctest.Wait()
	c.converged(t)
}

// the responder takes the answer to its rekey before the initiator's crossing request reaches it, so it decides with no crossing, refuses that request and sends its Delete of the crossed SA
// the path loses the refusal, its repeats and that Delete past the 120 s the responder kept the crossed SA before, while the responder's Child SA rekey draws the initiator's refusals, the initiator holding the responder's SA undecided
// the initiator's resends then draw the refusal the responder keeps on the crossed SA for them, the initiator takes the responder's SA, its first fresh request there ends what the responder keeps for them, and both sessions run on the responder's SA
func TestRefusalOfACrossingRekeyLostPastTheRetentionConverges(t *testing.T) {
	bubble.Run(testRefusalOfACrossingRekeyLostPastTheRetentionConverges)(t)
}

func testRefusalOfACrossingRekeyLostPastTheRetentionConverges(t *testing.T) {
	c := startCrossing(t, false, crossingLosses{toInitiator: true, staleRequests: true, initiatorRequestHeld: true})
	released, childRekeyed := c.refusedWithChildRekey(t)
	time.Sleep(time.Until(released.Add(crossingRefusalLost)))
	c.path.loseAnswers(false, false)
	c.path.loseStaleRequests(false)
	for deadline := time.Now().Add(crossingDecidedWithin); c.initiator.currentContext().spiI == c.crossed.spiI; time.Sleep(crossingStep) {
		if !time.Now().Before(deadline) {
			_, old := c.responder.contexts()
			t.Fatalf("the initiator took no answer within %v of the refusal passing, and the responder holds the crossed SA %v", crossingDecidedWithin, old != nil && old.spiI == c.crossed.spiI)
		}
	}
	if _, err := c.initiator.request(INFORMATIONAL, nil); err != nil {
		t.Fatalf("the initiator's first request on the responder's SA failed: %v", err)
	}
	time.Sleep(crossingStep)
	synctest.Wait()
	if _, old := c.responder.contexts(); old != nil && old.spiI == c.crossed.spiI {
		t.Errorf("the responder holds the crossed SA %016x after the initiator's first fresh request on the responder's SA", old.spiI)
	}
	time.Sleep(crossingSettled)
	synctest.Wait()
	c.converged(t)
	c.childRekeyEnded(t, childRekeyed)
	// the initiator's resends past the retention drew the kept refusal, told once
	if got := recordedKind(c.responderEvents, "ike.rekey.repeat_answered"); got != 1 {
		t.Errorf("the responder told %d repeats of the initiator's rekey answered past the retention, want 1: %q", got, c.responderEvents.recorded())
	}
}

// the crossing above with no Child SA rekey of the responder's, the refusal lost to either side of the initiator's last resend
// the record keeps the refusal to busyRequestBudget after the initiator's first send, past that resend, so a loss that ends crossingStep before it converges, and one that ends crossingStep after it loses that last send, and the initiator's session ends with no answer to its resends
func TestRefusalLostToTheLastResendOfTheCrossingRekey(t *testing.T) {
	for _, test := range []struct {
		name string
		loss time.Duration
		ends bool
	}{
		{name: "lost to a second before the last resend converges", loss: crossingLastResend - crossingStep},
		{name: "lost to a second after it ends the initiator's session", loss: crossingLastResend + crossingStep, ends: true},
	} {
		t.Run(test.name, bubble.Run(func(t *testing.T) {
			c := startCrossing(t, false, crossingLosses{toInitiator: true, staleRequests: true, initiatorRequestHeld: true})
			released := c.refused(t)
			time.Sleep(time.Until(released.Add(test.loss)))
			c.path.loseAnswers(false, false)
			c.path.loseStaleRequests(false)
			if !test.ends {
				time.Sleep(crossingSettled)
				synctest.Wait()
				c.converged(t)
				return
			}
			select {
			case err := <-c.runs[0]:
				if want := fmt.Sprintf("peer unresponsive after %d attempts", maxRetransmitsWhileBusy); !strings.Contains(fmt.Sprint(err), want) {
					t.Fatalf("the initiator's session ended %v after the release with %v, want %q", time.Since(released), err, want)
				}
			case <-time.After(crossingSettled):
				t.Fatalf("the initiator's session runs %v after the release, its last resend lost", time.Since(released))
			}
		}))
	}
}

// the crossing of TestRefusalOfACrossingRekeyLostPastTheRetentionConverges, where the initiator answers the responder's Child SA rekey TEMPORARY_FAILURE while its own crossing rekey holds the responder's SA undecided
// RFC 7296 section 2.25.1: "If a peer receives a request to rekey a Child SA that it is currently trying to close, it SHOULD reply with TEMPORARY_FAILURE."
// that refusal moves no IKE SA and is not kept: lost with every answer to the responder for crossingChildAnswersLost from the Child SA rekey's start, or not lost, the Child SA rekey ends with it and both sessions run on the responder's SA
func TestChildSARefusalDuringTheCrossingRekeyLeavesBothOnOneSA(t *testing.T) {
	for _, lost := range []time.Duration{0, crossingChildAnswersLost} {
		t.Run(fmt.Sprintf("answers to the responder lost %v", lost), bubble.Run(func(t *testing.T) {
			c := startCrossing(t, false, crossingLosses{toInitiator: true, staleRequests: true, initiatorRequestHeld: true})
			released, childRekeyed := c.refusedWithChildRekey(t)
			if lost > 0 {
				c.path.loseAnswers(true, true)
				time.Sleep(lost)
				c.path.loseAnswers(true, false)
			}
			time.Sleep(time.Until(released.Add(crossingRefusalLost)))
			c.path.loseAnswers(false, false)
			c.path.loseStaleRequests(false)
			time.Sleep(crossingSettled)
			synctest.Wait()
			select {
			case err := <-childRekeyed:
				if !rejectedWith(err, N_TEMPORARY_FAILURE) {
					t.Fatalf("the responder's Child SA rekey ended with %v, want the initiator's TEMPORARY_FAILURE", err)
				}
			default:
				t.Fatal("the responder's Child SA rekey still runs once every budget ran out")
			}
			c.converged(t)
		}))
	}
}

// RFC 7296 section 2.25: "If a peer continues to receive TEMPORARY_FAILURE on the same IKE SA after several minutes, it SHOULD conclude that the state information is out of sync and close the IKE SA."
// the crossing above with the refusal lost longer: the initiator takes the refusal at its first resend after the loss, and until then the responder's Child SA rekey draws TEMPORARY_FAILURE, its retries unjittered
// so the record keeps the refusal only as long as the responder's run of refusals stays short of temporaryFailureSpan at each retry
// a loss of crossingStreakSurvived lets the initiator's resend before that retry through and both sessions converge, and a loss of crossingStreakEnds loses that resend, so the responder ends its session for the run of refusals and the initiator's session then ends with no answer to its resends
func TestRefusalLostAgainstTheTemporaryFailureSpanOfAChildSARekey(t *testing.T) {
	for _, test := range []struct {
		name string
		loss time.Duration
		ends bool
	}{
		{name: "lost to the last resend that comes in time converges", loss: crossingStreakSurvived},
		{name: "lost one second longer ends at the run of refusals", loss: crossingStreakEnds, ends: true},
	} {
		t.Run(test.name, bubble.Run(func(t *testing.T) {
			c := startCrossing(t, false, crossingLosses{toInitiator: true, staleRequests: true, initiatorRequestHeld: true})
			released, childRekeyed := c.refusedWithChildRekey(t)
			time.Sleep(time.Until(released.Add(test.loss)))
			c.path.loseAnswers(false, false)
			c.path.loseStaleRequests(false)
			if !test.ends {
				time.Sleep(crossingSettled)
				synctest.Wait()
				c.converged(t)
				c.childRekeyEnded(t, childRekeyed)
				return
			}
			var ended [2]time.Time
			var errs [2]error
			for deadline := time.Now().Add(crossingSettled); (ended[0].IsZero() || ended[1].IsZero()) && time.Now().Before(deadline); time.Sleep(crossingStep) {
				for i, run := range c.runs {
					if ended[i].IsZero() {
						select {
						case errs[i] = <-run:
							ended[i] = time.Now()
						default:
						}
					}
				}
			}
			if ended[1].IsZero() || !rejectedWith(errs[1], N_TEMPORARY_FAILURE) || !strings.Contains(errs[1].Error(), temporaryFailureSpan.String()) {
				t.Fatalf("the responder's session ended %v after the release with %v, want an end for TEMPORARY_FAILURE answered for %v", ended[1].Sub(released), errs[1], temporaryFailureSpan)
			}
			if want := fmt.Sprintf("peer unresponsive after %d attempts", maxRetransmitsWhileBusy); ended[0].IsZero() || ended[0].Before(ended[1]) || !strings.Contains(fmt.Sprint(errs[0]), want) {
				t.Errorf("the initiator's session ended %v after the release with %v, want %q after the responder's end at %v", ended[0].Sub(released), errs[0], want, ended[1].Sub(released))
			}
		}))
	}
}

// refusedWithChildRekey is refused, then starts the responder's Child SA rekey with its retries unjittered
// it returns when it passed the request on and the end of that Child SA rekey's first exchange
func (c *crossingRun) refusedWithChildRekey(t *testing.T) (time.Time, <-chan error) {
	t.Helper()
	released := c.refused(t)
	childRekeyed := make(chan error, 1)
	go func() { childRekeyed <- c.responder.RekeyChild() }()
	return released, childRekeyed
}

// refused checks that the responder decided its rekey before the initiator's crossing request reached it while the initiator holds the responder's rekey as its collision, passes that request on, and waits for the responder's rekey to return
// it returns when it passed the request on
func (c *crossingRun) refused(t *testing.T) time.Time {
	t.Helper()
	if held, _ := holdsCrossing(c.initiator, c.nonces[1]); !held {
		t.Fatal("the initiator does not hold the responder's rekey as the collision of its own")
	}
	if c.holdsCandidate(c.responder, c.candidates[0]) || c.responder.currentContext().spiI != c.candidates[1] {
		t.Fatal("the responder did not decide its rekey before the initiator's request reached it")
	}
	c.responder.rekeyJitterSource = unjittered
	c.path.holdRekeysFrom(false, false)
	released := time.Now()
	// the responder's rekey holds the session's requests until its Delete of the crossed SA is given up
	select {
	case err := <-c.rekeyed[1]:
		if c.rekeyed[1] = nil; err != nil {
			t.Fatalf("the responder's rekey ended with %v", err)
		}
	case <-time.After(crossingDecidedWithin):
		t.Fatal("the responder's rekey still runs its Delete of the crossed SA")
	}
	return released
}

// childRekeyEnded fails t unless the first exchange of the responder's Child SA rekey, which ends on childRekeyed, ended once every budget ran out
func (c *crossingRun) childRekeyEnded(t *testing.T, childRekeyed <-chan error) {
	t.Helper()
	select {
	case <-childRekeyed:
	default:
		t.Error("the responder's Child SA rekey still runs once every budget ran out")
	}
}

// the winner of a crossing holds the loser's candidate for the loser's Delete of it, which a loser that adopted the winner's candidate on the winner's Delete never sends, since it never took the answer that made it
// the candidate is held while the winner's rekey runs, for retainedContextDeadline from that rekey's return, and then dropped with a warning that names that bound
func TestCrossingCandidateThePeerNeverDeletesGoesAtTheRetentionAfterTheRekey(t *testing.T) {
	bubble.Run(testCrossingCandidateThePeerNeverDeletesGoesAtTheRetentionAfterTheRekey)(t)
}

func testCrossingCandidateThePeerNeverDeletesGoesAtTheRetentionAfterTheRekey(t *testing.T) {
	lines := recordLines(t)
	c := startCrossing(t, true, crossingLosses{toInitiator: true, toResponder: true})
	c.mustHoldCrossing(t)
	time.Sleep(crossingAnswersLostBriefly)
	c.path.loseAnswers(false, true)
	var returned time.Time
	select {
	case err := <-c.rekeyed[0]:
		returned, c.rekeyed[0] = time.Now(), nil
		if err != nil {
			t.Fatalf("the initiator's crossing rekey ended with %v", err)
		}
	case <-time.After(crossingDecidedWithin + answerBudget):
		t.Fatal("the initiator's crossing rekey still runs once its answers pass")
	}
	c.path.loseAnswers(false, false)
	if loser := c.responder.currentContext(); loser.spiI != c.candidates[0] {
		t.Fatalf("the responder is current on %016x, want the initiator's candidate %016x it adopts on the initiator's Delete", loser.spiI, c.candidates[0])
	}

	time.Sleep(time.Until(returned.Add(retainedContextDeadline - crossingStep)))
	synctest.Wait()
	if !c.holdsCandidate(c.initiator, c.candidates[1]) {
		t.Fatalf("the initiator dropped the responder's candidate %v after its rekey returned, want it held %v", time.Since(returned), retainedContextDeadline)
	}
	time.Sleep(crossingStep)
	synctest.Wait()
	if c.holdsCandidate(c.initiator, c.candidates[1]) {
		t.Fatalf("the initiator still holds the responder's candidate %v after its rekey returned", time.Since(returned))
	}
	want := retainedContextDeadline.String() + " after this end's crossing rekey ended"
	told := lines.said(slog.LevelWarn, "ike dropping an IKE SA the peer never deleted", "at")
	if len(told) != 1 || told[0].String() != want {
		t.Errorf("the initiator warned of the dropped candidate at %v, want once at %q", told, want)
	}
}

// the initiator loses a crossing, and the responder's Delete of the crossed SA reaches it after its rekey decided it lost and before that rekey gives way, the rekey held at its line meanwhile
// the Delete makes the responder's candidate current and releases the crossed SA, and the rekey then gives way without holding that SA again, so no warning comes 2 minutes later of an SA the peer never deleted
func TestPeerDeleteBetweenTheLostDecisionAndTheYieldLeavesTheCrossedSAReleased(t *testing.T) {
	bubble.Run(testPeerDeleteBetweenTheLostDecisionAndTheYieldLeavesTheCrossedSAReleased)(t)
}

func testPeerDeleteBetweenTheLostDecisionAndTheYieldLeavesTheCrossedSAReleased(t *testing.T) {
	lines := parkLines(t, "ike simultaneous rekey selected peer candidate")
	c := startCrossing(t, false, crossingLosses{staleRequests: true})
	select {
	case <-lines.parked:
	default:
		t.Fatal("the initiator's rekey did not reach its lost decision")
	}
	c.path.loseStaleRequests(false)
	time.Sleep(crossingDecidedWithin)
	synctest.Wait()
	if current := c.initiator.currentContext(); current.spiI != c.candidates[c.winner] {
		t.Fatalf("the responder's Delete of the crossed SA left the initiator current on %016x, want the responder's candidate %016x", current.spiI, c.candidates[c.winner])
	}
	lines.unpark()
	time.Sleep(crossingStep)
	synctest.Wait()
	if _, old := c.initiator.contexts(); old != nil && old.spiI == c.crossed.spiI {
		t.Errorf("the initiator holds the crossed SA %016x again after it gave way, which the responder deleted", old.spiI)
	}
	time.Sleep(crossingSettled)
	synctest.Wait()
	if never := lines.said(slog.LevelWarn, "ike dropping an IKE SA the peer never deleted", "after"); len(never) != 0 {
		t.Errorf("the initiator warned %d times of an SA the peer never deleted", len(never))
	}
	c.converged(t)
	c.settledOnce(t, &lines.lineRecorder)
}

// the peer's Delete of the crossed SA reaches the end whose own rekey the crossing leaves on the peer's candidate wholly before that rekey's decision or wholly after it, where the mover is the yield of a lost crossing or the swap of a refusal from a peer that decided before this end's request reached it
// the Delete before the decision makes the peer's candidate current and the rekey returns nil, and the Delete after it retires the crossed SA, which the decision held
// where the peer decided first, the Delete before the refusal ends this end's request at the adoption, so that order reads no refusal
// in each order that end logs the peer's candidate selected once and records one completed rekey, and both ends run on the peer's candidate
func TestPeerDeleteOfTheCrossedSABeforeOrAfterTheDecisionSettlesOnce(t *testing.T) {
	for _, test := range []struct {
		name            string
		losses          crossingLosses
		before, refused bool
	}{
		{name: "yield with the Delete before the decision", losses: crossingLosses{toInitiator: true}, before: true},
		{name: "yield with the Delete after the decision", losses: crossingLosses{staleRequests: true}},
		{name: "adoption with the Delete before the refusal is read", losses: crossingLosses{initiatorRequestHeld: true}, before: true, refused: true},
		{name: "refusal with the Delete after the decision", losses: crossingLosses{staleRequests: true, initiatorRequestHeld: true}, refused: true},
	} {
		t.Run(test.name, bubble.Run(func(t *testing.T) {
			lines := recordLines(t)
			c := startCrossing(t, false, test.losses)
			if test.refused {
				if held, _ := holdsCrossing(c.initiator, c.nonces[1]); !held && !test.before {
					t.Fatal("the initiator does not hold the responder's rekey as the collision of its own")
				}
				if c.holdsCandidate(c.responder, c.candidates[0]) || c.responder.currentContext().spiI != c.candidates[1] {
					t.Fatal("the responder did not decide its rekey before the initiator's request reached it")
				}
				// no time passes, so the losses end before the second and last send of the responder's Delete
				c.path.holdRekeysFrom(false, false)
				synctest.Wait()
			}
			current, old := c.initiator.contexts()
			if current.spiI != c.candidates[c.winner] {
				t.Fatalf("the initiator is current on %016x before the losses end, want the responder's candidate %016x", current.spiI, c.candidates[c.winner])
			}
			if crossedHeld := old != nil && old.spiI == c.crossed.spiI; crossedHeld == test.before {
				t.Fatalf("the initiator holds the crossed SA %v before the losses end, want %v", crossedHeld, !test.before)
			}
			c.path.loseAnswers(false, false)
			c.path.loseStaleRequests(false)
			time.Sleep(crossingSettled)
			synctest.Wait()
			c.converged(t)
			c.settledOnce(t, lines)
			retired := 0
			for _, line := range c.events.recorded() {
				if strings.HasPrefix(line, "ike.sa.retired ") && strings.Contains(line, fmt.Sprintf("spi=%016x", c.crossed.spiI)) && strings.Contains(line, "reason=deleted") {
					retired++
				}
			}
			want := 1
			if test.before {
				want = 0
			}
			if retired != want {
				t.Errorf("the initiator told the crossed SA %016x retired as deleted %d times, want %d: %q", c.crossed.spiI, retired, want, c.events.recorded())
			}
		}))
	}
}

// settledOnce fails t unless lines hold one line of the peer's candidate selected and the initiator recorded one completed IKE SA rekey and no failed one, the line written by the initiator alone where the responder wins or decides with no crossing
func (c *crossingRun) settledOnce(t *testing.T, lines *lineRecorder) {
	t.Helper()
	if selected := lines.said(slog.LevelInfo, "ike simultaneous rekey selected peer candidate", ""); len(selected) != 1 {
		t.Errorf("the initiator logged the peer's candidate selected %d times, want once", len(selected))
	}
	completed, failed := 0, 0
	for _, line := range c.events.recorded() {
		switch {
		case strings.HasPrefix(line, "ike.rekey.completed ") && strings.Contains(line, "sa=ike"):
			completed++
		case strings.HasPrefix(line, "ike.rekey.failed ") && strings.Contains(line, "sa=ike"):
			failed++
		}
	}
	if completed != 1 || failed != 0 {
		t.Errorf("the initiator recorded ike.rekey.completed %d times and ike.rekey.failed %d times, want once and never", completed, failed)
	}
}

// parkedLines keeps every line as lineRecorder does, and holds the goroutine that first logs park until unpark
type parkedLines struct {
	lineRecorder
	park     string
	parked   chan struct{}
	release  chan struct{}
	first    sync.Once
	released sync.Once
}

// parkLines makes a new parkedLines the default until the test ends, and unparks it then
func parkLines(t *testing.T, park string) *parkedLines {
	t.Helper()
	p := &parkedLines{park: park, parked: make(chan struct{}), release: make(chan struct{})}
	logtest.SetDefault(t, slog.New(p))
	t.Cleanup(p.unpark)
	return p
}

func (p *parkedLines) unpark() { p.released.Do(func() { close(p.release) }) }

func (p *parkedLines) Handle(ctx context.Context, r slog.Record) error {
	_ = p.lineRecorder.Handle(ctx, r)
	held := false
	if r.Message == p.park {
		p.first.Do(func() { held = true })
	}
	if held {
		close(p.parked)
		<-p.release
	}
	return nil
}
func (p *parkedLines) WithAttrs([]slog.Attr) slog.Handler { return p }
func (p *parkedLines) WithGroup(string) slog.Handler      { return p }

// crossingRun is two ends of one session that rekey the IKE SA the responder's first rekey made at once, each answering the other's rekey
type crossingRun struct {
	initiator, responder *Session
	runs                 [2]<-chan error
	// rekeyed carries the end of each end's crossing rekey, the initiator's first, nil once the test took it
	rekeyed    [2]chan error
	path       *crossingPath
	espFailure func() error
	crossed    *ikeContext
	// candidates is the SPI each end's own rekey makes its SA under, the initiator's first, and winner indexes the end the nonces settle the crossing for
	candidates [2]uint64
	winner     int
	// nonces is each end's Ni in the crossing, the initiator's first
	nonces [2][]byte
	// events keeps what the initiator records, and responderEvents what the responder records
	events, responderEvents *recorder
}

// crossingLosses says whether the path loses the answers to rekeys sent to the initiator, those sent to the responder, and the responder's INFORMATIONAL requests on any IKE SA but its current one, from before the crossing's requests pass, and whether it holds the initiator's rekey request once the responder's passes
type crossingLosses struct{ toInitiator, toResponder, staleRequests, initiatorRequestHeld bool }

// startCrossing runs a session through the responder's first rekey, then starts both ends' rekeys of its replacement with the path holding both requests until both rekeys are recorded, and passes them on with losses in force
// the initiator's exchange holds the lowest nonce unless initiatorWins, so the end whose exchange does not wins
func startCrossing(t *testing.T, initiatorWins bool, losses crossingLosses) *crossingRun {
	t.Helper()
	responderEvents := &recorder{}
	h := newResponderHarness(t, nil, responderEvents.record)
	path := &crossingPath{}
	cfg := h.peerConfig()
	cfg.RemotePort = path.listen(t, h.remotePort)
	events := &recorder{}
	cfg.Events = events.record
	initiator, responder := dialPaused(t, h, cfg)
	path.responderSession.Store(responder)
	draws := [2]*crossingDraws{{}, {}}
	initiator.ikeRekeyNonce, responder.ikeRekeyNonce = draws[0].draw, draws[1].draw
	c := &crossingRun{initiator: initiator, responder: responder, path: path, events: events, responderEvents: responderEvents}
	c.runs = [2]<-chan error{runSession(t, initiator), runSession(t, responder)}
	c.espFailure = crossingESP(t, initiator, responder)

	time.Sleep(crossingQuiet)
	responderRekeyed := make(chan error, 1)
	go func() { responderRekeyed <- responder.RekeyIKE() }()
	time.Sleep(crossingQuiet)
	synctest.Wait()
	select {
	case err := <-responderRekeyed:
		if err != nil {
			t.Fatalf("the responder's first IKE SA rekey failed: %v", err)
		}
	default:
		t.Fatalf("the responder's first IKE SA rekey still ran %v after it began", crossingQuiet)
	}
	if same, ends := crossingCurrent(initiator, responder); !same {
		t.Fatalf("before the crossing %s", ends)
	}
	c.crossed = initiator.currentContext()

	// each end draws its Ni for its own rekey and then its Nr for its answer to the peer's
	// the loser's Ni is the lowest of the four, so the loser's exchange holds it
	loser, winner := 0, 1
	if initiatorWins {
		loser, winner = 1, 0
	}
	c.winner = winner
	c.nonces[loser], c.nonces[winner] = crossingNonce(1), crossingNonce(2)
	draws[loser].arm(c.nonces[loser], crossingNonce(4))
	draws[winner].arm(c.nonces[winner], crossingNonce(3))

	path.loseAnswers(losses.toInitiator, losses.toResponder)
	path.loseStaleRequests(losses.staleRequests)
	path.holdRekeys(true)
	c.rekeyed = [2]chan error{make(chan error, 1), make(chan error, 1)}
	for i, s := range []*Session{initiator, responder} {
		go func() { c.rekeyed[i] <- s.RekeyIKE() }()
	}
	time.Sleep(crossingStep)
	synctest.Wait()
	for i, s := range []*Session{initiator, responder} {
		s.stateMu.RLock()
		local := s.localRekey
		s.stateMu.RUnlock()
		if local == nil || local.old.spiI != c.crossed.spiI {
			t.Fatalf("end %d runs no rekey of the IKE SA %016x while the path holds both requests", i, c.crossed.spiI)
		}
		c.candidates[i] = local.spiI
	}
	path.holdRekeysFrom(losses.initiatorRequestHeld, false)
	time.Sleep(crossingStep)
	synctest.Wait()
	return c
}

// mustHoldCrossing fails t unless each end runs its own rekey of the crossed SA and holds the other's rekey of it as the collision, with the other's Ni
func (c *crossingRun) mustHoldCrossing(t *testing.T) {
	t.Helper()
	for i, s := range []*Session{c.initiator, c.responder} {
		held, current := holdsCrossing(s, c.nonces[1-i])
		if !held {
			t.Fatalf("end %d does not hold the other's rekey as the collision of its own, and is current on %016x, crossed %016x", i, current, c.crossed.spiI)
		}
	}
}

// holdsCrossing reports whether s runs its own rekey of its current IKE SA and holds the peer's rekey of that SA as the collision, its Ni peerNi, and names the SA s is current on
func holdsCrossing(s *Session, peerNi []byte) (bool, uint64) {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	local := s.localRekey
	return local != nil && local.old == s.current && s.collision != nil && !s.collision.ownDelete && bytes.Equal(local.peerNonce, peerNi), s.current.spiI
}

// holdsCandidate reports whether s holds the SA candidate names, the peer's, as the collision
func (c *crossingRun) holdsCandidate(s *Session, candidate uint64) bool {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return s.collision != nil && !s.collision.ownDelete && s.collision.spiI == candidate
}

// decided waits until s, the end name says, is current on an SA other than the crossed one
func (c *crossingRun) decided(t *testing.T, s *Session, name string) {
	t.Helper()
	deadline := time.Now().Add(crossingDecidedWithin)
	for s.currentContext().spiI == c.crossed.spiI {
		if !time.Now().Before(deadline) {
			t.Fatalf("the %s took no answer within %v of its answers passing", name, crossingDecidedWithin)
		}
		time.Sleep(crossingStep)
	}
}

// converged fails t unless both sessions run, current on the winner's candidate, each crossing rekey returned nil, and ESP and an exchange pass each way
func (c *crossingRun) converged(t *testing.T) {
	t.Helper()
	names := [2]string{"initiator", "responder"}
	var rekeys [2]error
	var outcome [2]string
	for i, done := range c.rekeyed {
		if done == nil {
			outcome[i] = "returned"
			continue
		}
		select {
		case rekeys[i] = <-done:
			outcome[i] = fmt.Sprintf("ended with %v", rekeys[i])
		case <-time.After(answerBudget):
			t.Fatalf("the %s's crossing rekey still ran once every budget ran out", names[i])
		}
	}
	where := fmt.Sprintf("the initiator's crossing rekey %s and the responder's %s", outcome[0], outcome[1])
	var ended [2]error
	for i, run := range c.runs {
		select {
		case err := <-run:
			ended[i] = fmt.Errorf("ended with %w", err)
		default:
		}
	}
	switch {
	case ended[0] != nil && ended[1] != nil:
		t.Fatalf("both sessions ended, the initiator's %v and the responder's %v, where %s", ended[0], ended[1], where)
	case ended[0] != nil:
		t.Fatalf("the initiator's session %v and the responder's runs on, where %s", ended[0], where)
	case ended[1] != nil:
		t.Fatalf("the responder's session %v and the initiator's runs on, where %s", ended[1], where)
	}
	same, ends := crossingCurrent(c.initiator, c.responder)
	if !same {
		t.Fatalf("both sessions run and the ends sit on different IKE SAs: %s, where %s", ends, where)
	}
	switch current := c.initiator.currentContext().spiI; current {
	case c.candidates[c.winner]:
	case c.crossed.spiI:
		t.Fatalf("both ends stay on the crossed IKE SA %016x, where %s", current, where)
	default:
		t.Fatalf("both ends are current on %016x and the winner's candidate is %016x, where %s", current, c.candidates[c.winner], where)
	}
	for i, err := range rekeys {
		if err != nil {
			t.Errorf("the %s's crossing rekey ended with %v, want nil once the crossing settled", names[i], err)
		}
	}
	if err := c.espFailure(); err != nil {
		t.Errorf("ESP under the inherited Child SAs failed: %v", err)
	}
	for _, way := range []struct {
		name     string
		from, to *Session
	}{{"initiator", c.initiator, c.responder}, {"responder", c.responder, c.initiator}} {
		if err := crossingPasses(way.from, way.to); err != nil {
			t.Errorf("ESP from the %s failed: %v", way.name, err)
		}
		if _, err := way.from.request(INFORMATIONAL, nil); err != nil {
			t.Errorf("an exchange from the %s on the current IKE SA failed: %v", way.name, err)
		}
	}
	stillRunning(t, c.runs[0])
	stillRunning(t, c.runs[1])
}

// crossingDraws hands an end's rekeys the nonces arm queued, in order, and random ones once none are queued
type crossingDraws struct {
	mu     sync.Mutex
	queued [][]byte
}

func (d *crossingDraws) arm(nonces ...[]byte) {
	d.mu.Lock()
	d.queued = append(d.queued, nonces...)
	d.mu.Unlock()
}

func (d *crossingDraws) draw(n []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.queued) == 0 {
		return randomIKERekeyNonce(n)
	}
	copy(n, d.queued[0])
	d.queued = d.queued[1:]
	return nil
}

// crossingCurrent reports whether initiator and responder, the two ends of one session, are current on one IKE SA, each in its own role, and names the SA each is current on
func crossingCurrent(initiator, responder *Session) (bool, string) {
	current, peer := initiator.currentContext(), responder.currentContext()
	same := current.spiI == peer.spiI && current.spiR == peer.spiR && current.responder != peer.responder &&
		bytes.Equal(current.skD, peer.skD) && bytes.Equal(current.skei, peer.skei) && bytes.Equal(current.sker, peer.sker)
	return same, fmt.Sprintf("the initiator is current on the IKE SA %016x/%016x and the responder on %016x/%016x", current.spiI, current.spiR, peer.spiI, peer.spiR)
}

// crossingPasses seals crossingPacket under from's Child SA and opens it under to's, or under the one to retires where from still seals under that one, as the dataplane does, and tells to of the authenticated traffic
func crossingPasses(from, to *Session) error {
	out := from.Child()
	in, retiring := to.Child(), to.retiringChild()
	if retiring.LocalSPI != 0 && retiring.LocalSPI == out.RemoteSPI {
		in = retiring
	}
	return crossingPassesUnder(to, out, in)
}

// crossingPassesUnder seals crossingPacket under out and opens it under in, to's inbound Child SA, and tells to of the authenticated traffic
func crossingPassesUnder(to *Session, outSA, inSA ChildSA) error {
	out, err := esp.NewOutbound(outSA)
	if err != nil {
		return err
	}
	in, err := esp.NewInbound(inSA)
	if err != nil {
		return err
	}
	sealed, err := out.Seal(crossingPacket, esp.NextHeaderIPv4)
	if err != nil {
		return err
	}
	plain, _, err := in.Open(sealed)
	if err != nil {
		return err
	}
	if !bytes.Equal(plain, crossingPacket) {
		return errors.New("the packet opened is not the packet sealed")
	}
	to.NoteTraffic()
	return nil
}

// crossingESP passes authenticated ESP each way between a and b every crossingESPEvery, opened under the receiver's retiring Child SA where the sender still seals under it, until the test's end or the returned function stops it, which returns the first failure the flow met
func crossingESP(t *testing.T, a, b *Session) func() error {
	t.Helper()
	stop, done := make(chan struct{}), make(chan struct{})
	var failure error
	go func() {
		defer close(done)
		for {
			for _, way := range [][2]*Session{{a, b}, {b, a}} {
				// the answering end of a Child SA rekey seals under the new SA before the asking end takes the answer, so a way whose receiver holds no SA the sender seals under is passed over while either end's Child SA rekey is outstanding, or where an install at either end fell inside the reads
				generations := [2]uint64{a.currentChildGeneration(), b.currentChildGeneration()}
				rekeying := a.childRekeying.Load() || b.childRekeying.Load()
				out, in, retiring := way[0].Child(), way[1].Child(), way[1].retiringChild()
				rekeying = rekeying || a.childRekeying.Load() || b.childRekeying.Load() || generations != [2]uint64{a.currentChildGeneration(), b.currentChildGeneration()}
				if retiring.LocalSPI != 0 && retiring.LocalSPI == out.RemoteSPI {
					in = retiring
				}
				if rekeying && in.LocalSPI != out.RemoteSPI {
					continue
				}
				if err := crossingPassesUnder(way[1], out, in); err != nil && failure == nil {
					failure = fmt.Errorf("ESP at %v: %w", time.Now(), err)
				}
			}
			select {
			case <-stop:
				return
			case <-time.After(crossingESPEvery):
			}
		}
	}()
	var once sync.Once
	end := func() error {
		once.Do(func() {
			close(stop)
			<-done
		})
		return failure
	}
	t.Cleanup(func() { _ = end() })
	return end
}

// crossingPath carries UDP between the initiator and the responder
// it loses the answers to rekeys sent to either end as loseAnswers says, holds the rekey requests from each end as holdRekeysFrom says, and loses the responder's INFORMATIONAL requests on any IKE SA but its current one while loseStaleRequests is set
type crossingPath struct {
	responderSession atomic.Pointer[Session]
	conn             *transport.MemoryConn
	responder        *net.UDPAddr

	mu                       sync.Mutex
	initiator                *net.UDPAddr
	toInitiator, toResponder bool
	// holding says whether the path holds the rekey requests from the initiator and from the responder
	holding [2]bool
	stale   bool
	held    []crossingDatagram
}

// crossingDatagram is a datagram the path holds, with where it goes on to and whether it came from the initiator
type crossingDatagram struct {
	raw           []byte
	to            *net.UDPAddr
	fromInitiator bool
}

// listen starts the path to the responder at responderPort and returns the port to dial
func (p *crossingPath) listen(t *testing.T, responderPort int) int {
	t.Helper()
	conn := listenPeer(t)
	p.conn, p.responder = conn, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: responderPort}
	done := make(chan struct{})
	t.Cleanup(func() {
		conn.Close()
		<-done
	})
	go func() {
		defer close(done)
		buf := make([]byte, 65536)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			fromInitiator := from.Port != responderPort
			p.mu.Lock()
			if fromInitiator {
				p.initiator = from
			}
			to := p.initiator
			p.mu.Unlock()
			if fromInitiator {
				to = p.responder
			}
			if to == nil {
				continue
			}
			if n > NonESPMarkerLen && p.keeps(fromInitiator, buf[:n], to) {
				continue
			}
			_, _ = conn.WriteToUDP(buf[:n], to)
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr).Port
}

// keeps reports whether the path keeps datagram, which carries an IKE message after its non-ESP marker on its way to to, from going on, lost or held
func (p *crossingPath) keeps(fromInitiator bool, datagram []byte, to *net.UDPAddr) bool {
	header, err := decodeHeader(datagram[NonESPMarkerLen:])
	if err != nil {
		return false
	}
	var current uint64
	if responder := p.responderSession.Load(); responder != nil && !fromInitiator {
		current = responder.currentContext().spiI
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	switch {
	case header.ExchangeType == CREATE_CHILD_SA && header.IsResponse():
		if fromInitiator {
			return p.toResponder
		}
		return p.toInitiator
	case header.ExchangeType == CREATE_CHILD_SA && p.holding[crossingFrom(fromInitiator)]:
		p.held = append(p.held, crossingDatagram{bytes.Clone(datagram), to, fromInitiator})
		return true
	case !fromInitiator && p.stale && !header.IsResponse() && header.ExchangeType == INFORMATIONAL && header.SPIInitiator != current:
		return true
	}
	return false
}

// loseAnswers sets whether the path loses the answers to rekeys sent to the initiator and to the responder
func (p *crossingPath) loseAnswers(toInitiator, toResponder bool) {
	p.mu.Lock()
	p.toInitiator, p.toResponder = toInitiator, toResponder
	p.mu.Unlock()
}

// holdRekeys sets whether the path holds the rekey requests either way, as holdRekeysFrom does for both ends
func (p *crossingPath) holdRekeys(holding bool) { p.holdRekeysFrom(holding, holding) }

// holdRekeysFrom sets whether the path holds the rekey requests from the initiator and from the responder, and sends on what it held from an end it holds no longer, in the order it came
func (p *crossingPath) holdRekeysFrom(initiator, responder bool) {
	p.mu.Lock()
	p.holding = [2]bool{initiator, responder}
	var out, kept []crossingDatagram
	for _, d := range p.held {
		if p.holding[crossingFrom(d.fromInitiator)] {
			kept = append(kept, d)
		} else {
			out = append(out, d)
		}
	}
	p.held = kept
	p.mu.Unlock()
	for _, d := range out {
		_, _ = p.conn.WriteToUDP(d.raw, d.to)
	}
}

// crossingFrom indexes the end a datagram came from, the initiator first
func crossingFrom(fromInitiator bool) int {
	if fromInitiator {
		return 0
	}
	return 1
}

// loseStaleRequests sets whether the path loses the responder's INFORMATIONAL requests on any IKE SA but its current one
func (p *crossingPath) loseStaleRequests(stale bool) {
	p.mu.Lock()
	p.stale = stale
	p.mu.Unlock()
}
