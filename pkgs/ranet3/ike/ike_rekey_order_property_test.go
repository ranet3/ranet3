// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package ike

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"
	"testing/synctest"
	"time"

	"ranet3.com/pkgs/ranet3/internal/bubble"
	"ranet3.com/pkgs/ranet3/transport"
)

// the orders the peer's request and the answer to this end's request reach this end in, against this end's own rekey
const (
	// each end answers the other's rekey before the answer to its own comes
	ikeCrossingRequestsFirst = iota
	// this end's answer comes first and the peer's request after this end's decision
	ikeCrossingAnswerFirst
	// the peer's request comes first and this end's answer is taken while the handler is between its check and its placement
	ikeCrossingAnswerDuringCheck
	// this end's request is lost and its resend comes once the peer's rekey ended
	ikeCrossingRequestLost
	ikeCrossingOrders
)

// ikeCrossingEnd is one of two sessions rekeying their IKE SA at once, whose requests the test carries to the other in place of Run and the path
type ikeCrossingEnd struct {
	s    *Session
	old  *ikeContext
	done <-chan error
	// pending is the request the rekey waits on, nil while it waits on nothing the test carries or once it ended
	pending *localRequest
	ended   bool
	// other is a second mux on the session's hub, which alone tells an SPI the session holds from one it released
	other *transport.Mux
	// beforeAnswer runs once, before the session draws the Nr of its answer to the peer's rekey
	beforeAnswer func()
}

type ikeCrossing struct{ a, b *ikeCrossingEnd }

// newIKECrossingEnd is a session on a hub of its own holding old under lists, which draws ni for its rekey and nr for its answer
func newIKECrossingEnd(t *testing.T, old *ikeContext, lists Suites, ni, nr []byte) *ikeCrossingEnd {
	t.Helper()
	mux, other := lifecycleMuxes(t)
	if err := mux.RegisterIKE(old.spiI); err != nil {
		t.Fatal(err)
	}
	e := &ikeCrossingEnd{old: old, other: other}
	e.s = seamed(&Session{mux: mux, current: old, requests: make(chan *localRequest, 1), suites: func() Suites { return lists }})
	drawn := 0
	e.s.ikeRekeyNonce = func(n []byte) error {
		if drawn++; drawn == 1 {
			copy(n, ni)
			return nil
		}
		if hook := e.beforeAnswer; hook != nil {
			e.beforeAnswer = nil
			hook()
		}
		copy(n, nr)
		return nil
	}
	return e
}

// settle waits until every goroutine of the test's bubble blocks, then takes the request each rekey sent or how it ended
func (c *ikeCrossing) settle() {
	synctest.Wait()
	for _, e := range []*ikeCrossingEnd{c.a, c.b} {
		if e.ended || e.pending != nil {
			continue
		}
		select {
		case e.pending = <-e.s.requests:
		case <-e.done:
			e.ended = true
		default:
		}
	}
}

// answer is to's answer to the request from's rekey waits on, nil where to holds no SA for it and empty where the answer carries nothing, as one to a Delete does
func (c *ikeCrossing) answer(t *testing.T, from, to *ikeCrossingEnd) []RawPayload {
	t.Helper()
	request := from.pending
	header := Header{SPIInitiator: request.context.spiI, SPIResponder: request.context.spiR, ExchangeType: request.exchange, MessageID: 1}
	ctx := to.s.contextForHeader(&header)
	if ctx == nil {
		return nil
	}
	answer, err := to.s.handleRequest(ctx, &header, nil, request.inner)
	if err != nil {
		t.Fatalf("a request of exchange %d ended the session that took it: %v", request.exchange, err)
	}
	if inner := sealedAnswer(t, ctx, answer.whole); inner != nil {
		return inner
	}
	return []RawPayload{}
}

// takes hands e's rekey the answer to its request as e's Run hands it on, nil where none came
// it mirrors Run's pass after its select, where an exchange whose context is retired ends and one whose sends are spent is deemed failed, and dispatch's hand-over of a matching answer: an exchange whose SA e no longer holds ends, an unanswered one Run's own keepReplaced keeps leaves its SA kept, another unanswered one on a retained SA ends that SA alone, and one on the current SA ends the session
func (c *ikeCrossing) takes(t *testing.T, e *ikeCrossingEnd, answer []RawPayload) {
	t.Helper()
	request := e.pending
	e.pending = nil
	switch {
	case e.s.contextRetired(request.context):
		request.result <- requestResult{err: errors.New("ike: the IKE SA carrying this exchange was replaced")}
	case answer != nil:
		request.result <- requestResult{inner: answer}
	case deletesIKE(request.inner) && e.s.keepReplaced(request.context):
		request.result <- requestResult{err: errReplacedKept}
	case e.s.retire(request.context, retiredUnanswered, ""):
		request.result <- requestResult{err: errors.New("ike: the retained IKE SA was deemed failed")}
	default:
		t.Fatalf("exchange %d on the current IKE SA found no SA at the peer", request.exchange)
	}
	c.settle()
}

func (c *ikeCrossing) carry(t *testing.T, from, to *ikeCrossingEnd) {
	t.Helper()
	c.takes(t, from, c.answer(t, from, to))
}

// finish carries every request, this end's first, until both rekeys ended
func (c *ikeCrossing) finish(t *testing.T) {
	t.Helper()
	for !c.a.ended || !c.b.ended {
		switch {
		case c.a.pending != nil:
			c.carry(t, c.a, c.b)
		case c.b.pending != nil:
			c.carry(t, c.b, c.a)
		default:
			t.Fatal("each end waits on the other with nothing to carry")
		}
	}
}

// newIKECrossing is two sessions on one IKE SA, this end its initiator, each rekeying it, classical or chained, whose four nonces hold the lowest at lowest as crossingNonces orders them, once each sent its request
func newIKECrossing(t *testing.T, chained bool, lowest int) *ikeCrossing {
	t.Helper()
	return newIKECrossingAfter(t, chained, lowest, nil)
}

// newIKECrossingAfter is newIKECrossing with before run on the two ends ahead of their rekeys, where it is not nil
func newIKECrossingAfter(t *testing.T, chained bool, lowest int, before func(c *ikeCrossing)) *ikeCrossing {
	t.Helper()
	suite, lists := classicalSuite, Suites{ikeCipher: []Transform{encrAES128}, kex: []kexEntry{entryX25519}}
	if chained {
		suite, lists = chainSuite, chainLists
	}
	// this end's Ni and the peer's Nr in this end's exchange, then the peer's Ni and this end's Nr in the peer's
	nonces := crossingNonces(t, lowest)
	oldA := chainContext(t, suite)
	oldB := &ikeContext{suite: suite, spiI: oldA.spiI, spiR: oldA.spiR, skD: oldA.skD, skei: oldA.skei, sker: oldA.sker, responder: true, established: oldA.established}
	c := &ikeCrossing{a: newIKECrossingEnd(t, oldA, lists, nonces[0], nonces[3]), b: newIKECrossingEnd(t, oldB, lists, nonces[2], nonces[1])}
	if before != nil {
		before(c)
	}
	c.a.done, c.b.done = rekeying(c.a.s), rekeying(c.b.s)
	c.settle()
	if c.a.pending == nil || c.b.pending == nil {
		t.Fatal("a rekey sent no request")
	}
	return c
}

// two ranet3 ends rekeying their IKE SA at once, classical or chained, end on the same IKE SA in every order the peer's request and the answer to this end's request reach this end in, and hold no other SA or SPI
// the model: where both ends answered the other's rekey before their own answer came, RFC 7296 section 2.8.2 has "The new IKE SA containing the lowest nonce SHOULD be deleted by the node that created it"
// where this end decided first, the peer's rekey reaching it then is refused with TEMPORARY_FAILURE and this end's SA survives, and where this end's request is lost until the peer's rekey ended, the peer's SA survives
// each of the orders runs with each end's exchange holding the lowest nonce at each of its two places, classical and chained
func TestTwoEndsCrossingIKESARekeysKeepOneSA(t *testing.T) {
	for _, chained := range []bool{false, true} {
		for order := range ikeCrossingOrders {
			for lowest := range 4 {
				t.Run(fmt.Sprintf("chained %v order %d lowest %d", chained, order, lowest), bubble.Run(func(t *testing.T) {
					testTwoEndsCrossingIKESARekeysKeepOneSA(t, chained, order, lowest)
				}))
			}
		}
	}
}

func testTwoEndsCrossingIKESARekeysKeepOneSA(t *testing.T, chained bool, order, lowest int) {
	c := newIKECrossing(t, chained, lowest)
	ownSPI := binary.BigEndian.Uint64(offerOf(t, c.a.pending.inner)[0].SPI)
	peerSPI := binary.BigEndian.Uint64(offerOf(t, c.b.pending.inner)[0].SPI)

	survivor := peerSPI
	switch order {
	case ikeCrossingRequestsFirst:
		toA, toB := c.answer(t, c.a, c.b), c.answer(t, c.b, c.a)
		c.takes(t, c.a, toA)
		c.takes(t, c.b, toB)
		if lowest >= 2 {
			survivor = ownSPI
		}
	case ikeCrossingAnswerFirst:
		c.takes(t, c.a, c.answer(t, c.a, c.b))
		c.carry(t, c.b, c.a)
		survivor = ownSPI
	case ikeCrossingAnswerDuringCheck:
		toA := c.answer(t, c.a, c.b)
		c.a.beforeAnswer = func() { c.takes(t, c.a, toA) }
		c.carry(t, c.b, c.a)
		if c.a.beforeAnswer != nil {
			t.Fatal("this end refused the peer's rekey before its handler drew its Nr")
		}
		survivor = ownSPI
	case ikeCrossingRequestLost:
		c.carry(t, c.b, c.a)
		for !c.b.ended {
			if c.b.pending == nil {
				t.Fatal("the peer's rekey waits with nothing to carry")
			}
			c.carry(t, c.b, c.a)
		}
	}
	c.finish(t)
	c.keepOne(t, survivor, ownSPI, peerSPI)
}

// a peer's rekey this end refuses while the refused SA is still current is resent until the refusal or this end's Delete reaches the peer, so once this end's own rekey replaces that SA the refusal is kept as the record of it, as one sent on the replaced SA is
// classical: the peer's rekey checked before this end's decision and refused after it, as its answer finds the SA taken
// chained: the peer's rekey refused while this end's won rekey runs its IKE_FOLLOWUP_KE, or checked before the decision and refused as its chain finds the SA taken, the SA current until the followup in both
// before the decision: refused for a stale SA in the collision slot, after which the decision counts a crossing with no peer nonce and wins, or for the limit on the peer's rekeys, after which it counts none
// a classical refusal after the decision, the SA already replaced, is the case the others are held to
// the crossing harness answers through handleRequest and keeps no answer, so the test reads the record's fields, and the record never serves a repeat here
func TestRefusalBeforeThisEndsRekeyReplacesTheSAIsRecorded(t *testing.T) {
	for _, test := range []struct {
		name            string
		chained, during bool
		// before is the refusal's cause set ahead of the decision: stale or limit, none where the decision itself causes it
		before string
	}{
		{"classical refused after the decision", false, false, ""},
		{"classical checked before the decision and refused after it", false, true, ""},
		{"chained refused before the followup", true, false, ""},
		{"chained checked before the decision and refused after it", true, true, ""},
		{"refused for a stale collision before the decision", false, false, "stale"},
		{"refused for the limit on the peer's rekeys before the decision", false, false, "limit"},
	} {
		t.Run(test.name, bubble.Run(func(t *testing.T) {
			c := newIKECrossingAfter(t, test.chained, 0, func(c *ikeCrossing) {
				if test.before == "stale" {
					c.a.s.stateMu.Lock()
					c.a.s.collision = chainContext(t, classicalSuite)
					c.a.s.stateMu.Unlock()
				}
			})
			if test.before == "limit" {
				// the peer's last rekey came now, inside minPeerIKERekeyInterval of this one
				c.a.s.lastPeerIKERekey.Store(int64(time.Since(c.a.s.started)) + 1)
			}
			var refused []RawPayload
			switch {
			case test.before != "":
				refused = c.answer(t, c.b, c.a)
				c.takes(t, c.a, c.answer(t, c.a, c.b))
			case test.during:
				toA := c.answer(t, c.a, c.b)
				c.a.beforeAnswer = func() { c.takes(t, c.a, toA) }
				refused = c.answer(t, c.b, c.a)
				if c.a.beforeAnswer != nil {
					t.Fatal("this end refused the peer's rekey before its handler drew its Nr")
				}
			default:
				c.takes(t, c.a, c.answer(t, c.a, c.b))
				refused = c.answer(t, c.b, c.a)
			}
			refusedAt := time.Now()
			if !notified(refused, N_TEMPORARY_FAILURE, nil) {
				t.Fatalf("this end answered the peer's rekey with %v", payloadTypes(refused))
			}
			if test.chained {
				if c.a.pending == nil || c.a.pending.exchange != IKE_FOLLOWUP_KE {
					t.Fatal("this end's chained rekey runs no IKE_FOLLOWUP_KE")
				}
				c.carry(t, c.a, c.b)
			}
			c.a.s.stateMu.RLock()
			old, current, record, oldBy := c.a.s.old, c.a.s.current, c.a.s.recovery, c.a.s.oldBy
			c.a.s.stateMu.RUnlock()
			if old != c.a.old || !old.ownDelete {
				t.Fatal("this end's rekey did not replace the SA the refusal came on")
			}
			if record.replaced != old || record.replacement != current || record.mid != 1 {
				t.Fatalf("the refusal is recorded of the replaced SA %v, of this end's SA %v, at Message ID %d, want both at Message ID 1", record.replaced == old, record.replacement == current, record.mid)
			}
			if want := refusedAt.Add(busyRequestBudget); !record.until.Equal(want) || !oldBy.Equal(want) {
				t.Errorf("the record ends %v and holds the replaced SA %v after the refusal, want both %v", record.until.Sub(refusedAt), oldBy.Sub(refusedAt), busyRequestBudget)
			}
		}))
	}
}

// a chained rekey whose first answer the path loses past the peer's wait for its IKE_FOLLOWUP_KE, so the peer drops its chain, crossed by the peer's next rekey of the same SA, which completes and is held as the collision's candidate while the late rekey waits
// with the peer's nonces lowest the late end yields to the candidate, and with its own lowest it wins and its IKE_FOLLOWUP_KE draws STATE_NOT_FOUND
// RFC 9370 section 2.2.4: "If the responder receives an IKE_FOLLOWUP_KE message for which it does not have a key exchange state, it MUST send back a new error type notification called "STATE_NOT_FOUND"."
// the late exchange made no SA then, and the candidate is the peer's chain's, which the peer ran to its IKE_FOLLOWUP_KE because it did not give way and runs on, so the late end takes it as it takes one held where its CREATE_CHILD_SA is refused, and both ends run on it once the peer's Delete of the old SA came
// the third STATE_NOT_FOUND in a row ends the IKE SA only where no candidate is held, and the IKE SA a held one replaces goes with the peer's Delete
func TestRefusedFollowupOfALateChainTakesThePeersCompletedRekey(t *testing.T) {
	for _, test := range []struct {
		name string
		// lowest places the lowest nonce as crossingNonces does, the late end's exchange first
		lowest int
		// held is whether the peer rekeys again and its SA is held as the candidate, third whether the refusal is the third STATE_NOT_FOUND in a row
		held, third bool
	}{
		{"late end yields to the candidate", 0, true, false},
		{"late end wins and its followup is refused", 2, true, false},
		{"third refusal in a row with the candidate held", 2, true, true},
		{"third refusal in a row with none held", 2, false, true},
	} {
		t.Run(test.name, bubble.Run(func(t *testing.T) {
			// the late end's Ni and the peer's Nr in its exchange, then the peer's Ni and the late end's Nr in the peer's
			n := crossingNonces(t, test.lowest)
			oldA := chainContext(t, chainSuite)
			oldB := &ikeContext{suite: chainSuite, spiI: oldA.spiI, spiR: oldA.spiR, skD: oldA.skD, skei: oldA.skei, sker: oldA.sker, responder: true, established: oldA.established}
			peer, late := newIKECrossingEnd(t, oldA, chainLists, n[2], n[1]), newIKECrossingEnd(t, oldB, chainLists, n[0], n[3])
			drawsInTurn(peer.s, n[1], n[2])
			drawsInTurn(late.s, n[0], n[3])
			if test.third {
				late.s.stateNotFounds = stateNotFoundLimit - 1
			}
			c := &ikeCrossing{a: peer, b: late}
			ended, done := make(chan error, 1), make(chan error, 1)
			go func() {
				err := late.s.RekeyIKE()
				ended <- err
				done <- err
			}()
			late.done = done
			c.settle()
			// the peer answers the late end's CREATE_CHILD_SA, opening its chain, and the path loses that answer until the chain expired
			lost := c.answer(t, late, peer)
			time.Sleep(followupWait)
			peer.s.expireChain(time.Now())
			made := oldA
			if test.held {
				// the peer rekeys the SA, the late end answers both its exchanges, and the path loses the peer's Delete of the SA it replaced
				peer.done = rekeying(peer.s)
				c.settle()
				c.carry(t, peer, late)
				if peer.pending == nil || peer.pending.exchange != IKE_FOLLOWUP_KE {
					t.Fatal("the peer's chained rekey runs no IKE_FOLLOWUP_KE")
				}
				c.carry(t, peer, late)
				if peer.pending == nil || !deletesIKE(peer.pending.inner) {
					t.Fatal("the peer sent no Delete of the SA it replaced")
				}
				made = peer.s.currentContext()
			}
			// the late end's resend draws the answer the peer kept for it
			c.takes(t, late, lost)
			for !late.ended {
				if late.pending == nil {
					t.Fatal("the late end's rekey waits with nothing to carry")
				}
				c.carry(t, late, peer)
			}
			err := <-ended
			if !test.held {
				if ending, ok := errors.AsType[*saEnding](err); !ok || ending.reason != "state not found" {
					t.Fatalf("the third STATE_NOT_FOUND in a row with no candidate held ended the rekey with %v, want the IKE SA ended", err)
				}
				return
			}
			if current := late.s.currentContext(); current.spiI != made.spiI {
				t.Fatalf("the late end's rekey ended with %v and it runs on %016x, the peer on %016x it made, whose Delete of %016x it would take for its current SA", err, current.spiI, made.spiI, oldB.spiI)
			}
			if err != nil {
				t.Fatalf("the late end took the peer's SA and its rekey ended with %v", err)
			}
			c.carry(t, peer, late)
			c.finish(t)
			c.keepOne(t, made.spiI, made.spiI)
		}))
	}
}

// the order of TestRefusedFollowupOfALateChainTakesThePeersCompletedRekey with the peer's Delete of the old SA lost and the late end's first answer lost past retainedContextDeadline after the peer's rekey
// the peer keeps the answer that opened the late end's chain as the record of the old SA, which serves the late end's resend, a repeat, past that retention
// the late end wins and its IKE_FOLLOWUP_KE on the old SA draws STATE_NOT_FOUND there, so it takes the candidate the peer's rekey made and both ends run on it
func TestRefusedFollowupOfALateChainPastThePeersRetentionTakesThePeersCompletedRekey(t *testing.T) {
	bubble.Run(testRefusedFollowupOfALateChainPastThePeersRetentionTakesThePeersCompletedRekey)(t)
}

func testRefusedFollowupOfALateChainPastThePeersRetentionTakesThePeersCompletedRekey(t *testing.T) {
	// the late end's Ni and the peer's Nr in its exchange, then the peer's Ni and the late end's Nr in the peer's, the lowest the peer's Ni so the late end wins
	n := crossingNonces(t, 2)
	oldA := chainContext(t, chainSuite)
	oldB := &ikeContext{suite: chainSuite, spiI: oldA.spiI, spiR: oldA.spiR, skD: oldA.skD, skei: oldA.skei, sker: oldA.sker, responder: true, established: oldA.established}
	peer, late := newIKECrossingEnd(t, oldA, chainLists, n[2], n[1]), newIKECrossingEnd(t, oldB, chainLists, n[0], n[3])
	drawsInTurn(peer.s, n[1], n[2])
	drawsInTurn(late.s, n[0], n[3])
	c := &ikeCrossing{a: peer, b: late}
	late.done = rekeying(late.s)
	c.settle()
	// the peer answers the late end's CREATE_CHILD_SA, opening its chain, and the path loses that answer until past the peer's retention
	request, crossed := c.sealed(t, late, peer)
	if opened := c.deliver(t, peer, crossed, request); opened == nil {
		t.Fatal("the peer answered nothing to the late end's rekey")
	}
	time.Sleep(followupWait)
	peer.s.expireChain(time.Now())
	// the peer rekeys the SA, the late end answers both its exchanges, and the path loses the peer's Delete of the SA it replaced
	peer.done = rekeying(peer.s)
	c.settle()
	c.carry(t, peer, late)
	c.carry(t, peer, late)
	if peer.pending == nil || !deletesIKE(peer.pending.inner) {
		t.Fatal("the peer sent no Delete of the SA it replaced")
	}
	c.takes(t, peer, nil)
	made := peer.s.currentContext()
	time.Sleep(retainedContextDeadline + pastRetentionBy)
	peer.s.expireRetainedContexts(time.Now())
	again := c.deliver(t, peer, crossed, request)
	if again == nil {
		t.Fatal("the late end's resend past the peer's retention drew nothing")
	}
	c.takes(t, late, again)
	if late.pending == nil || late.pending.exchange != IKE_FOLLOWUP_KE {
		t.Fatal("the late end's chained rekey did not win with its IKE_FOLLOWUP_KE to run")
	}
	followup, on := c.sealed(t, late, peer)
	refused := c.deliver(t, peer, on, followup)
	if !notified(refused, N_STATE_NOT_FOUND, nil) {
		t.Fatalf("the late end's IKE_FOLLOWUP_KE on the old SA past the peer's retention drew %v, want STATE_NOT_FOUND", payloadTypes(refused))
	}
	c.takes(t, late, refused)
	if current := late.s.currentContext(); current.spiI != made.spiI {
		t.Fatalf("the late end runs on %016x, the peer on %016x it made", current.spiI, made.spiI)
	}
	// the peer's STATE_NOT_FOUND leaves the old SA held to the end of the record of the answer before it, which no request of the late end's on the SA it took ends here
	peer.s.stateMu.RLock()
	held := peer.s.oldBy
	peer.s.stateMu.RUnlock()
	time.Sleep(max(time.Until(held), retainedContextDeadline) + pastRetentionBy)
	for _, e := range []*ikeCrossingEnd{peer, late} {
		e.s.expireRetainedContexts(time.Now())
	}
	c.finish(t)
	c.keepOne(t, made.spiI, made.spiI)
}

// this end decides first and wins with an additional key exchange, and refuses the peer's rekey placed after its decision, before its Delete of the old SA goes out, the old SA current until its IKE_FOLLOWUP_KE
// the path drops what this end sends on the old SA for the teardown's budget, the refusal and both sends of that Delete
// the old SA is still held then, so the peer's resend of its rekey, which dispatch takes as a repeat, draws the refusal again and the peer takes this end's SA
// neither end hears the other delete the old SA, so this end holds it to the end of the record of its refusal, busyRequestBudget after it, and no longer
// TestReplacedIKESAOutlastsTheTeardownBudgetForACrossingPeer holds the classical rekey over Run
func TestIKECrossingLossForTheTeardownBudgetKeepsOneSA(t *testing.T) {
	bubble.Run(testIKECrossingLossForTheTeardownBudgetKeepsOneSA)(t)
}

func testIKECrossingLossForTheTeardownBudgetKeepsOneSA(t *testing.T) {
	c := newIKECrossing(t, true, 0)
	ownSPI := binary.BigEndian.Uint64(offerOf(t, c.a.pending.inner)[0].SPI)
	peerSPI := binary.BigEndian.Uint64(offerOf(t, c.b.pending.inner)[0].SPI)
	// the peer answers this end's rekey while its own waits, and this end takes that answer before the peer's request reaches it
	c.takes(t, c.a, c.answer(t, c.a, c.b))
	request, crossed := c.sealed(t, c.b, c.a)
	if refused := c.deliver(t, c.a, crossed, request); !notified(refused, N_TEMPORARY_FAILURE, nil) {
		t.Fatalf("this end answered the peer's rekey placed after its decision with %v", payloadTypes(refused))
	}
	refusedAt := time.Now()
	if c.a.pending == nil || c.a.pending.exchange != IKE_FOLLOWUP_KE {
		t.Fatal("this end's chained rekey runs no IKE_FOLLOWUP_KE")
	}
	c.carry(t, c.a, c.b)
	if c.a.pending == nil || c.a.pending.exchange != INFORMATIONAL || !deletesIKE(c.a.pending.inner) {
		t.Fatal("this end sent no Delete of the old SA")
	}
	c.takes(t, c.a, nil)
	resent := c.deliver(t, c.a, crossed, request)
	if resent == nil {
		t.Fatal("this end answered nothing to the peer's resend on the old SA, so the peer stays on it")
	}
	c.takes(t, c.b, resent)
	c.finish(t)
	time.Sleep(time.Until(refusedAt.Add(busyRequestBudget - pastRetentionBy)))
	c.a.s.expireRetainedContexts(time.Now())
	if _, old := c.a.s.contexts(); old != c.a.old {
		t.Fatalf("this end no longer holds the old SA %v after its refusal, short of the end of the record of it at %v", time.Since(refusedAt), busyRequestBudget)
	}
	time.Sleep(2 * pastRetentionBy)
	for _, e := range []*ikeCrossingEnd{c.a, c.b} {
		e.s.expireRetainedContexts(time.Now())
	}
	c.keepOne(t, ownSPI, ownSPI, peerSPI)
}

// sealed is from's request as the path brings it to to, on the SA to holds for it at the Message ID that SA expects next, and that SA
func (c *ikeCrossing) sealed(t *testing.T, from, to *ikeCrossingEnd) ([]byte, *ikeContext) {
	t.Helper()
	request := from.pending
	header := Header{SPIInitiator: request.context.spiI, SPIResponder: request.context.spiR, ExchangeType: request.exchange}
	ctx := to.s.contextForHeader(&header)
	if ctx == nil {
		t.Fatalf("this end holds no SA for the request of exchange %d", request.exchange)
	}
	to.s.stateMu.RLock()
	header.MessageID = ctx.nextPeerMID
	to.s.stateMu.RUnlock()
	if ctx.responder {
		header.Flags = FlagInitiator
	}
	raw, err := EncryptMessage(ctx.suite, ctx.peerEncryptionKey(), header, nil, request.inner)
	if err != nil {
		t.Fatal(err)
	}
	return raw, ctx
}

// deliver hands raw, a request on ctx, to to's dispatch as the path hands it a datagram from the peer, and returns the answer to sent for it, nil where it sent none
// a repeat of a request to answered draws what dispatch kept for it, as on the path, and never reaches the handler again
func (c *ikeCrossing) deliver(t *testing.T, to *ikeCrossingEnd, ctx *ikeContext, raw []byte) []RawPayload {
	t.Helper()
	to.s.stateMu.RLock()
	before, answers := ctx.lastPeer.response, ctx.lastPeer.answers
	to.s.stateMu.RUnlock()
	var pending *pendingRequest
	to.s.dispatch(raw, to.s.mux.Endpoint(), &pending)
	to.s.stateMu.RLock()
	sent, again := ctx.lastPeer.response, ctx.lastPeer.answers > answers
	to.s.stateMu.RUnlock()
	if sent == nil || sent == before && !again {
		return nil
	}
	return sealedAnswer(t, ctx, sent.message.whole)
}

// keepOne fails t unless both ends are current on the SA survivor names, from either side, and hold no other SA or SPI among their old SA's, own and peer's
func (c *ikeCrossing) keepOne(t *testing.T, survivor uint64, spis ...uint64) {
	t.Helper()
	current, peerCurrent := c.a.s.currentContext(), c.b.s.currentContext()
	if current.spiI != peerCurrent.spiI || current.spiR != peerCurrent.spiR || current.responder == peerCurrent.responder ||
		!bytes.Equal(current.skD, peerCurrent.skD) || !bytes.Equal(current.skei, peerCurrent.skei) || !bytes.Equal(current.sker, peerCurrent.sker) {
		t.Fatalf("this end is current on %016x and the peer on %016x", current.spiI, peerCurrent.spiI)
	}
	if current.spiI != survivor {
		t.Fatalf("both ends are current on %016x, the model keeps %016x", current.spiI, survivor)
	}
	for _, e := range []*ikeCrossingEnd{c.a, c.b} {
		e.s.stateMu.RLock()
		retained, collision := e.s.old, e.s.collision
		e.s.stateMu.RUnlock()
		if retained != nil || collision != nil {
			t.Fatal("an end still holds an SA past the Deletes")
		}
		for _, spi := range append([]uint64{e.old.spiI}, spis...) {
			if registered := e.other.RegisterIKE(spi) != nil; registered != (spi == current.spiI) {
				t.Fatalf("SPI %016x is registered %v, current %016x", spi, registered, current.spiI)
			}
		}
	}
}

// both ends rekey chained and answer each other's rekey, this end wins by the nonces against the peer's chain still open here, and the path loses this end's answer to the peer's rekey and its Delete of the old SA
// RFC 7296 section 2.8.2: "The new IKE SA containing the lowest nonce SHOULD be deleted by the node that created it", and the peer, whose exchange holds it, makes its SA only at its IKE_FOLLOWUP_KE, which it then never sends
// the answer that opened the chain made no SA, so it is kept as the record of the old SA once this end's rekey replaces it, to busyRequestBudget after it went out
// the peer's resend, which dispatch takes as a repeat, before and after retainedContextDeadline past the rekey, draws that answer, and the peer decides on the four nonces, yields and runs on this end's SA
func TestWonCrossingAgainstThePeersOpenChainKeepsTheAnswerThatOpenedIt(t *testing.T) {
	for _, past := range []bool{false, true} {
		name, wait := "resend inside the retention", retainedContextDeadline-pastRetentionBy
		if past {
			name, wait = "resend past the retention", retainedContextDeadline+pastRetentionBy
		}
		t.Run(name, bubble.Run(func(t *testing.T) {
			c := newIKECrossing(t, true, 2)
			ownSPI := binary.BigEndian.Uint64(offerOf(t, c.a.pending.inner)[0].SPI)
			peerSPI := binary.BigEndian.Uint64(offerOf(t, c.b.pending.inner)[0].SPI)
			toA := c.answer(t, c.a, c.b)
			request, crossed := c.sealed(t, c.b, c.a)
			c.a.s.stateMu.RLock()
			mid := crossed.nextPeerMID
			c.a.s.stateMu.RUnlock()
			opened := c.deliver(t, c.a, crossed, request)
			openedAt := time.Now()
			link, err := linkOf(opened)
			if err != nil || link == nil {
				t.Fatalf("this end answered the peer's chained rekey with %v, want its chain opened", payloadTypes(opened))
			}
			c.takes(t, c.a, toA)
			if c.a.pending == nil || c.a.pending.exchange != IKE_FOLLOWUP_KE {
				t.Fatal("this end's chained rekey did not win with its IKE_FOLLOWUP_KE to run")
			}
			c.carry(t, c.a, c.b)
			if c.a.pending == nil || !deletesIKE(c.a.pending.inner) {
				t.Fatal("this end sent no Delete of the old SA")
			}
			c.takes(t, c.a, nil)
			c.a.s.stateMu.RLock()
			record, oldBy, replacedAt := c.a.s.recovery, c.a.s.oldBy, c.a.old.replacedAt
			c.a.s.stateMu.RUnlock()
			if record.replaced != c.a.old || record.mid != mid {
				t.Fatalf("this end won against the peer's open chain and keeps no record of the answer that opened it: record of the old SA %v at Message ID %d, want %d, the old SA held %v after the rekey", record.replaced == c.a.old, record.mid, mid, oldBy.Sub(replacedAt))
			}
			if want := openedAt.Add(busyRequestBudget); !record.until.Equal(want) || !oldBy.Equal(want) {
				t.Fatalf("the record ends %v and holds the old SA %v after the answer, want both %v", record.until.Sub(openedAt), oldBy.Sub(openedAt), busyRequestBudget)
			}
			time.Sleep(time.Until(replacedAt.Add(wait)))
			c.a.s.expireRetainedContexts(time.Now())
			again := c.deliver(t, c.a, crossed, request)
			if resent, err := linkOf(again); err != nil || !bytes.Equal(resent, link) {
				t.Fatalf("the peer's resend %v after this end's rekey drew %v, want the answer that opened its chain", time.Since(replacedAt), payloadTypes(again))
			}
			c.takes(t, c.b, again)
			c.finish(t)
			current, peerCurrent := c.a.s.currentContext(), c.b.s.currentContext()
			if current.spiI != ownSPI || peerCurrent.spiI != ownSPI || !bytes.Equal(current.skD, peerCurrent.skD) {
				t.Fatalf("this end is current on %016x and the peer on %016x, want both on this end's %016x", current.spiI, peerCurrent.spiI, ownSPI)
			}
			time.Sleep(time.Until(record.until.Add(pastBound)))
			for _, e := range []*ikeCrossingEnd{c.a, c.b} {
				e.s.expireRetainedContexts(time.Now())
			}
			c.keepOne(t, ownSPI, ownSPI, peerSPI)
		}))
	}
}

// this end wins against the peer's chain still open here, and the peer's IKE_FOLLOWUP_KE on that chain, which a peer that sends one after losing does, reaches this end while its own rekey runs its IKE_FOLLOWUP_KE
// that exchange is answered TEMPORARY_FAILURE and kept as the answer to the peer's later request, so the answer that opened the chain is not the one a repeat draws, and no record is made of it once this end's rekey replaces the SA
func TestPeersFollowupAfterThisEndsWinEndsTheMarkOfItsChain(t *testing.T) {
	bubble.Run(testPeersFollowupAfterThisEndsWinEndsTheMarkOfItsChain)(t)
}

func testPeersFollowupAfterThisEndsWinEndsTheMarkOfItsChain(t *testing.T) {
	c := newIKECrossing(t, true, 2)
	toA := c.answer(t, c.a, c.b)
	request, crossed := c.sealed(t, c.b, c.a)
	opened := c.deliver(t, c.a, crossed, request)
	link, err := linkOf(opened)
	if err != nil || link == nil {
		t.Fatalf("this end answered the peer's chained rekey with %v, want its chain opened", payloadTypes(opened))
	}
	c.takes(t, c.a, toA)
	if c.a.pending == nil || c.a.pending.exchange != IKE_FOLLOWUP_KE {
		t.Fatal("this end's chained rekey did not win with its IKE_FOLLOWUP_KE to run")
	}
	inner, _ := followupRequest(t, chainSuite.Addition, link)
	c.a.s.stateMu.RLock()
	header := Header{SPIInitiator: crossed.spiI, SPIResponder: crossed.spiR, ExchangeType: IKE_FOLLOWUP_KE, MessageID: crossed.nextPeerMID}
	c.a.s.stateMu.RUnlock()
	if crossed.responder {
		header.Flags = FlagInitiator
	}
	raw, err := EncryptMessage(crossed.suite, crossed.peerEncryptionKey(), header, nil, inner)
	if err != nil {
		t.Fatal(err)
	}
	if refused := c.deliver(t, c.a, crossed, raw); !notified(refused, N_TEMPORARY_FAILURE, nil) {
		t.Fatalf("this end answered the peer's IKE_FOLLOWUP_KE after its win with %v", payloadTypes(refused))
	}
	c.carry(t, c.a, c.b)
	if c.a.pending == nil || !deletesIKE(c.a.pending.inner) {
		t.Fatal("this end sent no Delete of the old SA")
	}
	c.takes(t, c.a, nil)
	c.a.s.stateMu.RLock()
	record, oldBy, replacedAt := c.a.s.recovery, c.a.s.oldBy, c.a.old.replacedAt
	c.a.s.stateMu.RUnlock()
	if record.replaced == c.a.old {
		t.Fatalf("the answer that opened the peer's chain is recorded at Message ID %d though the peer's IKE_FOLLOWUP_KE came after it", record.mid)
	}
	if want := replacedAt.Add(retainedContextDeadline); !oldBy.Equal(want) {
		t.Fatalf("this end holds the old SA %v after its rekey, want %v", oldBy.Sub(replacedAt), retainedContextDeadline)
	}
	// the peer takes the answer that opened its chain, loses on the four nonces and yields to this end's SA
	c.takes(t, c.b, opened)
	c.finish(t)
}

// RFC 9370 section 2.2.4: "if additional key exchanges are negotiated in the CREATE_CHILD_SA exchange in which the smallest nonce is used, then, because there is nothing to delete yet, the initiator of this exchange just stops the rekeying process, and it MUST NOT initiate the IKE_FOLLOWUP_KE exchange."
// a classical SA whose entry neither end's lists hold any more, the late end listing ecp256 before x25519 with ML-KEM-768 and the peer the other way round, so the late end's rekey is chained and the peer's classical on ecp256
// the peer's rekey holds the lowest nonce, so the peer takes the late end's answer with its chain open, gives way, deletes its SA and waits for the IKE_FOLLOWUP_KE, which the path loses past that wait along with the Delete
// the late end's IKE_FOLLOWUP_KE then draws STATE_NOT_FOUND, and the classical candidate it holds is one the peer gave way on, so it takes nothing, both ends stay on the old SA, and the late Delete retires the candidate
func TestStateNotFoundTakesNoClassicalCandidateThePeerGaveWayOn(t *testing.T) {
	bubble.Run(testStateNotFoundTakesNoClassicalCandidateThePeerGaveWayOn)(t)
}

func testStateNotFoundTakesNoClassicalCandidateThePeerGaveWayOn(t *testing.T) {
	// the late end's Ni and the peer's Nr in its exchange, then the peer's Ni and the late end's Nr in the peer's, the lowest the peer's Ni
	n := crossingNonces(t, 2)
	oldA := chainContext(t, classicalSuite)
	oldB := &ikeContext{suite: classicalSuite, spiI: oldA.spiI, spiR: oldA.spiR, skD: oldA.skD, skei: oldA.skei, sker: oldA.sker, responder: true, established: oldA.established}
	lateLists := Suites{ikeCipher: []Transform{encrAES128}, kex: []kexEntry{{group: DH_ECP_256}, entry768}}
	peerLists := Suites{ikeCipher: []Transform{encrAES128}, kex: []kexEntry{entry768, {group: DH_ECP_256}}}
	peer, late := newIKECrossingEnd(t, oldA, peerLists, n[2], n[1]), newIKECrossingEnd(t, oldB, lateLists, n[0], n[3])
	c := &ikeCrossing{a: peer, b: late}
	late.done, peer.done = rekeying(late.s), rekeying(peer.s)
	c.settle()
	if late.pending == nil || peer.pending == nil {
		t.Fatal("a rekey sent no request")
	}
	toLate := c.answer(t, late, peer)
	if link, _ := linkOf(toLate); link == nil {
		t.Fatalf("the peer answered the late end's rekey with %v, want its chain opened", payloadTypes(toLate))
	}
	// the peer's first offer draws INVALID_KE_PAYLOAD and its next runs on ecp256
	toPeer := c.answer(t, peer, late)
	for retry := 0; retry < 2 && findType(toPeer, PayloadSA) == nil; retry++ {
		c.takes(t, peer, toPeer)
		if peer.pending == nil {
			t.Fatal("the peer did not offer its rekey again")
		}
		toPeer = c.answer(t, peer, late)
	}
	if link, _ := linkOf(toPeer); link != nil || findType(toPeer, PayloadSA) == nil {
		t.Fatalf("the late end answered the peer's rekey with %v, want it classical", payloadTypes(toPeer))
	}
	late.s.stateMu.RLock()
	candidate := late.s.collision
	late.s.stateMu.RUnlock()
	if candidate == nil {
		t.Fatal("the late end holds no candidate of the peer's rekey")
	}
	c.takes(t, peer, toPeer)
	if peer.pending == nil || !deletesIKE(peer.pending.inner) {
		t.Fatal("the peer did not give way with a Delete of its SA")
	}
	deletion := peer.pending
	// the path loses the peer's Delete, and the late end's IKE_FOLLOWUP_KE until the peer's wait for it ran out
	c.takes(t, peer, nil)
	c.takes(t, late, toLate)
	if late.pending == nil || late.pending.exchange != IKE_FOLLOWUP_KE {
		t.Fatal("the late end's chained rekey did not win with its IKE_FOLLOWUP_KE to run")
	}
	time.Sleep(followupWait)
	peer.s.expireChain(time.Now())
	refused := c.answer(t, late, peer)
	if !notified(refused, N_STATE_NOT_FOUND, nil) {
		t.Fatalf("the late end's IKE_FOLLOWUP_KE drew %v, want STATE_NOT_FOUND", payloadTypes(refused))
	}
	c.takes(t, late, refused)
	if !late.ended {
		t.Fatal("the late end's rekey still runs after STATE_NOT_FOUND")
	}
	if current, at := late.s.currentContext(), peer.s.currentContext(); current.spiI != oldA.spiI || at.spiI != oldA.spiI {
		t.Fatalf("after STATE_NOT_FOUND the late end runs on %016x and the peer on %016x, want both on the old SA %016x", current.spiI, at.spiI, oldA.spiI)
	}
	header := Header{SPIInitiator: deletion.context.spiI, SPIResponder: deletion.context.spiR, ExchangeType: deletion.exchange, MessageID: 1}
	if ctx := late.s.contextForHeader(&header); ctx != nil {
		if _, err := late.s.handleRequest(ctx, &header, nil, deletion.inner); err != nil {
			t.Fatalf("the peer's late Delete of its candidate ended the late end's session: %v", err)
		}
	}
	if current := late.s.currentContext(); current.spiI != oldA.spiI {
		t.Errorf("after the peer's late Delete the late end runs on %016x, want the old SA %016x", current.spiI, oldA.spiI)
	}
}

// RFC 7296 section 2.25: "A TEMPORARY_FAILURE notification SHOULD be sent when a peer receives a request that cannot be completed due to a temporary condition such as a rekeying operation."
// the order of TestRefusedFollowupOfALateChainTakesThePeersCompletedRekey with the late end winning, its IKE_FOLLOWUP_KE answered TEMPORARY_FAILURE in place of STATE_NOT_FOUND
// a peer that answers so holds the chain or takes the exchange again later, so the late end takes no candidate on it and its rekey fails as before
func TestTemporaryFailureOfALateChainsFollowupTakesNoCandidate(t *testing.T) {
	bubble.Run(testTemporaryFailureOfALateChainsFollowupTakesNoCandidate)(t)
}

func testTemporaryFailureOfALateChainsFollowupTakesNoCandidate(t *testing.T) {
	// the late end's Ni and the peer's Nr in its exchange, then the peer's Ni and the late end's Nr in the peer's, the lowest the peer's Ni so the late end wins
	n := crossingNonces(t, 2)
	oldA := chainContext(t, chainSuite)
	oldB := &ikeContext{suite: chainSuite, spiI: oldA.spiI, spiR: oldA.spiR, skD: oldA.skD, skei: oldA.skei, sker: oldA.sker, responder: true, established: oldA.established}
	peer, late := newIKECrossingEnd(t, oldA, chainLists, n[2], n[1]), newIKECrossingEnd(t, oldB, chainLists, n[0], n[3])
	drawsInTurn(peer.s, n[1], n[2])
	drawsInTurn(late.s, n[0], n[3])
	c := &ikeCrossing{a: peer, b: late}
	ended, done := make(chan error, 1), make(chan error, 1)
	go func() {
		err := late.s.RekeyIKE()
		ended <- err
		done <- err
	}()
	late.done = done
	c.settle()
	// the peer answers the late end's CREATE_CHILD_SA, opening its chain, and the path loses that answer until the chain expired
	lost := c.answer(t, late, peer)
	time.Sleep(followupWait)
	peer.s.expireChain(time.Now())
	// the peer rekeys the SA, the late end answers both its exchanges, and the path loses the peer's Delete of the SA it replaced
	peer.done = rekeying(peer.s)
	c.settle()
	c.carry(t, peer, late)
	c.carry(t, peer, late)
	if peer.pending == nil || !deletesIKE(peer.pending.inner) {
		t.Fatal("the peer sent no Delete of the SA it replaced")
	}
	made := peer.s.currentContext()
	c.takes(t, late, lost)
	if late.pending == nil || late.pending.exchange != IKE_FOLLOWUP_KE {
		t.Fatal("the late end's chained rekey did not win with its IKE_FOLLOWUP_KE to run")
	}
	c.takes(t, late, notifyAnswer(N_TEMPORARY_FAILURE))
	if err := <-ended; !rejectedWith(err, N_TEMPORARY_FAILURE) {
		t.Fatalf("the late end's rekey ended with %v, want the TEMPORARY_FAILURE", err)
	}
	if current := late.s.currentContext(); current.spiI != oldB.spiI {
		t.Errorf("after TEMPORARY_FAILURE the late end runs on %016x, want the old SA %016x and not the peer's %016x", current.spiI, oldB.spiI, made.spiI)
	}
}

// both ends rekey a classical IKE SA at once and each answers the other's rekey, and this end's rekey takes the answer to its own request and settles the crossing while Run is between placing the peer's SA and keeping the answer to the peer's rekey, as Run hands that answer on to the rekey's goroutine
// the path MTU read inside transmit, which keepAnswer runs before it takes stateMu, is where the decision runs
// the path loses this end's answer to the peer's rekey and its Delete of old, so the peer resends its rekey on old past retainedContextDeadline after this end's rekey
// the record of old kept from that answer serves the resend either way the nonces settle it, and both ends end on one SA
func TestCrossingSettledWhileItsAnswerIsSentServesTheResendPastTheRetention(t *testing.T) {
	for _, test := range []struct {
		name string
		// lowest places the lowest nonce as crossingNonces does, this end's exchange first
		lowest int
	}{
		{"this end wins", 2},
		{"this end yields", 0},
	} {
		t.Run(test.name, bubble.Run(func(t *testing.T) {
			c := newIKECrossing(t, false, test.lowest)
			toA := c.answer(t, c.a, c.b)
			request, crossed := c.sealed(t, c.b, c.a)
			decided := false
			c.a.s.fragments = true
			c.a.s.pathMTU = func() (int, error) {
				if !decided {
					decided = true
					c.takes(t, c.a, toA)
				}
				return 0, errors.New("no path MTU")
			}
			lost := c.deliver(t, c.a, crossed, request)
			c.a.s.pathMTU = nil
			if !decided {
				t.Fatal("this end's rekey took its answer before Run kept the answer to the peer's rekey")
			}
			if lost == nil || findType(lost, PayloadSA) == nil {
				t.Fatalf("this end answered the peer's rekey with %v, want its SA", payloadTypes(lost))
			}
			if c.a.pending != nil && deletesIKE(c.a.pending.inner) {
				c.takes(t, c.a, nil)
			}
			s := c.a.s
			s.stateMu.RLock()
			record, oldBy, replacedAt := s.recovery, s.oldBy, c.a.old.replacedAt
			s.stateMu.RUnlock()
			if record.replaced != c.a.old || record.mid != 0 || oldBy.Sub(replacedAt) <= retainedContextDeadline {
				t.Fatalf("the record of old %v at Message ID %d, old held %v after the rekey, want the record of the answer to the peer's rekey past %v", record.replaced == c.a.old, record.mid, oldBy.Sub(replacedAt), retainedContextDeadline)
			}
			time.Sleep(time.Until(replacedAt.Add(retainedContextDeadline + pastRetentionBy)))
			s.expireRetainedContexts(time.Now())
			again := c.deliver(t, c.a, crossed, request)
			if again == nil {
				t.Fatalf("the peer's resend %v after this end's rekey drew nothing", time.Since(replacedAt))
			}
			c.takes(t, c.b, again)
			c.finish(t)
			if current, peerCurrent := c.a.s.currentContext(), c.b.s.currentContext(); current.spiI != peerCurrent.spiI {
				t.Errorf("this end runs on %016x and the peer on %016x", current.spiI, peerCurrent.spiI)
			}
		}))
	}
}
