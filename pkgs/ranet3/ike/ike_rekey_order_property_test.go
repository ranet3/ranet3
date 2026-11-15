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

// answer is to's answer to the request from's rekey waits on, nil where to holds no SA for it
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
	return sealedAnswer(t, ctx, answer.whole)
}

// takes hands e's rekey the answer to its request as e's Run hands it on, nil where none came
// it mirrors Run's pass after its select (liveness.go:786-801) and dispatch's hand-over of an answer (:1126): an exchange whose SA e no longer holds ends, an unanswered one on a retained SA ends that SA alone, and one on the current SA ends the session
func (c *ikeCrossing) takes(t *testing.T, e *ikeCrossingEnd, answer []RawPayload) {
	t.Helper()
	request := e.pending
	e.pending = nil
	switch {
	case e.s.contextRetired(request.context):
		request.result <- requestResult{err: errors.New("ike: the IKE SA carrying this exchange was replaced")}
	case answer != nil:
		request.result <- requestResult{inner: answer}
	case e.s.removeRetainedContext(request.context):
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
	suite, lists := classicalSuite, Suites{ikeCipher: []Transform{encrAES128}, kex: []kexEntry{entryX25519}}
	if chained {
		suite, lists = chainSuite, chainLists
	}
	// this end's Ni and the peer's Nr in this end's exchange, then the peer's Ni and this end's Nr in the peer's
	nonces := crossingNonces(t, lowest)
	oldA := chainContext(t, suite)
	oldB := &ikeContext{suite: suite, spiI: oldA.spiI, spiR: oldA.spiR, skD: oldA.skD, skei: oldA.skei, sker: oldA.sker, responder: true, established: oldA.established}
	c := &ikeCrossing{a: newIKECrossingEnd(t, oldA, lists, nonces[0], nonces[3]), b: newIKECrossingEnd(t, oldB, lists, nonces[2], nonces[1])}
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
