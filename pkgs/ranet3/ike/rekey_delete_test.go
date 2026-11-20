// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ike

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"ranet3.com/pkgs/ranet3/internal/bubble"
	"ranet3.com/pkgs/ranet3/transport"
)

// a quiet peer's liveness interval falls inside the sends of an unanswered request
const (
	quietRetransmit = 400 * time.Millisecond
	quietDPD        = 500 * time.Millisecond
)

// the times of the tests of a replaced IKE SA's Delete and of the SA kept past it, on a bubble's clock
const (
	// pastBound is how long past a deadline a test reads what the deadline did
	pastBound = time.Second
	// boundEdge is how close to a kept SA's bound a test asks on it before the bound and reads it dropped after
	boundEdge = time.Millisecond
	// answerWait is how long a peer of these tests waits for the session's answer before it takes none as the answer
	answerWait = time.Second
	// handledWithin is how long a test leaves Run to take a datagram it sent before it reads what the datagram did
	handledWithin = time.Second
	// readerIdle is the read deadline of a peer's reader loop, past every test
	readerIdle = time.Hour
	// oldLifetime is the lifetime of an old SA a test ends inside the test by its establishment time, and lateRekeyMargin puts that SA's own rekey due a second before it, behind the rekey the test starts
	oldLifetime, lateRekeyMargin = time.Hour, time.Second
	// keptAskAt is when after the rekey's answer a test asks on the kept SA well inside its bound
	keptAskAt = 30 * time.Second
	// nextRekeyAt is when after the rekey's answer this end's next rekey starts, with the old SA kept
	nextRekeyAt = 30 * time.Second
	// boundsApart is how far apart a kept SA's lifetime and its retention's bound lie, and dropLate how late the pass that drops it runs
	boundsApart, dropLate = 10 * time.Millisecond, 50 * time.Millisecond
	// failedEndWithin bounds how long after the rekey's answer a session that failed behind the Delete of the old SA takes to end
	failedEndWithin = 10 * time.Second
	// closeAfter is when after the rekey's answer a node closes the session
	closeAfter = 10 * time.Second
)

// keptRequestFailed is the warning of a kept SA that a request on it that failed ends alone
const keptRequestFailed = "ike dropping a replaced IKE SA kept after this end's unanswered Delete, since a request on it failed"

// keptRekeysAt are the times after this end's rekey's answer at which the peer rekeys the current SA with the old SA kept
var keptRekeysAt = []time.Duration{10 * time.Second, 30 * time.Second}

// sendTimes is when each of the first sends of a ranet3 request goes out, counted from its first send, where first is its first retransmission wait
func sendTimes(first time.Duration, sends int) []time.Duration {
	times := make([]time.Duration, sends)
	for attempt := 1; attempt < sends; attempt++ {
		times[attempt] = times[attempt-1] + retransmitDelay(first, attempt)
	}
	return times
}

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
// so the Delete ends after teardownRetransmits sends, which the session logs once, with that SA still held, the rekey stands, and a Child SA rekey waiting behind it completes over the new IKE SA
// a Delete's sends do not read the peer's liveness, so one peer, a quiet one, covers every peer, and TestKeptReplacedIKESAGoesAtItsBound holds how long the SA stays
func TestUnansweredDeleteOfAReplacedIKESAEndsAfterTheTeardownBudget(t *testing.T) {
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
	initiator.retransmitAfter, initiator.dpdEvery = quietRetransmit, quietDPD
	responder.dpdEvery = noDPD
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
	if initiator.contextRetired(old) {
		t.Error("the session dropped the IKE SA whose Delete went unanswered with the Delete")
	}
	if told := lines.said(slog.LevelInfo, "ike replaced IKE SA was not deleted by this end", "err"); len(told) != 1 {
		t.Errorf("the unanswered Delete was told %d times, want once", len(told))
	}
}

// RFC 7296 section 2.8.2: "The new IKE SA containing the lowest nonce SHOULD be deleted by the node that created it, and the other surviving new IKE SA MUST inherit all the Child SAs."
// the peer answers none of the sends of the Delete of the redundant IKE SA this end made
// so the Delete ends that SA alone after teardownRetransmits sends, which the session logs, the rekey stands, and a request waiting behind it is answered over the surviving IKE SA
func TestUnansweredDeleteOfARedundantIKESAEndsItAlone(t *testing.T) {
	lines := recordLines(t)
	p := newCollisionPeer(t, time.Now())
	s, suite := p.session, p.old.suite
	s.retransmitAfter, s.dpdEvery = unansweredRetransmit, noDPD

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

// RFC 7296 section 1.4.1: "Deleting an IKE SA implicitly closes any remaining Child SAs negotiated under it."
// this end's rekey loses the collision, and while its Delete of the redundant IKE SA is out the peer deletes the IKE SA the session runs on, as a peer that closes does
// the redundant SA is no collision the peer holds, so the session ends on the peer's Delete rather than take that SA
func TestPeerDeleteOfTheCurrentIKESAWhileTheRedundantOneIsDeletedEndsTheSession(t *testing.T) {
	bubble.Run(testPeerDeleteOfTheCurrentIKESAWhileTheRedundantOneIsDeletedEndsTheSession)(t)
}

func testPeerDeleteOfTheCurrentIKESAWhileTheRedundantOneIsDeletedEndsTheSession(t *testing.T) {
	p := newCollisionPeer(t, time.Now())
	s, suite := p.session, p.old.suite
	p.play(func(p *collisionPeer) {
		for {
			request, _, ok := p.read("the Delete of the redundant candidate")
			if !ok {
				return
			}
			if p.rekeyResend(request) {
				continue
			}
			if request.Header.SPIInitiator == p.localSPIi && request.Header.SPIResponder == collisionLoserSPIr && request.Header.ExchangeType == INFORMATIONAL {
				raw, err := EncryptMessage(suite, p.winner.SKei, Header{SPIInitiator: collisionPeerSPIi, SPIResponder: p.winnerSPIr, ExchangeType: INFORMATIONAL, Flags: FlagInitiator, MessageID: 0}, nil, deleteIKEPayloads())
				p.send("the peer's Delete of the IKE SA the session runs on", raw, err)
				return
			}
		}
	})
	run := runSession(t, s)
	go func() { _ = s.RekeyIKE() }()
	if err := endedWithin(t, run, "collided"); !errors.Is(err, errPeerDeletedIKE) {
		t.Errorf("the session ended with %v, want the peer's Delete", err)
	}
}

// this end's rekey is answered before the peer's crossing rekey reaches it, so it wins with no collision, and the peer holds this end's SA as its collision
// the path drops what this end sends on the old SA for the teardown's budget: the TEMPORARY_FAILURE to the peer's rekey and both sends of the Delete of the old SA
// the rekey then returns with the old SA still held, so the peer's resend of its rekey draws the TEMPORARY_FAILURE again, until the record of that refusal ends busyRequestBudget after it and drops the old SA
func TestReplacedIKESAOutlastsTheTeardownBudgetForACrossingPeer(t *testing.T) {
	bubble.Run(testReplacedIKESAOutlastsTheTeardownBudgetForACrossingPeer)(t)
}

func testReplacedIKESAOutlastsTheTeardownBudgetForACrossingPeer(t *testing.T) {
	retained := time.Now().Add(retainedContextDeadline)
	p := newCollisionPeer(t, time.Now())
	s, old := p.session, p.old
	// the peer's resends on the old SA are repeats, which prove nothing of it, so this end takes it as alive throughout and starts no liveness check
	s.dpdEvery = noDPD
	run := runSession(t, s)
	rekeyDone := make(chan error, 1)
	go func() { rekeyDone <- s.RekeyIKE() }()

	rekey, ownSPI := p.answerOwnRekey()
	answered := time.Now()
	deletion, _ := p.nextPast(rekey, "the Delete of the old SA", INFORMATIONAL, false)
	deletes := 1

	peerRekey, err := EncryptMessage(old.suite, old.sker, Header{SPIInitiator: collisionOldSPIi, SPIResponder: collisionOldSPIr, ExchangeType: CREATE_CHILD_SA, MessageID: 0}, nil, peerIKERekeyPayloads(t, collisionPeerSPIi))
	// refused reads this end's datagrams on the old SA until its answer to the peer's rekey, counting the sends of the Delete among them
	refused := func(what string) {
		t.Helper()
		for {
			message, raw, ok := p.read(what)
			if !ok {
				t.Fatalf("%s: none came, so the old SA stopped answering", what)
			}
			if message.Header.SPIInitiator != collisionOldSPIi {
				t.Fatalf("%s: none came on the old SA, and this end sent exchange %d on the IKE SA %016x", what, message.Header.ExchangeType, message.Header.SPIInitiator)
			}
			header, inner := p.opened(what, message, raw, message.Header.ExchangeType, message.Header.IsResponse())
			switch {
			case !header.IsResponse() && header.ExchangeType == INFORMATIONAL && header.MessageID == deletion.MessageID:
				deletes++
			case header.IsResponse() && header.ExchangeType == CREATE_CHILD_SA && header.MessageID == 0:
				if !notified(inner, N_TEMPORARY_FAILURE, nil) {
					t.Fatalf("the peer's rekey drew %v, want TEMPORARY_FAILURE", payloadTypes(inner))
				}
				return
			default:
				t.Fatalf("this end sent %+v on the old SA", *header)
			}
		}
	}
	if !p.send("the peer's rekey", peerRekey, err) {
		t.FailNow()
	}
	refused("the answer to the peer's rekey")
	refusedAt := time.Now()
	for deletes < teardownRetransmits {
		p.next("a send of the Delete of the old SA", INFORMATIONAL, false)
		deletes++
	}
	// the teardown's budget ends at the deadline after its last send, and the rekey with it, which frees the session's request
	if err := answeredWithin(t, rekeyDone, "the IKE SA rekey"); err != nil {
		t.Fatalf("the rekey failed: %v", err)
	}
	if held := time.Since(answered); held > teardownBudget(s) {
		t.Fatalf("the rekey held the session's request %v after its answer, past the teardown's budget %v of its Delete", held, teardownBudget(s))
	}
	if s.contextRetired(old) {
		t.Fatal("the session dropped the old SA with its unanswered Delete, so the peer's resend on it draws nothing")
	}
	// the peer resends its rekey on the old SA as a ranet3 peer's budget has it, its last idle send and the 2 its traffic adds, and this end's last send there was the Delete's second
	for _, at := range sendTimes(requestTimeout, maxRetransmits+2)[maxRetransmits-1:] {
		time.Sleep(time.Until(retained.Add(at - retainedContextDeadline)))
		if !p.send("the peer's rekey again", peerRekey, nil) {
			t.FailNow()
		}
		refused(fmt.Sprintf("the answer to the peer's rekey sent again at %v", at))
	}
	stillRunning(t, run)
	if deletes != teardownRetransmits {
		t.Errorf("the Delete of the old SA was sent %d times, want %d", deletes, teardownRetransmits)
	}
	if current := s.currentContext(); current.spiI != ownSPI {
		t.Errorf("the session is current on %016x, want this end's SA %016x", current.spiI, ownSPI)
	}
	time.Sleep(time.Until(refusedAt.Add(busyRequestBudget)) - pastBound)
	if s.contextRetired(old) {
		t.Fatalf("the session no longer holds the old SA %v after its refusal, short of the end of the record of it at %v", time.Since(refusedAt), busyRequestBudget)
	}
	time.Sleep(2 * pastBound)
	if !s.contextRetired(old) {
		t.Error("the session still holds the old SA past its deadline")
	}
}

// rekeyTransforms is the suite the peer of these tests answers this end's IKE SA rekey with
var rekeyTransforms = []Transform{{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128}, {Type: TransPRF, ID: PRF_HMAC_SHA2_256}, {Type: TransDH, ID: DH_CURVE25519}}

// ownRekeyAnswer is the peer's answer to the IKE SA rekey this end offered in inner, an SA whose responder SPI is spiR, with the SPI this end offered
func ownRekeyAnswer(t *testing.T, inner []RawPayload, spiR uint64) ([]RawPayload, uint64) {
	t.Helper()
	props, err := DecodeSA(findType(inner, PayloadSA).Body)
	if err != nil || len(props) == 0 {
		t.Fatalf("this end's rekey offers %v, %v", props, err)
	}
	answerDH, err := GenerateDH(DH_CURVE25519)
	if err != nil {
		t.Fatal(err)
	}
	return []RawPayload{
		{Type: PayloadSA, Body: EncodeSA([]Proposal{{Number: 1, Protocol: ProtoIKE, SPI: binary.BigEndian.AppendUint64(nil, spiR), Transforms: rekeyTransforms}})},
		{Type: PayloadNonce, Body: EncodeNonce(collisionAnswerNonce)},
		{Type: PayloadKE, Body: EncodeKE(DH_CURVE25519, answerDH.PublicBytes())},
	}, binary.BigEndian.Uint64(props[0].SPI)
}

// answerOwnRekey reads this end's IKE SA rekey on the old SA and answers it, and returns the request's header and the SPI this end offered
func (p *collisionPeer) answerOwnRekey() (*Header, uint64) {
	p.t.Helper()
	rekey, inner := p.next("this end's rekey", CREATE_CHILD_SA, false)
	answer, spi := ownRekeyAnswer(p.t, inner, collisionLoserSPIr)
	p.reply(CREATE_CHILD_SA, rekey.MessageID, answer)
	return rekey, spi
}

// peerIKERekeyPayloads is a peer's rekey of an IKE SA, offering the SPI spiI
func peerIKERekeyPayloads(t *testing.T, spiI uint64) []RawPayload {
	t.Helper()
	peerDH, err := GenerateDH(DH_CURVE25519)
	if err != nil {
		t.Fatal(err)
	}
	return []RawPayload{
		{Type: PayloadSA, Body: EncodeSA([]Proposal{{Number: 1, Protocol: ProtoIKE, SPI: binary.BigEndian.AppendUint64(nil, spiI), Transforms: rekeyTransforms}})},
		{Type: PayloadNonce, Body: EncodeNonce(collisionPeerNonce)},
		{Type: PayloadKE, Body: EncodeKE(DH_CURVE25519, peerDH.PublicBytes())},
	}
}

// sentDatagram is a datagram the session sent, decoded
type sentDatagram struct {
	message *Message
	raw     []byte
}

// unansweredReplacedDelete is a session whose classical IKE SA rekey the peer answers, with nothing after it, so every send of the Delete of the old SA goes unanswered
// it times the INFORMATIONAL requests the session then sends on the old SA and on the new one from the answer, and hands every other datagram to others
type unansweredReplacedDelete struct {
	p         *collisionPeer
	s         *Session
	old       *ikeContext
	run       <-chan error
	rekeyDone chan error
	newSPI    uint64
	answered  time.Time
	// deleting is closed at the first send of the Delete of the old SA
	deleting chan struct{}
	others   chan sentDatagram
	mu       sync.Mutex
	onOld    []time.Duration
	onNew    []time.Duration
}

// newUnansweredReplacedDelete runs the session after prepare set it up and answers its rekey
// the session starts now, so each time it takes the peer as alive reads as its own
func newUnansweredReplacedDelete(t *testing.T, prepare func(s *Session)) *unansweredReplacedDelete {
	t.Helper()
	p := newCollisionPeer(t, time.Now())
	u := &unansweredReplacedDelete{p: p, s: p.session, old: p.old, rekeyDone: make(chan error, 1), deleting: make(chan struct{}), others: make(chan sentDatagram, 64)}
	u.s.started = time.Now()
	prepare(u.s)
	u.run = runSession(t, u.s)
	go func() { u.rekeyDone <- u.s.RekeyIKE() }()
	_, u.newSPI = p.answerOwnRekey()
	u.answered = time.Now()
	peerLoop(t, p.conn, func() {
		buf := make([]byte, 4096)
		for {
			if err := p.conn.SetReadDeadline(time.Now().Add(readerIdle)); err != nil {
				return
			}
			n, _, err := p.conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			raw := append([]byte(nil), buf[4:n]...)
			message, err := DecodeMessage(raw)
			if err != nil {
				continue
			}
			if header := message.Header; header.IsResponse() || header.ExchangeType != INFORMATIONAL {
				select {
				case u.others <- sentDatagram{message, raw}:
				default:
				}
				continue
			}
			u.mu.Lock()
			switch message.Header.SPIInitiator {
			case collisionOldSPIi:
				if len(u.onOld) == 0 {
					close(u.deleting)
				}
				u.onOld = append(u.onOld, time.Since(u.answered))
			case u.newSPI:
				u.onNew = append(u.onNew, time.Since(u.answered))
			}
			u.mu.Unlock()
		}
	})
	return u
}

// sent is the times of the INFORMATIONAL requests the session sent on the old SA and on the new one so far
func (u *unansweredReplacedDelete) sent() (onOld, onNew []time.Duration) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return slices.Clone(u.onOld), slices.Clone(u.onNew)
}

// next is the session's next request of exchange on ctx, an SA this end initiated, read past every other datagram
func (u *unansweredReplacedDelete) next(t *testing.T, ctx *ikeContext, exchange ExchangeType) (*Header, []RawPayload) {
	t.Helper()
	deadline := time.After(answerBudget)
	for {
		select {
		case d := <-u.others:
			if header := d.message.Header; header.IsResponse() || header.SPIInitiator != ctx.spiI || header.ExchangeType != exchange {
				continue
			}
			inner, err := DecryptMessage(ctx.suite, ctx.skei, d.raw, d.message)
			if err != nil {
				t.Fatalf("decrypt the session's request: %v", err)
			}
			return &d.message.Header, inner
		case <-deadline:
			t.Fatalf("the session sent no request of exchange %d on %016x", exchange, ctx.spiI)
			return nil, nil
		}
	}
}

// ask sends the peer's request of exchange at mid on ctx, an SA this end initiated, and returns the session's answer, nil where none comes within answerWait
func (u *unansweredReplacedDelete) ask(t *testing.T, ctx *ikeContext, exchange ExchangeType, mid uint32, inner []RawPayload) []RawPayload {
	t.Helper()
	raw, err := EncryptMessage(ctx.suite, ctx.sker, Header{SPIInitiator: ctx.spiI, SPIResponder: ctx.spiR, ExchangeType: exchange, MessageID: mid}, nil, inner)
	if !u.p.send("the peer's request", raw, err) {
		t.FailNow()
	}
	deadline := time.After(answerWait)
	for {
		select {
		case d := <-u.others:
			if header := d.message.Header; !header.IsResponse() || header.SPIInitiator != ctx.spiI || header.ExchangeType != exchange || header.MessageID != mid {
				continue
			}
			answer, err := DecryptMessage(ctx.suite, ctx.skei, d.raw, d.message)
			if err != nil {
				t.Fatalf("decrypt the answer to the peer's request: %v", err)
			}
			if answer == nil {
				answer = []RawPayload{}
			}
			return answer
		case <-deadline:
			return nil
		}
	}
}

// answeredAtPeer reports whether the peer's own socket got an answer at mid on ctx, read once Run is blocked again
func (u *unansweredReplacedDelete) answeredAtPeer(ctx *ikeContext, mid uint32) bool {
	synctest.Wait()
	for {
		select {
		case d := <-u.others:
			if header := d.message.Header; header.IsResponse() && header.SPIInitiator == ctx.spiI && header.MessageID == mid {
				return true
			}
		default:
			return false
		}
	}
}

// heard is the session's endpoint and the time it last took the peer as alive, read once Run is blocked again
func (u *unansweredReplacedDelete) heard() (transport.Endpoint, int64) {
	synctest.Wait()
	return u.s.Mux().Endpoint(), u.s.lastActive.Load()
}

// leftAlone fails t where what came on the kept SA moved the session's endpoint or the time it last took the peer as alive from what heard read before it
func (u *unansweredReplacedDelete) leftAlone(t *testing.T, endpoint transport.Endpoint, active int64) {
	t.Helper()
	nowAt, nowActive := u.heard()
	if nowAt != endpoint {
		t.Errorf("what came on the kept SA moved the session's endpoint from %v to %v", endpoint, nowAt)
	}
	if nowActive != active {
		t.Errorf("what came on the kept SA took the peer as alive at %v, where the session last had it at %v", time.Duration(nowActive-1), time.Duration(active-1))
	}
}

// checksOnTime fails t where the session sent no INFORMATIONAL request on the new SA within a liveness interval of the rekey's answer, read just past that
func (u *unansweredReplacedDelete) checksOnTime(t *testing.T) {
	t.Helper()
	time.Sleep(time.Until(u.answered.Add(defaultDPDInterval + pastBound)))
	if _, onNew := u.sent(); len(onNew) == 0 || onNew[0] > defaultDPDInterval {
		t.Errorf("the session sent the INFORMATIONAL requests %v on the new SA, want a liveness check by %v after the rekey's answer", onNew, defaultDPDInterval)
	}
}

// sendFrom sends each datagram from conn, a peer's address the session does not send to, to the session
func (u *unansweredReplacedDelete) sendFrom(t *testing.T, conn *transport.MemoryConn, datagrams ...[]byte) {
	t.Helper()
	for _, raw := range datagrams {
		if _, err := conn.WriteToUDP(withNonESPMarker(raw), u.p.addr); err != nil {
			t.Fatalf("send to the session from %v: %v", conn.LocalAddr(), err)
		}
	}
}

// answerAt is the session's answer at mid on ctx that conn got within answerWait, decrypted, and nil where none came
func answerAt(t *testing.T, conn *transport.MemoryConn, ctx *ikeContext, mid uint32) []RawPayload {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(answerWait)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			return nil
		}
		if n <= NonESPMarkerLen {
			continue
		}
		raw := append([]byte(nil), buf[NonESPMarkerLen:n]...)
		message, err := DecodeMessage(raw)
		if err != nil {
			continue
		}
		if header := message.Header; !header.IsResponse() || header.SPIInitiator != ctx.spiI || header.MessageID != mid {
			continue
		}
		inner, err := DecryptMessage(ctx.suite, ctx.skei, raw, message)
		if err != nil {
			t.Fatalf("decrypt the answer at %v: %v", conn.LocalAddr(), err)
		}
		if inner == nil {
			inner = []RawPayload{}
		}
		return inner
	}
}

// teardownBudget is the time a Delete of an IKE SA takes from its first send to being deemed failed
func teardownBudget(s *Session) time.Duration {
	var budget time.Duration
	for attempt := 1; attempt <= teardownRetransmits; attempt++ {
		budget += retransmitDelay(s.retransmitAfter, attempt)
	}
	return budget
}

// noKeptSAWarning fails t where the session warned of the kept SA going
func noKeptSAWarning(t *testing.T, lines *lineRecorder) {
	t.Helper()
	for _, warning := range []string{"ike dropping an IKE SA a second rekey displaced", "ike dropping an IKE SA the peer never deleted", "ike dropping a replaced IKE SA at its lifetime"} {
		if told := lines.said(slog.LevelWarn, warning, "spi"); len(told) != 0 {
			t.Errorf("the session warned %q of the kept SA", warning)
		}
	}
}

// the rekey holds the session's one request through its Delete of the old SA, and an unanswered one for the teardown's budget, the old SA staying held past it
// the session is idle, so a liveness check on the new SA starts at the liveness interval from the rekey's answer
// a Delete's sends read neither the peer's liveness nor ESP, so a session with traffic takes the same path
func TestRekeyHoldsTheSessionsRequestForTheTeardownBudgetOfItsDelete(t *testing.T) {
	bubble.Run(testRekeyHoldsTheSessionsRequestForTheTeardownBudgetOfItsDelete)(t)
}

func testRekeyHoldsTheSessionsRequestForTheTeardownBudgetOfItsDelete(t *testing.T) {
	u := newUnansweredReplacedDelete(t, func(*Session) {})
	if err := answeredWithin(t, u.rekeyDone, "the IKE SA rekey"); err != nil {
		t.Fatalf("the rekey failed: %v", err)
	}
	if held, budget := time.Since(u.answered), teardownBudget(u.s); held > budget {
		t.Errorf("the rekey held the session's request %v after the answer, want at most %v", held, budget)
	}
	if u.s.contextRetired(u.old) {
		t.Error("the session dropped the old SA with its unanswered Delete")
	}
	time.Sleep(time.Until(u.answered.Add(defaultDPDInterval + pastBound)))
	onOld, onNew := u.sent()
	if len(onOld) != teardownRetransmits {
		t.Errorf("the Delete of the old SA was sent at %v, want %d sends", onOld, teardownRetransmits)
	}
	if len(onNew) == 0 || onNew[0] > defaultDPDInterval {
		t.Errorf("the session sent the INFORMATIONAL requests %v on the new SA, want a liveness check by %v", onNew, defaultDPDInterval)
	}
}

// the old SA reaches its lifetime while every send of its Delete goes unanswered, and past its lifetime it answers no request
// so the session drops it when that Delete is deemed failed instead of keeping it, and tells no kept SA
func TestUnansweredDeleteOfAReplacedIKESAPastItsLifetimeDropsIt(t *testing.T) {
	bubble.Run(testUnansweredDeleteOfAReplacedIKESAPastItsLifetimeDropsIt)(t)
}

func testUnansweredDeleteOfAReplacedIKESAPastItsLifetimeDropsIt(t *testing.T) {
	const left = 3 * time.Second
	lines := recordLines(t)
	u := newUnansweredReplacedDelete(t, func(s *Session) {
		s.timing.IKERekeyInterval, s.timing.RekeyMargin = oldLifetime, lateRekeyMargin
		s.rekeyJitterSource = func(time.Duration) (time.Duration, error) { return 0, nil }
		s.current.established = time.Now().Add(left - oldLifetime)
	})
	budget := teardownBudget(u.s)
	if budget <= left {
		t.Fatalf("the teardown budget %v ends inside the old SA's remaining lifetime %v", budget, left)
	}
	if err := answeredWithin(t, u.rekeyDone, "the IKE SA rekey"); err != nil {
		t.Fatalf("the rekey failed: %v", err)
	}
	if held := time.Since(u.answered); held > budget {
		t.Errorf("the rekey held the session's request %v after the answer, want at most %v", held, budget)
	}
	if onOld, _ := u.sent(); len(onOld) != teardownRetransmits {
		t.Errorf("the Delete of the old SA was sent at %v, want %d sends", onOld, teardownRetransmits)
	}
	if !u.s.contextRetired(u.old) {
		t.Error("the session keeps the old SA past its lifetime once its Delete went unanswered")
	}
	if told := lines.said(slog.LevelInfo, "ike dropping a replaced IKE SA kept after this end's unanswered Delete", "at"); len(told) != 0 {
		t.Errorf("the session told the old SA as kept past its Delete, at %v, where it never answered past it", told)
	}
	stillRunning(t, u.run)
}

// RFC 7296 section 2.8: "When the lifetime of a Security Association expires, the Security Association MUST NOT be used."
// the old SA kept once both sends of its Delete went unanswered answers the peer's requests at its next Message IDs while it is held, the last a moment before its bound
// and the session drops it at that bound, the earlier of its lifetime and retainedContextDeadline after the rekey, which it logs as the kept SA's end
func TestKeptReplacedIKESAGoesAtItsBound(t *testing.T) {
	for _, c := range []struct {
		at string
		// left is the old SA's lifetime left at the rekey, none where zero, and half the retention ends it first
		left time.Duration
	}{{keptToRetention, 0}, {"its lifetime", retainedContextDeadline / 2}} {
		t.Run(c.at, bubble.Run(func(t *testing.T) {
			lines := recordLines(t)
			var lifetime time.Time
			u := newUnansweredReplacedDelete(t, func(s *Session) {
				s.dpdEvery = noDPD
				if c.left > 0 {
					s.timing.IKERekeyInterval, s.timing.RekeyMargin = oldLifetime, lateRekeyMargin
					s.rekeyJitterSource = func(time.Duration) (time.Duration, error) { return 0, nil }
					s.current.established = time.Now().Add(c.left - oldLifetime)
					lifetime = time.Now().Add(c.left)
				}
			})
			bound := u.answered.Add(retainedContextDeadline)
			if c.left > 0 {
				bound = lifetime
			}
			if err := answeredWithin(t, u.rekeyDone, "the IKE SA rekey"); err != nil {
				t.Fatalf("the rekey failed: %v", err)
			}
			for mid, at := range []time.Time{u.answered.Add(keptAskAt), bound.Add(-boundEdge)} {
				time.Sleep(time.Until(at))
				if u.s.contextRetired(u.old) {
					t.Fatalf("the session dropped the old SA %v before its bound", time.Until(bound))
				}
				if answer := u.ask(t, u.old, INFORMATIONAL, uint32(mid), nil); answer == nil {
					t.Fatalf("the old SA, held %v before its bound, answered the peer's request at Message ID %d with nothing", time.Until(bound), mid)
				}
			}
			time.Sleep(time.Until(bound.Add(boundEdge)))
			if !u.s.contextRetired(u.old) {
				t.Error("the session still holds the old SA past its bound")
			}
			if told := lines.said(slog.LevelInfo, "ike dropping a replaced IKE SA kept after this end's unanswered Delete", "at"); len(told) != 1 || told[0].String() != c.at {
				t.Errorf("the session told the old SA's end at %v, want once at %q", told, c.at)
			}
			noKeptSAWarning(t, lines)
			stillRunning(t, u.run)
		}))
	}
}

// the kept SA's end is told by the deadline that dropped it, which a pass that runs late finds already past the other bound
// so a lifetime boundsApart after the retention's bound, both past at a drop dropLate late, still tells the retention, and a lifetime boundsApart before it tells the lifetime
func TestKeptReplacedIKESADropTellsTheBoundThatDroppedIt(t *testing.T) {
	for _, c := range []struct {
		at string
		// lifetimeAfter is how long after the retention's bound the old SA's lifetime ends, before it where negative
		lifetimeAfter time.Duration
	}{{keptToRetention, boundsApart}, {"its lifetime", -boundsApart}} {
		t.Run(c.at, func(t *testing.T) {
			lines := recordLines(t)
			p := newCollisionPeer(t, time.Now())
			s, old := p.session, p.old
			s.timing.IKERekeyInterval = oldLifetime
			retention := time.Now().Add(-dropLate)
			lifetime := retention.Add(c.lifetimeAfter)
			old.ownDelete, old.kept, old.established = true, true, lifetime.Add(-s.timing.IKERekeyInterval)
			s.current = &ikeContext{suite: old.suite, spiI: 0x6162636465666768, spiR: 0x7172737475767778, established: time.Now(), skD: old.skD, skei: make([]byte, 20), sker: make([]byte, 20)}
			s.old, s.oldBy = old, retention
			if lifetime.Before(retention) {
				s.oldBy = lifetime
			}
			s.expireRetainedContexts(time.Now())
			if !s.contextRetired(old) {
				t.Fatal("the session holds the kept SA past both of its bounds")
			}
			if told := lines.said(slog.LevelInfo, "ike dropping a replaced IKE SA kept after this end's unanswered Delete", "at"); len(told) != 1 || told[0].String() != c.at {
				t.Errorf("the session told the kept SA's end at %v, want once at %q", told, c.at)
			}
		})
	}
}

// the old SA kept once its Delete went unanswered serves a peer still on it, so it answers that peer's next request, and the peer's Delete of it ends that SA alone
func TestKeptReplacedIKESAAnswersThePeerStillOnIt(t *testing.T) {
	bubble.Run(testKeptReplacedIKESAAnswersThePeerStillOnIt)(t)
}

func testKeptReplacedIKESAAnswersThePeerStillOnIt(t *testing.T) {
	lines := recordLines(t)
	u := newUnansweredReplacedDelete(t, func(s *Session) { s.dpdEvery = noDPD })
	if err := answeredWithin(t, u.rekeyDone, "the IKE SA rekey"); err != nil {
		t.Fatalf("the rekey failed: %v", err)
	}
	if answer := u.ask(t, u.old, INFORMATIONAL, 0, nil); answer == nil {
		t.Fatal("the kept SA answered the peer's request at its next Message ID with nothing")
	}
	if answer := u.ask(t, u.old, INFORMATIONAL, 1, deleteIKEPayloads()); answer == nil {
		t.Error("the kept SA answered the peer's Delete of it with nothing")
	}
	time.Sleep(handledWithin)
	stillRunning(t, u.run)
	if !u.s.contextRetired(u.old) {
		t.Error("the peer's Delete of the kept SA left it held")
	}
	if told := lines.said(slog.LevelWarn, keptRequestFailed, "spi"); len(told) != 0 {
		t.Errorf("the session took the peer's Delete of the kept SA as a request on it that failed: %q", told)
	}
	if current := u.s.currentContext(); current.spiI != u.newSPI {
		t.Errorf("the session is current on %016x, want the SA its rekey made %016x", current.spiI, u.newSPI)
	}
}

// RFC 7296 section 2.11: "MUST respond to the address and port from which the request was received."
// a fresh request on the kept SA comes from an address the session does not send to, after this end's rekey returned and inside the liveness interval from its answer
// the answer goes to that address and not to the peer's own, and the request moves nothing of the session: its endpoint stays, its last proof of the peer stays, and the liveness check on the new SA falls due a liveness interval after the rekey's answer
// the same request again from a third address is a repeat, which moves nothing either
func TestKeptReplacedIKESAAnswersAtTheSourceAndMovesNothing(t *testing.T) {
	bubble.Run(testKeptReplacedIKESAAnswersAtTheSourceAndMovesNothing)(t)
}

func testKeptReplacedIKESAAnswersAtTheSourceAndMovesNothing(t *testing.T) {
	u := newUnansweredReplacedDelete(t, func(*Session) {})
	if err := answeredWithin(t, u.rekeyDone, "the IKE SA rekey"); err != nil {
		t.Fatalf("the rekey failed: %v", err)
	}
	if asked := time.Since(u.answered); asked >= defaultDPDInterval {
		t.Fatalf("the rekey returned %v after its answer, past the liveness interval %v the test asks inside", asked, defaultDPDInterval)
	}
	endpoint, active := u.heard()
	moved, third := listenPeer(t), listenPeer(t)
	request, err := EncryptMessage(u.old.suite, u.old.sker, Header{SPIInitiator: u.old.spiI, SPIResponder: u.old.spiR, ExchangeType: INFORMATIONAL, MessageID: 0}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	u.sendFrom(t, moved, request)
	if answerAt(t, moved, u.old, 0) == nil {
		t.Fatal("the kept SA sent no answer to the address the request came from")
	}
	u.sendFrom(t, third, request)
	u.leftAlone(t, endpoint, active)
	if u.answeredAtPeer(u.old, 0) {
		t.Error("the peer's own address got an answer to the request that came from another")
	}
	u.checksOnTime(t)
	stillRunning(t, u.run)
}

// a request on the kept SA that dispatch fails ends that SA alone, from any address: the session runs on over the new SA, the failure's answer, where one goes, reaches the address the request came from, and nothing of the session moves
func TestKeptReplacedIKESAFailureEndsItAlone(t *testing.T) {
	ask := func(t *testing.T, old *ikeContext, mid uint32, inner []RawPayload) [][]byte {
		t.Helper()
		raw, err := EncryptMessage(old.suite, old.sker, Header{SPIInitiator: old.spiI, SPIResponder: old.spiR, ExchangeType: INFORMATIONAL, MessageID: mid}, nil, inner)
		if err != nil {
			t.Fatal(err)
		}
		return [][]byte{raw}
	}
	invalidSyntax := func(answer []RawPayload) bool { return notified(answer, N_INVALID_SYNTAX, nil) }
	for _, c := range []struct {
		name    string
		prepare func(s *Session)
		// first is a request the kept SA answers before the failing datagrams, at Message ID 0
		first bool
		mid   uint32
		send  func(t *testing.T, old *ikeContext) [][]byte
		// answered reports whether an answer is the one the failure draws, and is nil where the failure draws none
		answered func(answer []RawPayload) bool
		// warned is whether the session warns keptRequestFailed, as it does where the request would otherwise end the session rather than a retained SA alone
		warned bool
	}{
		// RFC 7296 section 2.21.3: "If a peer parsing a request notices that it is badly formatted (after it has passed the message authentication code checks and window checks) and it returns an INVALID_SYNTAX notification, then this error notification is considered fatal in both peers, meaning that the IKE SA is deleted without needing an explicit Delete payload."
		{name: "a request whose payload chain does not decode", send: func(t *testing.T, old *ikeContext) [][]byte {
			raw, err := encryptMessagePlaintextIV(old.suite, old.sker, Header{SPIInitiator: old.spiI, SPIResponder: old.spiR, ExchangeType: INFORMATIONAL}, nil, PayloadN, []byte{0, 0, 0, 3, 0}, make([]byte, 8))
			if err != nil {
				t.Fatal(err)
			}
			return [][]byte{raw}
		}, answered: invalidSyntax},
		{name: "a Delete payload that does not decode", send: func(t *testing.T, old *ikeContext) [][]byte {
			return ask(t, old, 0, []RawPayload{{Type: PayloadD, Body: []byte{1}}})
		}, answered: invalidSyntax},
		// RFC 7383 section 5: "In either case, the receiver SHOULD drop the connection and discard all the received fragments."
		{name: "a request's fragments past the reassembly limit", prepare: func(s *Session) { s.fragments = true }, send: func(t *testing.T, old *ikeContext) [][]byte {
			return cutInto(t, old.suite, old.sker, Header{SPIInitiator: old.spiI, SPIResponder: old.spiR, ExchangeType: INFORMATIONAL}, []RawPayload{bulkyStatus(reassemblyLimit)}, 4000)
		}},
		{name: "a repeat's fragments past the reassembly limit", prepare: func(s *Session) { s.fragments = true }, first: true, send: func(t *testing.T, old *ikeContext) [][]byte {
			return cutInto(t, old.suite, old.sker, Header{SPIInitiator: old.spiI, SPIResponder: old.spiR, ExchangeType: INFORMATIONAL}, []RawPayload{bulkyStatus(reassemblyLimit)}, 4000)
		}},
		// RFC 7296 section 2.21.2: "In an IKE_AUTH exchange, or in the INFORMATIONAL exchange immediately following it (in case an error happened when processing a response to IKE_AUTH), the UNSUPPORTED_CRITICAL_PAYLOAD, INVALID_SYNTAX, and AUTHENTICATION_FAILED notifications are the only ones to cause the IKE SA to be deleted or not created, without a Delete payload."
		{name: "an authentication failure in the exchange after IKE_AUTH", prepare: func(s *Session) {
			s.current.answeredAuth, s.current.authMID, s.current.nextPeerMID = true, 1, 2
		}, mid: 2, send: func(t *testing.T, old *ikeContext) [][]byte {
			return ask(t, old, 2, []RawPayload{{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_AUTHENTICATION_FAILED})}})
		}, answered: func(answer []RawPayload) bool { return len(answer) == 0 }, warned: true},
		// RFC 7296 section 2.2: "In the unlikely event that Message IDs grow too large to fit in 32 bits, the IKE SA MUST be closed or rekeyed."
		{name: "a request at the last Message ID", prepare: func(s *Session) { s.current.nextPeerMID = maxMessageID }, mid: maxMessageID, send: func(t *testing.T, old *ikeContext) [][]byte {
			return ask(t, old, maxMessageID, nil)
		}, warned: true},
		// the kept SA's answer to a request in an IKE Fragment message seals at the SA's last IV, which leaves the answer's cut none, so this end cannot keep the answer
		{name: "an answer this end cannot keep", prepare: func(s *Session) { s.fragments = true }, send: func(t *testing.T, old *ikeContext) [][]byte {
			old.sendIV.Store(math.MaxUint64 - 1)
			return cutInto(t, old.suite, old.sker, Header{SPIInitiator: old.spiI, SPIResponder: old.spiR, ExchangeType: INFORMATIONAL}, nil, 4000)
		}, warned: true},
	} {
		t.Run(c.name, bubble.Run(func(t *testing.T) {
			lines := recordLines(t)
			u := newUnansweredReplacedDelete(t, func(s *Session) {
				if c.prepare != nil {
					c.prepare(s)
				}
			})
			if err := answeredWithin(t, u.rekeyDone, "the IKE SA rekey"); err != nil {
				t.Fatalf("the rekey failed: %v", err)
			}
			moved := listenPeer(t)
			if c.first {
				u.sendFrom(t, moved, ask(t, u.old, 0, nil)...)
				if answerAt(t, moved, u.old, 0) == nil {
					t.Fatal("the kept SA sent no answer to the request ahead of the failure")
				}
			}
			if asked := time.Since(u.answered); asked >= defaultDPDInterval {
				t.Fatalf("the failure comes %v after the rekey's answer, past the liveness interval %v the test asks inside", asked, defaultDPDInterval)
			}
			if !u.s.keptContext(u.old) || u.s.contextRetired(u.old) {
				t.Fatal("the session does not hold the old SA as kept")
			}
			endpoint, active := u.heard()
			u.sendFrom(t, moved, c.send(t, u.old)...)
			answer := answerAt(t, moved, u.old, c.mid)
			switch {
			case c.answered == nil && answer != nil:
				t.Errorf("the failure drew %v at the address it came from, want no answer", payloadTypes(answer))
			case c.answered != nil && answer == nil:
				t.Error("the failure drew no answer at the address it came from")
			case c.answered != nil && !c.answered(answer):
				t.Errorf("the failure drew %v at the address it came from", payloadTypes(answer))
			}
			u.leftAlone(t, endpoint, active)
			if u.answeredAtPeer(u.old, c.mid) {
				t.Error("the peer's own address got an answer to the failure that came from another")
			}
			stillRunning(t, u.run)
			if !u.s.contextRetired(u.old) {
				t.Error("the failure left the kept SA held")
			}
			if told := lines.said(slog.LevelWarn, keptRequestFailed, "spi"); (len(told) != 0) != c.warned {
				t.Errorf("the session warned %q, want the warning %v", told, c.warned)
			}
			if current := u.s.currentContext(); current.spiI != u.newSPI {
				t.Errorf("the session is current on %016x, want the SA its rekey made %016x", current.spiI, u.newSPI)
			}
			u.checksOnTime(t)
			stillRunning(t, u.run)
		}))
	}
}

// a kept IKE SA answers at the request's source, which need not be the endpoint the session's record of sends is about
// so its reply neither ends an outage of sends to the endpoint nor starts one
func TestKeptReplacedIKESAReplyLeavesTheRecordOfSends(t *testing.T) {
	bubble.Run(testKeptReplacedIKESAReplyLeavesTheRecordOfSends)(t)
}

func testKeptReplacedIKESAReplyLeavesTheRecordOfSends(t *testing.T) {
	mux, elsewhere := lifecycleMuxes(t)
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128}
	kept := &ikeContext{suite: suite, spiI: 3, spiR: 4, skei: make([]byte, 20), sker: make([]byte, 20), kept: true}
	events := &recorder{}
	s := &Session{mux: mux, current: &ikeContext{suite: suite, spiI: 1, spiR: 2}, old: kept, events: events.record, sendFailures: 1}
	request, err := EncryptMessage(suite, kept.sker, Header{SPIInitiator: kept.spiI, SPIResponder: kept.spiR, ExchangeType: INFORMATIONAL}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var pending *pendingRequest
	if s.dispatch(request, elsewhere.Endpoint(), &pending) {
		t.Error("the request on the kept SA was taken as the peer alive")
	}
	if kept.lastPeer.response == nil {
		t.Fatal("the kept SA kept no answer to the request")
	}
	if s.sendFailures != 1 || recordedKind(events, "ike.send.recovered") != 0 || recordedKind(events, "ike.send.failed") != 0 {
		t.Errorf("the kept SA's reply left %d failed sends to the endpoint and recorded %q, want the 1 before it and no event", s.sendFailures, events.recorded())
	}
}

// RFC 7383 section 5: "In either case, the receiver SHOULD drop the connection and discard all the received fragments."
// a kept IKE SA that this end's next rekey displaced while Run took its fragments is no longer held, and its fragments past the reassembly limit end nothing else: the session's mux stays open and no IKE SA is told closed
func TestFragmentsPastTheLimitOnADisplacedKeptIKESAEndNothingElse(t *testing.T) {
	bubble.Run(testFragmentsPastTheLimitOnADisplacedKeptIKESAEndNothingElse)(t)
}

func testFragmentsPastTheLimitOnADisplacedKeptIKESAEndNothingElse(t *testing.T) {
	mux, _ := lifecycleMuxes(t)
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128}
	displaced := &ikeContext{suite: suite, spiI: 3, spiR: 4, kept: true}
	events := &recorder{}
	s := &Session{mux: mux, current: &ikeContext{suite: suite, spiI: 1, spiR: 2}, events: events.record}
	s.fragmentLimit(displaced, 0, errFragmentLimit)
	if mux.IsClosed() || recordedKind(events, "ike.sa.closed") != 0 {
		t.Errorf("fragments past the limit on a displaced kept SA closed the session %v and recorded %q, want it open and no event", mux.IsClosed(), events.recorded())
	}
}

// RFC 7296 section 2.25.2: "If a peer receives a request to delete a Child SA when it is currently rekeying the IKE SA, it SHOULD reply as usual, with a Delete payload."
// the peer still on the kept SA deletes the Child SA the session carries, so the session closes it and names its own SPI of it in the answer
// a Delete naming an SPI the session does not hold draws an empty answer and leaves the Child SA, and the session runs on after either
func TestKeptReplacedIKESAClosesTheChildSAThePeerDeletes(t *testing.T) {
	const localSPI, remoteSPI, unheldSPI = 0x10203040, 0x50607080, 0x0badf00d
	for _, c := range []struct {
		name  string
		named uint32
		// closes is whether the Delete closes the Child SA, which the answer then names
		closes bool
	}{
		{name: "the Child SA the session carries", named: remoteSPI, closes: true},
		{name: "an SPI the session does not hold", named: unheldSPI},
	} {
		t.Run(c.name, bubble.Run(func(t *testing.T) {
			u := newUnansweredReplacedDelete(t, func(s *Session) {
				s.dpdEvery = noDPD
				s.child = ChildSA{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, LocalSPI: localSPI, RemoteSPI: remoteSPI}
			})
			if err := answeredWithin(t, u.rekeyDone, "the IKE SA rekey"); err != nil {
				t.Fatalf("the rekey failed: %v", err)
			}
			deletion := []RawPayload{{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoESP, SPIs: [][]byte{binary.BigEndian.AppendUint32(nil, c.named)}})}}
			answer := u.ask(t, u.old, INFORMATIONAL, 0, deletion)
			if answer == nil {
				t.Fatal("the kept SA answered the peer's Delete of a Child SA with nothing")
			}
			child := u.s.Child()
			if !c.closes {
				if len(answer) != 0 || child.LocalSPI != localSPI {
					t.Errorf("the Delete of an SPI the session does not hold drew %v and left the Child SA %08x, want an empty answer and %08x", payloadTypes(answer), child.LocalSPI, uint32(localSPI))
				}
			} else {
				d := findType(answer, PayloadD)
				if d == nil {
					t.Fatalf("the kept SA answered the peer's Delete of the Child SA with %v, want this end's Delete of it", payloadTypes(answer))
				}
				if named, err := DecodeDelete(d.Body); err != nil || named.Protocol != ProtoESP || len(named.SPIs) != 1 || binary.BigEndian.Uint32(named.SPIs[0]) != localSPI {
					t.Errorf("the answer deletes %+v, %v, want this end's SPI %08x of the Child SA", named, err, uint32(localSPI))
				}
				if child.LocalSPI != 0 {
					t.Errorf("the session still carries the Child SA %08x the peer deleted", child.LocalSPI)
				}
			}
			synctest.Wait()
			stillRunning(t, u.run)
		}))
	}
}

// RFC 7296 section 2.8: "After the new equivalent IKE SA is created, the initiator deletes the old IKE SA"
// once this end's Delete of the old SA is over, unanswered, the old SA serves only a peer still on it, which no later rekey of the current SA comes from
// so the peer's rekey of the SA the session runs on draws an SA, as with no SA kept, and so does this end's next rekey, and the kept SA gives way to either without a warning
func TestKeptReplacedIKESAGivesWayToALaterRekey(t *testing.T) {
	for _, at := range keptRekeysAt {
		t.Run(fmt.Sprintf("the peer's at %v", at), bubble.Run(func(t *testing.T) {
			lines := recordLines(t)
			u := newUnansweredReplacedDelete(t, func(s *Session) { s.dpdEvery = noDPD })
			if err := answeredWithin(t, u.rekeyDone, "the IKE SA rekey"); err != nil {
				t.Fatalf("the rekey failed: %v", err)
			}
			time.Sleep(time.Until(u.answered.Add(at)))
			const peerSPI = 0x5152535455565758
			if answer := u.ask(t, u.s.currentContext(), CREATE_CHILD_SA, 0, peerIKERekeyPayloads(t, peerSPI)); findType(answer, PayloadSA) == nil {
				t.Fatalf("the peer's rekey of the current SA %v after this end's rekey drew %v, want an SA", at, payloadTypes(answer))
			}
			if current := u.s.currentContext(); current.spiI != peerSPI {
				t.Errorf("the session is current on %016x, want the peer's SA %016x", current.spiI, uint64(peerSPI))
			}
			if !u.s.contextRetired(u.old) {
				t.Error("the kept SA did not give way to the peer's rekey")
			}
			noKeptSAWarning(t, lines)
			stillRunning(t, u.run)
		}))
	}
	t.Run("this end's next", bubble.Run(func(t *testing.T) {
		lines := recordLines(t)
		u := newUnansweredReplacedDelete(t, func(s *Session) { s.dpdEvery = noDPD })
		if err := answeredWithin(t, u.rekeyDone, "the IKE SA rekey"); err != nil {
			t.Fatalf("the rekey failed: %v", err)
		}
		time.Sleep(time.Until(u.answered.Add(nextRekeyAt)))
		current := u.s.currentContext()
		done := make(chan error, 1)
		go func() { done <- u.s.RekeyIKE() }()
		rekey, inner := u.next(t, current, CREATE_CHILD_SA)
		answer, spi := ownRekeyAnswer(t, inner, 0x4142434445464748)
		raw, err := EncryptMessage(current.suite, current.sker, Header{SPIInitiator: current.spiI, SPIResponder: current.spiR, ExchangeType: CREATE_CHILD_SA, Flags: FlagResponse, MessageID: rekey.MessageID}, nil, answer)
		if !u.p.send("the answer to this end's next rekey", raw, err) {
			t.FailNow()
		}
		if err := answeredWithin(t, done, "this end's next rekey"); err != nil {
			t.Fatalf("this end's next rekey failed: %v", err)
		}
		if now := u.s.currentContext(); now.spiI != spi {
			t.Errorf("the session is current on %016x, want the SA its next rekey made %016x", now.spiI, spi)
		}
		if !u.s.contextRetired(u.old) {
			t.Error("the kept SA did not give way to this end's next rekey")
		}
		if told := lines.said(slog.LevelInfo, "ike dropping a replaced IKE SA kept after this end's unanswered Delete, which a later rekey replaced", "spi"); len(told) != 1 {
			t.Errorf("the kept SA giving way was told %d times, want once", len(told))
		}
		noKeptSAWarning(t, lines)
		stillRunning(t, u.run)
	}))
}

// RFC 7296 section 2.8.2: "it SHOULD return TEMPORARY_FAILURE because it is an IKE SA that it is currently trying to close"
// while this end's Delete of the SA its rekey replaced is out, the peer rekeys that SA with a request that carries no KE payload
// a rekey of an SA that is not current is refused before the request is read, so the peer draws TEMPORARY_FAILURE and the SA stays for the Delete, where reading the request would answer INVALID_SYNTAX and end that SA
func TestPeerRekeyOfTheReplacedIKESADuringItsDeleteIsRefusedUnread(t *testing.T) {
	bubble.Run(testPeerRekeyOfTheReplacedIKESADuringItsDeleteIsRefusedUnread)(t)
}

func testPeerRekeyOfTheReplacedIKESADuringItsDeleteIsRefusedUnread(t *testing.T) {
	p := newCollisionPeer(t, time.Now())
	s, old := p.session, p.old
	s.dpdEvery = noDPD
	runSession(t, s)
	go func() { _ = s.RekeyIKE() }()
	rekey, _ := p.answerOwnRekey()
	p.nextPast(rekey, "the Delete of the old SA", INFORMATIONAL, false)
	p.request(CREATE_CHILD_SA, 0, peerIKERekeyPayloads(t, collisionPeerSPIi)[:2])
	for {
		message, raw, ok := p.read("the answer to the peer's rekey")
		if !ok {
			t.Fatal("no answer to the peer's rekey of the old SA")
		}
		header, inner := p.opened("a message on the old SA", message, raw, message.Header.ExchangeType, message.Header.IsResponse())
		if !header.IsResponse() {
			continue
		}
		if !notified(inner, N_TEMPORARY_FAILURE, nil) {
			t.Fatalf("the peer's rekey of the old SA during this end's Delete drew %v, want TEMPORARY_FAILURE", payloadTypes(inner))
		}
		break
	}
	synctest.Wait()
	if s.contextRetired(old) {
		t.Error("the peer's rekey of the old SA ended that SA during its Delete")
	}
}

// RFC 7296 section 2.4: "In this case, an IKE endpoint SHOULD send a Delete payload indicating that it has closed the IKE SA unless the other endpoint is no longer responding."
// the session ends on a failure of its own while the Delete of the old SA goes unanswered, and sends its Delete of the new SA within failedEndWithin of the rekey's answer
// a Delete's sends do not read the peer's liveness, so an idle peer covers one alive throughout
func TestRunEndingBehindAnUnansweredDeleteOfAReplacedIKESA(t *testing.T) {
	bubble.Run(testRunEndingBehindAnUnansweredDeleteOfAReplacedIKESA)(t)
}

func testRunEndingBehindAnUnansweredDeleteOfAReplacedIKESA(t *testing.T) {
	u := newUnansweredReplacedDelete(t, func(s *Session) { s.childFailed = make(chan error, 1) })
	failure := errors.New("the dataplane refused the Child SA")
	// the failure comes once the Delete is out, so it is the request the session's own Delete waits behind
	<-u.deleting
	u.s.ChildFailed(failure)
	if err := endedWithin(t, u.run, "failed"); !errors.Is(err, failure) {
		t.Errorf("the session ended with %v, want %v", err, failure)
	}
	if ended := time.Since(u.answered); ended > failedEndWithin {
		t.Errorf("the session ended %v after the rekey's answer, want at most %v", ended, failedEndWithin)
	}
	if _, onNew := u.sent(); len(onNew) == 0 {
		t.Error("the session sent no Delete of the new SA")
	}
}

// a node closes the session closeAfter a rekey whose Delete of the old SA goes unanswered, with the peer alive throughout
// the rekey has given the session's request back by then, so the close sends its Delete of the new SA at once, inside the deleteGrace internal/client waits for it
func TestCloseAfterAnUnansweredDeleteOfAReplacedIKESASendsItsDelete(t *testing.T) {
	bubble.Run(testCloseAfterAnUnansweredDeleteOfAReplacedIKESASendsItsDelete)(t)
}

func testCloseAfterAnUnansweredDeleteOfAReplacedIKESASendsItsDelete(t *testing.T) {
	u := newUnansweredReplacedDelete(t, func(s *Session) { s.dpdEvery = noDPD })
	time.Sleep(time.Until(u.answered.Add(closeAfter)))
	// a goroutine waiting on a mutex stops the bubble's clock, so the test asks whether the close would wait before it closes
	if !u.s.requestMu.TryLock() {
		t.Fatalf("the rekey still holds the session's request %v after its answer, so a close sends no Delete", closeAfter)
	}
	u.s.requestMu.Unlock()
	closed := time.Now()
	go func() { _ = u.s.DeleteIKE() }()
	time.Sleep(deleteGrace)
	if _, onNew := u.sent(); len(onNew) == 0 || onNew[0] < closed.Sub(u.answered) {
		t.Errorf("the session sent the INFORMATIONAL requests %v on the new SA, want the close's Delete within %v of %v", onNew, deleteGrace, closed.Sub(u.answered))
	}
	u.s.mux.Close()
	_ = endedWithin(t, u.run, "closed")
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
	initiator.dpdEvery, responder.dpdEvery = noDPD, noDPD
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
// that Delete ends after its teardownRetransmits sends, and the session then sends the Delete of the IKE SA it holds, which the peer answers, and ends with the lifetime's error
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
	initiator.rekeyJitterSource = func(time.Duration) (time.Duration, error) { return 0, nil }
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
