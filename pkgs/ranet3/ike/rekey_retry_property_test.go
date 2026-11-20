// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package ike

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/bubble"
	"ranet3.com/pkgs/ranet3/internal/pbt"
)

const (
	// modelSteps is the most steps one case of the model runs
	modelSteps = 8
	// modelDrop is how long one drop of the answers to rekeys lasts, shorter than a request's busy budget
	modelDrop = busyRequestBudget / 2
	// modelDropSpacing is how long after a drop ends the next one toward the same end may start: the longest wait between two sends of a request, so a send of every request running across the space falls in it, and answerBudget for that send's answer to return
	modelDropSpacing = requestTimeout<<(maxRetransmits-1) + answerBudget
)

// modelLists are the lists both ends of a case run, drawn first: the classical ones, and the defaults, whose x25519+mlkem768 rekeys run an additional key exchange
var modelLists = []Suites{classicalLists, {}}

// modelAdvances are the times a step lets pass after its event, on the bubble's clock
var modelAdvances = []time.Duration{time.Second, 30 * time.Second, retainedContextDeadline, busyRequestBudget / 2}

// the model's events, each drawn by its index
const (
	modelInitiatorRekeys = iota
	modelResponderRekeys
	modelBothRekey
	modelDropRekeyAnswers
	modelDropAnswersToInitiator
	modelDropAnswersToResponder
	modelHoldInitiatorDeletes
	modelHoldResponderDeletes
	modelReleaseDeletes
	modelInitiatorRequests
	modelResponderRequests
	modelHolderRequests
	// modelCrossingToResponderLost drops the answers to rekeys sent to the responder, holds the initiator's Deletes and starts both ends' rekeys, so an initiator that wins against the responder's chain still open at it keeps the answer that opened it for the responder's resends
	modelCrossingToResponderLost
	// modelCrossingToInitiatorLost is that crossing with the ends' parts swapped
	modelCrossingToInitiatorLost
)

// modelDraws lists each event as many times as it weighs in a step's draw: the rekeys, the holds of Deletes and the crossings that lose one end's answers, which lead to a crossing against an open chain, a refusal on the current SA from a crossing's candidate still held, and the answers the record keeps, twice or three times, the rest once
var modelDraws = []int{
	modelInitiatorRekeys, modelInitiatorRekeys,
	modelResponderRekeys, modelResponderRekeys,
	modelBothRekey, modelBothRekey,
	modelDropRekeyAnswers,
	modelDropAnswersToInitiator,
	modelDropAnswersToResponder,
	modelHoldInitiatorDeletes, modelHoldInitiatorDeletes,
	modelHoldResponderDeletes, modelHoldResponderDeletes,
	modelReleaseDeletes,
	modelInitiatorRequests,
	modelResponderRequests,
	modelHolderRequests,
	modelCrossingToResponderLost, modelCrossingToResponderLost, modelCrossingToResponderLost,
	modelCrossingToInitiatorLost, modelCrossingToInitiatorLost, modelCrossingToInitiatorLost,
}

// rekeyModel is one case of the model: two sessions over a path that drops the answers to rekeys either way or one way for a while and holds either end's Deletes, with ESP flowing each way throughout
type rekeyModel struct {
	// t is the test, whose network the path listens on
	t                    *testing.T
	ht                   *hegel.T
	initiator, responder *Session
	runs                 [2]chan error
	// ops holds the exchange each end runs in the background, nil where it runs none, and opSPI the SA the end was current on as its request began
	ops   [2]chan error
	opSPI [2]uint64
	// requested marks the end whose background exchange is a request rather than a rekey
	requested [2]bool

	mu sync.Mutex
	// dropFrom and dropUntil are when the path starts and stops dropping the answers to rekeys sent to the initiator, then to the responder
	dropFrom, dropUntil [2]time.Time
	// holding says, the initiator first, whether the path holds an end's INFORMATIONAL requests on any SA but its current one, and held lists the datagrams it holds
	holding [2]bool
	held    []modelHeld
	// answers is the first answer of each rekey the path saw, by SA, Message ID and direction, and differed marks a later answer that was not bitwise the first
	answers  map[[3]uint64][]byte
	differed bool
	// watched is the SA and Message ID of the holder's last request, and watchedAnswers counts the answers to it
	watched        [2]uint64
	watchedAnswers int
	// holderPast marks a holder's request sent past its SA's retention
	holderPast bool
	// overwritten marks a case where a holder's request inside the retention drew an answer, which takes the place of the answer a record kept, as master does, so a busy peer still waiting for that answer may run out of budget
	overwritten bool
	// untils is the end of each record seen, which never moves later
	untils map[*ikeContext]time.Time
}

// modelHeld is a datagram the path holds, with where it goes on to
type modelHeld struct {
	raw []byte
	to  *net.UDPAddr
}

// RFC 7296 section 2.1: "In order to allow saving memory, responders are allowed to forget the response after a timeout of several minutes."
// both ends rekey, alone or at once, over a path that drops the answers to rekeys either way or to one end alone for up to half a busy peer's budget and holds either end's Deletes, with ESP flowing throughout
// after each step a record serves only while its SA holds the answer it keeps, ends by busyRequestBudget from its retention and never later than it said, holds its SA exactly to its end, every repeat of a rekey draws the answer first sent, a replaced SA past its retention answers a holder of its keys nothing, and a fresh request on the replacement confirms it
// and once everything held goes through and every budget has run out, both sessions run on one IKE SA that carries ESP and an exchange each way
// it draws no run of drops that covers a request's whole budget: a request whose every answer is lost for its busy budget ends the session by rule, so drops toward one end are spaced by modelDropSpacing, and every request has a send whose answer returns
// each case runs one of modelLists at both ends and up to modelSteps steps of an event, drawn from modelDraws, and an advance, each drawn as an integer range, over pbt.Check's 200 cases, a count the test logs
func TestRekeyRetryModel(t *testing.T) { bubble.Run(testRekeyRetryModel)(t) }

func testRekeyRetryModel(t *testing.T) {
	h := newResponderHarness(t, nil)
	cases := 0
	pbt.Check(t, func(ht *hegel.T) {
		cases++
		m := &rekeyModel{t: t, ht: ht, answers: make(map[[3]uint64][]byte), untils: make(map[*ikeContext]time.Time)}
		lists := modelLists[hegel.Draw(ht, pbt.Spanning(0, len(modelLists)-1))]
		h.lists.Store(&lists)
		cfg := h.peerConfig()
		cfg.Suites = func() Suites { return lists }
		port, inject, release, closeRelay := m.relay(h.remotePort)
		defer closeRelay()
		cfg.RemotePort = port
		ctx, cancel := context.WithTimeout(context.Background(), answerBudget)
		initiator, err := InitiateContext(ctx, cfg)
		cancel()
		if err != nil {
			ht.Fatal(err)
		}
		m.initiator, m.responder = initiator, <-h.sessions
		<-h.identities
		run, stop := context.WithCancel(context.Background())
		for i, s := range []*Session{m.initiator, m.responder} {
			m.runs[i] = make(chan error, 1)
			go func() { m.runs[i] <- s.Run(run) }()
		}
		stopESP := make(chan struct{})
		espDone := make(chan struct{})
		go func() {
			defer close(espDone)
			for {
				_ = espPasses(m.initiator, m.responder)
				_ = espPasses(m.responder, m.initiator)
				select {
				case <-stopESP:
					return
				case <-time.After(espEvery):
				}
			}
		}()
		defer func() {
			close(stopESP)
			<-espDone
			m.initiator.Mux().Close()
			m.responder.Mux().Close()
			stop()
			for _, r := range m.runs {
				<-r
			}
			for _, op := range m.ops {
				if op != nil {
					<-op
				}
			}
		}()

		for range hegel.Draw(ht, pbt.Spanning(1, modelSteps)) {
			event := modelDraws[hegel.Draw(ht, pbt.Spanning(0, len(modelDraws)-1))]
			advance := modelAdvances[hegel.Draw(ht, pbt.Spanning(0, len(modelAdvances)-1))]
			m.step(event, inject, release)
			synctest.Wait()
			m.check()
			if m.leavesOut() {
				return
			}
			time.Sleep(advance)
			synctest.Wait()
			m.check()
			if m.leavesOut() {
				return
			}
		}
		m.quiesce(release)
	})
	t.Logf("the model drew %d cases", cases)
}

// step runs event
func (m *rekeyModel) step(event int, inject func([]byte), release func()) {
	switch event {
	case modelInitiatorRekeys:
		m.start(0, false)
	case modelResponderRekeys:
		m.start(1, false)
	case modelBothRekey:
		m.start(0, false)
		m.start(1, false)
	case modelDropRekeyAnswers:
		m.drop(0)
		m.drop(1)
	case modelDropAnswersToInitiator:
		m.drop(0)
	case modelDropAnswersToResponder:
		m.drop(1)
	case modelHoldInitiatorDeletes:
		m.hold(0)
	case modelHoldResponderDeletes:
		m.hold(1)
	case modelReleaseDeletes:
		release()
	case modelInitiatorRequests:
		m.start(0, true)
	case modelResponderRequests:
		m.start(1, true)
	case modelHolderRequests:
		m.holderRequests(inject)
	case modelCrossingToResponderLost, modelCrossingToInitiatorLost:
		lost := 1
		if event == modelCrossingToInitiatorLost {
			lost = 0
		}
		m.drop(lost)
		m.hold(1 - lost)
		m.start(0, false)
		m.start(1, false)
	}
}

// drop makes the path drop the answers to rekeys sent to end i, the initiator 0 and the responder 1, for modelDrop, unless a drop toward i is drawn or runs already
// a drop toward i after an earlier one starts modelDropSpacing after that one ended at the soonest, so no run of drops covers a request's whole budget
func (m *rekeyModel) drop(i int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	if now.Before(m.dropUntil[i]) {
		return
	}
	from := now
	if spaced := m.dropUntil[i].Add(modelDropSpacing); !m.dropUntil[i].IsZero() && from.Before(spaced) {
		from = spaced
	}
	m.dropFrom[i], m.dropUntil[i] = from, from.Add(modelDrop)
}

// hold makes the path hold end i's INFORMATIONAL requests on any SA but its current one
func (m *rekeyModel) hold(i int) {
	m.mu.Lock()
	m.holding[i] = true
	m.mu.Unlock()
}

// start runs a rekey of the IKE SA, or a request on it where request says so, at end i, the initiator 0 and the responder 1, unless an exchange of that end runs already
func (m *rekeyModel) start(i int, request bool) {
	if m.ops[i] != nil {
		return
	}
	s := []*Session{m.initiator, m.responder}[i]
	op := make(chan error, 1)
	m.ops[i], m.opSPI[i], m.requested[i] = op, s.currentContext().spiI, request
	go func() {
		if request {
			_, err := s.request(INFORMATIONAL, nil)
			op <- err
			return
		}
		op <- s.RekeyIKE()
	}()
}

// holderRequests sends a fresh INFORMATIONAL on the IKE SA a peer's rekey replaced at the responder, as a holder of the peer's keys of it, from the session's endpoint
// its draw meets such an SA past its retention only in some of the model's processes, so the model sees an answer there by chance and TestRequestsOnTheReplacedSAPastItsRetentionDrawNothing is the test that pins that rule
func (m *rekeyModel) holderRequests(inject func([]byte)) {
	m.responder.stateMu.RLock()
	old := m.responder.old
	var mid uint32
	var replacedAt time.Time
	own := false
	if old != nil {
		mid, replacedAt, own = old.nextPeerMID, old.replacedAt, old.ownDelete
	}
	m.responder.stateMu.RUnlock()
	if old == nil || replacedAt.IsZero() || own {
		return
	}
	var flags byte
	if old.responder {
		flags = FlagInitiator
	}
	raw, err := EncryptMessage(old.suite, old.peerEncryptionKey(), Header{SPIInitiator: old.spiI, SPIResponder: old.spiR, ExchangeType: INFORMATIONAL, Flags: flags, MessageID: mid}, nil, nil)
	if err != nil {
		m.ht.Fatal(err)
	}
	m.mu.Lock()
	m.watched, m.watchedAnswers = [2]uint64{old.spiI, uint64(mid)}, 0
	m.holderPast = !time.Now().Before(replacedAt.Add(retainedContextDeadline))
	m.mu.Unlock()
	inject(raw)
}

// check holds the model's invariants, and takes the background exchanges that ended
func (m *rekeyModel) check() {
	now := time.Now()
	for i, s := range []*Session{m.initiator, m.responder} {
		// a session that ended runs no expiry, so its record is left unchecked and the model reports the session's end
		if ended, err := m.runEnded(i); ended {
			if !m.overwritten {
				m.ht.Fatalf("the session of end %d ended with %v", i, err)
			}
			continue
		}
		s.stateMu.RLock()
		r, old, oldBy := s.recovery, s.old, s.oldBy
		live := r.replaced != nil && r.replaced == old && r.replaced.lastPeerResponseID == r.mid
		var replacedAt time.Time
		own := false
		if r.replaced != nil {
			replacedAt, own = r.replaced.replacedAt, r.replaced.ownDelete
		}
		s.stateMu.RUnlock()
		if !live {
			continue
		}
		// a refusal on the SA this end's own rekey replaced is answered no later than retainedContextDeadline after that rekey, since that SA takes no fresh request past it
		bound := replacedAt.Add(busyRequestBudget)
		if own {
			bound = bound.Add(retainedContextDeadline)
		}
		if r.until.After(bound) {
			m.ht.Fatalf("a record ends %v after its retention, past busyRequestBudget", r.until.Sub(replacedAt))
		}
		if oldBy.After(r.until) {
			m.ht.Fatalf("a record's SA is held %v past the record's end", oldBy.Sub(r.until))
		}
		if oldBy.Before(r.until) {
			m.ht.Fatalf("a record's SA goes %v before the record's end", r.until.Sub(oldBy))
		}
		if !now.Before(r.until) {
			m.ht.Fatalf("a record is held %v past its end", now.Sub(r.until))
		}
		if before, seen := m.untils[r.replaced]; seen && r.until.After(before) {
			m.ht.Fatalf("a record's end moved %v later", r.until.Sub(before))
		}
		m.untils[r.replaced] = r.until
	}
	m.mu.Lock()
	differed, past, answered := m.differed, m.holderPast, m.watchedAnswers
	if !past && answered != 0 {
		m.overwritten = true
	}
	// the holder's request is read once both ends took it, and the peer's own later request at that Message ID, its Delete among them, is not the holder's
	m.watched, m.holderPast, m.watchedAnswers = [2]uint64{}, false, 0
	m.mu.Unlock()
	if differed {
		m.ht.Fatal("a repeat of a rekey drew an answer that is not bitwise the first")
	}
	if past && answered != 0 {
		m.ht.Fatalf("a replaced IKE SA past its retention answered a holder of its keys %d times", answered)
	}
	for i, op := range m.ops {
		if op == nil {
			continue
		}
		select {
		case err := <-op:
			m.ops[i] = nil
			m.ended(i, err)
		default:
		}
	}
}

// ended checks the background exchange of end i that ended with err: a request answered on an SA both ends are current on, and that the asking end was current on when it began, confirms that SA at the other end
func (m *rekeyModel) ended(i int, err error) {
	if err != nil || !m.requested[i] {
		return
	}
	asking, other := []*Session{m.initiator, m.responder}[i], []*Session{m.initiator, m.responder}[1-i]
	current, peer := asking.currentContext(), other.currentContext()
	if current.spiI == m.opSPI[i] && peer.spiI == current.spiI && unconfirmedAt(other, peer) {
		m.ht.Fatalf("a request answered on the IKE SA %016x left it unconfirmed at the other end", peer.spiI)
	}
}

// runEnded reports whether the Run of end i returned, and what it returned, which it leaves for the next reader
func (m *rekeyModel) runEnded(i int) (bool, error) {
	select {
	case err := <-m.runs[i]:
		m.runs[i] <- err
		return true, err
	default:
		return false, nil
	}
}

// leavesOut reports the order the model does not draw, which ends the case: an end's own rekey begun on the SA it took from the peer's crossing rekey while that SA is unconfirmed
// the peer holds that SA once its own rekey's answer arrives, and where its answers are lost twice in a row the end's sends run out first and its session ends
func (m *rekeyModel) leavesOut() bool {
	for i, s := range []*Session{m.initiator, m.responder} {
		if m.ops[i] == nil || m.requested[i] {
			continue
		}
		s.stateMu.RLock()
		local, r := s.localRekey, s.recovery
		taken := local != nil && local.old.unconfirmed && local.old == r.replacement && r.replaced != nil
		s.stateMu.RUnlock()
		if taken {
			return true
		}
	}
	return false
}

// quiesce lets everything held go through and every budget run out, then holds that both sessions run on one IKE SA carrying ESP and an exchange each way
func (m *rekeyModel) quiesce(release func()) {
	m.mu.Lock()
	m.dropFrom, m.dropUntil = [2]time.Time{}, [2]time.Time{}
	m.mu.Unlock()
	release()
	time.Sleep(busyRequestBudget + retainedContextDeadline)
	synctest.Wait()
	m.check()
	for i, op := range m.ops {
		if op != nil {
			select {
			case err := <-op:
				m.ops[i] = nil
				m.ended(i, err)
			case <-time.After(answerBudget):
				m.ht.Fatalf("an exchange of end %d still ran once every budget ran out", i)
			}
		}
	}
	for i := range m.runs {
		if ended, err := m.runEnded(i); ended {
			if m.overwritten {
				return
			}
			m.ht.Fatalf("the session of end %d ended with %v", i, err)
		}
	}
	current, peer := m.initiator.currentContext(), m.responder.currentContext()
	if current.spiI != peer.spiI || current.spiR != peer.spiR || !bytes.Equal(current.skD, peer.skD) {
		m.ht.Fatalf("the initiator is current on %016x and the responder on %016x", current.spiI, peer.spiI)
	}
	for _, way := range [][2]*Session{{m.initiator, m.responder}, {m.responder, m.initiator}} {
		if err := espPasses(way[0], way[1]); err != nil {
			m.ht.Fatalf("ESP failed: %v", err)
		}
		if _, err := way[0].request(INFORMATIONAL, nil); err != nil {
			m.ht.Fatalf("an exchange on the current IKE SA failed: %v", err)
		}
	}
}

// relay is the case's path to the responder at responderPort: it drops the answers to rekeys sent to each end from its dropFrom until its dropUntil, holds each end's INFORMATIONAL requests on any SA but its current one while holding says so, and counts what the model watches
// inject sends a message to the responder from the path's address, release sends what was held on and stops holding, and closeRelay ends the path
func (m *rekeyModel) relay(responderPort int) (port int, inject func([]byte), release func(), closeRelay func()) {
	conn, err := testNetwork(m.t).ListenUDP(net.ParseIP("127.0.0.1"))
	if err != nil {
		m.ht.Fatal(err)
	}
	responder := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: responderPort}
	done := make(chan struct{})
	go func() {
		defer close(done)
		var initiator *net.UDPAddr
		buf := make([]byte, 65536)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			fromInitiator := from.Port != responderPort
			to := responder
			if fromInitiator {
				initiator = from
			} else {
				to = initiator
			}
			if to == nil {
				continue
			}
			if n > NonESPMarkerLen && m.keeps(fromInitiator, buf[:n], to) {
				continue
			}
			_, _ = conn.WriteToUDP(buf[:n], to)
		}
	}()
	inject = func(raw []byte) { _, _ = conn.WriteToUDP(withNonESPMarker(raw), responder) }
	release = func() {
		m.mu.Lock()
		out := m.held
		m.held, m.holding = nil, [2]bool{}
		m.mu.Unlock()
		for _, d := range out {
			_, _ = conn.WriteToUDP(d.raw, d.to)
		}
	}
	closeRelay = func() {
		conn.Close()
		<-done
	}
	return conn.LocalAddr().(*net.UDPAddr).Port, inject, release, closeRelay
}

// keeps reports whether the path keeps datagram, an IKE message after its non-ESP marker on its way to to, from going on, dropped or held, and notes what the model reads of it
func (m *rekeyModel) keeps(fromInitiator bool, datagram []byte, to *net.UDPAddr) bool {
	raw := datagram[NonESPMarkerLen:]
	header, err := decodeHeader(raw)
	if err != nil {
		return false
	}
	// sender indexes the end the datagram comes from and receiver the one it goes to, the initiator 0 and the responder 1
	sender, receiver := 1, 0
	if fromInitiator {
		sender, receiver = 0, 1
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if header.IsResponse() && !fromInitiator && header.SPIInitiator == m.watched[0] && uint64(header.MessageID) == m.watched[1] {
		m.watchedAnswers++
	}
	if header.IsResponse() && header.ExchangeType == CREATE_CHILD_SA {
		key := [3]uint64{header.SPIInitiator, uint64(header.MessageID), uint64(sender)}
		if first, seen := m.answers[key]; !seen {
			m.answers[key] = bytes.Clone(raw)
		} else if !bytes.Equal(first, raw) {
			m.differed = true
		}
		now := time.Now()
		return !now.Before(m.dropFrom[receiver]) && now.Before(m.dropUntil[receiver])
	}
	// a hold starts once both sessions are set, so they are read only under it
	if m.holding[sender] && !header.IsResponse() && header.ExchangeType == INFORMATIONAL {
		from := []*Session{m.initiator, m.responder}[sender]
		if header.SPIInitiator != from.currentContext().spiI {
			m.held = append(m.held, modelHeld{bytes.Clone(datagram), to})
			return true
		}
	}
	return false
}
