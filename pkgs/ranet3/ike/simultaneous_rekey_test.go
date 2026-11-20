// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ike

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"ranet3.com/pkgs/ranet3/esp"
	"ranet3.com/pkgs/ranet3/internal/bubble"
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
}

// crossingLosses says whether the path loses the answers to rekeys sent to the initiator and those sent to the responder, from before the crossing's requests pass
type crossingLosses struct{ toInitiator, toResponder bool }

// startCrossing runs a session through the responder's first rekey, then starts both ends' rekeys of its replacement with the path holding both requests until both rekeys are recorded, and passes them on with losses in force
// the initiator's exchange holds the lowest nonce unless initiatorWins, so the end whose exchange does not wins
func startCrossing(t *testing.T, initiatorWins bool, losses crossingLosses) *crossingRun {
	t.Helper()
	h := newResponderHarness(t, nil)
	path := &crossingPath{}
	cfg := h.peerConfig()
	cfg.RemotePort = path.listen(t, h.remotePort)
	initiator, responder := dialPaused(t, h, cfg)
	draws := [2]*crossingDraws{{}, {}}
	initiator.ikeRekeyNonce, responder.ikeRekeyNonce = draws[0].draw, draws[1].draw
	c := &crossingRun{initiator: initiator, responder: responder, path: path}
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
	path.holdRekeys(false)
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
// it loses the answers to rekeys sent to either end as loseAnswers says, and holds the rekey requests either way while holdRekeys is set
type crossingPath struct {
	conn      *transport.MemoryConn
	responder *net.UDPAddr

	mu                       sync.Mutex
	initiator                *net.UDPAddr
	toInitiator, toResponder bool
	holding                  bool
	held                     []crossingDatagram
}

// crossingDatagram is a datagram the path holds, with where it goes on to
type crossingDatagram struct {
	raw []byte
	to  *net.UDPAddr
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
	p.mu.Lock()
	defer p.mu.Unlock()
	switch {
	case header.ExchangeType == CREATE_CHILD_SA && header.IsResponse():
		if fromInitiator {
			return p.toResponder
		}
		return p.toInitiator
	case header.ExchangeType == CREATE_CHILD_SA && p.holding:
		p.held = append(p.held, crossingDatagram{bytes.Clone(datagram), to})
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

// holdRekeys sets whether the path holds the rekey requests either way, and once it stops, sends what it held on in the order it came
func (p *crossingPath) holdRekeys(holding bool) {
	p.mu.Lock()
	p.holding = holding
	out := p.held
	if !holding {
		p.held = nil
	}
	p.mu.Unlock()
	if holding {
		return
	}
	for _, d := range out {
		_, _ = p.conn.WriteToUDP(d.raw, d.to)
	}
}
