// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ike

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/internal/bubble"
	"ranet3.com/pkgs/ranet3/transport"
)

// the ESP flows of the outbound tests seal one packet each flowTick, and stop a flowDrain past the last trip so every packet in flight lands
const (
	flowTick  = 5 * time.Millisecond
	flowDrain = 100 * time.Millisecond
	// flowSettle is how long the flows run before the rekey starts
	flowSettle = 100 * time.Millisecond
)

// errRefusedInstall is the stand-in dataplane's refusal of a Child SA
var errRefusedInstall = errors.New("the dataplane refuses the Child SA")

// outboundMove is one change of a stand-in dataplane's outbound SA, from and to its SPI, 0 for none, and what made it
type outboundMove struct {
	from, to uint32
	by       string
	at       time.Time
}

// outboundPlane stands in for internal/client's tunnel as a session's dataplane, by the rules of its tunnel.go:
// install (place with hold false) adds the inbound SA and moves outbound traffic to the Child SA at once
// hold (place with hold true) adds the inbound SA and keeps outbound traffic where it is, holding the Child SA as replacement, or moves it at once where no outbound SA is left
// take moves outbound traffic to the replacement named by its inbound SPI, cancel drops a replacement that still waits with its inbound SA
// retire (tunnelSAs.without) drops an inbound SA with the outbound SA paired with it, whose place the replacement takes
// a packet that opens on the replacement's inbound SA takes it, as decryptBatch does
type outboundPlane struct {
	mu sync.Mutex
	in map[uint32]bool
	// out is the outbound SPI and outIn the inbound SPI of its Child SA, next and nextIn the replacement's
	out, outIn, next, nextIn uint32
	// refuse is how many installs are refused before one is taken
	refuse int
	// beforeCancel runs at the start of each cancel, on the session goroutine that cancels
	beforeCancel func()
	moves        []outboundMove
	// installed is when each Child SA was installed, by its inbound SPI
	installed map[uint32]time.Time
}

func newOutboundPlane(s *Session) *outboundPlane {
	p := &outboundPlane{in: map[uint32]bool{s.child.LocalSPI: true}, out: s.child.RemoteSPI, outIn: s.child.LocalSPI, installed: map[uint32]time.Time{}}
	s.SetChildHandler(func(child ChildSA) error { return p.place(child, false) })
	s.SetChildRetireHandler(p.retire)
	s.SetChildReplacementHandler(func(child ChildSA) error { return p.place(child, true) }, func(spi uint32) { p.take(spi, "session") }, p.cancel)
	return p
}

func (p *outboundPlane) moveLocked(out, outIn uint32, by string) {
	if out != p.out {
		p.moves = append(p.moves, outboundMove{from: p.out, to: out, by: by, at: time.Now()})
	}
	p.out, p.outIn = out, outIn
}

func (p *outboundPlane) place(child ChildSA, hold bool) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.refuse > 0 {
		p.refuse--
		return errRefusedInstall
	}
	if p.in[child.LocalSPI] {
		return fmt.Errorf("inbound ESP SPI %08x already installed", child.LocalSPI)
	}
	p.in[child.LocalSPI] = true
	p.installed[child.LocalSPI] = time.Now()
	p.next, p.nextIn = 0, 0
	if hold && p.out != 0 {
		p.next, p.nextIn = child.RemoteSPI, child.LocalSPI
		return nil
	}
	p.moveLocked(child.RemoteSPI, child.LocalSPI, "install")
	return nil
}

func (p *outboundPlane) take(spi uint32, by string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.next == 0 || p.nextIn != spi {
		return
	}
	p.moveLocked(p.next, p.nextIn, by)
	p.next, p.nextIn = 0, 0
}

func (p *outboundPlane) cancel(spi uint32) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.beforeCancel != nil {
		p.beforeCancel()
	}
	if p.next == 0 || p.nextIn != spi {
		return false
	}
	delete(p.in, spi)
	p.next, p.nextIn = 0, 0
	return true
}

func (p *outboundPlane) retire(spi uint32) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.in[spi] {
		return fmt.Errorf("retiring inbound ESP SPI %08x was not installed", spi)
	}
	delete(p.in, spi)
	switch spi {
	case p.nextIn:
		p.next, p.nextIn = 0, 0
	case p.outIn:
		p.moveLocked(p.next, p.nextIn, "retire")
		p.next, p.nextIn = 0, 0
	}
	return nil
}

// open reports whether a packet on spi opens, and takes the replacement it opens on
func (p *outboundPlane) open(spi uint32) bool {
	p.mu.Lock()
	held := p.in[spi]
	p.mu.Unlock()
	if held {
		p.take(spi, "packet")
	}
	return held
}

// holding reports whether a replacement waits to take outbound traffic
func (p *outboundPlane) holding() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.next != 0
}

func (p *outboundPlane) sending() uint32 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.out
}

func (p *outboundPlane) installedAt(spi uint32) (time.Time, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	at, ok := p.installed[spi]
	return at, ok
}

func (p *outboundPlane) recorded() []outboundMove {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]outboundMove(nil), p.moves...)
}

// espFlow counts the packets one end seals under its outbound SA, each flowTick, and what the other end opens and drops of them, and the ticks the sending end had no outbound SA
type espFlow struct {
	sent, opened, dropped, bare atomic.Int64
}

func (f *espFlow) send(from *Session, plane *outboundPlane, stop <-chan struct{}, flows *sync.WaitGroup) {
	flows.Go(func() {
		tick := time.NewTicker(flowTick)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
			}
			out := plane.sending()
			if out == 0 {
				f.bare.Add(1)
				continue
			}
			packet := binary.BigEndian.AppendUint32(make([]byte, 0, 24), out)
			packet = binary.BigEndian.AppendUint32(packet, uint32(f.sent.Add(1)))
			_ = from.Mux().SendESPBatch([][]byte{append(packet, make([]byte, 16)...)})
		}
	})
}

func (f *espFlow) receive(to *Session, plane *outboundPlane, flows *sync.WaitGroup) {
	flows.Go(func() {
		for {
			batch, err := to.Mux().RecvESPBatchConcurrent()
			if err != nil {
				return
			}
			for _, packet := range batch.Packets() {
				if len(packet) >= 4 && plane.open(binary.BigEndian.Uint32(packet)) {
					f.opened.Add(1)
					to.NoteTraffic()
				} else {
					f.dropped.Add(1)
				}
			}
			batch.Release()
		}
	})
}

// outboundCase is how a pair of sessions runs a Child SA rekey through a relay
type outboundCase struct {
	askerIsInitiator bool
	// delay is the relay's one-way delay, the same for every datagram, which keeps their order
	delay time.Duration
	// lostAnswers is how many sends of the answer to the asking end's CREATE_CHILD_SA the relay loses
	lostAnswers int
	// lostDeletes is how many sends of the asking end's next request, its Delete, the relay loses, and lostDeletesFor loses every one sent within that long of the dial
	lostDeletes    int
	lostDeletesFor time.Duration
	// refusals is how many Child SAs the asking end's dataplane refuses
	refusals int
	// configure and seed reach dialRefusing's
	configure func(*PeerConfig)
	seed      func(asker, answerer *Session)
	// watch sees the header of each IKE message the relay takes, and whether the asking end sent it
	watch func(fromAsker bool, h *Header)
}

// outboundPair is two sessions with a stand-in dataplane each and the ESP flows between them
type outboundPair struct {
	asker, answerer           *Session
	askerPlane, answererPlane *outboundPlane
	// toAsker is the answering end's flow and toAnswerer the asking end's
	toAsker, toAnswerer espFlow
	delay               time.Duration
	stop                chan struct{}
	stopped             sync.Once
	flows               sync.WaitGroup
}

func dialOutbound(t *testing.T, c outboundCase) *outboundPair {
	t.Helper()
	p := &outboundPair{delay: c.delay, stop: make(chan struct{})}
	dialed := time.Now()
	var mu sync.Mutex
	var answers, deletes int
	var rekeyID uint32
	rekeyed := false
	dialRefusing(t, func(cfg *PeerConfig) {
		if c.configure != nil {
			c.configure(cfg)
		}
		cfg.RemotePort = delayedRelay(t, cfg.RemotePort, c.delay, func(fromInitiator bool, h *Header) bool {
			fromAsker := fromInitiator == c.askerIsInitiator
			mu.Lock()
			defer mu.Unlock()
			if c.watch != nil {
				c.watch(fromAsker, h)
			}
			switch {
			case fromAsker && h.ExchangeType == CREATE_CHILD_SA && !h.IsResponse():
				rekeyID, rekeyed = h.MessageID, true
			case !fromAsker && h.ExchangeType == CREATE_CHILD_SA && h.IsResponse():
				answers++
				return answers <= c.lostAnswers
			case fromAsker && rekeyed && h.ExchangeType == INFORMATIONAL && !h.IsResponse() && h.MessageID == rekeyID+1:
				deletes++
				return deletes <= c.lostDeletes || time.Since(dialed) < c.lostDeletesFor
			}
			return false
		})
	}, func(initiator, responder *Session) {
		p.asker, p.answerer = initiator, responder
		if !c.askerIsInitiator {
			p.asker, p.answerer = responder, initiator
		}
		p.askerPlane, p.answererPlane = newOutboundPlane(p.asker), newOutboundPlane(p.answerer)
		p.askerPlane.refuse = c.refusals
		if c.seed != nil {
			c.seed(p.asker, p.answerer)
		}
	})
	p.toAsker.receive(p.asker, p.askerPlane, &p.flows)
	p.toAnswerer.receive(p.answerer, p.answererPlane, &p.flows)
	t.Cleanup(p.close)
	return p
}

// carry starts the flows from the answering end and from the asking end, as named
func (p *outboundPair) carry(fromAnswerer, fromAsker bool) {
	if fromAnswerer {
		p.toAsker.send(p.answerer, p.answererPlane, p.stop, &p.flows)
	}
	if fromAsker {
		p.toAnswerer.send(p.asker, p.askerPlane, p.stop, &p.flows)
	}
}

// halt stops the senders and waits until every packet they sent has landed
func (p *outboundPair) halt() {
	p.stopped.Do(func() {
		close(p.stop)
		time.Sleep(p.delay + flowDrain)
	})
}

// losses names each packet of a flow the other end did not open, each tick an end had no outbound SA and each move of an outbound SA to none
// the relay loses no ESP, so every packet sealed is one the other end receives
func (p *outboundPair) losses() []string {
	p.halt()
	var lost []string
	for _, flow := range []struct {
		name string
		f    *espFlow
	}{{"the answering end's", &p.toAsker}, {"the asking end's", &p.toAnswerer}} {
		sent, opened, dropped, bare := flow.f.sent.Load(), flow.f.opened.Load(), flow.f.dropped.Load(), flow.f.bare.Load()
		if dropped != 0 || opened != sent {
			lost = append(lost, fmt.Sprintf("of %s %d packets the other end opened %d and dropped %d", flow.name, sent, opened, dropped))
		}
		if bare != 0 {
			lost = append(lost, fmt.Sprintf("%s flow found no outbound SA at %d ticks", flow.name, bare))
		}
	}
	for _, end := range []struct {
		name  string
		plane *outboundPlane
	}{{"answering", p.answererPlane}, {"asking", p.askerPlane}} {
		for _, move := range end.plane.recorded() {
			if move.to == 0 {
				lost = append(lost, fmt.Sprintf("the %s end's outbound SA %08x went with no replacement by %s", end.name, move.from, move.by))
			}
		}
	}
	return lost
}

// close ends both sessions and the flows
func (p *outboundPair) close() {
	p.halt()
	_ = p.asker.Mux().Close()
	_ = p.answerer.Mux().Close()
	p.flows.Wait()
}

// delayedRelay carries UDP between an initiator and the responder at responderPort, each datagram delay later and in order, loses each IKE message lose reports, and returns the port to dial
func delayedRelay(t *testing.T, responderPort int, delay time.Duration, lose func(fromInitiator bool, h *Header) bool) int {
	t.Helper()
	conn := listenPeer(t)
	responder := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: responderPort}
	type datagram struct {
		due time.Time
		raw []byte
		to  *net.UDPAddr
	}
	queue := make(chan datagram, 1<<15)
	done := make(chan struct{})
	t.Cleanup(func() {
		conn.Close()
		<-done
	})
	go func() {
		defer close(done)
		for d := range queue {
			time.Sleep(time.Until(d.due))
			_, _ = conn.WriteToUDP(d.raw, d.to)
		}
	}()
	go func() {
		defer close(queue)
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
			// a datagram whose first four octets are zero carries IKE behind the non-ESP marker
			if n > 4 && binary.BigEndian.Uint32(buf[:4]) == 0 {
				if h, err := decodeHeader(buf[4:n]); err == nil && lose(fromInitiator, h) {
					continue
				}
			}
			queue <- datagram{time.Now().Add(delay), append([]byte(nil), buf[:n]...), to}
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr).Port
}

// outboundDelay is the relay's one-way delay in the outbound tests, and rekeyAnswered bounds how long a rekey of theirs takes in the bubble, its lost sends and their resends included
const (
	outboundDelay = 10 * time.Millisecond
	rekeyAnswered = 2 * time.Minute
	// outboundLifetime is the answering end's Child SA lifetime in the tests the replaced SA's lifetime ends, and rekeyAhead how long before it the asking end rekeys
	outboundLifetime = 3 * time.Second
	rekeyAhead       = time.Second
	// deleteLate is how far past an event the asking end's lost Deletes go on being lost
	deleteLate = 500 * time.Millisecond
)

// rekeyChild runs the asking end's Child SA rekey and returns what it ended with
func (p *outboundPair) rekeyChild(t *testing.T) error {
	t.Helper()
	ended := make(chan error, 1)
	go func() { ended <- p.asker.RekeyChild() }()
	select {
	case err := <-ended:
		return err
	case <-time.After(rekeyAnswered):
		t.Fatal("the Child SA rekey did not end")
		return nil
	}
}

// RFC 7296 section 2.8: "When rekeying an SA, the responder continues to send traffic on the old SA until one of those events occurs."
// the end that answers a Child SA rekey whose first answer the relay loses keeps sending on the replaced SA until the asking end's first packet on the new SA arrives, or its Delete of the replaced SA where it sends nothing, and each end opens every packet the other seals
// the asking end's first Delete is lost where it sends, so its packet comes first
func TestAnsweringEndKeepsSendingOnTheReplacedChildSA(t *testing.T) {
	for _, row := range []struct {
		name      string
		fromAsker bool
		by        string
	}{{"both ways", true, "packet"}, {"answering end alone", false, "session"}} {
		t.Run(row.name, bubble.Run(func(t *testing.T) {
			c := outboundCase{askerIsInitiator: true, delay: outboundDelay, lostAnswers: 1}
			if row.fromAsker {
				c.lostDeletes = 1
			}
			p := dialOutbound(t, c)
			old := p.answerer.Child()
			p.carry(true, row.fromAsker)
			time.Sleep(flowSettle)
			ended := make(chan error, 1)
			go func() { ended <- p.asker.RekeyChild() }()
			for done := false; !done; {
				time.Sleep(outboundDelay / 2)
				synctest.Wait()
				select {
				case err := <-ended:
					if err != nil {
						t.Fatalf("the Child SA rekey ended with %v", err)
					}
					done = true
				default:
				}
				made := p.answerer.Child()
				if _, installed := p.askerPlane.installedAt(made.RemoteSPI); made.LocalSPI != old.LocalSPI && !installed {
					if out := p.answererPlane.sending(); out != old.RemoteSPI {
						t.Fatalf("the answering end sends on %08x while the asking end has not installed the SA it names, want the replaced SA %08x", out, old.RemoteSPI)
					}
				}
			}
			made := p.answerer.Child()
			installed, _ := p.askerPlane.installedAt(made.RemoteSPI)
			moves := p.answererPlane.recorded()
			if len(moves) != 1 || moves[0].from != old.RemoteSPI || moves[0].to != made.RemoteSPI || moves[0].by != row.by || moves[0].at.Before(installed.Add(outboundDelay)) {
				t.Errorf("the answering end's outbound SA moved %+v, want once from %08x to %08x by the %s a trip after the asking end installed it at %v", moves, old.RemoteSPI, made.RemoteSPI, row.by, installed)
			}
			for _, lost := range p.losses() {
				t.Error(lost)
			}
		}))
	}
}

// an asking end whose dataplane refuses the Child SA its rekey made deletes that SA, and the answering end, whose outbound SA had not left the SA it replaced, makes that one current again with nothing awaiting retirement, so the next rekey is answered with an SA and no packet is lost
// where the replaced SA's lifetime moved the outbound SA first, the Delete takes the replacement with its outbound SA and puts nothing back
func TestDeletedReplacementMakesTheReplacedChildSACurrentAgain(t *testing.T) {
	t.Run("before outbound traffic moves", bubble.Run(func(t *testing.T) {
		p := dialOutbound(t, outboundCase{askerIsInitiator: true, delay: outboundDelay, refusals: 1, configure: func(cfg *PeerConfig) {
			cfg.RekeyRetryInitial, cfg.RekeyRetryMax = retryDelay, retryDelay
		}})
		old := p.answerer.Child()
		p.carry(true, true)
		time.Sleep(flowSettle)
		if err := p.rekeyChild(t); !errors.Is(err, errRefusedInstall) {
			t.Fatalf("the refused Child SA rekey ended with %v, want the dataplane's refusal", err)
		}
		if got, retiring := p.answerer.Child(), p.answerer.retiringChild(); got.LocalSPI != old.LocalSPI || got.RemoteSPI != old.RemoteSPI || retiring.LocalSPI != 0 {
			t.Fatalf("after the asking end's Delete the answering end holds %08x and awaits the retirement of %08x, want %08x again and none", got.LocalSPI, retiring.LocalSPI, old.LocalSPI)
		}
		// the asking end's schedule retries the failed rekey after its retry delay
		for deadline := time.Now().Add(rekeyAnswered); p.asker.Child().LocalSPI == old.RemoteSPI; time.Sleep(retryDelay) {
			if time.Now().After(deadline) {
				t.Fatal("no later rekey of the asking end's replaced a Child SA")
			}
		}
		if made := p.answerer.Child(); made.LocalSPI == old.LocalSPI || made.RemoteSPI != p.asker.Child().LocalSPI {
			t.Errorf("the answering end holds %08x/%08x after the later rekey, want the SA the asking end holds", made.LocalSPI, made.RemoteSPI)
		}
		for _, lost := range p.losses() {
			t.Error(lost)
		}
	}))
	t.Run("after outbound traffic moved", bubble.Run(func(t *testing.T) {
		var dialed time.Time
		p := dialOutbound(t, outboundCase{askerIsInitiator: true, delay: outboundDelay, refusals: 1, lostDeletesFor: outboundLifetime + deleteLate, seed: func(_, answerer *Session) {
			answerer.timing.ChildRekeyInterval, answerer.timing.RekeyMargin, answerer.timing.RekeyJitter = outboundLifetime, 0, 0
			dialed = answerer.childEstablished
		}})
		old := p.answerer.Child()
		time.Sleep(time.Until(dialed.Add(outboundLifetime - rekeyAhead)))
		if err := p.rekeyChild(t); !errors.Is(err, errRefusedInstall) {
			t.Fatalf("the refused Child SA rekey ended with %v, want the dataplane's refusal", err)
		}
		synctest.Wait()
		moves := p.answererPlane.recorded()
		if len(moves) != 2 || moves[0].from != old.RemoteSPI || moves[0].by != "retire" || moves[1].from != moves[0].to || moves[1].to != 0 {
			t.Errorf("the answering end's outbound SA moved %+v, want from %08x to the replacement at the replaced SA's lifetime and from it to none at the Delete", moves, old.RemoteSPI)
		}
		if got, retiring := p.answerer.Child(), p.answerer.retiringChild(); got.LocalSPI != 0 || retiring.LocalSPI != old.LocalSPI {
			t.Errorf("after the asking end's Delete the answering end holds %08x and awaits the retirement of %08x, want none and %08x", got.LocalSPI, retiring.LocalSPI, old.LocalSPI)
		}
	}))
}

// the replaced SA's lifetime and rekey margin in the test of a replaced SA made current again after its rekey fell due, and when the asking end rekeys it
// the asking end rekeys past restoredMargin, so a schedule counted from the replacement falls due past the replaced SA's lifetime, and early enough that its Delete, lost once and resent requestTimeout later, comes before that lifetime with a trip to spare
const (
	restoredLifetime = 4 * time.Second
	restoredMargin   = time.Second
	restoredAsk      = 1500 * time.Millisecond
	// restoredRead is how long before the replaced SA's lifetime the test reads which SA the answering end holds
	restoredRead = 200 * time.Millisecond
	// restoredRetry is the answering end's retry delay, so its rekey, which starts once the replaced SA is current again while the asking end's Delete still waits on its answer and which draws TEMPORARY_FAILURE, is retried before that lifetime
	restoredRetry = 100 * time.Millisecond
)

// the answering end's Child SA schedule falls due while the peer's rekey of its SA waits on the peer, and is armed again from the new SA, past the replaced SA's lifetime
// the peer's dataplane refuses that SA and its Delete makes the replaced SA current again, which then rekeys at its own due time, already past, and is replaced before its lifetime closes the IKE SA
// the asking end's retry is an hour off, so the rekey that replaces the SA is the answering end's
func TestRestoredChildSAIsRekeyedBeforeItsLifetime(t *testing.T) {
	bubble.Run(func(t *testing.T) {
		var dialed time.Time
		p := dialOutbound(t, outboundCase{askerIsInitiator: true, delay: outboundDelay, lostDeletes: 1, refusals: 1, seed: func(asker, answerer *Session) {
			answerer.timing.ChildRekeyInterval, answerer.timing.RekeyMargin, answerer.timing.RekeyJitter = restoredLifetime, restoredMargin, 0
			answerer.timing.RekeyRetryInitial, answerer.timing.RekeyRetryMax = restoredRetry, restoredRetry
			asker.timing.RekeyRetryInitial, asker.timing.RekeyRetryMax = time.Hour, time.Hour
			dialed = answerer.childEstablished
		}})
		old := p.answerer.Child()
		p.carry(true, true)
		time.Sleep(time.Until(dialed.Add(restoredAsk)))
		if err := p.rekeyChild(t); !errors.Is(err, errRefusedInstall) {
			t.Fatalf("the refused Child SA rekey ended with %v, want the dataplane's refusal", err)
		}
		time.Sleep(time.Until(dialed.Add(restoredLifetime - restoredRead)))
		synctest.Wait()
		if made, asked := p.answerer.Child(), p.asker.Child(); made.LocalSPI == old.LocalSPI || made.RemoteSPI != asked.LocalSPI || made.LocalSPI != asked.RemoteSPI {
			t.Errorf("before the replaced SA's lifetime the answering end holds %08x/%08x and the asking end %08x/%08x, want a new SA both hold", made.LocalSPI, made.RemoteSPI, asked.LocalSPI, asked.RemoteSPI)
		}
		time.Sleep(restoredRead + restoredMargin)
		synctest.Wait()
		if p.answerer.closing.Load() {
			t.Error("the answering end is closing the IKE SA")
		}
		for _, lost := range p.losses() {
			t.Error(lost)
		}
	})(t)
}

// the answering end's lifetime, rekey margin and retry delay in the test of a replaced SA made current again while a failed rekey's retry delay runs, and when each end acts
// the answering end's own rekey fails on the replaced SA awaiting retirement and starts its retry delay, which runs past the replaced SA's due time and past the asking end's Delete, lost once and resent requestTimeout later, and ends early enough before the lifetime for a rekey
const (
	retryWaitLifetime = 8 * time.Second
	retryWaitMargin   = 4500 * time.Millisecond
	retryWaitDelay    = 4 * time.Second
	retryWaitAsk      = 2 * time.Second
	retryWaitOwnAsk   = 2500 * time.Millisecond
)

// the answering end's own rekey, started while the peer's rekey waits on the peer, fails on the SA awaiting retirement and holds every Child SA exchange for its retry delay
// the peer's dataplane refuses its SA and the Delete that makes the replaced SA current again comes inside that delay and past that SA's due time
// a rekey started then would be refused with nothing to settle, so the schedule waits for the delay's end and rekeys the SA then, before its lifetime closes the IKE SA
func TestRestoredChildSAWaitsOutTheRetryDelayOfAFailedRekey(t *testing.T) {
	bubble.Run(func(t *testing.T) {
		var dialed time.Time
		p := dialOutbound(t, outboundCase{askerIsInitiator: true, delay: outboundDelay, lostDeletes: 1, refusals: 1, seed: func(asker, answerer *Session) {
			answerer.timing.ChildRekeyInterval, answerer.timing.RekeyMargin, answerer.timing.RekeyJitter = retryWaitLifetime, retryWaitMargin, 0
			answerer.timing.RekeyRetryInitial, answerer.timing.RekeyRetryMax = retryWaitDelay, retryWaitDelay
			answerer.rekeyJitterSource = unjittered
			asker.timing.RekeyRetryInitial, asker.timing.RekeyRetryMax = time.Hour, time.Hour
			dialed = answerer.childEstablished
		}})
		old := p.answerer.Child()
		p.carry(true, true)
		time.Sleep(time.Until(dialed.Add(retryWaitAsk)))
		ended := make(chan error, 1)
		go func() { ended <- p.asker.RekeyChild() }()
		time.Sleep(time.Until(dialed.Add(retryWaitOwnAsk)))
		if err := p.answerer.RekeyChild(); err == nil {
			t.Fatal("the answering end's rekey of the SA awaiting retirement succeeded")
		}
		if err := <-ended; !errors.Is(err, errRefusedInstall) {
			t.Fatalf("the refused Child SA rekey ended with %v, want the dataplane's refusal", err)
		}
		synctest.Wait()
		if got := p.answerer.Child(); got.LocalSPI != old.LocalSPI {
			t.Fatalf("after the asking end's Delete the answering end holds %08x, want the replaced SA %08x again", got.LocalSPI, old.LocalSPI)
		}
		time.Sleep(time.Until(dialed.Add(retryWaitLifetime - restoredRead)))
		synctest.Wait()
		if made, asked := p.answerer.Child(), p.asker.Child(); made.LocalSPI == old.LocalSPI || made.RemoteSPI != asked.LocalSPI || made.LocalSPI != asked.RemoteSPI {
			t.Errorf("before the replaced SA's lifetime the answering end holds %08x/%08x and the asking end %08x/%08x, want a new SA both hold", made.LocalSPI, made.RemoteSPI, asked.LocalSPI, asked.RemoteSPI)
		}
		time.Sleep(restoredRead + retryWaitMargin)
		synctest.Wait()
		if p.answerer.closing.Load() {
			t.Error("the answering end is closing the IKE SA")
		}
		for _, lost := range p.losses() {
			t.Error(lost)
		}
	})(t)
}

// the answering end's retry delay in the test of a rekey begun before a restore, and how long the test then watches for the retry
const (
	staleRetry = time.Second
	staleWatch = 5 * time.Second
	// queuedReloadWatch is how long the test of a restore with a reload queued waits for the rekey the reload forces reloadJitter later
	queuedReloadWatch = 3 * reloadJitter
)

// the answering end's own rekey records its start during the hold and is paused there, the peer's Delete of the SA it refused then makes the replaced SA current again, and the rekey goes on against that SA and fails on this end's dataplane
// its outcome counts against the SA it rekeyed, so the retry delay runs and the restored SA is replaced, with no rekey interval to fall back on
func TestRekeyBegunBeforeARestoreRetriesOnTheRestoredSA(t *testing.T) {
	bubble.Run(func(t *testing.T) {
		var armed atomic.Bool
		entered, release := make(chan struct{}), make(chan struct{})
		p := dialOutbound(t, outboundCase{askerIsInitiator: true, delay: outboundDelay, lostDeletes: 1, refusals: 1, seed: func(asker, answerer *Session) {
			answerer.timing.ChildRekeyInterval = 0
			answerer.timing.RekeyRetryInitial, answerer.timing.RekeyRetryMax = staleRetry, staleRetry
			asker.timing.RekeyRetryInitial, asker.timing.RekeyRetryMax = time.Hour, time.Hour
			answerer.events = func(_, _ identity.Identity, kind string, _ ...slog.Attr) {
				if kind == "ike.rekey.started" && armed.CompareAndSwap(true, false) {
					close(entered)
					<-release
				}
			}
		}})
		old := p.answerer.Child()
		refused := make(chan error, 1)
		go func() { refused <- p.asker.RekeyChild() }()
		for !p.answererPlane.holding() {
			time.Sleep(outboundDelay)
		}
		p.answererPlane.mu.Lock()
		p.answererPlane.refuse = 1
		p.answererPlane.mu.Unlock()
		armed.Store(true)
		own := make(chan error, 1)
		go func() { own <- p.answerer.RekeyChild() }()
		<-entered
		if err := <-refused; !errors.Is(err, errRefusedInstall) {
			t.Fatalf("the refused Child SA rekey ended with %v, want the dataplane's refusal", err)
		}
		for deadline := time.Now().Add(staleWatch); p.answerer.Child().LocalSPI != old.LocalSPI && time.Now().Before(deadline); {
			time.Sleep(outboundDelay)
		}
		if got := p.answerer.Child(); got.LocalSPI != old.LocalSPI {
			t.Fatalf("after the asking end's Delete the answering end holds %08x, want the replaced SA %08x again", got.LocalSPI, old.LocalSPI)
		}
		close(release)
		if err := <-own; !errors.Is(err, errRefusedInstall) {
			t.Fatalf("the answering end's rekey of the restored SA ended with %v, want its own dataplane's refusal", err)
		}
		time.Sleep(staleWatch)
		synctest.Wait()
		if made, asked := p.answerer.Child(), p.asker.Child(); made.LocalSPI == old.LocalSPI || made.RemoteSPI != asked.LocalSPI || made.LocalSPI != asked.RemoteSPI {
			t.Errorf("after the retry delay the answering end holds %08x/%08x and the asking end %08x/%08x, want a new SA both hold", made.LocalSPI, made.RemoteSPI, asked.LocalSPI, asked.RemoteSPI)
		}
	})(t)
}

// distantRetry is a retry delay past the end of the test of a rekey that read a canceled replacement: no retry of either end rekeys the restored SA in it
const distantRetry = time.Hour

// rekeyStartWait bounds that test's wait for the schedule's rekey of the restored SA, which starts in the instant the rekey that read the replacement ends
const rekeyStartWait = 100 * time.Millisecond

// the answering end's proactive rekey reads the SA the peer's rekey made, still held, as the SA it rekeys, and is held after that read while the peer's Delete of the held SA, lost once, makes the replaced SA current again past its due time
// the schedule's rekey at that restore finds the proactive one running and starts nothing, and the proactive one then ends before it sends its request, which would name an SA the peer deleted
// the schedule then starts a rekey of the restored SA at once, held at the same point before its request: with the retries of both ends an hour off, nothing else rekeys that SA before its lifetime closes the IKE SA
func TestRekeyOfACanceledReplacementEndsBeforeItsRequest(t *testing.T) {
	bubble.Run(func(t *testing.T) {
		lines := recordLines(t)
		scheduled := func() int {
			return len(slices.DeleteFunc(lines.said(slog.LevelInfo, "ike scheduled rekey starting", "sa"), func(sa slog.Value) bool { return sa.String() != "Child SA" }))
		}
		var dialed time.Time
		var sent atomic.Int32
		// a rekey of the answering end that reads the lists while armed is held there, after it read its SA and before it checks that SA, until the test lets it go
		var armed atomic.Bool
		held, resume := make(chan struct{}), make(chan struct{})
		p := dialOutbound(t, outboundCase{askerIsInitiator: true, delay: outboundDelay, lostDeletes: 1, refusals: 1,
			watch: func(fromAsker bool, h *Header) {
				if !fromAsker && h.ExchangeType == CREATE_CHILD_SA && !h.IsResponse() {
					sent.Add(1)
				}
			},
			seed: func(asker, answerer *Session) {
				answerer.timing.ChildRekeyInterval, answerer.timing.RekeyMargin, answerer.timing.RekeyJitter = restoredLifetime, restoredMargin, 0
				answerer.timing.RekeyRetryInitial, answerer.timing.RekeyRetryMax = distantRetry, distantRetry
				asker.timing.RekeyRetryInitial, asker.timing.RekeyRetryMax = distantRetry, distantRetry
				lists := answerer.suites
				answerer.suites = func() Suites {
					if answerer.childRekeying.Load() && armed.CompareAndSwap(true, false) {
						held <- struct{}{}
						<-resume
					}
					return current(lists)
				}
				dialed = answerer.childEstablished
			}})
		old := p.answerer.Child()
		p.carry(true, true)
		time.Sleep(time.Until(dialed.Add(restoredAsk)))
		refused := make(chan error, 1)
		go func() { refused <- p.asker.RekeyChild() }()
		for deadline := time.Now().Add(rekeyAnswered); !p.answererPlane.holding(); time.Sleep(outboundDelay) {
			if time.Now().After(deadline) {
				t.Fatal("the answering end holds no replacement")
			}
		}
		synctest.Wait()
		replacement := p.answerer.Child()
		armed.Store(true)
		asked := make(chan error, 1)
		go func() { asked <- p.answerer.RekeyChildProactively() }()
		<-held
		for deadline := time.Now().Add(rekeyAnswered); p.answerer.Child().LocalSPI != old.LocalSPI; time.Sleep(outboundDelay) {
			if time.Now().After(deadline) {
				t.Fatal("the asking end's Delete did not make the replaced SA current again")
			}
		}
		if err := <-refused; !errors.Is(err, errRefusedInstall) {
			t.Fatalf("the refused Child SA rekey ended with %v, want the dataplane's refusal", err)
		}
		synctest.Wait()
		if got, rekeys := scheduled(), sent.Load(); got != 1 || rekeys != 0 {
			t.Fatalf("at the restore the answering end's schedule started %d rekeys and the answering end sent %d requests, want 1 that found the proactive rekey running and none", got, rekeys)
		}
		armed.Store(true)
		resume <- struct{}{}
		if err := <-asked; !errors.Is(err, errChildReplaced) {
			t.Errorf("the rekey that read the replacement %08x ended with %v, want errChildReplaced", replacement.LocalSPI, err)
		}
		// a rekey that starts after it is held before its request: the count is that rekey's own
		if got := sent.Load(); got != 0 {
			t.Errorf("the rekey that read the replacement %08x put %d requests on the wire, want none", replacement.LocalSPI, got)
		}
		select {
		case <-held:
			if got := scheduled(); got != 2 {
				t.Errorf("the answering end's schedule had started %d rekeys when the next rekey was held, want 2", got)
			}
			resume <- struct{}{}
		case <-time.After(rekeyStartWait):
			t.Errorf("once the rekey that read the replacement %08x ended, the answering end started no rekey of the restored SA, with %d requests on the wire and %d scheduled starts, want one at once", replacement.LocalSPI, sent.Load(), scheduled())
		}
		time.Sleep(time.Until(dialed.Add(restoredLifetime + restoredRead)))
		synctest.Wait()
		if made, peer := p.answerer.Child(), p.asker.Child(); made.LocalSPI == old.LocalSPI || made.RemoteSPI != peer.LocalSPI || made.LocalSPI != peer.RemoteSPI {
			t.Errorf("past the restored SA's lifetime the answering end holds %08x/%08x and the asking end %08x/%08x, want a new SA both hold", made.LocalSPI, made.RemoteSPI, peer.LocalSPI, peer.RemoteSPI)
		}
		if p.answerer.closing.Load() {
			t.Error("the answering end is closing the IKE SA")
		}
		for _, lost := range p.losses() {
			t.Error(lost)
		}
	})(t)
}

// a reload whose check is asked for in the pass that makes the replaced SA current again, as one stored from the cancel itself is, is checked once against the lists with the restore's own check, so the SA is reported unlisted once and rekeyed once
func TestRestoreWithAReloadQueuedChecksTheListsOnce(t *testing.T) {
	bubble.Run(func(t *testing.T) {
		lists := new(atomic.Pointer[Suites])
		lists.Store(&Suites{})
		aes128 := suitesOf(t, Crypto{ESP: ESPSuites{Cipher: []string{"aes128gcm"}}})
		var unlisted, started atomic.Int32
		p := dialOutbound(t, outboundCase{askerIsInitiator: false, delay: outboundDelay, refusals: 1, configure: func(cfg *PeerConfig) {
			cfg.Suites = func() Suites { return *lists.Load() }
		}, seed: func(asker, answerer *Session) {
			answerer.timing.ChildRekeyInterval, answerer.timing.RekeyJitter = 0, reloadJitter
			answerer.rekeyJitterSource = func(bound time.Duration) (time.Duration, error) { return bound, nil }
			asker.timing.RekeyRetryInitial, asker.timing.RekeyRetryMax = time.Hour, time.Hour
			answerer.events = func(_, _ identity.Identity, kind string, attrs ...slog.Attr) {
				child := slices.ContainsFunc(attrs, func(a slog.Attr) bool { return a.Key == "sa" && a.Value.String() == "child" })
				switch {
				case kind == "ike.suite.unlisted" && child:
					unlisted.Add(1)
				case kind == "ike.rekey.started" && child:
					started.Add(1)
				}
			}
		}})
		old := p.answerer.Child()
		p.answererPlane.mu.Lock()
		p.answererPlane.beforeCancel = func() {
			lists.Store(&aes128)
			p.answerer.SuitesChanged()
		}
		p.answererPlane.mu.Unlock()
		if err := p.rekeyChild(t); !errors.Is(err, errRefusedInstall) {
			t.Fatalf("the refused Child SA rekey ended with %v, want the dataplane's refusal", err)
		}
		synctest.Wait()
		if got := p.answerer.Child(); got.LocalSPI != old.LocalSPI {
			t.Fatalf("after the asking end's Delete the answering end holds %08x, want the replaced SA %08x again", got.LocalSPI, old.LocalSPI)
		}
		time.Sleep(queuedReloadWatch)
		synctest.Wait()
		made, asked := p.answerer.Child(), p.asker.Child()
		if got := p.answerer.Suite().ESP(); got != "aes128gcm" || made.LocalSPI == old.LocalSPI || made.RemoteSPI != asked.LocalSPI {
			t.Errorf("the answering end holds %08x of %s and the asking end %08x/%08x, want a new SA of aes128gcm both hold", made.LocalSPI, got, asked.LocalSPI, asked.RemoteSPI)
		}
		if unlisted.Load() != 1 || started.Load() != 1 {
			t.Errorf("the restore with a reload queued reported the Child SA unlisted %d times and started %d rekeys, want once each", unlisted.Load(), started.Load())
		}
	})(t)
}

// when the reload of the test of a restore under a shut retry delay comes, before or after the answering end's own failed rekey
const (
	reloadBeforeOwnRekey = retryWaitAsk + (retryWaitOwnAsk-retryWaitAsk)/2
	reloadAfterOwnRekey  = retryWaitOwnAsk + retryWaitAsk/4
)

// the restore of TestRestoredChildSAWaitsOutTheRetryDelayOfAFailedRekey with the lists reloaded to leave out the restored SA's cipher, before or after the answering end's own rekey fails
// the schedule's wake at the delay's end and the forced rekey of the reload meet there, and the restored SA is rekeyed to the lists in force before its lifetime closes the IKE SA
func TestRestoredChildSAWaitsOutTheRetryDelayAndTakesTheReloadedLists(t *testing.T) {
	for _, row := range []struct {
		name     string
		reloadAt time.Duration
	}{{"reload before the own rekey", reloadBeforeOwnRekey}, {"reload after the own rekey", reloadAfterOwnRekey}} {
		t.Run(row.name, bubble.Run(func(t *testing.T) {
			lists := new(atomic.Pointer[Suites])
			lists.Store(&Suites{})
			aes128 := suitesOf(t, Crypto{ESP: ESPSuites{Cipher: []string{"aes128gcm"}}})
			var dialed time.Time
			p := dialOutbound(t, outboundCase{askerIsInitiator: true, delay: outboundDelay, lostDeletes: 1, refusals: 1, seed: func(asker, answerer *Session) {
				answerer.suites = func() Suites { return *lists.Load() }
				answerer.timing.ChildRekeyInterval, answerer.timing.RekeyMargin, answerer.timing.RekeyJitter = retryWaitLifetime, retryWaitMargin, 0
				answerer.timing.RekeyRetryInitial, answerer.timing.RekeyRetryMax = retryWaitDelay, retryWaitDelay
				answerer.rekeyJitterSource = unjittered
				asker.timing.RekeyRetryInitial, asker.timing.RekeyRetryMax = time.Hour, time.Hour
				asker.timing.RekeyJitter = time.Hour
				asker.rekeyJitterSource = func(bound time.Duration) (time.Duration, error) { return bound, nil }
				dialed = answerer.childEstablished
			}})
			old := p.answerer.Child()
			if got := p.answerer.Suite().ESP(); got != "aes256gcm" {
				t.Fatalf("the answering end's Child SA is of %s, want aes256gcm", got)
			}
			p.carry(true, true)
			time.Sleep(time.Until(dialed.Add(retryWaitAsk)))
			ended := make(chan error, 1)
			go func() { ended <- p.asker.RekeyChild() }()
			reload := func() {
				lists.Store(&aes128)
				p.answerer.SuitesChanged()
			}
			if row.reloadAt < retryWaitOwnAsk {
				time.Sleep(time.Until(dialed.Add(row.reloadAt)))
				reload()
			}
			time.Sleep(time.Until(dialed.Add(retryWaitOwnAsk)))
			if err := p.answerer.RekeyChild(); err == nil {
				t.Fatal("the answering end's rekey of the SA awaiting retirement succeeded")
			}
			if row.reloadAt > retryWaitOwnAsk {
				time.Sleep(time.Until(dialed.Add(row.reloadAt)))
				reload()
			}
			if err := <-ended; !errors.Is(err, errRefusedInstall) {
				t.Fatalf("the refused Child SA rekey ended with %v, want the dataplane's refusal", err)
			}
			synctest.Wait()
			if got := p.answerer.Child(); got.LocalSPI != old.LocalSPI {
				t.Fatalf("after the asking end's Delete the answering end holds %08x, want the replaced SA %08x again", got.LocalSPI, old.LocalSPI)
			}
			time.Sleep(time.Until(dialed.Add(retryWaitLifetime - restoredRead)))
			synctest.Wait()
			made, asked := p.answerer.Child(), p.asker.Child()
			if got := p.answerer.Suite().ESP(); got != "aes128gcm" || made.LocalSPI == old.LocalSPI || made.RemoteSPI != asked.LocalSPI {
				t.Errorf("before the replaced SA's lifetime the answering end holds %08x of %s and the asking end %08x/%08x, want a new SA of aes128gcm both hold", made.LocalSPI, got, asked.LocalSPI, asked.RemoteSPI)
			}
			time.Sleep(restoredRead + retryWaitMargin)
			synctest.Wait()
			if p.answerer.closing.Load() {
				t.Error("the answering end is closing the IKE SA")
			}
			for _, lost := range p.losses() {
				t.Error(lost)
			}
		}))
	}
}

// in the tests of a reload around a canceled replacement the answering end has no rekey interval, so only a rekey the lists force replaces the SA, which it forces reloadJitter after the lists change
// the asking end asks at reloadAsk and its Delete, lost once, comes requestTimeout later, the reload comes before the ask or during the wait at reloadAt, and reloadRead is when the test reads the cipher
const (
	reloadJitter = time.Second
	reloadAsk    = 500 * time.Millisecond
	reloadRead   = 6 * time.Second
	// reloadRetry is the answering end's retry delay, half of which its jitter draw takes off
	reloadRetry = 2 * time.Second
)

// RFC 7296 section 2.8: "Note that, when rekeying, the new Child SA SHOULD NOT have different Traffic Selectors and algorithms than the old one."
// a reload that leaves out the cipher of the answering end's Child SA forces a rekey of it, and a peer's rekey whose SA the peer then deletes makes that SA current again
// the SA made current again is still rekeyed to the lists in force, whether the lists changed before the peer's rekey, so the forced rekey's timer ran out on the new SA, or during the wait, so the forced rekey of the new SA failed on the SA awaiting retirement
func TestRestoredChildSAIsRekeyedToTheReloadedLists(t *testing.T) {
	for _, row := range []struct {
		name     string
		reloadAt time.Duration
	}{{"reload before the peer's rekey", reloadAsk / 5}, {"reload during the wait", 2 * reloadAsk}} {
		t.Run(row.name, bubble.Run(func(t *testing.T) {
			lists := new(atomic.Pointer[Suites])
			lists.Store(&Suites{})
			aes128 := suitesOf(t, Crypto{ESP: ESPSuites{Cipher: []string{"aes128gcm"}}})
			var dialed time.Time
			p := dialOutbound(t, outboundCase{askerIsInitiator: false, delay: outboundDelay, lostDeletes: 1, refusals: 1, configure: func(cfg *PeerConfig) {
				cfg.Suites = func() Suites { return *lists.Load() }
			}, seed: func(asker, answerer *Session) {
				answerer.timing.ChildRekeyInterval, answerer.timing.RekeyJitter = 0, reloadJitter
				answerer.timing.RekeyRetryInitial, answerer.timing.RekeyRetryMax = reloadRetry, reloadRetry
				answerer.rekeyJitterSource = func(bound time.Duration) (time.Duration, error) { return bound, nil }
				asker.timing.RekeyRetryInitial, asker.timing.RekeyRetryMax = time.Hour, time.Hour
				// a peer that reloaded the same lists before its rekey offers the cipher they keep, and forces no rekey of its own within the test
				if row.reloadAt < reloadAsk {
					asker.suites = func() Suites { return aes128 }
					asker.timing.RekeyJitter = time.Hour
					asker.rekeyJitterSource = func(bound time.Duration) (time.Duration, error) { return bound, nil }
				}
				dialed = answerer.childEstablished
			}})
			if got := p.answerer.Suite().ESP(); got != "aes256gcm" {
				t.Fatalf("the answering end's Child SA is of %s, want aes256gcm", got)
			}
			old := p.answerer.Child()
			reload := func() {
				lists.Store(&aes128)
				p.answerer.SuitesChanged()
			}
			if row.reloadAt < reloadAsk {
				time.Sleep(time.Until(dialed.Add(row.reloadAt)))
				reload()
			}
			time.Sleep(time.Until(dialed.Add(reloadAsk)))
			ended := make(chan error, 1)
			go func() { ended <- p.asker.RekeyChild() }()
			if row.reloadAt > reloadAsk {
				time.Sleep(time.Until(dialed.Add(row.reloadAt)))
				reload()
			}
			if err := <-ended; !errors.Is(err, errRefusedInstall) {
				t.Fatalf("the refused Child SA rekey ended with %v, want the dataplane's refusal", err)
			}
			synctest.Wait()
			if got := p.answerer.Child(); got.LocalSPI != old.LocalSPI {
				t.Fatalf("after the asking end's Delete the answering end holds %08x, want the replaced SA %08x again", got.LocalSPI, old.LocalSPI)
			}
			time.Sleep(time.Until(dialed.Add(reloadRead)))
			synctest.Wait()
			made, asked := p.answerer.Child(), p.asker.Child()
			if got := p.answerer.Suite().ESP(); got != "aes128gcm" || made.LocalSPI == old.LocalSPI || made.RemoteSPI != asked.LocalSPI {
				t.Errorf("the answering end holds %08x of %s and the asking end %08x/%08x, want a new SA of aes128gcm both hold", made.LocalSPI, got, asked.LocalSPI, asked.RemoteSPI)
			}
		}))
	}
}

// RFC 7296 section 2.8: "Note that, when rekeying, the new Child SA SHOULD NOT have different Traffic Selectors and algorithms than the old one."
// a reload that leaves out the cipher of the asking end's Child SA forces a rekey of it, whose new SA the asking end's dataplane refuses, so it deletes that SA itself
// its Child SA is the old one throughout, and the retry of the forced rekey still replaces it with an SA of the lists in force
func TestRefusedReplacementLeavesTheReloadedListsInForce(t *testing.T) {
	bubble.Run(func(t *testing.T) {
		lists := new(atomic.Pointer[Suites])
		lists.Store(&Suites{})
		aes128 := suitesOf(t, Crypto{ESP: ESPSuites{Cipher: []string{"aes128gcm"}}})
		both := suitesOf(t, Crypto{ESP: ESPSuites{Cipher: []string{"aes256gcm", "aes128gcm"}}})
		var dialed time.Time
		p := dialOutbound(t, outboundCase{askerIsInitiator: true, delay: outboundDelay, refusals: 1, seed: func(asker, answerer *Session) {
			asker.suites = func() Suites { return *lists.Load() }
			answerer.suites = func() Suites { return both }
			asker.timing.ChildRekeyInterval, asker.timing.RekeyJitter = 0, reloadJitter
			asker.timing.RekeyRetryInitial, asker.timing.RekeyRetryMax = reloadRetry, reloadRetry
			asker.rekeyJitterSource = func(bound time.Duration) (time.Duration, error) { return bound, nil }
			dialed = asker.childEstablished
		}})
		old := p.asker.Child()
		time.Sleep(time.Until(dialed.Add(reloadAsk / 5)))
		lists.Store(&aes128)
		p.asker.SuitesChanged()
		time.Sleep(time.Until(dialed.Add(reloadRead)))
		synctest.Wait()
		made, answered := p.asker.Child(), p.answerer.Child()
		if got := p.asker.Suite().ESP(); got != "aes128gcm" || made.LocalSPI == old.LocalSPI || made.RemoteSPI != answered.LocalSPI {
			t.Errorf("the asking end holds %08x of %s and the answering end %08x/%08x, want a new SA of aes128gcm both hold", made.LocalSPI, got, answered.LocalSPI, answered.RemoteSPI)
		}
		p.askerPlane.mu.Lock()
		refused := p.askerPlane.refuse
		p.askerPlane.mu.Unlock()
		if refused != 0 {
			t.Errorf("the asking end's dataplane has %d refusals left, want the forced rekey's SA refused", refused)
		}
	})(t)
}

// the answering end's replaced SA made current again and then spent, with the session's two orders driven by hand: the rekey the dataplane asks for running when the session hears of the spent SA, which replaces it and keeps the IKE SA, and the session hearing of it first, which closes the IKE SA as for any spent Child SA with no rekey running
// the test calls the session's two entry points itself and never reaches the tunnel's moveOffSpent, whose ask internal/client's tests drive
func TestSpentChildSAMadeCurrentAgainIsRekeyedWhileTheAskRuns(t *testing.T) {
	for _, row := range []struct {
		name      string
		askFirst  bool
		closesIKE bool
	}{{"rekey asked first", true, false}, {"spent heard first", false, true}} {
		t.Run(row.name, bubble.Run(func(t *testing.T) {
			p := dialOutbound(t, outboundCase{askerIsInitiator: true, delay: outboundDelay, refusals: 1, seed: func(asker, _ *Session) {
				asker.timing.RekeyRetryInitial, asker.timing.RekeyRetryMax = time.Hour, time.Hour
			}})
			old := p.answerer.Child()
			if err := p.rekeyChild(t); !errors.Is(err, errRefusedInstall) {
				t.Fatalf("the refused Child SA rekey ended with %v, want the dataplane's refusal", err)
			}
			synctest.Wait()
			if got := p.answerer.Child(); got.LocalSPI != old.LocalSPI {
				t.Fatalf("after the asking end's Delete the answering end holds %08x, want the replaced SA %08x again", got.LocalSPI, old.LocalSPI)
			}
			asked := make(chan error, 1)
			if row.askFirst {
				go func() { asked <- p.answerer.RekeyChildProactively() }()
				synctest.Wait()
			}
			p.answerer.ChildSequenceSpent(old.LocalSPI)
			synctest.Wait()
			if row.askFirst {
				if err := <-asked; err != nil {
					t.Fatalf("the rekey asked for the spent SA ended with %v", err)
				}
				synctest.Wait()
				if made, other := p.answerer.Child(), p.asker.Child(); made.LocalSPI == old.LocalSPI || made.RemoteSPI != other.LocalSPI {
					t.Errorf("the answering end holds %08x and the asking end %08x/%08x, want a new SA both hold", made.LocalSPI, other.LocalSPI, other.RemoteSPI)
				}
			}
			if got := p.answerer.closing.Load(); got != row.closesIKE {
				t.Errorf("the answering end is closing the IKE SA is %v, want %v", got, row.closesIKE)
			}
		}))
	}
}

// a peer's Delete that names the new SA and the SA it replaced closes both as a Delete of the replaced SA followed by one of the new SA does, so the replaced SA's inbound half drains and nothing is made current again
func TestDeleteOfBothChildSAsDrainsTheReplacedOne(t *testing.T) {
	bubble.Run(func(t *testing.T) {
		s, plane, _, old, made, _ := heldSession(t)
		s.childRetireDelay = childRetireDelay
		spis, err := s.deleteChildren([]uint32{made.RemoteSPI, old.RemoteSPI})
		if err != nil || len(spis) != 2 || !slices.Contains(spis, old.LocalSPI) || !slices.Contains(spis, made.LocalSPI) {
			t.Fatalf("the peer's Delete of both SAs was answered with %08x, %v, want both SPIs", spis, err)
		}
		if child, retiring := s.Child(), s.retiringChild(); child.LocalSPI != 0 || retiring.LocalSPI != 0 {
			t.Errorf("the session holds %08x and awaits the retirement of %08x, want neither", child.LocalSPI, retiring.LocalSPI)
		}
		if !plane.open(old.LocalSPI) {
			t.Error("the replaced SA's inbound half left at once, want it draining")
		}
		if out := plane.sending(); out != 0 {
			t.Errorf("the dataplane sends on %08x once both SAs are deleted, want no outbound SA", out)
		}
	})(t)
}

// the end that answers a Child SA rekey moves its outbound SA to the new one at the two ends of its wait the peer does not decide, its own Delete of the replaced SA at retirementDeadline and that SA's lifetime, and every packet it seals is opened
// at the deadline its Delete crosses the asking end's, which the relay lost until then, and each end skips the other's
func TestAnsweringEndMovesItsOutboundSAAtTheEndsOfItsWait(t *testing.T) {
	t.Run("deadline", bubble.Run(func(t *testing.T) {
		p := dialOutbound(t, outboundCase{askerIsInitiator: true, delay: outboundDelay, lostDeletesFor: flowSettle + retirementDeadline})
		old := p.answerer.Child()
		p.carry(true, false)
		time.Sleep(flowSettle)
		if err := p.rekeyChild(t); err != nil {
			t.Fatalf("the Child SA rekey ended with %v", err)
		}
		made := p.answerer.Child()
		held, _ := p.answererPlane.installedAt(made.LocalSPI)
		moves := p.answererPlane.recorded()
		if len(moves) != 1 || moves[0].to != made.RemoteSPI || moves[0].by != "session" || moves[0].at.Before(held.Add(retirementDeadline)) || !moves[0].at.Before(held.Add(retirementDeadline+outboundDelay)) {
			t.Errorf("the answering end's outbound SA moved %+v, want once from %08x to %08x by its own Delete at %v", moves, old.RemoteSPI, made.RemoteSPI, held.Add(retirementDeadline))
		}
		synctest.Wait()
		for _, end := range []*Session{p.answerer, p.asker} {
			if retiring := end.retiringChild(); retiring.LocalSPI != 0 {
				t.Errorf("an end still awaits the retirement of %08x after the crossing Deletes", retiring.LocalSPI)
			}
		}
		for _, lost := range p.losses() {
			t.Error(lost)
		}
	}))
	t.Run("lifetime", bubble.Run(func(t *testing.T) {
		var dialed time.Time
		p := dialOutbound(t, outboundCase{askerIsInitiator: true, delay: outboundDelay, lostDeletesFor: outboundLifetime + deleteLate, seed: func(_, answerer *Session) {
			answerer.timing.ChildRekeyInterval, answerer.timing.RekeyMargin, answerer.timing.RekeyJitter = outboundLifetime, 0, 0
			dialed = answerer.childEstablished
		}})
		old := p.answerer.Child()
		p.carry(true, false)
		time.Sleep(time.Until(dialed.Add(outboundLifetime - rekeyAhead)))
		if err := p.rekeyChild(t); err != nil {
			t.Fatalf("the Child SA rekey ended with %v", err)
		}
		made := p.answerer.Child()
		moves := p.answererPlane.recorded()
		if len(moves) != 1 || moves[0].to != made.RemoteSPI || moves[0].by != "retire" || moves[0].at.Before(dialed.Add(outboundLifetime)) {
			t.Errorf("the answering end's outbound SA moved %+v, want once from %08x to %08x at the replaced SA's lifetime %v", moves, old.RemoteSPI, made.RemoteSPI, dialed.Add(outboundLifetime))
		}
		for _, lost := range p.losses() {
			t.Error(lost)
		}
	}))
}

// heldSession is a session whose Child SA old, established at established and kexed by oldEntry, a peer's rekey replaced with made, outbound traffic still on old
func heldSession(t *testing.T) (s *Session, plane *outboundPlane, other *transport.Mux, old, made ChildSA, established time.Time) {
	t.Helper()
	mux, other := lifecycleMuxes(t)
	old, made = ChildSA{LocalSPI: 0x11111111, RemoteSPI: 0x33333333}, ChildSA{LocalSPI: 0x22222222, RemoteSPI: 0x44444444}
	if err := mux.RegisterESP(old.LocalSPI); err != nil {
		t.Fatal(err)
	}
	established = time.Now().Add(-time.Minute)
	s = &Session{mux: mux, child: old, timing: RekeyTiming{ChildRekeyInterval: time.Hour}, childEstablished: established, childGeneration: 7, childKex: keyedEntry{spi: old.LocalSPI, entry: oldEntry}, rekeyJitterSource: randomRekeyJitter}
	plane = newOutboundPlane(s)
	time.Sleep(rekeyAhead)
	if err := s.replaceKeyedChild(made, madeEntry, true); err != nil {
		t.Fatal(err)
	}
	if out := plane.sending(); out != old.RemoteSPI {
		t.Fatalf("the dataplane sends on %08x once the peer's rekey is installed, want the replaced SA's %08x", out, old.RemoteSPI)
	}
	return s, plane, other, old, made, established
}

// oldEntry and madeEntry are the kex entries of heldSession's two Child SAs
var oldEntry, madeEntry = kexEntry{group: DH_CURVE25519}, kexEntry{group: DH_ECP_384}

// a peer's Delete of the Child SA its rekey made, while outbound traffic still waits on the SA that one replaced, makes the replaced SA current again as it was, with its lifetime and its kex entry, under a generation no SA had, leaves nothing awaiting retirement, answers with the deleted SA's SPI, lets that SPI go and marks the Child SA schedule for Run to rearm
func TestDeletedReplacementRestoresTheReplacedChildSAAsItWas(t *testing.T) {
	bubble.Run(testDeletedReplacementRestoresTheReplacedChildSAAsItWas)(t)
}

func testDeletedReplacementRestoresTheReplacedChildSAAsItWas(t *testing.T) {
	s, plane, other, old, made, established := heldSession(t)
	if spis, err := s.deleteChildren([]uint32{made.RemoteSPI}); err != nil || !slices.Equal(spis, []uint32{made.LocalSPI}) {
		t.Fatalf("the peer's Delete of the SA its rekey made was answered with %08x, %v, want that SA's SPI", spis, err)
	}
	s.childMu.RLock()
	child, at, generation, entry := s.child, s.childEstablished, s.childGeneration, s.childEntryLocked()
	retiring, ends, by, deleting := s.retiring, s.retiringEnds, s.retiringBy, s.retiringDeleting
	s.childMu.RUnlock()
	if child.LocalSPI != old.LocalSPI || child.RemoteSPI != old.RemoteSPI || !at.Equal(established) || entry != oldEntry {
		t.Errorf("the session holds %08x/%08x established %v, kex %+v, want %08x/%08x as it was, %v and %+v", child.LocalSPI, child.RemoteSPI, at, entry, old.LocalSPI, old.RemoteSPI, established, oldEntry)
	}
	// generations 7 and 8 were the replaced SA's and the canceled one's
	if generation <= 8 {
		t.Errorf("the restored SA holds generation %d, want one no SA had", generation)
	}
	if !s.childRestored {
		t.Error("making the replaced SA current again left the Child SA schedule unmarked")
	}
	if retiring.LocalSPI != 0 || !ends.IsZero() || !by.IsZero() || deleting {
		t.Errorf("the session still awaits the retirement of %08x, ending %v, deleting by %v and %v, want nothing", retiring.LocalSPI, ends, by, deleting)
	}
	if out := plane.sending(); out != old.RemoteSPI {
		t.Errorf("the dataplane sends on %08x, want the replaced SA's %08x", out, old.RemoteSPI)
	}
	if err := other.RegisterESP(made.LocalSPI); err != nil {
		t.Errorf("the deleted SA's SPI is still routed to the session: %v", err)
	}
}

// a Child SA schedule armed for a replacement the peer then deleted reads the SA made current again, and a later SA, as replaced, so neither is rekeyed early as the canceled one
func TestRestoredChildSAIsNeverTakenForItsCanceledReplacement(t *testing.T) {
	bubble.Run(func(t *testing.T) {
		s, _, _, _, made, _ := heldSession(t)
		schedule, err := s.newRekeySchedule("Child SA", "child", s.timing.ChildRekeyInterval, nil, s.childEstablishedAt, func() any { return s.currentChildGeneration() })
		if err != nil {
			t.Fatal(err)
		}
		defer schedule.timer.Stop()
		if _, err := s.deleteChildren([]uint32{made.RemoteSPI}); err != nil {
			t.Fatal(err)
		}
		if !schedule.replaced() {
			t.Error("the schedule armed for the canceled SA reads the restored SA as that one")
		}
		if err := s.replaceChild(ChildSA{LocalSPI: 0x55555555, RemoteSPI: 0x66666666}); err != nil {
			t.Fatal(err)
		}
		if !schedule.replaced() {
			t.Error("the schedule armed for the canceled SA reads the next SA installed as that one")
		}
	})(t)
}

// each move of the held outbound SA the session makes, at the peer's Delete of the replaced SA, at this end's own Delete of it at retirementDeadline and at its lifetime, is made in the call that decides it, and a packet that opens on the new SA moves it in the dataplane
// none waits on the asking end: at the deadline and the lifetime this end has no sign that the peer installed the new SA, so these bound the wait
// once outbound traffic has moved, a Delete of the new SA closes it and puts nothing back
func TestHeldOutboundSAMovesAtEachEndOfItsWait(t *testing.T) {
	for _, row := range []struct {
		name string
		move func(t *testing.T, s *Session, plane *outboundPlane, old, made ChildSA, established time.Time)
	}{
		{"peer's Delete of the replaced SA", func(t *testing.T, s *Session, _ *outboundPlane, old, _ ChildSA, _ time.Time) {
			if spis, err := s.deleteChildren([]uint32{old.RemoteSPI}); err != nil || !slices.Equal(spis, []uint32{old.LocalSPI}) {
				t.Fatalf("the peer's Delete of the replaced SA was answered with %08x, %v, want its SPI", spis, err)
			}
		}},
		{"own Delete at the deadline", func(t *testing.T, s *Session, _ *outboundPlane, old, _ ChildSA, _ time.Time) {
			time.Sleep(retirementDeadline)
			if child, ok := s.overdueRetiring(time.Now()); !ok || child.LocalSPI != old.LocalSPI {
				t.Fatalf("the deadline marked %08x for its Delete, %v, want the replaced SA %08x", child.LocalSPI, ok, old.LocalSPI)
			}
		}},
		{"lifetime of the replaced SA", func(t *testing.T, s *Session, _ *outboundPlane, _, _ ChildSA, established time.Time) {
			time.Sleep(time.Until(established.Add(s.timing.ChildRekeyInterval)))
			if err := s.expireChild(time.Now()); err != nil {
				t.Fatal(err)
			}
		}},
		{"spent sequence space of the replaced SA", func(t *testing.T, s *Session, plane *outboundPlane, old, made ChildSA, _ time.Time) {
			plane.take(made.LocalSPI, "spent")
			s.ChildSequenceSpent(old.LocalSPI)
			if s.currentChildSpent() {
				t.Fatal("the session reads the new SA as spent once the replaced one ran out of sequence numbers")
			}
		}},
		{"packet on the new SA", func(t *testing.T, _ *Session, plane *outboundPlane, _, made ChildSA, _ time.Time) {
			if !plane.open(made.LocalSPI) {
				t.Fatal("the new SA does not open the peer's packet")
			}
		}},
	} {
		t.Run(row.name, bubble.Run(func(t *testing.T) {
			s, plane, _, old, made, established := heldSession(t)
			row.move(t, s, plane, old, made, established)
			if out := plane.sending(); out != made.RemoteSPI {
				t.Fatalf("the dataplane sends on %08x right after the move, want the new SA's %08x", out, made.RemoteSPI)
			}
			if spis, err := s.deleteChildren([]uint32{made.RemoteSPI}); err != nil || !slices.Equal(spis, []uint32{made.LocalSPI}) {
				t.Fatalf("the Delete of the new SA was answered with %08x, %v, want its SPI", spis, err)
			}
			if child := s.Child(); child.LocalSPI != 0 {
				t.Errorf("the Delete of the new SA after the move left %08x current, want none", child.LocalSPI)
			}
		}))
	}
}

// this end marks the replaced SA for its own Delete at retirementDeadline and moves outbound traffic in the same call, before the Delete goes out, so a Delete of the peer's that comes between the two finds outbound traffic moved
// RFC 7296 section 1.4.1: "If a node receives a delete request for SAs for which it has already issued a delete request, it MUST delete the outgoing SAs while processing the request and the incoming SAs while processing the response."
// a crossing Delete of the replaced SA is answered without its SPI and leaves its incoming half to this end's own, and a Delete of the new SA closes it and puts nothing back, so this end's Delete still names a replaced SA and never the current one
func TestCrossingDeleteFindsTheHeldOutboundSAMoved(t *testing.T) {
	for _, row := range []struct {
		name    string
		deleted func(old, made ChildSA) uint32
		answer  func(old, made ChildSA) []uint32
		current func(old, made ChildSA) uint32
	}{
		{"replaced SA", func(old, _ ChildSA) uint32 { return old.RemoteSPI }, func(ChildSA, ChildSA) []uint32 { return []uint32{} }, func(_, made ChildSA) uint32 { return made.LocalSPI }},
		{"new SA", func(_, made ChildSA) uint32 { return made.RemoteSPI }, func(_, made ChildSA) []uint32 { return []uint32{made.LocalSPI} }, func(ChildSA, ChildSA) uint32 { return 0 }},
	} {
		t.Run(row.name, bubble.Run(func(t *testing.T) {
			s, plane, _, old, made, _ := heldSession(t)
			time.Sleep(retirementDeadline)
			marked, ok := s.overdueRetiring(time.Now())
			if !ok || marked.LocalSPI != old.LocalSPI {
				t.Fatalf("the deadline marked %08x for its Delete, %v, want the replaced SA %08x", marked.LocalSPI, ok, old.LocalSPI)
			}
			if spis, err := s.deleteChildren([]uint32{row.deleted(old, made)}); err != nil || !slices.Equal(spis, row.answer(old, made)) {
				t.Fatalf("the peer's Delete between the mark and the send was answered with %08x, %v, want %08x", spis, err, row.answer(old, made))
			}
			if out := plane.sending(); out == old.RemoteSPI {
				t.Errorf("the dataplane still sends on the replaced SA %08x after the mark", out)
			}
			if child, retiring := s.Child(), s.retiringChild(); child.LocalSPI != row.current(old, made) || retiring.LocalSPI != old.LocalSPI {
				t.Errorf("the session holds %08x and awaits the retirement of %08x, want %08x and the replaced SA %08x its own Delete names", child.LocalSPI, retiring.LocalSPI, row.current(old, made), old.LocalSPI)
			}
		}))
	}
}

// the Child SA a peer's chain of IKE_FOLLOWUP_KE exchanges made is installed at the chain's last answer with outbound traffic left on the SA it replaces, which the first packet on the new SA moves
// RFC 9370 section 2.2.4: "Instead, they would be created only after the series of IKE_FOLLOWUP_KE exchanges is finished."
func TestPeersChainLeavesOutboundTrafficOnTheReplacedChildSA(t *testing.T) {
	bubble.Run(func(t *testing.T) {
		s, _ := answeringChain(t, modelSuite, Suites{kex: []kexEntry{entry768}})
		old, ctx := s.Child(), s.current
		plane := newOutboundPlane(s)
		p, request := newPeerChildRekey(t, s, childOffer, drawnOctets(t, 32))
		if answer := p.rekey(t, s.handleChildRekey, ctx, request); findType(answer, PayloadSA) == nil || len(p.link) != followupLinkLen {
			t.Fatalf("the rekey drew %v with the link %x, want an SA and a chain", payloadTypes(answer), p.link)
		}
		if last, err := p.followup(t, s, ctx, ML_KEM_768, p.link); err != nil || !p.installed(s) {
			t.Fatalf("the IKE_FOLLOWUP_KE drew %v, %v, want the Child SA installed", payloadTypes(last), err)
		}
		if out := plane.sending(); out != old.RemoteSPI {
			t.Errorf("the dataplane sends on %08x once the chain's SA is installed, want the replaced SA's %08x", out, old.RemoteSPI)
		}
		if !plane.open(p.espR) {
			t.Fatal("the chain's SA does not open the peer's packet")
		}
		if out := plane.sending(); out != p.espI {
			t.Errorf("the dataplane sends on %08x after a packet on the chain's SA, want %08x", out, p.espI)
		}
	})(t)
}
