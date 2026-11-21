// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/esp"
	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/ike"
)

// how long the test of a restored then spent Child SA waits for a session to answer, for a hold, a restore, the rekey the dataplane asks for and the outcome, and how often it looks
const (
	restoredSpentAnswer = 10 * time.Second
	restoredSpentWait   = 5 * time.Second
	restoredSpentPoll   = time.Millisecond
	// restoredSpentRetry is the answering end's retry delay
	restoredSpentRetry = 500 * time.Millisecond
)

var errRestoredSpentRefused = errors.New("the asking end's dataplane refuses the Child SA")

// restoredSpentPair is two running sessions over loopback: the answering end responder with the tunnel serveSession builds, the asking end initiator whose dataplane refuses its next Child SA
type restoredSpentPair struct {
	asker, answerer *ike.Session
	tun             *tunnel
	// rekeyStarted is closed once the answering end records the start of a Child SA rekey
	rekeyStarted chan struct{}
	// answered is closed when the asking end's dataplane is handed the new Child SA, which the answering end holds by then, and the refusal waits for refuse to close
	answered, refuse chan struct{}
	ended            chan error
	cancel           context.CancelFunc
	runs             sync.WaitGroup
}

func dialRestoredSpent(t *testing.T) *restoredSpentPair {
	t.Helper()
	alpha, bravo := newLoopbackMesh(t)
	t.Cleanup(func() { alpha.client.Close(); bravo.client.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	p := &restoredSpentPair{rekeyStarted: make(chan struct{}), answered: make(chan struct{}), refuse: make(chan struct{}), ended: make(chan error, 1), cancel: cancel}
	var startedOnce sync.Once
	events := func(_, _ identity.Identity, kind string, attrs ...slog.Attr) {
		if kind == "ike.rekey.started" {
			startedOnce.Do(func() { close(p.rekeyStarted) })
		}
	}
	timing := bravo.cfg.Crypto().Timing()
	timing.RekeyRetryInitial, timing.RekeyRetryMax = restoredSpentRetry, restoredSpentRetry
	askerTiming := timing
	askerTiming.RekeyRetryInitial, askerTiming.RekeyRetryMax = time.Hour, time.Hour
	bc := bravo.client
	responder, err := ike.NewResponder(ike.ResponderConfig{
		Hub: bc.hub, Local: bc.config().LocalFamilies(), LocalPrivateKey: bc.privateKey, Trust: liveTrust{bc},
		Aliases: func() ike.Aliases { return bc.config().Auth.Aliases }, RekeyTiming: timing, Suites: bc.suites, CookieAnswers: &bc.cookieAnswers, Events: events,
	})
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan *ike.Session, 1)
	go func() { _ = responder.Serve(ctx, func(s *ike.Session, _ ike.Accepted) { accepted <- s }) }()
	x := alpha.client.index()
	d := dials(alpha.cfg, x)[0]
	ep, remoteIP, err := resolveEndpoint(ctx, x, nil, testPrepare(), d.peer, d.local.Family, &names{})
	if err != nil {
		t.Fatal(err)
	}
	remotePub, err := x.Key(ep.ID)
	if err != nil {
		t.Fatal(err)
	}
	p.asker, err = ike.InitiateContext(ctx, ike.PeerConfig{Local: d.localID, LocalPrivateKey: alpha.client.privateKey, Remote: ep.ID, RemotePublicKey: remotePub,
		RemoteAddr: remoteIP, RemotePort: int(bravo.port), Aliases: alpha.cfg.Auth.Aliases, Hub: alpha.client.hub, RekeyTiming: askerTiming, Suites: alpha.client.suites})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case p.answerer = <-accepted:
	case <-time.After(restoredSpentAnswer):
		t.Fatal("no session answered")
	}
	if p.tun, err = sessionTunnel(p.answerer, p.answerer.Child(), bc.config().Crypto().ReplayWindow(), func(error) {}); err != nil {
		t.Fatal(err)
	}
	askerTun, err := sessionTunnel(p.asker, p.asker.Child(), alpha.client.config().Crypto().ReplayWindow(), func(error) {})
	if err != nil {
		t.Fatal(err)
	}
	refused := false
	p.asker.SetChildHandler(func(child esp.ChildSA) error {
		if !refused {
			refused = true
			close(p.answered)
			<-p.refuse
			return errRestoredSpentRefused
		}
		return askerTun.install(child)
	})
	p.runs.Go(func() { _ = p.asker.Run(ctx) })
	p.runs.Go(func() { p.ended <- p.answerer.Run(ctx) })
	t.Cleanup(func() {
		p.cancel()
		_ = p.asker.Mux().Close()
		_ = p.answerer.Mux().Close()
		p.runs.Wait()
	})
	return p
}

// untilRestoredSpent polls cond until it holds or restoredSpentWait passes, and reports whether it held
func untilRestoredSpent(cond func() bool) bool {
	for deadline := time.Now().Add(restoredSpentWait); time.Now().Before(deadline); time.Sleep(restoredSpentPoll) {
		if cond() {
			return true
		}
	}
	return cond()
}

// a reservation meets the answering end's outbound SA spent while a peer's rekey is held, the peer refuses the new SA and its Delete makes the replaced SA current again, and only then does the reservation move off the spent SA
// the dataplane leaves the spent SA selected and asks the running session for a rekey, which replaces it, and the IKE SA stays
// the session hears of the spent SA once that rekey has started, the order the ask's goroutine usually wins, since the session closes the IKE SA for a spent Child SA with no rekey running
func TestRestoredThenSpentChildSAIsRekeyedThroughTheTunnel(t *testing.T) {
	p := dialRestoredSpent(t)
	old := p.answerer.Child()
	p.tun.spent = func(spi uint32) {
		select {
		case <-p.rekeyStarted:
		case <-time.After(restoredSpentWait):
		}
		p.answerer.ChildSequenceSpent(spi)
	}
	refused := make(chan error, 1)
	go func() { refused <- p.asker.RekeyChild() }()
	select {
	case <-p.answered:
	case <-time.After(restoredSpentWait):
		t.Fatal("the asking end's dataplane was handed no new Child SA")
	}
	met := p.tun.sas.Load()
	if met.replacement == nil {
		t.Fatal("the answering end's tunnel holds no replacement once its answer is in")
	}
	for range 4 {
		_, _ = met.outbound.ReserveSequenceRange(1 << 30)
	}
	close(p.refuse)
	if err := <-refused; !errors.Is(err, errRestoredSpentRefused) {
		t.Fatalf("the asking end's rekey ended with %v, want its dataplane's refusal", err)
	}
	if !untilRestoredSpent(func() bool {
		current := p.tun.sas.Load()
		return p.answerer.Child().LocalSPI == old.LocalSPI && current.replacement == nil
	}) {
		t.Fatalf("the answering end holds %08x after the asking end's Delete, want the replaced SA %08x again", p.answerer.Child().LocalSPI, old.LocalSPI)
	}
	if p.tun.moveOffSpent(met) {
		t.Error("the reservation that met the spent SA before the restore reports another outbound SA")
	}
	var ended error
	replaced := untilRestoredSpent(func() bool {
		select {
		case ended = <-p.ended:
			return true
		default:
		}
		child := p.answerer.Child()
		return child.LocalSPI != old.LocalSPI && child.LocalSPI != 0
	})
	if child := p.answerer.Child(); ended != nil || !replaced || child.LocalSPI == old.LocalSPI {
		t.Errorf("the answering end holds %08x with Run ended by %v, want the restored spent SA %08x replaced and Run going on", child.LocalSPI, ended, old.LocalSPI)
	}
}

// heldReplacementWatch is how long the test of a served session's hold reads what the answering end sends once the asking end's rekey returns, five hellos of the loopback nodes
const heldReplacementWatch = time.Second

// holdRelay carries every datagram between alpha and bravo, alpha sending to it in place of bravo's port
// once armed and once bravo has answered a CREATE_CHILD_SA, it drops what alpha sends on any Child SA but the armed one and every INFORMATIONAL request of alpha's until release, so bravo hears nothing that ends the hold of its new Child SA, and it reports the SPI of each ESP packet bravo sends
type holdRelay struct {
	alphaSide, bravoSide *net.UDPConn
	bravo                *net.UDPAddr
	// sent gets the SPI of each ESP packet bravo sends once it has answered
	sent chan uint32

	mu                 sync.Mutex
	alpha              *net.UDPAddr
	armed              uint32
	answered, released bool
}

// newHoldRelay starts the relay and points alpha at it, so it must run before either node does
func newHoldRelay(t *testing.T, alpha, bravo *loopbackNode) *holdRelay {
	t.Helper()
	loopback := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
	alphaSide, err := net.ListenUDP("udp4", loopback)
	if err != nil {
		t.Fatal(err)
	}
	bravoSide, err := net.ListenUDP("udp4", loopback)
	if err != nil {
		t.Fatal(err)
	}
	r := &holdRelay{alphaSide: alphaSide, bravoSide: bravoSide, bravo: &net.UDPAddr{IP: loopback.IP, Port: int(bravo.port)}, sent: make(chan uint32, 1024)}
	pointAlphaAt(t, alpha, bravo, alphaSide.LocalAddr().(*net.UDPAddr).Port)
	var relaying sync.WaitGroup
	relaying.Go(r.fromAlpha)
	relaying.Go(r.fromBravo)
	t.Cleanup(func() {
		_ = alphaSide.Close()
		_ = bravoSide.Close()
		relaying.Wait()
	})
	return r
}

// arm has the relay drop, once bravo answers a CREATE_CHILD_SA, what alpha sends on any Child SA but the one bravo receives on as spi
func (r *holdRelay) arm(spi uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.armed = spi
}

// release stops the drops, so alpha's resends of what was dropped reach bravo
func (r *holdRelay) release() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.released = true
}

// ikeExchange is whether datagram is an IKE message of exchange, a response or a request as response says
func ikeExchange(datagram []byte, exchange ike.ExchangeType, response bool) bool {
	// the four zero octets of RFC 3948 section 2.2 come before an IKE header
	if len(datagram) < 4+ike.HeaderLen || binary.BigEndian.Uint32(datagram) != 0 {
		return false
	}
	header := datagram[4:]
	return ike.ExchangeType(header[18]) == exchange && (header[19]&ike.FlagResponse != 0) == response
}

// espSPI is the SPI of datagram as an ESP packet, and 0 for an IKE message or a keepalive
func espSPI(datagram []byte) uint32 {
	if len(datagram) < 8 {
		return 0
	}
	return binary.BigEndian.Uint32(datagram)
}

func (r *holdRelay) fromAlpha() {
	buf := make([]byte, 65536)
	for {
		n, from, err := r.alphaSide.ReadFromUDP(buf)
		if err != nil {
			return
		}
		spi := espSPI(buf[:n])
		r.mu.Lock()
		r.alpha = from
		drop := r.answered && !r.released && (spi != 0 && spi != r.armed || ikeExchange(buf[:n], ike.INFORMATIONAL, false))
		r.mu.Unlock()
		if !drop {
			_, _ = r.bravoSide.WriteToUDP(buf[:n], r.bravo)
		}
	}
}

func (r *holdRelay) fromBravo() {
	buf := make([]byte, 65536)
	for {
		n, _, err := r.bravoSide.ReadFromUDP(buf)
		if err != nil {
			return
		}
		r.mu.Lock()
		if r.armed != 0 && ikeExchange(buf[:n], ike.CREATE_CHILD_SA, true) {
			r.answered = true
		}
		answered, alpha := r.answered, r.alpha
		r.mu.Unlock()
		if spi := espSPI(buf[:n]); answered && spi != 0 {
			select {
			case r.sent <- spi:
			default:
			}
		}
		if alpha != nil {
			_, _ = r.alphaSide.WriteToUDP(buf[:n], alpha)
		}
	}
}

// the answering end of a Child SA rekey, in a session serveSession runs, holds the new Child SA and sends on the one it replaces until the asking end is heard on the new one, which fails where serveSession builds a tunnel the session does not hand its new Child SAs to hold
// the relay keeps from bravo what alpha sends on the new Child SA and alpha's INFORMATIONAL requests, the Delete of the replaced Child SA among them
func TestServedSessionHoldsTheChildSAOfAPeersRekey(t *testing.T) {
	alpha, bravo := newLoopbackMesh(t)
	// bravo answers and never dials, so both ends hold the one session alpha dials
	quiet := *bravo.cfg
	quiet.Dial.To = nil
	bravo.client.cfg.Store(&quiet)
	relay := newHoldRelay(t, alpha, bravo)
	run(t, alpha, bravo)
	waitFor(t, convergeBudget, "each node forwarding to the other's prefix", func() bool {
		return reaches(alpha, bravo) && reaches(bravo, alpha)
	})
	held := alpha.client.sessions.snapshot()
	if len(held) != 1 {
		t.Fatalf("alpha holds %d sessions, want the one it dialed", len(held))
	}
	replaced := held[0].session.Child()
	relay.arm(replaced.RemoteSPI)
	// the rekey returns once its Delete of the replaced Child SA is answered, which the relay keeps from bravo until release
	rekeyed := make(chan error, 1)
	go func() { rekeyed <- held[0].session.RekeyChild() }()
	var child ike.ChildSA
	waitFor(t, convergeBudget, "alpha making the new Child SA current", func() bool {
		child = held[0].session.Child()
		return child.LocalSPI != replaced.LocalSPI
	})
	onReplaced := 0
	watch := time.After(heldReplacementWatch)
	for watching := true; watching; {
		select {
		case spi := <-relay.sent:
			if spi == child.LocalSPI {
				t.Fatalf("bravo sent on the new Child SA of SPI %08x before alpha was heard on it", spi)
			}
			if spi == replaced.LocalSPI {
				onReplaced++
			}
		case <-watch:
			watching = false
		}
	}
	if onReplaced == 0 {
		t.Fatalf("bravo sent nothing on the replaced Child SA of SPI %08x in %v", replaced.LocalSPI, heldReplacementWatch)
	}
	relay.release()
	select {
	case err := <-rekeyed:
		if err != nil {
			t.Fatalf("alpha could not rekey its session: %v", err)
		}
	case <-time.After(convergeBudget):
		t.Fatal("alpha's rekey did not end once its Delete of the replaced Child SA could reach bravo")
	}
}
