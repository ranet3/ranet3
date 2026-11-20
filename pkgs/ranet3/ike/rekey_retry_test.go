// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ike

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"ranet3.com/pkgs/ranet3/esp"
	"ranet3.com/pkgs/ranet3/internal/bubble"
)

// the times of the tests of a rekey retried past the responder's retention and of a Delete held back past the next rekey, on a bubble's clock
const (
	// espEvery is how often authenticated ESP passes each way, well inside the liveness interval
	espEvery = defaultDPDInterval / 4
	// repliesHeldPast is how long past retainedContextDeadline the answers to the rekey stay suppressed, past the initiator's first two sends after that deadline and short of its third
	repliesHeldPast = 40 * time.Second
	// settledWithin is how long a test leaves both ends to take what it delivered before it reads them
	settledWithin = time.Second
	// pastRetentionBy is how far past retainedContextDeadline from its retention a request reaches the replaced IKE SA
	pastRetentionBy = time.Second
)

// fragmentOctets is the plaintext each IKE Fragment message of a request in fragments carries, short of a Delete payload of one SPI, so that request goes in two
const fragmentOctets = 8

// espPacket is the inner packet the tests pass under the Child SAs, an IPv4 header between two documentation addresses
var espPacket = []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2}

// busyRetryWindow is how long s resends a request whose peer keeps authenticated traffic flowing, from its first send to deeming the IKE SA failed
func busyRetryWindow(s *Session) time.Duration {
	sends := sendTimes(s.retransmitAfter, maxRetransmitsWhileBusy)
	return sends[len(sends)-1] + retransmitDelay(s.retransmitAfter, maxRetransmits)
}

// espPasses seals espPacket under from's Child SA and opens it under to's, as the dataplane does, and tells to of the authenticated traffic
func espPasses(from, to *Session) error {
	out, err := esp.NewOutbound(from.Child())
	if err != nil {
		return err
	}
	in, err := esp.NewInbound(to.Child())
	if err != nil {
		return err
	}
	sealed, err := out.Seal(espPacket, esp.NextHeaderIPv4)
	if err != nil {
		return err
	}
	plain, _, err := in.Open(sealed)
	if err != nil {
		return err
	}
	if !bytes.Equal(plain, espPacket) {
		return errors.New("the packet opened is not the packet sealed")
	}
	to.NoteTraffic()
	return nil
}

// flowESP passes authenticated ESP each way between a and b every espEvery until the returned function or the test's end stops it
// the function returns the first failure the flow met
func flowESP(t *testing.T, a, b *Session) func() error {
	t.Helper()
	stop, done := make(chan struct{}), make(chan struct{})
	var failure error
	go func() {
		defer close(done)
		for {
			for _, way := range [][2]*Session{{a, b}, {b, a}} {
				if err := espPasses(way[0], way[1]); err != nil && failure == nil {
					failure = fmt.Errorf("ESP at %v: %w", time.Now(), err)
				}
			}
			select {
			case <-stop:
				return
			case <-time.After(espEvery):
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

// holdingRelay is relay with a hold in place of a drop: hold sees each datagram as relay's pass does, one from the initiator that it reports is kept back, and release sends what was kept on to the responder in the order it came and returns how many
// inject sends an IKE message to the responder from the relay's address, which the responder takes for the initiator's
func holdingRelay(t *testing.T, responderPort int, hold func(fromInitiator bool, header *Header) bool) (port int, release func() int, inject func(raw []byte)) {
	t.Helper()
	conn := listenPeer(t)
	responder := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: responderPort}
	var mu sync.Mutex
	var held [][]byte
	done := make(chan struct{})
	t.Cleanup(func() {
		conn.Close()
		<-done
	})
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
			var header *Header
			if n > 4 {
				header, _ = decodeHeader(buf[4:n])
			}
			if hold(fromInitiator, header) && fromInitiator {
				mu.Lock()
				held = append(held, bytes.Clone(buf[:n]))
				mu.Unlock()
				continue
			}
			_, _ = conn.WriteToUDP(buf[:n], to)
		}
	}()
	release = func() int {
		mu.Lock()
		out := held
		held = nil
		mu.Unlock()
		for _, datagram := range out {
			if _, err := conn.WriteToUDP(datagram, responder); err != nil {
				t.Errorf("send a held datagram on: %v", err)
			}
		}
		return len(out)
	}
	inject = func(raw []byte) {
		if _, err := conn.WriteToUDP(withNonESPMarker(raw), responder); err != nil {
			t.Errorf("send a message to the responder: %v", err)
		}
	}
	return conn.LocalAddr().(*net.UDPAddr).Port, release, inject
}

// onOneIKESA fails t unless initiator and responder, the two ends of one session, are current on one IKE SA, each in its own role, and returns it as initiator holds it
func onOneIKESA(t *testing.T, initiator, responder *Session) *ikeContext {
	t.Helper()
	current, peer := initiator.currentContext(), responder.currentContext()
	if current.spiI != peer.spiI || current.spiR != peer.spiR || current.responder == peer.responder ||
		!bytes.Equal(current.skD, peer.skD) || !bytes.Equal(current.skei, peer.skei) || !bytes.Equal(current.sker, peer.sker) {
		t.Fatalf("the initiator is current on the IKE SA %016x/%016x and the responder on %016x/%016x", current.spiI, current.spiR, peer.spiI, peer.spiR)
	}
	return current
}

// carriesBothWays fails t unless initiator and responder still hold the Child SAs children names, which pass ESP each way, and their current IKE SA carries an exchange each way
func carriesBothWays(t *testing.T, initiator, responder *Session, children ChildSA) {
	t.Helper()
	for _, end := range []struct {
		name string
		s    *Session
		peer *Session
		spis [2]uint32
	}{{"initiator", initiator, responder, [2]uint32{children.LocalSPI, children.RemoteSPI}}, {"responder", responder, initiator, [2]uint32{children.RemoteSPI, children.LocalSPI}}} {
		if child := end.s.Child(); child.LocalSPI != end.spis[0] || child.RemoteSPI != end.spis[1] {
			t.Errorf("the %s holds the Child SA %08x/%08x, want the inherited %08x/%08x", end.name, child.LocalSPI, child.RemoteSPI, end.spis[0], end.spis[1])
		}
		if err := espPasses(end.s, end.peer); err != nil {
			t.Errorf("ESP from the %s under the inherited Child SA failed: %v", end.name, err)
		}
		if _, err := end.s.request(INFORMATIONAL, nil); err != nil {
			t.Errorf("an exchange from the %s on the current IKE SA failed: %v", end.name, err)
		}
	}
}

// RFC 7296 section 2.1: "the initiator MUST retransmit a request until it either receives a corresponding response or deems the IKE SA to have failed."
// authenticated ESP flows both ways throughout, so the initiator of the IKE SA rekey resends it for a busy peer's whole budget
// the answers to the rekey are suppressed until repliesHeldPast after retainedContextDeadline, the responder's retention, and then the initiator's next retry and its answer go through
// so both ends end on the replacement the responder made, neither session ends and redials, and the Child SAs both inherited carry ESP each way
func TestRekeyRetriedPastTheResponderRetentionConverges(t *testing.T) {
	bubble.Run(testRekeyRetriedPastTheResponderRetentionConverges)(t)
}

func testRekeyRetriedPastTheResponderRetentionConverges(t *testing.T) {
	events := &recorder{}
	h := newResponderHarness(t, nil, events.record)
	// releaseAt is when the answers to the rekey go through again, in Unix nanoseconds, none held while zero
	var releaseAt atomic.Int64
	var suppressed, passed atomic.Int32
	// answers is every answer to the rekey the responder sent, suppressed or not
	var answersMu sync.Mutex
	var answers [][]byte
	cfg := h.peerConfig()
	cfg.RemotePort = relay(t, h.remotePort, func(fromInitiator bool, header *Header, raw []byte) bool {
		if fromInitiator || header == nil || !header.IsResponse() || header.ExchangeType != CREATE_CHILD_SA {
			return true
		}
		answersMu.Lock()
		answers = append(answers, bytes.Clone(raw))
		answersMu.Unlock()
		if at := releaseAt.Load(); at != 0 && time.Now().UnixNano() < at {
			suppressed.Add(1)
			return false
		}
		passed.Add(1)
		return true
	})
	initiator, responder := dialPaused(t, h, cfg)
	old, children := initiator.currentContext(), initiator.Child()
	initiatorRun, responderRun := runSession(t, initiator), runSession(t, responder)
	stopESP := flowESP(t, initiator, responder)

	began := time.Now()
	releaseAt.Store(began.Add(retainedContextDeadline + repliesHeldPast).UnixNano())
	window := busyRetryWindow(initiator)
	rekeyed := make(chan error, 1)
	go func() { rekeyed <- initiator.RekeyIKE() }()
	// the responder answers the first send at once, and the SA it makes there is the one both ends must end on
	synctest.Wait()
	made := responder.currentContext()
	if made.spiI == old.spiI {
		t.Fatal("the responder made no replacement at its first answer")
	}
	// the rekey follows IKE_AUTH, so its Message ID is not 0, and the record is made where placement runs, before the answer is kept
	responder.stateMu.RLock()
	record := responder.recovery
	var nextPeerMID uint32
	if record.replaced != nil {
		nextPeerMID = record.replaced.nextPeerMID
	}
	responder.stateMu.RUnlock()
	if record.replaced == nil || record.replaced.spiI != old.spiI || record.replacement != made || record.mid == 0 || record.mid+1 != nextPeerMID {
		t.Fatalf("the responder's first answer left a record at Message ID %d, its SA expecting %d next, want one of the replaced SA %016x at the rekey's Message ID, which is not 0", record.mid, nextPeerMID, old.spiI)
	}
	select {
	case err := <-rekeyed:
		if err != nil {
			synctest.Wait()
			ended := "is still running"
			select {
			case runErr := <-initiatorRun:
				ended = fmt.Sprintf("ended with %v", runErr)
			default:
			}
			t.Fatalf("the initiator's IKE SA rekey ended %v after it began with %v, and the initiator's session %s, want it to take the replacement the responder made", time.Since(began), err, ended)
		}
	case <-time.After(window + pastBound):
		t.Fatalf("the initiator's IKE SA rekey still ran %v after it began", time.Since(began))
	}
	if suppressed.Load() == 0 || passed.Load() == 0 {
		t.Fatalf("the path suppressed %d answers to the rekey and let %d through, want both", suppressed.Load(), passed.Load())
	}
	if took := time.Since(began); took < retainedContextDeadline {
		t.Fatalf("the rekey took its answer %v after it began, inside the responder's retention of %v", took, retainedContextDeadline)
	}
	time.Sleep(settledWithin)
	replacement := onOneIKESA(t, initiator, responder)
	if replacement.spiI != made.spiI || replacement.spiR != made.spiR {
		t.Fatalf("both ends are current on %016x/%016x, want the replacement %016x/%016x the responder made at its first answer", replacement.spiI, replacement.spiR, made.spiI, made.spiR)
	}
	answersMu.Lock()
	sent := slices.Clone(answers)
	answersMu.Unlock()
	if len(sent) < 2 {
		t.Fatalf("the responder answered the rekey %d times, want its first answer and at least one repeat", len(sent))
	}
	for i, again := range sent[1:] {
		if !bytes.Equal(again, sent[0]) {
			t.Errorf("answer %d to the rekey differs from the first, where every repeat draws the answer kept", i+2)
		}
	}
	// past the busy peer's whole budget from the rekey's first send, where a session that never took the answer has ended
	time.Sleep(time.Until(began.Add(window + pastBound)))
	stillRunning(t, initiatorRun)
	stillRunning(t, responderRun)
	if again := onOneIKESA(t, initiator, responder); again.spiI != replacement.spiI {
		t.Fatalf("the ends moved from the replacement %016x to %016x", replacement.spiI, again.spiI)
	}
	if err := stopESP(); err != nil {
		t.Errorf("ESP under the inherited Child SAs failed while the rekey was retried: %v", err)
	}
	carriesBothWays(t, initiator, responder, children)
	stillRunning(t, initiatorRun)
	stillRunning(t, responderRun)
	// the repeats past the retention drew the answer the record kept, which the responder tells once
	if got, want := recordedOf(events, "ike.rekey.repeat_answered"), []string{fmt.Sprintf("sa=ike message_id=%d", record.mid)}; !slices.Equal(got, want) {
		t.Errorf("the responder recorded %q, want %q", got, want)
	}
}

// recordedOf is the attributes of each event of kind r recorded, in order, without the identities
func recordedOf(r *recorder, kind string) []string {
	var of []string
	for _, line := range r.recorded() {
		if fields := strings.SplitN(line, " ", 3); len(fields) == 3 && fields[0] == kind {
			of = append(of, fields[2])
		}
	}
	return of
}

// RFC 7296 section 1.4.1: "Deleting an IKE SA implicitly closes any remaining Child SAs negotiated under it."
// and section 2.8: "An IKE SA so created inherits all of the original IKE SA's Child SAs, and the new IKE SA is used for all control messages needed to maintain those Child SAs."
// every send of the initiator's Delete of the IKE SA its rekey replaced is held back on the path, and the initiator rekeys the replacement while the responder still waits for that Delete
// then the held Delete reaches the responder, naming the IKE SA two rekeys old, which neither end holds any more, so it draws nothing
// so both ends end on the newest IKE SA, which carries an exchange each way, neither session ends, and the Child SAs it inherited carry ESP each way
func TestDelayedDeleteOfAnOlderIKESALeavesTheNewestUsable(t *testing.T) {
	bubble.Run(testDelayedDeleteOfAnOlderIKESALeavesTheNewestUsable)(t)
}

func testDelayedDeleteOfAnOlderIKESALeavesTheNewestUsable(t *testing.T) {
	d := newDelayedDelete(t)
	if err := rekeyedWithin(t, d.initiator, "the rekey of the replacement"); err != nil {
		t.Fatalf("the rekey of the replacement, with the Delete of the IKE SA it replaced still owed to the responder, ended with %v", err)
	}
	newest := onOneIKESA(t, d.initiator, d.responder)
	if newest.spiI == d.replaced.spiI || newest.spiI == d.oldest.spiI {
		t.Fatalf("both ends are current on %016x, want the IKE SA the second rekey made", newest.spiI)
	}
	// both ends let the first IKE SA go at the second rekey, so the Delete naming it finds no SA and draws nothing
	d.deliver(t)
	if n := d.answeredOnOldest.Load(); n != 0 {
		t.Errorf("the responder answered the Delete of the first IKE SA %d times once the second rekey had replaced the SA after it", n)
	}
	if again := onOneIKESA(t, d.initiator, d.responder); again.spiI != newest.spiI {
		t.Fatalf("the Delete of the first IKE SA moved both ends from %016x to %016x", newest.spiI, again.spiI)
	}
	d.usable(t)
}

// the held Delete of the first IKE SA reaches the responder before the replacement is rekeyed, before and after a fresh request on the replacement
// the responder still holds the first SA then, so it answers the Delete and ends that SA alone, and the replacement and its rekey go on as if the Delete had come in time
func TestDelayedDeleteOfAHeldIKESAEndsOnlyThatSA(t *testing.T) {
	for _, c := range []struct {
		name    string
		confirm bool
	}{{"before a fresh request on the replacement", false}, {"after a fresh request on the replacement", true}} {
		t.Run(c.name, bubble.Run(func(t *testing.T) {
			d := newDelayedDelete(t)
			if c.confirm {
				if _, err := d.initiator.request(INFORMATIONAL, nil); err != nil {
					t.Fatalf("a request on the replacement failed: %v", err)
				}
			}
			d.deliver(t)
			if d.answeredOnOldest.Load() == 0 {
				t.Fatal("the responder drew no answer to the Delete of the first IKE SA it still held")
			}
			d.responder.stateMu.RLock()
			held := d.responder.old != nil && d.responder.old.spiI == d.oldest.spiI
			d.responder.stateMu.RUnlock()
			if held {
				t.Error("the responder still holds the first IKE SA after the peer's Delete of it")
			}
			if current := onOneIKESA(t, d.initiator, d.responder); current.spiI != d.replaced.spiI {
				t.Fatalf("the Delete of the first IKE SA moved both ends from the replacement %016x to %016x", d.replaced.spiI, current.spiI)
			}
			if err := rekeyedWithin(t, d.initiator, "the rekey of the replacement"); err != nil {
				t.Fatalf("the rekey of the replacement after the Delete of the IKE SA it replaced ended with %v", err)
			}
			d.usable(t)
		}))
	}
}

// delayedDelete is a session whose initiator rekeyed the handshake's IKE SA with every send of its Delete of that SA held back on the path
type delayedDelete struct {
	initiator, responder       *Session
	initiatorRun, responderRun <-chan error
	stopESP                    func() error
	release                    func() int
	inject                     func(raw []byte)
	children                   ChildSA
	// oldest is the handshake's IKE SA and replaced the SA the first rekey made, each as the initiator holds it
	oldest, replaced *ikeContext
	// answeredOnOldest counts the responder's INFORMATIONAL answers on the handshake's IKE SA once the rekey began
	answeredOnOldest atomic.Int32
	// answeredAtWatched counts the responder's answers of any exchange on the handshake's IKE SA at the Message ID watched holds
	watched           atomic.Uint32
	answeredAtWatched atomic.Int32
	// events keeps the responder's events
	events recorder
}

// newDelayedDelete dials, runs both sessions with ESP flowing, and rekeys the handshake's IKE SA from the initiator with its Delete held
func newDelayedDelete(t *testing.T) *delayedDelete {
	t.Helper()
	d := &delayedDelete{}
	h := newResponderHarness(t, nil, d.events.record)
	// first is the initiator's SPI of the handshake's IKE SA, on which the path holds the initiator's requests and counts the responder's answers once holding is set
	var first atomic.Uint64
	var holding atomic.Bool
	cfg := h.peerConfig()
	d.watched.Store(math.MaxUint32)
	cfg.RemotePort, d.release, d.inject = holdingRelay(t, h.remotePort, func(fromInitiator bool, header *Header) bool {
		if !holding.Load() || header == nil || header.SPIInitiator != first.Load() {
			return false
		}
		if !fromInitiator && header.IsResponse() && header.MessageID == d.watched.Load() {
			d.answeredAtWatched.Add(1)
		}
		if header.ExchangeType != INFORMATIONAL {
			return false
		}
		if !fromInitiator && header.IsResponse() {
			d.answeredOnOldest.Add(1)
		}
		return fromInitiator && !header.IsResponse()
	})
	d.initiator, d.responder = dialPaused(t, h, cfg)
	d.oldest, d.children = d.initiator.currentContext(), d.initiator.Child()
	first.Store(d.oldest.spiI)
	d.initiatorRun, d.responderRun = runSession(t, d.initiator), runSession(t, d.responder)
	d.stopESP = flowESP(t, d.initiator, d.responder)
	holding.Store(true)
	if err := rekeyedWithin(t, d.initiator, "the rekey of the first IKE SA"); err != nil {
		t.Fatalf("the rekey of the first IKE SA failed: %v", err)
	}
	d.replaced = onOneIKESA(t, d.initiator, d.responder)
	return d
}

// deliver sends the held Delete on to the responder and leaves both ends settledWithin to take it, with both sessions still running
func (d *delayedDelete) deliver(t *testing.T) {
	t.Helper()
	if n := d.release(); n == 0 {
		t.Fatal("the path held no send of the Delete of the first IKE SA")
	}
	time.Sleep(settledWithin)
	stillRunning(t, d.initiatorRun)
	stillRunning(t, d.responderRun)
}

// usable fails t unless ESP flowed throughout and the current IKE SA and the inherited Child SAs carry an exchange and ESP each way, with both sessions still running
func (d *delayedDelete) usable(t *testing.T) {
	t.Helper()
	if err := d.stopESP(); err != nil {
		t.Errorf("ESP under the inherited Child SAs failed across the rekeys: %v", err)
	}
	carriesBothWays(t, d.initiator, d.responder, d.children)
	stillRunning(t, d.initiatorRun)
	stillRunning(t, d.responderRun)
}

// rekeyedWithin runs one IKE SA rekey of s and returns how it ended, failing t where it runs past answerBudget
func rekeyedWithin(t *testing.T, s *Session, what string) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- s.RekeyIKE() }()
	return answeredWithin(t, done, what)
}

// responderSlots reads the IKE SA the responder holds in its old slot, its record and how long that SA is held
func (d *delayedDelete) responderSlots() (old *ikeContext, record recoveryRecord, oldBy time.Time) {
	d.responder.stateMu.RLock()
	defer d.responder.stateMu.RUnlock()
	return d.responder.old, d.responder.recovery, d.responder.oldBy
}

// replacedAt is when the responder retained the handshake's IKE SA at its answer to the first rekey, failing t where it holds no record of that SA
func (d *delayedDelete) replacedAt(t *testing.T) time.Time {
	t.Helper()
	old, record, _ := d.responderSlots()
	if old == nil || old.spiI != d.oldest.spiI || record.replaced != old {
		t.Fatal("the responder holds no record of the handshake's IKE SA its answer to the first rekey replaced")
	}
	d.responder.stateMu.RLock()
	defer d.responder.stateMu.RUnlock()
	return old.replacedAt
}

// nextOnOldest is the header of a request of exchange on the handshake's IKE SA at the Message ID the responder expects next there, which the fixture then watches for answers
func (d *delayedDelete) nextOnOldest(t *testing.T, exchange ExchangeType) Header {
	t.Helper()
	d.responder.stateMu.RLock()
	old := d.responder.old
	var mid uint32
	if old != nil {
		mid = old.nextPeerMID
	}
	d.responder.stateMu.RUnlock()
	if old == nil || old.spiI != d.oldest.spiI {
		t.Fatal("the responder no longer holds the handshake's IKE SA")
	}
	d.watched.Store(mid)
	return Header{SPIInitiator: d.oldest.spiI, SPIResponder: d.oldest.spiR, ExchangeType: exchange, Flags: FlagInitiator, MessageID: mid}
}

// sealOnOldest is the request of header carrying inner, sealed under the handshake's IKE SA as a holder of the initiator's keys of it seals it
func (d *delayedDelete) sealOnOldest(t *testing.T, header Header, inner []RawPayload) []byte {
	t.Helper()
	raw, err := EncryptMessage(d.oldest.suite, d.oldest.localEncryptionKey(), header, nil, inner)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// espDelete is an INFORMATIONAL's Delete of the Child SA the handshake made, as the initiator names it
func (d *delayedDelete) espDelete() []RawPayload {
	spi := binary.BigEndian.AppendUint32(nil, d.children.LocalSPI)
	return []RawPayload{{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoESP, SPIs: [][]byte{spi}})}}
}

// unconfirmedAt reads whether s holds ctx unconfirmed
func unconfirmedAt(s *Session, ctx *ikeContext) bool {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return ctx.unconfirmed
}

// RFC 7296 section 2.1: "In order to allow saving memory, responders are allowed to forget the response after a timeout of several minutes."
// the record keeps the answer to the rekey for the sends of a busy peer, which run from the first send to deeming the IKE SA failed
func TestBusyRequestBudgetIsTheSendsOfABusyPeer(t *testing.T) {
	var sends time.Duration
	for attempt := 1; attempt <= maxRetransmitsWhileBusy; attempt++ {
		sends += retransmitDelay(requestTimeout, attempt)
	}
	if sends != busyRequestBudget {
		t.Errorf("a busy peer's %d sends and the wait after the last take %v, and busyRequestBudget is %v", maxRetransmitsWhileBusy, sends, busyRequestBudget)
	}
}

// the peer's rekey of the replacement is the first fresh request on it, so the responder confirms the replacement on that request, before it answers the rekey
// the rekey is answered while the Delete of the SA before is still owed, since the responder does not delete that SA itself
func TestRekeyOfTheReplacementConfirmsIt(t *testing.T) {
	bubble.Run(testRekeyOfTheReplacementConfirmsIt)(t)
}

func testRekeyOfTheReplacementConfirmsIt(t *testing.T) {
	d := newDelayedDelete(t)
	replacement := d.responder.currentContext()
	if !unconfirmedAt(d.responder, replacement) {
		t.Fatal("the responder confirmed the replacement before any fresh request on it, with only ESP flowing")
	}
	if err := rekeyedWithin(t, d.initiator, "the rekey of the replacement"); err != nil {
		t.Fatalf("the rekey of the replacement, with the Delete of the IKE SA it replaced still owed, ended with %v", err)
	}
	if unconfirmedAt(d.responder, replacement) {
		t.Error("the peer's rekey of the replacement left the replacement unconfirmed")
	}
	newest := onOneIKESA(t, d.initiator, d.responder)
	if newest.spiI == replacement.spiI {
		t.Fatal("both ends are still current on the replacement after its rekey")
	}
	if !unconfirmedAt(d.responder, d.responder.currentContext()) {
		t.Error("the responder confirmed the SA of the peer's rekey of the replacement before any fresh request on it")
	}
	d.usable(t)
}

// a fresh request on the replacement confirms it and ends the record, which forgets the answer kept for the peer's resends of its rekey
// the replaced SA then waits for the peer's Delete for retainedContextDeadline from the last send of that answer
func TestFreshRequestOnTheReplacementEndsTheRecord(t *testing.T) {
	bubble.Run(testFreshRequestOnTheReplacementEndsTheRecord)(t)
}

func testFreshRequestOnTheReplacementEndsTheRecord(t *testing.T) {
	d := newDelayedDelete(t)
	replacement := d.responder.currentContext()
	_, record, _ := d.responderSlots()
	if record.replaced == nil {
		t.Fatal("the responder keeps no record of the replaced SA")
	}
	if _, err := d.initiator.request(INFORMATIONAL, nil); err != nil {
		t.Fatalf("a request on the replacement failed: %v", err)
	}
	if unconfirmedAt(d.responder, replacement) {
		t.Error("the first fresh request on the replacement left it unconfirmed")
	}
	old, after, oldBy := d.responderSlots()
	if old == nil || old.spiI != d.oldest.spiI {
		t.Fatal("the confirmation let the replaced SA go before the peer's Delete of it")
	}
	if after.replaced != nil {
		t.Error("the record outlived the confirmation of its replacement")
	}
	d.responder.stateMu.RLock()
	kept := old.lastPeer.response != nil
	d.responder.stateMu.RUnlock()
	if kept {
		t.Error("the replaced SA still keeps the answer to the rekey after the confirmation")
	}
	if want := record.lastSent.Add(retainedContextDeadline); !oldBy.Equal(want) {
		t.Errorf("the responder holds the replaced SA to %v after the answer's last send, want %v", oldBy.Sub(record.lastSent), retainedContextDeadline)
	}
	d.usable(t)
}

// the peer's Delete of the replaced SA ends that SA and its record before any fresh request on the replacement, and confirms nothing
// the first fresh request on the replacement then confirms it, with no SA left in the old slot for the confirmation to touch
func TestConfirmationAfterTheDeleteOfTheReplacedSA(t *testing.T) {
	bubble.Run(testConfirmationAfterTheDeleteOfTheReplacedSA)(t)
}

func testConfirmationAfterTheDeleteOfTheReplacedSA(t *testing.T) {
	d := newDelayedDelete(t)
	replacement := d.responder.currentContext()
	d.deliver(t)
	if old, record, _ := d.responderSlots(); old != nil || record.replaced != nil || record.replacement != nil {
		t.Fatalf("after the peer's Delete of the replaced SA the responder holds %v in its old slot and a record %v, want neither", old != nil, record.replaced != nil || record.replacement != nil)
	}
	if !unconfirmedAt(d.responder, replacement) {
		t.Fatal("the peer's Delete of the replaced SA confirmed the replacement")
	}
	if _, err := d.initiator.request(INFORMATIONAL, nil); err != nil {
		t.Fatalf("a request on the replacement failed: %v", err)
	}
	if unconfirmedAt(d.responder, replacement) {
		t.Error("the first fresh request on the replacement left it unconfirmed")
	}
	if old, record, _ := d.responderSlots(); old != nil || record.replaced != nil {
		t.Errorf("the confirmation left the responder holding %v in its old slot and a record %v, want neither", old != nil, record.replaced != nil)
	}
	d.usable(t)
}

// a fresh request on the replaced SA inside retainedContextDeadline from its retention is answered as on master, and its answer takes the place of the one the record kept
// so the record ends, and the responder holds the SA to retainedContextDeadline from its retention, as master holds it
func TestFreshRequestOnTheReplacedSAInsideItsRetentionEndsTheRecord(t *testing.T) {
	bubble.Run(testFreshRequestOnTheReplacedSAInsideItsRetentionEndsTheRecord)(t)
}

func testFreshRequestOnTheReplacedSAInsideItsRetentionEndsTheRecord(t *testing.T) {
	d := newDelayedDelete(t)
	replacedAt := d.replacedAt(t)
	d.inject(d.sealOnOldest(t, d.nextOnOldest(t, INFORMATIONAL), nil))
	time.Sleep(settledWithin)
	if d.answeredAtWatched.Load() == 0 {
		t.Fatal("the responder drew no answer to a fresh request on the replaced SA inside its retention")
	}
	old, record, oldBy := d.responderSlots()
	if old == nil || old.spiI != d.oldest.spiI {
		t.Fatal("the responder let the replaced SA go at a fresh request on it")
	}
	if record.replaced != nil {
		t.Error("the record outlived the answer that took the place of the one it kept")
	}
	if want := replacedAt.Add(retainedContextDeadline); !oldBy.Equal(want) {
		t.Errorf("the responder holds the replaced SA %v past its retention, want %v", oldBy.Sub(replacedAt), retainedContextDeadline)
	}
	stillRunning(t, d.initiatorRun)
	stillRunning(t, d.responderRun)
	d.usable(t)
}

// past retainedContextDeadline from its retention the replaced IKE SA takes the repeat its record serves and its Delete alone
// so a holder of its keys draws no answer there with a fresh request, an ESP Delete, an ESP Delete in fragments whose last comes past that point, or a CREATE_CHILD_SA carrying the IKE SA's Delete
// and the SA, the Message ID it expects, the Child SA and the responder's endpoint stay as they were
func TestRequestsOnTheReplacedSAPastItsRetentionDrawNothing(t *testing.T) {
	for _, c := range []struct {
		name string
		send func(t *testing.T, d *delayedDelete, past time.Time)
	}{
		{"a fresh request and an ESP Delete", func(t *testing.T, d *delayedDelete, past time.Time) {
			time.Sleep(time.Until(past))
			d.inject(d.sealOnOldest(t, d.nextOnOldest(t, INFORMATIONAL), nil))
			time.Sleep(settledWithin)
			d.inject(d.sealOnOldest(t, d.nextOnOldest(t, INFORMATIONAL), d.espDelete()))
		}},
		{"an ESP Delete in fragments whose last comes past that point", func(t *testing.T, d *delayedDelete, past time.Time) {
			if !d.responder.fragments {
				t.Fatal("the two ends negotiated no IKE fragmentation")
			}
			fragments := cutInto(t, d.oldest.suite, d.oldest.localEncryptionKey(), d.nextOnOldest(t, INFORMATIONAL), d.espDelete(), fragmentOctets)
			if len(fragments) < 2 {
				t.Fatalf("the ESP Delete went in %d fragments, want at least two", len(fragments))
			}
			time.Sleep(time.Until(past.Add(-2 * pastRetentionBy)))
			for _, fragment := range fragments[:len(fragments)-1] {
				d.inject(fragment)
			}
			time.Sleep(time.Until(past))
			d.inject(fragments[len(fragments)-1])
		}},
		{"a CREATE_CHILD_SA carrying the IKE SA's Delete", func(t *testing.T, d *delayedDelete, past time.Time) {
			time.Sleep(time.Until(past))
			d.inject(d.sealOnOldest(t, d.nextOnOldest(t, CREATE_CHILD_SA), deleteIKEPayloads()))
		}},
	} {
		t.Run(c.name, bubble.Run(func(t *testing.T) {
			d := newDelayedDelete(t)
			endpoint, child := d.responder.mux.Endpoint().AddrPort(), d.responder.Child()
			c.send(t, d, d.replacedAt(t).Add(retainedContextDeadline+pastRetentionBy))
			time.Sleep(settledWithin)
			stillRunning(t, d.initiatorRun)
			stillRunning(t, d.responderRun)
			if n := d.answeredAtWatched.Load(); n != 0 {
				t.Errorf("the responder answered %d times on the replaced SA past its retention", n)
			}
			mid := d.watched.Load()
			d.responder.stateMu.RLock()
			old := d.responder.old
			held := old != nil && old.spiI == d.oldest.spiI && old.nextPeerMID == mid
			d.responder.stateMu.RUnlock()
			if !held {
				t.Errorf("the responder no longer holds the replaced SA expecting Message ID %d", mid)
			}
			if moved := d.responder.mux.Endpoint().AddrPort(); moved != endpoint {
				t.Errorf("the responder's endpoint moved from %v to %v", endpoint, moved)
			}
			if now := d.responder.Child(); now.LocalSPI != child.LocalSPI || now.RemoteSPI != child.RemoteSPI {
				t.Errorf("the responder's Child SA went from %08x/%08x to %08x/%08x", child.LocalSPI, child.RemoteSPI, now.LocalSPI, now.RemoteSPI)
			}
			if current := d.responder.currentContext(); current.spiI != d.replaced.spiI {
				t.Errorf("the responder moved from the replacement %016x to %016x", d.replaced.spiI, current.spiI)
			}
			d.usable(t)
		}))
	}
}

// RFC 7296 section 3.11: "Deletion of the IKE SA is indicated by a protocol ID of 1 (IKE) but no SPIs."
// a Delete of the replaced SA past retainedContextDeadline from its retention goes through the Delete branch, which refuses a Delete payload that does not decode, and that refusal ends the replaced SA alone
// so the session runs on over the replacement
func TestDeleteWithAPayloadThatDoesNotDecodePastTheRetentionEndsTheReplacedSAAlone(t *testing.T) {
	bubble.Run(testDeleteWithAPayloadThatDoesNotDecodePastTheRetentionEndsTheReplacedSAAlone)(t)
}

func testDeleteWithAPayloadThatDoesNotDecodePastTheRetentionEndsTheReplacedSAAlone(t *testing.T) {
	d := newDelayedDelete(t)
	time.Sleep(time.Until(d.replacedAt(t).Add(retainedContextDeadline + pastRetentionBy)))
	// one octet, short of the four every Delete payload carries
	inner := append([]RawPayload{{Type: PayloadD, Body: []byte{3}}}, deleteIKEPayloads()...)
	d.inject(d.sealOnOldest(t, d.nextOnOldest(t, INFORMATIONAL), inner))
	time.Sleep(settledWithin)
	stillRunning(t, d.initiatorRun)
	stillRunning(t, d.responderRun)
	if old, record, _ := d.responderSlots(); old != nil || record.replaced != nil {
		t.Errorf("the responder still holds the replaced SA %v or its record %v", old != nil, record.replaced != nil)
	}
	if current := d.responder.currentContext(); current.spiI != d.replaced.spiI {
		t.Errorf("the responder moved from the replacement %016x to %016x", d.replaced.spiI, current.spiI)
	}
	d.usable(t)
}

// the responder tells the end of the SA the first rekey replaced once, with the reason it ended for: the peer's Delete, a second rekey that displaced it, the end of its record, or a refused Delete past its retention
// and it tells the confirmation of the replacement once, at the first fresh request on it
func TestRetiredAndConfirmedSAsAreRecorded(t *testing.T) {
	retired := func(d *delayedDelete, reason string) []string {
		return []string{fmt.Sprintf("sa=ike spi=%016x replaced=peer reason=%s", d.oldest.spiI, reason)}
	}
	for _, c := range []struct {
		name string
		// end ends the SA the first rekey replaced, and want gives the responder's ike.sa.retired events then
		end  func(t *testing.T, d *delayedDelete)
		want func(d *delayedDelete) []string
	}{
		{"the peer's Delete", func(t *testing.T, d *delayedDelete) { d.deliver(t) },
			func(d *delayedDelete) []string { return retired(d, "deleted") }},
		{"a second rekey", func(t *testing.T, d *delayedDelete) {
			if err := rekeyedWithin(t, d.initiator, "the rekey of the replacement"); err != nil {
				t.Fatalf("the rekey of the replacement ended with %v", err)
			}
		}, func(d *delayedDelete) []string {
			// the initiator's Delete of the replacement, which its own rekey replaced, then ends the replacement at the responder
			return append(retired(d, "displaced"), fmt.Sprintf("sa=ike spi=%016x replaced=peer reason=deleted", d.replaced.spiI))
		}},
		{"the end of its record", func(t *testing.T, d *delayedDelete) {
			_, record, _ := d.responderSlots()
			time.Sleep(time.Until(record.until.Add(settledWithin)))
		}, func(d *delayedDelete) []string { return retired(d, "bound") }},
		{"a Delete past its retention that does not decode", func(t *testing.T, d *delayedDelete) {
			time.Sleep(time.Until(d.replacedAt(t).Add(retainedContextDeadline + pastRetentionBy)))
			inner := append([]RawPayload{{Type: PayloadD, Body: []byte{3}}}, deleteIKEPayloads()...)
			d.inject(d.sealOnOldest(t, d.nextOnOldest(t, INFORMATIONAL), inner))
			time.Sleep(settledWithin)
		}, func(d *delayedDelete) []string {
			return []string{fmt.Sprintf("sa=ike spi=%016x replaced=peer reason=failed failure=syntax", d.oldest.spiI)}
		}},
	} {
		t.Run(c.name, bubble.Run(func(t *testing.T) {
			d := newDelayedDelete(t)
			c.end(t, d)
			stillRunning(t, d.initiatorRun)
			stillRunning(t, d.responderRun)
			if got, want := recordedOf(&d.events, "ike.sa.retired"), c.want(d); !slices.Equal(got, want) {
				t.Errorf("the responder recorded %q, want %q", got, want)
			}
			replacement := d.responder.currentContext()
			if !unconfirmedAt(d.responder, replacement) {
				return
			}
			if _, err := d.initiator.request(INFORMATIONAL, nil); err != nil {
				t.Fatalf("a request on the current IKE SA failed: %v", err)
			}
			got, want := recordedOf(&d.events, "ike.rekey.confirmed"), fmt.Sprintf("sa=ike spi=%016x", replacement.spiI)
			if n := len(slices.DeleteFunc(slices.Clone(got), func(line string) bool { return line != want })); n != 1 {
				t.Errorf("the responder recorded %q, want %q once", got, want)
			}
		}))
	}
}

// crossed is a session whose rekey of its IKE SA old crosses the peer's chained rekey of old, its CREATE_CHILD_SA at Message ID 0 and its IKE_FOLLOWUP_KE at crossedMID, each answered and kept as dispatch keeps it, the peer's SA held as the collision
// where keep is false, old keeps the answer to the peer's later request at crossedMID+1 in place of that answer
func crossed(t *testing.T, keep bool) (*Session, *ikeContext, *ikeRekey) {
	t.Helper()
	s, _ := initiatingSession(t, chainSuite, chainLists)
	old := s.current
	local := &ikeRekey{old: old}
	s.localRekey = local
	peer, request := newPeerRekey(t, hybridOffer, drawnOctets(t, 32))
	raw, err := s.handleIKERekey(old, 0, request)
	if err != nil {
		t.Fatalf("the peer's rekey ended the IKE SA: %v", err)
	}
	if peer.read(t, sealedAnswer(t, old, raw.whole)); peer.link == nil {
		t.Fatal("the peer's rekey drew no link")
	}
	keepPeerAnswer(t, s, old, 0, CREATE_CHILD_SA, request, raw)
	followup, decapsulate := followupRequest(t, ML_KEM_768, peer.link)
	raw, err = s.handleFollowup(old, crossedMID, followup)
	if raw == nil || err != nil {
		t.Fatalf("the peer's IKE_FOLLOWUP_KE failed: %v", err)
	}
	peer.take(t, sealedAnswer(t, old, raw.whole), ML_KEM_768, decapsulate)
	keepPeerAnswer(t, s, old, crossedMID, IKE_FOLLOWUP_KE, followup, raw)
	if !keep {
		later, err := s.response(old, crossedMID+1, INFORMATIONAL, nil)
		if err != nil {
			t.Fatal(err)
		}
		keepPeerAnswer(t, s, old, crossedMID+1, INFORMATIONAL, nil, later)
	}
	s.stateMu.Lock()
	held := s.collision
	s.stateMu.Unlock()
	if held == nil {
		t.Fatal("the peer's SA is not held as the collision")
	}
	return s, old, local
}

// crossedMID is the Message ID of the IKE_FOLLOWUP_KE that placed crossed's peer SA, the one after its CREATE_CHILD_SA
const crossedMID = 1

// RFC 7296 section 2.1: "In order to allow saving memory, responders are allowed to forget the response after a timeout of several minutes."
// this end answered the peer's crossing rekey as it was placed, and its own rekey decides the crossing long after, lost or won
// the record keeps that answer for busyRequestBudget from its send, and no less than retainedContextDeadline from the decision, capped by the SA's lifetime
// the SA a lost rekey left is held to the record's end, and the SA a won rekey replaced is held for this end's Delete of it to the decision plus retainedContextDeadline at least, as with no record
// dropped at that hold, the SA's line names the bound that applied
func TestRecordOfACrossingRunsFromTheAnswer(t *testing.T) {
	// lifetimeAfter is how long after the decision the SA before reaches its lifetime, where a case sets one
	const lifetimeAfter = time.Minute
	type want struct {
		until, held time.Duration
		at          string
	}
	for _, c := range []struct {
		name     string
		won      bool
		age      time.Duration
		lifetime bool
		want     want
	}{
		{"lost, the answer's budget outlasting the retention", false, 300 * time.Second, false, want{busyRequestBudget - 300*time.Second, busyRequestBudget - 300*time.Second, recordToAnswer}},
		{"lost, the retention outlasting the answer's budget", false, 500 * time.Second, false, want{retainedContextDeadline, retainedContextDeadline, keptToRetention}},
		{"lost, the lifetime first", false, 300 * time.Second, true, want{lifetimeAfter, lifetimeAfter, "its lifetime"}},
		{"won, the answer's budget outlasting the retention", true, 300 * time.Second, false, want{busyRequestBudget - 300*time.Second, busyRequestBudget - 300*time.Second, recordToAnswer}},
		{"won, the retention outlasting the answer's budget", true, 500 * time.Second, false, want{retainedContextDeadline, retainedContextDeadline, keptToRetention}},
		{"won, the lifetime first", true, 300 * time.Second, true, want{lifetimeAfter, retainedContextDeadline, "its lifetime"}},
	} {
		t.Run(c.name, bubble.Run(func(t *testing.T) {
			lines := recordLines(t)
			s, old, local := crossed(t, true)
			time.Sleep(c.age)
			decided := time.Now()
			s.stateMu.Lock()
			if c.lifetime {
				s.timing.IKERekeyInterval = decided.Add(lifetimeAfter).Sub(old.established)
			}
			if c.won {
				s.replaceLocked(old, chainContext(t, chainSuite))
				s.recordCollisionLocked(old, local)
			}
			winner := s.collision
			s.stateMu.Unlock()
			if !c.won {
				if err := s.yieldIKERekey(old, nil, winner, local); err != nil {
					t.Fatalf("this end's rekey gave way with %v", err)
				}
			}
			s.stateMu.RLock()
			held, record, oldBy := s.old, s.recovery, s.oldBy
			s.stateMu.RUnlock()
			if held != old || record.replaced != old || record.mid != crossedMID || !old.replacedAt.Equal(decided) {
				t.Fatalf("the SA before is held %v, recorded %v at Message ID %d, retained at the decision %v, want all of them at Message ID %d",
					held == old, record.replaced == old, record.mid, old.replacedAt.Equal(decided), crossedMID)
			}
			if got := record.until.Sub(decided); got != c.want.until {
				t.Errorf("the record ends %v after the decision, %v after this end's answer, want %v after the decision", got, record.until.Sub(local.peerAnswered), c.want.until)
			}
			if got := oldBy.Sub(decided); got != c.want.held {
				t.Errorf("the SA before is held %v after the decision, want %v", got, c.want.held)
			}
			time.Sleep(time.Until(oldBy))
			s.expireRetainedContexts(time.Now())
			told := lines.said(slog.LevelInfo, "ike dropping a replaced IKE SA kept for the peer's resends of its rekey", "at")
			if len(told) != 1 || told[0].String() != c.want.at {
				t.Errorf("the SA before was dropped at %v, want once at %q", told, c.want.at)
			}
		}))
	}
}

// chainCrossedByAChain is a session of chainSuite whose own chained rekey sent its CREATE_CHILD_SA, and a peer's chained rekey of the same SA then ran to its IKE_FOLLOWUP_KE, its Ni of zeros the lowest nonce
// a peer whose chain lost runs no IKE_FOLLOWUP_KE, so this is a peer that runs it anyway, the only order in which the session holds the peer's candidate of a chain while its own rekey goes on to win
// it returns the session, the SA both rekeyed, the rekey's end, its CREATE_CHILD_SA and the peer's candidate, with the session's answer to the peer's rekey kept on the SA as the send that the test stands in for keeps it
func chainCrossedByAChain(t *testing.T) (*Session, *ikeContext, <-chan error, *localRequest, *ikeContext) {
	t.Helper()
	s, _ := initiatingSession(t, chainSuite, chainLists)
	old := s.current
	done := rekeying(s)
	create := requested(t, s, done, CREATE_CHILD_SA)
	peer, request := newPeerRekey(t, hybridOffer, make([]byte, 32))
	raw, err := s.handleIKERekey(old, 0, request)
	if err != nil {
		t.Fatalf("the peer's rekey ended the IKE SA: %v", err)
	}
	if peer.read(t, sealedAnswer(t, old, raw.whole)); peer.link == nil {
		t.Fatal("the peer's rekey drew no link")
	}
	if _, err := peer.followup(t, s, old, ML_KEM_768, peer.link); err != nil {
		t.Fatalf("the peer's IKE_FOLLOWUP_KE failed: %v", err)
	}
	s.stateMu.Lock()
	old.lastPeer.response, old.lastPeerResponseID = &transmission{}, s.localRekey.peerMID
	candidate := s.collision
	s.stateMu.Unlock()
	if candidate == nil {
		t.Fatal("the peer's SA is not held as the collision")
	}
	return s, old, done, create, candidate
}

// this end's chained rekey has sent its CREATE_CHILD_SA when a peer's chain of the same SA crosses it, and this end wins
// once its IKE_FOLLOWUP_KE makes its SA, the SA before is held by a record of this end's answer to the peer's rekey, before this end's Delete of it goes out
func TestChainedRekeyWonOverACrossingKeepsTheAnswer(t *testing.T) {
	bubble.Run(testChainedRekeyWonOverACrossingKeepsTheAnswer)(t)
}

func testChainedRekeyWonOverACrossingKeepsTheAnswer(t *testing.T) {
	s, old, done, create, _ := chainCrossedByAChain(t)
	answer, peer := answerRekey(t, create.inner, 0, []byte("link"), nil)
	create.result <- requestResult{inner: answer}
	followup := requested(t, s, done, IKE_FOLLOWUP_KE)
	followup.result <- requestResult{inner: peer.answerFollowup(t, followup.inner, ML_KEM_768, nil)}
	deletion := requested(t, s, done, INFORMATIONAL)
	s.stateMu.RLock()
	record, live, held := s.recovery, s.liveRecordLocked() != nil, s.old
	s.stateMu.RUnlock()
	if !live || record.replaced != old || held != old {
		t.Errorf("the SA before is held %v and recorded %v, the record live %v, want all three", held == old, record.replaced == old, live)
	}
	deletion.result <- requestResult{}
	if err := ended(t, s, done); err != nil {
		t.Fatal(err)
	}
}

// this end's chained rekey has sent its CREATE_CHILD_SA when a peer's chain of the same SA crosses it, and this end wins
// the peer's Delete of the old SA comes while this end's IKE_FOLLOWUP_KE runs, so this end takes the peer's SA there, and its rekey returns nil as the IKE_FOLLOWUP_KE on the deleted SA fails
func TestChainedRekeyAdoptedDuringItsFollowupReturnsNil(t *testing.T) {
	bubble.Run(testChainedRekeyAdoptedDuringItsFollowupReturnsNil)(t)
}

func testChainedRekeyAdoptedDuringItsFollowupReturnsNil(t *testing.T) {
	s, old, done, create, candidate := chainCrossedByAChain(t)
	answer, _ := answerRekey(t, create.inner, 0, []byte("link"), nil)
	create.result <- requestResult{inner: answer}
	followup := requested(t, s, done, IKE_FOLLOWUP_KE)
	if !s.peerDeletedIKE(old) {
		t.Fatal("the peer's Delete of the old SA did not make its SA current")
	}
	followup.result <- requestResult{err: errors.New("ike: the IKE SA carrying this exchange was replaced")}
	if err := ended(t, s, done); err != nil {
		t.Errorf("the rekey returned %v, want nil", err)
	}
	if current, _ := s.contexts(); current != candidate {
		t.Error("the session is not current on the peer's SA")
	}
}

// RFC 7296 section 2.8.2: "The new IKE SA containing the lowest nonce SHOULD be deleted by the node that created it, and the other surviving new IKE SA MUST inherit all the Child SAs."
// the peer's SA held as the collision becomes current where this end's rekey lost and where the peer refused it, and the SA before is then replaced through this end's answer to the peer's rekey
// so it is recorded there as at a peer's rekey with no collision, provided the SA before still keeps that answer
func TestRecordAtTheLostCollisionAndTheSwap(t *testing.T) {
	refused := refusal("IKE SA rekey", notifyAnswer(N_TEMPORARY_FAILURE))
	swap := func(t *testing.T, s *Session, old *ikeContext, local *ikeRekey) {
		if err := s.refusedIKERekey(local, refused); err != nil {
			t.Fatalf("this end's rekey ended with %v, want the peer's SA adopted", err)
		}
	}
	lose := func(t *testing.T, s *Session, old *ikeContext, local *ikeRekey) {
		s.stateMu.RLock()
		winner := s.collision
		s.stateMu.RUnlock()
		if err := s.yieldIKERekey(old, nil, winner, local); err != nil {
			t.Fatalf("this end's rekey gave way with %v", err)
		}
	}
	for _, c := range []struct {
		name   string
		keep   bool
		decide func(t *testing.T, s *Session, old *ikeContext, local *ikeRekey)
	}{
		{"the swap", true, swap},
		{"the lost collision", true, lose},
		{"the swap with the answer no longer kept", false, swap},
		{"the lost collision with the answer no longer kept", false, lose},
	} {
		t.Run(c.name, bubble.Run(func(t *testing.T) {
			s, old, local := crossed(t, c.keep)
			c.decide(t, s, old, local)
			s.stateMu.RLock()
			current, held, oldBy, record, replacedAt, unconfirmed := s.current, s.old, s.oldBy, s.recovery, old.replacedAt, s.current.unconfirmed
			s.stateMu.RUnlock()
			if held != old || current == old {
				t.Fatal("the decision did not replace the SA before with the peer's")
			}
			if !unconfirmed {
				t.Error("the peer's SA is confirmed with no fresh request on it")
			}
			if !c.keep {
				if record.replaced != nil || !replacedAt.IsZero() {
					t.Error("the SA before is recorded though it no longer keeps the answer to the peer's rekey")
				}
				return
			}
			if record.replaced != old || record.replacement != current || record.mid != crossedMID || replacedAt.IsZero() || !oldBy.Equal(record.until) {
				t.Errorf("the record is of the SA before %v, of the peer's SA %v, at Message ID %d, retained %v, held to its end %v, want all of them at Message ID %d",
					record.replaced == old, record.replacement == current, record.mid, !replacedAt.IsZero(), oldBy.Equal(record.until), crossedMID)
			}
			if want := replacedAt.Add(busyRequestBudget); !record.until.Equal(want) {
				t.Errorf("the record ends %v after the retention, want %v", record.until.Sub(replacedAt), busyRequestBudget)
			}
		}))
	}
}

// keepPeerAnswer keeps response on ctx as the answer to the peer's request of exchange at mid carrying inner, as dispatch keeps it once the request is handled
func keepPeerAnswer(t *testing.T, s *Session, ctx *ikeContext, mid uint32, exchange ExchangeType, inner []RawPayload, response *outbound) {
	t.Helper()
	raw, err := EncryptMessage(ctx.suite, ctx.peerEncryptionKey(), Header{SPIInitiator: ctx.spiI, SPIResponder: ctx.spiR, ExchangeType: exchange, MessageID: mid}, nil, inner)
	if err != nil {
		t.Fatal(err)
	}
	message, err := DecodeMessage(raw)
	if err != nil {
		t.Fatal(err)
	}
	var q reassembly
	request, err := s.open(ctx, &q, raw, message)
	if err != nil || request == nil {
		t.Fatalf("the peer's request at Message ID %d did not open: %v", mid, err)
	}
	if _, err := s.keepAnswer(ctx, mid, response, request); err != nil {
		t.Fatalf("the answer at Message ID %d was not kept: %v", mid, err)
	}
}

// RFC 7296 section 2.1: "In order to allow saving memory, responders are allowed to forget the response after a timeout of several minutes."
// Run places the peer's crossing SA as it answers the peer's rekey and keeps that answer after, while this end's rekey settles the crossing on its own goroutine
// a crossing settled between the two, lost or won, records the answer once it is kept, as one settled after it, and holds the SA before to the record's end
func TestCrossingSettledBeforeItsAnswerIsKeptIsRecordedOnceKept(t *testing.T) {
	for _, won := range []bool{false, true} {
		name := "lost"
		if won {
			name = "won"
		}
		t.Run(name, bubble.Run(func(t *testing.T) {
			s, _ := initiatingSession(t, classicalSuite, Suites{ikeCipher: []Transform{encrAES128}, kex: []kexEntry{entryX25519}})
			old := s.current
			local := &ikeRekey{old: old}
			s.localRekey = local
			_, request := newPeerRekey(t, classicalOffer, drawnOctets(t, 32))
			response, err := s.handleIKERekey(old, 0, request)
			if err != nil {
				t.Fatalf("the peer's rekey ended the IKE SA: %v", err)
			}
			s.stateMu.RLock()
			candidate := s.collision
			s.stateMu.RUnlock()
			if candidate == nil {
				t.Fatal("the peer's SA is not held as the collision")
			}
			decided := time.Now()
			if won {
				s.stateMu.Lock()
				s.replaceLocked(old, chainContext(t, classicalSuite))
				s.recordCollisionLocked(old, local)
				s.stateMu.Unlock()
			} else if err := s.yieldIKERekey(old, nil, candidate, local); err != nil {
				t.Fatalf("this end's rekey gave way with %v", err)
			}
			// Run keeps the answer a moment after the decision, and the record still dates the SA's retention from the decision
			time.Sleep(crossingStep)
			keepPeerAnswer(t, s, old, 0, CREATE_CHILD_SA, request, response)
			s.stateMu.RLock()
			held, record, oldBy := s.old, s.recovery, s.oldBy
			s.stateMu.RUnlock()
			if held != old || record.replaced != old || record.replacement != s.currentContext() || record.mid != 0 {
				t.Fatalf("the SA before is held %v, recorded %v, for the current SA %v, at Message ID %d, want all of them at Message ID 0", held == old, record.replaced == old, record.replacement == s.currentContext(), record.mid)
			}
			if want := local.peerAnswered.Add(busyRequestBudget); !record.until.Equal(want) || !oldBy.Equal(want) {
				t.Errorf("the record ends %v and holds the SA before %v after the answer, want both %v", record.until.Sub(local.peerAnswered), oldBy.Sub(local.peerAnswered), busyRequestBudget)
			}
			s.stateMu.RLock()
			replacedAt := old.replacedAt
			s.stateMu.RUnlock()
			if !replacedAt.Equal(decided) {
				t.Errorf("the SA before is retained from %v after the decision, want from the decision", replacedAt.Sub(decided))
			}
		}))
	}
}
