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
	// insideRetentionBy is how long before a replaced SA's retention ends a request comes that falls inside it
	insideRetentionBy = 10 * time.Second
	// refusedAfterTheRekey is how long after this end's rekey the peer's rekey of the SA it replaced is refused, inside retainedContextDeadline
	refusedAfterTheRekey = retainedContextDeadline / 2
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

// a won crossing's record names this end's SA as the replacement, on which a ranet3 peer sends a fresh request only once its own crossing rekey ended, since it runs one request at a time
// so the peer's first fresh request there ends the record, and the SA before is held for this end's Delete no longer than retainedContextDeadline after the decision
func TestFreshRequestOnThisEndsSAEndsAWonCrossingsRecord(t *testing.T) {
	bubble.Run(testFreshRequestOnThisEndsSAEndsAWonCrossingsRecord)(t)
}

func testFreshRequestOnThisEndsSAEndsAWonCrossingsRecord(t *testing.T) {
	s, old, local := crossed(t, true)
	// the answer's budget then outlasts the retention from the decision
	const age = 300 * time.Second
	time.Sleep(age)
	decided := time.Now()
	s.stateMu.Lock()
	s.replaceLocked(old, chainContext(t, chainSuite))
	s.recordCollisionLocked(old, local)
	own := s.current
	s.stateMu.Unlock()
	slots := func() (recoveryRecord, time.Time) {
		s.stateMu.RLock()
		defer s.stateMu.RUnlock()
		return s.recovery, s.oldBy
	}
	if record, oldBy := slots(); record.replaced != old || record.replacement != own || !oldBy.Equal(decided.Add(busyRequestBudget-age)) {
		t.Fatalf("the won crossing is recorded of the SA before %v, of this end's SA %v, holding the SA before %v after the decision, want both and %v", record.replaced == old, record.replacement == own, oldBy.Sub(decided), busyRequestBudget-age)
	}
	time.Sleep(crossingStep)
	s.confirm(own)
	record, oldBy := slots()
	if record.replaced != nil {
		t.Error("the won crossing's record outlived the peer's first fresh request on this end's SA")
	}
	if want := decided.Add(retainedContextDeadline); !oldBy.Equal(want) {
		t.Errorf("the SA before is held %v after the decision, want %v", oldBy.Sub(decided), retainedContextDeadline)
	}
}

// chainCrossedByAChain is a session of chainSuite whose own chained rekey sent its CREATE_CHILD_SA, and a peer's chained rekey of the same SA then ran to its IKE_FOLLOWUP_KE, its Ni of zeros the lowest nonce
// a peer whose chain lost runs no IKE_FOLLOWUP_KE, so this is a peer that runs it anyway, the only order in which the session holds the peer's candidate of a chain while its own rekey goes on to win
// it returns the session, the SA both rekeyed, the rekey's end, its CREATE_CHILD_SA and the peer's candidate, with the session's answer to the peer's IKE_FOLLOWUP_KE kept on the SA and the window past it, as the sends that the test stands in for keep them
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
	s.stateMu.Lock()
	old.nextPeerMID = 1
	s.stateMu.Unlock()
	if _, err := peer.followup(t, s, old, ML_KEM_768, peer.link); err != nil {
		t.Fatalf("the peer's IKE_FOLLOWUP_KE failed: %v", err)
	}
	s.stateMu.Lock()
	old.lastPeer.response, old.lastPeerResponseID = &transmission{}, s.localRekey.peerMID
	old.nextPeerMID = s.localRekey.peerMID + 1
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

// this end's rekey draws a refusal after the peer's Delete of the SA it rekeys made the peer's candidate current, as where Run hands the refusal to the rekey and then takes the Delete before the rekey reads the refusal
// the crossing settled by that Delete, so the rekey ends as a lost crossing ends, with nil and ike.rekey.completed
func TestRefusalReadAfterAnAdoptionSettlesTheRekey(t *testing.T) {
	bubble.Run(testRefusalReadAfterAnAdoptionSettlesTheRekey)(t)
}

func testRefusalReadAfterAnAdoptionSettlesTheRekey(t *testing.T) {
	mux, _ := lifecycleMuxes(t)
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	old := &ikeContext{suite: suite, spiI: 11, spiR: 12, skD: make([]byte, 32), skei: make([]byte, 20), sker: make([]byte, 20)}
	events := &recorder{}
	s := seamed(&Session{mux: mux, current: old, suites: func() Suites { return classicalLists }, requests: make(chan *localRequest, 1), events: events.record})
	done := rekeying(s)
	request := requested(t, s, done, CREATE_CHILD_SA)
	candidate := &ikeContext{suite: suite, spiI: 31, spiR: 32, responder: true, unconfirmed: true}
	s.stateMu.Lock()
	s.collision = candidate
	s.localRekey.peerNonce, s.localRekey.peerResponseNonce = bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{2}, 32)
	s.stateMu.Unlock()
	if !s.peerDeletedIKE(old) {
		t.Fatal("the peer's Delete of the SA this end rekeys ended the session")
	}
	request.result <- requestResult{inner: notifyAnswer(N_TEMPORARY_FAILURE)}
	if err := ended(t, s, done); err != nil {
		t.Errorf("the rekey ended with %v, want nil once the peer's Delete settled the crossing", err)
	}
	if current, _ := s.contexts(); current != candidate {
		t.Errorf("the session is current on %016x, want the peer's candidate %016x", current.spiI, candidate.spiI)
	}
	completed, failed := 0, 0
	for _, line := range events.recorded() {
		switch {
		case strings.HasPrefix(line, "ike.rekey.completed "):
			completed++
		case strings.HasPrefix(line, "ike.rekey.failed "):
			failed++
		}
	}
	if completed != 1 || failed != 0 {
		t.Errorf("the rekey recorded ike.rekey.completed %d times and ike.rekey.failed %d times, want once and never: %q", completed, failed, events.recorded())
	}
}

// RFC 7296 section 2.8.2: "when the peer that did not notice the simultaneous rekey gets the request to rekey the IKE SA that it has already successfully rekeyed, it SHOULD return TEMPORARY_FAILURE"
// this end's rekey replaced old, and the peer's rekey of old comes inside retainedContextDeadline of that rekey and is refused
// the refusal is recorded for the peer's resends for busyRequestBudget from its send and old held to that end, old retained from this end's rekey, and past that rekey plus retainedContextDeadline old takes the repeat of the refused rekey and its Delete alone
func TestRefusalOfARekeyOnTheSAThisEndReplacedIsRecorded(t *testing.T) {
	bubble.Run(testRefusalOfARekeyOnTheSAThisEndReplacedIsRecorded)(t)
}

func testRefusalOfARekeyOnTheSAThisEndReplacedIsRecorded(t *testing.T) {
	s, _ := initiatingSession(t, chainSuite, chainLists)
	old := s.current
	s.stateMu.Lock()
	s.replaceLocked(old, chainContext(t, chainSuite))
	replacement := s.current
	s.stateMu.Unlock()
	replaced := time.Now()
	time.Sleep(refusedAfterTheRekey)
	_, request := newPeerRekey(t, classicalOffer, drawnOctets(t, nonceLen))
	raw, err := s.handleIKERekey(old, 0, request)
	if err != nil {
		t.Fatalf("the peer's rekey of the replaced SA ended the IKE SA: %v", err)
	}
	if err := refusal("IKE SA rekey", sealedAnswer(t, old, raw.whole)); !rejectedWith(err, N_TEMPORARY_FAILURE) {
		t.Fatalf("the peer's rekey of the replaced SA drew %v, want TEMPORARY_FAILURE", err)
	}
	refused := time.Now()
	s.stateMu.RLock()
	record, oldBy, retainedAt := s.recovery, s.oldBy, old.replacedAt
	s.stateMu.RUnlock()
	if record.replaced != old || record.replacement != replacement || record.mid != 0 || !retainedAt.Equal(replaced) {
		t.Fatalf("the refusal is recorded of the replaced SA %v, of this end's SA %v, at Message ID %d, the replaced SA retained at this end's rekey %v, want all of them at Message ID 0",
			record.replaced == old, record.replacement == replacement, record.mid, retainedAt.Equal(replaced))
	}
	if want := refused.Add(busyRequestBudget); !record.until.Equal(want) || !oldBy.Equal(want) {
		t.Errorf("the record ends %v and holds the replaced SA %v after the refusal, want both %v", record.until.Sub(refused), oldBy.Sub(refused), busyRequestBudget)
	}
	time.Sleep(time.Until(replaced.Add(retainedContextDeadline - pastRetentionBy)))
	if s.pastRetention(old) {
		t.Error("the replaced SA is past its retention before retainedContextDeadline from this end's rekey")
	}
	time.Sleep(2 * pastRetentionBy)
	if !s.pastRetention(old) {
		t.Errorf("the replaced SA takes every fresh request %v after this end's rekey", time.Since(replaced))
	}
}

// a peer that sends a later request on the SA after this end refused its rekey there took that refusal, so this end's rekey that then replaces the SA records nothing of it and holds the SA for its Delete to the retention alone
func TestRefusalFollowedByAPeerRequestIsNotRecordedAtTheReplacement(t *testing.T) {
	bubble.Run(testRefusalFollowedByAPeerRequestIsNotRecordedAtTheReplacement)(t)
}

func testRefusalFollowedByAPeerRequestIsNotRecordedAtTheReplacement(t *testing.T) {
	for _, later := range []bool{false, true} {
		s, _ := initiatingSession(t, chainSuite, chainLists)
		old := s.current
		// send seals inner as a request of exchange on old at the Message ID old expects next, hands it to dispatch as the path would, and returns the answer this end sent, nil where it sent none
		send := func(exchange ExchangeType, inner []RawPayload) []RawPayload {
			t.Helper()
			s.stateMu.RLock()
			header := Header{SPIInitiator: old.spiI, SPIResponder: old.spiR, ExchangeType: exchange, MessageID: old.nextPeerMID}
			before := old.lastPeer.response
			s.stateMu.RUnlock()
			if old.responder {
				header.Flags = FlagInitiator
			}
			raw, err := EncryptMessage(old.suite, old.peerEncryptionKey(), header, nil, inner)
			if err != nil {
				t.Fatal(err)
			}
			var pending *pendingRequest
			s.dispatch(raw, s.mux.Endpoint(), &pending)
			s.stateMu.RLock()
			sent := old.lastPeer.response
			s.stateMu.RUnlock()
			if sent == before {
				return nil
			}
			return sealedAnswer(t, old, sent.message.whole)
		}
		// the peer's last rekey came now, inside minPeerIKERekeyInterval of this one
		s.lastPeerIKERekey.Store(int64(time.Since(s.started)) + 1)
		_, request := newPeerRekey(t, hybridOffer, drawnOctets(t, nonceLen))
		if refused := send(CREATE_CHILD_SA, request); !notified(refused, N_TEMPORARY_FAILURE, nil) {
			t.Fatalf("the peer's rekey of the current SA drew notify %d, want TEMPORARY_FAILURE", notifyIn(t, refused))
		}
		if later && send(INFORMATIONAL, nil) == nil {
			t.Fatal("the peer's INFORMATIONAL after the refusal drew no answer")
		}
		time.Sleep(crossingStep)
		s.stateMu.Lock()
		s.replaceLocked(old, chainContext(t, chainSuite))
		record, oldBy := s.recovery, s.oldBy
		s.stateMu.Unlock()
		replaced := time.Now()
		if recorded := record.replaced == old; recorded == later {
			t.Errorf("with a later request of the peer's %v, this end's rekey recorded the refusal before it %v", later, recorded)
		}
		if want := replaced.Add(retainedContextDeadline); later && !oldBy.Equal(want) {
			t.Errorf("with a later request of the peer's, the replaced SA is held %v after the rekey, want %v", oldBy.Sub(replaced), retainedContextDeadline)
		}
	}
}

// a peer's rekey of the SA held as the crossing's candidate is refused, that SA not current yet, and the peer resends it on that SA until the refusal reaches it
// the candidate becomes current where the peer refuses this end's rekey, and where this end's next rekey replaces it the refusal is kept as the record of it, as one sent on the current SA is, to busyRequestBudget after it
func TestRefusalOnTheHeldCandidateIsRecordedOnceThisEndReplacesIt(t *testing.T) {
	bubble.Run(testRefusalOnTheHeldCandidateIsRecordedOnceThisEndReplacesIt)(t)
}

func testRefusalOnTheHeldCandidateIsRecordedOnceThisEndReplacesIt(t *testing.T) {
	s, _ := initiatingSession(t, chainSuite, chainLists)
	old := s.current
	// the peer's rekey of old made candidate, which this end answered while its own rekey of old runs
	candidate := chainContext(t, chainSuite)
	candidate.responder, candidate.unconfirmed = true, true
	if err := s.mux.RegisterIKE(candidate.spiI); err != nil {
		t.Fatal(err)
	}
	local := &ikeRekey{old: old, peerNonce: drawnOctets(t, nonceLen), peerResponseNonce: drawnOctets(t, nonceLen)}
	s.stateMu.Lock()
	s.localRekey = local
	s.retainCollisionLocked(candidate)
	mid := candidate.nextPeerMID
	header := Header{SPIInitiator: candidate.spiI, SPIResponder: candidate.spiR, ExchangeType: CREATE_CHILD_SA, MessageID: mid, Flags: FlagInitiator}
	s.stateMu.Unlock()
	_, request := newPeerRekey(t, hybridOffer, drawnOctets(t, nonceLen))
	raw, err := EncryptMessage(candidate.suite, candidate.peerEncryptionKey(), header, nil, request)
	if err != nil {
		t.Fatal(err)
	}
	var pending *pendingRequest
	s.dispatch(raw, s.mux.Endpoint(), &pending)
	s.stateMu.RLock()
	sent := candidate.lastPeer.response
	s.stateMu.RUnlock()
	if sent == nil || !notified(sealedAnswer(t, candidate, sent.message.whole), N_TEMPORARY_FAILURE, nil) {
		t.Fatal("the peer's rekey of the held candidate drew no TEMPORARY_FAILURE")
	}
	refusedAt := time.Now()
	if err := s.refusedIKERekey(local, refusal("IKE SA rekey", notifyAnswer(N_TEMPORARY_FAILURE))); err != nil || s.currentContext() != candidate {
		t.Fatalf("this end's refused rekey ended with %v and left the candidate current %v", err, s.currentContext() == candidate)
	}
	time.Sleep(crossingStep)
	s.stateMu.Lock()
	s.replaceLocked(candidate, chainContext(t, chainSuite))
	record, oldBy := s.recovery, s.oldBy
	s.stateMu.Unlock()
	if record.replaced != candidate || record.mid != mid {
		t.Fatalf("once this end's rekey replaced the candidate, the refusal of the peer's rekey of it is recorded %v at Message ID %d, want at %d", record.replaced == candidate, record.mid, mid)
	}
	if want := refusedAt.Add(busyRequestBudget); !record.until.Equal(want) || !oldBy.Equal(want) {
		t.Errorf("the record ends %v and holds the candidate %v after the refusal, want both %v", record.until.Sub(refusedAt), oldBy.Sub(refusedAt), busyRequestBudget)
	}
}

// the answer that opened the peer's chain is kept as the record of the SA this end's rekey replaced, and a peer that takes it past that SA's retention sends its IKE_FOLLOWUP_KE next
// RFC 9370 section 2.2.4: "If the responder receives an IKE_FOLLOWUP_KE message for which it does not have a key exchange state, it MUST send back a new error type notification called "STATE_NOT_FOUND"."
// that request draws STATE_NOT_FOUND, after which the record serves no repeat of the rekey and holds its SA to the record's end, and a further one there draws nothing, as every other fresh request past the retention
func TestFollowupOfTheKeptChainAnswerPastTheRetentionDrawsStateNotFound(t *testing.T) {
	bubble.Run(testFollowupOfTheKeptChainAnswerPastTheRetentionDrawsStateNotFound)(t)
}

func testFollowupOfTheKeptChainAnswerPastTheRetentionDrawsStateNotFound(t *testing.T) {
	s, _ := initiatingSession(t, chainSuite, chainLists)
	old := s.current
	// send seals inner as a request of exchange on old at the Message ID old expects next, hands it to dispatch as the path would, and returns the answer this end sent, nil where it sent none
	send := func(exchange ExchangeType, inner []RawPayload) []RawPayload {
		t.Helper()
		s.stateMu.RLock()
		header := Header{SPIInitiator: old.spiI, SPIResponder: old.spiR, ExchangeType: exchange, MessageID: old.nextPeerMID}
		before := old.lastPeer.response
		s.stateMu.RUnlock()
		if old.responder {
			header.Flags = FlagInitiator
		}
		raw, err := EncryptMessage(old.suite, old.peerEncryptionKey(), header, nil, inner)
		if err != nil {
			t.Fatal(err)
		}
		var pending *pendingRequest
		s.dispatch(raw, s.mux.Endpoint(), &pending)
		s.stateMu.RLock()
		sent := old.lastPeer.response
		s.stateMu.RUnlock()
		if sent == before {
			return nil
		}
		return sealedAnswer(t, old, sent.message.whole)
	}
	_, request := newPeerRekey(t, hybridOffer, drawnOctets(t, nonceLen))
	opened := send(CREATE_CHILD_SA, request)
	link, err := linkOf(opened)
	if err != nil || link == nil {
		t.Fatalf("the peer's chained rekey drew %v, want its chain opened", payloadTypes(opened))
	}
	s.stateMu.Lock()
	s.replaceLocked(old, chainContext(t, chainSuite))
	record := s.recovery
	s.stateMu.Unlock()
	if record.replaced != old || record.mid != 0 {
		t.Fatalf("the answer that opened the chain is recorded %v at Message ID %d, want at 0", record.replaced == old, record.mid)
	}
	time.Sleep(retainedContextDeadline + pastRetentionBy)
	followup, _ := followupRequest(t, ML_KEM_768, link)
	if answer := send(IKE_FOLLOWUP_KE, followup); answer == nil || !notified(answer, N_STATE_NOT_FOUND, nil) {
		t.Fatalf("the peer's IKE_FOLLOWUP_KE after the kept answer, past the retention, drew %v, want STATE_NOT_FOUND", payloadTypes(answer))
	}
	s.stateMu.RLock()
	live := s.liveRecordLocked()
	s.stateMu.RUnlock()
	if live != nil {
		t.Error("the record still serves after the peer's IKE_FOLLOWUP_KE was answered")
	}
	s.expireRetainedContexts(time.Now())
	if _, held := s.contexts(); held != old {
		t.Errorf("the replaced SA went %v before the record's end once the peer's IKE_FOLLOWUP_KE was answered", time.Until(record.until))
	}
	if answer := send(IKE_FOLLOWUP_KE, followup); answer != nil {
		t.Errorf("a further IKE_FOLLOWUP_KE on the replaced SA past its retention drew %v", payloadTypes(answer))
	}
}

// a holder of the keys of the SA this end's rekey replaced draws a refusal of its rekey there no later than retainedContextDeadline after that rekey, and the record of that refusal holds the SA busyRequestBudget after it
// past retainedContextDeadline that SA takes no fresh request but its Delete, so a fresh rekey and a fresh INFORMATIONAL there draw no answer and leave the record's end where it was, and the SA goes at that end
// so the record holds the SA no later than the rekey plus retainedContextDeadline and busyRequestBudget, whoever holds its keys
func TestRefusalOnTheSAThisEndReplacedHoldsItNoLongerThanItsRetentionAllows(t *testing.T) {
	bubble.Run(testRefusalOnTheSAThisEndReplacedHoldsItNoLongerThanItsRetentionAllows)(t)
}

func testRefusalOnTheSAThisEndReplacedHoldsItNoLongerThanItsRetentionAllows(t *testing.T) {
	s, _ := initiatingSession(t, chainSuite, chainLists)
	old := s.current
	s.stateMu.Lock()
	s.replaceLocked(old, chainContext(t, chainSuite))
	s.stateMu.Unlock()
	replaced := time.Now()
	// send seals inner as a request of exchange on old at the Message ID old expects next, hands it to dispatch as the path would, and returns the answer this end sent, nil where it sent none
	send := func(exchange ExchangeType, inner []RawPayload) []RawPayload {
		t.Helper()
		s.stateMu.RLock()
		header := Header{SPIInitiator: old.spiI, SPIResponder: old.spiR, ExchangeType: exchange, MessageID: old.nextPeerMID}
		before := old.lastPeer.response
		s.stateMu.RUnlock()
		if old.responder {
			header.Flags = FlagInitiator
		}
		raw, err := EncryptMessage(old.suite, old.peerEncryptionKey(), header, nil, inner)
		if err != nil {
			t.Fatal(err)
		}
		var pending *pendingRequest
		s.dispatch(raw, s.mux.Endpoint(), &pending)
		s.stateMu.RLock()
		sent := old.lastPeer.response
		s.stateMu.RUnlock()
		if sent == before {
			return nil
		}
		return sealedAnswer(t, old, sent.message.whole)
	}
	slots := func() (recoveryRecord, time.Time) {
		s.stateMu.RLock()
		defer s.stateMu.RUnlock()
		return s.recovery, s.oldBy
	}
	time.Sleep(retainedContextDeadline - pastRetentionBy)
	_, request := newPeerRekey(t, classicalOffer, drawnOctets(t, nonceLen))
	if refused := send(CREATE_CHILD_SA, request); !notified(refused, N_TEMPORARY_FAILURE, nil) {
		t.Fatalf("the peer's rekey of the replaced SA drew %v, want TEMPORARY_FAILURE", payloadTypes(refused))
	}
	refused := time.Now()
	record, oldBy := slots()
	if want := refused.Add(busyRequestBudget); record.replaced != old || !record.until.Equal(want) || !oldBy.Equal(want) {
		t.Fatalf("the refusal %v after the rekey is recorded %v, ending %v after the rekey and holding the SA %v after it, want both %v", refused.Sub(replaced), record.replaced == old, record.until.Sub(replaced), oldBy.Sub(replaced), want.Sub(replaced))
	}
	time.Sleep(time.Until(replaced.Add(retainedContextDeadline + pastRetentionBy)))
	_, again := newPeerRekey(t, classicalOffer, drawnOctets(t, nonceLen))
	if answer := send(CREATE_CHILD_SA, again); answer != nil {
		t.Errorf("a fresh rekey on the replaced SA past its retention drew %v", payloadTypes(answer))
	}
	if answer := send(INFORMATIONAL, nil); answer != nil {
		t.Errorf("a fresh INFORMATIONAL on the replaced SA past its retention drew %v", payloadTypes(answer))
	}
	if now, nowBy := slots(); now.replaced != old || !now.until.Equal(record.until) || !nowBy.Equal(oldBy) {
		t.Errorf("fresh requests past the retention left the record %v, ending %v after the rekey and holding the SA %v after it, want %v", now.replaced == old, now.until.Sub(replaced), nowBy.Sub(replaced), record.until.Sub(replaced))
	}
	time.Sleep(time.Until(record.until.Add(-pastRetentionBy)))
	s.expireRetainedContexts(time.Now())
	if _, held := s.contexts(); held != old {
		t.Fatalf("the replaced SA went %v after the rekey, before the record's end at %v", time.Since(replaced), record.until.Sub(replaced))
	}
	time.Sleep(2 * pastRetentionBy)
	s.expireRetainedContexts(time.Now())
	if _, held := s.contexts(); held != nil {
		t.Errorf("the session holds the replaced SA %v after the record's end", time.Since(record.until))
	}
}

// a peer's rekey of the current SA passes the refusal of a rekey on the SA this end's rekey replaced while this end's rekey of that SA runs, and this end's decision can replace the SA after that check and before the answer is placed
// each refusal the answer then draws keeps the refusal for the peer's resends as that refusal does, since the peer that sent it resends it on the replaced SA until the refusal or this end's Delete reaches it
// the decision comes at the suites read after the check or at the draw of Nr, both of which every answer runs
func TestRefusalAfterThisEndsDecisionIsRecorded(t *testing.T) {
	lists := Suites{ikeCipher: []Transform{encrAES128}, kex: []kexEntry{entryX25519, entry768}}
	for _, c := range []struct {
		name  string
		offer []Transform
		// refusal names the refusal the answer draws after the decision: placed, chain, limit, unlisted, routed, group, nonce or spi
		refusal string
		notify  NotifyType
	}{
		{"the classical answer not placed", classicalOffer, "placed", N_TEMPORARY_FAILURE},
		{"the chain of an additional key exchange not opened", hybridOffer, "chain", N_TEMPORARY_FAILURE},
		{"the limit on the peer's rekeys", classicalOffer, "limit", N_TEMPORARY_FAILURE},
		{"the offer no longer listed", classicalOffer, "unlisted", N_NO_PROPOSAL_CHOSEN},
		{"the peer's SPI routed by this end's SA", classicalOffer, "routed", N_NO_PROPOSAL_CHOSEN},
		{"the offer's key exchange no longer the one listed", []Transform{encrAES128, prfSHA256, {Type: TransDH, ID: DH_ECP_256}, dhX25519}, "group", N_INVALID_KE_PAYLOAD},
		{"the draw of Nr failing", classicalOffer, "nonce", N_TEMPORARY_FAILURE},
		{"the peer's SPI taken before the answer is placed", classicalOffer, "spi", N_TEMPORARY_FAILURE},
	} {
		t.Run(c.name, bubble.Run(func(t *testing.T) {
			s, _ := initiatingSession(t, classicalSuite, lists)
			// a second mux on the session's hub alone tells an SPI the session holds from one it released
			mux, other := lifecycleMuxes(t)
			s.mux = mux
			old := s.current
			nonces := crossingNonces(t, 1)
			var create, deletion *localRequest
			var peer *peerRekey
			var rekey <-chan error
			decide := func() {
				answer, _ := answerRekey(t, create.inner, 0, nil, nonces[1])
				create.result <- requestResult{inner: answer}
				deletion = requested(t, s, rekey, INFORMATIONAL)
			}
			var atLists atomic.Bool
			suites := s.suites
			s.suites = func() Suites {
				if !atLists.CompareAndSwap(true, false) {
					return suites()
				}
				decide()
				switch c.refusal {
				case "limit":
					// the peer's last rekey came now, inside minPeerIKERekeyInterval of this one
					s.lastPeerIKERekey.Store(int64(time.Since(s.started)) + 1)
				case "unlisted":
					return Suites{ikeCipher: []Transform{{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 256}}, kex: lists.kex}
				case "group":
					return Suites{ikeCipher: lists.ikeCipher, kex: []kexEntry{{group: DH_ECP_256}}}
				}
				return suites()
			}
			drawn := 0
			s.ikeRekeyNonce = func(n []byte) error {
				drawn++
				if drawn == 1 {
					copy(n, nonces[0])
					return nil
				}
				decide()
				switch c.refusal {
				case "nonce":
					return errors.New("no entropy")
				case "spi":
					if err := other.RegisterIKE(peer.spiI); err != nil {
						t.Fatal(err)
					}
				}
				copy(n, nonces[3])
				return nil
			}
			rekey = rekeying(s)
			create = requested(t, s, rekey, CREATE_CHILD_SA)
			var request []RawPayload
			peer, request = newPeerRekey(t, c.offer, nonces[2])
			if c.refusal == "routed" {
				// the peer offers the SPI this end's rekey made its SA under, which that SA routes once this end decided
				spi := offerOf(t, create.inner)[0].SPI
				peer.spiI = binary.BigEndian.Uint64(spi)
				request[0] = RawPayload{Type: PayloadSA, Body: EncodeSA([]Proposal{{Number: 1, Protocol: ProtoIKE, SPI: spi, Transforms: c.offer}})}
			}
			atLists.Store(c.refusal == "limit" || c.refusal == "unlisted" || c.refusal == "routed" || c.refusal == "group")
			if refused := peer.rekey(t, s.handleIKERekey, old, request); notifyIn(t, refused) != c.notify {
				t.Fatalf("the peer's rekey drew notify %d, want %d", notifyIn(t, refused), c.notify)
			}
			refused := time.Now()
			s.stateMu.RLock()
			record, oldBy, current := s.recovery, s.oldBy, s.current
			s.stateMu.RUnlock()
			if record.replaced != old || record.replacement != current || current == old || record.mid != 0 {
				t.Fatalf("the refusal is recorded of the replaced SA %v, of this end's SA %v, at Message ID %d, want both at Message ID 0", record.replaced == old, record.replacement == current && current != old, record.mid)
			}
			if want := refused.Add(busyRequestBudget); !record.until.Equal(want) || !oldBy.Equal(want) {
				t.Errorf("the record ends %v and holds the replaced SA %v after the refusal, want both %v", record.until.Sub(refused), oldBy.Sub(refused), busyRequestBudget)
			}
			deletion.result <- requestResult{}
			if err := ended(t, s, rekey); err != nil {
				t.Fatal(err)
			}
		}))
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

// RFC 7296 section 2.1: "The responder MUST remember each response until it receives a request whose sequence number is larger than or equal to the sequence number in the response plus its window size."
// the STATE_NOT_FOUND that answers the peer's IKE_FOLLOWUP_KE on the SA this end's rekey replaced, inside that SA's retention or past it, leaves the SA held to the end of the record of the answer before it, so the peer's repeat of that request, sent where the answer was lost, draws the same answer past the retention after Run's next pass
// the SA goes at the record's end, logged as the record's hold, at the peer's switch to the replacement and at the peer's Delete, and past its retention it opens nothing but that repeat and the Delete
func TestRepeatOfTheFollowupPastTheRetentionDrawsTheSameStateNotFound(t *testing.T) {
	for _, when := range []struct {
		name string
		// before is how long before the retention's end the IKE_FOLLOWUP_KE comes, negative for past it
		before time.Duration
	}{
		{"answered past the retention", -pastRetentionBy},
		{"answered inside the retention", insideRetentionBy},
	} {
		t.Run(when.name, func(t *testing.T) { testRepeatOfTheFollowupDrawsTheSameStateNotFound(t, when.before) })
	}
}

func testRepeatOfTheFollowupDrawsTheSameStateNotFound(t *testing.T, before time.Duration) {
	for _, row := range []struct {
		name string
		// then runs after the repeat drew its answer, and reports whether the SA is to be gone at Run's pass after it
		then func(t *testing.T, s *Session, old *ikeContext, seal func(ExchangeType, []RawPayload) []byte, deliver func([]byte) []RawPayload, until time.Time) bool
	}{
		{"the record's end drops the SA", func(t *testing.T, s *Session, old *ikeContext, seal func(ExchangeType, []RawPayload) []byte, deliver func([]byte) []RawPayload, until time.Time) bool {
			time.Sleep(time.Until(until))
			return true
		}},
		{"the peer's switch to the replacement drops the SA", func(t *testing.T, s *Session, old *ikeContext, seal func(ExchangeType, []RawPayload) []byte, deliver func([]byte) []RawPayload, until time.Time) bool {
			s.confirm(s.currentContext())
			return true
		}},
		{"the peer's Delete drops the SA", func(t *testing.T, s *Session, old *ikeContext, seal func(ExchangeType, []RawPayload) []byte, deliver func([]byte) []RawPayload, until time.Time) bool {
			if answer := deliver(seal(INFORMATIONAL, deleteIKEPayloads())); answer == nil {
				t.Error("the peer's Delete of the replaced SA past its retention drew no answer")
			}
			return true
		}},
		{"a request at the next Message ID draws nothing", func(t *testing.T, s *Session, old *ikeContext, seal func(ExchangeType, []RawPayload) []byte, deliver func([]byte) []RawPayload, until time.Time) bool {
			followup, _ := followupRequest(t, ML_KEM_768, []byte{1})
			if answer := deliver(seal(IKE_FOLLOWUP_KE, followup)); answer != nil {
				t.Errorf("an IKE_FOLLOWUP_KE at the next Message ID drew %v", payloadTypes(answer))
			}
			return false
		}},
		{"an INFORMATIONAL that is not the Delete draws nothing", func(t *testing.T, s *Session, old *ikeContext, seal func(ExchangeType, []RawPayload) []byte, deliver func([]byte) []RawPayload, until time.Time) bool {
			if answer := deliver(seal(INFORMATIONAL, nil)); answer != nil {
				t.Errorf("an empty INFORMATIONAL at the next Message ID drew %v", payloadTypes(answer))
			}
			return false
		}},
	} {
		t.Run(row.name, bubble.Run(func(t *testing.T) {
			lines := recordLines(t)
			s, _ := initiatingSession(t, chainSuite, chainLists)
			old := s.current
			// seal is inner as a request of exchange on old at the Message ID old expects next
			seal := func(exchange ExchangeType, inner []RawPayload) []byte {
				t.Helper()
				s.stateMu.RLock()
				header := Header{SPIInitiator: old.spiI, SPIResponder: old.spiR, ExchangeType: exchange, MessageID: old.nextPeerMID}
				s.stateMu.RUnlock()
				if old.responder {
					header.Flags = FlagInitiator
				}
				raw, err := EncryptMessage(old.suite, old.peerEncryptionKey(), header, nil, inner)
				if err != nil {
					t.Fatal(err)
				}
				return raw
			}
			// deliver hands raw to dispatch as the path would and returns the answer this end sent for it, nil where it sent none
			deliver := func(raw []byte) []RawPayload {
				t.Helper()
				s.stateMu.RLock()
				before, answers := old.lastPeer.response, old.lastPeer.answers
				s.stateMu.RUnlock()
				var pending *pendingRequest
				s.dispatch(raw, s.mux.Endpoint(), &pending)
				s.stateMu.RLock()
				sent, again := old.lastPeer.response, old.lastPeer.answers > answers
				s.stateMu.RUnlock()
				if sent == nil || sent == before && !again {
					return nil
				}
				return sealedAnswer(t, old, sent.message.whole)
			}
			// pass is the top of Run's loop, which drops a retained SA past its hold before Run takes the next datagram
			pass := func() bool {
				t.Helper()
				time.Sleep(time.Nanosecond)
				s.expireRetainedContexts(time.Now())
				_, held := s.contexts()
				return held == old
			}
			_, request := newPeerRekey(t, hybridOffer, drawnOctets(t, nonceLen))
			link, err := linkOf(deliver(seal(CREATE_CHILD_SA, request)))
			if err != nil || link == nil {
				t.Fatal("the peer's chained rekey drew no answer opening its chain")
			}
			s.stateMu.Lock()
			s.replaceLocked(old, chainContext(t, chainSuite))
			until := s.recovery.until
			s.stateMu.Unlock()
			time.Sleep(retainedContextDeadline - before)
			followup, _ := followupRequest(t, ML_KEM_768, link)
			raw := seal(IKE_FOLLOWUP_KE, followup)
			if first := deliver(raw); !notified(first, N_STATE_NOT_FOUND, nil) {
				t.Fatalf("the peer's IKE_FOLLOWUP_KE after the kept answer, %v before the retention's end, drew %v, want STATE_NOT_FOUND", before, payloadTypes(first))
			}
			if !pass() {
				t.Fatalf("Run's next pass dropped the replaced SA %v before the record's end", time.Until(until))
			}
			time.Sleep(max(before, 0) + pastRetentionBy)
			if !pass() {
				t.Fatalf("Run's next pass dropped the replaced SA %v before the record's end", time.Until(until))
			}
			// the path lost that answer, and the peer sends the same request again
			if again := deliver(raw); !notified(again, N_STATE_NOT_FOUND, nil) {
				t.Fatalf("the repeat of the IKE_FOLLOWUP_KE after Run's next pass drew %v, want the same STATE_NOT_FOUND", payloadTypes(again))
			}
			gone := row.then(t, s, old, seal, deliver, until)
			if held := pass(); held == gone {
				t.Fatalf("the replaced SA is held %v at Run's pass after the row, want %v", held, !gone)
			}
			if !time.Now().Before(until) {
				if at := lines.said(slog.LevelInfo, "ike dropping a replaced IKE SA kept for the peer's resends of its rekey", "at"); len(at) != 1 || at[0].String() != recordToAnswer {
					t.Errorf("the replaced SA was dropped at the record's end with the line at %v, want once at %q", at, recordToAnswer)
				}
				if after := lines.said(slog.LevelWarn, "ike dropping an IKE SA the peer never deleted", "after"); len(after) != 0 {
					t.Errorf("the replaced SA the record held was logged as one the peer never deleted, after %v", after)
				}
			}
			if again := deliver(raw); gone && again != nil || !gone && !notified(again, N_STATE_NOT_FOUND, nil) {
				t.Errorf("the repeat of the IKE_FOLLOWUP_KE drew %v with the SA held %v", payloadTypes(again), !gone)
			}
		}))
	}
}

// the STATE_NOT_FOUND that took a record's kept answer's place marks that answer for that record alone, so a later record of the same SA, of a refusal the SA keeps for a fresh rekey, ends at the fresh request after its answer as any record does
func TestStateNotFoundTakesTheKeptAnswersPlaceForItsRecordAlone(t *testing.T) {
	bubble.Run(testStateNotFoundTakesTheKeptAnswersPlaceForItsRecordAlone)(t)
}

func testStateNotFoundTakesTheKeptAnswersPlaceForItsRecordAlone(t *testing.T) {
	s, _ := initiatingSession(t, chainSuite, chainLists)
	old := s.current
	// send seals inner as a request of exchange on old at the Message ID old expects next, hands it to dispatch as the path would, and returns the answer this end sent, nil where it sent none
	send := func(exchange ExchangeType, inner []RawPayload) []RawPayload {
		t.Helper()
		s.stateMu.RLock()
		header := Header{SPIInitiator: old.spiI, SPIResponder: old.spiR, ExchangeType: exchange, MessageID: old.nextPeerMID}
		before := old.lastPeer.response
		s.stateMu.RUnlock()
		if old.responder {
			header.Flags = FlagInitiator
		}
		raw, err := EncryptMessage(old.suite, old.peerEncryptionKey(), header, nil, inner)
		if err != nil {
			t.Fatal(err)
		}
		var pending *pendingRequest
		s.dispatch(raw, s.mux.Endpoint(), &pending)
		s.stateMu.RLock()
		sent := old.lastPeer.response
		s.stateMu.RUnlock()
		if sent == before {
			return nil
		}
		return sealedAnswer(t, old, sent.message.whole)
	}
	_, request := newPeerRekey(t, hybridOffer, drawnOctets(t, nonceLen))
	link, err := linkOf(send(CREATE_CHILD_SA, request))
	if err != nil || link == nil {
		t.Fatal("the peer's chained rekey drew no answer opening its chain")
	}
	s.stateMu.Lock()
	s.replaceLocked(old, chainContext(t, chainSuite))
	s.stateMu.Unlock()
	time.Sleep(retainedContextDeadline - insideRetentionBy)
	followup, _ := followupRequest(t, ML_KEM_768, link)
	if answer := send(IKE_FOLLOWUP_KE, followup); !notified(answer, N_STATE_NOT_FOUND, nil) {
		t.Fatalf("the peer's IKE_FOLLOWUP_KE after the kept answer drew %v, want STATE_NOT_FOUND", payloadTypes(answer))
	}
	time.Sleep(pastRetentionBy)
	_, again := newPeerRekey(t, classicalOffer, drawnOctets(t, nonceLen))
	if refused := send(CREATE_CHILD_SA, again); !notified(refused, N_TEMPORARY_FAILURE, nil) {
		t.Fatalf("the peer's fresh rekey of the replaced SA drew %v, want TEMPORARY_FAILURE", payloadTypes(refused))
	}
	s.stateMu.RLock()
	record := s.recovery
	s.stateMu.RUnlock()
	if record.replaced != old || record.mid != old.lastPeerResponseID {
		t.Fatalf("the refusal is recorded %v at Message ID %d, want at %d", record.replaced == old, record.mid, old.lastPeerResponseID)
	}
	time.Sleep(pastRetentionBy)
	if answer := send(INFORMATIONAL, nil); answer == nil {
		t.Fatal("a fresh INFORMATIONAL on the replaced SA inside its retention drew nothing")
	}
	s.stateMu.RLock()
	record, oldBy := s.recovery, s.oldBy
	s.stateMu.RUnlock()
	if want := old.replacedAt.Add(retainedContextDeadline); record.replaced != nil || !oldBy.Equal(want) {
		t.Errorf("the fresh request after the refusal left the record %v and the SA held %v after the rekey, want no record and %v", record.replaced == old, oldBy.Sub(old.replacedAt), retainedContextDeadline)
	}
}

// a peer's chained rekey replaces old, and its repeat of the IKE_FOLLOWUP_KE past old's retention draws the kept answer again, which moves the record's last send
// the peer's switch to the SA its rekey made then ends the record, and old is kept for the peer's Delete for retainedContextDeadline from that last send, past the retention counted from the rekey
// dropped at that hold, old's line names the bound that applied, the last send of the answer
func TestDropAfterThePeersSwitchCountsFromTheAnswersLastSend(t *testing.T) {
	bubble.Run(testDropAfterThePeersSwitchCountsFromTheAnswersLastSend)(t)
}

func testDropAfterThePeersSwitchCountsFromTheAnswersLastSend(t *testing.T) {
	lines := recordLines(t)
	s, _ := initiatingSession(t, chainSuite, chainLists)
	old := s.current
	// send seals inner as a request of exchange on old at the Message ID old expects next, hands it to dispatch as the path would, and returns the answer this end sent, nil where it sent none
	send := func(raw []byte) []RawPayload {
		t.Helper()
		s.stateMu.RLock()
		before, answers := old.lastPeer.response, old.lastPeer.answers
		s.stateMu.RUnlock()
		var pending *pendingRequest
		s.dispatch(raw, s.mux.Endpoint(), &pending)
		s.stateMu.RLock()
		sent, again := old.lastPeer.response, old.lastPeer.answers > answers
		s.stateMu.RUnlock()
		if sent == nil || sent == before && !again {
			return nil
		}
		return sealedAnswer(t, old, sent.message.whole)
	}
	seal := func(exchange ExchangeType, inner []RawPayload) []byte {
		t.Helper()
		s.stateMu.RLock()
		header := Header{SPIInitiator: old.spiI, SPIResponder: old.spiR, ExchangeType: exchange, MessageID: old.nextPeerMID}
		s.stateMu.RUnlock()
		if old.responder {
			header.Flags = FlagInitiator
		}
		raw, err := EncryptMessage(old.suite, old.peerEncryptionKey(), header, nil, inner)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	_, request := newPeerRekey(t, hybridOffer, drawnOctets(t, nonceLen))
	link, err := linkOf(send(seal(CREATE_CHILD_SA, request)))
	if err != nil || link == nil {
		t.Fatal("the peer's chained rekey drew no answer opening its chain")
	}
	followup, _ := followupRequest(t, ML_KEM_768, link)
	raw := seal(IKE_FOLLOWUP_KE, followup)
	if answer := send(raw); findType(answer, PayloadKE) == nil {
		t.Fatalf("the peer's IKE_FOLLOWUP_KE drew %v, want its KE", payloadTypes(answer))
	}
	s.stateMu.RLock()
	held, record := s.old, s.recovery
	s.stateMu.RUnlock()
	if held != old || record.replaced != old || s.currentContext() == old {
		t.Fatalf("the peer's chained rekey left old held %v and recorded %v", held == old, record.replaced == old)
	}
	time.Sleep(2 * retainedContextDeadline)
	if again := send(raw); findType(again, PayloadKE) == nil {
		t.Fatalf("the repeat of the IKE_FOLLOWUP_KE past the retention drew %v, want the kept answer", payloadTypes(again))
	}
	resent := time.Now()
	s.confirm(s.currentContext())
	s.stateMu.RLock()
	record, oldBy := s.recovery, s.oldBy
	s.stateMu.RUnlock()
	if want := resent.Add(retainedContextDeadline); record.replaced != nil || !oldBy.Equal(want) {
		t.Fatalf("the peer's switch left the record %v and old held %v after the last send, want no record and %v", record.replaced == old, oldBy.Sub(resent), retainedContextDeadline)
	}
	time.Sleep(time.Until(oldBy))
	s.expireRetainedContexts(time.Now())
	if _, held := s.contexts(); held != nil {
		t.Fatalf("old is held %v after the rekey, past its hold", time.Since(old.replacedAt))
	}
	if at := lines.said(slog.LevelWarn, "ike dropping an IKE SA the peer never deleted", "at"); len(at) != 1 || at[0].String() != retainedFromAnswer {
		t.Errorf("old, held %v after the rekey, was dropped with the line at %v, want once at %q", oldBy.Sub(old.replacedAt), at, retainedFromAnswer)
	}
	// said gives an empty value for a line without the key, so the line above carries no bound counted from the rekey
	if after := lines.said(slog.LevelWarn, "ike dropping an IKE SA the peer never deleted", "after"); len(after) != 1 || after[0].Any() != nil {
		t.Errorf("old, held %v after the rekey, was logged as dropped after %v", oldBy.Sub(old.replacedAt), after)
	}
}

// this end's own rekey replaces old with no peer rekey answered on it, and old reaches the expiry pass at its hold, as where this end's Delete of it is still unanswered at retainedContextDeadline
// on the real clock replacedAt and the hold come from two reads of the clock, so the hold falls a little past replacedAt plus the retention, and old's line still names the retention from the rekey and no answer of a peer's rekey
// it runs outside the bubble for that reason
func TestOwnRekeysDropOnTheRealClockNamesTheRetention(t *testing.T) {
	lines := recordLines(t)
	s, _ := initiatingSession(t, chainSuite, chainLists)
	old := s.current
	s.stateMu.Lock()
	s.replaceLocked(old, chainContext(t, chainSuite))
	oldBy, record := s.oldBy, s.recovery.replaced
	s.stateMu.Unlock()
	if record != nil {
		t.Fatal("this end's own rekey with no peer rekey answered made a record")
	}
	s.expireRetainedContexts(oldBy)
	if _, held := s.contexts(); held != nil {
		t.Fatal("the expiry pass at old's hold kept old")
	}
	if at := lines.said(slog.LevelWarn, "ike dropping an IKE SA the peer never deleted", "at"); len(at) != 1 || at[0].Any() != nil {
		t.Errorf("old, which this end's own rekey replaced, was dropped with the line at %v, want none", at)
	}
	if after := lines.said(slog.LevelWarn, "ike dropping an IKE SA the peer never deleted", "after"); len(after) != 1 || after[0].Duration() != retainedContextDeadline {
		t.Errorf("old was dropped after %v, want once after %v", after, retainedContextDeadline)
	}
}

// a fresh request after the STATE_NOT_FOUND that took the kept answer's place inside the retention ends the record, and its answer is no STATE_NOT_FOUND
// so past the retention a repeat of that request is not served as a repeat of the STATE_NOT_FOUND
func TestFreshRequestAfterTheStateNotFoundIsNotServedAsItsRepeat(t *testing.T) {
	bubble.Run(testFreshRequestAfterTheStateNotFoundIsNotServedAsItsRepeat)(t)
}

func testFreshRequestAfterTheStateNotFoundIsNotServedAsItsRepeat(t *testing.T) {
	s, _ := initiatingSession(t, chainSuite, chainLists)
	old := s.current
	send := func(exchange ExchangeType, inner []RawPayload) []RawPayload {
		t.Helper()
		s.stateMu.RLock()
		header := Header{SPIInitiator: old.spiI, SPIResponder: old.spiR, ExchangeType: exchange, MessageID: old.nextPeerMID}
		before := old.lastPeer.response
		s.stateMu.RUnlock()
		if old.responder {
			header.Flags = FlagInitiator
		}
		raw, err := EncryptMessage(old.suite, old.peerEncryptionKey(), header, nil, inner)
		if err != nil {
			t.Fatal(err)
		}
		var pending *pendingRequest
		s.dispatch(raw, s.mux.Endpoint(), &pending)
		s.stateMu.RLock()
		sent := old.lastPeer.response
		s.stateMu.RUnlock()
		if sent == before {
			return nil
		}
		return sealedAnswer(t, old, sent.message.whole)
	}
	_, request := newPeerRekey(t, hybridOffer, drawnOctets(t, nonceLen))
	link, err := linkOf(send(CREATE_CHILD_SA, request))
	if err != nil || link == nil {
		t.Fatal("the peer's chained rekey drew no answer opening its chain")
	}
	s.stateMu.Lock()
	s.replaceLocked(old, chainContext(t, chainSuite))
	s.stateMu.Unlock()
	time.Sleep(retainedContextDeadline - insideRetentionBy)
	followup, _ := followupRequest(t, ML_KEM_768, link)
	if answer := send(IKE_FOLLOWUP_KE, followup); !notified(answer, N_STATE_NOT_FOUND, nil) {
		t.Fatalf("the peer's IKE_FOLLOWUP_KE after the kept answer drew %v, want STATE_NOT_FOUND", payloadTypes(answer))
	}
	if answer := send(INFORMATIONAL, nil); answer == nil {
		t.Fatal("a fresh INFORMATIONAL on the replaced SA inside its retention drew nothing")
	}
	s.stateMu.RLock()
	record, mid := s.recovery, old.lastPeerResponseID
	s.stateMu.RUnlock()
	if record.replaced != nil {
		t.Fatal("the fresh request after the STATE_NOT_FOUND left the record")
	}
	if s.servesRepeat(old, mid) {
		t.Errorf("a repeat of the fresh request at Message ID %d is served as a repeat of the STATE_NOT_FOUND, with no record left", mid)
	}
}

// the record names the SA it holds, and a slot that drops that SA ends the record with it, so the dropped SA and its keys are reached from no slot or record of the session
// the SA goes at the record's end, at the outcome of this end's Delete of it, and where a second rekey of this end displaces it, whose line says the record held it
func TestRecordGoesWithTheSAItHolds(t *testing.T) {
	for _, row := range []struct {
		name string
		drop func(t *testing.T, s *Session, old *ikeContext, until time.Time)
		// line is the line the drop logs at info, once, empty for a row whose line another test reads
		line string
	}{
		{"the record's end", func(t *testing.T, s *Session, old *ikeContext, until time.Time) {
			time.Sleep(time.Until(until) + time.Nanosecond)
			s.expireRetainedContexts(time.Now())
		}, ""},
		{"this end's Delete", func(t *testing.T, s *Session, old *ikeContext, until time.Time) {
			s.retireOwn(old, nil)
		}, ""},
		{"a second rekey of this end", func(t *testing.T, s *Session, old *ikeContext, until time.Time) {
			s.stateMu.Lock()
			s.replaceLocked(s.current, chainContext(t, chainSuite))
			s.stateMu.Unlock()
		}, "ike dropping a replaced IKE SA kept for the peer's resends of its rekey, which a later rekey replaced"},
	} {
		t.Run(row.name, bubble.Run(func(t *testing.T) {
			lines := recordLines(t)
			s, _ := initiatingSession(t, chainSuite, chainLists)
			old := s.current
			s.stateMu.RLock()
			header := Header{SPIInitiator: old.spiI, SPIResponder: old.spiR, ExchangeType: CREATE_CHILD_SA, MessageID: old.nextPeerMID}
			s.stateMu.RUnlock()
			if old.responder {
				header.Flags = FlagInitiator
			}
			_, request := newPeerRekey(t, hybridOffer, drawnOctets(t, nonceLen))
			raw, err := EncryptMessage(old.suite, old.peerEncryptionKey(), header, nil, request)
			if err != nil {
				t.Fatal(err)
			}
			var pending *pendingRequest
			s.dispatch(raw, s.mux.Endpoint(), &pending)
			s.stateMu.Lock()
			s.replaceLocked(old, chainContext(t, chainSuite))
			record := s.recovery
			s.stateMu.Unlock()
			if record.replaced != old {
				t.Fatal("the answer that opened the peer's chain is not recorded for the SA this end's rekey replaced")
			}
			row.drop(t, s, old, record.until)
			s.stateMu.RLock()
			held, named := s.old == old || s.collision == old, s.recovery.replaced == old
			s.stateMu.RUnlock()
			if held {
				t.Fatal("the session still holds the SA the row drops")
			}
			if named {
				t.Error("the record still names the SA no slot holds any more")
			}
			if row.line != "" {
				if told := lines.said(slog.LevelInfo, row.line, "spi"); len(told) != 1 || told[0].Uint64() != old.spiI {
					t.Errorf("the drop was told %v times at info as %q, want once for %016x", told, row.line, old.spiI)
				}
			}
		}))
	}
}
