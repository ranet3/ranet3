// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

package ike

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/bubble"
	"ranet3.com/pkgs/ranet3/internal/logtest"
	"ranet3.com/pkgs/ranet3/transport"
)

func TestSessionRunStopsOnContextCancellation(t *testing.T) {
	bubble.Run(testSessionRunStopsOnContextCancellation)(t)
}

func testSessionRunStopsOnContextCancellation(t *testing.T) {
	mux, _ := lifecycleMuxes(t)
	s := &Session{mux: mux}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Session.Run did not stop after context cancellation")
	}
}

func TestRequestReturnsWhenTransportCloses(t *testing.T) {
	for _, waitingForResponse := range []bool{false, true} {
		t.Run(fmt.Sprint(waitingForResponse), bubble.Run(func(t *testing.T) {
			mux, _ := lifecycleMuxes(t)
			s := &Session{mux: mux, current: &ikeContext{}, requests: make(chan *localRequest)}
			done := make(chan error, 1)
			go func() {
				_, err := s.request(CREATE_CHILD_SA, nil)
				done <- err
			}()
			if waitingForResponse {
				<-s.requests
			}
			mux.Close()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("request succeeded after transport closed")
				}
			case <-time.After(time.Second):
				t.Fatal("request remained blocked after transport closed")
			}
		}))
	}
}

func TestNextDueRekeyPreservesChildPriority(t *testing.T) {
	child := &rekeySchedule{name: "Child SA", due: true}
	ike := &rekeySchedule{name: "IKE SA", due: true}
	if got := nextDueRekey([]*rekeySchedule{child, ike}, nil); got != child {
		t.Fatalf("first due schedule = %v, want Child SA", got)
	}
	if got := nextDueRekey([]*rekeySchedule{child, ike}, child); got != nil {
		t.Fatalf("selected %v while another rekey was running", got)
	}
	if got := nextDueRekey([]*rekeySchedule{child, ike}, nil); got != ike {
		t.Fatalf("second due schedule = %v, want IKE SA", got)
	}
}

// RFC 7296 section 3.2: "all implementations MUST understand all payload types defined in this document"
// this end understands every payload type RFC 7296 defines and the Encrypted Fragment payload of RFC 7383, and no other
func TestSupportedPayloadTypeNamesEveryTypeThisEndUnderstands(t *testing.T) {
	understood := []PayloadType{PayloadSA, PayloadKE, PayloadIDi, PayloadIDr, PayloadCERT, PayloadCERTREQ, PayloadAUTH, PayloadNonce,
		PayloadN, PayloadD, PayloadV, PayloadTSi, PayloadTSr, PayloadSK, PayloadCP, PayloadEAP, PayloadSKF}
	for value := range 256 {
		payloadType := PayloadType(value)
		if got := supportedPayloadType(payloadType); got != slices.Contains(understood, payloadType) {
			t.Errorf("payload type %d is understood %v", payloadType, got)
		}
	}
}

func TestRekeyRetryDelay(t *testing.T) {
	s := &Session{
		rekeyRetryInitial: 5 * time.Second,
		rekeyRetryMax:     time.Minute,
		rekeyJitterSource: func(time.Duration) (time.Duration, error) { return 0, nil },
	}
	for _, test := range []struct {
		failures uint
		want     time.Duration
	}{
		{1, 5 * time.Second},
		{2, 10 * time.Second},
		{3, 20 * time.Second},
		{4, 40 * time.Second},
		{5, time.Minute},
		{6, time.Minute},
	} {
		if got := s.rekeyRetryDelay(test.failures); got != test.want {
			t.Errorf("retry delay after %d failures = %s, want %s", test.failures, got, test.want)
		}
	}
}

// Two ends of a simultaneous rekey fail at the same instant and reset the same
// backoff, so an unjittered retry collides again on every attempt.
func TestRekeyRetryDelayIsSpreadOverUpperHalfOfWindow(t *testing.T) {
	s := &Session{rekeyRetryInitial: 5 * time.Second, rekeyRetryMax: time.Minute}
	seen := make(map[time.Duration]bool)
	for range 64 {
		got := s.rekeyRetryDelay(3)
		if got < 10*time.Second || got > 20*time.Second {
			t.Fatalf("retry delay = %s, want it within 10s..20s", got)
		}
		seen[got] = true
	}
	if len(seen) < 32 {
		t.Fatalf("64 draws produced %d distinct delays, want a spread", len(seen))
	}
}

func TestRequestRetransmitDelayIsExponential(t *testing.T) {
	want := []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 32 * time.Second}
	for i, delay := range want {
		if got := retransmitDelay(requestTimeout, i+1); got != delay {
			t.Fatalf("attempt %d delay = %v, want %v", i+1, got, delay)
		}
	}
}

// a Delete the peer retransmits until an unanswered exchange gives up still finds the replaced IKE SA it names
func TestRetainedIKESAOutlastsAnUnansweredExchange(t *testing.T) {
	var budget time.Duration
	for attempt := range maxRetransmits {
		budget += retransmitDelay(requestTimeout, attempt+1)
	}
	if retainedContextDeadline <= budget {
		t.Errorf("a replaced IKE SA is kept %s, within the %s an unanswered exchange retransmits for", retainedContextDeadline, budget)
	}
}

func TestPostHandshakeRetransmitsRequireLivePeerToContinue(t *testing.T) {
	ordinary := &pendingRequest{attempts: maxRetransmits}
	if pendingRetransmitsExhausted(ordinary, true) {
		t.Fatal("ordinary request exhausted retransmissions while receiving authenticated traffic")
	}
	if !pendingRetransmitsExhausted(ordinary, false) {
		t.Fatal("unanswered rekey kept a silent peer alive indefinitely")
	}
	dpd := &pendingRequest{attempts: maxRetransmits, localRequest: localRequest{dpd: true}}
	if !pendingRetransmitsExhausted(dpd, true) {
		t.Fatal("DPD request did not exhaust retransmissions")
	}
}

func TestNoteTrafficCoalescesPacketsUntilRunConsumesThem(t *testing.T) {
	var s Session
	for range 1000 {
		s.NoteTraffic()
	}
	if !s.trafficSeen.Swap(false) {
		t.Fatal("authenticated traffic was not recorded")
	}
	if s.trafficSeen.Swap(false) {
		t.Fatal("traffic indication was not consumed")
	}
	s.NoteTraffic()
	if !s.trafficSeen.Swap(false) {
		t.Fatal("traffic after consumption was not recorded")
	}
}

// a request whose first send fails is pending with that attempt spent
func TestStartRequestConsumesMessageIDWhetherOrNotItsSendGoesOut(t *testing.T) {
	bubble.Run(testStartRequestConsumesMessageIDWhetherOrNotItsSendGoesOut)(t)
}

func testStartRequestConsumesMessageIDWhetherOrNotItsSendGoesOut(t *testing.T) {
	mux, _ := lifecycleMuxes(t)
	ctx := &ikeContext{
		suite: SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128},
		skei:  make([]byte, 20), spiI: 1, spiR: 2, nextLocalMID: 7,
	}
	s := &Session{mux: mux, current: ctx}
	if _, err := s.startRequest(&localRequest{exchange: INFORMATIONAL}); err != nil {
		t.Fatal(err)
	}
	if ctx.nextLocalMID != 8 {
		t.Fatalf("Message ID after successful send = %d, want 8", ctx.nextLocalMID)
	}

	failedCtx := &ikeContext{
		suite: SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128},
		skei:  make([]byte, 20), spiI: 3, spiR: 4, nextLocalMID: 11,
	}
	failed := &Session{mux: unsendableMux(t), current: failedCtx}
	pending, err := failed.startRequest(&localRequest{exchange: INFORMATIONAL})
	if err != nil {
		t.Fatalf("a request whose send failed was refused rather than left pending: %v", err)
	}
	if failedCtx.nextLocalMID != 12 || pending.msgID != 11 {
		t.Fatalf("the request took Message ID %d and left %d next, want 11 and 12", pending.msgID, failedCtx.nextLocalMID)
	}
	if pending.sent != 1 || pending.attempts != 1 || failed.sendFailures != 1 {
		t.Errorf("the failed send counted %d sends and %d attempts with %d failures, want one of each", pending.sent, pending.attempts, failed.sendFailures)
	}
}

// unsendableMux sends to port zero, which linux and darwin both refuse
func unsendableMux(t *testing.T) *transport.Mux {
	t.Helper()
	mux, err := listenHub(t).NewMux(net.IPv4(127, 0, 0, 1), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := mux.SendIKE([]byte("refused")); err == nil {
		t.Fatal("a send to port zero went out, so this mux proves nothing")
	}
	return mux
}

func TestMessageIDExhaustionCannotWrap(t *testing.T) {
	t.Run("local request", bubble.Run(func(t *testing.T) {
		mux, _ := lifecycleMuxes(t)
		ctx := &ikeContext{nextLocalMID: maxMessageID}
		s := &Session{mux: mux, current: ctx, requests: make(chan *localRequest, 1)}
		runDone := make(chan error, 1)
		go func() { runDone <- s.Run(context.Background()) }()
		if _, err := s.request(INFORMATIONAL, nil); !errors.Is(err, errMessageIDExhausted) {
			t.Fatalf("request error = %v", err)
		}
		if ctx.nextLocalMID != maxMessageID {
			t.Fatalf("local Message ID wrapped to %d", ctx.nextLocalMID)
		}
		if err := <-runDone; !errors.Is(err, errMessageIDExhausted) {
			t.Fatalf("Run error = %v", err)
		}
		if !mux.IsClosed() {
			t.Fatal("IKE SA remained open at local Message ID exhaustion")
		}
	}))

	t.Run("peer request", bubble.Run(func(t *testing.T) {
		mux, _ := lifecycleMuxes(t)
		suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128}
		ctx := &ikeContext{
			suite: suite, spiI: 1, spiR: 2, sker: make([]byte, 20),
			nextPeerMID: maxMessageID,
		}
		s := &Session{mux: mux, current: ctx}
		request, err := EncryptMessage(suite, ctx.sker, Header{
			SPIInitiator: 1, SPIResponder: 2, ExchangeType: INFORMATIONAL,
			MessageID: maxMessageID,
		}, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		var pending *pendingRequest
		if !s.dispatch(request, nil, &pending) {
			t.Fatal("exhausting peer request was not authenticated")
		}
		if ctx.nextPeerMID != maxMessageID {
			t.Fatalf("peer Message ID wrapped to %d", ctx.nextPeerMID)
		}
		if !mux.IsClosed() {
			t.Fatal("IKE SA remained open at peer Message ID exhaustion")
		}
	}))
}

// acceptedMux is the mux a responder makes from a datagram configured sent
func acceptedMux(t *testing.T, configured *transport.MemoryConn, spiI uint64) *transport.Mux {
	t.Helper()
	hub := listenHub(t)
	unclaimed := hub.Listen()
	opening := make([]byte, 28)
	binary.BigEndian.PutUint64(opening[:8], spiI)
	to := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: hub.LocalAddr().(*net.UDPAddr).Port}
	if _, err := configured.WriteToUDP(withNonESPMarker(opening), to); err != nil {
		t.Fatal(err)
	}
	select {
	case first := <-unclaimed:
		mux, err := hub.NewMuxTo(first.Endpoint)
		if err != nil {
			t.Fatal(err)
		}
		return mux
	case <-time.After(answerBudget):
		t.Fatal("the opening datagram never arrived")
		return nil
	}
}

func recordedKind(r *recorder, kind string) int {
	count := 0
	for _, line := range r.recorded() {
		if strings.HasPrefix(line, kind+" ") {
			count++
		}
	}
	return count
}

func TestReplayedRequestDoesNotRefreshOrAdoptEndpoint(t *testing.T) {
	bubble.Run(testReplayedRequestDoesNotRefreshOrAdoptEndpoint)(t)
}

func testReplayedRequestDoesNotRefreshOrAdoptEndpoint(t *testing.T) {
	configured := listenPeer(t)
	rebound := listenPeer(t)

	ikeCtx := testContext()
	mux := acceptedMux(t, configured, ikeCtx.spiI)
	defer mux.Close()
	moves := &recorder{}
	s := &Session{mux: mux, current: ikeCtx, events: moves.record}
	if err := mux.RegisterIKE(ikeCtx.spiI); err != nil {
		t.Fatal(err)
	}

	dst := muxLoopback(mux)
	readIKE := func(peer *transport.MemoryConn) []byte {
		t.Helper()
		buf := make([]byte, 2048)
		if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		n, _, err := peer.ReadFromUDP(buf)
		if err != nil {
			t.Fatal(err)
		}
		return append([]byte(nil), buf[4:n]...)
	}
	dispatchFrom := func(peer *transport.MemoryConn, request []byte) bool {
		t.Helper()
		if _, err := peer.WriteToUDP(withNonESPMarker(request), dst); err != nil {
			t.Fatal(err)
		}
		raw, source, err := mux.RecvIKEFromUntil(time.Now().Add(answerBudget))
		if err != nil {
			t.Fatal(err)
		}
		var pending *pendingRequest
		return s.dispatch(raw, source, &pending)
	}

	request, err := EncryptMessage(ikeCtx.suite, ikeCtx.sker, Header{
		SPIInitiator: ikeCtx.spiI,
		SPIResponder: ikeCtx.spiR,
		ExchangeType: INFORMATIONAL,
		MessageID:    0,
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !dispatchFrom(configured, request) {
		t.Fatal("fresh request was not reported as peer activity")
	}
	response := readIKE(configured)
	if got := recordedKind(moves, "ike.endpoint.moved"); got != 0 {
		t.Errorf("a request from where the session already sends recorded %d moves", got)
	}

	if dispatchFrom(rebound, request) {
		t.Fatal("replayed request was reported as fresh peer activity")
	}
	if replayResponse := readIKE(rebound); !bytes.Equal(replayResponse, response) {
		t.Fatal("replayed request did not receive the cached response")
	}
	if err := mux.SendIKE([]byte("probe")); err != nil {
		t.Fatal(err)
	}
	if got := readIKE(configured); string(got) != "probe" {
		t.Fatalf("packet after replay = %q, want configured endpoint", got)
	}

	freshRequest, err := EncryptMessage(ikeCtx.suite, ikeCtx.sker, Header{
		SPIInitiator: ikeCtx.spiI,
		SPIResponder: ikeCtx.spiR,
		ExchangeType: INFORMATIONAL,
		MessageID:    1,
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !dispatchFrom(rebound, freshRequest) {
		t.Fatal("fresh request from rebound endpoint was not reported as peer activity")
	}
	_ = readIKE(rebound)
	if err := mux.SendIKE([]byte("future")); err != nil {
		t.Fatal(err)
	}
	if got := readIKE(rebound); string(got) != "future" {
		t.Fatalf("packet after fresh request = %q, want rebound endpoint", got)
	}
	if got := recordedKind(moves, "ike.endpoint.moved"); got != 1 {
		t.Errorf("the session recorded %d moves, want the one a fresh request from a new endpoint made", got)
	}
}

// RFC 7296 section 2.3: "This Notify message MUST NOT be sent in a response" and "the invalid request MUST NOT be acknowledged."
// a request at a Message ID ahead of the window is dropped unanswered and moves the window nowhere, so the request at its next Message ID is the one answered
func TestRequestAheadOfTheWindowIsNotAcknowledged(t *testing.T) {
	bubble.Run(testRequestAheadOfTheWindowIsNotAcknowledged)(t)
}

func testRequestAheadOfTheWindowIsNotAcknowledged(t *testing.T) {
	s, peer, _ := probedSession(t)
	held := s.current
	if err := s.mux.RegisterIKE(held.spiI); err != nil {
		t.Fatal(err)
	}
	runSession(t, s)
	request := func(id uint32) {
		t.Helper()
		raw, err := EncryptMessage(held.suite, held.sker, Header{SPIInitiator: held.spiI, SPIResponder: held.spiR, ExchangeType: INFORMATIONAL, MessageID: id}, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := peer.WriteToUDP(withNonESPMarker(raw), muxLoopback(s.mux)); err != nil {
			t.Fatal(err)
		}
	}
	request(1)
	buf := make([]byte, 2048)
	if err := peer.SetReadDeadline(time.Now().Add(quietPeriod)); err != nil {
		t.Fatal(err)
	}
	if n, _, err := peer.ReadFromUDP(buf); err == nil {
		t.Fatalf("a request ahead of the window drew %x, want no answer", buf[NonESPMarkerLen:n])
	}
	if next := s.nextPeerMessageID(held); next != 0 {
		t.Errorf("a request ahead of the window moved it to Message ID %d", next)
	}
	request(0)
	if err := peer.SetReadDeadline(time.Now().Add(answerBudget)); err != nil {
		t.Fatal(err)
	}
	n, _, err := peer.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("the request at the window's next Message ID went unanswered: %v", err)
	}
	if header, err := decodeHeader(buf[NonESPMarkerLen:n]); err != nil || !header.IsResponse() || header.MessageID != 0 {
		t.Errorf("the request at Message ID 0 drew %+v (%v), want its answer", header, err)
	}
}

// a dialed session follows its peer to where a fresh request that passed its integrity check came from, RFC 7296 section 2.23,
// and leaves by the kernel's choice of source rather than the address the request arrived on
// linux holds all of 127.0.0.0/8 and chooses 127.0.0.1 to reach any of it, which tells the two apart
// so it runs on loopback, whose endpoints keep the address a datagram arrived on where the network in memory keeps none
func TestDialedSessionFollowsItsPeerFromTheKernelsSource(t *testing.T) {
	movedTo, arrival := net.IPv4(127, 0, 0, 1), net.IPv4(127, 0, 0, 1)
	if runtime.GOOS == "linux" {
		movedTo, arrival = net.IPv4(127, 0, 0, 2), net.IPv4(127, 0, 0, 3)
	}
	configured, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { configured.Close() })
	moved, err := net.ListenUDP("udp4", &net.UDPAddr{IP: movedTo})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { moved.Close() })
	hub, err := transport.NewHub(":0", transport.Underlay{}, transport.Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { hub.Close() })
	configuredAddr := configured.LocalAddr().(*net.UDPAddr)
	mux, err := hub.NewMux(configuredAddr.IP, configuredAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	ikeCtx := testContext()
	moves := &recorder{}
	s := &Session{mux: mux, current: ikeCtx, events: moves.record}
	if err := mux.RegisterIKE(ikeCtx.spiI); err != nil {
		t.Fatal(err)
	}
	request, err := EncryptMessage(ikeCtx.suite, ikeCtx.sker, Header{SPIInitiator: ikeCtx.spiI, SPIResponder: ikeCtx.spiR,
		ExchangeType: INFORMATIONAL}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	arrive := func(raw []byte) bool {
		t.Helper()
		if _, err := moved.WriteToUDP(withNonESPMarker(raw), &net.UDPAddr{IP: arrival, Port: muxLoopback(mux).Port}); err != nil {
			t.Fatal(err)
		}
		received, source, err := mux.RecvIKEFromUntil(time.Now().Add(answerBudget))
		if err != nil {
			t.Fatal(err)
		}
		var pending *pendingRequest
		return s.dispatch(received, source, &pending)
	}
	dialedTo := mux.Endpoint().String()
	forged := append([]byte(nil), request...)
	forged[len(forged)-1] ^= 1
	if arrive(forged) || mux.Endpoint().String() != dialedTo {
		t.Fatalf("a request that failed its integrity check moved the session to %s", mux.Endpoint())
	}
	if !arrive(request) {
		t.Fatal("a fresh request was not taken")
	}
	read := func() (string, *net.UDPAddr) {
		t.Helper()
		buf := make([]byte, 2048)
		if err := moved.SetReadDeadline(time.Now().Add(answerBudget)); err != nil {
			t.Fatal(err)
		}
		n, from, err := moved.ReadFromUDP(buf)
		if err != nil {
			t.Fatal(err)
		}
		return string(buf[NonESPMarkerLen:n]), from
	}
	if _, from := read(); !from.IP.Equal(arrival) {
		t.Errorf("the reply came from %s, want the address the request arrived on", from)
	}
	if err := mux.SendIKE([]byte("next")); err != nil {
		t.Fatal(err)
	}
	if got, from := read(); got != "next" || !from.IP.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Errorf("the peer read %q from %s where it moved, want the next request from the kernel's choice of 127.0.0.1", got, from)
	}
	if got := recordedKind(moves, "ike.endpoint.moved"); got != 1 {
		t.Errorf("the session recorded %d moves, want one", got)
	}
}

// testContext is an SA this node dialed, keyed with zeros
func testContext() *ikeContext {
	return &ikeContext{suite: SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256},
		spiI: 0x0102030405060708, spiR: 0x1112131415161718, skei: make([]byte, 20), sker: make([]byte, 20)}
}

func TestAuthenticatedMalformedRequestGetsInvalidSyntax(t *testing.T) {
	bubble.Run(testAuthenticatedMalformedRequestGetsInvalidSyntax)(t)
}

func testAuthenticatedMalformedRequestGetsInvalidSyntax(t *testing.T) {
	peer := listenPeer(t)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	mux, err := testNetwork(t).Dial(peerAddr.IP, peerAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()

	const spiI = 0x0102030405060708
	const spiR = 0x1112131415161718
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	ikeCtx := &ikeContext{
		suite: suite,
		spiI:  spiI,
		spiR:  spiR,
		skei:  make([]byte, 20),
		sker:  make([]byte, 20),
	}
	s := &Session{mux: mux, current: ikeCtx}
	if err := mux.RegisterIKE(spiI); err != nil {
		t.Fatal(err)
	}

	// The authenticated plaintext contains a generic payload whose declared
	// length is shorter than its four-byte header, followed by zero padding.
	request, err := encryptMessagePlaintextIV(suite, ikeCtx.sker, Header{
		SPIInitiator: spiI,
		SPIResponder: spiR,
		ExchangeType: INFORMATIONAL,
		MessageID:    0,
	}, nil, PayloadN, []byte{0, 0, 0, 3, 0}, make([]byte, 8))
	if err != nil {
		t.Fatal(err)
	}
	dst := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: mux.LocalAddr().(*net.UDPAddr).Port}
	if _, err := peer.WriteToUDP(withNonESPMarker(request), dst); err != nil {
		t.Fatal(err)
	}
	raw, source, err := mux.RecvIKEFromUntil(time.Now().Add(answerBudget))
	if err != nil {
		t.Fatal(err)
	}
	var pending *pendingRequest
	if !s.dispatch(raw, source, &pending) {
		t.Fatal("authenticated malformed request was not handled")
	}

	buf := make([]byte, 2048)
	if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	n, _, err := peer.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	responseRaw := buf[4:n]
	response, err := DecodeMessage(responseRaw)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := DecryptMessage(suite, ikeCtx.skei, responseRaw, response)
	if err != nil {
		t.Fatal(err)
	}
	if len(inner) != 1 || inner[0].Type != PayloadN {
		t.Fatalf("response payloads = %#v, want INVALID_SYNTAX", inner)
	}
	notify, err := DecodeNotify(inner[0].Body)
	if err != nil || notify.Type != N_INVALID_SYNTAX {
		t.Fatalf("response notify = %#v, %v", notify, err)
	}
	if !mux.IsClosed() {
		t.Fatal("IKE SA remained open after fatal INVALID_SYNTAX")
	}
}

// RFC 7296 section 3.1: "An Encrypted payload MUST be the last payload in a packet and an Encrypted payload MUST NOT contain another Encrypted payload."
// section 2.21.3: "If a peer parsing a request notices that it is badly formatted (after it has passed the message authentication code checks and window checks) and it returns an INVALID_SYNTAX notification, then this error notification is considered fatal in both peers, meaning that the IKE SA is deleted without needing an explicit Delete payload."
// a request whose SK carries an SK payload after a Delete of the Child SA draws INVALID_SYNTAX and ends the IKE SA, and the Delete is not acted on
func TestSessionRefusesAnSKPayloadInsideAnotherWithInvalidSyntax(t *testing.T) {
	bubble.Run(testSessionRefusesAnSKPayloadInsideAnotherWithInvalidSyntax)(t)
}

func testSessionRefusesAnSKPayloadInsideAnotherWithInvalidSyntax(t *testing.T) {
	peer := listenPeer(t)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	mux, err := testNetwork(t).Dial(peerAddr.IP, peerAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	held := testContext()
	s := &Session{mux: mux, current: held, Child: ChildSA{LocalSPI: 0x01020304, RemoteSPI: 0x50607080}}
	if err := mux.RegisterIKE(held.spiI); err != nil {
		t.Fatal(err)
	}
	header := Header{SPIInitiator: held.spiI, SPIResponder: held.spiR, ExchangeType: INFORMATIONAL, MessageID: 0}
	request, err := EncryptMessage(held.suite, held.sker, header, nil, []RawPayload{
		{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoESP, SPIs: [][]byte{binary.BigEndian.AppendUint32(nil, 0x50607080)}})},
		{Type: PayloadSK, Body: make([]byte, 24)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := peer.WriteToUDP(withNonESPMarker(request), muxLoopback(mux)); err != nil {
		t.Fatal(err)
	}
	raw, source, err := mux.RecvIKEFromUntil(time.Now().Add(answerBudget))
	if err != nil {
		t.Fatal(err)
	}
	var pending *pendingRequest
	if !s.dispatch(raw, source, &pending) {
		t.Fatal("the request was not taken as a fresh authenticated request")
	}
	buf := make([]byte, 2048)
	_ = peer.SetReadDeadline(time.Now().Add(answerBudget))
	n, _, err := peer.ReadFromUDP(buf)
	if err != nil || n <= 4 {
		t.Fatalf("the request drew no answer: %d bytes, %v", n, err)
	}
	answer, err := DecodeMessage(buf[4:n])
	if err != nil {
		t.Fatal(err)
	}
	inner, err := DecryptMessage(held.suite, held.skei, buf[4:n], answer)
	if err != nil || answer.Header.MessageID != 0 || !notified(inner, N_INVALID_SYNTAX, nil) {
		t.Errorf("the request drew %v at Message ID %d (%v), want INVALID_SYNTAX at 0", inner, answer.Header.MessageID, err)
	}
	if !mux.IsClosed() || s.Child.LocalSPI != 0x01020304 {
		t.Errorf("the IKE SA is closed %v and the Child SA is %08x, want the IKE SA ended and the Child SA as it was", mux.IsClosed(), s.Child.LocalSPI)
	}
}

// RFC 7296 section 3.10.1 on INVALID_SYNTAX: "Indicates the IKE message that was received was invalid because some type, length, or value was out of range or because the request was rejected for policy reasons."
// and: "To avoid leaking information to someone probing a node, this status MUST be sent in response to any error not covered by one of the other status types."
// section 2.21.3: "If a peer parsing a request notices that it is badly formatted (after it has passed the message authentication code checks and window checks) and it returns an INVALID_SYNTAX notification, then this error notification is considered fatal in both peers, meaning that the IKE SA is deleted without needing an explicit Delete payload."
// section 1.3.2 gives an IKE SA rekey request as "HDR, SK {SA, Ni, KEi}", and section 1.3.3 a Child SA rekey request as "HDR, SK {N(REKEY_SA), SA, Ni, [KEi,] TSi, TSr}"
// section 2.7: "An SA payload consists of one or more proposals."
// section 2.9: "Each TS payload contains one or more Traffic Selectors."
// section 3.9: "The size of the Nonce Data MUST be between 16 and 256 octets, inclusive."
// section 2.18 on NONE for the Diffie-Hellman transform of an IKE SA rekey: "a responder MUST NOT accept such a proposal."
// a CREATE_CHILD_SA request outside its figure, or with a payload that does not decode, an SA payload of no proposal or a TS payload of no selector, draws INVALID_SYNTAX and ends the IKE SA
// one that parses and asks for what this end does not take draws the notify that says so, and the IKE SA and its Child SA stay
func TestSessionAnswersAMalformedCreateChildSAWithInvalidSyntax(t *testing.T) {
	child := ChildSA{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, LocalSPI: 0x10203040, RemoteSPI: 0x50607080}
	with := func(base []RawPayload, more ...RawPayload) []RawPayload { return append(slices.Clone(base), more...) }
	without := func(base []RawPayload, gone PayloadType) []RawPayload {
		return slices.DeleteFunc(slices.Clone(base), func(payload RawPayload) bool { return payload.Type == gone })
	}
	// replaced has payload in place of the first payload of its type
	replaced := func(base []RawPayload, payload RawPayload) []RawPayload {
		out := slices.Clone(base)
		out[slices.IndexFunc(out, func(held RawPayload) bool { return held.Type == payload.Type })] = payload
		return out
	}
	rekeySA := func(protocol ProtocolID, spi []byte) RawPayload {
		return RawPayload{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_REKEY_SA, Protocol: protocol, SPI: spi})}
	}
	childSA := func(transforms ...Transform) RawPayload {
		return RawPayload{Type: PayloadSA, Body: EncodeSA([]Proposal{{Number: 1, Protocol: ProtoESP, SPI: binary.BigEndian.AppendUint32(nil, 0x90a0b0c0), Transforms: transforms}})}
	}
	ke := func(group uint16, value []byte) RawPayload {
		return RawPayload{Type: PayloadKE, Body: EncodeKE(group, value)}
	}
	dh, err := GenerateDH(DH_CURVE25519)
	if err != nil {
		t.Fatal(err)
	}
	aes, noESN := Transform{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128}, Transform{Type: TransESN, ID: ESN_NO}
	rekey, ikeRekey := childRekeyRequest(child.RemoteSPI), ikeRekeyRequest(t)
	// a Child SA rekey asking for a Curve25519 exchange, whose KE payload each row gives
	pfs := replaced(rekey, childSA(aes, noESN, Transform{Type: TransDH, ID: DH_CURVE25519}))
	undecodable := RawPayload{Type: PayloadN, Body: []byte{0, 0, 0}}
	// an IKE SA rekey offer whose one PRF is not the one the IKE SA keeps
	otherPRF := RawPayload{Type: PayloadSA, Body: EncodeSA([]Proposal{ikeRekeyProposal(binary.BigEndian.AppendUint64(nil, 0x2122232425262728), PRF_HMAC_SHA2_384)})}
	// an IKE SA rekey offer whose one Diffie-Hellman transform is NONE
	noneDH := ikeRekeyProposal(binary.BigEndian.AppendUint64(nil, 0x2122232425262728), PRF_HMAC_SHA2_256)
	noneDH.Transforms = append(slices.DeleteFunc(noneDH.Transforms, func(transform Transform) bool { return transform.Type == TransDH }), Transform{Type: TransDH})
	offersNoneDH := RawPayload{Type: PayloadSA, Body: EncodeSA([]Proposal{noneDH})}
	// and one that lists NONE beside Curve25519, the group of ikeRekey's KE payload
	noneBeside := noneDH
	noneBeside.Transforms = append(slices.Clone(noneDH.Transforms), Transform{Type: TransDH, ID: DH_CURVE25519})
	offersNoneBesideAGroup := RawPayload{Type: PayloadSA, Body: EncodeSA([]Proposal{noneBeside})}
	answered := func(t *testing.T, s *Session, ctx *ikeContext, response *outbound, err error, want NotifyType) Notify {
		t.Helper()
		if ended := err != nil; ended != (want == N_INVALID_SYNTAX) {
			t.Errorf("the IKE SA ended %v (%v), want %v", ended, err, want == N_INVALID_SYNTAX)
		}
		if response == nil {
			t.Fatal("the request drew no answer")
		}
		message, decodeErr := DecodeMessage(response.whole)
		if decodeErr != nil {
			t.Fatalf("the request drew no answer: %v", decodeErr)
		}
		inner, decryptErr := DecryptMessage(ctx.suite, ctx.skei, response.whole, message)
		if decryptErr != nil || message.Header.ExchangeType != CREATE_CHILD_SA || message.Header.MessageID != 5 || len(inner) != 1 || inner[0].Type != PayloadN {
			t.Fatalf("the request drew exchange %d at Message ID %d carrying %v (%v), want one notify at 5", message.Header.ExchangeType, message.Header.MessageID, inner, decryptErr)
		}
		notify, decodeErr := DecodeNotify(inner[0].Body)
		if decodeErr != nil || notify.Type != want {
			t.Errorf("the request drew notify type %d (%v), want %d", notify.Type, decodeErr, want)
		}
		if got := s.currentChild(); got.LocalSPI != child.LocalSPI || got.RemoteSPI != child.RemoteSPI || s.currentContext() != ctx {
			t.Errorf("the Child SA is %08x and %08x and the IKE SA current %v, want both as they were", got.LocalSPI, got.RemoteSPI, s.currentContext() == ctx)
		}
		return notify
	}
	for name, test := range map[string]struct {
		inner []RawPayload
		want  NotifyType
	}{
		"Child SA rekey with a notify that does not decode":             {with(rekey, undecodable), N_INVALID_SYNTAX},
		"Child SA rekey with two SA payloads":                           {with(rekey, rekey[1]), N_INVALID_SYNTAX},
		"Child SA rekey with two nonces":                                {with(rekey, rekey[2]), N_INVALID_SYNTAX},
		"Child SA rekey with two TSi payloads":                          {with(rekey, rekey[3]), N_INVALID_SYNTAX},
		"Child SA rekey with two KE payloads":                           {with(pfs, ke(DH_CURVE25519, dh.PublicBytes()), ke(DH_CURVE25519, dh.PublicBytes())), N_INVALID_SYNTAX},
		"Child SA rekey with no SA payload":                             {without(rekey, PayloadSA), N_INVALID_SYNTAX},
		"Child SA rekey with no nonce":                                  {without(rekey, PayloadNonce), N_INVALID_SYNTAX},
		"Child SA rekey with no TSr payload":                            {without(rekey, PayloadTSr), N_INVALID_SYNTAX},
		"Child SA rekey with a nonce of 15 octets":                      {replaced(rekey, RawPayload{Type: PayloadNonce, Body: make([]byte, 15)}), N_INVALID_SYNTAX},
		"Child SA rekey with a nonce of 257 octets":                     {replaced(rekey, RawPayload{Type: PayloadNonce, Body: make([]byte, 257)}), N_INVALID_SYNTAX},
		"Child SA rekey whose REKEY_SA names the IKE SA":                {replaced(rekey, rekeySA(ProtoIKE, binary.BigEndian.AppendUint32(nil, child.RemoteSPI))), N_INVALID_SYNTAX},
		"Child SA rekey whose REKEY_SA SPI is 8 octets":                 {replaced(rekey, rekeySA(ProtoESP, binary.BigEndian.AppendUint64(nil, uint64(child.RemoteSPI)<<32))), N_INVALID_SYNTAX},
		"Child SA rekey whose SA payload does not decode":               {replaced(rekey, RawPayload{Type: PayloadSA, Body: []byte{0}}), N_INVALID_SYNTAX},
		"Child SA rekey whose SA payload carries no proposal":           {replaced(rekey, RawPayload{Type: PayloadSA}), N_INVALID_SYNTAX},
		"Child SA rekey whose TSi payload does not decode":              {replaced(rekey, RawPayload{Type: PayloadTSi, Body: []byte{1, 0, 0, 0}}), N_INVALID_SYNTAX},
		"Child SA rekey whose TSr payload carries no selector":          {replaced(rekey, RawPayload{Type: PayloadTSr, Body: EncodeTS(nil)}), N_INVALID_SYNTAX},
		"Child SA rekey whose KE payload does not decode":               {with(pfs, RawPayload{Type: PayloadKE, Body: []byte{0, 31}}), N_INVALID_SYNTAX},
		"Child SA rekey with a KE payload in group 0":                   {with(pfs, ke(0, dh.PublicBytes())), N_INVALID_SYNTAX},
		"Child SA rekey with a KE payload in group 14 carrying nothing": {with(pfs, ke(14, nil)), N_INVALID_SYNTAX},
		"Child SA rekey with a Curve25519 value of 31 octets":           {with(pfs, ke(DH_CURVE25519, make([]byte, 31))), N_INVALID_SYNTAX},
		"Child SA rekey offering a cipher this end does not implement":  {replaced(rekey, childSA(Transform{Type: TransEncr, ID: 3}, noESN)), N_NO_PROPOSAL_CHOSEN},
		"Child SA rekey with selectors narrower than this end takes":    {replaced(rekey, RawPayload{Type: PayloadTSi, Body: narrowSelectors()}), N_NO_PROPOSAL_CHOSEN},
		"Child SA rekey whose REKEY_SA names an AH SA":                  {replaced(rekey, rekeySA(ProtoAH, binary.BigEndian.AppendUint32(nil, child.RemoteSPI))), N_CHILD_SA_NOT_FOUND},
		"IKE SA rekey with a notify that does not decode":               {with(ikeRekey, undecodable), N_INVALID_SYNTAX},
		"IKE SA rekey with two SA payloads":                             {with(ikeRekey, ikeRekey[0]), N_INVALID_SYNTAX},
		"IKE SA rekey with two nonces":                                  {with(ikeRekey, ikeRekey[1]), N_INVALID_SYNTAX},
		"IKE SA rekey with two KE payloads":                             {with(ikeRekey, ikeRekey[2]), N_INVALID_SYNTAX},
		"IKE SA rekey with a TSi payload":                               {with(ikeRekey, RawPayload{Type: PayloadTSi, Body: fullRangeSelectors()}), N_INVALID_SYNTAX},
		"IKE SA rekey with a TSr payload":                               {with(ikeRekey, RawPayload{Type: PayloadTSr, Body: fullRangeSelectors()}), N_INVALID_SYNTAX},
		"IKE SA rekey with no nonce":                                    {without(ikeRekey, PayloadNonce), N_INVALID_SYNTAX},
		"IKE SA rekey with no KE payload":                               {without(ikeRekey, PayloadKE), N_INVALID_SYNTAX},
		"IKE SA rekey with a nonce of 15 octets":                        {replaced(ikeRekey, RawPayload{Type: PayloadNonce, Body: make([]byte, 15)}), N_INVALID_SYNTAX},
		"IKE SA rekey with a nonce of 257 octets":                       {replaced(ikeRekey, RawPayload{Type: PayloadNonce, Body: make([]byte, 257)}), N_INVALID_SYNTAX},
		"IKE SA rekey whose KE payload does not decode":                 {replaced(ikeRekey, RawPayload{Type: PayloadKE, Body: []byte{0, 31}}), N_INVALID_SYNTAX},
		"IKE SA rekey with a KE payload in group 0":                     {replaced(ikeRekey, ke(0, dh.PublicBytes())), N_INVALID_SYNTAX},
		"IKE SA rekey with a KE payload in group 14 carrying nothing":   {replaced(ikeRekey, ke(14, nil)), N_INVALID_SYNTAX},
		"IKE SA rekey with a Curve25519 value of 31 octets":             {replaced(ikeRekey, ke(DH_CURVE25519, make([]byte, 31))), N_INVALID_SYNTAX},
		"IKE SA rekey offering a PRF this end does not keep":            {replaced(ikeRekey, otherPRF), N_NO_PROPOSAL_CHOSEN},
		"IKE SA rekey offering NONE for Diffie-Hellman":                 {replaced(ikeRekey, offersNoneDH), N_NO_PROPOSAL_CHOSEN},
		"IKE SA rekey offering NONE beside Curve25519":                  {replaced(ikeRekey, offersNoneBesideAGroup), N_NO_PROPOSAL_CHOSEN},
	} {
		t.Run(name, bubble.Run(func(t *testing.T) {
			mux, _ := lifecycleMuxes(t)
			ctx := testContext()
			s := &Session{mux: mux, current: ctx, Child: child}
			raw, err := s.handleRequest(ctx, &Header{ExchangeType: CREATE_CHILD_SA, MessageID: 5}, nil, test.inner)
			notify := answered(t, s, ctx, raw, err, test.want)
			// section 2.25: "The SA that the initiator attempted to rekey is indicated by the SPI field in the Notify payload, which is copied from the SPI field in the REKEY_SA notification."
			if test.want == N_CHILD_SA_NOT_FOUND && (notify.Protocol != ProtoAH || !bytes.Equal(notify.SPI, binary.BigEndian.AppendUint32(nil, child.RemoteSPI))) {
				t.Errorf("CHILD_SA_NOT_FOUND names protocol %d SPI %x, want the REKEY_SA's AH and %08x", notify.Protocol, notify.SPI, child.RemoteSPI)
			}
		}))
	}
	// handleRequest takes an SA payload that does not decode or carries no proposal for a Child SA's, so the IKE SA rekey's own refusals are reached directly
	for name, body := range map[string][]byte{"does not decode": {0}, "carries no proposal": nil} {
		t.Run("IKE SA rekey whose SA payload "+name, bubble.Run(func(t *testing.T) {
			mux, _ := lifecycleMuxes(t)
			ctx := testContext()
			s := &Session{mux: mux, current: ctx, Child: child}
			raw, err := s.handleIKERekey(ctx, 5, replaced(ikeRekey, RawPayload{Type: PayloadSA, Body: body}))
			answered(t, s, ctx, raw, err, N_INVALID_SYNTAX)
		}))
	}
	// section 2.10's "half the key size of the negotiated pseudorandom function", under an IKE SA whose PRF is HMAC-SHA2-384 and an offer that keeps it
	for _, size := range []int{16, 23} {
		t.Run(fmt.Sprintf("IKE SA rekey under PRF_HMAC_SHA2_384 with a nonce of %d octets", size), bubble.Run(func(t *testing.T) {
			mux, _ := lifecycleMuxes(t)
			ctx := testContext()
			ctx.suite.PRFID = PRF_HMAC_SHA2_384
			s := &Session{mux: mux, current: ctx, Child: child}
			raw, err := s.handleRequest(ctx, &Header{ExchangeType: CREATE_CHILD_SA, MessageID: 5}, nil, replaced(replaced(ikeRekey, otherPRF), RawPayload{Type: PayloadNonce, Body: make([]byte, size)}))
			answered(t, s, ctx, raw, err, N_INVALID_SYNTAX)
		}))
	}
}

// section 2.21.3: "If a peer parsing a request notices that it is badly formatted (after it has passed the message authentication code checks and window checks) and it returns an INVALID_SYNTAX notification, then this error notification is considered fatal in both peers, meaning that the IKE SA is deleted without needing an explicit Delete payload."
// a running session answers a CREATE_CHILD_SA request carrying two nonces with INVALID_SYNTAX and ends, and sends nothing after
func TestSessionEndsWithoutADeleteOnceItAnswersInvalidSyntax(t *testing.T) {
	bubble.Run(testSessionEndsWithoutADeleteOnceItAnswersInvalidSyntax)(t)
}

func testSessionEndsWithoutADeleteOnceItAnswersInvalidSyntax(t *testing.T) {
	peer, s := closingAfterAuth(t)
	peer.to = muxLoopback(s.mux)
	done := runSession(t, s)
	request := childRekeyRequest(0x50607080)
	peer.send(t, Header{ExchangeType: CREATE_CHILD_SA, MessageID: 0}, append(request, request[2]))
	if answer := peer.answer(t); answer.Header.ExchangeType != CREATE_CHILD_SA || answer.Header.MessageID != 0 || !notified(answer.inner, N_INVALID_SYNTAX, nil) {
		t.Fatalf("the request drew exchange %d at Message ID %d carrying %v, want INVALID_SYNTAX at 0", answer.Header.ExchangeType, answer.Header.MessageID, answer.inner)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Error("the session ended with no error")
		}
	case <-time.After(answerBudget):
		t.Fatal("the session went on after answering INVALID_SYNTAX")
	}
	if err := peer.conn.SetReadDeadline(time.Now().Add(quietPeriod)); err != nil {
		t.Fatal(err)
	}
	if n, _, err := peer.conn.ReadFromUDP(make([]byte, 2048)); err == nil {
		t.Errorf("the session sent %d more bytes after INVALID_SYNTAX, want nothing", n)
	}
}

// RFC 7296 section 2.21.4: "A peer receiving such an unprotected Notify payload MUST NOT respond and MUST NOT change the state of any existing SAs."
// an INVALID_IKE_SPI in the clear under the IKE SA's SPIs, as the answer to the exchange under way and as a request, settles nothing and draws nothing
func TestSessionTakesNothingFromANotifyInTheClear(t *testing.T) {
	bubble.Run(testSessionTakesNothingFromANotifyInTheClear)(t)
}

func testSessionTakesNothingFromANotifyInTheClear(t *testing.T) {
	peer := listenPeer(t)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	mux, err := testNetwork(t).Dial(peerAddr.IP, peerAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	held := testContext()
	s := &Session{mux: mux, current: held}
	if err := mux.RegisterIKE(held.spiI); err != nil {
		t.Fatal(err)
	}
	result := make(chan requestResult, 1)
	waiting := &pendingRequest{localRequest: localRequest{exchange: INFORMATIONAL, result: result}, context: held, msgID: 3}
	pending := waiting
	// INVALID_IKE_SPI, the notify a node sends in the clear about a message under SPIs it does not know
	invalidSPI := []RawPayload{{Type: PayloadN, Body: EncodeNotify(Notify{Type: 4})}}
	for _, flags := range []uint8{FlagResponse, 0} {
		header := Header{SPIInitiator: held.spiI, SPIResponder: held.spiR, ExchangeType: INFORMATIONAL, Flags: flags, MessageID: 3}
		if _, err := peer.WriteToUDP(withNonESPMarker(encodeTestMessage(t, header, invalidSPI)), muxLoopback(mux)); err != nil {
			t.Fatal(err)
		}
		raw, source, err := mux.RecvIKEFromUntil(time.Now().Add(answerBudget))
		if err != nil {
			t.Fatal(err)
		}
		if s.dispatch(raw, source, &pending) {
			t.Errorf("the notify in the clear with flags %#x was taken as a fresh authenticated message", flags)
		}
	}
	if pending != waiting || len(result) != 0 {
		t.Error("a notify in the clear settled the exchange under way")
	}
	_ = peer.SetReadDeadline(time.Now().Add(quietPeriod))
	if _, _, err := peer.ReadFromUDP(make([]byte, 2048)); err == nil {
		t.Error("a notify in the clear drew an answer")
	}
}

// RFC 7296 section 2.21.4: "A node receiving a suspicious message from an IP address (and port, if NAT traversal is used) with which it has an IKE SA SHOULD send an IKE Notify payload in an IKE INFORMATIONAL exchange over that SA."
// section 2.21.4: "The recipient MUST NOT change the state of any SAs as a result"
// section 3.10.1: "Unrecognized error types in a request and status types in a request or response MUST be ignored, and they should be logged."
// an INFORMATIONAL request telling this end of INVALID_SPI for the SPI its Child SA sends with and of INVALID_IKE_SPI, and carrying an error notify and a status notify of types nothing assigns, is answered empty, and the IKE SA and the Child SA stay
func TestSessionChangesNothingForTheErrorNotifiesAPeerSends(t *testing.T) {
	bubble.Run(testSessionChangesNothingForTheErrorNotifiesAPeerSends)(t)
}

func testSessionChangesNothingForTheErrorNotifiesAPeerSends(t *testing.T) {
	peer := listenPeer(t)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	mux, err := testNetwork(t).Dial(peerAddr.IP, peerAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	held := testContext()
	s := &Session{mux: mux, current: held, Child: ChildSA{LocalSPI: 0x01020304, RemoteSPI: 0x50607080}}
	if err := mux.RegisterIKE(held.spiI); err != nil {
		t.Fatal(err)
	}
	header := Header{SPIInitiator: held.spiI, SPIResponder: held.spiR, ExchangeType: INFORMATIONAL, MessageID: 0}
	request, err := EncryptMessage(held.suite, held.sker, header, nil, []RawPayload{
		// INVALID_SPI, whose data section 1.5 gives as "the SPI of the invalid packet"
		{Type: PayloadN, Body: EncodeNotify(Notify{Type: 11, Data: binary.BigEndian.AppendUint32(nil, 0x50607080)})},
		// INVALID_IKE_SPI
		{Type: PayloadN, Body: EncodeNotify(Notify{Type: 4})},
		unrecognizedError,
		unrecognizedStatus,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := peer.WriteToUDP(withNonESPMarker(request), muxLoopback(mux)); err != nil {
		t.Fatal(err)
	}
	raw, source, err := mux.RecvIKEFromUntil(time.Now().Add(answerBudget))
	if err != nil {
		t.Fatal(err)
	}
	var pending *pendingRequest
	if !s.dispatch(raw, source, &pending) {
		t.Fatal("the INFORMATIONAL request was not taken")
	}
	buf := make([]byte, 2048)
	_ = peer.SetReadDeadline(time.Now().Add(answerBudget))
	n, _, err := peer.ReadFromUDP(buf)
	if err != nil || n <= 4 {
		t.Fatalf("the INFORMATIONAL request drew no answer: %d bytes, %v", n, err)
	}
	answer, err := DecodeMessage(buf[4:n])
	if err != nil {
		t.Fatal(err)
	}
	inner, err := DecryptMessage(held.suite, held.skei, buf[4:n], answer)
	if err != nil || answer.Header.MessageID != 0 || !answer.Header.IsResponse() || len(inner) != 0 {
		t.Errorf("the INFORMATIONAL request drew %v at Message ID %d (%v), want an empty answer at 0", inner, answer.Header.MessageID, err)
	}
	if mux.IsClosed() || s.Child.LocalSPI != 0x01020304 || s.Child.RemoteSPI != 0x50607080 {
		t.Errorf("the IKE SA is closed %v and the Child SA is %08x and %08x after the notifies, want both as they were", mux.IsClosed(), s.Child.LocalSPI, s.Child.RemoteSPI)
	}
}

// RFC 7296 section 2.5: "If an endpoint receives a message with a higher major version number, it MUST drop the message and SHOULD send an unauthenticated Notify message of type INVALID_MAJOR_VERSION containing the highest (closest) version number it supports."
// section 3.1 on the minor version: "They MUST ignore the minor version number of received messages."
// section 2.21.4: "If a response is sent, the response MUST be sent to the IP address and port from where it came with the same IKE SPIs and the Message ID copied."
// a Delete of the IKE SA at major version 3 that authenticates, sent from an address other than the peer's, is answered so in the clear at that address and not acted on, so the request at version 2.1 with the V bit and every X bit set after it takes the same Message ID
func TestSessionAnswersAHigherMajorVersionAndDropsIt(t *testing.T) {
	bubble.Run(testSessionAnswersAHigherMajorVersionAndDropsIt)(t)
}

func testSessionAnswersAHigherMajorVersionAndDropsIt(t *testing.T) {
	peer := listenPeer(t)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	mux, err := testNetwork(t).Dial(peerAddr.IP, peerAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	held := testContext()
	s := &Session{mux: mux, current: held}
	if err := mux.RegisterIKE(held.spiI); err != nil {
		t.Fatal(err)
	}

	var pending *pendingRequest
	buf := make([]byte, 2048)
	sender := listenPeer(t)
	answer := func(request []byte) (bool, []byte) {
		t.Helper()
		if _, err := sender.WriteToUDP(withNonESPMarker(request), muxLoopback(mux)); err != nil {
			t.Fatal(err)
		}
		raw, source, err := mux.RecvIKEFromUntil(time.Now().Add(answerBudget))
		if err != nil {
			t.Fatal(err)
		}
		taken := s.dispatch(raw, source, &pending)
		if err := sender.SetReadDeadline(time.Now().Add(answerBudget)); err != nil {
			t.Fatal(err)
		}
		n, _, err := sender.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("the request drew no answer: %v", err)
		}
		return taken, slices.Clone(buf[4:n])
	}
	header := Header{SPIInitiator: held.spiI, SPIResponder: held.spiR, ExchangeType: INFORMATIONAL, MessageID: 0}
	deletion := sealedEdited(t, held.suite, held.sker, header, deleteIKEPayloads(), atMajorVersion3)
	taken, reply := answer(deletion)
	if taken {
		t.Fatal("the Delete at major version 3 was taken as a fresh authenticated request")
	}
	wantMajorVersionRefusal(t, reply, header)
	sender = peer
	// section 3.1 on the X bits: "'X' bits MUST be cleared when sending and MUST be ignored on receipt."
	// section 3.1 on the V bit: "Implementations of IKEv2 MUST clear this bit when sending and MUST ignore it in incoming messages."
	header.Flags |= FlagVersion | 0xc7

	taken, reply = answer(sealedEdited(t, held.suite, held.sker, header, nil, atMinorVersion1))
	// section 2.5: "If it receives a message with a major version that it supports, it MUST respond with that version number."
	if reply[17] != 0x20 {
		t.Errorf("the answer's version octet is %#x, want 2.0", reply[17])
	}
	// section 3.1 on the I bit: "This bit MUST be set in messages sent by the original initiator of the IKE SA and MUST be cleared in messages sent by the original responder."
	if reply[19] != FlagInitiator|FlagResponse {
		t.Errorf("the answer's flags are %#x, want the Initiator and Response bits alone", reply[19])
	}
	message, err := DecodeMessage(reply)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := DecryptMessage(held.suite, held.skei, reply, message)
	if !taken || err != nil || message.Header.MessageID != 0 || len(inner) != 0 {
		t.Errorf("the request at version 2.1 after it drew %v at Message ID %d (%v), want an empty answer at 0", inner, message.Header.MessageID, err)
	}
}

// RFC 7296 section 3.2 on the critical bit: "MUST be ignored by the recipient if the recipient understands the payload type code."
// section 2.5: "If the critical flag is set and the payload type is unrecognized, the message MUST be rejected"
// section 2.5: "If the critical flag is not set and the payload type is unsupported, that payload MUST be ignored."
// section 2.5: "Payloads sent in IKE response messages MUST NOT have the critical flag set."
// a request or response marking every payload critical, its SK payload, a Vendor ID and a Delete the exchange does not take among them, and adding one of a type nothing assigns unmarked, is taken as one marking none, and the answers mark nothing
// one carrying a critical payload of a type nothing assigns is refused, in the clear ahead of SK as inside it
// section 2.21.3 on errors in a response: "Because sending such error messages as an INFORMATIONAL exchange might lead to further errors that could cause loops, such errors SHOULD NOT be sent."
// so the response refused draws nothing
func TestSessionHeedsTheCriticalBitOnlyOnAnUnsupportedType(t *testing.T) {
	bubble.Run(testSessionHeedsTheCriticalBitOnlyOnAnUnsupportedType)(t)
}

func testSessionHeedsTheCriticalBitOnlyOnAnUnsupportedType(t *testing.T) {
	peer := listenPeer(t)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	mux, err := testNetwork(t).Dial(peerAddr.IP, peerAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	held := testContext()
	held.skD = []byte("test child creation SK_d material")
	s := &Session{mux: mux, current: held}
	if err := mux.RegisterIKE(held.spiI); err != nil {
		t.Fatal(err)
	}

	var pending *pendingRequest
	deliver := func(raw []byte) bool {
		t.Helper()
		if _, err := peer.WriteToUDP(withNonESPMarker(raw), muxLoopback(mux)); err != nil {
			t.Fatal(err)
		}
		got, source, err := mux.RecvIKEFromUntil(time.Now().Add(answerBudget))
		if err != nil {
			t.Fatal(err)
		}
		return s.dispatch(got, source, &pending)
	}
	buf := make([]byte, 2048)
	answer := func() (Header, []RawPayload) {
		t.Helper()
		if err := peer.SetReadDeadline(time.Now().Add(answerBudget)); err != nil {
			t.Fatal(err)
		}
		n, _, err := peer.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("the request drew no answer: %v", err)
		}
		raw := slices.Clone(buf[4:n])
		message, err := DecodeMessage(raw)
		if err != nil {
			t.Fatal(err)
		}
		inner, err := DecryptMessage(held.suite, held.skei, raw, message)
		if err != nil {
			t.Fatal(err)
		}
		if raw[HeaderLen+1]&0x80 != 0 {
			t.Error("the answer marks its SK payload critical")
		}
		for _, payload := range inner {
			if payload.Critical {
				t.Errorf("the answer marks payload type %d critical", payload.Type)
			}
		}
		return message.Header, inner
	}
	marked := func(payloads ...RawPayload) []RawPayload {
		for i := range payloads {
			payloads[i].Critical = true
		}
		return append(payloads, RawPayload{Type: PayloadType(250), Body: []byte{1}})
	}
	vendor := RawPayload{Type: PayloadV, Body: []byte("a vendor this end does not know")}
	deletion := RawPayload{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoESP, SPIs: [][]byte{{0, 0, 0, 9}}})}

	// a Child SA asked for with no REKEY_SA, which this end creates while it holds none
	create := marked(append(childRekeyRequest(0)[1:], vendor, deletion)...)
	header := Header{SPIInitiator: held.spiI, SPIResponder: held.spiR, ExchangeType: CREATE_CHILD_SA, MessageID: 0}
	if !deliver(sealedEdited(t, held.suite, held.sker, header, create, criticalSK)) {
		t.Fatal("the Child SA request marking every payload critical was not taken")
	}
	if got, inner := answer(); got.MessageID != 0 || len(inner) == 0 || inner[0].Type != PayloadSA {
		t.Errorf("the Child SA request marking every payload critical drew %v at Message ID %d, want the Child SA at 0", inner, got.MessageID)
	}

	header = Header{SPIInitiator: held.spiI, SPIResponder: held.spiR, ExchangeType: INFORMATIONAL, MessageID: 1}
	inTheClear, err := EncryptMessage(held.suite, held.sker, header, []RawPayload{unsupportedCritical}, nil)
	if err != nil {
		t.Fatal(err)
	}
	deliver(inTheClear)
	if got, inner := answer(); got.MessageID != 1 || !notified(inner, N_UNSUPPORTED_CRITICAL_PAYLOAD, []byte{byte(unsupportedCritical.Type)}) {
		t.Errorf("the request with a critical payload in the clear drew %v at Message ID %d, want UNSUPPORTED_CRITICAL_PAYLOAD for type %d at 1", inner, got.MessageID, unsupportedCritical.Type)
	}

	for messageID, response := range []struct {
		inner []RawPayload
		taken bool
	}{
		{marked(RawPayload{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_INITIAL_CONTACT})}, vendor), true},
		{[]RawPayload{unsupportedCritical}, false},
	} {
		result := make(chan requestResult, 1)
		pending = &pendingRequest{localRequest: localRequest{exchange: INFORMATIONAL, result: result}, context: held, msgID: uint32(messageID)}
		header := Header{SPIInitiator: held.spiI, SPIResponder: held.spiR, ExchangeType: INFORMATIONAL, Flags: FlagResponse, MessageID: uint32(messageID)}
		deliver(sealedEdited(t, held.suite, held.sker, header, response.inner, criticalSK))
		select {
		case got := <-result:
			if taken := got.err == nil && samePayloads(got.inner, response.inner); taken != response.taken {
				t.Errorf("the response carrying %v was taken %v (%v), want %v", response.inner, taken, got.err, response.taken)
			}
		default:
			t.Errorf("the response carrying %v settled nothing", response.inner)
		}
	}
	_ = peer.SetReadDeadline(time.Now().Add(quietPeriod))
	if n, _, err := peer.ReadFromUDP(buf); err == nil {
		t.Errorf("the responses drew %d bytes", n)
	}
}

// RFC 7296 section 2.5: "If the critical flag is set and the payload type is unrecognized, the message MUST be rejected and the response to the IKE request containing that payload MUST include a Notify payload UNSUPPORTED_CRITICAL_PAYLOAD, indicating an unsupported critical payload was included. In that Notify payload, the Notification Data contains the one-octet payload type."
// a request for a Child SA carrying a critical payload of a type nothing assigns, inside SK or in the clear ahead of it, draws that notify naming the type and creates nothing
func TestSessionRefusesACreateChildSAMarkingAnUnsupportedPayloadCritical(t *testing.T) {
	for placement, request := range map[string]struct{ cleartext, inner []RawPayload }{
		"inside SK":    {nil, append(childRekeyRequest(0)[1:], unsupportedCritical)},
		"in the clear": {[]RawPayload{unsupportedCritical}, childRekeyRequest(0)[1:]},
	} {
		t.Run(placement, bubble.Run(func(t *testing.T) {
			peer := listenPeer(t)
			peerAddr := peer.LocalAddr().(*net.UDPAddr)
			mux, err := testNetwork(t).Dial(peerAddr.IP, peerAddr.Port)
			if err != nil {
				t.Fatal(err)
			}
			defer mux.Close()
			held := testContext()
			held.skD = []byte("test child creation SK_d material")
			s := &Session{mux: mux, current: held}
			if err := mux.RegisterIKE(held.spiI); err != nil {
				t.Fatal(err)
			}
			header := Header{SPIInitiator: held.spiI, SPIResponder: held.spiR, ExchangeType: CREATE_CHILD_SA, MessageID: 0}
			raw, err := EncryptMessage(held.suite, held.sker, header, request.cleartext, request.inner)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := peer.WriteToUDP(withNonESPMarker(raw), muxLoopback(mux)); err != nil {
				t.Fatal(err)
			}
			got, source, err := mux.RecvIKEFromUntil(time.Now().Add(answerBudget))
			if err != nil {
				t.Fatal(err)
			}
			var pending *pendingRequest
			if !s.dispatch(got, source, &pending) {
				t.Fatal("the request was not taken as a fresh authenticated request")
			}
			buf := make([]byte, 2048)
			if err := peer.SetReadDeadline(time.Now().Add(answerBudget)); err != nil {
				t.Fatal(err)
			}
			n, _, err := peer.ReadFromUDP(buf)
			if err != nil {
				t.Fatalf("the request drew no answer: %v", err)
			}
			answer, err := DecodeMessage(buf[4:n])
			if err != nil {
				t.Fatal(err)
			}
			inner, err := DecryptMessage(held.suite, held.skei, buf[4:n], answer)
			if err != nil {
				t.Fatal(err)
			}
			if answer.Header.ExchangeType != CREATE_CHILD_SA || answer.Header.MessageID != 0 || !notified(inner, N_UNSUPPORTED_CRITICAL_PAYLOAD, []byte{byte(unsupportedCritical.Type)}) {
				t.Errorf("the request drew exchange %d Message ID %d carrying %v, want UNSUPPORTED_CRITICAL_PAYLOAD for type %d at 0",
					answer.Header.ExchangeType, answer.Header.MessageID, inner, unsupportedCritical.Type)
			}
			if child := s.currentChild(); child.LocalSPI != 0 || mux.IsClosed() {
				t.Errorf("the refused request left Child SA %08x and the IKE SA closed %v, want no Child SA and the IKE SA open", child.LocalSPI, mux.IsClosed())
			}
		}))
	}
}

// RFC 7296 section 2.21.3 on errors in a response: "Because sending such error messages as an INFORMATIONAL exchange might lead to further errors that could cause loops, such errors SHOULD NOT be sent."
// a response to the exchange under way that authenticates and whose payloads do not parse ends that exchange with an error and draws nothing
func TestSessionSaysNothingOfAMalformedResponse(t *testing.T) {
	bubble.Run(testSessionSaysNothingOfAMalformedResponse)(t)
}

func testSessionSaysNothingOfAMalformedResponse(t *testing.T) {
	peer := listenPeer(t)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	mux, err := testNetwork(t).Dial(peerAddr.IP, peerAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	held := testContext()
	s := &Session{mux: mux, current: held}
	if err := mux.RegisterIKE(held.spiI); err != nil {
		t.Fatal(err)
	}
	result := make(chan requestResult, 1)
	pending := &pendingRequest{localRequest: localRequest{exchange: INFORMATIONAL, result: result}, context: held, msgID: 3}
	// a Notify whose stated length is shorter than its own header, then no padding
	header := Header{SPIInitiator: held.spiI, SPIResponder: held.spiR, ExchangeType: INFORMATIONAL, Flags: FlagResponse, MessageID: 3}
	malformed, err := encryptMessagePlaintextIV(held.suite, held.sker, header, nil, PayloadN, []byte{0, 0, 0, 3, 0}, make([]byte, 8))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := peer.WriteToUDP(withNonESPMarker(malformed), muxLoopback(mux)); err != nil {
		t.Fatal(err)
	}
	raw, source, err := mux.RecvIKEFromUntil(time.Now().Add(answerBudget))
	if err != nil {
		t.Fatal(err)
	}
	if !s.dispatch(raw, source, &pending) {
		t.Fatal("the malformed response was not taken as an authenticated message")
	}
	select {
	case got := <-result:
		if got.err == nil {
			t.Errorf("the malformed response settled the exchange with %v", got.inner)
		}
	default:
		t.Error("the malformed response settled nothing")
	}
	_ = peer.SetReadDeadline(time.Now().Add(quietPeriod))
	if n, _, err := peer.ReadFromUDP(make([]byte, 2048)); err == nil {
		t.Errorf("the malformed response drew %d bytes", n)
	}
}

func TestChildRequestRejectionNotifications(t *testing.T) {
	const unknownSPI = 0x10203040
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	ikeCtx := &ikeContext{
		suite: suite,
		spiI:  0x0102030405060708,
		spiR:  0x1112131415161718,
		skei:  make([]byte, 20),
		sker:  make([]byte, 20),
	}
	s := &Session{current: ikeCtx, Child: ChildSA{RemoteSPI: 0x50607080}}
	newSPI := make([]byte, 4)
	binary.BigEndian.PutUint32(newSPI, 0x90a0b0c0)
	base := []RawPayload{
		{Type: PayloadSA, Body: EncodeSA([]Proposal{{
			Number: 1, Protocol: ProtoESP, SPI: newSPI,
			Transforms: []Transform{{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128}, {Type: TransESN, ID: ESN_NO}},
		}})},
		{Type: PayloadNonce, Body: EncodeNonce(make([]byte, 32))},
		{Type: PayloadTSi, Body: fullRangeSelectors()},
		{Type: PayloadTSr, Body: fullRangeSelectors()},
	}

	decodeResponse := func(response *outbound) Notify {
		t.Helper()
		message, err := DecodeMessage(response.whole)
		if err != nil {
			t.Fatal(err)
		}
		inner, err := DecryptMessage(suite, ikeCtx.skei, response.whole, message)
		if err != nil {
			t.Fatal(err)
		}
		if len(inner) != 1 || inner[0].Type != PayloadN {
			t.Fatalf("response payloads = %#v, want one Notify", inner)
		}
		notify, err := DecodeNotify(inner[0].Body)
		if err != nil {
			t.Fatal(err)
		}
		return notify
	}

	dh, err := GenerateDH(DH_CURVE25519)
	if err != nil {
		t.Fatal(err)
	}
	additionalRequest := append([]RawPayload(nil), base[:2]...)
	additionalRequest = append(additionalRequest, RawPayload{Type: PayloadKE, Body: EncodeKE(DH_CURVE25519, dh.PublicBytes())})
	additionalRequest = append(additionalRequest, base[2:]...)
	response, err := s.handleChildRekey(ikeCtx, 1, additionalRequest)
	if err != nil {
		t.Fatal(err)
	}
	additional := decodeResponse(response)
	if additional.Type != N_NO_ADDITIONAL_SAS || additional.Protocol != 0 || len(additional.SPI) != 0 {
		t.Fatalf("additional Child SA rejection = %#v", additional)
	}

	unknown := make([]byte, 4)
	binary.BigEndian.PutUint32(unknown, unknownSPI)
	rekey := append([]RawPayload{{Type: PayloadN, Body: EncodeNotify(Notify{Protocol: ProtoESP, SPI: unknown, Type: N_REKEY_SA})}}, base...)
	response, err = s.handleChildRekey(ikeCtx, 2, rekey)
	if err != nil {
		t.Fatal(err)
	}
	notFound := decodeResponse(response)
	if notFound.Type != N_CHILD_SA_NOT_FOUND || notFound.Protocol != ProtoESP || !bytes.Equal(notFound.SPI, unknown) {
		t.Fatalf("unknown Child SA rejection = %#v", notFound)
	}
}

func TestChildRequestCreatesMissingChild(t *testing.T) {
	bubble.Run(testChildRequestCreatesMissingChild)(t)
}

func testChildRequestCreatesMissingChild(t *testing.T) {
	mux, _ := lifecycleMuxes(t)
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	ikeCtx := &ikeContext{
		suite: suite,
		spiI:  0x0102030405060708,
		spiR:  0x1112131415161718,
		skei:  make([]byte, 20),
		sker:  make([]byte, 20),
		skD:   []byte("test child creation SK_d material"),
	}
	s := &Session{mux: mux, current: ikeCtx}
	remoteSPI := make([]byte, 4)
	binary.BigEndian.PutUint32(remoteSPI, 0x50607080)
	request := []RawPayload{
		{Type: PayloadSA, Body: EncodeSA([]Proposal{{
			Number: 1, Protocol: ProtoESP, SPI: remoteSPI,
			Transforms: []Transform{{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128}, {Type: TransESN, ID: ESN_NO}},
		}})},
		{Type: PayloadNonce, Body: EncodeNonce(make([]byte, 32))},
		{Type: PayloadTSi, Body: fullRangeSelectors()},
		{Type: PayloadTSr, Body: fullRangeSelectors()},
	}
	response, err := s.handleChildRekey(ikeCtx, 1, request)
	if err != nil {
		t.Fatal(err)
	}
	message, err := DecodeMessage(response.whole)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := DecryptMessage(suite, ikeCtx.skei, response.whole, message)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeChildExchangePayloads(inner, PRF_HMAC_SHA2_256); err != nil {
		t.Fatalf("invalid Child SA creation response: %v", err)
	}
	child := s.currentChild()
	if child.LocalSPI == 0 || child.RemoteSPI != 0x50607080 || len(child.InboundKey) == 0 || len(child.OutboundKey) == 0 {
		t.Fatalf("created Child SA = %#v", child)
	}
}

func TestInformationalDeletesEveryDesignatedChildSA(t *testing.T) {
	bubble.Run(testInformationalDeletesEveryDesignatedChildSA)(t)
}

func testInformationalDeletesEveryDesignatedChildSA(t *testing.T) {
	mux, other := lifecycleMuxes(t)
	current := ChildSA{LocalSPI: 0x10203040, RemoteSPI: 0x50607080}
	retiring := ChildSA{LocalSPI: 0x90a0b0c0, RemoteSPI: 0xd0e0f000}
	if err := mux.RegisterESP(current.LocalSPI); err != nil {
		t.Fatal(err)
	}
	if err := mux.RegisterESP(retiring.LocalSPI); err != nil {
		t.Fatal(err)
	}
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	ikeCtx := &ikeContext{
		suite: suite,
		spiI:  0x0102030405060708,
		spiR:  0x1112131415161718,
		skei:  make([]byte, 20),
		sker:  make([]byte, 20),
	}
	s := &Session{mux: mux, current: ikeCtx, Child: current, retiring: retiring}
	var retired []uint32
	s.SetChildRetireHandler(func(localSPI uint32) error {
		retired = append(retired, localSPI)
		return nil
	})
	spi := func(value uint32) []byte {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, value)
		return b
	}
	response, err := s.handleRequest(ikeCtx, &Header{ExchangeType: INFORMATIONAL, MessageID: 4}, nil, []RawPayload{
		{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoESP, SPIs: [][]byte{spi(current.RemoteSPI), spi(0xdeadbeef)}})},
		{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoESP, SPIs: [][]byte{spi(retiring.RemoteSPI)}})},
	})
	if err != nil {
		t.Fatal(err)
	}
	message, err := DecodeMessage(response.whole)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := DecryptMessage(suite, ikeCtx.skei, response.whole, message)
	if err != nil {
		t.Fatal(err)
	}
	if len(inner) != 1 || inner[0].Type != PayloadD {
		t.Fatalf("Delete response payloads = %#v", inner)
	}
	deleted, err := DecodeDelete(inner[0].Body)
	if err != nil {
		t.Fatal(err)
	}
	if deleted.Protocol != ProtoESP || len(deleted.SPIs) != 2 || binary.BigEndian.Uint32(deleted.SPIs[0]) != current.LocalSPI || binary.BigEndian.Uint32(deleted.SPIs[1]) != retiring.LocalSPI {
		t.Fatalf("Delete response = %#v", deleted)
	}
	if len(retired) != 2 || retired[0] != current.LocalSPI || retired[1] != retiring.LocalSPI {
		t.Fatalf("retired SPIs = %08x", retired)
	}
	if got := s.currentChild(); got.LocalSPI != 0 || got.RemoteSPI != 0 {
		t.Fatalf("current Child SA remains: %#v", got)
	}
	if got := s.retiringChild(); got.LocalSPI != 0 || got.RemoteSPI != 0 {
		t.Fatalf("retiring Child SA remains: %#v", got)
	}
	if err := other.RegisterESP(current.LocalSPI); err != nil {
		t.Fatalf("current inbound SPI remains registered: %v", err)
	}
	if err := other.RegisterESP(retiring.LocalSPI); err != nil {
		t.Fatalf("retiring inbound SPI remains registered: %v", err)
	}
}

// RFC 7296 section 2.21.2: "In an IKE_AUTH exchange, or in the INFORMATIONAL exchange immediately following it (in case an error happened when processing a response to IKE_AUTH), the UNSUPPORTED_CRITICAL_PAYLOAD, INVALID_SYNTAX, and AUTHENTICATION_FAILED notifications are the only ones to cause the IKE SA to be deleted or not created, without a Delete payload."
// a responder's session therefore ends on one at the Message ID after its IKE_AUTH on the SA IKE_AUTH made, 2 or one more for each IKE_INTERMEDIATE, and keeps the SA on one anywhere else
func TestAuthenticationFailureEndsOnlyTheSAWhoseIKEAuthItFollows(t *testing.T) {
	notify := func(kind NotifyType, data ...byte) []RawPayload {
		return []RawPayload{{Type: PayloadN, Body: EncodeNotify(Notify{Type: kind, Data: data})}}
	}
	for name, test := range map[string]struct {
		answeredAuth       bool
		authMID, messageID uint32
		inner              []RawPayload
		ends               bool
	}{
		"AUTHENTICATION_FAILED right after IKE_AUTH":                          {true, 1, 2, notify(N_AUTHENTICATION_FAILED), true},
		"INVALID_SYNTAX right after IKE_AUTH":                                 {true, 1, 2, notify(N_INVALID_SYNTAX), true},
		"UNSUPPORTED_CRITICAL_PAYLOAD right after IKE_AUTH":                   {true, 1, 2, notify(N_UNSUPPORTED_CRITICAL_PAYLOAD, byte(PayloadD)), true},
		"AUTHENTICATION_FAILED in a later exchange":                           {true, 1, 3, notify(N_AUTHENTICATION_FAILED), false},
		"AUTHENTICATION_FAILED on an SA a rekey made":                         {false, 0, 2, notify(N_AUTHENTICATION_FAILED), false},
		"another error right after IKE_AUTH":                                  {true, 1, 2, notify(N_NO_PROPOSAL_CHOSEN), false},
		"AUTHENTICATION_FAILED right after an IKE_AUTH at Message ID 2":       {true, 2, 3, notify(N_AUTHENTICATION_FAILED), true},
		"AUTHENTICATION_FAILED at Message ID 2 after an IKE_INTERMEDIATE ran": {true, 2, 2, notify(N_AUTHENTICATION_FAILED), false},
	} {
		t.Run(name, func(t *testing.T) {
			ikeCtx := testContext()
			ikeCtx.responder, ikeCtx.answeredAuth, ikeCtx.authMID = true, test.answeredAuth, test.authMID
			s := &Session{current: ikeCtx}
			response, err := s.handleRequest(ikeCtx, &Header{ExchangeType: INFORMATIONAL, MessageID: test.messageID}, nil, test.inner)
			if ended := err != nil; ended != test.ends {
				t.Errorf("the session ended %v (%v), want %v", ended, err, test.ends)
			}
			if response == nil {
				t.Fatal("the request drew no answer")
			}
			message, err := DecodeMessage(response.whole)
			if err != nil {
				t.Fatalf("the request drew no answer: %v", err)
			}
			inner, err := DecryptMessage(ikeCtx.suite, ikeCtx.sker, response.whole, message)
			if err != nil || len(inner) != 0 || message.Header.MessageID != test.messageID {
				t.Errorf("the answer is %v at Message ID %d (%v), want an empty one at %d", inner, message.Header.MessageID, err, test.messageID)
			}
		})
	}
}

func TestInitialResponseHeaderValidation(t *testing.T) {
	req := &Header{SPIInitiator: 1, SPIResponder: 0, ExchangeType: IKE_SA_INIT, Flags: FlagInitiator, MessageID: 0}
	valid := &Header{SPIInitiator: 1, SPIResponder: 2, MajorVersion: 2, ExchangeType: IKE_SA_INIT, Flags: FlagResponse, MessageID: 0, Length: HeaderLen}
	if !validResponseHeader(req, valid, HeaderLen) {
		t.Fatal("valid initial response rejected")
	}
	initialError := *valid
	initialError.SPIResponder = 0
	if !validResponseHeader(req, &initialError, HeaderLen) {
		t.Fatal("valid initial error response rejected")
	}
	// RFC 7296 section 3.1 on the minor version: "They MUST ignore the minor version number of received messages."
	// and on the V flag: "Implementations of IKEv2 MUST clear this bit when sending and MUST ignore it in incoming messages."
	// and on the X bits: "'X' bits MUST be cleared when sending and MUST be ignored on receipt."
	for name, ignored := range map[string]func(*Header){
		"minor version 1": func(h *Header) { h.MinorVersion = 1 },
		"V flag":          func(h *Header) { h.Flags |= FlagVersion },
		"X bits":          func(h *Header) { h.Flags |= 0xc7 },
	} {
		got := *valid
		ignored(&got)
		if !validResponseHeader(req, &got, HeaderLen) {
			t.Errorf("a response with the %s was rejected", name)
		}
	}
	mutations := []func(*Header){
		func(h *Header) { h.MajorVersion = 3 }, func(h *Header) { h.ExchangeType = IKE_AUTH },
		func(h *Header) { h.Flags |= FlagInitiator },
		func(h *Header) { h.SPIInitiator++ }, func(h *Header) { h.MessageID++ },
		func(h *Header) { h.Length++ },
	}
	for i, mutate := range mutations {
		got := *valid
		mutate(&got)
		if validResponseHeader(req, &got, HeaderLen) {
			t.Errorf("invalid header mutation %d accepted: %+v", i, got)
		}
	}
}

func TestSetRekeyRetry(t *testing.T) {
	s := new(Session)
	if err := s.SetRekeyRetry(5*time.Second, time.Minute); err != nil {
		t.Fatal(err)
	}
	if s.rekeyRetryInitial != 5*time.Second || s.rekeyRetryMax != time.Minute {
		t.Fatalf("retry delays = %s, %s", s.rekeyRetryInitial, s.rekeyRetryMax)
	}
	for _, delays := range [][2]time.Duration{{0, time.Second}, {time.Second, 0}, {-time.Second, time.Second}, {time.Minute, time.Second}} {
		if err := s.SetRekeyRetry(delays[0], delays[1]); err == nil {
			t.Fatalf("SetRekeyRetry(%s, %s) succeeded", delays[0], delays[1])
		}
	}
	if err := s.SetRekeyRetry(0, 0); err != nil {
		t.Fatalf("SetRekeyRetry(0, 0) refused: %v", err)
	}
	if s.rekeyRetryInitial != 0 || s.rekeyRetryMax != 0 {
		t.Errorf("after SetRekeyRetry(0, 0) the retry delays are %s, %s, want both zero", s.rekeyRetryInitial, s.rekeyRetryMax)
	}
}

// Active compares against a window of seconds, so measuring it on the wall
// clock makes every session on the node flip together on any step larger than
// that: a laptop waking, an NTP correction at boot, a VM resuming. A wall step
// cannot be produced in-process, so pin the representation instead. A unix
// nanosecond timestamp is six orders of magnitude larger than any offset from
// a session's own start.
func TestLivenessClockIsOffsetRatherThanWallTimestamp(t *testing.T) {
	s := &Session{started: time.Now()}
	s.noteEstablished()
	if got := s.lastActive.Load(); got <= 0 || got > int64(time.Hour) {
		t.Fatalf("lastActive = %d, want a small offset from the session start", got)
	}
	if !s.Active() {
		t.Error("a session that has just been established reads as dead")
	}
}

func TestActiveExpiresAndComesBack(t *testing.T) {
	s := &Session{started: time.Now().Add(-time.Hour)}
	s.lastActive.Store(1) // last proof of life at the session's start
	if s.Active() {
		t.Fatal("a session last active an hour ago reads as live")
	}
	s.noteActive()
	if !s.Active() {
		t.Error("a session that just proved itself still reads as dead")
	}
}

// An exchange holds the one outstanding local request IKEv2 allows, so while
// it is open there is no rekey, no Delete on teardown and no dead peer
// detection, and the session reports up. A peer that keeps ESP flowing and
// never answers IKE, which RFC 4303 section 2.6 dummy packets alone are enough
// for, must not be able to pin it until the sequence space runs out.
func TestUnansweredExchangeStillEnds(t *testing.T) {
	ordinary := &pendingRequest{}
	for range maxRetransmits {
		ordinary.attempts = min(ordinary.attempts+1, maxRetransmits)
		ordinary.sent++
	}
	if pendingRetransmitsExhausted(ordinary, true) {
		t.Fatal("an exchange gave up at the ordinary limit while the peer was still proving it is there")
	}
	if !pendingRetransmitsExhausted(ordinary, false) {
		t.Fatal("an exchange to a silent peer did not give up at the ordinary limit")
	}
	for ordinary.sent < maxRetransmitsWhileBusy {
		ordinary.sent++
	}
	if !pendingRetransmitsExhausted(ordinary, true) {
		t.Errorf("an exchange retransmitted %d times against a peer that answers ESP and not IKE, with no end in sight", ordinary.sent)
	}

	// Dead peer detection keeps its own tighter bound, because that exchange
	// exists to decide exactly this.
	dpd := &pendingRequest{localRequest: localRequest{dpd: true}, attempts: maxRetransmits, sent: maxRetransmits}
	if !pendingRetransmitsExhausted(dpd, true) {
		t.Error("a liveness check kept retransmitting because other traffic was arriving")
	}
}

// a Delete of an IKE SA ends after teardownRetransmits sends, whether or not the peer keeps other traffic coming
// the budget goes by what the request deletes, so it is the same whoever sent the Delete, Run's own teardown or a caller
func TestDeleteEndingAnIKESAHasTheTeardownBudget(t *testing.T) {
	ender := &pendingRequest{localRequest: localRequest{inner: deleteIKEPayloads()}}
	for ender.sent < teardownRetransmits-1 {
		ender.sent++
		ender.attempts++
	}
	for _, alive := range []bool{false, true} {
		if pendingRetransmitsExhausted(ender, alive) {
			t.Fatalf("the Delete gave up after %d of its %d sends, peer alive %v", ender.sent, teardownRetransmits, alive)
		}
	}
	ender.sent++
	ender.attempts++
	for _, alive := range []bool{false, true} {
		if !pendingRetransmitsExhausted(ender, alive) {
			t.Errorf("the Delete went on past its %d sends, peer alive %v", teardownRetransmits, alive)
		}
	}
}

// whichever way the IKE SA ends, its own Delete answered or unanswered or the peer's Delete crossing it, run returns why it was deleting
// an IKE SA rekey that comes due while the Delete is out is not started
func TestRunEndingReturnsWhyItDeletedTheIKESA(t *testing.T) {
	why := errors.New("the reason to delete")
	for _, peerDoes := range []string{"answers", "crosses", "stays silent"} {
		t.Run(peerDoes, bubble.Run(func(t *testing.T) {
			peer, s := closingAfterAuth(t)
			events := &recorder{}
			s.requests, s.events = make(chan *localRequest, 1), events.record
			const due = 100 * time.Millisecond
			s.rekeyJitterSource = func(time.Duration) (time.Duration, error) { return 0, nil }
			if err := s.SetRekeyIntervals(0, time.Hour); err != nil {
				t.Fatal(err)
			}
			if err := s.SetRekeyTiming(time.Hour-due, 0); err != nil {
				t.Fatal(err)
			}
			if peerDoes == "stays silent" {
				s.retransmitAfter = due
			}
			var ended error
			finished := make(chan struct{})
			go func() { defer close(finished); ended = s.run(context.Background(), why) }()
			t.Cleanup(func() {
				s.mux.Close()
				<-finished
			})

			own := peer.read(t)
			if own.Header.ExchangeType != INFORMATIONAL || own.Header.IsResponse() || len(own.inner) != 1 || own.inner[0].Type != PayloadD {
				t.Fatalf("the peer got exchange %d response %v carrying %v, want a Delete request", own.Header.ExchangeType, own.Header.IsResponse(), own.inner)
			}
			if deleted, err := DecodeDelete(own.inner[0].Body); err != nil || deleted.Protocol != ProtoIKE {
				t.Fatalf("the request deletes %+v (%v), want the IKE SA", deleted, err)
			}
			time.Sleep(3 * due)
			switch peerDoes {
			case "answers":
				peer.send(t, Header{ExchangeType: INFORMATIONAL, Flags: FlagResponse, MessageID: own.Header.MessageID}, nil)
			case "crosses":
				peer.send(t, Header{ExchangeType: INFORMATIONAL, MessageID: 0}, deleteIKEPayloads())
				if answer := peer.answer(t); answer.Header.MessageID != 0 {
					t.Errorf("the peer's crossing Delete drew an answer at Message ID %d, want 0", answer.Header.MessageID)
				}
			}
			select {
			case <-finished:
			case <-time.After(answerBudget):
				t.Fatal("run went on after the exchange that ends the IKE SA")
			}
			if !errors.Is(ended, why) {
				t.Errorf("run returned %v, want why it was deleting, %v", ended, why)
			}
			for _, line := range events.recorded() {
				if strings.HasPrefix(line, "ike.rekey.started") {
					t.Errorf("run started a rekey while its Delete of the IKE SA was out: %q", events.recorded())
					break
				}
			}
		}))
	}
}

// The retirement sweep used to be reached by a hundred-millisecond poll that
// this series removed, so the loop's own deadline is now the only thing that
// brings it around. Everything else the loop waits for on an idle session is
// dead peer detection ten seconds out, so a replaced inbound SA would sit
// registered until something unrelated happened to wake the loop.
func TestRunLoopWakesForRetirement(t *testing.T) { bubble.Run(testRunLoopWakesForRetirement)(t) }

func testRunLoopWakesForRetirement(t *testing.T) {
	mux, _ := lifecycleMuxes(t)
	retired := make(chan uint32, 1)
	s := &Session{mux: mux, current: &ikeContext{}, requests: make(chan *localRequest)}
	s.SetChildRetireHandler(func(spi uint32) error { retired <- spi; return nil })
	const spi = uint32(0x11223344)
	s.childMu.Lock()
	s.retired = append(s.retired, childRetirement{spi: spi, expiresAt: time.Now().Add(200 * time.Millisecond)})
	s.childMu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	select {
	case got := <-retired:
		if got != spi {
			t.Fatalf("the sweep retired SPI %08x, which is not the one that expired, %08x", got, spi)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the loop never woke for the retirement, so the replaced keys stay installed")
	}
	cancel()
	<-done
}

// The same wiring for a retained IKE SA. While one is held, handleIKERekey
// answers every peer-initiated rekey with TEMPORARY_FAILURE, so the loop has
// to wake for its deadline rather than leave it to whatever happens next: a
// peer that rekeys once and goes quiet produces no other event at all.
func TestRunLoopWakesForRetainedIKESA(t *testing.T) { bubble.Run(testRunLoopWakesForRetainedIKESA)(t) }

func testRunLoopWakesForRetainedIKESA(t *testing.T) {
	mine, theirs := lifecycleMuxes(t)
	const spi = uint64(0x1122334455667788)
	replaced := &ikeContext{spiI: spi, spiR: 2}
	s := &Session{mux: mine, current: &ikeContext{spiI: 3, spiR: 4}, requests: make(chan *localRequest)}
	if err := mine.RegisterIKE(spi); err != nil {
		t.Fatal(err)
	}
	s.stateMu.Lock()
	s.old, s.oldBy = replaced, time.Now().Add(200*time.Millisecond)
	s.stateMu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	// Waited for on the SPI rather than on contextRetired: the flag flips
	// under stateMu and the mux is told after the unlock, so polling the flag
	// and then reading the hub reads through that window.
	deadline := time.Now().Add(5 * time.Second)
	for theirs.RegisterIKE(spi) != nil {
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatal("the loop never woke for the deadline, so every later peer rekey stays refused")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !s.contextRetired(replaced) {
		t.Error("the SPI was released while the session still holds the SA it belongs to")
	}
	cancel()
	<-done
}

// captureLevels keeps the level of every record logged until the test ends
func captureLevels(t *testing.T) *[]slog.Level {
	t.Helper()
	levels := new([]slog.Level)
	logtest.SetDefault(t, slog.New(&levelRecorder{levels: levels}))
	return levels
}

func countLevel(levels []slog.Level, level slog.Level) int {
	count := 0
	for _, logged := range levels {
		if logged == level {
			count++
		}
	}
	return count
}

func runSession(t *testing.T, s *Session) <-chan error {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	result, exited := make(chan error, 1), make(chan struct{})
	go func() {
		defer close(exited)
		result <- s.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-exited:
		case <-time.After(answerBudget):
			t.Error("the session's control loop did not return")
		}
	})
	return result
}

// unbuildableSession holds a key encrypt refuses, and with it builds no request
// it answers the error a check it starts ends the session with
func unbuildableSession(t *testing.T, dpdEvery time.Duration) (*Session, string) {
	t.Helper()
	mux, _ := lifecycleMuxes(t)
	ikeCtx := testContext()
	ikeCtx.skei = []byte{1, 2, 3}
	_, refused := EncryptMessage(ikeCtx.suite, ikeCtx.skei, Header{}, nil, nil)
	if refused == nil {
		t.Fatal("encrypt took a three-byte key, so this session proves nothing")
	}
	return &Session{mux: mux, current: ikeCtx, requests: make(chan *localRequest), probes: make(chan struct{}, 1), dpdEvery: dpdEvery},
		"ike: start a liveness check: " + refused.Error()
}

// a liveness check that cannot be built ends the session with why
// retrying it would send nothing for as long as the session stood
func TestLivenessCheckThatCannotBeBuiltEndsTheSession(t *testing.T) {
	bubble.Run(testLivenessCheckThatCannotBeBuiltEndsTheSession)(t)
}

func testLivenessCheckThatCannotBeBuiltEndsTheSession(t *testing.T) {
	const interval = 20 * time.Millisecond
	s, want := unbuildableSession(t, interval)
	select {
	case err := <-runSession(t, s):
		if err == nil || err.Error() != want {
			t.Errorf("the session ended with %v, want %s", err, want)
		}
	case <-time.After(answerBudget):
		t.Fatal("a session whose liveness check cannot be built never ended")
	}
	if !s.mux.IsClosed() {
		t.Error("the session ended with its mux open")
	}
}

// a failed send says nothing about the peer, RFC 7296 section 2.4, so only the spent budget ends the session
func TestSessionThatCannotSendEndsAfterItsBudget(t *testing.T) {
	bubble.Run(testSessionThatCannotSendEndsAfterItsBudget)(t)
}

func testSessionThatCannotSendEndsAfterItsBudget(t *testing.T) {
	levels := captureLevels(t)
	const interval, first = 20 * time.Millisecond, 10 * time.Millisecond
	// the check starts an interval in
	// and its attempts wait 1, 2, 4, 8 and 16 times first
	budget := interval + first*(1+2+4+8+16)
	events := &recorder{}
	s := &Session{mux: unsendableMux(t), current: testContext(), requests: make(chan *localRequest),
		dpdEvery: interval, retransmitAfter: first, events: events.record}
	started := time.Now()
	done := runSession(t, s)
	select {
	case err := <-done:
		if elapsed := time.Since(started); elapsed < budget {
			t.Errorf("the session ended after %s, before its budget of %s ran out: %v", elapsed, budget, err)
		}
		if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("unresponsive after %d attempts", maxRetransmits)) {
			t.Errorf("the session ended with %v, want its budget run out", err)
		}
	case <-time.After(answerBudget):
		t.Fatal("a session that cannot send never ended, so its dialer never dials again")
	}
	if s.sendFailures != maxRetransmits {
		t.Errorf("%d sends failed, want every one of the %d attempts", s.sendFailures, maxRetransmits)
	}
	if got := countLevel(*levels, slog.LevelWarn); got != 1 {
		t.Errorf("%d failed sends warned %d times, want once", maxRetransmits, got)
	}
	if got := countLevel(*levels, slog.LevelDebug); got != maxRetransmits-1 {
		t.Errorf("the failures after the first logged %d debug lines, want %d", got, maxRetransmits-1)
	}
	if failed, recovered := recordedKind(events, "ike.send.failed"), recordedKind(events, "ike.send.recovered"); failed != 1 || recovered != 0 {
		t.Errorf("the outage recorded %d failures and %d recoveries, want one failure", failed, recovered)
	}
}

// an outage of replies is said once and ended by a reply that goes out
// a cached reply goes to the address a replay came from, so it neither adds to an outage nor ends one, and one that cannot go out ends nothing
func TestFailedReplyKeepsTheSession(t *testing.T) { bubble.Run(testFailedReplyKeepsTheSession)(t) }

func testFailedReplyKeepsTheSession(t *testing.T) {
	levels := captureLevels(t)
	peer := listenPeer(t)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	mux, err := listenHub(t).NewMux(peerAddr.IP, peerAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	ikeCtx := testContext()
	events := &recorder{}
	s := &Session{mux: mux, current: ikeCtx, events: events.record}
	if err := mux.RegisterIKE(ikeCtx.spiI); err != nil {
		t.Fatal(err)
	}
	// sends to it are refused as to an arrival address that went away
	unreachable := unsendableMux(t).Endpoint()
	request := func(id uint32) []byte {
		t.Helper()
		raw, err := EncryptMessage(ikeCtx.suite, ikeCtx.sker, Header{SPIInitiator: ikeCtx.spiI, SPIResponder: ikeCtx.spiR,
			ExchangeType: INFORMATIONAL, MessageID: id}, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	var pending *pendingRequest
	fromPeer := func(raw []byte) bool {
		t.Helper()
		if _, err := peer.WriteToUDP(withNonESPMarker(raw), muxLoopback(mux)); err != nil {
			t.Fatal(err)
		}
		received, source, err := mux.RecvIKEFromUntil(time.Now().Add(answerBudget))
		if err != nil {
			t.Fatal(err)
		}
		taken := s.dispatch(received, source, &pending)
		buf := make([]byte, 2048)
		if err := peer.SetReadDeadline(time.Now().Add(answerBudget)); err != nil {
			t.Fatal(err)
		}
		if n, _, err := peer.ReadFromUDP(buf); err != nil || ikeCtx.lastPeer.response == nil || len(ikeCtx.lastPeer.response.datagrams) != 1 || !bytes.Equal(buf[NonESPMarkerLen:n], ikeCtx.lastPeer.response.datagrams[0]) {
			t.Fatalf("the peer was not answered with the reply kept for its request: %v", err)
		}
		return taken
	}
	outage := func(step string, failures, warned, failed, recovered int) {
		t.Helper()
		got := [4]int{s.sendFailures, countLevel(*levels, slog.LevelWarn), recordedKind(events, "ike.send.failed"), recordedKind(events, "ike.send.recovered")}
		if want := [4]int{failures, warned, failed, recovered}; got != want {
			t.Errorf("%s: the session counts failures, warnings, recorded failures and recoveries as %v, want %v", step, got, want)
		}
	}

	// a replay is the request bitwise, as RFC 7296 section 2.1 has a retransmission
	first := request(0)
	if !s.dispatch(first, unreachable, &pending) {
		t.Fatal("a fresh request was not taken")
	}
	if mux.IsClosed() {
		t.Fatal("a reply that could not go out ended the session")
	}
	outage("a reply that could not go out", 1, 1, 1, 0)
	if s.dispatch(first, unreachable, &pending) || mux.IsClosed() || ikeCtx.lastPeer.answers != 1 {
		t.Fatalf("a replay whose reply could not go out was taken as fresh or ended the session, after %d answers, want 1", ikeCtx.lastPeer.answers)
	}
	// the session's endpoint moved to the address the fresh request came from, so the peer's own replay draws the reply within the octets it sent
	if fromPeer(first) {
		t.Fatal("a replay was taken as fresh")
	}
	outage("replays answered from the cache", 1, 1, 1, 0)
	if !fromPeer(request(1)) {
		t.Fatal("a fresh request from the peer was not taken")
	}
	outage("a reply that went out", 0, 1, 1, 1)
	if !s.dispatch(request(2), unreachable, &pending) {
		t.Fatal("a fresh request was not taken")
	}
	outage("a second outage", 1, 2, 2, 1)
}

// probedSession dials a peer socket with its timers an hour out
func probedSession(t *testing.T) (*Session, *transport.MemoryConn, *recorder) {
	t.Helper()
	peer := listenPeer(t)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	mux, err := listenHub(t).NewMux(peerAddr.IP, peerAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	events := &recorder{}
	return &Session{mux: mux, current: testContext(), requests: make(chan *localRequest), probes: make(chan struct{}, 1),
		dpdEvery: time.Hour, retransmitAfter: time.Hour, events: events.record}, peer, events
}

// readRequest checks the session sent an empty INFORMATIONAL request
func readRequest(t *testing.T, s *Session, peer *transport.MemoryConn) []byte {
	t.Helper()
	raw, header, inner := readOwnRequest(t, s, peer)
	if header.ExchangeType != INFORMATIONAL || len(inner) != 0 {
		t.Fatalf("the session sent exchange %d with %d payloads, want a liveness check", header.ExchangeType, len(inner))
	}
	return raw
}

func awaitProbes(t *testing.T, events *recorder, count int) {
	t.Helper()
	for deadline := time.Now().Add(answerBudget); recordedKind(events, "ike.probe") < count; time.Sleep(recordPoll) {
		if time.Now().After(deadline) {
			t.Fatalf("the session acted on %d probes, want %d", recordedKind(events, "ike.probe"), count)
		}
	}
}

// the liveness interval here is an hour
func TestProbeStartsALivenessCheckAtOnce(t *testing.T) {
	bubble.Run(testProbeStartsALivenessCheckAtOnce)(t)
}

func testProbeStartsALivenessCheckAtOnce(t *testing.T) {
	s, peer, events := probedSession(t)
	runSession(t, s)
	s.Probe()
	readRequest(t, s, peer)
	awaitProbes(t, events, 1)
	if got := events.recorded(); !slices.Contains(got, "ike.probe > action=liveness check message_id=0") {
		t.Errorf("the session recorded %q, want the liveness check it sent", got)
	}
}

// the retransmission is due an hour later, and RFC 7296 section 2.1 has it sent bit for bit
func TestProbeRetransmitsTheOutstandingRequestAtOnce(t *testing.T) {
	bubble.Run(testProbeRetransmitsTheOutstandingRequestAtOnce)(t)
}

func testProbeRetransmitsTheOutstandingRequestAtOnce(t *testing.T) {
	s, peer, events := probedSession(t)
	runSession(t, s)
	s.Probe()
	first := readRequest(t, s, peer)
	awaitProbes(t, events, 1)
	s.Probe()
	if again := readRequest(t, s, peer); !bytes.Equal(again, first) {
		t.Error("the probe sent something other than the outstanding request")
	}
	awaitProbes(t, events, 2)
	if got := events.recorded(); !slices.Contains(got, "ike.probe > action=retransmission message_id=0") {
		t.Errorf("the session recorded %q, want the retransmission it sent", got)
	}
}

// a probe resends the outstanding request bit for bit and leaves its attempts and its backoff to the schedule
func TestProbeResendsWithoutSpendingAnAttempt(t *testing.T) {
	bubble.Run(testProbeResendsWithoutSpendingAnAttempt)(t)
}

func testProbeResendsWithoutSpendingAnAttempt(t *testing.T) {
	s, peer, _ := probedSession(t)
	pending, err := s.startLiveness()
	if err != nil {
		t.Fatal(err)
	}
	first := readRequest(t, s, peer)
	sent, attempts, deadline := pending.sent, pending.attempts, pending.deadline
	for range maxRetransmits {
		if probed, err := s.probe(pending); err != nil || probed != pending {
			t.Fatalf("a probe with a request outstanding answered %v, another request %v", err, probed != pending)
		}
		if again := readRequest(t, s, peer); !bytes.Equal(again, first) {
			t.Fatal("a probe sent something other than the outstanding request")
		}
	}
	if pending.sent != sent || pending.attempts != attempts || !pending.deadline.Equal(deadline) {
		t.Errorf("probes left %d sends and %d attempts due at %s, want the %d and %d due at %s they found",
			pending.sent, pending.attempts, pending.deadline, sent, attempts, deadline)
	}
}

// both ends of a real handshake take probes, which the constructors make room for
func TestProbesRunHasNotGotToAreOne(t *testing.T) { bubble.Run(testProbesRunHasNotGotToAreOne)(t) }

func testProbesRunHasNotGotToAreOne(t *testing.T) {
	answered, dialed := &recorder{}, &recorder{}
	h := newResponderHarness(t, nil, answered.record)
	cfg := h.peerConfig()
	cfg.Events = dialed.record
	ctx, cancel := context.WithTimeout(context.Background(), answerBudget)
	defer cancel()
	initiator, err := InitiateContext(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	responder := <-h.sessions
	<-h.identities
	for range 5 {
		initiator.Probe()
		responder.Probe()
	}
	runSession(t, initiator)
	runSession(t, responder)
	awaitProbes(t, dialed, 1)
	awaitProbes(t, answered, 1)
	time.Sleep(quietPeriod)
	if got := recordedKind(dialed, "ike.probe"); got != 1 {
		t.Errorf("five probes before the dialed session's loop ran were acted on %d times, want once", got)
	}
	if got := recordedKind(answered, "ike.probe"); got != 1 {
		t.Errorf("five probes before the answered session's loop ran were acted on %d times, want once", got)
	}
}

// a probe that cannot build the check it asks for ends the session as that check would
// the liveness interval here is an hour, and only the probe starts a check
func TestProbeThatCannotBuildACheckEndsTheSession(t *testing.T) {
	bubble.Run(testProbeThatCannotBuildACheckEndsTheSession)(t)
}

func testProbeThatCannotBuildACheckEndsTheSession(t *testing.T) {
	s, want := unbuildableSession(t, time.Hour)
	done := runSession(t, s)
	s.Probe()
	select {
	case err := <-done:
		if err == nil || err.Error() != want {
			t.Errorf("the session ended with %v, want %s", err, want)
		}
	case <-time.After(answerBudget):
		t.Fatal("a session whose probe cannot build a check never ended")
	}
	if !s.mux.IsClosed() {
		t.Error("the session ended with its mux open")
	}
}

// probes resend an unanswered exchange without spending its attempts, so it ends on its schedule and not before
func TestProbesLeaveAnUnansweredExchangeToItsSchedule(t *testing.T) {
	bubble.Run(testProbesLeaveAnUnansweredExchangeToItsSchedule)(t)
}

func testProbesLeaveAnUnansweredExchangeToItsSchedule(t *testing.T) {
	const first, every = 20 * time.Millisecond, 5 * time.Millisecond
	s := &Session{mux: unsendableMux(t), current: testContext(), requests: make(chan *localRequest), probes: make(chan struct{}, 1),
		dpdEvery: time.Hour, retransmitAfter: first}
	started := time.Now()
	done := runSession(t, s)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		tick := time.NewTicker(every)
		defer tick.Stop()
		for {
			s.Probe()
			select {
			case <-stop:
				return
			case <-tick.C:
			}
		}
	}()
	// the check the first probe starts waits 1, 2, 4, 8 and 16 times first
	scheduled := first * (1 + 2 + 4 + 8 + 16)
	select {
	case err := <-done:
		if elapsed := time.Since(started); elapsed < scheduled {
			t.Errorf("the exchange ended after %s, before its schedule of %s ran out: %v", elapsed, scheduled, err)
		}
	case <-time.After(answerBudget):
		t.Fatal("probes kept an exchange the peer never answers alive")
	}
}

// RFC 7296 section 2.3: "An IKE endpoint MUST wait for a response to each of its messages before sending a subsequent message unless it has received a SET_WINDOW_SIZE Notify message from its peer informing it that the peer is prepared to maintain state for multiple outstanding messages in order to allow greater throughput."
// a request queued while a liveness check is out goes out only once the check is answered, at the next Message ID
func TestLocalRequestWaitsForTheOutstandingExchange(t *testing.T) {
	bubble.Run(testLocalRequestWaitsForTheOutstandingExchange)(t)
}

func testLocalRequestWaitsForTheOutstandingExchange(t *testing.T) {
	s, peer, _ := probedSession(t)
	s.requests = make(chan *localRequest, 1)
	held := s.current
	if err := s.mux.RegisterIKE(held.spiI); err != nil {
		t.Fatal(err)
	}
	runSession(t, s)
	answer := func(raw []byte) {
		t.Helper()
		header, err := decodeHeader(raw)
		if err != nil {
			t.Fatal(err)
		}
		response, err := EncryptMessage(held.suite, held.sker, Header{SPIInitiator: held.spiI, SPIResponder: held.spiR,
			ExchangeType: INFORMATIONAL, Flags: FlagResponse, MessageID: header.MessageID}, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := peer.WriteToUDP(withNonESPMarker(response), muxLoopback(s.mux)); err != nil {
			t.Fatal(err)
		}
	}
	s.Probe()
	check := readRequest(t, s, peer)
	requested := make(chan error, 1)
	go func() {
		_, err := s.request(INFORMATIONAL, nil)
		requested <- err
	}()
	if err := peer.SetReadDeadline(time.Now().Add(quietPeriod)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	if n, _, err := peer.ReadFromUDP(buf); err == nil {
		t.Fatalf("the session sent %x while its liveness check was out, want nothing", buf[NonESPMarkerLen:n])
	}
	answer(check)
	next := readRequest(t, s, peer)
	if header, err := decodeHeader(next); err != nil || header.MessageID != 1 {
		t.Fatalf("the queued request went out as %+v (%v), want Message ID 1", header, err)
	}
	answer(next)
	select {
	case err := <-requested:
		if err != nil {
			t.Errorf("the queued request ended with %v, want its answer", err)
		}
	case <-time.After(answerBudget):
		t.Fatal("the queued request never ended")
	}
}

// sessions dialed and answered with no rekey retry configured back off from DefaultRetryFirst to DefaultRetryMax once they run
func TestSessionsWithNoRetryConfiguredBackOffByTheDefaults(t *testing.T) {
	bubble.Run(testSessionsWithNoRetryConfiguredBackOffByTheDefaults)(t)
}

func testSessionsWithNoRetryConfiguredBackOffByTheDefaults(t *testing.T) {
	h := newResponderHarness(t, nil)
	initiator, err := h.dial(t)
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}
	defer initiator.Mux().Close()
	var responder *Session
	select {
	case responder = <-h.sessions:
	case <-time.After(answerBudget):
		t.Fatal("the responder produced no session")
	}
	defer responder.Mux().Close()
	for name, s := range map[string]*Session{"initiator": initiator, "responder": responder} {
		s.rekeyJitterSource = func(time.Duration) (time.Duration, error) { return 0, nil }
		done := runSession(t, s)
		s.Mux().Close()
		select {
		case <-done:
		case <-time.After(answerBudget):
			t.Fatalf("the %s's control loop did not return", name)
		}
		if first, last := s.rekeyRetryDelay(1), s.rekeyRetryDelay(64); first != DefaultRetryFirst || last != DefaultRetryMax {
			t.Errorf("the %s backs off from %s to %s, want %s to %s", name, first, last, DefaultRetryFirst, DefaultRetryMax)
		}
	}
}
