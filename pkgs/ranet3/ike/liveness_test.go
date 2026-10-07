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

	"ranet3.com/pkgs/ranet3/transport"
)

func TestSessionRunStopsOnContextCancellation(t *testing.T) {
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
		t.Run(fmt.Sprint(waitingForResponse), func(t *testing.T) {
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
		})
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

func TestSupportedPayloadTypeRejectsUnknownCriticalType(t *testing.T) {
	if supportedPayloadType(PayloadType(250)) {
		t.Fatal("unknown payload type reported as supported")
	}
	if !supportedPayloadType(PayloadSA) {
		t.Fatal("SA payload type reported as unsupported")
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
	t.Run("local request", func(t *testing.T) {
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
	})

	t.Run("peer request", func(t *testing.T) {
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
	})
}

// acceptedMux is the mux a responder makes from a datagram configured sent
func acceptedMux(t *testing.T, configured *net.UDPConn, spiI uint64) *transport.Mux {
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
	readIKE := func(peer *net.UDPConn) []byte {
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
	dispatchFrom := func(peer *net.UDPConn, request []byte) bool {
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

// a dialed session follows its peer to where a fresh request that passed its integrity check came from, RFC 7296 section 2.23,
// and leaves by the kernel's choice of source rather than the address the request arrived on
// linux holds all of 127.0.0.0/8 and chooses 127.0.0.1 to reach any of it, which tells the two apart
func TestDialedSessionFollowsItsPeerFromTheKernelsSource(t *testing.T) {
	movedTo, arrival := net.IPv4(127, 0, 0, 1), net.IPv4(127, 0, 0, 1)
	if runtime.GOOS == "linux" {
		movedTo, arrival = net.IPv4(127, 0, 0, 2), net.IPv4(127, 0, 0, 3)
	}
	configured := listenPeer(t)
	moved, err := net.ListenUDP("udp4", &net.UDPAddr{IP: movedTo})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { moved.Close() })
	hub := listenHub(t)
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
	peer := listenPeer(t)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	mux, err := transport.Dial("127.0.0.1:0", peerAddr.IP, peerAddr.Port)
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

	decodeResponse := func(raw []byte) Notify {
		t.Helper()
		message, err := DecodeMessage(raw)
		if err != nil {
			t.Fatal(err)
		}
		inner, err := DecryptMessage(suite, ikeCtx.skei, raw, message)
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
	message, err := DecodeMessage(response)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := DecryptMessage(suite, ikeCtx.skei, response, message)
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
	response, err := s.handleRequest(ikeCtx, &Header{ExchangeType: INFORMATIONAL, MessageID: 4}, []RawPayload{
		{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoESP, SPIs: [][]byte{spi(current.RemoteSPI), spi(0xdeadbeef)}})},
		{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoESP, SPIs: [][]byte{spi(retiring.RemoteSPI)}})},
	})
	if err != nil {
		t.Fatal(err)
	}
	message, err := DecodeMessage(response)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := DecryptMessage(suite, ikeCtx.skei, response, message)
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
	for _, delays := range [][2]time.Duration{{0, time.Second}, {time.Second, 0}, {time.Minute, time.Second}} {
		if err := s.SetRekeyRetry(delays[0], delays[1]); err == nil {
			t.Fatalf("SetRekeyRetry(%s, %s) succeeded", delays[0], delays[1])
		}
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

// The retirement sweep used to be reached by a hundred-millisecond poll that
// this series removed, so the loop's own deadline is now the only thing that
// brings it around. Everything else the loop waits for on an idle session is
// dead peer detection ten seconds out, so a replaced inbound SA would sit
// registered until something unrelated happened to wake the loop.
func TestRunLoopWakesForRetirement(t *testing.T) {
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
func TestRunLoopWakesForRetainedIKESA(t *testing.T) {
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
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })
	slog.SetDefault(slog.New(&levelRecorder{levels: levels}))
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
// a cached reply goes to wherever a replay came from, so it neither adds to an outage nor ends one
func TestFailedReplyKeepsTheSession(t *testing.T) {
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
		if n, _, err := peer.ReadFromUDP(buf); err != nil || !bytes.Equal(buf[NonESPMarkerLen:n], ikeCtx.lastPeerResponse) {
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

	if !s.dispatch(request(0), unreachable, &pending) {
		t.Fatal("a fresh request was not taken")
	}
	if mux.IsClosed() {
		t.Fatal("a reply that could not go out ended the session")
	}
	outage("a reply that could not go out", 1, 1, 1, 0)
	if s.dispatch(request(0), unreachable, &pending) {
		t.Fatal("a replay was taken as fresh")
	}
	if fromPeer(request(0)) {
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
func probedSession(t *testing.T) (*Session, *net.UDPConn, *recorder) {
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
func readRequest(t *testing.T, s *Session, peer *net.UDPConn) []byte {
	t.Helper()
	buf := make([]byte, 2048)
	if err := peer.SetReadDeadline(time.Now().Add(answerBudget)); err != nil {
		t.Fatal(err)
	}
	n, _, err := peer.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("no request arrived within %s: %v", answerBudget, err)
	}
	raw := append([]byte(nil), buf[NonESPMarkerLen:n]...)
	message, err := DecodeMessage(raw)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := DecryptMessage(s.current.suite, s.current.skei, raw, message)
	if err != nil {
		t.Fatal(err)
	}
	if message.Header.ExchangeType != INFORMATIONAL || message.Header.IsResponse() || len(inner) != 0 {
		t.Fatalf("the session sent exchange %d response %v with %d payloads, want a liveness check",
			message.Header.ExchangeType, message.Header.IsResponse(), len(inner))
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
func TestProbesRunHasNotGotToAreOne(t *testing.T) {
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
