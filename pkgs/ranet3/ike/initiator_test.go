// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

package ike

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/transport"
)

// muxLoopback is the mux's own address with an explicit loopback host. The
// hub binds the wildcard and reports only a port, and sending to an address
// with no host reaches the local machine on Linux but is unroutable on darwin.
func muxLoopback(mux *transport.Mux) *net.UDPAddr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: mux.LocalAddr().(*net.UDPAddr).Port}
}

// listenPeer opens a plain UDP socket standing in for the IKE responder, so
// sendRecv's behavior can be tested without a real handshake.
func listenPeer(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// peerLoop runs one fake-peer goroutine and joins it with the test. The
// goroutine reports through t, and a socket with no deadline parks for as long
// as the session under test does not send: a t.Fatal elsewhere would otherwise
// finish the test with the goroutine still parked, and its first log line then
// panics the whole package binary with "Log in goroutine after test completed"
// instead of printing the failure that caused it.
func peerLoop(t *testing.T, peer *net.UDPConn, body func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); body() }()
	t.Cleanup(func() {
		_ = peer.SetDeadline(time.Now())
		<-done
	})
}

func TestSessionScheduledRekeyFailureRetries(t *testing.T) {
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
	s := &Session{
		mux: mux,
		current: &ikeContext{suite: suite, spiI: spiI, spiR: spiR, authMID: 1, nextLocalMID: 2,
			skei: make([]byte, 20), sker: make([]byte, 20), skD: []byte("test child rekey SK_d material")},
		Child:            ChildSA{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, LocalSPI: 0x10203040, RemoteSPI: 0x50607080},
		childEstablished: time.Now(),
		requests:         make(chan *localRequest, 1),
	}
	if err := mux.RegisterIKE(spiI); err != nil {
		t.Fatal(err)
	}
	// the rekey is due a millisecond in and the Child SA lives an hour, so the retry falls inside its lifetime
	s.rekeyJitterSource = func(time.Duration) (time.Duration, error) { return 0, nil }
	if err := s.SetRekeyIntervals(time.Hour, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRekeyTiming(time.Hour-time.Millisecond, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRekeyRetry(10*time.Millisecond, time.Second); err != nil {
		t.Fatal(err)
	}

	retried := make(chan struct{})
	peerLoop(t, peer, func() {
		buf := make([]byte, 2048)
		n, addr, err := peer.ReadFromUDP(buf)
		if err != nil {
			t.Errorf("read scheduled rekey request: %v", err)
			return
		}
		raw := append([]byte(nil), buf[4:n]...)
		m, err := DecodeMessage(raw)
		if err != nil {
			t.Errorf("decode scheduled rekey request: %v", err)
			return
		}
		response, err := EncryptMessage(suite, s.current.sker, Header{SPIInitiator: spiI, SPIResponder: spiR, ExchangeType: m.Header.ExchangeType, Flags: FlagResponse, MessageID: m.Header.MessageID}, nil, []RawPayload{{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_NO_PROPOSAL_CHOSEN})}})
		if err != nil {
			t.Errorf("encrypt scheduled rekey response: %v", err)
			return
		}
		if _, err := peer.WriteToUDP(withNonESPMarker(response), addr); err != nil {
			t.Errorf("write scheduled rekey response: %v", err)
			return
		}
		n, _, err = peer.ReadFromUDP(buf)
		if err != nil {
			t.Errorf("read scheduled rekey retry: %v", err)
			return
		}
		retry, err := DecodeMessage(buf[4:n])
		if err != nil {
			t.Errorf("decode scheduled rekey retry: %v", err)
			return
		}
		if retry.Header.ExchangeType != CREATE_CHILD_SA || retry.Header.MessageID == m.Header.MessageID {
			t.Errorf("after the refusal the session sent exchange %d at Message ID %d, want a new CREATE_CHILD_SA", retry.Header.ExchangeType, retry.Header.MessageID)
			return
		}
		close(retried)
	})

	runDone := make(chan error, 1)
	go func() { runDone <- s.Run(context.Background()) }()
	select {
	case <-retried:
	case <-time.After(5 * time.Second):
		t.Fatal("scheduled rekey was not retried")
	}
	select {
	case err := <-runDone:
		t.Fatalf("Run returned after scheduled rekey failure: %v", err)
	default:
	}
	_ = mux.Close()
	if err := <-runDone; err == nil {
		t.Fatal("Run returned nil after mux close")
	}
}

func TestRekeyDelay(t *testing.T) {
	s := &Session{rekeyMargin: 5 * time.Minute, rekeyJitter: time.Minute}
	var limits []time.Duration
	s.rekeyJitterSource = func(max time.Duration) (time.Duration, error) {
		limits = append(limits, max)
		return max, nil
	}

	established := time.Now().Add(-time.Minute)
	due, err := s.rekeyDue(time.Hour, established)
	if err != nil {
		t.Fatal(err)
	}
	if want := established.Add(54 * time.Minute); !due.Equal(want) {
		t.Fatalf("rekey due %s after its SA was established, want %s", due.Sub(established), want.Sub(established))
	}
	if len(limits) != 1 || limits[0] != time.Minute {
		t.Fatalf("jitter limits = %v, want [%s]", limits, time.Minute)
	}

	s.rekeyJitterSource = func(time.Duration) (time.Duration, error) { return time.Minute + time.Nanosecond, nil }
	if _, err := s.rekeyDue(time.Hour, established); err == nil {
		t.Fatal("rekeyDue succeeded with out-of-range jitter")
	}
}

func TestSessionScheduledRekeyChild(t *testing.T) {
	peer := listenPeer(t)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	mux, err := transport.Dial("127.0.0.1:0", peerAddr.IP, peerAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()

	const spiI = 0x0102030405060708
	const spiR = 0x1112131415161718
	const oldLocalSPI = 0x10203040
	const oldRemoteSPI = 0x50607080
	const newRemoteSPI = 0x90a0b0c0
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	s := &Session{
		mux: mux,
		current: &ikeContext{suite: suite, spiI: spiI, spiR: spiR, authMID: 1, nextLocalMID: 2,
			skei: make([]byte, 20), sker: make([]byte, 20), skD: []byte("test child rekey SK_d material")},
		Child:            ChildSA{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, LocalSPI: oldLocalSPI, RemoteSPI: oldRemoteSPI},
		childEstablished: time.Now(),
		requests:         make(chan *localRequest, 1),
	}
	if err := mux.RegisterIKE(spiI); err != nil {
		t.Fatal(err)
	}
	// the rekey falls due at once, long before the Child SA's lifetime
	s.rekeyJitterSource = func(time.Duration) (time.Duration, error) { return 0, nil }
	if err := s.SetRekeyIntervals(time.Hour, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRekeyTiming(time.Hour-25*time.Millisecond, 0); err != nil {
		t.Fatal(err)
	}
	installed := make(chan ChildSA, 1)
	s.SetChildHandler(func(child ChildSA) error {
		installed <- child
		return nil
	})
	rekeyed := make(chan struct{})
	s.SetChildRetireHandler(func(spi uint32) error {
		if spi != oldLocalSPI {
			t.Errorf("retired SPI = %08x, want %08x", spi, oldLocalSPI)
		}
		close(rekeyed)
		return nil
	})

	peerDone := make(chan struct{})
	peerLoop(t, peer, func() {
		defer close(peerDone)
		buf := make([]byte, 2048)
		n, addr, err := peer.ReadFromUDP(buf)
		if err != nil {
			t.Errorf("read request: %v", err)
			return
		}
		raw := append([]byte(nil), buf[4:n]...)
		m, err := DecodeMessage(raw)
		if err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		inner, err := DecryptMessage(suite, s.current.skei, raw, m)
		if err != nil {
			t.Errorf("decrypt request: %v", err)
			return
		}
		if m.Header.ExchangeType != CREATE_CHILD_SA || findType(inner, PayloadKE) != nil {
			t.Errorf("unexpected rekey exchange")
			return
		}
		notifyPayload, saPayload := findType(inner, PayloadN), findType(inner, PayloadSA)
		noncePayload, tsiPayload, tsrPayload := findType(inner, PayloadNonce), findType(inner, PayloadTSi), findType(inner, PayloadTSr)
		if notifyPayload == nil || saPayload == nil || noncePayload == nil || tsiPayload == nil || tsrPayload == nil {
			t.Errorf("incomplete rekey request")
			return
		}
		// RFC 7296 section 2.5: "implementations SHOULD send the payloads defined in this specification in the order shown in the figures in Sections 1 and 2"
		// the figure of section 1.3.3: "HDR, SK {N(REKEY_SA), SA, Ni, [KEi,] TSi, TSr}"
		if got, want := payloadTypes(inner), []PayloadType{PayloadN, PayloadSA, PayloadNonce, PayloadTSi, PayloadTSr}; !slices.Equal(got, want) {
			t.Errorf("the rekey request carries payload types %v, want %v", got, want)
		}
		notify, err := DecodeNotify(notifyPayload.Body)
		if err != nil || notify.Type != N_REKEY_SA || notify.Protocol != ProtoESP || len(notify.SPI) != 4 || binary.BigEndian.Uint32(notify.SPI) != oldLocalSPI {
			t.Errorf("bad REKEY_SA notify: %#v, %v", notify, err)
			return
		}
		proposal, err := DecodeSA(saPayload.Body)
		if err != nil || len(proposal) != 1 || len(proposal[0].SPI) != 4 || binary.BigEndian.Uint32(proposal[0].SPI) == 0 {
			t.Errorf("bad proposal: %#v, %v", proposal, err)
			return
		}
		nonce := noncePayload.Body
		tsv4, tsv6 := FullRangeV4(), FullRangeV6()
		selectors := EncodeTS([]TrafficSelector{tsv4, tsv6})
		if len(nonce) == 0 || string(tsiPayload.Body) != string(selectors) || string(tsrPayload.Body) != string(selectors) {
			t.Errorf("bad rekey nonce or traffic selectors")
			return
		}
		remoteSPI := make([]byte, 4)
		binary.BigEndian.PutUint32(remoteSPI, newRemoteSPI)
		nr := []byte("responder nonce for child rekey")
		// section 2.5: "implementations MUST NOT reject as invalid a message with those payloads in any other order."
		// so the answer has them in reverse
		response, err := EncryptMessage(suite, s.current.sker, Header{SPIInitiator: spiI, SPIResponder: spiR, ExchangeType: CREATE_CHILD_SA, Flags: FlagResponse, MessageID: m.Header.MessageID}, nil, []RawPayload{
			{Type: PayloadTSr, Body: EncodeTS([]TrafficSelector{tsv4, tsv6})},
			{Type: PayloadTSi, Body: EncodeTS([]TrafficSelector{tsv4, tsv6})},
			{Type: PayloadNonce, Body: EncodeNonce(nr)},
			{Type: PayloadSA, Body: EncodeSA([]Proposal{{Number: 1, Protocol: ProtoESP, SPI: remoteSPI, Transforms: []Transform{{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128}, {Type: TransESN, ID: ESN_NO}}}})},
		})
		if err != nil {
			t.Errorf("encrypt response: %v", err)
			return
		}
		if _, err := peer.WriteToUDP(withNonESPMarker(response), addr); err != nil {
			t.Errorf("write response: %v", err)
			return
		}
		n, addr, err = peer.ReadFromUDP(buf)
		if err != nil {
			t.Errorf("read delete request: %v", err)
			return
		}
		raw = append([]byte(nil), buf[4:n]...)
		m, err = DecodeMessage(raw)
		if err != nil {
			t.Errorf("decode delete request: %v", err)
			return
		}
		inner, err = DecryptMessage(suite, s.current.skei, raw, m)
		if err != nil {
			t.Errorf("decrypt delete request: %v", err)
			return
		}
		dp := findType(inner, PayloadD)
		if m.Header.ExchangeType != INFORMATIONAL || dp == nil {
			t.Errorf("unexpected retire exchange")
			return
		}
		d, err := DecodeDelete(dp.Body)
		if err != nil || d.Protocol != ProtoESP || len(d.SPIs) != 1 || len(d.SPIs[0]) != 4 || binary.BigEndian.Uint32(d.SPIs[0]) != oldLocalSPI {
			t.Errorf("bad retire delete: %#v, %v", d, err)
			return
		}
		remote := make([]byte, 4)
		binary.BigEndian.PutUint32(remote, oldRemoteSPI)
		response, err = EncryptMessage(suite, s.current.sker, Header{SPIInitiator: spiI, SPIResponder: spiR, ExchangeType: INFORMATIONAL, Flags: FlagResponse, MessageID: m.Header.MessageID}, nil, []RawPayload{{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoESP, SPIs: [][]byte{remote}})}})
		if err != nil {
			t.Errorf("encrypt delete response: %v", err)
			return
		}
		if _, err := peer.WriteToUDP(withNonESPMarker(response), addr); err != nil {
			t.Errorf("write delete response: %v", err)
			return
		}
		n, addr, err = peer.ReadFromUDP(buf)
		if err != nil {
			t.Errorf("read post-rekey request: %v", err)
			return
		}
		raw = append([]byte(nil), buf[4:n]...)
		m, err = DecodeMessage(raw)
		if err != nil {
			t.Errorf("decode post-rekey request: %v", err)
			return
		}
		if _, err := DecryptMessage(suite, s.current.skei, raw, m); err != nil {
			t.Errorf("decrypt post-rekey request: %v", err)
			return
		}
		if m.Header.ExchangeType != INFORMATIONAL {
			t.Errorf("post-rekey exchange = %d, want INFORMATIONAL", m.Header.ExchangeType)
			return
		}
		response, err = EncryptMessage(suite, s.current.sker, Header{SPIInitiator: spiI, SPIResponder: spiR, ExchangeType: INFORMATIONAL, Flags: FlagResponse, MessageID: m.Header.MessageID}, nil, nil)
		if err != nil {
			t.Errorf("encrypt post-rekey response: %v", err)
			return
		}
		if _, err := peer.WriteToUDP(withNonESPMarker(response), addr); err != nil {
			t.Errorf("write post-rekey response: %v", err)
		}
	})

	runDone := make(chan error, 1)
	go func() { runDone <- s.Run(context.Background()) }()
	select {
	case <-rekeyed:
	case <-time.After(5 * time.Second):
		t.Fatal("scheduled Child SA rekey did not complete")
	}
	if _, err := s.request(INFORMATIONAL, nil); err != nil {
		t.Fatalf("post-rekey request: %v", err)
	}
	<-peerDone
	child := <-installed
	if child.LocalSPI == oldLocalSPI || child.RemoteSPI != newRemoteSPI || len(child.InboundKey) == 0 || len(child.OutboundKey) == 0 {
		t.Fatalf("installed child = %#v", child)
	}
	if got := s.currentChild(); got.LocalSPI != child.LocalSPI || got.RemoteSPI != child.RemoteSPI || string(got.InboundKey) != string(child.InboundKey) || string(got.OutboundKey) != string(child.OutboundKey) {
		t.Fatalf("current child = %#v, want %#v", got, child)
	}
	_ = mux.Close()
	if err := <-runDone; err == nil {
		t.Fatal("Run returned nil after mux close")
	}
}

func TestSessionRekeyIKE(t *testing.T) {
	peer := listenPeer(t)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	mux, err := transport.Dial("127.0.0.1:0", peerAddr.IP, peerAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()

	const oldSPIi = 0x0102030405060708
	const oldSPIr = 0x1112131415161718
	const newSPIr = 0x2122232425262728
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256, DHGroup: DH_CURVE25519}
	old := &ikeContext{suite: suite, spiI: oldSPIi, spiR: oldSPIr, authMID: 1, nextLocalMID: 2,
		skD: []byte("old IKE rekey SK_d material-------"), skei: make([]byte, 20), sker: make([]byte, 20)}
	child := ChildSA{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, LocalSPI: 0x10203040, RemoteSPI: 0x50607080}
	s := &Session{mux: mux, current: old, Child: child, requests: make(chan *localRequest, 1), suites: func() Suites { return classicalLists }}
	if err := mux.RegisterIKE(oldSPIi); err != nil {
		t.Fatal(err)
	}

	peerDone := make(chan struct{})
	peerLoop(t, peer, func() {
		defer close(peerDone)
		buf := make([]byte, 2048)
		n, addr, err := peer.ReadFromUDP(buf)
		if err != nil {
			t.Errorf("read rekey request: %v", err)
			return
		}
		raw := append([]byte(nil), buf[4:n]...)
		m, err := DecodeMessage(raw)
		if err != nil {
			t.Errorf("decode rekey request: %v", err)
			return
		}
		inner, err := DecryptMessage(suite, old.skei, raw, m)
		if err != nil {
			t.Errorf("decrypt rekey request: %v", err)
			return
		}
		sa, nonce, ke := findType(inner, PayloadSA), findType(inner, PayloadNonce), findType(inner, PayloadKE)
		if m.Header.ExchangeType != CREATE_CHILD_SA || m.Header.MessageID != 2 || sa == nil || nonce == nil || ke == nil {
			t.Errorf("incomplete IKE rekey request")
			return
		}
		// RFC 7296 section 2.5: "implementations SHOULD send the payloads defined in this specification in the order shown in the figures in Sections 1 and 2"
		// the figure of section 1.3.2: "HDR, SK {SA, Ni, KEi}"
		if got, want := payloadTypes(inner), []PayloadType{PayloadSA, PayloadNonce, PayloadKE}; !slices.Equal(got, want) {
			t.Errorf("the rekey request carries payload types %v, want %v", got, want)
		}
		props, err := DecodeSA(sa.Body)
		if err != nil || len(props) != 3 || props[0].Protocol != ProtoIKE || len(props[0].SPI) != 8 {
			t.Errorf("bad IKE rekey proposal: %#v, %v", props, err)
			return
		}
		newSPIi := binary.BigEndian.Uint64(props[0].SPI)
		group, _, err := DecodeKE(ke.Body)
		if err != nil || group != DH_CURVE25519 || len(nonce.Body) == 0 || newSPIi == 0 {
			t.Errorf("bad IKE rekey KE or nonce: %d, %v", group, err)
			return
		}
		// RFC 7296 section 3.4 on the KE payload's group: "SHOULD match the Diffie-Hellman group in the first group in the first proposal, if such exists."
		if want := offeredIKESA(props[0].SPI, []byte{5}, []byte{31, 20, 19}); !bytes.Equal(sa.Body, want) {
			t.Errorf("the rekey request offers\n%x\nwant\n%x", sa.Body, want)
		}
		invalidKEData := make([]byte, 2)
		binary.BigEndian.PutUint16(invalidKEData, DH_ECP_256)
		response, err := EncryptMessage(suite, old.sker, Header{SPIInitiator: oldSPIi, SPIResponder: oldSPIr, ExchangeType: CREATE_CHILD_SA, Flags: FlagResponse, MessageID: m.Header.MessageID}, nil, []RawPayload{
			{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_INVALID_KE_PAYLOAD, Data: invalidKEData})},
		})
		if err != nil {
			t.Errorf("encrypt INVALID_KE_PAYLOAD response: %v", err)
			return
		}
		if _, err := peer.WriteToUDP(withNonESPMarker(response), addr); err != nil {
			t.Errorf("write INVALID_KE_PAYLOAD response: %v", err)
			return
		}

		n, addr, err = peer.ReadFromUDP(buf)
		if err != nil {
			t.Errorf("read retried rekey request: %v", err)
			return
		}
		raw = append([]byte(nil), buf[4:n]...)
		m, err = DecodeMessage(raw)
		if err != nil {
			t.Errorf("decode retried rekey request: %v", err)
			return
		}
		inner, err = DecryptMessage(suite, old.skei, raw, m)
		if err != nil {
			t.Errorf("decrypt retried rekey request: %v", err)
			return
		}
		sa, nonce, ke = findType(inner, PayloadSA), findType(inner, PayloadNonce), findType(inner, PayloadKE)
		if m.Header.ExchangeType != CREATE_CHILD_SA || m.Header.MessageID != 3 || sa == nil || nonce == nil || ke == nil {
			t.Errorf("incomplete retried IKE rekey request")
			return
		}
		if got, want := payloadTypes(inner), []PayloadType{PayloadSA, PayloadNonce, PayloadKE}; !slices.Equal(got, want) {
			t.Errorf("the retried rekey request carries payload types %v, want %v", got, want)
		}
		props, err = DecodeSA(sa.Body)
		if err != nil || len(props) != 3 || props[0].Protocol != ProtoIKE || len(props[0].SPI) != 8 {
			t.Errorf("bad retried IKE rekey proposal: %#v, %v", props, err)
			return
		}
		group, _, err = DecodeKE(ke.Body)
		if err != nil || group != DH_ECP_256 || len(nonce.Body) == 0 || binary.BigEndian.Uint64(props[0].SPI) == 0 {
			t.Errorf("bad retried IKE rekey KE or nonce: %d, %v", group, err)
			return
		}
		// the retry an INVALID_KE_PAYLOAD naming P-256 draws offers P-256 first and the other groups after it in their order
		if want := offeredIKESA(props[0].SPI, []byte{5}, []byte{19, 31, 20}); !bytes.Equal(sa.Body, want) {
			t.Errorf("the retried rekey request offers\n%x\nwant\n%x", sa.Body, want)
		}
		responderDH, err := GenerateDH(group)
		if err != nil {
			t.Errorf("generate responder DH: %v", err)
			return
		}
		nr := []byte("responder nonce for IKE rekey")
		spiR := make([]byte, 8)
		binary.BigEndian.PutUint64(spiR, newSPIr)
		// section 2.5: "implementations MUST NOT reject as invalid a message with those payloads in any other order."
		// so the answer has them in reverse
		response, err = EncryptMessage(suite, old.sker, Header{SPIInitiator: oldSPIi, SPIResponder: oldSPIr, ExchangeType: CREATE_CHILD_SA, Flags: FlagResponse, MessageID: m.Header.MessageID}, nil, []RawPayload{
			{Type: PayloadKE, Body: EncodeKE(group, responderDH.PublicBytes())},
			{Type: PayloadNonce, Body: EncodeNonce(nr)},
			{Type: PayloadSA, Body: EncodeSA([]Proposal{{Number: 1, Protocol: ProtoIKE, SPI: spiR, Transforms: []Transform{{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128}, {Type: TransPRF, ID: PRF_HMAC_SHA2_256}, {Type: TransDH, ID: group}}}})},
		})
		if err != nil {
			t.Errorf("encrypt rekey response: %v", err)
			return
		}
		if _, err := peer.WriteToUDP(withNonESPMarker(response), addr); err != nil {
			t.Errorf("write rekey response: %v", err)
			return
		}

		n, addr, err = peer.ReadFromUDP(buf)
		if err != nil {
			t.Errorf("read old IKE delete: %v", err)
			return
		}
		raw = append([]byte(nil), buf[4:n]...)
		m, err = DecodeMessage(raw)
		if err != nil {
			t.Errorf("decode old IKE delete: %v", err)
			return
		}
		inner, err = DecryptMessage(suite, old.skei, raw, m)
		if err != nil {
			t.Errorf("decrypt old IKE delete: %v", err)
			return
		}
		d := findType(inner, PayloadD)
		if m.Header.SPIInitiator != oldSPIi || m.Header.SPIResponder != oldSPIr || m.Header.ExchangeType != INFORMATIONAL || m.Header.MessageID != 4 || d == nil {
			t.Errorf("unexpected old IKE delete")
			return
		}
		deletePayload, err := DecodeDelete(d.Body)
		if err != nil || deletePayload.Protocol != ProtoIKE || len(deletePayload.SPIs) != 0 {
			t.Errorf("bad old IKE delete: %#v, %v", deletePayload, err)
			return
		}
		response, err = EncryptMessage(suite, old.sker, Header{SPIInitiator: oldSPIi, SPIResponder: oldSPIr, ExchangeType: INFORMATIONAL, Flags: FlagResponse, MessageID: m.Header.MessageID}, nil, nil)
		if err != nil {
			t.Errorf("encrypt old IKE delete response: %v", err)
			return
		}
		if _, err := peer.WriteToUDP(withNonESPMarker(response), addr); err != nil {
			t.Errorf("write old IKE delete response: %v", err)
		}
	})

	runDone := make(chan error, 1)
	go func() { runDone <- s.Run(context.Background()) }()
	stop := stopRun(mux, runDone)
	if err := s.RekeyIKE(); err != nil {
		stop()
		t.Fatalf("RekeyIKE: %v", err)
	}
	<-peerDone
	current, retained := s.contexts()
	if current == old || current.spiR != newSPIr || current.suite.DHGroup != DH_ECP_256 || retained != nil {
		stop()
		t.Fatalf("IKE contexts not promoted and retired: current=%#v old=%#v", current, retained)
	}
	if got := s.currentChild(); got.EncrID != child.EncrID || got.EncrKeyBits != child.EncrKeyBits || got.LocalSPI != child.LocalSPI || got.RemoteSPI != child.RemoteSPI || len(got.InboundKey) != 0 || len(got.OutboundKey) != 0 {
		stop()
		t.Fatalf("Child SA changed during IKE rekey: %#v, want %#v", got, child)
	}
	if s.contextForHeader(&Header{SPIInitiator: oldSPIi, SPIResponder: oldSPIr}) != nil {
		stop()
		t.Fatal("old IKE context is still retained")
	}
	if err := stop(); err == nil {
		t.Fatal("Run returned nil after mux close")
	}
}

// stopRun ends the Run whose result runDone carries by closing mux, and gives that result, once however often it is called
// a failure calls it first, so it formats no context Run still writes and leaves no Run going into the next iteration
func stopRun(mux *transport.Mux, runDone <-chan error) func() error {
	return sync.OnceValue(func() error {
		_ = mux.Close()
		return <-runDone
	})
}

func TestSessionHandlesPeerIKERekey(t *testing.T) {
	peer := listenPeer(t)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	mux, err := transport.Dial("127.0.0.1:0", peerAddr.IP, peerAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()

	const oldSPIi = 0x0102030405060708
	const oldSPIr = 0x1112131415161718
	const newSPIi = 0x2122232425262728
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	old := &ikeContext{suite: suite, spiI: oldSPIi, spiR: oldSPIr,
		skD: []byte("old IKE rekey SK_d material-------"), skei: make([]byte, 20), sker: make([]byte, 20)}
	child := ChildSA{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, LocalSPI: 0x10203040, RemoteSPI: 0x50607080}
	s := &Session{mux: mux, current: old, Child: child, requests: make(chan *localRequest, 1)}
	if err := mux.RegisterIKE(oldSPIi); err != nil {
		t.Fatal(err)
	}

	runDone := make(chan error, 1)
	go func() { runDone <- s.Run(context.Background()) }()

	// proposal 1 names a PRF other than the one the SA keeps
	// so the answer is proposal 2 in the first group of the lists, the KE payload's
	dh, err := GenerateDH(DH_CURVE25519)
	if err != nil {
		t.Fatal(err)
	}
	ni := []byte("peer nonce for IKE rekey")
	spi := make([]byte, 8)
	binary.BigEndian.PutUint64(spi, newSPIi)
	// RFC 7296 section 2.5: "implementations MUST NOT reject as invalid a message with those payloads in any other order."
	// so the request has them in reverse
	// section 3.10.1: "Unrecognized error types in a request and status types in a request or response MUST be ignored, and they should be logged."
	// so it carries one of each besides
	request, err := EncryptMessage(suite, old.sker, Header{SPIInitiator: oldSPIi, SPIResponder: oldSPIr, ExchangeType: CREATE_CHILD_SA, MessageID: 0}, nil, []RawPayload{
		{Type: PayloadKE, Body: EncodeKE(DH_CURVE25519, dh.PublicBytes())},
		{Type: PayloadNonce, Body: EncodeNonce(ni)},
		{Type: PayloadSA, Body: EncodeSA([]Proposal{
			{Number: 1, Protocol: ProtoIKE, SPI: spi, Transforms: []Transform{{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 256}, {Type: TransPRF, ID: PRF_HMAC_SHA2_384}, {Type: TransDH, ID: DH_ECP_256}}},
			{Number: 2, Protocol: ProtoIKE, SPI: spi, Transforms: ikeProposal().Transforms},
		})},
		unrecognizedError,
		unrecognizedStatus,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := peer.WriteToUDP(withNonESPMarker(request), muxLoopback(mux)); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 2048)
	peer.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := peer.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	responseRaw := append([]byte(nil), buf[4:n]...)
	response, err := DecodeMessage(responseRaw)
	if err != nil {
		t.Fatal(err)
	}
	if response.Header.SPIInitiator != oldSPIi || response.Header.SPIResponder != oldSPIr || response.Header.Flags != FlagInitiator|FlagResponse {
		t.Fatalf("rekey response header = %#v", response.Header)
	}
	inner, err := DecryptMessage(suite, old.skei, responseRaw, response)
	if err != nil {
		t.Fatalf("decrypt old-context rekey response: %v", err)
	}
	sa, nonce, ke := findType(inner, PayloadSA), findType(inner, PayloadNonce), findType(inner, PayloadKE)
	if sa == nil || nonce == nil || ke == nil || findType(inner, PayloadTSi) != nil || findType(inner, PayloadTSr) != nil {
		t.Fatalf("invalid peer rekey response payloads: %#v", inner)
	}
	// section 2.5: "implementations SHOULD send the payloads defined in this specification in the order shown in the figures in Sections 1 and 2"
	// the figure of section 1.3.2: "HDR, SK {SA, Nr, KEr}"
	if got, want := payloadTypes(inner), []PayloadType{PayloadSA, PayloadNonce, PayloadKE}; !slices.Equal(got, want) {
		t.Errorf("the rekey answer carries payload types %v, want %v", got, want)
	}
	props, err := DecodeSA(sa.Body)
	if err != nil || len(props) != 1 || props[0].Number != 2 || props[0].Protocol != ProtoIKE || len(props[0].SPI) != 8 || len(props[0].Transforms) != 3 {
		t.Fatalf("invalid peer rekey response proposal: %#v, %v", props, err)
	}
	newSPIr := binary.BigEndian.Uint64(props[0].SPI)
	selectedProposal := props[0]
	selectedProposal.Number = 1
	selectedProposal.SPI = nil
	newSuite, err := suiteFromProposal(selectedProposal, []Proposal{ikeProposal()}, false)
	if err != nil {
		t.Fatal(err)
	}
	group, public, err := DecodeKE(ke.Body)
	if err != nil || group != DH_CURVE25519 || newSPIr == 0 || len(nonce.Body) == 0 {
		t.Fatalf("invalid peer rekey response KE: group=%d spi=%016x err=%v", group, newSPIr, err)
	}
	shared, err := dh.SharedSecret(public)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := DeriveRekeyedIKEKeys(old.suite.PRFID, old.skD, newSuite, shared, ni, nonce.Body, newSPIi, newSPIr)
	if err != nil {
		t.Fatal(err)
	}
	current, retained := s.contexts()
	if current == old || !current.responder || retained != old || current.suite != newSuite || current.spiI != newSPIi || current.spiR != newSPIr || string(current.skD) != string(keys.SKd) || string(current.skei) != string(keys.SKei) || string(current.sker) != string(keys.SKer) {
		t.Fatalf("peer rekey contexts = current %#v old %#v", current, retained)
	}
	if got := s.currentChild(); got.EncrID != child.EncrID || got.EncrKeyBits != child.EncrKeyBits || got.LocalSPI != child.LocalSPI || got.RemoteSPI != child.RemoteSPI || len(got.InboundKey) != 0 || len(got.OutboundKey) != 0 {
		t.Fatalf("Child SA changed during peer IKE rekey: %#v, want %#v", got, child)
	}

	request, err = EncryptMessage(current.suite, keys.SKei, Header{SPIInitiator: newSPIi, SPIResponder: newSPIr, ExchangeType: INFORMATIONAL, Flags: FlagInitiator, MessageID: 0}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := peer.WriteToUDP(withNonESPMarker(request), muxLoopback(mux)); err != nil {
		t.Fatal(err)
	}
	n, _, err = peer.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	responseRaw = append([]byte(nil), buf[4:n]...)
	response, err = DecodeMessage(responseRaw)
	if err != nil || response.Header.SPIInitiator != newSPIi || response.Header.SPIResponder != newSPIr || response.Header.Flags != FlagResponse {
		t.Fatalf("new-context response header = %#v, err=%v", response.Header, err)
	}
	if _, err := DecryptMessage(current.suite, keys.SKer, responseRaw, response); err != nil {
		t.Fatalf("decrypt new-context response: %v", err)
	}

	request, err = EncryptMessage(old.suite, old.sker, Header{SPIInitiator: oldSPIi, SPIResponder: oldSPIr, ExchangeType: INFORMATIONAL, MessageID: 1}, nil, deleteIKEPayloads())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := peer.WriteToUDP(withNonESPMarker(request), muxLoopback(mux)); err != nil {
		t.Fatal(err)
	}
	n, _, err = peer.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	responseRaw = append([]byte(nil), buf[4:n]...)
	response, err = DecodeMessage(responseRaw)
	if err != nil || response.Header.SPIInitiator != oldSPIi || response.Header.SPIResponder != oldSPIr {
		t.Fatalf("old delete response header = %#v, err=%v", response.Header, err)
	}
	if _, err := DecryptMessage(old.suite, old.skei, responseRaw, response); err != nil {
		t.Fatalf("decrypt old delete response: %v", err)
	}
	_, retained = s.contexts()
	if retained != nil || s.contextForHeader(&Header{SPIInitiator: oldSPIi, SPIResponder: oldSPIr}) != nil {
		t.Fatal("old IKE context was not removed after peer delete")
	}

	_ = mux.Close()
	if err := <-runDone; err == nil {
		t.Fatal("Run returned nil after mux close")
	}
}

func TestPeerIKERekeyInvalidKERequestsPreferredGroup(t *testing.T) {
	const spiI = 0x0102030405060708
	const spiR = 0x1112131415161718
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	ctx := &ikeContext{suite: suite, spiI: spiI, spiR: spiR, skei: make([]byte, 20), sker: make([]byte, 20)}
	s := &Session{current: ctx}
	newSPI := make([]byte, 8)
	binary.BigEndian.PutUint64(newSPI, 0x2122232425262728)

	raw, err := s.handleIKERekey(ctx, 0, []RawPayload{
		{Type: PayloadSA, Body: EncodeSA([]Proposal{{Number: 1, Protocol: ProtoIKE, SPI: newSPI, Transforms: ikeProposal().Transforms}})},
		{Type: PayloadNonce, Body: EncodeNonce([]byte("peer rekey nonce"))},
		{Type: PayloadKE, Body: EncodeKE(14, []byte{1})},
	})
	if err != nil {
		t.Fatal(err)
	}
	response, err := DecodeMessage(raw.whole)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := DecryptMessage(suite, ctx.skei, raw.whole, response)
	if err != nil {
		t.Fatal(err)
	}
	notifyPayload := findType(inner, PayloadN)
	if notifyPayload == nil {
		t.Fatalf("IKE rekey response has no notify: %#v", inner)
	}
	notify, err := DecodeNotify(notifyPayload.Body)
	if err != nil {
		t.Fatal(err)
	}
	if notify.Type != N_INVALID_KE_PAYLOAD || len(notify.Data) != 2 || binary.BigEndian.Uint16(notify.Data) != DH_CURVE25519 {
		t.Fatalf("IKE rekey notify = %#v, want INVALID_KE_PAYLOAD for group %d", notify, DH_CURVE25519)
	}
}

func TestSessionRekeyIKECollisionKeepsHigherNonceCandidate(t *testing.T) {
	peer := listenPeer(t)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	mux, err := transport.Dial("127.0.0.1:0", peerAddr.IP, peerAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()

	const oldSPIi = 0x0102030405060708
	const oldSPIr = 0x1112131415161718
	const peerSPIi = 0x2122232425262728
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256, DHGroup: DH_CURVE25519}
	old := &ikeContext{suite: suite, spiI: oldSPIi, spiR: oldSPIr, authMID: 1, nextLocalMID: 2,
		skD: []byte("old IKE rekey SK_d material-------"), skei: make([]byte, 20), sker: make([]byte, 20)}
	localNonce := make([]byte, 32)
	for i := range localNonce {
		localNonce[i] = 2
	}
	peerNonce := make([]byte, 32)
	for i := range peerNonce {
		peerNonce[i] = 1
	}
	events := &recorder{}
	s := &Session{mux: mux, current: old, requests: make(chan *localRequest, 1), suites: func() Suites { return classicalLists }, events: events.record, ikeRekeyNonce: func(n []byte) error {
		copy(n, localNonce)
		return nil
	}}
	if err := mux.RegisterIKE(oldSPIi); err != nil {
		t.Fatal(err)
	}

	peerDone := make(chan struct{})
	winnerSPIi := make(chan uint64, 1)
	go func() {
		defer close(peerDone)
		peer.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 2048)
		n, addr, err := peer.ReadFromUDP(buf)
		if err != nil {
			t.Errorf("read local rekey request: %v", err)
			return
		}
		localRaw := append([]byte(nil), buf[4:n]...)
		localRequest, err := DecodeMessage(localRaw)
		if err != nil {
			t.Errorf("decode local rekey request: %v", err)
			return
		}
		localInner, err := DecryptMessage(suite, old.skei, localRaw, localRequest)
		if err != nil {
			t.Errorf("decrypt local rekey request: %v", err)
			return
		}
		localSA, localNI, localKE := findType(localInner, PayloadSA), findType(localInner, PayloadNonce), findType(localInner, PayloadKE)
		if localSA == nil || localNI == nil || localKE == nil {
			t.Errorf("invalid local rekey request")
			return
		}
		localProps, err := DecodeSA(localSA.Body)
		if err != nil || len(localProps) != 3 {
			t.Errorf("invalid local rekey proposal: %v", err)
			return
		}
		localSPIi := binary.BigEndian.Uint64(localProps[0].SPI)
		winnerSPIi <- localSPIi
		localGroup, _, err := DecodeKE(localKE.Body)
		if err != nil || localGroup != DH_CURVE25519 || string(localNI.Body) != string(localNonce) {
			t.Errorf("local rekey nonce or KE = %x, group %d, err %v", localNI.Body, localGroup, err)
			return
		}

		peerDH, err := GenerateDH(DH_CURVE25519)
		if err != nil {
			t.Errorf("generate peer DH: %v", err)
			return
		}
		spi := make([]byte, 8)
		binary.BigEndian.PutUint64(spi, peerSPIi)
		collisionRequest, err := EncryptMessage(suite, old.sker, Header{SPIInitiator: oldSPIi, SPIResponder: oldSPIr, ExchangeType: CREATE_CHILD_SA, MessageID: 0}, nil, []RawPayload{
			{Type: PayloadSA, Body: EncodeSA([]Proposal{{Number: 1, Protocol: ProtoIKE, SPI: spi, Transforms: []Transform{{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128}, {Type: TransPRF, ID: PRF_HMAC_SHA2_256}, {Type: TransDH, ID: DH_CURVE25519}}}})},
			{Type: PayloadNonce, Body: EncodeNonce(peerNonce)},
			{Type: PayloadKE, Body: EncodeKE(DH_CURVE25519, peerDH.PublicBytes())},
		})
		if err != nil {
			t.Errorf("build peer rekey request: %v", err)
			return
		}
		if _, err := peer.WriteToUDP(withNonESPMarker(collisionRequest), addr); err != nil {
			t.Errorf("write peer rekey request: %v", err)
			return
		}

		n, _, err = peer.ReadFromUDP(buf)
		if err != nil {
			t.Errorf("read peer rekey response: %v", err)
			return
		}
		collisionRaw := append([]byte(nil), buf[4:n]...)
		collisionResponse, err := DecodeMessage(collisionRaw)
		if err != nil {
			t.Errorf("decode peer rekey response: %v", err)
			return
		}
		collisionInner, err := DecryptMessage(suite, old.skei, collisionRaw, collisionResponse)
		if err != nil {
			t.Errorf("decrypt peer rekey response: %v", err)
			return
		}
		collisionSA, collisionNR, collisionKE := findType(collisionInner, PayloadSA), findType(collisionInner, PayloadNonce), findType(collisionInner, PayloadKE)
		if collisionSA == nil || collisionNR == nil || collisionKE == nil {
			t.Errorf("invalid peer rekey response")
			return
		}
		collisionProps, err := DecodeSA(collisionSA.Body)
		if err != nil || len(collisionProps) != 1 {
			t.Errorf("invalid peer rekey proposal: %v", err)
			return
		}
		peerSPIr := binary.BigEndian.Uint64(collisionProps[0].SPI)
		_, responderPublic, err := DecodeKE(collisionKE.Body)
		if err != nil {
			t.Errorf("decode peer response KE: %v", err)
			return
		}
		shared, err := peerDH.SharedSecret(responderPublic)
		if err != nil {
			t.Errorf("derive peer shared secret: %v", err)
			return
		}
		collisionKeys, err := DeriveRekeyedIKEKeys(old.suite.PRFID, old.skD, suite, shared, peerNonce, collisionNR.Body, peerSPIi, peerSPIr)
		if err != nil {
			t.Errorf("derive collision keys: %v", err)
			return
		}
		if s.contextForHeader(&Header{SPIInitiator: peerSPIi, SPIResponder: peerSPIr}) == nil {
			t.Error("lower-nonce candidate is not routed while awaiting retirement")
			return
		}

		responderDH, err := GenerateDH(DH_CURVE25519)
		if err != nil {
			t.Errorf("generate local rekey responder DH: %v", err)
			return
		}
		spi = make([]byte, 8)
		binary.BigEndian.PutUint64(spi, 0x3132333435363738)
		localResponse, err := EncryptMessage(suite, old.sker, Header{SPIInitiator: oldSPIi, SPIResponder: oldSPIr, ExchangeType: CREATE_CHILD_SA, Flags: FlagResponse, MessageID: localRequest.Header.MessageID}, nil, []RawPayload{
			{Type: PayloadSA, Body: EncodeSA([]Proposal{{Number: 1, Protocol: ProtoIKE, SPI: spi, Transforms: []Transform{{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128}, {Type: TransPRF, ID: PRF_HMAC_SHA2_256}, {Type: TransDH, ID: DH_CURVE25519}}}})},
			{Type: PayloadNonce, Body: EncodeNonce(localNonce)},
			{Type: PayloadKE, Body: EncodeKE(DH_CURVE25519, responderDH.PublicBytes())},
		})
		if err != nil {
			t.Errorf("build local rekey response: %v", err)
			return
		}
		if _, err := peer.WriteToUDP(withNonESPMarker(localResponse), addr); err != nil {
			t.Errorf("write local rekey response: %v", err)
			return
		}

		// the winner sends one Delete, for the SA its rekey replaced, and the peer created the losing candidate
		// RFC 7296 section 2.8.2: "The new IKE SA containing the lowest nonce SHOULD be deleted by the node that created it, and the other surviving new IKE SA MUST inherit all the Child SAs."
		n, _, err = peer.ReadFromUDP(buf)
		if err != nil {
			t.Errorf("read replaced-context delete: %v", err)
			return
		}
		oldDeleteRaw := append([]byte(nil), buf[4:n]...)
		oldDelete, err := DecodeMessage(oldDeleteRaw)
		if err != nil {
			t.Errorf("decode replaced-context delete: %v", err)
			return
		}
		oldDeleteInner, err := DecryptMessage(suite, old.skei, oldDeleteRaw, oldDelete)
		oldDeletePayload := findType(oldDeleteInner, PayloadD)
		if err != nil || oldDeletePayload == nil || oldDelete.Header.SPIInitiator != oldSPIi || oldDelete.Header.SPIResponder != oldSPIr {
			t.Errorf("invalid replaced-context delete: %#v, %v", oldDelete.Header, err)
			return
		}
		oldDeleteResponse, err := EncryptMessage(suite, old.sker, Header{SPIInitiator: oldSPIi, SPIResponder: oldSPIr, ExchangeType: INFORMATIONAL, Flags: FlagResponse, MessageID: oldDelete.Header.MessageID}, nil, nil)
		if err != nil {
			t.Errorf("build replaced-context delete response: %v", err)
			return
		}
		if _, err := peer.WriteToUDP(withNonESPMarker(oldDeleteResponse), addr); err != nil {
			t.Errorf("write replaced-context delete response: %v", err)
			return
		}

		// the peer retires its own losing candidate, which this end kept routable for that
		loserDelete, err := EncryptMessage(suite, collisionKeys.SKei, Header{SPIInitiator: peerSPIi, SPIResponder: peerSPIr, ExchangeType: INFORMATIONAL, Flags: FlagInitiator, MessageID: 0}, nil, deleteIKEPayloads())
		if err != nil {
			t.Errorf("build loser delete: %v", err)
			return
		}
		if _, err := peer.WriteToUDP(withNonESPMarker(loserDelete), addr); err != nil {
			t.Errorf("write loser delete: %v", err)
			return
		}
		n, _, err = peer.ReadFromUDP(buf)
		if err != nil {
			t.Errorf("read loser delete response: %v", err)
			return
		}
		loserRaw := append([]byte(nil), buf[4:n]...)
		loserResponse, err := DecodeMessage(loserRaw)
		if err != nil {
			t.Errorf("decode loser delete response: %v", err)
			return
		}
		if _, err := DecryptMessage(suite, collisionKeys.SKer, loserRaw, loserResponse); err != nil {
			t.Errorf("invalid loser delete response: %v", err)
			return
		}
	}()

	runDone := make(chan error, 1)
	go func() { runDone <- s.Run(context.Background()) }()
	stop := stopRun(mux, runDone)
	if err := s.RekeyIKE(); err != nil {
		stop()
		t.Fatalf("RekeyIKE: %v", err)
	}
	<-peerDone
	localSPIi := <-winnerSPIi
	current, retained := s.contexts()
	s.stateMu.RLock()
	collision := s.collision
	s.stateMu.RUnlock()
	if current == old || current.spiI != localSPIi || retained != nil || collision != nil {
		stop()
		t.Fatalf("collision contexts = current %#v old %#v collision %#v", current, retained, collision)
	}
	if s.contextForHeader(&Header{SPIInitiator: oldSPIi, SPIResponder: oldSPIr}) != nil {
		stop()
		t.Fatal("replaced IKE context remains routed")
	}
	if err := stop(); err == nil {
		t.Fatal("Run returned nil after mux close")
	}
	// Run joins every rekey it started before it returns, so a rekey of its own beside the test's is counted here
	if got := recordedKind(events, "ike.rekey.started"); got != 1 {
		t.Errorf("the session started %d IKE SA rekeys, want the test's one", got)
	}
}

func TestCompareIKENonces(t *testing.T) {
	tests := []struct {
		a, b []byte
		want int
	}{
		{[]byte{0x00, 0xff}, []byte{0x01, 0x00}, -1},
		{[]byte{0x80}, []byte{0x7f}, 1},
		{[]byte{0x42}, []byte{0x42}, 0},
		{[]byte{0x00, 0x01}, []byte{0x01}, -1},
		{[]byte{0xff}, []byte{0x01, 0x00}, 1},
	}
	for _, test := range tests {
		got := compareIKENonces(test.a, test.b)
		if (got < 0 && test.want < 0) || (got == 0 && test.want == 0) || (got > 0 && test.want > 0) {
			continue
		}
		t.Errorf("compareIKENonces(%x, %x) = %d, want sign %d", test.a, test.b, got, test.want)
	}
}

func TestLowestNonceSelectsRedundantExchange(t *testing.T) {
	tests := []struct {
		name                             string
		firstI, firstR, secondI, secondR byte
		firstLoses                       bool
	}{
		{"first initiator lowest", 1, 4, 2, 3, true},
		{"first responder lowest", 4, 1, 2, 3, true},
		{"second initiator lowest", 2, 4, 1, 3, false},
		{"second responder lowest", 2, 3, 4, 1, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := lowestNonceBelongsToFirst([]byte{test.firstI}, []byte{test.firstR}, []byte{test.secondI}, []byte{test.secondR})
			if got != test.firstLoses {
				t.Fatalf("firstLoses = %v, want %v", got, test.firstLoses)
			}
		})
	}
}

func encodeTestMessage(t *testing.T, hdr Header, payloads []RawPayload) []byte {
	t.Helper()
	m := &Message{Header: hdr, Payloads: payloads}
	return m.Encode()
}

// withNonESPMarker prepends the 4-byte zero marker transport.Mux uses to
// demux IKE from ESP traffic (RFC 3948). Without it, a reply sent by the
// mock peer below would be classified as ESP and never reach RecvIKEUntil.
func withNonESPMarker(b []byte) []byte {
	return append([]byte{0, 0, 0, 0}, b...)
}

func TestIKEAuthAuthenticatesBeforeChildFailure(t *testing.T) {
	testIKEAuthAuthenticatesBeforeChildFailure(t, "ranet-test")
}

func TestIKEAuthAcrossOrganizations(t *testing.T) {
	testIKEAuthAuthenticatesBeforeChildFailure(t, "remote-org")
}

func testIKEAuthAuthenticatesBeforeChildFailure(t *testing.T, remoteOrganization string) {
	t.Helper()
	peer := listenPeer(t)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	mux, err := transport.Dial("127.0.0.1:0", peerAddr.IP, peerAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()

	_, localPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	remotePublic, remotePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cfg := PeerConfig{
		Local:           identity.MustParse("ranet-test/initiator:1"),
		LocalPrivateKey: localPrivate,
		Remote:          identity.MustParse(remoteOrganization + "/responder:2"),
		RemotePublicKey: remotePublic,
	}

	const spiI = 0x0102030405060708
	const spiR = 0x1112131415161718
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	s := &Session{
		mux: mux,
		current: &ikeContext{
			suite: suite, spiI: spiI, spiR: spiR, authMID: 1, nextLocalMID: 2,
			skei: make([]byte, 20), sker: make([]byte, 20),
			skD: make([]byte, 32), skpi: make([]byte, 32), skpr: make([]byte, 32),
		},
		requests: make(chan *localRequest, 1),
	}
	realMessage1 := []byte("test IKE_SA_INIT request")
	realMessage2 := []byte("test IKE_SA_INIT response")
	ni := make([]byte, 32)
	nr := make([]byte, 32)

	peerDone := make(chan error, 1)
	go func() {
		peerDone <- func() error {
			buf := make([]byte, 4096)
			peer.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, clientAddr, err := peer.ReadFromUDP(buf)
			if err != nil {
				return fmt.Errorf("read IKE_AUTH request: %w", err)
			}
			if n <= 4 {
				return fmt.Errorf("short marked IKE_AUTH request: %d bytes", n)
			}
			raw := append([]byte(nil), buf[4:n]...)
			request, err := DecodeMessage(raw)
			if err != nil {
				return fmt.Errorf("decode IKE_AUTH request: %w", err)
			}
			if request.Header.ExchangeType != IKE_AUTH || request.Header.MessageID != 1 {
				return fmt.Errorf("unexpected IKE_AUTH header: exchange=%d message-id=%d", request.Header.ExchangeType, request.Header.MessageID)
			}
			if _, err := DecryptMessage(suite, s.current.skei, raw, request); err != nil {
				return fmt.Errorf("decrypt IKE_AUTH request: %w", err)
			}

			idr := idBody(remoteOrganization + "/responder:2")
			macedID := prf(suite.PRFID, s.current.skpr, idr)
			auth := BuildAuth(remotePrivate, concat(realMessage2, ni, macedID))
			response, err := EncryptMessage(suite, s.current.sker, Header{
				SPIInitiator: spiI, SPIResponder: spiR, ExchangeType: IKE_AUTH,
				Flags: FlagResponse, MessageID: 1,
			}, nil, []RawPayload{
				{Type: PayloadIDr, Body: idr},
				{Type: PayloadAUTH, Body: auth},
				{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_NO_PROPOSAL_CHOSEN})},
			})
			if err != nil {
				return fmt.Errorf("encrypt IKE_AUTH response: %w", err)
			}
			// an SK-shaped packet with a forged tag ends no exchange
			forged := append([]byte(nil), response...)
			forged[len(forged)-1] ^= 1
			if _, err := peer.WriteToUDP(withNonESPMarker(forged), clientAddr); err != nil {
				return err
			}
			if _, err := peer.WriteToUDP(withNonESPMarker(response), clientAddr); err != nil {
				return fmt.Errorf("write IKE_AUTH response: %w", err)
			}

			n, _, err = peer.ReadFromUDP(buf)
			if err != nil {
				return fmt.Errorf("read IKE Delete request: %w", err)
			}
			if n <= 4 {
				return fmt.Errorf("short marked IKE Delete request: %d bytes", n)
			}
			raw = append([]byte(nil), buf[4:n]...)
			deleteMessage, err := DecodeMessage(raw)
			if err != nil {
				return fmt.Errorf("decode IKE Delete request: %w", err)
			}
			if deleteMessage.Header.ExchangeType != INFORMATIONAL || deleteMessage.Header.MessageID != 2 {
				return fmt.Errorf("unexpected IKE Delete header: exchange=%d message-id=%d", deleteMessage.Header.ExchangeType, deleteMessage.Header.MessageID)
			}
			deleteInner, err := DecryptMessage(suite, s.current.skei, raw, deleteMessage)
			if err != nil {
				return fmt.Errorf("decrypt IKE Delete request: %w", err)
			}
			if len(deleteInner) != 1 || deleteInner[0].Type != PayloadD {
				return fmt.Errorf("IKE Delete inner payloads = %v, want one Delete", deleteInner)
			}
			deletePayload, err := DecodeDelete(deleteInner[0].Body)
			if err != nil {
				return fmt.Errorf("decode IKE Delete payload: %w", err)
			}
			if deletePayload.Protocol != ProtoIKE || len(deletePayload.SPIs) != 0 {
				return fmt.Errorf("IKE Delete = %+v, want protocol IKE and no SPIs", deletePayload)
			}

			deleteResponse, err := EncryptMessage(suite, s.current.sker, Header{
				SPIInitiator: spiI, SPIResponder: spiR, ExchangeType: INFORMATIONAL,
				Flags: FlagResponse, MessageID: 2,
			}, nil, nil)
			if err != nil {
				return fmt.Errorf("encrypt IKE Delete response: %w", err)
			}
			forged = append([]byte(nil), deleteResponse...)
			forged[len(forged)-1] ^= 1
			if _, err := peer.WriteToUDP(withNonESPMarker(forged), clientAddr); err != nil {
				return err
			}
			if _, err := peer.WriteToUDP(withNonESPMarker(deleteResponse), clientAddr); err != nil {
				return fmt.Errorf("write IKE Delete response: %w", err)
			}
			return nil
		}()
	}()

	err = s.completeIKEAuth(cfg, realMessage1, realMessage2, ni, nr, intAuth{})
	if err == nil || err.Error() != "ike: Child SA rejected: notify type 14" {
		t.Fatalf("completeIKEAuth error = %v, want authenticated Child SA rejection", err)
	}
	if err := <-peerDone; err != nil {
		t.Fatal(err)
	}
}

// the responder holds an authenticated SA until told, so a Delete whose mux closes before its answer arrives goes out once more
// RFC 7296 section 2.1: "A retransmission from the initiator MUST be bitwise identical to the original request."
func TestAuthenticatedSAIsDeletedAgainWhenItsMuxClosesUnderTheDelete(t *testing.T) {
	peer := listenPeer(t)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	hub, err := transport.NewHub("127.0.0.1:0", transport.Underlay{}, transport.Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { hub.Close() })
	mux, err := hub.NewMux(peerAddr.IP, peerAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()

	_, localPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	remotePublic, remotePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cfg := PeerConfig{
		Local:           identity.MustParse("ranet-test/initiator:1"),
		LocalPrivateKey: localPrivate,
		Remote:          identity.MustParse("ranet-test/responder:2"),
		RemotePublicKey: remotePublic,
	}
	const spiI = 0x0102030405060708
	const spiR = 0x1112131415161718
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	s := &Session{
		mux: mux,
		current: &ikeContext{
			suite: suite, spiI: spiI, spiR: spiR, authMID: 1, nextLocalMID: 2,
			skei: make([]byte, 20), sker: make([]byte, 20),
			skD: make([]byte, 32), skpi: make([]byte, 32), skpr: make([]byte, 32),
		},
		requests: make(chan *localRequest, 1),
	}
	realMessage1 := []byte("test IKE_SA_INIT request")
	realMessage2 := []byte("test IKE_SA_INIT response")
	ni := make([]byte, 32)
	nr := make([]byte, 32)

	buf := make([]byte, 4096)
	readDelete := func() ([]byte, error) {
		for {
			n, _, err := peer.ReadFromUDP(buf)
			if err != nil {
				return nil, err
			}
			if n <= 4 {
				continue
			}
			raw := bytes.Clone(buf[4:n])
			m, err := DecodeMessage(raw)
			if err != nil || m.Header.ExchangeType != INFORMATIONAL || m.Header.MessageID != 2 {
				continue
			}
			inner, err := DecryptMessage(suite, s.current.skei, raw, m)
			if err != nil {
				return nil, fmt.Errorf("decrypt the INFORMATIONAL request: %w", err)
			}
			if len(inner) != 1 || inner[0].Type != PayloadD {
				return nil, fmt.Errorf("the INFORMATIONAL request carries %v, want one Delete", inner)
			}
			if d, err := DecodeDelete(inner[0].Body); err != nil || d.Protocol != ProtoIKE {
				return nil, fmt.Errorf("the INFORMATIONAL request deletes %+v (%v), want the IKE SA", d, err)
			}
			return raw, nil
		}
	}
	peerDone := make(chan error, 1)
	go func() {
		peerDone <- func() error {
			peer.SetReadDeadline(time.Now().Add(answerBudget))
			_, clientAddr, err := peer.ReadFromUDP(buf)
			if err != nil {
				return fmt.Errorf("read IKE_AUTH request: %w", err)
			}
			idr := idBody("ranet-test/responder:2")
			auth := BuildAuth(remotePrivate, concat(realMessage2, ni, prf(suite.PRFID, s.current.skpr, idr)))
			response, err := EncryptMessage(suite, s.current.sker, Header{
				SPIInitiator: spiI, SPIResponder: spiR, ExchangeType: IKE_AUTH, Flags: FlagResponse, MessageID: 1,
			}, nil, []RawPayload{
				{Type: PayloadIDr, Body: idr},
				{Type: PayloadAUTH, Body: auth},
				{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_NO_PROPOSAL_CHOSEN})},
			})
			if err != nil {
				return fmt.Errorf("encrypt IKE_AUTH response: %w", err)
			}
			if _, err := peer.WriteToUDP(withNonESPMarker(response), clientAddr); err != nil {
				return fmt.Errorf("write IKE_AUTH response: %w", err)
			}
			first, err := readDelete()
			if err != nil {
				return fmt.Errorf("read IKE Delete request: %w", err)
			}
			// the Delete goes unanswered and its mux closes while it waits
			mux.Close()
			again, err := readDelete()
			if err != nil {
				return fmt.Errorf("read IKE Delete request after the mux closed: %w", err)
			}
			if !bytes.Equal(again, first) {
				return fmt.Errorf("the Delete sent after the mux closed is a new encryption, not the request it retransmits")
			}
			return nil
		}()
	}()

	if err := s.completeIKEAuth(cfg, realMessage1, realMessage2, ni, nr, intAuth{}); err == nil {
		t.Fatal("completeIKEAuth took an authenticated Child SA rejection")
	}
	if err := <-peerDone; err != nil {
		t.Fatal(err)
	}
}

// an active attacker that answered IKE_SA_INIT itself holds SK_er
// so the checks the initiator makes on the IKE_AUTH answer are all that keep it from installing a Child SA with that attacker
// RFC 7296 section 2.21.2: "If the error occurs on the initiator, the notification MAY be returned in a separate INFORMATIONAL exchange, usually with no other payloads."
// RFC 7296 section 2.15 signs "RestOfRespIDPayload = IDType | RESERVED | RespIDData", and an IDr naming the endpoint dialed in other octets than the ones AUTH signed is refused
func TestInitiatorRefusesWrongIKEAuthAnswers(t *testing.T) {
	full := fullRangeSelectors()
	narrowed := EncodeTS([]TrafficSelector{{Type: TS_IPV4_ADDR_RANGE, EndPort: 0xffff,
		StartAddr: net.IPv4(10, 0, 0, 0).To4(), EndAddr: net.IPv4(10, 255, 255, 255).To4()}, FullRangeV6()})
	child := func(spi []byte, transforms ...Transform) []byte {
		return EncodeSA([]Proposal{{Number: 1, Protocol: ProtoESP, SPI: spi, Transforms: transforms}})
	}
	encryption := Transform{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128}
	esn := Transform{Type: TransESN, ID: ESN_NO}
	usable := child([]byte{0, 0, 0, 9}, encryption, esn)
	deletion := RawPayload{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoIKE})}
	refusal := func(notify NotifyType, data ...byte) RawPayload {
		return RawPayload{Type: PayloadN, Body: EncodeNotify(Notify{Type: notify, Data: data})}
	}
	mapped := append(make([]byte, 10), 0xff, 0xff, 192, 0, 2, 10)
	reserved := idBody("ranet-test/responder:2")
	reserved[1] = 1
	for name, test := range map[string]struct {
		idr          []byte       // the answer's IDr payload body, the responder's DN where nil
		signed       []byte       // the IDr payload body the answer's AUTH signs, idr where nil
		aliases      Aliases      // the initiator's auth.aliases
		forged       bool         // another key than the responder's signs the answer's AUTH
		alone        []RawPayload // the answer carries these and no IDr or AUTH
		notifies     []RawPayload // the answer carries these after AUTH
		critical     PayloadType  // the answer ends in a payload of this type, marked critical
		trailing     bool         // a byte past the answer's payload chain makes it malformed
		sa, tsi, tsr []byte       // nil leaves the payload out
		esp          []string     // the initiator's cap.crypto esp cipher, every cipher where nil
		want         string
		follow       RawPayload // what the INFORMATIONAL request at Message ID 2 carries, with no request where its type is zero
	}{
		"an IDr naming another node": {idr: idBody("ranet-test/elsewhere:2"), sa: usable, tsi: full, tsr: full,
			want: "names ranet-test/elsewhere:2, and this node dialed ranet-test/responder:2", follow: refusal(N_AUTHENTICATION_FAILED)},
		"IDr holding no distinguished name": {idr: EncodeID(ID_DER_ASN1_DN, []byte{0x04, 0x00}), sa: usable, tsi: full, tsr: full,
			want: "not a single RDNSequence", follow: refusal(N_AUTHENTICATION_FAILED)},
		"an FQDN IDr no alias names": {idr: EncodeID(ID_FQDN, []byte("responder.ranet-test.example")), sa: usable, tsi: full, tsr: full,
			want: `fqdn ID "responder.ranet-test.example" names no endpoint auth.aliases.remote lists`, follow: refusal(N_AUTHENTICATION_FAILED)},
		"an IDr whose alias names another endpoint": {
			aliases: Aliases{Remote: RemoteAliases{FQDN: map[string]identity.Identity{"responder.ranet-test.example": identity.MustParse("ranet-test/responder:3")}}},
			idr:     EncodeID(ID_FQDN, []byte("responder.ranet-test.example")), sa: usable, tsi: full, tsr: full,
			want: "names ranet-test/responder:3, and this node dialed ranet-test/responder:2", follow: refusal(N_AUTHENTICATION_FAILED)},
		"a KEY_ID IDr spelling another endpoint": {idr: EncodeID(ID_KEY_ID, []byte("ranet-test/responder:3")), sa: usable, tsi: full, tsr: full,
			want: "names ranet-test/responder:3, and this node dialed ranet-test/responder:2", follow: refusal(N_AUTHENTICATION_FAILED)},
		"an email IDr whose local part differs in case from the alias": {
			aliases: Aliases{Remote: RemoteAliases{Email: map[string]identity.Identity{"Responder@ranet-test.example": identity.MustParse("ranet-test/responder:2")}}},
			idr:     EncodeID(ID_RFC822_ADDR, []byte("responder@ranet-test.example")), sa: usable, tsi: full, tsr: full,
			want: "names no endpoint auth.aliases.remote lists", follow: refusal(N_AUTHENTICATION_FAILED)},
		"an IPv6 IDr mapping the IPv4 alias": {
			aliases: Aliases{Remote: RemoteAliases{IP: map[string]identity.Identity{"192.0.2.10": identity.MustParse("ranet-test/responder:2")}}},
			idr:     EncodeID(ID_IPV6_ADDR, mapped), sa: usable, tsi: full, tsr: full,
			want: "names no endpoint auth.aliases.remote lists", follow: refusal(N_AUTHENTICATION_FAILED)},
		"an IPv4 IDr of five octets": {idr: EncodeID(ID_IPV4_ADDR, []byte{192, 0, 2, 10, 0}), sa: usable, tsi: full, tsr: full,
			want: "carries a 5 octet address", follow: refusal(N_AUTHENTICATION_FAILED)},
		"an IPv6 IDr of four octets": {idr: EncodeID(ID_IPV6_ADDR, []byte{192, 0, 2, 10}), sa: usable, tsi: full, tsr: full,
			want: "carries a 4 octet address", follow: refusal(N_AUTHENTICATION_FAILED)},
		"an FQDN IDr holding a terminator": {
			aliases: Aliases{Remote: RemoteAliases{FQDN: map[string]identity.Identity{"responder.ranet-test.example": identity.MustParse("ranet-test/responder:2")}}},
			idr:     EncodeID(ID_FQDN, []byte("responder.ranet-test.example\r")), sa: usable, tsi: full, tsr: full,
			want: "holds the terminator", follow: refusal(N_AUTHENTICATION_FAILED)},
		"an IDr of a type no alias holds": {idr: EncodeID(10, []byte{0x30, 0x00}), sa: usable, tsi: full, tsr: full,
			want: `10 ID "0\x00" names no endpoint, since it is of a type no alias holds`, follow: refusal(N_AUTHENTICATION_FAILED)},
		"an FQDN IDr in another case than the one AUTH signed": {
			aliases: Aliases{Remote: RemoteAliases{FQDN: map[string]identity.Identity{"responder.ranet-test.example": identity.MustParse("ranet-test/responder:2")}}},
			idr:     EncodeID(ID_FQDN, []byte("RESPONDER.ranet-test.example")), signed: EncodeID(ID_FQDN, []byte("responder.ranet-test.example")),
			sa: usable, tsi: full, tsr: full, want: "AUTH signature verification failed", follow: refusal(N_AUTHENTICATION_FAILED)},
		"an IDr whose RESERVED octets changed after AUTH signed it": {idr: reserved, signed: idBody("ranet-test/responder:2"), sa: usable, tsi: full, tsr: full,
			want: "AUTH signature verification failed", follow: refusal(N_AUTHENTICATION_FAILED)},
		"AUTH another key signed": {forged: true, sa: usable, tsi: full, tsr: full,
			want: "AUTH signature verification failed", follow: refusal(N_AUTHENTICATION_FAILED)},
		"no IDr or AUTH beside a status notify": {alone: []RawPayload{{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_INITIAL_CONTACT})}},
			want: "incomplete IKE_AUTH response", follow: refusal(N_AUTHENTICATION_FAILED)},
		"payload chain short of its plaintext": {trailing: true, sa: usable, tsi: full, tsr: full,
			want: "trailing bytes", follow: refusal(N_INVALID_SYNTAX)},
		// PS, which RFC 8019 defines and this end does not implement
		"critical payload this end does not implement": {critical: 54, sa: usable, tsi: full, tsr: full,
			want: "marks unsupported payload type 54 critical", follow: refusal(N_UNSUPPORTED_CRITICAL_PAYLOAD, 54)},
		"responder's own refusal": {alone: []RawPayload{{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_AUTHENTICATION_FAILED})}},
			want: fmt.Sprintf("notify type %d", N_AUTHENTICATION_FAILED)},
		"responder's own refusal after a status notify": {alone: []RawPayload{
			{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_INITIAL_CONTACT})},
			{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_AUTHENTICATION_FAILED})},
		}, want: fmt.Sprintf("notify type %d", N_AUTHENTICATION_FAILED)},
		// RFC 7296 section 3.10.1: "An implementation receiving a Notify payload with one of these types that it does not recognize in a response MUST assume that the corresponding request has failed entirely."
		"an error notify of a type nothing assigns and no IDr or AUTH": {alone: []RawPayload{unrecognizedError},
			want: "IKE_AUTH rejected inside SK: notify type 8191"},
		"an error notify of a type nothing assigns beside a Child SA": {notifies: []RawPayload{unrecognizedError}, sa: usable, tsi: full, tsr: full,
			want: "Child SA rejected: notify type 8191", follow: deletion},
		// section 2.21.2: "In an IKE_AUTH exchange, or in the INFORMATIONAL exchange immediately following it (in case an error happened when processing a response to IKE_AUTH), the UNSUPPORTED_CRITICAL_PAYLOAD, INVALID_SYNTAX, and AUTHENTICATION_FAILED notifications are the only ones to cause the IKE SA to be deleted or not created, without a Delete payload."
		"AUTHENTICATION_FAILED beside AUTH and a Child SA": {notifies: []RawPayload{refusal(N_AUTHENTICATION_FAILED)}, sa: usable, tsi: full, tsr: full,
			want: fmt.Sprintf("IKE_AUTH rejected inside SK: notify type %d", N_AUTHENTICATION_FAILED)},
		"INVALID_SYNTAX beside AUTH and a Child SA": {notifies: []RawPayload{refusal(N_INVALID_SYNTAX)}, sa: usable, tsi: full, tsr: full,
			want: fmt.Sprintf("IKE_AUTH rejected inside SK: notify type %d", N_INVALID_SYNTAX)},
		"UNSUPPORTED_CRITICAL_PAYLOAD beside AUTH and a Child SA": {notifies: []RawPayload{refusal(N_UNSUPPORTED_CRITICAL_PAYLOAD, 250)}, sa: usable, tsi: full, tsr: full,
			want: fmt.Sprintf("IKE_AUTH rejected inside SK: notify type %d", N_UNSUPPORTED_CRITICAL_PAYLOAD)},
		"a notify that does not decode beside a Child SA": {notifies: []RawPayload{{Type: PayloadN, Body: []byte{0}}}, sa: usable, tsi: full, tsr: full,
			want: "short notify payload", follow: refusal(N_INVALID_SYNTAX)},
		"narrowed initiator selectors": {sa: usable, tsi: narrowed, tsr: full,
			want: "unsupported initiator traffic selectors", follow: deletion},
		"narrowed responder selectors": {sa: usable, tsi: full, tsr: narrowed,
			want: "unsupported responder traffic selectors", follow: deletion},
		"no traffic selectors": {sa: usable,
			want: "incomplete IKE_AUTH response", follow: deletion},
		"no Child SA": {tsi: full, tsr: full,
			want: "incomplete IKE_AUTH response", follow: deletion},
		"a Child SA with a zero SPI": {sa: child([]byte{0, 0, 0, 0}, encryption, esn), tsi: full, tsr: full,
			want: "zero SPI", follow: deletion},
		"two encryption transforms": {sa: child([]byte{0, 0, 0, 9}, encryption, encryption), tsi: full, tsr: full,
			want: "duplicate encryption transforms", follow: deletion},
		"a transform type the offer did not name": {sa: child([]byte{0, 0, 0, 9}, encryption, Transform{Type: TransInteg, ID: INTEG_NONE}),
			tsi: full, tsr: full, want: "transform type 3", follow: deletion},
		// RFC 7296 section 3.3.6: "The initiator of an exchange MUST check that the accepted offer is consistent with one of its proposals, and if not MUST terminate the exchange."
		"a cipher the initiator's lists left out": {esp: []string{"aes256gcm", "chacha20poly1305"}, sa: usable, tsi: full, tsr: full,
			want: "unoffered transform", follow: deletion},
	} {
		t.Run(name, func(t *testing.T) {
			peer := listenPeer(t)
			peerAddr := peer.LocalAddr().(*net.UDPAddr)
			mux, err := transport.Dial("127.0.0.1:0", peerAddr.IP, peerAddr.Port)
			if err != nil {
				t.Fatal(err)
			}
			defer mux.Close()
			_, localPrivate, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			remotePublic, remotePrivate, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			cfg := PeerConfig{
				Local: identity.MustParse("ranet-test/initiator:1"), LocalPrivateKey: localPrivate,
				Remote: identity.MustParse("ranet-test/responder:2"), RemotePublicKey: remotePublic,
				Aliases: test.aliases,
			}
			const spiI, spiR = 0x0102030405060708, 0x1112131415161718
			suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
			lists := suitesOf(t, Crypto{ESP: ESPSuites{Cipher: test.esp}})
			s := &Session{
				mux: mux,
				current: &ikeContext{
					suite: suite, spiI: spiI, spiR: spiR, authMID: 1, nextLocalMID: 2,
					skei: make([]byte, 20), sker: make([]byte, 20),
					skD: make([]byte, 32), skpi: make([]byte, 32), skpr: make([]byte, 32),
				},
				requests: make(chan *localRequest, 1),
				suites:   func() Suites { return lists },
			}
			realMessage2 := []byte("test IKE_SA_INIT response")
			ni, nr := make([]byte, 32), make([]byte, 32)

			buf := make([]byte, 4096)
			receive := func(exchange ExchangeType, messageID uint32, wait time.Duration) (*net.UDPAddr, []RawPayload, error) {
				for {
					_ = peer.SetReadDeadline(time.Now().Add(wait))
					n, from, err := peer.ReadFromUDP(buf)
					if err != nil || n <= 4 {
						return nil, nil, fmt.Errorf("read request %d: %d bytes, %v", messageID, n, err)
					}
					raw := slices.Clone(buf[4:n])
					request, err := DecodeMessage(raw)
					if err != nil {
						return nil, nil, err
					}
					// the initiator retransmits a request already answered when the answer takes longer than its timer, as on a loaded machine
					if request.Header.MessageID < messageID {
						continue
					}
					if request.Header.ExchangeType != exchange || request.Header.MessageID != messageID {
						return nil, nil, fmt.Errorf("request is exchange %d message %d, want %d and %d",
							request.Header.ExchangeType, request.Header.MessageID, exchange, messageID)
					}
					inner, err := DecryptMessage(suite, s.current.skei, raw, request)
					return from, inner, err
				}
			}
			answer := func(to *net.UDPAddr, exchange ExchangeType, messageID uint32, payloads []RawPayload) error {
				header := Header{SPIInitiator: spiI, SPIResponder: spiR, ExchangeType: exchange, Flags: FlagResponse, MessageID: messageID}
				first, plain := PayloadNone, encodePayloadChain(payloads)
				if len(payloads) > 0 {
					first = payloads[0].Type
				}
				if test.trailing && exchange == IKE_AUTH {
					plain = append(plain, 0xff)
				}
				iv := make([]byte, 8)
				rand.Read(iv)
				plain = append(plain, 0)
				response, err := encryptMessagePlaintextIV(suite, s.current.sker, header, nil, first, plain, iv)
				if err != nil {
					return err
				}
				_, err = peer.WriteToUDP(withNonESPMarker(response), to)
				return err
			}
			peerDone := make(chan error, 1)
			go func() {
				peerDone <- func() error {
					from, _, err := receive(IKE_AUTH, 1, answerBudget)
					if err != nil {
						return err
					}
					signer := remotePrivate
					if test.forged {
						signer = localPrivate
					}
					idr := idBody("ranet-test/responder:2")
					if test.idr != nil {
						idr = test.idr
					}
					signed := idr
					if test.signed != nil {
						signed = test.signed
					}
					auth := BuildAuth(signer, concat(realMessage2, ni, prf(suite.PRFID, s.current.skpr, signed)))
					payloads := []RawPayload{{Type: PayloadIDr, Body: idr}, {Type: PayloadAUTH, Body: auth}}
					if test.alone != nil {
						payloads = test.alone
					}
					payloads = append(payloads, test.notifies...)
					for _, p := range []RawPayload{{Type: PayloadSA, Body: test.sa}, {Type: PayloadTSi, Body: test.tsi}, {Type: PayloadTSr, Body: test.tsr}} {
						if p.Body != nil {
							payloads = append(payloads, p)
						}
					}
					if test.critical != PayloadNone {
						payloads = append(payloads, RawPayload{Type: test.critical, Critical: true, Body: []byte{0}})
					}
					if err := answer(from, IKE_AUTH, 1, payloads); err != nil {
						return err
					}
					if test.follow.Type == 0 {
						return nil
					}
					from, inner, err := receive(INFORMATIONAL, 2, answerBudget)
					if err != nil {
						return fmt.Errorf("the INFORMATIONAL request after IKE_AUTH: %w", err)
					}
					if len(inner) != 1 || inner[0].Type != test.follow.Type || !bytes.Equal(inner[0].Body, test.follow.Body) {
						return fmt.Errorf("the INFORMATIONAL request after IKE_AUTH carries %v, want %v", inner, test.follow)
					}
					return answer(from, INFORMATIONAL, 2, nil)
				}()
			}()

			err = s.completeIKEAuth(cfg, []byte("test IKE_SA_INIT request"), realMessage2, ni, nr, intAuth{})
			if err == nil {
				t.Fatal("the initiator took an IKE_AUTH answer it should have refused")
			}
			if !strings.Contains(err.Error(), test.want) || strings.Contains(err.Error(), "additionally failed") {
				t.Fatalf("the initiator refused with %q, want a refusal naming %q", err, test.want)
			}
			if err := <-peerDone; err != nil {
				t.Fatal(err)
			}
			if test.follow.Type == 0 {
				if _, inner, err := receive(INFORMATIONAL, 2, quietPeriod); err == nil {
					t.Errorf("the initiator answered the responder's own refusal with %v", inner)
				}
			}
		})
	}
}

// RFC 7296 section 3.2 on the critical bit: "MUST be ignored by the recipient if the recipient understands the payload type code."
// section 2.5: "If the critical flag is not set and the payload type is unsupported, that payload MUST be ignored."
// section 3.12: "Unfamiliar Vendor IDs MUST be ignored."
// a responder marking every payload of both its answers critical, the SK payload and the CERTREQ, CERT, CP and Vendor ID this end skips among them, and adding one of a type nothing assigns unmarked, is dialed as one marking none
// section 3.2 on the sender: "MUST be set to zero for payload types defined in this document."
func TestInitiatorIgnoresTheCriticalBitOnPayloadsItUnderstands(t *testing.T) {
	vendor := RawPayload{Type: PayloadV, Body: []byte("a vendor this end does not know")}
	marked := func(exchange ExchangeType, payloads []RawPayload) []RawPayload {
		if exchange == IKE_SA_INIT {
			// an X.509 certificate request naming one authority by the hash of its key
			payloads = append(payloads, RawPayload{Type: PayloadCERTREQ, Body: append([]byte{4}, make([]byte, 20)...)}, vendor)
		} else {
			payloads = append(payloads,
				RawPayload{Type: PayloadCERT, Body: append([]byte{4}, "a certificate this end does not read"...)},
				// a CFG_REPLY with no attributes
				RawPayload{Type: PayloadCP, Body: []byte{2, 0, 0, 0}},
				vendor,
			)
		}
		for i := range payloads {
			payloads[i].Critical = true
		}
		return append(payloads, RawPayload{Type: PayloadType(250), Body: []byte{1}})
	}
	saInit, auth, authRaw, err := dialPlayedResponder(t, marked, criticalSK)
	if err != nil {
		t.Fatalf("the initiator refused answers marking every payload critical: %v", err)
	}
	for request, payloads := range map[string][]RawPayload{"IKE_SA_INIT": saInit.Payloads, "IKE_AUTH": auth} {
		for _, payload := range payloads {
			if payload.Critical {
				t.Errorf("the %s request marks payload type %d critical", request, payload.Type)
			}
		}
	}
	if authRaw[HeaderLen+1]&0x80 != 0 {
		t.Error("the IKE_AUTH request marks its SK payload critical")
	}
}

// RFC 7296 section 2.5: "implementations MUST NOT reject as invalid a message with those payloads in any other order."
// section 2.5: "implementations SHOULD send the payloads defined in this specification in the order shown in the figures in Sections 1 and 2"
// a responder answering both requests with their payloads in reverse is dialed as one answering in order, and the requests keep the order of the figures
func TestInitiatorTakesAnswersInAnyOrderAndAsksInTheFiguresOrder(t *testing.T) {
	reversed := func(_ ExchangeType, payloads []RawPayload) []RawPayload {
		slices.Reverse(payloads)
		return payloads
	}
	asSent := func([]byte) {}
	saInit, auth, _, err := dialPlayedResponder(t, reversed, asSent)
	if err != nil {
		t.Fatalf("the initiator refused answers with their payloads in reverse: %v", err)
	}
	// the figure of section 1.2: "HDR, SAi1, KEi, Ni"
	// the notifies follow Ni, INTERMEDIATE_EXCHANGE_SUPPORTED among them for the default list's x25519+mlkem768
	if got, want := payloadTypes(saInit.Payloads), []PayloadType{PayloadSA, PayloadKE, PayloadNonce, PayloadN, PayloadN, PayloadN, PayloadN, PayloadN}; !slices.Equal(got, want) {
		t.Errorf("the IKE_SA_INIT request carries payload types %v, want %v", got, want)
	}
	// the figure of section 1.2: "HDR, SK {IDi, [CERT,] [CERTREQ,] [IDr,] AUTH, SAi2, TSi, TSr}"
	if got, want := payloadTypes(auth), []PayloadType{PayloadIDi, PayloadIDr, PayloadAUTH, PayloadSA, PayloadTSi, PayloadTSr}; !slices.Equal(got, want) {
		t.Errorf("the IKE_AUTH request carries payload types %v, want %v", got, want)
	}
}

// RFC 7296 section 3.10.1: "Notify payloads with status types MAY be added to any message and MUST be ignored if not recognized."
// a responder adding a status notify of a type nothing assigns to both its answers is dialed as one adding none
func TestInitiatorIgnoresStatusNotifiesItDoesNotRecognize(t *testing.T) {
	added := func(_ ExchangeType, payloads []RawPayload) []RawPayload {
		return append(payloads, unrecognizedStatus)
	}
	asSent := func([]byte) {}
	if _, _, _, err := dialPlayedResponder(t, added, asSent); err != nil {
		t.Fatalf("the initiator refused answers carrying status notify type 40000: %v", err)
	}
}

// RFC 7296 section 2.21.1: "In an IKE_SA_INIT exchange, any error notification causes the exchange to fail."
// section 2.21.1: "Because all error notifications are completely unauthenticated, the recipient should continue trying for some time before giving up."
// section 3.10.1: "An implementation receiving a Notify payload with one of these types that it does not recognize in a response MUST assume that the corresponding request has failed entirely."
// IKE_SA_INIT answers that carry an SA beside an error notify of a type nothing assigns, beside NO_PROPOSAL_CHOSEN and beside a notify that does not decode are passed over, and the IKE_AUTH request follows the answer after them, which carries a status notify of a type nothing assigns
func TestInitiatorPassesOverIKESAInitAnswersCarryingAnErrorNotify(t *testing.T) {
	peer := listenPeer(t)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	_, localPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	remotePublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cfg := PeerConfig{
		Local: identity.MustParse("ranet-test/initiator:1"), LocalPrivateKey: localPrivate,
		Remote: identity.MustParse("ranet-test/responder:2"), RemotePublicKey: remotePublic,
		RemoteAddr: peerAddr.IP, RemotePort: peerAddr.Port,
	}
	ctx, cancel := context.WithTimeout(context.Background(), answerBudget)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		if session, err := InitiateContext(ctx, cfg); err == nil {
			session.Mux().Close()
		}
	}()
	defer func() {
		cancel()
		<-finished
	}()

	buf := make([]byte, 4096)
	if err := peer.SetReadDeadline(time.Now().Add(answerBudget)); err != nil {
		t.Fatal(err)
	}
	n, from, err := peer.ReadFromUDP(buf)
	if err != nil || n <= 4 {
		t.Fatalf("the initiator sent no IKE_SA_INIT: %d bytes, %v", n, err)
	}
	request, err := DecodeMessage(slices.Clone(buf[4:n]))
	if err != nil {
		t.Fatal(err)
	}
	sa, ke := request.find(PayloadSA), request.find(PayloadKE)
	if sa == nil || ke == nil {
		t.Fatalf("the IKE_SA_INIT request carries %v", request.Payloads)
	}
	group, _, err := DecodeKE(ke.Body)
	if err != nil {
		t.Fatal(err)
	}
	proposal, suite, err := selectIKEProposal(sa.Body, group, Suites{}, false)
	if err != nil {
		t.Fatal(err)
	}
	dh, err := GenerateDH(suite.DHGroup)
	if err != nil {
		t.Fatal(err)
	}
	// each answer under its own responder SPI, so the IKE_AUTH request names the one it follows
	for i, notify := range []RawPayload{unrecognizedError, {Type: PayloadN, Body: EncodeNotify(Notify{Type: N_NO_PROPOSAL_CHOSEN})}, {Type: PayloadN, Body: []byte{0}}, unrecognizedStatus} {
		answer := (&Message{Header: Header{SPIInitiator: request.Header.SPIInitiator, SPIResponder: uint64(i + 1), ExchangeType: IKE_SA_INIT, Flags: FlagResponse}, Payloads: []RawPayload{
			{Type: PayloadSA, Body: EncodeSA([]Proposal{proposal})},
			{Type: PayloadKE, Body: EncodeKE(suite.DHGroup, dh.PublicBytes())},
			{Type: PayloadNonce, Body: EncodeNonce(make([]byte, 32))},
			{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_SIGNATURE_HASH_ALGORITHMS, Data: binary.BigEndian.AppendUint16(nil, HashIdentity)})},
			notify,
		}}).Encode()
		if _, err := peer.WriteToUDP(withNonESPMarker(answer), from); err != nil {
			t.Fatal(err)
		}
	}
	// past any retransmission of the IKE_SA_INIT request
	for {
		n, _, err := peer.ReadFromUDP(buf)
		if err != nil || n <= 4 {
			t.Fatalf("the initiator sent no IKE_AUTH: %d bytes, %v", n, err)
		}
		header, err := decodeHeader(buf[4:n])
		if err != nil {
			t.Fatal(err)
		}
		if header.ExchangeType == IKE_AUTH {
			if header.SPIResponder != 4 {
				t.Errorf("the IKE_AUTH request names responder SPI %d, want 4, that of the answer carrying no error", header.SPIResponder)
			}
			return
		}
	}
}

// dialPlayedResponder dials a responder the test plays, which answers IKE_SA_INIT and IKE_AUTH with the payloads shape makes of the ones it would send, sealing the IKE_AUTH answer after edit has changed its header and SK payload header
// it returns the IKE_SA_INIT request, the IKE_AUTH request decrypted with its wire image, and how the dial ended
func dialPlayedResponder(t *testing.T, shape func(exchange ExchangeType, payloads []RawPayload) []RawPayload, edit func(aad []byte)) (*Message, []RawPayload, []byte, error) {
	t.Helper()
	peer := listenPeer(t)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	_, localPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	remotePublic, remotePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cfg := PeerConfig{
		Local: identity.MustParse("ranet-test/initiator:1"), LocalPrivateKey: localPrivate,
		Remote: identity.MustParse("ranet-test/responder:2"), RemotePublicKey: remotePublic,
		RemoteAddr: peerAddr.IP, RemotePort: peerAddr.Port,
	}
	ctx, cancel := context.WithTimeout(context.Background(), answerBudget)
	var dialErr error
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		session, err := InitiateContext(ctx, cfg)
		if err == nil {
			session.Mux().Close()
		}
		dialErr = err
	}()
	defer func() {
		cancel()
		<-finished
	}()

	buf := make([]byte, 4096)
	if err := peer.SetReadDeadline(time.Now().Add(answerBudget)); err != nil {
		t.Fatal(err)
	}
	// read passes over retransmissions of the request before the one of exchange
	read := func(exchange ExchangeType) (*Message, []byte, *net.UDPAddr) {
		t.Helper()
		for {
			n, from, err := peer.ReadFromUDP(buf)
			if err != nil {
				t.Fatalf("the initiator sent no request of exchange %d: %v", exchange, err)
			}
			raw := slices.Clone(buf[4:n])
			message, err := DecodeMessage(raw)
			if err != nil {
				t.Fatal(err)
			}
			if message.Header.ExchangeType == exchange {
				return message, raw, from
			}
		}
	}

	saInit, _, from := read(IKE_SA_INIT)
	sa, ke, nonce := saInit.find(PayloadSA), saInit.find(PayloadKE), saInit.find(PayloadNonce)
	if sa == nil || ke == nil || nonce == nil {
		t.Fatalf("the IKE_SA_INIT request carries %v", saInit.Payloads)
	}
	group, public, err := DecodeKE(ke.Body)
	if err != nil {
		t.Fatal(err)
	}
	proposal, suite, err := selectIKEProposal(sa.Body, group, Suites{}, false)
	if err != nil {
		t.Fatal(err)
	}
	dh, err := GenerateDH(suite.DHGroup)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := dh.SharedSecret(public)
	if err != nil {
		t.Fatal(err)
	}
	ni, nr := DecodeNonce(nonce.Body), make([]byte, 32)
	rand.Read(nr)
	spiI, spiR := saInit.Header.SPIInitiator, randUint64Nonzero()
	message2 := (&Message{Header: Header{SPIInitiator: spiI, SPIResponder: spiR, ExchangeType: IKE_SA_INIT, Flags: FlagResponse}, Payloads: shape(IKE_SA_INIT, []RawPayload{
		{Type: PayloadSA, Body: EncodeSA([]Proposal{proposal})},
		{Type: PayloadKE, Body: EncodeKE(suite.DHGroup, dh.PublicBytes())},
		{Type: PayloadNonce, Body: EncodeNonce(nr)},
		{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_SIGNATURE_HASH_ALGORITHMS, Data: binary.BigEndian.AppendUint16(nil, HashIdentity)})},
	})}).Encode()
	if _, err := peer.WriteToUDP(withNonESPMarker(message2), from); err != nil {
		t.Fatal(err)
	}
	keys, err := DeriveIKEKeys(suite, shared, ni, nr, spiI, spiR)
	if err != nil {
		t.Fatal(err)
	}

	auth, authRaw, from := read(IKE_AUTH)
	inner, err := DecryptMessage(suite, keys.SKei, authRaw, auth)
	if err != nil {
		t.Fatal(err)
	}
	idr := idBody("ranet-test/responder:2")
	child := Proposal{Number: 1, Protocol: ProtoESP, SPI: []byte{0, 0, 0, 9}, Transforms: []Transform{
		{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128}, {Type: TransESN, ID: ESN_NO}}}
	header := Header{SPIInitiator: spiI, SPIResponder: spiR, ExchangeType: IKE_AUTH, Flags: FlagResponse, MessageID: 1}
	answer := sealedEdited(t, suite, keys.SKer, header, shape(IKE_AUTH, []RawPayload{
		{Type: PayloadIDr, Body: idr},
		{Type: PayloadAUTH, Body: BuildAuth(remotePrivate, concat(message2, ni, prf(suite.PRFID, keys.SKpr, idr)))},
		{Type: PayloadSA, Body: EncodeSA([]Proposal{child})},
		{Type: PayloadTSi, Body: fullRangeSelectors()},
		{Type: PayloadTSr, Body: fullRangeSelectors()},
	}), edit)
	if _, err := peer.WriteToUDP(withNonESPMarker(answer), from); err != nil {
		t.Fatal(err)
	}
	<-finished
	return saInit, inner, authRaw, dialErr
}

// RFC 7296 section 2.5: "If the critical flag is set and the payload type is unrecognized, the message MUST be rejected"
// an IKE_SA_INIT answer that carries a critical payload of a type nothing assigns ends the dial with that refusal
func TestInitiatorRefusesAnIKESAInitAnswerMarkingAnUnsupportedPayloadCritical(t *testing.T) {
	peer := listenPeer(t)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	peerLoop(t, peer, func() {
		buf := make([]byte, 4096)
		_ = peer.SetReadDeadline(time.Now().Add(answerBudget))
		n, from, err := peer.ReadFromUDP(buf)
		if err != nil || n <= 4 {
			t.Errorf("the initiator sent no IKE_SA_INIT: %d bytes, %v", n, err)
			return
		}
		request, err := DecodeMessage(buf[4:n])
		if err != nil {
			t.Error(err)
			return
		}
		sa, ke := request.find(PayloadSA), request.find(PayloadKE)
		if sa == nil || ke == nil {
			t.Errorf("the IKE_SA_INIT request carries %v", request.Payloads)
			return
		}
		group, _, err := DecodeKE(ke.Body)
		if err != nil {
			t.Error(err)
			return
		}
		proposal, suite, err := selectIKEProposal(sa.Body, group, Suites{}, false)
		if err != nil {
			t.Error(err)
			return
		}
		dh, err := GenerateDH(suite.DHGroup)
		if err != nil {
			t.Error(err)
			return
		}
		answer := encodeTestMessage(t, Header{SPIInitiator: request.Header.SPIInitiator, SPIResponder: randUint64Nonzero(), ExchangeType: IKE_SA_INIT, Flags: FlagResponse}, []RawPayload{
			{Type: PayloadSA, Body: EncodeSA([]Proposal{proposal})},
			{Type: PayloadKE, Body: EncodeKE(suite.DHGroup, dh.PublicBytes())},
			{Type: PayloadNonce, Body: EncodeNonce(make([]byte, 32))},
			{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_SIGNATURE_HASH_ALGORITHMS, Data: binary.BigEndian.AppendUint16(nil, HashIdentity)})},
			unsupportedCritical,
		})
		if _, err := peer.WriteToUDP(withNonESPMarker(answer), from); err != nil {
			t.Error(err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), answerBudget)
	defer cancel()
	session, err := InitiateContext(ctx, PeerConfig{RemoteAddr: peerAddr.IP, RemotePort: peerAddr.Port})
	if err == nil {
		session.Mux().Close()
	}
	if err == nil || !strings.Contains(err.Error(), "marks unsupported payload type 250 critical") {
		t.Errorf("the dial ended with %v, want the answer refused for payload type 250", err)
	}
}

// TestSendRecvIgnoresUnauthenticatedErrorNotify verifies the RFC 7815 section 2.1
// fix directly: a bare, unauthenticated error notify (no SA payload, as an
// on-path attacker could forge given only the initiator's SPI, sent in the
// clear in the request) must not abort the exchange: sendRecv must keep
// waiting and accept the real response that follows.
func TestSendRecvIgnoresUnauthenticatedErrorNotify(t *testing.T) {
	peer := listenPeer(t)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)

	mux, err := transport.Dial("127.0.0.1:0", peerAddr.IP, peerAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()

	const spiI = 0x0102030405060708
	req := encodeTestMessage(t, Header{SPIInitiator: spiI, ExchangeType: IKE_SA_INIT, Flags: FlagInitiator, MessageID: 0}, nil)

	accept := func(raw []byte) bool {
		m, err := DecodeMessage(raw)
		return err == nil && m.find(PayloadSA) != nil
	}

	type result struct {
		raw []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		raw, err := sendRecv(mux, req, accept)
		done <- result{raw, err}
	}()

	buf := make([]byte, 2048)
	peer.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, clientAddr, err := peer.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("peer did not receive request: %v", err)
	}
	_ = n

	// Forged/unauthenticated error response: correlates by SPI+MessageID
	// but carries only a Notify, no SA, so accept() must reject this.
	bogus := withNonESPMarker(encodeTestMessage(t, Header{SPIInitiator: spiI, SPIResponder: 0xdead, ExchangeType: IKE_SA_INIT, Flags: FlagResponse, MessageID: 0},
		[]RawPayload{{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_NO_PROPOSAL_CHOSEN})}}))
	if _, err := peer.WriteToUDP(bogus, clientAddr); err != nil {
		t.Fatal(err)
	}

	// The real response, sent right after: accept() must take this one.
	real := withNonESPMarker(encodeTestMessage(t, Header{SPIInitiator: spiI, SPIResponder: 0xf00d, ExchangeType: IKE_SA_INIT, Flags: FlagResponse, MessageID: 0},
		[]RawPayload{{Type: PayloadSA, Body: []byte{0x01, 0x02}}}))
	if _, err := peer.WriteToUDP(real, clientAddr); err != nil {
		t.Fatal(err)
	}

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("sendRecv returned an error instead of the real response: %v", r.err)
		}
		got, err := DecodeMessage(r.raw)
		if err != nil {
			t.Fatalf("decode returned response: %v", err)
		}
		if got.find(PayloadSA) == nil {
			t.Fatal("sendRecv returned the bogus notify-only response instead of the real one")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("sendRecv did not return in time, likely blocked waiting past the accepted response")
	}
}

// TestSendRecvAcceptsNilAsAlwaysTrue verifies the nil-accept shorthand still
// treats the first correlated response as final, matching sendRecv's
// documented default.
func TestSendRecvAcceptsNilAsAlwaysTrue(t *testing.T) {
	peer := listenPeer(t)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)

	mux, err := transport.Dial("127.0.0.1:0", peerAddr.IP, peerAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()

	const spiI = 0xaabbccddeeff0011
	const spiR = 0x1122334455667788
	req := encodeTestMessage(t, Header{SPIInitiator: spiI, SPIResponder: spiR, ExchangeType: INFORMATIONAL, Flags: FlagInitiator, MessageID: 3}, nil)

	done := make(chan []byte, 1)
	go func() {
		raw, err := sendRecv(mux, req, nil)
		if err != nil {
			t.Errorf("sendRecv: %v", err)
			return
		}
		done <- raw
	}()

	buf := make([]byte, 2048)
	peer.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, clientAddr, err := peer.ReadFromUDP(buf); err != nil {
		t.Fatalf("peer did not receive request: %v", err)
	} else {
		resp := withNonESPMarker(encodeTestMessage(t, Header{SPIInitiator: spiI, SPIResponder: spiR, ExchangeType: INFORMATIONAL, Flags: FlagResponse, MessageID: 3}, nil))
		if _, err := peer.WriteToUDP(resp, clientAddr); err != nil {
			t.Fatal(err)
		}
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("sendRecv with nil accept did not return")
	}
}

func TestSessionRequestSerializesLocalMessageIDs(t *testing.T) {
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
	s := &Session{
		mux: mux,
		current: &ikeContext{suite: suite, spiI: spiI, spiR: spiR, authMID: 1, nextLocalMID: 2,
			skei: make([]byte, 20), sker: make([]byte, 20)},
		requests: make(chan *localRequest, 1),
	}
	if err := mux.RegisterIKE(spiI); err != nil {
		t.Fatal(err)
	}

	var ids []uint32
	peerDone := make(chan struct{})
	peerLoop(t, peer, func() {
		defer close(peerDone)
		buf := make([]byte, 2048)
		for range 2 {
			n, addr, err := peer.ReadFromUDP(buf)
			if err != nil {
				t.Errorf("read request: %v", err)
				return
			}
			raw := append([]byte(nil), buf[4:n]...)
			m, err := DecodeMessage(raw)
			if err != nil {
				t.Errorf("decode request: %v", err)
				return
			}
			if _, err := DecryptMessage(suite, s.current.skei, raw, m); err != nil {
				t.Errorf("decrypt request: %v", err)
				return
			}
			ids = append(ids, m.Header.MessageID)
			response, err := EncryptMessage(suite, s.current.sker, Header{SPIInitiator: spiI, SPIResponder: spiR, ExchangeType: m.Header.ExchangeType, Flags: FlagResponse, MessageID: m.Header.MessageID}, nil, nil)
			if err != nil {
				t.Errorf("encrypt response: %v", err)
				return
			}
			if _, err := peer.WriteToUDP(withNonESPMarker(response), addr); err != nil {
				t.Errorf("write response: %v", err)
				return
			}
		}
	})

	runDone := make(chan error, 1)
	go func() { runDone <- s.Run(context.Background()) }()
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			if _, err := s.request(INFORMATIONAL, nil); err != nil {
				t.Errorf("request: %v", err)
			}
		})
	}
	wg.Wait()
	<-peerDone
	slices.Sort(ids)
	if len(ids) != 2 || ids[0] != 2 || ids[1] != 3 {
		t.Fatalf("local message IDs = %v, want [2 3]", ids)
	}
	_ = mux.Close()
	if err := <-runDone; err == nil {
		t.Fatal("Run returned nil after mux close")
	}
}

func TestSessionRunUsesOldIKEContext(t *testing.T) {
	peer := listenPeer(t)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	mux, err := transport.Dial("127.0.0.1:0", peerAddr.IP, peerAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()

	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	current := &ikeContext{suite: suite, spiI: 0x0102030405060708, spiR: 0x1112131415161718, skei: make([]byte, 20), sker: make([]byte, 20)}
	old := &ikeContext{suite: suite, spiI: 0x2122232425262728, spiR: 0x3132333435363738, skei: []byte("old initiator key---"), sker: []byte("old responder key---")}
	s := &Session{mux: mux, current: current, old: old, requests: make(chan *localRequest, 1)}
	if err := mux.RegisterIKE(current.spiI); err != nil {
		t.Fatal(err)
	}
	if err := mux.RegisterIKE(old.spiI); err != nil {
		t.Fatal(err)
	}

	runDone := make(chan error, 1)
	go func() { runDone <- s.Run(context.Background()) }()
	request, err := EncryptMessage(old.suite, old.sker, Header{SPIInitiator: old.spiI, SPIResponder: old.spiR, ExchangeType: INFORMATIONAL, MessageID: 0}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := peer.WriteToUDP(withNonESPMarker(request), muxLoopback(mux)); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 2048)
	peer.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := peer.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	responseRaw := append([]byte(nil), buf[4:n]...)
	response, err := DecodeMessage(responseRaw)
	if err != nil {
		t.Fatal(err)
	}
	if response.Header.SPIInitiator != old.spiI || response.Header.SPIResponder != old.spiR {
		t.Fatalf("response SPI pair = %016x/%016x, want old %016x/%016x", response.Header.SPIInitiator, response.Header.SPIResponder, old.spiI, old.spiR)
	}
	if _, err := DecryptMessage(old.suite, old.skei, responseRaw, response); err != nil {
		t.Fatalf("decrypt old-context response: %v", err)
	}
	oldMID, currentMID := s.nextPeerMessageID(old), s.nextPeerMessageID(current)
	if oldMID != 1 || currentMID != 0 {
		t.Fatalf("peer message IDs old/current = %d/%d, want 1/0", oldMID, currentMID)
	}
	_ = mux.Close()
	if err := <-runDone; err == nil {
		t.Fatal("Run returned nil after mux close")
	}
}

// both notifies arrive before anything is authenticated
// so anyone who can see this end's SPI can send them
// a cookie is echoed in the retry
// so taking one of any length turns one spoofed datagram into as many oversized ones as this end retransmits
// RFC 7296 section 2.6: "The data associated with this notification MUST be between 1 and 64 octets in length (inclusive)"
// a group this end did not offer ends the dial with no retry
// so acting on one aborts the handshake for free
func TestOnlyUsableUnauthenticatedInitNotifiesAreActedOn(t *testing.T) {
	message := func(notify Notify) *Message {
		return &Message{Payloads: []RawPayload{{Type: PayloadN, Body: EncodeNotify(notify)}}}
	}
	group := func(id uint16) []byte {
		data := make([]byte, 2)
		binary.BigEndian.PutUint16(data, id)
		return data
	}
	// RFC 7296 section 2.6: "The data associated with this notification MUST be between 1 and 64 octets in length (inclusive), and its generation is described later in this section."
	for name, tc := range map[string]struct {
		notify Notify
		usable bool
	}{
		"a cookie of the smallest allowed length":   {Notify{Type: N_COOKIE, Data: bytes.Repeat([]byte{1}, 1)}, true},
		"a cookie of the largest allowed length":    {Notify{Type: N_COOKIE, Data: bytes.Repeat([]byte{1}, 64)}, true},
		"an empty cookie":                           {Notify{Type: N_COOKIE, Data: nil}, false},
		"a cookie one octet past the bound":         {Notify{Type: N_COOKIE, Data: bytes.Repeat([]byte{1}, 65)}, false},
		"a cookie far past the bound":               {Notify{Type: N_COOKIE, Data: bytes.Repeat([]byte{1}, 4096)}, false},
		"a group we offer":                          {Notify{Type: N_INVALID_KE_PAYLOAD, Data: group(DH_CURVE25519)}, true},
		"a group we cannot generate":                {Notify{Type: N_INVALID_KE_PAYLOAD, Data: group(1)}, false},
		"a group name too short to read":            {Notify{Type: N_INVALID_KE_PAYLOAD, Data: []byte{0}}, false},
		"anything else unauthenticated":             {Notify{Type: N_NO_PROPOSAL_CHOSEN}, false},
		"an authentication failure we cannot trust": {Notify{Type: N_AUTHENTICATION_FAILED}, false},
	} {
		t.Run(name, func(t *testing.T) {
			got, ok := usefulInitNotify(message(tc.notify), false, false, ikeProposal().Transforms)
			if ok && !tc.usable {
				t.Fatal("acted on, so anyone who can see our SPI can steer this handshake")
			}
			if !ok && tc.usable {
				t.Fatal("ignored, so the exchange waits for a response the peer will not send")
			}
			if ok && got.Type != tc.notify.Type {
				t.Fatalf("acted on notify %d rather than the one that arrived, %d", got.Type, tc.notify.Type)
			}
		})
	}

	// a group ike kex left out is one this end can generate and still ignores
	// a retry in a group the offer left out ends the dial
	p256Only := transformsOf(suitesOf(t, Crypto{IKE: IKESuites{Kex: []string{"p256"}}}).ikeProposals(DH_ECP_256))
	if _, ok := usefulInitNotify(message(Notify{Type: N_INVALID_KE_PAYLOAD, Data: group(DH_CURVE25519)}), false, false, p256Only); ok {
		t.Error("a group the lists left out was acted on, so an unauthenticated notify ends the dial")
	}

	// a cookie is acted on once for each group tried and a group correction once
	// or a peer sending them again keeps the exchange restarting instead of finishing
	cookie := message(Notify{Type: N_COOKIE, Data: []byte{1}})
	if _, ok := usefulInitNotify(cookie, true, false, ikeProposal().Transforms); ok {
		t.Error("a second cookie in the same group was acted on, so the exchange can be restarted indefinitely")
	}
	wrongGroup := message(Notify{Type: N_INVALID_KE_PAYLOAD, Data: group(DH_CURVE25519)})
	if _, ok := usefulInitNotify(wrongGroup, false, true, ikeProposal().Transforms); ok {
		t.Error("a second group correction was acted on")
	}

	// RFC 7296 section 3.2 on the critical bit: "MUST be ignored by the recipient if the recipient understands the payload type code."
	// section 2.5: "If the critical flag is set and the payload type is unrecognized, the message MUST be rejected"
	marked := message(Notify{Type: N_COOKIE, Data: []byte{1}})
	marked.Payloads[0].Critical = true
	if _, ok := usefulInitNotify(marked, false, false, ikeProposal().Transforms); !ok {
		t.Error("a cookie whose notify is marked critical was ignored")
	}
	marked.Payloads = append(marked.Payloads, unsupportedCritical)
	if _, ok := usefulInitNotify(marked, false, false, ikeProposal().Transforms); ok {
		t.Error("a cookie beside a critical payload of a type this end does not support was acted on")
	}
}

// RFC 7296 section 3.10.1: "Types in the range 0 - 16383 are intended for reporting errors."
// the types on either side of the line between the two ranges, and the far end of each
func TestFirstErrorNotifyReadsTypesUpTo16383AsErrors(t *testing.T) {
	for notifyType, isError := range map[NotifyType]bool{0: true, 16383: true, 16384: false, 65535: false} {
		notify, failed, err := firstErrorNotify([]RawPayload{{Type: PayloadN, Body: EncodeNotify(Notify{Type: notifyType})}})
		if err != nil || failed != isError || failed && notify.Type != notifyType {
			t.Errorf("notify type %d read as an error %v as %d (%v), want %v", notifyType, failed, notify.Type, err, isError)
		}
	}
}

// RFC 7296 section 2.6: "Each endpoint chooses one of the two SPIs and MUST choose them so as to be unique identifiers of an IKE SA."
// two dials send their IKE_SA_INIT under two nonzero initiator SPIs that differ
func TestInitiatorGivesEachIKESAItsOwnSPI(t *testing.T) {
	peer := listenPeer(t)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	ctx, cancel := context.WithCancel(context.Background())
	var dials sync.WaitGroup
	defer func() {
		cancel()
		dials.Wait()
	}()
	var spis []uint64
	buf := make([]byte, 4096)
	for range 2 {
		dials.Go(func() { _, _ = InitiateContext(ctx, PeerConfig{RemoteAddr: peerAddr.IP, RemotePort: peerAddr.Port}) })
		if err := peer.SetReadDeadline(time.Now().Add(answerBudget)); err != nil {
			t.Fatal(err)
		}
		n, _, err := peer.ReadFromUDP(buf)
		if err != nil || n <= 4 {
			t.Fatalf("a dial sent no IKE_SA_INIT: %d bytes, %v", n, err)
		}
		header, err := decodeHeader(buf[4:n])
		if err != nil {
			t.Fatal(err)
		}
		spis = append(spis, header.SPIInitiator)
	}
	if spis[0] == 0 || spis[1] == 0 || spis[0] == spis[1] {
		t.Errorf("the initiator opened two IKE SAs under SPIs %016x and %016x", spis[0], spis[1])
	}
}

// RFC 7296 section 2.6.1: "if the responder includes the KEi payloads in cookie calculation, it will reject the request by sending a new cookie."
// section 2.6.1: "Implementations SHOULD support this shorter exchange, but MUST NOT fail if other implementations do not support this shorter exchange."
// the responder here binds each cookie to the KE group and takes P-256 alone, so the dial meets COOKIE, INVALID_KE_PAYLOAD and COOKIE again
// past that a third cookie or a second group correction draws no new request, so the far end cannot keep the dial restarting
func TestInitiatorAnswersTheCookieThatFollowsAGroupChange(t *testing.T) {
	peer := listenPeer(t)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	cookieFor := func(group uint16) []byte { return fmt.Appendf(nil, "cookie bound to group %d", group) }

	type request struct {
		raw        []byte
		spiI, spiR uint64
		cookie     []byte
		group      uint16
		rest       []RawPayload
	}
	var seen []request
	reached, peerDone := false, make(chan struct{})
	peerLoop(t, peer, func() {
		defer close(peerDone)
		buf := make([]byte, 4096)
		var from *net.UDPAddr
		next := func() (request, error) {
			n, addr, err := peer.ReadFromUDP(buf)
			if err != nil {
				return request{}, err
			}
			if n <= 4 {
				return request{}, fmt.Errorf("short marked request: %d bytes", n)
			}
			from = addr
			raw := append([]byte(nil), buf[4:n]...)
			m, err := DecodeMessage(raw)
			if err != nil {
				return request{}, err
			}
			req := request{raw: raw, spiI: m.Header.SPIInitiator, spiR: m.Header.SPIResponder, rest: m.Payloads}
			if len(m.Payloads) > 0 && m.Payloads[0].Type == PayloadN {
				if notify, err := DecodeNotify(m.Payloads[0].Body); err == nil && notify.Type == N_COOKIE {
					req.cookie, req.rest = notify.Data, m.Payloads[1:]
				}
			}
			if ke := findType(req.rest, PayloadKE); ke != nil {
				req.group, _, _ = DecodeKE(ke.Body)
			}
			return req, nil
		}
		answer := func(req request, notify Notify) {
			response := encodeTestMessage(t, Header{SPIInitiator: req.spiI, ExchangeType: IKE_SA_INIT, Flags: FlagResponse}, []RawPayload{{Type: PayloadN, Body: EncodeNotify(notify)}})
			if _, err := peer.WriteToUDP(withNonESPMarker(response), from); err != nil {
				t.Errorf("answer the request: %v", err)
			}
		}

		_ = peer.SetReadDeadline(time.Now().Add(answerBudget))
		var target request
		for !reached {
			req, err := next()
			if err != nil {
				t.Errorf("the dial stopped after %d requests without answering the cookie its group change drew: %v", len(seen), err)
				return
			}
			if len(seen) == 0 || !bytes.Equal(req.raw, seen[len(seen)-1].raw) {
				seen = append(seen, req)
			}
			switch {
			case !bytes.Equal(req.cookie, cookieFor(req.group)):
				answer(req, Notify{Type: N_COOKIE, Data: cookieFor(req.group)})
			case req.group != DH_ECP_256:
				answer(req, Notify{Type: N_INVALID_KE_PAYLOAD, Data: binary.BigEndian.AppendUint16(nil, DH_ECP_256)})
			default:
				target, reached = req, true
			}
		}

		answer(target, Notify{Type: N_COOKIE, Data: []byte("a third cookie")})
		answer(target, Notify{Type: N_INVALID_KE_PAYLOAD, Data: binary.BigEndian.AppendUint16(nil, DH_ECP_384)})
		_ = peer.SetReadDeadline(time.Now().Add(quietPeriod))
		for {
			again, err := next()
			if err != nil {
				return
			}
			if !bytes.Equal(again.raw, target.raw) {
				t.Errorf("a third cookie or a second group correction was acted on, drawing a request with cookie %q in group %d", again.cookie, again.group)
				return
			}
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dialed := make(chan error, 1)
	go func() {
		_, err := InitiateContext(ctx, PeerConfig{RemoteAddr: peerAddr.IP, RemotePort: peerAddr.Port})
		dialed <- err
	}()
	<-peerDone
	cancel()
	select {
	case err := <-dialed:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("the dial ended on %v before it was canceled", err)
		}
	case <-time.After(answerBudget):
		t.Fatal("the canceled dial did not end")
	}
	if !reached {
		return
	}

	want := []struct {
		cookie []byte
		group  uint16
	}{
		{nil, DH_CURVE25519},
		{cookieFor(DH_CURVE25519), DH_CURVE25519},
		{cookieFor(DH_CURVE25519), DH_ECP_256},
		{cookieFor(DH_ECP_256), DH_ECP_256},
	}
	if len(seen) != len(want) {
		t.Fatalf("the dial sent %d requests up to the one carrying its second cookie, want %d", len(seen), len(want))
	}
	for i, w := range want {
		if !bytes.Equal(seen[i].cookie, w.cookie) || seen[i].group != w.group {
			t.Errorf("request %d carries cookie %q in group %d, want cookie %q in group %d", i+1, seen[i].cookie, seen[i].group, w.cookie, w.group)
		}
	}
	// RFC 7296 section 3.1 on the initiator's SPI: "This value MUST NOT be zero."
	// section 3.1 on the responder's SPI: "This value MUST be zero in the first message of an IKE initial exchange (including repeats of that message including a cookie)."
	for i, req := range seen {
		if req.spiI == 0 || req.spiI != seen[0].spiI || req.spiR != 0 {
			t.Errorf("request %d carries SPIs %016x and %016x, want the first request's nonzero initiator SPI and a zero responder SPI", i+1, req.spiI, req.spiR)
		}
	}
	// RFC 7296 section 2.6: "include the COOKIE notification containing the received data as the first payload, and all other payloads unchanged"
	for _, i := range []int{1, 3} {
		if !samePayloads(seen[i].rest, seen[i-1].rest) {
			t.Errorf("request %d answers its cookie with other payloads than request %d carried", i+1, i)
		}
	}
}

// RFC 7296 section 3.9: "Nonce values MUST NOT be reused."
// two dials send IKE_SA_INIT requests with different nonces
func TestEachIKESAInitDrawsItsOwnNonce(t *testing.T) {
	peer := listenPeer(t)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	seen := map[uint64]bool{}
	// dial reads the nonce of the first IKE_SA_INIT one dial sends, and ends the dial
	dial := func() []byte {
		t.Helper()
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			_, err := InitiateContext(ctx, PeerConfig{RemoteAddr: peerAddr.IP, RemotePort: peerAddr.Port})
			done <- err
		}()
		defer func() {
			cancel()
			<-done
		}()
		if err := peer.SetReadDeadline(time.Now().Add(answerBudget)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 4096)
		for {
			n, _, err := peer.ReadFromUDP(buf)
			if err != nil || n <= NonESPMarkerLen {
				t.Fatalf("the dial sent nothing: %d bytes, %v", n, err)
			}
			request, err := DecodeMessage(buf[NonESPMarkerLen:n])
			if err != nil {
				t.Fatal(err)
			}
			// a retransmission of a dial before this one
			if seen[request.Header.SPIInitiator] {
				continue
			}
			seen[request.Header.SPIInitiator] = true
			nonce := request.find(PayloadNonce)
			if nonce == nil {
				t.Fatalf("the IKE_SA_INIT request carries %v and no nonce", payloadTypes(request.Payloads))
			}
			return DecodeNonce(nonce.Body)
		}
	}
	if first, second := dial(), dial(); bytes.Equal(first, second) {
		t.Errorf("two dials sent the same nonce %x", first)
	}
}

// RFC 7296 section 3.4 on the KE payload's group: "SHOULD match the Diffie-Hellman group in the first group in the first proposal, if such exists."
// section 1.2: "The initiator MUST again propose its full set of acceptable cryptographic suites because the rejection message was unauthenticated and otherwise an active attacker could trick the endpoints into negotiating a weaker suite than a stronger one that they both prefer."
// the retry an INVALID_KE_PAYLOAD naming P-256 draws offers P-256 first and the other groups after it in their order, the rest of the offer as before, octet for octet
func TestInitiatorRetriesWithTheNamedGroupFirst(t *testing.T) {
	peer := listenPeer(t)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	peerDone := make(chan struct{})
	peerLoop(t, peer, func() {
		defer close(peerDone)
		buf := make([]byte, 4096)
		_ = peer.SetReadDeadline(time.Now().Add(answerBudget))
		var answered []byte
		for i, want := range []struct {
			group uint16
			sa    []byte
		}{
			{DH_CURVE25519, offeredIKESA(nil, []byte{6, 5}, []byte{31, 20, 19})},
			{DH_ECP_256, offeredIKESA(nil, []byte{6, 5}, []byte{19, 31, 20})},
		} {
			n, from, err := peer.ReadFromUDP(buf)
			// a retransmission of the request already answered
			for err == nil && n > 4 && bytes.Equal(buf[4:n], answered) {
				n, from, err = peer.ReadFromUDP(buf)
			}
			if err != nil || n <= 4 {
				t.Errorf("the initiator sent no IKE_SA_INIT with its KE payload in group %d: %d bytes, %v", want.group, n, err)
				return
			}
			raw := slices.Clone(buf[4:n])
			request, err := DecodeMessage(raw)
			if err != nil {
				t.Error(err)
				return
			}
			sa, ke := request.find(PayloadSA), request.find(PayloadKE)
			if sa == nil || ke == nil {
				t.Errorf("the IKE_SA_INIT request carries %v", request.Payloads)
				return
			}
			if group, _, err := DecodeKE(ke.Body); err != nil || group != want.group {
				t.Errorf("request %d has its KE payload in group %d (%v), want %d", i+1, group, err, want.group)
			}
			if !bytes.Equal(sa.Body, want.sa) {
				t.Errorf("request %d offers\n%x\nwant\n%x", i+1, sa.Body, want.sa)
			}
			if i == 0 {
				answer := encodeTestMessage(t, Header{SPIInitiator: request.Header.SPIInitiator, ExchangeType: IKE_SA_INIT, Flags: FlagResponse},
					[]RawPayload{{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_INVALID_KE_PAYLOAD, Data: binary.BigEndian.AppendUint16(nil, DH_ECP_256)})}})
				if _, err := peer.WriteToUDP(withNonESPMarker(answer), from); err != nil {
					t.Error(err)
					return
				}
				answered = raw
			}
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dialed := make(chan error, 1)
	go func() {
		session, err := InitiateContext(ctx, PeerConfig{RemoteAddr: peerAddr.IP, RemotePort: peerAddr.Port, Suites: func() Suites { return classicalLists }})
		if err == nil {
			session.Mux().Close()
		}
		dialed <- err
	}()
	<-peerDone
	cancel()
	select {
	case <-dialed:
	case <-time.After(answerBudget):
		t.Fatal("the canceled dial did not end")
	}
}

// RFC 7296 section 1.2: "Thus, the SA payloads in the IKE_AUTH exchange cannot contain Transform Type 4 (Diffie-Hellman group) with any value other than NONE. Implementations SHOULD omit the whole transform substructure instead of sending value NONE."
// the Child SA offer of the IKE_AUTH request names no Diffie-Hellman transform
func TestInitiatorOffersNoDiffieHellmanTransformInIKEAuth(t *testing.T) {
	unchanged := func(_ ExchangeType, payloads []RawPayload) []RawPayload { return payloads }
	asSent := func([]byte) {}
	_, auth, _, err := dialPlayedResponder(t, unchanged, asSent)
	if err != nil {
		t.Fatal(err)
	}
	sa := findType(auth, PayloadSA)
	if sa == nil {
		t.Fatalf("the IKE_AUTH request carries %v", auth)
	}
	proposals, err := DecodeSA(sa.Body)
	if err != nil {
		t.Fatal(err)
	}
	for _, proposal := range proposals {
		for _, transform := range proposal.Transforms {
			if transform.Type == TransDH {
				t.Errorf("proposal %d of the IKE_AUTH request names Diffie-Hellman group %d", proposal.Number, transform.ID)
			}
		}
	}
}

// offeredIKESA is, octet by octet, the proposals this end offers for an IKE SA, one for each Diffie-Hellman group named in the order given
// each holds spi, its three ciphers, the PRFs named in the order given and its group
func offeredIKESA(spi, prfs, groups []byte) []byte {
	var sa []byte
	for i, group := range groups {
		// the first octet of a proposal says whether another follows, 2 for one more and 0 for none
		more := byte(2)
		if i == len(groups)-1 {
			more = 0
		}
		proposal := append([]byte{more, 0, 0, 0, byte(i + 1), 1, byte(len(spi)), byte(3 + len(prfs) + 1)}, spi...)
		proposal = append(proposal,
			3, 0, 0, 12, 1, 0, 0, 20, 0x80, 14, 1, 0, // ENCR_AES_GCM_16 with a 256-bit key
			3, 0, 0, 12, 1, 0, 0, 20, 0x80, 14, 0, 128, // ENCR_AES_GCM_16 with a 128-bit key
			3, 0, 0, 8, 1, 0, 0, 28, // ENCR_CHACHA20_POLY1305
		)
		for _, prf := range prfs {
			proposal = append(proposal, 3, 0, 0, 8, 2, 0, 0, prf)
		}
		// the first octet of the last transform says none follows
		proposal = append(proposal, 0, 0, 0, 8, 4, 0, 0, group)
		binary.BigEndian.PutUint16(proposal[2:4], uint16(len(proposal)))
		sa = append(sa, proposal...)
	}
	return sa
}
