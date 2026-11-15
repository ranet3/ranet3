// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ike

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/transport"
)

// benchmarkInitEndpoint observes the peer through a temporary mux, leaving its SPI free for the responder
func benchmarkInitEndpoint(b *testing.B) (*transport.Hub, *transport.MemoryConn, transport.Endpoint) {
	b.Helper()
	network := transport.NewMemoryNetwork()
	hub, err := network.NewHub()
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = hub.Close() })
	ip := net.IPv4(127, 0, 0, 1)
	peer, err := network.ListenUDP(ip)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = peer.Close() })
	mux, err := hub.NewMux(ip, peer.LocalAddr().(*net.UDPAddr).Port)
	if err != nil {
		b.Fatal(err)
	}
	defer mux.Close()
	if err := mux.RegisterIKE(1); err != nil {
		b.Fatal(err)
	}
	raw := make([]byte, HeaderLen)
	binary.BigEndian.PutUint64(raw, 1)
	if _, err := peer.WriteToUDP(withNonESPMarker(raw), &net.UDPAddr{IP: ip, Port: hub.LocalAddr().(*net.UDPAddr).Port}); err != nil {
		b.Fatal(err)
	}
	_, endpoint, err := mux.RecvIKEFromUntil(time.Now().Add(answerBudget))
	if err != nil {
		b.Fatal(err)
	}
	return hub, peer, endpoint
}

func BenchmarkResponderAdmission(b *testing.B) {
	hub, _, endpoint := benchmarkInitEndpoint(b)
	r := &Responder{cfg: ResponderConfig{Hub: hub}, cookieRotated: time.Now()}
	nonce := bytes.Repeat([]byte{7}, 32)
	request := &Message{}
	b.ReportAllocs()
	for b.Loop() {
		if required, err := r.admit(request, nonce, 1, endpoint); required || err != nil {
			b.Fatalf("admission refused: %v, %v", required, err)
		}
		r.leaveHalfOpen(endpoint.AddrPort().Addr())
	}
}

func BenchmarkResponderCookie(b *testing.B) {
	hub, peer, endpoint := benchmarkInitEndpoint(b)
	var answers atomic.Uint64
	r := &Responder{cfg: ResponderConfig{Hub: hub, CookieAnswers: &answers}, halfOpen: cookieThreshold}
	raw := encodeTestSAInit(b, 1, bytes.Repeat([]byte{7}, 32), ikeProposal(), nil)
	datagram := transport.Unclaimed{Raw: raw, Endpoint: endpoint}
	var buf [2048]byte
	if err := peer.SetReadDeadline(time.Now().Add(time.Minute)); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, _, err := r.handshake(b.Context(), datagram); !errors.Is(err, errCookieChallenge) {
			b.Fatalf("cookie answer: %v", err)
		}
		n, _, err := peer.ReadFromUDP(buf[:])
		if err != nil || n < 4+HeaderLen || buf[4+16] != byte(PayloadN) {
			b.Fatalf("cookie answer has %d bytes: %v", n, err)
		}
	}
}

func BenchmarkDecodeMessage(b *testing.B) {
	b.Run("SAInit", func(b *testing.B) {
		raw := encodeTestSAInit(b, 1, bytes.Repeat([]byte{7}, 32), ikeProposal(), nil)
		b.ReportAllocs()
		for b.Loop() {
			if _, err := DecodeMessage(raw); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("EmptyPayloads64KiB", func(b *testing.B) {
		h := Header{SPIInitiator: 1, ExchangeType: IKE_SA_INIT, Flags: FlagInitiator, NextPayload: PayloadNonce, Length: 64 << 10}
		raw := append(h.encode(), make([]byte, (64<<10)-HeaderLen)...)
		for at := HeaderLen; at < len(raw); at += genericPayloadHeaderLen {
			if at+genericPayloadHeaderLen < len(raw) {
				raw[at] = byte(PayloadNonce)
			}
			binary.BigEndian.PutUint16(raw[at+2:], genericPayloadHeaderLen)
		}
		b.ReportAllocs()
		for b.Loop() {
			if _, err := DecodeMessage(raw); err != nil {
				b.Fatal(err)
			}
		}
	})
}
