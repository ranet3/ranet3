// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ike

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/transport"
)

func TestCookieCannotShiftNonceIntoSourceAddress(t *testing.T) {
	long := netip.MustParseAddr("192.0.2.1").As4()
	short := long
	short[0] %= 100
	nonce := bytes.Repeat([]byte{7}, 32)
	var spi [8]byte
	copy(spi[:], []byte("abcdefg1"))
	shifted := append([]byte{nonce[len(nonce)-1]}, spi[:7]...)
	answer := func(ip net.IP, ni []byte, id uint64, cookie []byte) Notify {
		t.Helper()
		network := transport.NewMemoryNetwork()
		hub, err := network.NewHub()
		if err != nil {
			t.Fatal(err)
		}
		defer hub.Close()
		peer, err := network.ListenUDP(ip)
		if err != nil {
			t.Fatal(err)
		}
		defer peer.Close()
		addr, _ := netip.AddrFromSlice(ip)
		r := &Responder{cfg: ResponderConfig{Hub: hub}, cookieRotated: time.Now(), halfOpen: halfOpenPerSourceWithoutCookie,
			halfOpenBySource: map[netip.Addr]int{addr.Unmap(): halfOpenPerSourceWithoutCookie},
			started:          time.Now(), failureReported: make(map[netip.Addr]time.Duration), failureSaid: -handshakeFloor}
		hub.Listen()
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() {
			done <- r.Serve(ctx, func(*Session, Accepted) { t.Error("an unauthenticated request completed") })
		}()
		defer func() { cancel(); <-done }()
		payloads := []RawPayload{{Type: PayloadSA}, {Type: PayloadKE}, {Type: PayloadNonce, Body: ni}, {Type: PayloadV, Body: make([]byte, 32)}}
		if cookie != nil {
			payloads = append([]RawPayload{{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_COOKIE, Data: cookie})}}, payloads...)
		}
		raw := (&Message{Header: Header{SPIInitiator: id, ExchangeType: IKE_SA_INIT, Flags: FlagInitiator}, Payloads: payloads}).Encode()
		if _, err := peer.WriteToUDP(withNonESPMarker(raw), &net.UDPAddr{IP: ip, Port: hub.LocalAddr().(*net.UDPAddr).Port}); err != nil {
			t.Fatal(err)
		}
		if err := peer.SetReadDeadline(time.Now().Add(answerBudget)); err != nil {
			t.Fatal(err)
		}
		var buf [2048]byte
		n, _, err := peer.ReadFromUDP(buf[:])
		if err != nil || n <= 4 {
			t.Fatalf("no cookie answer: %v", err)
		}
		return firstTestNotify(t, buf[4:n])
	}
	issued := answer(net.IP(short[:]), nonce, binary.BigEndian.Uint64(spi[:]), nil)
	if issued.Type != N_COOKIE {
		t.Fatalf("initial request drew %v, want COOKIE", issued.Type)
	}
	got := answer(net.IP(long[:]), nonce[:len(nonce)-1], binary.BigEndian.Uint64(shifted), issued.Data)
	if got.Type != N_COOKIE || bytes.Equal(got.Data, issued.Data) {
		t.Fatal("a cookie for another nonce, SPI and source passed admission")
	}
}
