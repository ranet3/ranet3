// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

package ike

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/transport"
)

func TestInitiateCancellationLeavesSharedHubOpen(t *testing.T) {
	peer := listenPeer(t)
	address := peer.LocalAddr().(*net.UDPAddr)
	hub, err := transport.NewHub(":0", transport.Underlay{}, transport.Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := InitiateContext(ctx, PeerConfig{RemoteAddr: address.IP, RemotePort: address.Port, Hub: hub})
		done <- err
	}()
	peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := peer.ReadFromUDP(make([]byte, 4096)); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled handshake is still waiting for retransmission")
	}
	mux, err := hub.NewMux(address.IP, address.Port)
	if err != nil {
		t.Fatalf("handshake cancellation closed the shared hub: %v", err)
	}
	defer mux.Close()
	if err := mux.SendIKE(encodeTestMessage(t, Header{SPIInitiator: 123, ExchangeType: IKE_SA_INIT, Flags: FlagInitiator}, nil)); err != nil {
		t.Fatalf("shared hub cannot transmit after cancellation: %v", err)
	}
}

// an exchange whose mux closes ends at once and sends nothing more, since a closed mux still reaches the shared socket
func TestClosedMuxEndsTheExchangeWithoutRetransmitting(t *testing.T) {
	peer := listenPeer(t)
	address := peer.LocalAddr().(*net.UDPAddr)
	hub, err := transport.NewHub(":0", transport.Underlay{}, transport.Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	mux, err := hub.NewMux(address.IP, address.Port)
	if err != nil {
		t.Fatal(err)
	}
	request := encodeTestMessage(t, Header{SPIInitiator: 123, ExchangeType: IKE_SA_INIT, Flags: FlagInitiator}, nil)
	done := make(chan error, 1)
	go func() {
		_, err := sendRecv(mux, request, nil)
		done <- err
	}()
	buf := make([]byte, 4096)
	peer.SetReadDeadline(time.Now().Add(answerBudget))
	if _, _, err := peer.ReadFromUDP(buf); err != nil {
		t.Fatal(err)
	}
	mux.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("an exchange whose mux closed reported a response")
		}
	case <-time.After(answerBudget):
		t.Fatal("the exchange kept waiting after its mux closed")
	}
	peer.SetReadDeadline(time.Now().Add(quietPeriod))
	if _, _, err := peer.ReadFromUDP(buf); err == nil {
		t.Error("the exchange retransmitted its request after its mux closed")
	}
}

func TestFullRangeSelectorSemantics(t *testing.T) {
	narrow := FullRangeV4()
	narrow.EndPort = 80
	reserved := fullRangeSelectors()
	reserved[1], reserved[2], reserved[3] = 1, 2, 3
	for _, test := range []struct {
		name string
		body []byte
		ok   bool
	}{
		{"canonical", fullRangeSelectors(), true},
		{"reversed", EncodeTS([]TrafficSelector{FullRangeV6(), FullRangeV4()}), true},
		{"reserved", reserved, true},
		{"duplicate", EncodeTS([]TrafficSelector{FullRangeV4(), FullRangeV4()}), false},
		{"narrowed", EncodeTS([]TrafficSelector{narrow, FullRangeV6()}), false},
		{"missing family", EncodeTS([]TrafficSelector{FullRangeV4()}), false},
		{"trailing data", append(fullRangeSelectors(), 0), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload := &RawPayload{Body: test.body}
			if err := validateFullRangeSelectors(payload, payload); (err == nil) != test.ok {
				t.Fatalf("validation = %v; want accepted=%v", err, test.ok)
			}
		})
	}
}

// an exchange's failure names the sends of the budget it spent, which differs from the default for the teardown Delete
func TestSendRecvReportsTheBudgetItSpent(t *testing.T) {
	peer := listenPeer(t)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	mux, err := transport.Dial("127.0.0.1:0", peerAddr.IP, peerAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	request := (&Message{Header: Header{
		SPIInitiator: randUint64Nonzero(), ExchangeType: INFORMATIONAL,
		Flags: FlagInitiator, MessageID: 0,
	}}).Encode()

	start := time.Now()
	_, err = sendRecvWithin(mux, &transmission{datagrams: [][]byte{request}}, 1, requestTimeout, nil, nil, nil)
	if err == nil {
		t.Fatal("an unanswered exchange reported success")
	}
	if !strings.Contains(err.Error(), "after 1 attempts") {
		t.Errorf("the failure says %q, want it to name the one attempt it made", err)
	}
	if elapsed := time.Since(start); elapsed > 3*requestTimeout {
		t.Errorf("one attempt took %s, which is more than the budget it was given", elapsed)
	}
}

// a request whose first copy is lost is sent again within its budget
// and the answer to the second copy is the one returned
func TestSendRecvSendsAnUnansweredRequestAgain(t *testing.T) {
	peer := listenPeer(t)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	mux, err := transport.Dial("127.0.0.1:0", peerAddr.IP, peerAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	header := Header{SPIInitiator: randUint64Nonzero(), SPIResponder: randUint64Nonzero(),
		ExchangeType: INFORMATIONAL, Flags: FlagInitiator, MessageID: 4}
	request := encodeTestMessage(t, header, nil)
	header.Flags = FlagResponse
	answer := encodeTestMessage(t, header, nil)
	peerLoop(t, peer, func() {
		buf := make([]byte, 2048)
		for read := 1; ; read++ {
			n, from, err := peer.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if !bytes.Equal(buf[:n], withNonESPMarker(request)) {
				t.Errorf("copy %d differs from the request", read)
			}
			// the first copy goes unanswered, as if it had been lost
			if read == 2 {
				_, _ = peer.WriteToUDP(withNonESPMarker(answer), from)
			}
		}
	})

	raw, err := sendRecvWithin(mux, &transmission{datagrams: [][]byte{request}}, 2, requestTimeout, nil, nil, nil)
	if err != nil {
		t.Fatalf("a request whose first copy went unanswered failed: %v", err)
	}
	if !bytes.Equal(raw, answer) {
		t.Errorf("returned %x, want the answer to the second copy %x", raw, answer)
	}
}

// RFC 7296 section 2.5: "If an endpoint receives a message with a higher major version number, it MUST drop the message and SHOULD send an unauthenticated Notify message of type INVALID_MAJOR_VERSION containing the highest (closest) version number it supports."
// section 2.21.4: "If a response is sent, the response MUST be sent to the IP address and port from where it came with the same IKE SPIs and the Message ID copied."
// a request at major version 3 that reaches an exchange's wait from an address other than the peer's is answered so at that address and handed to nothing, and a response at it sent from there first is neither taken nor answered
// section 3.1 on the minor version: "They MUST ignore the minor version number of received messages."
// section 3.1 on the X bits: "'X' bits MUST be cleared when sending and MUST be ignored on receipt."
// section 3.1 on the V bit: "Implementations of IKEv2 MUST clear this bit when sending and MUST ignore it in incoming messages."
// so the request and the response after them, at version 2.1 with the V bit and every X bit set, are handed on and taken
func TestExchangeAnswersAHigherMajorVersionAndDropsIt(t *testing.T) {
	peer := listenPeer(t)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	mux, err := transport.Dial("127.0.0.1:0", peerAddr.IP, peerAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	header := Header{SPIInitiator: randUint64Nonzero(), SPIResponder: randUint64Nonzero(),
		ExchangeType: INFORMATIONAL, Flags: FlagInitiator, MessageID: 4}
	request := encodeTestMessage(t, header, nil)
	answered := header
	answered.Flags = FlagResponse
	answer := encodeTestMessage(t, answered, nil)
	asked := Header{SPIInitiator: header.SPIInitiator, SPIResponder: header.SPIResponder, ExchangeType: INFORMATIONAL, MessageID: 0}
	ignoring := func(h Header) []byte {
		h.Flags |= FlagVersion | 0xc7
		return atVersion(encodeTestMessage(t, h, nil), 0x21)
	}
	laterRequest, laterAnswer := ignoring(asked), ignoring(answered)
	elsewhere := listenPeer(t)
	peerLoop(t, peer, func() {
		buf := make([]byte, 2048)
		_ = peer.SetReadDeadline(time.Now().Add(answerBudget))
		_, from, err := peer.ReadFromUDP(buf)
		if err != nil {
			t.Errorf("read the request: %v", err)
			return
		}
		for _, raw := range [][]byte{atVersion(answer, 0x30), atVersion(encodeTestMessage(t, asked, nil), 0x30)} {
			if _, err := elsewhere.WriteToUDP(withNonESPMarker(raw), from); err != nil {
				t.Errorf("write: %v", err)
				return
			}
		}
		_ = elsewhere.SetReadDeadline(time.Now().Add(answerBudget))
		n, _, err := elsewhere.ReadFromUDP(buf)
		if err != nil {
			t.Errorf("the request at major version 3 drew no answer at the address it came from: %v", err)
			return
		}
		wantMajorVersionRefusal(t, slices.Clone(buf[4:n]), asked)
		for _, raw := range [][]byte{laterRequest, laterAnswer} {
			if _, err := peer.WriteToUDP(withNonESPMarker(raw), from); err != nil {
				t.Errorf("write: %v", err)
				return
			}
		}
	})

	var handed [][]byte
	raw, err := sendRecvWithin(mux, &transmission{datagrams: [][]byte{request}}, maxRetransmits, requestTimeout, nil, nil, func(raw []byte, _ transport.Endpoint) bool { handed = append(handed, slices.Clone(raw)); return false })
	if err != nil {
		t.Fatalf("the exchange failed: %v", err)
	}
	if !bytes.Equal(raw, laterAnswer) {
		t.Errorf("the exchange took %x, want the answer at version 2.1 %x", raw, laterAnswer)
	}
	if len(handed) != 1 || !bytes.Equal(handed[0], laterRequest) {
		t.Errorf("the exchange handed on %x, want the request at version 2.1 alone", handed)
	}
}

// atVersion is raw with the version octet of its header replaced
func atVersion(raw []byte, version uint8) []byte {
	out := slices.Clone(raw)
	out[17] = version
	return out
}

// sealedEdited is inner sealed under key in a message whose header and SK payload header edit has changed
// both are associated data, so the message authenticates as the holder of key sent it only when sealed after the edit
func sealedEdited(t *testing.T, suite SASuite, key []byte, header Header, inner []RawPayload, edit func(aad []byte)) []byte {
	t.Helper()
	params, err := aeadParams(suite.EncrID, suite.EncrKeyBits)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := newAEAD(suite.EncrID, key[:params.KeyLen])
	if err != nil {
		t.Fatal(err)
	}
	first := PayloadNone
	if len(inner) > 0 {
		first = inner[0].Type
	}
	plain, iv := append(encodePayloadChain(inner), 0), make([]byte, params.IVLen)
	rand.Read(iv)
	raw, err := encryptMessagePlaintextIV(suite, key, header, nil, first, plain, iv)
	if err != nil {
		t.Fatal(err)
	}
	aad := raw[:HeaderLen+genericPayloadHeaderLen]
	edit(aad)
	nonce := append(slices.Clone(key[params.KeyLen:]), iv...)
	return aead.Seal(slices.Clone(raw[:len(aad)+len(iv)]), nonce, plain, aad)
}

func atMajorVersion3(aad []byte) { aad[17] = 0x30 }

func atMinorVersion1(aad []byte) { aad[17] = 0x21 }

func criticalSK(aad []byte) { aad[HeaderLen+1] |= 0x80 }

// wantMajorVersionRefusal checks raw is the answer to request at a higher major version
// RFC 7296 section 1.5: "In the second and third cases, the message is always sent without cryptographic protection (outside of an IKE SA), and includes either an INVALID_IKE_SPI or an INVALID_MAJOR_VERSION notification (with no notification data)."
// section 1.5: "The message is a response message, and thus it is sent to the IP address and port from whence it came with the same IKE SPIs and the Message ID and Exchange Type are copied from the request. The Response flag is set to 1, and the version flags are set in the normal fashion."
func wantMajorVersionRefusal(t *testing.T, raw []byte, request Header) {
	t.Helper()
	answer, err := DecodeMessage(raw)
	if err != nil {
		t.Errorf("the answer does not decode: %v", err)
		return
	}
	header := answer.Header
	if raw[17] != 0x20 || header.Flags&^(FlagInitiator|FlagResponse) != 0 {
		t.Errorf("the answer's version octet is %#x with flags %#x, want 2.0 with no flag but Initiator and Response", raw[17], header.Flags)
	}
	if header.SPIInitiator != request.SPIInitiator || header.SPIResponder != request.SPIResponder ||
		header.ExchangeType != request.ExchangeType || header.MessageID != request.MessageID ||
		!header.IsResponse() || header.IsInitiator() == request.IsInitiator() {
		t.Errorf("the answer's header is %+v, want the SPIs, exchange and Message ID of %+v in a response from its other end", header, request)
	}
	if !notified(answer.Payloads, N_INVALID_MAJOR_VERSION, nil) {
		t.Errorf("the answer carries %v, want INVALID_MAJOR_VERSION and nothing else", answer.Payloads)
	}
}
