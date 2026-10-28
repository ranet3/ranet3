// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package ike

import (
	"fmt"
	"net"
	"slices"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/bubble"
	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/transport"
)

// endpointKinds are the datagrams the endpoint property hands dispatch, each drawn outright
var endpointKinds = []string{
	"a fresh request", "a replayed request", "a matching answer", "an answer after its request cleared",
	"an answer at another Message ID", "a datagram failing its ICV", "a fragment short of its message",
}

// requests, replays, answers and stale datagrams from a peer that moves among four places reach dispatch, and the session sends where the model says
// the model: the session sends to the place the last fresh request or matching answer came from, or to the first place where none came, and records a move for exactly each of those that changed it, naming the packet
// RFC 7296 section 2.23: "SHOULD send all packets (including retransmission packets) to the IP address and port in the validated packet"
// and: "dynamic address update should only be done in response to a new packet"
func TestSessionFollowsTheLastFreshMessageAsTheModelDoes(t *testing.T) {
	bubble.Run(testSessionFollowsTheLastFreshMessageAsTheModelDoes)(t)
}

func testSessionFollowsTheLastFreshMessageAsTheModelDoes(t *testing.T) {
	hub := listenHub(t)
	var places []transport.Endpoint
	for _, spi := range []uint64{0x81, 0x82, 0x83, 0x84} {
		place, _ := observedPeerFrom(t, hub, spi, net.IPv4(127, 0, 0, 1))
		places = append(places, place)
	}
	pbt.Check(t, func(ht *hegel.T) {
		mux, err := hub.NewMuxTo(places[0])
		if err != nil {
			ht.Fatal(err)
		}
		defer mux.Close()
		ctx := testContext()
		if err := mux.RegisterIKE(ctx.spiI); err != nil {
			ht.Fatal(err)
		}
		moves := &recorder{}
		s := &Session{mux: mux, current: ctx, fragments: true, events: moves.record}
		seal := func(flags uint8, mid uint32) []byte {
			raw, err := EncryptMessage(ctx.suite, ctx.sker, Header{SPIInitiator: ctx.spiI, SPIResponder: ctx.spiR, ExchangeType: INFORMATIONAL, Flags: flags, MessageID: mid}, nil, nil)
			if err != nil {
				ht.Fatal(err)
			}
			return raw
		}
		var pending *pendingRequest
		ask := func() {
			if pending != nil {
				return
			}
			if pending, err = s.startRequest(&localRequest{exchange: INFORMATIONAL, context: ctx, dpd: true, result: make(chan requestResult, 1)}); err != nil {
				ht.Fatal(err)
			}
		}

		// the model's state: the place the session sends to, the moves it records, the peer's next Message ID, and the last request and answer that came
		at, nextPeer := 0, uint32(0)
		var want []string
		var lastRequest, lastAnswer []byte
		for step := range hegel.Draw(ht, pbt.Spanning(1, 16)) {
			kind := endpointKinds[hegel.Draw(ht, pbt.Spanning(0, len(endpointKinds)-1))]
			from := hegel.Draw(ht, pbt.Spanning(0, len(places)-1))
			fresh, packet := false, ""
			var raw []byte
			switch kind {
			case "a fresh request":
				raw, fresh, packet = seal(0, nextPeer), true, "request"
				lastRequest = raw
				nextPeer++
			case "a replayed request":
				// before any request came, a request at the Message ID before the window's
				raw = lastRequest
				if raw == nil {
					raw = seal(0, nextPeer-1)
				}
			case "a matching answer":
				ask()
				raw, fresh, packet = seal(FlagResponse, pending.msgID), true, "response"
				lastAnswer = raw
			case "an answer after its request cleared":
				// before any answer came, an answer at the Message ID this end uses next, which no request of its has
				raw = lastAnswer
				if raw == nil {
					raw = seal(FlagResponse, ctx.nextLocalMID)
				}
			case "an answer at another Message ID":
				ask()
				raw = seal(FlagResponse, pending.msgID+uint32(hegel.Draw(ht, pbt.Spanning(1, 3))))
			case "a datagram failing its ICV":
				if hegel.Draw(ht, hegel.Booleans()) {
					raw = seal(0, nextPeer)
				} else {
					ask()
					raw = seal(FlagResponse, pending.msgID)
				}
				raw[len(raw)-1] ^= 1
			case "a fragment short of its message":
				flags, mid := uint8(0), nextPeer
				if hegel.Draw(ht, hegel.Booleans()) {
					ask()
					flags, mid = FlagResponse, pending.msgID
				}
				total := hegel.Draw(ht, pbt.Spanning(2, 4))
				number := uint16(hegel.Draw(ht, pbt.Spanning(1, total-1)))
				next := PayloadNone
				if number == 1 {
					next = PayloadN
				}
				if raw, err = sealedFragment(ctx.suite, ctx.sker, Header{SPIInitiator: ctx.spiI, SPIResponder: ctx.spiR, ExchangeType: INFORMATIONAL, Flags: flags, MessageID: mid}, nil, next, 0, number, uint16(total), make([]byte, 32)); err != nil {
					ht.Fatal(err)
				}
			default:
				ht.Fatalf("no datagram is built for %s", kind)
			}
			if fresh && from != at {
				at = from
				want = append(want, fmt.Sprintf("endpoint=%s packet=%s", places[from], packet))
			}

			what := fmt.Sprintf("step %d, %s from place %d", step, kind, from)
			if taken := s.dispatch(raw, places[from], &pending); taken != fresh {
				ht.Fatalf("%s was taken as fresh %v, want %v", what, taken, fresh)
			}
			if kind == "a matching answer" && pending != nil {
				ht.Fatalf("%s left its request outstanding", what)
			}
			if got := mux.Endpoint().AddrPort(); got != places[at].AddrPort() {
				ht.Fatalf("after %s the session sends to %s, want place %d at %s", what, got, at, places[at])
			}
			if got := recordedMoves(moves); !slices.Equal(got, want) {
				ht.Fatalf("after %s the session recorded the moves %q, want %q", what, got, want)
			}
		}
	})
}
