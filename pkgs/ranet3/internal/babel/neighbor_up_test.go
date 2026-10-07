// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package babel

import (
	"log/slog"
	"net/netip"
	"slices"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/netstack"
)

// packets deliver hands over before it takes the exchange for endless
const deliveryBudget = 1 << 10

// heldWire holds each packet until deliver, so a reply never goes out from inside the delivery that caused it
type heldWire struct {
	t                    *testing.T
	a, b                 *Speaker
	peerBForA, peerAForB *netstack.Peer
	toA, toB             [][]byte
}

func newHeldWire(t *testing.T, packetSize int) *heldWire {
	t.Helper()
	cfg := Config{Hello: dur(time.Second), Update: dur(10 * time.Minute)}
	w := &heldWire{t: t}
	var err error
	if w.a, err = New(cfg, Routes{}, Runtime{}, &netstack.Mesh{Routes: netstack.NewRouteTable()}); err != nil {
		t.Fatal(err)
	}
	if w.b, err = New(cfg, Routes{}, Runtime{PacketSize: packetSize}, &netstack.Mesh{Routes: netstack.NewRouteTable()}); err != nil {
		t.Fatal(err)
	}
	hold := func(queue *[][]byte) func([]byte) error {
		return func(raw []byte) error {
			*queue = append(*queue, slices.Clone(raw))
			return nil
		}
	}
	w.peerBForA = netstack.NewPeer("b", plainEncrypt, hold(&w.toB))
	w.peerAForB = netstack.NewPeer("a", plainEncrypt, hold(&w.toA))
	return w
}

func (w *heldWire) joinA() { w.a.AddPeer(w.peerBForA) }

func (w *heldWire) joinB() { w.b.AddPeer(w.peerAForB) }

func (w *heldWire) deliver() {
	w.t.Helper()
	delivered := 0
	for len(w.toA) > 0 || len(w.toB) > 0 {
		if delivered >= deliveryBudget {
			w.t.Fatal("the speakers were still answering each other past the delivery budget")
		}
		if len(w.toB) > 0 {
			raw := w.toB[0]
			w.toB = w.toB[1:]
			w.b.Receive(w.peerAForB, raw)
			delivered++
		}
		if len(w.toA) > 0 {
			raw := w.toA[0]
			w.toA = w.toA[1:]
			w.a.Receive(w.peerBForA, raw)
			delivered++
		}
	}
}

func (w *heldWire) helloFromB() { w.a.Receive(w.peerBForA, helloPacket(w.b, "a")) }

func helloPacket(from *Speaker, neighbor string) []byte {
	from.mu.Lock()
	defer from.mu.Unlock()
	return buildPacket(from.linkLocal, multicastGroup, EncodePacket(from.helloAction(from.neighbors[neighbor], time.Now()).tlvs))
}

func TestNodeThatMissedAStartupIsToldTheNeighborsRoutesAtItsFirstHello(t *testing.T) {
	w := newHeldWire(t, 0)
	dest := netip.MustParsePrefix("fd00:b::/64")
	w.b.Originate(dest)

	// b's session-start traffic reaches a before a has the session, and a drops it
	w.joinB()
	w.helloFromB()
	w.b.flushUpdates()
	w.deliver()
	if peer, ok := w.a.mesh.Routes.Lookup(dest.Addr(), dest.Addr()); ok {
		t.Fatalf("a learned the route through %q from a session it had not registered, so this proves nothing", peer.ID)
	}

	w.joinA()
	w.helloFromB()
	w.deliver()
	if peer, ok := w.a.mesh.Routes.Lookup(dest.Addr(), dest.Addr()); !ok || peer != w.peerBForA {
		t.Errorf("a did not learn the neighbor's route from its first hello, and holds %v", w.a.mesh.Routes.Debug())
	}
}

func TestNeighborComingUpIsAskedForItsWholeTable(t *testing.T) {
	bus := events.New()
	speaker, neighbor, packets := captureSpeaker(t, Config{}, Runtime{Events: bus})
	hello := func(seqno, interval uint16) []byte {
		return EncodePacket([]RawTLV{EncodeHello(Hello{Seqno: seqno, Interval: interval})})
	}
	requests := func() []RouteRequest {
		t.Helper()
		var out []RouteRequest
		for _, raw := range *packets {
			to, _ := netip.AddrFromSlice(raw[24:40])
			from, payload, err := parsePacket(raw, neighbor.addr)
			if err != nil || from != speaker.linkLocal || to != neighbor.addr {
				t.Fatalf("a packet from %v to %v was sent, want one from %v to %v: %v", from, to, speaker.linkLocal, neighbor.addr, err)
			}
			tlvs, err := DecodePacket(payload)
			if err != nil || len(tlvs) != 1 || tlvs[0].Type != TLVRouteRequest {
				t.Fatalf("a packet carrying %v was sent, want one Route Request: %v", tlvs, err)
			}
			request, err := DecodeRouteRequest(tlvs[0].Body)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, request)
		}
		return out
	}
	recorded := func(kind string) int {
		return len(bus.Recorded(func(got, peer string, _ []slog.Attr) bool {
			return got == kind && peer == neighbor.peer.ID
		}, 0))
	}
	check := func(step string, want int) {
		t.Helper()
		got := requests()
		if len(got) != want || recorded("babel.request.sent") != want {
			t.Fatalf("%s: %d requests sent and %d recorded, want %d of each", step, len(got), recorded("babel.request.sent"), want)
		}
		for _, request := range got {
			if request != (RouteRequest{AE: AEWildcard}) {
				t.Fatalf("%s: the request was %+v, want the wildcard", step, request)
			}
		}
	}

	// an unscheduled Hello promises no next Hello, RFC 8966 section 3.4.1
	speaker.handlePacket(neighbor, hello(1, 0))
	check("an unscheduled hello", 0)

	speaker.handlePacket(neighbor, hello(2, 100))
	check("the first scheduled hello", 1)

	speaker.handlePacket(neighbor, hello(3, 100))
	check("a hello from a neighbor that is up", 1)

	later := time.Now().Add(deadTimeout(neighbor.helloInterval) + time.Second)
	speaker.mu.Lock()
	speaker.sweepExpiredLocked(later)
	send := speaker.emitLocked(speaker.handlePacketLocked(neighbor, hello(4, 100), later))
	speaker.mu.Unlock()
	send()
	if recorded("babel.neighbor.down") != 1 {
		t.Fatal("the neighbor was not declared down, so this proves nothing")
	}
	check("a hello from a neighbor that returned", 2)
}

func TestRequestLeavesWithTheRepliesToTheHelloThatBroughtTheNeighborUp(t *testing.T) {
	speaker, neighbor, packets := captureSpeaker(t, Config{})
	speaker.Originate(netip.MustParsePrefix("fd00:a::/64"))
	speaker.handlePacket(neighbor, EncodePacket([]RawTLV{
		EncodeHello(Hello{Seqno: 1, Interval: 100}),
		EncodeRouteRequest(RouteRequest{AE: AEWildcard}),
	}))
	if len(*packets) != 1 {
		t.Fatalf("the neighbor was sent %d packets, want the answer and the request in one", len(*packets))
	}
	tlvs, err := DecodePacket((*packets)[0][ipv6HeaderLen+udpHeaderLen:])
	if err != nil {
		t.Fatal(err)
	}
	var kinds []TLVType
	for _, tlv := range tlvs {
		kinds = append(kinds, tlv.Type)
	}
	if want := []TLVType{TLVRouteRequest, TLVRouterID, TLVUpdate}; !slices.Equal(kinds, want) {
		t.Errorf("the packet carries %v, want the request and then the route announced", kinds)
	}
}
