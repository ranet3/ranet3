// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"encoding/binary"
	"log/slog"
	"net/netip"
	"slices"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
)

// the tun reads' sources by family, beside the decision's tests' addresses
// assigned is an address cap.table assigns this node, and internet a host outside the overlay that a reply of the exit's egress comes from
var (
	edgeAssigned = map[int]netip.Addr{4: segAddr("192.0.2.6"), 6: segAddr("3fff::6")}
	edgeInternet = transitNowhere
)

// edgeMesh is a mesh with no tun, the overlay of the decision's tests and a peer that every address the decision's tests name as another node's routes to
// this node owns transitOwn, a host route of its own, and edgeAssigned, an address cap.table assigns it, and holds transitHeldHost unreachable
func edgeMesh(tb testing.TB) (*Mesh, *Peer) {
	tb.Helper()
	m := &Mesh{Name: "test0", Routes: NewRouteTable(), closed: make(chan struct{})}
	m.startSegmentReports()
	m.SetOverlay(transitOverlay)
	peer := (&recordingPeer{}).peer(tb, "peer")
	for _, family := range []int{4, 6} {
		m.Routes.Set(netip.Prefix{}, hostPrefix(transitSender[family]), peer)
		m.Routes.Set(netip.Prefix{}, hostPrefix(transitFar[family]), peer)
		m.Routes.Set(netip.Prefix{}, hostPrefix(transitOwn[family]), Local)
		m.Routes.Set(netip.Prefix{}, hostPrefix(edgeAssigned[family]), Assigned)
		m.Routes.Set(netip.Prefix{}, hostPrefix(transitHeldHost[family]), Unreachable)
	}
	return m, peer
}

// readSent classifies b, which holds packets as one read off the tun, and reports which of them went to peer
func readSent(m *Mesh, b *outboundBatch, peer *Peer, packets ...[]byte) []bool {
	fill(b, packets...)
	m.classify(b)
	sent := make([]bool, len(packets))
	for i := range packets {
		sent[i] = b.peers[i] == peer
	}
	return sent
}

// classified is readSent over a read of its own
func classified(m *Mesh, peer *Peer, packets ...[]byte) []bool {
	return readSent(m, newOutboundBatch(len(packets)), peer, packets...)
}

// withRouting is raw, an IPv6 packet, with a routing header of kind between its fixed header and what followed it, segments left 0
func withRouting(raw []byte, kind byte) []byte {
	out := slices.Concat(raw[:40], []byte{raw[6], 0, kind, 0, 0, 0, 0, 0}, raw[40:])
	out[6] = 43
	binary.BigEndian.PutUint16(out[4:], uint16(len(out)-40))
	return out
}

// a read off the tun is dropped as forged when the mesh routes its source to another node or holds it, the table rule
// or when its source lies inside the overlay and no entry of this node's own covers it, the overlay rule
// a source this node owns through a host route or an address cap.table assigns passes, and so does one outside the overlay that nothing routes
// each counted once the read is classified, in both families
func TestTUNReadFromASourceOfAnotherNodeIsForged(t *testing.T) {
	for _, family := range []int{4, 6} {
		m, peer := edgeMesh(t)
		cases := []struct {
			name   string
			source netip.Addr
			forged bool
		}{
			{"this node's host route", transitOwn[family], false},
			{"an address cap.table assigns", edgeAssigned[family], false},
			{"outside the overlay with no route", transitNowhere[family], false},
			{"another node's", transitSender[family], true},
			{"held", transitHeldHost[family], true},
			{"inside the overlay with no route", transitUnrouted[family], true},
		}
		var packets [][]byte
		for _, c := range cases {
			packets = append(packets, udpPacket(c.source, transitFar[family], 100, false))
		}
		sent := classified(m, peer, packets...)
		forged := uint64(0)
		for i, c := range cases {
			if sent[i] == c.forged {
				t.Errorf("IPv%d from %s, %s, went to the peer %t, want %t", family, c.source, c.name, sent[i], !c.forged)
			}
			if c.forged {
				forged++
			}
		}
		if got := m.TransitCounters(); got != (TransitCounters{Forged: forged}) {
			t.Errorf("an IPv%d read with %d forged sources counted %+v", family, forged, got)
		}
	}
}

// the overlay rule needs cap.border's overlay written, and without it an overlay address no route holds is no node's and passes
// while the table rule needs none, for a source routed to another node and for one held alike
func TestTUNReadWithNoOverlayIsForgedByTheTableAlone(t *testing.T) {
	for _, family := range []int{4, 6} {
		m, peer := edgeMesh(t)
		m.SetOverlay(nil)
		sent := classified(m, peer,
			udpPacket(transitUnrouted[family], transitFar[family], 100, false),
			udpPacket(transitSender[family], transitFar[family], 100, false),
			udpPacket(transitHeldHost[family], transitFar[family], 100, false),
		)
		if want := []bool{true, false, false}; !slices.Equal(sent, want) {
			t.Errorf("with no overlay IPv%d reads from an unrouted overlay address, another node's and a held one went to the peer %v, want %v", family, sent, want)
		}
	}
}

// an exit's egress replies carry the internet's sources, which another exit's default, its /1 halves or four /2s route to a peer
// an entry counting as a default makes no source another node's, so the replies pass at an exit that learned them, toward a leaf's address
// and an overlay source this node does not own is forged though the exit's own default covers it, since a default makes no source this node's
func TestTUNReadPassesOverEntriesCountingAsADefault(t *testing.T) {
	shapes := []struct {
		name     string
		prefixes []string
	}{
		{"a default", []string{"0.0.0.0/0", "::/0"}},
		{"a pair of halves", []string{"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"}},
		{"four quarters", []string{"0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/2", "192.0.0.0/2", "::/2", "4000::/2", "8000::/2", "c000::/2"}},
	}
	for _, shape := range shapes {
		for _, family := range []int{4, 6} {
			m, peer := edgeMesh(t)
			other := (&recordingPeer{}).peer(t, "other exit")
			for _, prefix := range shape.prefixes {
				m.Routes.Set(netip.Prefix{}, segPrefix(prefix), other)
			}
			// this node is an exit of its own
			m.Routes.Set(netip.Prefix{}, segPrefix("0.0.0.0/0"), Local)
			m.Routes.Set(netip.Prefix{}, segPrefix("::/0"), Local)
			sent := classified(m, peer,
				udpPacket(edgeInternet[family], transitFar[family], 100, false),
				udpPacket(transitUnrouted[family], transitFar[family], 100, false),
			)
			if !sent[0] {
				t.Errorf("%s of IPv%d learned from another exit forged an egress reply from %s", shape.name, family, edgeInternet[family])
			}
			if sent[1] {
				t.Errorf("under %s of IPv%d and this node's own default an overlay source no entry of its own covers went to the peer", shape.name, family)
			}
			if got := m.TransitCounters().Forged; got != 1 {
				t.Errorf("under %s of IPv%d the read counted %d forged, want 1", shape.name, family, got)
			}
		}
	}
}

// a source's answer is the route a reply to the packet takes, so a route announced from a source prefix covers a source only for replies to that prefix
// within one read, in either order, the packet to the prefix the route is announced from is forged and the one to elsewhere passes
// which an answer kept per source alone, or looked up with no source, would give both packets the same verdict
func TestTUNReadAnswersASourceForEachDestination(t *testing.T) {
	for _, family := range []int{4, 6} {
		m, peer := edgeMesh(t)
		// another node announces transitUnrouted's network from the network transitFar lies in
		from, to := hostPrefix(transitFar[family]), netip.PrefixFrom(transitUnrouted[family], transitUnrouted[family].BitLen()-2)
		m.SetOverlay(nil)
		m.Routes.Set(from, to.Masked(), (&recordingPeer{}).peer(t, "another node"))
		m.Routes.Set(netip.Prefix{}, hostPrefix(transitNowhere[family]), peer)
		toFar := udpPacket(transitUnrouted[family], transitFar[family], 100, false)
		elsewhere := udpPacket(transitUnrouted[family], transitNowhere[family], 100, false)
		for _, order := range [][2]bool{{true, false}, {false, true}} {
			packets := [][]byte{toFar, elsewhere}
			if !order[0] {
				packets = [][]byte{elsewhere, toFar}
			}
			sent := classified(m, peer, packets...)
			if sent[0] != !order[0] || sent[1] != !order[1] {
				t.Errorf("IPv%d from %s to %s and elsewhere, in the order %v, went to the peer %v", family, transitUnrouted[family], transitFar[family], order, sent)
			}
		}
	}
}

// the answers a read leaves for the next go once the table changes, so a route the table gains between two reads of one batch from one source decides the second
func TestTUNReadAnswersFromTheTableAsItIsAtTheRead(t *testing.T) {
	for _, family := range []int{4, 6} {
		m, peer := edgeMesh(t)
		raw := udpPacket(transitNowhere[family], transitFar[family], 100, false)
		b := newOutboundBatch(2)
		if sent := readSent(m, b, peer, raw, raw); !sent[0] || !sent[1] {
			t.Fatalf("IPv%d from %s, which nothing routes, went to the peer %v", family, transitNowhere[family], sent)
		}
		b.reset()
		m.Routes.Set(netip.Prefix{}, hostPrefix(transitNowhere[family]), (&recordingPeer{}).peer(t, "another node"))
		if sent := readSent(m, b, peer, raw, raw); sent[0] || sent[1] {
			t.Errorf("IPv%d from %s, routed to another node since the last read, went to the peer %v", family, transitNowhere[family], sent)
		}
	}
}

// a tun read carrying a routing header of a type the mesh's edge refuses is dropped and counted, behind other headers as well
// one of type 2 passes, and a chain the walk cannot finish is counted invalid
// the walk comes first, so an SRH from another node's address or to a SID of this node's is counted for its routing header
func TestTUNReadWithARoutingHeaderIsDropped(t *testing.T) {
	m, peer := edgeMesh(t)
	sid := segAddr("3fff:6::1")
	segments, err := srv6.NewLocalTable([]srv6.Segment{{SID: schema.AddrFrom(sid), Behavior: srv6.BehaviorEnd}}, transitOverlay)
	if err != nil {
		t.Fatal(err)
	}
	m.SetSegments(segments)
	plain := udpPacket(transitOwn[6], transitFar[6], 100, false)
	cut := withRouting(plain, 2)
	cut[41] = 255
	sent := classified(m, peer,
		withRouting(plain, 4),
		withRouting(withRouting(plain, 0), 2),
		withRouting(plain, 2),
		cut,
		withRouting(udpPacket(transitSender[6], transitFar[6], 100, false), 4),
		withRouting(udpPacket(transitOwn[6], sid, 100, false), 4),
	)
	if want := []bool{false, false, true, false, false, false}; !slices.Equal(sent, want) {
		t.Errorf("reads with an SRH, a type 0 behind a type 2, a type 2, a chain cut short, an SRH from another node's address and one to this node's SID went to the peer %v, want %v", sent, want)
	}
	if got := m.TransitCounters(); got != (TransitCounters{RoutingHeader: 4, Invalid: 1}) {
		t.Errorf("the read counted %+v", got)
	}
}

// a tun read to a SID of this node's is dropped and counted, a SID acting only on what a session delivers
// one outside every entry of this node's own, which a learned route would otherwise carry to the peer, and one under a prefix it announces
// and a node configuring no segments drops nothing for it
// the SID check comes before the source's, so a read to the SID from another node's address is counted for the SID
func TestTUNReadToASIDOfThisNodeIsDropped(t *testing.T) {
	learned, owned := segAddr("3fff:5::1"), segAddr("3fff:6::1")
	table, err := srv6.NewLocalTable([]srv6.Segment{
		{SID: schema.AddrFrom(learned), Behavior: srv6.BehaviorEndDT46},
		{SID: schema.AddrFrom(owned), Behavior: srv6.BehaviorEnd},
	}, transitOverlay)
	if err != nil {
		t.Fatal(err)
	}
	for _, segments := range []*srv6.LocalTable{table, nil} {
		m, peer := edgeMesh(t)
		m.SetSegments(segments)
		m.Routes.Set(netip.Prefix{}, segPrefix("3fff:5::/64"), peer)
		m.Routes.Set(netip.Prefix{}, segPrefix("3fff:6::/64"), Local)
		sent := classified(m, peer,
			udpPacket(transitOwn[6], learned, 100, false),
			udpPacket(transitOwn[6], owned, 100, false),
			udpPacket(transitSender[6], learned, 100, false),
		)
		sid, forged, counted := uint64(3), uint64(0), false
		if segments == nil {
			sid, forged, counted = 0, 1, true
		}
		if sent[0] != counted || sent[2] {
			t.Errorf("with segments %v reads to %s under a learned route from this node's own address and another node's went to the peer %v", segments.Segments(), learned, sent)
		}
		if got := m.TransitCounters(); got.SID != sid || got.Forged != forged {
			t.Errorf("with segments %v the read counted %d to a SID and %d forged, want %d and %d", segments.Segments(), got.SID, got.Forged, sid, forged)
		}
	}
}

// a packet a policy steers is checked as it was read, before the steer wraps it in a routing header the edge would refuse
// so of two packets the policy claims, the one from this node's own source is steered and the one from another node's is dropped before any steer
func TestTUNReadIsCheckedBeforeItIsSteered(t *testing.T) {
	m, peer := edgeMesh(t)
	m.SetSteering(steerBothFrom(t, 1))
	m.Routes.Set(netip.Prefix{}, segPrefix("3fff:1::/64"), peer)
	m.Routes.Set(netip.Prefix{}, hostPrefix(tooBigSource[6]), Local)
	m.Routes.Set(netip.Prefix{}, hostPrefix(tooBigSource[4]), (&recordingPeer{}).peer(t, "another node"))
	sent := classified(m, peer,
		udpPacket(tooBigSource[6], tooBigDestination[6], 100, false),
		udpPacket(tooBigSource[4], tooBigDestination[4], 100, false),
	)
	if !sent[0] || sent[1] {
		t.Errorf("a steered read from this node's own source and one from another node's went to the peer %v, want true and false", sent)
	}
	if got := m.SegmentCounters().Steered; got != 1 {
		t.Errorf("the read steered %d packets, want 1", got)
	}
	if got := m.TransitCounters(); got != (TransitCounters{Forged: 1}) {
		t.Errorf("the read counted %+v", got)
	}
}

// a tun read's drop reports through the decision's report, with the event naming its reason, source and destination
func TestTUNReadDropRecordsTheEvent(t *testing.T) {
	m, peer := edgeMesh(t)
	bus := events.New()
	m.events = bus.Emit
	classified(m, peer, udpPacket(transitSender[6], transitFar[6], 100, false))
	recorded := bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "netstack.transit.dropped" }, 0)
	if len(recorded) != 1 {
		t.Fatalf("a forged read recorded %d drop events", len(recorded))
	}
	want := map[string]string{"reason": "forged", "src": transitSender[6].String(), "dst": transitFar[6].String()}
	for key, value := range want {
		if got := recorded[0].Attrs[key]; got != value {
			t.Errorf("the drop's event holds %s %v, want %s", key, got, value)
		}
	}
}
