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
// lan is a host on a link of this node's the mesh routes nothing to, neighbor a host on its uplink, and subnet a network beyond another node the mesh routes
var (
	edgeAssigned   = map[int]netip.Addr{4: segAddr("192.0.2.6"), 6: segAddr("3fff::6")}
	edgeInternet   = transitNowhere
	edgeLAN        = map[int]netip.Addr{4: segAddr("198.51.100.20"), 6: segAddr("2001:db8:100::20")}
	edgeNeighbor   = map[int]netip.Addr{4: segAddr("198.51.100.30"), 6: segAddr("2001:db8:100::30")}
	edgeSubnet     = map[int]netip.Prefix{4: segPrefix("203.0.113.128/25"), 6: segPrefix("2001:db8:5::/48")}
	edgeSubnetHost = map[int]netip.Addr{4: segAddr("203.0.113.130"), 6: segAddr("2001:db8:5::1")}
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

// ownHosts gives m a host route of this node's own for each address, so a read off the tun from it toward a default comes from this node
func ownHosts(m *Mesh, addresses ...map[int]netip.Addr) {
	for _, byFamily := range addresses {
		for _, address := range byFamily {
			m.Routes.Set(netip.Prefix{}, hostPrefix(address), Local)
		}
	}
}

// ownSources is ownHosts for the source of each packet
func ownSources(m *Mesh, packets ...[]byte) {
	for _, raw := range packets {
		if source, _, _, ok := addrsOf(raw); ok {
			m.Routes.Set(netip.Prefix{}, hostPrefix(source), Local)
		}
	}
}

// classifiedTo classifies packets as one read off the tun and reports the peer each went to, nil for none
func classifiedTo(m *Mesh, packets ...[]byte) []*Peer {
	b := newOutboundBatch(len(packets))
	fill(b, packets...)
	m.classify(b)
	return slices.Clone(b.peers[:len(packets)])
}

// edgeLeaf is edgeMesh at a leaf that learned prefixes from an exit, which it returns beside the peer, and the peer's subnet
func edgeLeaf(tb testing.TB, prefixes ...string) (*Mesh, *Peer, *Peer) {
	tb.Helper()
	m, peer := edgeMesh(tb)
	exit := (&recordingPeer{}).peer(tb, "exit")
	for _, prefix := range prefixes {
		m.Routes.Set(netip.Prefix{}, segPrefix(prefix), exit)
	}
	for _, family := range []int{4, 6} {
		m.Routes.Set(netip.Prefix{}, edgeSubnet[family], peer)
	}
	return m, peer, exit
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
		went := classifiedTo(m, packets...)
		forged := uint64(0)
		for i, c := range cases {
			if sent := went[i] == peer; sent == c.forged {
				t.Errorf("IPv%d from %s, %s, went to the peer %t, want %t", family, c.source, c.name, sent, !c.forged)
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
		went := classifiedTo(m,
			udpPacket(transitUnrouted[family], transitFar[family], 100, false),
			udpPacket(transitSender[family], transitFar[family], 100, false),
			udpPacket(transitHeldHost[family], transitFar[family], 100, false),
		)
		if want := []*Peer{peer, nil, nil}; !slices.Equal(went, want) {
			t.Errorf("with no overlay IPv%d reads from an unrouted overlay address, another node's and a held one went to %v, want %v", family, went, want)
		}
	}
}

// countedShapes are the ways an exit advertises the internet, each entry of them counting as a default
var countedShapes = []struct {
	name     string
	prefixes []string
}{
	{"a default", []string{"0.0.0.0/0", "::/0"}},
	{"a pair of halves", []string{"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"}},
	{"four quarters", []string{"0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/2", "192.0.0.0/2", "::/2", "4000::/2", "8000::/2", "c000::/2"}},
}

// an exit's egress replies carry the internet's sources, which another exit's default, its /1 halves or four /2s route to a peer
// an entry counting as a default makes no source another node's, so the replies pass at an exit that learned them, toward a leaf's address
// and an overlay source this node does not own is forged though the exit's own default covers it, since a default makes no source this node's
func TestTUNReadPassesOverEntriesCountingAsADefault(t *testing.T) {
	for _, shape := range countedShapes {
		for _, family := range []int{4, 6} {
			m, peer := edgeMesh(t)
			other := (&recordingPeer{}).peer(t, "other exit")
			for _, prefix := range shape.prefixes {
				m.Routes.Set(netip.Prefix{}, segPrefix(prefix), other)
			}
			// this node is an exit of its own
			m.Routes.Set(netip.Prefix{}, segPrefix("0.0.0.0/0"), Local)
			m.Routes.Set(netip.Prefix{}, segPrefix("::/0"), Local)
			went := classifiedTo(m,
				udpPacket(edgeInternet[family], transitFar[family], 100, false),
				udpPacket(transitUnrouted[family], transitFar[family], 100, false),
			)
			if went[0] != peer {
				t.Errorf("%s of IPv%d learned from another exit forged an egress reply from %s", shape.name, family, edgeInternet[family])
			}
			if went[1] != nil {
				t.Errorf("under %s of IPv%d and this node's own default an overlay source no entry of its own covers went to the peer", shape.name, family)
			}
			if got := m.TransitCounters().Forged; got != 1 {
				t.Errorf("under %s of IPv%d the read counted %d forged, want 1", shape.name, family, got)
			}
		}
	}
}

// at a leaf that learned an exit's default, its /1 halves or four /2s, a read toward the internet leaves the mesh only from a source of this node's own
// its own overlay address and one cap.table assigns it reach the exit, a host on its LAN and a neighbor on its uplink are dropped
// and replies toward an overlay address and toward a subnet the mesh routes pass whatever their source
func TestTUNReadThroughAnEntryCountingAsADefaultComesFromThisNode(t *testing.T) {
	for _, shape := range countedShapes {
		for _, family := range []int{4, 6} {
			m, peer, exit := edgeLeaf(t, shape.prefixes...)
			cases := []struct {
				name        string
				source, to  netip.Addr
				destination *Peer
			}{
				{"this node's overlay address to the internet", transitOwn[family], edgeInternet[family], exit},
				{"an address cap.table assigns to the internet", edgeAssigned[family], edgeInternet[family], exit},
				{"a host on its LAN to the internet", edgeLAN[family], edgeInternet[family], nil},
				{"a neighbor to the internet", edgeNeighbor[family], edgeInternet[family], nil},
				{"a host on its LAN to an overlay address", edgeLAN[family], transitFar[family], peer},
				{"a neighbor to a subnet the mesh routes", edgeNeighbor[family], edgeSubnetHost[family], peer},
			}
			var packets [][]byte
			for _, c := range cases {
				packets = append(packets, udpPacket(c.source, c.to, 100, false))
			}
			went := classifiedTo(m, packets...)
			for i, c := range cases {
				if went[i] != c.destination {
					t.Errorf("under %s of IPv%d a read from %s, %s, went to %v, want %v", shape.name, family, c.source, c.name, went[i], c.destination)
				}
			}
			if got := m.TransitCounters(); got != (TransitCounters{UnownedSource: 2}) {
				t.Errorf("under %s of IPv%d the read counted %+v, want 2 from an unowned source", shape.name, family, got)
			}
		}
	}
}

// this node's own default from a source prefix counts as a default, so it makes no address it covers this node's
// a host's packet toward the internet through the exit's default is dropped though a reply to it would take this node's own entry
func TestTUNReadFromASourceUnderAnEntryOfThisNodeCountingAsADefaultIsNotOwned(t *testing.T) {
	from := map[int]string{4: "203.0.113.0/24", 6: "2001:db8::/48"}
	unspecified := map[int]string{4: "0.0.0.0/0", 6: "::/0"}
	for _, family := range []int{4, 6} {
		m, _, _ := edgeLeaf(t, "0.0.0.0/0", "::/0")
		m.Routes.Set(segPrefix(from[family]), segPrefix(unspecified[family]), Local)
		if went := classifiedTo(m, udpPacket(edgeLAN[family], edgeInternet[family], 100, false)); went[0] != nil {
			t.Errorf("IPv%d from a host on its LAN to the internet went to %v under this node's own default from %s", family, went[0], from[family])
		}
		if got := m.TransitCounters(); got != (TransitCounters{UnownedSource: 1}) {
			t.Errorf("IPv%d the read counted %+v", family, got)
		}
	}
}

// a source's answer is the route a reply to the packet takes, kept for each source and destination of a read, and the owned-source rule is judged for each packet by its own destination
// so of one read from one source to two destinations, in either order, the packet each rule drops is dropped and the other passes
// a route announced from a source prefix covers a source only for replies to that prefix, which an answer kept per source alone, or looked up with no source, would give both packets
// and a host on its LAN reaches a subnet the mesh routes but not the internet through an exit's default
func TestTUNReadJudgesEachPacketOfASourceByItsOwnDestination(t *testing.T) {
	for _, family := range []int{4, 6} {
		announced, peer := edgeMesh(t)
		// another node announces transitUnrouted's network from the network transitFar lies in
		from, to := hostPrefix(transitFar[family]), netip.PrefixFrom(transitUnrouted[family], transitUnrouted[family].BitLen()-2)
		announced.SetOverlay(nil)
		announced.Routes.Set(from, to.Masked(), (&recordingPeer{}).peer(t, "another node"))
		announced.Routes.Set(netip.Prefix{}, hostPrefix(transitNowhere[family]), peer)
		leaf, leafPeer, _ := edgeLeaf(t, "0.0.0.0/0", "::/0")
		for _, c := range []struct {
			name            string
			m               *Mesh
			peer            *Peer
			passes, dropped []byte
			want            TransitCounters
		}{
			{
				"from a source another node announces from a source prefix", announced, peer,
				udpPacket(transitUnrouted[family], transitNowhere[family], 100, false), udpPacket(transitUnrouted[family], transitFar[family], 100, false),
				TransitCounters{Forged: 2},
			},
			{
				"from a host on its LAN", leaf, leafPeer,
				udpPacket(edgeLAN[family], edgeSubnetHost[family], 100, false), udpPacket(edgeLAN[family], edgeInternet[family], 100, false),
				TransitCounters{UnownedSource: 2},
			},
		} {
			if went := classifiedTo(c.m, c.passes, c.dropped); went[0] != c.peer || went[1] != nil {
				t.Errorf("IPv%d a read %s, first where it passes, went to %v", family, c.name, went)
			}
			if went := classifiedTo(c.m, c.dropped, c.passes); went[0] != nil || went[1] != c.peer {
				t.Errorf("IPv%d a read %s, first where it is dropped, went to %v", family, c.name, went)
			}
			if got := c.m.TransitCounters(); got != c.want {
				t.Errorf("IPv%d the two reads %s counted %+v, want %+v", family, c.name, got, c.want)
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
		fill(b, raw, raw)
		m.classify(b)
		if went := b.peers[:2]; went[0] != peer || went[1] != peer {
			t.Fatalf("IPv%d from %s, which nothing routes, went to %v", family, transitNowhere[family], went)
		}
		b.reset()
		m.Routes.Set(netip.Prefix{}, hostPrefix(transitNowhere[family]), (&recordingPeer{}).peer(t, "another node"))
		fill(b, raw, raw)
		m.classify(b)
		if went := b.peers[:2]; went[0] != nil || went[1] != nil {
			t.Errorf("IPv%d from %s, routed to another node since the last read, went to %v", family, transitNowhere[family], went)
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
	went := classifiedTo(m,
		withRouting(plain, 4),
		withRouting(withRouting(plain, 0), 2),
		withRouting(plain, 2),
		cut,
		withRouting(udpPacket(transitSender[6], transitFar[6], 100, false), 4),
		withRouting(udpPacket(transitOwn[6], sid, 100, false), 4),
	)
	if want := []*Peer{nil, nil, peer, nil, nil, nil}; !slices.Equal(went, want) {
		t.Errorf("reads with an SRH, a type 0 behind a type 2, a type 2, a chain cut short, an SRH from another node's address and one to this node's SID went to %v, want %v", went, want)
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
		went := classifiedTo(m,
			udpPacket(transitOwn[6], learned, 100, false),
			udpPacket(transitOwn[6], owned, 100, false),
			udpPacket(transitSender[6], learned, 100, false),
		)
		sid, forged, counted := uint64(3), uint64(0), false
		if segments == nil {
			sid, forged, counted = 0, 1, true
		}
		if (went[0] == peer) != counted || went[2] != nil {
			t.Errorf("with segments %v reads to %s under a learned route from this node's own address and another node's went to %v", segments.Segments(), learned, []*Peer{went[0], went[2]})
		}
		if got := m.TransitCounters(); got.SID != sid || got.Forged != forged {
			t.Errorf("with segments %v the read counted %d to a SID and %d forged, want %d and %d", segments.Segments(), got.SID, got.Forged, sid, forged)
		}
	}
}

// a packet a policy steers is checked as it was read, before the steer wraps it in a routing header the edge would refuse
// so of the packets a policy claims, one from this node's own address is steered and one from another node's is dropped as forged before any steer
// and a host's packet is judged by the destination it was read with, dropped toward the internet where a learned default covers it and steered toward an overlay address
func TestTUNReadIsCheckedBeforeItIsSteered(t *testing.T) {
	for _, family := range []int{4, 6} {
		m, peer, _ := edgeLeaf(t, "0.0.0.0/0", "::/0")
		var steers []srv6.Steer
		for _, source := range []netip.Addr{transitOwn[family], transitSender[family], edgeLAN[family]} {
			steers = append(steers, srv6.Steer{From: schema.PrefixFrom(hostPrefix(source)), Via: []schema.Addr{schema.MustAddr("3fff:1::1")}})
		}
		steering, err := srv6.NewSteerTable(steers, schema.MustAddr("3fff:1:69c:8c0::1"))
		if err != nil {
			t.Fatal(err)
		}
		m.SetSteering(steering)
		m.Routes.Set(netip.Prefix{}, segPrefix("3fff:1::/64"), peer)
		cases := []struct {
			name                string
			source, destination netip.Addr
			want                *Peer
		}{
			{"from this node's own address", transitOwn[family], transitFar[family], peer},
			{"from another node's address", transitSender[family], transitFar[family], nil},
			{"from a host on its LAN to the internet", edgeLAN[family], edgeInternet[family], nil},
			{"from a host on its LAN to an overlay address", edgeLAN[family], transitFar[family], peer},
		}
		var packets [][]byte
		for _, c := range cases {
			packets = append(packets, udpPacket(c.source, c.destination, 100, false))
		}
		went := classifiedTo(m, packets...)
		for i, c := range cases {
			if went[i] != c.want {
				t.Errorf("IPv%d a steered read %s went to %v, want %v", family, c.name, went[i], c.want)
			}
		}
		if got := m.SegmentCounters().Steered; got != 2 {
			t.Errorf("IPv%d the read steered %d packets, want 2", family, got)
		}
		if got := m.TransitCounters(); got != (TransitCounters{Forged: 1, UnownedSource: 1}) {
			t.Errorf("IPv%d the read counted %+v", family, got)
		}
	}
}

// a tun read's drop reports through the decision's report, with the event naming its reason, source and destination
func TestTUNReadDropRecordsTheEvent(t *testing.T) {
	m, _ := edgeMesh(t)
	bus := events.New()
	m.events = bus.Emit
	classifiedTo(m, udpPacket(transitSender[6], transitFar[6], 100, false))
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
