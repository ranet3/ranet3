// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"bytes"
	"net/netip"
	"slices"
	"testing"

	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
)

// pathVia is cap.exit via as the tests write it, a waypoint whose /128 a peer routes and then an exit's egress segment, and pathSource the outer source, this node's IPv6 overlay address
var (
	pathVia    = []netip.Addr{segAddr("3fff:7::1"), segAddr("3fff:8::46")}
	pathSource = transitOwn[6]
)

// pathSteering is a steering table holding cap.exit via's path alone, or beside entries where some are given
func pathSteering(tb testing.TB, entries ...srv6.Steer) *srv6.SteerTable {
	tb.Helper()
	trie, err := srv6.NewSteerTable(entries, schema.AddrFrom(pathSource))
	if err != nil {
		tb.Fatal(err)
	}
	table, err := trie.WithDefault(pathSource, pathVia)
	if err != nil {
		tb.Fatal(err)
	}
	return table
}

// pathMesh is edgeMesh in mode 3 with a mesh subnet beyond its peer, each of prefixes routed to an exit, and the waypoint's /128 to a peer of its own
// it returns the mesh, its peer, the exit and the waypoint
func pathMesh(tb testing.TB, prefixes ...string) (*Mesh, *Peer, *Peer, *Peer) {
	tb.Helper()
	m, peer, exit := edgeLeaf(tb, prefixes...)
	waypoint := (&recordingPeer{}).peer(tb, "waypoint")
	m.Routes.Set(netip.Prefix{}, netip.PrefixFrom(pathVia[0], 128), waypoint)
	m.SetSteering(pathSteering(tb))
	return m, peer, exit, waypoint
}

// classifiedBatch classifies packets as one read off the tun and returns the read
func classifiedBatch(m *Mesh, packets ...[]byte) *outboundBatch {
	b := newOutboundBatch(len(packets))
	fill(b, packets...)
	m.classify(b)
	return b
}

// checkAlongPath fails unless sent is raw encapsulated along pathVia from pathSource, its routing header pushed for every segment, RFC 8986 section 5.1
func checkAlongPath(tb testing.TB, sent, raw []byte) {
	tb.Helper()
	header, err := srv6.Parse(sent)
	if err != nil {
		tb.Fatalf("the packet sent is no segment routed packet: %v", err)
	}
	source, destination := netip.AddrFrom16([16]byte(sent[8:24])), netip.AddrFrom16([16]byte(sent[24:40]))
	if source != pathSource || destination != pathVia[0] || !slices.Equal(header.Path(), pathVia) {
		tb.Fatalf("the packet went from %s to %s along %v, want from %s along %v", source, destination, header.Path(), pathSource, pathVia)
	}
	if !bytes.Equal(sent[len(sent)-len(raw):], raw) || len(sent) != len(raw)+srv6.Overhead(len(pathVia)) {
		tb.Fatal("the packet sent does not carry the packet read whole behind the path's header")
	}
}

// a host packet toward the internet that no entry covers, or only an entry counting as a default, an exit's default, a /1 half, a /2, one held or one from a source prefix
// leaves to the waypoint encapsulated along the path, in both families, and is counted steered
func TestDefaultSteerTakesWhatOnlyADefaultOrNothingCovers(t *testing.T) {
	for name, prefixes := range map[string][]string{
		"no entry":                  nil,
		"another exit's default":    {"0.0.0.0/0", "::/0"},
		"a pair of halves":          {"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"},
		"four quarters":             countedShapes[2].prefixes,
		"a default from an overlay": {},
	} {
		for _, family := range []int{4, 6} {
			m, _, _, waypoint := pathMesh(t, prefixes...)
			if name == "a default from an overlay" {
				m.Routes.Set(segPrefix(map[int]string{4: "192.0.2.0/24", 6: "3fff::/20"}[family]), segPrefix(map[int]string{4: "0.0.0.0/0", 6: "::/0"}[family]), (&recordingPeer{}).peer(t, "exit"))
			}
			raw := udpPacket(transitOwn[family], edgeInternet[family], 100, false)
			b := classifiedBatch(m, raw)
			if b.peers[0] != waypoint {
				t.Fatalf("under %s an IPv%d packet to the internet went to %v, want the waypoint", name, family, b.peers[0])
			}
			checkAlongPath(t, b.packets[0], raw)
			if got := m.SegmentCounters().Steered; got != 1 {
				t.Errorf("under %s an IPv%d packet to the internet was counted steered %d times", name, family, got)
			}
		}
	}
	for _, family := range []int{4, 6} {
		m, _, _, waypoint := pathMesh(t)
		m.Routes.Set(netip.Prefix{}, segPrefix(map[int]string{4: "0.0.0.0/0", 6: "::/0"}[family]), Unreachable)
		raw := udpPacket(transitOwn[family], edgeInternet[family], 100, false)
		if b := classifiedBatch(m, raw); b.peers[0] != waypoint {
			t.Errorf("under a held default an IPv%d packet to the internet went to %v, want the waypoint", family, b.peers[0])
		}
	}
}

// a host packet the table answers through an entry not counting as a default is followed as the mesh's own route, never along the path
// to an overlay host and a mesh subnet beyond a peer, under an exit's default too, to a held host, to an address of this node's own
// and one to an overlay address, which an exit would refuse, follows the exit's default where one covers it and is answered where none does
func TestDefaultSteerLeavesTheMeshItsOwnRoutes(t *testing.T) {
	for _, family := range []int{4, 6} {
		m, peer, exit, _ := pathMesh(t, "0.0.0.0/0", "::/0")
		went := classifiedTo(m,
			udpPacket(transitOwn[family], transitFar[family], 100, false),
			udpPacket(transitOwn[family], edgeSubnetHost[family], 100, false),
			udpPacket(transitOwn[family], transitHeldHost[family], 100, false),
			udpPacket(transitOwn[family], edgeAssigned[family], 100, false),
			udpPacket(transitOwn[family], transitUnrouted[family], 100, false),
		)
		if want := []*Peer{peer, peer, nil, nil, exit}; !slices.Equal(went, want) {
			t.Errorf("IPv%d reads to an overlay host, a mesh subnet, a held host, its own address and an unrouted overlay address went to %v, want %v", family, went, want)
		}
		if got := m.SegmentCounters().Steered; got != 0 {
			t.Errorf("IPv%d reads the mesh routes were steered %d times", family, got)
		}

		bare, _, _, _ := pathMesh(t)
		if went := classifiedTo(bare, udpPacket(transitOwn[family], transitUnrouted[family], 100, false)); went[0] != nil || bare.SegmentCounters().Steered != 0 {
			t.Errorf("IPv%d a read to an overlay address no entry covers went to %v, steered %d times", family, went[0], bare.SegmentCounters().Steered)
		}
	}
}

// a cap.segment steer entry claims a packet ahead of the path, and ranet3 down steering stops the entries and leaves the path, so the packet goes along the path then
func TestDefaultSteerComesAfterTheEntriesAndOutlastsTheirStop(t *testing.T) {
	m, _, _, waypoint := pathMesh(t)
	entryPeer := (&recordingPeer{}).peer(t, "entry's segment")
	m.Routes.Set(netip.Prefix{}, segPrefix("3fff:9::/64"), entryPeer)
	m.SetSteering(pathSteering(t, srv6.Steer{To: schema.PrefixFrom(hostPrefix(edgeInternet[6])), Via: []schema.Addr{schema.MustAddr("3fff:9::1")}}))
	raw := udpPacket(transitOwn[6], edgeInternet[6], 100, false)
	if went := classifiedTo(m, raw); went[0] != entryPeer {
		t.Errorf("a packet a cap.segment steer entry claims went to %v, want the entry's first segment", went[0])
	}
	m.SetSteeringEnabled(false)
	b := classifiedBatch(m, raw)
	if b.peers[0] != waypoint {
		t.Fatalf("with steering stopped the packet went to %v, want the path's waypoint", b.peers[0])
	}
	checkAlongPath(t, b.packets[0], raw)
}

// a read is checked before the path takes it, so one from another node's address toward the internet is dropped as forged rather than steered
// and one carrying a routing header is dropped for it rather than wrapped in another
func TestDefaultSteerTakesOnlyWhatTheChecksPass(t *testing.T) {
	m, _, _, _ := pathMesh(t)
	plain := udpPacket(transitOwn[6], edgeInternet[6], 100, false)
	went := classifiedTo(m,
		udpPacket(transitSender[6], edgeInternet[6], 100, false),
		udpPacket(transitSender[4], edgeInternet[4], 100, false),
		withRouting(plain, 4),
	)
	if !slices.Equal(went, make([]*Peer, 3)) {
		t.Errorf("a forged read in each family and one with an SRH went to %v", went)
	}
	if got := m.TransitCounters(); got != (TransitCounters{Forged: 2, RoutingHeader: 1}) {
		t.Errorf("the reads counted %+v", got)
	}
	if got := m.SegmentCounters().Steered; got != 0 {
		t.Errorf("reads the checks dropped were steered %d times", got)
	}
}

// with no route to the path's first segment a host packet the path takes is answered into the tun with destination unreachable, no route, from its destination
// and counted unrouted, in both families, whether no entry covers the segment or a hold does
func TestDefaultSteerWithNoRouteToTheFirstSegmentIsAnswered(t *testing.T) {
	for _, prefixes := range [][]string{nil, {"3fff:7::/64"}} {
		for _, family := range []int{4, 6} {
			m, dev := recordingMesh(t)
			m.SetOverlay(transitOverlay)
			ownHosts(m, transitOwn)
			for _, prefix := range prefixes {
				m.Routes.Set(netip.Prefix{}, segPrefix(prefix), Unreachable)
			}
			m.SetSteering(pathSteering(t))
			raw := udpPacket(transitOwn[family], edgeInternet[family], 100, false)
			b, written := classifyOne(m, dev, raw)
			if b.peers[0] != nil || len(written) != 1 {
				t.Fatalf("under %v an IPv%d packet with no route to its first segment went to %v and wrote %d packets into the tun", prefixes, family, b.peers[0], len(written))
			}
			if family == 6 {
				checkICMPv6(t, written[0], raw, edgeInternet[6], 1, 0, 0)
			} else {
				checkICMPv4(t, written[0], raw, edgeInternet[4], 3, 0, 0)
			}
			if got := m.SegmentCounters(); got.Steered != 1 || got.Unrouted != 1 {
				t.Errorf("under %v an IPv%d packet with no route to its first segment counted %+v", prefixes, family, got)
			}
		}
	}
}
