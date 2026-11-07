// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
)

// Steering happens before the route lookup, so a steered packet goes to the
// peer its first segment selects rather than to the one its own destination
// would have selected. Calling steer directly cannot see that: the seam has to
// re-read the addresses off the encapsulated packet, and dropping that leaves
// the packet correctly encapsulated and handed to the wrong peer, which
// arrives at a node holding no such segment.
func TestOutboundSeamRoutesBySegmentRatherThanByDestination(t *testing.T) {
	exit := segAddr("3fff:b:0:206::1")
	table, err := srv6.NewSteerTable([]srv6.Steer{{
		From: schema.PrefixFrom(segPrefix("3fff:a::17/128")),
		Via:  []schema.Addr{schema.AddrFrom(exit)},
	}}, schema.MustAddr("3fff:b:0:100::1"))
	if err != nil {
		t.Fatal(err)
	}

	viaSegment := make(chan []byte, 1)
	viaDestination := make(chan []byte, 1)
	segmentPeer := sealingPeer(t, "segment", viaSegment)
	destinationPeer := sealingPeer(t, "destination", viaDestination)

	dev := &scriptedDevice{reads: make(chan scriptedRead, 1), closed: make(chan struct{})}
	m := &Mesh{Routes: NewRouteTable(), closed: make(chan struct{})}
	m.setDevice(dev)
	m.SetSteering(table)
	// The two halves of the mesh: the segment goes one way, the address the
	// packet was written to goes the other.
	m.Routes.Set(netip.Prefix{}, netip.MustParsePrefix("3fff:b:0:206::1/128"), segmentPeer)
	m.Routes.Set(netip.Prefix{}, netip.MustParsePrefix("2001:4860:4860::8888/128"), destinationPeer)
	m.startOutboundPipeline()
	t.Cleanup(m.Close)

	dev.reads <- scriptedRead{packets: [][]byte{plainV6(segAddr("3fff:a::17"), segAddr("2001:4860:4860::8888"), "payload")}}
	select {
	case sent := <-viaSegment:
		if got := netip.AddrFrom16([16]byte(sent[24:40])); got != exit {
			t.Errorf("the peer was handed a packet addressed to %s", got)
		}
	case <-viaDestination:
		t.Fatal("a steered packet went to the peer its inner destination selects")
	case <-time.After(5 * time.Second):
		t.Fatal("nothing was sent")
	}
}

// A steered packet whose first segment the mesh cannot reach is gone at the
// route lookup, counted unrouted and no_route, and answered into the tun with destination
// unreachable, no route, from the destination it was read with, as RFC 4443
// section 3.1 has the originating node answer it.
func TestSteeredPacketWithNoRouteIsCounted(t *testing.T) {
	table, err := srv6.NewSteerTable([]srv6.Steer{{
		From: schema.PrefixFrom(segPrefix("3fff:a::17/128")),
		Via:  []schema.Addr{schema.MustAddr("3fff:b:0:206::1")},
	}}, schema.MustAddr("3fff:b:0:100::1"))
	if err != nil {
		t.Fatal(err)
	}
	m, dev := recordingMesh(t)
	m.SetSteering(table)
	read := udpPacket(segAddr("3fff:a::17"), segAddr("2001:db8:c::9"), 100, false)
	_, written := classifyOne(m, dev, read)
	if len(written) != 1 {
		t.Fatalf("a steered packet with nowhere to go put %d packets into the tun, want its answer", len(written))
	}
	checkICMPv6(t, written[0], read, segAddr("2001:db8:c::9"), 1, 0, 0)
	// Unrouted rather than Dropped: this is a packet of this node's own that
	// its steering could not deliver, not one a peer addressed to a segment
	// here, and status reports the two on different lines.
	counters := m.SegmentCounters()
	if counters.Unrouted != 1 || counters.Steered != 1 {
		t.Errorf("the packet was counted unrouted %d and steered %d times, want once each", counters.Unrouted, counters.Steered)
	}
	if counters.Dropped != 0 {
		t.Errorf("this node's own steering was counted against its segment table %d times", counters.Dropped)
	}
	if transit := m.TransitCounters(); transit != (TransitCounters{NoRoute: 1, Answered: 1}) {
		t.Errorf("the read was counted %+v, want no_route and its answer", transit)
	}
}

// unencapsulable is the size of an IPv6 read whose encapsulation behind one segment would carry more than an IPv6 payload length counts, RFC 8200 section 3
const unencapsulable = 0xffff - 8 - 16 + 1

// a read a policy claims and cannot encapsulate is counted unsteered and too_big, and sent nowhere
func TestReadTooLargeToSteerIsCountedTooBig(t *testing.T) {
	table, err := srv6.NewSteerTable([]srv6.Steer{{
		From: schema.PrefixFrom(segPrefix("3fff:a::17/128")),
		Via:  []schema.Addr{schema.MustAddr("3fff:b:0:206::1")},
	}}, schema.MustAddr("3fff:b:0:100::1"))
	if err != nil {
		t.Fatal(err)
	}
	m, dev := recordingMesh(t)
	m.SetSteering(table)
	b, written := classifyOne(m, dev, udpPacket(segAddr("3fff:a::17"), segAddr("2001:db8:c::9"), unencapsulable, false))
	if len(written) != 0 || b.peers[0] != nil {
		t.Errorf("a read too large to steer put %d packets into the tun and went to %v", len(written), b.peers[0])
	}
	if counters, transit := m.SegmentCounters(), m.TransitCounters(); counters.Unsteered != 1 || transit != (TransitCounters{TooBig: 1}) {
		t.Errorf("the read was counted %+v and %+v, want unsteered and too_big", counters, transit)
	}
}

// A stopped steering passes the packet its policy claims, unencapsulated and
// uncounted, so the route table decides where it goes: the node behaves as one
// whose file carries no steer policy at all. The table stays loaded, so a
// diagnostic still reports what was stopped.
func TestStoppedSteeringPassesTheClaimedPacket(t *testing.T) {
	exit := segAddr("3fff:b:0:206::1")
	table, err := srv6.NewSteerTable([]srv6.Steer{{
		From: schema.PrefixFrom(segPrefix("3fff:a::17/128")),
		Via:  []schema.Addr{schema.AddrFrom(exit)},
	}}, schema.MustAddr("3fff:b:0:100::1"))
	if err != nil {
		t.Fatal(err)
	}
	m, dev := recordingMesh(t)
	m.SetSteering(table)
	source, destination := segAddr("3fff:a::17"), segAddr("2001:4860:4860::8888")
	segmentPeer := (&recordingPeer{}).peer(t, "segment")
	destinationPeer := (&recordingPeer{}).peer(t, "destination")
	m.Routes.Set(netip.Prefix{}, netip.PrefixFrom(exit, 128), segmentPeer)
	m.Routes.Set(netip.Prefix{}, netip.PrefixFrom(destination, 128), destinationPeer)
	read := plainV6(source, destination, "payload")

	if b, _ := classifyOne(m, dev, read); b.peers[0] != segmentPeer {
		t.Fatalf("the fixture policy sent the read to %v rather than to its first segment's peer, so this proves nothing", b.peers[0])
	}
	m.SetSteeringEnabled(false)
	if b, _ := classifyOne(m, dev, read); b.peers[0] != destinationPeer {
		t.Errorf("a stopped steering sent the claimed read to %v, want the peer its destination selects", b.peers[0])
	}
	if got := m.SegmentCounters().Steered; got != 1 {
		t.Errorf("%d encapsulations counted, want only the one before the stop", got)
	}
	if m.Steering() == nil {
		t.Error("stopping unloaded the table, so nothing can report which policies were stopped")
	}
	m.SetSteeringEnabled(true)
	if policy, _ := m.steerPolicy(m.Steering(), source, destination, false); policy == nil {
		t.Error("steering started again did not claim the packet")
	}
}

// Each tun reader adds its read's steering counts once the read is classified,
// so readers classifying reads of one mesh at once leave every counter at the
// sum of their reads' own: a read steered along a cap.segment steer entry to a
// routed segment, one to an unrouted segment, one too large to steer, two along
// cap.exit via's path and one no steering claims.
func TestSteeringCountsAddUpAcrossReaders(t *testing.T) {
	const readers, reads = 8, 64
	m, _, _, waypoint := pathMesh(t)
	entryPeer := (&recordingPeer{}).peer(t, "entry's segment")
	m.Routes.Set(netip.Prefix{}, segPrefix("3fff:9::/64"), entryPeer)
	routed, unrouted := segAddr("2001:db8::9"), segAddr("2001:db8::a")
	m.SetSteering(pathSteering(t,
		srv6.Steer{To: schema.PrefixFrom(hostPrefix(routed)), Via: []schema.Addr{schema.MustAddr("3fff:9::1")}},
		srv6.Steer{To: schema.PrefixFrom(hostPrefix(unrouted)), Via: []schema.Addr{schema.MustAddr("3fff:a::1")}},
	))
	packets := [][]byte{
		udpPacket(transitOwn[6], routed, 100, false),
		udpPacket(transitOwn[6], unrouted, 100, false),
		udpPacket(transitOwn[6], routed, unencapsulable, false),
		udpPacket(transitOwn[6], edgeInternet[6], 100, false),
		udpPacket(transitOwn[4], edgeInternet[4], 100, false),
		udpPacket(transitOwn[6], edgeSubnetHost[6], 100, false),
	}
	// a read's counts as the list above has them, two of its steered packets the path's
	perRead := SegmentCounters{Steered: 4, Unsteered: 1, Unrouted: 1}

	b := classifiedBatch(m, packets...)
	unclaimed := b.peers[5]
	if unclaimed == nil || unclaimed == waypoint || unclaimed == entryPeer {
		t.Fatalf("the packet no steering claims went to %v, so this proves nothing", unclaimed)
	}
	if want := []*Peer{entryPeer, nil, nil, waypoint, waypoint, unclaimed}; !slices.Equal(b.peers, want) {
		t.Fatalf("the read went to %v, want %v, so this proves nothing", b.peers, want)
	}
	if got := m.SegmentCounters(); got != perRead {
		t.Fatalf("one read counted %+v, want %+v", got, perRead)
	}

	var wg sync.WaitGroup
	for range readers {
		wg.Go(func() {
			b := newOutboundBatch(len(packets))
			fill(b, packets...)
			for range reads {
				b.n = len(packets)
				m.classify(b)
				b.reset()
			}
		})
	}
	wg.Wait()
	times := uint64(1 + readers*reads)
	want := SegmentCounters{Steered: times * perRead.Steered, Unsteered: times * perRead.Unsteered, Unrouted: times * perRead.Unrouted}
	if got := m.SegmentCounters(); got != want {
		t.Errorf("%d readers of %d reads each counted %+v, want %+v", readers, reads, got, want)
	}
	if got, want := m.PathCounters(), (PathCounters{Steered: times * 2}); got != want {
		t.Errorf("%d readers of %d reads each counted %+v for the path, want %+v", readers, reads, got, want)
	}
}

// sealingPeer records what a peer was handed, so a test can tell which peer a
// packet went to rather than only that it left.
func sealingPeer(t *testing.T, id string, seen chan []byte) *Peer {
	t.Helper()
	peer := NewPeer(id, func(int) (BatchSealer, error) {
		return func(raw [][]byte, _ []byte, out [][]byte) ([][]byte, error) {
			seen <- append([]byte(nil), raw[0]...)
			return out[:0], nil
		}, nil
	}, func([][]byte) error { return nil }, nil)
	t.Cleanup(peer.Close)
	return peer
}

// Each packet of a batch is steered into a side buffer the batch keeps from
// read to read, so a read that steers its packets allocates no more than
// encapsulating them does.
func TestSteeredReadAllocatesNoMoreThanItsEncapsulation(t *testing.T) {
	steering := steerBothFrom(t, 2)
	packets := [][]byte{
		udpPacket(tooBigSource[4], tooBigDestination[4], 1400, false),
		udpPacket(tooBigSource[6], tooBigDestination[6], 1400, false),
	}
	policies := []*srv6.Policy{
		steering.Lookup(tooBigSource[4], tooBigDestination[4]),
		steering.Lookup(tooBigSource[6], tooBigDestination[6]),
	}
	m := &Mesh{Name: "test0", Routes: NewRouteTable(), closed: make(chan struct{})}
	m.startSegmentReports()
	m.SetSteering(steering)
	peer := (&recordingPeer{}).peer(t, "peer")
	peer.SetMTU(0xffff)
	m.Routes.Set(netip.Prefix{}, segPrefix("::/0"), peer)
	m.Routes.Set(netip.Prefix{}, segPrefix("0.0.0.0/0"), peer)
	ownHosts(m, tooBigSource)
	b := newOutboundBatch(len(packets))
	fill(b, packets...)
	read := func() {
		b.n = len(packets)
		m.classify(b)
		b.reset()
	}
	read()
	if got := m.SegmentCounters().Steered; got != uint64(len(packets)) {
		t.Fatalf("%d of the read's %d packets were steered, so this proves nothing", got, len(packets))
	}

	outs := make([][]byte, len(packets))
	encapsulate := func() {
		for i, packet := range packets {
			outs[i], _ = srv6.AppendEncapsulated(outs[i][:0], packet, policies[i].Source, policies[i].Path)
		}
	}
	if got, want := testing.AllocsPerRun(100, read), testing.AllocsPerRun(100, encapsulate); got > want {
		t.Errorf("a read steering %d packets allocated %.0f times, want at most the %.0f of encapsulating them", len(packets), got, want)
	}
}
