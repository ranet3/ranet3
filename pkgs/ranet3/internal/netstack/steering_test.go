// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"net/netip"
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
	exit := segAddr("3fff:1:69c:98d6::1")
	table, err := srv6.NewSteerTable([]srv6.Steer{{
		From: schema.PrefixFrom(segPrefix("3fff:a::17/128")),
		Via:  []schema.Addr{schema.AddrFrom(exit)},
	}}, schema.MustAddr("3fff:1:69c:8c0::1"))
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
	m.Routes.Set(netip.Prefix{}, netip.MustParsePrefix("3fff:1:69c:98d6::1/128"), segmentPeer)
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
// route lookup. Without a counter there the steered figure climbs while the
// traffic disappears and nothing anywhere says so. It gets no answer in the
// tun.
func TestSteeredPacketWithNoRouteIsCounted(t *testing.T) {
	table, err := srv6.NewSteerTable([]srv6.Steer{{
		From: schema.PrefixFrom(segPrefix("3fff:a::17/128")),
		Via:  []schema.Addr{schema.MustAddr("3fff:1:69c:98d6::1")},
	}}, schema.MustAddr("3fff:1:69c:8c0::1"))
	if err != nil {
		t.Fatal(err)
	}
	m, dev := recordingMesh(t)
	m.SetSteering(table)
	if _, written := classifyOne(m, dev, plainV6(segAddr("3fff:a::17"), segAddr("2001:db8:c::9"), "payload")); len(written) != 0 {
		t.Errorf("a steered packet with nowhere to go put %d packets into the tun", len(written))
	}
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
}

// sealingPeer records what a peer was handed, so a test can tell which peer a
// A stopped steering passes the packet its policy claims, unencapsulated and
// uncounted, so the route table decides where it goes: the node behaves as one
// whose file carries no steer policy at all. The table stays loaded, so a
// diagnostic still reports what was stopped.
func TestStoppedSteeringPassesTheClaimedPacket(t *testing.T) {
	table, err := srv6.NewSteerTable([]srv6.Steer{{
		From: schema.PrefixFrom(segPrefix("3fff:a::17/128")),
		Via:  []schema.Addr{schema.MustAddr("3fff:1:69c:98d6::1")},
	}}, schema.MustAddr("3fff:1:69c:8c0::1"))
	if err != nil {
		t.Fatal(err)
	}
	m := &Mesh{Routes: NewRouteTable()}
	m.SetSteering(table)
	source, destination := segAddr("3fff:a::17"), segAddr("2001:4860:4860::8888")

	policy := m.steerPolicy(source, destination)
	if policy == nil {
		t.Fatal("the fixture policy did not claim the packet, so this proves nothing")
	}
	if _, ok := m.steer(nil, plainV6(source, destination, "payload"), policy); !ok {
		t.Fatal("the fixture policy could not encapsulate the packet, so this proves nothing")
	}
	m.SetSteeringEnabled(false)
	if policy := m.steerPolicy(source, destination); policy != nil {
		t.Errorf("a stopped steering claimed the packet for %v", policy)
	}
	if got := m.SegmentCounters().Steered; got != 1 {
		t.Errorf("%d encapsulations counted, want only the one before the stop", got)
	}
	if m.Steering() == nil {
		t.Error("stopping unloaded the table, so nothing can report which policies were stopped")
	}
	m.SetSteeringEnabled(true)
	if m.steerPolicy(source, destination) == nil {
		t.Error("steering started again did not claim the packet")
	}
}

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
