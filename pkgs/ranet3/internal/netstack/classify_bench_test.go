// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"net/netip"
	"testing"

	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
)

// classifyShape names the packets of a classify benchmark's read other than plain ones
type classifyShape int

const (
	classifyPlain classifyShape = iota
	// classifySteered is a read a cap.segment steer policy claims, which classify resolves by the destination it was read with and again by its first segment
	classifySteered
)

// classifyArms are the reads the classify benchmark times, each of 128 packets
var classifyArms = []struct {
	name            string
	family, sources int
	shape           classifyShape
}{
	{"IPv4 from one source", 4, 1, classifyPlain},
	{"IPv4 from 128 sources", 4, 128, classifyPlain},
	{"IPv6 from one source", 6, 1, classifyPlain},
	{"IPv6 from 128 sources", 6, 128, classifyPlain},
	{"IPv6 steered from one source", 6, 1, classifySteered},
	{"IPv6 steered from 128 sources", 6, 128, classifySteered},
}

// classifyRead is the read of the classify benchmark, count packets of family and shape to one peer's destination
// from one source this node owns or from count of them, under the overlay of the decision's tests and with a SID of this node's, so each packet meets every check
// it fails tb unless every packet of the read passes the checks to the peer, since the benchmark would otherwise time the drops
func classifyRead(tb testing.TB, family, count, sources int, shape classifyShape) (*Mesh, *outboundBatch) {
	tb.Helper()
	m := &Mesh{Name: "test0", Routes: NewRouteTable(), closed: make(chan struct{})}
	m.startSegmentReports()
	m.SetOverlay(transitOverlay)
	segments, err := srv6.NewLocalTable([]srv6.Segment{{SID: schema.AddrFrom(segAddr("3fff:6::1")), Behavior: srv6.BehaviorEndDT46}}, transitOverlay)
	if err != nil {
		tb.Fatal(err)
	}
	m.SetSegments(segments)
	peer := (&recordingPeer{}).peer(tb, "peer")
	m.Routes.Set(netip.Prefix{}, hostPrefix(transitFar[family]), peer)
	owned := netip.MustParsePrefix("192.0.2.128/25")
	if family == 6 {
		owned = netip.MustParsePrefix("3fff:0:0:1::/64")
	}
	m.Routes.Set(netip.Prefix{}, owned, Local)
	if shape == classifySteered {
		steering, err := srv6.NewSteerTable([]srv6.Steer{{From: schema.PrefixFrom(owned), Via: []schema.Addr{schema.MustAddr("3fff:1::1")}}}, schema.MustAddr("3fff:1:69c:8c0::1"))
		if err != nil {
			tb.Fatal(err)
		}
		m.SetSteering(steering)
		m.Routes.Set(netip.Prefix{}, segPrefix("3fff:1::/64"), peer)
	}
	packets := make([][]byte, count)
	for i := range packets {
		source := owned.Addr()
		for range i % sources {
			source = source.Next()
		}
		// a read of count packets is the segments of one GSO frame of at most 65535 octets, which the read's slab holds
		packets[i] = udpPacket(source, transitFar[family], 65535/count, false)
	}
	b := newOutboundBatch(count)
	fill(b, packets...)
	m.classify(b)
	for i := range count {
		if b.peers[i] != peer {
			tb.Fatalf("IPv%d packet %d of the read of shape %d from %d sources went to %v, not the peer", family, i, shape, sources, b.peers[i])
		}
	}
	if got := m.TransitCounters(); got != (TransitCounters{}) {
		tb.Fatalf("IPv%d the read of shape %d from %d sources counted %+v", family, shape, sources, got)
	}
	if steered := m.SegmentCounters().Steered; steered != uint64(count) && shape == classifySteered {
		tb.Fatalf("IPv%d the read under a steer policy from %d sources steered %d of its %d packets", family, sources, steered, count)
	}
	b.reset()
	b.n = count
	return m, b
}

// every read the benchmark times passes every check to the peer
func TestClassifyBenchmarkReadPassesEveryCheck(t *testing.T) {
	for _, arm := range classifyArms {
		classifyRead(t, arm.family, 128, arm.sources, arm.shape)
	}
}

// classify over each read of classifyArms, the cost the checks of what enters the mesh add to a tun read
// the same benchmark at the commit before the checks is the arm without them
func BenchmarkClassify(b *testing.B) {
	for _, arm := range classifyArms {
		b.Run(arm.name, func(b *testing.B) {
			m, read := classifyRead(b, arm.family, 128, arm.sources, arm.shape)
			count := read.n
			b.ReportAllocs()
			for b.Loop() {
				read.n = count
				m.classify(read)
				read.reset()
			}
		})
	}
}
