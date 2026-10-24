// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"net/netip"
	"testing"

	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
)

// classifyRead is the read of the classify benchmark, count packets of family to one peer's destination
// from one source this node owns or from count of them, under the overlay of the decision's tests and with a SID of this node's, so each packet meets every check
// it fails tb unless every packet of the read passes the checks to the peer, since the benchmark would otherwise time the drops
func classifyRead(tb testing.TB, family, count, sources int) (*Mesh, *outboundBatch) {
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
			tb.Fatalf("IPv%d packet %d of the read from %d sources went to %v, not the peer", family, i, sources, b.peers[i])
		}
	}
	if got := m.TransitCounters(); got != (TransitCounters{}) {
		tb.Fatalf("IPv%d the read from %d sources counted %+v", family, sources, got)
	}
	b.reset()
	b.n = count
	return m, b
}

// the benchmark's reads pass every check to the peer, in each family, from one source and from 128
func TestClassifyBenchmarkReadPassesEveryCheck(t *testing.T) {
	for _, family := range []int{4, 6} {
		for _, sources := range []int{1, 128} {
			classifyRead(t, family, 128, sources)
		}
	}
}

// classify over one read of 128 packets of each family from one source and from 128, the cost the checks of what enters the mesh add to a tun read
// the same benchmark at the commit before the checks is the arm without them
func BenchmarkClassify(b *testing.B) {
	for _, family := range []int{4, 6} {
		for _, sources := range []int{1, 128} {
			b.Run(map[int]string{4: "IPv4", 6: "IPv6"}[family]+map[int]string{1: " from one source", 128: " from 128 sources"}[sources], func(b *testing.B) {
				m, read := classifyRead(b, family, 128, sources)
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
}
