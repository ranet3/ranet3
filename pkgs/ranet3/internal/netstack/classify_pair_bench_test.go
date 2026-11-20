// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"net/netip"
	"testing"

	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
)

// classifyPairArm is a read of count packets laid in runs of run packets of one source and destination
// run k goes from the (k mod sources)th source this node owns to the host of the (k mod peers)th peer
type classifyPairArm struct {
	name               string
	family, count, run int
	peers, sources     int
}

// classifyPairArms are one flow filling the read, two peers alternating every packet, 128 sources to one peer
// runs of 4 packets to two peers in turn, and a read of one packet, in each family
var classifyPairArms = func() []classifyPairArm {
	var arms []classifyPairArm
	for _, family := range []int{4, 6} {
		prefix := "IPv4 "
		if family == 6 {
			prefix = "IPv6 "
		}
		arms = append(arms,
			classifyPairArm{prefix + "one flow", family, 128, 128, 1, 1},
			classifyPairArm{prefix + "two peers alternating every packet", family, 128, 1, 2, 1},
			classifyPairArm{prefix + "128 sources to one peer", family, 128, 1, 1, 128},
			classifyPairArm{prefix + "two peers alternating every 4 packets", family, 128, 4, 2, 1},
			classifyPairArm{prefix + "one packet", family, 1, 1, 1, 1},
		)
	}
	return arms
}()

// classifyPairHosts are the hosts behind the arms' peers by family, one behind each peer
var classifyPairHosts = map[int][]netip.Addr{
	4: {segAddr("192.0.2.3"), segAddr("192.0.2.6")},
	6: {segAddr("3fff::3"), segAddr("3fff::6")},
}

// classifyPairRead is arm's read on a mesh built as classifyRead builds its plain one, with a peer for each host
// it fails tb unless every packet goes to the peer its run names and nothing is counted
func classifyPairRead(tb testing.TB, arm classifyPairArm) (*Mesh, *outboundBatch) {
	tb.Helper()
	m := &Mesh{Name: "test0", Routes: NewRouteTable(), closed: make(chan struct{})}
	m.startSegmentReports()
	m.SetOverlay(transitOverlay)
	segments, err := srv6.NewLocalTable([]srv6.Segment{{SID: schema.AddrFrom(segAddr("3fff:6::1")), Behavior: srv6.BehaviorEndDT46}}, transitOverlay)
	if err != nil {
		tb.Fatal(err)
	}
	m.SetSegments(segments)
	owned := netip.MustParsePrefix("192.0.2.128/25")
	if arm.family == 6 {
		owned = netip.MustParsePrefix("3fff:0:0:1::/64")
	}
	m.Routes.Set(netip.Prefix{}, owned, Local)
	peers := make([]*Peer, arm.peers)
	for p := range peers {
		peers[p] = (&recordingPeer{}).peer(tb, string(rune('a'+p)))
		m.Routes.Set(netip.Prefix{}, hostPrefix(classifyPairHosts[arm.family][p]), peers[p])
	}
	size := 65535 / arm.count
	if arm.count == 1 {
		size = 20 + 8 + 64
		if arm.family == 6 {
			size = 40 + 8 + 64
		}
	}
	packets := make([][]byte, arm.count)
	want := make([]*Peer, arm.count)
	for i := range packets {
		k := i / arm.run
		source := owned.Addr()
		for range k % arm.sources {
			source = source.Next()
		}
		packets[i] = udpPacket(source, classifyPairHosts[arm.family][k%arm.peers], size, false)
		want[i] = peers[k%arm.peers]
	}
	b := newOutboundBatch(len(packets))
	fill(b, packets...)
	m.classify(b)
	for i := range packets {
		if b.peers[i] != want[i] {
			tb.Fatalf("%s: packet %d went to %v, not %v", arm.name, i, b.peers[i], want[i])
		}
	}
	if got := m.TransitCounters(); got != (TransitCounters{}) {
		tb.Fatalf("%s counted %+v", arm.name, got)
	}
	b.reset()
	b.n = arm.count
	return m, b
}

// the first read of each arm of BenchmarkClassifyPairs goes where its runs name, and a read of it allocates nothing
func TestClassifyPairReadsGoWhereTheirRunsName(t *testing.T) {
	for _, arm := range classifyPairArms {
		m, b := classifyPairRead(t, arm)
		allocs := testing.AllocsPerRun(20, func() {
			b.n = arm.count
			m.classify(b)
			b.reset()
		})
		if allocs != 0 {
			t.Errorf("%s allocated %.1f times a read", arm.name, allocs)
		}
	}
}

// classify over each read of classifyPairArms
func BenchmarkClassifyPairs(b *testing.B) {
	for _, arm := range classifyPairArms {
		b.Run(arm.name, func(b *testing.B) {
			m, read := classifyPairRead(b, arm)
			b.ReportAllocs()
			for b.Loop() {
				read.n = arm.count
				m.classify(read)
				read.reset()
			}
		})
	}
}
