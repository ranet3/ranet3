// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"ranet3.com/pkgs/ranet3/esp"
	"ranet3.com/pkgs/ranet3/internal/packet"
	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
)

// classifyShape names the packets of a classify benchmark's read other than plain ones
type classifyShape int

const (
	classifyPlain classifyShape = iota
	// classifySteered is a read a cap.segment steer policy claims, which classify resolves by the destination it was read with and again by its first segment
	classifySteered
	// classifyCarried is a read of IPv6 packets to another node's SID each carrying a packet of the read's family, which classify resolves and checks as well
	classifyCarried
	// classifyPath is a read to the internet that no entry covers in mode 3, which cap.exit via's path takes and classify resolves again by its first segment
	classifyPath
	// classifyPathPassed is classifyPlain's read in mode 3, which the path passes over for the peer's route
	classifyPathPassed
	// classifyDefault is a read to the internet through another exit's learned 0.0.0.0/0 and ::/0 with no steering table, mode 2's
	classifyDefault
	// classifyDefaultPath is classifyDefault's read in mode 3, which cap.exit via's path takes over the learned default, a leaf's common read
	classifyDefaultPath
)

// encapsulated is inner, an IPv4 or IPv6 packet or one cut short, carried in a packet of source's family from source to destination
// whose next header or protocol names inner's version
func encapsulated(source, destination netip.Addr, inner []byte) []byte {
	carried := byte(esp.NextHeaderIPv6)
	if inner[0]>>4 == 4 {
		carried = esp.NextHeaderIPv4
	}
	if source.Is4() {
		out := make([]byte, 20, 20+len(inner))
		out[0] = 0x45
		binary.BigEndian.PutUint16(out[2:], uint16(20+len(inner)))
		out[8], out[9] = 64, carried
		copy(out[12:], source.AsSlice())
		copy(out[16:], destination.AsSlice())
		binary.BigEndian.PutUint16(out[10:], ^uint16(packet.Sum(0, out)))
		return append(out, inner...)
	}
	out := make([]byte, 40, 40+len(inner))
	out[0] = 0x60
	binary.BigEndian.PutUint16(out[4:], uint16(len(inner)))
	out[6], out[7] = carried, 64
	copy(out[8:], source.AsSlice())
	copy(out[24:], destination.AsSlice())
	return append(out, inner...)
}

// classifyArm is a read the classify benchmark times, count packets of family and shape from sources of this node's
// along a cap.exit via path of segments where the shape is mode 3's
type classifyArm struct {
	name                   string
	family, count, sources int
	shape                  classifyShape
	segments               int
}

// classifyArms are the reads the classify benchmark times
// a read of 128 packets is the segments of a GSO frame, and a read of one a UDP flow's, which the tun hands one datagram a read
// a read of one packet from two sources is each one's in turn, read by read
var classifyArms = []classifyArm{
	{"IPv4 from one source", 4, 128, 1, classifyPlain, 0},
	{"IPv4 from 128 sources", 4, 128, 128, classifyPlain, 0},
	{"IPv6 from one source", 6, 128, 1, classifyPlain, 0},
	{"IPv6 from 128 sources", 6, 128, 128, classifyPlain, 0},
	{"IPv6 steered from one source", 6, 128, 1, classifySteered, 0},
	{"IPv6 steered from 128 sources", 6, 128, 128, classifySteered, 0},
	{"IPv6 carried from one source", 6, 128, 1, classifyCarried, 0},
	{"IPv6 carried from 128 sources", 6, 128, 128, classifyCarried, 0},
	{"IPv4 along the exit path from one source", 4, 128, 1, classifyPath, 1},
	{"IPv6 along the exit path from one source", 6, 128, 1, classifyPath, 1},
	{"IPv4 past the exit path from one source", 4, 128, 1, classifyPathPassed, 1},
	{"IPv6 past the exit path from one source", 6, 128, 1, classifyPathPassed, 1},
	{"IPv4 through a learned default from one source", 4, 128, 1, classifyDefault, 0},
	{"IPv6 through a learned default from one source", 6, 128, 1, classifyDefault, 0},
	{"IPv4 along a path of 1 segment over a learned default from one source", 4, 128, 1, classifyDefaultPath, 1},
	{"IPv6 along a path of 1 segment over a learned default from one source", 6, 128, 1, classifyDefaultPath, 1},
	{"IPv4 along a path of 2 segments over a learned default from one source", 4, 128, 1, classifyDefaultPath, 2},
	{"IPv6 along a path of 2 segments over a learned default from one source", 6, 128, 1, classifyDefaultPath, 2},
	{"IPv4 one packet from one source", 4, 1, 1, classifyPlain, 0},
	{"IPv6 one packet from one source", 6, 1, 1, classifyPlain, 0},
	{"IPv4 one packet from two sources in turn", 4, 1, 2, classifyPlain, 0},
}

// oneSteeredRead is a read of one IPv6 packet a cap.segment steer policy claims
var oneSteeredRead = classifyArm{name: "IPv6 steered one packet from one source", family: 6, count: 1, sources: 1, shape: classifySteered}

// classifyPathSIDs are the segments of the benchmark's cap.exit via path, a waypoint whose /64 the peer routes and then an exit, of which a path of n takes the first n
var classifyPathSIDs = []netip.Addr{segAddr("3fff:1::1"), segAddr("3fff:2::46")}

// classifyRead is the read of the classify benchmark, arm's packets to one peer's destination, and the packets it holds
// from one source this node owns or from sources of them, under the overlay of the decision's tests and with a SID of this node's, so each packet meets every check
// a read of fewer packets than sources holds a packet from each, classified once before it is returned
// it fails tb unless every packet of the read passes the checks to the peer, since the benchmark would otherwise time the drops
func classifyRead(tb testing.TB, arm classifyArm) (*Mesh, *outboundBatch, [][]byte) {
	tb.Helper()
	family, count, sources, shape := arm.family, arm.count, arm.sources, arm.shape
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
		steering, err := srv6.NewSteerTable([]srv6.Steer{{From: schema.PrefixFrom(owned), Via: []schema.Addr{schema.MustAddr("3fff:1::1")}}}, schema.MustAddr("3fff:b:0:100::1"))
		if err != nil {
			tb.Fatal(err)
		}
		m.SetSteering(steering)
		m.Routes.Set(netip.Prefix{}, segPrefix("3fff:1::/64"), peer)
	}
	destination := transitFar[family]
	if shape == classifyPath || shape == classifyDefault || shape == classifyDefaultPath {
		destination = transitNowhere[family]
	}
	if shape == classifyDefault || shape == classifyDefaultPath {
		m.Routes.Set(netip.Prefix{}, segPrefix("0.0.0.0/0"), peer)
		m.Routes.Set(netip.Prefix{}, segPrefix("::/0"), peer)
	}
	if arm.segments > 0 {
		steering, err := (*srv6.SteerTable)(nil).WithDefault(segAddr("3fff:b:0:100::1"), classifyPathSIDs[:arm.segments])
		if err != nil {
			tb.Fatal(err)
		}
		m.SetSteering(steering)
		m.Routes.Set(netip.Prefix{}, netip.PrefixFrom(classifyPathSIDs[0], 128), peer)
	}
	otherSID := segAddr("3fff:7::46")
	if shape == classifyCarried {
		m.Routes.Set(netip.Prefix{}, segPrefix("3fff:7::/64"), peer)
	}
	packets := make([][]byte, max(count, sources))
	for i := range packets {
		source := owned.Addr()
		for range i % sources {
			source = source.Next()
		}
		// a read of count packets is the segments of one GSO frame of at most 65535 octets, which the read's slab holds
		// and a read of one packet a datagram of 64 octets of payload
		size := 65535 / count
		if count == 1 {
			size = 20 + 8 + 64
			if family == 6 {
				size = 40 + 8 + 64
			}
		}
		if shape == classifyCarried {
			packets[i] = encapsulated(source, otherSID, udpPacket(source, transitFar[family], size-40, false))
			continue
		}
		packets[i] = udpPacket(source, destination, size, false)
	}
	b := newOutboundBatch(len(packets))
	fill(b, packets...)
	m.classify(b)
	for i := range packets {
		if b.peers[i] != peer {
			tb.Fatalf("IPv%d packet %d of the read of shape %d from %d sources went to %v, not the peer", family, i, shape, sources, b.peers[i])
		}
	}
	if got := m.TransitCounters(); got != (TransitCounters{}) {
		tb.Fatalf("IPv%d the read of shape %d from %d sources counted %+v", family, shape, sources, got)
	}
	steered := m.SegmentCounters().Steered
	want := uint64(0)
	if shape == classifySteered || shape == classifyPath || shape == classifyDefaultPath {
		want = uint64(len(packets))
	}
	if steered != want {
		tb.Fatalf("IPv%d the read of shape %d from %d sources steered %d of its %d packets", family, shape, sources, steered, len(packets))
	}
	b.reset()
	b.n = count
	return m, b, packets
}

// every read the benchmark times passes every check to the peer
func TestClassifyBenchmarkReadPassesEveryCheck(t *testing.T) {
	for _, arm := range classifyArms {
		classifyRead(t, arm)
	}
}

// a read cap.exit via's path steers allocates nothing, along a path of 1 segment or 2, since its header is written from the path as it stands
func TestClassifyAlongThePathAllocatesNothing(t *testing.T) {
	for _, arm := range classifyArms {
		if arm.shape != classifyDefaultPath {
			continue
		}
		m, read, _ := classifyRead(t, arm)
		if allocs := testing.AllocsPerRun(20, func() {
			read.n = arm.count
			m.classify(read)
			read.reset()
		}); allocs != 0 {
			t.Errorf("%s allocated %.1f times a read", arm.name, allocs)
		}
	}
}

// classify over each read of classifyArms, the cost the checks of what enters the mesh add to a tun read
// the same benchmark at the commit before the checks is the arm without them
func BenchmarkClassify(b *testing.B) {
	for _, arm := range classifyArms {
		b.Run(arm.name, func(b *testing.B) {
			m, read, _ := classifyRead(b, arm)
			inTurn := arm.count < arm.sources
			b.ReportAllocs()
			for b.Loop() {
				read.n = arm.count
				m.classify(read)
				read.reset()
				if inTurn {
					read.reads[0], read.reads[1] = read.reads[1], read.reads[0]
				}
			}
		})
	}
}

// classify over the reads of a path of 1 segment over a learned default from one mesh's readers at once, a batch and its kept answers each
// as a tun's queues are read, one reader a CPU, so -cpu sets how many readers share the mesh's counters and pointers
func BenchmarkClassifyParallel(b *testing.B) {
	for _, arm := range classifyArms {
		if arm.shape != classifyDefaultPath || arm.segments != 1 {
			continue
		}
		b.Run(arm.name, func(b *testing.B) {
			m, _, packets := classifyRead(b, arm)
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				read := newOutboundBatch(len(packets))
				fill(read, packets...)
				for pb.Next() {
					read.n = arm.count
					m.classify(read)
					read.reset()
				}
			})
		})
	}
}
