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

// classifyArms are the reads the classify benchmark times, count packets each from sources of this node's
// a read of 128 packets is the segments of a GSO frame, and a read of one a UDP flow's, which the tun hands one datagram a read
// a read of one packet from two sources is each one's in turn, read by read
var classifyArms = []struct {
	name                   string
	family, count, sources int
	shape                  classifyShape
}{
	{"IPv4 from one source", 4, 128, 1, classifyPlain},
	{"IPv4 from 128 sources", 4, 128, 128, classifyPlain},
	{"IPv6 from one source", 6, 128, 1, classifyPlain},
	{"IPv6 from 128 sources", 6, 128, 128, classifyPlain},
	{"IPv6 steered from one source", 6, 128, 1, classifySteered},
	{"IPv6 steered from 128 sources", 6, 128, 128, classifySteered},
	{"IPv6 carried from one source", 6, 128, 1, classifyCarried},
	{"IPv6 carried from 128 sources", 6, 128, 128, classifyCarried},
	{"IPv4 one packet from one source", 4, 1, 1, classifyPlain},
	{"IPv6 one packet from one source", 6, 1, 1, classifyPlain},
	{"IPv4 one packet from two sources in turn", 4, 1, 2, classifyPlain},
}

// classifyRead is the read of the classify benchmark, count packets of family and shape to one peer's destination
// from one source this node owns or from sources of them, under the overlay of the decision's tests and with a SID of this node's, so each packet meets every check
// a read of fewer packets than sources holds a packet from each, classified once before it is returned
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
		steering, err := srv6.NewSteerTable([]srv6.Steer{{From: schema.PrefixFrom(owned), Via: []schema.Addr{schema.MustAddr("3fff:1::1")}}}, schema.MustAddr("3fff:b:0:100::1"))
		if err != nil {
			tb.Fatal(err)
		}
		m.SetSteering(steering)
		m.Routes.Set(netip.Prefix{}, segPrefix("3fff:1::/64"), peer)
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
		packets[i] = udpPacket(source, transitFar[family], size, false)
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
	if steered := m.SegmentCounters().Steered; steered != uint64(len(packets)) && shape == classifySteered {
		tb.Fatalf("IPv%d the read under a steer policy from %d sources steered %d of its %d packets", family, sources, steered, len(packets))
	}
	b.reset()
	b.n = count
	return m, b
}

// every read the benchmark times passes every check to the peer
func TestClassifyBenchmarkReadPassesEveryCheck(t *testing.T) {
	for _, arm := range classifyArms {
		classifyRead(t, arm.family, arm.count, arm.sources, arm.shape)
	}
}

// classify over each read of classifyArms, the cost the checks of what enters the mesh add to a tun read
// the same benchmark at the commit before the checks is the arm without them
func BenchmarkClassify(b *testing.B) {
	for _, arm := range classifyArms {
		b.Run(arm.name, func(b *testing.B) {
			m, read := classifyRead(b, arm.family, arm.count, arm.sources, arm.shape)
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
