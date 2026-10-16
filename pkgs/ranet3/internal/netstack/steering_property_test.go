// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package netstack

import (
	"bytes"
	"net/netip"
	"slices"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/srv6"
)

// readSpacing is the bytes a slab read leaves before, between and after the packets it holds
// readMTU is the largest packet the reads below carry
const (
	readSpacing = 64
	readMTU     = 9000
)

// a read laid out as a slab holds it, readSpacing bytes between packets, leaves the classifier with every byte as it was read
// and each packet a policy claims leaves as the policy's outer header, from its source through its segments, in front of the packet as it was read
// one packet no policy claims leaves as it was read
// the segment counts either side of where the header passes readSpacing, one and two, are drawn outright
func TestSteeringLeavesTheReadAsItWasRead(t *testing.T) {
	unclaimed := map[int]netip.Addr{4: segAddr("10.1.0.2"), 6: segAddr("3fff:a::2")}
	pbt.Check(t, func(ht *hegel.T) {
		segments := hegel.Draw(ht, hegel.OneOf(hegel.SampledFrom([]int{1, 2}), pbt.Spanning(1, srv6.MaxSegments)))
		steering := steerBothFrom(ht, segments)
		m := &Mesh{Name: "test0", Routes: NewRouteTable(), closed: make(chan struct{})}
		m.startSegmentReports()
		m.SetSteering(steering)
		peer := (&recordingPeer{}).peer(ht, "peer")
		peer.SetMTU(0xffff)
		m.Routes.Set(netip.Prefix{}, segPrefix("::/0"), peer)
		m.Routes.Set(netip.Prefix{}, segPrefix("0.0.0.0/0"), peer)

		count := hegel.Draw(ht, pbt.Spanning(1, 8))
		packets, policies := make([][]byte, count), make([]*srv6.Policy, count)
		for i := range packets {
			family, least := 4, 20+8
			if hegel.Draw(ht, hegel.Booleans()) {
				family, least = 6, 40+8
			}
			source := unclaimed[family]
			if hegel.Draw(ht, hegel.WeightedBooleans(3.0/4)) {
				source = tooBigSource[family]
				policies[i] = steering.Lookup(source, tooBigDestination[family])
			}
			packets[i] = udpPacket(source, tooBigDestination[family], hegel.Draw(ht, pbt.Spanning(least, readMTU)), false)
		}
		b, slab := slabRead(m, packets)
		read := bytes.Clone(slab)

		m.classify(b)

		if !bytes.Equal(slab, read) {
			ht.Fatalf("steering %d packets through %d segments wrote into the read", count, segments)
		}
		overhead, steered := srv6.Overhead(segments), 0
		for i, packet := range packets {
			sent, policy := b.packets[i], policies[i]
			if b.peers[i] != peer {
				ht.Fatalf("packet %d of %d bytes did not go to its peer", i, len(packet))
			}
			if policy == nil {
				if !bytes.Equal(sent, packet) {
					ht.Fatalf("packet %d, claimed by no policy, left as %d bytes that are not the %d it was read as", i, len(sent), len(packet))
				}
				continue
			}
			steered++
			header, err := srv6.Parse(sent)
			if err != nil {
				ht.Fatalf("steered packet %d carries no routing header: %v", i, err)
			}
			if source := netip.AddrFrom16([16]byte(sent[8:24])); source != policy.Source || !slices.Equal(header.Path(), policy.Path) {
				ht.Fatalf("steered packet %d leaves from %s through %v, want %s through %v", i, source, header.Path(), policy.Source, policy.Path)
			}
			if len(sent) != overhead+len(packet) || !bytes.Equal(sent[overhead:], packet) {
				ht.Fatalf("steered packet %d carries %d bytes behind its %d byte header that are not the %d it was read as", i, len(sent)-overhead, overhead, len(packet))
			}
		}
		if got := m.SegmentCounters().Steered; got != uint64(steered) {
			ht.Fatalf("%d packets steered were counted as %d", steered, got)
		}
	})
}

// slabRead is a read of packets as a slab holds them, readSpacing bytes before, between and after them, and the slab
// each packet's read buffer runs on to the end of the slab, so a write past a packet lands in the spacing or the next packet
// the slab starts filled with one byte, so a write into the spacing shows
func slabRead(m *Mesh, packets [][]byte) (*outboundBatch, []byte) {
	size := readSpacing
	for _, packet := range packets {
		size += len(packet) + readSpacing
	}
	slab := bytes.Repeat([]byte{0xa5}, size)
	b := m.newOutboundBatch(len(packets))
	offset := readSpacing
	for i, packet := range packets {
		b.bufs[i] = slab[offset-tunOffset:]
		b.sizes[i] = copy(slab[offset:], packet)
		offset += len(packet) + readSpacing
	}
	b.n = len(packets)
	return b, slab
}
