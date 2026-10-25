// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package netstack

import (
	"bytes"
	"fmt"
	"net/netip"
	"slices"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/schema"
)

// segmentKind names a frame of a drawn batch, and so where the model sends it
type segmentKind int

const (
	kindPass segmentKind = iota
	kindDeliver
	kindForward
	kindEgress
	kindOuterOutside
	kindInnerOutside
	kindRefusedHeader
	kindCount
)

// segmentPlace is where a frame ends, a destination that receives it or a counter alone
type segmentPlace int

const (
	placeCounter segmentPlace = iota
	placeTUN
	placeEgress
	placeForward
)

// frameTag marks the payload of frame i, which every place a frame can reach carries whole
func frameTag(i int) []byte { return fmt.Appendf(nil, "frame%02d", i) }

func tagged(raw []byte, frames int) (int, bool) {
	for i := range frames {
		if bytes.Contains(raw, frameTag(i)) {
			return i, true
		}
	}
	return 0, false
}

// a drawn batch mixes passed packets, packets for an End.DT46 to the mesh, a waypoint and an egress segment
// egress packets with both sources in the allow list, with the outer or the inner one outside it, of either inner family
// and headers the waypoint refuses, with each family ready to egress or not
// every frame ends in exactly one place, the tun as a delivery, the tun as an egress result, the forward path or a counter alone
// the place is the one its kind names, and an allowed egress packet of a family not ready is counted not ready
// so no packet with a source outside the allow list reaches the tun
// each place takes its frames in batch order, the egress results in one write of their own ahead of the deliveries
// an answer quotes only a refused header, never a refused source
// and each counter counts exactly the frames of the kinds it names
func TestEveryFrameOfABatchEndsInOnePlace(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		kinds := make([]segmentKind, hegel.Draw(ht, pbt.Spanning(1, 10)))
		frames := make([][]byte, len(kinds))
		families := make([]int, len(kinds))
		for i := range kinds {
			kinds[i] = segmentKind(hegel.Draw(ht, pbt.Spanning(0, int(kindCount)-1)))
			family := 6
			if hegel.Draw(ht, hegel.Booleans()) {
				family = 4
			}
			families[i] = family
			source := map[int]netip.Addr{4: segAddr("10.1.0.1"), 6: segAddr("3fff:a::1")}[family]
			if kinds[i] == kindInnerOutside {
				source = stranger[family]
			}
			// a delivery goes to one of the node's own destinations, and everything else to one no route covers
			destination := map[int]netip.Addr{4: tooBigDestination[4], 6: segAddr("2001:db8:4860::8888")}[family]
			if kinds[i] == kindDeliver {
				destination = map[int]netip.Addr{4: egressOwned[4], 6: egressOwned[2]}[family]
			}
			inner := plainV6(source, destination, string(frameTag(i)))
			if family == 4 {
				inner = udpPacket(source, destination, 20+8+len(frameTag(i)), false)
				copy(inner[20+8:], frameTag(i))
			}
			switch kinds[i] {
			case kindPass:
				frames[i] = plainV6(segAddr("2001:db8::1"), segAddr("2001:db8::a"), string(frameTag(i)))
			case kindDeliver:
				frames[i] = steered(ht, inner, headend, meshExit)
			case kindForward:
				frames[i] = steered(ht, inner, headend, egressWaypoint, egressNext)
			case kindEgress, kindInnerOutside:
				frames[i] = steered(ht, inner, headend, egressExit)
			case kindOuterOutside:
				frames[i] = steered(ht, inner, stranger[6], egressExit)
			case kindRefusedHeader:
				frames[i] = plainV6(headend, egressWaypoint, string(frameTag(i)))
			}
		}
		ready := map[int]bool{4: hegel.Draw(ht, hegel.Booleans()), 6: hegel.Draw(ht, hegel.Booleans())}

		m, meshTUN := egressMesh(ht)
		m.SetEgressReady(ready[4], ready[6])
		next, back := &recordingPeer{}, &recordingPeer{}
		m.Routes.Set(netip.Prefix{}, netip.PrefixFrom(egressNext, 128), next.peer(ht, "next"))
		answers := back.peer(ht, "back")
		m.Routes.Set(netip.Prefix{}, netip.PrefixFrom(headend, 128), answers)
		m.Routes.Set(netip.Prefix{}, netip.PrefixFrom(stranger[6], 128), answers)
		m.DeliverInboundBatch(framed(frames...), DefaultMTU, nil)

		reached := make([][]segmentPlace, len(kinds))
		order := map[segmentPlace][]int{}
		receive := func(place segmentPlace, raw []byte) {
			i, ok := tagged(raw, len(kinds))
			if !ok {
				ht.Fatalf("%v took %x, which carries no frame's tag", place, raw)
			}
			reached[i] = append(reached[i], place)
			order[place] = append(order[place], i)
		}
		// a write is the egress results' where it carries one, which the frame's kind tells, and the first such write must be the tun's first
		var egressWrites []int
		for w, write := range tunWrites(meshTUN) {
			place := placeTUN
			if i, ok := tagged(write[0], len(kinds)); ok && kinds[i] == kindEgress {
				place = placeEgress
				egressWrites = append(egressWrites, w)
			}
			for _, raw := range write {
				receive(place, raw)
			}
		}
		for _, raw := range next.packets(ht) {
			receive(placeForward, raw)
		}

		var want SegmentCounters
		for i, kind := range kinds {
			place := placeCounter
			switch kind {
			case kindPass:
				place = placeTUN
			case kindDeliver:
				place = placeTUN
				want.Delivered++
			case kindForward:
				place = placeForward
				want.Forwarded++
			case kindEgress:
				if ready[families[i]] {
					place = placeEgress
					want.Egressed++
				} else {
					want.NotReady++
				}
			case kindOuterOutside, kindInnerOutside:
				want.Refused++
				want.Dropped++
			case kindRefusedHeader:
				want.Dropped++
			}
			var wantReached []segmentPlace
			if place != placeCounter {
				wantReached = []segmentPlace{place}
			}
			if !slices.Equal(reached[i], wantReached) {
				ht.Fatalf("frame %d of kind %d and family %d with ready %v reached %v, want %v", i, kind, families[i], ready, reached[i], wantReached)
			}
		}
		for place, frames := range order {
			for j := 1; j < len(frames); j++ {
				if frames[j] <= frames[j-1] {
					ht.Fatalf("%v took the frames %v, out of batch order", place, frames)
				}
			}
		}
		if len(egressWrites) > 1 || len(egressWrites) == 1 && egressWrites[0] != 0 {
			ht.Fatalf("the egress results reached the tun as its writes %v, want one write ahead of the deliveries", egressWrites)
		}
		sent := back.packets(ht)
		for _, answer := range sent {
			if i, ok := tagged(answer, len(kinds)); !ok || kinds[i] != kindRefusedHeader {
				ht.Fatalf("an answer went back about frame %d of kind %d, want only refused headers answered", i, kinds[i])
			}
		}
		want.Answered = uint64(len(sent))
		if got := m.SegmentCounters(); got != want {
			ht.Fatalf("the batch %v of families %v with ready %v counted %+v, want %+v", kinds, families, ready, got, want)
		}
	})
}

// egressRefused is the rule an egress segment refuses an inner packet by, at a node holding entries under overlay
// some entry holds destination, and source where it is announced from a source prefix, and schema.CapturesTheMachine does not count it as a default
// each entry is another node's, a hold or this node's own, and one counting as a default counts every entry covering it, so the entry the mesh prefers is such an entry exactly where one is
func egressRefused(entries []exactnessEntry, overlay []schema.Prefix, source, destination netip.Addr) bool {
	return slices.ContainsFunc(entries, func(entry exactnessEntry) bool {
		return entry.prefix.Contains(destination) && (!entry.from.IsValid() || entry.from.Contains(source)) && !schema.CapturesTheMachine(entry.prefix, overlay)
	})
}

// the prefixes and the destinations the refusal property draws, by family
// short prefixes the overlay does not hold and longer ones of both documentation blocks, and destinations under each and under the short ones alone
var (
	refusalPrefixes = map[int][]netip.Prefix{
		4: {segPrefix("0.0.0.0/0"), segPrefix("0.0.0.0/1"), segPrefix("128.0.0.0/1"), segPrefix("192.0.0.0/3"),
			segPrefix("203.0.113.0/24"), segPrefix("203.0.113.0/25"), segPrefix("203.0.113.128/25"), segPrefix("203.0.113.5/32"), segPrefix("192.0.2.0/24")},
		6: {segPrefix("::/0"), segPrefix("::/1"), segPrefix("8000::/1"), segPrefix("2000::/3"),
			segPrefix("2001:db8::/48"), segPrefix("2001:db8:8000::/33"), segPrefix("2001:db8::5/128"), segPrefix("3fff::/20")},
	}
	refusalDestinations = map[int][]netip.Addr{
		4: {segAddr("203.0.113.5"), segAddr("203.0.113.100"), segAddr("203.0.113.200"), segAddr("198.51.100.7"), segAddr("192.0.2.9")},
		6: {segAddr("2001:db8::5"), segAddr("2001:db8::9"), segAddr("2001:db8:8000::5"), segAddr("2001:db8:4000::5"), segAddr("3fff:b::9")},
	}
	refusalSources = map[int][]netip.Addr{4: {segAddr("192.0.2.65"), segAddr("192.0.2.67")}, 6: {segAddr("3fff:a::5"), segAddr("3fff:a::6")}}
)

// over a drawn table of entries counting as a default and not, another node's, holds, this node's own and addresses cap.table assigns it, some announced from a source the batch sends from
// and a drawn batch of inner packets to an egress segment from sources the mesh routes a reply to, more pairs than a batch keeps answers for among them
// an inner packet reaches the tun exactly where its pair does not resolve, ignoring the entries counting as a default, to another node, a hold or this node, as egressRefused says
// in batch order in one write, and every one refused is counted refused and dropped
func TestEgressSegmentEgressesNothingTheMeshRoutes(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		m, meshTUN := egressMesh(ht)
		m.SetOverlay(transitOverlay)
		other := (&recordingPeer{}).peer(ht, "other")
		values := map[Verdict]*Peer{RoutePeer: other, RouteHeld: Unreachable, RouteLocal: Local}
		var entries []exactnessEntry
		for _, own := range egressOwned {
			entries = append(entries, exactnessEntry{prefix: hostPrefix(own), verdict: RouteLocal})
		}
		for _, family := range []int{4, 6} {
			routeLeaf(ht, m, refusalSources[family]...)
			entries = append(entries, exactnessEntry{prefix: hostPrefix(tooBigSource[family]), verdict: RoutePeer})
			for _, source := range refusalSources[family] {
				entries = append(entries, exactnessEntry{prefix: hostPrefix(source), verdict: RoutePeer})
			}
			for _, prefix := range refusalPrefixes[family] {
				if !hegel.Draw(ht, hegel.Booleans()) {
					continue
				}
				verdict := hegel.Draw(ht, hegel.SampledFrom([]Verdict{RoutePeer, RouteHeld, RouteLocal}))
				value := values[verdict]
				// cap.table's addresses are this node's own as Local is, under a sentinel of their own
				if verdict == RouteLocal && hegel.Draw(ht, hegel.Booleans()) {
					value = Assigned
				}
				m.Routes.Set(netip.Prefix{}, prefix, value)
				entries = append(entries, exactnessEntry{prefix: prefix, verdict: verdict})
			}
			// a route announced from a source prefix holds only that source's packets, so the answer for one pair is not another's
			for _, prefix := range refusalPrefixes[family] {
				if !hegel.Draw(ht, hegel.Booleans()) {
					continue
				}
				from := hostPrefix(hegel.Draw(ht, hegel.SampledFrom(refusalSources[family])))
				verdict := hegel.Draw(ht, hegel.SampledFrom([]Verdict{RoutePeer, RouteHeld, RouteLocal}))
				m.Routes.Set(from, prefix, values[verdict])
				entries = append(entries, exactnessEntry{prefix: prefix, from: from, verdict: verdict})
			}
		}

		var frames, want [][]byte
		var refused uint64
		for i := range hegel.Draw(ht, pbt.Spanning(1, 3*egressPairs)) {
			family := 6
			if hegel.Draw(ht, hegel.Booleans()) {
				family = 4
			}
			source := hegel.Draw(ht, hegel.SampledFrom(refusalSources[family]))
			destination := hegel.Draw(ht, hegel.SampledFrom(refusalDestinations[family]))
			inner := plainV6(source, destination, string(frameTag(i)))
			if family == 4 {
				inner = udpPacket(source, destination, 20+8+len(frameTag(i)), false)
				copy(inner[20+8:], frameTag(i))
			}
			frames = append(frames, steered(ht, inner, headend, egressExit))
			if egressRefused(entries, transitOverlay, source, destination) {
				refused++
				continue
			}
			want = append(want, inner)
		}
		m.DeliverInboundBatch(framed(frames...), DefaultMTU, nil)

		var got [][]byte
		writes := tunWrites(meshTUN)
		if len(writes) > 1 {
			ht.Fatalf("the egress results reached the tun in %d writes, want one", len(writes))
		}
		if len(writes) == 1 {
			got = writes[0]
		}
		if !slices.EqualFunc(got, want, bytes.Equal) {
			ht.Fatalf("over the table %v the tun took %d packets, want the %d whose destinations the mesh does not route, in order", entries, len(got), len(want))
		}
		if counters := m.SegmentCounters(); counters != (SegmentCounters{Egressed: uint64(len(want)), Refused: refused, Dropped: refused}) {
			ht.Fatalf("over the table %v %d refused and %d egressed counted %+v", entries, refused, len(want), counters)
		}
	})
}
