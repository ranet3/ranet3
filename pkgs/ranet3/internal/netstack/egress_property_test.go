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
	// kindCounted is a packet the decision takes to an entry of this node's counting as a default, and kindSubnet one to an entry counting as none
	kindCounted
	kindSubnet
	kindCount
)

// segmentPlace is where a frame ends, a destination that receives it or a counter alone
type segmentPlace int

const (
	placeCounter segmentPlace = iota
	placeTUN
	placeExit
	placeForward
)

// decidedSubnets are the entries counting as no default the property draws, a subnet router's LAN of each family
var decidedSubnets = map[int]netip.Prefix{4: segPrefix("198.51.100.0/24"), 6: segPrefix("2001:db8:5::/48")}

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
// headers the waypoint refuses, and packets the decision takes to an entry of this node's counting as a default or to a subnet's counting as none
// over a drawn table, each family's counted entry a default, a pair of halves or four quarters, it and the subnet each advertised by cap.egress or announced by cap.route
// with each family ready or not by the egress segments' word and by the advertised prefixes' word
// every frame ends in exactly one place, the tun as a delivery, the exit, the forward path or a counter alone
// the place is the one its kind names, so the exit takes exactly the egress segments' allowed packets and the decision's counted cap.egress verdicts of a ready family
// and an allowed packet of a family not ready is counted not ready by its own mode's word
// so no packet with a source outside the allow list, of a subnet or of a cap.route announcement reaches the exit, and none of the exit's reaches the tun
// each place takes its frames in batch order, the exit mode 3's in one batch and then mode 2's in another
// an answer quotes only a refused header, never a refused source
// and each counter counts exactly the frames of the kinds it names
func TestEveryFrameOfABatchEndsInOnePlace(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		// the table first, by family: the counted entry's shape and who advertises it and the subnet
		shape := map[int]int{}
		countedByEgress, subnetByEgress := map[int]bool{}, map[int]bool{}
		for _, family := range []int{4, 6} {
			shape[family] = hegel.Draw(ht, pbt.Spanning(0, len(exitShapes)-1))
			countedByEgress[family] = hegel.Draw(ht, hegel.Booleans())
			subnetByEgress[family] = hegel.Draw(ht, hegel.Booleans())
		}
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
			// a delivery goes to one of the node's own destinations, the decision's to its entries, and everything else to one no route covers
			destination := map[int]netip.Addr{4: tooBigDestination[4], 6: segAddr("2001:db8:4860::8888")}[family]
			switch kinds[i] {
			case kindDeliver:
				destination = map[int]netip.Addr{4: egressOwned[4], 6: egressOwned[2]}[family]
			case kindCounted:
				destination = transitNowhere[family]
			case kindSubnet:
				destination = decidedSubnets[family].Addr().Next()
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
			case kindCounted, kindSubnet:
				frames[i] = inner
			}
		}
		ready := map[int]bool{4: hegel.Draw(ht, hegel.Booleans()), 6: hegel.Draw(ht, hegel.Booleans())}
		advertisedReady := map[int]bool{4: hegel.Draw(ht, hegel.Booleans()), 6: hegel.Draw(ht, hegel.Booleans())}

		m, meshTUN := egressMesh(ht)
		exit := &recordingExit{}
		m.SetExit(exit)
		var advertised []netip.Prefix
		for _, family := range []int{4, 6} {
			counted := exitShapes[shape[family]].prefixes[family]
			for _, prefix := range append(slices.Clone(counted), decidedSubnets[family]) {
				m.Routes.Set(netip.Prefix{}, prefix, Local)
			}
			if countedByEgress[family] {
				advertised = append(advertised, counted...)
			}
			if subnetByEgress[family] {
				advertised = append(advertised, decidedSubnets[family])
			}
		}
		m.SetEgressPrefixes(advertised)
		m.SetEgressReady(ready[4], ready[6])
		m.SetAdvertisedReady(advertisedReady[4], advertisedReady[6])
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
		for _, write := range tunWrites(meshTUN) {
			for _, raw := range write {
				receive(placeTUN, raw)
			}
		}
		// each batch the exit took holds one mode's frames in batch order, told by their kind
		var modes []segmentKind
		for _, batch := range exit.taken() {
			last := -1
			for _, raw := range batch {
				i, ok := tagged(raw, len(kinds))
				if !ok {
					ht.Fatalf("the exit took %x, which carries no frame's tag", raw)
				}
				if last >= 0 && (i <= last || kinds[i] != kinds[last]) {
					ht.Fatalf("the exit took frame %d of kind %d after frame %d of kind %d in one batch", i, kinds[i], last, kinds[last])
				}
				reached[i], last = append(reached[i], placeExit), i
			}
			if last >= 0 {
				modes = append(modes, kinds[last])
			}
		}
		for _, raw := range next.packets(ht) {
			receive(placeForward, raw)
		}

		var want SegmentCounters
		var wantDecided TransitCounters
		var wantModes []segmentKind
		for i, kind := range kinds {
			place := placeCounter
			switch kind {
			case kindPass:
				place = placeTUN
				wantDecided.Delivered++
			case kindDeliver:
				place = placeTUN
				want.Delivered++
				wantDecided.Delivered++
			case kindForward:
				place = placeForward
				want.Forwarded++
			case kindEgress:
				if ready[families[i]] {
					place = placeExit
					want.Egressed++
				} else {
					want.NotReady++
				}
			case kindOuterOutside, kindInnerOutside:
				want.Refused++
				want.Dropped++
			case kindRefusedHeader:
				want.Dropped++
			case kindCounted:
				switch {
				case !countedByEgress[families[i]]:
					place = placeTUN
					wantDecided.Delivered++
				case advertisedReady[families[i]]:
					place = placeExit
					wantDecided.Delivered++
				default:
					wantDecided.NotReady++
				}
			case kindSubnet:
				place = placeTUN
				wantDecided.Delivered++
			}
			var wantReached []segmentPlace
			if place != placeCounter {
				wantReached = []segmentPlace{place}
			}
			if !slices.Equal(reached[i], wantReached) {
				ht.Fatalf("frame %d of kind %d and family %d with ready %v and advertised ready %v reached %v, want %v", i, kind, families[i], ready, advertisedReady, reached[i], wantReached)
			}
			if place == placeExit && !slices.Contains(wantModes, kind) {
				wantModes = append(wantModes, kind)
			}
		}
		// kindEgress sorts ahead of kindCounted, as mode 3's batch goes ahead of mode 2's
		slices.Sort(wantModes)
		if !slices.Equal(modes, wantModes) {
			ht.Fatalf("the exit took batches of the kinds %v, want %v, mode 3's ahead of mode 2's", modes, wantModes)
		}
		for place, frames := range order {
			for j := 1; j < len(frames); j++ {
				if frames[j] <= frames[j-1] {
					ht.Fatalf("%v took the frames %v, out of batch order", place, frames)
				}
			}
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
		if got := m.TransitCounters(); got != wantDecided {
			ht.Fatalf("the batch %v of families %v with advertised ready %v had the decision count %+v, want %+v", kinds, families, advertisedReady, got, wantDecided)
		}
	})
}

// egressRefused is the rule an egress segment refuses an inner packet by, at a node holding entries under overlay
// the destination lies inside overlay, or some entry holds it, and source where it is announced from a source prefix, and schema.CapturesTheMachine does not count it as a default
// each entry is another node's, a hold or this node's own, and one counting as a default counts every entry covering it, so the entry the mesh prefers is such an entry exactly where one is
func egressRefused(entries []exactnessEntry, overlay []schema.Prefix, source, destination netip.Addr) bool {
	if slices.ContainsFunc(overlay, func(prefix schema.Prefix) bool { return prefix.Contains(destination) }) {
		return true
	}
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
	// refusalOverlay is the overlay's entries the property draws from, the sources' and one under each family's longer documentation prefixes
	refusalOverlay = append(slices.Clone(transitOverlay), schema.PrefixFrom(segPrefix("203.0.113.128/25")), schema.PrefixFrom(segPrefix("2001:db8:8000::/33")))
)

// over a drawn overlay, a drawn table of entries counting as a default and not, another node's, holds, this node's own and addresses cap.table assigns it, some announced from a source the batch sends from
// and a drawn batch of inner packets to an egress segment from sources the mesh routes a reply to, more pairs than a batch keeps answers for among them
// an inner packet reaches the tun exactly where its destination lies outside the overlay and its pair does not resolve, ignoring the entries counting as a default, to another node, a hold or this node, as egressRefused says
// in batch order in one write, and every one refused is counted refused and dropped
func TestEgressSegmentEgressesNothingTheMeshRoutes(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		m, meshTUN := egressMesh(ht)
		overlay := pbt.Subset(ht, refusalOverlay, 0, len(refusalOverlay))
		m.SetOverlay(overlay)
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
			if egressRefused(entries, overlay, source, destination) {
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
