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
// and headers the waypoint refuses, with an egress device installed or none, and each family ready to egress or not
// every frame ends in exactly one place, the mesh tun, the egress device, the forward path or a counter alone
// the place is the one its kind names, and an allowed egress packet with no device or of a family not ready is counted not ready
// so no packet with a source outside the allow list reaches the egress device or the mesh tun
// each destination takes its frames in batch order, the egress device in at most one write
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
			inner := plainV6(source, segAddr("2001:4860:4860::8888"), string(frameTag(i)))
			if family == 4 {
				inner = udpPacket(source, tooBigDestination[4], 20+8+len(frameTag(i)), false)
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
		present := hegel.Draw(ht, hegel.Booleans())
		ready := map[int]bool{4: hegel.Draw(ht, hegel.Booleans()), 6: hegel.Draw(ht, hegel.Booleans())}

		m, meshTUN := egressMesh(ht)
		m.SetEgressReady(ready[4], ready[6])
		next, back := &recordingPeer{}, &recordingPeer{}
		m.Routes.Set(netip.Prefix{}, netip.PrefixFrom(egressNext, 128), next.peer(ht, "next"))
		answers := back.peer(ht, "back")
		m.Routes.Set(netip.Prefix{}, netip.PrefixFrom(headend, 128), answers)
		m.Routes.Set(netip.Prefix{}, netip.PrefixFrom(stranger[6], 128), answers)
		dev := newFakeEgress()
		if present {
			m.SetEgress(dev)
		}
		m.DeliverInboundBatch(framed(frames...), DefaultMTU)

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
		writes := dev.accepted()
		for _, write := range writes {
			for _, raw := range write {
				receive(placeEgress, raw)
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
				if present && ready[families[i]] {
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
				ht.Fatalf("frame %d of kind %d and family %d with the device present %v and ready %v reached %v, want %v", i, kind, families[i], present, ready, reached[i], wantReached)
			}
		}
		for place, frames := range order {
			for j := 1; j < len(frames); j++ {
				if frames[j] <= frames[j-1] {
					ht.Fatalf("%v took the frames %v, out of batch order", place, frames)
				}
			}
		}
		if len(writes) > 1 {
			ht.Fatalf("the egress device took %d writes from one batch", len(writes))
		}
		sent := back.packets(ht)
		for _, answer := range sent {
			if i, ok := tagged(answer, len(kinds)); !ok || kinds[i] != kindRefusedHeader {
				ht.Fatalf("an answer went back about frame %d of kind %d, want only refused headers answered", i, kinds[i])
			}
		}
		want.Answered = uint64(len(sent))
		if got := m.SegmentCounters(); got != want {
			ht.Fatalf("the batch %v of families %v with the device present %v and ready %v counted %+v, want %+v", kinds, families, present, ready, got, want)
		}
	})
}
