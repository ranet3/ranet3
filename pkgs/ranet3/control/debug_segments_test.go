// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package control

import (
	"net/netip"
	"strings"
	"testing"
)

// segmentsFixtures is one answer of the segments view for each golden file:
// an exit's End and egress segments with two policies steering and no
// cap.exit via, a node with neither, the same policies stopped beside cap.exit
// via's path, and a node whose only path is cap.exit via's
func segmentsFixtures() map[string]SegmentsInfo {
	sid := netip.MustParseAddr
	via := &SteerPolicy{Source: sid("3fff:b:0:100::1"), Path: []netip.Addr{sid("3fff:b:0:406::1")}, Overhead: 64}
	steering := &Steering{Enabled: true, Overhead: 80, Policies: []SteerPolicy{
		{From: netip.MustParsePrefix("192.0.2.1/32"), Source: sid("3fff:b:0:100::1"), Path: []netip.Addr{sid("3fff:b:0:206::1")}, Overhead: 64},
		{From: netip.MustParsePrefix("3fff:a::/48"), To: netip.MustParsePrefix("2001:db8::/32"), Source: sid("3fff:b:0:100::1"),
			Path: []netip.Addr{sid("3fff:b:0:206::1"), sid("3fff:b:0:406::1")}, Overhead: 80},
	}}
	full := SegmentsInfo{
		Segments: []LocalSegment{
			{SID: sid("3fff:b:0:200::1"), Behavior: "End"},
			{SID: sid("3fff:b:0:200::2"), Behavior: "End.DT46", Deliver: "mesh"},
			{SID: sid("3fff:b:0:200::3"), Behavior: "End.DT46", Deliver: "egress", Allow: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("3fff:a::/32")},
				Egress: &SegmentEgress{Served: true, Ready: []string{"ipv4", "ipv6"}}},
		},
		Steering: steering,
		Counters: SegmentCounters{Forwarded: 12, Delivered: 7, Dropped: 2, Steered: 40, Answered: 1, Egressed: 5, Refused: 1},
	}
	stopped := full
	stoppedSteering := *steering
	stoppedSteering.Enabled, stoppedSteering.Via = false, via
	stopped.Steering = &stoppedSteering
	stopped.Segments = []LocalSegment{{SID: sid("3fff:b:0:200::3"), Behavior: "End.DT46", Deliver: "egress", Allow: full.Segments[2].Allow, Egress: &SegmentEgress{}}}
	viaOnly := SegmentsInfo{Steering: &Steering{Enabled: true, Overhead: via.Overhead, Via: via}, Counters: SegmentCounters{Steered: 9}}
	return map[string]SegmentsInfo{"segments": full, "segments-bare": {}, "segments-stopped": stopped, "segments-via": viaOnly}
}

func TestSegmentsRenderAsTheGoldenFiles(t *testing.T) {
	for name, info := range segmentsFixtures() {
		var out strings.Builder
		RenderSegments(&out, info)
		golden(t, name+".txt", []byte(out.String()))
	}
	goldenJSON(t, "segments.json", segmentsFixtures()["segments"])
	goldenJSON(t, "segments-via.json", segmentsFixtures()["segments-via"])
}
