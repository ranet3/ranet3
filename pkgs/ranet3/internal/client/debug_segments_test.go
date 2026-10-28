// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"net/netip"
	"reflect"
	"testing"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
)

// The segments view reads each local segment, an egress one with whether its
// SID is served and the families the mesh egresses, each steering policy with
// its selector, stopped or not, and the counters ranet3 status reports
func TestDebugSegmentsReadsTheSegmentsAndSteeringTheMeshHolds(t *testing.T) {
	c := writable(t)
	table, err := srv6.NewLocalTable([]srv6.Segment{
		{SID: schema.MustAddr("3fff:b:0:200::1"), Behavior: srv6.BehaviorEnd},
		egressSegment("3fff:b:0:200::2", "3fff:a::/32"),
	}, []schema.Prefix{schema.MustPrefix("3fff::/16")})
	if err != nil {
		t.Fatal(err)
	}
	c.Mesh.SetSegments(table)
	c.SetEgressReady(false, true, true)
	got := c.DebugSegments()
	sid := func(s string) netip.Addr { return netip.MustParseAddr(s) }
	want := control.SegmentsInfo{
		Segments: []control.LocalSegment{
			{SID: sid("3fff:b:0:200::1"), Behavior: "End"},
			{SID: sid("3fff:b:0:200::2"), Behavior: "End.DT46", Deliver: "egress", Allow: []netip.Prefix{netip.MustParsePrefix("3fff:a::/32")},
				Egress: &control.SegmentEgress{Served: true, Ready: []string{"ipv6"}}},
		},
		Steering: &control.Steering{Enabled: true, Overhead: srv6.Overhead(1), Policies: []control.SteerPolicy{
			{To: netip.MustParsePrefix("3fff:1::/48"), Source: sid("3fff:b:0:100::1"), Path: []netip.Addr{sid("3fff:b:0:206::1")}, Overhead: srv6.Overhead(1)},
		}},
		Counters: segmentCounters(c.Mesh.SegmentCounters()),
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("the segments view reads\n%+v\nwant\n%+v", got, want)
	}
	c.Mesh.SetSteeringEnabled(false)
	c.SetBorderReady(false)
	if got := c.DebugSegments(); got.Steering.Enabled || got.Segments[1].Egress.Served {
		t.Errorf("stopped steering and a border holding the SIDs read %+v and %+v", got.Steering, got.Segments[1].Egress)
	}
	c.Mesh.SetSegments(nil)
	c.Mesh.SetSteering(nil)
	if got := c.DebugSegments(); got.Segments != nil || got.Steering != nil {
		t.Errorf("a node with no segment and no policy reads %+v", got)
	}
}
