// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
)

// refusalMesh is a mesh holding segment of behavior, whose one route, to 3fff:b:0:100::/56, reaches the recorder
func refusalMesh(t *testing.T, segment srv6.Segment) (*Mesh, *recordingPeer) {
	t.Helper()
	table, err := srv6.NewLocalTable([]srv6.Segment{segment}, everySource)
	if err != nil {
		t.Fatal(err)
	}
	recorder := &recordingPeer{}
	m := &Mesh{Routes: NewRouteTable()}
	m.startSegmentReports()
	m.SetSegments(table)
	m.Routes.Set(netip.Prefix{}, segPrefix("3fff:b:0:100::/56"), recorder.peer(t, "sender"))
	return m, recorder
}

// oneAnswer fails unless the recorder took exactly one packet, an ICMPv6 message of kind and code from from to to, and returns it
func oneAnswer(t *testing.T, recorder *recordingPeer, kind, code byte, from, to netip.Addr) []byte {
	t.Helper()
	sent := recorder.packets(t)
	if len(sent) != 1 {
		t.Fatalf("%d packets went back, want one answer", len(sent))
	}
	answer := sent[0]
	if answer[6] != 58 || answer[40] != kind || answer[41] != code {
		t.Fatalf("the answer is next header %d, ICMPv6 type %d code %d, want type %d code %d", answer[6], answer[40], answer[41], kind, code)
	}
	if gotFrom, gotTo := netip.AddrFrom16([16]byte(answer[8:24])), netip.AddrFrom16([16]byte(answer[24:40])); gotFrom != from || gotTo != to {
		t.Errorf("the answer goes from %s to %s, want from %s to %s", gotFrom, gotTo, from, to)
	}
	return answer
}

// RFC 8986 section 4.8 S03: "Send an ICMP Parameter Problem to the Source Address with Code 0 (Erroneous header field encountered) and Pointer set to the Segments Left field"
// and S10's section 4.1.1 S04: "Send an ICMP Parameter Problem to the Source Address with Code 4 (SR Upper-layer Header Error) and Pointer set to the offset of the Upper-Layer header"
// so an End.DT46 of this node answers both from its SID, on either delivery
func TestExitAnswersSegmentsLeftAndAnUpperLayerHeaderItCannotDeliver(t *testing.T) {
	exit, steerer := segAddr("3fff:b:0:206::1"), segAddr("3fff:b:0:100::1")
	inner := plainV6(segAddr("3fff:a::1"), segAddr("3fff:a::2"), "payload")
	midPath, err := srv6.Encapsulate(inner, steerer, []netip.Addr{exit, segAddr("3fff:b:0:506::1")})
	if err != nil {
		t.Fatal(err)
	}
	notIP, err := srv6.Encapsulate(inner, steerer, []netip.Addr{exit})
	if err != nil {
		t.Fatal(err)
	}
	// the fixed header names UDP, so the upper-layer header follows it
	notIP[6] = 17
	for name, segment := range map[string]srv6.Segment{
		"delivering to the mesh": {SID: schema.AddrFrom(exit), Behavior: srv6.BehaviorEndDT46},
		"egress": {SID: schema.AddrFrom(exit), Behavior: srv6.BehaviorEndDT46, Deliver: srv6.DeliverEgress,
			Allow: []schema.Prefix{schema.MustPrefix("3fff:b:0:100::/56"), schema.MustPrefix("3fff:a::/64")}},
	} {
		for _, c := range []struct {
			what    string
			raw     []byte
			code    byte
			pointer uint32
		}{
			{"an exit reached with segments left", midPath, 0, ipv6HeaderOffsetSegmentsLeft},
			{"udp behind the fixed header", notIP, 4, 40},
		} {
			t.Run(name+"/"+c.what, func(t *testing.T) {
				m, recorder := refusalMesh(t, segment)
				m.applySegments(framed(append([]byte(nil), c.raw...)), DefaultMTU, nil, nil)
				answer := oneAnswer(t, recorder, 4, c.code, exit, steerer)
				if pointer := binary.BigEndian.Uint32(answer[44:48]); pointer != c.pointer {
					t.Errorf("the answer points at %d, want %d", pointer, c.pointer)
				}
			})
		}
	}
}

// RFC 8986 section 4.1 S15: "Submit the packet to the egress IPv6 FIB lookup for transmission to the new destination"
// RFC 4443 section 3.1: "If the reason for the failure to deliver is lack of a matching entry in the forwarding node's routing table, the Code field is set to 0"
// so an End whose next segment no route of the mesh carries answers Destination Unreachable, code 0, from its SID
func TestWaypointAnswersANextSegmentNoRouteCarries(t *testing.T) {
	waypoint, steerer, nowhere := segAddr("3fff:b:0:106::2"), segAddr("3fff:b:0:100::1"), segAddr("3fff:c::1")
	m, recorder := refusalMesh(t, srv6.Segment{SID: schema.AddrFrom(waypoint), Behavior: srv6.BehaviorEnd})
	outer, err := srv6.Encapsulate(plainV6(segAddr("3fff:a::1"), segAddr("3fff:a::2"), "payload"), steerer, []netip.Addr{waypoint, nowhere})
	if err != nil {
		t.Fatal(err)
	}
	m.applySegments(framed(outer), DefaultMTU, nil, nil)
	answer := oneAnswer(t, recorder, 1, 0, waypoint, steerer)
	// the answer quotes the packet End rewrote, bound for the segment no route carries
	if quoted := netip.AddrFrom16([16]byte(answer[48+24 : 48+40])); quoted != nowhere {
		t.Errorf("the answer quotes a packet to %s, want the rewritten one to %s", quoted, nowhere)
	}
	if counters := m.SegmentCounters(); counters.Dropped != 1 || counters.Forwarded != 0 {
		t.Errorf("the waypoint counted %+v, want the segment dropped", counters)
	}
}

// RFC 8754 section 4.3.2: "If Segments Left is greater than 0, send an ICMP Parameter Problem, Code 0, message to the Source Address, pointing to the unrecognized Routing Type"
// so an End whose next segment is an address cap.table assigns this node, which is no SID, answers a segment with segments left from its SID
// and drops one at segments left 0 with no answer, as it does one to a prefix this node originates
func TestWaypointAnswersANextSegmentAssignedThisNodeWithSegmentsLeft(t *testing.T) {
	waypoint, steerer, assigned, beyond := segAddr("3fff:b:0:106::2"), segAddr("3fff:b:0:100::1"), segAddr("3fff:b:0:106::9"), segAddr("3fff:b:0:206::1")
	for _, c := range []struct {
		name   string
		value  *Peer
		path   []netip.Addr
		answer bool
	}{
		{"an assigned address with segments left", Assigned, []netip.Addr{waypoint, assigned, beyond}, true},
		{"an assigned address at segments left 0", Assigned, []netip.Addr{waypoint, assigned}, false},
		{"a prefix this node originates with segments left", Local, []netip.Addr{waypoint, assigned, beyond}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			m, recorder := refusalMesh(t, srv6.Segment{SID: schema.AddrFrom(waypoint), Behavior: srv6.BehaviorEnd})
			m.Routes.Set(netip.Prefix{}, hostPrefix(assigned), c.value)
			outer, err := srv6.Encapsulate(plainV6(segAddr("3fff:a::1"), segAddr("3fff:a::2"), "payload"), steerer, c.path)
			if err != nil {
				t.Fatal(err)
			}
			m.applySegments(framed(outer), DefaultMTU, nil, nil)
			if counters := m.SegmentCounters(); counters.Dropped != 1 || counters.Forwarded != 0 {
				t.Errorf("the waypoint counted %+v, want the segment dropped", counters)
			}
			if !c.answer {
				if sent := recorder.packets(t); len(sent) != 0 {
					t.Fatalf("%d packets went back, want none", len(sent))
				}
				return
			}
			answer := oneAnswer(t, recorder, 4, 0, waypoint, steerer)
			if pointer := binary.BigEndian.Uint32(answer[44:48]); pointer != 42 {
				t.Errorf("the answer points at %d, want the Routing Type at 42", pointer)
			}
		})
	}
}
