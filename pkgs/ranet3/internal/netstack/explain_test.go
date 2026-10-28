// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"bytes"
	"net/netip"
	"testing"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
)

// explainCase is one arm of the decision or of the checks, the mesh it runs on, a packet that takes it and what the walk says of it
type explainCase struct {
	name string
	mesh func(t *testing.T) *Mesh
	raw  []byte
	want Explanation
}

// explainNode is a tracedNode, its own default advertised, IPv4 ready and IPv6 not
func explainNode(t *testing.T) *Mesh { n, _ := tracedNode(t); return n.m }

// explainPlain is a transit node with no default
func explainPlain(t *testing.T) *Mesh { return newTransitNode(t, tracedMTU).m }

// explainOff is explainNode with cap.transit off
func explainOff(t *testing.T) *Mesh {
	m := explainNode(t)
	m.SetTransit(false)
	return m
}

// explainLeaf is a tracedLeaf, under an exit's default
func explainLeaf(t *testing.T) *Mesh { m, _ := tracedLeaf(t); return m }

// explainBare is an edgeMesh, with no default
func explainBare(t *testing.T) *Mesh { m, _ := edgeMesh(t); return m }

// explainSegment is the one segment the walk's steered cases are steered through
var explainSegment = segAddr("3fff:1::1")

// steerOwn has m steer what this node's own IPv6 address sends through explainSegment
func steerOwn(t *testing.T, m *Mesh) *Mesh {
	t.Helper()
	steering, err := srv6.NewSteerTable([]srv6.Steer{{From: schema.PrefixFrom(hostPrefix(transitOwn[6])), Via: []schema.Addr{schema.AddrFrom(explainSegment)}}}, schema.MustAddr("3fff:b:0:100::1"))
	if err != nil {
		t.Fatal(err)
	}
	m.SetSteering(steering)
	return m
}

// explainSteered is explainLeaf steering its own IPv6 address through explainSegment, which it routes to a peer other than the destination's
func explainSteered(t *testing.T) *Mesh {
	m := explainLeaf(t)
	segment := (&recordingPeer{}).peer(t, "segment")
	segment.SetMTU(tracedMTU)
	m.Routes.Set(netip.Prefix{}, segPrefix("3fff:1::/64"), segment)
	return steerOwn(t, m)
}

// explainStranded is explainBare steering the same with no route to explainSegment
func explainStranded(t *testing.T) *Mesh { return steerOwn(t, explainBare(t)) }

func explainedDrop(reason string, match Match) Explanation {
	return Explanation{Decision: TraceDrop, Reason: reason, Match: match}
}

func explainedAnswer(reason, answer string, match Match) Explanation {
	return Explanation{Decision: TraceAnswer, Reason: reason, Answer: answer, Match: match}
}

func heldTo(e Explanation, next string, mtu int) Explanation {
	e.Next, e.MTU = next, mtu
	return e
}

// sessionCases are the arms of decide, in its order
var sessionCases = func() []explainCase {
	far, own := Match{Bits: 32}, Match{Bits: 32}
	far6 := Match{Bits: 128}
	exit := Match{Counted: true, Egress: true}
	looseRoute := []byte{131, 7, 4, 192, 0, 2, 3, 0}
	badChecksum := udpPacket(transitSender[4], transitFar[4], 100, false)
	badChecksum[10] ^= 0xff
	return []explainCase{
		{"not one IP packet", explainNode, udpPacket(transitSender[4], transitFar[4], 100, false)[:60], explainedDrop("invalid", Match{})},
		{"link scope", explainNode, udpPacket(transitSender[6], segAddr("ff02::1"), 100, false), Explanation{Decision: TraceDeliver}},
		{"a martian destination", explainNode, udpPacket(transitSender[4], segAddr("127.0.0.1"), 100, false), explainedDrop("martian", Match{})},
		{"a martian source", explainNode, udpPacket(segAddr("::1"), transitFar[6], 100, false), explainedDrop("martian", Match{})},
		{"an IPv4 link-local source", explainNode, udpPacket(segAddr("169.254.0.9"), transitFar[4], 100, false), explainedDrop("martian", Match{})},
		{"an IPv6 link-local source", explainNode, udpPacket(segAddr("fe80::9"), transitFar[6], 100, false), explainedAnswer("martian", "beyond_scope", Match{})},
		{"an IPv4 header failing its checksum", explainNode, badChecksum, explainedDrop("invalid", far)},
		{"this node's own", explainNode, udpPacket(transitSender[4], transitOwn[4], 100, false), Explanation{Decision: TraceDeliver, Match: own}},
		{"an egress", explainNode, udpPacket(transitSender[4], transitNowhere[4], 100, false), Explanation{Decision: TraceEgress, Match: exit}},
		{"a family not ready", explainNode, udpPacket(transitSender[6], transitNowhere[6], 100, false), explainedDrop("not_ready", exit)},
		{"an unrouted source", explainNode, udpPacket(transitStranger[4], transitNowhere[4], 100, false), explainedDrop("unrouted_source", exit)},
		{"an overlay address no node announces", explainNode, udpPacket(transitSender[4], transitUnrouted[4], 100, false), explainedAnswer("no_route", "host_unreachable", exit)},
		{"no route", explainPlain, udpPacket(transitSender[6], transitUnrouted[6], 100, false), explainedAnswer("no_route", "no_route", Match{})},
		{"a hold", explainNode, udpPacket(transitSender[4], transitHeldHost[4], 100, false), explainedAnswer("held", "host_unreachable", Match{Bits: 32})},
		{"transit off", explainOff, udpPacket(transitSender[6], transitFar[6], 100, false), explainedAnswer("refused", "prohibited", far6)},
		{"an expired packet", explainNode, withTTL(udpPacket(transitSender[4], transitFar[4], 100, false), 1), explainedAnswer("expired", "expired", far)},
		{"a source route", explainNode, withOptions(udpPacket(transitSender[4], transitFar[4], 100, false), looseRoute), explainedDrop("source_route", far)},
		{"options that do not read", explainNode, withOptions(udpPacket(transitSender[4], transitFar[4], 100, false), []byte{7, 9, 4, 0}), explainedAnswer("invalid", "parameter", far)},
		{"a forward", explainNode, withTTL(udpPacket(transitSender[6], transitFar[6], 100, false), 2), heldTo(Explanation{Decision: TraceForward, Match: far6}, "out", tracedMTU)},
		{"a forward with Record Route", explainNode, withOptions(udpPacket(transitSender[4], transitFar[4], 100, false), []byte{7, 7, 4, 0, 0, 0, 0, 0}), heldTo(Explanation{Decision: TraceForward, Match: far}, "out", tracedMTU)},
		{"a forward cut into fragments", explainNode, udpPacket(transitSender[4], transitFar[4], tracedMTU+100, false), heldTo(Explanation{Decision: TraceForward, Match: far}, "out", tracedMTU)},
		{"IPv4 too big with DF", explainNode, udpPacket(transitSender[4], transitFar[4], tracedMTU+1, true), heldTo(explainedAnswer("too_big", "too_big", far), "out", tracedMTU)},
		{"IPv6 too big", explainNode, udpPacket(transitSender[6], transitFar[6], tracedMTU+1, false), heldTo(explainedAnswer("too_big", "too_big", far6), "out", tracedMTU)},
		{"IPv6 at the session's MTU", explainNode, udpPacket(transitSender[6], transitFar[6], tracedMTU, false), heldTo(Explanation{Decision: TraceForward, Match: far6}, "out", tracedMTU)},
	}
}()

// readCases are the arms of classify, in its order
var readCases = func() []explainCase {
	far4, far6 := Match{Bits: 32}, Match{Bits: 128}
	exit := Match{Counted: true}
	steered := heldTo(Explanation{Decision: TraceForward, Segment: explainSegment, Overhead: srv6.Overhead(1), Match: far6}, "segment", tracedMTU)
	steeredTooBig := steered
	steeredTooBig.Decision, steeredTooBig.Reason, steeredTooBig.Answer = TraceAnswer, "too_big", "too_big"
	// an IPv4 read past its session's MTU without DF whose header fails its checksum, which the cut refuses with no octet at fault
	unsound := udpPacket(transitOwn[4], transitFar[4], tracedMTU+100, false)
	unsound[10] ^= 0xff
	return []explainCase{
		{"not one IP packet", explainLeaf, []byte{0x45, 0, 0, 10, 0, 0, 0, 0, 64, 17}, explainedDrop("invalid", Match{})},
		{"a group", explainLeaf, udpPacket(transitOwn[6], segAddr("ff02::1"), 100, false), explainedDrop("multicast", Match{})},
		{"the limited broadcast", explainLeaf, udpPacket(transitOwn[4], segAddr("255.255.255.255"), 100, false), explainedDrop("multicast", Match{})},
		{"a forged source", explainLeaf, udpPacket(transitSender[6], transitFar[6], 100, false), explainedDrop("forged", far6)},
		{"a routing header", explainLeaf, withRouting(udpPacket(transitOwn[6], transitFar[6], 100, false), 4), explainedDrop("routing_header", far6)},
		{"this node's SID", explainLeaf, udpPacket(transitOwn[6], edgeOwnSID, 100, false), explainedDrop("sid", exit)},
		{"an unowned source toward a default", explainLeaf, udpPacket(edgeLAN[4], edgeInternet[4], 100, false), explainedDrop("unowned_source", exit)},
		{"a carried packet carrying another", explainLeaf, encapsulated(transitOwn[6], edgeOtherSID, encapsulated(transitOwn[4], transitFar[4], udpPacket(transitOwn[6], transitFar[6], 100, false))), explainedDrop("nested", Match{Bits: 64})},
		{"this node's own", explainLeaf, udpPacket(transitOwn[4], edgeAssigned[4], 100, false), explainedDrop("looped", Match{Bits: 32})},
		{"a hold", explainLeaf, udpPacket(transitOwn[4], transitHeldHost[4], 100, false), explainedAnswer("held", "host_unreachable", Match{Bits: 32})},
		{"no route", explainBare, udpPacket(transitOwn[6], transitUnrouted[6], 100, false), explainedAnswer("no_route", "no_route", Match{})},
		{"a forward", explainLeaf, udpPacket(transitOwn[4], transitFar[4], 100, false), heldTo(Explanation{Decision: TraceForward, Match: far4}, "peer", tracedMTU)},
		{"a forward cut into fragments", explainLeaf, udpPacket(transitOwn[4], transitFar[4], tracedMTU+100, false), heldTo(Explanation{Decision: TraceForward, Match: far4}, "peer", tracedMTU)},
		{"a cut refused at its options", explainLeaf, withOptions(udpPacket(transitOwn[4], transitFar[4], tracedMTU+100, false), []byte{7, 9, 4, 0}), heldTo(explainedAnswer("invalid", "parameter", far4), "peer", tracedMTU)},
		{"a cut refused with no fault", explainLeaf, unsound, heldTo(explainedDrop("too_big", far4), "peer", tracedMTU)},
		{"IPv4 too big with DF", explainLeaf, udpPacket(transitOwn[4], transitFar[4], tracedMTU+1, true), heldTo(explainedAnswer("too_big", "too_big", far4), "peer", tracedMTU)},
		{"IPv6 too big", explainLeaf, udpPacket(transitOwn[6], transitFar[6], tracedMTU+1, false), heldTo(explainedAnswer("too_big", "too_big", far6), "peer", tracedMTU)},
		{"a steer", explainSteered, udpPacket(transitOwn[6], transitFar[6], 100, false), steered},
		{"a steer past the session's MTU", explainSteered, udpPacket(transitOwn[6], transitFar[6], tracedMTU-srv6.Overhead(1)+1, false), steeredTooBig},
		{"a steer the encapsulation refuses", explainSteered, udpPacket(transitOwn[6], transitFar[6], 65535, false), Explanation{Decision: TraceDrop, Reason: "too_big", Segment: explainSegment, Match: far6}},
		{"a steer with no route to its segment", explainStranded, udpPacket(transitOwn[6], transitFar[6], 100, false), Explanation{Decision: TraceDrop, Reason: "no_route", Segment: explainSegment, Match: far6}},
	}
}()

// each arm of decide is explained with its decision, reason, answer, the session it is held to and the table's match
func TestExplainNamesEachArmOfTheDecision(t *testing.T) {
	for _, c := range sessionCases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.mesh(t).Explain(bytes.Clone(c.raw)); got != c.want {
				t.Errorf("got %+v, want %+v", got, c.want)
			}
		})
	}
}

// each arm of classify is explained with its decision, reason, answer, the session and segment it is held to and the table's match
func TestExplainReadNamesEachArmOfTheChecks(t *testing.T) {
	for _, c := range readCases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.mesh(t).ExplainRead(bytes.Clone(c.raw)); got != c.want {
				t.Errorf("got %+v, want %+v", got, c.want)
			}
		})
	}
}

// explainCases are the cases of a walk and the walk, which spends nothing
var explainCases = []struct {
	explain func(*Mesh, []byte) Explanation
	cases   []explainCase
}{{(*Mesh).Explain, sessionCases}, {(*Mesh).ExplainRead, readCases}}

// the walk spends no ICMP token, moves no counter, the answers sent among them, writes nothing to the tun, records nothing and leaves the packet as it was
// over more of each case than one source's bucket holds
func TestExplainSpendsAndChangesNothing(t *testing.T) {
	for _, set := range explainCases {
		for _, c := range set.cases {
			t.Run(c.name, func(t *testing.T) {
				m := c.mesh(t)
				feed := openTrace(t, m, TraceFilter{}, 0, control.TraceRateMax)
				raw := bytes.Clone(c.raw)
				for range icmpSourceBurst + 1 {
					set.explain(m, raw)
				}
				if !bytes.Equal(raw, c.raw) {
					t.Errorf("the walk rewrote the packet to %x", raw)
				}
				if got := m.TransitCounters(); got != (TransitCounters{}) {
					t.Errorf("the walk counted %+v", got)
				}
				if got := m.SegmentCounters(); got != (SegmentCounters{}) {
					t.Errorf("the walk counted %+v", got)
				}
				if bySource, byNode := m.ICMPWithheld(); bySource+byNode != 0 || m.TooBigAnswered() != 0 || m.MSSClamped() != 0 {
					t.Errorf("the walk withheld %d and %d answers, answered %d about a size and clamped %d", bySource, byNode, m.TooBigAnswered(), m.MSSClamped())
				}
				if records := queued(feed); len(records) != 0 {
					t.Errorf("the walk was traced as %+v", records)
				}
				if dev, ok := m.dev.(*scriptedDevice); ok {
					if writes := tunWrites(&dev.recordingDevice); len(writes) != 0 {
						t.Errorf("the walk wrote %d batches to the tun", len(writes))
					}
				}
			})
		}
	}
}
