// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/netip"
	"reflect"
	"testing"
	"testing/synctest"
	"time"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/srv6"
)

// transitClosed is a host the decision's tests route to a closed peer, whose budget refuses every share
var transitClosed = map[int]netip.Addr{4: segAddr("192.0.2.7"), 6: segAddr("3fff::7")}

// tracedMTU is the largest packet the out peer of a traced node carries
const tracedMTU = 1280

// tracedNode is newTransitNode with out carrying tracedMTU and a feed selecting every packet with all of it
// IPv4 egresses through a default cap.egress advertises, while IPv6's translation is not ready
// and transitClosed is routed to a closed peer
func tracedNode(t testing.TB) (*transitNode, *TraceFeed) {
	t.Helper()
	n := newTransitNode(t, tracedMTU)
	for _, family := range []int{4, 6} {
		n.m.Routes.Set(netip.Prefix{}, exitShapes[0].prefixes[family][0], Local)
		n.m.SetEgressPrefixes(append(exitShapes[0].prefixes[4], exitShapes[0].prefixes[6]...))
	}
	n.m.SetAdvertisedReady(true, false)
	closed := (&recordingPeer{}).peer(t, "closed")
	closed.Close()
	for _, family := range []int{4, 6} {
		n.m.Routes.Set(netip.Prefix{}, hostPrefix(transitClosed[family]), closed)
	}
	return n, openTrace(t, n.m, TraceFilter{}, control.TracePayloadMax, control.TraceRateMax)
}

// deliverTraced hands n's mesh packets as the session to its from peer delivers them, and returns the records the feed took
func deliverTraced(n *transitNode, feed *TraceFeed, packets ...[]byte) []TraceRecord {
	n.m.DeliverInboundBatch(framed(packets...), DefaultMTU, n.fromPeer)
	return queued(feed)
}

// tracedLeaf is carriedLeaf, its peer carrying tracedMTU and its IPv4 answers a TTL of 64, with a feed selecting every packet
func tracedLeaf(t testing.TB) (*Mesh, *TraceFeed) {
	t.Helper()
	m, peer := carriedLeaf(t)
	peer.SetMTU(tracedMTU)
	m.SetAnswerTTL(64)
	return m, openTrace(t, m, TraceFilter{}, 0, control.TraceRateMax)
}

// headendSteered is inner encapsulated at headend under path, as steered builds it outside a test
func headendSteered(inner []byte, path ...netip.Addr) []byte {
	outer, err := srv6.Encapsulate(inner, headend, path)
	if err != nil {
		panic(err)
	}
	return outer
}

// readTraced classifies packets as one read off m's tun, and returns the records the feed took
func readTraced(m *Mesh, feed *TraceFeed, packets ...[]byte) []TraceRecord {
	classifiedTo(m, packets...)
	return queued(feed)
}

// tracedSegments is egressMesh with egressNext routed to a peer named next, and a feed selecting every packet with all of it
func tracedSegments(t *testing.T) (*Mesh, *TraceFeed) {
	t.Helper()
	m, _ := egressMesh(t)
	m.Routes.Set(netip.Prefix{}, segPrefix("3fff:b:0:206::/64"), (&recordingPeer{}).peer(t, "next"))
	return m, openTrace(t, m, TraceFilter{}, control.TracePayloadMax, control.TraceRateMax)
}

// closedPeer is the closed peer a tracedNode routes transitClosed to
func closedPeer(n *transitNode) *Peer {
	peer, _, _ := n.m.Routes.Resolve(netip.Addr{}, transitClosed[4])
	return peer
}

// decisionOf is the part of a record that names what the decision did, the rest being read from the packet
func decisionOf(r TraceRecord) TraceRecord {
	return TraceRecord{Arrival: r.Arrival, From: r.From, Decision: r.Decision, Reason: r.Reason, Next: r.Next, Segment: r.Segment, Fragments: r.Fragments, Answer: r.Answer, Outcome: r.Outcome}
}

// outcomeCase is one outcome a site of the decision records, the reason it names, and the input that draws it
type outcomeCase struct {
	name   string
	reason transitReason
	run    func(t *testing.T) []TraceRecord
	want   TraceRecord
}

func session(decision TraceDecision, reason string) TraceRecord {
	return TraceRecord{Arrival: TraceArrivedSession, From: "from", Decision: decision, Reason: reason}
}

func read(decision TraceDecision, reason string) TraceRecord {
	return TraceRecord{Arrival: TraceArrivedTUN, Decision: decision, Reason: reason}
}

func with(r TraceRecord, edit func(*TraceRecord)) TraceRecord {
	edit(&r)
	return r
}

// throughDecide runs packets through a traced node's decision, edit setting the node up first
func throughDecide(edit func(*transitNode), packets ...[]byte) func(t *testing.T) []TraceRecord {
	return func(t *testing.T) []TraceRecord {
		n, feed := tracedNode(t)
		if edit != nil {
			edit(n)
		}
		return deliverTraced(n, feed, packets...)
	}
}

// classified runs packets through a traced leaf's checks as one read
func classified(packets ...[]byte) func(t *testing.T) []TraceRecord {
	return func(t *testing.T) []TraceRecord {
		m, feed := tracedLeaf(t)
		return readTraced(m, feed, packets...)
	}
}

// acted runs packets a session to a peer named from delivers through a traced mesh's segments, edit setting the mesh up first
func acted(edit func(*Mesh), packets ...[]byte) func(t *testing.T) []TraceRecord {
	return func(t *testing.T) []TraceRecord {
		m, feed := tracedSegments(t)
		if edit != nil {
			edit(m)
		}
		m.DeliverInboundBatch(framed(packets...), DefaultMTU, (&recordingPeer{}).peer(t, "from"))
		return queued(feed)
	}
}

// outcomeCases are the outcomes of decide, classify, the segments and the budget, one input each
// the cases of the reasons the transit counters count in arrival at one site each
var outcomeCases = func() []outcomeCase {
	udp := func(family int, from, to map[int]netip.Addr, size int, df bool) []byte {
		return udpPacket(from[family], to[family], size, df)
	}
	looseRoute := []byte{131, 7, 4, 192, 0, 2, 3, 0}
	unparseable := []byte{0x45, 0, 0, 10, 0, 0, 0, 0, 64, 17}
	end := func(hops byte) []byte {
		return withTTL(headendSteered(udpPacket(tooBigSource[6], transitNowhere[6], 100, false), egressWaypoint, egressNext), hops)
	}
	return []outcomeCase{
		{"a forward", transitForwarded, throughDecide(nil, udp(4, transitSender, transitFar, 100, false)), with(session(TraceForward, ""), func(r *TraceRecord) { r.Next = "out" })},
		{"a forward cut into fragments", transitForwarded, throughDecide(nil, udp(4, transitSender, transitFar, tracedMTU+100, false)), with(session(TraceForward, ""), func(r *TraceRecord) { r.Next, r.Fragments = "out", 2 })},
		{"a delivery to this node", transitDelivered, throughDecide(nil, udp(6, transitSender, transitOwn, 100, false)), session(TraceDeliver, "")},
		{"a delivery of link scope", transitDelivered, throughDecide(nil, udpPacket(transitSender[6], segAddr("ff02::1"), 100, false)), session(TraceDeliver, "")},
		{"an egress", transitDelivered, throughDecide(nil, udp(4, transitSender, transitNowhere, 100, false)), session(TraceEgress, "")},
		{"an expired packet", transitExpired, throughDecide(nil, withTTL(udp(4, transitSender, transitFar, 100, false), 1)), with(session(TraceAnswer, "expired"), func(r *TraceRecord) { r.Answer, r.Outcome = "expired", TraceSent })},
		{"no route", transitNoRoute, throughDecide(nil, udp(6, transitSender, transitUnrouted, 100, false)), with(session(TraceAnswer, "no_route"), func(r *TraceRecord) { r.Answer, r.Outcome = "no_route", TraceSent })},
		{"a hold", transitHeld, throughDecide(nil, udp(4, transitSender, transitHeldHost, 100, false)), with(session(TraceAnswer, "held"), func(r *TraceRecord) { r.Answer, r.Outcome = "host_unreachable", TraceSent })},
		{"transit off", transitRefused, throughDecide(func(n *transitNode) { n.m.SetTransit(false) }, udp(6, transitSender, transitFar, 100, false)), with(session(TraceAnswer, "refused"), func(r *TraceRecord) { r.Answer, r.Outcome = "prohibited", TraceSent })},
		{"a martian", transitMartian, throughDecide(nil, udpPacket(transitSender[4], segAddr("127.0.0.1"), 100, false)), session(TraceDrop, "martian")},
		{"a link-local source", transitMartian, throughDecide(nil, udpPacket(segAddr("fe80::1"), transitFar[6], 100, false)), with(session(TraceAnswer, "martian"), func(r *TraceRecord) { r.Answer, r.Outcome = "beyond_scope", TraceSent })},
		{"a source route", transitSourceRoute, throughDecide(nil, withOptions(udp(4, transitSender, transitFar, 100, false), looseRoute)), session(TraceDrop, "source_route")},
		{"options that do not read", transitInvalid, throughDecide(nil, withOptions(udp(4, transitSender, transitFar, 100, false), []byte{7, 9, 4, 0})), with(session(TraceAnswer, "invalid"), func(r *TraceRecord) { r.Answer, r.Outcome = "parameter", TraceSent })},
		{"an unrouted source", transitUnroutedSource, throughDecide(nil, udp(4, transitStranger, transitNowhere, 100, false)), session(TraceDrop, "unrouted_source")},
		{"a translation not ready", transitNotReady, throughDecide(nil, udp(6, transitSender, transitNowhere, 100, false)), session(TraceDrop, "not_ready")},
		{"a packet too big", transitTooBig, throughDecide(nil, udp(6, transitSender, transitFar, tracedMTU+100, false)), with(session(TraceAnswer, "too_big"), func(r *TraceRecord) { r.Answer, r.Outcome = "too_big", TraceSent })},
		{"a budget refused", traceBudget, throughDecide(nil, udp(4, transitSender, transitClosed, 100, false)), with(session(TraceDrop, "budget"), func(r *TraceRecord) { r.Next = "closed" })},
		{"an unparseable read", transitInvalid, classified(unparseable), read(TraceDrop, "invalid")},
		{"a read to a group", transitMulticast, classified(udpPacket(transitOwn[4], segAddr("224.0.0.1"), 100, false)), read(TraceDrop, "multicast")},
		{"a forged read", transitForged, classified(udp(6, transitSender, transitFar, 100, false)), read(TraceDrop, "forged")},
		{"a read with an SRH", transitRoutingHeader, classified(withRouting(udp(6, transitOwn, transitFar, 100, false), 4)), read(TraceDrop, "routing_header")},
		{"a read to this node's SID", transitOwnSID, classified(udpPacket(transitOwn[6], edgeOwnSID, 100, false)), read(TraceDrop, "sid")},
		{"a read from the LAN to the internet", transitUnownedSource, classified(udp(4, edgeLAN, edgeInternet, 100, false)), read(TraceDrop, "unowned_source")},
		{"a read carrying a carried packet", transitNested, classified(encapsulated(transitOwn[6], edgeOtherSID, encapsulated(transitOwn[4], transitFar[4], udp(6, transitOwn, transitFar, 100, false)))), read(TraceDrop, "nested")},
		{"a read to this node", transitLooped, classified(udp(4, transitOwn, edgeAssigned, 100, false)), read(TraceDrop, "looped")},
		{"a read queued for its peer", transitForwarded, classified(udp(4, transitOwn, transitFar, 100, false)), with(read(TraceForward, ""), func(r *TraceRecord) { r.Next = "peer" })},
		{"a read a policy steers", transitForwarded, func(t *testing.T) []TraceRecord {
			m, batch := classifyRead(t, 6, 1, 1, classifySteered)
			feed := openTrace(t, m, TraceFilter{}, 0, control.TraceRateMax)
			m.classify(batch)
			return queued(feed)
		}, with(read(TraceForward, ""), func(r *TraceRecord) { r.Next, r.Segment = "peer", segAddr("3fff:1::1") })},
		{"a steered read with no route to its first segment", transitNoRoute, func(t *testing.T) []TraceRecord {
			m, batch := classifyRead(t, 6, 1, 1, classifySteered)
			m.Routes.Remove(netip.Prefix{}, segPrefix("3fff:1::/64"))
			feed := openTrace(t, m, TraceFilter{}, 0, control.TraceRateMax)
			m.classify(batch)
			return queued(feed)
		}, with(read(TraceDrop, "no_route"), func(r *TraceRecord) { r.Segment = segAddr("3fff:1::1") })},
		{"a read to a hold", transitHeld, classified(udp(4, transitOwn, transitHeldHost, 100, false)), with(read(TraceAnswer, "held"), func(r *TraceRecord) { r.Answer, r.Outcome = "host_unreachable", TraceSent })},
		{"a read too big", transitTooBig, classified(udp(6, transitOwn, transitFar, tracedMTU+100, false)), with(read(TraceAnswer, "too_big"), func(r *TraceRecord) { r.Answer, r.Outcome = "too_big", TraceSent })},
		{"an egress segment", transitDelivered, acted(nil, headendSteered(udp(4, tooBigSource, transitNowhere, 100, false), egressExit)), with(session(TraceEgress, ""), func(r *TraceRecord) { r.Segment = egressExit })},
		{"an egress segment refusing a source", transitRefused, acted(nil, headendSteered(udpPacket(stranger[6], transitNowhere[6], 100, false), egressExit)), with(session(TraceDrop, "refused"), func(r *TraceRecord) { r.Segment = egressExit })},
		{"an egress segment not ready", transitNotReady, acted(func(m *Mesh) { m.SetEgressReady(false, false) }, headendSteered(udp(6, tooBigSource, transitNowhere, 100, false), egressExit)), with(session(TraceDrop, "not_ready"), func(r *TraceRecord) { r.Segment = egressExit })},
		{"an egress segment after End", transitDelivered, acted(nil, headendSteered(udp(4, tooBigSource, transitNowhere, 100, false), egressWaypoint, egressExit)), with(session(TraceEgress, ""), func(r *TraceRecord) { r.Segment = egressExit })},
		{"an egress segment refusing a source after End", transitRefused, acted(nil, headendSteered(udpPacket(stranger[6], transitNowhere[6], 100, false), egressWaypoint, egressExit)), with(session(TraceDrop, "refused"), func(r *TraceRecord) { r.Segment = egressExit })},
		{"End", transitForwarded, acted(nil, end(64)), with(session(TraceForward, ""), func(r *TraceRecord) { r.Next, r.Segment = "next", egressNext })},
		{"End to a peer whose budget refused it", traceBudget, acted(func(m *Mesh) {
			closed := NewPeer("closed", func(int) (BatchSealer, error) { return benchSealer, nil }, func([][]byte) error { return nil }, nil)
			closed.Close()
			m.Routes.Set(netip.Prefix{}, segPrefix("3fff:b:0:206::/64"), closed)
		}, end(64)), with(session(TraceDrop, "budget"), func(r *TraceRecord) { r.Next = "closed" })},
		{"End past the hop limit", transitExpired, acted(nil, end(1)), with(session(TraceDrop, "expired"), func(r *TraceRecord) { r.Segment = egressWaypoint })},
	}
}()

// each outcome of decide, classify, the segments and the budget records the decision, reason, next peer, segment and answer it met
// and once every case ran, every reason the transit counters name but answered, and budget, has a case that recorded it, so a reason added without a record fails here
func TestTraceRecordsEachOutcome(t *testing.T) {
	covered := map[transitReason]bool{}
	ran := 0
	for _, c := range outcomeCases {
		t.Run(c.name, func(t *testing.T) {
			ran++
			records := c.run(t)
			var got []TraceRecord
			for _, r := range records {
				got = append(got, decisionOf(r))
			}
			for _, r := range got {
				if reflect.DeepEqual(r, c.want) {
					covered[c.reason] = true
					return
				}
			}
			t.Errorf("the records are %+v, want one of %+v", got, c.want)
		})
	}
	if ran < len(outcomeCases) {
		return
	}
	for reason := range transitReasonCount + 1 {
		if reason != transitAnswered && !covered[reason] {
			t.Errorf("no input draws a record of reason %s", traceReasonName(reason))
		}
	}
}

// an answer the limits hold back is recorded withheld, its source's bucket spent by the answers before it
func TestTraceRecordsAnAnswerTheLimitWithholds(t *testing.T) {
	n, feed := tracedNode(t)
	packets := make([][]byte, icmpSourceBurst+1)
	for i := range packets {
		packets[i] = udpPacket(transitSender[4], transitUnrouted[4], 100, false)
	}
	records := deliverTraced(n, feed, packets...)
	if len(records) != len(packets) {
		t.Fatalf("the feed took %d records of %d packets", len(records), len(packets))
	}
	for i, r := range records {
		want := TraceSent
		if i == icmpSourceBurst {
			want = TraceWithheld
		}
		if r.Decision != TraceAnswer || r.Outcome != want {
			t.Errorf("record %d is %v %v, want an answer %v", i, r.Decision, r.Outcome, want)
		}
	}
}

// an answer no ICMP error may make is recorded not answerable, and one with no address to come from unanswered
func TestTraceRecordsAnAnswerNoneIsSentFor(t *testing.T) {
	n, feed := tracedNode(t)
	echoReply := withProtocol(udpPacket(transitSender[6], transitUnrouted[6], 100, false), 58)
	echoReply[40] = 1
	if r := deliverTraced(n, feed, echoReply); len(r) != 1 || r[0].Outcome != TraceNotAnswerable {
		t.Errorf("an ICMPv6 error drew %+v, want an answer not answerable", r)
	}
	n.m.SetAnswerSources(AnswerSources{})
	if r := deliverTraced(n, feed, udpPacket(transitSender[6], transitUnrouted[6], 100, false)); len(r) != 1 || r[0].Outcome != TraceUnanswered {
		t.Errorf("a node with no IPv6 address to answer from drew %+v, want an answer unanswered", r)
	}
}

// a forward's record carries the packet as it arrived, its hop limit or TTL, its MSS and its options, which the forward then rewrites
// and End's, and that of a drop a later segment of this node met, carry it before End moved its destination, segments left and hop limit
// and so does End's forward of a packet a filter takes in a batch whose End forwards before it the filter left out
// an egress after End carries the packet the segments carried, which End never touched
func TestTraceRecordsTheForwardAsItArrived(t *testing.T) {
	syn := func(family int) []byte {
		return tcpPacket(family, 0, false, synFlag, []byte{optionMSS, mssLen, 0x05, 0xb4}, 0, 10)
	}
	for _, c := range []struct {
		name string
		raw  []byte
	}{
		{"IPv4 of TTL 9", withTTL(udpPacket(transitSender[4], transitFar[4], 100, false), 9)},
		{"IPv6 of hop limit 9", withTTL(udpPacket(transitSender[6], transitFar[6], 100, false), 9)},
		{"IPv4 with Record Route", withOptions(udpPacket(transitSender[4], transitFar[4], 100, false), []byte{7, 7, 4, 0, 0, 0, 0, 0})},
		{"IPv4 cut into fragments", udpPacket(transitSender[4], transitFar[4], tracedMTU+100, false)},
	} {
		t.Run(c.name, func(t *testing.T) {
			n, feed := tracedNode(t)
			records := deliverTraced(n, feed, bytes.Clone(c.raw))
			if len(records) != 1 || records[0].Decision != TraceForward {
				t.Fatalf("the feed took %+v", records)
			}
			if got, want := records[0].HopLimit, hopLimit(c.raw, c.raw[0]>>4); got != want {
				t.Errorf("the record's hop limit is %d, want %d as it arrived", got, want)
			}
			if !bytes.Equal(records[0].Payload, c.raw) {
				t.Errorf("the record carries %x, want the packet as it arrived %x", records[0].Payload, c.raw)
			}
		})
	}
	for _, family := range []int{4, 6} {
		t.Run(fmt.Sprintf("IPv%d SYN of MSS 1460", family), func(t *testing.T) {
			n, feed := tracedNode(t)
			n.m.Routes.Set(netip.Prefix{}, hostPrefix(tooBigDestination[family]), n.outPeer)
			raw := syn(family)
			records := deliverTraced(n, feed, bytes.Clone(raw))
			if len(records) != 1 || records[0].Decision != TraceForward || !bytes.Equal(records[0].Payload, raw) {
				t.Errorf("the feed took %+v, want the forward of the SYN as it arrived %x", records, raw)
			}
			if n.m.MSSClamped() != 1 {
				t.Errorf("the forward clamped %d SYNs, want this one", n.m.MSSClamped())
			}
		})
	}
	for _, c := range []struct {
		name     string
		inner    []byte
		next     netip.Addr
		decision TraceDecision
	}{
		{"End", udpPacket(tooBigSource[6], transitNowhere[6], 100, false), egressNext, TraceForward},
		{"a drop after End", udpPacket(stranger[6], transitNowhere[6], 100, false), egressExit, TraceDrop},
	} {
		t.Run(c.name, func(t *testing.T) {
			m, feed := tracedSegments(t)
			raw := withTTL(headendSteered(c.inner, egressWaypoint, c.next), 9)
			m.DeliverInboundBatch(framed(bytes.Clone(raw)), DefaultMTU, nil)
			records := queued(feed)
			if len(records) != 1 || records[0].Decision != c.decision || records[0].HopLimit != 9 || records[0].Destination != egressWaypoint {
				t.Fatalf("the feed took %+v", records)
			}
			if !bytes.Equal(records[0].Payload, raw) {
				t.Errorf("the record carries %x, want the packet as it arrived %x", records[0].Payload, raw)
			}
		})
	}
	t.Run("End's forwards of one source in a batch of another's", func(t *testing.T) {
		m, _ := egressMesh(t)
		m.Routes.Set(netip.Prefix{}, segPrefix("3fff:b:0:206::/64"), (&recordingPeer{}).peer(t, "next"))
		taken := segAddr("3fff:b:0:200::2")
		inner := udpPacket(tooBigSource[6], transitNowhere[6], 100, false)
		var batch, want [][]byte
		for i, source := range []netip.Addr{headend, taken, headend, taken} {
			raw := withTTL(steered(t, inner, source, egressWaypoint, egressNext), byte(9-i))
			batch = append(batch, bytes.Clone(raw))
			if source == taken {
				want = append(want, raw)
			}
		}
		// the whole packet, and a rate with room for every packet of the batch
		feed := openTrace(t, m, TraceFilter{Sources: []netip.Prefix{hostPrefix(taken)}}, len(batch[0]), len(batch))
		m.DeliverInboundBatch(framed(batch...), DefaultMTU, nil)
		records := queued(feed)
		if len(records) != len(want) {
			t.Fatalf("the feed took %+v, want the forwards of the %d packets from %s", records, len(want), taken)
		}
		for i, r := range records {
			if r.Decision != TraceForward || r.Source != taken || r.Destination != egressWaypoint || !bytes.Equal(r.Payload, want[i]) {
				t.Errorf("record %d is %s from %s to %s carrying %x, want the forward from %s as it arrived %x", i, r.Decision, r.Source, r.Destination, r.Payload, taken, want[i])
			}
		}
	})
	t.Run("an egress after End", func(t *testing.T) {
		m, feed := tracedSegments(t)
		inner := udpPacket(tooBigSource[4], transitNowhere[4], 100, false)
		m.DeliverInboundBatch(framed(withTTL(headendSteered(bytes.Clone(inner), egressWaypoint, egressExit), 9)), DefaultMTU, nil)
		records := queued(feed)
		if len(records) != 1 || records[0].Decision != TraceEgress || !bytes.Equal(records[0].Payload, inner) {
			t.Errorf("the feed took %+v, want the egress of the packet it carried as it arrived %x", records, inner)
		}
	})
}

// routeClosed routes prefix on m to a closed peer named closed, whose budget refuses every share, and returns the peer
func routeClosed(m *Mesh, prefix netip.Prefix) *Peer {
	closed := NewPeer("closed", func(int) (BatchSealer, error) { return benchSealer, nil }, func([][]byte) error { return nil }, nil)
	closed.Close()
	m.Routes.Set(netip.Prefix{}, prefix, closed)
	return closed
}

// budgetDropsEachFragment checks that records hold a forward cut into fragments and then the budget drop of each fragment
func budgetDropsEachFragment(t *testing.T, records []TraceRecord) {
	t.Helper()
	if len(records) == 0 || records[0].Decision != TraceForward || records[0].Fragments < 2 {
		t.Fatalf("the feed took %+v, want a forward cut into fragments first", records)
	}
	drops := 0
	for _, r := range records[1:] {
		if r.Decision == TraceDrop && r.Reason == "budget" {
			drops++
		}
	}
	if drops != records[0].Fragments {
		t.Errorf("the feed took %d budget drops after a forward of %d fragments: %+v", drops, records[0].Fragments, records)
	}
}

// a filter on the destination a packet arrived with takes what this node's segments did with it after End moved the destination on
// a drop a later segment met, and the budget drop that follows End's forward, which reads the packet as it was queued
// and a filter on the destination of a read a policy steered takes the budget drop that follows its forward
// and where the forward cut the packet into fragments, the budget drop of each fragment
func TestTraceFiltersByThePacketItsForwardShowed(t *testing.T) {
	arrivedAt := TraceFilter{Destinations: []netip.Prefix{hostPrefix(egressWaypoint)}}
	t.Run("a drop after End", func(t *testing.T) {
		m, _ := egressMesh(t)
		feed := openTrace(t, m, arrivedAt, 0, control.TraceRateMax)
		m.DeliverInboundBatch(framed(headendSteered(udpPacket(stranger[6], transitNowhere[6], 100, false), egressWaypoint, egressExit)), DefaultMTU, nil)
		if records := queued(feed); len(records) != 1 || records[0].Decision != TraceDrop || records[0].Segment != egressExit {
			t.Errorf("the feed took %+v, want the drop %s met", records, egressExit)
		}
	})
	t.Run("End's forward to a peer whose budget refused it", func(t *testing.T) {
		m, _ := egressMesh(t)
		routeClosed(m, segPrefix("3fff:b:0:206::/64"))
		feed := openTrace(t, m, arrivedAt, 0, control.TraceRateMax)
		m.DeliverInboundBatch(framed(headendSteered(udpPacket(tooBigSource[6], transitNowhere[6], 100, false), egressWaypoint, egressNext)), DefaultMTU, nil)
		records := queued(feed)
		if len(records) != 2 || records[0].Decision != TraceForward || records[1].Decision != TraceDrop || records[1].Reason != "budget" {
			t.Fatalf("the feed took %+v, want the forward and its budget drop", records)
		}
		if got := records[1]; got.Destination != egressNext || got.HopLimit != 63 || got.Segment.IsValid() {
			t.Errorf("the budget drop reads %s at hop limit %d and segment %s, want the packet as queued for %s at 63 and no segment", got.Destination, got.HopLimit, got.Segment, egressNext)
		}
	})
	t.Run("a read a policy steered to a peer whose budget refused it", func(t *testing.T) {
		m, read := classifyRead(t, 6, 1, 1, classifySteered)
		m.outboundJobs = make(chan *outboundBatch, 1)
		steeredTo := segAddr("3fff:1::1")
		routeClosed(m, segPrefix("3fff:1::/64"))
		feed := openTrace(t, m, TraceFilter{Destinations: []netip.Prefix{hostPrefix(transitFar[6])}}, 0, control.TraceRateMax)
		m.classify(read)
		m.dispatchOutbound(read)
		records := queued(feed)
		if len(records) != 2 || records[0].Decision != TraceForward || records[1].Decision != TraceDrop || records[1].Reason != "budget" || records[1].Arrival != TraceArrivedTUN {
			t.Fatalf("the feed took %+v, want the read's forward and its budget drop", records)
		}
		if got := records[1]; got.Destination != steeredTo || got.Segment.IsValid() {
			t.Errorf("the budget drop reads %s and segment %s, want the packet as queued for %s and no segment", got.Destination, got.Segment, steeredTo)
		}
	})
	t.Run("End's forward cut into fragments to a peer whose budget refused them", func(t *testing.T) {
		m, _ := egressMesh(t)
		routeClosed(m, segPrefix("3fff:b:0:206::/64")).SetMTU(tracedMTU)
		feed := openTrace(t, m, arrivedAt, 0, control.TraceRateMax)
		m.DeliverInboundBatch(framed(headendSteered(udpPacket(tooBigSource[4], transitNowhere[4], 2000, false), egressWaypoint, egressNext)), DefaultMTU, nil)
		budgetDropsEachFragment(t, queued(feed))
	})
	t.Run("a read a policy steered cut into fragments to a peer whose budget refused them", func(t *testing.T) {
		m, _ := classifyRead(t, 4, 1, 1, classifySteered)
		m.outboundJobs = make(chan *outboundBatch, 1)
		routeClosed(m, segPrefix("3fff:1::/64")).SetMTU(tracedMTU)
		read := newOutboundBatch(1)
		fill(read, udpPacket(segAddr("192.0.2.128"), transitFar[4], 2000, false))
		feed := openTrace(t, m, TraceFilter{Destinations: []netip.Prefix{hostPrefix(transitFar[4])}}, 0, control.TraceRateMax)
		m.classify(read)
		m.dispatchOutbound(read)
		budgetDropsEachFragment(t, queued(feed))
	})
}

// a client selecting drops alone at the least rate spends none of it on the forwards beside them
// decide's held forward before the drop, or after the drop spent the rate, and End's forward in the batch of a drop
func TestTraceForwardsSpendNoRateOfAClientOfDrops(t *testing.T) {
	drops := TraceFilter{Decision: TraceDrop}
	forward := udpPacket(transitSender[4], transitFar[4], 100, false)
	martian := udpPacket(transitSender[4], segAddr("127.0.0.1"), 100, false)
	check := func(t *testing.T, feed *TraceFeed, records []TraceRecord) {
		t.Helper()
		if len(records) != 1 || records[0].Decision != TraceDrop || feed.Counts() != (TraceCounts{Recorded: 1}) {
			t.Errorf("the feed took %+v and counted %+v, want the drop alone and nothing refused", records, feed.Counts())
		}
	}
	for _, c := range []struct {
		name    string
		packets [][]byte
	}{
		{"a forward before the drop", [][]byte{forward, martian}},
		{"a forward after the drop spent the rate", [][]byte{martian, forward}},
	} {
		t.Run(c.name, func(t *testing.T) {
			n := newTransitNode(t, tracedMTU)
			feed := openTrace(t, n.m, drops, 64, control.TraceRateMin)
			check(t, feed, deliverTraced(n, feed, c.packets...))
		})
	}
	t.Run("End's forward in the batch of End past the hop limit", func(t *testing.T) {
		m, _ := egressMesh(t)
		m.Routes.Set(netip.Prefix{}, segPrefix("3fff:b:0:206::/64"), (&recordingPeer{}).peer(t, "next"))
		feed := openTrace(t, m, drops, 64, control.TraceRateMin)
		end := func(hops byte) []byte {
			return withTTL(headendSteered(udpPacket(tooBigSource[6], transitNowhere[6], 100, false), egressWaypoint, egressNext), hops)
		}
		m.DeliverInboundBatch(framed(end(64), end(1)), DefaultMTU, (&recordingPeer{}).peer(t, "from"))
		check(t, feed, queued(feed))
	})
}

// a segment's drop of a packet arrive left uncopied, the client's rate of one record a second holding no room as it arrived, has no record
// though the rate has room again by the drop, since the packet as it arrived is gone
// the bubble moves time only while the segment's step sleeps
func TestTraceRecordsNoDropOfASegmentPacketItHadNoRoomToCopy(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := traceMesh(t)
		feed := openTrace(t, m, TraceFilter{Decision: TraceDrop}, 64, 1)
		trace := m.tracer.Load()
		c := trace.clients[0]
		for c.draw(trace.now()) {
		}
		packet := plainV6(segAddr("2001:db8::1"), egressExit, "refused")
		trace.actOnSegments(m, framed(packet), DefaultMTU, nil, func([]byte) srv6.Result {
			time.Sleep(time.Duration(c.interval) + time.Millisecond)
			if !c.room(trace.now()) {
				t.Fatal("the rate has no room by the drop")
			}
			return srv6.Result{Action: srv6.ActionDrop, Err: srv6.ErrSourceRefused}
		})
		if records := queued(feed); len(records) != 0 || feed.Counts() != (TraceCounts{}) {
			t.Errorf("the feed took %+v and counted %+v, want nothing", records, feed.Counts())
		}
	})
}

// a client selecting drops or answers alone takes what decide held as a forward and then dropped or answered
// a source route its options refuse, options that do not read, and a packet too big for its peer
func TestTraceTakesTheDropsAndAnswersOfAHeldForward(t *testing.T) {
	looseRoute := []byte{131, 7, 4, 192, 0, 2, 3, 0}
	for _, c := range []struct {
		name     string
		decision TraceDecision
		packet   []byte
		want     TraceRecord
	}{
		{"a source route", TraceDrop, withOptions(udpPacket(transitSender[4], transitFar[4], 100, false), looseRoute), session(TraceDrop, "source_route")},
		{"options that do not read", TraceAnswer, withOptions(udpPacket(transitSender[4], transitFar[4], 100, false), []byte{7, 9, 4, 0}),
			with(session(TraceAnswer, "invalid"), func(r *TraceRecord) { r.Answer, r.Outcome = "parameter", TraceSent })},
		{"a packet too big", TraceAnswer, udpPacket(transitSender[6], transitFar[6], tracedMTU+100, false),
			with(session(TraceAnswer, "too_big"), func(r *TraceRecord) { r.Answer, r.Outcome = "too_big", TraceSent })},
	} {
		t.Run(c.name, func(t *testing.T) {
			n := newTransitNode(t, tracedMTU)
			feed := openTrace(t, n.m, TraceFilter{Decision: c.decision}, 0, control.TraceRateMax)
			records := deliverTraced(n, feed, c.packet)
			if len(records) != 1 || !reflect.DeepEqual(decisionOf(records[0]), c.want) {
				t.Errorf("the feed took %+v, want %+v", records, c.want)
			}
		})
	}
}

// a budget drop names the session whose packets decide queued in the batch, none for packets of no session
// though the trace opened while decide held the batch it filled untraced, and though the batch last held another session's packets
func TestTraceBudgetDropNamesTheSessionOfItsBatch(t *testing.T) {
	toClosed := udpPacket(transitSender[4], transitClosed[4], 100, false)
	budget := TraceRecord{Decision: TraceDrop, Reason: "budget", Next: "closed"}
	t.Run("a trace opened while decide held the batch", func(t *testing.T) {
		var n *transitNode
		var feed *TraceFeed
		batch := [][]byte{udpPacket(transitSender[4], segAddr("127.0.0.1"), 100, false), toClosed}
		// the martian's drop report opens the trace after decide loaded the tracer and before it queues the forward behind it
		n = newRecordingTransitNode(t, tracedMTU, func(kind, _ string, _ ...slog.Attr) {
			if kind == "netstack.transit.dropped" && feed == nil {
				// a rate with room for a record of each packet
				feed = openTrace(t, n.m, TraceFilter{}, 0, len(batch))
			}
		})
		routeClosed(n.m, hostPrefix(transitClosed[4]))
		n.m.DeliverInboundBatch(framed(batch...), DefaultMTU, n.fromPeer)
		if feed == nil {
			t.Fatal("the martian's drop reported nothing")
		}
		want := with(budget, func(r *TraceRecord) { r.Arrival, r.From = TraceArrivedSession, "from" })
		if records := queued(feed); len(records) != 1 || !reflect.DeepEqual(decisionOf(records[0]), want) {
			t.Errorf("the feed took %+v, want the budget drop alone, %+v", records, want)
		}
	})
	t.Run("a batch that last held another session's packets", func(t *testing.T) {
		n := newTransitNode(t, tracedMTU)
		routeClosed(n.m, hostPrefix(transitClosed[4]))
		// every forward batch but one is held, so the second delivery takes the batch the first filled
		for range cap(n.m.forwardFree) - 1 {
			<-n.m.forwardFree
		}
		n.m.DeliverInboundBatch(framed(toClosed), DefaultMTU, n.fromPeer)
		// a rate with room for the forward and its budget drop
		feed := openTrace(t, n.m, TraceFilter{}, 0, 2)
		n.m.DeliverInboundBatch(framed(toClosed), DefaultMTU, nil)
		want := []TraceRecord{{Decision: TraceForward, Next: "closed"}, budget}
		records := queued(feed)
		var got []TraceRecord
		for _, r := range records {
			got = append(got, decisionOf(r))
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("the feed took %+v, want the forward and the budget drop of no session, %+v", got, want)
		}
	})
}
