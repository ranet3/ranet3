// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"bytes"
	"context"
	"encoding/binary"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/logtest"
	"ranet3.com/pkgs/ranet3/internal/packet"
	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
)

func segAddr(s string) netip.Addr     { return netip.MustParseAddr(s) }
func segPrefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }

// everySource is an overlay admitting every outer source, for a table whose
// tests do not reach the overlay's bound
var everySource = []schema.Prefix{schema.MustPrefix("::/0")}

// plainV6 is a minimal IPv6 packet, enough for the header reading the
// dataplane does.
func plainV6(src, dst netip.Addr, payload string) []byte {
	raw := make([]byte, 40+len(payload))
	raw[0] = 0x60
	binary.BigEndian.PutUint16(raw[4:], uint16(len(payload)))
	raw[6] = 59
	raw[7] = 64
	copy(raw[8:], src.AsSlice())
	copy(raw[24:], dst.AsSlice())
	copy(raw[40:], payload)
	return raw
}

// recordingPeer collects what the mesh sent through one peer, sealing each
// packet into a copy so a test sees the bytes the caller handed over.
// headers are the next headers the packets were sealed under, in the order they were sealed
type recordingPeer struct {
	mu      sync.Mutex
	sent    [][]byte
	headers []byte
	sender  *Peer
}

func (r *recordingPeer) peer(tb testing.TB, id string) *Peer {
	r.sender = NewPeer(id, func(int) (BatchSealer, error) { return r.seal, nil },
		func(sealed [][]byte) error {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.sent = append(r.sent, sealed...)
			return nil
		}, nil)
	tb.Cleanup(r.sender.Close)
	return r.sender
}

func (r *recordingPeer) seal(raw [][]byte, headers []byte, out [][]byte) ([][]byte, error) {
	r.mu.Lock()
	r.headers = append(r.headers, headers...)
	r.mu.Unlock()
	return cloning(raw, headers, out)
}

// packets returns the packets the peer transmitted, once its sender has given
// back all of both its budgets
func (r *recordingPeer) packets(tb testing.TB) [][]byte {
	waitForBudget(tb, r.sender)
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([][]byte(nil), r.sent...)
}

func (r *recordingPeer) nextHeaders() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return bytes.Clone(r.headers)
}

// A node that configures no segments returns the batch it was given, with no
// copy and no allocation, because that is every node on this mesh today.
func TestBatchWithoutSegmentsIsUntouched(t *testing.T) {
	mesh := &Mesh{Routes: NewRouteTable()}
	batch := framed(plainV6(segAddr("2001:db8::1"), segAddr("2001:db8::2"), "one"))
	got := mesh.applySegments(batch, DefaultMTU)
	if &got[0] != &batch[0] || len(got) != len(batch) {
		t.Fatal("a batch with no segments configured was rebuilt")
	}
	if counters := mesh.SegmentCounters(); counters != (SegmentCounters{}) {
		t.Errorf("a node with no segments counted %+v", counters)
	}
}

// An exit takes the outer header off and what was inside goes to the tun in
// place of it, so the batch that comes back carries the inner packet.
// its frame is the tail of the outer packet's, the end of the outer header the headroom in front of it, rather than a copy
func TestExitDeliversWhatWasInside(t *testing.T) {
	exit := segAddr("3fff:1:69c:8c6::1")
	table, err := srv6.NewLocalTable([]srv6.Segment{{SID: schema.AddrFrom(exit), Behavior: srv6.BehaviorEndDT46}}, everySource)
	if err != nil {
		t.Fatal(err)
	}
	mesh := &Mesh{Routes: NewRouteTable()}
	mesh.SetSegments(table)

	inner := plainV6(segAddr("3fff:a::1"), segAddr("3fff:a::2"), "payload")
	outer, err := srv6.Encapsulate(inner, segAddr("3fff:1:69c:98d0::1"), []netip.Addr{exit})
	if err != nil {
		t.Fatal(err)
	}
	passer := plainV6(segAddr("2001:db8::1"), segAddr("2001:db8::2"), "not ours")

	frames := framed(passer, outer)
	left := mesh.applySegments(frames, DefaultMTU)
	if len(left) != 2 {
		t.Fatalf("the batch came back with %d packets", len(left))
	}
	got := unframed(left)
	if !bytes.Equal(got[0], passer) || &left[0][0] != &frames[0][0] {
		t.Error("a packet that was not ours was changed")
	}
	if !bytes.Equal(got[1], inner) {
		t.Error("the exit delivered something other than the inner packet")
	}
	if outerFrame := frames[1]; &left[1][0] != &outerFrame[len(outerFrame)-len(left[1])] {
		t.Error("the exit delivered the inner packet in a frame other than the tail of the outer packet's")
	}
	if counters := mesh.SegmentCounters(); counters.Delivered != 1 || counters.Forwarded != 0 || counters.Dropped != 0 {
		t.Errorf("the exit counted %+v", counters)
	}
}

// A waypoint forwards to the peer the next segment routes to, and the packet
// leaves the batch: writing it to the tun would deliver a packet addressed to
// somebody else's segment to this node's own stack.
func TestWaypointForwardsInsteadOfDelivering(t *testing.T) {
	waypoint := segAddr("3fff:1:69c:8c6::2")
	exit := segAddr("3fff:1:69c:98d6::1")
	table, err := srv6.NewLocalTable([]srv6.Segment{{SID: schema.AddrFrom(waypoint), Behavior: srv6.BehaviorEnd}}, everySource)
	if err != nil {
		t.Fatal(err)
	}
	mesh := &Mesh{Routes: NewRouteTable()}
	mesh.SetSegments(table)
	recorder := &recordingPeer{}
	mesh.Routes.Set(netip.Prefix{}, segPrefix("3fff:1:69c:98d6::/64"), recorder.peer(t, "exit"))

	inner := plainV6(segAddr("3fff:a::1"), segAddr("3fff:a::2"), "payload")
	outer, err := srv6.Encapsulate(inner, segAddr("3fff:1:69c:8c0::1"), []netip.Addr{waypoint, exit})
	if err != nil {
		t.Fatal(err)
	}

	got := mesh.applySegments(framed(outer), DefaultMTU)
	if len(got) != 0 {
		t.Fatalf("a forwarded packet was also delivered to the tun: %v", got)
	}
	sent := recorder.packets(t)
	if len(sent) != 1 {
		t.Fatalf("the waypoint sent %d packets", len(sent))
	}
	if got := netip.AddrFrom16([16]byte(sent[0][24:40])); got != exit {
		t.Errorf("the forwarded packet is addressed to %s, want the next segment %s", got, exit)
	}
	if counters := mesh.SegmentCounters(); counters.Forwarded != 1 || counters.Delivered != 0 {
		t.Errorf("the waypoint counted %+v", counters)
	}
}

// A segment of ours the node cannot act on, and one whose next segment nothing
// routes to, are both counted and dropped rather than written to the tun,
// where they would arrive as undeliverable packets addressed to us.
func TestSegmentsThatCannotBeActedOnAreDropped(t *testing.T) {
	waypoint := segAddr("3fff:1:69c:8c6::2")
	table, err := srv6.NewLocalTable([]srv6.Segment{{SID: schema.AddrFrom(waypoint), Behavior: srv6.BehaviorEnd}}, everySource)
	if err != nil {
		t.Fatal(err)
	}

	// Addressed to our waypoint with no routing header.
	mesh := &Mesh{Routes: NewRouteTable()}
	mesh.SetSegments(table)
	if got := mesh.applySegments(framed(plainV6(segAddr("2001:db8::1"), waypoint, "payload")), DefaultMTU); len(got) != 0 {
		t.Fatalf("a refused segment reached the tun: %v", got)
	}
	if counters := mesh.SegmentCounters(); counters.Dropped != 1 {
		t.Errorf("a refused segment counted %+v", counters)
	}

	// Well formed, and the mesh has no route to the segment after this one.
	unrouted := &Mesh{Routes: NewRouteTable()}
	unrouted.SetSegments(table)
	outer, err := srv6.Encapsulate(
		plainV6(segAddr("3fff:a::1"), segAddr("3fff:a::2"), "payload"),
		segAddr("3fff:1:69c:8c0::1"),
		[]netip.Addr{waypoint, segAddr("3fff:1:69c:98d6::1")})
	if err != nil {
		t.Fatal(err)
	}
	if got := unrouted.applySegments(framed(outer), DefaultMTU); len(got) != 0 {
		t.Fatalf("a segment with nowhere to go reached the tun: %v", got)
	}
	if counters := unrouted.SegmentCounters(); counters.Dropped != 1 || counters.Forwarded != 0 {
		t.Errorf("a segment with nowhere to go counted %+v", counters)
	}
}

// The replacement slice is built from the first packet that is ours, so the
// ones before it have to survive in order. A batch that is all passers keeps
// its own backing array.
func TestPacketsBeforeAndAfterASegmentKeepTheirOrder(t *testing.T) {
	exit := segAddr("3fff:1:69c:8c6::1")
	table, err := srv6.NewLocalTable([]srv6.Segment{{SID: schema.AddrFrom(exit), Behavior: srv6.BehaviorEndDT46}}, everySource)
	if err != nil {
		t.Fatal(err)
	}
	mesh := &Mesh{Routes: NewRouteTable()}
	mesh.SetSegments(table)

	first := plainV6(segAddr("2001:db8::1"), segAddr("2001:db8::a"), "first")
	second := plainV6(segAddr("2001:db8::1"), segAddr("2001:db8::b"), "second")
	last := plainV6(segAddr("2001:db8::1"), segAddr("2001:db8::c"), "last")
	inner := plainV6(segAddr("3fff:a::1"), segAddr("3fff:a::2"), "inner")
	outer, err := srv6.Encapsulate(inner, segAddr("3fff:1:69c:98d0::1"), []netip.Addr{exit})
	if err != nil {
		t.Fatal(err)
	}

	got := unframed(mesh.applySegments(framed(first, second, outer, last), DefaultMTU))
	if len(got) != 4 {
		t.Fatalf("the batch came back with %d packets", len(got))
	}
	for i, want := range [][]byte{first, second, inner, last} {
		if !bytes.Equal(got[i], want) {
			t.Errorf("packet %d is not the one that belongs there", i)
		}
	}
}

// A packet a policy claims leaves encapsulated and is routed by its first
// segment rather than by the address it was addressed to, which is the whole
// point of steering it and the thing a route lookup done first would undo.
func TestSteeredPacketIsRoutedByItsFirstSegment(t *testing.T) {
	exit := segAddr("3fff:1:69c:98d6::1")
	table, err := srv6.NewSteerTable([]srv6.Steer{{
		From: schema.PrefixFrom(segPrefix("3fff:a::17/128")),
		Via:  []schema.Addr{schema.AddrFrom(exit)},
	}}, schema.MustAddr("3fff:1:69c:8c0::1"))
	if err != nil {
		t.Fatal(err)
	}
	mesh := &Mesh{Routes: NewRouteTable()}
	mesh.SetSteering(table)

	inner := plainV6(segAddr("3fff:a::17"), segAddr("2001:4860:4860::8888"), "payload")
	policy := mesh.steerPolicy(segAddr("3fff:a::17"), segAddr("2001:4860:4860::8888"))
	if policy == nil {
		t.Fatal("a packet the policy names was not claimed")
	}
	steered, ok := mesh.steer(nil, inner, policy)
	if !ok {
		t.Fatal("a packet the policy names was not steered")
	}
	if len(steered) != len(inner)+srv6.Overhead(1) {
		t.Fatalf("the steered packet is %d bytes, want %d", len(steered), len(inner)+srv6.Overhead(1))
	}
	if got := netip.AddrFrom16([16]byte(steered[24:40])); got != exit {
		t.Errorf("the steered packet is addressed to %s, want the first segment %s", got, exit)
	}
	if counters := mesh.SegmentCounters(); counters.Steered != 1 || counters.Unsteered != 0 {
		t.Errorf("steering counted %+v", counters)
	}

	// A packet from another address is claimed by no policy.
	if policy := mesh.steerPolicy(segAddr("3fff:a::18"), segAddr("2001:4860:4860::8888")); policy != nil {
		t.Errorf("a packet no policy names was claimed by %v", policy)
	}
}

// A packet a policy claims and cannot encapsulate is dropped rather than sent
// as it was, and the counter says it happened: the policy selects an exit, so
// the route this packet would otherwise take puts it out of a different node
// under a source that node does not announce. A packet whose encapsulation
// would carry more than an IPv6 payload length counts is one srv6 refuses.
func TestPacketThatCannotBeSteeredIsDropped(t *testing.T) {
	table, err := srv6.NewSteerTable([]srv6.Steer{{
		From: schema.PrefixFrom(segPrefix("3fff:a::17/128")),
		Via:  []schema.Addr{schema.MustAddr("3fff:1:69c:98d6::1")},
	}}, schema.MustAddr("3fff:1:69c:8c0::1"))
	if err != nil {
		t.Fatal(err)
	}
	mesh := &Mesh{Routes: NewRouteTable()}
	mesh.SetSteering(table)

	// RFC 8200 section 3, the payload length is 16 bits and counts the 8 + 16 bytes of the routing header too
	inner := plainV6(segAddr("3fff:a::17"), segAddr("2001:4860:4860::8888"), string(make([]byte, 0xffff-8-16-40+1)))
	original := bytes.Clone(inner)
	side := make([]byte, 3, 64)
	steered, ok := mesh.steer(side, inner, mesh.steerPolicy(segAddr("3fff:a::17"), segAddr("2001:4860:4860::8888")))
	if ok || len(steered) != len(side) || cap(steered) != cap(side) {
		t.Fatalf("a packet that could not be encapsulated reported %v with %d bytes in its side buffer", ok, len(steered))
	}
	if !bytes.Equal(inner, original) {
		t.Error("a packet that could not be steered was changed anyway")
	}
	if counters := mesh.SegmentCounters(); counters.Unsteered != 1 || counters.Steered != 0 {
		t.Errorf("a refused encapsulation counted %+v", counters)
	}
}

// A whole inbound batch of waypointed packets reserves once for each peer, as
// a tun read does: one ticket, one sequence range and one seal for the share,
// rather than one of each per packet.
func TestWaypointBatchTakesOnePlacePerPeer(t *testing.T) {
	waypoint := segAddr("3fff:1:69c:8c6::2")
	table, err := srv6.NewLocalTable([]srv6.Segment{{SID: schema.AddrFrom(waypoint), Behavior: srv6.BehaviorEnd}}, everySource)
	if err != nil {
		t.Fatal(err)
	}
	exit := segAddr("3fff:1:69c:98d6::1")

	// The peer is asked to reserve for a number of packets, and seals once per
	// reserved batch, so the two together say how the batch was split.
	var batches, reserved, forwarded atomic.Int64
	peer := NewPeer("next", func(n int) (BatchSealer, error) {
		reserved.Add(int64(n))
		return func(raw [][]byte, _ []byte, out [][]byte) ([][]byte, error) {
			batches.Add(1)
			forwarded.Add(int64(len(raw)))
			return out[:0], nil
		}, nil
	}, func([][]byte) error { return nil }, nil)
	defer peer.Close()

	m := &Mesh{Routes: NewRouteTable()}
	m.startSegmentReports()
	m.SetSegments(table)
	m.Routes.Set(netip.Prefix{}, netip.MustParsePrefix("3fff:1:69c:98d6::1/128"), peer)

	const count = 64
	batch := make([][]byte, 0, count)
	for range count {
		outer, err := srv6.Encapsulate(
			plainV6(segAddr("3fff:a::1"), segAddr("3fff:a::2"), "payload"),
			segAddr("3fff:1:69c:8c0::1"), []netip.Addr{waypoint, exit})
		if err != nil {
			t.Fatal(err)
		}
		batch = append(batch, outer)
	}
	if left := m.applySegments(framed(batch...), DefaultMTU); len(left) != 0 {
		t.Fatalf("%d waypointed packets reached the tun", len(left))
	}
	if got := batches.Load(); got != 1 {
		t.Errorf("a batch of %d waypointed packets was split into %d, want one for the peer", count, got)
	}
	// The budget counts packets, so the reservation names every packet the
	// share carries, or the share holds less of the budget than it uses.
	if got := reserved.Load(); got != count {
		t.Errorf("the peer reserved for %d packets and was handed %d", got, count)
	}
	if got := forwarded.Load(); got != count {
		t.Errorf("the peer was handed %d of %d packets", got, count)
	}
	if got := m.SegmentCounters(); got.Forwarded != count || got.Dropped != 0 {
		t.Errorf("the batch forwarded %d and dropped %d of %d", got.Forwarded, got.Dropped, count)
	}
}

// a node sending refused headers in a loop gets its own bucket's burst and refill and no more, RFC 4443 section 2.4 (f)
// while the counters keep the whole record, and a second node's refused header is answered after the flood as before it
func TestRefusedPacketsAreAnsweredAtABoundedRate(t *testing.T) {
	waypoint := segAddr("3fff:1:69c:8c6::2")
	table, err := srv6.NewLocalTable([]srv6.Segment{{SID: schema.AddrFrom(waypoint), Behavior: srv6.BehaviorEnd}}, everySource)
	if err != nil {
		t.Fatal(err)
	}
	recorder := &recordingPeer{}
	m := &Mesh{Routes: NewRouteTable()}
	m.startSegmentReports()
	m.SetSegments(table)
	// The error goes back to the node that encapsulated the packet, so the
	// route that has to exist is the one to its tunnel source.
	m.Routes.Set(netip.Prefix{}, segPrefix("3fff:1:69c::/48"), recorder.peer(t, "sender"))

	// A segment list this node will not act on, which is the refusal RFC 8986
	// section 4.1 S10 answers with a Parameter Problem.
	refused := func(from netip.Addr) []byte {
		outer, err := srv6.Encapsulate(
			plainV6(segAddr("3fff:a::1"), segAddr("3fff:a::2"), "payload"),
			from, []netip.Addr{waypoint, segAddr("3fff:1:69c:98d6::1")})
		if err != nil {
			t.Fatal(err)
		}
		outer[ipv6HeaderOffsetSegmentsLeft] = 9 // past the last entry
		return outer
	}
	const flood = 500
	batch := make([][]byte, 0, flood)
	for range flood {
		batch = append(batch, refused(segAddr("3fff:1:69c:8c0::1")))
	}
	m.applySegments(framed(batch...), DefaultMTU)

	// the bucket starts full with 6 and earns one back every 100 milliseconds since the mesh started
	most := 6 + uint64(time.Since(m.segmentsStarted)/(100*time.Millisecond))
	counters := m.SegmentCounters()
	if counters.Dropped != flood {
		t.Errorf("%d of %d refused packets were counted", counters.Dropped, flood)
	}
	if counters.Answered < 6 || counters.Answered > most {
		t.Errorf("%d answers went out for %d refused packets from one source, want from the burst of 6 to %d", counters.Answered, flood, most)
	}
	if source, node := m.ICMPWithheld(); source != flood-counters.Answered || node != 0 {
		t.Errorf("the limits withheld %d answers by source and %d by the node's cap, want %d and 0", source, node, flood-counters.Answered)
	}
	m.applySegments(framed(refused(segAddr("3fff:1:69c:8c1::1"))), DefaultMTU)
	if got := m.SegmentCounters().Answered; got != counters.Answered+1 {
		t.Errorf("a second source's refused packet after the flood was answered %d times, want once", got-counters.Answered)
	}
	sent := recorder.packets(t)
	if uint64(len(sent)) != counters.Answered+1 {
		t.Errorf("%d packets went to the peer against %d counted", len(sent), counters.Answered+1)
	}
	// RFC 8986 section 4.1 S10 points at Segments Left
	for i, answer := range sent {
		if kind, code, pointer := answer[40], answer[41], binary.BigEndian.Uint32(answer[44:48]); kind != 4 || code != 0 || pointer != ipv6HeaderOffsetSegmentsLeft {
			t.Errorf("answer %d is ICMPv6 type %d code %d pointing at %d, want parameter problem code 0 pointing at %d", i, kind, code, pointer, ipv6HeaderOffsetSegmentsLeft)
		}
	}
}

// a segment whose hop limit runs out at an End SID of this node gets one time exceeded, code 0, RFC 8986 section 4.1 S06 and RFC 4443 section 3.3
// from that SID back to the node that steered it, and goes no further
func TestHopLimitRunningOutAtAWaypointIsAnsweredWithTimeExceeded(t *testing.T) {
	waypoint, steerer := segAddr("3fff:1:69c:8c6::2"), segAddr("3fff:1:69c:8c0::1")
	table, err := srv6.NewLocalTable([]srv6.Segment{{SID: schema.AddrFrom(waypoint), Behavior: srv6.BehaviorEnd}}, everySource)
	if err != nil {
		t.Fatal(err)
	}
	recorder := &recordingPeer{}
	m := &Mesh{Routes: NewRouteTable()}
	m.startSegmentReports()
	m.SetSegments(table)
	// the steering node and the next segment share one route, so a segment that went on would reach the recorder too
	m.Routes.Set(netip.Prefix{}, segPrefix("3fff:1:69c::/48"), recorder.peer(t, "sender"))
	outer, err := srv6.Encapsulate(plainV6(segAddr("3fff:a::1"), segAddr("3fff:a::2"), "payload"), steerer, []netip.Addr{waypoint, segAddr("3fff:1:69c:98d6::1")})
	if err != nil {
		t.Fatal(err)
	}
	outer[7] = 1
	m.applySegments(framed(outer), DefaultMTU)
	sent := recorder.packets(t)
	if len(sent) != 1 {
		t.Fatalf("a segment whose hop limit ran out here sent %d packets, want its one answer", len(sent))
	}
	answer := sent[0]
	if answer[6] != 58 || answer[40] != 3 || answer[41] != 0 {
		t.Errorf("the answer is next header %d, ICMPv6 type %d code %d, want time exceeded code 0", answer[6], answer[40], answer[41])
	}
	if from, to := netip.AddrFrom16([16]byte(answer[8:24])), netip.AddrFrom16([16]byte(answer[24:40])); from != waypoint || to != steerer {
		t.Errorf("the answer goes from %s to %s, want from %s to %s", from, to, waypoint, steerer)
	}
	if counters := m.SegmentCounters(); counters.Dropped != 1 || counters.Answered != 1 || counters.Forwarded != 0 {
		t.Errorf("the waypoint counted %+v, want the segment dropped and answered once", counters)
	}
}

// a refused packet past its source's bucket, or past the node's cap, costs no answer built, since the builder draws before it builds
// and so do packets past their session past the cap, of either family
func TestPacketsPastALimitBuildNoAnswer(t *testing.T) {
	from := segAddr("3fff:1:69c:8c0::1")
	outer, err := srv6.Encapsulate(plainV6(segAddr("3fff:a::1"), segAddr("3fff:a::2"), "payload"), from, []netip.Addr{segAddr("3fff:1:69c:8c6::2")})
	if err != nil {
		t.Fatal(err)
	}
	tooBig6 := udpPacket(tooBigSource[6], tooBigDestination[6], DefaultMTU, false)
	tooBig4 := udpPacket(tooBigSource[4], tooBigDestination[4], DefaultMTU, true)
	answerTooBig := func(inner []byte) func(m *Mesh) bool {
		return func(m *Mesh) bool {
			answer, _ := m.answerTooBig(inner, srv6.MinimumIPv6MTU, false, netip.Addr{})
			return answer != nil
		}
	}
	for _, c := range []struct {
		name   string
		spend  func(m *Mesh)
		answer func(m *Mesh) bool
	}{
		{"a refused packet past its source's bucket", func(m *Mesh) {
			for m.takeICMPToken(from) {
			}
		}, func(m *Mesh) bool { m.answerRefused(outer, srv6.ErrHeaderInvalid); return false }},
		{"a refused packet past the cap", func(m *Mesh) { capHolding(m, 0) }, func(m *Mesh) bool { m.answerRefused(outer, srv6.ErrHopLimit); return false }},
		{"packet too big past the cap", func(m *Mesh) { capHolding(m, 0) }, answerTooBig(tooBig6)},
		{"fragmentation needed past the cap", func(m *Mesh) { capHolding(m, 0) }, answerTooBig(tooBig4)},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := &Mesh{Routes: NewRouteTable()}
			m.startSegmentReports()
			m.SetAnswerTTL(64)
			c.spend(m)
			answered := false
			if allocs := testing.AllocsPerRun(100, func() { answered = c.answer(m) || answered }); allocs != 0 || answered {
				t.Errorf("%s cost %.0f allocations and was answered %t, want none and no answer", c.name, allocs, answered)
			}
		})
	}
}

// a packet no error may answer spends nothing of the node's cap or of its source's bucket, and counts nothing withheld
// on each path an answer takes, a segment refused here, packet too big and fragmentation needed, an IPv4 header whose checksum fails among them
// and so does a packet to a multicast group past its session, which gets no packet too big, departing from RFC 4443 section 3.2
// a stream of them twice the cap long leaves the limit as it found it, and an answerable packet after it is answered
func TestPacketsNoErrorAnswersLeaveTheLimitsUntouched(t *testing.T) {
	const stream = 2 * icmpNodeBurst
	waypoint := segAddr("3fff:1:69c:8c6::2")
	refused := func(damage func(outer []byte)) []byte {
		outer, err := srv6.Encapsulate(plainV6(segAddr("3fff:a::1"), segAddr("3fff:a::2"), "payload"), segAddr("3fff:1:69c:8c0::1"), []netip.Addr{waypoint, segAddr("3fff:1:69c:98d6::1")})
		if err != nil {
			t.Fatal(err)
		}
		damage(outer)
		return outer
	}
	// the routing header of two segments ends 80 bytes in, where the packet it carries starts
	// an ICMPv6 error behind a first fragment, offset 0 with M set, or behind an AH of 24 octets, RFC 8200 section 4.5 and RFC 4302 section 2.2
	behindFragment := []byte{58, 0, 0, 1, 0, 0, 0, 7, 1}
	behindAH := append(append([]byte{58, 4}, make([]byte, 22)...), 1)
	refusedCases := map[string][]byte{
		"a segment refused at a multicast destination":                       refused(func(outer []byte) { copy(outer[24:40], segAddr("ff02::1").AsSlice()) }),
		"a segment refused from the unspecified source":                      refused(func(outer []byte) { copy(outer[8:24], segAddr("::").AsSlice()) }),
		"a segment refused carrying an icmpv6 error":                         refused(func(outer []byte) { outer[40], outer[80] = 58, 1 }),
		"a segment refused carrying an icmpv6 error behind a first fragment": refused(func(outer []byte) { outer[40] = 44; copy(outer[80:], behindFragment) }),
		"a segment refused carrying an icmpv6 error behind ah":               refused(func(outer []byte) { outer[40] = 51; copy(outer[80:], behindAH) }),
	}
	for name, offending := range refusedCases {
		t.Run(name, func(t *testing.T) {
			recorder := &recordingPeer{}
			m := &Mesh{Routes: NewRouteTable()}
			m.startSegmentReports()
			m.Routes.Set(netip.Prefix{}, segPrefix("::/0"), recorder.peer(t, "sender"))
			for range stream {
				m.answerRefused(offending, srv6.ErrHopLimit)
			}
			untouched(t, m)
			m.answerRefused(refused(func([]byte) {}), srv6.ErrHopLimit)
			if sent := len(recorder.packets(t)); sent != 1 {
				t.Errorf("%d answers went out, want the one to the answerable segment after the stream", sent)
			}
		})
	}

	tooBig6 := func(source, destination netip.Addr) []byte { return udpPacket(source, destination, DefaultMTU, false) }
	tooBig4 := func(source, destination netip.Addr) []byte { return udpPacket(source, destination, DefaultMTU, true) }
	icmp6Error := tooBig6(tooBigSource[6], tooBigDestination[6])
	icmp6Error[6], icmp6Error[40] = 58, 1
	icmp6ErrorBehindFragment := tooBig6(tooBigSource[6], tooBigDestination[6])
	icmp6ErrorBehindFragment[6] = 44
	copy(icmp6ErrorBehindFragment[40:], behindFragment)
	icmp6ErrorBehindAH := tooBig6(tooBigSource[6], tooBigDestination[6])
	icmp6ErrorBehindAH[6] = 51
	copy(icmp6ErrorBehindAH[40:], behindAH)
	icmp4Error := tooBig4(tooBigSource[4], tooBigDestination[4])
	icmp4Error[9], icmp4Error[20] = 1, 3
	binary.BigEndian.PutUint16(icmp4Error[10:], 0)
	binary.BigEndian.PutUint16(icmp4Error[10:], ^uint16(packet.Sum(0, icmp4Error[:20])))
	damaged4 := tooBig4(tooBigSource[4], tooBigDestination[4])
	damaged4[10] ^= 0x01
	answerable6, answerable4 := tooBig6(tooBigSource[6], tooBigDestination[6]), tooBig4(tooBigSource[4], tooBigDestination[4])
	tooBigCases := map[string]struct{ offending, answerable []byte }{
		"packet too big to a multicast group, a departure from rfc 4443 section 3.2":      {tooBig6(tooBigSource[6], segAddr("ff0e::1")), answerable6},
		"packet too big from the unspecified source":                                      {tooBig6(segAddr("::"), tooBigDestination[6]), answerable6},
		"packet too big to an icmpv6 error":                                               {icmp6Error, answerable6},
		"packet too big to an icmpv6 error behind a first fragment":                       {icmp6ErrorBehindFragment, answerable6},
		"packet too big to an icmpv6 error behind ah":                                     {icmp6ErrorBehindAH, answerable6},
		"fragmentation needed to a multicast group":                                       {tooBig4(tooBigSource[4], segAddr("239.1.2.3")), answerable4},
		"fragmentation needed to the limited broadcast":                                   {tooBig4(tooBigSource[4], segAddr("255.255.255.255")), answerable4},
		"fragmentation needed from this network":                                          {tooBig4(segAddr("0.1.2.3"), tooBigDestination[4]), answerable4},
		"fragmentation needed to an icmp error":                                           {icmp4Error, answerable4},
		"fragmentation needed to a header whose checksum fails, rfc 1812 section 4.3.2.7": {damaged4, answerable4},
	}
	for name, c := range tooBigCases {
		t.Run(name, func(t *testing.T) {
			m := &Mesh{Routes: NewRouteTable()}
			m.startSegmentReports()
			m.SetAnswerTTL(64)
			for range stream {
				if answer, cut := m.answerTooBig(c.offending, srv6.MinimumIPv6MTU, false, netip.Addr{}); answer != nil || cut {
					t.Fatalf("a packet no error may answer was answered %t or cut %t", answer != nil, cut)
				}
			}
			untouched(t, m)
			if answer, _ := m.answerTooBig(c.answerable, srv6.MinimumIPv6MTU, false, netip.Addr{}); answer == nil {
				t.Error("an answerable packet after the stream was not answered")
			}
		})
	}
}

// ipv6HeaderOffsetSegmentsLeft is where Segments Left sits in a packet whose
// routing header follows the fixed header.
const ipv6HeaderOffsetSegmentsLeft = 40 + 3

// A segment list may name two segments of one node, which the fleet's own
// addressing makes spellable: an End and an End.DT46 sit on the same node.
// A kernel repeats its FIB lookup after a waypoint rewrites the destination
// and acts on the second, and a node that only consulted its mesh routes would
// drop the packet one hop short, because a node has no route to itself.
func TestTwoSegmentsOfThisNodeInOneListAreBothActedOn(t *testing.T) {
	waypoint, exit := segAddr("3fff:1:69c:8c6::2"), segAddr("3fff:1:69c:8c6::1")
	table, err := srv6.NewLocalTable([]srv6.Segment{
		{SID: schema.AddrFrom(waypoint), Behavior: srv6.BehaviorEnd},
		{SID: schema.AddrFrom(exit), Behavior: srv6.BehaviorEndDT46},
	}, everySource)
	if err != nil {
		t.Fatal(err)
	}
	mesh := &Mesh{Routes: NewRouteTable()}
	mesh.startSegmentReports()
	mesh.SetSegments(table)

	inner := plainV6(segAddr("3fff:a::1"), segAddr("3fff:a::2"), "payload")
	outer, err := srv6.Encapsulate(inner, segAddr("3fff:1:69c:8c0::1"), []netip.Addr{waypoint, exit})
	if err != nil {
		t.Fatal(err)
	}
	got := unframed(mesh.applySegments(framed(outer), DefaultMTU))
	if len(got) != 1 || !bytes.Equal(got[0], inner) {
		t.Fatalf("the exit on this node did not deliver the inner packet: %v", got)
	}
	if counters := mesh.SegmentCounters(); counters.Delivered != 1 || counters.Dropped != 0 {
		t.Errorf("a list naming two of this node's segments counted %+v", counters)
	}
}

// The report interval is measured on the monotonic clock, which needs a start.
// time.Since of a zero time saturates, so a counter set that was never started
// would report once and then suppress everything for 292 years, which is the
// failure a rate limit exists to prevent rather than to cause.
func TestDropReportsSurviveACounterSetThatWasNeverStarted(t *testing.T) {
	lines := countRecords(t)

	started := &Mesh{Routes: NewRouteTable()}
	started.startSegmentReports()
	for range 3 {
		started.reportSegmentDrop("spaced")
	}
	if got := *lines; got != 1 {
		t.Errorf("a started set wrote %d lines for three drops, want one", got)
	}

	*lines = 0
	var unstarted Mesh
	if !unstarted.segmentsStarted.IsZero() {
		t.Fatal("the unstarted case is no longer reachable, so this is not testing it")
	}
	for range 3 {
		unstarted.reportSegmentDrop("still speaking")
	}
	if got := *lines; got != 3 {
		t.Errorf("an unstarted set wrote %d lines for three drops, want every one", got)
	}
}

// countRecords points the default logger at a counter for the test's duration.
func countRecords(t *testing.T) *int {
	t.Helper()
	counter := new(int)
	logtest.SetDefault(t, slog.New(countingHandler{n: counter}))
	return counter
}

type countingHandler struct{ n *int }

func (h countingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h countingHandler) Handle(context.Context, slog.Record) error {
	*h.n++
	return nil
}
func (h countingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h countingHandler) WithGroup(string) slog.Handler      { return h }
