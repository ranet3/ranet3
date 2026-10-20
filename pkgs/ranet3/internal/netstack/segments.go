// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"errors"
	"log/slog"
	"net/netip"
	"sync/atomic"
	"time"

	"ranet3.com/pkgs/ranet3/internal/packet"
	"ranet3.com/pkgs/ranet3/srv6"
)

// This file is where segment routing meets the dataplane. The decision itself
// is in package srv6, which takes bytes and returns bytes. Here is the part
// that knows about peers, about the tun and about backpressure.
//
// It sits on the inbound path rather than on the kernel's forwarding table
// because a decrypted packet passes through this process before anything else
// sees it, and because three of the four platforms this tree builds for have
// no forwarding table to put a local SID in.

// errNotIP is a waypoint's result that is no longer an IP packet, which
// cannot happen while End only rewrites two fields, and is reported rather
// than silently dropped so that a change which made it possible is visible.
var errNotIP = errors.New("netstack: a forwarded segment is not an IP packet")

// SetSteering installs the table deciding which of this node's own packets go
// through a segment list, or nil for none. Like SetSegments it is called
// before the device carries anything and read on the hot path, so the pointer
// is swapped rather than the table mutated.
func (m *Mesh) SetSteering(table *srv6.SteerTable) { m.steerTable.Store(table) }

// Steering is the table currently installed.
func (m *Mesh) Steering() *srv6.SteerTable { return m.steerTable.Load() }

// SetSteeringEnabled stops or starts steering without taking the table away,
// so a diagnostic still reports the policies that would apply and an operator
// can see what was stopped. A packet already encapsulated is not unwound: the
// flag decides the packets looked at after it is stored, exactly as the table
// pointer does.
func (m *Mesh) SetSteeringEnabled(on bool) { m.steerStopped.Store(!on) }

// SteeringEnabled reports whether the policies are being acted on.
func (m *Mesh) SteeringEnabled() bool { return !m.steerStopped.Load() }

// steerPolicy is the policy that claims one outbound packet, nil for one no policy claims
// a packet no policy claims costs one trie lookup, the same lookup the forwarding table is about to do anyway
func (m *Mesh) steerPolicy(source, destination netip.Addr) *srv6.Policy {
	table := m.steerTable.Load()
	// The stop is read after the table, so a node that steers nothing pays the
	// one load it already paid and the second is on the nodes that do steer.
	if table == nil || m.steerStopped.Load() {
		return nil
	}
	return table.Lookup(source, destination)
}

// steer appends raw, encapsulated under policy, to dst, never touching raw
// false is a packet the policy claimed and this node could not encapsulate, which is dropped rather than sent as it was
//
// A steering policy here selects an exit, so sending the packet by the metric
// instead puts it out of a different node under a source address that node
// does not announce, which is a wrong path rather than a degraded one. Every
// reason the encapsulation can fail is refused when the configuration is
// read, so what is left needs a packet larger than the device MTU this node
// set, and that is a deployment to fix rather than to carry.
func (m *Mesh) steer(dst, raw []byte, policy *srv6.Policy) ([]byte, bool) {
	encapsulated, err := srv6.AppendEncapsulated(dst, raw, policy.Source, policy.Path)
	if err != nil {
		m.segmentsUnsteered.Add(1)
		m.reportSegmentDrop("a packet a policy claimed could not be encapsulated", "policy", policy, "err", err)
		return dst, false
	}
	m.segmentsSteered.Add(1)
	return encapsulated, true
}

// SetSegments installs the segments this node answers for, or nil for none.
// It is called before any session exists and read on the inbound path, so the
// pointer is swapped rather than the table mutated.
func (m *Mesh) SetSegments(table *srv6.LocalTable) { m.segmentTable.Store(table) }

// Segments is the table currently installed, for a diagnostic to report.
func (m *Mesh) Segments() *srv6.LocalTable { return m.segmentTable.Load() }

// SegmentCounters records how this node has acted as a waypoint and as an
// exit.
type SegmentCounters struct {
	// Forwarded counts the packets sent on to a next segment
	// a segment cut to fit the session to it counts once for each of its fragments
	Forwarded uint64
	Delivered uint64
	Dropped   uint64
	// Steered counts this node's own packets that a policy encapsulated,
	// Unsteered the ones a policy claimed and this node could not, and
	// Unrouted the ones it encapsulated and the mesh had no route to the
	// first segment of. Both failures drop the packet rather than send it by
	// the route the policy exists to override, and both are this node's own
	// steering rather than anything a peer did, so neither is counted in
	// Dropped.
	Steered   uint64
	Unsteered uint64
	Unrouted  uint64
	// Answered counts the ICMP errors sent for dropped packets, which is the
	// half of Dropped a sender was told about.
	Answered uint64
	// Egressed counts the packets the egress device accepted
	Egressed uint64
	// Refused counts the packets a local SID refused for their source, an outer source outside cap.border overlay at any SID or, at an egress segment, a source outside its allow list or an inner source it cannot read, a part of Dropped never answered
	Refused uint64
	// NotReady counts the egress results dropped with no egress device installed, closed under the write or not ready for their family
	// it is this node's own state, so it is not in Dropped
	NotReady uint64
	// Drained counts the packets read off the egress device and thrown away, each one a route into the wrong device
	// a packet to an IPv6 multicast address of interface-local or link-local scope is the kernel's own and not counted
	Drained uint64
}

func (m *Mesh) SegmentCounters() SegmentCounters {
	return SegmentCounters{
		Forwarded: m.segmentsForwarded.Load(),
		Delivered: m.segmentsDelivered.Load(),
		Dropped:   m.segmentsDropped.Load(),
		Steered:   m.segmentsSteered.Load(),
		Unsteered: m.segmentsUnsteered.Load(),
		Unrouted:  m.segmentsUnrouted.Load(),
		Answered:  m.segmentsAnswered.Load(),
		Egressed:  m.segmentsEgressed.Load(),
		Refused:   m.segmentsRefused.Load(),
		NotReady:  m.segmentsNotReady.Load(),
		Drained:   m.segmentsDrained.Load(),
	}
}

// applySegments takes the frames whose packets are addressed to this node's
// own segments out of an inbound batch, acts on each, and returns the frames
// left to be written to the tun.
// a packet an exit takes out of its outer header leaves in the tail of its own frame, the end of the header it lost being its headroom
// mtu is the largest packet the session the batch came through carries
// a SYN an End.DT46 delivers or egresses has its MSS clamped to it here, since the session's clamp saw only the outer header
func (m *Mesh) applySegments(frames [][]byte, mtu int) [][]byte {
	table := m.segmentTable.Load()
	if table == nil {
		return frames
	}
	return m.actOnSegments(frames, mtu, func(packet []byte) srv6.Result { return actLocally(table, packet) })
}

func (m *Mesh) actOnSegments(frames [][]byte, mtu int, act func([]byte) srv6.Result) [][]byte {
	var deliver, egress [][]byte
	take := func(i int) {
		if deliver == nil {
			deliver = append(make([][]byte, 0, len(frames)), frames[:i]...)
		}
	}
	var forward []forwardedSegment
	var ready uint32
	readyRead := false
	for i, frame := range frames {
		packet := frame[TUNHeadroom:]
		result := act(packet)
		switch result.Action {
		case srv6.ActionPass:
			if deliver != nil {
				deliver = append(deliver, frame)
			}
		case srv6.ActionDeliver:
			take(i)
			m.segmentsDelivered.Add(1)
			m.ClampMSS(result.Inner, mtu)
			// Decap hands back the tail of the packet it was given, behind at least the fixed header
			deliver = append(deliver, frame[len(frame)-TUNHeadroom-len(result.Inner):])
		case srv6.ActionEgress:
			take(i)
			if !readyRead {
				ready, readyRead = m.egressReady.Load(), true
			}
			// a packet written while its family's translation is missing leaves the uplink untranslated
			if ready&egressReadyFor(result.Family) == 0 {
				m.segmentsNotReady.Add(1)
				continue
			}
			m.ClampMSS(result.Inner, mtu)
			if egress == nil {
				egress = make([][]byte, 0, len(frames)-i)
			}
			egress = append(egress, frame[len(frame)-TUNHeadroom-len(result.Inner):])
		case srv6.ActionForward:
			take(i)
			forward = append(forward, forwardedSegment{raw: packet, next: result.Next})
		case srv6.ActionDrop:
			take(i)
			m.noteSegmentDrop(result.Err)
			m.answerRefused(packet, result.Err)
		default:
			take(i)
			m.segmentsDropped.Add(1)
			m.reportSegmentDrop("a segment's result names an action this node does not act on", "action", result.Action)
		}
	}
	m.forwardSegments(forward)
	m.writeEgress(egress)
	if deliver == nil {
		return frames
	}
	return deliver
}

// actLocally runs this node's own segments until the packet is going somewhere
// else. A kernel repeats its FIB lookup after a waypoint rewrites the
// destination, so a list naming two segments of one node is acted on twice
// there, and consulting the table again does the same here. Without it the
// second segment has no mesh route, because a node does not route to itself,
// and the packet is dropped one hop short.
//
// The number of times is bounded by the longest list this node acts on rather
// than by the hop limit, which the peer chooses.
func actLocally(table *srv6.LocalTable, packet []byte) srv6.Result {
	result := table.Handle(packet)
	for range srv6.MaxSegments {
		if result.Action != srv6.ActionForward {
			return result
		}
		again := table.Handle(packet)
		if again.Action == srv6.ActionPass {
			return result
		}
		result = again
	}
	return result
}

// forwardedSegment is one waypointed packet between the decision and the send,
// held so that a whole batch can be reserved for at once.
type forwardedSegment struct {
	raw        []byte
	next       netip.Addr
	peer       *Peer
	nextHeader byte
}

// forwardSegments sends the packets a waypoint has rewritten on to the peers
// their new destinations select.
//
// Each peer's share of the batch takes one ticket and one sequence range and
// is sealed in one call, as a share of a tun read is, against the bytes of the
// peer's budget it carries.
//
// The budget is the peer's ordinary one rather than the control budget babel
// runs on, because this is somebody else's traffic: a segment list pointed at
// this node must not be able to spend the allowance this node's own routing
// protocol needs. A peer whose budget has no room for its share drops it and
// counts it, the way a full egress queue drops.
func (m *Mesh) forwardSegments(segments []forwardedSegment) {
	if len(segments) == 0 {
		return
	}
	// Sized for the peers a batch names, one in the ordinary case, rather than
	// for its packets.
	counts := make(map[*Peer]outboundShare)
	order := make([]*Peer, 0, 4)
	// cut holds the fragments of the segments too large for their next sessions
	var cut fragmentList
	for i := range segments {
		segment := &segments[i]
		src, dst, nextHeader, ok := addrsOf(segment.raw)
		if !ok {
			m.noteSegmentDrop(errNotIP)
			continue
		}
		peer, verdict := m.Routes.Resolve(src, dst)
		if verdict != RoutePeer || peer == nil {
			m.segmentsDropped.Add(1)
			m.reportSegmentDrop("no route to the next segment", "segment", segment.next)
			continue
		}
		share, seen := counts[peer]
		if !seen {
			share.mtu = peer.MTU()
			order = append(order, peer)
		}
		if len(segment.raw) > share.mtu {
			count, bytes := m.segmentTooBig(&cut, segment, peer, nextHeader, share.mtu)
			share.count += count
			share.bytes += bytes
		} else {
			share.count++
			share.bytes += len(segment.raw)
			segment.peer, segment.nextHeader = peer, nextHeader
		}
		counts[peer] = share
	}
	batches := make(map[*Peer]*peerBatch, len(order))
	for _, peer := range order {
		share := counts[peer]
		if share.count == 0 {
			continue
		}
		batch := peer.reserveBatchNow(share.count, share.bytes)
		if batch == nil {
			m.segmentsDropped.Add(uint64(share.count))
			continue
		}
		batches[peer] = batch
	}
	for _, segment := range segments {
		if batch := batches[segment.peer]; batch != nil {
			batch.append(segment.raw, segment.nextHeader)
		}
	}
	cut.appendTo(batches)
	for _, peer := range order {
		batch := batches[peer]
		if batch == nil {
			continue
		}
		if err := batch.enqueue(); err != nil {
			m.segmentsDropped.Add(uint64(counts[peer].count))
			m.reportSegmentDrop("the transport lost a forwarded segment", "err", err)
			continue
		}
		m.segmentsForwarded.Add(uint64(counts[peer].count))
	}
}

func (m *Mesh) noteSegmentDrop(err error) {
	m.segmentsDropped.Add(1)
	if errors.Is(err, srv6.ErrSourceRefused) {
		m.segmentsRefused.Add(1)
	}
	m.reportSegmentDrop("a packet addressed to one of this node's segments was refused", "err", err)
}

// answerRefused sends the ICMP error RFC 8986 section 4.1 answers a refused
// packet with, S06 for a hop limit that ran out here and S10 for a header this
// node will not act on. Everything else is dropped in silence, because an
// error is only worth sending where it names something the sender can fix.
//
// The budget is the whole of the bound. An error is a packet a peer's packet
// caused this node to send, which is the shape every amplification this tree
// has had took, and RFC 4443 section 2.4 (f) requires a limit for that reason.
// A burst covers a traceroute's three probes per hop, and the refill bounds a
// node sending refused headers in a loop.
func (m *Mesh) answerRefused(offending []byte, reason error) {
	var answer []byte
	var ok bool
	source := netip.AddrFrom16([16]byte(offending[24:40]))
	switch {
	case errors.Is(reason, srv6.ErrHopLimit):
		answer, ok = srv6.TimeExceeded(offending, source)
	case errors.Is(reason, srv6.ErrHeaderInvalid):
		answer, ok = srv6.ParameterProblem(offending, source)
	}
	if !ok || !m.takeICMPToken() {
		return
	}
	m.sendBack(answer)
}

// segmentTooBig takes a forwarded segment larger than mtu, the largest the session to its next segment carries
// the packet it carries is held to mtu less the headers in front of it, which each fragment keeps
// it reports how many fragments it queued in cut and their bytes, and an answer goes back through the mesh
func (m *Mesh) segmentTooBig(cut *fragmentList, segment *forwardedSegment, peer *Peer, nextHeader byte, mtu int) (int, int) {
	var answer []byte
	if offset, ok := carriedPacket(segment.raw); ok {
		inner := segment.raw[offset:]
		var fragment bool
		if answer, fragment = m.answerTooBig(inner, mtu-offset); fragment {
			if count, bytes := cut.add(peer, nextHeader, segment.raw[:offset], inner, mtu); count != 0 {
				return count, bytes
			}
		}
	}
	m.segmentsDropped.Add(1)
	m.reportSegmentDrop("a forwarded segment is larger than the session to its next segment carries", "segment", segment.next, "mtu", mtu)
	if answer != nil && m.sendBack(answer) {
		m.tooBigAnswered.Add(1)
	}
	return 0, 0
}

// carriedPacket is the offset of the IP packet behind the routing header of raw, which runs to its end
// it reports false for a routing header naming anything else next, and for a packet other than the one it names
func carriedPacket(raw []byte) (int, bool) {
	header, err := srv6.Parse(raw)
	if err != nil {
		return 0, false
	}
	// RFC 8754 section 2, a routing header is 8 bytes and Hdr Ext Len units of 8 more
	offset := header.Offset + 8 + 8*int(raw[header.Offset+1])
	// addrsOf names a family by the protocol number a header in front of the packet names it with
	if _, _, next, ok := addrsOf(raw[offset:]); !ok || next != header.NextHeader {
		return 0, false
	}
	return offset, true
}

// answerTooBig answers inner, a packet larger than mtu, the largest its next link carries, from the address it went to
// IPv6 with packet too big and IPv4 with DF with fragmentation needed, under the bucket answerRefused draws from
// the token goes first, which spares a flood the answers it would build and drop
// cut reports IPv4 without DF, which a router cuts into fragments rather than answers
func (m *Mesh) answerTooBig(inner []byte, mtu int) (answer []byte, cut bool) {
	var ok bool
	switch {
	case inner[0]>>4 == 6:
		if !m.takeICMPToken() {
			return nil, false
		}
		answer, ok = srv6.PacketTooBig(inner, netip.AddrFrom16([16]byte(inner[24:40])), mtu)
	// DF, RFC 791 section 3.1
	case inner[6]&0x40 != 0:
		if !m.takeICMPToken() {
			return nil, false
		}
		answer, ok = packet.FragmentationNeeded(inner, netip.AddrFrom4([4]byte(inner[16:20])), mtu)
	default:
		return nil, true
	}
	if !ok {
		return nil, false
	}
	return answer, false
}

// TooBigAnswered is how many answers with packet too big or fragmentation needed to packets past their session's budget this node sent
func (m *Mesh) TooBigAnswered() uint64 { return m.tooBigAnswered.Load() }

// sendBack sends an ICMP error to the source of the packet it answers, through the peer its own addresses route to
func (m *Mesh) sendBack(answer []byte) bool {
	source, destination, nextHeader, ok := addrsOf(answer)
	if !ok {
		return false
	}
	peer, verdict := m.Routes.Resolve(source, destination)
	if verdict != RoutePeer || peer == nil {
		return false
	}
	batch := peer.reserveBatchNow(1, len(answer))
	if batch == nil {
		return false
	}
	batch.append(answer, nextHeader)
	if err := batch.enqueue(); err != nil {
		m.reportSegmentDrop("the transport lost an icmp error", "err", err)
		return false
	}
	m.segmentsAnswered.Add(1)
	return true
}

// takeICMPToken reports whether this node may answer one more refused packet.
// The bucket holds icmpBurst and refills at icmpRefill, so a traceroute gets
// its probes answered and a flood gets the refill rate.
func (m *Mesh) takeICMPToken() bool {
	now := int64(time.Since(m.segmentsStarted))
	for {
		last := m.icmpFilled.Load()
		tokens := min(icmpBurst, m.icmpTokens.Load()+(now-last)/int64(icmpRefill))
		if tokens < 1 {
			return false
		}
		if m.icmpFilled.CompareAndSwap(last, now) {
			m.icmpTokens.Store(tokens - 1)
			return true
		}
	}
}

// reportSegmentDrop writes at most one line per interval, whatever the reason,
// so a peer sending a stream of refused headers costs a counter rather than a
// log. The counter is the record, while the line is there to say what kind.
func (m *Mesh) reportSegmentDrop(message string, args ...any) {
	if m.segmentsStarted.IsZero() {
		// time.Since of a zero time saturates, so an unstarted counter set
		// would report once and then suppress everything for 292 years. A
		// Mesh built without startSegmentReports only exists in a test, and
		// reporting is the answer that cannot hide anything.
		slog.Warn(message, append([]any{"interface", m.Name}, args...)...)
		return
	}
	now := int64(time.Since(m.segmentsStarted))
	previous := m.segmentReported.Load()
	if now-previous < int64(segmentDropInterval) || !m.segmentReported.CompareAndSwap(previous, now) {
		return
	}
	slog.Warn(message, append([]any{"interface", m.Name}, args...)...)
}

// segmentCounters is the atomic half of SegmentCounters, embedded in Mesh.
type segmentCounters struct {
	segmentTable      atomic.Pointer[srv6.LocalTable]
	segmentsForwarded atomic.Uint64
	segmentsDelivered atomic.Uint64
	segmentsDropped   atomic.Uint64
	steerTable        atomic.Pointer[srv6.SteerTable]
	// steerStopped holds the policies back without unloading them. Stored as
	// the negative so the zero Mesh steers, as every caller that never asks
	// expects it to.
	steerStopped      atomic.Bool
	segmentsSteered   atomic.Uint64
	segmentsUnsteered atomic.Uint64
	segmentsUnrouted  atomic.Uint64
	segmentsAnswered  atomic.Uint64
	segmentsEgressed  atomic.Uint64
	segmentsRefused   atomic.Uint64
	segmentsNotReady  atomic.Uint64
	segmentsDrained   atomic.Uint64
	// icmpTokens and icmpFilled are the bucket answerRefused draws from, in
	// tokens and in nanoseconds since segmentsStarted.
	icmpTokens atomic.Int64
	icmpFilled atomic.Int64
	// segmentsStarted and segmentReported space the drop reports on the
	// monotonic clock, as Peer.sendErrReported does, so a backward step of the
	// wall clock cannot suppress every report until it catches up.
	segmentsStarted time.Time
	segmentReported atomic.Int64
}

// startSegmentReports lets the first refused packet report immediately and
// spaces the rest.
func (c *segmentCounters) startSegmentReports() {
	c.segmentsStarted = time.Now()
	c.segmentReported.Store(-int64(segmentDropInterval))
	c.icmpTokens.Store(icmpBurst)
}
