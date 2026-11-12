// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"cmp"
	"encoding/hex"
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

// SetSteeringEnabled stops or starts cap.segment steer's entries without
// taking the table away, so a diagnostic still reports the policies that would
// apply and an operator can see what was stopped. cap.exit via's path is not
// stopped, since a stop would send its packets to whichever exit the mesh
// prefers, which mode 3 exists to rule out. A packet already encapsulated is
// not unwound: the flag decides the packets looked at after it is stored,
// exactly as the table pointer does.
func (m *Mesh) SetSteeringEnabled(on bool) { m.steerStopped.Store(!on) }

// SteeringEnabled reports whether cap.segment steer's entries are being acted
// on.
func (m *Mesh) SteeringEnabled() bool { return !m.steerStopped.Load() }

// steerPolicy is the policy of table that claims a read off the tun from source to destination, nil for one none claims, and whether it is cap.exit via's path
// a cap.segment steer entry claims it first, then cap.exit via's path where alongPath, classify's test, says the path takes it
func (m *Mesh) steerPolicy(table *srv6.SteerTable, source, destination netip.Addr, alongPath bool) (*srv6.Policy, bool) {
	if table == nil {
		return nil, false
	}
	if !m.steerStopped.Load() {
		if policy := table.Lookup(source, destination); policy != nil {
			return policy, false
		}
	}
	if alongPath {
		return table.Default(), true
	}
	return nil, false
}

// sessionToward is the peer whose session classify sends a read off the tun from source to destination by under table, a steered read's first segment's, nil where it routes the read to no peer
// it is classify's choice of route alone, every drop classify makes before that choice left out, its multicast and limited broadcast drop and edgeCheck's drops among them,
// and it names a peer for a read classify drops there
// Lane.SameSession asks it toward an ICMP error's source as well as toward the leaf, and on the source's side that shows, among other cases,
// toward a source the exit reaches through an entry counting as a default or along cap.exit via's path, where it names that entry's peer or the path's first segment's and classify drops a read from a source this node does not own as leaving the mesh,
// and toward a multicast or limited broadcast source that an entry covering it routes to a peer, where it names that peer
// it takes classify's steps in classify's order through the functions classify calls, so classify's hot path stays its own, and TestLaneSendsByTheSessionSameSessionNames holds the two to one answer:
// classify's nil test before takesPath only spares the call, since takesPath gives the same for a table with no path,
// and classify resolves the first segment from the outer header it parsed, which writeOuter builds from the policy's source and first segment
func (m *Mesh) sessionToward(table *srv6.SteerTable, source, destination netip.Addr) *Peer {
	peer, verdict, match := m.Routes.Resolve(source, destination)
	alongPath, _ := m.takesPath(table, verdict, match, destination)
	if policy, path := m.steerPolicy(table, source, destination, alongPath); policy != nil {
		var firstMatch Match
		if peer, verdict, firstMatch = m.Routes.Resolve(policy.Source, policy.Path[0]); firstUnrouted(path, verdict, firstMatch) {
			return nil
		}
	}
	if verdict != RoutePeer {
		return nil
	}
	return peer
}

// takesPath is whether cap.exit via's path of table takes a read off the tun toward destination that resolves to verdict through match, and whether the read leaves the mesh
// the path takes a read that resolves through an entry counting as a default or through none, toward a destination outside the overlay, since an exit refuses one inside as an inner destination
// and a read the path takes leaves the mesh through its exit as one through an entry counting as a default does
func (m *Mesh) takesPath(table *srv6.SteerTable, verdict Verdict, match Match, destination netip.Addr) (alongPath, leaves bool) {
	alongPath = table.Default() != nil && (match.Counted || verdict == RouteNone) && !m.inOverlay(destination)
	return alongPath, match.Counted || alongPath
}

// firstUnrouted is whether a steered read whose first segment resolves to verdict through match is answered as one with no route to that segment, path saying cap.exit via's path steered it
// a first segment of this node's own is its steering's failure rather than a loop
// and the path reaches its first segment only through the segment's own /128, since through a shorter entry a node via does not name takes the read:
// an exit behind an entry counting as a default egresses it where the segment lies outside the overlay and answers it inside, and a node behind a subnet may hand it to its own host
func firstUnrouted(path bool, verdict Verdict, match Match) bool {
	return verdict != RoutePeer || path && match.Bits != 128
}

// PathCounters is the part of SegmentCounters' Steered and Unrouted cap.exit via's path took
type PathCounters struct {
	Steered, Unrouted uint64
}

func (m *Mesh) PathCounters() PathCounters {
	return PathCounters{Steered: m.pathSteered.Load(), Unrouted: m.pathUnrouted.Load()}
}

// steer appends raw, encapsulated under policy, to dst, never touching raw
// false is a packet the policy claimed and this node could not encapsulate, which is dropped rather than sent as it was
// the caller counts a packet steered
//
// A steering policy here selects an exit, so sending the packet by the metric
// instead puts it out of a different node under a source address that node
// does not announce, which is a wrong path rather than a degraded one. Every
// reason the encapsulation can fail is refused when the configuration is
// read, so what is left needs a packet larger than the device MTU this node
// set, and that is a deployment to fix rather than to carry.
func (m *Mesh) steer(dst, raw []byte, policy *srv6.Policy) ([]byte, bool) {
	encapsulated, err := policy.AppendEncapsulated(dst, raw)
	if err != nil {
		m.segmentsUnsteered.Add(1)
		m.reportSegmentDrop("a packet a policy claimed could not be encapsulated", "policy", policy, "err", err)
		return dst, false
	}
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
	// Delivered counts the packets an End.DT46 took the outer header off and handed to the forwarding decision
	Delivered uint64
	// Dropped counts the packets addressed to one of this node's segments that it refused or would not act on, and the ones End rewrote that went no further
	Dropped uint64
	// Steered counts this node's own packets that a policy encapsulated,
	// Unsteered the ones a policy claimed and this node could not, and
	// Unrouted the ones it encapsulated toward a first segment the mesh had
	// no route to, or, along cap.exit via's path, a first segment that has no
	// route of its own. Both failures drop the packet rather than send it by
	// the route the policy exists to override, and both are this node's own
	// steering rather than anything a peer did, so neither is counted in
	// Dropped. Steered and Unrouted are added once a read off the tun is
	// classified.
	Steered   uint64
	Unsteered uint64
	Unrouted  uint64
	// Answered counts the ICMP errors sent for dropped packets, which is the
	// half of Dropped a sender was told about.
	Answered uint64
	// Egressed counts the inner packets an egress segment handed to the exit
	Egressed uint64
	// Refused counts the packets a local SID refused, for an outer source outside overlay at any SID or, at an egress segment, for an outer source outside its allow list's entries inside overlay or an inner source outside the list, or an inner packet to a destination other than a multicast destination or the limited broadcast, but a Not-ECT one that arrived under an outer CE, that no router forwards, that the mesh routes no reply to or whose destination the mesh routes itself or overlay holds, a part of Dropped never answered
	Refused uint64
	// NotReady counts the egress results dropped as not ready for their family
	// it is this node's own state, so it is not in Dropped
	NotReady uint64
	// ECNUnused counts the packets an End.DT46 decapsulated whose inner and outer ECN fields RFC 6040 section 4.2's Figure 4 marks currently unused, the dropped ones among them
	ECNUnused uint64
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
		ECNUnused: m.ecnUnused.total.Load(),
	}
}

// applySegments takes the frames whose packets are addressed to this node's own segments out of an inbound batch and acts on each
// it returns the frames left for the forwarding decision
// a packet an End.DT46 delivering to the mesh takes out of its outer header leaves in the tail of its own frame, the end of the header it lost being its headroom
// granted marks those frames among the ones returned, nil where there are none, since configuring the segment grants what arrives on it transit
// mtu is the largest packet the session the batch came through carries
// a SYN an End.DT46 delivers or egresses has its MSS clamped to it here, since the session's clamp saw only the outer header
// from is the peer of that session, nil for packets of no session, and hold covers the frames' storage as DeliverInboundBatch's does
func (m *Mesh) applySegments(frames [][]byte, mtu int, from *Peer, hold Hold) (routed [][]byte, granted []bool) {
	table := m.segmentTable.Load()
	if table == nil {
		return frames, nil
	}
	act := func(packet []byte) srv6.Result { return actLocally(table, packet) }
	if trace := m.tracer.Load(); trace != nil {
		return trace.actOnSegments(m, frames, mtu, from, hold, act)
	}
	return m.actOnSegments(frames, mtu, hold, nil, act)
}

// actOnSegments is applySegments over act, which acts on each packet as the segment table does, records holding what a trace records each packet with, nil for none
// an End.DT46's inner packet that goes on to the decision is the decision's to record
func (m *Mesh) actOnSegments(frames [][]byte, mtu int, hold Hold, records *segmentRecords, act func([]byte) srv6.Result) ([][]byte, []bool) {
	var routed, egress [][]byte
	var granted []bool
	take := func(i int) {
		if routed == nil {
			routed = append(make([][]byte, 0, len(frames)), frames[:i]...)
		}
	}
	// keep adds frame to routed, and to granted where it is an End.DT46's inner packet or granted already holds one
	keep := func(frame []byte, inner bool) {
		if inner && granted == nil {
			granted = make([]bool, len(routed), cap(routed))
		}
		routed = append(routed, frame)
		if granted != nil {
			granted = append(granted, inner)
		}
	}
	var forward []forwardedSegment
	var check egressCheck
	for i, frame := range frames {
		packet := frame[TUNHeadroom:]
		result := act(packet)
		if result.Unused {
			m.noteECNUnused(packet, result.Inner)
		}
		switch result.Action {
		case srv6.ActionPass:
			if routed != nil {
				keep(frame, false)
			}
		case srv6.ActionDeliver:
			take(i)
			m.segmentsDelivered.Add(1)
			m.ClampMSS(result.Inner, mtu)
			// Decap hands back the tail of the packet it was given, behind at least the fixed header
			keep(frame[len(frame)-TUNHeadroom-len(result.Inner):], true)
		case srv6.ActionEgress:
			take(i)
			// past the allow list the inner source has to be one the mesh routes a reply to, as the decision's egress has
			version := byte(6)
			if result.Family == srv6.NextHeaderIPv4 {
				version = 4
			}
			source, destination := addressesOf(result.Inner, version)
			// a group or the limited broadcast reaches no exit, whatever its source, as the decision's reaches no tun
			if linkScoped(destination) && group(destination) {
				m.segmentsDropped.Add(1)
				m.transitCounts[transitSessionMulticast].Add(1)
				m.reportTransitDrop(transitSessionMulticast, source, destination)
				if records != nil {
					records.acted(TraceDrop, transitSessionMulticast, packet, result.Inner)
				}
				continue
			}
			// the kernel exit's host forwards what the uplink takes, so the martians the decision drops are dropped here too
			if martian(source, destination) {
				if m.refuseEgress() {
					slog.Warn("an egress segment refused an inner packet no router forwards", "interface", m.Name, "source", source, "destination", destination)
				}
				if records != nil {
					records.acted(TraceDrop, transitRefused, packet, result.Inner)
				}
				continue
			}
			answer := m.pairAnswer(&check, source, destination, true)
			if !answer.routed {
				if m.refuseEgress() {
					slog.Warn("an egress segment refused an inner source the mesh routes no reply to", "interface", m.Name, "source", source)
				}
				if records != nil {
					records.acted(TraceDrop, transitRefused, packet, result.Inner)
				}
				continue
			}
			// egress carries nothing for the mesh, so a destination the mesh routes to another node or holds is refused
			// and so is one of this node's own, which is the decision's to deliver rather than egress, and one inside the overlay, which no node that writes it egresses
			// where no node announces it, an exit with an overlay whose table selects its own entry counting as a default answers it as no route, and a node whose table selects that exit's entry routes it there
			// an exit with no overlay written has none, so its decision egresses such an address as any destination outside the mesh
			if answer.forMesh {
				if m.refuseEgress() {
					slog.Warn("an egress segment refused an inner destination the mesh routes or its overlay holds", "interface", m.Name, "destination", destination)
				}
				if records != nil {
					records.acted(TraceDrop, transitRefused, packet, result.Inner)
				}
				continue
			}
			// a packet the kernel exit writes while its family's translation is missing leaves the uplink untranslated
			// the answer is about the inner packet, since the segment's source is the headend that encapsulated it rather than its sender
			if !m.readyFor(&check, result.Family, false) {
				m.segmentsNotReady.Add(1)
				if records != nil {
					records.answered(m, transitNotReady, answerNoRoute, packet, result.Inner, version)
				} else {
					m.answer(result.Inner, version, answerNoRoute, 0)
				}
				continue
			}
			if records != nil {
				records.acted(TraceEgress, transitDelivered, packet, result.Inner)
			}
			m.ClampMSS(result.Inner, mtu)
			if egress == nil {
				egress = make([][]byte, 0, len(frames)-i)
			}
			egress = append(egress, frame[len(frame)-TUNHeadroom-len(result.Inner):])
		case srv6.ActionForward:
			take(i)
			forward = append(forward, forwardedSegment{raw: packet, next: result.Next, sid: result.SID, srh: result.SRH})
			if records != nil {
				records.forwarded(len(forward)-1, len(frames))
			}
		case srv6.ActionDrop:
			take(i)
			m.noteSegmentDrop(result.Err)
			if records != nil && records.arrived != nil {
				records.refusal(m, packet, result.Err)
			} else {
				m.answerRefused(packet, result.Err, (*Mesh).takeICMPToken)
			}
		default:
			take(i)
			m.segmentsDropped.Add(1)
			m.reportSegmentDrop("a segment's result names an action this node does not act on", "action", result.Action)
			if records != nil {
				records.acted(TraceDrop, transitInvalid, packet, records.arrived)
			}
		}
	}
	arrivals, from, trace := records.forwarding()
	m.forwardSegments(forward, arrivals, from, trace)
	if len(egress) != 0 {
		m.segmentsEgressed.Add(uint64(len(egress)))
		m.egress(egress, hold)
	}
	if routed == nil {
		return frames, nil
	}
	return routed, granted
}

// martian is a packet no router forwards by its source, or by a destination other than the limited broadcast and multicast, the test the decision applies past its link-scoped destinations
func martian(source, destination netip.Addr) bool {
	return packet.InvalidSource(source) || martianDestination(destination)
}

// refuseEgress counts an egress segment's refusal of a packet, dropped and refused, and claims the interval's report as segmentDropDue does
// so a caller boxes the addresses it reports only for the one line an interval writes
func (m *Mesh) refuseEgress() bool {
	m.segmentsDropped.Add(1)
	m.segmentsRefused.Add(1)
	return m.segmentDropDue()
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
	raw  []byte
	next netip.Addr
	// sid is the segment of this node the packet was addressed to, which an answer about it may come from
	sid netip.Addr
	// srh is where the SRH End acted on starts in raw
	srh        int
	peer       *Peer
	nextHeader byte
}

// forwardSegments sends the packets a waypoint has rewritten on to the peers
// their new destinations select.
//
// Each peer's share of the batch takes one place and one sequence range and
// is sealed in one call, as a share of a tun read is, against the bytes of the
// peer's budget it carries.
//
// The budget is the peer's ordinary one rather than the control budget babel
// runs on, because this is somebody else's traffic: a segment list pointed at
// this node must not be able to spend the allowance this node's own routing
// protocol needs. A peer whose budget has no room for its share drops it and
// counts it, the way a full egress queue drops.
//
// from is the peer of the session the segments came through, and trace records what each met, nil for none.
// arrived holds each segment's packet as it arrived, which its records carry, nil for one the tracer's arrive did not copy, and is nil where trace is.
func (m *Mesh) forwardSegments(segments []forwardedSegment, arrived [][]byte, from *Peer, trace *tracer) {
	if len(segments) == 0 {
		return
	}
	// Sized for the peers a batch names, one in the ordinary case, rather than
	// for its packets.
	counts := make(map[*Peer]outboundShare)
	order := make([]*Peer, 0, 4)
	// cut holds the fragments of the segments too large for their next sessions, and cutArrived the packet each was cut from as it arrived
	var cut fragmentList
	var cutArrived [][]byte
	for i := range segments {
		segment := &segments[i]
		src, dst, nextHeader, ok := addrsOf(segment.raw)
		if !ok {
			m.noteSegmentDrop(errNotIP)
			if trace != nil && arrived[i] != nil {
				trace.segmentAt(from, TraceDrop, transitInvalid, netip.Addr{}, arrived[i])
			}
			continue
		}
		// a next segment only an entry counting as a default reaches is unrouted, since the exit behind that entry would carry one outside the overlay out of the mesh
		peer, verdict, match := m.Routes.Resolve(src, dst)
		if verdict != RoutePeer || peer == nil || match.Counted {
			m.segmentsDropped.Add(1)
			m.reportSegmentDrop("no route counting as no default to the next segment", "segment", segment.next)
			// Resolve answers an address cap.table assigns this node RouteLocal as it does a prefix this node originates, so a second lookup tells the two apart
			unrouted := verdict != RouteLocal || match.Counted
			if trace != nil && arrived[i] != nil {
				trace.unroutedSegment(m, from, segment, src, dst, unrouted, arrived[i])
			} else {
				m.answerNextSegment(segment, src, dst, unrouted, (*Mesh).takeICMPToken)
			}
			continue
		}
		share, seen := counts[peer]
		if !seen {
			share.mtu = peer.MTU()
			order = append(order, peer)
		}
		fragments, tooBig := 0, len(segment.raw) > share.mtu
		var kind answerKind
		fate := TraceNoAnswer
		if tooBig {
			var count, bytes int
			if trace != nil && arrived[i] != nil {
				count, bytes, kind, fate = m.segmentTooBigDrawn(&cut, segment, peer, nextHeader, share.mtu)
			} else {
				count, bytes, _, _ = m.segmentTooBig(&cut, segment, peer, nextHeader, share.mtu, (*Mesh).takeICMPToken)
			}
			share.count += count
			share.bytes += bytes
			fragments = count
			if trace != nil {
				for range count {
					cutArrived = append(cutArrived, arrived[i])
				}
			}
		} else {
			share.count++
			share.bytes += len(segment.raw)
			segment.peer, segment.nextHeader = peer, nextHeader
		}
		if trace != nil && arrived[i] != nil {
			trace.end(from, peer, segment.next, tooBig, fragments, kind, fate, arrived[i])
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
			if trace != nil {
				trace.refusedSegments(segments, arrived, &cut, cutArrived, from, peer)
			}
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
		if err := batch.finish(); err != nil {
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

// noteECNUnused counts a packet an End.DT46 took inner out of whose ECN fields, outer's and inner's, RFC 6040 section 4.2's Figure 4 marks currently unused
// and records netstack.ecn.unused at most once an interval, with the count since the last record and inner's IP header, as section 4.2 asks such a combination logged and rate-limited
// and RFC 3168 section 9.2.2 a record of them to hold one such packet's headers
// the figure writes no unused cell's field into inner, so inner's field is the one it arrived with
func (m *Mesh) noteECNUnused(outer, inner []byte) {
	count, record := m.ecnUnused.add(int64(time.Since(m.segmentsStarted)))
	if !record {
		return
	}
	length := 40
	if inner[0]>>4 == 4 {
		length = int(inner[0]&0x0f) * 4
	}
	header := hex.EncodeToString(inner[:min(len(inner), length)])
	if m.events != nil {
		m.events("netstack.ecn.unused", "", slog.String("interface", m.Name), slog.String("outer", packet.ECNOf(outer).String()), slog.String("inner", packet.ECNOf(inner).String()),
			slog.Uint64("count", count), slog.String("header", header))
	}
	slog.Debug("segments arrived at an end.dt46 with an ecn combination no tunnel sends", "interface", m.Name, "outer", packet.ECNOf(outer), "inner", packet.ECNOf(inner), "count", count, "header", header)
}

// answerRefused sends the ICMP error a segment's refusal is answered with: a
// Time Exceeded for a hop limit that ran out here, RFC 8986 section 4.1 S06,
// and a Parameter Problem with the code and pointer of an srv6.Refusal. Any
// other refusal is dropped with no answer.
//
// RFC 4443 section 2.4 (f) requires the limit, which the builder draws from
// once the packet is one an error may answer and before it builds, so a flood
// past its bucket builds nothing.
//
// it reports the answer's kind and its fate as sentBack says, TraceNoAnswer for a refusal no error answers
func (m *Mesh) answerRefused(offending []byte, reason error, take takeAnswer) (answerKind, TraceOutcome) {
	sender := netip.AddrFrom16([16]byte(offending[8:24]))
	segment := netip.AddrFrom16([16]byte(offending[24:40]))
	allow := m.allowAnswer(take, sender)
	if refusal, ok := errors.AsType[*srv6.Refusal](reason); ok {
		return answerParameter, m.sentBack(srv6.ParameterProblem(offending, segment, refusal, allow))
	}
	if errors.Is(reason, srv6.ErrHopLimit) {
		return answerExpired, m.sentBack(srv6.TimeExceeded(offending, segment, allow))
	}
	return answerNone, TraceNoAnswer
}

// sentBack sends answer back as sendBack does and reports its fate, TraceNotAnswerable for none built
func (m *Mesh) sentBack(answer []byte) TraceOutcome {
	switch {
	case answer == nil:
		return TraceNotAnswerable
	case !m.sendBack(answer):
		return TraceUnsent
	}
	return TraceSent
}

// answerUnroutedSegment answers a forwarded segment whose next segment the mesh routes to no other node, or only through a route counting as a default, from the SID it matched, within the limits answerRefused's answers draw on
// as a steered read whose first segment has no route is answered, since a route counting as a default carries no segment
// RFC 8986 section 4.1 S16 submits the rewritten packet to the lookup for its new destination, and RFC 4443 section 3.1 answers one no route carries with Destination Unreachable, code 0
// it reports the answer's fate as sentBack says
func (m *Mesh) answerUnroutedSegment(segment *forwardedSegment, take takeAnswer) TraceOutcome {
	sender := netip.AddrFrom16([16]byte(segment.raw[8:24]))
	return m.sentBack(srv6.NoRoute(segment.raw, segment.sid, m.allowAnswer(take, sender)))
}

// answerAssignedSegment answers a forwarded segment whose next segment is an address cap.table assigns this node, which is no SID, as RFC 8754 section 4.3.2 has such an address answer one with segments left
// from the SID it matched, within the limits answerRefused's answers draw on
// one at segments left 0 is dropped with no answer
// it reports the answer's fate as sentBack says, TraceNoAnswer for one at segments left 0
func (m *Mesh) answerAssignedSegment(segment *forwardedSegment, take takeAnswer) TraceOutcome {
	refusal := srv6.AtLocalInterface(segment.raw, segment.srh)
	if refusal == nil {
		return TraceNoAnswer
	}
	sender := netip.AddrFrom16([16]byte(segment.raw[8:24]))
	return m.sentBack(srv6.ParameterProblem(segment.raw, segment.sid, refusal, m.allowAnswer(take, sender)))
}

// answerNextSegment answers a forwarded segment whose next segment has no route counting as no default, at src and dst
// as answerUnroutedSegment does where unrouted, and otherwise as answerAssignedSegment does where the next segment is an address cap.table assigns this node
// it reports the answer's kind and fate, TraceNoAnswer for a segment neither answers
func (m *Mesh) answerNextSegment(segment *forwardedSegment, src, dst netip.Addr, unrouted bool, take takeAnswer) (answerKind, TraceOutcome) {
	switch {
	case unrouted:
		return answerNoRoute, m.answerUnroutedSegment(segment, take)
	case m.Routes.assigned(src, dst):
		return answerParameter, m.answerAssignedSegment(segment, take)
	}
	return answerNone, TraceNoAnswer
}

// segmentTooBig takes a forwarded segment larger than mtu, the largest the session to its next segment carries
// the packet it carries is held to mtu less the headers in front of it, which each fragment keeps
// it reports how many fragments it queued in cut and their bytes, and an answer goes back as sendTooBig sends it
// for a segment it queued none of it reports the answer's kind and fate as tooBig does, TraceNoAnswer for one carrying an IPv4 header that fails its checks
func (m *Mesh) segmentTooBig(cut *fragmentList, segment *forwardedSegment, peer *Peer, nextHeader byte, mtu int, take takeAnswer) (int, int, answerKind, TraceOutcome) {
	var answer []byte
	var tun bool
	kind := answerTooBig
	if offset, ok := carriedPacket(segment.raw, segment.srh); ok {
		inner := segment.raw[offset:]
		var fragment bool
		if answer, fragment, tun = m.answerTooBig(inner, mtu-offset, true, segment.sid, take); fragment {
			count, bytes, fault := cut.add(peer, nextHeader, segment.raw[:offset], inner, mtu)
			switch {
			case count != 0:
				return count, bytes, answerNone, TraceNoAnswer
			case fault != 0:
				// a packet that was to be cut is answered about its options, not its size
				kind = answerParameter
				answer, tun = m.answerOptions(inner, fault, true, take)
			case !packet.HeaderValid(inner):
				// RFC 1812 section 5.2.2 discards a header failing its checks silently
				// carriedPacket took a whole packet, so its checksum is the one check left to fail
				m.dropTooBig(segment, mtu)
				return 0, 0, answerNone, TraceNoAnswer
			default:
				// every other refusal of the cut is about size
				answer, tun = m.answerSegmentTooBig(segment, mtu, take)
			}
		}
	} else {
		answer, tun = m.answerSegmentTooBig(segment, mtu, take)
	}
	m.dropTooBig(segment, mtu)
	switch {
	case answer == nil:
		return 0, 0, kind, TraceNotAnswerable
	case !m.sendTooBig(answer, tun):
		return 0, 0, kind, TraceUnsent
	}
	if kind == answerTooBig {
		m.tooBigAnswered.Add(1)
	}
	return 0, 0, kind, TraceSent
}

// answerSegmentTooBig is the packet too big about segment itself, as End rewrote it, to its outer source, naming mtu, and reports one that goes into the tun
// RFC 8200 section 4.4 has a node discard a packet its routing header sends onto a link too small for it and answer the packet's source
// the builder draws through take, on no limit, as every packet too big does
func (m *Mesh) answerSegmentTooBig(segment *forwardedSegment, mtu int, take takeAnswer) ([]byte, bool) {
	source, tun := m.answerFrom(segment.raw, true, segment.sid)
	return srv6.PacketTooBig(segment.raw, source, mtu, m.allowAnswer(take, netip.Addr{})), tun
}

func (m *Mesh) dropTooBig(segment *forwardedSegment, mtu int) {
	m.segmentsDropped.Add(1)
	m.reportSegmentDrop("a forwarded segment is larger than the session to its next segment carries", "segment", segment.next, "mtu", mtu)
}

// segmentTooBigDrawn is segmentTooBig for a traced segment, drawing through an answerDraw, and reports the fate the record reads
//
//go:noinline
func (m *Mesh) segmentTooBigDrawn(cut *fragmentList, segment *forwardedSegment, peer *Peer, nextHeader byte, mtu int) (int, int, answerKind, TraceOutcome) {
	var draw answerDraw
	count, bytes, kind, fate := m.segmentTooBig(cut, segment, peer, nextHeader, mtu, draw.take)
	return count, bytes, kind, draw.met(fate)
}

func (m *Mesh) sendTooBig(answer []byte, tun bool) bool {
	if !tun {
		return m.sendBack(answer)
	}
	m.writeHostPacket(answer)
	m.segmentsAnswered.Add(1)
	return true
}

// carriedPacket is the offset of the IP packet behind the SRH at srh in raw, which runs to raw's end
// raw holds the SRH's first 2 octets
func carriedPacket(raw []byte, srh int) (int, bool) {
	// RFC 8754 section 2, a routing header is 8 bytes and Hdr Ext Len units of 8 more
	offset := srh + 8 + 8*int(raw[srh+1])
	if offset > len(raw) {
		return 0, false
	}
	// addrsOf names a family by the protocol number a header in front of the packet names it with
	if _, _, next, ok := addrsOf(raw[offset:]); !ok || next != raw[srh] {
		return 0, false
	}
	return offset, true
}

// answerTooBig answers inner, a packet larger than mtu, the largest its next link carries
// IPv6 with packet too big and IPv4 with DF with fragmentation needed, which no limit holds back
// cut reports IPv4 without DF, which a router cuts into fragments rather than answers
// end is a packet a forwarded segment carries to End, which matched sid, and otherwise inner was read off the tun
// the answer comes from where answerFrom says, and tun reports one that goes into the tun
// the builder draws through take
func (m *Mesh) answerTooBig(inner []byte, mtu int, end bool, sid netip.Addr, take takeAnswer) (answer []byte, cut, tun bool) {
	version := inner[0] >> 4
	if !unfragmentable(inner, version) {
		return nil, true, false
	}
	source, tun := m.answerFrom(inner, end, sid)
	allow := m.allowAnswer(take, netip.Addr{})
	if version == 6 {
		return srv6.PacketTooBig(inner, source, mtu, allow), false, tun
	}
	return packet.FragmentationNeeded(inner, source, m.AnswerTTL(), mtu, allow), false, tun
}

// answerOptions answers inner, an IPv4 packet without DF the cut refused for its option list, with parameter problem at fault
// the octet at fault RFC 1812 section 4.3.3.5 has the answer name, under the bucket of inner's source and the node's cap
// and from the address answerTooBig's fragmentation needed would come from, tun reporting an answer that goes into the tun
// a fault of 0 is a packet refused for anything else, which goes unanswered
// the builder draws through take
func (m *Mesh) answerOptions(inner []byte, fault int, end bool, take takeAnswer) (answer []byte, tun bool) {
	if fault == 0 {
		return nil, false
	}
	source, tun := m.answerFrom(inner, end, netip.Addr{})
	sender := netip.AddrFrom4([4]byte(inner[12:16]))
	return packet.ParameterProblem(inner, source, m.AnswerTTL(), fault, m.allowAnswer(take, sender)), tun
}

// answerFrom is the address an answer to inner, a packet past its next link, comes from, and reports whether the answer goes into the tun
// end is a packet End answers, a forwarded segment that matched sid or the packet one carries, and otherwise inner was read off the tun
// a tun read is answered into the tun from its destination, the one source every check of the sending host takes
// the host drops a packet arriving from one of its own addresses, under nftables' fib in either family and over IPv4 by fib_validate_source unless accept_local is set
// and its strict reverse path check drops one from an address it routes out of another link, a SID or a router-id it routes elsewhere among them
// so an answer to this host or a network behind it comes from inner's destination too, as the forwarding decision's does
// with no router-id an IPv6 answer comes from sid, as RFC 4443 section 2.2 (b) asks
func (m *Mesh) answerFrom(inner []byte, end bool, sid netip.Addr) (netip.Addr, bool) {
	version := inner[0] >> 4
	src, dst := addressesOf(inner, version)
	if !end {
		return dst, true
	}
	if _, verdict, match := m.replyRoute(src, dst); verdict == RouteLocal && !match.Counted {
		return dst, true
	}
	sources := m.AnswerSources()
	if version == 6 {
		return cmp.Or(sources.Router6, sid), false
	}
	return cmp.Or(sources.Router4, dst), false
}

// TooBigAnswered is how many answers with packet too big or fragmentation needed to packets past their session's budget this node sent
func (m *Mesh) TooBigAnswered() uint64 { return m.tooBigAnswered.Load() }

// sendBack sends an ICMP error about a segment to the source of the packet it answers, as sendAnswer does, and counts it answered
func (m *Mesh) sendBack(answer []byte) bool {
	if !m.sendAnswer(answer) {
		return false
	}
	m.segmentsAnswered.Add(1)
	return true
}

// sendAnswer sends an ICMP error to the source of the packet it answers, through the peer its own addresses route to
func (m *Mesh) sendAnswer(answer []byte) bool {
	source, destination, nextHeader, ok := addrsOf(answer)
	if !ok {
		return false
	}
	peer, verdict, _ := m.Routes.Resolve(source, destination)
	if verdict != RoutePeer || peer == nil {
		return false
	}
	return m.sendThrough(peer, answer, nextHeader)
}

// sendThrough sends one packet under nextHeader through peer, sealed on the caller's goroutine, and drops it where peer's budget has no room
func (m *Mesh) sendThrough(peer *Peer, raw []byte, nextHeader byte) bool {
	batch := peer.reserveBatchNow(1, len(raw))
	if batch == nil {
		return false
	}
	batch.append(raw, nextHeader)
	if err := batch.finish(); err != nil {
		m.reportSegmentDrop("the transport lost an icmp error", "err", err)
		return false
	}
	return true
}

// takeICMPToken reports whether this node may send one more ICMP error to sender, the source of the packet it answers
// sender is the zero Addr for packet too big and fragmentation needed, which no limit holds back
func (m *Mesh) takeICMPToken(sender netip.Addr) bool {
	now := int64(time.Since(m.segmentsStarted))
	verdict := m.icmpLimit.take(now, sender)
	var report *reportedCount
	var limit string
	switch verdict {
	case icmpBySource:
		report, limit = &m.withheldBySource, "source"
	case icmpByNode:
		report, limit = &m.withheldByNode, "node"
	default:
		return true
	}
	if report.claim(now, report.next.Load()) {
		withheld := report.since(m.icmpLimit.withheld(verdict))
		if m.events != nil {
			m.events("netstack.icmp.withheld", "", slog.String("interface", m.Name), slog.String("limit", limit), slog.Uint64("withheld", withheld))
		}
	}
	return false
}

// ICMPWithheld is how many ICMP errors this node did not send, those its source's bucket withheld and those the node's cap withheld
func (m *Mesh) ICMPWithheld() (source, node uint64) {
	return m.icmpLimit.withheld(icmpBySource), m.icmpLimit.withheld(icmpByNode)
}

// reportSegmentDrop writes at most one line per interval, whatever the reason
// so a peer sending a stream of refused headers costs a counter rather than a log, the counter being the record and the line saying what kind
func (m *Mesh) reportSegmentDrop(message string, args ...any) {
	if m.segmentDropDue() {
		slog.Warn(message, append([]any{"interface", m.Name}, args...)...)
	}
}

// reportUnroutedSegment is reportSegmentDrop for a steered read firstUnrouted answered, its first segment resolving to verdict through match,
// naming how the table answered that segment in the words the kernel's path names it in
// the interval claimed before the segment is boxed, since a read classify answers costs no allocation
func (m *Mesh) reportUnroutedSegment(first netip.Addr, verdict Verdict, match Match) {
	if !m.segmentDropDue() {
		return
	}
	answer := "no route"
	switch {
	case verdict == RouteHeld:
		answer = "held"
	case verdict == RouteLocal:
		answer = "this node's own"
	case verdict == RoutePeer && match.Counted:
		answer = "only through a route that counts as a default"
	case verdict == RoutePeer:
		answer = "no route of its own"
	}
	slog.Warn("the first segment of a steered packet is unrouted", "interface", m.Name, "segment", first, "verdict", answer)
}

// segmentDropDue claims the interval's one segment drop report, and a caller holding it writes the line
func (m *Mesh) segmentDropDue() bool {
	return m.segmentReport.claim(int64(time.Since(m.segmentsStarted)), m.segmentReport.next.Load())
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
	// pathSteered and pathUnrouted are the part of segmentsSteered and segmentsUnrouted cap.exit via's path took
	pathSteered, pathUnrouted atomic.Uint64
	// icmpLimit holds back the ICMP errors past their limits, its clock nanoseconds since segmentsStarted
	icmpLimit icmpLimit
	// withheldBySource and withheldByNode space the reports of the answers a source's bucket and the node's cap withheld, which the limit's shards count as IcmpOutRateLimitHost and IcmpOutRateLimitGlobal count them
	withheldBySource, withheldByNode reportedCount
	// ecnUnused counts the packets SegmentCounters.ECNUnused counts and spaces their records
	ecnUnused reportedCount
	// segmentReport spaces the segment drop reports
	segmentReport reportedCount
	// segmentsStarted is the start of the clock the mesh's reports and ICMP limit read through time.Since, which keeps it monotonic
	segmentsStarted time.Time
}

// steerTally is one read's steering counts, added to the mesh's once the read is classified
// so the tun readers share no counter per steered packet
type steerTally struct {
	steered, unrouted, pathSteered, pathUnrouted uint32
}

// addSteerTally adds tally to the mesh's counts, steered first
// the other three are parts of steered, so a read that steered none has none of them
func (m *Mesh) addSteerTally(tally *steerTally) {
	if tally.steered == 0 {
		return
	}
	m.segmentsSteered.Add(uint64(tally.steered))
	if tally.pathSteered != 0 {
		m.pathSteered.Add(uint64(tally.pathSteered))
	}
	if tally.unrouted != 0 {
		m.segmentsUnrouted.Add(uint64(tally.unrouted))
	}
	if tally.pathUnrouted != 0 {
		m.pathUnrouted.Add(uint64(tally.pathUnrouted))
	}
}

// startSegmentReports starts the clock the mesh's reports and ICMP limit read
func (c *segmentCounters) startSegmentReports() {
	c.segmentsStarted = time.Now()
}
