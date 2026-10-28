// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"net/netip"
	"slices"

	"ranet3.com/pkgs/ranet3/internal/packet"
	"ranet3.com/pkgs/ranet3/srv6"
)

// Explanation names the mesh's action on one packet, as a trace's record of the packet names it
type Explanation struct {
	Decision TraceDecision
	// Reason names why the packet is answered or dropped, as TraceRecord.Reason does, empty for any other decision
	Reason string
	// Answer names the ICMP error the packet is answered with, as TraceRecord.Answer does
	Answer string
	// Next is the ID of the peer whose session the packet is held to, for a forward and for an answer or a drop about its size, empty for any other
	// MTU is the largest packet that session carries, and Overhead the bytes a policy puts in front of the packet, which the session carries as well
	Next          string
	MTU, Overhead int
	// Segment is the first segment of a packet a policy steers
	Segment netip.Addr
	// Match is the entry the table matched for the packet's destination as it arrived, the zero Match where the walk ended before the table
	Match Match
}

// Explain names decide's action on raw, one packet a session delivers that no segment of this node takes
// it calls decide's checks in decide's order, on the table, the overlay, cap.transit and the readiness as they are now
// and spends no ICMP token, moves no counter, takes no forward batch, writes nothing and leaves raw as it is
// a packet an End.DT46 of this node delivers to the mesh goes on whatever cap.transit says, which Explain does not ask
func (m *Mesh) Explain(raw []byte) Explanation {
	var e Explanation
	raw, version := packet.Payload(raw)
	if version == 0 {
		return e.decided(sessionSite(nil, TraceDrop, transitInvalid))
	}
	src, dst := addressesOf(raw, version)
	if linkScoped(dst) {
		return e.decided(sessionSite(nil, TraceDeliver, transitDelivered))
	}
	if invalid := martianDestination(dst); packet.InvalidSource(src) || invalid {
		site := sessionSite(nil, TraceDrop, transitMartian)
		if version == 6 && src.IsLinkLocalUnicast() && !invalid {
			site = sessionSite(nil, TraceAnswer, transitMartian).answered(answerBeyondScope, TraceNoAnswer)
		}
		return e.decided(site)
	}
	peer, verdict, match := m.Routes.Resolve(src, dst)
	if verdict == RouteLocal && match.Counted && m.inOverlay(dst) {
		verdict = RouteNone
	}
	e.Match = match
	if verdict != RouteLocal && version == 4 && !packet.HeaderValid(raw) {
		return e.decided(sessionSite(nil, TraceDrop, transitInvalid))
	}
	switch verdict {
	case RouteLocal:
		if match.Counted {
			var check egressCheck
			if reason, ok := m.egresses(&check, src, dst, version, match); !ok {
				return e.decided(sessionSite(nil, TraceDrop, reason))
			}
			if match.Egress {
				return e.decided(sessionSite(nil, TraceEgress, transitDelivered))
			}
		}
		return e.decided(sessionSite(nil, TraceDeliver, transitDelivered))
	case RouteNone, RouteHeld:
		return e.decided(sessionSite(nil, TraceAnswer, unroutedReason(verdict)).answered(m.unreachable(verdict, match, dst), TraceNoAnswer))
	}
	if !m.transitOn.Load() {
		return e.decided(sessionSite(nil, TraceAnswer, transitRefused).answered(answerProhibited, TraceNoAnswer))
	}
	if hopLimit(raw, version) <= 1 {
		return e.decided(sessionSite(nil, TraceAnswer, transitExpired).answered(answerExpired, TraceNoAnswer))
	}
	if version == 4 && hasOptions(raw) {
		// judged on a copy, which the options' processing stamps
		switch reason, _, ok := m.judgeOptions(slices.Clone(raw)); {
		case reason == transitInvalid:
			return e.decided(sessionSite(nil, TraceAnswer, reason).answered(answerParameter, TraceNoAnswer))
		case !ok:
			return e.decided(sessionSite(nil, TraceDrop, reason))
		}
	}
	return e.sized(sessionSite(nil, TraceForward, transitForwarded), raw, nil, peer)
}

// ExplainRead names classify's action on raw, one packet read off the tun
// it calls classify's checks in classify's order, on the table, the overlay, this node's segments and the steering as they are now
// the checks of its source looked up afresh rather than kept from an earlier read
// and as Explain spends, moves, writes and changes nothing
func (m *Mesh) ExplainRead(raw []byte) Explanation {
	var e Explanation
	src, dst, nextHeader, ok := addrsOf(raw)
	if !ok {
		return e.decided(readSite(TraceDrop, transitInvalid))
	}
	if dst.IsMulticast() || dst == packet.LimitedBroadcast {
		return e.decided(readSite(TraceDrop, transitMulticast))
	}
	peer, verdict, match := m.Routes.Resolve(src, dst)
	e.Match = match
	var kept keptAnswers
	if reason, dropped := m.edgeCheck(&kept, m.segmentTable.Load(), raw, nextHeader, src, dst, match.Counted); dropped {
		return e.decided(readSite(TraceDrop, reason))
	}
	site, header := readSite(TraceForward, transitForwarded), []byte(nil)
	if policy := m.steerPolicy(src, dst); policy != nil {
		steered, err := srv6.AppendEncapsulated(nil, raw, policy.Source, policy.Path)
		if err != nil {
			site = readSite(TraceDrop, transitTooBig)
			site.segment = policy.Path[0]
			return e.decided(site)
		}
		header = steered[:len(steered)-len(raw)]
		src, dst, _, _ = addrsOf(steered)
		site.segment = dst
		if peer, verdict, _ = m.Routes.Resolve(src, dst); verdict != RoutePeer {
			site.decision, site.reason = TraceDrop, transitNoRoute
			return e.decided(site)
		}
	}
	switch verdict {
	case RouteLocal:
		return e.decided(readSite(TraceDrop, transitLooped))
	case RouteNone, RouteHeld:
		return e.decided(readSite(TraceAnswer, unroutedReason(verdict)).answered(m.unreachable(verdict, match, dst), TraceNoAnswer))
	}
	return e.sized(site, raw, header, peer)
}

// sized is e for raw held to the session to peer behind header, the bytes a policy put in front of it, as forwardOne and tooBig hold it
// site is the packet's forward, which a packet past that session's MTU meets as IPv4 without DF cut into fragments, or answered otherwise
func (e Explanation) sized(site traceSite, raw, header []byte, peer *Peer) Explanation {
	e.Next, e.MTU, e.Overhead = peer.ID, peer.MTU(), len(header)
	switch {
	case len(header)+len(raw) <= e.MTU:
	// RFC 8200 section 4.5 lets only the source fragment, and DF is RFC 791 section 3.1's
	case raw[0]>>4 == 6 || raw[6]&0x40 != 0:
		site = site.answered(answerTooBig, TraceNoAnswer)
		site.reason = transitTooBig
	default:
		// the cut refuses an option list that does not describe itself at the octet at fault, which forwardOptions refuses first in a session's packet
		if _, fault, ok := packet.AppendFragments(nil, header, raw, e.MTU-len(header)); fault != 0 {
			site = site.answered(answerParameter, TraceNoAnswer)
			site.reason = transitInvalid
		} else if !ok {
			site.decision, site.reason = TraceDrop, transitTooBig
		}
	}
	return e.decided(site)
}

// decided is e with the decision site names, as a record of the packet names it
func (e Explanation) decided(site traceSite) Explanation {
	var h traceHold
	r := h.build(&site, 0)
	e.Decision, e.Reason, e.Answer, e.Segment = r.Decision, r.Reason, r.Answer, r.Segment
	return e
}
