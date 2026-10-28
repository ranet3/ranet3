// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"slices"
	"time"

	"ranet3.com/pkgs/ranet3/internal/packet"
)

// Explanation names the mesh's action on one packet, as a trace's record of the packet names it
type Explanation struct {
	Decision TraceDecision
	// Reason names why the packet is answered or dropped, as TraceRecord.Reason does, empty for any other decision
	Reason string
	// Answer names the ICMP error the packet is answered with, as TraceRecord.Answer does
	Answer string
	// Next is the ID of the peer whose session the packet is held to, for a forward and for an answer or a drop about its size, empty for any other
	// and MTU the largest packet that session carries
	Next string
	MTU  int
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
		// read off a copy, which the options' processing stamps
		address, _ := m.errorSource(false)
		switch options, _ := packet.ForwardOptions(slices.Clone(raw), address, m.ownAddress, time.Now()); options {
		case packet.OptionsSourceRouted:
			return e.decided(sessionSite(nil, TraceDrop, transitSourceRoute))
		case packet.OptionsMalformed:
			return e.decided(sessionSite(nil, TraceAnswer, transitInvalid).answered(answerParameter, TraceNoAnswer))
		}
	}
	return e.sized(sessionSite(nil, TraceForward, transitForwarded), raw, peer)
}

// sized is e for raw held to the session to peer, as forwardOne holds it
// site is the packet's forward, which a packet past that session's MTU meets as IPv4 without DF cut into fragments, or answered otherwise
func (e Explanation) sized(site traceSite, raw []byte, peer *Peer) Explanation {
	e.Next, e.MTU = peer.ID, peer.MTU()
	switch {
	case len(raw) <= e.MTU:
	// RFC 8200 section 4.5 lets only the source fragment, and DF is RFC 791 section 3.1's
	case raw[0]>>4 == 6 || raw[6]&0x40 != 0:
		site = site.answered(answerTooBig, TraceNoAnswer)
		site.reason = transitTooBig
	default:
		if _, _, ok := packet.AppendFragments(nil, nil, raw, e.MTU); !ok {
			site.decision, site.reason = TraceDrop, transitTooBig
		}
	}
	return e.decided(site)
}

// decided is e with the decision site names, as a record of the packet names it
func (e Explanation) decided(site traceSite) Explanation {
	var h traceHold
	r := h.build(&site, 0)
	e.Decision, e.Reason, e.Answer = r.Decision, r.Reason, r.Answer
	return e
}
