// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"net/netip"

	"ranet3.com/pkgs/ranet3/esp"
	"ranet3.com/pkgs/ranet3/srv6"
)

// sourceAnswer is the table's answer for the source of a read off the tun, looked up as the route a reply to the packet takes
type sourceAnswer struct {
	verdict Verdict
	// counted is the matched entry counting as a default, which the checks pass over, so another exit's default or halves make no source another node's
	counted bool
	// overlay is the source lying inside cap.border's overlay
	overlay bool
}

// owned is a source an entry of this node's own covers that does not count as a default
func (a sourceAnswer) owned() bool { return a.verdict == RouteLocal && !a.counted }

// forged is a source the mesh says is another node's, RFC 3704 section 2.2's strict check against the tun that passes a source no route covers
// an entry that does not count as a default routing it to a peer or holding it, or the source lying inside the overlay where this node does not own it
func (a sourceAnswer) forged() bool {
	return (!a.counted && (a.verdict == RoutePeer || a.verdict == RouteHeld)) || (a.overlay && !a.owned())
}

// keptAnswers holds answers for the sources of reads off the tun, kept from read to read while the table's generation holds
// each source and destination is looked up once, and again only once keptPairs pairs have filled the answers and started them over
// a route announced from a source prefix covers a source only for replies to some destinations, so the answer is kept per pair
// the zero value holds none
type keptAnswers struct {
	// generation is the table's generation the answers were looked up under
	generation uint64
	// last is the pair of the last lookup, reads mostly carrying one flow's packets in a row
	last       [2]netip.Addr
	lastAnswer sourceAnswer
	pairs      map[[2]netip.Addr]sourceAnswer
}

// keepFor drops every answer unless generation, the table's as a read begins, is the one they were looked up under
func (k *keptAnswers) keepFor(generation uint64) {
	if generation == k.generation {
		return
	}
	k.generation, k.last = generation, [2]netip.Addr{}
	clear(k.pairs)
}

func (m *Mesh) answerFor(kept *keptAnswers, source, destination netip.Addr) sourceAnswer {
	pair := [2]netip.Addr{source, destination}
	if pair == kept.last {
		return kept.lastAnswer
	}
	answer, seen := kept.pairs[pair]
	if !seen {
		_, verdict, match := m.replyRoute(source, destination)
		answer = sourceAnswer{verdict: verdict, counted: match.Counted, overlay: m.inOverlay(source)}
		switch {
		case kept.pairs == nil:
			kept.pairs = make(map[[2]netip.Addr]sourceAnswer)
		// answers outlive reads, so pairs past the bound start them over rather than grow them
		case len(kept.pairs) == keptPairs:
			clear(kept.pairs)
		}
		kept.pairs[pair] = answer
	}
	kept.last, kept.lastAnswer = pair, answer
	return answer
}

// edgeCheck checks raw, one packet of family the tun handed this node from source to destination, before it is steered
// and reports true with the reason for a packet it drops
// everything entering the mesh through this node is read off the tun, the host's own packets and what its kernel forwards from its other links alike
// segments is this node's own SIDs, and counted is the entry the destination resolves through counting as a default
func (m *Mesh) edgeCheck(kept *keptAnswers, segments *srv6.LocalTable, raw []byte, family byte, source, destination netip.Addr, counted bool) (transitReason, bool) {
	if family == esp.NextHeaderIPv6 {
		switch verdict, _, _ := srv6.WalkEdge(raw); verdict {
		case srv6.EdgeRoutingHeader:
			return transitRoutingHeader, true
		case srv6.EdgeInvalid:
			return transitInvalid, true
		}
		// RFC 8754 section 5.1 level 1, a packet entering the SR domain to one of its SIDs is dropped
		if segments.Holds(destination) {
			return transitOwnSID, true
		}
	}
	answer := m.answerFor(kept, source, destination)
	if answer.forged() {
		return transitForged, true
	}
	// a packet leaving the mesh through an exit comes from this node, so a host's neighbor reaches no exit through it
	if counted && !answer.owned() {
		return transitUnownedSource, true
	}
	return 0, false
}
