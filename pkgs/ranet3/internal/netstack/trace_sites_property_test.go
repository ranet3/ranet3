// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package netstack

import (
	"net/netip"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// siteKind is a packet the property draws, of the families it applies to, and the record the decision gives it, reason a TraceRecord.Reason
type siteKind struct {
	name     string
	families []int
	packet   func(family int) []byte
	decision TraceDecision
	reason   string
	// forwarded is a kind the decision would forward, which it answers refused while cap.transit is off
	forwarded bool
	// budget is a kind whose peer's budget refuses it once forwarded
	budget bool
}

var both, v4, v6 = []int{4, 6}, []int{4}, []int{6}

// decideKinds are the packets of a session the property draws for a tracedNode
var decideKinds = []siteKind{
	{"forward", both, func(f int) []byte { return udpPacket(transitSender[f], transitFar[f], 100, false) }, TraceForward, "", true, false},
	{"cut", v4, func(f int) []byte { return udpPacket(transitSender[f], transitFar[f], tracedMTU+100, false) }, TraceForward, "", true, false},
	{"budget", both, func(f int) []byte { return udpPacket(transitSender[f], transitClosed[f], 100, false) }, TraceForward, "", true, true},
	{"deliver", both, func(f int) []byte { return udpPacket(transitSender[f], transitOwn[f], 100, false) }, TraceDeliver, "", false, false},
	{"link scope", v6, func(f int) []byte { return udpPacket(transitSender[f], segAddr("ff02::1"), 100, false) }, TraceDeliver, "", false, false},
	{"egress", v4, func(f int) []byte { return udpPacket(transitSender[f], transitNowhere[f], 100, false) }, TraceEgress, "", false, false},
	{"not ready", v6, func(f int) []byte { return udpPacket(transitSender[f], transitNowhere[f], 100, false) }, TraceDrop, "not_ready", false, false},
	{"unrouted source", v4, func(f int) []byte { return udpPacket(transitStranger[f], transitNowhere[f], 100, false) }, TraceDrop, "unrouted_source", false, false},
	{"no route", both, func(f int) []byte { return udpPacket(transitSender[f], transitUnrouted[f], 100, false) }, TraceAnswer, "no_route", false, false},
	{"held", both, func(f int) []byte { return udpPacket(transitSender[f], transitHeldHost[f], 100, false) }, TraceAnswer, "held", false, false},
	{"expired", both, func(f int) []byte { return withTTL(udpPacket(transitSender[f], transitFar[f], 100, false), 1) }, TraceAnswer, "expired", true, false},
	{"too big", both, func(f int) []byte { return udpPacket(transitSender[f], transitFar[f], tracedMTU+100, true) }, TraceAnswer, "too_big", true, false},
	{"martian", both, func(f int) []byte {
		return udpPacket(transitSender[f], map[int]netip.Addr{4: segAddr("127.0.0.1"), 6: segAddr("::1")}[f], 100, false)
	}, TraceDrop, "martian", false, false},
	{"source route", v4, func(f int) []byte {
		return withOptions(udpPacket(transitSender[f], transitFar[f], 100, false), []byte{131, 7, 4, 192, 0, 2, 3, 0})
	}, TraceDrop, "source_route", true, false},
	{"truncated", v4, func(f int) []byte { return udpPacket(transitSender[f], transitFar[f], 100, false)[:60] }, TraceDrop, "invalid", false, false},
}

// classifyKinds are the reads the property draws for a tracedLeaf
var classifyKinds = []siteKind{
	{"queued", both, func(f int) []byte { return udpPacket(transitOwn[f], transitFar[f], 100, false) }, TraceForward, "", false, false},
	{"multicast", both, func(f int) []byte {
		return udpPacket(transitOwn[f], map[int]netip.Addr{4: segAddr("224.0.0.1"), 6: segAddr("ff02::1")}[f], 100, false)
	}, TraceDrop, "multicast", false, false},
	{"forged", both, func(f int) []byte { return udpPacket(transitSender[f], transitFar[f], 100, false) }, TraceDrop, "forged", false, false},
	{"routing header", v6, func(f int) []byte { return withRouting(udpPacket(transitOwn[f], transitFar[f], 100, false), 4) }, TraceDrop, "routing_header", false, false},
	{"sid", v6, func(f int) []byte { return udpPacket(transitOwn[f], edgeOwnSID, 100, false) }, TraceDrop, "sid", false, false},
	{"unowned source", both, func(f int) []byte { return udpPacket(edgeLAN[f], edgeInternet[f], 100, false) }, TraceDrop, "unowned_source", false, false},
	{"nested", v6, func(f int) []byte {
		return encapsulated(transitOwn[6], edgeOtherSID, encapsulated(transitOwn[4], transitFar[4], udpPacket(transitOwn[6], transitFar[6], 100, false)))
	}, TraceDrop, "nested", false, false},
	{"looped", both, func(f int) []byte { return udpPacket(transitOwn[f], edgeAssigned[f], 100, false) }, TraceDrop, "looped", false, false},
	{"unparseable", v4, func(int) []byte { return []byte{0x45, 0, 0, 10, 0, 0, 0, 0, 64, 17} }, TraceDrop, "invalid", false, false},
	{"held", both, func(f int) []byte { return udpPacket(transitOwn[f], transitHeldHost[f], 100, false) }, TraceAnswer, "held", false, false},
	{"too big", v6, func(f int) []byte { return udpPacket(transitOwn[f], transitFar[f], tracedMTU+100, false) }, TraceAnswer, "too_big", false, false},
}

// drawKinds draws a batch of kinds, each with a family it applies to
func drawKinds(tc hegel.TestCase, kinds []siteKind) ([]siteKind, [][]byte) {
	var drawn []siteKind
	var packets [][]byte
	for range hegel.Draw(tc, pbt.Spanning(1, 16)) {
		kind := kinds[hegel.Draw(tc, pbt.Spanning(0, len(kinds)-1))]
		family := kind.families[hegel.Draw(tc, pbt.Spanning(0, len(kind.families)-1))]
		drawn = append(drawn, kind)
		packets = append(packets, kind.packet(family))
	}
	return drawn, packets
}

// counted is the counters a record's decision and reason move, as TransitCounters names them, the answered among them only for an answer sent
func counted(records []TraceRecord) (counters TransitCounters, budget int) {
	byReason := map[string]*uint64{
		"expired": &counters.Expired, "no_route": &counters.NoRoute, "held": &counters.Held, "refused": &counters.Refused,
		"invalid": &counters.Invalid, "martian": &counters.Martian, "source_route": &counters.SourceRoute,
		"unrouted_source": &counters.UnroutedSource, "not_ready": &counters.NotReady, "too_big": &counters.TooBig,
		"multicast": &counters.Multicast, "forged": &counters.Forged, "routing_header": &counters.RoutingHeader, "sid": &counters.SID,
		"unowned_source": &counters.UnownedSource, "nested": &counters.Nested, "looped": &counters.Looped,
	}
	for _, r := range records {
		switch r.Decision {
		case TraceForward:
			counters.Forwarded++
		case TraceDeliver, TraceEgress:
			counters.Delivered++
		default:
			if r.Reason == "budget" {
				budget++
				continue
			}
			*byReason[r.Reason]++
		}
		if r.Outcome == TraceSent {
			counters.Answered++
		}
	}
	return counters, budget
}

// over drawn batches a session delivers, of every outcome the decision gives, with cap.transit on and off
// the records come in the order the packets did, one for each, the decision and reason each kind meets, and a budget drop after each forward its peer's budget refused
// and each counter of TransitCounters and the refusing peer's Dropped moved exactly as the records say
func TestTraceRecordsTheDecisionsCountersOnePerPacket(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		n, feed := tracedNode(ht)
		transit := hegel.Draw(ht, hegel.Booleans())
		n.m.SetTransit(transit)
		kinds, packets := drawKinds(ht, decideKinds)
		records := deliverTraced(n, feed, packets...)
		var decided, budget []TraceRecord
		for _, r := range records {
			if r.Reason == "budget" {
				budget = append(budget, r)
			} else {
				decided = append(decided, r)
			}
		}
		if len(decided) != len(kinds) {
			ht.Fatalf("%d packets drew %d records but budget drops, want one each: %+v", len(kinds), len(decided), records)
		}
		refused := 0
		for i, kind := range kinds {
			decision, reason := kind.decision, kind.reason
			if kind.forwarded && !transit {
				decision, reason = TraceAnswer, "refused"
			}
			if r := decided[i]; r.Decision != decision || r.Reason != reason {
				ht.Fatalf("packet %d, %s with cap.transit %v, drew %v %q, want %v %q", i, kind.name, transit, r.Decision, r.Reason, decision, reason)
			}
			if kind.budget && transit {
				refused++
			}
		}
		if len(budget) != refused {
			ht.Fatalf("%d forwards to the closed peer drew %d budget drops", refused, len(budget))
		}
		want, dropped := counted(records)
		if got := n.m.TransitCounters(); got != want {
			ht.Fatalf("the decision counted %+v, the records say %+v", got, want)
		}
		if got := closedPeer(n).Dropped(); got != uint64(dropped) {
			ht.Fatalf("the closed peer dropped %d, the records say %d", got, dropped)
		}
	})
}

// over drawn reads off the tun of every outcome the checks give, the records come one for each packet in the order it was read, the decision and reason each kind meets
// each counter of TransitCounters moved as the records say, the answers about a size as TooBigAnswered alone, and the forwards are the packets classify queued for their peer
func TestTraceRecordsTheChecksCountersOnePerRead(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		m, feed := tracedLeaf(ht)
		kinds, packets := drawKinds(ht, classifyKinds)
		went := classifiedTo(m, packets...)
		records := queued(feed)
		if len(records) != len(kinds) {
			ht.Fatalf("%d reads drew %d records, want one each: %+v", len(kinds), len(records), records)
		}
		var sizes, unrouted, rest []TraceRecord
		queuedReads := 0
		for i, kind := range kinds {
			r := records[i]
			if r.Decision != kind.decision || r.Reason != kind.reason {
				ht.Fatalf("read %d, %s, drew %v %q, want %v %q", i, kind.name, r.Decision, r.Reason, kind.decision, kind.reason)
			}
			if went[i] != nil {
				queuedReads++
			}
			switch {
			case r.Decision == TraceForward:
			case r.Reason == "too_big":
				sizes = append(sizes, r)
			case r.Decision == TraceAnswer:
				unrouted = append(unrouted, r)
			default:
				rest = append(rest, r)
			}
		}
		forwards := len(records) - len(sizes) - len(unrouted) - len(rest)
		if forwards != queuedReads {
			ht.Fatalf("%d forward records for %d reads queued for their peer", forwards, queuedReads)
		}
		// the checks count a read they drop by its reason, and one to no route or a hold as answered alone
		want, _ := counted(rest)
		for _, r := range unrouted {
			if r.Outcome == TraceSent {
				want.Answered++
			}
		}
		if got := m.TransitCounters(); got != want {
			ht.Fatalf("the checks counted %+v, the records say %+v", got, want)
		}
		sent := 0
		for _, r := range sizes {
			if r.Outcome == TraceSent {
				sent++
			}
		}
		if got := m.TooBigAnswered(); got != uint64(sent) {
			ht.Fatalf("the reads answered %d about their size, the records say %d", got, sent)
		}
	})
}
