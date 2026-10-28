// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package netstack

import (
	"bytes"
	"net/netip"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
)

// the addresses the drift property draws packets between, by family
// the overlay's hosts, the internet, a network behind a peer, a LAN, the addresses no router forwards, and SIDs
var explainAddresses = map[int][]netip.Addr{
	4: {
		transitSender[4], transitOwn[4], transitFar[4], transitHeldHost[4], transitUnrouted[4], edgeAssigned[4],
		transitNowhere[4], transitStranger[4], edgeSubnetHost[4], edgeLAN[4],
		segAddr("169.254.0.9"), segAddr("224.0.0.1"), segAddr("255.255.255.255"), segAddr("127.0.0.1"), segAddr("0.0.0.0"),
	},
	6: {
		transitSender[6], transitOwn[6], transitFar[6], transitHeldHost[6], transitUnrouted[6], edgeAssigned[6],
		transitNowhere[6], transitStranger[6], edgeSubnetHost[6], edgeLAN[6],
		segAddr("fe80::9"), segAddr("ff02::1"), segAddr("::1"), segAddr("::"), segAddr("::ffff:192.0.2.3"),
		edgeOwnSID, edgeOtherSID,
	},
}

// the destination prefixes the drift property draws entries of, counting as a default and not, by family
var explainPrefixes = map[int][]netip.Prefix{
	4: {
		segPrefix("0.0.0.0/0"), segPrefix("0.0.0.0/1"), segPrefix("128.0.0.0/1"), segPrefix("192.0.0.0/2"),
		segPrefix("192.0.2.0/24"), segPrefix("203.0.113.0/24"), edgeSubnet[4], segPrefix("198.51.100.0/24"),
		hostPrefix(transitSender[4]), hostPrefix(transitOwn[4]), hostPrefix(transitFar[4]), hostPrefix(transitHeldHost[4]), hostPrefix(edgeAssigned[4]),
	},
	6: {
		segPrefix("::/0"), segPrefix("::/1"), segPrefix("2000::/3"), segPrefix("3fff::/20"),
		segPrefix("2001:db8::/32"), edgeSubnet[6], segPrefix("2001:db8:100::/64"), segPrefix("3fff:7::/64"),
		hostPrefix(transitSender[6]), hostPrefix(transitOwn[6]), hostPrefix(transitFar[6]), hostPrefix(transitHeldHost[6]), hostPrefix(edgeAssigned[6]),
	},
}

// the source prefixes an entry of the drift property may carry, RFC 9079's source-specific routes
var explainSources = map[int][]netip.Prefix{
	4: {segPrefix("192.0.2.0/24"), segPrefix("198.51.100.0/24")},
	6: {segPrefix("3fff::/20"), segPrefix("2001:db8:100::/64")},
}

// explainMesh is a transit node's mesh, its tun recording, with a feed of every record, this node's SID, and the table and settings hegel draws
// from is the peer of the session its packets arrive through, which the table may route to as to any other
func explainMesh(ht *hegel.T) (*Mesh, *Peer, *TraceFeed) {
	m, _ := startTransitMesh(nil)
	ht.Cleanup(m.Close)
	m.SetExit(&recordingExit{})
	mtu := hegel.Draw(ht, pbt.Spanning(1280, 1500))
	from, peer := (&recordingPeer{}).peer(ht, "from"), (&recordingPeer{}).peer(ht, "peer")
	from.SetMTU(mtu)
	peer.SetMTU(mtu)
	if !hegel.Draw(ht, hegel.Booleans()) {
		m.SetOverlay(nil)
	}
	m.SetTransit(hegel.Draw(ht, hegel.Booleans()))
	m.SetAdvertisedReady(hegel.Draw(ht, hegel.Booleans()), hegel.Draw(ht, hegel.Booleans()))
	values := []*Peer{from, peer, Local, Assigned, Unreachable}
	var advertised []netip.Prefix
	for _, family := range []int{4, 6} {
		// the sender routed back, far routed on, this node's own address, and the family's way out drawn outright: this node's own default cap.egress advertises, another node's, a hold or none
		m.Routes.Set(netip.Prefix{}, hostPrefix(transitSender[family]), from)
		m.Routes.Set(netip.Prefix{}, hostPrefix(transitFar[family]), peer)
		m.Routes.Set(netip.Prefix{}, hostPrefix(transitOwn[family]), Local)
		switch out := exitShapes[0].prefixes[family][0]; hegel.Draw(ht, pbt.Spanning(0, 3)) {
		case 0:
			m.Routes.Set(netip.Prefix{}, out, Local)
			advertised = append(advertised, out)
		case 1:
			m.Routes.Set(netip.Prefix{}, out, peer)
		case 2:
			m.Routes.Set(netip.Prefix{}, out, Unreachable)
		}
		for _, destination := range pbt.Subset(ht, explainPrefixes[family], 0, len(explainPrefixes[family])) {
			var source netip.Prefix
			if hegel.Draw(ht, pbt.Spanning(0, 3)) == 0 {
				source = explainSources[family][hegel.Draw(ht, pbt.Spanning(0, len(explainSources[family])-1))]
			}
			value := values[hegel.Draw(ht, pbt.Spanning(0, len(values)-1))]
			m.Routes.Set(source, destination, value)
			if value == Local && !source.IsValid() && hegel.Draw(ht, hegel.Booleans()) {
				advertised = append(advertised, destination)
			}
		}
	}
	m.SetEgressPrefixes(advertised)
	segments, err := srv6.NewLocalTable([]srv6.Segment{{SID: schema.AddrFrom(edgeOwnSID), Behavior: srv6.BehaviorEndDT46}}, transitOverlay)
	if err != nil {
		ht.Fatal(err)
	}
	m.SetSegments(segments)
	return m, from, openTrace(ht, m, TraceFilter{}, 0, control.TraceRateMax)
}

// explainAddress draws an address of family, either end of ends outright or any of explainAddresses admits takes
func explainAddress(ht *hegel.T, family int, ends [2]map[int]netip.Addr, admits func(netip.Addr) bool) netip.Addr {
	switch hegel.Draw(ht, pbt.Spanning(0, 2)) {
	case 0:
		return ends[0][family]
	case 2:
		return ends[1][family]
	}
	var allowed []netip.Addr
	for _, address := range explainAddresses[family] {
		if admits(address) {
			allowed = append(allowed, address)
		}
	}
	return allowed[hegel.Draw(ht, pbt.Spanning(0, len(allowed)-1))]
}

// explainPacket draws a packet from an address of sources to one of destinations admits takes, as explainAddress draws them, a hop limit around expiry
// of a size at or beside one of limits, well under them or well past the first
// and, where its family carries them, IPv4 options, a header failing its checksum, an IPv6 extension header or a packet it carries
// it is cut short one time in sixteen
func explainPacket(ht *hegel.T, limits []int, sources, destinations [2]map[int]netip.Addr, admits func(netip.Addr) bool) []byte {
	family := []int{4, 6}[hegel.Draw(ht, pbt.Spanning(0, 1))]
	source := explainAddress(ht, family, sources, func(netip.Addr) bool { return true })
	destination := explainAddress(ht, family, destinations, admits)
	sizes := []int{100}
	for _, limit := range limits {
		sizes = append(sizes, limit-1, limit, limit+1)
	}
	sizes = append(sizes, limits[0]+100)
	size := sizes[hegel.Draw(ht, pbt.Spanning(0, len(sizes)-1))]
	raw := withTTL(udpPacket(source, destination, size, hegel.Draw(ht, hegel.Booleans())), []byte{1, 2, 64}[hegel.Draw(ht, pbt.Spanning(0, 2))])
	// an option list that does not describe itself and a carried packet at an end of the span, the two kinds the fewest draws reach
	switch kind := hegel.Draw(ht, pbt.Spanning(0, 4)); {
	case kind == 1 && family == 4:
		raw = withOptions(raw, []byte{7, 7, 4, 0, 0, 0, 0, 0})
	case kind == 2 && family == 4:
		raw = withOptions(raw, []byte{131, 7, 4, 192, 0, 2, 3, 0})
	case kind == 4 && family == 4:
		raw = withOptions(raw, []byte{7, 9, 4, 0})
	case kind == 3 && family == 4:
		raw[10] ^= 0xff
	case kind == 1 && family == 6:
		raw = withRouting(raw, []byte{2, 4}[hegel.Draw(ht, pbt.Spanning(0, 1))])
	case kind == 2 && family == 6:
		raw = withDestinationOptions(raw)
	case kind == 4 && family == 6:
		inner := []int{4, 6}[hegel.Draw(ht, pbt.Spanning(0, 1))]
		raw = encapsulated(source, destination, udpPacket(transitOwn[inner], transitFar[inner], 100, false))
	}
	if hegel.Draw(ht, pbt.Spanning(0, 15)) == 0 {
		raw = raw[:len(raw)-10]
	}
	return raw
}

// recorded is the part of a record naming its packet's decision, the next peer only for a forward, whose record alone names one
func recorded(r TraceRecord) Explanation {
	e := Explanation{Decision: r.Decision, Reason: r.Reason, Answer: r.Answer}
	if r.Decision == TraceForward {
		e.Next = r.Next
	}
	return e
}

// walked is the part of an Explanation a record names
func walked(e Explanation) Explanation {
	out := Explanation{Decision: e.Decision, Reason: e.Reason, Answer: e.Answer}
	if e.Decision == TraceForward {
		out.Next = e.Next
	}
	return out
}

// decisionRecord is the one record of a packet's decision among records, the budget's refusal of a forward left out
func decisionRecord(ht *hegel.T, records []TraceRecord) TraceRecord {
	var decided []TraceRecord
	for _, r := range records {
		if r.Reason != "budget" {
			decided = append(decided, r)
		}
	}
	if len(decided) != 1 {
		ht.Fatalf("one packet drew %d records of its decision: %+v", len(decided), records)
	}
	return decided[0]
}

// over drawn tables and settings, and drawn packets a session delivers that no segment of this node takes
// Explain names the decision, reason, answer and next peer of the record the tracer takes when decide runs the same packet
func TestExplainNamesWhatTheDecisionRecords(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		m, from, feed := explainMesh(ht)
		// a sender the mesh routes back and a stranger, the internet and an overlay address no node announces, drawn outright
		for range hegel.Draw(ht, pbt.Spanning(1, 16)) {
			raw := explainPacket(ht, []int{from.MTU()}, [2]map[int]netip.Addr{transitSender, transitStranger}, [2]map[int]netip.Addr{transitNowhere, transitUnrouted}, func(a netip.Addr) bool { return !m.Segments().Holds(a) })
			explained := m.Explain(raw)
			m.DeliverInboundBatch(framed(bytes.Clone(raw)), from.MTU(), from)
			if got, want := walked(explained), recorded(decisionRecord(ht, queued(feed))); got != want {
				ht.Fatalf("Explain of %x is %+v, the record %+v", raw, got, want)
			}
		}
	})
}
