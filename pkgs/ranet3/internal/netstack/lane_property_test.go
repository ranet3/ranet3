// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package netstack

import (
	"net/netip"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
)

// the segments the session property's paths visit, one or two of them in a drawn order
var sessionSegments = []netip.Addr{segAddr("3fff:7::1"), segAddr("3fff:8::1"), segAddr("3fff:9::1")}

// the outer sources a policy of the session property sends from, the block's and an entry's or the path's own, and the source prefixes covering each
var sessionOuter = []netip.Addr{segAddr("3fff:b:0:100::1"), segAddr("3fff:c::1")}
var sessionOuterSources = []netip.Prefix{segPrefix("3fff:b::/32"), segPrefix("3fff:c::/32")}

// the sources a lane packet of the session property comes from, by family: this node's own address and a server's no route covers
// and the source prefixes covering each, which entries toward the destinations and the segments may carry
var sessionSources = map[int][]netip.Addr{4: {transitOwn[4], segAddr("198.51.100.5")}, 6: {transitOwn[6], segAddr("2001:db8:100::5")}}
var sessionReadSources = map[int][]netip.Prefix{4: {segPrefix("192.0.2.0/30"), segPrefix("198.51.100.0/24")}, 6: {segPrefix("3fff::/32"), segPrefix("2001:db8:100::/64")}}

// the destinations a lane packet of the session property goes to, by family: two overlay hosts and an address outside the overlay
// and the destination prefixes the property draws entries of, a default, the overlay, the two hosts and a network outside the overlay holding the third
var sessionDestinations = map[int][]netip.Addr{4: {transitSender[4], transitFar[4], transitNowhere[4]}, 6: {transitSender[6], transitFar[6], transitNowhere[6]}}
var sessionPrefixes = map[int][]netip.Prefix{
	4: {segPrefix("0.0.0.0/0"), segPrefix("192.0.2.0/24"), hostPrefix(transitSender[4]), hostPrefix(transitFar[4]), segPrefix("203.0.113.0/24")},
	6: {segPrefix("::/0"), segPrefix("3fff::/20"), hostPrefix(transitSender[6]), hostPrefix(transitFar[6]), segPrefix("2001:db8::/48")},
}

// the selectors of the steer entries the session property draws, none covering a probe, each sent through its own drawn path and source
var sessionSteers = []srv6.Steer{
	{To: schema.PrefixFrom(hostPrefix(transitSender[6]))},
	{To: schema.PrefixFrom(hostPrefix(transitSender[4]))},
	{To: schema.PrefixFrom(segPrefix("2001:db8::/48"))},
	{To: schema.PrefixFrom(segPrefix("203.0.113.0/24"))},
	{From: schema.PrefixFrom(segPrefix("2001:db8:100::/64")), To: schema.PrefixFrom(segPrefix("2001:db8::/48"))},
	{From: schema.PrefixFrom(hostPrefix(transitOwn[4])), To: schema.PrefixFrom(hostPrefix(transitFar[4]))},
}

// sessionProbes is an overlay address of each family per peer of the session property, routed to that peer alone by its own host route
// no steer entry claims one and cap.exit via's path takes none, so SameSession toward a probe is the probe's peer's session
var sessionProbes = map[int][]netip.Addr{
	4: {segAddr("192.0.2.20"), segAddr("192.0.2.21"), segAddr("192.0.2.22")},
	6: {segAddr("3fff:e::20"), segAddr("3fff:e::21"), segAddr("3fff:e::22")},
}

// sessionPath draws a path of one or two segments and the outer source it is sent from
func sessionPath(ht *hegel.T) ([]netip.Addr, netip.Addr) {
	return pbt.Subset(ht, sessionSegments, 1, 2), sessionOuter[hegel.Draw(ht, pbt.Spanning(0, len(sessionOuter)-1))]
}

// sessionMesh is a mesh with its outbound pipeline running and three recording peers, each holding its probes
// with this node's own address of each family its own, and drawn routes, steer entries, cap.exit via's path and whether the entries are stopped
// an entry toward a segment may carry a source prefix covering a policy's outer source or a lane packet's source, which then resolve the segment apart
func sessionMesh(ht *hegel.T) (*Mesh, []*recordingPeer) {
	m, _ := startTransitMesh(nil)
	ht.Cleanup(m.Close)
	m.ownedOnly = hegel.Draw(ht, hegel.Booleans())
	recorders := []*recordingPeer{{}, {}, {}}
	values := []*Peer{Local, Unreachable}
	for i, recorder := range recorders {
		peer := recorder.peer(ht, string(rune('0'+i)))
		values = append(values, peer)
		for _, family := range []int{4, 6} {
			m.Routes.Set(netip.Prefix{}, hostPrefix(sessionProbes[family][i]), peer)
		}
	}
	draw := func(sources []netip.Prefix, destination netip.Prefix) {
		var source netip.Prefix
		if pick := hegel.Draw(ht, pbt.Spanning(0, len(sources))); pick != 0 {
			source = sources[pick-1]
		}
		m.Routes.Set(source, destination, values[hegel.Draw(ht, pbt.Spanning(0, len(values)-1))])
	}
	for _, family := range []int{4, 6} {
		m.Routes.Set(netip.Prefix{}, hostPrefix(transitOwn[family]), Local)
		for _, destination := range pbt.Subset(ht, sessionPrefixes[family], 0, len(sessionPrefixes[family])) {
			draw(sessionReadSources[family], destination)
		}
	}
	// a segment's own /128 or a /48 covering it, each from no source, a policy's or a lane packet's
	segmentSources := append(append([]netip.Prefix(nil), sessionOuterSources...), sessionReadSources[6]...)
	for _, segment := range sessionSegments {
		for range hegel.Draw(ht, pbt.Spanning(0, 4)) {
			destination := hostPrefix(segment)
			if hegel.Draw(ht, hegel.Booleans()) {
				destination = netip.PrefixFrom(segment, 48).Masked()
			}
			draw(segmentSources, destination)
		}
	}
	steers := pbt.Subset(ht, sessionSteers, 0, len(sessionSteers))
	for i := range steers {
		path, source := sessionPath(ht)
		steers[i].Source = schema.AddrFrom(source)
		for _, segment := range path {
			steers[i].Via = append(steers[i].Via, schema.AddrFrom(segment))
		}
	}
	steering, err := srv6.NewSteerTable(steers, schema.AddrFrom(sessionOuter[0]))
	if err != nil {
		ht.Fatal(err)
	}
	// the path three times in four, since only reads from this node's own address outside the overlay meet it
	if hegel.Draw(ht, pbt.Spanning(0, 3)) != 0 {
		path, source := sessionPath(ht)
		if steering, err = steering.WithDefault(source, path); err != nil {
			ht.Fatal(err)
		}
	}
	m.SetSteering(steering)
	m.SetSteeringEnabled(hegel.Draw(ht, hegel.Booleans()))
	return m, recorders
}

// sessionSent is how many packets each recorder's peer transmitted, once each gave back its budgets
func sessionSent(ht *hegel.T, recorders []*recordingPeer) []int {
	sent := make([]int, len(recorders))
	for i, recorder := range recorders {
		sent[i] = len(recorder.packets(ht))
	}
	return sent
}

// routedNowhere is how many reads classify routed to no peer past the checks: written back, looped, unrouted or held
func routedNowhere(m *Mesh) uint64 {
	var n uint64
	for _, reason := range []transitReason{transitDelivered, transitLooped, transitNoRoute, transitHeld} {
		n += m.transitCounts[reason].Load()
	}
	return n
}

// transitTotal is every count of TransitCounters, the drops edgeCheck counts among them
func transitTotal(m *Mesh) uint64 {
	var n uint64
	for reason := range transitReasonCount {
		n += m.transitCounts[reason].Load()
	}
	return n
}

// over drawn routes, steer entries of one and two segments, cap.exit via's path and entries stopped or not
// a lane packet classify sends to a peer has SameSession name that peer's session toward its destination and no other's
// and one classify routes to no peer has SameSession name none: the session check and classify keep one steered resolution
// a lane packet edgeCheck drops is left out, since sessionToward skips edgeCheck
func TestLaneSendsByTheSessionSameSessionNames(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		m, recorders := sessionMesh(ht)
		lane := m.OpenLane()
		defer lane.Close()
		for range hegel.Draw(ht, pbt.Spanning(1, 8)) {
			family := []int{4, 6}[hegel.Draw(ht, pbt.Spanning(0, 1))]
			source := sessionSources[family][hegel.Draw(ht, pbt.Spanning(0, len(sessionSources[family])-1))]
			destination := sessionDestinations[family][hegel.Draw(ht, pbt.Spanning(0, len(sessionDestinations[family])-1))]
			before, nowhere, counted := sessionSent(ht, recorders), routedNowhere(m), transitTotal(m)
			if !lane.Fill(laid(udpPacket(source, destination, 100, false))) {
				ht.Fatal("an open lane of an open mesh filled nothing")
			}
			after := sessionSent(ht, recorders)
			sent := -1
			for i := range recorders {
				switch after[i] - before[i] {
				case 0:
				case 1:
					if sent != -1 {
						ht.Fatalf("a lane packet from %s to %s went to peers %d and %d", source, destination, sent, i)
					}
					sent = i
				default:
					ht.Fatalf("a lane packet from %s to %s went to peer %d %d times", source, destination, i, after[i]-before[i])
				}
			}
			toward := "none"
			if peer := m.sessionToward(m.Steering(), source, destination); peer != nil {
				toward = peer.ID
			}
			switch {
			case sent != -1:
				for i := range recorders {
					if got := lane.SameSession(source, destination, sessionProbes[family][i]); got != (i == sent) {
						ht.Fatalf("a lane packet from %s to %s went to peer %d, and SameSession with peer %d's probe is %t, sessionToward naming %s", source, destination, sent, i, got, toward)
					}
				}
			case routedNowhere(m) != nowhere:
				if lane.SameSession(source, destination, destination) {
					ht.Fatalf("a lane packet from %s to %s went to no peer, and SameSession names peer %s", source, destination, toward)
				}
			case transitTotal(m) == counted:
				ht.Fatalf("a lane packet from %s to %s went to no peer, and classify counted it nowhere", source, destination)
			}
		}
	})
}
