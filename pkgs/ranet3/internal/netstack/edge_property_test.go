// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package netstack

import (
	"net/netip"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/esp"
	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
)

// bestUncounted is the entry RFC 9079 section 4 prefers among those matching a packet from src to dst that do not count as a default with the overlay
// the entries that count are left out before any is compared, RFC 3704 section 2.5's check ignoring default routes
func (m *routeModel) bestUncounted(src, dst netip.Addr) (tableEntry, bool) {
	var best tableEntry
	found := false
	for _, e := range m.entries {
		if !e.matches(src, dst) || schema.CapturesTheMachine(e.destination, m.overlay) {
			continue
		}
		longer := e.destination.Bits() > best.destination.Bits() ||
			e.destination.Bits() == best.destination.Bits() && e.source.Bits() > best.source.Bits()
		if !found || longer {
			best, found = e, true
		}
	}
	return best, found
}

// forged is the model's verdict on a packet from source to destination read off the tun, by the route a reply to it takes
// the table rule, an entry routing source to a peer or holding it, and the overlay rule, source inside the overlay with no entry of this node's covering it
func (m *routeModel) forged(source, destination netip.Addr) (forged, owned, others bool) {
	e, found := m.bestUncounted(destination, source)
	owned = found && (e.kind == localEntry || e.kind == assignedEntry)
	others = found && (e.kind == learnedEntry || e.kind == heldEntry)
	inside := false
	for _, prefix := range m.overlay {
		inside = inside || prefix.Contains(source)
	}
	return others || inside && !owned, owned, others
}

// drawEdgeTable draws a mesh with no tun over a table of learned routes, holds and this node's own entries of both kinds, with and without source prefixes, long and short enough to count as a default, under a drawn overlay
// the model of the same table, and the sources and destinations of reads to draw: the entries' edges and addresses drawn inside them and anywhere
func drawEdgeTable(tc hegel.TestCase) (*Mesh, *routeModel, []netip.Addr, []netip.Addr) {
	anchors4 := hegel.Draw(tc, hegel.Lists(hegel.IPAddresses().IPv4()).MinSize(1).MaxSize(3))
	anchors6 := hegel.Draw(tc, hegel.Lists(hegel.IPAddresses().IPv6()).MinSize(1).MaxSize(3))
	model := &routeModel{peers: []*Peer{{ID: "a"}, {ID: "b"}}}
	m := &Mesh{Name: "test0", Routes: NewRouteTable(), closed: make(chan struct{})}
	for range hegel.Draw(tc, pbt.Spanning(1, 10)) {
		anchors := anchors6
		if hegel.Draw(tc, hegel.Booleans()) {
			anchors = anchors4
		}
		e := drawEntry(tc, anchors, len(model.peers))
		value := model.peers[e.peer]
		switch e.kind {
		case heldEntry:
			value = Unreachable
		case localEntry:
			value = Local
		case assignedEntry:
			value = Assigned
		}
		m.Routes.Set(e.source, e.destination, value)
		model.set(e)
	}
	model.overlay = model.drawOverlay(tc, anchors4, anchors6)
	m.SetOverlay(model.overlay)

	// sources are looked up as destinations and destinations as sources, so each is drawn from the other side of the entries
	var sources, destinations []netip.Addr
	for _, e := range model.entries {
		sources = append(sources, edges(e.destination)...)
		destinations = append(destinations, edges(e.source)...)
		sources = append(sources, anchorNear(tc, e.destination.Addr(), e.destination.Bits()))
		if e.source.IsValid() {
			destinations = append(destinations, anchorNear(tc, e.source.Addr(), e.source.Bits()))
		}
	}
	for _, anchor := range append(anchors4, anchors6...) {
		destinations = append(destinations, anchorNear(tc, anchor, hegel.Draw(tc, pbt.Spanning(0, anchor.BitLen()))))
	}
	return m, model, sources, destinations
}

// over drawn tables, a read off the tun carrying packets between the entries' edges and addresses drawn inside them and anywhere is forged exactly where a model passing over every counted entry says
// and dropped for its source otherwise exactly where its destination resolves through an entry counting as a default and no uncounted entry of this node's own covers the source
// a source an entry of this node's own covers always passes, one the table routes to a peer or holds never does, whatever the read's other packets
func TestTUNReadIsDroppedExactlyWhereTheModelSkippingCountedEntriesSays(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		m, model, sources, destinations := drawEdgeTable(ht)
		var kept keptAnswers
		for range hegel.Draw(ht, pbt.Spanning(1, 16)) {
			source := hegel.Draw(ht, hegel.SampledFrom(sources))
			destination := hegel.Draw(ht, hegel.SampledFrom(destinations))
			if source.Zone() != "" || destination.Zone() != "" || source.Is4() != destination.Is4() {
				continue
			}
			family := byte(esp.NextHeaderIPv6)
			if source.Is4() {
				family = esp.NextHeaderIPv4
			}
			_, _, match := m.Routes.Resolve(source, destination)
			reason, dropped := m.edgeCheck(&kept, nil, udpPacket(source, destination, 100, false), family, source, destination, match.Counted)
			forged, owned, others := model.forged(source, destination)
			_, _, toward := model.answer(source, destination)
			want, drop := transitReason(0), false
			switch {
			case forged:
				want, drop = transitForged, true
			case toward.Counted && !owned:
				want, drop = transitUnownedSource, true
			}
			switch {
			case dropped != drop || dropped && reason != want:
				ht.Fatalf("a read from %v to %v was dropped %t for reason %d, the model drops it %t for reason %d, in %#v under the overlay %v", source, destination, dropped, reason, drop, want, model.entries, model.overlay)
			case owned && dropped, others && !dropped:
				ht.Fatalf("a read from %v to %v that an entry of this node's covers %t or another node's %t was dropped %t", source, destination, owned, others, dropped)
			}
		}
	})
}

// a packet an IPv6 read carries meets exactly the checks it meets read itself, one level deep
// over drawn tables, a packet of either family between drawn addresses or to this node's SID, behind a routing header of a drawn type or none, carrying a packet or none
// carried from this node's own address to another node's SID, it takes the verdict of the carrying header alone where that one is dropped
// and otherwise its own as a read of its own with what it carries left out, nested where it carries a packet that verdict passes
func TestTUNReadCarriedPacketMeetsExactlyTheChecksItMeetsReadItself(t *testing.T) {
	sid := segAddr("3fff:6::1")
	segments, err := srv6.NewLocalTable([]srv6.Segment{{SID: schema.AddrFrom(sid), Behavior: srv6.BehaviorEndDT46}}, transitOverlay)
	if err != nil {
		t.Fatal(err)
	}
	outerSource, outerDestination := segAddr("3fff:0:5ee::1"), segAddr("3fff:0:5ee::2")
	pbt.Check(t, func(ht *hegel.T) {
		m, _, sources, destinations := drawEdgeTable(ht)
		m.Routes.Set(netip.Prefix{}, hostPrefix(outerSource), Local)
		m.Routes.Set(netip.Prefix{}, hostPrefix(outerDestination), &Peer{ID: "another node"})
		destinations = append(destinations, sid)
		check := func(raw []byte) (transitReason, bool) {
			var kept keptAnswers
			source, destination, family, _ := addrsOf(raw)
			_, _, match := m.Routes.Resolve(source, destination)
			return m.edgeCheck(&kept, segments, raw, family, source, destination, match.Counted)
		}
		ends := func() (netip.Addr, netip.Addr, bool) {
			source := hegel.Draw(ht, hegel.SampledFrom(sources))
			destination := hegel.Draw(ht, hegel.SampledFrom(destinations))
			return source, destination, source.Zone() == "" && destination.Zone() == "" && source.Is4() == destination.Is4()
		}
		for range hegel.Draw(ht, pbt.Spanning(1, 8)) {
			source, destination, ok := ends()
			if !ok {
				continue
			}
			alone := udpPacket(source, destination, 100, false)
			sent := alone
			if hegel.Draw(ht, hegel.Booleans()) {
				if carriedSource, carriedDestination, ok := ends(); ok {
					sent = encapsulated(source, destination, udpPacket(carriedSource, carriedDestination, 100, false))
				}
			}
			if source.Is6() && hegel.Draw(ht, hegel.Booleans()) {
				kind := hegel.Draw(ht, hegel.SampledFrom([]byte{0, 1, 2, 3, 4, 5, 253, 254}))
				alone, sent = withRouting(alone, kind), withRouting(sent, kind)
			}
			want, drop := check(udpPacket(outerSource, outerDestination, 100, false))
			if !drop {
				want, drop = check(alone)
			}
			if !drop && len(sent) != len(alone) {
				want, drop = transitNested, true
			}
			if got, dropped := check(encapsulated(outerSource, outerDestination, sent)); dropped != drop || dropped && got != want {
				ht.Fatalf("a packet from %v to %v carried in IPv6 was dropped %t for reason %d, read itself %t for reason %d, carrying a packet %t", source, destination, dropped, got, drop, want, len(sent) != len(alone))
			}
		}
	})
}
