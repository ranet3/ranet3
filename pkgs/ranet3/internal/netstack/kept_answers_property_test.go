// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package netstack

import (
	"net/netip"
	"slices"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/sadr"
	"ranet3.com/pkgs/ranet3/schema"
)

// changesReadPackets is the most packets one read of the changes property carries
const changesReadPackets = 4

// over drawn tables and drawn runs of changes to what the sources' answers of reads off the tun read, the table's entries, the overlay and the egress prefixes, each change followed by a read
// each read carries a packet of each of a few drawn pairs, the entries and overlay prefixes written cover their sources and destinations at drawn lengths, and the entries and peers removed are mostly ones their replies resolve through
// each read through one batch, whose answers outlive the read, sends every packet where a mesh of the same table sends it read alone with answers of its own
// and counts what that mesh counts
func TestTUNReadsAcrossChangesGoWhereFreshAnswersSendThem(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		m, model, sources, destinations := drawEdgeTable(ht)
		for _, peer := range model.peers {
			peer.SetMTU(DefaultMTU)
		}
		// half the runs start with no overlay, where the table alone decides a source, as the overlay forges an unowned source whatever the table says
		if hegel.Draw(ht, hegel.Booleans()) {
			model.overlay = nil
			m.SetOverlay(nil)
		}
		fresh := &Mesh{Name: "test0", Routes: NewRouteTable(), closed: make(chan struct{})}
		fresh.SetOverlay(model.overlay)
		for _, route := range m.Routes.Snapshot() {
			fresh.Routes.Set(route.Source, route.Destination, route.Value)
		}
		m.startSegmentReports()
		fresh.startSegmentReports()
		var pairs [][2]netip.Addr
		for range hegel.Draw(ht, pbt.Spanning(1, 4)) {
			source := hegel.Draw(ht, hegel.SampledFrom(sources))
			destination := hegel.Draw(ht, hegel.SampledFrom(destinations))
			if source.Zone() == "" && destination.Zone() == "" && source.Is4() == destination.Is4() {
				pairs = append(pairs, [2]netip.Addr{source, destination})
			}
		}
		if len(pairs) == 0 {
			return
		}
		// near is a prefix covering address at a drawn length, so a write lands over the pairs' sources and destinations
		near := func(address netip.Addr) netip.Prefix {
			return netip.PrefixFrom(address, hegel.Draw(ht, pbt.Spanning(0, address.BitLen()))).Masked()
		}
		both := func(change func(*Mesh)) {
			change(m)
			change(fresh)
		}
		// covering is the entries some pair's reply resolves through or passes over, so a removal of one moves an answer
		covering := func() []sadr.Route[*Peer] {
			var routes []sadr.Route[*Peer]
			for _, route := range m.Routes.Snapshot() {
				if slices.ContainsFunc(pairs, func(pair [2]netip.Addr) bool { return route.Destination.Contains(pair[0]) }) {
					routes = append(routes, route)
				}
			}
			return routes
		}
		b := newOutboundBatch(changesReadPackets)
		// read reads every pair in a drawn order, so each answer a change moves is read after it, from the last read's last pair or another
		read := func() {
			packets := make([][]byte, len(pairs))
			for i, pair := range pairs {
				packets[i] = udpPacket(pair[0], pair[1], 100, false)
			}
			for i := len(packets) - 1; i > 0; i-- {
				j := hegel.Draw(ht, hegel.Integers(0, i))
				packets[i], packets[j] = packets[j], packets[i]
			}
			got := rereadTo(m, b, packets...)
			var want []*Peer
			for _, raw := range packets {
				want = append(want, classifiedTo(fresh, raw)...)
			}
			if !slices.Equal(got, want) {
				ht.Fatalf("a read went to %v, its packets read alone with answers of their own to %v, in %v under the overlay %v", got, want, m.Routes.Debug(), model.overlay)
			}
			if counted, wantCounted := m.TransitCounters(), fresh.TransitCounters(); counted != wantCounted {
				ht.Fatalf("the reads counted %+v, their packets read alone with answers of their own %+v", counted, wantCounted)
			}
		}
		for range hegel.Draw(ht, pbt.Spanning(1, 16)) {
			// a change, or none, and a read after it
			switch hegel.Draw(ht, hegel.Integers(0, 5)) {
			case 0:
				// a reply's lookup goes from the read's destination to its source, so the entry's destination covers the source
				pair := hegel.Draw(ht, hegel.SampledFrom(pairs))
				e := tableEntry{destination: near(pair[0])}
				if hegel.Draw(ht, hegel.Booleans()) {
					e.source = near(pair[1])
				}
				e.kind = hegel.Draw(ht, hegel.SampledFrom([]entryKind{learnedEntry, heldEntry, localEntry, assignedEntry}))
				e.peer = hegel.Draw(ht, hegel.Integers(0, len(model.peers)-1))
				value := model.peers[e.peer]
				switch e.kind {
				case heldEntry:
					value = Unreachable
				case localEntry:
					value = Local
				case assignedEntry:
					value = Assigned
				}
				both(func(n *Mesh) { n.Routes.Set(e.source, e.destination, value) })
				model.set(e)
			case 1:
				if routes := covering(); len(routes) > 0 {
					route := hegel.Draw(ht, hegel.SampledFrom(routes))
					both(func(n *Mesh) { n.Routes.Remove(route.Source, route.Destination) })
				}
			case 2:
				// a peer some pair's reply resolves to through an entry not counting as a default, so its removal moves that answer
				// where none does, a host entry first routes a pair's source to a drawn peer, and a read keeps that answer before the peer goes
				var through []*Peer
				for _, pair := range pairs {
					if peer, verdict, match := m.Routes.Resolve(pair[1], pair[0]); verdict == RoutePeer && !match.Counted && !m.inOverlay(pair[0]) {
						through = append(through, peer)
					}
				}
				if len(through) == 0 {
					pair := hegel.Draw(ht, hegel.SampledFrom(pairs))
					e := tableEntry{destination: hostPrefix(pair[0]), kind: learnedEntry, peer: hegel.Draw(ht, hegel.Integers(0, len(model.peers)-1))}
					both(func(n *Mesh) { n.Routes.Set(e.source, e.destination, model.peers[e.peer]) })
					model.set(e)
					read()
					through = []*Peer{model.peers[e.peer]}
				}
				peer := hegel.Draw(ht, hegel.SampledFrom(through))
				both(func(n *Mesh) { n.Routes.RemovePeer(peer) })
			case 3:
				var overlay []schema.Prefix
				for _, route := range m.Routes.Snapshot() {
					if hegel.Draw(ht, hegel.Booleans()) {
						overlay = append(overlay, schema.PrefixFrom(near(route.Destination.Addr())))
					}
				}
				for _, pair := range pairs {
					if hegel.Draw(ht, hegel.Booleans()) {
						overlay = append(overlay, schema.PrefixFrom(near(pair[0])))
					}
				}
				model.overlay = overlay
				both(func(n *Mesh) { n.SetOverlay(overlay) })
			case 4:
				var advertised []netip.Prefix
				for _, route := range m.Routes.Snapshot() {
					if hegel.Draw(ht, hegel.Booleans()) {
						advertised = append(advertised, route.Destination)
					}
				}
				both(func(n *Mesh) { n.SetEgressPrefixes(advertised) })
			}
			read()
		}
	})
}
