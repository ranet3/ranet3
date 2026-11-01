// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package netstack

import (
	"bytes"
	"net/netip"
	"slices"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
)

// steerEntry is one entry of the model's table, its value aside
type steerEntry struct{ source, destination netip.Prefix }

// modelMatch is the entry RFC 9079 section 4 prefers for a packet from source to destination among entries, by
// "destination-first ordering, where routing table entry R1 is preferred to routing table entry R2 when either R1's destination prefix is more specific than R2's
// or the destination prefixes are equal and R1's source prefix is more specific than R2's", an entry with no source prefix matching every source
func modelMatch(entries []steerEntry, source, destination netip.Addr) (steerEntry, bool) {
	sourceBits := func(e steerEntry) int {
		if !e.source.IsValid() {
			return -1
		}
		return e.source.Bits()
	}
	best, found := steerEntry{}, false
	for _, e := range entries {
		if !e.destination.Contains(destination) || e.source.IsValid() && !e.source.Contains(source) {
			continue
		}
		if !found || e.destination.Bits() > best.destination.Bits() || e.destination.Bits() == best.destination.Bits() && sourceBits(e) > sourceBits(best) {
			best, found = e, true
		}
	}
	return best, found
}

// modelSteered is transit section 5.5's three steps for a packet no cap.segment steer entry claims, with section 5.5's overlay case
// the path takes a destination outside the overlay that no entry covers, or whose preferred entry counts as a default
func modelSteered(entries []steerEntry, overlay []schema.Prefix, source, destination netip.Addr) bool {
	for _, prefix := range overlay {
		if prefix.Contains(destination) {
			return false
		}
	}
	e, found := modelMatch(entries, source, destination)
	return !found || schema.CapturesTheMachine(e.destination, overlay)
}

// modelUnowned is the owned-source rule for a source outside the overlay that no entry of this node's own covers, while cap.exit via is set
// forged where the entry a reply from destination to source prefers routes it elsewhere and counts as no default, RFC 3704 section 2.2's strict check
// else unowned where the packet would leave the mesh through an exit: the entry it prefers counts as a default, inside the overlay or not,
// or no entry covers a destination outside the overlay, which the path takes
func modelUnowned(entries []steerEntry, overlay []schema.Prefix, source, destination netip.Addr) (forged, unowned bool) {
	if reply, found := modelMatch(entries, destination, source); found && !schema.CapturesTheMachine(reply.destination, overlay) {
		return true, false
	}
	if e, found := modelMatch(entries, source, destination); found {
		return false, schema.CapturesTheMachine(e.destination, overlay)
	}
	return false, !slices.ContainsFunc(overlay, func(prefix schema.Prefix) bool { return prefix.Contains(destination) })
}

// over drawn tables holding defaults, /1 halves, /2 quarters, defaults from a source prefix, mesh subnets and overlay hosts, each held or not
// and drawn host packets to the internet, a mesh subnet and overlay addresses, in both families
// each from this node's overlay address, an address cap.table assigns it, a host on its LAN and a neighbor, the last two no entry of its own covers
// a packet from its own address the model has the path take leaves to the waypoint encapsulated along the path from its source, and no other packet is encapsulated
// a packet from another source is never encapsulated, and is counted unowned_source exactly where the model says it would leave through an exit and is not forged
// the /1 pair and the four /2s, where a split exit would take one half only, are drawn as often as a plain default
func TestDefaultSteerTakesExactlyWhatTheModelSends(t *testing.T) {
	learned := [][]string{
		{"0.0.0.0/0", "::/0"},
		{"0.0.0.0/1"}, {"128.0.0.0/1"}, {"::/1"}, {"8000::/1"},
		{"0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/2", "192.0.0.0/2"},
		{"::/2", "4000::/2", "8000::/2", "c000::/2"},
		{"192.0.0.0/2"}, {"::/2"},
		{"2000::/3"},
		{"203.0.113.128/25", "2001:db8:5::/48"},
		{"203.0.113.0/24", "2001:db8::/32"},
	}
	sourced := []steerEntry{
		{segPrefix("192.0.2.0/24"), segPrefix("0.0.0.0/0")},
		{segPrefix("3fff::/20"), segPrefix("::/0")},
		{segPrefix("198.51.100.0/24"), segPrefix("0.0.0.0/0")},
		{segPrefix("2001:db8:100::/48"), segPrefix("::/0")},
	}
	destinations := []netip.Addr{
		segAddr("203.0.113.9"), segAddr("203.0.113.130"), segAddr("198.51.100.9"), segAddr("192.0.2.3"), segAddr("192.0.2.5"),
		segAddr("2001:db8::9"), segAddr("2001:db8:5::1"), segAddr("3fff::3"), segAddr("3fff::5"),
	}
	pbt.Check(t, func(ht *hegel.T) {
		m, _, _, waypoint := pathMesh(t)
		// the fixed entries pathMesh holds, as the model reads them
		entries := []steerEntry{{destination: netip.PrefixFrom(pathVia[0], 128)}}
		for _, family := range []int{4, 6} {
			for _, host := range []netip.Addr{transitSender[family], transitFar[family], transitOwn[family], edgeAssigned[family], transitHeldHost[family]} {
				entries = append(entries, steerEntry{destination: hostPrefix(host)})
			}
			entries = append(entries, steerEntry{destination: edgeSubnet[family]})
		}
		exit := (&recordingPeer{}).peer(t, "exit")
		value := func() *Peer {
			if hegel.Draw(ht, hegel.WeightedBooleans(1.0/4)) {
				return Unreachable
			}
			return exit
		}
		for _, group := range pbt.Subset(ht, learned, 0, 4) {
			for _, prefix := range group {
				m.Routes.Set(netip.Prefix{}, segPrefix(prefix), value())
				entries = append(entries, steerEntry{destination: segPrefix(prefix)})
			}
		}
		for _, e := range pbt.Subset(ht, sourced, 0, len(sourced)) {
			m.Routes.Set(e.source, e.destination, value())
			entries = append(entries, e)
		}
		var packets [][]byte
		for _, destination := range pbt.Subset(ht, destinations, 1, len(destinations)) {
			family := 6
			if destination.Is4() {
				family = 4
			}
			for _, source := range []map[int]netip.Addr{transitOwn, edgeAssigned, edgeLAN, edgeNeighbor} {
				packets = append(packets, udpPacket(source[family], destination, 100, false))
			}
		}
		b := classifiedBatch(m, packets...)
		steered, unowned := uint64(0), uint64(0)
		for i, raw := range packets {
			source, destination, _, _ := addrsOf(raw)
			if source == edgeLAN[4] || source == edgeLAN[6] || source == edgeNeighbor[4] || source == edgeNeighbor[6] {
				forged, dropped := modelUnowned(entries, transitOverlay, source, destination)
				if dropped {
					unowned++
				}
				if (forged || dropped) && b.peers[i] != nil {
					ht.Fatalf("a packet from %s to %s the model drops went to %v under %v", source, destination, b.peers[i], m.Routes.Debug())
				}
				if b.peers[i] == waypoint || b.packets[i] != nil && !bytes.Equal(b.packets[i], raw) {
					ht.Fatalf("a packet from %s to %s, a source this node does not own, was steered under %v", source, destination, m.Routes.Debug())
				}
				continue
			}
			if modelSteered(entries, transitOverlay, source, destination) {
				steered++
				if b.peers[i] != waypoint {
					ht.Fatalf("a packet to %s the model steers went to %v under %v", destination, b.peers[i], m.Routes.Debug())
				}
				if netip.AddrFrom16([16]byte(b.packets[i][8:24])) != pathSource || !slices.Equal(steeredPath(b.packets[i]), pathVia) || !bytes.Equal(b.packets[i][srv6.Overhead(len(pathVia)):], raw) {
					ht.Fatalf("a packet to %s the model steers left as %x", destination, b.packets[i])
				}
				continue
			}
			if b.packets[i] != nil && !bytes.Equal(b.packets[i], raw) {
				ht.Fatalf("a packet to %s the model leaves alone was sent as %x under %v", destination, b.packets[i], m.Routes.Debug())
			}
			if b.peers[i] == waypoint {
				ht.Fatalf("a packet to %s the model leaves alone went to the waypoint", destination)
			}
		}
		if got := m.SegmentCounters().Steered; got != steered {
			ht.Fatalf("%d packets were counted steered, the model steers %d", got, steered)
		}
		if got := m.TransitCounters().UnownedSource; got != unowned {
			ht.Fatalf("%d packets were counted unowned_source, the model drops %d", got, unowned)
		}
	})
}
