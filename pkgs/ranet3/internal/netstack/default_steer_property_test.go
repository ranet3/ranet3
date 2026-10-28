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

// over drawn tables holding defaults, /1 halves, /2 quarters, defaults from a source prefix, mesh subnets and overlay hosts, each held or not
// and drawn host packets from this node's own addresses to the internet, a mesh subnet and overlay addresses, in both families
// a packet the model has the path take leaves to the waypoint encapsulated along the path from its source, and no other packet is encapsulated
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
			packets = append(packets, udpPacket(transitOwn[family], destination, 100, false))
		}
		b := classifiedBatch(m, packets...)
		steered := uint64(0)
		for i, raw := range packets {
			source, destination, _, _ := addrsOf(raw)
			if modelSteered(entries, transitOverlay, source, destination) {
				steered++
				if b.peers[i] != waypoint {
					ht.Fatalf("a packet to %s the model steers went to %v under %v", destination, b.peers[i], m.Routes.Debug())
				}
				header, err := srv6.Parse(b.packets[i])
				if err != nil || netip.AddrFrom16([16]byte(b.packets[i][8:24])) != pathSource || !slices.Equal(header.Path(), pathVia) || !bytes.Equal(b.packets[i][srv6.Overhead(len(pathVia)):], raw) {
					ht.Fatalf("a packet to %s the model steers left as %x, %v", destination, b.packets[i], err)
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
	})
}
