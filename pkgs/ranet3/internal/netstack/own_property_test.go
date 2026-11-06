// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package netstack

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"slices"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/packet"
	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// the addresses the property draws its table over, by family
// hosts take a host key each, of this node's own, assigned it or another node's, the first always this node's own and the source of its own reads
// inner lies in a shorter prefix of this node's own or another node's, and another is another node's, the source of the forged reads
var (
	ownPropertyHosts = map[int][]netip.Addr{
		4: {segAddr("192.0.2.10"), segAddr("192.0.2.11"), segAddr("192.0.2.12"), segAddr("192.0.2.13"), segAddr("192.0.2.14")},
		6: {segAddr("3fff::a"), segAddr("3fff::b"), segAddr("3fff::c"), segAddr("3fff::d"), segAddr("3fff::e")},
	}
	ownPropertyPrefix  = map[int]netip.Prefix{4: segPrefix("192.0.2.128/26"), 6: segPrefix("3fff:0:0:80::/64")}
	ownPropertyInner   = map[int]netip.Addr{4: segAddr("192.0.2.130"), 6: segAddr("3fff:0:0:80::9")}
	ownPropertyAnother = map[int]netip.Addr{4: segAddr("192.0.2.200"), 6: segAddr("3fff::c8")}
)

// transportVerifies reports whether the checksum of raw, an IPv6 UDP or TCP packet with no extension header, adds up to all ones over RFC 8200 section 8.1's pseudo-header and its segment
// and is not a UDP checksum field of zero, which that section has a receiver discard
func transportVerifies(raw []byte) bool {
	field, _ := transportField(raw)
	return packet.Sum(pseudoSum(raw, 40, raw[6]), raw[40:]) == 0xffff && !(raw[6] == 17 && binary.BigEndian.Uint16(raw[field:]) == 0)
}

// over drawn tables of this node's own and assigned host keys, another node's, and a shorter prefix of this node's own or another node's
// drawn sets of addresses the tun holds, among them and beyond them, with and without ownedOnly
// and reads of both families from this node's own address or another node's to destinations held or not, drawn outright
// a read goes into the tun exactly when the table answers it as this node's own, its source is this node's, which the edge passes, and the tun holds its destination
// each in the order read, the read with nothing changed but an IPv6 UDP or TCP checksum, which verifies after and is left alone where it verified before
// and delivered and looped together move by exactly the reads from this node's own address the table answers as this node's own
func TestTunReadGoesBackIntoTheTunExactlyToAnAddressItHolds(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		m, dev := unroutedMesh(ht, nil)
		dev.writes = make(chan recordedWrite, 16)
		m.ownedOnly = hegel.Draw(ht, hegel.Booleans())
		peer := (&recordingPeer{}).peer(ht, "peer")
		var candidates []netip.Addr
		for _, family := range []int{4, 6} {
			for i, host := range ownPropertyHosts[family] {
				value := []*Peer{Local, Assigned, peer}[hegel.Draw(ht, pbt.Spanning(0, 2))]
				if i == 0 {
					value = Local
				}
				m.Routes.Set(netip.Prefix{}, hostPrefix(host), value)
			}
			prefix := peer
			if hegel.Draw(ht, hegel.Booleans()) {
				prefix = Local
			}
			m.Routes.Set(netip.Prefix{}, ownPropertyPrefix[family], prefix)
			m.Routes.Set(netip.Prefix{}, hostPrefix(ownPropertyAnother[family]), peer)
			candidates = append(candidates, ownPropertyHosts[family]...)
			candidates = append(candidates, ownPropertyInner[family], ownPropertyAnother[family])
		}
		held := pbt.Subset(ht, candidates, 0, len(candidates))
		m.SetTunAddresses(held)

		var reads, want [][]byte
		var local uint64
		for range hegel.Draw(ht, pbt.Spanning(1, 12)) {
			family := []int{4, 6}[hegel.Draw(ht, pbt.Spanning(0, 1))]
			var heldHere, notHeld []netip.Addr
			for _, address := range append(append([]netip.Addr{}, ownPropertyHosts[family]...), ownPropertyInner[family], ownPropertyAnother[family]) {
				if slices.Contains(held, address) {
					heldHere = append(heldHere, address)
				} else {
					notHeld = append(notHeld, address)
				}
			}
			// the edge between held and not drawn outright, a held destination where the family has one
			pool := notHeld
			if hegel.Draw(ht, pbt.Spanning(0, 1)) == 0 && len(heldHere) != 0 || len(notHeld) == 0 {
				pool = heldHere
			}
			destination := pool[hegel.Draw(ht, pbt.Spanning(0, len(pool)-1))]
			source, own := ownPropertyHosts[family][0], true
			if hegel.Draw(ht, pbt.Spanning(0, 3)) == 0 {
				source, own = ownPropertyAnother[family], false
			}
			var raw []byte
			switch {
			case family == 4:
				raw = udpPacket(source, destination, 100, false)
				// a UDP checksum IPv4 carries none of, or one that fails
				if hegel.Draw(ht, hegel.Booleans()) {
					binary.BigEndian.PutUint16(raw[20+6:], 0x1234)
				}
				// a later fragment whose identification and fragment octet an IPv6 reading takes for a payload length and next header UDP or TCP
				if hegel.Draw(ht, hegel.Booleans()) {
					binary.BigEndian.PutUint16(raw[4:], uint16(hegel.Draw(ht, pbt.Spanning(tcpHeaderLen, len(raw)-40))))
					raw[6] = []byte{17, tcpProtocol}[hegel.Draw(ht, pbt.Spanning(0, 1))]
				}
			case hegel.Draw(ht, hegel.Booleans()):
				raw = withTransportSum(udpPacket(source, destination, 100, false), hegel.Draw(ht, hegel.Booleans()))
			default:
				raw = withTransportSum(tcpBetween(source, destination), hegel.Draw(ht, hegel.Booleans()))
			}
			reads = append(reads, raw)
			_, verdict, _ := m.Routes.Resolve(source, destination)
			if verdict == RouteLocal && own {
				local++
				if slices.Contains(held, destination) {
					want = append(want, raw)
				}
			}
		}
		was := m.TransitCounters()
		copies := make([][]byte, len(reads))
		for i, read := range reads {
			copies[i] = bytes.Clone(read)
		}
		written := classifyWritten(m, dev, copies...)
		if len(written) != len(want) {
			ht.Fatalf("%d reads put %d packets into the tun, want %d, the tun holding %v", len(reads), len(written), len(want), held)
		}
		for i, read := range want {
			got := written[i]
			field, checked := transportField(read)
			if len(got) != len(read) {
				ht.Fatalf("the read %x went into the tun as %x", read, got)
			}
			for at := range read {
				if got[at] != read[at] && !(checked && (at == field || at == field+1)) {
					ht.Fatalf("the read %x went into the tun as %x, octet %d changed", read, got, at)
				}
			}
			if checked && !transportVerifies(got) {
				ht.Fatalf("the read %x went into the tun as %x, its checksum failing", read, got)
			}
			if (!checked || transportVerifies(read)) && !bytes.Equal(got, read) {
				ht.Fatalf("the read %x, its checksum verifying or none to complete, went into the tun as %x", read, got)
			}
		}
		now := m.TransitCounters()
		if delivered := now.Delivered - was.Delivered; delivered != uint64(len(want)) {
			ht.Fatalf("%d reads went into the tun and %d were counted delivered", len(want), delivered)
		}
		if moved := now.Delivered + now.Looped - was.Delivered - was.Looped; moved != local {
			ht.Fatalf("%d reads from this node's own address to its own destinations moved delivered and looped by %d, %+v", local, moved, now)
		}
	})
}
