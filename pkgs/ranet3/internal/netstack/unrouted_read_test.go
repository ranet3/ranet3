// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/packet"
	"ranet3.com/pkgs/ranet3/schema"
)

// the ends of the reads below: an address of this node's own inside the
// overlay and an uplink address the table holds nothing for, by family
var (
	ownSource    = map[int]netip.Addr{4: segAddr("192.0.2.1"), 6: segAddr("3fff::1")}
	uplinkSource = map[int]netip.Addr{4: segAddr("198.51.100.10"), 6: segAddr("2001:db8:a::10")}
)

// unroutedMesh is a recording mesh with the overlay 192.0.2.0/24 and
// 3fff::/20, holding ownSource as its own and the entries set writes
func unroutedMesh(tb testing.TB, set func(*RouteTable)) (*Mesh, *recordingDevice) {
	tb.Helper()
	m, dev := recordingMesh(tb)
	m.SetOverlay([]schema.Prefix{schema.MustPrefix("192.0.2.0/24"), schema.MustPrefix("3fff::/20")})
	for _, own := range ownSource {
		m.Routes.Set(netip.Prefix{}, netip.PrefixFrom(own, own.BitLen()), Local)
	}
	if set != nil {
		set(m.Routes)
	}
	return m, dev
}

// a packet the host routes into the tun toward a destination no route reaches,
// or a hold holds, is answered back into the tun from that destination,
// whether its source is this node's own or, toward a destination no entry
// counting as a default covers, an uplink address the mesh holds no route to
// and counted answered and under its reason, no_route or held
// over IPv4 a hold counting as a default, and no route, answer network
// unreachable outside the overlay, and a hold that does not count, or the
// overlay, host
// unreachable, RFC 1812 section 5.2.7.1, and over IPv6 no route, RFC 4443
// section 3.1 code 0
func TestTunReadNoRouteReachesIsAnsweredIntoTheTun(t *testing.T) {
	const netUnreachable, hostUnreachable = 0, 1
	for name, read := range map[string]struct {
		family      int
		destination netip.Addr
		set         func(*RouteTable)
		// counted is the destination's entry counting as a default, where the
		// edge drops a read from a source no entry of this node's own covers
		counted bool
		code    byte
	}{
		"ipv4 under a counted hold": {4, segAddr("203.0.113.9"), func(r *RouteTable) {
			r.Set(netip.Prefix{}, segPrefix("0.0.0.0/0"), Unreachable)
		}, true, netUnreachable},
		"ipv4 under a hold that does not count": {4, segAddr("203.0.113.9"), func(r *RouteTable) {
			r.Set(netip.Prefix{}, segPrefix("203.0.113.0/24"), Unreachable)
		}, false, hostUnreachable},
		"ipv4 with no route":                {4, segAddr("203.0.113.9"), nil, false, netUnreachable},
		"ipv4 inside the overlay, no route": {4, segAddr("192.0.2.9"), nil, false, hostUnreachable},
		"ipv6 under a counted hold":         {6, segAddr("2001:db8:c::9"), func(r *RouteTable) { r.Set(netip.Prefix{}, segPrefix("::/0"), Unreachable) }, true, 0},
		"ipv6 with no route":                {6, segAddr("2001:db8:c::9"), nil, false, 0},
		"ipv6 inside the overlay, no route": {6, segAddr("3fff::9"), nil, false, 0},
	} {
		sources := map[string]netip.Addr{"own": ownSource[read.family]}
		if !read.counted {
			sources["uplink"] = uplinkSource[read.family]
		}
		for sourceName, source := range sources {
			t.Run(name+" from an "+sourceName+" source", func(t *testing.T) {
				m, dev := unroutedMesh(t, read.set)
				raw := udpPacket(source, read.destination, 200, false)
				_, written := classifyOne(m, dev, raw)
				if len(written) != 1 {
					t.Fatalf("the read put %d packets into the tun, want its answer", len(written))
				}
				if read.family == 6 {
					checkICMPv6(t, written[0], raw, read.destination, 1, read.code, 0)
				} else {
					checkICMPv4(t, written[0], raw, read.destination, 3, read.code, 0)
				}
				reason := transitNoRoute
				if read.set != nil {
					reason = transitHeld
				}
				if got, dropped := m.transitCounts[transitAnswered].Load(), m.transitCounts[reason].Load(); got != 1 || dropped != 1 {
					t.Errorf("the answer was counted %d times and the read %d times as %s, want each once", got, dropped, transitReasonNames[reason])
				}
			})
		}
	}
}

// a read toward a hold counting as a default from an uplink address, which no
// entry of this node's own covers, is dropped at the edge as unowned_source and
// never reaches the answer
func TestTunReadUnderACountedHoldFromAnUplinkSourceIsDroppedUnanswered(t *testing.T) {
	for family, hold := range map[int]string{4: "0.0.0.0/0", 6: "::/0"} {
		m, dev := unroutedMesh(t, func(r *RouteTable) { r.Set(netip.Prefix{}, segPrefix(hold), Unreachable) })
		destination := map[int]netip.Addr{4: segAddr("203.0.113.9"), 6: segAddr("2001:db8:c::9")}[family]
		if _, written := classifyOne(m, dev, udpPacket(uplinkSource[family], destination, 200, false)); len(written) != 0 {
			t.Errorf("ipv%d: the read put %d packets into the tun, want none", family, len(written))
		}
		if dropped, answered := m.transitCounts[transitUnownedSource].Load(), m.transitCounts[transitAnswered].Load(); dropped != 1 || answered != 0 {
			t.Errorf("ipv%d: the read was counted %d times as unowned_source and %d as answered, want once and never", family, dropped, answered)
		}
	}
}

// a read whose source's bucket is spent goes unanswered, one the table answers as this node's own counted looped and one no route reaches counted no_route
func TestTunReadFromASpentSourceIsLeftUnanswered(t *testing.T) {
	for family := range ownSource {
		m, dev := unroutedMesh(t, nil)
		for range icmpSourceBurst {
			if !m.takeICMPToken(uplinkSource[family]) {
				t.Fatalf("a fresh bucket of %s held fewer than %d answers", uplinkSource[family], icmpSourceBurst)
			}
		}
		destination := map[int]netip.Addr{4: segAddr("203.0.113.9"), 6: segAddr("2001:db8:c::9")}[family]
		for _, to := range []netip.Addr{ownSource[family], destination} {
			if _, written := classifyOne(m, dev, udpPacket(uplinkSource[family], to, 200, false)); len(written) != 0 {
				t.Errorf("ipv%d: a read from a spent source to %s was answered", family, to)
			}
		}
		if looped, dropped, answered := m.transitCounts[transitLooped].Load(), m.transitCounts[transitNoRoute].Load(), m.transitCounts[transitAnswered].Load(); looped != 1 || dropped != 1 || answered != 0 {
			t.Errorf("ipv%d: the reads were counted %d times looped, %d no_route and %d answered, want once, once and never", family, looped, dropped, answered)
		}
	}
}

// heldMesh is unroutedMesh with its tun holding ownSource and recording every write of reads, the most reads the test classifies at once
// with room for two writes a read, a write-back and an answer, so a test fails by its check where a read meets both rather than block in the write
func heldMesh(tb testing.TB, reads int, set func(*RouteTable)) (*Mesh, *recordingDevice) {
	tb.Helper()
	m, dev := unroutedMesh(tb, set)
	dev.writes = make(chan recordedWrite, 2*reads)
	m.SetTunAddresses([]netip.Addr{ownSource[4], ownSource[6]})
	return m, dev
}

// classifyWritten runs classify over reads as one read off the tun and returns every packet the mesh wrote into the tun on the way, in order
func classifyWritten(m *Mesh, dev *recordingDevice, reads ...[]byte) [][]byte {
	b := newOutboundBatch(len(reads))
	fill(b, reads...)
	m.classify(b)
	var written [][]byte
	for {
		select {
		case write := <-dev.writes:
			written = append(written, write.packets...)
		default:
			return written
		}
	}
}

// pseudoSum is the sum of the pseudo-header of the transport segment at offset in raw, its next header protocol
// RFC 9293 section 3.1's under IPv4 and RFC 8200 section 8.1's under IPv6
func pseudoSum(raw []byte, offset int, protocol byte) uint32 {
	length := len(raw) - offset
	if raw[0]>>4 == 4 {
		return packet.Sum(packet.Sum(0, raw[12:20]), []byte{0, protocol, byte(length >> 8), byte(length)})
	}
	return packet.Sum(packet.Sum(0, raw[8:40]), append(binary.BigEndian.AppendUint32(nil, uint32(length)), 0, 0, 0, protocol))
}

// transportField is where raw's UDP or TCP checksum lies, raw an IPv6 packet with no extension header, false for another protocol or an IPv4 packet
func transportField(raw []byte) (int, bool) {
	if raw[0]>>4 != 6 {
		return 0, false
	}
	switch raw[6] {
	case 17:
		return 40 + 6, true
	case tcpProtocol:
		return 40 + tcpChecksum, true
	}
	return 0, false
}

// withTransportSum is raw, an IPv6 UDP or TCP packet with no extension header, its checksum over RFC 8200 section 8.1's pseudo-header set
// or, unfinished, its checksum field holding the pseudo-header's sum alone, which a host leaves for its interface's offload to complete
func withTransportSum(raw []byte, unfinished bool) []byte {
	out := bytes.Clone(raw)
	field, _ := transportField(out)
	binary.BigEndian.PutUint16(out[field:], 0)
	pseudo := pseudoSum(out, 40, out[6])
	sum := uint16(pseudo)
	if !unfinished {
		sum = ^uint16(packet.Sum(pseudo, out[40:]))
		if sum == 0 && out[6] == 17 {
			sum = 0xffff
		}
	}
	binary.BigEndian.PutUint16(out[field:], sum)
	return out
}

// tcpBetween is a TCP SYN from source to destination, IPv6 addresses, carrying 10 bytes, its checksum stale for its addresses, which withTransportSum sets
func tcpBetween(source, destination netip.Addr) []byte {
	raw := tcpPacket(6, 0, false, synFlag, nil, 0, 10)
	copy(raw[8:24], source.AsSlice())
	copy(raw[24:40], destination.AsSlice())
	return raw
}

// a read the table answers as this node's own whose destination the tun holds goes back into the tun once, byte for byte as read
// from that address itself and from an uplink address, counted delivered and not looped, in each family
func TestTunReadToAnAddressTheTunHoldsIsWrittenBack(t *testing.T) {
	for _, family := range []int{4, 6} {
		m, dev := heldMesh(t, 2, nil)
		reads := [][]byte{
			udpPacket(ownSource[family], ownSource[family], 200, false),
			udpPacket(uplinkSource[family], ownSource[family], 200, false),
		}
		if family == 6 {
			for i := range reads {
				reads[i] = withTransportSum(reads[i], false)
			}
		}
		written := classifyWritten(m, dev, reads...)
		if len(written) != len(reads) {
			t.Fatalf("ipv%d: %d reads to %s put %d packets into the tun, want each once", family, len(reads), ownSource[family], len(written))
		}
		for i := range reads {
			if !bytes.Equal(written[i], reads[i]) {
				t.Errorf("ipv%d: read %d went back into the tun as %x, want it as read, %x", family, i, written[i], reads[i])
			}
		}
		if got := m.TransitCounters(); got != (TransitCounters{Delivered: 2}) {
			t.Errorf("ipv%d: the reads counted %+v, want 2 delivered", family, got)
		}
	}
}

// summingToZero is raw, an IPv6 UDP or TCP packet with no extension header, its payload word at offset set so that the checksum its bytes call for is zero, and its checksum field zero
func summingToZero(raw []byte, offset int) []byte {
	out := bytes.Clone(raw)
	binary.BigEndian.PutUint16(out[offset:], 0)
	field, _ := transportField(out)
	// the word takes the checksum the rest calls for, so that the whole adds up to all ones
	copy(out[offset:offset+2], withTransportSum(out, false)[field:])
	binary.BigEndian.PutUint16(out[field:], 0)
	return out
}

// an IPv6 UDP or TCP read written back whose checksum the host left unfinished goes back with it completed, and nothing else changed
// a UDP checksum completed as zero goes back as all ones, and a UDP checksum field of zero is completed whatever the rest adds up to
// a read whose checksum verifies, in either form of zero too, a segment shorter than its header, an IPv6 read behind an extension header, of another protocol, and an IPv4 read go back as read, whatever their checksum
func TestTunReadWrittenBackHasItsUnfinishedChecksumCompleted(t *testing.T) {
	own4, own6 := ownSource[4], ownSource[6]
	udp6, tcp6 := udpPacket(own6, own6, 200, false), tcpBetween(own6, own6)
	behindOptions := withDestinationOptions(withTransportSum(udp6, true))
	icmp := withTransportSum(udp6, true)
	icmp[6] = 58
	badUDP4 := udpPacket(own4, own4, 200, false)
	binary.BigEndian.PutUint16(badUDP4[20+6:], 0x1234)
	// a later fragment whose identification and fragment octet an IPv6 reading takes for a payload length and next header UDP
	fragment4 := bytes.Clone(badUDP4)
	binary.BigEndian.PutUint16(fragment4[4:], 8)
	fragment4[6] = 17
	udpZero, tcpZero := summingToZero(udp6, 40+8), summingToZero(tcp6, 40+tcpHeaderLen)
	if binary.BigEndian.Uint16(withTransportSum(udpZero, false)[40+6:]) != 0xffff || binary.BigEndian.Uint16(withTransportSum(tcpZero, false)[40+tcpChecksum:]) != 0 {
		t.Fatalf("the segments %x and %x do not call for a checksum of zero", udpZero, tcpZero)
	}
	tcpAlternate := bytes.Clone(tcpZero)
	binary.BigEndian.PutUint16(tcpAlternate[40+tcpChecksum:], 0xffff)
	shortUDP := udpPacket(own6, own6, 48, false)[:44]
	binary.BigEndian.PutUint16(shortUDP[4:], 4)
	shortTCP := tcpBetween(own6, own6)[:50]
	binary.BigEndian.PutUint16(shortTCP[4:], 10)
	for _, c := range []struct {
		name       string
		read, want []byte
	}{
		{"udp unfinished", withTransportSum(udp6, true), withTransportSum(udp6, false)},
		{"tcp unfinished", withTransportSum(tcp6, true), withTransportSum(tcp6, false)},
		{"udp unfinished summing to zero", withTransportSum(udpZero, true), withTransportSum(udpZero, false)},
		{"udp zero field summing to zero", udpZero, withTransportSum(udpZero, false)},
		{"udp verified", withTransportSum(udp6, false), withTransportSum(udp6, false)},
		{"tcp verified", withTransportSum(tcp6, false), withTransportSum(tcp6, false)},
		{"tcp verifying in its other zero", tcpAlternate, tcpAlternate},
		{"udp segment shorter than its header", shortUDP, shortUDP},
		{"tcp segment shorter than its header", shortTCP, shortTCP},
		{"udp behind a destination options header", behindOptions, behindOptions},
		{"icmpv6", icmp, icmp},
		{"ipv4 udp failing its checksum", badUDP4, badUDP4},
		{"ipv4 fragment reading as ipv6 udp", fragment4, fragment4},
	} {
		t.Run(c.name, func(t *testing.T) {
			m, dev := heldMesh(t, 1, nil)
			written := classifyWritten(m, dev, bytes.Clone(c.read))
			if len(written) != 1 || !bytes.Equal(written[0], c.want) {
				t.Fatalf("the read %x went back into the tun as %x, want %x", c.read, written, c.want)
			}
			if got := m.TransitCounters(); got != (TransitCounters{Delivered: 1}) {
				t.Errorf("the read counted %+v, want 1 delivered", got)
			}
		})
	}
}

// a read the table answers as this node's own whose destination the tun does not hold is counted looped and never written back
// to an address inside a prefix this node originates, from this node's own address or an uplink one, to a host route of its own, and to the internet through its own default
// each is answered into the tun from its destination, quoting the read: over IPv6 with RFC 4443 section 3.1 code 3
// over IPv4 with host unreachable, but network unreachable under its own default, which counts as one, RFC 1812 section 5.2.7.1
// and no read is answered that is an ICMP error, or that goes to the prefix's base address or, over IPv4, its all-ones host, RFC 1812 sections 4.2.2.11 and 4.3.2.7
// the base of its own default among them, but in a /31 or a /127, whose two addresses are hosts, and a host route, whose base is its host
// a read to the limited broadcast is counted multicast before its route is looked up, and so unanswered as well
// so the answers are all the reads put into the tun
func TestTunReadToAnOwnDestinationTheTunDoesNotHoldIsAnsweredAndNotWrittenBack(t *testing.T) {
	const netUnreachable, hostUnreachable, addressUnreachable = 0, 1, 3
	inPrefix := map[int]netip.Addr{4: segAddr("192.0.2.130"), 6: segAddr("3fff:0:0:80::9")}
	ownHost := map[int]netip.Addr{4: segAddr("192.0.2.9"), 6: segAddr("3fff::9")}
	// both addresses of a /31 and of a /127 are hosts, RFC 3021 and RFC 6164
	pointToPoint := map[int][]string{4: {"192.0.2.6", "192.0.2.7"}, 6: {"3fff:0:0:7::", "3fff:0:0:7::1"}}
	noHost := map[int][]netip.Addr{4: {segAddr("192.0.2.128"), segAddr("192.0.2.255"), segAddr("0.0.0.0")}, 6: {segAddr("3fff:0:0:80::"), segAddr("::")}}
	// answeredRead is a read and the code of the answer it gets
	type answeredRead struct {
		read []byte
		code byte
	}
	for _, family := range []int{4, 6} {
		code := func(ipv4 byte) byte {
			if family == 6 {
				return addressUnreachable
			}
			return ipv4
		}
		answered := []answeredRead{
			{udpPacket(ownSource[family], inPrefix[family], 200, false), code(hostUnreachable)},
			{udpPacket(uplinkSource[family], inPrefix[family], 200, false), code(hostUnreachable)},
			{udpPacket(ownSource[family], ownHost[family], 200, false), code(hostUnreachable)},
			{udpPacket(ownSource[family], edgeInternet[family], 200, false), code(netUnreachable)},
		}
		for _, to := range pointToPoint[family] {
			answered = append(answered, answeredRead{udpPacket(ownSource[family], segAddr(to), 200, false), code(hostUnreachable)})
		}
		// a destination unreachable, over IPv4 behind a header whose checksum still holds
		icmpError := icmpv6Error(ownSource[6], inPrefix[6], 200)
		if family == 4 {
			icmpError = withTTL(withProtocol(udpPacket(ownSource[4], inPrefix[4], 200, false), 1), 64)
			icmpError[20] = 3
		}
		unanswered := [][]byte{icmpError}
		for _, to := range noHost[family] {
			unanswered = append(unanswered, udpPacket(ownSource[family], to, 200, false))
		}
		var reads [][]byte
		for _, c := range answered {
			reads = append(reads, c.read)
		}
		all := append(reads, unanswered...)
		want := TransitCounters{Looped: uint64(len(all)), Answered: uint64(len(answered))}
		if family == 4 {
			all = append(all, udpPacket(ownSource[4], packet.LimitedBroadcast, 200, false))
			want.Multicast = 1
		}
		m, dev := heldMesh(t, len(all), func(r *RouteTable) {
			for _, prefix := range []string{"192.0.2.128/25", "192.0.2.6/31", "3fff:0:0:80::/64", "3fff:0:0:7::/127", "0.0.0.0/0", "::/0"} {
				r.Set(netip.Prefix{}, segPrefix(prefix), Local)
			}
			r.Set(netip.Prefix{}, hostPrefix(ownHost[family]), Local)
		})
		written := classifyWritten(m, dev, all...)
		if len(written) != len(answered) {
			t.Fatalf("ipv%d: %d reads to this node's own destinations the tun does not hold put %d packets into the tun, want an answer to each of the first %d", family, len(all), len(written), len(answered))
		}
		for i, c := range answered {
			_, destination, _, _ := addrsOf(c.read)
			if family == 6 {
				checkICMPv6(t, written[i], c.read, destination, 1, c.code, 0)
			} else {
				checkICMPv4(t, written[i], c.read, destination, 3, c.code, 0)
			}
		}
		if got := m.TransitCounters(); got != want {
			t.Errorf("ipv%d: the reads counted %+v, want %+v", family, got, want)
		}
	}
}

// a read toward an address the tun holds that the edge refuses writes nothing into the tun
// from a source the mesh routes to another node, counted forged, and under ownedOnly from an uplink address, counted unowned_source
func TestTunReadTheEdgeRefusesTowardAHeldAddressIsNotWrittenBack(t *testing.T) {
	another := map[int]netip.Addr{4: segAddr("192.0.2.77"), 6: segAddr("3fff::77")}
	for _, family := range []int{4, 6} {
		peer := (&recordingPeer{}).peer(t, "peer")
		m, dev := heldMesh(t, 1, func(r *RouteTable) { r.Set(netip.Prefix{}, hostPrefix(another[family]), peer) })
		if written := classifyWritten(m, dev, udpPacket(another[family], ownSource[family], 200, false)); len(written) != 0 {
			t.Errorf("ipv%d: a forged read to a held address put %d packets into the tun", family, len(written))
		}
		m.ownedOnly = true
		if written := classifyWritten(m, dev, udpPacket(uplinkSource[family], ownSource[family], 200, false)); len(written) != 0 {
			t.Errorf("ipv%d: an unowned read to a held address under ownedOnly put %d packets into the tun", family, len(written))
		}
		if got := m.TransitCounters(); got != (TransitCounters{Forged: 1, UnownedSource: 1}) {
			t.Errorf("ipv%d: the reads counted %+v, want 1 forged and 1 unowned_source", family, got)
		}
	}
}
