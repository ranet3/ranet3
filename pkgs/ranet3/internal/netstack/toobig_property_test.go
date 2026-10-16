// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package netstack

import (
	"bytes"
	"net/netip"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/esp"
	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/srv6"
)

// a packet within the largest its peer's session carries leaves for the peer as it came, under its steering header if a policy claims it
// past that, an IPv6 one, and an IPv4 one with DF, are answered into the tun from their destination
// with packet too big or fragmentation needed carrying the session's MTU less the steering header
// the first quoting as much of the packet as fits 1280 bytes, the second its header and 8 bytes, each summing as its receiver checks it
// and an IPv4 one without DF leaves for the peer as fragments that each fit the session
// each behind the steering header the packet would have had, its payload length counting the fragment
// each family, with and without DF and steering, one byte either side of the session's MTU, is tried before anything is drawn
func TestPacketsPastTheirSessionAreAnsweredOrCut(t *testing.T) {
	check := func(tb testing.TB, family, segments, mtu, excess int, df bool) {
		tb.Helper()
		steering := steerBothFrom(tb, segments)
		overhead := steering.Overhead()
		source, destination := tooBigSource[family], tooBigDestination[family]
		inner := udpPacket(source, destination, mtu+excess-overhead, df)
		b, peer, answers := readOff(tb, inner, steering, mtu)
		share := b.shares[peer]
		if excess <= 0 {
			sent := b.packets[0]
			if b.peers[0] != peer || share.count != 1 || len(answers) != 0 || len(b.cut.fragments) != 0 {
				tb.Fatalf("a %d byte packet within a %d byte session went to %v with %d answers and %d fragments", len(sent), mtu, b.peers[0], len(answers), len(b.cut.fragments))
			}
			if len(sent) != len(inner)+overhead || !bytes.Equal(sent[overhead:], inner) {
				tb.Fatalf("a packet within its session left as %d bytes that do not carry the %d it came as", len(sent), len(inner))
			}
			return
		}
		if b.peers[0] != nil {
			tb.Fatalf("a packet %d bytes past its %d byte session went to its peer", excess, mtu)
		}
		limit := mtu - overhead
		if family == 6 || df {
			if len(answers) != 1 || share.count != 0 || len(b.cut.fragments) != 0 {
				tb.Fatalf("an IPv%d packet past its session left %d answers, %d packets and %d fragments", family, len(answers), share.count, len(b.cut.fragments))
			}
			checkAnswer(tb, answers[0], inner, limit)
			return
		}
		if len(answers) != 0 || share.count != len(b.cut.fragments) || len(b.cut.fragments) < 2 {
			tb.Fatalf("an IPv4 packet without DF past its session left %d answers and %d fragments counted as %d", len(answers), len(b.cut.fragments), share.count)
		}
		wantHeader, steered := byte(esp.NextHeaderIPv4), []byte(nil)
		if overhead != 0 {
			policy := steering.Lookup(source, destination)
			encapsulated, err := srv6.Encapsulate(inner, policy.Source, policy.Path)
			if err != nil {
				tb.Fatal(err)
			}
			wantHeader, steered = esp.NextHeaderIPv6, encapsulated[:overhead]
		}
		sent := make([][]byte, len(b.cut.fragments))
		for i, fragment := range b.cut.fragments {
			if fragment.peer != peer || fragment.header != wantHeader {
				tb.Fatalf("fragment %d goes to %v under next header %d, want %v under %d", i, fragment.peer, fragment.header, peer, wantHeader)
			}
			sent[i] = fragment.raw
		}
		checkFragments(tb, sent, steered, inner, mtu)
	}
	for _, family := range []int{4, 6} {
		for _, segments := range []int{0, 2} {
			for excess := -1; excess <= 1; excess++ {
				check(t, family, segments, srv6.MinimumIPv6MTU+srv6.Overhead(2), excess, false)
				check(t, family, segments, DefaultMTU, excess, true)
			}
		}
	}
	pbt.Check(t, func(ht *hegel.T) {
		family := 4
		if hegel.Draw(ht, hegel.Booleans()) {
			family = 6
		}
		df := family == 4 && hegel.Draw(ht, hegel.Booleans())
		segments := hegel.Draw(ht, pbt.Spanning(0, 2))
		mtu := hegel.Draw(ht, pbt.Spanning(srv6.MinimumIPv6MTU, 9000))
		excess := hegel.Draw(ht, pbt.Spanning(-1, 1))
		if hegel.Draw(ht, hegel.Booleans()) {
			excess = hegel.Draw(ht, pbt.Spanning(-512, 4096))
		}
		check(ht, family, segments, mtu, excess, df)
	})
}

// a forwarded segment within the largest the session to its next segment carries goes on as End left it
// past that, the IPv6 packet it carries, and the IPv4 one with DF, are answered back through the mesh from that packet's destination
// with packet too big or fragmentation needed carrying the session's MTU less the headers in front of the packet
// the answer to the segment's own source would reach the node that steered it, which has nothing to tell
// and the IPv4 one without DF goes on as fragments that each fit the session, each behind those headers
// those headers take each shape srv6.Parse walks, with hop-by-hop and destination options in front of the routing header and TLVs after its list
// each family, with and without DF, one byte either side of the session's MTU, is tried with each shape before anything is drawn
func TestSegmentsPastTheirNextSessionAreAnsweredOrCut(t *testing.T) {
	check := func(tb testing.TB, family, segments, mtu, excess int, df bool, shape headerShape) {
		tb.Helper()
		path := make([]netip.Addr, segments)
		for i := range path {
			path[i] = netip.AddrFrom16([16]byte{0x3f, 0xff, 0, 2, 15: byte(i + 1)})
		}
		session, next := sessionOf(tb, mtu)
		m, sender := waypointOf(tb, path[0], session)
		overhead := srv6.Overhead(1+segments) + shape.size()
		inner := udpPacket(tooBigSource[family], tooBigDestination[family], mtu+excess-overhead, df)
		outer := shape.around(steeredThrough(tb, inner, path...))
		forwarded := bytes.Clone(outer)
		if _, err := srv6.End(forwarded); err != nil {
			tb.Fatal(err)
		}
		if left := m.applySegments([][]byte{outer}, DefaultMTU); len(left) != 0 {
			tb.Fatalf("a forwarded segment reached the tun as %d packets", len(left))
		}
		sent, answers, counters := next.packets(tb), sender.packets(tb), m.SegmentCounters()
		// a session seals each packet under the next header naming its family, which its receiver holds the packet to
		for _, header := range next.nextHeaders() {
			if header != esp.NextHeaderIPv6 {
				tb.Fatalf("a segment went on under next header %d, want the %d of its outer IPv6 header", header, esp.NextHeaderIPv6)
			}
		}
		if excess <= 0 {
			if len(sent) != 1 || !bytes.Equal(sent[0], forwarded) || len(answers) != 0 || counters.Forwarded != 1 {
				tb.Fatalf("a %d byte segment within a %d byte session went on as %d packets with %d answers, counted %+v", len(outer), mtu, len(sent), len(answers), counters)
			}
			return
		}
		if family == 6 || df {
			if len(sent) != 0 || len(answers) != 1 || counters.Dropped != 1 || counters.Answered != 1 {
				tb.Fatalf("a segment carrying IPv%d past its %d byte session went on as %d packets with %d answers, counted %+v", family, mtu, len(sent), len(answers), counters)
			}
			checkAnswer(tb, answers[0], inner, mtu-overhead)
			if _, _, want, _ := addrsOf(inner); !bytes.Equal(sender.nextHeaders(), []byte{want}) {
				tb.Fatalf("the answer went back under next headers %v, want the %d of its family", sender.nextHeaders(), want)
			}
			return
		}
		if len(answers) != 0 || counters.Dropped != 0 || counters.Forwarded != uint64(len(sent)) {
			tb.Fatalf("a segment carrying IPv4 without DF past its session went on as %d packets with %d answers, counted %+v", len(sent), len(answers), counters)
		}
		checkFragments(tb, sent, forwarded[:overhead], inner, mtu)
	}
	fronts := [][]byte{nil, {hopByHop}, {destinationOptions}, {hopByHop, destinationOptions}}
	shapes := []headerShape{{}, {front: fronts[1]}, {front: fronts[2]}, {tlv: 8}, {front: fronts[3], tlv: 16}}
	for _, family := range []int{4, 6} {
		for _, segments := range []int{1, 3} {
			for _, shape := range shapes {
				for excess := -1; excess <= 1; excess++ {
					check(t, family, segments, srv6.MinimumIPv6MTU+srv6.Overhead(1+segments)+shape.size(), excess, false, shape)
					check(t, family, segments, DefaultMTU, excess, true, shape)
				}
			}
		}
	}
	pbt.Check(t, func(ht *hegel.T) {
		family := 4
		if hegel.Draw(ht, hegel.Booleans()) {
			family = 6
		}
		df := family == 4 && hegel.Draw(ht, hegel.Booleans())
		segments := hegel.Draw(ht, pbt.Spanning(1, 3))
		mtu := hegel.Draw(ht, pbt.Spanning(srv6.MinimumIPv6MTU, 9000))
		excess := hegel.Draw(ht, pbt.Spanning(-1, 1))
		if hegel.Draw(ht, hegel.Booleans()) {
			excess = hegel.Draw(ht, pbt.Spanning(-512, 4096))
		}
		shape := headerShape{front: fronts[hegel.Draw(ht, hegel.Integers(0, len(fronts)-1))], tlv: 8 * hegel.Draw(ht, pbt.Spanning(0, 2))}
		check(ht, family, segments, mtu, excess, df, shape)
	})
}
