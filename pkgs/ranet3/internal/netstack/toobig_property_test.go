// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package netstack

import (
	"bytes"
	"encoding/binary"
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
// and an IPv4 one without DF leaves for the peer as fragments that each fit the session under the same steering header
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
			sent := b.bufs[0][tunOffset : tunOffset+b.sizes[0]]
			if b.peers[0] != peer || share.count != 1 || len(answers) != 0 || len(b.fragments) != 0 {
				tb.Fatalf("a %d byte packet within a %d byte session went to %v with %d answers and %d fragments", len(sent), mtu, b.peers[0], len(answers), len(b.fragments))
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
			if len(answers) != 1 || share.count != 0 || len(b.fragments) != 0 {
				tb.Fatalf("an IPv%d packet past its session left %d answers, %d packets and %d fragments", family, len(answers), share.count, len(b.fragments))
			}
			checkAnswer(tb, answers[0], inner, limit)
			return
		}
		if len(answers) != 0 || share.count != len(b.fragments) || len(b.fragments) < 2 {
			tb.Fatalf("an IPv4 packet without DF past its session left %d answers and %d fragments counted as %d", len(answers), len(b.fragments), share.count)
		}
		wantHeader := byte(esp.NextHeaderIPv4)
		if overhead != 0 {
			wantHeader = esp.NextHeaderIPv6
		}
		var data []byte
		for i, fragment := range b.fragments {
			if fragment.peer != peer || fragment.header != wantHeader || len(fragment.raw) > mtu {
				tb.Fatalf("fragment %d is %d bytes for %v with next header %d, against a %d byte session", i, len(fragment.raw), fragment.peer, fragment.header, mtu)
			}
			cut := fragment.raw[overhead:]
			if !bytes.Equal(cut[12:20], inner[12:20]) || int(binary.BigEndian.Uint16(cut[2:4])) != len(cut) || len(cut) > limit {
				tb.Fatalf("fragment %d carries a %d byte packet from %x past a %d byte limit", i, len(cut), cut[12:20], limit)
			}
			data = append(data, cut[20:]...)
		}
		if !bytes.Equal(data, inner[20:]) {
			tb.Fatalf("%d fragments carry %d bytes of data that are not the packet's %d", len(b.fragments), len(data), len(inner)-20)
		}
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
