// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package packet

import (
	"bytes"
	"encoding/binary"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// ipv6Packet is an IPv6 packet whose first next header is next, with data
// bytes behind its fixed header counting up in 16 bit words from seed
func ipv6Packet(next byte, seed uint16, data int) []byte {
	raw := make([]byte, ipv6HeaderLen+data)
	raw[0], raw[1], raw[2], raw[3] = 0x6a, 0xb1, 0x23, 0x45
	binary.BigEndian.PutUint16(raw[4:6], uint16(data))
	raw[6], raw[7] = next, 57
	copy(raw[8:24], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5})
	copy(raw[24:40], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})
	for i := ipv6HeaderLen; i < len(raw); i++ {
		word := uint16((i-ipv6HeaderLen)/2) + seed
		raw[i] = byte(word >> (8 * (1 - (i-ipv6HeaderLen)%2)))
	}
	return raw
}

// fragments6Of splits what AppendFragments6 wrote after start into its
// packets, by the payload length each one carries
func fragments6Of(tb testing.TB, out []byte, start int) [][]byte {
	tb.Helper()
	var packets [][]byte
	for rest := out[start:]; len(rest) != 0; {
		if len(rest) < ipv6HeaderLen {
			tb.Fatalf("%d bytes trail the last fragment, short of a header", len(rest))
		}
		length := ipv6HeaderLen + int(binary.BigEndian.Uint16(rest[4:6]))
		if length > len(rest) {
			tb.Fatalf("a fragment claims %d bytes with %d left", length, len(rest))
		}
		packets = append(packets, rest[:length])
		rest = rest[length:]
	}
	return packets
}

// reassemble6 puts fragments of original back together as RFC 8200 section
// 4.5 has a destination reassemble them, checking each on the way: every one
// at most mtu bytes, its fixed header the original's but for the payload
// length and the next header, which names a fragment header naming the
// original's next header under id, the offsets following on with no gap or
// overlap, M set on all but the last, and the data of all but the last a
// multiple of 8 bytes
func reassemble6(tb testing.TB, fragments [][]byte, original []byte, mtu int, id uint32) []byte {
	tb.Helper()
	var data []byte
	for i, fragment := range fragments {
		if len(fragment) > mtu || len(fragment) < ipv6HeaderLen+ipv6FragmentLen {
			tb.Fatalf("fragment %d of %d is %d bytes against an mtu of %d", i, len(fragments), len(fragment), mtu)
		}
		if !bytes.Equal(fragment[:4], original[:4]) || fragment[7] != original[7] || !bytes.Equal(fragment[8:ipv6HeaderLen], original[8:ipv6HeaderLen]) {
			tb.Fatalf("fragment %d carries a fixed header %x unlike the packet's %x", i, fragment[:ipv6HeaderLen], original[:ipv6HeaderLen])
		}
		header := fragment[ipv6HeaderLen : ipv6HeaderLen+ipv6FragmentLen]
		if fragment[6] != nextFragment || header[0] != original[6] || header[1] != 0 || binary.BigEndian.Uint32(header[4:8]) != id {
			tb.Fatalf("fragment %d names %d, then %d with reserved %d under id %#x, want 44, then %d under %#x",
				i, fragment[6], header[0], header[1], binary.BigEndian.Uint32(header[4:8]), original[6], id)
		}
		field := binary.BigEndian.Uint16(header[2:4])
		if at := int(field &^ 7); at != len(data) {
			tb.Fatalf("fragment %d starts at byte %d of the payload, want %d", i, at, len(data))
		}
		if field&6 != 0 {
			tb.Fatalf("fragment %d sets the reserved bits of its offset field, %#04x", i, field)
		}
		last := i == len(fragments)-1
		if more := field&ipv6MoreFragments != 0; more == last {
			tb.Fatalf("fragment %d of %d has M %t", i, len(fragments), more)
		}
		carried := fragment[ipv6HeaderLen+ipv6FragmentLen:]
		if !last && (len(carried) == 0 || len(carried)%fragmentUnit != 0) {
			tb.Fatalf("fragment %d of %d carries %d bytes, which is no whole number of 8 byte units", i, len(fragments), len(carried))
		}
		data = append(data, carried...)
	}
	whole := append(bytes.Clone(original[:ipv6HeaderLen]), data...)
	binary.BigEndian.PutUint16(whole[4:6], uint16(len(data)))
	return whole
}

// for any IPv6 packet of a transport the exit builds a reply of, any size and
// any mtu with room for 8 bytes of data past both headers, the packet comes
// back as itself where it fits, and otherwise as fragments that each fit, are
// cut at 8 byte units and reassemble to the packet. The sizes at a whole
// number of fragments and one byte either side are tried before anything is
// drawn.
func TestIPv6FragmentsReassembleToThePacket(t *testing.T) {
	check := func(tb testing.TB, next byte, seed uint16, data, mtu int, id uint32) {
		tb.Helper()
		original := ipv6Packet(next, seed, data)
		prefix := []byte("kept")
		out, ok := AppendFragments6(prefix, original, mtu, id)
		if !ok {
			tb.Fatalf("a %d byte packet was refused at an mtu of %d", len(original), mtu)
		}
		if !bytes.Equal(out[:len(prefix)], []byte("kept")) {
			tb.Fatal("the fragments were not appended after what dst held")
		}
		if len(original) <= mtu {
			if !bytes.Equal(out[len(prefix):], original) {
				tb.Fatalf("a %d byte packet that fits an mtu of %d came back changed", len(original), mtu)
			}
			return
		}
		fragments := fragments6Of(tb, out, len(prefix))
		if got := reassemble6(tb, fragments, original, mtu, id); !bytes.Equal(got, original) {
			tb.Fatalf("%d fragments reassemble to %d bytes that differ from the %d byte packet", len(fragments), len(got), len(original))
		}
	}
	least := ipv6HeaderLen + ipv6FragmentLen + fragmentUnit
	for mtu := least; mtu < least+fragmentUnit; mtu++ {
		chunk := (mtu - ipv6HeaderLen - ipv6FragmentLen) &^ (fragmentUnit - 1)
		for _, data := range []int{0, 1, chunk - 1, chunk, chunk + 1, 3*chunk - 1, 3 * chunk, 3*chunk + 1} {
			check(t, 17, 0, data, mtu, 7)
		}
	}
	for _, mtu := range []int{1280, 1500} {
		check(t, 58, 0x1234, 3000, mtu, 0xfeedbeef)
	}
	pbt.Check(t, func(ht *hegel.T) {
		next := []byte{6, 17, 58}[hegel.Draw(ht, hegel.Integers(0, 2))]
		data := hegel.Draw(ht, pbt.Spanning(0, 0xffff))
		mtu := hegel.Draw(ht, pbt.Spanning(least, max(least, ipv6HeaderLen+data+fragmentUnit)))
		seed := hegel.Draw(ht, hegel.Integers[uint16](0, 0xffff))
		id := hegel.Draw(ht, hegel.Integers[uint32](0, 0xffffffff))
		check(ht, next, seed, data, mtu, id)
	})
}

// what RFC 8200 section 4.5 cannot cut as the exit's replies are cut is
// refused, and dst comes back as it was
func TestIPv6FragmentsAreRefusedForWhatCannotBeCut(t *testing.T) {
	wrongLength := ipv6Packet(17, 0, 3000)
	binary.BigEndian.PutUint16(wrongLength[4:6], 2999)
	for _, c := range []struct {
		name   string
		packet []byte
		mtu    int
	}{
		{"an IPv4 packet", ipv4Packet(nil, 0, 0, 3000), 1280},
		{"a payload length unlike the packet's", wrongLength, 1280},
		{"a hop-by-hop header first", ipv6Packet(0, 0, 3000), 1280},
		{"a routing header first", ipv6Packet(43, 0, 3000), 1280},
		{"a fragment already", ipv6Packet(44, 0, 3000), 1280},
		{"an mtu with no room for 8 bytes of data", ipv6Packet(17, 0, 3000), ipv6HeaderLen + ipv6FragmentLen + fragmentUnit - 1},
		{"a packet shorter than its header", ipv6Packet(17, 0, 0)[:39], 1280},
	} {
		t.Run(c.name, func(t *testing.T) {
			out, ok := AppendFragments6([]byte("kept"), c.packet, c.mtu, 1)
			if ok || !bytes.Equal(out, []byte("kept")) {
				t.Errorf("cut to %d bytes, reported %t, want refused with dst as it was", len(out), ok)
			}
		})
	}
}
