// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package kernel

import (
	"bytes"
	"encoding/binary"
	"slices"
	"testing"
)

// completeOwnChecksum sets the transport checksum of packet, an IPv6 packet
// whose next header is UDP or TCP, to the one its bytes call for where it does
// not verify, and changes nothing else. A host sending to an address of its
// own on a utun computes that checksum for lo0, the interface of the kernel's
// own route at the address, whose offload leaves the pseudo-header's sum in
// the field and never runs on the packet, which leaves by the utun. The mesh
// completes it before it writes such a packet back (completeChecksum in
// internal/netstack), and a test writing one back in the mesh's place
// completes it here. An IPv6 packet with an extension header, whose checksum
// the host computes itself, and an IPv4 packet are left as read, as the mesh
// leaves them.
func completeOwnChecksum(packet []byte) {
	if len(packet) < 40 || packet[0]>>4 != 6 {
		return
	}
	segment, protocol := packet[40:], packet[6]
	var field int
	switch {
	// RFC 768
	case protocol == 17 && len(segment) >= 8:
		field = 6
	// RFC 9293 section 3.1
	case protocol == 6 && len(segment) >= 20:
		field = 16
	default:
		return
	}
	old := binary.BigEndian.Uint16(segment[field:])
	// RFC 8200 section 8.1 has a receiver discard an IPv6 UDP datagram whose
	// checksum field is zero, whatever the sum
	if ownSum(packet) == 0xffff && (protocol != 17 || old != 0) {
		return
	}
	binary.BigEndian.PutUint16(segment[field:], 0)
	checksum := ^ownSum(packet)
	// RFC 8200 section 8.1 sends a UDP checksum computed as zero as all ones
	if checksum == 0 && protocol == 17 {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(segment[field:], checksum)
}

// ownSum is the folded one's complement sum of packet's transport segment and
// the pseudo-header of RFC 8200 section 8.1, its upper-layer length the
// segment's
func ownSum(packet []byte) uint16 {
	segment := packet[40:]
	sum := uint32(len(segment)>>16) + uint32(len(segment)&0xffff) + uint32(packet[6])
	for _, words := range [][]byte{packet[8:40], segment} {
		for i := 0; i < len(words); i += 2 {
			word := uint32(words[i]) << 8
			if i+1 < len(words) {
				word |= uint32(words[i+1])
			}
			sum += word
		}
	}
	for sum > 0xffff {
		sum = sum&0xffff + sum>>16
	}
	return uint16(sum)
}

// ownPacket is an IPv6 packet from 3fff:10::1 to itself with next header
// next and segment after its fixed header
func ownPacket(next byte, segment ...byte) []byte {
	address := []byte{0x3f, 0xff, 0, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	packet := []byte{0x60, 0, 0, 0, byte(len(segment) >> 8), byte(len(segment)), next, 64}
	return slices.Concat(packet, address, address, segment)
}

// completeOwnChecksum sets an IPv6 UDP or TCP checksum lo0's offload left
// unfinished to the one its bytes call for, worked by hand below, and leaves
// a verifying one, an ICMPv6 packet, one with an extension header before its
// UDP header and an IPv4 packet as read. It completes one over a segment of
// odd length and a zero UDP field whose bytes sum to all ones, which RFC 8200
// never takes as verifying, and sends a UDP sum computed as zero as all ones.
// The pseudo-header of 3fff:10::1 to itself sums to 0x4010 twice plus the
// length plus the next header: 0x8041 for 16 bytes of UDP, the value a Mac
// read in such a datagram's field, and 0x803a for 20 of TCP.
func TestCompleteOwnChecksumFinishesWhatTheOffloadLeft(t *testing.T) {
	// ports 0x8000 to 9, length 16, eight zero bytes: 0x8041 + 0x8000 + 9 + 0x10 folds to 0x005b
	udp := []byte{0x80, 0, 0, 9, 0, 16, 0x80, 0x41, 0, 0, 0, 0, 0, 0, 0, 0}
	// ports 0x8000 to 9, a SYN of five words, window 0xffff: 0x803a + 0x8000 + 9 + 0x5002 + 0xffff folds to 0x5046
	tcp := []byte{0x80, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x02, 0xff, 0xff, 0x80, 0x3a, 0, 0}
	// the darwin test's datagram, "own address", a segment of 19 bytes, its last byte padded:
	// 0x8020 + 0x13 + 0x11 = 0x8044, + 0x8000 + 9 + 0x13 + 0x6f77 + 0x6e20 + 0x6164 + 0x6472 + 0x6573 + 0x7300 = 0x37c40, folds to 0x7c43
	odd := slices.Concat([]byte{0x80, 0, 0, 9, 0, 19, 0x80, 0x44}, []byte("own address"))
	// the udp datagram with its first payload word 0xffa4, whose bytes with the field zero sum to 0x005b + 0xffa4 = 0xffff
	allOnes := slices.Concat(udp[:8], []byte{0xff, 0xa4}, udp[10:])
	// a hop-by-hop header of eight bytes, its next header UDP, before the UDP datagram
	hopByHop := slices.Concat([]byte{17, 0, 1, 4, 0, 0, 0, 0}, udp)
	ipv4 := []byte{0x45, 0, 0, 36, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 192, 0, 2, 1, 0x80, 0, 0, 9, 0, 16, 0x80, 0x41, 0, 0, 0, 0, 0, 0, 0, 0}
	for _, c := range []struct {
		name   string
		packet []byte
		// field is the checksum's offset in the packet and want its value after, or -1 for a packet left as read
		field int
		want  uint16
	}{
		{"an unfinished UDP checksum", ownPacket(17, udp...), 46, 0xffa4},
		{"an unfinished TCP checksum", ownPacket(6, tcp...), 56, 0xafb9},
		{"a verifying UDP checksum", ownPacket(17, slices.Concat(udp[:6], []byte{0xff, 0xa4}, udp[8:])...), 46, 0xffa4},
		{"a UDP checksum field of zero whose bytes call for 0xffa4", ownPacket(17, slices.Concat(udp[:6], []byte{0, 0}, udp[8:])...), 46, 0xffa4},
		{"an unfinished UDP checksum over an odd segment", ownPacket(17, odd...), 46, 0x83bc},
		// RFC 8200 section 8.1: a zero field never verifies, though the bytes sum to all ones with it
		{"a UDP checksum field of zero whose bytes sum to all ones", ownPacket(17, slices.Concat(allOnes[:6], []byte{0, 0}, allOnes[8:])...), 46, 0xffff},
		// the sum computed is zero, which RFC 8200 section 8.1 sends as all ones
		{"an unfinished UDP checksum computed as zero", ownPacket(17, allOnes...), 46, 0xffff},
		{"an ICMPv6 echo request", ownPacket(58, 128, 0, 0x12, 0x34, 0, 1, 0, 1), -1, 0},
		{"a hop-by-hop header before UDP", ownPacket(0, hopByHop...), -1, 0},
		{"an IPv4 datagram", ipv4, -1, 0},
	} {
		packet := slices.Clone(c.packet)
		completeOwnChecksum(packet)
		if c.field < 0 {
			if !bytes.Equal(packet, c.packet) {
				t.Errorf("%s: the packet changed from % x to % x", c.name, c.packet, packet)
			}
			continue
		}
		if got := binary.BigEndian.Uint16(packet[c.field:]); got != c.want {
			t.Errorf("%s: the checksum reads %#04x, want %#04x", c.name, got, c.want)
		}
		if ownSum(packet) != 0xffff {
			t.Errorf("%s: the completed packet does not verify", c.name)
		}
		packet[c.field], packet[c.field+1] = c.packet[c.field], c.packet[c.field+1]
		if !bytes.Equal(packet, c.packet) {
			t.Errorf("%s: a byte beside the checksum changed", c.name)
		}
	}
}
