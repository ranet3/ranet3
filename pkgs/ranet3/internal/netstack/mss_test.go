// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"bytes"
	"encoding/binary"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/packet"
)

// tcpPacket is one whole IP packet carrying a TCP header with flags, options and a payload of payload bytes, its checksum valid
// field is IPv4's flags and fragment offset, and extension puts a destination options header in front of TCP under IPv6
// offset, when not zero, is the data offset written in place of the one the options take
func tcpPacket(family int, field uint16, extension bool, flags byte, options []byte, offset byte, payload int) []byte {
	ipHeader := 20
	if family == 6 {
		ipHeader = 40
		if extension {
			ipHeader += 8
		}
	}
	tcp := make([]byte, tcpHeaderLen+len(options)+payload)
	binary.BigEndian.PutUint16(tcp[0:], 40000)
	binary.BigEndian.PutUint16(tcp[2:], 443)
	binary.BigEndian.PutUint32(tcp[4:], 0x01020304)
	if offset == 0 {
		offset = byte((tcpHeaderLen + len(options)) / 4)
	}
	tcp[12] = offset << 4
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:], 64240)
	copy(tcp[tcpHeaderLen:], options)
	for i := tcpHeaderLen + len(options); i < len(tcp); i++ {
		tcp[i] = byte(i * 7)
	}
	raw := make([]byte, ipHeader+len(tcp))
	if family == 4 {
		raw[0] = 0x45
		binary.BigEndian.PutUint16(raw[2:], uint16(len(raw)))
		binary.BigEndian.PutUint16(raw[6:], field)
		raw[8], raw[9] = 64, tcpProtocol
		copy(raw[12:], []byte{10, 1, 0, 1, 10, 2, 0, 9})
		binary.BigEndian.PutUint16(raw[10:], ^uint16(packet.Sum(0, raw[:20])))
	} else {
		raw[0] = 0x60
		binary.BigEndian.PutUint16(raw[4:], uint16(len(raw)-40))
		raw[6], raw[7] = tcpProtocol, 64
		copy(raw[8:], tooBigSource[6].AsSlice())
		copy(raw[24:], tooBigDestination[6].AsSlice())
		if extension {
			raw[6] = 60
			raw[40] = tcpProtocol
			raw[42], raw[43] = 1, 4
		}
	}
	copy(raw[ipHeader:], tcp)
	binary.BigEndian.PutUint16(raw[ipHeader+tcpChecksum:], tcpSum(raw, ipHeader))
	return raw
}

// tcpSum is the checksum of the TCP segment at offset in raw, computed afresh over RFC 9293's pseudo-header with the field itself as zero
func tcpSum(raw []byte, offset int) uint16 {
	segment := bytes.Clone(raw[offset:])
	binary.BigEndian.PutUint16(segment[tcpChecksum:], 0)
	var pseudo []byte
	if raw[0]>>4 == 4 {
		pseudo = append(bytes.Clone(raw[12:20]), 0, tcpProtocol, byte(len(segment)>>8), byte(len(segment)))
	} else {
		pseudo = append(bytes.Clone(raw[8:40]), binary.BigEndian.AppendUint32(nil, uint32(len(segment)))...)
		pseudo = append(pseudo, 0, 0, 0, tcpProtocol)
	}
	return ^uint16(packet.Sum(packet.Sum(0, pseudo), segment))
}

// a SYN read off the tun has its MSS clamped to what its peer's session carries, less the IP and TCP headers
// and a steered one inside the header steering put on it, against the session less that header too
func TestReaderClampsTheMSSOfASYNToItsSession(t *testing.T) {
	const session = 1300
	for _, family := range []int{4, 6} {
		for segments := range 3 {
			steering := steerBothFrom(t, segments)
			syn := tcpPacket(family, 0, false, synFlag, []byte{optionMSS, mssLen, 0x05, 0xb4}, 0, 0)
			b, peer, _ := readOff(t, syn, steering, session)
			if b.peers[0] != peer {
				t.Fatalf("an IPv%d SYN under %d segments did not go to its peer", family, segments)
			}
			inner := b.bufs[0][tunOffset+steering.Overhead() : tunOffset+b.sizes[0]]
			offset := 20
			if family == 6 {
				offset = 40
			}
			want := session - steering.Overhead() - offset - tcpHeaderLen
			if got := int(binary.BigEndian.Uint16(inner[offset+tcpHeaderLen+2:])); got != want {
				t.Errorf("an IPv%d SYN under %d segments carries an MSS of %d, want %d", family, segments, got, want)
			}
			if got, want := binary.BigEndian.Uint16(inner[offset+tcpChecksum:]), tcpSum(inner, offset); got != want {
				t.Errorf("an IPv%d SYN under %d segments carries the checksum %#04x, want %#04x", family, segments, got, want)
			}
		}
	}
}
