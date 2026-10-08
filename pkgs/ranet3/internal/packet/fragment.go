// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package packet

import (
	"encoding/binary"
	"slices"
)

// the IPv4 header as RFC 791 section 3.1 lays it out
const (
	ipv4HeaderLen    = 20
	maxIPv4HeaderLen = 60
	// the three flags and the fragment offset share one 16 bit field
	reservedFlag   = 0x8000
	dontFragment   = 0x4000
	moreFragments  = 0x2000
	fragmentOffset = 0x1fff
	// fragmentUnit is the 8 bytes a fragment offset counts in
	fragmentUnit = 8
	// optionEnd and optionNOP are the two options of one byte
	// copiedOption is the flag of an option type every fragment carries
	optionEnd    = 0
	optionNOP    = 1
	copiedOption = 0x80
	// maxDatagram is the most the 16 bit total length counts, which a reassembled datagram stays within
	maxDatagram = 0xffff
)

// AppendFragments appends to dst the fragments RFC 791 section 3.2 cuts an IPv4 packet into for a link of mtu bytes, one after another
// the first carries the packet's own header and every later one the options whose copied flag is set, with NOPs where the others stood
// every header is then as long as the packet's, every fragment at most mtu bytes, and the data of all but the last a multiple of 8 bytes
// the last keeps the packet's more fragments flag, which lets a fragment cut again reassemble where it came from
// a packet that fits comes back as itself with its header checksum recomputed
// it reports false for anything but one whole IPv4 packet, for DF, for an option list that does not describe itself,
// for data past the largest datagram, and for an mtu with no room for 8 bytes of data past the header
func AppendFragments(dst, packet []byte, mtu int) ([]byte, bool) {
	if Version(packet) != 4 {
		return dst, false
	}
	headerLen := int(packet[0]&0x0f) * 4
	field := binary.BigEndian.Uint16(packet[6:8])
	offset := int(field&fragmentOffset) * fragmentUnit
	data := packet[headerLen:]
	chunk := (mtu - headerLen) &^ (fragmentUnit - 1)
	if field&dontFragment != 0 || offset+len(data) > maxDatagram || chunk < fragmentUnit {
		return dst, false
	}
	var later [maxIPv4HeaderLen]byte
	copy(later[:], packet[:headerLen])
	if !blankUncopied(later[ipv4HeaderLen:headerLen]) {
		return dst, false
	}
	count := max(1, (len(data)+chunk-1)/chunk)
	dst = slices.Grow(dst, len(packet)+(count-1)*headerLen)
	header := packet[:headerLen]
	for i := range count {
		start, end := i*chunk, min((i+1)*chunk, len(data))
		flags := field & (reservedFlag | moreFragments)
		if i < count-1 {
			flags |= moreFragments
		}
		at := len(dst)
		dst = append(dst, header...)
		dst = append(dst, data[start:end]...)
		fragment := dst[at:]
		binary.BigEndian.PutUint16(fragment[2:], uint16(len(fragment)))
		binary.BigEndian.PutUint16(fragment[6:], flags|uint16((offset+start)/fragmentUnit))
		binary.BigEndian.PutUint16(fragment[10:], 0)
		binary.BigEndian.PutUint16(fragment[10:], ^uint16(Sum(0, fragment[:headerLen])))
		header = later[:headerLen]
	}
	return dst, true
}

// blankUncopied writes NOPs over every option whose copied flag is clear, which a later fragment does not carry
// and reports false for an option list that does not describe itself
// what follows the end of the list is padding and stays as it is
func blankUncopied(options []byte) bool {
	for i := 0; i < len(options); {
		kind := options[i]
		if kind == optionEnd {
			return true
		}
		if kind == optionNOP {
			i++
			continue
		}
		if i+1 == len(options) {
			return false
		}
		length := int(options[i+1])
		if length < 2 || i+length > len(options) {
			return false
		}
		if kind&copiedOption == 0 {
			for j := range length {
				options[i+j] = optionNOP
			}
		}
		i += length
	}
	return true
}
