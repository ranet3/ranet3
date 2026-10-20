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
// each behind a copy of outer, the header of a tunnel carrying them, empty for none and counted in no fragment's mtu
// the first carries the packet's own header and every later one the options whose copied flag is set, with NOPs where the others stood
// every header is then as long as the packet's, every fragment at most mtu bytes, and the data of all but the last a multiple of 8 bytes
// the last keeps the packet's more fragments flag, which lets a fragment cut again reassemble where it came from
// a packet that fits comes back as itself
// it reports false for anything but one whole IPv4 packet whose header HeaderValid passes, as RFC 1812 section 5.2.2 has a router discard any other
// for DF, for an option list that does not describe itself, for data past the largest datagram, and for an mtu with no room for 8 bytes of data past the header
// fault is the octet an option list that does not describe itself goes wrong at, counted from the header's first, and 0 for every other refusal
func AppendFragments(dst, outer, packet []byte, mtu int) (out []byte, fault int, ok bool) {
	if Version(packet) != 4 || !HeaderValid(packet) {
		return dst, 0, false
	}
	headerLen := int(packet[0]&0x0f) * 4
	field := binary.BigEndian.Uint16(packet[6:8])
	offset := int(field&fragmentOffset) * fragmentUnit
	data := packet[headerLen:]
	chunk := (mtu - headerLen) &^ (fragmentUnit - 1)
	if field&dontFragment != 0 || offset+len(data) > maxDatagram || chunk < fragmentUnit {
		return dst, 0, false
	}
	var later [maxIPv4HeaderLen]byte
	copy(later[:], packet[:headerLen])
	if at, ok := blankUncopied(later[ipv4HeaderLen:headerLen]); !ok {
		return dst, ipv4HeaderLen + at, false
	}
	count := max(1, (len(data)+chunk-1)/chunk)
	dst = slices.Grow(dst, len(packet)+(count-1)*headerLen+count*len(outer))
	header := packet[:headerLen]
	for i := range count {
		start, end := i*chunk, min((i+1)*chunk, len(data))
		flags := field & (reservedFlag | moreFragments)
		if i < count-1 {
			flags |= moreFragments
		}
		dst = append(dst, outer...)
		at := len(dst)
		dst = append(dst, header...)
		dst = append(dst, data[start:end]...)
		fragment := dst[at:]
		binary.BigEndian.PutUint16(fragment[2:], uint16(len(fragment)))
		binary.BigEndian.PutUint16(fragment[6:], flags|uint16((offset+start)/fragmentUnit))
		putHeaderChecksum(fragment[:headerLen])
		header = later[:headerLen]
	}
	return dst, 0, true
}

// blankUncopied writes NOPs over every option whose copied flag is clear, which a later fragment does not carry
// and reports false for an option list that does not describe itself, with the offset of the option at fault
// what follows the end of the list is padding and stays as it is
func blankUncopied(options []byte) (int, bool) {
	for i := 0; ; {
		start, end, fault := nextOption(options, i)
		switch {
		case fault:
			return start, false
		case start == end:
			return 0, true
		case options[start]&copiedOption == 0:
			for j := start; j < end; j++ {
				options[j] = optionNOP
			}
		}
		i = end
	}
}

// nextOption frames the first option at offset i of list, an IPv4 option list, or past the NOPs there, as list[start:end]
// an empty span where the list ends, at its last byte or its end of list option, which padding follows
// fault reports an option whose framing RFC 791 cannot read, with start the offset of its type octet
// a type octet in the list's last byte, a length under 2 or a length past the list
func nextOption(list []byte, i int) (start, end int, fault bool) {
	for i < len(list) && list[i] == optionNOP {
		i++
	}
	switch {
	case i == len(list) || list[i] == optionEnd:
		return len(list), len(list), false
	case i+1 == len(list):
		return i, i, true
	}
	length := int(list[i+1])
	if length < 2 || i+length > len(list) {
		return i, i, true
	}
	return i, i + length, false
}
