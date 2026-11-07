// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package packet

import (
	"encoding/binary"
	"slices"
)

// the IPv6 header and its fragment header as RFC 8200 sections 3 and 4.5 lay them out
const (
	ipv6HeaderLen = 40
	// ipv6FragmentLen is the fragment header, its next header, a reserved
	// octet, the offset with the M flag, and the identification
	ipv6FragmentLen = 8
	// nextHopByHop, nextRouting and nextFragment are the extension headers a
	// packet's unfragmentable part holds or that say it is cut already
	nextHopByHop = 0
	nextRouting  = 43
	nextFragment = 44
	// ipv6MoreFragments is the M flag in the fragment header's offset field
	ipv6MoreFragments = 1
)

// AppendFragments6 appends to dst the fragments RFC 8200 section 4.5 cuts an
// IPv6 packet into for a link of mtu bytes, as its source cuts it, one after
// another under the identification id. The packet's own fixed header is its
// unfragmentable part, and each fragment carries a copy of it, its payload
// length its own, naming the fragment header, which names the packet's first
// next header. Every fragment is at most mtu bytes, and the data of all but the
// last a multiple of 8 bytes. A packet that fits comes back as itself.
//
// It reports false for anything but one whole IPv6 packet, for one whose first
// next header is a hop-by-hop or routing header, which an unfragmentable part
// holds, or a fragment header, which says it is cut already, and for an mtu
// with no room for 8 bytes of data past the two headers.
func AppendFragments6(dst, packet []byte, mtu int, id uint32) ([]byte, bool) {
	if Version(packet) != 6 || len(packet) < ipv6HeaderLen || int(binary.BigEndian.Uint16(packet[4:6])) != len(packet)-ipv6HeaderLen {
		return dst, false
	}
	next := packet[6]
	if next == nextHopByHop || next == nextRouting || next == nextFragment {
		return dst, false
	}
	if len(packet) <= mtu {
		return append(dst, packet...), true
	}
	chunk := (mtu - ipv6HeaderLen - ipv6FragmentLen) &^ (fragmentUnit - 1)
	if chunk < fragmentUnit {
		return dst, false
	}
	data := packet[ipv6HeaderLen:]
	count := (len(data) + chunk - 1) / chunk
	dst = slices.Grow(dst, len(packet)+count*(ipv6HeaderLen+ipv6FragmentLen))
	for i := range count {
		start, end := i*chunk, min((i+1)*chunk, len(data))
		at := len(dst)
		dst = append(dst, packet[:ipv6HeaderLen]...)
		dst = append(dst, make([]byte, ipv6FragmentLen)...)
		dst = append(dst, data[start:end]...)
		fragment := dst[at:]
		binary.BigEndian.PutUint16(fragment[4:6], uint16(ipv6FragmentLen+end-start))
		fragment[6] = nextFragment
		header := fragment[ipv6HeaderLen : ipv6HeaderLen+ipv6FragmentLen]
		header[0] = next
		offset := uint16(start)
		if i < count-1 {
			offset |= ipv6MoreFragments
		}
		binary.BigEndian.PutUint16(header[2:4], offset)
		binary.BigEndian.PutUint32(header[4:8], id)
	}
	return dst, true
}
