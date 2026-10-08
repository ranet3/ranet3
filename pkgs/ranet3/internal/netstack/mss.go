// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"encoding/binary"
	"math/bits"
)

// the TCP of RFC 9293 section 3.1 that a SYN's MSS option is read out of
const (
	tcpProtocol  = 6
	tcpHeaderLen = 20
	// tcpFlags is where the flags sit in the header, and synFlag the one a SYN and a SYN-ACK carry
	tcpFlags = 13
	synFlag  = 0x02
	// tcpChecksum is where the checksum sits in the header
	tcpChecksum = 16
	// optionEnd and optionNOP are the two options of one byte, and optionMSS with its length the one the clamp lowers
	optionEnd = 0
	optionNOP = 1
	optionMSS = 2
	mssLen    = 4
	// ipv4Segment and ipv6Segment are the IP and TCP headers an MSS leaves out of a packet, RFC 9293 section 3.7.1
	ipv4Segment = 20 + tcpHeaderLen
	ipv6Segment = 40 + tcpHeaderLen
)

// ClampMSS lowers the MSS option of a TCP SYN or SYN-ACK in packet to what a session carrying mtu byte packets takes
// mtu less 40 under IPv4 and less 60 under IPv6, with the checksum updated as RFC 1624 updates it
// a fragment, IPv6 with an extension header before TCP and an option list that does not describe itself pass as they came
// and so does a SYN with no MSS option, which RFC 9293 section 3.7.1 reads as 536 or 1220, within any session
// packet is one whole IP packet, and mtu at least the 1280 bytes IPv6 asks of every link less a steering header
func ClampMSS(packet []byte, mtu int) {
	var offset, limit int
	switch packet[0] >> 4 {
	case 4:
		if packet[9] != tcpProtocol {
			return
		}
		offset, limit = int(packet[0]&0x0f)*4, mtu-ipv4Segment
	case 6:
		if packet[6] != tcpProtocol {
			return
		}
		offset, limit = 40, mtu-ipv6Segment
	default:
		return
	}
	if len(packet) < offset+tcpHeaderLen || packet[offset+tcpFlags]&synFlag == 0 {
		return
	}
	// the bytes past a fragment's header are TCP's only in the first, and need not hold its whole header there
	if packet[0]>>4 == 4 && binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 {
		return
	}
	clampSYN(packet[offset:], limit)
}

// clampSYN lowers to limit every MSS option past it in the TCP header segment starts with
// once the whole option list has shown it describes itself
func clampSYN(segment []byte, limit int) {
	end := int(segment[12]>>4) * 4
	if end < tcpHeaderLen || end > len(segment) || !describesItself(segment[tcpHeaderLen:end]) {
		return
	}
	for i := tcpHeaderLen; i < end; {
		switch segment[i] {
		case optionEnd:
			return
		case optionNOP:
			i++
			continue
		}
		length := int(segment[i+1])
		if segment[i] == optionMSS && length == mssLen {
			if from := binary.BigEndian.Uint16(segment[i+2:]); int(from) > limit {
				checksum := binary.BigEndian.Uint16(segment[tcpChecksum:])
				binary.BigEndian.PutUint16(segment[tcpChecksum:], adjusted(checksum, from, uint16(limit), i%2 == 1))
				binary.BigEndian.PutUint16(segment[i+2:], uint16(limit))
			}
		}
		i += length
	}
}

// describesItself reports whether every option of a TCP option list but the two of one byte carries a length that fits the list
func describesItself(options []byte) bool {
	for i := 0; i < len(options); {
		switch options[i] {
		case optionEnd:
			return true
		case optionNOP:
			i++
			continue
		}
		if i+1 == len(options) || options[i+1] < 2 || i+int(options[i+1]) > len(options) {
			return false
		}
		i += int(options[i+1])
	}
	return true
}

// adjusted is checksum once a 16 bit field it covers moved from one value to another, RFC 1624 equation 3
// a field at an odd offset straddles two of the 16 bit words the checksum adds up, which take its bytes swapped
func adjusted(checksum, from, to uint16, odd bool) uint16 {
	if odd {
		from, to = bits.ReverseBytes16(from), bits.ReverseBytes16(to)
	}
	sum := uint32(^checksum) + uint32(^from) + uint32(to)
	sum = sum&0xffff + sum>>16
	sum = sum&0xffff + sum>>16
	return ^uint16(sum)
}
