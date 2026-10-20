// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"encoding/binary"

	"ranet3.com/pkgs/ranet3/internal/packet"
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
// it never raises an MSS
func (m *Mesh) ClampMSS(packet []byte, mtu int) {
	if clampMSS(packet, mtu) {
		m.mssClamped.Add(1)
	}
}

// MSSClamped is how many SYNs had their MSS lowered to a session's budget
func (m *Mesh) MSSClamped() uint64 { return m.mssClamped.Load() }

// MSSLimits is the MSS a SYN through a session carrying mtu byte packets leaves with at most, under IPv4 and under IPv6
func MSSLimits(mtu int) (ipv4, ipv6 int) { return mtu - ipv4Segment, mtu - ipv6Segment }

// clampMSS updates the checksum as RFC 1624 does
// a SYN without an MSS option passes, which RFC 9293 section 3.7.1 reads as 536 or 1220, within any session
// an mtu leaving no room past the headers passes every packet, which keeps the clamp from raising an MSS
func clampMSS(packet []byte, mtu int) bool {
	// bytes short of the least IPv4 and TCP headers hold no SYN, and any more hold the protocol fields read next
	if len(packet) < ipv4Segment {
		return false
	}
	var offset, limit int
	switch packet[0] >> 4 {
	case 4:
		if packet[9] != tcpProtocol {
			return false
		}
		offset, limit = int(packet[0]&0x0f)*4, mtu-ipv4Segment
	case 6:
		if packet[6] != tcpProtocol {
			return false
		}
		offset, limit = 40, mtu-ipv6Segment
	default:
		return false
	}
	if limit <= 0 || len(packet) < offset+tcpHeaderLen || packet[offset+tcpFlags]&synFlag == 0 {
		return false
	}
	// the bytes past a fragment's header are TCP's only in the first, and need not hold its whole header there
	if packet[0]>>4 == 4 && binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 {
		return false
	}
	return clampSYN(packet[offset:], limit)
}

// clampSYN lowers to limit every MSS option past it in the TCP header segment starts with
// once the whole option list has shown it describes itself
func clampSYN(segment []byte, limit int) bool {
	end := int(segment[12]>>4) * 4
	if end < tcpHeaderLen || end > len(segment) || !describesItself(segment[tcpHeaderLen:end]) {
		return false
	}
	lowered := false
	for i := tcpHeaderLen; i < end; {
		switch segment[i] {
		case optionEnd:
			return lowered
		case optionNOP:
			i++
			continue
		}
		length := int(segment[i+1])
		if segment[i] == optionMSS && length == mssLen {
			if from := binary.BigEndian.Uint16(segment[i+2:]); int(from) > limit {
				checksum := binary.BigEndian.Uint16(segment[tcpChecksum:])
				binary.BigEndian.PutUint16(segment[tcpChecksum:], packet.AdjustChecksum(checksum, from, uint16(limit), i%2 == 1))
				binary.BigEndian.PutUint16(segment[i+2:], uint16(limit))
				lowered = true
			}
		}
		i += length
	}
	return lowered
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
