// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package packet

import "encoding/binary"

// ECN is the ECN field of an IP header, the two low bits of the IPv4 TOS octet or the IPv6 traffic class (RFC 3168 section 5)
type ECN uint8

const (
	NotECT ECN = 0b00
	ECT1   ECN = 0b01
	ECT0   ECN = 0b10
	CE     ECN = 0b11
)

func (e ECN) String() string {
	switch e {
	case NotECT:
		return "Not-ECT"
	case ECT1:
		return "ECT(1)"
	case ECT0:
		return "ECT(0)"
	case CE:
		return "CE"
	}
	return "invalid"
}

func ECNOfTrafficClass(class uint8) ECN { return ECN(class & 0b11) }

// ECNOf is the ECN field of p, an IPv4 or IPv6 packet Payload passed
// an IPv6 traffic class takes the low half of the first octet and the high half of the second, its ECN field the second's bits 4 and 5
func ECNOf(p []byte) ECN {
	if p[0]>>4 == 4 {
		return ECNOfTrafficClass(p[1])
	}
	return ECNOfTrafficClass(p[1] >> 4)
}

// SetECN writes e into the ECN field of p, an IPv4 or IPv6 packet Payload passed
// the IPv4 header checksum follows its first 16 bit word by RFC 1624 section 3's equation 3
func SetECN(p []byte, e ECN) {
	if p[0]>>4 == 4 {
		before := binary.BigEndian.Uint16(p[0:2])
		p[1] = p[1]&^0b11 | byte(e)
		binary.BigEndian.PutUint16(p[10:], AdjustChecksum(binary.BigEndian.Uint16(p[10:12]), before, binary.BigEndian.Uint16(p[0:2]), false))
		return
	}
	p[1] = p[1]&^0b11_0000 | byte(e)<<4
}

// severity ranks the codepoints as RFC 6040 section 4.2 does, CE over ECT(1) over ECT(0) over Not-ECT
var severity = [4]uint8{NotECT: 0, ECT0: 1, ECT1: 2, CE: 3}

// Decapsulate is the cell of RFC 6040 section 4.2's Figure 4 for an arriving inner and outer ECN field
// drop is the cell that drops the packet, and unused a combination the figure marks (!!!) or (!), which no tunnel ingress sends
func Decapsulate(inner, outer ECN) (out ECN, drop, unused bool) {
	if inner == NotECT {
		return NotECT, outer == CE, outer != NotECT
	}
	out = inner
	if severity[outer] > severity[inner] {
		out = outer
	}
	return out, false, inner == ECT1 && outer == ECT0 || inner == CE && outer == ECT1
}
