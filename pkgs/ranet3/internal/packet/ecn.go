// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package packet

// ECN is the ECN field of an IP header, the two low bits of the IPv4 TOS octet or the IPv6 traffic class (RFC 3168 section 5)
type ECN uint8

const (
	NotECT ECN = 0b00
	ECT1   ECN = 0b01
	ECT0   ECN = 0b10
	CE     ECN = 0b11
)

// ECNOfTrafficClass is the ECN field of an IPv4 TOS octet or an IPv6 traffic class
func ECNOfTrafficClass(class uint8) ECN { return ECN(class & 0b11) }
