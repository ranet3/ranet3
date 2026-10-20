// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package packet

// HeaderValid reports whether p, an IPv4 packet as the link delivered it, passes RFC 1812 section 5.2.2's five tests
// the length the link reported, the checksum, the version, the header length and the total length
// it also holds the total length within what the link delivered, which the same section has a router verify
func HeaderValid(p []byte) bool {
	if _, version := Payload(p); version != 4 {
		return false
	}
	return Sum(0, p[:int(p[0]&0x0f)*4]) == 0xffff
}
