// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package packet

import (
	"encoding/binary"
	"testing"
)

// HeaderValid refuses any version but 4, RFC 1812 section 5.2.2's third test, whatever the sum
// here an IPv6 packet whose first 20 bytes fold to 0xffff, as a valid IPv4 header of 5 words does
func TestHeaderValidRefusesAnIPv6PacketThatSumsAsAHeader(t *testing.T) {
	raw := make([]byte, 40)
	// version 6, with a traffic class whose low bits read as a header length of 5 words
	raw[0] = 0x65
	// two bytes of the source address bring the sum of the first 20 bytes to 0xffff
	binary.BigEndian.PutUint16(raw[10:], ^uint16(Sum(0, raw[:20])))
	if _, version := Payload(raw); version != 6 || Sum(0, raw[:20]) != 0xffff {
		t.Fatalf("the packet reads as version %d with its first 20 bytes summing to %#x, want 6 and 0xffff", version, Sum(0, raw[:20]))
	}
	if HeaderValid(raw) {
		t.Errorf("HeaderValid took an IPv6 packet whose first 20 bytes sum as an IPv4 header")
	}
}
