// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package packet

import (
	"bytes"
	"encoding/binary"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// every codepoint, swept in each case rather than drawn
var codepoints = []ECN{NotECT, ECT1, ECT0, CE}

// for any IPv4 header of every length from 20 to 60 bytes with a valid checksum, and every codepoint
// SetECN changes the two low bits of the TOS octet and the checksum alone, the checksum a receiver's full sum still accepts, and ECNOf reads the codepoint back
func TestSetECNKeepsAnIPv4HeaderValid(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		drawn := hegel.Draw(ht, hegel.Binary(maxIPv4HeaderLen, maxIPv4HeaderLen))
		for headerLen := ipv4HeaderLen; headerLen <= maxIPv4HeaderLen; headerLen += 4 {
			for _, e := range codepoints {
				header := bytes.Clone(drawn[:headerLen])
				header[0] = 4<<4 | byte(headerLen/4)
				binary.BigEndian.PutUint16(header[2:], uint16(headerLen))
				binary.BigEndian.PutUint16(header[10:], 0)
				binary.BigEndian.PutUint16(header[10:], ^headerSum(header))
				before := bytes.Clone(header)

				SetECN(header, e)
				if got := ECNOf(header); got != e {
					ht.Fatalf("a %d byte header set to %s reads back %s", headerLen, e, got)
				}
				if sum := headerSum(header); sum != 0xffff {
					ht.Fatalf("a %d byte header set to %s sums to %#04x, its TOS octet %#02x before and %#02x after", headerLen, e, sum, before[1], header[1])
				}
				if header[1]&^0b11 != before[1]&^0b11 {
					ht.Fatalf("setting %s changed the DSCP of %#02x to %#02x", e, before[1], header[1])
				}
				header[1], header[10], header[11] = before[1], before[10], before[11]
				if !bytes.Equal(header, before) {
					ht.Fatal("a byte other than the TOS octet and the checksum changed")
				}
			}
		}
	})
}

// for any IPv6 header and every codepoint, SetECN changes bits 20 and 21 of the first 32 bit word alone, the low two of the traffic class, and ECNOf reads the codepoint back
func TestSetECNChangesOnlyTheIPv6ECNBits(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		drawn := hegel.Draw(ht, hegel.Binary(40, 40))
		drawn[0] = 6<<4 | drawn[0]&0x0f
		for _, e := range codepoints {
			header := bytes.Clone(drawn)
			SetECN(header, e)
			if got := ECNOf(header); got != e {
				ht.Fatalf("a header set to %s reads back %s", e, got)
			}
			first, was := binary.BigEndian.Uint32(header), binary.BigEndian.Uint32(drawn)
			if (first^was)&^(0b11<<20) != 0 || first>>20&0b11 != uint32(e) {
				ht.Fatalf("setting %s made the first word %#08x of %#08x", e, first, was)
			}
			if !bytes.Equal(header[4:], drawn[4:]) {
				ht.Fatal("a byte past the first word changed")
			}
		}
	})
}
