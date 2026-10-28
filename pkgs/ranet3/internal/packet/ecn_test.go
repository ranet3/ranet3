// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package packet

import (
	"encoding/binary"
	"strings"
	"testing"
)

// figure4 is RFC 6040 section 4.2's Figure 4 as rfc6040.txt:571-580 prints it, a row per arriving inner header and a column per arriving outer header in figure4Order
// <drop> is written drop, and (!!!) and (!) mark the currently unused combinations
var figure4 = [4][4]string{
	{"Not-ECT", "Not-ECT(!!!)", "Not-ECT(!!!)", "drop(!!!)"},
	{"ECT(0)", "ECT(0)", "ECT(1)", "CE"},
	{"ECT(1)", "ECT(1) (!)", "ECT(1)", "CE"},
	{"CE", "CE", "CE(!!!)", "CE"},
}

var (
	figure4Order     = [4]ECN{NotECT, ECT0, ECT1, CE}
	figure4Codepoint = map[string]ECN{"Not-ECT": NotECT, "ECT(0)": ECT0, "ECT(1)": ECT1, "CE": CE}
)

// ecnHeaders is an IPv4 header with a valid checksum and an IPv6 header, each with the DSCP 0x2e and the ECN field field
func ecnHeaders(field ECN) [][]byte {
	v4 := make([]byte, ipv4HeaderLen)
	v4[0], v4[1], v4[8], v4[9] = 0x45, 0xb8|byte(field), 64, 17
	binary.BigEndian.PutUint16(v4[2:], ipv4HeaderLen)
	copy(v4[12:], []byte{192, 0, 2, 1, 198, 51, 100, 1})
	putHeaderChecksum(v4)
	v6 := make([]byte, 40)
	binary.BigEndian.PutUint32(v6, 6<<28|uint32(0xb8|field)<<20|0x12345)
	v6[6], v6[7] = 17, 64
	return [][]byte{v4, v6}
}

// every cell of Figure 4, for an IPv4 and an IPv6 inner header: the drop, the unused combinations, and the outgoing field once written and read back, with the IPv4 checksum still valid
func TestDecapsulationFollowsFigure4(t *testing.T) {
	for row, inner := range figure4Order {
		for column, outer := range figure4Order {
			cell := figure4[row][column]
			want, unused := strings.CutSuffix(strings.TrimSuffix(cell, " (!)"), "(!!!)")
			unused = unused || strings.HasSuffix(cell, "(!)")
			out, drop, flagged := Decapsulate(inner, outer)
			if drop != (want == "drop") || flagged != unused {
				t.Errorf("inner %s under outer %s: drop %t and unused %t, Figure 4 has %q", inner, outer, drop, flagged, cell)
			}
			if want == "drop" {
				continue
			}
			for _, header := range ecnHeaders(inner) {
				SetECN(header, out)
				if got := ECNOf(header); got != figure4Codepoint[want] {
					t.Errorf("inner %s under outer %s leaves an IPv%d header %s, Figure 4 has %q", inner, outer, header[0]>>4, got, cell)
				}
				if header[0]>>4 == 4 && Sum(0, header) != 0xffff {
					t.Errorf("inner %s under outer %s leaves an IPv4 header whose checksum fails", inner, outer)
				}
			}
		}
	}
}
