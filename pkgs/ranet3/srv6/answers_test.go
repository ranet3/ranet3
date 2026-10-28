// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package srv6

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/goldentest"
)

// each error answers a short packet quoting all of it and a long one quoting what fits the IPv6 minimum MTU, RFC 4443 section 2.4 (c)
// the golden file shows each answer's header, its ICMPv6 header and the length it quotes
func TestErrorsMatchTheirGoldenAnswers(t *testing.T) {
	sid := addr("3fff:b:0:106::2")
	long := append(segmentRouted(t), make([]byte, 2000)...)
	binary.BigEndian.PutUint16(long[4:], uint16(len(long)-ipv6HeaderLen))
	var out strings.Builder
	for _, offending := range [][]byte{segmentRouted(t), long} {
		for _, builder := range errorBuilders {
			answer := builder.build(offending, sid, always)
			if answer == nil {
				t.Fatalf("%s refused a %d byte packet", builder.name, len(offending))
			}
			if answer[ipv6HeaderLen] != builder.kind || answer[ipv6HeaderLen+1] != builder.code {
				t.Errorf("%s is type %d code %d, want %d and %d", builder.name, answer[ipv6HeaderLen], answer[ipv6HeaderLen+1], builder.kind, builder.code)
			}
			if got := verify(sid, netip.AddrFrom16([16]byte(answer[24:40])), answer[ipv6HeaderLen:]); got != 0 {
				t.Errorf("a receiver sums %s to %#04x, want zero", builder.name, got)
			}
			fmt.Fprintf(&out, "%s answering %d bytes: %d bytes from %v to %v, type %d code %d, quoting %d\n",
				builder.name, len(offending), len(answer), netip.AddrFrom16([16]byte(answer[8:24])), netip.AddrFrom16([16]byte(answer[24:40])),
				answer[ipv6HeaderLen], answer[ipv6HeaderLen+1], len(answer)-ipv6HeaderLen-icmpHeaderLen)
			out.WriteString(hex.Dump(answer[:ipv6HeaderLen+icmpHeaderLen]))
		}
	}
	goldentest.Check(t, "./srv6", filepath.Join("testdata", "answers", "ipv6.txt"), []byte(out.String()))
}
