// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package packet

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

// always lets every answer out, for a test of what an answer holds
func always() bool { return true }

// each error answers a short datagram quoting all of it and a long one quoting what fits 576 bytes
// and every error refuses alike what RFC 1812 section 4.3.2.7 lets no error answer, a header section 5.2.2 refuses, and a source that is not one host
// the golden file shows each answer's header, its ICMP header and the length it quotes, and each case refused
func TestErrorsMatchTheirGoldenAnswers(t *testing.T) {
	source := netip.AddrFrom4([4]byte{198, 51, 100, 1})
	var out strings.Builder
	for _, offending := range [][]byte{validHeader(8), validHeader(1216)} {
		for _, builder := range errorBuilders {
			answer := builder.build(offending, source, 64, 1400, always)
			if builder.kind == icmpParameterProblem {
				answer = builder.build(offending, source, 64, ipv4HeaderLen, always)
			}
			if answer == nil {
				t.Fatalf("%s refused a %d byte datagram", builder.name, len(offending))
			}
			fmt.Fprintf(&out, "%s answering %d bytes: %d bytes from %v to %v, type %d code %d, quoting %d\n",
				builder.name, len(offending), len(answer), netip.AddrFrom4([4]byte(answer[12:16])), netip.AddrFrom4([4]byte(answer[16:20])),
				answer[20], answer[21], len(answer)-ipv4HeaderLen-icmpHeaderLen)
			out.WriteString(hex.Dump(answer[:ipv4HeaderLen+icmpHeaderLen]))
		}
	}
	edited := func(edit func([]byte)) []byte {
		raw := validHeader(8)
		edit(raw)
		return resum(raw)
	}
	for _, refused := range []struct {
		name   string
		raw    []byte
		source netip.Addr
	}{
		{"an ICMP error", edited(func(raw []byte) { raw[9], raw[24] = icmpProtocol, icmpTimeExceeded }), source},
		{"a fragment but the first", edited(func(raw []byte) { binary.BigEndian.PutUint16(raw[6:], moreFragments|1) }), source},
		{"a datagram from this network", edited(func(raw []byte) { copy(raw[12:], []byte{0, 1, 2, 3}) }), source},
		{"a datagram from loopback", edited(func(raw []byte) { copy(raw[12:], []byte{127, 0, 0, 1}) }), source},
		{"a datagram to a group", edited(func(raw []byte) { copy(raw[16:], []byte{224, 0, 0, 5}) }), source},
		{"a datagram to the limited broadcast", edited(func(raw []byte) { copy(raw[16:], []byte{255, 255, 255, 255}) }), source},
		{"a header failing its checksum", func() []byte { raw := validHeader(8); raw[11]++; return raw }(), source},
		{"a header longer than the datagram", edited(func(raw []byte) { binary.BigEndian.PutUint16(raw[2:], 20) }), source},
		{"a datagram longer than the bytes read", edited(func(raw []byte) { binary.BigEndian.PutUint16(raw[2:], 64) }), source},
		{"a datagram with bytes after it", append(validHeader(8), 0), source},
		{"a datagram answered from a group", validHeader(8), netip.AddrFrom4([4]byte{224, 0, 0, 5})},
		{"a datagram answered from an IPv6 address", validHeader(8), netip.MustParseAddr("3fff::1")},
	} {
		var answered []string
		for _, builder := range errorBuilders {
			if builder.build(refused.raw, refused.source, 64, 1400, always) != nil {
				answered = append(answered, builder.name)
			}
		}
		if len(answered) == 0 {
			fmt.Fprintf(&out, "%s: refused by every error\n", refused.name)
		} else {
			fmt.Fprintf(&out, "%s: answered by %s\n", refused.name, strings.Join(answered, ", "))
		}
	}
	goldentest.Check(t, "./internal/packet", filepath.Join("testdata", "answers", "ipv4.txt"), []byte(out.String()))
}
