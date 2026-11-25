// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT

package tun

import (
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	gvisorChecksum "gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func TestEverySplitSegmentCarriesAValidChecksum(t *testing.T) {
	for _, version := range []int{4, 6} {
		for _, protocol := range []uint8{ipProtoTCP, ipProtoUDP} {
			for _, size := range []int{1, 128, 512, 1000, 1400} {
				for _, tail := range []int{0, 1} {
					for _, overlap := range []bool{false, true} {
						name := fmt.Sprintf("ipv%d/proto%d/size%d/tail%d/overlap%t", version, protocol, size, tail, overlap)
						t.Run(name, func(t *testing.T) {
							checkSplitChecksum(t, version, protocol, size, tail, overlap)
						})
					}
				}
			}
		}
	}
}

func checkSplitChecksum(t *testing.T, version int, protocol uint8, size, tail int, overlap bool) {
	t.Helper()
	iphLen, transportLen, offset := 20, 20, uint16(16)
	if version == 6 {
		iphLen = 40
	}
	if protocol == ipProtoUDP {
		transportLen, offset = 8, 6
	}
	hdrLen := iphLen + transportLen
	payloadLen := 2 * size
	if tail != 0 {
		payloadLen += size - 1
	}
	packet := make([]byte, hdrLen+payloadLen)
	if version == 4 {
		header.IPv4(packet).Encode(&header.IPv4Fields{
			SrcAddr:  tcpip.AddrFromSlice(netip.MustParseAddr("192.0.2.1").AsSlice()),
			DstAddr:  tcpip.AddrFromSlice(netip.MustParseAddr("192.0.2.2").AsSlice()),
			Protocol: protocol, TTL: 64, TotalLength: uint16(len(packet)),
		})
	} else {
		header.IPv6(packet).Encode(&header.IPv6Fields{
			SrcAddr:           tcpip.AddrFromSlice(netip.MustParseAddr("2001:db8::1").AsSlice()),
			DstAddr:           tcpip.AddrFromSlice(netip.MustParseAddr("2001:db8::2").AsSlice()),
			TransportProtocol: tcpip.TransportProtocolNumber(protocol), HopLimit: 64, PayloadLength: uint16(len(packet) - 40),
		})
	}
	gsoType := GSOTCPv4
	if version == 6 {
		gsoType = GSOTCPv6
	}
	if protocol == ipProtoUDP {
		gsoType = GSOUDPL4
		binary.BigEndian.PutUint16(packet[iphLen+4:], uint16(transportLen+payloadLen))
	} else {
		packet[iphLen+12] = 5 << 4
		packet[iphLen+13] = tcpFlagPSH | tcpFlagACK
		binary.BigEndian.PutUint32(packet[iphLen+4:], 100)
	}
	binary.BigEndian.PutUint16(packet[iphLen+int(offset):], 0xffff)
	rng := rand.New(rand.NewPCG(uint64(size), uint64(version)<<8|uint64(protocol)))
	for i := hdrLen; i < len(packet); i++ {
		packet[i] = byte(rng.Uint32())
	}
	const spacing = ReadPacketSpacing
	slab := make([]byte, len(packet)+3*hdrLen+4*spacing+size)
	input := packet
	if overlap {
		copy(slab[spacing:], packet)
		input = slab[spacing : spacing+len(packet)]
	}
	options := GSOOptions{GSOType: gsoType, HdrLen: uint16(hdrLen), CsumStart: uint16(iphLen), CsumOffset: offset, GSOSize: uint16(size), NeedsCsum: true}
	packets := make([]ReadPacket, 4)
	n, err := GSOSplit(input, options, slab, packets, spacing)
	if err != nil {
		t.Fatal(err)
	}
	want := 2
	if tail != 0 && size > 1 {
		want++
	}
	if n != want {
		t.Fatalf("split into %d segments, want %d", n, want)
	}
	for i, descriptor := range packets[:n] {
		segment := slab[descriptor.Offset : descriptor.Offset+descriptor.Size]
		field := binary.BigEndian.Uint16(segment[iphLen+int(offset):])
		if field == 0 {
			t.Errorf("segment %d has a zero transport checksum", i)
			continue
		}
		var src, dst tcpip.Address
		if version == 4 {
			src = tcpip.AddrFromSlice(segment[12:16])
			dst = tcpip.AddrFromSlice(segment[16:20])
		} else {
			src = tcpip.AddrFromSlice(segment[8:24])
			dst = tcpip.AddrFromSlice(segment[24:40])
		}
		pseudo := header.PseudoHeaderChecksum(tcpip.TransportProtocolNumber(protocol), src, dst, uint16(len(segment)-iphLen))
		if got := gvisorChecksum.Checksum(segment[iphLen:], pseudo); got != 0xffff {
			t.Errorf("segment %d checksum verifies as %#x, want 0xffff", i, got)
		}
	}
}
