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

type splitChecksumCase struct {
	version, size, segments, tail int
	ipv4Options, tcpOptions       int
	protocol                      uint8
	overlap                       bool
	spacing                       int
	seed                          uint64
}

func TestEverySplitSegmentCarriesAValidChecksum(t *testing.T) {
	for _, version := range []int{4, 6} {
		for _, protocol := range []uint8{ipProtoTCP, ipProtoUDP} {
			for _, size := range []int{1, 128, 512, 1000, 1400} {
				for _, tail := range []int{0, 1} {
					for _, overlap := range []bool{false, true} {
						last := 0
						if tail != 0 {
							last = size - 1
						}
						c := splitChecksumCase{version: version, protocol: protocol, size: size, segments: 2, tail: last, overlap: overlap, spacing: ReadPacketSpacing}
						t.Run(fmt.Sprintf("ipv%d/proto%d/size%d/tail%d/overlap%t", version, protocol, size, tail, overlap), func(t *testing.T) {
							checkSplitChecksum(t, c)
						})
					}
				}
			}
			generated := rand.New(rand.NewPCG(uint64(version), uint64(protocol)))
			for i := range 128 {
				c := splitChecksumCase{
					version: version, protocol: protocol,
					size: 1 + generated.IntN(1400), segments: 2 + generated.IntN(3),
					overlap: generated.IntN(2) == 0, spacing: generated.IntN(4) * ReadPacketSpacing,
					seed: generated.Uint64(),
				}
				c.tail = generated.IntN(c.size)
				if version == 4 {
					c.ipv4Options = 4 * generated.IntN(11)
				}
				if protocol == ipProtoTCP {
					c.tcpOptions = 4 * generated.IntN(11)
				}
				t.Run(fmt.Sprintf("generated/ipv%d/proto%d/case%d", version, protocol, i), func(t *testing.T) {
					checkSplitChecksum(t, c)
				})
			}
		}
	}
}

func checkSplitChecksum(t *testing.T, c splitChecksumCase) {
	t.Helper()
	version, protocol, size, tail, overlap := c.version, c.protocol, c.size, c.tail, c.overlap
	iphLen, transportLen, offset := 20+c.ipv4Options, 20+c.tcpOptions, uint16(16)
	if version == 6 {
		iphLen = 40
	}
	if protocol == ipProtoUDP {
		transportLen, offset = 8, 6
	}
	hdrLen := iphLen + transportLen
	payloadLen := c.segments*size + tail
	packet := make([]byte, hdrLen+payloadLen)
	if version == 4 {
		header.IPv4(packet).Encode(&header.IPv4Fields{
			SrcAddr:  tcpip.AddrFromSlice(netip.MustParseAddr("192.0.2.1").AsSlice()),
			DstAddr:  tcpip.AddrFromSlice(netip.MustParseAddr("192.0.2.2").AsSlice()),
			Protocol: protocol, TTL: 64, TotalLength: uint16(len(packet)),
		})
		packet[0] = 0x40 | byte(iphLen/4)
		for i := 20; i < iphLen; i++ {
			packet[i] = 1
		}
		packet[10], packet[11] = 0, 0
		binary.BigEndian.PutUint16(packet[10:], ^gvisorChecksum.Checksum(packet[:iphLen], 0))
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
		packet[iphLen+12] = byte(transportLen/4) << 4
		packet[iphLen+13] = tcpFlagPSH | tcpFlagACK
		binary.BigEndian.PutUint32(packet[iphLen+4:], 100)
		for i := iphLen + 20; i < hdrLen; i++ {
			packet[i] = 1
		}
	}
	// NEEDS_CSUM carries the pseudo-header sum for the entire unsplit transport packet.
	addrStart, addrLen := 12, 4
	if version == 6 {
		addrStart, addrLen = 8, 16
	}
	src := tcpip.AddrFromSlice(packet[addrStart : addrStart+addrLen])
	dst := tcpip.AddrFromSlice(packet[addrStart+addrLen : addrStart+2*addrLen])
	partial := header.PseudoHeaderChecksum(tcpip.TransportProtocolNumber(protocol), src, dst, uint16(len(packet)-iphLen))
	binary.BigEndian.PutUint16(packet[iphLen+int(offset):], partial)
	rng := rand.New(rand.NewPCG(uint64(size)^c.seed, uint64(version)<<8|uint64(protocol)))
	for i := hdrLen; i < len(packet); i++ {
		packet[i] = byte(rng.Uint32())
	}
	spacing := c.spacing
	slab := make([]byte, (c.segments+1)*(hdrLen+size+spacing)+spacing)
	input := packet
	if overlap {
		copy(slab[spacing:], packet)
		input = slab[spacing : spacing+len(packet)]
	}
	options := GSOOptions{GSOType: gsoType, HdrLen: uint16(hdrLen), CsumStart: uint16(iphLen), CsumOffset: offset, GSOSize: uint16(size), NeedsCsum: true}
	packets := make([]ReadPacket, c.segments+1)
	n, err := GSOSplit(input, options, slab, packets, spacing)
	if err != nil {
		t.Fatal(err)
	}
	want := c.segments
	if tail != 0 {
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
