// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"fmt"
	"testing"
)

// BenchmarkWriteHost writes a delivery of one frame and one of 32 TCP flows of 4 packets each to a tun of 1, 4 and 16 lanes that discard every write
func BenchmarkWriteHost(b *testing.B) {
	const flows, packetsPerFlow = 32, 4
	packets := make([][]byte, 0, flows*packetsPerFlow)
	for sequence := range packetsPerFlow {
		for flow := range flows {
			packets = append(packets, ipv6TCPPacket(uint16(40000+flow), 5201, byte(sequence)))
		}
	}
	for _, lanes := range []int{1, 4, 16} {
		b.Run(fmt.Sprintf("lanes=%d", lanes), func(b *testing.B) {
			m := discardLanes(b, lanes)
			for _, delivery := range [][][]byte{framed(packets[0]), framed(packets...)} {
				b.Run(fmt.Sprintf("frames=%d", len(delivery)), func(b *testing.B) {
					b.ReportAllocs()
					for b.Loop() {
						m.WriteHost(delivery, nil)
					}
				})
			}
		})
	}
}
