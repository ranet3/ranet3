// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"encoding/binary"
	"slices"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/packet"
)

// what the emit adds for the ECN field to a batch of 64 inner ECT(0) IPv4 packets of 1400 octets, by the outer field every datagram of the batch arrived with
// nil is a batch that arrived Not-ECT throughout, which the transport hands as no fields at all
// every arm puts the octet holding each packet's field back as it arrived with one store, so the ce arm writes every packet in every iteration
func BenchmarkEmitECN(b *testing.B) {
	const batch, size = 64, 1400
	for _, arm := range []struct {
		name  string
		outer []inboundECN
	}{
		{"nil", nil},
		{"not-ect", slices.Repeat([]inboundECN{packet.NotECT}, batch)},
		{"ect0", slices.Repeat([]inboundECN{packet.ECT0}, batch)},
		{"ce", slices.Repeat([]inboundECN{packet.CE}, batch)},
	} {
		b.Run(arm.name, func(b *testing.B) {
			c := &Client{}
			inner := make([][]byte, batch)
			for i := range inner {
				inner[i] = make([]byte, size)
				copy(inner[i], ecnPacket(4, packet.ECT0, uint16(i)))
				binary.BigEndian.PutUint16(inner[i][2:], size)
			}
			arrived := inner[0][1]
			var ecn sessionECN
			b.ReportAllocs()
			for b.Loop() {
				for i, p := range inner {
					if arm.outer != nil && !ecn.decapsulate(p, arm.outer[i]) {
						b.Fatal("a packet was dropped")
					}
					p[1] = arrived
				}
				c.settleECN(&ecn, "example/gateway:0@0")
			}
		})
	}
}
