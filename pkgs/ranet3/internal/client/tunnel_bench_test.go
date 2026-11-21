// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"fmt"
	"testing"

	"ranet3.com/pkgs/ranet3/esp"
)

// BenchmarkTunnelDecryptBatch times decryptBatch on a batch of the peer's packets under one SPI, or under two in two runs as a batch across a rekey holds them, with no replacement held
func BenchmarkTunnelDecryptBatch(b *testing.B) {
	for _, shape := range []struct{ spis, size int }{{1, 1}, {1, 16}, {1, 64}, {2, 2}, {2, 16}, {2, 64}} {
		b.Run(fmt.Sprintf("spis=%d/batch=%d", shape.spis, shape.size), func(b *testing.B) {
			tun := &tunnel{replayWindow: 4096}
			sealed := make([][]byte, shape.size)
			for i := range shape.spis {
				child := tunnelChild(uint32(i + 1))
				if err := tun.install(child); err != nil {
					b.Fatal(err)
				}
				child.RemoteSPI, child.OutboundKey = child.LocalSPI, child.InboundKey
				peer, err := esp.NewOutbound(child)
				if err != nil {
					b.Fatal(err)
				}
				for at := i * shape.size / shape.spis; at < (i+1)*shape.size/shape.spis; at++ {
					plain := make([]byte, 24)
					plain[0], plain[3] = 0x45, 24
					if sealed[at], err = peer.Seal(plain, esp.NextHeaderIPv4); err != nil {
						b.Fatal(err)
					}
				}
			}
			// decryption is in place, so each iteration starts from a copy of the sealed packets
			packets := make([][]byte, shape.size)
			for i := range packets {
				packets[i] = make([]byte, len(sealed[i]))
			}
			var results []inboundDecrypted
			b.ReportAllocs()
			for b.Loop() {
				for i := range packets {
					copy(packets[i], sealed[i])
				}
				results = tun.decryptBatch(packets, results[:0])
			}
			for _, result := range results {
				if result.Err != nil {
					b.Fatal(result.Err)
				}
			}
		})
	}
}
