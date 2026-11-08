// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package transport

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/packet"
)

const (
	// benchDatagramSize is the size of each ESP datagram the hub benchmark hands the receive loop
	benchDatagramSize = 1400
	// benchGROSegments is the datagrams of one GRO message of the benchmark, which spreads a vector over 3 blocks
	benchGROSegments = 43
)

// BenchmarkHubReceivesESP runs the hub's receive loop on the benchmark's goroutine over vectors of ESP datagrams from a stranger's address, one vector an op
// on the SPI of the hub's one mux, with every outer ECN field Not-ECT, ECT(0) or CE, and on an SPI no mux holds, as a flood is
// the receive function takes the batch of the vector before and releases it only once it has refilled the blocks for the next
// each vector lies in blocks of the hub's pool as a reader leaves them, espSendBatch datagrams in GRO messages of benchGROSegments, espSendBatch in a block each as a shared socket without GRO reads them, or one a call as darwin reads
// in the GRO arms of a mux's SPI the batch holds the blocks its datagrams share, so each refill finds them held and takes fresh ones from the pool, as a reader does whose last batch is still on its way to the tun
// in the arms of a datagram a block each datagram is alone in its block and the batch takes a copy of it from the pool instead, and the arm of an unknown SPI makes no batch, so each refill of these keeps every block
// a block is laid out only when the pool makes it, since the kernel's write into it is no cost of the loop's, and goes back to the pool unpoisoned, as a hub on a socket puts it back
func BenchmarkHubReceivesESP(b *testing.B) {
	for _, bench := range []struct {
		name             string
		spi              uint32
		ecn              packet.ECN
		vector, perBlock int
	}{
		{"a mux's SPI", knownSPI, packet.NotECT, espSendBatch, benchGROSegments},
		{"a mux's SPI under ECT(0)", knownSPI, packet.ECT0, espSendBatch, benchGROSegments},
		{"a mux's SPI under CE", knownSPI, packet.CE, espSendBatch, benchGROSegments},
		{"an unknown SPI", strayedSPI, packet.NotECT, espSendBatch, benchGROSegments},
		{"a mux's SPI a block each", knownSPI, packet.NotECT, espSendBatch, 1},
		{"a mux's SPI one a call", knownSPI, packet.NotECT, 1, 1},
	} {
		b.Run(bench.name, func(b *testing.B) {
			network := NewMemoryNetwork()
			p := network.hold(netip.Addr{})
			hub := startHub(&memoryBind{network: network, port: p}, nil, p.port, Runtime{})
			defer hub.Close()
			hub.pool.poison = nil
			mux, err := hub.NewMux(net.ParseIP("192.0.2.1"), 4500)
			if err != nil {
				b.Fatal(err)
			}
			if err := mux.RegisterESP(knownSPI); err != nil {
				b.Fatal(err)
			}
			datagram := binary.BigEndian.AppendUint32(nil, bench.spi)
			datagram = append(datagram, make([]byte, benchDatagramSize-len(datagram))...)
			source := netip.MustParseAddrPort("198.51.100.7:4500")
			slots := make([]*rxBlock, (bench.vector+bench.perBlock-1)/bench.perBlock)
			vectors, taken := 0, 0
			receive := func(pool *blockPool, bufs [][]byte, sizes []int, endpoints []Endpoint, records []receiveRecord, _ *refusals) (int, error) {
				var held *Received
				select {
				case held = <-mux.espCh:
					if (held.ECN() != nil) != (bench.ecn != packet.NotECT) {
						b.Fatalf("the batch under %v holds %d outer ECN fields", bench.ecn, len(held.ECN()))
					}
					if packets := held.Packets(); len(packets) != bench.vector {
						b.Fatalf("the session took %d datagrams, want the vector of %d", len(packets), bench.vector)
					}
					taken++
				default:
				}
				if vectors == b.N {
					if held != nil {
						held.Release()
					}
					return 0, net.ErrClosed
				}
				vectors++
				for k := range slots {
					// a block the pool hands again still holds the datagrams laid in it
					if pool.refill(&slots[k]) && binary.BigEndian.Uint32(slots[k].data) != bench.spi {
						for offset := 0; offset+len(datagram) <= len(slots[k].data); offset += len(datagram) {
							copy(slots[k].data[offset:], datagram)
						}
					}
				}
				if held != nil {
					held.Release()
				}
				for i := range bench.vector {
					block, offset := slots[i/bench.perBlock], i%bench.perBlock*len(datagram)
					bufs[i], sizes[i], endpoints[i] = block.data[offset:offset+len(datagram)], len(datagram), nil
					records[i] = receiveRecord{source: source, ecn: bench.ecn, block: block}
				}
				return bench.vector, nil
			}
			b.SetBytes(int64(bench.vector * benchDatagramSize))
			b.ReportAllocs()
			b.ResetTimer()
			hub.receiveLoop(receive, func(error) {})
			if bench.spi == knownSPI && taken != vectors {
				b.Fatalf("the session took %d of %d vectors", taken, vectors)
			}
		})
	}
}
