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

// benchDatagramSize is the size of each ESP datagram the hub benchmark hands the receive loop
const benchDatagramSize = 1400

// BenchmarkHubReceivesESP runs the hub's receive loop on the benchmark's goroutine over vectors of espSendBatch ESP datagrams from a stranger's address, one vector an op
// on the SPI of the hub's one mux, whose queue the receive function empties before each vector as the session would, with every outer ECN field Not-ECT, ECT(0) or CE, and on an SPI no mux holds, as a flood is
func BenchmarkHubReceivesESP(b *testing.B) {
	for _, bench := range []struct {
		name string
		spi  uint32
		ecn  packet.ECN
	}{
		{"a mux's SPI", knownSPI, packet.NotECT},
		{"a mux's SPI under ECT(0)", knownSPI, packet.ECT0},
		{"a mux's SPI under CE", knownSPI, packet.CE},
		{"an unknown SPI", strayedSPI, packet.NotECT},
	} {
		b.Run(bench.name, func(b *testing.B) {
			network := NewMemoryNetwork()
			p := network.hold(netip.Addr{})
			hub := startHub(&memoryBind{network: network, port: p}, nil, p.port, Underlay{}, 0, Runtime{})
			defer hub.Close()
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
			vectors, taken := 0, 0
			receive := func(bufs [][]byte, sizes []int, endpoints []Endpoint, records []receiveRecord) (int, int, error) {
				select {
				case batch := <-mux.espCh:
					if (batch.ecn != nil) != (bench.ecn != packet.NotECT) {
						b.Fatalf("the batch under %v holds %d outer ECN fields", bench.ecn, len(batch.ecn))
					}
					if packets := mux.takeESP(batch); len(packets) != espSendBatch {
						b.Fatalf("the session took %d datagrams, want the vector of %d", len(packets), espSendBatch)
					}
					taken++
				default:
				}
				if vectors == b.N {
					return 0, 0, net.ErrClosed
				}
				vectors++
				for i := range bufs {
					bufs[i], sizes[i], endpoints[i], records[i] = datagram, len(datagram), nil, receiveRecord{source: source, ecn: bench.ecn}
				}
				return len(bufs), 0, nil
			}
			b.SetBytes(espSendBatch * benchDatagramSize)
			b.ReportAllocs()
			b.ResetTimer()
			hub.receiveLoop(receive, func(error) {})
			if bench.spi == knownSPI && taken != vectors {
				b.Fatalf("the session took %d of %d vectors", taken, vectors)
			}
		})
	}
}
