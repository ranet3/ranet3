// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"fmt"
	"log/slog"
	"net/netip"
	"runtime"
	"sync/atomic"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/logtest"
)

// BenchmarkApplySegmentsRefused takes batches of inboundWriteBatchSize packets steered to an egress segment that refuses each of them
// by an outer source outside its allow list, which the segment table refuses, and by an inner source the mesh routes no reply to, which the egress check refuses
// on one goroutine and on as many as RunParallel starts, each with batches of its own, as sessions deliver
// every refusal counts and claims the interval's report on a started mesh, and the one line it writes goes to a log that keeps nothing
func BenchmarkApplySegmentsRefused(b *testing.B) {
	logtest.SetDefault(b, slog.New(slog.DiscardHandler))
	for _, c := range []struct {
		name  string
		inner []byte
		outer netip.Addr
	}{
		{"outer source outside the allow list", plainV6(segAddr("3fff:a::1"), segAddr("2001:db8:4860::8888"), "refused"), segAddr("3fff:bad::1")},
		{"inner source with no reply route", udpPacket(segAddr("10.9.9.9"), segAddr("203.0.113.1"), 100, false), headend},
	} {
		packet := steered(b, c.inner, c.outer, egressExit)
		for _, parallel := range []bool{false, true} {
			b.Run(fmt.Sprintf("%s parallel=%t", c.name, parallel), func(b *testing.B) {
				m := ownEgressOwned(&Mesh{Name: "bench0", Routes: NewRouteTable(), closed: make(chan struct{})})
				m.setDevice(&discardDevice{})
				m.SetExit(tunExit{m.WriteHost})
				m.SetSegments(egressTable(b))
				m.SetEgressReady(true, true)
				m.startSegmentReports()
				b.Cleanup(m.Close)
				batch := func() [][]byte {
					packets := make([][]byte, inboundWriteBatchSize)
					for i := range packets {
						packets[i] = packet
					}
					return framed(packets...)
				}
				b.ReportAllocs()
				if parallel {
					batches := make([][][]byte, runtime.GOMAXPROCS(0))
					for i := range batches {
						batches[i] = batch()
					}
					var started atomic.Int64
					b.ResetTimer()
					b.RunParallel(func(pb *testing.PB) {
						frames := batches[started.Add(1)-1]
						for pb.Next() {
							m.applySegments(frames, DefaultMTU, nil, nil)
						}
					})
				} else {
					frames := batch()
					for b.Loop() {
						m.applySegments(frames, DefaultMTU, nil, nil)
					}
				}
				b.StopTimer()
				if got, want := m.SegmentCounters(), uint64(b.N*inboundWriteBatchSize); got.Refused != want || got.Dropped != want || got.Egressed != 0 {
					b.Fatalf("the segments counted %+v for %d packets, want each refused and dropped", got, want)
				}
				b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*inboundWriteBatchSize), "ns/packet")
			})
		}
	}
}
