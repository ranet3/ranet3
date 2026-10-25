// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"fmt"
	"net/netip"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/packet"
)

// decideBatch is the number of packets one delivery of a session hands the decision
const decideBatch = 64

// resolveTable is a table of count routes to peer, IPv4 host routes inside the overlay or IPv6 /64s inside it
// with an address inside each and the length each matches at
func resolveTable(peer *Peer, family, count int) (*RouteTable, []netip.Addr, int) {
	rt := NewRouteTable()
	addresses := make([]netip.Addr, count)
	bits := 64
	if family == 4 {
		bits = 32
	}
	for i := range addresses {
		if family == 4 {
			addresses[i] = netip.AddrFrom4([4]byte{192, 0, 2, byte(i)})
		} else {
			addresses[i] = netip.AddrFrom16([16]byte{0x3f, 0xff, 0, 0, byte(i >> 8), byte(i), 15: 1})
		}
		rt.Set(netip.Prefix{}, netip.PrefixFrom(addresses[i], bits).Masked(), peer)
	}
	return rt, addresses, bits
}

func BenchmarkResolve(b *testing.B) {
	peer := benchPeer(b)
	for _, c := range []struct{ family, count int }{{4, 16}, {4, 256}, {6, 16}, {6, 1024}, {6, 16384}} {
		b.Run(fmt.Sprintf("IPv%d routes=%d", c.family, c.count), func(b *testing.B) {
			rt, addresses, bits := resolveTable(peer, c.family, c.count)
			source := transitSender[c.family]
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				i := 0
				for pb.Next() {
					if got, verdict, match := rt.Resolve(source, addresses[i]); got != peer || verdict != RoutePeer || match.Bits != bits {
						b.Errorf("Resolve(%s, %s) = %v %d /%d, want the peer at /%d", source, addresses[i], got, verdict, match.Bits, bits)
						return
					}
					i = (i + 1) % len(addresses)
				}
			})
		})
	}
}

// benchTransitMesh is a mesh deciding with cap.transit on, far's addresses routed to a peer that seals and sends nothing
// own's held as this node's, and every sender's routed back to that peer
func benchTransitMesh(b *testing.B) *Mesh {
	b.Helper()
	m, _ := startTransitMesh(nil)
	return benchRouted(b, m)
}

// the tun keeps nothing, so it takes every batch an exit writes for as long as a benchmark runs, where startTransitMesh's recording tun holds 64
func benchEgressMesh(b *testing.B) *Mesh {
	b.Helper()
	m := &Mesh{Name: "bench0", Routes: NewRouteTable(), closed: make(chan struct{})}
	m.setDevice(&discardDevice{})
	m.SetTransit(true)
	m.SetOverlay(transitOverlay)
	return benchRouted(b, m)
}

func benchRouted(b *testing.B, m *Mesh) *Mesh {
	b.Helper()
	b.Cleanup(m.Close)
	peer := benchPeer(b)
	for _, family := range []int{4, 6} {
		m.Routes.Set(netip.Prefix{}, hostPrefix(transitFar[family]), peer)
		m.Routes.Set(netip.Prefix{}, hostPrefix(transitOwn[family]), Local)
	}
	m.Routes.Set(netip.Prefix{}, segPrefix("192.0.2.128/25"), peer)
	m.Routes.Set(netip.Prefix{}, segPrefix("3fff:0:0:1::/64"), peer)
	return m
}

// headerLen is the length of the header of raw, one IP packet, which the decision changes in a packet it forwards
func headerLen(raw []byte) int {
	if raw[0]>>4 == 6 {
		return 40
	}
	return int(raw[0]&0x0f) * 4
}

// benchmarkDecide is the decision over batches of decideBatch packets drawn in turn from packets, their headers as packets has them
// each goroutine RunParallel starts stands for the emitter of one session, and takes batches of its own built before the timer starts
func benchmarkDecide(b *testing.B, m *Mesh, packets [][]byte) {
	sets := make([][][][]byte, runtime.GOMAXPROCS(0))
	for k := range sets {
		batches := make([][][]byte, max(1, len(packets)/decideBatch))
		for i := range batches {
			batch := make([][]byte, decideBatch)
			for j := range batch {
				batch[j] = packets[(i*decideBatch+j)%len(packets)]
			}
			batches[i] = framed(batch...)
		}
		sets[k] = batches
	}
	var started atomic.Int64
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		batches := sets[started.Add(1)-1]
		for i := 0; pb.Next(); i++ {
			frames := batches[i%len(batches)]
			for j, frame := range frames {
				template := packets[(i%len(batches)*decideBatch+j)%len(packets)]
				copy(frame[TUNHeadroom:], template[:headerLen(template)])
			}
			m.decide(frames, nil, nil)
		}
	})
	b.StopTimer()
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*decideBatch), "ns/packet")
}

func BenchmarkDecide(b *testing.B) {
	recordRoute := []byte{7, 7, 4, 0, 0, 0, 0}
	for _, c := range []struct {
		name   string
		packet []byte
	}{
		{"forwarded IPv4", udpPacket(transitSender[4], transitFar[4], 100, false)},
		{"forwarded IPv6", udpPacket(transitSender[6], transitFar[6], 100, false)},
		{"forwarded IPv4 with Record Route", withOptions(udpPacket(transitSender[4], transitFar[4], 100, false), recordRoute)},
		{"delivered IPv4", udpPacket(transitSender[4], transitOwn[4], 100, false)},
		{"delivered IPv6", udpPacket(transitSender[6], transitOwn[6], 100, false)},
	} {
		b.Run(c.name, func(b *testing.B) {
			benchmarkDecide(b, benchTransitMesh(b), [][]byte{c.packet})
		})
	}
}

// BenchmarkDecideWithheld takes every packet to an address no route holds, from one sender and from many, each routed back through the mesh
// with each sender held in the table, its bucket spent, and the node's cap full
// one IPv4 sender, 64 IPv4 senders and one IPv6 sender earn back 1, 64 and 10 answers a second, under the cap's rate, so the limit withholds nearly every answer by its source
// 4096 IPv6 senders earn back 40960 a second, past the cap's 10000, so once the cap's burst is spent nearly every answer is withheld by the cap before its sender's bucket is read
func BenchmarkDecideWithheld(b *testing.B) {
	for _, c := range withheldArms {
		b.Run(fmt.Sprintf("IPv%d sources=%d", c.family, c.sources), func(b *testing.B) {
			m := benchTransitMesh(b)
			sources := withheldSources(b, m, c.family, c.sources)
			packets := make([][]byte, len(sources))
			for i, source := range sources {
				packets[i] = udpPacket(source, transitNowhere[c.family], 100, false)
			}
			benchmarkDecide(b, m, packets)
		})
	}
}

// BenchmarkDecideEgressed takes every packet out through an entry of this node's counting as a default that cap.egress advertises, past the egress check, to the exit
// which writes each batch to a tun of one lane that keeps nothing, as the kernel exit writes them
// from one source to one destination, whose answer a batch keeps, and to as many destinations as a batch holds packets, past what it keeps
func BenchmarkDecideEgressed(b *testing.B) {
	for _, c := range []struct{ family, destinations int }{{4, 1}, {4, decideBatch}, {6, 1}, {6, decideBatch}} {
		b.Run(fmt.Sprintf("IPv%d destinations=%d", c.family, c.destinations), func(b *testing.B) {
			m := benchEgressMesh(b)
			m.SetExit(tunExit{m.WriteHost})
			m.Routes.Set(netip.Prefix{}, exitShapes[0].prefixes[c.family][0], Local)
			m.SetEgressPrefixes(exitShapes[0].prefixes[c.family])
			m.SetAdvertisedReady(true, true)
			source := map[int]netip.Addr{4: segAddr("192.0.2.129"), 6: segAddr("3fff:0:0:1::1")}[c.family]
			packets := make([][]byte, c.destinations)
			for i := range packets {
				destination := netip.AddrFrom4([4]byte{203, 0, 113, byte(i)})
				if c.family == 6 {
					destination = netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 15: byte(i)})
				}
				packets[i] = udpPacket(source, destination, 100, false)
			}
			benchmarkDecide(b, m, packets)
		})
	}
}

// BenchmarkApplySegmentsEgress takes batches of inboundWriteBatchSize packets through an egress segment to an exit writing to the tun, past its reply and mesh checks
// from one source to one destination, whose answers a batch keeps, and to 64 destinations, past the pairs it keeps
func BenchmarkApplySegmentsEgress(b *testing.B) {
	for _, c := range []struct{ family, destinations int }{{4, 1}, {4, 64}, {6, 1}, {6, 64}} {
		b.Run(fmt.Sprintf("IPv%d destinations=%d", c.family, c.destinations), func(b *testing.B) {
			m := ownEgressOwned(&Mesh{Name: "test0", Routes: NewRouteTable(), closed: make(chan struct{})})
			m.setDevice(&discardDevice{})
			m.SetExit(tunExit{m.WriteHost})
			m.SetSegments(egressTable(b))
			m.SetEgressReady(true, true)
			routeLeaf(b, m, tooBigSource[c.family])
			b.Cleanup(m.Close)
			packets := make([][]byte, inboundWriteBatchSize)
			for i := range packets {
				last := byte(i%c.destinations + 1)
				destination := netip.AddrFrom4([4]byte{203, 0, 113, last})
				if c.family == 6 {
					destination = netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0x48, 0x60, 15: last})
				}
				packets[i] = steered(b, udpPacket(tooBigSource[c.family], destination, 100, false), headend, egressExit)
			}
			frames := framed(packets...)
			m.applySegments(frames, DefaultMTU)
			if got := m.SegmentCounters().Egressed; got != inboundWriteBatchSize {
				b.Fatalf("%d of the batch's %d packets took the egress segment, so this measures another path", got, inboundWriteBatchSize)
			}
			b.ReportAllocs()
			for b.Loop() {
				m.applySegments(frames, DefaultMTU)
			}
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*inboundWriteBatchSize), "ns/packet")
		})
	}
}

// BenchmarkSegmentsEgressed takes a batch of decideBatch packets steered to an egress segment through the segments' actions to the exit
// which writes them to a tun of one lane that keeps nothing, as the kernel exit writes them
func BenchmarkSegmentsEgressed(b *testing.B) {
	for _, family := range []int{4, 6} {
		b.Run(fmt.Sprintf("IPv%d", family), func(b *testing.B) {
			m := &Mesh{Name: "bench0", Routes: NewRouteTable(), closed: make(chan struct{})}
			m.setDevice(&discardDevice{})
			m.SetExit(tunExit{m.WriteHost})
			m.SetSegments(egressTable(b))
			m.SetEgressReady(true, true)
			routeLeaf(b, m, tooBigSource[family])
			b.Cleanup(m.Close)
			inner := udpPacket(tooBigSource[family], transitNowhere[family], 100, false)
			batch := make([][]byte, decideBatch)
			for i := range batch {
				batch[i] = steered(b, inner, headend, egressExit)
			}
			frames := framed(batch...)
			b.ReportAllocs()
			for b.Loop() {
				m.applySegments(frames, DefaultMTU)
			}
			if got, want := m.SegmentCounters().Egressed, uint64(b.N*decideBatch); got != want {
				b.Fatalf("%d packets took the egress segment, want each of the %d handed it", got, want)
			}
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*decideBatch), "ns/packet")
		})
	}
}

// BenchmarkOptionStage is the stage the decision runs on a forwarded IPv4 header for its options
// against the call that reads the clock and the router-id for every header
func BenchmarkOptionStage(b *testing.B) {
	m := benchTransitMesh(b)
	plain := udpPacket(transitSender[4], transitFar[4], 100, false)
	for _, c := range []struct {
		name  string
		raw   []byte
		eager bool
	}{
		{"IHL 5 with the clock read for every header", plain, true},
		{"IHL 5", plain, false},
		{"Record Route", withOptions(plain, []byte{7, 7, 4, 0, 0, 0, 0}), false},
		{"Timestamp with addresses", withOptions(plain, []byte{68, 12, 5, 1, 0, 0, 0, 0, 0, 0, 0, 0}), false},
	} {
		b.Run(c.name, func(b *testing.B) {
			raw := make([]byte, len(c.raw))
			b.ReportAllocs()
			for b.Loop() {
				copy(raw, c.raw[:headerLen(c.raw)])
				if c.eager {
					address, _ := m.errorSource(false)
					packet.ForwardOptions(raw, address, m.ownAddress, time.Now())
				} else if hasOptions(raw) {
					m.forwardOptions(raw)
				}
			}
		})
	}
}
