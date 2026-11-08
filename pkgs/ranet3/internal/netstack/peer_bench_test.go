// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"
)

var oneByte = []byte{0}

func benchSealer(raw [][]byte, _ []byte, storage [][]byte) ([][]byte, error) {
	storage = storage[:0]
	for range raw {
		// One byte stands in for the ciphertext. The point is the pipeline,
		// and a real seal would dominate the measurement.
		storage = append(storage, oneByte)
	}
	return storage, nil
}

func benchPeer(b *testing.B) *Peer {
	b.Helper()
	peer := NewPeer("bench",
		func(int) (BatchSealer, error) { return benchSealer, nil },
		func([][]byte) error { return nil }, nil)
	b.Cleanup(peer.Close)
	return peer
}

// The send pipeline's own cost on the path routed traffic takes, with the
// crypto and the syscall replaced by nothing. What remains is the price of
// ordered transmission: the packet budget, the place and sequence range taken
// under one lock, the allocations ReportAllocs counts, and the handoff to the
// ordered sender.
//
// finish does not wait for the send, which BenchmarkPeerSenderRoundTrip waits for.
func benchmarkPeerEnqueue(b *testing.B, workers, batch int) {
	peer := benchPeer(b)
	payload := make([]byte, 1400)
	// Deliberately no SetBytes. append stores the slice header and the stand-in
	// sealer never reads it, so no payload byte is touched. Reporting MB/s over
	// them prints a figure four orders of magnitude above what the pipeline
	// really moves. ns/packet below is the honest axis.
	b.ReportAllocs()
	b.ResetTimer()

	var group sync.WaitGroup
	each := max(b.N/workers, 1)
	for range workers {
		group.Go(func() {
			for range each {
				pb := peer.reserveBatch(batch, batch*len(payload))
				for range batch {
					pb.append(payload, 4)
				}
				if err := pb.finish(); err != nil {
					b.Error(err)
					return
				}
			}
		})
	}
	group.Wait()
	b.StopTimer()
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(each*workers*batch), "ns/packet")
}

// One worker is the floor: no contention, just the pipeline's fixed cost.
func BenchmarkPeerEnqueueSerialSinglePacket(b *testing.B) { benchmarkPeerEnqueue(b, 1, 1) }
func BenchmarkPeerEnqueueSerialBatched(b *testing.B)      { benchmarkPeerEnqueue(b, 1, 128) }

// One packet per batch is the worst case for a per-batch cost, and a TCP ACK
// stream produces it: each arrives as its own TUN read.
func BenchmarkPeerEnqueueParallelSinglePacket(b *testing.B) {
	benchmarkPeerEnqueue(b, runtime.GOMAXPROCS(0), 1)
}

// A full TUN read batch, where the fixed cost is amortized over 128 packets.
func BenchmarkPeerEnqueueParallelBatched(b *testing.B) {
	benchmarkPeerEnqueue(b, runtime.GOMAXPROCS(0), 128)
}

// dispatchReadPackets is the packets of each read the dispatch benchmark hands the workers, split evenly over its peers
// dispatchStamps is how many reservation times each peer's stand-in keeps at once, twice the batches its budget holds
// so a stamp is written again only after the batch that carried it was transmitted
const (
	dispatchReadPackets = 128
	dispatchStamps      = 2 * peerDataBudget / leastPacketBytes
)

// readers dispatching reads to the shared workers, each read 128 packets over 1 peer or 64, with the crypto and the syscall replaced by nothing
// ns/read is the readers' time for one read, which stops once the last reader has dispatched its last read
// dropped/read is the packets of a read the peers dropped, at their budgets or for the delay through their queues, and the row drops nothing where it is 0
// queued-batches is the batches still held between their reservation and their transmit when the time stopped
// transmit-p99-ns is the 99th percentile of a batch's wait from its reservation to the transmit that carried it, over every batch transmitted
// all measured through the stand-in SA and transport, so the benchmark runs on a tree with or without the sender's histograms
func BenchmarkDispatchToPeers(b *testing.B) {
	for _, readers := range []int{1, 9, runtime.GOMAXPROCS(0)} {
		for _, peers := range []int{1, 64} {
			b.Run(fmt.Sprintf("readers=%d/peers=%d", readers, peers), func(b *testing.B) { benchmarkDispatch(b, readers, peers) })
		}
	}
}

// dispatchStand is one peer's stand-in SA and transport for the dispatch benchmark
// each batch carries its reservation time in its stand-in packets, a stamp of stamps, to the transport
type dispatchStand struct {
	start  time.Time
	stamps [dispatchStamps][8]byte
	// next is the next stamp, under the peer's reserveMu as reserveFn is
	next int
	// waits is written by the transport, which only the peer's sender calls
	waits []int64
}

func (s *dispatchStand) reserve(int) (BatchSealer, error) {
	stamp := s.stamps[s.next%len(s.stamps)][:]
	s.next++
	binary.BigEndian.PutUint64(stamp, uint64(time.Since(s.start)))
	return func(raw [][]byte, _ []byte, storage [][]byte) ([][]byte, error) {
		storage = storage[:0]
		for range raw {
			storage = append(storage, stamp)
		}
		return storage, nil
	}, nil
}

// transmit notes each batch's wait once, its packets sharing one stamp
func (s *dispatchStand) transmit(packets [][]byte) error {
	now := time.Since(s.start)
	var last *byte
	for _, packet := range packets {
		if &packet[0] != last {
			last = &packet[0]
			s.waits = append(s.waits, int64(now)-int64(binary.BigEndian.Uint64(packet)))
		}
	}
	return nil
}

func benchmarkDispatch(b *testing.B, readers, count int) {
	start := time.Now()
	stands := make([]*dispatchStand, count)
	peers := make([]*Peer, count)
	for i := range peers {
		stands[i] = &dispatchStand{start: start, waits: make([]int64, 0, dispatchStamps)}
		peers[i] = NewPeer(fmt.Sprintf("bench%d", i), stands[i].reserve, stands[i].transmit, nil)
		b.Cleanup(peers[i].Close)
	}
	workers := runtime.GOMAXPROCS(0)
	m := &Mesh{closed: make(chan struct{})}
	m.outboundFree = make(chan *outboundBatch, outboundJobsPerWorker*workers+readers)
	m.outboundJobs = make(chan *outboundBatch, cap(m.outboundFree))
	for range cap(m.outboundFree) {
		m.outboundFree <- newOutboundBatch(dispatchReadPackets)
	}
	m.outboundWorkerWG.Add(workers)
	for range workers {
		go m.outboundWorker()
	}
	payload := make([]byte, 1400)
	b.ReportAllocs()
	b.ResetTimer()
	var group sync.WaitGroup
	each := max(b.N/readers, 1)
	for range readers {
		group.Go(func() {
			for range each {
				read := <-m.outboundFree
				for i := range dispatchReadPackets {
					peer := peers[i%count]
					read.packets[i], read.peers[i], read.headers[i] = payload, peer, 4
					share, ok := read.shares[peer]
					if !ok {
						read.peerOrder = append(read.peerOrder, peer)
					}
					share.count++
					share.bytes += len(payload)
					read.shares[peer] = share
				}
				read.n = dispatchReadPackets
				m.dispatchOutbound(read)
			}
		})
	}
	group.Wait()
	b.StopTimer()
	var held int64
	for _, p := range peers {
		held += p.dataBudget.used.Load()
	}
	// every batch reaches its transmit before the drops and the waits are read
	for _, p := range peers {
		waitForBudget(b, p)
	}
	close(m.closed)
	close(m.outboundJobs)
	m.outboundWorkerWG.Wait()
	var dropped uint64
	var waits []int64
	for i, p := range peers {
		dropped += p.Dropped()
		waits = append(waits, stands[i].waits...)
	}
	reads := each * readers
	share := dispatchReadPackets / count
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(reads), "ns/read")
	b.ReportMetric(float64(dropped)/float64(reads), "dropped/read")
	b.ReportMetric(float64(held)/float64(dataCharge(share, share*len(payload))), "queued-batches")
	if len(waits) != 0 {
		slices.Sort(waits)
		b.ReportMetric(float64(waits[len(waits)*99/100]), "transmit-p99-ns")
	}
}

// One packet, with the caller waiting for the ordered sender to hand it to the
// transport, which is the round trip of one batch through the sender.
func BenchmarkPeerSenderRoundTrip(b *testing.B) {
	carried := make(chan struct{}, 1)
	peer := NewPeer("bench",
		func(int) (BatchSealer, error) { return benchSealer, nil },
		func([][]byte) error { carried <- struct{}{}; return nil }, nil)
	b.Cleanup(peer.Close)
	payload := make([]byte, 1400)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		pb := peer.reserveBatch(1, len(payload))
		pb.append(payload, 4)
		if err := pb.finish(); err != nil {
			b.Fatal(err)
		}
		<-carried
	}
}
