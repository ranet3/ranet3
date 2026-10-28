// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package transport

import (
	"encoding/binary"
	"errors"
	"math"
	"slices"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/packet"
)

const (
	// hubAllocReads is how many more reads the allocation test's longer run takes than its shorter one
	hubAllocReads = 64
	// hubAllocDatagrams is how many datagrams each read of the allocation test holds
	hubAllocDatagrams = 16
)

// errScriptDone ends a scripted receive loop once its reads are handed out
var errScriptDone = errors.New("the scripted reads are done")

// scriptedDatagram is one ESP datagram of a scripted read, for the mux of that index, with its outer ECN field
type scriptedDatagram struct {
	mux int
	ecn packet.ECN
}

// ecnHub is a hub whose tables hold n muxes, the ESP SPI of each its index plus one
func ecnHub(n int) (*Hub, []*Mux) {
	h := &Hub{muxes: make(map[*Mux]struct{}), done: make(chan struct{}), started: time.Now()}
	esp := make(map[uint32]*Mux)
	muxes := make([]*Mux, n)
	for i := range muxes {
		muxes[i] = &Mux{hub: h, espCh: make(chan espDatagramBatch, espChanSize), done: make(chan struct{})}
		esp[uint32(i+1)] = muxes[i]
	}
	h.tables.Store(&spiTables{ike: make(map[uint64]*Mux), esp: esp})
	return h, muxes
}

// scriptedReads answers a receiver that hands out one read of reads per call and then fails with errScriptDone, each time it is called
// each datagram is eight octets, the SPI of its mux and then its number among all the script's datagrams
func scriptedReads(reads [][]scriptedDatagram) func() receiveFunc {
	var storage [][][]byte
	number := uint32(0)
	for _, read := range reads {
		var datagrams [][]byte
		for _, d := range read {
			datagrams = append(datagrams, binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, uint32(d.mux+1)), number))
			number++
		}
		storage = append(storage, datagrams)
	}
	return func() receiveFunc {
		next := 0
		return func(bufs [][]byte, sizes []int, endpoints []Endpoint, records []receiveRecord) (int, int, error) {
			if next == len(reads) {
				return 0, 0, errScriptDone
			}
			for i, d := range reads[next] {
				datagram := storage[next][i]
				bufs[i], sizes[i], endpoints[i], records[i] = datagram, len(datagram), nil, receiveRecord{ecn: d.ecn}
			}
			next++
			return len(reads[next-1]), 0, nil
		}
	}
}

// one read holds the ESP datagrams of two muxes interleaved, and each mux's batch holds its packets in order with the outer ECN field of each
// a batch whose packets all arrived Not-ECT holds no fields, and one marked datagram among Not-ECT ones marks its batch
func TestHubCarriesEachPacketsOuterECN(t *testing.T) {
	reads := [][]scriptedDatagram{
		{{0, packet.NotECT}, {1, packet.NotECT}, {0, packet.CE}, {1, packet.NotECT}, {0, packet.ECT0}, {0, packet.NotECT}, {1, packet.NotECT}},
		{{1, packet.NotECT}, {1, packet.CE}, {1, packet.NotECT}, {0, packet.ECT1}},
	}
	h, muxes := ecnHub(2)
	var failed error
	h.receiveLoop(scriptedReads(reads)(), func(err error) { failed = err })
	if !errors.Is(failed, errScriptDone) {
		t.Fatalf("the receive loop ended with %v", failed)
	}
	number := uint32(0)
	for r, read := range reads {
		want := make([][]uint32, len(muxes))
		fields := make([][]packet.ECN, len(muxes))
		for _, d := range read {
			want[d.mux] = append(want[d.mux], number)
			fields[d.mux] = append(fields[d.mux], d.ecn)
			number++
		}
		for i, m := range muxes {
			if !slices.ContainsFunc(fields[i], func(e packet.ECN) bool { return e != packet.NotECT }) {
				fields[i] = nil
			}
			var batch espDatagramBatch
			select {
			case batch = <-m.espCh:
			default:
				t.Fatalf("read %d: mux %d was handed no batch", r, i)
			}
			var got []uint32
			for _, p := range batch.packets {
				got = append(got, binary.BigEndian.Uint32(p[4:]))
			}
			if !slices.Equal(got, want[i]) {
				t.Errorf("read %d: mux %d was handed the datagrams %v, want %v", r, i, got, want[i])
			}
			if (batch.ecn == nil) != (fields[i] == nil) || !slices.Equal(batch.ecn, fields[i]) {
				t.Errorf("read %d: mux %d was handed the ECN fields %v, want %v", r, i, batch.ecn, fields[i])
			}
		}
	}
}

// demultiplexing a read to one peer allocates that peer's packet slices and one block for their bytes, and nothing per datagram
// a batch whose datagrams carry an outer ECN field keeps the fields in that block
func TestHubReadAllocatesOnlyEachPeersBatch(t *testing.T) {
	for _, field := range []packet.ECN{packet.NotECT, packet.CE} {
		read := make([]scriptedDatagram, hubAllocDatagrams)
		for i := range read {
			read[i] = scriptedDatagram{mux: 0, ecn: field}
		}
		allocs := func(n int) float64 {
			reads := make([][]scriptedDatagram, n)
			for i := range reads {
				reads[i] = read
			}
			receiver := scriptedReads(reads)
			return testing.AllocsPerRun(1, func() {
				h, _ := ecnHub(1)
				h.receiveLoop(receiver(), func(error) {})
			})
		}
		// under -race a run can count a stray allocation outside the loop, which moves the per-read count by 1/hubAllocReads
		if perRead := (allocs(2*hubAllocReads) - allocs(hubAllocReads)) / hubAllocReads; math.Round(perRead) != 2 {
			t.Errorf("a read of %d datagrams with the ECN field %d for one peer allocated %v times, want 2", hubAllocDatagrams, field, perRead)
		}
	}
}
