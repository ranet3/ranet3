// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package transport

import (
	"encoding/binary"
	"slices"
	"sync"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/packet"
)

// laidRead is a receiver that lays the datagrams of one read into blocks it takes from the hub's pool, perBlock of them to a block, and then fails with errScriptDone
// blocks is each block it took, whose reference stays the reader's
func laidRead(datagrams [][]byte, perBlock int, blocks *[]*rxBlock) receiveFunc {
	done := false
	return func(pool *blockPool, bufs [][]byte, sizes []int, endpoints []Endpoint, records []receiveRecord, _ *refusals) (int, error) {
		if done {
			return 0, errScriptDone
		}
		done = true
		offset := 0
		for i, datagram := range datagrams {
			if i%perBlock == 0 {
				*blocks, offset = append(*blocks, pool.get()), 0
			}
			block := (*blocks)[len(*blocks)-1]
			end := offset + copy(block.data[offset:], datagram)
			bufs[i], sizes[i], endpoints[i], records[i] = block.data[offset:end], end-offset, nil, receiveRecord{block: block}
			offset = end
		}
		return len(datagrams), nil
	}
}

// espTo is an ESP datagram for the mux of ecnHub's index, its number behind the SPI
func espTo(mux int, number uint32) []byte {
	return binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, uint32(mux+1)), number)
}

// queued takes the one batch m holds
func queued(t *testing.T, m *Mux) *Received {
	t.Helper()
	select {
	case batch := <-m.espCh:
		return batch
	default:
		t.Fatal("the mux was handed no batch")
		return nil
	}
}

// each packet of a batch ends where its datagram does, though the next datagram of its block lies right behind it
// so an append to one reaches no other, which another worker may be decrypting for another session
func TestReceivedPacketsEndAtTheirDatagrams(t *testing.T) {
	h, muxes := ecnHub(2)
	var blocks []*rxBlock
	h.receiveLoop(laidRead([][]byte{espTo(0, 0), espTo(1, 1), espTo(0, 2)}, 3, &blocks), func(error) {})
	for i, m := range muxes {
		batch := queued(t, m)
		for j, packet := range batch.Packets() {
			if len(packet) != cap(packet) {
				t.Errorf("packet %d of mux %d holds %d bytes and reaches %d", j, i, len(packet), cap(packet))
			}
		}
		batch.Release()
	}
}

// a batch holds one reference to each block it has a packet in, whatever the packets of other muxes in the block, and gives each back once
func TestReceivedHoldsEachBlockOnce(t *testing.T) {
	h, muxes := ecnHub(2)
	var blocks []*rxBlock
	// mux 0 has two packets in the first block and one in the second, and mux 1 one in each
	h.receiveLoop(laidRead([][]byte{espTo(0, 0), espTo(1, 1), espTo(0, 2), espTo(0, 3), espTo(1, 4)}, 3, &blocks), func(error) {})
	if len(blocks) != 2 {
		t.Fatalf("the read took %d blocks, want 2", len(blocks))
	}
	for i, block := range blocks {
		if got := block.refs.Load(); got != 3 {
			t.Errorf("block %d holds %d references, want the reader's and one of each mux's batch", i, got)
		}
	}
	for i, m := range muxes {
		batch := queued(t, m)
		if got, want := batch.charge, 2*readBufferSize; got != want {
			t.Errorf("mux %d's batch is charged %d, want both its blocks whole, %d", i, got, want)
		}
		batch.Release()
		if got := m.espHeld.Load(); got != 0 {
			t.Errorf("mux %d holds %d bytes once its batch is released", i, got)
		}
	}
	for i, block := range blocks {
		if got := block.refs.Load(); got != 1 {
			t.Errorf("block %d holds %d references once both batches are released, want the reader's", i, got)
		}
	}
}

// a datagram alone in its block goes into a copy of the least power of two from 2 KiB that holds it, up to half a block, and its batch is charged the copy and holds no reference to the block
// a datagram past half a block stays in its block, which its batch holds and is charged whole
func TestDatagramAloneInItsBlockIsCopied(t *testing.T) {
	sizes := []int{9, 1400, 2048, 2049, readBufferSize / 2, readBufferSize/2 + 1}
	copies := []int{2048, 2048, 2048, 4096, readBufferSize / 2, 0}
	h, muxes := ecnHub(1)
	datagrams := make([][]byte, len(sizes))
	for i, size := range sizes {
		head := espTo(0, uint32(i))
		datagrams[i] = append(head, make([]byte, size-len(head))...)
	}
	var blocks []*rxBlock
	h.receiveLoop(laidRead(datagrams, 1, &blocks), func(error) {})
	batch := queued(t, muxes[0])
	charge := 0
	for i, packet := range batch.Packets() {
		inBlock := &packet[0] == &blocks[i].data[0]
		if inBlock != (copies[i] == 0) || !slices.Equal(packet, datagrams[i]) {
			t.Errorf("the datagram of %d bytes reads %d bytes, in its block %v, want in its block %v", sizes[i], len(packet), inBlock, copies[i] == 0)
		}
		want := int32(1)
		if copies[i] == 0 {
			want, charge = 2, charge+readBufferSize
		} else {
			charge += copies[i]
			if !slices.ContainsFunc(batch.blocks, func(b *rxBlock) bool { return len(b.data) == copies[i] && &b.data[0] == &packet[0] }) {
				t.Errorf("the datagram of %d bytes lies in no copy of %d bytes the batch holds", sizes[i], copies[i])
			}
		}
		if got := blocks[i].refs.Load(); got != want {
			t.Errorf("the block of the datagram of %d bytes counts %d references, want %d", sizes[i], got, want)
		}
	}
	if batch.charge != charge || muxes[0].espHeld.Load() != int64(charge) {
		t.Errorf("the batch is charged %d and the mux holds %d, want %d", batch.charge, muxes[0].espHeld.Load(), charge)
	}
	batch.Release()
	for i, block := range blocks {
		if got := block.refs.Load(); got != 1 {
			t.Errorf("the block of the datagram of %d bytes counts %d references once the batch is released, want the reader's", sizes[i], got)
		}
	}
}

// copyAllocDatagrams is how many datagrams, each alone in its block, each read of the copy allocation test holds
const copyAllocDatagrams = 16

// demultiplexing reads of datagrams each alone in its block takes each copy from its pool once the batches of the reads before are released
// a copy taken afresh costs two allocations, its block and its buffer, so a copy dropped on release costs a read two a copy
// under -race a sync.Pool drops a quarter of what is put back, so a pooled read takes about a quarter of its copies and its batch afresh, under one allocation a copy
func TestHubCopiesComeBackFromTheirPool(t *testing.T) {
	datagrams := make([][]byte, copyAllocDatagrams)
	for i := range datagrams {
		head := espTo(0, uint32(i))
		datagrams[i] = append(head, make([]byte, 1400-len(head))...)
	}
	allocs := func(n int) float64 {
		return testing.AllocsPerRun(1, func() {
			h, muxes := ecnHub(1)
			slots := make([]*rxBlock, len(datagrams))
			reads := 0
			h.receiveLoop(releasing(muxes, func(pool *blockPool, bufs [][]byte, sizes []int, endpoints []Endpoint, records []receiveRecord, _ *refusals) (int, error) {
				if reads == n {
					return 0, errScriptDone
				}
				reads++
				for i, datagram := range datagrams {
					pool.refill(&slots[i])
					bufs[i], sizes[i], endpoints[i] = slots[i].data[:copy(slots[i].data, datagram)], len(datagram), nil
					records[i] = receiveRecord{block: slots[i]}
				}
				return len(datagrams), nil
			}), func(error) {})
		})
	}
	if perRead := (allocs(2*hubAllocReads) - allocs(hubAllocReads)) / hubAllocReads; perRead >= copyAllocDatagrams {
		t.Errorf("a read of %d datagrams each alone in its block allocated %v times, want under one a copy", copyAllocDatagrams, perRead)
	}
}

// datagrams that share a block stay in it however small, the block held once by each batch with a datagram in it and charged whole to each
func TestDatagramsSharingABlockAreNotCopied(t *testing.T) {
	h, muxes := ecnHub(2)
	var blocks []*rxBlock
	h.receiveLoop(laidRead([][]byte{espTo(0, 0), espTo(1, 1)}, 2, &blocks), func(error) {})
	for i, m := range muxes {
		batch := queued(t, m)
		if packet := batch.Packets()[0]; &packet[0] != &blocks[0].data[i*8] {
			t.Errorf("the datagram of mux %d was copied out of the block it shares", i)
		}
		if batch.charge != readBufferSize {
			t.Errorf("the batch of mux %d is charged %d, want the block whole", i, batch.charge)
		}
		defer batch.Release()
	}
	if got := blocks[0].refs.Load(); got != 3 {
		t.Errorf("the shared block counts %d references, want the reader's and each batch's", got)
	}
}

// each copy size is the least power of two from smallestCopy that holds its datagram, under twice the datagram once that passes half smallestCopy, and none past half a block
// smallestCopy is the least power of two that holds a datagram a 1500 byte IPv4 path carries, and the largest copy is half a block, each size going back to a pool of its own
func TestCopySizes(t *testing.T) {
	path := 1500 - 20 - 8
	least := 1
	for least < path {
		least *= 2
	}
	if smallestCopy != least {
		t.Errorf("smallestCopy is %d, want %d, the least power of two holding %d bytes", smallestCopy, least, path)
	}
	if largest := smallestCopy << (copyClasses - 1); largest != readBufferSize/2 {
		t.Errorf("the largest of %d copy sizes is %d, want half a block", copyClasses, largest)
	}
	var pool blockPool
	homes := map[*sync.Pool]bool{pool.home(readBufferSize): true}
	for n := 1; n <= readBufferSize; n++ {
		want := smallestCopy
		for want < n {
			want *= 2
		}
		if want > readBufferSize/2 {
			want = 0
		}
		size := copySize(n)
		if size != want || n > smallestCopy/2 && size >= 2*n {
			t.Fatalf("a datagram of %d bytes takes a copy of %d, want %d", n, size, want)
		}
		if size != 0 {
			homes[pool.home(size)] = true
		}
	}
	if len(homes) != copyClasses+1 {
		t.Errorf("the copies and blocks go back to %d pools, want %d", len(homes), copyClasses+1)
	}
}

// a mux holding all its receive storage takes no reference to a block and no copy, so the reader reads into each block again at once
// the read lays two datagrams in one block and a third alone in the next
func TestRefusedChainHoldsNoBlock(t *testing.T) {
	h, muxes := ecnHub(1)
	muxes[0].espHeld.Store(espHeldBytes)
	var blocks []*rxBlock
	h.receiveLoop(laidRead([][]byte{espTo(0, 0), espTo(0, 1), espTo(0, 2)}, 2, &blocks), func(error) {})
	if got := h.Dropped(); got != 3 {
		t.Errorf("the hub dropped %d datagrams, want all 3", got)
	}
	if len(muxes[0].espCh) != 0 {
		t.Error("a mux holding all its storage was handed a batch")
	}
	for i, block := range blocks {
		if got := block.refs.Load(); got != 1 {
			t.Errorf("block %d holds %d references after its chain was refused, want the reader's alone", i, got)
		}
	}
	// a copy taken and given back would wait in its pool, which the hub has never put one in otherwise
	if h.pool.copies[0].Get() != nil {
		t.Error("the refused chain took a copy of its lone datagram")
	}
}

// a batch dispatchESP refuses gives back its blocks and the charge it never took, on both of its arms
// a receive loop of the other family may take the room hasRoomForESP saw in the mux's held storage, or the last slot of its queue
func TestRefusedDispatchFreesTheBatch(t *testing.T) {
	var pool blockPool
	short := &Mux{espCh: make(chan *Received, espChanSize), done: make(chan struct{})}
	short.espHeld.Store(espHeldBytes - readBufferSize + 1)
	full := &Mux{espCh: make(chan *Received, 1), done: make(chan struct{})}
	if !full.dispatchESP(testBatch(&pool, []byte("first"))) {
		t.Fatal("the first batch was refused")
	}
	for _, refusal := range []struct {
		name string
		m    *Mux
	}{{"held storage short of a block", short}, {"a full queue", full}} {
		held := refusal.m.espHeld.Load()
		refused := testBatch(&pool, []byte("refused"))
		block := refused.blocks[0]
		// the reader's reference, which a batch of a read retains beside
		block.retain()
		if refusal.m.dispatchESP(refused) {
			t.Fatalf("a mux with %s took the batch", refusal.name)
		}
		if got := block.refs.Load(); got != 1 {
			t.Errorf("the block of a batch refused for %s holds %d references, want the reader's alone", refusal.name, got)
		}
		if got := refusal.m.espHeld.Load(); got != held {
			t.Errorf("the refusal for %s moved the held storage from %d to %d", refusal.name, held, got)
		}
	}
}

// a batch's ECN fields are its own, Not-ECT, ECT(0) and CE as its datagrams arrived, and a batch put back and taken again for a read of Not-ECT datagrams alone holds none
func TestReceivedECNIsEachBatchsOwn(t *testing.T) {
	reads := [][]scriptedDatagram{{{0, packet.CE}, {0, packet.ECT0}, {0, packet.NotECT}}, {{0, packet.NotECT}, {0, packet.NotECT}}}
	want := [][]packet.ECN{{packet.CE, packet.ECT0, packet.NotECT}, nil}
	h, muxes := ecnHub(1)
	taken := 0
	// take checks and releases the batch of the read before, so the next read may take the same batch from the pool
	take := func() {
		batch := queued(t, muxes[0])
		if got := batch.ECN(); (got == nil) != (want[taken] == nil) || !slices.Equal(got, want[taken]) {
			t.Errorf("the batch of read %d holds the ECN fields %v, want %v", taken, got, want[taken])
		}
		taken++
		batch.Release()
	}
	read := scriptedReads(reads)()
	h.receiveLoop(func(pool *blockPool, bufs [][]byte, sizes []int, endpoints []Endpoint, records []receiveRecord, refused *refusals) (int, error) {
		if len(muxes[0].espCh) != 0 {
			take()
		}
		return read(pool, bufs, sizes, endpoints, records, refused)
	}, func(error) {})
	if taken != len(reads) {
		t.Errorf("the mux was handed %d batches, want one for each of the %d reads", taken, len(reads))
	}
}

// a block released once more than it was held panics rather than go to the pool twice, where two readers would fill it at once
func TestBlockReleasedTwicePanics(t *testing.T) {
	var pool blockPool
	block := pool.get()
	block.release()
	defer func() {
		if recover() == nil {
			t.Error("a second release of a block went unnoticed")
		}
	}()
	block.release()
}

// the reader keeps a block nothing else holds and reads into a fresh one where a batch holds it, giving back its own reference to that one
func TestRefillReplacesOnlyAHeldBlock(t *testing.T) {
	var pool blockPool
	var slot *rxBlock
	if !pool.refill(&slot) || slot == nil {
		t.Fatal("an empty slot took no block")
	}
	kept := slot
	if pool.refill(&slot) || slot != kept {
		t.Error("the reader let go of a block nothing else holds")
	}
	kept.retain()
	if !pool.refill(&slot) || slot == kept {
		t.Error("the reader read again into a block a batch holds")
	}
	if got := kept.refs.Load(); got != 1 {
		t.Errorf("the held block holds %d references once the reader let go of it, want the batch's", got)
	}
}
