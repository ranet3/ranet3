// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package transport

import (
	"math/bits"
	"sync"
	"sync/atomic"

	"ranet3.com/pkgs/ranet3/internal/packet"
)

// rxBlock is one receive buffer, counted by the reader that fills it and by each batch holding a view of it, or one copy, counted by its batch alone
// data is allocated apart from the block, so the count's cache line is not one a worker decrypting in place writes
type rxBlock struct {
	data []byte
	refs atomic.Int32
	pool *blockPool
}

// blockPool is the receive buffers, copies and batches of one hub
// a buffer, copy or batch never released is the collector's and is never reused, so nothing counts the free ones
type blockPool struct {
	blocks sync.Pool
	// copies holds the copies of each size, smallestCopy doubled by the index
	copies  [copyClasses]sync.Pool
	batches sync.Pool
	// poison is nil but in a test, which overwrites each buffer put back so a view read after its release reads what it wrote
	poison func([]byte)
}

func (p *blockPool) get() *rxBlock { return p.take(readBufferSize) }

// take is a buffer of size, a receive buffer's or a copy's, held once by the one it is taken for
func (p *blockPool) take(size int) *rxBlock {
	b, _ := p.home(size).Get().(*rxBlock)
	if b == nil {
		b = &rxBlock{data: make([]byte, size), pool: p}
	}
	b.refs.Store(1)
	return b
}

// home is the pool a buffer of size goes back to
func (p *blockPool) home(size int) *sync.Pool {
	if size == readBufferSize {
		return &p.blocks
	}
	return &p.copies[bits.Len(uint(size/smallestCopy))-1]
}

// copySize is the size of the copy a datagram of n bytes alone in its receive buffer goes into, the least power of two from smallestCopy that holds it
// and 0 past half a receive buffer, where its batch holds a view of the receive buffer instead
func copySize(n int) int {
	size := max(smallestCopy, 1<<bits.Len(uint(n-1)))
	if size > readBufferSize/2 {
		return 0
	}
	return size
}

// refill gives slot a fresh block where it holds none or one a batch still retains, and reports whether it did
// only the reader's goroutine retains its blocks, so between its calls a count only falls, and a count of 1 read there means only the reader holds the block
func (p *blockPool) refill(slot **rxBlock) bool {
	if b := *slot; b != nil {
		if b.refs.Load() == 1 {
			return false
		}
		b.release()
	}
	*slot = p.get()
	return true
}

func (b *rxBlock) retain() { b.refs.Add(1) }

// release puts b back in its pool once nothing holds it
// a count below zero is a block released twice, which the pool would hand to two readers at once
func (b *rxBlock) release() {
	switch refs := b.refs.Add(-1); {
	case refs > 0:
	case refs == 0:
		if b.pool.poison != nil {
			b.pool.poison(b.data)
		}
		b.pool.home(len(b.data)).Put(b)
	default:
		panic("transport: a receive buffer was released more times than it was held")
	}
}

// Received is one mux's ESP datagrams of one read, each a view of the receive buffer it arrived in or of its copy
// the buffers stay unwritten until Release, which the holder calls once and after its last read of a packet
type Received struct {
	ticket  uint64
	packets [][]byte
	// ecn holds the outer ECN field of each packet, nil when every one arrived Not-ECT
	ecn    []packet.ECN
	blocks []*rxBlock
	// charge is the receive storage this batch holds against its mux's bound, each buffer it holds a view of counted whole
	charge int
	mux    *Mux
	pool   *blockPool

	packetSlots [espSendBatch][]byte
	ecnSlots    [espSendBatch]packet.ECN
	blockSlots  [espSendBatch]*rxBlock
}

func (p *blockPool) batch() *Received {
	r, _ := p.batches.Get().(*Received)
	if r == nil {
		r = &Received{pool: p}
	}
	return r
}

// Ticket is the batch's place in its mux's receive order
func (r *Received) Ticket() uint64 { return r.ticket }

// Packets are the batch's datagrams in the order they arrived, each ending at its datagram, so no append reaches the next
func (r *Received) Packets() [][]byte { return r.packets }

// ECN is the outer ECN field of each packet, nil when every one arrived Not-ECT
func (r *Received) ECN() []packet.ECN { return r.ecn }

// Release gives back the batch's share of its mux's bound and its hold on each receive buffer
func (r *Received) Release() {
	r.mux.espHeld.Add(-int64(r.charge))
	r.free()
}

// free lets go of r's buffers and puts r back, for a batch whose charge is given back or was never taken
func (r *Received) free() {
	for _, b := range r.blocks {
		b.release()
	}
	clear(r.packets)
	clear(r.blocks)
	r.ticket, r.packets, r.ecn, r.blocks, r.charge, r.mux = 0, nil, nil, nil, 0, nil
	r.pool.batches.Put(r)
}
