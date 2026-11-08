// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux

package transport

import (
	"encoding/binary"
	"net"
	"net/netip"
	"slices"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

const (
	// poolMuxes is how many muxes the pool property's hub holds
	poolMuxes = 3
	// poolMessages is the messages of the pool property's receive vector, whose GRO messages of 64 datagrams make a read longer than one walk hands out
	poolMessages = 4
	// poolSPI is the ESP SPI of the pool property's first mux, the others following it, and strayedPoolSPI one no mux holds
	poolSPI        = 0x100
	strayedPoolSPI = 0x777
	// espHeaderLen is the SPI and sequence number in front of every ESP payload
	espHeaderLen = 8
)

// poolSegment is one datagram of a drawn read, for the mux of its index or for none at -1, and the tag that tells it apart
type poolSegment struct {
	mux int
	tag uint32
}

// poolMessage is one GRO message of a drawn read, its datagrams of size each
type poolMessage struct {
	size     int
	segments []poolSegment
}

// modelBatch is the batch the model says a mux was dispatched, the tags of its datagrams, the blocks those not copied lie in and its charge
type modelBatch struct {
	tags   []uint32
	blocks []*byte
	charge int
}

// poolModel holds the state the pool property expects the hub in, written apart from the hub
type poolModel struct {
	// holders counts the live batches with a datagram in each block, keyed by the block's first byte
	holders map[*byte]int
	// queues are the batches each mux holds and no consumer took, oldest first
	queues [poolMuxes][]modelBatch
	charge [poolMuxes]int
	closed [poolMuxes]bool
	// slots is the block each message of the vector last read into
	slots   [poolMessages]*byte
	dropped uint64
}

// modelCopy is the size of the copy a datagram of size alone in its block goes into, the least of 2 KiB, 4 KiB and on to half a block that holds it, and 0 where none does
func modelCopy(size int) int {
	for c := 2048; c <= readBufferSize/2; c *= 2 {
		if size <= c {
			return c
		}
	}
	return 0
}

// dispatch moves the model as the hub moves on one walk's hand-out of datagrams, each its mux, its tag, its size and its block
// a datagram the hand-out holds no other of its block beside goes into a copy where modelCopy has one, and the batch is charged the copy and holds no block for it
func (m *poolModel) dispatch(muxes []int, tags []uint32, sizes []int, blocks []*byte) {
	for mux := range poolMuxes {
		if m.closed[mux] {
			continue
		}
		var batch modelBatch
		var last *byte
		for i := range muxes {
			if muxes[i] != mux {
				continue
			}
			batch.tags = append(batch.tags, tags[i])
			alone := !slices.Contains(blocks[:i], blocks[i]) && !slices.Contains(blocks[i+1:], blocks[i])
			if size := modelCopy(sizes[i]); alone && size != 0 {
				batch.charge += size
				continue
			}
			if blocks[i] != last {
				batch.blocks, last = append(batch.blocks, blocks[i]), blocks[i]
				batch.charge += readBufferSize
			}
		}
		if len(batch.tags) == 0 {
			continue
		}
		if len(m.queues[mux]) == espChanSize || m.charge[mux]+batch.charge > espHeldBytes {
			m.dropped += uint64(len(batch.tags))
			continue
		}
		m.queues[mux] = append(m.queues[mux], batch)
		m.charge[mux] += batch.charge
		for _, block := range batch.blocks {
			m.holders[block]++
		}
	}
}

func (m *poolModel) release(mux int, batch modelBatch) {
	m.charge[mux] -= batch.charge
	for _, block := range batch.blocks {
		m.holders[block]--
	}
}

// heldBatch is a batch a consumer took and holds, beside what the model said of it
type heldBatch struct {
	mux   int
	batch *Received
	model modelBatch
}

// tagsOf is the tag behind the SPI of each packet
func tagsOf(packets [][]byte) []uint32 {
	tags := make([]uint32, len(packets))
	for i, packet := range packets {
		tags[i] = binary.BigEndian.Uint32(packet[4:])
	}
	return tags
}

// the hub's receive buffers against a model, over drawn reads of the real walk and receive loop interleaved with consumers that take, hold and release batches in any order and close muxes
// each read lays tagged datagrams of three muxes and of an SPI none holds into GRO messages as recvmmsg would, and a read longer than one walk hands out goes over two
// a datagram a hand-out holds alone of its block goes into a copy up to half a block, charged at the copy's size, and holds no block
// after every step each datagram a consumer holds still carries its tag, each block counts the reader where it is a message's buffer and each live batch with a datagram in it not copied,
// and each mux holds the model's charge, at most espHeldBytes, and the hub dropped what the model did
// a read goes only into blocks no live batch holds, and a message keeps a block no live batch holds
// once every batch of an open mux is released, each block counts the reader and the batches closed muxes kept, and each open mux holds nothing
func TestReceiveBuffersAgainstAModel(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		network := NewMemoryNetwork()
		port := network.hold(netip.Addr{})
		messages := receiveVector(poolMessages)
		var source udpSource
		putSource(&source, netip.MustParseAddrPort("192.0.2.1:4500"))
		reading, reads := make(chan struct{}), make(chan []poolMessage)
		read := func() (int, error) {
			reading <- struct{}{}
			drawn := <-reads
			if drawn == nil {
				return 0, errScriptDone
			}
			for i, message := range drawn {
				m := &messages[i]
				for j, segment := range message.segments {
					raw := m.Buffers[0][j*message.size:]
					spi := uint32(strayedPoolSPI)
					if segment.mux >= 0 {
						spi = uint32(poolSPI + segment.mux)
					}
					binary.BigEndian.PutUint32(raw, spi)
					binary.BigEndian.PutUint32(raw[4:], segment.tag)
				}
				m.N, m.Flags, m.Addr = len(message.segments)*message.size, 0, &source
				control := appendUDPSegment(m.OOB[:0], message.size)
				(*unix.Cmsghdr)(unsafe.Pointer(&control[0])).Type = unix.UDP_GRO
				m.NN = len(control)
			}
			return len(drawn), nil
		}
		walked := (&udpSocket{}).walk(messages, read)
		entered, resume := make(chan struct{}), make(chan struct{})
		blocks := make(map[*byte]*rxBlock)
		var handed []receiveRecord
		stepped := func(pool *blockPool, bufs [][]byte, sizes []int, endpoints []Endpoint, records []receiveRecord, refused *refusals) (int, error) {
			entered <- struct{}{}
			<-resume
			n, err := walked(pool, bufs, sizes, endpoints, records, refused)
			handed = append(handed[:0], records[:n]...)
			for _, record := range records[:n] {
				blocks[&record.block.data[0]] = record.block
			}
			return n, err
		}
		hub := startHub(&memoryBind{network: network, port: port}, []receiveFunc{stepped}, port.port, Runtime{})
		muxes := make([]*Mux, poolMuxes)
		for i := range muxes {
			var err error
			if muxes[i], err = hub.NewMux(net.ParseIP("192.0.2.1"), 4500+i); err != nil {
				ht.Fatal(err)
			}
			if err := muxes[i].RegisterESP(uint32(poolSPI + i)); err != nil {
				ht.Fatal(err)
			}
		}
		model := &poolModel{holders: make(map[*byte]int)}
		var held []heldBatch
		// pending is the datagrams of the last read the walks have not handed out, each its mux, tag, size and block
		var pendingMuxes, pendingSizes []int
		var pendingTags []uint32
		var pendingBlocks []*byte
		tag := uint32(0)

		check := func(step int) {
			for _, h := range held {
				if got := tagsOf(h.batch.Packets()); !slices.Equal(got, h.model.tags) {
					ht.Fatalf("step %d: a batch mux %d holds reads %v, want %v", step, h.mux, got, h.model.tags)
				}
			}
			for key, block := range blocks {
				want := int32(model.holders[key])
				if slices.Contains(model.slots[:], key) {
					want++
				}
				if got := block.refs.Load(); got != want {
					ht.Fatalf("step %d: a block counts %d references, want %d", step, got, want)
				}
			}
			for i, m := range muxes {
				if got := m.espHeld.Load(); got != int64(model.charge[i]) || got > espHeldBytes {
					ht.Fatalf("step %d: mux %d holds %d bytes, want %d", step, i, got, model.charge[i])
				}
			}
			if got := hub.Dropped(); got != model.dropped {
				ht.Fatalf("step %d: the hub dropped %d datagrams, want %d", step, got, model.dropped)
			}
		}
		// take takes a batch as a session's worker does, through the receive call while the mux is open, and from its queue once it is closed
		take := func(step, mux int) {
			queue := muxes[mux].espCh
			if !model.closed[mux] && len(queue) != 0 {
				ready := make(chan *Received, 1)
				batch, err := muxes[mux].RecvESPBatchConcurrent()
				if err != nil {
					ht.Fatalf("step %d: the receive of open mux %d failed with %v", step, mux, err)
				}
				ready <- batch
				queue = ready
			}
			select {
			case batch := <-queue:
				if len(model.queues[mux]) == 0 {
					ht.Fatalf("step %d: mux %d was handed a batch of %v the model dispatched no batch for", step, mux, tagsOf(batch.Packets()))
				}
				want := model.queues[mux][0]
				model.queues[mux] = model.queues[mux][1:]
				if got := tagsOf(batch.Packets()); !slices.Equal(got, want.tags) || batch.charge != want.charge {
					ht.Fatalf("step %d: mux %d was handed %v charged %d, want %v charged %d", step, mux, got, batch.charge, want.tags, want.charge)
				}
				held = append(held, heldBatch{mux, batch, want})
			default:
				if len(model.queues[mux]) != 0 {
					ht.Fatalf("step %d: mux %d holds no batch, want %d", step, mux, len(model.queues[mux]))
				}
			}
		}
		release := func(step, at int) {
			h := held[at]
			if got := tagsOf(h.batch.Packets()); !slices.Equal(got, h.model.tags) {
				ht.Fatalf("step %d: a batch of mux %d released reads %v, want %v", step, h.mux, got, h.model.tags)
			}
			h.batch.Release()
			model.release(h.mux, h.model)
			held = slices.Delete(held, at, at+1)
		}
		// walk hands out what the hub reads next, reading a drawn read first once the last is handed out
		walk := func(step int) {
			resume <- struct{}{}
			if len(pendingTags) == 0 {
				<-reading
				drawn := drawRead(ht)
				for i := range messages {
					key := &messages[i].Buffers[0][0]
					if model.holders[key] != 0 {
						ht.Fatalf("step %d: message %d reads into a block %d live batches hold", step, i, model.holders[key])
					}
					if previous := model.slots[i]; previous != nil && model.holders[previous] == 0 && previous != key {
						ht.Fatalf("step %d: message %d let go of a block no live batch holds", step, i)
					}
					model.slots[i] = key
				}
				for i := range drawn {
					key := model.slots[i]
					for j := range drawn[i].segments {
						drawn[i].segments[j].tag = tag
						pendingMuxes = append(pendingMuxes, drawn[i].segments[j].mux)
						pendingTags = append(pendingTags, tag)
						pendingSizes = append(pendingSizes, drawn[i].size)
						pendingBlocks = append(pendingBlocks, key)
						tag++
					}
				}
				reads <- drawn
			}
			<-entered
			n := len(handed)
			if n != min(len(pendingTags), espSendBatch) {
				ht.Fatalf("step %d: the walk handed out %d datagrams, want %d", step, n, min(len(pendingTags), espSendBatch))
			}
			model.dispatch(pendingMuxes[:n], pendingTags[:n], pendingSizes[:n], pendingBlocks[:n])
			pendingMuxes, pendingTags, pendingSizes, pendingBlocks = pendingMuxes[n:], pendingTags[n:], pendingSizes[n:], pendingBlocks[n:]
		}

		<-entered
		steps := hegel.Draw(ht, pbt.Spanning(1, 8))
		for step := range steps {
			for range hegel.Draw(ht, pbt.Spanning(0, 3)) {
				switch hegel.Draw(ht, hegel.Integers(0, 5)) {
				case 0, 1, 2:
					take(step, hegel.Draw(ht, hegel.Integers(0, poolMuxes-1)))
				case 3, 4:
					if len(held) != 0 {
						release(step, hegel.Draw(ht, hegel.Integers(0, len(held)-1)))
					}
				case 5:
					mux := hegel.Draw(ht, hegel.Integers(0, poolMuxes-1))
					_ = muxes[mux].Close()
					model.closed[mux] = true
				}
			}
			check(step)
			walk(step)
			check(step)
		}
		for len(pendingTags) != 0 {
			walk(steps)
		}
		for len(held) != 0 {
			release(steps, 0)
		}
		for mux := range poolMuxes {
			if model.closed[mux] {
				continue
			}
			for len(model.queues[mux]) != 0 {
				take(steps, mux)
				release(steps, 0)
			}
			if got := muxes[mux].espHeld.Load(); got != 0 {
				ht.Fatalf("mux %d holds %d bytes once every batch is released", mux, got)
			}
		}
		check(steps)
		resume <- struct{}{}
		<-reading
		reads <- nil
		<-hub.Done()
	})
}

// one mux's held receive storage against the bound, over reads it never releases, of drawn datagram sizes laid a drawn number to a block
// a block of several datagrams is counted whole, and a datagram alone in its block goes into a copy counted at its size, the least power of two of 2 KiB or more that holds it
// a read's batch is taken exactly while its charge fits under espHeldBytes beside what the mux holds, and a refused read's blocks count the reader alone, as does a block whose one datagram was copied
// so datagrams of a few bytes each in a block of its own hold no block and no more than espHeldBytes / 2 KiB copies, and those sharing blocks no more than espHeldBytes / readBufferSize blocks
func TestHeldStorageAgainstTheBound(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		h, muxes := ecnHub(1)
		type laid struct {
			blocks []*rxBlock
			// alone says the block of that index holds one datagram
			alone []bool
			taken bool
		}
		// enough reads that blocks of two datagrams each pass the bound
		reads := make([]laid, hegel.Draw(ht, pbt.Spanning(1, 16)))
		held, total, taken, copies := 0, 0, 0, 0
		for i := range reads {
			count := hegel.Draw(ht, pbt.Spanning(1, 64))
			size := hegel.Draw(ht, hegel.SampledFrom([]int{espHeaderLen + 1, 100, 1400}))
			perBlock := min(hegel.Draw(ht, pbt.Spanning(1, count)), readBufferSize/size)
			datagrams := make([][]byte, count)
			for j := range datagrams {
				datagrams[j] = append(espTo(0, uint32(total+j)), make([]byte, size-espHeaderLen)...)
			}
			total += count
			h.receiveLoop(laidRead(datagrams, perBlock, &reads[i].blocks), func(error) {})
			charge, alone := 0, 0
			for k := range reads[i].blocks {
				one := min((k+1)*perBlock, count)-k*perBlock == 1
				reads[i].alone = append(reads[i].alone, one)
				if one {
					charge, alone = charge+2048, alone+1
				} else {
					charge += readBufferSize
				}
			}
			reads[i].taken = held+charge <= espHeldBytes
			if reads[i].taken {
				held, taken, copies = held+charge, taken+1, copies+alone
			}
			if got := len(muxes[0].espCh); got != taken {
				ht.Fatalf("read %d of %d blocks left the mux %d batches, want %d", i, len(reads[i].blocks), got, taken)
			}
			if reads[i].taken {
				continue
			}
			// a refused read's blocks go back to the pool once checked, so the reads after take them again
			for _, block := range reads[i].blocks {
				if got := block.refs.Load(); got != 1 {
					ht.Fatalf("a block of refused read %d counts %d references, want the reader's", i, got)
				}
				block.release()
			}
			reads[i].blocks, reads[i].alone = nil, nil
		}
		if got := muxes[0].espHeld.Load(); got != int64(held) || got > espHeldBytes {
			ht.Fatalf("the mux holds %d bytes, want %d", got, held)
		}
		blocks := 0
		for i, read := range reads {
			for k, block := range read.blocks {
				want := int32(1)
				if read.taken && !read.alone[k] {
					want, blocks = 2, blocks+1
				}
				if got := block.refs.Load(); got != want {
					ht.Fatalf("block %d of read %d, taken %v, alone %v, counts %d references, want %d", k, i, read.taken, read.alone[k], got, want)
				}
			}
		}
		if blocks > espHeldBytes/readBufferSize || copies > espHeldBytes/2048 {
			ht.Fatalf("the mux holds %d blocks and %d copies, past the %d and %d its bound allows", blocks, copies, espHeldBytes/readBufferSize, espHeldBytes/2048)
		}
	})
}

// drawRead draws the GRO messages of one read, one to poolMessages of them, of 1, 2, 63 or 64 datagrams each
// datagrams of one byte past the ESP header, of 1400, at each side of the smallest copy and of half a block, or as large as fit a block, of one mux, of two muxes alternating, or of any mux or none
func drawRead(ht *hegel.T) []poolMessage {
	read := make([]poolMessage, hegel.Draw(ht, pbt.Spanning(1, poolMessages)))
	for i := range read {
		count := hegel.Draw(ht, hegel.SampledFrom([]int{1, 2, 63, 64}))
		size := hegel.Draw(ht, hegel.SampledFrom([]int{espHeaderLen + 1, 1400, smallestCopy, smallestCopy + 1, readBufferSize / 2, readBufferSize/2 + 1, readBufferSize}))
		size = max(min(size, readBufferSize/count), espHeaderLen+1)
		read[i] = poolMessage{size: size, segments: make([]poolSegment, count)}
		first, second := hegel.Draw(ht, hegel.Integers(0, poolMuxes-1)), hegel.Draw(ht, hegel.Integers(0, poolMuxes-1))
		switch hegel.Draw(ht, hegel.Integers(0, 2)) {
		case 0:
			for j := range count {
				read[i].segments[j] = poolSegment{mux: first}
			}
		case 1:
			for j := range count {
				read[i].segments[j] = poolSegment{mux: []int{first, second}[j%2]}
			}
		default:
			for j := range count {
				read[i].segments[j] = poolSegment{mux: hegel.Draw(ht, hegel.Integers(-1, poolMuxes-1))}
			}
		}
	}
	return read
}
