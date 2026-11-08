// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package transport

import (
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"
)

// heldSPI is the SPI of the datagrams the darwin receiver's refill test reads
const heldSPI = 0x4242

// darwin's receiver reads each datagram into a block of the hub's pool, and a block a batch still holds is not read into again, and its bytes stay those of the first read while the next goes into a fresh block
// a block nothing holds any more is read into again in place
func TestDarwinReadLeavesAHeldBlockAlone(t *testing.T) {
	bind, receivers, port, err := openPacketBind(0, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer bind.Close()
	if bind.(*darwinBind).v4 == nil {
		t.Skip("IPv4 unavailable")
	}
	receive := receivers[0]
	loopback := net.IPv4(127, 0, 0, 1)
	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: loopback})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	destination := &net.UDPAddr{IP: loopback, Port: int(port)}
	var pool blockPool
	bufs, sizes, endpoints, records := make([][]byte, espSendBatch), make([]int, espSendBatch), make([]Endpoint, espSendBatch), make([]receiveRecord, espSendBatch)
	// read sends one datagram marked mark and reads it, from the block it answers and the view it was handed
	read := func(mark byte) (*rxBlock, []byte) {
		t.Helper()
		if _, err := sender.WriteToUDP(append(binary.BigEndian.AppendUint32(nil, heldSPI), mark, 0, 0, 0), destination); err != nil {
			t.Fatal(err)
		}
		n, err := receive(&pool, bufs, sizes, endpoints, records, new(refusals))
		if err != nil {
			t.Fatal(err)
		}
		if n != 1 || bufs[0][4] != mark {
			t.Fatalf("the read of the datagram marked %c handed out %d datagrams, the first %x", mark, n, bufs[0])
		}
		return records[0].block, bufs[0]
	}
	first, view := read('a')
	first.retain()
	second, _ := read('b')
	if second == first {
		t.Fatal("the read went into a block a batch holds")
	}
	if view[4] != 'a' {
		t.Errorf("the held datagram reads %c once the next read is done", view[4])
	}
	if got := first.refs.Load(); got != 1 {
		t.Errorf("the held block counts %d references once the reader let go of it, want the batch's", got)
	}
	if third, _ := read('c'); third != second {
		t.Error("a block nothing holds was not read into again")
	}
	first.release()
}

// darwin reads one datagram a call, so the receive loop copies each of a mux's datagrams into a copy of the least power of two from 2 KiB that holds it and charges the mux that copy
// the block it was read into stays the reader's alone, and the next read goes into it again while the batch is still held
func TestDarwinCopiesEachDatagramOutOfItsBlock(t *testing.T) {
	bind, receivers, port, err := openPacketBind(0, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer bind.Close()
	socket := bind.(*darwinBind).v4
	if socket == nil {
		t.Skip("IPv4 unavailable")
	}
	loopback := net.IPv4(127, 0, 0, 1)
	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: loopback})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	destination := &net.UDPAddr{IP: loopback, Port: int(port)}
	h, muxes := ecnHub(1)
	// read sends one datagram of 1400 bytes for the mux, marked mark, and runs the receive loop over one darwin read of it, answering the block it read into
	read := func(mark byte) *rxBlock {
		t.Helper()
		head := espTo(0, uint32(mark))
		datagram := append(head, make([]byte, 1400-len(head))...)
		if _, err := sender.WriteToUDP(datagram, destination); err != nil {
			t.Fatal(err)
		}
		if err := socket.conn.SetReadDeadline(time.Now().Add(arrivalBudget)); err != nil {
			t.Fatal(err)
		}
		var block *rxBlock
		done := false
		var failed error
		h.receiveLoop(func(pool *blockPool, bufs [][]byte, sizes []int, endpoints []Endpoint, records []receiveRecord, refused *refusals) (int, error) {
			if done {
				return 0, errScriptDone
			}
			done = true
			n, err := receivers[0](pool, bufs, sizes, endpoints, records, refused)
			if n == 1 {
				block = records[0].block
			}
			return n, err
		}, func(err error) { failed = err })
		if !errors.Is(failed, errScriptDone) || block == nil {
			t.Fatalf("the read of the datagram marked %d ended with %v", mark, failed)
		}
		return block
	}
	block := read(1)
	batch := queued(t, muxes[0])
	packet := batch.Packets()[0]
	if len(packet) != 1400 || binary.BigEndian.Uint32(packet[4:]) != 1 || &packet[0] == &block.data[0] {
		t.Fatalf("the datagram of 1400 bytes reads %d bytes numbered %d, in its block %v", len(packet), binary.BigEndian.Uint32(packet[4:]), &packet[0] == &block.data[0])
	}
	if len(batch.blocks) != 1 || len(batch.blocks[0].data) != 2048 || batch.charge != 2048 {
		t.Errorf("the batch holds %d buffers and is charged %d, want one copy of 2048 bytes charged at its size", len(batch.blocks), batch.charge)
	}
	if got := block.refs.Load(); got != 1 {
		t.Errorf("the block the datagram was read into counts %d references, want the reader's alone", got)
	}
	if next := read(2); next != block {
		t.Error("the read after a copied datagram went into a fresh block")
	}
	if binary.BigEndian.Uint32(packet[4:]) != 1 {
		t.Error("the held copy changed once the next read went into the block it came from")
	}
	batch.Release()
	queued(t, muxes[0]).Release()
}
