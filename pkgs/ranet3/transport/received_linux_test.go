// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package transport

import (
	"encoding/binary"
	"net"
	"runtime"
	"testing"
	"time"
)

const (
	// groSegments is how many datagrams each send of the GRO test and benchmark carries in one UDP_SEGMENT message
	groSegments = 40
	// groBenchSegments is the datagrams of each message the GRO benchmark sends, as many as an older kernel's UDP_SEGMENT takes
	groBenchSegments = gsoMaxSegments
	// groBenchWindow is how many of its messages the GRO benchmark lets the hub hold unread before it sends another, which keeps the socket's buffer from dropping any
	groBenchWindow = 64
	// groBenchSize is the size of each datagram the GRO benchmark sends, so that groBenchSegments of them fit the 64 KiB of one UDP_SEGMENT message
	groBenchSize = 1000
	// groSPI is the SPI the GRO test and benchmark send on
	groSPI = 0x4242
)

// groPair is a socket of a bind as a hub opens it, UDP_GRO on, and a bind sending to it over loopback with UDP_SEGMENT
func groPair(tb testing.TB) (*udpSocket, packetBind, Endpoint) {
	tb.Helper()
	bind, _, port, err := openPacketBind(0, nil, nil)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = bind.Close() })
	socket := bind.(*udpBind).v4
	if socket == nil {
		tb.Skip("IPv4 unavailable")
	}
	sender, _, _, err := openPacketBind(0, nil, nil)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = sender.Close() })
	endpoint, err := sender.ParseEndpoint((&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)}).String())
	if err != nil {
		tb.Fatal(err)
	}
	return socket, sender, endpoint
}

// tagged is count ESP datagrams of size on groSPI, each tagged with mark and its index
func tagged(count, size int, mark byte) [][]byte {
	storage := make([]byte, count*size)
	packets := make([][]byte, count)
	for i := range packets {
		packets[i] = storage[i*size : (i+1)*size]
		binary.BigEndian.PutUint32(packets[i], groSPI)
		packets[i][4], packets[i][5] = mark, byte(i)
	}
	return packets
}

// a GRO read lies in a block of the hub's pool, and a block a batch still holds is not read into again, and its bytes stay those of the first read while the kernel writes the next into a fresh block the read points it at
// a block nothing holds any more is read into again in place
func TestGROReadLeavesAHeldBlockAlone(t *testing.T) {
	socket, sender, endpoint := groPair(t)
	messages := receiveVector(pairReadMessages)
	reader := newUDPReader(socket.raw, messages)
	receive := socket.walk(messages, reader.read)
	var pool blockPool
	bufs, sizes, endpoints, records := make([][]byte, espSendBatch), make([]int, espSendBatch), make([]Endpoint, espSendBatch), make([]receiveRecord, espSendBatch)
	// read sends count datagrams marked mark and reads them, each from the one block it answers
	read := func(mark byte) *rxBlock {
		t.Helper()
		if err := sender.Send(tagged(groSegments, 100, mark), endpoint); err != nil {
			t.Fatal(err)
		}
		var block *rxBlock
		for received := 0; received < groSegments; {
			n, err := receive(&pool, bufs, sizes, endpoints, records, new(refusals))
			if err != nil {
				t.Fatal(err)
			}
			for i := range n {
				if bufs[i][4] != mark || int(bufs[i][5]) != received+i {
					t.Fatalf("datagram %d of the send marked %c reads %c %d", received+i, mark, bufs[i][4], bufs[i][5])
				}
				if block == nil {
					block = records[i].block
				}
				if records[i].block != block {
					t.Fatalf("the send marked %c was read into more than one block, so GRO did not coalesce it", mark)
				}
			}
			received += n
		}
		return block
	}
	first := read('a')
	first.retain()
	second := read('b')
	if second == first {
		t.Fatal("the read went into a block a batch holds")
	}
	if got := &messages[0].Buffers[0][0]; reader.iovecs[0].Base != got || got != &second.data[0] {
		t.Error("the kernel was not pointed at the fresh block the message took")
	}
	for i := range groSegments {
		if datagram := first.data[i*100:]; datagram[4] != 'a' || int(datagram[5]) != i {
			t.Fatalf("datagram %d of the held block reads %c %d once the next read is done", i, datagram[4], datagram[5])
		}
	}
	if got := first.refs.Load(); got != 1 {
		t.Errorf("the held block counts %d references once the reader let go of it, want the batch's", got)
	}
	if third := read('c'); third != second {
		t.Error("a block nothing holds was not read into again")
	}
	first.release()
}

// BenchmarkHubReceivesGRO is a hub's receive path from the socket to a batch released, over loopback, one message of groBenchSegments datagrams an op
// a sender seals nothing and sends datagrams on a registered SPI with UDP_SEGMENT, which the hub's socket coalesces back, and a drain takes and releases each batch as the workers would
// it reports the datagrams a second the hub took, what it allocated, and the collector's cycles for each million datagrams
func BenchmarkHubReceivesGRO(b *testing.B) {
	hub, err := NewHub(0, Runtime{})
	if err != nil {
		b.Fatal(err)
	}
	defer hub.Close()
	mux, err := hub.NewMux(net.IPv4(127, 0, 0, 1), 9)
	if err != nil {
		b.Fatal(err)
	}
	if err := mux.RegisterESP(groSPI); err != nil {
		b.Fatal(err)
	}
	sender, _, _, err := openPacketBind(0, nil, nil)
	if err != nil {
		b.Fatal(err)
	}
	defer sender.Close()
	endpoint, err := sender.ParseEndpoint((&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(hub.port)}).String())
	if err != nil {
		b.Fatal(err)
	}
	packets := tagged(groBenchSegments, groBenchSize, 'g')
	// taken carries the datagrams of each batch the drain released
	taken := make(chan int, espChanSize)
	go func() {
		for {
			batch, err := mux.RecvESPBatchConcurrent()
			if err != nil {
				close(taken)
				return
			}
			n := len(batch.Packets())
			batch.Release()
			select {
			case taken <- n:
			case <-mux.Done():
				return
			}
		}
	}()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	b.SetBytes(groBenchSegments * groBenchSize)
	b.ReportAllocs()
	b.ResetTimer()
	start := time.Now()
	sent, received := 0, 0
	for b.Loop() {
		for sent-received >= groBenchWindow*groBenchSegments {
			received += <-taken
		}
		if err := sender.Send(packets, endpoint); err != nil {
			b.Fatal(err)
		}
		sent += groBenchSegments
	}
	for received < sent-int(hub.Dropped()) {
		select {
		case n := <-taken:
			received += n
		case <-time.After(arrivalBudget):
			b.Fatalf("the hub took %d of %d datagrams, and dropped %d", received, sent, hub.Dropped())
		}
	}
	elapsed := time.Since(start)
	b.StopTimer()
	runtime.ReadMemStats(&after)
	b.ReportMetric(float64(received)/elapsed.Seconds(), "datagrams/s")
	b.ReportMetric(float64(after.NumGC-before.NumGC)*1e6/float64(received), "gc/Mdatagram")
}
