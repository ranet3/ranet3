// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

package netstack

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"ranet3.com/pkgs/wireguard/tun"
)

// recordedWrite is one write into a recordingDevice, the packets it carried copied out
// storage is where each buffer it was handed starts, the frame's own first byte
type recordedWrite struct {
	packets [][]byte
	offset  int
	storage []*byte
}

type recordingDevice struct {
	writes chan recordedWrite
	events chan tun.Event
}

func (d *recordingDevice) File() *os.File { return nil }
func (d *recordingDevice) Read([]byte, []tun.ReadPacket) (int, error) {
	return 0, errors.New("not implemented")
}
func (d *recordingDevice) Write(bufs [][]byte, offset int) (int, error) {
	w := recordedWrite{
		packets: make([][]byte, len(bufs)),
		offset:  offset,
		storage: make([]*byte, len(bufs)),
	}
	for i := range bufs {
		w.packets[i] = append([]byte(nil), bufs[i][offset:]...)
		w.storage[i] = &bufs[i][0]
	}
	d.writes <- w
	return len(bufs), nil
}
func (d *recordingDevice) MTU() (int, error)        { return DefaultMTU, nil }
func (d *recordingDevice) Name() (string, error)    { return "test0", nil }
func (d *recordingDevice) Events() <-chan tun.Event { return d.events }
func (d *recordingDevice) Close() error             { return nil }
func (d *recordingDevice) BatchSize() int           { return 128 }

// laneDevice is a multiqueue tun whose every lane is a device of its own, the first standing for the tun as a whole
// a write to a flow goes to the lane of that index
type laneDevice struct {
	tun.Device
	lanes []tun.Device
}

func lanesOf(lanes ...tun.Device) *laneDevice { return &laneDevice{Device: lanes[0], lanes: lanes} }

func (d *laneDevice) Queues() []tun.Queue {
	queues := make([]tun.Queue, len(d.lanes))
	for i, lane := range d.lanes {
		queues[i] = lane
	}
	return queues
}

func (d *laneDevice) WriteTo(flow int, bufs [][]byte, offset int) (int, error) {
	return d.lanes[flow].Write(bufs, offset)
}

// layOut puts packets into slab as a read off the tun does, tun.ReadPacketSpacing before, between and after them, and says where in reads
func layOut(slab []byte, reads []tun.ReadPacket, packets [][]byte) int {
	offset := tun.ReadPacketSpacing
	for i, packet := range packets {
		reads[i] = tun.ReadPacket{Offset: offset, Size: copy(slab[offset:], packet)}
		offset += len(packet) + tun.ReadPacketSpacing
	}
	return len(packets)
}

// fill makes packets the read b holds
func fill(b *outboundBatch, packets ...[]byte) {
	b.n = layOut(b.slab, b.reads, packets)
}

// espTrailer stands for the ESP trailer and ICV a datagram holds behind its packet, RFC 4303 section 2
const espTrailer = 2 + 16

// framed is packets as a session hands them to the mesh, one buffer holding them as their datagrams lie
// each packet is TUNHeadroom bytes into its datagram, an ESP trailer and ICV between it and the next datagram
// and its frame runs from the start of its datagram to its own end, with no room past it
func framed(packets ...[]byte) [][]byte {
	var datagrams []byte
	for _, packet := range packets {
		datagrams = append(append(append(datagrams, make([]byte, TUNHeadroom)...), packet...), bytes.Repeat([]byte{0xee}, espTrailer)...)
	}
	frames := make([][]byte, len(packets))
	for i, start := 0, 0; i < len(packets); i++ {
		end := start + TUNHeadroom + len(packets[i])
		frames[i] = datagrams[start:end:end]
		start = end + espTrailer
	}
	return frames
}

// unframed is the packet behind the headroom of each frame
func unframed(frames [][]byte) [][]byte {
	packets := make([][]byte, len(frames))
	for i, frame := range frames {
		packets[i] = frame[TUNHeadroom:]
	}
	return packets
}

func TestOutboundWorkersEncryptOneQueueInParallelAndTransmitInOrder(t *testing.T) {
	started := make(chan byte, 2)
	releaseFirst := make(chan struct{})
	transmitted := make(chan byte, 2)
	nextSequence := byte(1)
	peer := NewPeer("peer", func(count int) (BatchSealer, error) {
		first := nextSequence
		nextSequence += byte(count)
		next := first
		return func(raw [][]byte, _ []byte, _ [][]byte) ([][]byte, error) {
			sealed := make([][]byte, 0, len(raw))
			for _, packet := range raw {
				started <- packet[0]
				if packet[0] == 1 {
					<-releaseFirst
				}
				sealed = append(sealed, []byte{next, packet[0]})
				next++
			}
			return sealed, nil
		}, nil
	}, func(sealed [][]byte) error {
		for _, packet := range sealed {
			transmitted <- packet[0]
		}
		return nil
	}, nil)
	defer peer.Close()

	m := &Mesh{
		closed:       make(chan struct{}),
		outboundJobs: make(chan *outboundBatch, 2),
		outboundFree: make(chan *outboundBatch, 2),
	}
	m.outboundWorkerWG.Add(2)
	go m.outboundWorker()
	go m.outboundWorker()
	defer func() {
		close(m.closed)
		close(m.outboundJobs)
		m.outboundWorkerWG.Wait()
	}()

	for marker := byte(1); marker <= 2; marker++ {
		b := &outboundBatch{
			n:         1,
			packets:   [][]byte{{marker}},
			peers:     []*Peer{peer},
			headers:   []byte{0},
			shares:    map[*Peer]outboundShare{peer: {count: 1, bytes: 1}},
			batches:   map[*Peer]*peerBatch{peer: peer.reserveBatch(1, 1)},
			peerOrder: []*Peer{peer},
		}
		m.outboundJobs <- b
	}

	for range 2 {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("batches did not encrypt concurrently")
		}
	}
	select {
	case seq := <-transmitted:
		t.Fatalf("later sequence %d transmitted while the first batch was encrypting", seq)
	default:
	}
	close(releaseFirst)
	got := make([]byte, 0, 2)
	for range 2 {
		select {
		case seq := <-transmitted:
			got = append(got, seq)
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for ordered transmission")
		}
	}
	if !bytes.Equal(got, []byte{1, 2}) {
		t.Fatalf("transmission sequence order = %v, want [1 2]", got)
	}
}

func TestPeerWorkersDoNotWaitForOrderedSender(t *testing.T) {
	startedSend := make(chan struct{})
	releaseSend := make(chan struct{})
	var releaseOnce sync.Once
	transmitted := make(chan byte, 2)
	nextSequence := byte(1)
	peer := NewPeer("peer", func(int) (BatchSealer, error) {
		sequence := nextSequence
		nextSequence++
		return func([][]byte, []byte, [][]byte) ([][]byte, error) { return [][]byte{{sequence}}, nil }, nil
	}, func(sealed [][]byte) error {
		if sealed[0][0] == 1 {
			close(startedSend)
			<-releaseSend
		}
		for _, packet := range sealed {
			transmitted <- packet[0]
		}
		return nil
	}, nil)
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(releaseSend) })
		peer.Close()
	})

	first := peer.reserveBatch(1, 1)
	first.append([]byte{1}, 0)
	if err := first.enqueue(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-startedSend:
	case <-time.After(time.Second):
		t.Fatal("ordered sender did not start the first batch")
	}

	second := peer.reserveBatch(1, 1)
	second.append([]byte{2}, 0)
	enqueued := make(chan error, 1)
	go func() { enqueued <- second.enqueue() }()
	select {
	case err := <-enqueued:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("worker waited for the ordered sender instead of enqueueing its batch")
	}

	releaseOnce.Do(func() { close(releaseSend) })
	for want := byte(1); want <= 2; want++ {
		select {
		case got := <-transmitted:
			if got != want {
				t.Fatalf("transmitted sequence %d, want %d", got, want)
			}
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for transmitted sequence %d", want)
		}
	}
}

func TestSenderMergesReadyBatchesAndCompletesEveryTicket(t *testing.T) {
	sendErr := errors.New("send failed")
	cryptoErr := errors.New("crypto failed")
	transmitted := make(chan []byte, 1)
	p := &Peer{
		ID: "peer", completed: make(chan *peerBatch, 3), started: time.Now(),
		stop: make(chan struct{}), senderDone: make(chan struct{}),
		transmitBatchFn: func(packets [][]byte) error {
			var order []byte
			for _, packet := range packets {
				order = append(order, packet[0])
			}
			transmitted <- order
			return sendErr
		},
	}
	var failures []chan error
	for i := range 3 {
		failed := make(chan error, 1)
		b := &peerBatch{peer: p, ticket: uint64(i), held: 1, sealed: [][]byte{{byte(i)}}, onFailure: func(err error) { failed <- err }}
		if i == 1 {
			b.sealed, b.err = nil, cryptoErr
		}
		p.dataBudget.used.Add(1)
		p.completed <- b
		failures = append(failures, failed)
	}
	go p.senderLoop()
	defer p.Close()
	select {
	case got := <-transmitted:
		if !bytes.Equal(got, []byte{0, 2}) {
			t.Fatalf("merged transmission = %v, want [0 2]", got)
		}
	case <-time.After(time.Second):
		t.Fatal("ready packets were not transmitted")
	}
	for i, result := range failures {
		want := sendErr
		if i == 1 {
			want = cryptoErr
		}
		select {
		case err := <-result:
			if !errors.Is(err, want) {
				t.Fatalf("ticket %d error = %v, want %v", i, err, want)
			}
		case <-time.After(time.Second):
			t.Fatalf("ticket %d never completed", i)
		}
	}
	if got := p.dataBudget.used.Load(); got != 0 {
		t.Fatalf("merged transmission kept %d bytes of the budget", got)
	}
}

// a write into the tun hands the device each frame it was given, its own storage with the packet TUNHeadroom bytes in, on one lane as on several
// the frames lie in one buffer as a session's datagrams do
// darwin and the BSDs write their frame header into the headroom, and linux refuses an offset under its virtio-net header
func TestInboundWritesHandTheDeviceTheFramesThemselves(t *testing.T) {
	for _, lanes := range []int{1, 2} {
		t.Run(fmt.Sprintf("%d lanes", lanes), func(t *testing.T) {
			dev := &recordingDevice{writes: make(chan recordedWrite, 1)}
			devices := make([]tun.Device, lanes)
			for i := range devices {
				devices[i] = dev
			}
			m := ownEverything(&Mesh{closed: make(chan struct{})})
			m.setDevice(lanesOf(devices...))
			m.startInboundWriters()
			t.Cleanup(m.Close)

			want := [][]byte{ipv6TCPPacket(40000, 5201, 1), ipv6TCPPacket(40000, 5201, 2)}
			frames := framed(want...)
			m.DeliverInboundBatch(frames, DefaultMTU, nil)
			select {
			case got := <-dev.writes:
				if got.offset != TUNHeadroom {
					t.Fatalf("the write handed the device its packets %d bytes into their buffers, want %d", got.offset, TUNHeadroom)
				}
				if len(got.packets) != len(want) {
					t.Fatalf("the write carried %d packets, want %d", len(got.packets), len(want))
				}
				for i := range want {
					if !bytes.Equal(got.packets[i], want[i]) {
						t.Errorf("packet %d reached the device as %x, want %x", i, got.packets[i], want[i])
					}
					if got.storage[i] != &frames[i][0] {
						t.Errorf("packet %d reached the device in a buffer other than the frame it was delivered in", i)
					}
				}
			case <-time.After(deliveryTimeout):
				t.Fatal("nothing was written into the tun")
			}
		})
	}
}

func ipv6TCPPacket(srcPort, dstPort uint16, marker byte) []byte {
	packet := make([]byte, 61)
	packet[0] = 0x60
	packet[4], packet[5] = 0, 21
	packet[6] = 6
	copy(packet[8:24], []byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	copy(packet[24:40], []byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})
	packet[40], packet[41] = byte(srcPort>>8), byte(srcPort)
	packet[42], packet[43] = byte(dstPort>>8), byte(dstPort)
	packet[60] = marker
	return packet
}

func TestDeliverInboundBatchUsesFlowAffineQueues(t *testing.T) {
	const queueCount = 8
	devices := make([]tun.Device, queueCount)
	recorders := make([]*recordingDevice, queueCount)
	for i := range devices {
		recorders[i] = &recordingDevice{
			writes: make(chan recordedWrite, 1),
			events: make(chan tun.Event),
		}
		devices[i] = recorders[i]
	}
	m := ownEverything(&Mesh{closed: make(chan struct{})})
	m.setDevice(lanesOf(devices...))
	m.startInboundWriters()
	t.Cleanup(m.Close)

	packets := make([][]byte, 0, 32)
	want := make([][][]byte, queueCount)
	for stream := range 16 {
		for sequence := range 2 {
			packet := ipv6TCPPacket(uint16(40000+stream), 5201, byte(sequence))
			packets = append(packets, packet)
			lane := int(innerFlowHash(packet) % queueCount)
			want[lane] = append(want[lane], packet)
		}
	}
	m.DeliverInboundBatch(framed(packets...), DefaultMTU, nil)

	active := 0
	for lane, expected := range want {
		if len(expected) == 0 {
			continue
		}
		active++
		select {
		case got := <-recorders[lane].writes:
			if len(got.packets) != len(expected) {
				t.Fatalf("queue %d wrote %d packets, want %d", lane, len(got.packets), len(expected))
			}
			for i := range expected {
				if !bytes.Equal(got.packets[i], expected[i]) {
					t.Fatalf("queue %d packet %d did not preserve flow order", lane, i)
				}
			}
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for queue %d", lane)
		}
	}
	if active < queueCount/2 {
		t.Fatalf("16 TCP streams used only %d/%d queues", active, queueCount)
	}

	forward := ipv6TCPPacket(40000, 5201, 0)
	reverse := ipv6TCPPacket(5201, 40000, 0)
	copy(reverse[8:24], forward[24:40])
	copy(reverse[24:40], forward[8:24])
	if innerFlowHash(forward)%queueCount != innerFlowHash(reverse)%queueCount {
		t.Fatal("opposite directions of one flow mapped to different queues")
	}
}

func TestCollectReadyInboundCoalescesQueuedDeliveries(t *testing.T) {
	queue := make(chan inboundWriteBatch, 2)
	queue <- inboundWriteBatch{frames: [][]byte{{2}, {3}}}
	queue <- inboundWriteBatch{frames: [][]byte{{4}}}

	got := collectReadyInbound(
		inboundWriteBatch{frames: [][]byte{{1}}},
		queue,
		make([][]byte, 0, inboundWriteBatchSize),
	)
	if len(got) != 4 {
		t.Fatalf("collected %d packets, want 4", len(got))
	}
	for i, packet := range got {
		if len(packet) != 1 || packet[0] != byte(i+1) {
			t.Fatalf("packet %d = %v, want [%d]", i, packet, i+1)
		}
	}
}
