// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

package netstack

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/logtest"
	"ranet3.com/pkgs/wireguard/tun"
)

// Both halves of Place.OnFailure: a packet the transport loses is reported,
// and one it carries is not.
func TestOnFailureReportsAPacketLostAfterItWasQueued(t *testing.T) {
	for name, fails := range map[string]bool{
		"the transport fails": true,
		"the transport works": false,
	} {
		t.Run(name, func(t *testing.T) {
			peer := NewPeer("peer",
				func(int) (BatchSealer, error) { return passThrough, nil }, func([][]byte) error {
					if fails {
						return errors.New("sendto: network is unreachable")
					}
					return nil
				}, nil)
			defer peer.Close()
			place, err := peer.ReserveRawOrDrop([]byte("packet"), 41)
			if err != nil {
				t.Fatal(err)
			}
			lost := make(chan error, 1)
			place.OnFailure(func(err error) { lost <- err })
			if err := place.Send(); err != nil {
				t.Fatalf("send: %v", err)
			}
			select {
			case err := <-lost:
				if !fails {
					t.Errorf("a packet that reached the wire was reported lost: %v", err)
				}
				if err == nil {
					t.Error("the callback ran with no error")
				}
			case <-time.After(500 * time.Millisecond):
				if fails {
					t.Error("a packet lost in the transport was never reported back")
				}
			}
		})
	}
}

// A peer that closes before its sender takes the batch loses it too, and the
// caller has to hear about that the same way.
func TestOnFailureReportsWhatAClosedPeerDropped(t *testing.T) {
	peer := NewPeer("peer",
		func(int) (BatchSealer, error) { return passThrough, nil }, func([][]byte) error { return nil }, nil)
	place, err := peer.ReserveRawOrDrop([]byte("packet"), 41)
	if err != nil {
		t.Fatal(err)
	}
	lost := make(chan error, 1)
	place.OnFailure(func(err error) { lost <- err })
	// Closed with the place taken and not yet sent, which is the teardown
	// window: the batch holds a ticket the sender is waiting on, and nothing
	// will transmit it.
	peer.Close()
	if err := place.Send(); err == nil {
		t.Error("sending into a closed peer reported success")
	}
	select {
	case <-lost:
	case <-time.After(2 * time.Second):
		t.Error("a packet a closing peer gave back was never reported to its caller")
	}
}

// A reader that has handed its batch to the workers has also handed them every
// ticket it reserved, and a ticket the sender never sees stalls that peer for
// good. Close therefore has to drain the queue rather than abandon it, and has
// to return while a peer is still open and still behind.
func TestMeshCloseDrainsQueuedTickets(t *testing.T) {
	peer := NewPeer("peer", func(int) (BatchSealer, error) {
		return func(raw [][]byte, _ []byte, _ [][]byte) ([][]byte, error) { return [][]byte{bytes.Clone(raw[0])}, nil }, nil
	}, func([][]byte) error { return nil }, nil)
	defer peer.Close()
	// Keep the sender waiting on its first ticket, with the whole budget
	// spoken for, so the dispatch below reserves nothing and Close still has a
	// peer that will never finish.
	peer.reserveBatch(1, peerDataBudget)
	m := &Mesh{closed: make(chan struct{}), outboundJobs: make(chan *outboundBatch, 4), outboundFree: make(chan *outboundBatch, 4)}
	m.outboundWorkerWG.Add(1)
	go m.outboundWorker()
	m.outboundReaderWG.Go(func() {
		m.dispatchOutbound(&outboundBatch{
			n: 1, packets: [][]byte{{1}}, headers: []byte{0}, peers: []*Peer{peer},
			peerOrder: []*Peer{peer}, shares: map[*Peer]outboundShare{peer: {count: 1, bytes: 1}}, batches: make(map[*Peer]*peerBatch),
		})
	})
	done := make(chan struct{})
	go func() { m.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		peer.Close()
		<-done
		t.Fatal("Mesh.Close did not return while a peer was still behind")
	}
	if len(m.outboundJobs) != 0 {
		t.Fatal("Mesh.Close abandoned queued transmission tickets")
	}
}

// closeHold is how long a test watches Close to see that it is still waiting
const closeHold = 100 * time.Millisecond

// heldDevice holds every write until the test lets it go
// and says when one has started
type heldDevice struct {
	recordingDevice
	entered chan struct{}
	release chan struct{}
}

func (d *heldDevice) Write(bufs [][]byte, _ int) (int, error) {
	d.entered <- struct{}{}
	<-d.release
	return len(bufs), nil
}

// an inbound writer can be inside a write when Close comes
// and Close has to wait for it, or the writer outlives the mesh
// writing into a device Close has already closed
func TestCloseWaitsForInboundWriters(t *testing.T) {
	dev := &heldDevice{entered: make(chan struct{}, 2), release: make(chan struct{})}
	// two lanes, so the writers run, both on the one device so either lane is held
	m := ownEverything(&Mesh{closed: make(chan struct{})})
	m.setDevice(lanesOf(dev, dev))
	m.startInboundWriters()
	m.DeliverInboundBatch(framed(ipv6TCPPacket(40000, 5201, 1)), DefaultMTU, nil)
	select {
	case <-dev.entered:
	case <-time.After(deliveryTimeout):
		close(dev.release)
		t.Fatal("no writer took the delivered packet, so this proves nothing")
	}

	closed := make(chan struct{})
	go func() { m.Close(); close(closed) }()
	select {
	case <-closed:
		close(dev.release)
		t.Fatal("Close returned while a writer was still inside a write to the device")
	case <-time.After(closeHold):
	}
	close(dev.release)
	select {
	case <-closed:
	case <-time.After(deliveryTimeout):
		t.Fatal("Close did not return once the write it waited for had finished")
	}
}

// closingDevice accepts writes until its Close and refuses every one after it, as a closed descriptor does
// late counts the writes that began after the test saw Mesh.Close return
type closingDevice struct {
	recordingDevice
	mu         sync.Mutex
	closed     bool
	accepted   int
	meshClosed atomic.Bool
	late       atomic.Int64
}

func (d *closingDevice) Write(bufs [][]byte, _ int) (int, error) {
	if d.meshClosed.Load() {
		d.late.Add(1)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return 0, os.ErrClosed
	}
	d.accepted++
	return len(bufs), nil
}

func (d *closingDevice) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	return nil
}

func (d *closingDevice) written() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.accepted
}

// deliveries from many sessions keep coming while the mesh closes
// every one of them returns and so does Close
// with one queue a delivery still running writes only into the closed device
// with several the writers are gone once Close returns, and nothing writes to the device after it
func TestDeliveriesRacingCloseAllReturn(t *testing.T) {
	const sessions, deliveries = 8, 4000
	for _, lanes := range []int{1, 4} {
		t.Run(fmt.Sprintf("%d lanes", lanes), func(t *testing.T) {
			dev := &closingDevice{}
			devs := make([]tun.Device, lanes)
			for i := range devs {
				devs[i] = dev
			}
			m := ownEverything(&Mesh{closed: make(chan struct{})})
			m.setDevice(lanesOf(devs...))
			m.startInboundWriters()
			var delivering sync.WaitGroup
			for session := range sessions {
				delivering.Go(func() {
					for i := range deliveries {
						m.DeliverInboundBatch(framed(ipv6TCPPacket(uint16(40000+session), uint16(i), 1)), DefaultMTU, nil)
					}
				})
			}
			waitUntil(t, "a delivery to reach the device before Close", func() bool { return dev.written() > 0 })

			closed := make(chan struct{})
			go func() { m.Close(); dev.meshClosed.Store(true); close(closed) }()
			select {
			case <-closed:
			case <-time.After(deliveryTimeout):
				t.Fatal("Close did not return while deliveries were running")
			}
			returned := make(chan struct{})
			go func() { delivering.Wait(); close(returned) }()
			select {
			case <-returned:
			case <-time.After(deliveryTimeout):
				t.Fatal("a delivery never returned after the mesh closed")
			}
			if late := dev.late.Load(); lanes > 1 && late != 0 {
				t.Errorf("%d writes reached the device after Close returned", late)
			}
		})
	}
}

func TestSingleQueueInboundSplitsLargeBatches(t *testing.T) {
	dev := &recordingDevice{writes: make(chan recordedWrite, 2)}
	m := &Mesh{closed: make(chan struct{})}
	m.setDevice(dev)
	packets := make([][]byte, inboundWriteBatchSize+1)
	for i := range packets {
		packets[i] = []byte{byte(i)}
	}
	m.writeHost(framed(packets...))
	if len(dev.writes) != 2 {
		t.Fatalf("got %d TUN writes, want two bounded batches", len(dev.writes))
	}
	first, second := <-dev.writes, <-dev.writes
	if len(first.packets) != inboundWriteBatchSize || len(second.packets) != 1 {
		t.Fatal("single-queue delivery exceeded the TUN GRO table capacity")
	}
	if second.packets[0][0] != byte(inboundWriteBatchSize) {
		t.Fatal("split delivery changed packet order")
	}
}

// One peer whose transport is behind must not stop the mesh forwarding to any
// other. A batch read off one queue carries whichever destinations the kernel
// hashed onto it, so a reservation that waits there puts every other peer of
// that read, and every read the reader has not taken yet, behind the slowest
// peer on the mesh.
//
// the bound is no wait at all
// every read reaches the other peer while the stuck transport has not returned once
// through more reads than the stuck peer's budget holds
// and the stuck peer drops exactly what its budget had no room for
func TestCongestedPeerDoesNotStallOthers(t *testing.T) {
	sealer := func(raw [][]byte, _ []byte, _ [][]byte) ([][]byte, error) {
		sealed := make([][]byte, len(raw))
		for i := range raw {
			sealed[i] = bytes.Clone(raw[i])
		}
		return sealed, nil
	}
	reserve := func(int) (BatchSealer, error) { return sealer, nil }
	release := make(chan struct{})
	var returned atomic.Int64
	stuck := NewPeer("stuck", reserve, func([][]byte) error {
		<-release
		returned.Add(1)
		return nil
	}, nil)
	var transmitted atomic.Int64
	healthy := NewPeer("healthy", reserve, func(packets [][]byte) error {
		transmitted.Add(int64(len(packets)))
		return nil
	}, nil)

	// each read stands for packets of size bytes, though it carries one byte of each
	const perRead, size = 64, 1400
	const reads = peerDataBudget/(perRead*size) + 4
	m := &Mesh{closed: make(chan struct{}), outboundJobs: make(chan *outboundBatch, 4), outboundFree: make(chan *outboundBatch, reads)}
	m.outboundWorkerWG.Add(2)
	go m.outboundWorker()
	go m.outboundWorker()
	dispatched := make(chan struct{})
	// the transport lets go first, so a dispatch that waited on it can finish before the queue closes
	t.Cleanup(func() {
		close(release)
		<-dispatched
		m.Close()
		stuck.Close()
		healthy.Close()
	})

	go func() {
		defer close(dispatched)
		for range reads {
			b := &outboundBatch{shares: map[*Peer]outboundShare{stuck: {count: perRead, bytes: perRead * size}, healthy: {count: perRead, bytes: perRead * size}},
				batches: make(map[*Peer]*peerBatch), peerOrder: []*Peer{stuck, healthy}}
			for i := range 2 * perRead {
				b.packets = append(b.packets, []byte{byte(i)})
				b.headers = append(b.headers, 0)
				b.peers = append(b.peers, []*Peer{stuck, healthy}[i%2])
			}
			b.n = len(b.packets)
			m.dispatchOutbound(b)
		}
	}()
	select {
	case <-dispatched:
	case <-time.After(deliveryTimeout):
		t.Fatal("the congested peer held up the reader that feeds the other peer")
	}
	waitUntil(t, "the peer that was not congested to send every packet it was given", func() bool { return transmitted.Load() >= reads*perRead })
	if got := returned.Load(); got != 0 {
		t.Fatalf("the stuck transport returned %d times, so this proves nothing", got)
	}
	if got := stuck.Dropped(); got != reads*perRead-peerDataBudget/size {
		t.Errorf("the congested peer counted %d dropped packets, want the %d its budget had no room for", got, reads*perRead-peerDataBudget/size)
	}
	if got := healthy.Dropped(); got != 0 {
		t.Errorf("the peer that was not congested counted %d dropped packets, want 0", got)
	}
}

// goneDevice answers its first working reads with a packet each and every read after them with err
// as a queue of a tun whose link is gone does
type goneDevice struct {
	recordingDevice
	reads   atomic.Int64
	working int64
	err     error
}

func (d *goneDevice) Read(slab []byte, packets []tun.ReadPacket) (int, error) {
	if d.reads.Add(1) > d.working {
		return 0, d.err
	}
	return layOut(slab, packets, [][]byte{{0x60}}), nil
}

// a read error other than closure is the device gone, which nothing in the process can make again
// so every queue's reader stops rather than reads on, and gives its batch back
// and the failure is reported once, whichever queue saw it first, for the daemon to shut down on
func TestTunReadFailureIsReportedAndGivesTheBatchBack(t *testing.T) {
	var logs bytes.Buffer
	logtest.SetDefault(t, slog.New(slog.NewTextHandler(&logs, nil)))
	bus := events.New()

	const queues, working = 4, 2
	lanes := make([]*goneDevice, queues)
	devices := make([]tun.Device, queues)
	for i := range lanes {
		lanes[i] = &goneDevice{working: working, err: &os.PathError{Op: "read", Path: "/dev/net/tun", Err: syscall.EFAULT}}
		devices[i] = lanes[i]
	}
	m := &Mesh{Name: "test0", closed: make(chan struct{}), Routes: NewRouteTable(),
		outboundFree: make(chan *outboundBatch, 2*queues), events: bus.Emit}
	m.setDevice(lanesOf(devices...))
	for range cap(m.outboundFree) {
		m.outboundFree <- newOutboundBatch(4)
	}
	for _, queue := range m.queues {
		m.outboundReaderWG.Add(1)
		go m.outboundReader(queue)
	}
	stopped := make(chan struct{})
	go func() { m.outboundReaderWG.Wait(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(deliveryTimeout):
		t.Fatal("the readers did not all return after their device was gone")
	}
	select {
	case <-m.Failed():
	default:
		t.Fatal("a device gone under an open mesh was not reported")
	}
	for i, lane := range lanes {
		if got := lane.reads.Load(); got != working+1 {
			t.Errorf("queue %d was read %d times, want the %d up to the failure", i, got, working+1)
		}
	}
	if len(m.outboundFree) != cap(m.outboundFree) {
		t.Errorf("the readers kept %d of their batches", cap(m.outboundFree)-len(m.outboundFree))
	}
	if got := bytes.Count(logs.Bytes(), []byte("netstack tun failed")); got != 1 {
		t.Errorf("%d queues failing wrote %d error lines, want 1: %s", queues, got, logs.Bytes())
	}
	got := tunEvents(bus)
	if len(got) != 1 || got[0].Kind != "netstack.tun.failed" || got[0].Attrs["interface"] != "test0" {
		t.Errorf("%d queues failing recorded %+v, want one netstack.tun.failed on test0", queues, got)
	}
}

// enteringDevice says each time a reader enters Read
type enteringDevice struct {
	scriptedDevice
	entered chan struct{}
}

func (d *enteringDevice) Read(slab []byte, packets []tun.ReadPacket) (int, error) {
	d.entered <- struct{}{}
	return d.scriptedDevice.Read(slab, packets)
}

// Close ending every reader inside its read is the ordinary closure and reports nothing
func TestTunClosedByCloseReportsNothing(t *testing.T) {
	const lanes = 2
	var logs bytes.Buffer
	logtest.SetDefault(t, slog.New(slog.NewTextHandler(&logs, nil)))
	bus := events.New()
	dev := &enteringDevice{scriptedDevice{reads: make(chan scriptedRead), closed: make(chan struct{})}, make(chan struct{}, lanes)}
	m := &Mesh{Name: "test0", Routes: NewRouteTable(), closed: make(chan struct{}), events: bus.Emit}
	m.setDevice(lanesOf(dev, dev))
	m.startOutboundPipeline()
	for range lanes {
		select {
		case <-dev.entered:
		case <-time.After(deliveryTimeout):
			m.Close()
			t.Fatal("a reader never entered its read, so this proves nothing")
		}
	}
	closed := make(chan struct{})
	go func() { m.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(deliveryTimeout):
		t.Fatal("Close did not return")
	}
	select {
	case <-m.Failed():
		t.Error("Close was reported as the device gone")
	default:
	}
	if bytes.Contains(logs.Bytes(), []byte("netstack tun failed")) {
		t.Errorf("Close wrote an error line: %s", logs.Bytes())
	}
	if got := tunEvents(bus); len(got) != 0 {
		t.Errorf("Close recorded %+v", got)
	}
}

// Close has to return whether or not the sender does. A send already inside
// the socket is not interrupted by closing the logical Mux (that checks its
// done channel on entry and then loops on the hub's bind, which only Hub.Close
// closes and which sets no write deadline), so an unbounded wait here makes
// one session's teardown wait on a socket nobody is going to unblock, and the
// client's peer group never drains behind it.
func TestClosingAPeerDoesNotWaitOnTheTransportForever(t *testing.T) {
	stuck, entered := make(chan struct{}), make(chan struct{})
	defer close(stuck)
	p := NewPeer("stuck",
		func(int) (BatchSealer, error) { return passThrough, nil },
		func([][]byte) error { close(entered); <-stuck; return nil }, nil)
	p.closeGrace = 100 * time.Millisecond

	place, err := p.ReserveRawOrDrop([]byte("one packet"), 4)
	if err != nil {
		t.Fatal(err)
	}
	if err := place.Send(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the sender never reached the transport, so this proves nothing")
	}

	done := make(chan struct{})
	go func() { p.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close waited on a sender stuck in the transport, so a session teardown holds the whole peer group")
	}
}
