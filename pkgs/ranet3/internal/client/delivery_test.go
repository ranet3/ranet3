// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/esp"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/packet"
	"ranet3.com/pkgs/ranet3/transport"
	"ranet3.com/pkgs/wireguard/tun"
)

// deliveryWait is how long a delivery test waits for a lane's write, an emit or a receive's end it expects
const deliveryWait = 5 * time.Second

// countedHold is a hold that counts its references, one its caller's from the start, as a session's delivery does
type countedHold struct{ refs atomic.Int32 }

func newCountedHold() *countedHold {
	h := &countedHold{}
	h.refs.Store(1)
	return h
}

func (h *countedHold) Retain()  { h.refs.Add(1) }
func (h *countedHold) Release() { h.refs.Add(-1) }

// pausedTun is a tun of two queues whose every write says it has started and waits for resume, then records each packet it was handed, copied out
type pausedTun struct {
	entered chan struct{}
	resume  chan struct{}
	mu      sync.Mutex
	packets [][]byte
}

func (d *pausedTun) File() *os.File                             { return nil }
func (d *pausedTun) Read([]byte, []tun.ReadPacket) (int, error) { return 0, os.ErrClosed }
func (d *pausedTun) MTU() (int, error)                          { return netstack.DefaultMTU, nil }
func (d *pausedTun) Name() (string, error)                      { return "ranet0", nil }
func (d *pausedTun) Events() <-chan tun.Event                   { return nil }
func (d *pausedTun) Close() error                               { return nil }
func (d *pausedTun) BatchSize() int                             { return 128 }
func (d *pausedTun) Queues() []tun.Queue                        { return []tun.Queue{d, d} }

func (d *pausedTun) Write(bufs [][]byte, offset int) (int, error) {
	d.entered <- struct{}{}
	<-d.resume
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, buf := range bufs {
		d.packets = append(d.packets, bytes.Clone(buf[offset:]))
	}
	return len(bufs), nil
}

func (d *pausedTun) WriteTo(_ int, bufs [][]byte, offset int) (int, error) {
	return d.Write(bufs, offset)
}

// written is every packet the tun recorded so far
func (d *pausedTun) written() [][]byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([][]byte(nil), d.packets...)
}

// packetIndex is the index receivedBatches gave a packet, or -1 once the packet's buffer was overwritten
func packetIndex(raw []byte) int {
	if binary.BigEndian.Uint32(raw) != receivedSPI {
		return -1
	}
	return int(raw[4])
}

// emitted runs the emitter over completed and hands each hold it emits to holds, retained as a lane of the mesh retains one, until completed closes
func emitted(completed chan *inboundBatch, holds chan<- netstack.Hold) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		emitInboundBatches(completed, make(chan *inboundBatch, cap(completed)), func(_ []inboundDecrypted, _ []inboundECN, hold netstack.Hold) {
			hold.Retain()
			holds <- hold
		})
	}()
	return done
}

// batches the emitter merges into one emit go in one delivery, which holds every one of them
// so a holder in the mesh that retains it keeps each batch's storage after the emitter lets go, and its release gives back both
func TestMergedDeliveryHoldsEveryBatchToItsEnd(t *testing.T) {
	received := receivedBatches(t, 2)
	packets := [][]byte{received[0].Packets()[0], received[1].Packets()[0]}
	completed, holds := make(chan *inboundBatch, 2), make(chan netstack.Hold, 2)
	done := emitted(completed, holds)
	// the second completes first, so the emitter holds it until the first comes and emits both together
	completed <- &inboundBatch{ticket: 1, results: []inboundDecrypted{{Err: errors.New("second")}}, received: received[1]}
	completed <- &inboundBatch{ticket: 0, results: []inboundDecrypted{{Err: errors.New("first")}}, received: received[0]}
	close(completed)
	<-done
	if len(holds) != 1 {
		t.Fatalf("the emitter handed %d holds, want one for both batches it merged", len(holds))
	}
	hold := <-holds
	if d, ok := hold.(*delivery); !ok || len(d.batches) != 2 {
		t.Fatalf("the emit was handed %#v, want a delivery of both batches", hold)
	}
	for i, packet := range packets {
		if got := packetIndex(packet); got != i {
			t.Errorf("batch %d's packet reads %d once the emitter let go of the delivery a holder keeps, want its own", i, got)
		}
	}
	hold.Release()
	for i, packet := range packets {
		if got := packetIndex(packet); got != -1 {
			t.Errorf("batch %d's packet still reads %d once the delivery's last holder let go, so its batch was never released", i, got)
		}
	}
}

// a batch the emitter still holds out of order when completed closes is released then, so a session's end gives back its storage
func TestEmitterReleasesItsPendingBatchesAtItsEnd(t *testing.T) {
	received := receivedBatches(t, 2)
	t.Cleanup(received[0].Release)
	packet := received[1].Packets()[0]
	completed, holds := make(chan *inboundBatch, 2), make(chan netstack.Hold, 2)
	done := emitted(completed, holds)
	completed <- &inboundBatch{ticket: 1, results: []inboundDecrypted{{Err: errors.New("second")}}, received: received[1]}
	close(completed)
	<-done
	if len(holds) != 0 {
		t.Fatal("the emitter emitted a batch whose turn never came")
	}
	if got := packetIndex(packet); got != -1 {
		t.Errorf("the pending batch's packet still reads %d once the emitter ended, so it was never released", got)
	}
}

// a session's emit hands its hold through the mesh's delivery to the writer lane of a multiqueue tun that takes the packet
// so the lane keeps a reference while it writes, after the emitter gave back its own, and gives it back once its write has returned
func TestSessionEmitHandsItsHoldToTheLane(t *testing.T) {
	c := writable(t)
	dev := &pausedTun{entered: make(chan struct{}, 1), resume: make(chan struct{})}
	resume := sync.OnceFunc(func() { close(dev.resume) })
	c.Mesh = netstack.NewOnDevice(dev)
	t.Cleanup(func() {
		resume()
		c.Mesh.Close()
	})
	c.Mesh.Routes.Set(netip.Prefix{}, netip.MustParsePrefix("198.51.100.1/32"), netstack.Local)
	session := newECNSession(t, c, "example/gateway:0@0", tunnelChild(1))
	sent := ecnPacket(4, packet.NotECT, 1)
	sealed, err := session.remote.Seal(sent, esp.NextHeaderIPv4)
	if err != nil {
		t.Fatal(err)
	}
	hold := newCountedHold()
	session.emit(session.tunnel.decryptBatch([][]byte{sealed}, nil), nil, hold)
	// the emitter's own, given back once emit returns
	hold.Release()
	select {
	case <-dev.entered:
	case <-time.After(deliveryWait):
		t.Fatal("no lane wrote the packet the session delivered")
	}
	if got := hold.refs.Load(); got != 1 {
		t.Fatalf("the hold counts %d references while the lane writes, want the lane's", got)
	}
	resume()
	waitFor(t, deliveryWait, "the lane to give back its reference once its write returned", func() bool { return hold.refs.Load() == 0 })
	if got := dev.written(); len(got) != 1 || !bytes.Equal(got[0], sent) {
		t.Errorf("the tun was written %x, want the packet sent", got)
	}
}

// on one worker the receive emits inline, and the delivery it hands emit holds the batch for a holder that retains it past emit's return
// so the next datagram is read into a fresh buffer, and the frame that holder reads later is still the packet sent
func TestInlineReceiveHoldsTheBatchPastEmit(t *testing.T) {
	child := tunnelChild(1)
	network := transport.NewMemoryNetwork()
	hub, err := network.NewHub()
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	loopback := net.IPv4(127, 0, 0, 1)
	sender, err := network.ListenUDP(loopback)
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	mux, err := hub.NewMux(loopback, sender.LocalAddr().(*net.UDPAddr).Port)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	if err := mux.RegisterESP(child.LocalSPI); err != nil {
		t.Fatal(err)
	}
	tunnel := &tunnel{replayWindow: 4096}
	if err := tunnel.install(child); err != nil {
		t.Fatal(err)
	}
	type emitted struct {
		frame []byte
		hold  netstack.Hold
		err   error
	}
	emits := make(chan emitted, 2)
	done := make(chan error, 1)
	go func() {
		done <- receiveESP(mux, 1, tunnel.decryptBatch, func(results []inboundDecrypted, _ []inboundECN, hold netstack.Hold) {
			esp.CommitBatch(results)
			frame, _, err := results[0].Frame(netstack.TUNHeadroom)
			// retained as a lane retains it, where emit is handed a hold
			if hold != nil {
				hold.Retain()
			}
			emits <- emitted{frame, hold, err}
		})
	}()

	remote := remoteSA(t, child)
	destination := &net.UDPAddr{IP: loopback, Port: hub.LocalAddr().(*net.UDPAddr).Port}
	receive := func(id uint32) emitted {
		if _, err := sender.WriteToUDP(sealTestPacket(t, remote, id), destination); err != nil {
			t.Fatal(err)
		}
		select {
		case e := <-emits:
			if e.err != nil {
				t.Fatalf("packet %d does not open inside emit, its buffer let go of before emit read it: %v", id, e.err)
			}
			return e
		case <-time.After(deliveryWait):
			t.Fatalf("packet %d was never emitted", id)
			return emitted{}
		}
	}
	first := receive(0)
	// sent once the first was emitted, so it is read into the first's buffer unless the first's batch still holds it
	second := receive(1)
	if got := binary.BigEndian.Uint32(first.frame[netstack.TUNHeadroom+20:]); got != 0 {
		t.Errorf("the frame of packet 0 reads packet %d once the next datagram was read, so its buffer was read into while its holder kept it", got)
	}
	for _, e := range []emitted{first, second} {
		if e.hold != nil {
			e.hold.Release()
		}
	}
	_ = mux.Close()
	select {
	case <-done:
	case <-time.After(deliveryWait):
		t.Fatal("the receive did not end once its mux closed")
	}
}
