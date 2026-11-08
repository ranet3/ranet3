// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux

package client

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/esp"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/transport"
	"ranet3.com/pkgs/wireguard/tun"
)

const (
	// pathLanes is the queues of the tun the whole path's mesh writes to
	pathLanes = 3
	// pathWorkers is the decryption workers of the whole path's receive
	pathWorkers = 4
	// pathMostPackets is the most packets one case of the whole path sends
	pathMostPackets = 300
	// pathBudget is how long a case of the whole path waits for its packets to reach the tun and for its receive to end
	pathBudget = 10 * time.Second
	// pathPoll is how often a case of the whole path looks at what reached the tun while it waits
	pathPoll = time.Millisecond
)

// delayedTun is a tun of pathLanes queues whose every write waits the next of its delays and then records each packet it was handed, copied out
type delayedTun struct {
	delays  []time.Duration
	next    atomic.Int64
	mu      sync.Mutex
	packets [][]byte
}

func (d *delayedTun) File() *os.File                             { return nil }
func (d *delayedTun) Read([]byte, []tun.ReadPacket) (int, error) { return 0, os.ErrClosed }
func (d *delayedTun) MTU() (int, error)                          { return netstack.DefaultMTU, nil }
func (d *delayedTun) Name() (string, error)                      { return "ranet0", nil }
func (d *delayedTun) Events() <-chan tun.Event                   { return nil }
func (d *delayedTun) Close() error                               { return nil }
func (d *delayedTun) BatchSize() int                             { return 128 }

func (d *delayedTun) Write(bufs [][]byte, offset int) (int, error) {
	time.Sleep(d.delays[int(d.next.Add(1))%len(d.delays)])
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, buf := range bufs {
		d.packets = append(d.packets, bytes.Clone(buf[offset:]))
	}
	return len(bufs), nil
}

func (d *delayedTun) Queues() []tun.Queue {
	queues := make([]tun.Queue, pathLanes)
	for i := range queues {
		queues[i] = d
	}
	return queues
}

func (d *delayedTun) WriteTo(_ int, bufs [][]byte, offset int) (int, error) {
	return d.Write(bufs, offset)
}

// written is every packet the tun recorded so far
func (d *delayedTun) written() [][]byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([][]byte(nil), d.packets...)
}

// pathPacket is inner IPv4 packet id of size bytes, its source the id's own so the packets spread over the lanes, its payload the id and then bytes counting up from it
func pathPacket(id uint32, size int) []byte {
	raw := make([]byte, size)
	raw[0] = 0x45
	binary.BigEndian.PutUint16(raw[2:], uint16(size))
	copy(raw[12:16], []byte{198, 51, 100, byte(id)})
	copy(raw[16:20], []byte{192, 0, 2, 1})
	binary.BigEndian.PutUint32(raw[20:24], id)
	for i := 24; i < size; i++ {
		raw[i] = byte(id) + byte(i)
	}
	return raw
}

// the whole receive path, from a memory hub's pool through four workers and the emitter to a mesh's three lanes, writes each packet as it was sent
// though each lane writes after the emitter let go of its delivery, at a delay drawn for each write, and every block goes back to the pool overwritten once its last holder lets go
// so a block read into again, or released, while a lane still has a frame in it reaches the tun as bytes no packet was sent with, and the race detector sees the memory hub's write into it
func TestReceivedPacketsReachTheTunAsSent(t *testing.T) {
	child := tunnelChild(1)
	pbt.Check(t, func(ht *hegel.T) {
		sizes := make([]int, hegel.Draw(ht, pbt.Spanning(1, pathMostPackets)))
		for i := range sizes {
			sizes[i] = hegel.Draw(ht, hegel.SampledFrom([]int{24, 200, 1400}))
		}
		delays := make([]time.Duration, hegel.Draw(ht, pbt.Spanning(1, 8)))
		for i := range delays {
			delays[i] = hegel.Draw(ht, hegel.SampledFrom([]time.Duration{0, 20 * time.Microsecond, 300 * time.Microsecond}))
		}

		network := transport.NewMemoryNetwork()
		hub, err := network.NewHub()
		if err != nil {
			ht.Fatal(err)
		}
		defer hub.Close()
		loopback := net.IPv4(127, 0, 0, 1)
		sender, err := network.ListenUDP(loopback)
		if err != nil {
			ht.Fatal(err)
		}
		defer sender.Close()
		mux, err := hub.NewMux(loopback, sender.LocalAddr().(*net.UDPAddr).Port)
		if err != nil {
			ht.Fatal(err)
		}
		defer mux.Close()
		if err := mux.RegisterESP(child.LocalSPI); err != nil {
			ht.Fatal(err)
		}
		tunnel := &tunnel{replayWindow: 4096}
		if err := tunnel.install(child); err != nil {
			ht.Fatal(err)
		}
		dev := &delayedTun{delays: delays}
		mesh := netstack.NewOnDevice(dev)
		defer mesh.Close()

		var refused atomic.Int64
		done := make(chan error, 1)
		go func() {
			done <- receiveESP(mux, pathWorkers, tunnel.decryptBatch, func(results []inboundDecrypted, _ []inboundECN, hold netstack.Hold) {
				esp.CommitBatch(results)
				frames := make([][]byte, 0, len(results))
				for i := range results {
					frame, _, err := results[i].Frame(netstack.TUNHeadroom)
					if err != nil {
						refused.Add(1)
						continue
					}
					frames = append(frames, frame)
				}
				mesh.WriteHost(frames, hold)
			})
		}()

		remote := remoteSA(t, child)
		destination := &net.UDPAddr{IP: loopback, Port: hub.LocalAddr().(*net.UDPAddr).Port}
		sent := make(map[uint32][]byte, len(sizes))
		for id, size := range sizes {
			inner := pathPacket(uint32(id), size)
			sent[uint32(id)] = inner
			sealed, err := remote.Seal(inner, esp.NextHeaderIPv4)
			if err != nil {
				ht.Fatal(err)
			}
			if _, err := sender.WriteToUDP(sealed, destination); err != nil {
				ht.Fatal(err)
			}
		}
		deadline := time.Now().Add(pathBudget)
		for len(dev.written())+int(hub.Dropped())+int(refused.Load()) < len(sizes) {
			if time.Now().After(deadline) {
				ht.Fatalf("%d of %d packets reached the tun, the hub dropped %d and %d failed to open", len(dev.written()), len(sizes), hub.Dropped(), refused.Load())
			}
			time.Sleep(pathPoll)
		}
		_ = mux.Close()
		select {
		case <-done:
		case <-time.After(pathBudget):
			ht.Fatal("the receive did not end once its mux closed")
		}
		mesh.Close()

		if n := refused.Load(); n != 0 {
			ht.Fatalf("%d packets failed to open", n)
		}
		seen := make(map[uint32]bool, len(sizes))
		for _, packet := range dev.written() {
			if len(packet) < 24 {
				ht.Fatalf("the tun was written %x, shorter than any packet sent", packet)
			}
			id := binary.BigEndian.Uint32(packet[20:24])
			want, ok := sent[id]
			if !ok || !bytes.Equal(packet, want) {
				ht.Fatalf("the tun was written %x, which matches no packet sent", packet)
			}
			if seen[id] {
				ht.Fatalf("packet %d reached the tun twice", id)
			}
			seen[id] = true
		}
	})
}
