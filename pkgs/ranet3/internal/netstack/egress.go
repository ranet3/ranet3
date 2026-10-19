// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"ranet3.com/pkgs/ranet3/srv6"
	"ranet3.com/pkgs/wireguard/tun"
)

// egressMu orders SetEgress against Close, and the dataplane reads egress
type egressSlot struct {
	egressMu sync.Mutex
	egress   atomic.Pointer[egressDevice]
	// egressReady holds egressReady4 and egressReady6 for the families the translator reported ready, none at first
	egressReady atomic.Uint32
}

const (
	egressReady4 uint32 = 1 << iota
	egressReady6
)

// SetEgressReady tells the mesh which families the egress device carries out
// translated, from the translator's last pass, and an egress result of a
// family that is not ready is dropped and counted NotReady
func (m *Mesh) SetEgressReady(v4, v6 bool) {
	var ready uint32
	if v4 {
		ready |= egressReady4
	}
	if v6 {
		ready |= egressReady6
	}
	m.egressReady.Store(ready)
}

// egressReadyFor is the bit of egressReady that family, an srv6 next header, needs
func egressReadyFor(family uint8) uint32 {
	if family == srv6.NextHeaderIPv4 {
		return egressReady4
	}
	return egressReady6
}

// egressDevice is an installed egress device and the drains reading its queues
// closing is closed before the device is, so an error after it is the close
type egressDevice struct {
	dev     tun.Device
	closing chan struct{}
	drains  sync.WaitGroup
}

// SetEgress installs dev as the egress device, or nil for none, while sessions deliver
// dev takes frames as the mesh tun does, TUNHeadroom bytes then the packet
// the mesh owns dev from the call, and closes the device it replaces and waits for that device's drains before it returns
// a mesh that has closed closes dev and installs nothing
func (m *Mesh) SetEgress(dev tun.Device) {
	m.egressMu.Lock()
	defer m.egressMu.Unlock()
	var next *egressDevice
	if dev != nil {
		select {
		case <-m.closed:
			_ = dev.Close()
			return
		default:
		}
		next = &egressDevice{dev: dev, closing: make(chan struct{})}
		for _, queue := range tun.QueuesOf(dev) {
			next.drains.Go(func() { m.drain(next, queue) })
		}
	}
	m.egress.Swap(next).retire()
}

func (e *egressDevice) retire() {
	if e == nil {
		return
	}
	close(e.closing)
	_ = e.dev.Close()
	e.drains.Wait()
}

// the device's Write reports bytes on linux rather than packets, so a write that fails counts every frame it held
func (m *Mesh) writeEgress(frames [][]byte) {
	if len(frames) == 0 {
		return
	}
	e := m.egress.Load()
	if e == nil {
		m.segmentsNotReady.Add(uint64(len(frames)))
		return
	}
	for len(frames) != 0 {
		write := frames[:min(len(frames), inboundWriteBatchSize)]
		frames = frames[len(write):]
		if _, err := e.dev.Write(write, TUNHeadroom); err != nil {
			select {
			case <-e.closing:
				m.segmentsNotReady.Add(uint64(len(write)))
			default:
				m.segmentsDropped.Add(uint64(len(write)))
				m.reportSegmentDrop("the egress device refused a write", "packets", len(write), "err", err)
			}
			continue
		}
		m.segmentsEgressed.Add(uint64(len(write)))
	}
}

// every route into the overlay names the mesh tun, so a packet counted here took a route into the wrong device
// no route sends to an IPv6 multicast address of interface-local or link-local scope, so a packet to one is the kernel's own, its MLD reports among them, and is not counted
func (m *Mesh) drain(e *egressDevice, queue tun.Queue) {
	slab := make([]byte, outboundSlabSize)
	reads := make([]tun.ReadPacket, e.dev.BatchSize())
	for {
		n, err := queue.Read(slab, reads)
		routed := 0
		for _, read := range reads[:n] {
			if !linkScopedMulticast(slab[read.Offset : read.Offset+read.Size]) {
				routed++
			}
		}
		m.segmentsDrained.Add(uint64(routed))
		if err == nil || errors.Is(err, tun.ErrTooManySegments) {
			continue
		}
		select {
		case <-e.closing:
			return
		default:
		}
		m.reportSegmentDrop("the egress device's drain could not read it", "err", err)
		select {
		case <-e.closing:
			return
		case <-time.After(egressDrainRetry):
		}
	}
}

// linkScopedMulticast reports an IPv6 packet to a multicast address whose scope, the low nibble of its second byte, is interface-local or link-local (RFC 4291 section 2.7)
func linkScopedMulticast(packet []byte) bool {
	return len(packet) >= 40 && packet[0]>>4 == 6 && packet[24] == 0xff && packet[25]&0x0f <= 2
}
