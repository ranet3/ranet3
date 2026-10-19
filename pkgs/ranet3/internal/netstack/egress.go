// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"ranet3.com/pkgs/wireguard/tun"
)

// egressMu orders SetEgress against Close, and the dataplane reads egress
type egressSlot struct {
	egressMu sync.Mutex
	egress   atomic.Pointer[egressDevice]
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

// every route into the overlay names the mesh tun, so a packet here took a route into the wrong device
func (m *Mesh) drain(e *egressDevice, queue tun.Queue) {
	slab := make([]byte, outboundSlabSize)
	reads := make([]tun.ReadPacket, e.dev.BatchSize())
	for {
		n, err := queue.Read(slab, reads)
		m.segmentsDrained.Add(uint64(n))
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
