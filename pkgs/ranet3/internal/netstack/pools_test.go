// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import "testing"

// A mesh's pools count a slab for each read batch its pipeline made and each
// tun queue's own buffers, past which only the batches' slices of the
// device's batch size come, and a mesh with no device holds none
func TestPoolBytesCountsEveryReadBatchAndQueue(t *testing.T) {
	dev := &scriptedDevice{reads: make(chan scriptedRead), closed: make(chan struct{})}
	m := &Mesh{Name: "test0", Routes: NewRouteTable(), closed: make(chan struct{})}
	m.setDevice(lanesOf(dev, dev))
	m.startOutboundPipeline()
	defer m.Close()
	least := int64(cap(m.outboundFree))*outboundSlabSize + int64(len(m.queues))*tunQueueBytes
	most := least + int64(cap(m.outboundFree)+cap(m.forwardFree))*int64(dev.BatchSize())*128
	if got := m.PoolBytes(); got < least || got > most {
		t.Errorf("counted %d bytes of pools, want from %d, a slab for each of %d read batches and %d tun queues, to %d", got, least, cap(m.outboundFree), len(m.queues), most)
	}
	if got := (&Mesh{Routes: NewRouteTable()}).PoolBytes(); got != 0 {
		t.Errorf("a mesh with no device counted %d bytes", got)
	}
}
