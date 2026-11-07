// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package transport

import (
	"net"
	"slices"
	"testing"
	"time"
)

// clonedPackets is batch's packets copied out, with the batch released
func clonedPackets(batch *Received) [][]byte {
	packets := make([][]byte, len(batch.Packets()))
	for i, packet := range batch.Packets() {
		packets[i] = slices.Clone(packet)
	}
	batch.Release()
	return packets
}

// testBatch is packets laid into one block of pool, as a batch holding the block's only reference and charged it whole, every packet Not-ECT
func testBatch(pool *blockPool, packets ...[]byte) *Received {
	block := pool.get()
	r := pool.batch()
	r.packets, r.blocks, r.charge = r.packetSlots[:len(packets)], append(r.blockSlots[:0], block), len(block.data)
	offset := 0
	for i, packet := range packets {
		end := offset + copy(block.data[offset:], packet)
		r.packets[i] = block.data[offset:end:end]
		offset = end
	}
	return r
}

// pooledReads is fn with each datagram it hands out laid into blocks of the hub's pool as the memory network lays them, for a fake receiver that hands out bytes of its own
func pooledReads(fn receiveFunc) receiveFunc {
	var layout blockLayout
	return func(pool *blockPool, bufs [][]byte, sizes []int, endpoints []Endpoint, records []receiveRecord, refused *refusals) (int, error) {
		n, err := fn(pool, bufs, sizes, endpoints, records, refused)
		layout.start(pool)
		for i := range n {
			bufs[i], records[i].block, _ = layout.lay(pool, bufs[i][:sizes[i]], records[i].source)
		}
		return n, err
	}
}

// dial is a mux to remoteIP and remotePort on a hub of its own at an ephemeral port, the hub closed when the test ends
func dial(t *testing.T, remoteIP net.IP, remotePort int) *Mux {
	t.Helper()
	hub, err := NewHub(0, Runtime{Prepare: testPrepare()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	m, err := hub.NewMux(remoteIP, remotePort)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func (m *Mux) RecvIKE() ([]byte, error) {
	select {
	case d := <-m.ikeCh:
		return d.Raw, nil
	case <-m.done:
		return nil, m.doneError()
	}
}

func (m *Mux) RecvIKEUntil(deadline time.Time) ([]byte, error) {
	b, _, err := m.RecvIKEFromUntil(deadline)
	return b, err
}

func (m *Mux) SendESP(b []byte) error { return m.SendESPBatch([][]byte{b}) }

// espReader reads a mux's ESP one packet at a time through RecvESPBatchConcurrent, keeping copies of the rest of each batch it released for the reads after
type espReader struct {
	m       *Mux
	pending [][]byte
}

func newESPReader(m *Mux) *espReader { return &espReader{m: m} }

// next is the next packet, waiting for a batch until deadline
// a wait that times out closes the mux, which ends the receive it started
func (r *espReader) next(deadline time.Time) ([]byte, error) {
	if len(r.pending) == 0 {
		var packets [][]byte
		read := make(chan error, 1)
		go func() {
			batch, err := r.m.RecvESPBatchConcurrent()
			if err == nil {
				packets = clonedPackets(batch)
			}
			read <- err
		}()
		timer := time.NewTimer(time.Until(deadline))
		defer timer.Stop()
		select {
		case err := <-read:
			if err != nil {
				return nil, err
			}
		case <-timer.C:
			_ = r.m.Close()
			<-read
			return nil, errTimeout
		}
		r.pending = packets
	}
	packet := r.pending[0]
	r.pending = r.pending[1:]
	return packet, nil
}
