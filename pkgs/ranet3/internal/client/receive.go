// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-License-Identifier: MIT

package client

import (
	"sync"
	"sync/atomic"

	"ranet3.com/pkgs/ranet3/esp"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/packet"
	"ranet3.com/pkgs/ranet3/transport"
)

type inboundDecrypted = esp.AuthenticatedPacket

// inboundECN is the ECN field of a decrypted packet's outer IP header
type inboundECN = packet.ECN

type inboundBatch struct {
	ticket  uint64
	results []inboundDecrypted
	// ecn holds the outer ECN field of each result, nil when every one arrived Not-ECT
	ecn []inboundECN
	// received holds the storage the results were decrypted in
	received *transport.Received
}

// delivery is the received batches of one emit call, which it holds for the emitter and for each holder in the mesh that retains it
// the last release releases every batch
type delivery struct {
	refs    atomic.Int32
	batches []*transport.Received
}

var deliveries = sync.Pool{New: func() any { return new(delivery) }}

func newDelivery() *delivery {
	d := deliveries.Get().(*delivery)
	d.refs.Store(1)
	return d
}

func (d *delivery) Retain() { d.refs.Add(1) }

// a count below zero is a delivery released twice, whose batches another delivery may hold by then
func (d *delivery) Release() {
	switch refs := d.refs.Add(-1); {
	case refs > 0:
	case refs == 0:
		for _, batch := range d.batches {
			batch.Release()
		}
		clear(d.batches)
		d.batches = d.batches[:0]
		deliveries.Put(d)
	default:
		panic("client: a delivery was released more times than it was held")
	}
}

// emitInboundBatches absorbs out-of-order worker completions and emits only
// receive-order results. Consecutive batches that are already complete are
// merged into one call so flow bucketing and TUN GRO see a larger vector
// without delaying a lone packet. The outer ECN fields are merged beside the
// results, and emit is handed nil for them when every merged packet arrived
// Not-ECT. emit is handed a hold on the merged batches' storage, which the
// emitter releases once emit returns, and on its end the batches still
// pending.
func emitInboundBatches(completed <-chan *inboundBatch, recycle chan<- *inboundBatch, emit func([]inboundDecrypted, []inboundECN, netstack.Hold)) {
	pending := make(map[uint64]*inboundBatch, cap(completed))
	defer func() {
		for _, batch := range pending {
			batch.received.Release()
		}
	}()
	merged := make([]inboundDecrypted, 0, 128)
	mergedECN := make([]inboundECN, 0, 128)
	next := uint64(0)
	for batch := range completed {
		pending[batch.ticket] = batch
	drain:
		for range cap(completed) {
			select {
			case ready, ok := <-completed:
				if !ok {
					break drain
				}
				pending[ready.ticket] = ready
			default:
				break drain
			}
		}
		merged = merged[:0]
		mergedECN = mergedECN[:0]
		marked := false
		var held *delivery
		for {
			ready := pending[next]
			if ready == nil {
				break
			}
			delete(pending, next)
			if ready.ecn == nil {
				mergedECN = append(mergedECN, make([]inboundECN, len(ready.results))...)
			} else {
				mergedECN, marked = append(mergedECN, ready.ecn...), true
			}
			merged = append(merged, ready.results...)
			if held == nil {
				held = newDelivery()
			}
			held.batches = append(held.batches, ready.received)
			clear(ready.results)
			ready.results, ready.ecn, ready.received = ready.results[:0], nil, nil
			recycle <- ready
			next++
		}
		if held == nil {
			continue
		}
		if len(merged) != 0 {
			fields := mergedECN
			if !marked {
				fields = nil
			}
			emit(merged, fields, held)
			clear(merged)
		}
		held.Release()
	}
}

// receiveESP keeps crypto parallel and replay commits in intake order. On one
// core those stages run inline, avoiding queues that cannot provide parallelism.
// emit is handed each result with the outer ECN field of its datagram, nil when every one arrived Not-ECT,
// and a hold on the storage the results lie in, which receiveESP releases once emit returns.
func receiveESP(mux *transport.Mux, workers int, decrypt func([][]byte, []inboundDecrypted) []inboundDecrypted, emit func([]inboundDecrypted, []inboundECN, netstack.Hold)) error {
	if workers <= 1 {
		results := make([]inboundDecrypted, 0, 128)
		for {
			received, err := mux.RecvESPBatchConcurrent()
			if err != nil {
				return err
			}
			results = decrypt(received.Packets(), results[:0])
			held := newDelivery()
			held.batches = append(held.batches, received)
			emit(results, received.ECN(), held)
			held.Release()
			clear(results)
		}
	}
	queueSize := 2 * workers
	free := make(chan *inboundBatch, queueSize)
	completed := make(chan *inboundBatch, queueSize)
	for range queueSize {
		free <- &inboundBatch{results: make([]inboundDecrypted, 0, 128)}
	}
	emitterDone := make(chan struct{})
	go func() {
		defer close(emitterDone)
		emitInboundBatches(completed, free, emit)
	}()
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for {
				batch := <-free
				received, err := mux.RecvESPBatchConcurrent()
				if err != nil {
					free <- batch
					errs <- err
					return
				}
				batch.ticket, batch.ecn, batch.received = received.Ticket(), received.ECN(), received
				batch.results = decrypt(received.Packets(), batch.results)
				completed <- batch
			}
		})
	}
	err := <-errs
	_ = mux.Close()
	wg.Wait()
	close(completed)
	<-emitterDone
	return err
}
