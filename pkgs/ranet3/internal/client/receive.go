// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-License-Identifier: MIT

package client

import (
	"sync"

	"ranet3.com/pkgs/ranet3/esp"
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
}

// emitInboundBatches absorbs out-of-order worker completions and emits only
// receive-order results. Consecutive batches that are already complete are
// merged into one call so flow bucketing and TUN GRO see a larger vector
// without delaying a lone packet. The outer ECN fields are merged beside the
// results, and emit is handed nil for them when every merged packet arrived
// Not-ECT.
func emitInboundBatches(completed <-chan *inboundBatch, recycle chan<- *inboundBatch, emit func([]inboundDecrypted, []inboundECN)) {
	pending := make(map[uint64]*inboundBatch, cap(completed))
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
			clear(ready.results)
			ready.results, ready.ecn = ready.results[:0], nil
			recycle <- ready
			next++
		}
		if len(merged) != 0 {
			fields := mergedECN
			if !marked {
				fields = nil
			}
			emit(merged, fields)
			clear(merged)
		}
	}
}

// receiveESP keeps crypto parallel and replay commits in intake order. On one
// core those stages run inline, avoiding queues that cannot provide parallelism.
// emit is handed each result with the outer ECN field of its datagram, nil when every one arrived Not-ECT.
func receiveESP(mux *transport.Mux, workers int, decrypt func([][]byte, []inboundDecrypted) []inboundDecrypted, emit func([]inboundDecrypted, []inboundECN)) error {
	if workers <= 1 {
		results := make([]inboundDecrypted, 0, 128)
		for {
			_, packets, ecn, err := mux.RecvESPBatchConcurrent()
			if err != nil {
				return err
			}
			results = decrypt(packets, results[:0])
			emit(results, ecn)
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
				ticket, packets, ecn, err := mux.RecvESPBatchConcurrent()
				if err != nil {
					free <- batch
					errs <- err
					return
				}
				batch.ticket, batch.ecn = ticket, ecn
				batch.results = decrypt(packets, batch.results)
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
