// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package netstack

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// orderStep is one reservation a reserver makes, a data share of count packets of size bytes each or a control place
// and the yields its filler makes before it seals it
type orderStep struct {
	control     bool
	count, size int
	yields      int
}

// orderBatch is a reservation on its way to a filler, through its place when it is a control one
type orderBatch struct {
	batch *peerBatch
	place *Place
	step  orderStep
}

// several reservers take places concurrently on one peer, data shares of sizes drawn on each side of the budget's edges and control places
// and several fillers seal what they admitted in whatever order they take it, each after its drawn yields
// the peer's SA hands out sequence numbers in the order of the reservations, which the model counts
// and the transport carries every number an admitted reservation took, once each, rising from zero
// so a refused reservation takes none, and none is carried ahead of one taken before it
func TestSequenceLeavesInOrderAcrossReservers(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		reservers := hegel.Draw(ht, pbt.Spanning(2, 16))
		plans := make([][]orderStep, reservers)
		for r := range plans {
			for range hegel.Draw(ht, pbt.Spanning(1, 6)) {
				step := orderStep{control: hegel.Draw(ht, hegel.Booleans()), count: 1, size: 1, yields: hegel.Draw(ht, pbt.Spanning(0, 8))}
				if !step.control {
					step.count = hegel.Draw(ht, pbt.Spanning(1, transmitBatchSize))
					step.size = hegel.Draw(ht, pbt.Spanning(1, peerDataBudget/step.count))
				}
				plans[r] = append(plans[r], step)
			}
		}
		fillers := hegel.Draw(ht, pbt.Spanning(1, 4))

		var next atomic.Uint64
		var mu sync.Mutex
		var sent []uint64
		peer := NewPeer("peer", func(count int) (BatchSealer, error) {
			first := next.Add(uint64(count)) - uint64(count)
			return func(raw [][]byte, _ []byte, out [][]byte) ([][]byte, error) {
				out = out[:0]
				for i := range raw {
					out = append(out, binary.BigEndian.AppendUint64(nil, first+uint64(i)))
				}
				return out, nil
			}, nil
		}, func(sealed [][]byte) error {
			mu.Lock()
			defer mu.Unlock()
			for _, packet := range sealed {
				sent = append(sent, binary.BigEndian.Uint64(packet))
			}
			return nil
		}, nil)
		defer peer.Close()

		payload := make([]byte, peerDataBudget)
		var admitted atomic.Uint64
		var failures sync.Map
		queue := make(chan orderBatch, reservers*6)
		var filling sync.WaitGroup
		for range fillers {
			filling.Go(func() {
				for o := range queue {
					for range o.step.yields {
						runtime.Gosched()
					}
					var err error
					if o.place != nil {
						err = o.place.Send()
					} else {
						err = o.batch.finish()
					}
					if err != nil {
						failures.Store(fmt.Sprintf("an open peer refused a batch: %v", err), true)
					}
				}
			})
		}
		var reserving sync.WaitGroup
		start := make(chan struct{})
		for _, plan := range plans {
			reserving.Go(func() {
				<-start
				for _, step := range plan {
					o := orderBatch{step: step}
					if step.control {
						place, err := peer.ReserveRawOrDrop(payload[:1], 41)
						if err != nil {
							continue
						}
						o.place, o.batch = place, place.batch
					} else {
						if o.batch = peer.reserveBatchNow(step.count, step.count*step.size); o.batch == nil {
							continue
						}
						for i := range step.count {
							o.batch.append(payload[i*step.size:(i+1)*step.size], 0)
						}
						// read below the delay control's target however long the case runs
						o.batch.admitted += time.Hour
					}
					admitted.Add(uint64(step.count))
					queue <- o
				}
			})
		}
		close(start)
		reserving.Wait()
		close(queue)
		filling.Wait()
		failures.Range(func(key, _ any) bool { ht.Error(key); return true })

		waitUntil(ht, "the peer to carry every packet it admitted", func() bool {
			mu.Lock()
			defer mu.Unlock()
			return uint64(len(sent)) == admitted.Load() && peer.dataBudget.used.Load() == 0 && peer.controlBudget.used.Load() == 0
		})
		if got, want := next.Load(), admitted.Load(); got != want {
			ht.Fatalf("the SA handed out %d sequence numbers for %d admitted packets", got, want)
		}
		mu.Lock()
		defer mu.Unlock()
		for i, number := range sent {
			if number != uint64(i) {
				ht.Fatalf("the transport carried sequence number %d as packet %d, among %v", number, i, sent[max(0, i-4):min(len(sent), i+4)])
			}
		}
	})
}
