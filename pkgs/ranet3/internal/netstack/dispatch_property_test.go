// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package netstack

import (
	"encoding/binary"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// dispatchStepTimeout is how long the scheduler waits for a resumed reader to park again or finish
// and how long the peers have to drain once every reader is done
const dispatchStepTimeout = 2 * time.Second

// sequencedPeer hands out sequence numbers under its reserveMu, as an outbound SA does
// and records the number of every packet its transport carries once the valve lets it
type sequencedPeer struct {
	*Peer
	// next is the first number of the next reservation, written under the peer's reserveMu
	next uint64
	mu   sync.Mutex
	sent []uint64
}

func newSequencedPeer(id string, v *valve) *sequencedPeer {
	s := &sequencedPeer{}
	s.Peer = NewPeer(id, func(count int) (BatchSealer, error) {
		first := s.next
		s.next += uint64(count)
		return func(raw [][]byte, _ []byte, out [][]byte) ([][]byte, error) {
			out = out[:0]
			for i := range raw {
				out = append(out, binary.BigEndian.AppendUint64(nil, first+uint64(i)))
			}
			return out, nil
		}, nil
	}, func(sealed [][]byte) error {
		if err := v.transmit(sealed); err != nil {
			return err
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		for _, packet := range sealed {
			s.sent = append(s.sent, binary.BigEndian.Uint64(packet))
		}
		return nil
	}, nil)
	return s
}

// transmitted is how many packets the transport carried and whether each one's number rose above the one before it
func (s *sequencedPeer) transmitted() (int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := 1; i < len(s.sent); i++ {
		if s.sent[i] <= s.sent[i-1] {
			return len(s.sent), false
		}
	}
	return len(s.sent), true
}

// dispatchStep is one reservation a reader makes
// a share of count packets coming to bytes for peer, the reader's gate, or a control place on peer after its read
type dispatchStep struct {
	peer         int
	count, bytes int
	gate         bool
	control      bool
}

// dispatchEvent says a reader parked at its gate or finished its reads
type dispatchEvent struct {
	reader int
	parked bool
}

// dispatchModel counts what one peer holds while its transport takes nothing, so nothing it admitted has come back
// data is bytes of the data budget, control places of the control one, and reserved and refused count packets
type dispatchModel struct {
	data, control     int
	reserved, refused uint64
}

// take admits a step the way the budgets are specified to, and counts it reserved or refused
func (d *dispatchModel) take(step dispatchStep) {
	switch {
	case step.control && d.control < controlQueueSize:
		d.control++
	case !step.control && d.data+charge(step.count, step.bytes) <= peerDataBudget:
		d.data += charge(step.count, step.bytes)
	default:
		d.refused += uint64(step.count)
		return
	}
	d.reserved += uint64(step.count)
}

// shareBytes draws the bytes a share of count packets comes to, on each side of both edges of its charge
// under count*leastPacketBytes, charged that much, up to peerDataBudget, charged its bytes, and past it, charged the whole budget
func shareBytes(ht *hegel.T, count int) int {
	switch hegel.Draw(ht, pbt.Spanning(0, 2)) {
	case 0:
		return hegel.Draw(ht, pbt.Spanning(count, count*leastPacketBytes-1))
	case 1:
		return hegel.Draw(ht, pbt.Spanning(count*leastPacketBytes, peerDataBudget))
	default:
		return hegel.Draw(ht, pbt.Spanning(peerDataBudget+1, 2*peerDataBudget))
	}
}

// several readers dispatch reads for the same peers, each parking at a gate of its own at a drawn point among a read's reservations
// and the scheduler runs one reader at a time from one gate to the next, in a drawn order
// so the readers interleave between any two reservations of a read, holding tickets of some peers
// while the others fill those peers' budgets behind the tickets they hold, by shares of every size the charge tells apart, and take control places
// the transport takes nothing until every reader is done, so each step is held to a model of the budgets
// every reader runs from one gate to the next without waiting
// a reservation is admitted exactly when the model has room for its charge, and a refusal counts its packets
// then the transport opens and either every reserved ticket drains or the peers close with tickets on their way
// each peer's transport carries its packets in the order of the sequence numbers their reservations took
// every packet offered is counted once, and both budgets are back to empty
func TestReadersInterleavedAtAnyReservationAllDrain(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		readers := hegel.Draw(ht, hegel.Integers(2, 3))
		v := newValve()
		peers := make([]*sequencedPeer, hegel.Draw(ht, hegel.Integers(2, 3)))
		for i := range peers {
			peers[i] = newSequencedPeer(fmt.Sprintf("peer%d", i), v)
		}
		plans := make([][][]dispatchStep, readers)
		for r := range plans {
			for range hegel.Draw(ht, hegel.Integers(1, 3)) {
				var read []dispatchStep
				remaining := make([]int, len(peers))
				for i := range remaining {
					remaining[i] = i
				}
				for range hegel.Draw(ht, hegel.Integers(1, len(peers))) {
					i := hegel.Draw(ht, hegel.Integers(0, len(remaining)-1))
					count := hegel.Draw(ht, pbt.Spanning(1, 4))
					read = append(read, dispatchStep{peer: remaining[i], count: count, bytes: shareBytes(ht, count)})
					remaining = slices.Delete(remaining, i, i+1)
				}
				read = slices.Insert(read, hegel.Draw(ht, pbt.Spanning(0, len(read))), dispatchStep{count: 1, bytes: 1, gate: true})
				if hegel.Draw(ht, hegel.Booleans()) {
					read = append(read, dispatchStep{peer: hegel.Draw(ht, hegel.Integers(0, len(peers)-1)), count: 1, control: true})
				}
				plans[r] = append(plans[r], read)
			}
		}

		events := make(chan dispatchEvent, readers*4)
		resume := make([]chan struct{}, readers)
		gates := make([]*Peer, readers)
		for r := range gates {
			resume[r] = make(chan struct{})
			gates[r] = NewPeer(fmt.Sprintf("gate%d", r), func(int) (BatchSealer, error) {
				events <- dispatchEvent{reader: r, parked: true}
				<-resume[r]
				return passThrough, nil
			}, func([][]byte) error { return nil }, nil)
		}
		m := &Mesh{closed: make(chan struct{}), outboundJobs: make(chan *outboundBatch, readers*4), outboundFree: make(chan *outboundBatch, readers*4)}
		m.outboundWorkerWG.Add(2)
		go m.outboundWorker()
		go m.outboundWorker()
		var readersDone sync.WaitGroup
		// a case that fails lets every reader and every transport go before the mesh closes
		// readers waiting for room behind tickets each other holds never return, and are left behind with the mesh
		defer func() {
			v.set(true, false)
			for _, ch := range resume {
				close(ch)
			}
			finished := make(chan struct{})
			go func() { readersDone.Wait(); close(finished) }()
			select {
			case <-finished:
			case <-time.After(dispatchStepTimeout):
				return
			}
			m.Close()
			for _, gate := range gates {
				gate.Close()
			}
			for _, peer := range peers {
				peer.Close()
			}
		}()

		for r, plan := range plans {
			readersDone.Go(func() {
				<-resume[r]
				for _, read := range plan {
					b := &outboundBatch{shares: make(map[*Peer]outboundShare), batches: make(map[*Peer]*peerBatch)}
					var places []*Peer
					for _, step := range read {
						p := gates[r]
						switch {
						case step.control:
							places = append(places, peers[step.peer].Peer)
							continue
						case !step.gate:
							p = peers[step.peer].Peer
						}
						b.peerOrder = append(b.peerOrder, p)
						b.shares[p] = outboundShare{count: step.count, bytes: step.bytes}
						for range step.count {
							b.bufs = append(b.bufs, framed(0))
							b.sizes = append(b.sizes, 1)
							b.headers = append(b.headers, 0)
							b.peers = append(b.peers, p)
						}
					}
					b.n = len(b.bufs)
					m.dispatchOutbound(b)
					for _, p := range places {
						if place, err := p.ReserveRawOrDrop([]byte{1}, 41); err == nil {
							_ = place.Send()
						}
					}
				}
				events <- dispatchEvent{reader: r}
			})
		}

		model := make([]dispatchModel, len(peers))
		// cursor is where each reader's plan resumes, as a read and a step within it
		cursor := make([][2]int, readers)
		parked := make([]int, readers)
		for r := range parked {
			parked[r] = r
		}
		for len(parked) > 0 {
			i := hegel.Draw(ht, hegel.Integers(0, len(parked)-1))
			r := parked[i]
			parked = slices.Delete(parked, i, i+1)
			resume[r] <- struct{}{}
			var e dispatchEvent
			select {
			case e = <-events:
			case <-time.After(dispatchStepTimeout):
				ht.Fatalf("reader %d neither parked nor finished within %s, so one of its reservations waited", r, dispatchStepTimeout)
			}
			if e.reader != r {
				ht.Fatalf("reader %d moved while reader %d was the one running", e.reader, r)
			}
		walk:
			for read, step := cursor[r][0], cursor[r][1]; read < len(plans[r]); read, step = read+1, 0 {
				for ; step < len(plans[r][read]); step++ {
					s := plans[r][read][step]
					if s.gate {
						cursor[r] = [2]int{read, step + 1}
						break walk
					}
					model[s.peer].take(s)
				}
			}
			for i, peer := range peers {
				want := model[i]
				if data, control := peer.dataBudget.used.Load(), peer.controlBudget.used.Load(); data != int64(want.data) || control != int64(want.control) {
					ht.Fatalf("peer %d holds %d bytes and %d control places, the model %d and %d", i, data, control, want.data, want.control)
				}
				if peer.next != want.reserved || peer.Dropped()-peer.DelayDropped() != want.refused {
					ht.Fatalf("peer %d reserved %d packets and refused %d, the model %d and %d", i, peer.next, peer.Dropped()-peer.DelayDropped(), want.reserved, want.refused)
				}
			}
			if e.parked {
				parked = append(parked, r)
				slices.Sort(parked)
			}
		}

		v.set(true, false)
		closing := hegel.Draw(ht, hegel.Booleans())
		if closing {
			// the workers hand every batch to its peer before the mesh closes, and the peers close as their senders drain
			m.Close()
			for _, peer := range peers {
				peer.Close()
			}
		}
		for i, peer := range peers {
			for deadline := time.Now().Add(dispatchStepTimeout); !closing; time.Sleep(budgetSettle) {
				sent, _ := peer.transmitted()
				if uint64(sent)+peer.DelayDropped() == peer.next && peer.dataBudget.used.Load() == 0 && peer.controlBudget.used.Load() == 0 {
					break
				}
				if time.Now().After(deadline) {
					ht.Fatalf("peer %d carried %d and delay dropped %d of the %d packets it reserved, holding %d bytes and %d control places, so a ticket never drained",
						i, sent, peer.DelayDropped(), peer.next, peer.dataBudget.used.Load(), peer.controlBudget.used.Load())
				}
			}
			peer.Close()
			if data, control := peer.dataBudget.used.Load(), peer.controlBudget.used.Load(); data != 0 || control != 0 {
				ht.Fatalf("peer %d closed holding %d bytes and %d control places", i, data, control)
			}
			sent, rising := peer.transmitted()
			if !rising {
				ht.Fatalf("peer %d carried its packets out of the order their reservations took: %v", i, peer.sent)
			}
			if offered := model[i].reserved + model[i].refused; uint64(sent)+peer.Dropped() != offered {
				ht.Fatalf("peer %d was offered %d packets and counted %d carried and %d dropped", i, offered, sent, peer.Dropped())
			}
		}
	})
}
