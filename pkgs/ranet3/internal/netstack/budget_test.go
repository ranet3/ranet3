// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// passThrough seals a packet as itself, into the storage the pool hands back
func passThrough(raw [][]byte, _ []byte, out [][]byte) ([][]byte, error) {
	return append(out[:0], raw...), nil
}

// waitForBudget waits until both budgets of p hold nothing
func waitForBudget(t *testing.T, p *Peer) {
	t.Helper()
	waitUntil(t, "the peer to give back both of its budgets", func() bool {
		return p.dataBudget.used.Load() == 0 && p.controlBudget.used.Load() == 0
	})
}

// the data budget counts packets rather than reads
// a read that fits is admitted however the rest of the budget is split
// and one that does not fit is refused whole and counted in packets, without taking a ticket or a sequence range
func TestDataBudgetAdmitsByPackets(t *testing.T) {
	var asked atomic.Int64
	peer := NewPeerReserved("peer", func(count int) (BatchSealer, error) {
		asked.Add(int64(count))
		return passThrough, nil
	}, func([][]byte) error { return nil }, nil)
	defer peer.Close()

	// one full read, then single packets, up to one packet short of the budget
	if peer.reserveBatchNow(transmitBatchSize) == nil {
		t.Fatal("an empty budget refused a full read")
	}
	for i := range peerDataBudget - transmitBatchSize - 1 {
		if peer.reserveBatchNow(1) == nil {
			t.Fatalf("the budget refused packet %d below its size", transmitBatchSize+i)
		}
	}
	tickets := peer.reserved

	if peer.reserveBatchNow(2) != nil {
		t.Fatal("a read of two packets was admitted with room for one")
	}
	if got := peer.Dropped(); got != 2 {
		t.Errorf("the refused read counted %d drops, want its 2 packets", got)
	}
	if peer.reserved != tickets || asked.Load() != peerDataBudget-1 {
		t.Errorf("the refused read took a ticket or a sequence range: %d tickets against %d, %d packets asked of the SA",
			peer.reserved, tickets, asked.Load())
	}
	if peer.reserveBatchNow(1) == nil {
		t.Fatal("the last packet of room was refused")
	}
	if peer.reserveBatchNow(1) != nil {
		t.Fatal("a full budget admitted one more packet")
	}
	if got := peer.Dropped(); got != 3 {
		t.Errorf("the peer counted %d drops, want the 3 packets it refused", got)
	}
}

// reservers racing for the last packet of one budget never hold more than it allows between them
// take checks the room and takes it in one atomic step
// or two reservers that both saw the last packet free would both take it
// and every packet taken comes back once
func TestBudgetHoldsItsLimitUnderConcurrentReservers(t *testing.T) {
	const reservers, takes = 16, 1000
	budget := packetBudget{limit: controlQueueSize}
	budget.used.Store(controlQueueSize - 1)
	var over atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range reservers {
		wg.Go(func() {
			<-start
			for range takes {
				if !budget.take(1) {
					continue
				}
				if used := budget.used.Load(); used > budget.limit {
					over.Store(used)
				}
				budget.used.Add(-1)
			}
		})
	}
	close(start)
	wg.Wait()
	if got := over.Load(); got != 0 {
		t.Errorf("%d reservers held %d packets of a budget of %d between them", reservers, got, budget.limit)
	}
	if got := budget.used.Load(); got != controlQueueSize-1 {
		t.Errorf("the budget holds %d packets once every reserver gave back what it took, want the %d taken before", got, controlQueueSize-1)
	}
}

// every packet a budget gives out comes back once the transmit that carried it returns
// whether the transport took it or lost it, whether it sealed or not, and whether the peer closed before or after the batch was queued
// a packet that never comes back is room the peer has lost for good
func TestBudgetComesBackOnEveryPath(t *testing.T) {
	sendErr, sealErr, saErr := errors.New("sendto: no route"), errors.New("seal"), errors.New("no child sa")
	type path struct {
		name     string
		reserve  func(int) (BatchSealer, error)
		send     func([][]byte) error
		drive    func(t *testing.T, p *Peer)
		dropped  uint64
		failed   uint64
		graceful bool
	}
	sealing := func(int) (BatchSealer, error) { return passThrough, nil }
	sent := func([][]byte) error { return nil }
	transmitThree := func(t *testing.T, p *Peer) {
		b := filled(p, 3)
		if b == nil {
			t.Fatal("an empty budget refused the batch")
		}
		_ = b.transmit()
	}
	for _, test := range []path{
		{name: "sent", reserve: sealing, send: sent, drive: transmitThree},
		{name: "lost in the transport", reserve: sealing, send: func([][]byte) error { return sendErr }, drive: transmitThree, failed: 3},
		{name: "sealed nothing", reserve: func(int) (BatchSealer, error) {
			return func([][]byte, []byte, [][]byte) ([][]byte, error) { return nil, sealErr }, nil
		}, send: sent, drive: transmitThree, dropped: 3},
		{name: "refused a sequence range", reserve: func(int) (BatchSealer, error) { return nil, saErr }, send: sent, drive: transmitThree, dropped: 3},
		{name: "closed before the batch was queued", reserve: sealing, send: sent, dropped: 3, drive: func(t *testing.T, p *Peer) {
			b := filled(p, 3)
			p.Close()
			if b.enqueue() == nil {
				t.Error("a closed peer queued the batch")
			}
		}},
		{name: "closed with the batch queued behind an earlier ticket", reserve: sealing, send: sent, dropped: 5, drive: func(t *testing.T, p *Peer) {
			first, second := filled(p, 2), filled(p, 3)
			if err := second.enqueue(); err != nil {
				t.Fatalf("an open peer refused the batch: %v", err)
			}
			p.Close()
			_ = first.enqueue()
		}},
		{name: "closed with the batch inside a transport that returns later", reserve: sealing, graceful: true, drive: func(t *testing.T, p *Peer) {
			if err := filled(p, 3).enqueue(); err != nil {
				t.Fatalf("an open peer refused the batch: %v", err)
			}
		}},
		{name: "control sent", reserve: sealing, send: sent, drive: func(t *testing.T, p *Peer) {
			if err := sendOrDrop(p, []byte("hello"), 41); err != nil {
				t.Fatalf("an empty control budget refused the packet: %v", err)
			}
		}},
		{name: "control lost in the transport", reserve: sealing, send: func([][]byte) error { return sendErr }, failed: 1, drive: func(t *testing.T, p *Peer) {
			if err := sendOrDrop(p, []byte("hello"), 41); err != nil {
				t.Fatalf("an empty control budget refused the packet: %v", err)
			}
		}},
		{name: "control closed before the place was sent", reserve: sealing, send: sent, dropped: 1, drive: func(t *testing.T, p *Peer) {
			place, err := p.ReserveRawOrDrop([]byte("hello"), 41)
			if err != nil {
				t.Fatalf("an empty control budget refused the packet: %v", err)
			}
			p.Close()
			if place.Send() == nil {
				t.Error("a closed peer queued the place")
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			send := test.send
			entered, release := make(chan struct{}), make(chan struct{})
			if test.graceful {
				// the transport holds the batch past the grace Close waits for
				send = func([][]byte) error { close(entered); <-release; return nil }
			}
			p := NewPeerReserved("peer", test.reserve, send, nil)
			defer p.Close()
			test.drive(t, p)
			if test.graceful {
				select {
				case <-entered:
				case <-time.After(deliveryTimeout):
					t.Fatal("the batch never reached the transport, so this proves nothing")
				}
				p.closeGrace = deliveryPoll
				p.Close()
				close(release)
			}
			waitForBudget(t, p)
			if got := p.Dropped(); got != test.dropped {
				t.Errorf("the peer counted %d drops, want %d", got, test.dropped)
			}
			if got := p.SendFailed(); got != test.failed {
				t.Errorf("the peer counted %d packets lost in the transport, want %d", got, test.failed)
			}
		})
	}
}

// every batch with a ticket holds at least one packet of a budget
// so a queue as long as both budgets together takes every batch they admit
// and enqueue never has to give a batch back for want of room
// the sender is held where it holds nothing of either budget, in the failure callback of a control packet the transport lost
// so both budgets fill the queue to exactly their sum
func TestQueueHoldsEverythingTheBudgetsAdmit(t *testing.T) {
	var lose atomic.Bool
	lose.Store(true)
	var transmitted atomic.Int64
	peer := NewPeerReserved("peer", func(int) (BatchSealer, error) { return passThrough, nil }, func(sealed [][]byte) error {
		if lose.Load() {
			return errors.New("sendto: network is unreachable")
		}
		transmitted.Add(int64(len(sealed)))
		return nil
	}, nil)
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer peer.Close()
	defer unblock()

	lost, err := peer.ReserveRawOrDrop([]byte{1}, 41)
	if err != nil {
		t.Fatalf("an empty control budget refused the packet: %v", err)
	}
	lost.OnFailure(func(error) { close(entered); <-release })
	if err := lost.Send(); err != nil {
		t.Fatalf("an open peer refused the place: %v", err)
	}
	select {
	case <-entered:
	case <-time.After(deliveryTimeout):
		t.Fatal("the sender never reported the lost packet, so this proves nothing")
	}
	lose.Store(false)
	if data, control := peer.dataBudget.used.Load(), peer.controlBudget.used.Load(); data != 0 || control != 0 {
		t.Fatalf("the sender reports a loss holding %d data and %d control packets of the budgets", data, control)
	}

	// the smallest batches the budgets can admit, as many as they admit
	queued := 0
	for {
		b := filled(peer, 1)
		if b == nil {
			break
		}
		if err := b.enqueue(); err != nil {
			t.Fatalf("batch %d of the data budget was given back rather than queued: %v", queued, err)
		}
		queued++
	}
	for i := range controlQueueSize {
		if err := sendOrDrop(peer, []byte{1}, 41); err != nil {
			t.Fatalf("control place %d was given back rather than queued: %v", i, err)
		}
		queued++
	}
	if queued != peerDataBudget+controlQueueSize {
		t.Fatalf("the budgets admitted %d single packets, want %d", queued, peerDataBudget+controlQueueSize)
	}
	if got := peer.Dropped(); got != 1 {
		t.Errorf("the peer counted %d drops, want only the one packet past the data budget", got)
	}

	unblock()
	waitUntil(t, "the peer to transmit every packet it queued", func() bool { return transmitted.Load() == int64(queued) })
	waitForBudget(t, peer)
}

// a batch reuses only sealed storage grown by at most twice its own packets
// single packets can stand by the thousand under the budget
// and each one handed storage a full read grew would pin all of it
func TestSmallBatchIsNeverHandedStorageALargeOneGrew(t *testing.T) {
	var handed int
	sealer := func(raw [][]byte, _ []byte, reuse [][]byte) ([][]byte, error) {
		handed = cap(reuse)
		return append(reuse[:0], raw...), nil
	}
	peer := NewPeerReserved("peer", func(int) (BatchSealer, error) { return sealer, nil }, func([][]byte) error { return nil }, nil)
	defer peer.Close()
	const large = 45
	// sync.Pool drops a quarter of what it is given under the race detector
	// so a single pass could miss the storage it must never hand over
	for range 32 {
		b := filled(peer, large)
		b.encrypt()
		b.releaseStorage()
		small := filled(peer, 1)
		small.encrypt()
		if handed > 1 {
			t.Fatalf("a batch of one packet was handed storage for %d, grown by a batch of %d", handed, large)
		}
		small.releaseStorage()
	}
}
