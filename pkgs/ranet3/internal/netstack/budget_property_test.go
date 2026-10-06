// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package netstack

import (
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// budgetSettle is how often the machine looks at the budgets while it waits for the sender
// and budgetSettleTimeout how long it waits, short enough that a case which fails here shrinks in minutes
const (
	budgetSettle        = 50 * time.Microsecond
	budgetSettleTimeout = 2 * time.Second
)

// valve holds the peer's transport until a step opens it
// and decides what the transport answers while it is open
type valve struct {
	mu          sync.Mutex
	cond        *sync.Cond
	open        bool
	fail        bool
	transmitted atomic.Int64
}

func newValve() *valve {
	v := &valve{}
	v.cond = sync.NewCond(&v.mu)
	return v
}

func (v *valve) transmit(sealed [][]byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	for !v.open {
		v.cond.Wait()
	}
	if v.fail {
		return errors.New("sendto: network is unreachable")
	}
	v.transmitted.Add(int64(len(sealed)))
	return nil
}

func (v *valve) set(open, fail bool) {
	v.mu.Lock()
	v.open, v.fail = open, fail
	v.mu.Unlock()
	v.cond.Broadcast()
}

// heldBatch is a reservation the machine has made and not yet seen to its end
type heldBatch struct {
	batch   *peerBatch
	place   *Place
	count   int
	control bool
	queued  bool
}

// send hands the reservation to the peer's sender, through its place when it has one
func (h *heldBatch) send() error {
	if h.place != nil {
		return h.place.Send()
	}
	return h.batch.enqueue()
}

// budgetMachine drives one peer beside a model that counts the packets each budget holds
// its rules reserve any size on both budgets, send in any order and have transmits succeed or fail
// the transport returns only while a drain step holds it open
// so the model knows at every step which packets have come back
type budgetMachine struct {
	peer  *Peer
	valve *valve
	held  []*heldBatch
	// data, control, dropped and failed are the model's counts in packets
	data, control   int
	dropped, failed uint64
	offered         uint64
}

// holdData records a data reservation of count packets the budget admitted
// stamped an hour ahead, so the delay control reads it below its target however long the case runs
// and the model need not count delay drops
func (m *budgetMachine) holdData(b *peerBatch, count int) {
	b.admitted += time.Hour
	m.data += count
	m.held = append(m.held, &heldBatch{batch: b, count: count})
}

// reservationKinds are where a data reservation is drawn
// anywhere, exactly the room left, or one packet past it
var reservationKinds = []string{"any size", "the room left", "one past the room left"}

// RuleReserveData asks the data budget for a read of some size, the edges of the room left among them
func (m *budgetMachine) RuleReserveData(tc hegel.TestCase) {
	room := peerDataBudget - m.data
	count := hegel.Draw(tc, pbt.Spanning(1, 2*transmitBatchSize))
	switch hegel.Draw(tc, hegel.SampledFrom(reservationKinds)) {
	case "the room left":
		count = max(1, room)
	case "one past the room left":
		count = room + 1
	}
	m.offered += uint64(count)
	b := filled(m.peer, count)
	if fits := count <= room; (b != nil) != fits {
		tc.Errorf("a read of %d packets with %d of room was admitted %v, the model says %v", count, room, b != nil, fits)
		return
	}
	if b == nil {
		m.dropped += uint64(count)
		return
	}
	m.holdData(b, count)
}

// RuleReserveControl asks the control budget for one packet's place, as babel does
func (m *budgetMachine) RuleReserveControl(tc hegel.TestCase) {
	m.offered++
	place, err := m.peer.ReserveRawOrDrop([]byte{2}, 41)
	if fits := m.control < controlQueueSize; (err == nil) != fits {
		tc.Errorf("a control packet with %d of %d places taken was admitted %v, the model says %v", m.control, controlQueueSize, err == nil, fits)
		return
	}
	if err != nil {
		m.dropped++
		return
	}
	m.control++
	m.held = append(m.held, &heldBatch{batch: place.batch, place: place, count: 1, control: true})
}

// RuleSend sends one reservation the machine holds, in any order
func (m *budgetMachine) RuleSend(tc hegel.TestCase) {
	var unsent []*heldBatch
	for _, h := range m.held {
		if !h.queued {
			unsent = append(unsent, h)
		}
	}
	tc.Assume(len(unsent) > 0)
	h := unsent[hegel.Draw(tc, hegel.Integers(0, len(unsent)-1))]
	if err := h.send(); err != nil {
		tc.Errorf("an open peer refused ticket %d: %v", h.batch.ticket, err)
	}
	h.queued = true
}

// RuleDrain lets the transport take everything the sender can reach, every ticket sent before the first one that is not
// and has the transport succeed or fail
// those packets come back to their budgets and nothing else does
func (m *budgetMachine) RuleDrain(tc hegel.TestCase) {
	fail := hegel.Draw(tc, hegel.Booleans())
	slices.SortFunc(m.held, func(a, b *heldBatch) int { return int(a.batch.ticket) - int(b.batch.ticket) })
	reach := 0
	for reach < len(m.held) && m.held[reach].queued {
		reach++
	}
	data, control := m.data, m.control
	var packets uint64
	for _, h := range m.held[:reach] {
		if h.control {
			control -= h.count
		} else {
			data -= h.count
		}
		packets += uint64(h.count)
	}
	m.valve.set(true, fail)
	m.settle(tc, data, control)
	m.valve.set(false, false)
	m.data, m.control = data, control
	if fail {
		m.failed += packets
	}
	m.held = m.held[reach:]
}

// settle waits for the sender to bring both budgets to what the model holds
func (m *budgetMachine) settle(tc hegel.TestCase, data, control int) {
	for deadline := time.Now().Add(budgetSettleTimeout); ; time.Sleep(budgetSettle) {
		gotData, gotControl := m.peer.dataBudget.used.Load(), m.peer.controlBudget.used.Load()
		if gotData == int64(data) && gotControl == int64(control) {
			return
		}
		if time.Now().After(deadline) {
			tc.Errorf("the budgets hold %d data and %d control packets, the model %d and %d", gotData, gotControl, data, control)
			return
		}
	}
}

// InvariantCountsAgreeWithModel holds the budgets and both drop counters to the model at every step
func (m *budgetMachine) InvariantCountsAgreeWithModel(tc hegel.TestCase) {
	if got := m.peer.dataBudget.used.Load(); got != int64(m.data) {
		tc.Errorf("the data budget holds %d packets, the model %d", got, m.data)
	}
	if got := m.peer.controlBudget.used.Load(); got != int64(m.control) {
		tc.Errorf("the control budget holds %d packets, the model %d", got, m.control)
	}
	if got := m.peer.Dropped(); got != m.dropped {
		tc.Errorf("the peer counted %d drops, the model %d", got, m.dropped)
	}
	if got := m.peer.SendFailed(); got != m.failed {
		tc.Errorf("the peer counted %d packets lost in the transport, the model %d", got, m.failed)
	}
}

// a peer's two budgets count packets from their reservation until the transmit that carried them returns
// whatever sizes the machine reserves on either budget, in whatever order it sends, and whether its transmits succeed or fail
// a reservation is admitted exactly when the model has room for its packets
// a refusal counts all of them, and every packet comes back once its transmit returns
// then the peer closes with reservations still held, or sent and waiting behind one that is held
// and every packet it was offered is counted once, as transmitted, lost in the transport or dropped
// and both budgets are back to empty
func TestBudgetAgreesWithItsModel(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		v := newValve()
		m := &budgetMachine{valve: v, peer: NewPeerReserved("peer",
			func(int) (BatchSealer, error) { return passThrough, nil }, v.transmit, nil)}
		// most of a budget taken up front, so a case reaches its edge in a few steps
		if prefill := hegel.Draw(ht, pbt.Spanning(0, peerDataBudget)); prefill > 0 {
			m.offered += uint64(prefill)
			m.holdData(filled(m.peer, prefill), prefill)
		}
		for range hegel.Draw(ht, pbt.Spanning(0, controlQueueSize)) {
			m.RuleReserveControl(ht)
		}
		hegel.RunStateful(ht, m, hegel.WithAlwaysCheckInvariants("InvariantCountsAgreeWithModel"))

		// then the session ends
		// and the peer closes with whatever is held, sent or on its way to the transport
		v.set(true, false)
		m.peer.Close()
		for _, h := range m.held {
			if h.queued {
				continue
			}
			if h.send() == nil {
				ht.Fatalf("a closed peer queued ticket %d", h.batch.ticket)
			}
		}
		select {
		case <-m.peer.senderDone:
		case <-time.After(budgetSettleTimeout):
			ht.Fatal("the sender never finished after the peer closed")
		}
		m.settle(ht, 0, 0)
		if counted := uint64(v.transmitted.Load()) + m.peer.SendFailed() + m.peer.Dropped(); counted != m.offered {
			ht.Fatalf("the peer was offered %d packets and counted %d: %d transmitted, %d lost in the transport, %d dropped",
				m.offered, counted, v.transmitted.Load(), m.peer.SendFailed(), m.peer.Dropped())
		}
	})
}
