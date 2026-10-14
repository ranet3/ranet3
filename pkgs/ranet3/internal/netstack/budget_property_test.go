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
// count is its packets, bytes what they come to and charge what the model says it holds of its budget
type heldBatch struct {
	batch   *peerBatch
	place   *Place
	count   int
	bytes   int
	charge  int
	control bool
	queued  bool
}

// smallestPacket and largestPacket bound the data packets the machine draws
// an IPv4 header alone, and the largest link.mtu takes, what one ESP-in-UDP datagram carries over IPv4
// mostFragments is how many fragments a largestPacket IPv4 packet is cut into for a session at 1280, each carrying 1256 bytes of its payload
const (
	smallestPacket = 20
	largestPacket  = 65470
	mostFragments  = (largestPacket - 20 + 1255) / 1256
)

// packetBytes backs every data packet the machine reserves, each a prefix of it
var packetBytes = make([]byte, largestPacket)

// split cuts bytes into the largest packets and the shorter one left over
func split(bytes int) []int {
	sizes := slices.Repeat([]int{largestPacket}, bytes/largestPacket)
	if rest := bytes % largestPacket; rest != 0 {
		sizes = append(sizes, rest)
	}
	return sizes
}

// charge is the part of the data budget the model holds for a share of count packets coming to bytes
func charge(count, bytes int) int {
	return min(max(bytes, count*leastPacketBytes), peerDataBudget)
}

func total(sizes []int) int {
	bytes := 0
	for _, size := range sizes {
		bytes += size
	}
	return bytes
}

// reserveSized reserves the data budget for packets of the sizes given and appends them
// nil when the budget has no room for them
func reserveSized(p *Peer, sizes []int) *peerBatch {
	b := p.reserveBatchNow(len(sizes), total(sizes))
	if b != nil {
		for _, size := range sizes {
			b.append(packetBytes[:size], 0)
		}
	}
	return b
}

// send hands the reservation to the peer's sender, through its place when it has one
func (h *heldBatch) send() error {
	if h.place != nil {
		return h.place.Send()
	}
	return h.batch.enqueue()
}

// budgetMachine drives one peer beside a model of what each budget holds
// its rules reserve any size on both budgets, send in any order and have transmits succeed or fail
// the transport returns only while a drain step holds it open
// so the model knows at every step which packets have come back
type budgetMachine struct {
	peer  *Peer
	valve *valve
	held  []*heldBatch
	// data and control are the model's counts of the data budget in bytes and the control budget in packets
	data, control int
	// dataBytes and dataPackets are the bytes and the packets of the data shares held from their reservation until their transmit returns
	dataBytes, dataPackets int
	// dropped, failed and offered count packets
	dropped, failed uint64
	offered         uint64
}

// reserveData asks the data budget for a share of packets of the sizes given
// a refusal the model has room for is an error, and an admission it has no room for is left to the invariants
// stamped an hour ahead, so the delay control reads it below its target however long the case runs
// and the model need not count delay drops
func (m *budgetMachine) reserveData(tc hegel.TestCase, sizes []int) {
	room, bytes := peerDataBudget-m.data, total(sizes)
	m.offered += uint64(len(sizes))
	b := reserveSized(m.peer, sizes)
	if b == nil {
		if m.data == 0 {
			tc.Errorf("an empty budget refused a share of %d packets coming to %d bytes", len(sizes), bytes)
		} else if charge(len(sizes), bytes) <= room {
			tc.Errorf("a share of %d packets coming to %d bytes was refused with %d of room", len(sizes), bytes, room)
		}
		m.dropped += uint64(len(sizes))
		return
	}
	b.admitted += time.Hour
	h := &heldBatch{batch: b, count: len(sizes), bytes: bytes, charge: charge(len(sizes), bytes)}
	m.data += h.charge
	m.dataBytes += h.bytes
	m.dataPackets += h.count
	m.held = append(m.held, h)
}

// reservationKinds are where a data reservation is drawn
// anywhere, exactly the room left, or one byte past it
var reservationKinds = []string{"any size", "the room left", "one past the room left"}

// RuleReserveData asks the data budget for a share of some size, the edges of the room left among them
// and a read whose every packet is cut into fragments, more packets than the budget holds of leastPacketBytes each
func (m *budgetMachine) RuleReserveData(tc hegel.TestCase) {
	room := peerDataBudget - m.data
	size := hegel.Draw(tc, pbt.Spanning(smallestPacket, largestPacket))
	sizes := slices.Repeat([]int{size}, hegel.Draw(tc, pbt.Spanning(1, transmitBatchSize*mostFragments)))
	switch hegel.Draw(tc, hegel.SampledFrom(reservationKinds)) {
	case "the room left":
		sizes = split(max(1, room))
	case "one past the room left":
		sizes = split(room + 1)
	}
	m.reserveData(tc, sizes)
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
	m.held = append(m.held, &heldBatch{batch: place.batch, place: place, count: 1, charge: 1, control: true})
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
	data, control, dataBytes, dataPackets := m.data, m.control, m.dataBytes, m.dataPackets
	var packets uint64
	for _, h := range m.held[:reach] {
		if h.control {
			control -= h.charge
		} else {
			data -= h.charge
			dataBytes -= h.bytes
			dataPackets -= h.count
		}
		packets += uint64(h.count)
	}
	m.valve.set(true, fail)
	m.settle(tc, data, control)
	m.valve.set(false, false)
	m.data, m.control, m.dataBytes, m.dataPackets = data, control, dataBytes, dataPackets
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
			tc.Errorf("the budgets hold %d data bytes and %d control packets, the model %d and %d", gotData, gotControl, data, control)
			return
		}
	}
}

// dataShares is how many data shares the peer holds
func (m *budgetMachine) dataShares() int {
	shares := 0
	for _, h := range m.held {
		if !h.control {
			shares++
		}
	}
	return shares
}

// InvariantBytesHeldWithinBudget holds the bytes of the data packets the peer admitted and has not yet transmitted to its budget at every step
// but for one share larger than the whole budget, which only an empty budget admits
func (m *budgetMachine) InvariantBytesHeldWithinBudget(tc hegel.TestCase) {
	if m.dataBytes > peerDataBudget && m.dataShares() > 1 {
		tc.Errorf("the peer holds %d bytes of data packets in %d shares, past its budget of %d", m.dataBytes, m.dataShares(), peerDataBudget)
	}
}

// InvariantPacketsHeldWithinBudget holds the data packets the peer admitted and has not yet transmitted to as many as the budget holds of leastPacketBytes each
// however small they are, but for one share of more, which only an empty budget admits
func (m *budgetMachine) InvariantPacketsHeldWithinBudget(tc hegel.TestCase) {
	if m.dataPackets > peerDataBudget/leastPacketBytes && m.dataShares() > 1 {
		tc.Errorf("the peer holds %d data packets in %d shares, past the %d its budget holds of %d bytes each", m.dataPackets, m.dataShares(), peerDataBudget/leastPacketBytes, leastPacketBytes)
	}
}

// InvariantPeerAgreesWithModel holds the budgets and both drop counters to the model at every step
func (m *budgetMachine) InvariantPeerAgreesWithModel(tc hegel.TestCase) {
	if m.data > peerDataBudget {
		tc.Errorf("the model holds %d bytes of the data budget, past its %d", m.data, peerDataBudget)
	}
	if got := m.peer.dataBudget.used.Load(); got != int64(m.data) {
		tc.Errorf("the data budget holds %d bytes, the model %d", got, m.data)
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

// a peer's data budget counts bytes, at least leastPacketBytes a packet and at most the whole budget a share, and its control budget packets
// from their reservation until the transmit that carried them returns
// whatever sizes up to the largest link.mtu the machine reserves on either budget, in whatever order it sends, and whether its transmits succeed or fail
// a reservation is admitted exactly when the model has room for it, and an empty budget admits a share of any size
// the data packets held never come to more bytes than the budget, nor to more packets than it holds of 1400 bytes each, but for one share admitted alone
// a refusal counts all of its packets, and everything held comes back once its transmit returns
// then the peer closes with reservations still held, or sent and waiting behind one that is held
// and every packet it was offered is counted once, as transmitted, lost in the transport or dropped
// and both budgets are back to empty
func TestBudgetAgreesWithItsModel(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		v := newValve()
		m := &budgetMachine{valve: v, peer: NewPeerReserved("peer",
			func(int) (BatchSealer, error) { return passThrough, nil }, v.transmit, nil)}
		// reads of one size and count taken up front, up to one more than the budget holds of the smallest full ones
		// so a case reaches its edge in a few steps, by bytes or by packets
		// a read cut into more packets than the budget holds of leastPacketBytes each among them
		size := hegel.Draw(ht, pbt.Spanning(smallestPacket, largestPacket))
		count := hegel.Draw(ht, pbt.Spanning(transmitBatchSize, transmitBatchSize*mostFragments))
		for range hegel.Draw(ht, pbt.Spanning(0, peerDataBudget/leastPacketBytes/transmitBatchSize+1)) {
			m.reserveData(ht, slices.Repeat([]int{size}, count))
		}
		for range hegel.Draw(ht, pbt.Spanning(0, controlQueueSize)) {
			m.RuleReserveControl(ht)
		}
		hegel.RunStateful(ht, m, hegel.WithAlwaysCheckInvariants("InvariantBytesHeldWithinBudget", "InvariantPacketsHeldWithinBudget", "InvariantPeerAgreesWithModel"))

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
