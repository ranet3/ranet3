// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package netstack

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// budgetSettle is how often a wait looks again at what the sender has done
// and budgetStopTimeout how long the machine waits for a closed peer's sender to end, which Close waits for only through its grace
// minutes, past any stall a loaded host gives the sender
const (
	budgetSettle      = 50 * time.Microsecond
	budgetStopTimeout = 2 * time.Minute
)

// valve holds the peer's transport until a step opens it
// and decides what the transport answers while it is open
// returned counts the packets of every transmit that has returned, failed or not, and is written under mu
type valve struct {
	mu          sync.Mutex
	cond        *sync.Cond
	open        bool
	fail        bool
	returned    uint64
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
	v.returned += uint64(len(sealed))
	v.cond.Broadcast()
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

// await waits until the transport has returned packets packets in all
func (v *valve) await(packets uint64) {
	v.mu.Lock()
	defer v.mu.Unlock()
	for v.returned < packets {
		v.cond.Wait()
	}
}

// heldBatch is a reservation the machine has made and not yet seen to its end
// index is its place among the machine's reservations, count its packets, bytes what they come to and charge what the model says it holds of its budget
type heldBatch struct {
	batch   *peerBatch
	place   *Place
	index   uint64
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
	return h.batch.finish()
}

// budgetMachine drives one peer beside a model of what each budget holds
// its rules reserve any size on both budgets, send in any order, have transmits succeed or fail and close the peer
// the transport returns only while a drain step holds it open
// so the model knows at every step which packets have come back
type budgetMachine struct {
	peer  *Peer
	valve *valve
	held  []*heldBatch
	// reserved counts the reservations the peer's SA was asked for, each sealed into packets that carry its index
	// written under the peer's reserveMu
	reserved uint64
	// orderMu guards last and disorder, the index the transport was last handed and the first index it was handed after a later one
	orderMu  sync.Mutex
	last     uint64
	disorder string
	// all is every batch the peer handed the machine, whose done channels must be empty once the peer has closed
	all []*peerBatch
	// data and control are the model's counts of the data budget in bytes and the control budget in packets
	data, control int
	// dataBytes and dataPackets are the bytes and the packets of the data shares held from their reservation until their transmit returns
	dataBytes, dataPackets int
	// dropped, failed and offered count packets
	dropped, failed uint64
	offered         uint64
	// through counts the packets the drains have let through the transport
	through uint64
	closed  bool
}

// newBudgetMachine is a machine whose peer seals each packet as the index of its reservation
// and whose transport notes the first packet it is handed after one of a later reservation, whether or not the valve then lets it through
func newBudgetMachine() *budgetMachine {
	m := &budgetMachine{valve: newValve()}
	m.peer = NewPeer("peer", func(int) (BatchSealer, error) {
		tag := binary.BigEndian.AppendUint64(nil, m.reserved)
		m.reserved++
		return func(raw [][]byte, _ []byte, out [][]byte) ([][]byte, error) {
			out = out[:0]
			for range raw {
				out = append(out, tag)
			}
			return out, nil
		}, nil
	}, func(sealed [][]byte) error {
		m.orderMu.Lock()
		for _, packet := range sealed {
			index := binary.BigEndian.Uint64(packet)
			if index < m.last && m.disorder == "" {
				m.disorder = fmt.Sprintf("reservation %d after %d", index, m.last)
			}
			m.last = index
		}
		m.orderMu.Unlock()
		return m.valve.transmit(sealed)
	}, nil)
	return m
}

// reserveData asks the data budget for a share of packets of the sizes given
// a refusal the model has room for is an error, and an admission it has no room for is left to the invariants
// stamped an hour ahead, so the delay control reads it below its target however long the case runs
// and the model need not count delay drops
// a closed peer refuses it and counts its packets
func (m *budgetMachine) reserveData(tc hegel.TestCase, sizes []int) {
	room, bytes := peerDataBudget-m.data, total(sizes)
	m.offered += uint64(len(sizes))
	index := m.reserved
	b := reserveSized(m.peer, sizes)
	if m.closed {
		if b != nil {
			tc.Errorf("a closed peer admitted a share of %d packets", len(sizes))
		}
		m.dropped += uint64(len(sizes))
		return
	}
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
	m.all = append(m.all, b)
	h := &heldBatch{batch: b, index: index, count: len(sizes), bytes: bytes, charge: charge(len(sizes), bytes)}
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
	index := m.reserved
	place, err := m.peer.ReserveRawOrDrop([]byte{2}, 41)
	if fits := !m.closed && m.control < controlQueueSize; (err == nil) != fits {
		tc.Errorf("a control packet with %d of %d places taken, the peer closed %v, was admitted %v, the model says %v", m.control, controlQueueSize, m.closed, err == nil, fits)
		return
	}
	if err != nil {
		m.dropped++
		return
	}
	m.control++
	m.all = append(m.all, place.batch)
	m.held = append(m.held, &heldBatch{batch: place.batch, place: place, index: index, count: 1, charge: 1, control: true})
}

// RuleSend sends one reservation the machine holds, in any order
// a closed peer refuses it, counts its packets and gives back what it held
func (m *budgetMachine) RuleSend(tc hegel.TestCase) {
	var unsent []*heldBatch
	for _, h := range m.held {
		if !h.queued {
			unsent = append(unsent, h)
		}
	}
	tc.Assume(len(unsent) > 0)
	h := unsent[hegel.Draw(tc, hegel.Integers(0, len(unsent)-1))]
	err := h.send()
	h.queued = true
	if !m.closed {
		if err != nil {
			tc.Errorf("an open peer refused reservation %d: %v", h.index, err)
		}
		return
	}
	if err == nil {
		tc.Errorf("a closed peer queued reservation %d", h.index)
	}
	m.giveBack(h)
	m.dropped += uint64(h.count)
	m.held = slices.DeleteFunc(m.held, func(held *heldBatch) bool { return held == h })
}

// giveBack takes what h holds off the model's budgets
func (m *budgetMachine) giveBack(h *heldBatch) {
	if h.control {
		m.control -= h.charge
		return
	}
	m.data -= h.charge
	m.dataBytes -= h.bytes
	m.dataPackets -= h.count
}

// reach is how many of the reservations held, from the first, were sent before the first that was not
func (m *budgetMachine) reach() int {
	reach := 0
	for reach < len(m.held) && m.held[reach].queued {
		reach++
	}
	return reach
}

// RuleClose closes the peer with its transport open
// the sender transmits every reservation sent before the first that was not, and gives back every other sent one, counting its packets
// the reservations not yet sent keep what they hold until they are sent
func (m *budgetMachine) RuleClose(tc hegel.TestCase) {
	tc.Assume(!m.closed)
	reach := m.reach()
	var kept []*heldBatch
	for i, h := range m.held {
		switch {
		case i < reach:
			m.giveBack(h)
		case h.queued:
			m.giveBack(h)
			m.dropped += uint64(h.count)
		default:
			kept = append(kept, h)
		}
	}
	m.valve.set(true, false)
	m.peer.Close()
	m.stopped(tc)
	m.held, m.closed = kept, true
}

// stopped waits for the peer's sender to end, which Close waits for only through its grace
func (m *budgetMachine) stopped(tc hegel.TestCase) {
	select {
	case <-m.peer.senderDone:
	case <-time.After(budgetStopTimeout):
		tc.Errorf("the sender never finished after the peer closed")
	}
}

// RuleDrain lets the transport take everything the sender can reach, every reservation sent before the first one that is not
// and has the transport succeed or fail
// those packets come back to their budgets and nothing else does
func (m *budgetMachine) RuleDrain(tc hegel.TestCase) {
	tc.Assume(!m.closed)
	fail := hegel.Draw(tc, hegel.Booleans())
	reach := m.reach()
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
	m.through += packets
	m.valve.set(true, fail)
	m.settle(tc, data, control)
	m.valve.set(false, false)
	m.data, m.control, m.dataBytes, m.dataPackets = data, control, dataBytes, dataPackets
	if fail {
		m.failed += packets
	}
	m.held = m.held[reach:]
}

// settle waits for the transport to return every packet the drains let through and for the sender to give back what they held
// then holds both budgets to what the model holds
// the sender adds a run of transmits to its release sizes only after the last of them has given its budget back
// so a sum that counts every packet let through finds each of them back in its budget
// both counts reach the drains' total only while the delay control drops none of those packets, as reserveData's stamp an hour ahead and the control's skip of control places ensure
// neither wait has a bound, since a stall of any length only delays both events
func (m *budgetMachine) settle(tc hegel.TestCase, data, control int) {
	m.valve.await(m.through)
	for m.peer.SendStats().Releases.Sum < m.through {
		time.Sleep(budgetSettle)
	}
	if gotData, gotControl := m.peer.dataBudget.used.Load(), m.peer.controlBudget.used.Load(); gotData != int64(data) || gotControl != int64(control) {
		tc.Errorf("the budgets hold %d data bytes and %d control packets, the model %d and %d", gotData, gotControl, data, control)
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

// InvariantSentInReservationOrder holds the transport to packets in the order of their reservations
func (m *budgetMachine) InvariantSentInReservationOrder(tc hegel.TestCase) {
	m.orderMu.Lock()
	defer m.orderMu.Unlock()
	if m.disorder != "" {
		tc.Errorf("the transport was handed %s", m.disorder)
	}
}

// a peer's data budget counts bytes, at least leastPacketBytes a packet and at most the whole budget a share, and its control budget packets
// from their reservation until the transmit that carried them returns
// whatever sizes up to the largest link.mtu the machine reserves on either budget, in whatever order it sends, and whether its transmits succeed or fail
// a reservation is admitted exactly when the model has room for it, and an empty budget admits a share of any size
// the data packets held never come to more bytes than the budget, nor to more packets than it holds of 1400 bytes each, but for one share admitted alone
// a refusal counts all of its packets, and everything held comes back once its transmit returns
// the transport is handed packets in the order of their reservations
// the peer may close at any step, after which it refuses every reservation and every send and counts their packets
// and at the end the peer closes, if it has not, with reservations still held, or sent and waiting behind one that is held
// and every packet it was offered is counted once, as transmitted, lost in the transport or dropped
// both budgets are back to empty, and no batch it handed out holds a token of its seal
func TestBudgetAgreesWithItsModel(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		m := newBudgetMachine()
		v := m.valve
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
		hegel.RunStateful(ht, m, hegel.WithAlwaysCheckInvariants("InvariantBytesHeldWithinBudget", "InvariantPacketsHeldWithinBudget", "InvariantPeerAgreesWithModel", "InvariantSentInReservationOrder"))

		// then the session ends
		// and the peer closes with whatever is held, sent or on its way to the transport
		v.set(true, false)
		m.peer.Close()
		m.stopped(ht)
		for _, h := range m.held {
			if h.queued {
				continue
			}
			if h.send() == nil {
				ht.Fatalf("a closed peer queued reservation %d", h.index)
			}
		}
		m.settle(ht, 0, 0)
		if counted := uint64(v.transmitted.Load()) + m.peer.SendFailed() + m.peer.Dropped(); counted != m.offered {
			ht.Fatalf("the peer was offered %d packets and counted %d: %d transmitted, %d lost in the transport, %d dropped",
				m.offered, counted, v.transmitted.Load(), m.peer.SendFailed(), m.peer.Dropped())
		}
		m.InvariantSentInReservationOrder(ht)
		for _, b := range m.all {
			if len(b.done) != 0 {
				ht.Fatal("a batch went back to the pool holding the token of its seal")
			}
		}
	})
}
