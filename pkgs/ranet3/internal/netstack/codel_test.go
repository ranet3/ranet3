// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/internal/events"
)

// the delay control on a fake clock, one batch a millisecond unless a phase spaces them out
// every batch of a phase reads the same sojourn, and in some phases the queue empties after each batch
// each drop falls on the first batch at or after the time the RFC 8289 control law gives, the interval over the square root of the count
// the count starts at one on a fresh entry, and at the last state's drops past its first on an entry within 16 intervals of that state's schedule
// an empty queue ends the dropping state and starts the interval over, as RFC 8289 section 5.5 has it
// and keeps the count and the schedule, so a delay back soon after it starts at the rate the state had reached
// the phases run with the clock at zero and an hour in, where a schedule reset to zero is older than the 16 intervals a quick entry allows
func TestCodelEntersStaysLeavesAndReenters(t *testing.T) {
	for _, clock := range []struct {
		name string
		age  time.Duration
	}{{"a clock at zero", 0}, {"a clock an hour in", time.Hour}} {
		t.Run(clock.name, func(t *testing.T) { codelPhases(t, clock.age) })
	}
}

// codelPhases runs the delay control through the phases of TestCodelEntersStaysLeavesAndReenters on a clock that reads age at its start
func codelPhases(t *testing.T, age time.Duration) {
	var c codel
	total := 0
	for _, phase := range []struct {
		name              string
		from, to, sojourn int // milliseconds
		gap               int // milliseconds between two batches, one when zero
		empty             bool
		drops             []int
		dropping          bool // the state the phase ends in
	}{
		{name: "below the target", from: 1, to: 50, sojourn: 1},
		{name: "above it for less than an interval", from: 51, to: 120, sojourn: 20},
		{name: "below it again", from: 121, to: 130, sojourn: 1},
		// an interval after the delay went above, then 100, 70.7, 57.7, 50, 44.7 and 40.8 milliseconds apart
		{name: "above it for long enough", from: 131, to: 600, sojourn: 20, dropping: true,
			drops: []int{231, 331, 402, 460, 510, 555, 595}},
		{name: "below it", from: 601, to: 650, sojourn: 1},
		// soon after the last state, so the count starts at its 6 drops past the first
		{name: "above it soon after", from: 651, to: 900, sojourn: 20, dropping: true,
			drops: []int{751, 792, 830, 865, 899}},
		// a batch before the next drop is due, after which the queue is empty
		{name: "the queue empties while dropping", from: 901, to: 901, sojourn: 20, empty: true},
		// so the interval starts over rather than finding a drop long due
		// and the entry that follows is soon enough for the count to start at the state's 4 drops past its first
		{name: "above it again once the queue emptied", from: 902, to: 1150, sojourn: 20, dropping: true,
			drops: []int{1002, 1052, 1097, 1138}},
		{name: "below it for 2 seconds", from: 1151, to: 2900, sojourn: 1},
		// past 16 intervals, so the count starts over at one
		{name: "above it long after", from: 2901, to: 3200, sojourn: 20, dropping: true,
			drops: []int{3001, 3101, 3172}},
		{name: "below it once more", from: 3201, to: 3300, sojourn: 1},
		// each batch alone in the queue, so none finds the interval of the one before it run out
		{name: "lone batches above it further apart than the interval", from: 3301, to: 5301, gap: 200, sojourn: 8, empty: true},
	} {
		var drops []int
		for at := phase.from; at <= phase.to; at += max(phase.gap, 1) {
			if c.drop(age+time.Duration(at)*time.Millisecond, time.Duration(phase.sojourn)*time.Millisecond) {
				drops = append(drops, at)
			}
			if phase.empty {
				c.empty()
			}
		}
		if !slices.Equal(drops, phase.drops) {
			t.Errorf("%s: dropped at %v milliseconds, want %v", phase.name, drops, phase.drops)
		}
		if c.dropping != phase.dropping {
			t.Errorf("%s: ended in the dropping state %v, want %v", phase.name, c.dropping, phase.dropping)
		}
		total += len(drops)
	}
	if total != 19 {
		t.Errorf("the delay control dropped %d times, want 19", total)
	}
}

// codelEvents lists the events the delay control of the peers on bus recorded
func codelEvents(bus *events.Bus) []control.Event {
	return bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return strings.HasPrefix(kind, "netstack.codel.") }, 0)
}

// holdingTransport records what a peer's sender hands it
// and holds the sender inside its first transmit until letGo
type holdingTransport struct {
	entered, release chan struct{}
	hold, let        sync.Once
	fails            bool
	mu               sync.Mutex
	sent             [][]byte
}

func newHoldingTransport(fails bool) *holdingTransport {
	return &holdingTransport{entered: make(chan struct{}), release: make(chan struct{}), fails: fails}
}

func (h *holdingTransport) transmit(sealed [][]byte) error {
	h.hold.Do(func() {
		close(h.entered)
		<-h.release
	})
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, packet := range sealed {
		h.sent = append(h.sent, bytes.Clone(packet))
	}
	if h.fails {
		return errors.New("sendto: network is unreachable")
	}
	return nil
}

func (h *holdingTransport) letGo() { h.let.Do(func() { close(h.release) }) }

// transmitted is every packet the transport has been handed so far
func (h *holdingTransport) transmitted() [][]byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.sent)
}

// stand holds the sender in the transport with what first queues
// then queues what behind queues, and lets the transport go an interval later
// so every data batch behind finds the delay above the target for a whole interval once its turn comes
func stand(t *testing.T, h *holdingTransport, first, behind func()) {
	t.Helper()
	first()
	select {
	case <-h.entered:
	case <-time.After(deliveryTimeout):
		t.Fatal("the sender never reached the transport, so nothing waits behind it")
	}
	behind()
	time.Sleep(codelInterval)
	h.letGo()
}

// aged reserves a batch of the packets given, as if it had been reserved age ago
func aged(t *testing.T, p *Peer, age time.Duration, packets ...string) *peerBatch {
	t.Helper()
	b := p.reserveBatchNow(len(packets))
	if b == nil {
		t.Fatalf("the budget refused a batch of %d packets", len(packets))
	}
	for _, packet := range packets {
		b.append([]byte(packet), 0)
	}
	b.admitted -= age
	return b
}

// queue hands b to its peer's sender
func queue(t *testing.T, b *peerBatch) {
	t.Helper()
	if err := b.enqueue(); err != nil {
		t.Fatalf("an open peer refused the batch: %v", err)
	}
}

// sojournOf is the sojourn an event of the delay control carries
func sojournOf(t *testing.T, event control.Event) time.Duration {
	t.Helper()
	sojourn, err := time.ParseDuration(event.Attrs["sojourn"])
	if err != nil {
		t.Fatalf("the event %+v carries no sojourn: %v", event, err)
	}
	return sojourn
}

// once the delay through a peer's queue has stood above the target for an interval
// the sender drops the first packet of the batch whose turn it is and sends the rest
// counts the drop among the packets the peer did not send on purpose and under the delay's own reason
// and records the change of state, as it does again when a batch comes through below the target
// a packet the transport then loses is counted there and only there
func TestSenderDropsTheHeadOfAStandingQueue(t *testing.T) {
	for _, transportFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "the transport takes the rest", true: "the transport loses the rest"}[transportFails], func(t *testing.T) {
			h := newHoldingTransport(transportFails)
			bus := events.New()
			peer := NewPeerReserved("peer", func(int) (BatchSealer, error) { return passThrough, nil }, h.transmit, bus.Emit)
			defer peer.Close()
			defer h.letGo()

			stand(t, h, func() {
				queue(t, aged(t, peer, time.Second, "first"))
			}, func() {
				queue(t, aged(t, peer, time.Second, "head", "tail"))
				// and one that reads below the target ends the dropping state
				queue(t, aged(t, peer, -time.Second, "fresh"))
			})
			waitForBudget(t, peer)

			want := [][]byte{[]byte("first"), []byte("tail"), []byte("fresh")}
			if got := h.transmitted(); !slices.EqualFunc(got, want, bytes.Equal) {
				t.Errorf("the transport was handed %q, want %q", got, want)
			}
			if peer.Dropped() != 1 || peer.DelayDropped() != 1 {
				t.Errorf("the peer counted %d drops, %d of them for the delay, want the one head", peer.Dropped(), peer.DelayDropped())
			}
			if want := map[bool]uint64{false: 0, true: 3}[transportFails]; peer.SendFailed() != want {
				t.Errorf("the peer counted %d packets lost in the transport, want %d", peer.SendFailed(), want)
			}
			got := codelEvents(bus)
			if len(got) != 2 || got[0].Kind != "netstack.codel.dropping" || got[1].Kind != "netstack.codel.drained" {
				t.Fatalf("the peer recorded %+v, want it to start dropping and then drain", got)
			}
			for _, event := range got {
				if event.Peer != "peer" || event.Attrs["target"] != codelTarget.String() {
					t.Errorf("the peer recorded %+v, want its own name and a target of %s", event, codelTarget)
				}
			}
			if dropping, drained := sojournOf(t, got[0]), sojournOf(t, got[1]); dropping < time.Second || drained >= codelTarget {
				t.Errorf("the events carry sojourns of %s and %s, want the batch a second old and the one below the target", dropping, drained)
			}

			// a read the budget has no room for is dropped too, under no reason of the delay's
			if peer.reserveBatchNow(peerDataBudget+1) != nil {
				t.Fatal("the budget admitted more packets than it holds")
			}
			if peer.Dropped() != 1+peerDataBudget+1 || peer.DelayDropped() != 1 {
				t.Errorf("a refused read left %d drops, %d of them for the delay", peer.Dropped(), peer.DelayDropped())
			}
		})
	}
}

// control packets carry babel and the completion its callers wait for
// so the delay control never drops one, however long the data queue they wait in has stood
func TestSenderNeverDropsAControlPacketForTheDelay(t *testing.T) {
	h := newHoldingTransport(false)
	peer := NewPeerReserved("peer", func(int) (BatchSealer, error) { return passThrough, nil }, h.transmit, nil)
	defer peer.Close()
	defer h.letGo()
	// control queues one control packet a second old
	control := func(packet string) {
		place, err := peer.ReserveRawOrDrop([]byte(packet), 41)
		if err != nil {
			t.Fatalf("an empty control budget refused the packet: %v", err)
		}
		place.batch.admitted -= time.Second
		if err := place.Send(); err != nil {
			t.Fatalf("an open peer refused the place: %v", err)
		}
	}

	stand(t, h, func() {
		queue(t, aged(t, peer, time.Second, "first"))
	}, func() {
		control("hello")
		queue(t, aged(t, peer, time.Second, "head", "tail"))
		control("update")
	})
	waitForBudget(t, peer)

	want := [][]byte{[]byte("first"), []byte("hello"), []byte("tail"), []byte("update")}
	if got := h.transmitted(); !slices.EqualFunc(got, want, bytes.Equal) {
		t.Errorf("the transport was handed %q, want %q", got, want)
	}
	if peer.Dropped() != 1 || peer.DelayDropped() != 1 {
		t.Errorf("the peer counted %d drops, %d of them for the delay, want the one data head", peer.Dropped(), peer.DelayDropped())
	}
}

// RFC 8289 section 5.5 ends the dropping state and starts the interval over once the queue is empty
// so the sender records the end of the state, with a sojourn of zero, as soon as its queue empties
// and a late ticket after the idle queue, which delays every batch behind it at once, drops nothing
func TestSenderForgetsTheDelayOnceItsQueueEmpties(t *testing.T) {
	h := newHoldingTransport(false)
	bus := events.New()
	peer := NewPeerReserved("peer", func(int) (BatchSealer, error) { return passThrough, nil }, h.transmit, bus.Emit)
	defer peer.Close()
	defer h.letGo()

	stand(t, h, func() {
		queue(t, aged(t, peer, time.Second, "first"))
	}, func() {
		queue(t, aged(t, peer, time.Second, "head"))
	})
	waitUntil(t, "the peer to record two changes of its delay state", func() bool { return len(codelEvents(bus)) >= 2 })
	got := codelEvents(bus)
	if len(got) != 2 || got[0].Kind != "netstack.codel.dropping" || got[1].Kind != "netstack.codel.drained" || sojournOf(t, got[1]) != 0 {
		t.Fatalf("the peer recorded %+v, want it to start dropping and to drain with a sojourn of 0s once its queue emptied", got)
	}
	if peer.DelayDropped() != 1 {
		t.Fatalf("the standing queue lost %d packets to the delay control, want its one head", peer.DelayDropped())
	}

	// idle past the drop the ended state had scheduled next
	time.Sleep(codelInterval)
	late := aged(t, peer, 10*time.Millisecond, "late")
	for i := range 20 {
		queue(t, aged(t, peer, 10*time.Millisecond, fmt.Sprintf("behind %d", i)))
	}
	queue(t, late)
	waitForBudget(t, peer)
	if got := peer.DelayDropped(); got != 1 {
		t.Errorf("the late ticket and the 20 batches behind it lost %d packets to the delay control, want none", got-1)
	}
	if got := len(h.transmitted()); got != 22 {
		t.Errorf("the transport was handed %d packets, want the first and the 21 that came after the idle queue", got)
	}
}

// a data batch reserved and still with its worker holds packets of the budget, so the queue the delay control measures is not empty
// the sender that has sent all it was handed and waits for that batch keeps the delay state it is in
// and drops the head of the batch once it arrives, since the next drop of the state has come due
func TestSenderKeepsTheDelayWhileADataBatchIsStillReserved(t *testing.T) {
	h := newHoldingTransport(false)
	peer := NewPeerReserved("peer", func(int) (BatchSealer, error) { return passThrough, nil }, h.transmit, nil)
	defer peer.Close()
	defer h.letGo()

	var late *peerBatch
	stand(t, h, func() {
		queue(t, aged(t, peer, time.Second, "first"))
	}, func() {
		queue(t, aged(t, peer, time.Second, "head", "tail"))
		// reserved behind them and not queued, as while its worker still seals it
		late = aged(t, peer, time.Second, "late head", "late tail")
	})
	waitUntil(t, "the sender to drop the head of the standing queue", func() bool { return peer.DelayDropped() == 1 })
	// the sender sends the tail and waits for late
	// and the drop that follows the first by an interval has come due by the time late is queued
	time.Sleep(codelInterval)
	queue(t, late)
	waitForBudget(t, peer)

	if got := peer.DelayDropped(); got != 2 {
		t.Errorf("the batch the sender waited for lost %d packets to the delay control, want its head", got-1)
	}
	want := [][]byte{[]byte("first"), []byte("tail"), []byte("late tail")}
	if got := h.transmitted(); !slices.EqualFunc(got, want, bytes.Equal) {
		t.Errorf("the transport was handed %q, want %q", got, want)
	}
}

// a batch alone in the queue that reads above the target leaves the queue empty behind it
// so the next one, an interval or more later, starts the interval over rather than finding it run out
// and a sparse flow whose every packet waits a little too long, as on a loaded node, loses none of them
func TestLoneLateBatchesLoseNothing(t *testing.T) {
	h := newHoldingTransport(false)
	h.letGo()
	bus := events.New()
	peer := NewPeerReserved("peer", func(int) (BatchSealer, error) { return passThrough, nil }, h.transmit, bus.Emit)
	defer peer.Close()
	const lone = 3
	for i := range lone {
		queue(t, aged(t, peer, 8*time.Millisecond, fmt.Sprintf("lone %d", i)))
		waitForBudget(t, peer)
		time.Sleep(codelInterval)
	}
	if got := len(h.transmitted()); got != lone || peer.Dropped() != 0 || len(codelEvents(bus)) != 0 {
		t.Errorf("the transport was handed %d of %d lone packets, the peer dropped %d and recorded %+v", got, lone, peer.Dropped(), codelEvents(bus))
	}
}

// a batch whose reservation or seal failed sealed nothing and still reaches the sender in its turn
// the delay control leaves it alone, having no packet of it to drop
// so its packets are counted once among the drops and none of them for the delay
func TestDelayControlLeavesABatchThatSealedNothing(t *testing.T) {
	refused, unsealed := errors.New("no child sa"), errors.New("seal")
	// failure is the error the next reservation meets, nil for none
	var failure error
	h := newHoldingTransport(false)
	peer := NewPeerReserved("peer", func(int) (BatchSealer, error) {
		switch failure {
		case refused:
			return nil, refused
		case unsealed:
			return func([][]byte, []byte, [][]byte) ([][]byte, error) { return nil, unsealed }, nil
		}
		return passThrough, nil
	}, h.transmit, nil)
	defer peer.Close()
	defer h.letGo()

	stand(t, h, func() {
		queue(t, aged(t, peer, time.Second, "first"))
	}, func() {
		// first in line once the delay has stood for an interval, where a batch with packets would lose its head
		for _, err := range []error{refused, unsealed} {
			failure = err
			queue(t, aged(t, peer, time.Second, "lost", "lost"))
		}
		failure = nil
		queue(t, aged(t, peer, time.Second, "head", "tail"))
	})
	waitForBudget(t, peer)

	if peer.Dropped() != 5 || peer.DelayDropped() != 1 {
		t.Errorf("the peer counted %d drops, %d of them for the delay, want the 4 that sealed nothing and the head, and only the head for the delay",
			peer.Dropped(), peer.DelayDropped())
	}
	want := [][]byte{[]byte("first"), []byte("tail")}
	if got := h.transmitted(); !slices.EqualFunc(got, want, bytes.Equal) {
		t.Errorf("the transport was handed %q, want %q", got, want)
	}
}

// the delay the control reads is from the reservation, not from the peer's start
// or every batch of a peer that has run past the target would read as late and an idle queue would be dropped from
func TestBatchIsStampedWhenReserved(t *testing.T) {
	peer := NewPeerReserved("peer", func(int) (BatchSealer, error) { return passThrough, nil },
		func([][]byte) error { return nil }, nil)
	defer peer.Close()
	// the sender reads started only once a batch reaches it, after this
	peer.started = peer.started.Add(-time.Hour)
	b := peer.reserveBatchNow(1)
	if age := time.Since(peer.started) - b.admitted; age < 0 || age >= deliveryTimeout {
		t.Errorf("a batch just reserved reads %s old", age)
	}
}
