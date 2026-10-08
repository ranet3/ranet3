// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"bytes"
	"errors"
	"fmt"
	"math/bits"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"
)

// passThrough seals a packet as itself, into the storage the pool hands back
func passThrough(raw [][]byte, _ []byte, out [][]byte) ([][]byte, error) {
	return append(out[:0], raw...), nil
}

// cloning seals each packet as a copy of its own
// for a peer whose plaintext is recycled before its sender transmits
func cloning(raw [][]byte, _ []byte, out [][]byte) ([][]byte, error) {
	out = out[:0]
	for _, packet := range raw {
		out = append(out, bytes.Clone(packet))
	}
	return out, nil
}

// waitForBudget waits until both budgets of p hold nothing
func waitForBudget(tb testing.TB, p *Peer) {
	tb.Helper()
	waitUntil(tb, "the peer to give back both of its budgets", func() bool {
		return p.dataBudget.used.Load() == 0 && p.controlBudget.used.Load() == 0
	})
}

// the data budget counts bytes rather than packets or reads, and a packet holds at least leastPacketBytes of it
// a read that fits is admitted however the rest of the budget is split
// and one that does not fit is refused whole and counted in packets, without taking a ticket or a sequence range
func TestDataBudgetAdmitsByBytes(t *testing.T) {
	var asked atomic.Int64
	peer := NewPeerReserved("peer", func(count int) (BatchSealer, error) {
		asked.Add(int64(count))
		return passThrough, nil
	}, func([][]byte) error { return nil }, nil)
	defer peer.Close()

	const jumbo = transmitBatchSize * 8918
	if peer.reserveBatchNow(transmitBatchSize, jumbo) == nil {
		t.Fatal("an empty budget refused a full read of jumbo packets")
	}
	if peer.reserveBatchNow(1, 60) == nil {
		t.Fatal("the budget refused one small packet")
	}
	if got := peer.dataBudget.used.Load(); got != jumbo+leastPacketBytes {
		t.Fatalf("the budget holds %d bytes, want the jumbo read's %d and the least a packet holds, %d", got, jumbo, leastPacketBytes)
	}
	room := int(peerDataBudget - peer.dataBudget.used.Load())
	tickets := peer.reserved

	if peer.reserveBatchNow(2, room+1) != nil {
		t.Fatalf("a read of %d bytes was admitted with room for %d", room+1, room)
	}
	if got := peer.Dropped(); got != 2 {
		t.Errorf("the refused read counted %d drops, want its 2 packets", got)
	}
	if peer.reserved != tickets || asked.Load() != transmitBatchSize+1 {
		t.Errorf("the refused read took a ticket or a sequence range: %d tickets against %d, %d packets asked of the SA",
			peer.reserved, tickets, asked.Load())
	}
	if peer.reserveBatchNow(3, room) == nil {
		t.Fatal("a read of exactly the room left was refused")
	}
	if peer.reserveBatchNow(1, 1) != nil {
		t.Fatal("a full budget admitted one more byte")
	}
	if got := peer.Dropped(); got != 3 {
		t.Errorf("the peer counted %d drops, want the 3 packets it refused", got)
	}
}

// a share larger than the whole data budget, as a full read at the largest link.mtu comes to, is admitted into an empty budget and holds all of it
// and refused while anything else is held
func TestShareLargerThanTheBudgetIsAdmittedOnlyAlone(t *testing.T) {
	peer := NewPeerReserved("peer", func(int) (BatchSealer, error) { return passThrough, nil }, func([][]byte) error { return nil }, nil)
	defer peer.Close()
	const largest = transmitBatchSize * 65470
	small := filled(peer, 1)
	if peer.reserveBatchNow(transmitBatchSize, largest) != nil {
		t.Fatal("a budget holding one packet admitted a share larger than the whole of it")
	}
	if err := small.enqueue(); err != nil {
		t.Fatal(err)
	}
	waitForBudget(t, peer)
	if peer.reserveBatchNow(transmitBatchSize, largest) == nil {
		t.Fatal("an empty budget refused a share larger than the whole of it")
	}
	if got := peer.dataBudget.used.Load(); got != peerDataBudget {
		t.Errorf("the share holds %d bytes of the budget, want all %d", got, peerDataBudget)
	}
}

// a read holds of its peer's data budget the bytes it sends the peer, a packet cut into fragments by the fragments' own bytes
// and so does a batch of forwarded segments, a segment cut into fragments among them
// every packet here holds more than leastPacketBytes, so the bytes rather than the floor decide what each share holds
func TestReservationHoldsTheBytesItSends(t *testing.T) {
	const mtu = 3000
	handed, release := make(chan int, 1), make(chan struct{})
	peer := NewPeerReserved("peer", func(int) (BatchSealer, error) { return passThrough, nil },
		func(sealed [][]byte) error { handed <- sealedBytes(sealed); <-release; return nil }, nil)
	defer peer.Close()
	defer close(release)
	peer.SetMTU(mtu)
	m := &Mesh{Name: "test0", Routes: NewRouteTable(), closed: make(chan struct{}),
		outboundBufferSize: tunOffset + 4000, outboundJobs: make(chan *outboundBatch, 1)}
	m.startSegmentReports()
	m.Routes.Set(netip.Prefix{}, segPrefix("::/0"), peer)
	m.Routes.Set(netip.Prefix{}, segPrefix("0.0.0.0/0"), peer)

	t.Run("read", func(t *testing.T) {
		b := m.newOutboundBatch(2)
		b.sizes[0] = copy(b.bufs[0][tunOffset:], udpPacket(tooBigSource[6], tooBigDestination[6], 2000, false))
		b.sizes[1] = copy(b.bufs[1][tunOffset:], udpPacket(tooBigSource[4], tooBigDestination[4], 4000, false))
		b.n = 2
		m.classify(b)
		m.dispatchOutbound(b)
		<-m.outboundJobs
		batch, used := b.batches[peer], peer.dataBudget.used.Load()
		if batch == nil {
			t.Fatal("the budget refused the read")
		}
		// the ticket goes to the sender with nothing in it, or the forwarded segments behind it wait for it
		if err := batch.enqueue(); err != nil {
			t.Fatal(err)
		}
		if len(b.cut.fragments) != 2 {
			t.Fatalf("the read cut %d fragments, want the two of its IPv4 packet", len(b.cut.fragments))
		}
		want := 2000 + len(b.cut.bytes)
		if used != int64(want) || batch.size != want {
			t.Errorf("the read holds %d bytes of the budget and is keyed by %d, want its %d", used, batch.size, want)
		}
		waitUntil(t, "the peer to give back the read's bytes", func() bool { return peer.dataBudget.used.Load() == 0 })
	})

	t.Run("forwarded segments", func(t *testing.T) {
		m.forwardSegments([]forwardedSegment{
			{raw: udpPacket(tooBigSource[6], tooBigDestination[6], 2000, false)},
			{raw: udpPacket(tooBigSource[6], tooBigDestination[6], 1900, false)},
			{raw: steeredThrough(t, udpPacket(tooBigSource[4], tooBigDestination[4], 4000, false), segAddr("3fff:1:69c:98d6::1"))},
		})
		var sent int
		select {
		case sent = <-handed:
		case <-time.After(deliveryTimeout):
			t.Fatal("the segments never reached the transport")
		}
		if cut := int(m.SegmentCounters().Forwarded) - 2; cut < 2 {
			t.Fatalf("the waypoint forwarded %d fragments of the segment too large for its session, want at least two", cut)
		}
		if got := peer.dataBudget.used.Load(); got != int64(sent) {
			t.Errorf("the segments hold %d bytes of the budget, want the %d the transport was handed", got, sent)
		}
	})
}

// sealedBytes is the length of packets, summed
func sealedBytes(packets [][]byte) int {
	bytes := 0
	for _, packet := range packets {
		bytes += len(packet)
	}
	return bytes
}

// reservers racing for the last packet of one budget never hold more than it allows between them
// take checks the room and takes it in one atomic step
// or two reservers that both saw the last packet free would both take it
// and every packet taken comes back once
func TestBudgetHoldsItsLimitUnderConcurrentReservers(t *testing.T) {
	const reservers, takes = 16, 1000
	budget := peerBudget{limit: controlQueueSize}
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
	sendThree := func(t *testing.T, p *Peer) {
		b := filled(p, 3)
		if b == nil {
			t.Fatal("an empty budget refused the batch")
		}
		_ = b.enqueue()
	}
	for _, test := range []path{
		{name: "sent", reserve: sealing, send: sent, drive: sendThree},
		{name: "lost in the transport", reserve: sealing, send: func([][]byte) error { return sendErr }, drive: sendThree, failed: 3},
		{name: "sealed nothing", reserve: func(int) (BatchSealer, error) {
			return func([][]byte, []byte, [][]byte) ([][]byte, error) { return nil, sealErr }, nil
		}, send: sent, drive: sendThree, dropped: 3},
		{name: "refused a sequence range", reserve: func(int) (BatchSealer, error) { return nil, saErr }, send: sent, drive: sendThree, dropped: 3},
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

// every batch with a ticket holds at least leastPacketBytes of the data budget or one packet of the control one
// so a queue of peerDataBudget / leastPacketBytes and controlQueueSize together takes every batch they admit
// and enqueue never has to give a batch back for want of room, however few bytes each batch carries
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
	if want := peerDataBudget/leastPacketBytes + controlQueueSize; queued != want {
		t.Fatalf("the budgets admitted %d single packets, want %d", queued, want)
	}
	if got := peer.Dropped(); got != 1 {
		t.Errorf("the peer counted %d drops, want only the one packet past the data budget", got)
	}

	unblock()
	waitUntil(t, "the peer to transmit every packet it queued", func() bool { return transmitted.Load() == int64(queued) })
	waitForBudget(t, peer)
}

// a data batch pins at most twice its charge in sealed storage and a control place twice its packet
// each with the sealing overhead of as many packets as twice that holds at leastPacketBytes each
// single packets can stand by the thousand under the budget, and each one handed storage many small packets grew would pin all of it
// so would every babel place handed storage a path MTU probe grew
func TestSmallBatchIsNeverHandedStorageALargeOneGrew(t *testing.T) {
	// esp seals each packet with an 8 byte IV, a 16 byte ICV and up to 3 octets of padding, and puts a 12 byte nonce after them
	const espMostOverhead, espNonce = 8 + 8 + 3 + 2 + 16, 12
	espSealedLen := func(n int) int { return 8 + 8 + n + (4-(n+2)%4)%4 + 2 + 16 }
	slot := int(unsafe.Sizeof([]byte(nil)))
	limit := func(size int) int {
		return 2*size + max(2*size/leastPacketBytes, 1)*(espMostOverhead+slot) + espNonce
	}
	// payload backs every packet and backing every storage the sealer grows, so the sweep allocates neither per batch
	payload, backing := make([]byte, peerDataBudget), make([]byte, 2*peerDataBudget)
	// keeps the storage and the vector while they are large enough, as esp's SealBatchInto does
	sealer := func(raw [][]byte, _ []byte, reuse [][]byte) ([][]byte, error) {
		total := 0
		for _, packet := range raw {
			total += espSealedLen(len(packet))
		}
		var storage []byte
		if len(reuse) != 0 {
			storage = reuse[0][:0]
		}
		if cap(storage) < total+espNonce {
			storage = backing[: 0 : total+espNonce]
		}
		sealed := reuse
		if cap(sealed) < len(raw) {
			sealed = make([][]byte, len(raw))
		}
		sealed = sealed[:len(raw)]
		for i, packet := range raw {
			start := len(storage)
			storage = storage[:start+espSealedLen(len(packet))]
			sealed[i] = storage[start:]
		}
		return sealed, nil
	}
	type shape struct {
		control     bool
		count, size int
	}
	// many ACKs grow storage well past their bytes, and a probe or a read at a jumbo link.mtu past a babel packet's
	var shapes []shape
	for count := 1; count <= peerDataBudget/leastPacketBytes; count *= 2 {
		for _, size := range []int{20, 40, 700, leastPacketBytes} {
			shapes = append(shapes, shape{count: count, size: size})
		}
	}
	// a share just past each power of two, the least a pool takes, which a pool too few hands storage grown for more than twice its charge
	for power := 1 << bits.Len(leastPacketBytes); power < peerDataBudget; power *= 2 {
		shapes = append(shapes, shape{count: power/leastPacketBytes + 1, size: leastPacketBytes})
	}
	for _, size := range []int{1025, 2048, 8918, 65470} {
		shapes = append(shapes, shape{count: 1, size: size})
	}
	for _, size := range []int{60, 1280, 1400, 2048, 8918, 65470} {
		shapes = append(shapes, shape{control: true, count: 1, size: size})
	}
	describe := func(s shape) string {
		switch {
		case s.control:
			return fmt.Sprintf("a control place of %d bytes", s.size)
		case s.count == 1:
			return fmt.Sprintf("a data packet of %d bytes", s.size)
		}
		return fmt.Sprintf("%d data packets of %d bytes", s.count, s.size)
	}
	// seal seals a batch of s, gives it back and returns the storage it pinned and the size that storage is held to
	seal := func(p *Peer, s shape) (pinned, size int) {
		var b *peerBatch
		if s.control {
			place, err := p.ReserveRawOrDrop(payload[:s.size], 41)
			if err != nil {
				t.Fatalf("an empty control budget refused %s: %v", describe(s), err)
			}
			b, size = place.batch, s.size
		} else {
			if b = p.reserveBatchNow(s.count, s.count*s.size); b == nil {
				t.Fatalf("an empty data budget refused %s", describe(s))
			}
			for i := range s.count {
				b.append(payload[i*s.size:(i+1)*s.size], 0)
			}
			size = b.held
		}
		b.encrypt()
		pinned = cap(b.sealed[0]) + slot*cap(b.sealed)
		b.releaseStorage()
		b.releaseBudget()
		return pinned, size
	}
	// sync.Pool drops a quarter of what it is given under the race detector
	// so a single pass could miss the storage it must never hand over
	const passes, reported = 4, 8
	over := 0
	for _, grower := range shapes {
		for _, taker := range shapes {
			p := NewPeerReserved("peer", func(int) (BatchSealer, error) { return sealer, nil }, func([][]byte) error { return nil }, nil)
			for range passes {
				seal(p, grower)
				if pinned, size := seal(p, taker); pinned > limit(size) {
					if over++; over <= reported {
						t.Errorf("%s pinned %d bytes of storage after %s, past the %d it may", describe(taker), pinned, describe(grower), limit(size))
					}
					break
				}
			}
			p.Close()
		}
	}
	if over != 0 {
		t.Errorf("%d of %d ordered pairs pinned more storage than they may", over, len(shapes)*len(shapes))
	}
}
