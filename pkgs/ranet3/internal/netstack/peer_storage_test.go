// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

package netstack

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/logtest"
	"ranet3.com/pkgs/wireguard/conn"
)

func TestPeerKeepsCiphertextUntilSendCompletes(t *testing.T) {
	for _, sendErr := range []error{nil, errors.New("transport failed")} {
		t.Run(fmt.Sprint(sendErr), func(t *testing.T) {
			started := make(chan struct{})
			release := make(chan struct{})
			var once sync.Once
			var sent []byte
			p := NewPeer("peer", func(int) (BatchSealer, error) {
				return func(raw [][]byte, _ []byte, reuse [][]byte) ([][]byte, error) {
					if len(reuse) == 0 {
						reuse = [][]byte{{0}}
					}
					reuse[0][0] = raw[0][0]
					return reuse, nil
				}, nil
			}, func(packets [][]byte) error {
				if len(sent) == 0 {
					close(started)
					<-release
				}
				for _, packet := range packets {
					sent = append(sent, packet[0])
				}
				return sendErr
			}, nil)
			t.Cleanup(func() { once.Do(func() { close(release) }); p.Close() })
			failures := make(chan error, 2)
			first := p.reserveBatch(1, 1)
			first.append([]byte{1}, 0)
			first.onFailure = func(err error) { failures <- err }
			if err := first.finish(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("sender did not start")
			}
			// read while the transport holds the batch, before it goes back to the pool
			if first.storage == nil || first.sealed == nil {
				t.Fatal("ciphertext recycled while transport still owns it")
			}
			second := p.reserveBatch(1, 1)
			second.append([]byte{2}, 0)
			second.onFailure = func(err error) { failures <- err }
			if err := second.finish(); err != nil {
				t.Fatal(err)
			}
			once.Do(func() { close(release) })
			waitForBudget(t, p)
			// both batches are told the transport's error, and neither is told anything when it took them
			told := 0
			if sendErr != nil {
				told = 2
			}
			for range told {
				select {
				case err := <-failures:
					if !errors.Is(err, sendErr) {
						t.Fatalf("send result = %v, want %v", err, sendErr)
					}
				case <-time.After(time.Second):
					t.Fatal("sender did not complete")
				}
			}
			if len(failures) != 0 {
				t.Fatalf("a batch the transport took was told it failed: %v", <-failures)
			}
			if !bytes.Equal(sent, []byte{1, 2}) {
				t.Fatalf("in-flight ciphertext was overwritten: got %v", sent)
			}
		})
	}
}

// The speaker walks every neighbor from one goroutine, and Receive runs on the
// sending peer's decrypt path, so a control send that waits on a backed-up
// peer stops every other neighbor with it and lets two such peers hold each
// other's emitter. Dropping keeps the stall local.
func TestSendRawOrDropDoesNotWaitForBackedUpPeer(t *testing.T) {
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	var sent atomic.Int64
	peer := NewPeer("stalled", func(int) (BatchSealer, error) { return passThrough, nil }, func(sealed [][]byte) error {
		<-release
		sent.Add(int64(len(sealed))) // the sender merges batches into one call
		return nil
	}, nil)
	defer func() { unblock(); peer.Close() }()

	// Fill the queue, then keep going against a transport that never returns.
	// Each attempt gives up rather than waiting for a place that is never
	// coming, so the whole run is bounded. The sends are on their own
	// goroutine so a blocking one is reported rather than hanging.
	const beyond = 20
	attempts := controlQueueSize + beyond
	dropped := make(chan int, 1)
	go func() {
		n := 0
		for range attempts {
			if err := sendOrDrop(peer, []byte("control packet"), 41); errors.Is(err, ErrSendQueueFull) {
				n++
			}
		}
		dropped <- n
	}()
	var lost int
	budget := 10 * time.Second
	select {
	case lost = <-dropped:
	case <-time.After(budget):
		t.Fatalf("%d control sends against a stalled peer took longer than %s", attempts, budget)
	}
	if lost == 0 {
		t.Fatal("nothing was dropped, so the queue never filled and this proves nothing")
	}

	// A dropped packet must not have consumed a place or a sequence range,
	// or the ordered sender would never reach the batches behind it.
	unblock()
	drained := time.Now().Add(10 * time.Second)
	for int(sent.Load()) < attempts-lost {
		if time.Now().After(drained) {
			t.Fatalf("the sender stalled at %d of %d queued packets", sent.Load(), attempts-lost)
		}
		time.Sleep(time.Millisecond)
	}
}

// A queue full of bulk data drops control packets, and the caller has to be
// told so it can give back whatever the packet consumed. What must not happen
// is a drop reported as a send.
func TestControlPacketDropsAreReported(t *testing.T) {
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	peer := NewPeer("busy", func(int) (BatchSealer, error) { return passThrough, nil }, func([][]byte) error {
		<-release
		return nil
	}, nil)
	defer func() { unblock(); peer.Close() }()

	var dropped int
	for range controlQueueSize + 50 {
		if err := sendOrDrop(peer, []byte("control packet"), 41); errors.Is(err, ErrSendQueueFull) {
			dropped++
		}
	}
	if dropped == 0 {
		t.Fatal("a stalled peer accepted every control packet, so nothing tells the caller to redo it")
	}

	// Once the transport drains, the peer takes them again.
	unblock()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if err := sendOrDrop(peer, []byte("control packet"), 41); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the peer never took a control packet again after its transport drained")
		}
		time.Sleep(time.Millisecond)
	}
}

// A peer whose outbound SA cannot give out a sequence range transmits nothing,
// which is how a peer that has just deleted its Child SA looks from this
// side. Counting only the budget refusals would leave the drop counter reading
// zero through exactly that window.
func TestReservationFailureCountsAsADrop(t *testing.T) {
	refused := errors.New("no child sa")
	peer := NewPeer("peer",
		func(int) (BatchSealer, error) { return nil, refused },
		func([][]byte) error { return nil }, nil)
	defer peer.Close()

	// The caller is told, so it can give back whatever the packet consumed,
	// and the place is sent anyway so the sender is not left waiting for it.
	if _, err := peer.ReserveRawOrDrop([]byte("packet"), 41); !errors.Is(err, refused) {
		t.Errorf("reserving reported %v, want the reservation's own error", err)
	}
	if got := peer.Dropped(); got != 1 {
		t.Errorf("the peer counted %d drops, want the one packet it could not send", got)
	}
}

// Babel and the dataplane must not share one budget. A bulk transfer consumes
// all of the data budget, and sharing dropped 98 of every 100 control packets
// under load. Three lost hellos withdraw every route through the peer, so the
// transfer then has nowhere to go and the loss feeds itself.
func TestControlTrafficHasItsOwnBudget(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	peer := NewPeer("peer",
		func(int) (BatchSealer, error) { return passThrough, nil },
		func([][]byte) error { <-release; return nil }, nil)
	defer func() { unblock(); peer.Close() }()

	// The dataplane takes everything it is allowed, which is how a bulk
	// transfer through a backpressured socket looks from here.
	if peer.reserveBatchNow(1, peerDataBudget) == nil {
		t.Fatal("the dataplane was refused its own budget")
	}
	if peer.reserveBatchNow(1, 1) != nil {
		t.Fatal("the dataplane took more than its budget, so this proves nothing")
	}

	// Babel still gets through, for as many packets as a periodic dump needs.
	for i := range controlQueueSize {
		if _, err := peer.ReserveRawOrDrop([]byte("hello"), 41); err != nil {
			t.Fatalf("control packet %d was dropped because the dataplane had filled its own budget: %v", i, err)
		}
	}
	if _, err := peer.ReserveRawOrDrop([]byte("hello"), 41); err == nil {
		t.Error("control traffic is bounded by nothing of its own")
	}
}

// A closed peer must refuse everything it is offered. A select with both the
// budget and the stop channel ready picks uniformly, so half of what a closed
// peer was offered was accepted, reported as sent, never transmitted, and
// never counted as dropped, which is the one counter that would have shown it.
func TestClosedPeerRefusesAndCountsEverything(t *testing.T) {
	peer := NewPeer("peer",
		func(int) (BatchSealer, error) { return passThrough, nil },
		func([][]byte) error { return nil }, nil)
	peer.Close()

	const offered = 64
	for range offered {
		if place, err := peer.ReserveRawOrDrop([]byte("packet"), 41); err == nil {
			place.Send()
			t.Fatal("a closed peer took a control packet")
		}
		if peer.reserveBatchNow(1, 1) != nil {
			t.Fatal("a closed peer took a data batch")
		}
	}
	if got := peer.Dropped(); got != 2*offered {
		t.Errorf("the peer counted %d of %d packets it refused", got, 2*offered)
	}
}

// a reserver that passed the stop check and took its budget before the sender stopped is refused at the queue
// counted, its budget given back, since no sender is left to take the batch
func TestReservationPastTheStopCheckIsRefusedAtTheQueue(t *testing.T) {
	peer := NewPeer("peer",
		func(int) (BatchSealer, error) { return passThrough, nil },
		func([][]byte) error { t.Error("a closed peer transmitted"); return nil }, nil)
	peer.Close()
	size := dataCharge(1, 1)
	if !peer.dataBudget.take(size) {
		t.Fatal("an empty budget refused one packet")
	}
	if b := peer.reservePlace(1, size, false); b != nil {
		b.append([]byte{1}, 0)
		_ = b.finish()
		t.Fatal("the queue of a stopped sender took a batch")
	}
	if got := peer.Dropped(); got != 1 {
		t.Errorf("the peer counted %d packets dropped, want the 1 it refused", got)
	}
	if got := peer.dataBudget.used.Load(); got != 0 {
		t.Errorf("%d of the data budget stayed held", got)
	}
}

// A batch reserved before Close and sealed after it is in the queue the
// stopped sender no longer reads. Accepted, it would be reported as sent,
// never transmitted, and counted by nothing, which is the one signal that
// would have shown it. Every session teardown and replacement creates that
// overlap.
func TestBatchReservedBeforeCloseIsRefusedAndCounted(t *testing.T) {
	peer := NewPeer("peer",
		func(int) (BatchSealer, error) { return passThrough, nil },
		func([][]byte) error { t.Error("a closed peer transmitted"); return nil }, nil)

	// Reserved while the peer is open, so each holds a place and its bytes
	// of the budget, all of it between them.
	const size, packets = 1400, peerDataBudget / 1400
	var batches []*peerBatch
	for i, count := range []int{1, 5, packets - 6} {
		b := filledSized(peer, count, size)
		if b == nil {
			t.Fatalf("the peer refused reservation %d while it was open", i)
		}
		batches = append(batches, b)
	}
	peer.Close()

	for i, b := range batches {
		if err := b.finish(); err == nil {
			t.Fatalf("batch %d was accepted by a closed peer and will never be transmitted", i)
		}
	}
	if got := peer.Dropped(); got != packets {
		t.Errorf("the peer counted %d of the %d packets it will never send", got, packets)
	}
	// and gave back every byte of the budget they held
	if got := peer.dataBudget.used.Load(); got != 0 {
		t.Errorf("a closed peer kept %d bytes of its budget", got)
	}
}

// A batch whose sealer could not give out a sequence range is counted where
// that happens, which is the case a peer that deleted its Child SA presents,
// and Close follows on the same path. Counting it again when the closed peer
// refuses it makes the drop counter report more packets than the peer was
// ever given.
func TestReservationFailureIsCountedOnce(t *testing.T) {
	refused := errors.New("no child sa")
	peer := NewPeer("peer",
		func(int) (BatchSealer, error) { return nil, refused },
		func([][]byte) error { return nil }, nil)

	b := peer.reserveBatchNow(1, 1)
	if b == nil {
		t.Fatal("the peer refused a reservation while it was open")
	}
	b.append([]byte{1}, 0)
	if peer.Dropped() != 1 {
		t.Fatalf("the sealer failure counted %d, want one", peer.Dropped())
	}
	peer.Close()
	if err := b.finish(); err == nil {
		t.Fatal("a closed peer accepted the batch")
	}
	if got := peer.Dropped(); got != 1 {
		t.Errorf("the peer counted %d drops for one packet it was given once", got)
	}
}

// The reservation is the only place a batch is counted early, so that is the
// only thing abandon may treat as already counted. A batch that reserved a
// sequence range and then failed to seal has its packets counted by nothing
// else, and reading the error field instead of a flag that says "counted"
// silently puts every such packet outside the one counter that would show it.
func TestSealFailureOnAClosedPeerIsStillCounted(t *testing.T) {
	sealing := errors.New("seal")
	peer := NewPeer("peer",
		func(int) (BatchSealer, error) {
			return func([][]byte, []byte, [][]byte) ([][]byte, error) { return nil, sealing }, nil
		},
		func([][]byte) error { t.Error("a closed peer transmitted"); return nil }, nil)

	b := peer.reserveBatchNow(2, 2)
	if b == nil {
		t.Fatal("the peer refused a reservation while it was open")
	}
	b.append([]byte{1}, 0)
	b.append([]byte{2}, 0)
	if got := peer.Dropped(); got != 0 {
		t.Fatalf("a reservation that succeeded counted %d drops", got)
	}
	peer.Close()
	if err := b.finish(); err == nil {
		t.Fatal("a closed peer accepted the batch")
	}
	if got := peer.Dropped(); got != 2 {
		t.Errorf("the peer counted %d of the 2 packets it will never send", got)
	}
}

// Every packet a peer will not send has to reach the counter exactly once, and
// the sender's own stop path was the hole: a batch already queued behind the
// one the sender is waiting for is holding packets of the budget and a place in
// the transmission order, and returning from the loop left both, with its
// packets counted by nothing.
func TestBatchesStrandedInTheSenderAreCounted(t *testing.T) {
	peer := NewPeer("peer",
		func(int) (BatchSealer, error) { return passThrough, nil },
		func([][]byte) error { return nil }, nil)

	// each batch is told its failure under its reservation's index, from whichever goroutine gives it back
	var mu sync.Mutex
	var discarded []int
	var batches [3]*peerBatch
	for i, count := range []int{3, 5, 7} {
		b := peer.reserveBatchNow(count, count)
		if b == nil {
			t.Fatal("the peer refused a reservation while it was open")
		}
		for range count {
			b.append([]byte{1}, 0)
		}
		b.onFailure = func(error) { mu.Lock(); discarded = append(discarded, i); mu.Unlock() }
		batches[i] = b
	}
	// The first is never sealed, so the sender holds the other two waiting for
	// it, which is where Close finds them. They are sealed out of order so the
	// order they come back in is the sender's doing rather than the caller's.
	for _, batch := range []*peerBatch{batches[2], batches[1]} {
		if err := batch.finish(); err != nil {
			t.Fatalf("an open peer refused the batch: %v", err)
		}
	}
	peer.Close()
	mu.Lock()
	byTheSender := slices.Clone(discarded)
	mu.Unlock()
	if err := batches[0].finish(); err == nil {
		t.Fatal("a closed peer accepted the batch")
	}
	if got := peer.Dropped(); got != 15 {
		t.Errorf("the peer counted %d of the 15 packets it will never send", got)
	}
	// Given back in reservation order, which is the order everything else in
	// this peer observes, and the first by its own filler after them.
	if !slices.Equal(byTheSender, []int{1, 2}) {
		t.Errorf("the sender gave back the batches reserved %v, want the two it was holding in reservation order", byTheSender)
	}
	if !slices.Equal(discarded, []int{1, 2, 0}) {
		t.Errorf("the batches were given back in the order %v, want the unsealed one last, by its filler", discarded)
	}
}

// failure queues the batch and waits for the error its failure callback is told
func failure(t *testing.T, b *peerBatch) error {
	t.Helper()
	told := make(chan error, 1)
	b.onFailure = func(err error) { told <- err }
	if err := b.finish(); err != nil {
		return err
	}
	select {
	case err := <-told:
		return err
	case <-time.After(deliveryTimeout):
		t.Fatal("the sender never told the batch it failed")
		return nil
	}
}

// A batch that could not seal produced nothing for the transport, so its
// packets are gone whether or not the peer is closing. The sender logged that
// and counted nothing, which put every packet lost this way outside the one
// counter that would show it.
func TestSealFailureOnAnOpenPeerIsCounted(t *testing.T) {
	sealing := errors.New("seal")
	peer := NewPeer("peer",
		func(int) (BatchSealer, error) {
			return func([][]byte, []byte, [][]byte) ([][]byte, error) { return nil, sealing }, nil
		},
		func([][]byte) error { t.Error("a batch that sealed nothing reached the transport"); return nil }, nil)
	defer peer.Close()

	b := peer.reserveBatchNow(4, 4)
	if b == nil {
		t.Fatal("the peer refused a reservation while it was open")
	}
	for range 4 {
		b.append([]byte{1}, 0)
	}
	if err := failure(t, b); !errors.Is(err, sealing) {
		t.Fatalf("the batch was told %v, want the sealer's own error", err)
	}
	if got := peer.Dropped(); got != 4 {
		t.Errorf("the peer counted %d of the 4 packets that never reached the transport", got)
	}
}

// A batch that sealed and then lost the syscall was attempted, which is not
// the same as one this peer refused: the first says the link or the socket is
// failing and the second says this node is out of room. Neither reached a
// counter at all before, so a link losing everything read as a quiet node.
func TestTransportFailureIsCountedApartFromARefusal(t *testing.T) {
	sending := errors.New("no route to host")
	peer := NewPeer("peer",
		func(int) (BatchSealer, error) { return passThrough, nil },
		func([][]byte) error { return sending }, nil)
	defer peer.Close()

	b := peer.reserveBatchNow(3, 3)
	if b == nil {
		t.Fatal("the peer refused a reservation while it was open")
	}
	for range 3 {
		b.append([]byte{1}, 0)
	}
	if err := failure(t, b); !errors.Is(err, sending) {
		t.Fatalf("the batch was told %v, want the transport's own error", err)
	}
	if got := peer.SendFailed(); got != 3 {
		t.Errorf("the peer counted %d of the 3 packets the transport lost", got)
	}
	if got := peer.Dropped(); got != 0 {
		t.Errorf("it also counted %d as refused, which means this node ran out of room", got)
	}
}

// A peer whose Child SA the other end deleted fails every reservation from
// then on, so a line per failed batch is a line per TUN batch for as long as
// that lasts. The count is exact: only the saying of it is bounded.
func TestTransportFailureIsSaidRarely(t *testing.T) {
	var lines atomic.Int64
	logtest.SetDefault(t, slog.New(slog.NewTextHandler(countingWriter{&lines}, nil)))

	sending := errors.New("no route to host")
	peer := NewPeer("peer",
		func(int) (BatchSealer, error) { return passThrough, nil },
		func([][]byte) error { return sending }, nil)
	defer peer.Close()

	// The sender gives the budget back only after the transport returns, so a
	// batch that finds no room is waited for rather than counted as a failure
	// to send.
	const batches = 200
	for sent := 0; sent < batches; {
		b := peer.reserveBatchNow(1, 1)
		if b == nil {
			time.Sleep(time.Millisecond)
			continue
		}
		b.append([]byte{1}, 0)
		if err := b.finish(); err != nil {
			t.Fatalf("an open peer refused the batch: %v", err)
		}
		sent++
	}
	deadline := time.Now().Add(10 * time.Second)
	for lines.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no failure was said at all, so an operator sees nothing")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := lines.Load(); got != 1 {
		t.Errorf("%d failed batches wrote %d lines, want the one the interval allows", batches, got)
	}
}

// countingWriter counts writes rather than keeping them, the unit a report
// that must not be one line per batch is measured in.
type countingWriter struct{ n *atomic.Int64 }

func (w countingWriter) Write(b []byte) (int, error) { w.n.Add(1); return len(b), nil }

// A batch that joins the queue after the sender's stop has taken it is read
// by nobody: never transmitted, never counted, its budget never given back,
// and its caller told it went. Testing the stop channel before the
// reservation cannot close that, because the stop can happen between the test
// and the append. Every teardown and every session replacement creates the
// window.
//
// The window is narrow without help: reverting the fix loses about one batch
// in ninety thousand here and none at all in some runs. Under -race, which is
// how this suite and the flake check run it, the scheduler widens it enough to
// lose one every time.
func TestNoBatchIsLostBetweenTheStopCheckAndTheQueue(t *testing.T) {
	const teardowns, producers, packets = 2000, 4, 6
	for range teardowns {
		var transmitted atomic.Int64
		peer := NewPeer("peer",
			func(int) (BatchSealer, error) { return passThrough, nil },
			func(sealed [][]byte) error { transmitted.Add(int64(len(sealed))); return nil }, nil)

		var sent atomic.Int64
		var wg sync.WaitGroup
		start := make(chan struct{})
		for range producers {
			wg.Go(func() {
				<-start
				for range packets {
					b := peer.reserveBatchNow(1, 1)
					if b == nil {
						continue // the budget was full, which is counted where it happens
					}
					b.append([]byte{1}, 0)
					if err := b.finish(); err == nil {
						sent.Add(1)
					}
				}
			})
		}
		close(start)
		peer.Close()
		wg.Wait()

		// Counted against what reached the transport, not against what the
		// caller was told: a lost batch was told it went, so a test that
		// believes the caller cannot see the loss at all.
		offered := int64(producers * packets)
		if got := transmitted.Load() + int64(peer.Dropped()); got != offered {
			t.Fatalf("%d packets were reserved, %d reached the transport and %d were counted as dropped",
				offered, transmitted.Load(), peer.Dropped())
		}
		// finish returning nil promises the queue took the batch, not that it
		// left: the sender may still give it back, and that is counted above.
		_ = sent.Load()
		// And every packet of the budgets came back, or the next session on
		// this peer has less room for good.
		if got := peer.dataBudget.used.Load() + peer.controlBudget.used.Load(); got != 0 {
			t.Fatalf("%d of the budgets were not given back", got)
		}
	}
}

// a batch the transport took reached the wire, so a peer that closes while the transport holds it tells its caller of no failure
func TestBatchInTheTransportWhenThePeerClosesIsNotToldItFailed(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	peer := NewPeer("peer",
		func(int) (BatchSealer, error) { return passThrough, nil },
		func([][]byte) error {
			close(entered)
			<-release
			return nil
		}, nil)

	b := peer.reserveBatchNow(1, 1)
	if b == nil {
		t.Fatal("the peer refused a reservation while it was open")
	}
	b.append([]byte{1}, 0)
	failed := make(chan error, 1)
	b.onFailure = func(err error) { failed <- err }
	if err := b.finish(); err != nil {
		t.Fatalf("an open peer refused the batch: %v", err)
	}

	<-entered
	// closed directly rather than through Close, which would wait on the sender this test holds inside the transport
	close(peer.stop)
	close(release)
	<-peer.senderDone
	select {
	case err := <-failed:
		t.Fatalf("the batch the transport took was told %v", err)
	default:
	}
}

// senderIdle is how long a test leaves a sender with nothing queued, so it is waiting on its queue when the next reservation comes
const senderIdle = 20 * time.Millisecond

// a sender with nothing queued waits on its queue, and the seal of a batch reserved into it wakes the sender, however long it has waited
// the reservation alone does not, so the sender never takes the batch unsealed only to wait on it and wake a second time
func TestIdleSenderWakesForASealedBatch(t *testing.T) {
	carried := make(chan struct{}, 1)
	peer := NewPeer("peer", func(int) (BatchSealer, error) { return passThrough, nil },
		func([][]byte) error { carried <- struct{}{}; return nil }, nil)
	defer peer.Close()
	for i := range 3 {
		time.Sleep(senderIdle)
		b := filled(peer, 1)
		// a sender the reservation woke would take the batch meanwhile
		time.Sleep(senderIdle)
		peer.reserveMu.Lock()
		untaken := peer.head == b
		peer.reserveMu.Unlock()
		if !untaken {
			t.Errorf("the sender took batch %d out of its queue before it was sealed", i)
		}
		if err := b.finish(); err != nil {
			t.Fatal(err)
		}
		select {
		case <-carried:
		case <-time.After(deliveryTimeout):
			t.Fatalf("an idle sender never sent batch %d sealed into its empty queue", i)
		}
	}
}

// the sender holds every batch behind the head of its queue until the head is sealed, however long that takes
// and then sends the head before them, its sealed packets and not the nothing it held unsealed
// no batch goes back to the pool holding the token of its seal
func TestSenderWaitsForAnUnsealedHead(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var hold sync.Once
	var mu sync.Mutex
	var carried []byte
	peer := NewPeer("peer", func(int) (BatchSealer, error) { return passThrough, nil }, func(sealed [][]byte) error {
		hold.Do(func() { close(entered); <-release })
		mu.Lock()
		defer mu.Unlock()
		for _, packet := range sealed {
			carried = append(carried, packet[0])
		}
		return nil
	}, nil)
	defer peer.Close()
	marked := func(mark byte) *peerBatch {
		b := peer.reserveBatchNow(1, 1)
		if b == nil {
			t.Fatal("the peer refused a reservation while it was open")
		}
		b.append([]byte{mark}, 0)
		return b
	}
	if err := marked(1).finish(); err != nil {
		t.Fatal(err)
	}
	<-entered
	// the head is reserved and left unsealed, and the batch behind it sealed
	head, behind := marked(2), marked(3)
	done := [...]chan struct{}{head.done, behind.done}
	if err := behind.finish(); err != nil {
		t.Fatal(err)
	}
	close(release)
	taken(t, peer)
	time.Sleep(senderIdle)
	mu.Lock()
	early := slices.Clone(carried)
	mu.Unlock()
	if !slices.Equal(early, []byte{1}) {
		// the sender went on past the head, which it may have put back in the pool, so the head is not sealed here
		t.Fatalf("the transport carried %v while the head was unsealed, want only the batch before it", early)
	}
	if err := head.finish(); err != nil {
		t.Fatal(err)
	}
	waitForBudget(t, peer)
	mu.Lock()
	defer mu.Unlock()
	if !slices.Equal(carried, []byte{1, 2, 3}) {
		t.Errorf("the transport carried %v, want the head's sealed packet before the batch sealed behind it", carried)
	}
	for _, d := range done {
		if len(d) != 0 {
			t.Error("a batch went back to the pool holding the token of its seal")
		}
	}
}

// a pooled batch has room for less than twice the packets of the reservation that takes it, or for 1 when it takes 1
// so a backlog of single packets behind full reads holds none of the slices the reads grew
// and a batch grown past the packets a read holds, for a share cut into fragments, keeps no slices for the next
func TestPooledBatchHasRoomForLessThanTwiceItsPackets(t *testing.T) {
	sizes := []int{1, 2, 3, 64, 65, conn.IdealBatchSize, conn.IdealBatchSize + 1, peerDataBudget / leastPacketBytes}
	for _, grown := range sizes {
		for _, count := range sizes {
			b := batchPool(grown).Get().(*peerBatch)
			b.raw, b.headers = slices.Grow(b.raw, grown), slices.Grow(b.headers, grown)
			b.recycle()
			got := batchPool(count).Get().(*peerBatch)
			if room := cap(got.raw); room > 1 && room >= 2*count {
				t.Errorf("a reservation of %d packets after a batch grown for %d was handed room for %d", count, grown, room)
			}
			got.recycle()
		}
	}
}

// a batch fitted for a read has room for its packets, and goes back to the pool its reservation took it from with its slices
// whatever room it had for the reservation before, so reads of changing sizes do not grow batches out of their pools
func TestFittedBatchGoesBackToItsPool(t *testing.T) {
	for _, count := range []int{1, 2, 3, 64, 65, 100, conn.IdealBatchSize} {
		for _, room := range []int{0, 1, count / 2, count - 1, count} {
			b := &peerBatch{raw: make([][]byte, 0, room), headers: make([]byte, 0, room)}
			b.fit(count)
			if cap(b.raw) < count || cap(b.headers) < count || cap(b.raw) > conn.IdealBatchSize || batchPool(cap(b.raw)) != batchPool(count) {
				t.Errorf("a batch with room for %d fitted for %d packets has room for %d and %d headers, which leaves the pool it came from", room, count, cap(b.raw), cap(b.headers))
			}
		}
	}
}

// a recycled batch goes back to the pool of its slices' room, whichever pool it came from
// so the batch of a full read never reaches a reservation of a few packets, and the next full read takes it rather than a new one
func TestRecycledBatchGoesBackToThePoolOfItsRoom(t *testing.T) {
	for _, room := range []int{1, 2, 3, 64, 65, conn.IdealBatchSize} {
		if !comesBackFrom(room) {
			t.Errorf("a recycled batch with room for %d packets never came out of the pool for %d", room, room)
		}
	}
}

// comesBackFrom says whether a batch with room for room packets, once recycled, comes out of the pool for room
// the pool hands out what this goroutine gave it before ahead of the batch, so a few draws are held until the batch comes
// and the race detector drops a quarter of what the pool is given, so it tries again with a new batch
func comesBackFrom(room int) bool {
	for range 100 {
		b := &peerBatch{raw: make([][]byte, 0, room), headers: make([]byte, 0, room), done: make(chan struct{}, 1)}
		b.recycle()
		held := make([]*peerBatch, 0, 8)
		found := false
		for range cap(held) {
			got := batchPool(room).Get().(*peerBatch)
			held = append(held, got)
			if got == b {
				found = true
				break
			}
		}
		for _, h := range held {
			h.recycle()
		}
		if found {
			return true
		}
	}
	return false
}

// the stopped sender takes the token of a sealed batch it gives back
// a batch back in the pool holding one would read as sealed to the sender of its next reservation before anything filled it
func TestStoppedSenderLeavesNoTokenBehind(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	peer := NewPeer("peer",
		func(int) (BatchSealer, error) { return passThrough, nil },
		func([][]byte) error {
			close(entered)
			<-release
			return nil
		}, nil)

	first := filled(peer, 1)
	if err := first.finish(); err != nil {
		t.Fatalf("an open peer refused the batch: %v", err)
	}
	<-entered
	// the second is never sealed before the stop, so the sender waits on it with the third sealed behind it
	second, third := filled(peer, 2), filled(peer, 3)
	if second == nil || third == nil {
		t.Fatal("the peer refused a reservation while it was open")
	}
	if err := third.finish(); err != nil {
		t.Fatalf("an open peer refused the batch: %v", err)
	}
	// closed directly rather than through Close, which would wait on the sender this test holds inside the transport
	close(peer.stop)
	close(release)
	<-peer.senderDone
	if len(third.done) != 0 {
		t.Error("the stopped sender gave back a sealed batch with the token of its seal still in it")
	}
	if err := second.finish(); err == nil {
		t.Fatal("a stopped sender's peer accepted the batch")
	}
	if got := peer.Dropped(); got != 5 {
		t.Errorf("the peer counted %d of the 5 packets it will never send", got)
	}
	if data, control := peer.dataBudget.used.Load(), peer.controlBudget.used.Load(); data != 0 || control != 0 {
		t.Errorf("the stopped peer holds %d bytes and %d control places", data, control)
	}
}

// a batch's cycle from its reservation through its seal and transmit back to the pool allocates nothing once the pools hold what it needs
// but what cycleAllocations allows the race detector's pool drops
func TestBatchCycleAllocatesNothing(t *testing.T) {
	carried := make(chan struct{}, 1)
	peer := NewPeer("peer", func(int) (BatchSealer, error) { return passThrough, nil },
		func([][]byte) error { carried <- struct{}{}; return nil }, nil)
	defer peer.Close()
	payload := []byte{1}
	// the sender gives the last batch back before it transmits the next, so the pools never need more than two
	cycle := func() {
		b := peer.reserveBatchNow(1, 1)
		if b == nil {
			t.Fatal("the budget refused one packet with nothing else held")
		}
		b.append(payload, 0)
		if err := b.finish(); err != nil {
			t.Fatal(err)
		}
		<-carried
	}
	cycle()
	cycle()
	if allocations := testing.AllocsPerRun(1000, cycle); allocations > cycleAllocations {
		t.Errorf("a batch's cycle allocates %v times", allocations)
	}
}

// a batch taken from the pool carries nothing of its last reservation
// a callback, an error or a count left in it would be told or read for a packet it never held
func TestRecycledBatchCarriesNothing(t *testing.T) {
	peer := NewPeer("peer", func(int) (BatchSealer, error) { return passThrough, nil }, func([][]byte) error { return nil }, nil)
	defer peer.Close()
	// the pool hands back what this goroutine put in it last, but under the race detector, which drops a quarter of what it is given
	for range 100 {
		b := batchPool(1).Get().(*peerBatch)
		*b = peerBatch{peer: peer, next: b, done: b.done, sealer: passThrough, sealed: [][]byte{{1}}, storage: new([][]byte),
			raw: append(b.raw[:0], []byte{1}), headers: append(b.headers[:0], 1), err: errors.New("seal"), counted: true,
			onFailure: func(error) {}, failed: true, size: 1, held: 1, control: true, probe: true, admitted: time.Second, shed: 1}
		b.state.Store(batchSealed)
		raw := b.raw
		b.recycle()
		got := batchPool(1).Get().(*peerBatch)
		if got != b {
			got.recycle()
			continue
		}
		if got.peer != nil || got.next != nil || got.sealer != nil || got.sealed != nil || got.storage != nil || got.err != nil || got.counted ||
			got.onFailure != nil || got.failed || got.size != 0 || got.held != 0 || got.control || got.probe || got.admitted != 0 || got.shed != 0 {
			t.Errorf("a batch came back from the pool holding its last reservation: %+v", got)
		}
		if got.state.Load() != batchFilling || len(got.raw) != 0 || len(got.headers) != 0 || raw[0] != nil {
			t.Error("a batch came back from the pool sealed, holding packets or a view of the last plaintext")
		}
		got.recycle()
		return
	}
	t.Fatal("the pool never handed back the batch just put in it")
}
