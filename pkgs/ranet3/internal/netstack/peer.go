// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

package netstack

import (
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"math/bits"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// Peer separates parallel packet encryption from ordered, batched transport.
type Peer struct {
	ID              string
	encryptFn       func(raw []byte, nextHeader byte) ([]byte, error)
	reserveFn       func(count int) (BatchSealer, error)
	transmitBatchFn func(sealed [][]byte) error

	reserveMu sync.Mutex
	reserved  uint64
	dropped   atomic.Uint64
	// delayDropped is the part of dropped the sender dropped for the delay through the queue
	// delay is the control that decides those drops, which only the sender touches
	delayDropped atomic.Uint64
	delay        codel
	// events records the peer's changes of state, nil recording nothing
	events func(kind, peer string, attrs ...slog.Attr)
	// sendFailed counts packets that were sealed, handed to the transport and
	// lost in the syscall. Separate from dropped, which counts what this peer
	// refused on purpose: one says the link or the socket is failing and the
	// other says this node is out of room, and an operator reading the second
	// needs it not to move for the first. The sender merges several batches
	// into one call, so an error covers every packet in it -- how many of them
	// actually left is not knowable from here.
	sendFailed atomic.Uint64
	// sendErrReported is nanoseconds since started, read through time.Since so
	// it comes off the monotonic clock, and primed one interval in the past so
	// the first failure is still said out loud. A peer that deleted its Child
	// SA and kept the IKE SA, which RFC 7296 section 1.4.1 permits and this
	// tree stays connected for, fails every reservation from then on: without
	// this that is one synchronous log write per TUN batch, for as long as the
	// peer stays in that state. Dropped is the exact count.
	sendErrReported atomic.Int64
	started         time.Time
	// closeGrace overrides defaultCloseGrace; zero means the default.
	closeGrace time.Duration
	// noteDiscarded is nil in production. A test replaces it to observe the
	// order discardQueued gives batches back in, which nothing else can see.
	noteDiscarded func(ticket uint64)

	// Reserved peers hand completed crypto batches to one sender. dataBudget
	// bounds the packets this peer holds from their reservation through
	// encryption, the wait behind an earlier ticket and the transport syscall.
	//
	// controlBudget is the same bound for babel, kept separate on purpose. The
	// data budget is entirely consumed by a bulk transfer, so sharing it
	// dropped 98 of every 100 control packets under load, measured. Three lost
	// hellos withdraw every route through the peer and the transfer then has
	// nowhere to go. Control traffic is small and rare enough that a budget of
	// its own costs a few hundred kilobytes.
	// queueMu makes closing the queue and inserting into it one decision.
	// The sender's stop path drains what it holds and returns, so a batch
	// that lands in the queue after that drain is read by nobody: never
	// transmitted, never counted, its budget never given back, and its caller
	// told it succeeded. Testing p.stop before the send cannot close that,
	// because the drain can happen between the test and the send.
	queueMu       sync.Mutex
	queueClosed   bool
	completed     chan *peerBatch
	dataBudget    packetBudget
	controlBudget packetBudget
	stop          chan struct{}
	senderDone    chan struct{}
	closeOnce     sync.Once
	// sealedPool holds sealed storage, each a *[][]byte returned only after the transport finishes
	// it keeps one pool for each power of two of a batch's packets up to transmitBatchSize
	// so a batch reuses only storage grown by at most twice its own packets
	sealedPool []sync.Pool

	// Compatibility peers allocate their sequence number during encryption,
	// so their complete encrypt/send operation remains synchronously ordered.
	sendMu   sync.Mutex
	sendCond *sync.Cond
	nextSend uint64
}

// BatchSealer consumes a sequence range previously reserved from one outbound
// SA. It returns packet slices backed by one packed allocation so the transport
// can hand them to UDP GSO without another copy. reuse is a previous result
// whose transport has finished; the sealer may overwrite it or replace it.
// Output must not alias raw, whose TUN buffers are recycled after encryption.
type BatchSealer func(raw [][]byte, nextHeaders []byte, reuse [][]byte) ([][]byte, error)

func NewPeer(id string, encryptFn func(raw []byte, nextHeader byte) ([]byte, error), transmitFn func(sealed []byte) error) *Peer {
	return NewPeerBatched(id, encryptFn, func(sealed [][]byte) error {
		for _, packet := range sealed {
			if err := transmitFn(packet); err != nil {
				return err
			}
		}
		return nil
	})
}

// NewPeerBatched constructs a compatibility peer for an encryptor that cannot
// reserve sequence ranges. Its complete encrypt-and-send operation is ordered,
// so it is safe but intentionally cannot encrypt multiple batches in parallel.
func NewPeerBatched(id string, encryptFn func(raw []byte, nextHeader byte) ([]byte, error), transmitBatchFn func(sealed [][]byte) error) *Peer {
	return newPeer(id, encryptFn, nil, transmitBatchFn, nil)
}

// NewPeerReserved constructs a peer whose expensive encryption can run in
// parallel. reserveFn is called in packet-intake order and must return a sealer
// owning count consecutive sequence numbers from the current outbound SA.
// transmitBatchFn must finish using every packet before returning.
// events records the peer's changes of state under its ID, nil recording nothing
func NewPeerReserved(id string, reserveFn func(count int) (BatchSealer, error), transmitBatchFn func(sealed [][]byte) error, events func(kind, peer string, attrs ...slog.Attr)) *Peer {
	return newPeer(id, nil, reserveFn, transmitBatchFn, events)
}

func newPeer(id string, encryptFn func(raw []byte, nextHeader byte) ([]byte, error), reserveFn func(count int) (BatchSealer, error), transmitBatchFn func(sealed [][]byte) error, events func(kind, peer string, attrs ...slog.Attr)) *Peer {
	p := &Peer{ID: id, encryptFn: encryptFn, reserveFn: reserveFn, transmitBatchFn: transmitBatchFn,
		events: events, started: time.Now()}
	p.sendErrReported.Store(-int64(sendErrReportInterval))
	if reserveFn == nil {
		p.sendCond = sync.NewCond(&p.sendMu)
	} else {
		p.dataBudget.limit = peerDataBudget
		p.controlBudget.limit = controlQueueSize
		// every batch with a ticket holds at least one packet of a budget
		// so the queue holds them all and enqueue never waits
		p.completed = make(chan *peerBatch, peerDataBudget+controlQueueSize)
		p.sealedPool = make([]sync.Pool, bits.Len(transmitBatchSize))
		p.stop = make(chan struct{})
		p.senderDone = make(chan struct{})
		go p.senderLoop()
	}
	return p
}

// Close stops the reserved peer's ordered sender. Compatibility peers do not
// own a goroutine, so closing them is a no-op.
func (p *Peer) Close() {
	if p == nil || p.stop == nil {
		return
	}
	p.closeOnce.Do(func() { close(p.stop) })
	grace := p.closeGrace
	if grace <= 0 {
		grace = defaultCloseGrace
	}
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case <-p.senderDone:
	case <-timer.C:
		slog.Warn("netstack gave up waiting for a peer sender still in the transport",
			"peer", p.ID, "waited", grace)
	}
}

// ErrSendQueueFull reports a packet dropped rather than queued, so the caller
// can count it without treating the peer as broken.
var ErrSendQueueFull = errors.New("netstack: peer send queue is full")

// Place is one packet holding its position in a peer's transmission order. A
// peer sends in the order places were taken, not in the order Send is called.
type Place struct{ batch *peerBatch }

// ReserveRawOrDrop takes the peer's next place for one packet, and drops the
// packet rather than waiting when the control budget has no room. Babel sends
// this way because waiting does not stay local: the speaker walks every
// neighbor from one goroutine, and Receive runs on the sending peer's own
// decrypt path, so one peer whose queue is backed up would stop hellos,
// updates and retractions to every other neighbor until it drained, and two
// such peers would each hold the other's emitter. The caller is told, and
// gives back whatever the dropped packet had consumed.
//
// Taking the place and sending are separate so a caller that decides several
// packets under a lock it cannot hold while sending can take all the places
// under that lock, after which nothing can invert them. Every place taken has
// to be sent, because one that is never used stalls everything behind it.
func (p *Peer) ReserveRawOrDrop(raw []byte, nextHeader byte) (*Place, error) {
	b := p.reserveNow(&p.controlBudget, 1, true)
	if b == nil {
		return nil, ErrSendQueueFull
	}
	if b.err != nil {
		// The place was taken and has to be sent, so the sender is not
		// stranded, but nothing in it will leave. Telling the caller now is
		// what lets it give back the bookkeeping the packet consumed.
		place := &Place{batch: b}
		_ = place.Send()
		return nil, b.err
	}
	b.append(raw, nextHeader)
	return &Place{batch: b}, nil
}

// Send hands the packet to the peer's sender, which emits it once everything
// reserved ahead of it has gone.
func (p *Place) Send() error { return p.batch.enqueue() }

// OnFailure registers what to run if this packet does not reach the wire. Send
// reports only that the packet was queued: the transport error surfaces on the
// sender goroutine, after Send has returned, so a caller that gave back its
// bookkeeping at the reservation alone never hears about a packet lost from
// there on.
//
// It must be called before Send, because the batch belongs to the sender from
// then on. The callback runs at most once, on whichever goroutine finishes
// with the batch, so it must not block.
func (p *Place) OnFailure(f func(error)) { p.batch.onFailure = f }

type peerBatch struct {
	peer      *Peer
	ticket    uint64
	reserved  bool
	sealer    BatchSealer
	sealed    [][]byte
	storage   *[][]byte
	raw       [][]byte
	headers   []byte
	encrypted bool
	err       error
	// counted says this batch's packets have already reached p.dropped, so
	// whoever discards it last leaves the counter alone. Only reserve failure
	// counts early, because that is where the packet count is still known, and
	// an implicit test on err would read every other reason err is set -- a
	// batch that failed to seal, say -- as counted too, and lose those
	// packets from the counter entirely.
	counted bool
	done    chan error
	// onFailure is the caller's completion signal, set through Place. failed
	// keeps it to one call: a batch reaches exactly one terminal state, but
	// several sites decide it.
	onFailure func(error)
	failed    bool
	// held is the packets this batch holds of its peer's budget
	// zero once they are given back, or for a peer with no budget
	held int
	// control says which budget the place came from, so it goes back where it
	// was taken from.
	control bool
	// admitted is when the batch was reserved, as time since the peer started
	admitted time.Duration
	// shed is how many sealed packets the delay control dropped from the head of the batch
	shed int
}

// packetBudget is the room a peer has for packets from their reservation until the transmit that carried them returns
type packetBudget struct {
	used  atomic.Int64
	limit int64
}

// take holds count packets if they fit, without waiting, and says whether they did
func (b *packetBudget) take(count int) bool {
	for {
		used := b.used.Load()
		if used+int64(count) > b.limit {
			return false
		}
		if b.used.CompareAndSwap(used, used+int64(count)) {
			return true
		}
	}
}

// reserveBatchNow takes count packets of the data budget only if they fit.
// A caller that would rather drop its packets than wait gets nil, having
// consumed neither a ticket nor a sequence range, which is why the budget is
// taken before either: a reserved ticket that never reaches the sender stalls
// it forever. The count is the caller's packet count, at least one, and the
// refusal is counted in the same unit.
//
// It does not wait at all, even briefly. The budget frees as the peer's sender
// returns from the transport, so a budget that is full is one whose socket is
// backpressured, and that lasts far longer than any wait worth having. A wait
// would only add latency before dropping anyway. The caller also runs on a
// goroutine that serves other peers: Mesh dispatches under a lock every TUN
// reader takes. ReserveRawOrDrop says the same of its own callers.
func (p *Peer) reserveBatchNow(count int) *peerBatch {
	return p.reserveNow(&p.dataBudget, count, false)
}

// reserveNow takes count packets from budget if they fit, and otherwise
// reports the packets dropped.
func (p *Peer) reserveNow(budget *packetBudget, count int, control bool) *peerBatch {
	// a compatibility peer sends in its caller and holds no budget
	if p.completed == nil {
		return p.reserveTicket(count, 0, control)
	}
	// a closed peer refuses and counts everything it is offered
	select {
	case <-p.stop:
		p.dropped.Add(uint64(count))
		return nil
	default:
	}
	if !budget.take(count) {
		p.dropped.Add(uint64(count))
		return nil
	}
	return p.reserveTicket(count, count, control)
}

// Dropped counts the packets this peer did not transmit on purpose: its
// budget had no room for them, the peer was already closing, the outbound SA
// could not give out a sequence range, which is how a peer that deleted its
// Child SA looks from here, a batch of them failed to seal, or the delay
// through its queue had stayed above the target. A peer whose path is
// congested or whose SA is gone shows up as a rising counter rather than as
// latency somewhere else.
func (p *Peer) Dropped() uint64 { return p.dropped.Load() }

// DelayDropped is the part of Dropped the sender dropped from the head of the queue
// because the delay of the data batches through it had stayed above codelTarget for codelInterval
// it counts a queue that stands
// the rest of Dropped counts reads the budget refused, a closing peer's packets, reservations the outbound SA refused and batches that sealed nothing
func (p *Peer) DelayDropped() uint64 { return p.delayDropped.Load() }

// SendFailed is how many packets this peer sealed and could not put on the
// wire. See Peer.sendFailed.
func (p *Peer) SendFailed() uint64 { return p.sendFailed.Load() }

// reserveTicket takes the peer's next ticket and its sequence range for count packets
// for a batch that holds held packets of a budget
func (p *Peer) reserveTicket(count, held int, control bool) *peerBatch {
	p.reserveMu.Lock()
	ticket := p.reserved
	p.reserved++
	b := &peerBatch{peer: p, ticket: ticket, reserved: p.reserveFn != nil, held: held, control: control}
	if p.reserveFn != nil {
		b.sealer, b.err = p.reserveFn(count)
	}
	p.reserveMu.Unlock()
	b.admitted = time.Since(p.started)
	if b.err != nil {
		// The batch keeps its ticket, so the sender is not stranded, but
		// nothing in it will be transmitted: the sequence range it needed does
		// not exist. Counted here rather than where the sender discards it,
		// because this is where the packet count is still known.
		p.dropped.Add(uint64(count))
		b.counted = true
	}
	b.raw = make([][]byte, 0, count)
	b.headers = make([]byte, 0, count)
	return b
}

// append retains a view of plaintext owned by the surrounding TUN batch.
// enqueue performs reserved batch encryption in that same worker before the
// TUN buffers are recycled.
func (b *peerBatch) append(raw []byte, nextHeader byte) {
	b.raw = append(b.raw, raw)
	b.headers = append(b.headers, nextHeader)
}

func (b *peerBatch) encrypt() {
	if b.encrypted || b.err != nil {
		return
	}
	b.encrypted = true
	if b.reserved {
		b.storage, _ = b.peer.storagePool(len(b.raw)).Get().(*[][]byte)
		if b.storage == nil {
			b.storage = new([][]byte)
		}
		b.sealed, b.err = b.sealer(b.raw, b.headers, *b.storage)
		return
	}
	for i, raw := range b.raw {
		sealed, err := b.peer.encryptFn(raw, b.headers[i])
		if err != nil {
			b.err = err
			continue
		}
		b.sealed = append(b.sealed, sealed)
	}
}

// enqueue hands a completed reserved batch to the dedicated ordered sender and
// returns as soon as the bounded queue accepts it. That keeps crypto workers
// available while an earlier batch is in sendmmsg. Compatibility peers retain
// their synchronous ordered path.
func (b *peerBatch) enqueue() error {
	p := b.peer
	if p.completed == nil {
		return b.transmit()
	}
	b.encrypt()
	p.queueMu.Lock()
	if p.queueClosed {
		p.queueMu.Unlock()
		return b.abandon()
	}
	// Never blocks: p.completed holds every batch the two budgets can hand a
	// ticket to, since each such batch holds at least one of their packets, and
	// every batch that reaches here is one of them. The default arm is
	// therefore unreachable, and giving the batch back is the answer if it ever
	// is, rather than blocking with queueMu held.
	select {
	case p.completed <- b:
		p.queueMu.Unlock()
		return nil
	default:
		p.queueMu.Unlock()
		return b.abandon()
	}
}

// abandon gives back what a batch reserved and counts its packets as dropped,
// for a peer that closed after it had its ticket. A batch that could not
// reserve a sequence range was counted there instead, and the two overlap in
// the ordinary teardown window: a peer that deleted its Child SA cannot hand
// out a sequence range, and Close follows on the same path. Anything else that
// leaves a batch unsendable -- a seal that failed on the way here -- is
// counted once, here, which is the same thing the caller is told.
func (b *peerBatch) abandon() error {
	if !b.counted {
		b.peer.dropped.Add(uint64(len(b.raw)))
		b.counted = true
	}
	b.releaseStorage()
	b.releaseBudget()
	err := fmt.Errorf("netstack: peer %s closed", b.peer.ID)
	b.fail(err)
	return err
}

// fail tells whoever reserved the place that this packet will not reach the
// wire, once.
func (b *peerBatch) fail(err error) {
	if b.onFailure == nil || b.failed {
		return
	}
	b.failed = true
	b.onFailure(err)
}

// transmit is the synchronous form used by control traffic and tests. Routed
// data uses enqueue so workers never wait for the transport syscall.
func (b *peerBatch) transmit() error {
	p := b.peer
	if p.completed != nil {
		b.done = make(chan error, 1)
		if err := b.enqueue(); err != nil {
			return err
		}
		// Waited for on the answer alone. Every batch that carries done is
		// answered exactly once: the sender answers what it transmits, and
		// discardQueued answers what it gives back, and those are the only two
		// readers of the queue. Racing that against p.stop made a batch the
		// transport had already taken report "closed" whenever the close won
		// the pick, which is about half the time once both are ready.
		return <-b.done
	}

	p.sendMu.Lock()
	for b.ticket != p.nextSend {
		p.sendCond.Wait()
	}
	defer func() {
		p.nextSend++
		p.sendCond.Broadcast()
		p.sendMu.Unlock()
	}()

	return b.send()
}

func (b *peerBatch) send() error {
	p := b.peer
	if !b.reserved {
		b.encrypt()
	}
	var sendErr error
	if len(b.sealed) != 0 {
		sendErr = p.transmitBatchFn(b.sealed)
		if sendErr != nil && b.err == nil {
			b.err = sendErr
		}
	}
	// A compatibility peer has no sender goroutine, so this is the only place
	// its packets can be counted, and without it Dropped was structurally zero
	// on an exported constructor. Counted in two parts because they mean
	// different things, and by difference rather than by batch so a batch that
	// sealed some of its packets and lost the rest says so.
	if !b.counted {
		if missing := len(b.raw) - len(b.sealed); missing > 0 {
			p.dropped.Add(uint64(missing))
		}
		if sendErr != nil {
			p.sendFailed.Add(uint64(len(b.sealed)))
		}
		b.counted = true
	}
	if b.err != nil {
		b.fail(b.err)
	}
	return b.err
}

// discardQueued gives back every batch the sender still holds, in ticket
// order so a caller watching the counter sees what it expects, and drains
// whatever else is already in the queue behind them.
func (p *Peer) discardQueued(pending map[uint64]*peerBatch) {
	// Closed first, so nothing can arrive behind the drain. enqueue takes the
	// same lock and gives its batch back rather than queueing it.
	p.queueMu.Lock()
	p.queueClosed = true
	p.queueMu.Unlock()
	for {
		select {
		case b := <-p.completed:
			pending[b.ticket] = b
		default:
			tickets := slices.Sorted(maps.Keys(pending))
			for _, ticket := range tickets {
				b := pending[ticket]
				delete(pending, ticket)
				if p.noteDiscarded != nil {
					p.noteDiscarded(ticket)
				}
				err := b.abandon()
				if b.done != nil {
					b.done <- err
				}
			}
			return
		}
	}
}

// releaseBudget gives back the packets the batch holds of its peer's budget
func (b *peerBatch) releaseBudget() {
	budget := &b.peer.dataBudget
	if b.control {
		budget = &b.peer.controlBudget
	}
	budget.used.Add(-int64(b.held))
	b.held = 0
}

func (b *peerBatch) releaseStorage() {
	if b.storage != nil {
		*b.storage = b.sealed
		b.peer.storagePool(len(b.raw)).Put(b.storage)
		b.storage, b.sealed = nil, nil
	}
}

// storagePool is where a batch of n packets takes its sealed storage and gives it back
// the pool of the power of two at or above n, the last one also taking any batch longer than transmitBatchSize
func (p *Peer) storagePool(n int) *sync.Pool {
	return &p.sealedPool[min(bits.Len(uint(n-1)), len(p.sealedPool)-1)]
}

func (p *Peer) noteSendError(err error) {
	now := int64(time.Since(p.started))
	previous := p.sendErrReported.Load()
	if now-previous < int64(sendErrReportInterval) || !p.sendErrReported.CompareAndSwap(previous, now) {
		return
	}
	slog.Warn("netstack send batch failed", "peer", p.ID, "err", err, "dropped_total", p.dropped.Load())
}

func (p *Peer) senderLoop() {
	defer close(p.senderDone)
	pending := make(map[uint64]*peerBatch)
	ready := make([]*peerBatch, 0, transmitBatchSize)
	packets := make([][]byte, 0, transmitBatchSize)
	next := uint64(0)
	for {
		if pending[next] == nil {
			// with nothing of the data budget held no data packet waits between its reservation and its transmit
			// so the queue the delay control measures is empty
			if p.dataBudget.used.Load() == 0 && p.delay.empty() {
				p.recordDelayState(0)
			}
			select {
			case b := <-p.completed:
				pending[b.ticket] = b
			case <-p.stop:
				// Everything queued behind the stop is given back rather than
				// left where it is: each of these holds packets of a budget
				// and a place in the order, and its packets have been counted
				// by nothing. A caller waiting on one is told, or transmit
				// never returns.
				p.discardQueued(pending)
				return
			}
		}
		// Small packets such as TCP ACKs arrive as individual TUN reads. Merge
		// completed work without waiting for another packet or changing order.
	drain:
		for range cap(p.completed) {
			select {
			case b := <-p.completed:
				pending[b.ticket] = b
			default:
				break drain
			}
		}
		now := time.Since(p.started)
		for len(packets) < transmitBatchSize {
			b := pending[next]
			if b == nil {
				break
			}
			delete(pending, next)
			ready = append(ready, b)
			p.shedHead(b, now)
			packets = append(packets, b.sealed[b.shed:]...)
			next++
		}
		var sendErr error
		if len(packets) != 0 {
			sendErr = p.transmitBatchFn(packets)
		}
		for _, b := range ready {
			if b.err == nil {
				b.err = sendErr
			}
			// A batch that sealed nothing never reached the transport at all,
			// so its packets are gone and this peer refused them. One that
			// sealed and then lost the syscall was attempted, which is a
			// different number.
			if b.err != nil && !b.counted {
				if len(b.sealed) == 0 {
					p.dropped.Add(uint64(len(b.raw)))
				} else {
					p.sendFailed.Add(uint64(len(b.raw) - b.shed))
				}
				b.counted = true
			}
			b.releaseStorage()
			b.releaseBudget()
			if b.err != nil {
				b.fail(b.err)
			}
			if b.done != nil {
				b.done <- b.err
			} else if b.err != nil {
				p.noteSendError(b.err)
			}
		}
		clear(packets)
		clear(ready)
		packets, ready = packets[:0], ready[:0]
	}
}

// shedHead runs the delay control on a batch the sender has just taken in ticket order
// and drops the batch's head packet when the control calls for a drop
// a control batch carries babel and the completion its caller waits for
// so it neither feeds the control nor loses a packet to it
// a batch whose reservation or seal failed sealed nothing and has no packet to lose
func (p *Peer) shedHead(b *peerBatch, now time.Duration) {
	if b.control || len(b.sealed) == 0 {
		return
	}
	sojourn := now - b.admitted
	dropping := p.delay.dropping
	if p.delay.drop(now, sojourn) {
		b.shed = 1
		// the total goes up first
		// so a reader that loads the delay drops before the total never sees more of them than of it
		p.dropped.Add(1)
		p.delayDropped.Add(1)
	}
	if p.delay.dropping != dropping {
		p.recordDelayState(sojourn)
	}
}

// recordDelayState records that the delay control began or stopped dropping
// sojourn is how long the batch that changed the state had waited since its reservation, zero when the queue emptied
func (p *Peer) recordDelayState(sojourn time.Duration) {
	if p.events == nil {
		return
	}
	kind := "netstack.codel.drained"
	if p.delay.dropping {
		kind = "netstack.codel.dropping"
	}
	p.events(kind, p.ID, slog.Duration("sojourn", sojourn), slog.Duration("target", codelTarget))
}
