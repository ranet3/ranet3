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

	"ranet3.com/pkgs/ranet3/transport"
)

// Peer separates parallel packet encryption from ordered, batched transport.
type Peer struct {
	ID              string
	reserveFn       func(count int) (BatchSealer, error)
	transmitBatchFn func(sealed [][]byte) error
	// mtu is the largest inner packet the session carries, DefaultMTU until whoever builds the peer sets it
	mtu atomic.Int64
	// sent is set once the sender hands the transport a data packet, and TakeSent clears it
	sent atomic.Bool

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
	// other says this node chose not to send, and an operator reading the second
	// needs it not to move for the first. The sender merges several batches
	// into one call, so an error covers every packet in it. How many of them
	// actually left is not knowable from here, but for a bare path report,
	// which refused only the packets past the path it names.
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
	// closeGrace overrides defaultCloseGrace, and zero means the default.
	closeGrace time.Duration
	// noteDiscarded is nil in production. A test replaces it to observe the
	// order discardQueued gives batches back in, which nothing else can see.
	noteDiscarded func(ticket uint64)

	// A peer hands completed crypto batches to one sender. dataBudget
	// bounds the bytes this peer holds from their reservation through
	// encryption, the wait behind an earlier ticket and the transport syscall.
	//
	// controlBudget is the same bound for babel, kept separate so a bulk
	// transfer cannot starve control traffic.
	// queueMu makes closing the queue and inserting into it one decision.
	// The sender's stop path drains what it holds and returns, so a batch
	// that lands in the queue after that drain is read by nobody: never
	// transmitted, never counted, its budget never given back, and its caller
	// told it succeeded. Testing p.stop before the send cannot close that,
	// because the drain can happen between the test and the send.
	queueMu       sync.Mutex
	queueClosed   bool
	completed     chan *peerBatch
	dataBudget    peerBudget
	controlBudget peerBudget
	stop          chan struct{}
	senderDone    chan struct{}
	closeOnce     sync.Once
	// sealedPool holds sealed storage, each a *[][]byte returned only after the transport finishes
	// it keeps one pool for each power of two of a batch's size up to peerDataBudget
	// so a batch reuses only storage grown for at most twice its size
	// but for storage a share holding more bytes than peerDataBudget grew in the last pool, since its size is the budget alone
	sealedPool []sync.Pool
}

// BatchSealer consumes a sequence range previously reserved from one outbound
// SA. It returns packet slices backed by one packed allocation so the transport
// can hand them to UDP GSO without another copy. reuse is a previous result
// whose transport has finished. The sealer may overwrite it or replace it.
// Output must not alias raw, whose TUN buffers are recycled after encryption.
type BatchSealer func(raw [][]byte, nextHeaders []byte, reuse [][]byte) ([][]byte, error)

// NewPeer constructs a peer whose expensive encryption can run in
// parallel. reserveFn is called in packet-intake order and must return a sealer
// owning count consecutive sequence numbers from the current outbound SA.
// transmitBatchFn must finish using every packet before returning.
// events records the peer's changes of state under its ID, nil recording nothing
func NewPeer(id string, reserveFn func(count int) (BatchSealer, error), transmitBatchFn func(sealed [][]byte) error, events func(kind, peer string, attrs ...slog.Attr)) *Peer {
	p := &Peer{ID: id, reserveFn: reserveFn, transmitBatchFn: transmitBatchFn,
		events: events, started: time.Now()}
	p.mtu.Store(DefaultMTU)
	p.sendErrReported.Store(-int64(sendErrReportInterval))
	p.dataBudget.limit = peerDataBudget
	p.controlBudget.limit = controlQueueSize
	// every batch with a ticket holds at least leastPacketBytes of the data budget or one packet of the control one
	// so the queue holds them all and enqueue never waits
	p.completed = make(chan *peerBatch, peerDataBudget/leastPacketBytes+controlQueueSize)
	p.sealedPool = make([]sync.Pool, bits.Len(peerDataBudget)+1)
	p.stop = make(chan struct{})
	p.senderDone = make(chan struct{})
	go p.senderLoop()
	return p
}

// SetMTU sets the largest inner packet the peer's session carries
func (p *Peer) SetMTU(mtu int) { p.mtu.Store(int64(mtu)) }

// MTU is the largest inner packet the peer's session carries
// the mesh answers a packet past it, cuts it into fragments or drops it, rather than send it
func (p *Peer) MTU() int { return int(p.mtu.Load()) }

// TakeSent reports whether the sender handed the transport a data packet since the last call
func (p *Peer) TakeSent() bool { return p.sent.Swap(false) }

// Close stops the peer's ordered sender
func (p *Peer) Close() {
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
	b := p.reserveNow(1, len(raw), true)
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
	peer    *Peer
	ticket  uint64
	sealer  BatchSealer
	sealed  [][]byte
	storage *[][]byte
	raw     [][]byte
	headers []byte
	err     error
	// counted says this batch's packets have already reached p.dropped, so
	// whoever discards it last leaves the counter alone. Only reserve failure
	// counts early, because that is where the packet count is still known, and
	// an implicit test on err would read every other reason err is set (a
	// batch that failed to seal, say) as counted too, and lose those
	// packets from the counter entirely.
	counted bool
	// onFailure is the caller's completion signal, set through Place. failed
	// keeps it to one call: a batch reaches exactly one terminal state, but
	// several sites decide it.
	onFailure func(error)
	failed    bool
	// size picks the batch's sealed storage, a data batch's charge or a control place's packet length
	// keyed by the control budget's one packet, every babel place would take storage a path MTU probe grew
	size int
	// held is the part of its peer's budget this batch holds, bytes of the data budget or packets of the control one
	// zero once it is given back
	held int
	// control says which budget the place came from, so it goes back where it
	// was taken from.
	control bool
	// admitted is when the batch was reserved, as time since the peer started
	admitted time.Duration
	// shed is how many sealed packets the delay control dropped from the head of the batch
	shed int
}

// peerBudget is the room a peer has from a reservation until the transmit that carried it returns
type peerBudget struct {
	used  atomic.Int64
	limit int64
}

// take holds n of the budget if it fits, without waiting, and says whether it did
func (b *peerBudget) take(n int) bool {
	for {
		used := b.used.Load()
		if used+int64(n) > b.limit {
			return false
		}
		if b.used.CompareAndSwap(used, used+int64(n)) {
			return true
		}
	}
}

// dataCharge is the part of the data budget a share of count packets coming to bytes holds
// each packet holds at least leastPacketBytes, and a share at most the whole budget, so an empty budget admits a share of any size
func dataCharge(count, bytes int) int { return min(max(bytes, count*leastPacketBytes), peerDataBudget) }

// reserveBatchNow takes the data budget for count packets of bytes only if they fit.
// A caller that would rather drop its packets than wait gets nil, having
// consumed neither a ticket nor a sequence range, which is why the budget is
// taken before either: a reserved ticket that never reaches the sender stalls
// it forever. The refusal is counted in packets.
//
// It does not wait at all, even briefly. The budget frees as the peer's sender
// returns from the transport, so a budget is full when its socket is
// backpressured, when its reads still wait for or sit in a crypto worker, or
// when its sender has not yet run to drain it. Backpressure lasts far longer
// than any wait worth having, so a wait for it would only add latency before
// dropping anyway. The caller also runs on a goroutine that serves other peers:
// a TUN reader holds the tickets it has reserved for the rest of its read until
// it submits them. ReserveRawOrDrop says the same of its own callers.
func (p *Peer) reserveBatchNow(count, bytes int) *peerBatch {
	return p.reserveNow(count, dataCharge(count, bytes), false)
}

// reserveNow takes a batch of count packets and size if it fits, and otherwise reports the packets dropped
// a data batch holds its size of the data budget and a control place its packets of the control one
func (p *Peer) reserveNow(count, size int, control bool) *peerBatch {
	budget, n := &p.dataBudget, size
	if control {
		budget, n = &p.controlBudget, count
	}
	// a closed peer refuses and counts everything it is offered
	select {
	case <-p.stop:
		p.dropped.Add(uint64(count))
		return nil
	default:
	}
	if !budget.take(n) {
		p.dropped.Add(uint64(count))
		return nil
	}
	return p.reserveTicket(count, size, control)
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
// for a batch of size, which holds size of the data budget or count places of the control one
func (p *Peer) reserveTicket(count, size int, control bool) *peerBatch {
	b := &peerBatch{peer: p, size: size, held: size, control: control}
	if control {
		b.held = count
	}
	p.reserveMu.Lock()
	b.ticket = p.reserved
	p.reserved++
	b.sealer, b.err = p.reserveFn(count)
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
// enqueue seals the batch in that same worker before the TUN buffers are
// recycled.
func (b *peerBatch) append(raw []byte, nextHeader byte) {
	b.raw = append(b.raw, raw)
	b.headers = append(b.headers, nextHeader)
}

func (b *peerBatch) encrypt() {
	if b.err != nil {
		return
	}
	b.storage, _ = b.peer.storagePool(b.size).Get().(*[][]byte)
	if b.storage == nil {
		b.storage = new([][]byte)
	}
	b.sealed, b.err = b.sealer(b.raw, b.headers, *b.storage)
}

// enqueue seals the batch, hands it to the peer's ordered sender and returns as
// soon as the bounded queue accepts it, so a crypto worker never waits while an
// earlier batch is in sendmmsg.
func (b *peerBatch) enqueue() error {
	p := b.peer
	b.encrypt()
	p.queueMu.Lock()
	if p.queueClosed {
		p.queueMu.Unlock()
		return b.abandon()
	}
	// Never blocks: p.completed holds every batch the two budgets can hand a
	// ticket to, since each such batch holds at least leastPacketBytes of the
	// data budget or one packet of the control one, and every batch that
	// reaches here is one of them. The default arm is therefore unreachable,
	// and giving the batch back is the answer if it ever is, rather than
	// blocking with queueMu held.
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
// leaves a batch unsendable (a seal that failed on the way here) is
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
				b.abandon()
			}
			return
		}
	}
}

// releaseBudget gives back what the batch holds of its peer's budget
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
		b.peer.storagePool(b.size).Put(b.storage)
		b.storage, b.sealed = nil, nil
	}
}

// storagePool is where a batch of size n takes its sealed storage and gives it back
// the pool of the power of two at or above n, the last one also taking a size of none
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
				// left where it is: each of these holds part of a budget
				// and a place in the order, and its packets have been counted
				// by nothing.
				p.discardQueued(pending)
				return
			}
		}
		// small packets such as TCP ACKs arrive one TUN read each, so the sender takes every batch already queued before it transmits
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
		data := false
		for len(packets) < transmitBatchSize {
			b := pending[next]
			if b == nil {
				break
			}
			delete(pending, next)
			ready = append(ready, b)
			p.shedHead(b, now)
			packets = append(packets, b.sealed[b.shed:]...)
			data = data || (!b.control && len(b.sealed) > b.shed)
			next++
		}
		var sendErr error
		// report is a bare path report, which refused only the packets past the path and sent the rest
		var report *transport.PathMTUError
		if len(packets) != 0 {
			if sendErr = p.transmitBatchFn(packets); sendErr != nil {
				report, _ = sendErr.(*transport.PathMTUError)
			}
		}
		if data && !p.sent.Load() {
			p.sent.Store(true)
		}
		for _, b := range ready {
			lost := len(b.raw) - b.shed
			if b.err == nil {
				b.err = sendErr
				if report != nil {
					// a batch whose every packet went has not failed, so its caller undoes nothing
					// a packet that went ahead of the refusal on a path that narrowed meanwhile counts as refused
					if lost = b.past(report.Largest()); lost == 0 {
						b.err = nil
					}
				}
			}
			// A batch that sealed nothing never reached the transport at all,
			// so its packets are gone and this peer refused them. One that
			// sealed and then lost the syscall was attempted, which is a
			// different number.
			if b.err != nil && !b.counted {
				if len(b.sealed) == 0 {
					p.dropped.Add(uint64(len(b.raw)))
				} else {
					p.sendFailed.Add(uint64(lost))
				}
				b.counted = true
			}
			b.releaseStorage()
			b.releaseBudget()
			if b.err != nil {
				b.fail(b.err)
			}
			if b.err != nil {
				p.noteSendError(b.err)
			}
		}
		clear(packets)
		clear(ready)
		packets, ready = packets[:0], ready[:0]
	}
}

// past counts the batch's packets the transmit carried that are longer than largest
func (b *peerBatch) past(largest int) int {
	n := 0
	for _, packet := range b.sealed[b.shed:] {
		if len(packet) > largest {
			n++
		}
	}
	return n
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
