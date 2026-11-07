// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

package netstack

import (
	"errors"
	"fmt"
	"log/slog"
	"math/bits"
	"sync"
	"sync/atomic"
	"time"

	"ranet3.com/pkgs/ranet3/transport"
	"ranet3.com/pkgs/wireguard/conn"
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

	// reserveMu makes a batch's sequence range and its place at the tail of the queue one step
	// and the sender's stop closing the queue, so no batch joins it once the sender has given back what it held
	reserveMu sync.Mutex
	// head and tail are the batches reserved and not yet taken by the sender, in reservation order
	// closed refuses every reservation once the sender has stopped, all three under reserveMu
	head, tail *peerBatch
	closed     bool
	// queued holds a token once a filler has sealed a batch, which wakes the sender waiting on its empty queue
	queued  chan struct{}
	dropped atomic.Uint64
	// delayDropped is the part of dropped the sender dropped for the delay through the queue
	// delay is the control that decides those drops, which only the sender touches
	delayDropped atomic.Uint64
	delay        codel
	// events records the peer's changes of state, nil recording nothing
	events func(kind, peer string, attrs ...slog.Attr)
	// sendFailed counts packets that were sealed, handed to the transport and
	// lost in the syscall, but for a path MTU probe the host refused as past
	// the path. Separate from dropped, which counts what this peer
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

	// dataBudget bounds the bytes this peer holds from their reservation
	// through encryption, the wait behind an earlier batch and the transport
	// syscall. controlBudget is the same bound for babel, kept separate so a
	// bulk transfer cannot starve control traffic.
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
	p.queued = make(chan struct{}, 1)
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
	if err := b.err; err != nil {
		// The place was taken and has to be sent, so the sender is not
		// stranded, but nothing in it will leave. Telling the caller now is
		// what lets it give back the bookkeeping the packet consumed.
		_ = (&Place{batch: b}).Send()
		return nil, err
	}
	b.append(raw, nextHeader)
	return &Place{batch: b}, nil
}

// Send hands the packet to the peer's sender, which emits it once everything
// reserved ahead of it has gone. The place is dead once Send is called: its
// batch goes back to a pool shared by every peer when the sender is done
// with it.
func (p *Place) Send() error { return p.batch.finish() }

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

// MarkProbe marks the packet as a probe of the path's MTU, which the host
// refusing as past the path answers rather than fails. It must be called
// before Send, as OnFailure must.
func (p *Place) MarkProbe() { p.batch.probe = true }

// a batch belongs to its filler until the filler seals it, then to the sender
// a batch the stopped sender found still filling is orphaned, and its filler gives it back
const (
	batchFilling uint32 = iota
	batchSealed
	batchOrphaned
)

// batchPools hold the batches no owner holds, each with nothing in done
// pool k those whose slices have room for more than 1<<(k-1) packets and at most 1<<k, the first those with room for 1 or none
// so a reservation reuses only slices with room for less than twice its packets, and a backlog of small batches behind large reads holds none of the room the reads took
// a batch grown past the packets one read holds, which only a share cut into fragments grows, goes back with no slices rather than keep that room in a pool
var batchPools = newBatchPools()

func newBatchPools() []sync.Pool {
	pools := make([]sync.Pool, bits.Len(conn.IdealBatchSize-1)+1)
	for i := range pools {
		pools[i].New = func() any { return &peerBatch{done: make(chan struct{}, 1)} }
	}
	return pools
}

// batchPool is where a batch for count packets comes from, and where one whose slices have room for count goes back
func batchPool(count int) *sync.Pool {
	return &batchPools[min(bits.Len(uint(max(count, 1)-1)), len(batchPools)-1)]
}

type peerBatch struct {
	peer *Peer
	// next is the batch reserved after this one, written under the peer's reserveMu
	next *peerBatch
	// state is batchFilling, batchSealed or batchOrphaned
	// done takes one token from the filler that moves state to batchSealed
	state   atomic.Uint32
	done    chan struct{}
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
	// probe says the place holds a probe of the path, set through Place
	probe bool
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
// consumed neither a place nor a sequence range, which is why the budget is
// taken before either: a place that is never finished stalls the sender
// forever. The refusal is counted in packets.
//
// It does not wait at all, even briefly. The budget frees as the peer's sender
// returns from the transport, so a budget is full when its socket is
// backpressured, when its reads still wait for or sit in a crypto worker, or
// when its sender has not yet run to drain it. Backpressure lasts far longer
// than any wait worth having, so a wait for it would only add latency before
// dropping anyway. The caller also runs on a goroutine that serves other peers:
// a TUN reader holds the places it has reserved for the rest of its read until
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
	return p.reservePlace(count, size, control)
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

// reservePlace takes the peer's next place in its queue and its sequence range for count packets
// for a batch of size, which holds size of the data budget or count places of the control one, taken by the caller
// a closed peer gives that back and counts the packets dropped
func (p *Peer) reservePlace(count, size int, control bool) *peerBatch {
	b := batchPool(count).Get().(*peerBatch)
	b.peer, b.size, b.held, b.control = p, size, size, control
	if control {
		b.held = count
	}
	b.fit(count)
	p.reserveMu.Lock()
	if p.closed {
		p.reserveMu.Unlock()
		b.releaseBudget()
		b.recycle()
		p.dropped.Add(uint64(count))
		return nil
	}
	b.sealer, b.err = p.reserveFn(count)
	if p.tail == nil {
		p.head = b
	} else {
		p.tail.next = b
	}
	p.tail = b
	p.reserveMu.Unlock()
	b.admitted = time.Since(p.started)
	if b.err != nil {
		// The batch keeps its place, so the sender is not stranded, but
		// nothing in it will be transmitted: the sequence range it needed does
		// not exist. Counted here rather than where the sender discards it,
		// because this is where the packet count is still known.
		p.dropped.Add(uint64(count))
		b.counted = true
	}
	return b
}

// append retains a view of plaintext owned by the surrounding TUN batch.
// finish seals the batch in that same worker before the TUN buffers are
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

// finish seals the batch and hands it to the peer's ordered sender without
// waiting, so a crypto worker never waits while an earlier batch is in
// sendmmsg. A batch the stopped sender orphaned is given back here instead.
func (b *peerBatch) finish() error {
	p := b.peer
	b.encrypt()
	if !b.state.CompareAndSwap(batchFilling, batchSealed) {
		err := b.abandon()
		b.recycle()
		return err
	}
	// the only token of this reservation, into a slot the batch's last owner left empty
	b.done <- struct{}{}
	// b is the sender's from here and may be back in the pool, so the wake goes through p
	// a sender waiting on its empty queue wakes at a seal, never at a reservation it would find unsealed
	select {
	case p.queued <- struct{}{}:
	default:
	}
	return nil
}

// sealedNow takes the batch's token if its filler has sealed it, without waiting
func (b *peerBatch) sealedNow() bool {
	select {
	case <-b.done:
		return true
	default:
		return false
	}
}

// fit gives the batch slices with room for count packets
// slices short of that room are replaced, not grown, by ones with room for the power of two at or above count
// for count up to the packets of a read, that room is the most packets of count's pool
// past them it is a room recycle drops, so a share of more packets than a read allocates its slices at every reservation
// growth would overshoot that room, into a larger pool or, past the packets of a read, to slices recycle drops
// so a batch fitted for a read goes back to the pool it came from with its slices, whatever reservation it served before
func (b *peerBatch) fit(count int) {
	if cap(b.raw) < count || cap(b.headers) < count {
		room := 1 << bits.Len(uint(count-1))
		b.raw, b.headers = make([][]byte, 0, room), make([]byte, 0, room)
	}
}

// recycle puts a batch no owner holds any more back in the pool of its slices' room, keeping the slices of a batch no larger than a read
func (b *peerBatch) recycle() {
	clear(b.raw)
	raw, headers := b.raw[:0], b.headers[:0]
	if cap(raw) > conn.IdealBatchSize {
		raw, headers = nil, nil
	}
	*b = peerBatch{raw: raw, headers: headers, done: b.done}
	batchPool(cap(raw)).Put(b)
}

// abandon gives back what a batch reserved and counts its packets as dropped,
// for a peer that closed after it had its place. A batch that could not
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

// takeQueue takes every batch reserved since the last take, the first of them linked to the rest in reservation order
func (p *Peer) takeQueue() *peerBatch {
	p.reserveMu.Lock()
	head := p.head
	p.head, p.tail = nil, nil
	p.reserveMu.Unlock()
	return head
}

// stopSending closes the queue and gives back every batch in it, held first and in reservation order
// held is the batches the sender took and did not send, none of whose tokens it has taken
// a batch still filling is orphaned and left to its filler, so the stop waits on no filler
func (p *Peer) stopSending(held *peerBatch) {
	p.reserveMu.Lock()
	p.closed = true
	rest := p.head
	p.head, p.tail = nil, nil
	p.reserveMu.Unlock()
	for _, list := range [...]*peerBatch{held, rest} {
		for b := list; b != nil; {
			next := b.next
			if !b.state.CompareAndSwap(batchFilling, batchOrphaned) {
				// sealed, and its filler sends the token right after its own swap
				<-b.done
				b.abandon()
				b.recycle()
			}
			b = next
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

// noteSendError warns of a failed send at most once every sendErrReportInterval, and says a send on a closed mux or a bare path report at debug, since the session's end and the path search answer for them
// their lost packets still count
// sealed is a batch the transport was handed, whose loss sendFailed counts and the warning names, where dropped counts one that never reached it
func (p *Peer) noteSendError(err error, sealed bool) {
	if _, bare := err.(*transport.PathMTUError); bare || errors.Is(err, transport.ErrClosed) {
		slog.Debug("netstack send batch ended at a closed mux or past the path", "peer", p.ID, "err", err)
		return
	}
	now := int64(time.Since(p.started))
	previous := p.sendErrReported.Load()
	if now-previous < int64(sendErrReportInterval) || !p.sendErrReported.CompareAndSwap(previous, now) {
		return
	}
	if sealed {
		slog.Warn("netstack send batch failed", "peer", p.ID, "err", err, "send_failed_total", p.sendFailed.Load())
		return
	}
	slog.Warn("netstack send batch failed", "peer", p.ID, "err", err, "dropped_total", p.dropped.Load())
}

// senderLoop sends the peer's batches in reservation order, each once its filler has sealed it
func (p *Peer) senderLoop() {
	defer close(p.senderDone)
	// head is the first batch the sender took from the queue and has not sent, the rest linked behind it
	var head *peerBatch
	ready := make([]*peerBatch, 0, transmitBatchSize)
	packets := make([][]byte, 0, transmitBatchSize)
	for {
		if head == nil {
			head = p.takeQueue()
		}
		if head == nil {
			// with nothing of the data budget held no data packet waits between its reservation and its transmit
			// so the queue the delay control measures is empty
			if p.dataBudget.used.Load() == 0 && p.delay.empty() {
				p.recordDelayState(0)
			}
			select {
			case <-p.queued:
				continue
			case <-p.stop:
				p.stopSending(nil)
				return
			}
		}
		if !head.sealedNow() {
			select {
			case <-head.done:
			case <-p.stop:
				p.stopSending(head)
				return
			}
		}
		// small packets such as TCP ACKs arrive one TUN read each, so the sender takes every batch already sealed behind the head before it transmits
		now := time.Since(p.started)
		data := false
		for b := head; b != nil; {
			head = b.next
			// a batch reserved after now was read, as one the merge takes from the queue may be, is measured against a clock read after its reservation
			// its token came after its reservation, so that clock reads no earlier and its sojourn is never negative
			if b.admitted > now {
				now = time.Since(p.started)
			}
			ready = append(ready, b)
			p.shedHead(b, now)
			packets = append(packets, b.sealed[b.shed:]...)
			data = data || (!b.control && len(b.sealed) > b.shed)
			b = nil
			if len(packets) < transmitBatchSize {
				if head == nil {
					head = p.takeQueue()
				}
				if head != nil && head.sealedNow() {
					b = head
				}
			}
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
					// a probe refused past the path has its answer, which the search takes from the report
					if lost = b.past(report.Largest()); lost == 0 || b.probe {
						b.err = nil
					}
				}
			}
			// A batch that sealed nothing never reached the transport at all,
			// so its packets are gone and this peer refused them. One that
			// sealed and then lost the syscall was attempted, which is a
			// different number.
			sealed := len(b.sealed) != 0
			if b.err != nil && !b.counted {
				if !sealed {
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
				p.noteSendError(b.err, sealed)
			}
			b.recycle()
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

// shedHead runs the delay control on a batch the sender has just taken in reservation order
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
