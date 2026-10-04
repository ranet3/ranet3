// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

// events records what the node did and hands it to whoever is watching
// an event is a state change, never a packet
// the daemon owns one Bus and threads it through the subsystems it builds
package events

import (
	"cmp"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ranet3.com/pkgs/ranet3/control"
)

// stopping is why every subscription ends at shutdown
const stopping = "the daemon is stopping"

// Bus records events and fans them out
// one ring per subsystem keeps a flood in one from evicting another's history
// an emit holds its ring's lock for the append and the bus lock for the number and the offers to the queues
// a reader holds one ring's lock at a time, to copy that ring, and selects, sorts and renders outside every lock
type Bus struct {
	started time.Time
	// now is the clock the window is read on, which a test replaces
	now func() time.Time
	// rings is replaced whole under mu when a subsystem first emits, and read without a lock
	rings atomic.Pointer[map[string]*ring]

	mu     sync.Mutex
	seq    uint64
	subs   map[*Subscription]struct{}
	closed bool
}

func New() *Bus {
	b := &Bus{started: time.Now(), now: time.Now, subs: map[*Subscription]struct{}{}}
	b.rings.Store(&map[string]*ring{})
	return b
}

// Match takes an event by its kind, its peer and its attributes, which are the event's own to read during the call
// a subscription's match runs under the bus's lock at every emit, so it may not block
type Match func(kind, peer string, attrs []slog.Attr) bool

// record is an event as a ring holds it
// kept rendered its floats, its times and the values that can point at the emitter's state when the event was emitted
// its other attributes are rendered when it is read, or once at the emit when a follow takes it
type record struct {
	seq        uint64
	at         time.Time
	mono       time.Duration
	kind, peer string
	attrs      []slog.Attr
}

// Emit records one event and offers it to every subscriber that wants it
// it never waits on a subscriber
// a full one counts the event as dropped
// a nil Bus records nothing, which is a node built without one
func (b *Bus) Emit(kind, peer string, attrs ...slog.Attr) {
	if b == nil {
		return
	}
	now := b.now()
	rec := record{at: now, mono: now.Sub(b.started), kind: kind, peer: peer, attrs: kept(attrs)}
	subsystem, _, _ := strings.Cut(kind, ".")
	r := b.ring(subsystem)
	r.mu.Lock()
	defer r.mu.Unlock()
	// numbered and offered under the bus lock, so the numbers have no gap and every queue takes them in order
	// the ring lock is held from before the number until the append, so a subscription that saw the number finds the event in its copy
	b.mu.Lock()
	b.seq++
	rec.seq = b.seq
	var event control.Event
	rendered := false
	for sub := range b.subs {
		if !sub.match(kind, peer, rec.attrs) {
			continue
		}
		// a full queue refuses the event, counted without rendering it
		// only an emit sends on a queue, so one with room here still has room at the send
		if len(sub.queue) == cap(sub.queue) {
			sub.refused++
			continue
		}
		if !rendered {
			event, rendered = rec.event(), true
		}
		// the run refused before goes with the event the queue takes, which marks where the run was lost
		sub.queue <- control.Delivery{Event: event, Dropped: sub.refused}
		sub.refused = 0
	}
	b.mu.Unlock()
	r.add(rec)
}

// ring is the subsystem's ring, made the first time it emits
func (b *Bus) ring(subsystem string) *ring {
	if r := (*b.rings.Load())[subsystem]; r != nil {
		return r
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	rings := *b.rings.Load()
	if r := rings[subsystem]; r != nil {
		return r
	}
	grown := maps.Clone(rings)
	grown[subsystem] = &ring{}
	b.rings.Store(&grown)
	return grown[subsystem]
}

// Recorded is every recorded event match takes from the last window, in order
// a zero window takes everything the rings still hold
// the read is cut at the number last given before the copy, as Subscribe's is, and holds every event up to it that the rings still hold
func (b *Bus) Recorded(match Match, window time.Duration) []control.Event {
	b.mu.Lock()
	last := b.seq
	b.mu.Unlock()
	return b.selected(b.copied(), match, window, last)
}

// Subscribe is Recorded and a subscription to every later event match takes
// the two meet without a gap and without an event twice
func (b *Bus) Subscribe(match Match, window time.Duration) ([]control.Event, *Subscription) {
	sub := &Subscription{bus: b, match: match, queue: make(chan control.Delivery, queueSize)}
	b.mu.Lock()
	if b.closed {
		sub.reason = stopping
		close(sub.queue)
	} else {
		b.subs[sub] = struct{}{}
	}
	// every event numbered up to last was offered to the queues before sub joined them and every later one is offered to sub
	// each was in its ring before the ring lock that numbered it was let go, so the copy below finds it
	last := b.seq
	b.mu.Unlock()
	return b.selected(b.copied(), match, window, last), sub
}

// copied is everything the rings hold, each ring copied under its own lock alone, in no order
// a ring that grew since its size was read is copied again once the copy has grown, outside its lock
func (b *Bus) copied() []record {
	rings := *b.rings.Load()
	size := 0
	for _, r := range rings {
		size += int(r.held.Load())
	}
	out := make([]record, 0, size)
	for _, r := range rings {
		var fits bool
		if out, fits = r.copyTo(out); !fits {
			// a ring holds ringSize at most, so the second copy fits
			out, _ = r.copyTo(slices.Grow(out, ringSize))
		}
	}
	return out
}

// selected is the records numbered up to last that match takes from the window, rendered in order
func (b *Bus) selected(records []record, match Match, window time.Duration, last uint64) []control.Event {
	from := b.now().Sub(b.started) - window
	records = slices.DeleteFunc(records, func(rec record) bool {
		return rec.seq > last || window != 0 && rec.mono < from || !match(rec.kind, rec.peer, rec.attrs)
	})
	slices.SortFunc(records, func(x, y record) int { return cmp.Compare(x.seq, y.seq) })
	out := make([]control.Event, len(records))
	for i, rec := range records {
		out[i] = rec.event()
	}
	return out
}

// Close ends every subscription and every later one, saying the daemon is stopping
// the rings go on recording, so what the shutdown did stays readable while the process lasts
func (b *Bus) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	for sub := range b.subs {
		sub.end(stopping)
	}
}

// kept is attrs as a ring holds them, a copy whose values cannot change after the call
// a value of a kind that can point at state the caller goes on changing is rendered at once
// a float or a time is kept as the text it renders, which a match compares without rendering under the bus lock
func kept(attrs []slog.Attr) []slog.Attr {
	if len(attrs) == 0 {
		return nil
	}
	out := slices.Clone(attrs)
	for i, attr := range out {
		switch attr.Value.Kind() {
		case slog.KindAny, slog.KindLogValuer, slog.KindGroup, slog.KindFloat64, slog.KindTime:
			out[i].Value = slog.StringValue(attr.Value.Resolve().String())
		}
	}
	return out
}

func (rec record) event() control.Event {
	event := control.Event{Seq: rec.seq, At: rec.at, Mono: control.Duration(rec.mono), Kind: rec.kind, Peer: rec.peer}
	if len(rec.attrs) > 0 {
		event.Attrs = make(map[string]string, len(rec.attrs))
		for _, attr := range rec.attrs {
			event.Attrs[attr.Key] = attr.Value.String()
		}
	}
	return event
}

// ring is a subsystem's last ringSize events, oldest first once rotated by next
type ring struct {
	mu     sync.Mutex
	events []record
	next   int
	// held is len(events), which a reader sizes its copy by before it takes mu
	held atomic.Int64
}

func (r *ring) add(rec record) {
	if len(r.events) < ringSize {
		r.events = append(r.events, rec)
		r.held.Store(int64(len(r.events)))
		return
	}
	r.events[r.next] = rec
	r.next = (r.next + 1) % ringSize
}

// copyTo appends the ring's events to out, oldest first, and reports whether out had room for them
// out without room takes nothing, so no copy grows while the ring's lock is held
func (r *ring) copyTo(out []record) ([]record, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if cap(out)-len(out) < len(r.events) {
		return out, false
	}
	return append(append(out, r.events[r.next:]...), r.events[:r.next]...), true
}

// Subscription is one watcher's queue on a Bus, a control.Subscription
type Subscription struct {
	bus   *Bus
	match Match
	// queue, refused and reason are sent on, counted and set under bus.mu alone
	queue chan control.Delivery
	// refused is the run of events refused since queue last took one or Dropped took the run
	refused uint64
	reason  string
}

func (s *Subscription) C() <-chan control.Delivery { return s.queue }

// Dropped takes the run once the queue holds no event before it
// while the queue holds one the run stays, for the next event the queue takes or a later call
func (s *Subscription) Dropped() uint64 {
	s.bus.mu.Lock()
	defer s.bus.mu.Unlock()
	if len(s.queue) > 0 {
		return 0
	}
	dropped := s.refused
	s.refused = 0
	return dropped
}

func (s *Subscription) Reason() string {
	s.bus.mu.Lock()
	defer s.bus.mu.Unlock()
	return s.reason
}

// Close ends the subscription from the reading side, once
func (s *Subscription) Close() {
	s.bus.mu.Lock()
	defer s.bus.mu.Unlock()
	if _, live := s.bus.subs[s]; live {
		s.end("its reader closed it")
	}
}

// end runs under bus.mu
func (s *Subscription) end(reason string) {
	delete(s.bus.subs, s)
	s.reason = reason
	close(s.queue)
}
