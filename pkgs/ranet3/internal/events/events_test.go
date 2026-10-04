// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package events

import (
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/control"
)

const (
	// testWait is how long a test waits for something it expects, generous for a loaded machine
	testWait = 10 * time.Second
	// emitBound is the longest an emit to a stopped subscriber may take, far above what two locks and an append cost
	emitBound = 50 * time.Millisecond
	// subscribeRounds is how many subscriptions race the emitters, so that a lost or doubled event shows in any run
	subscribeRounds = 200
	// firstEmitRounds is how many fresh buses race eight first emits of one subsystem, so that a ring made twice shows in any run
	firstEmitRounds = 200
	// readRounds is how many buses a reader reads while four emitters write, so that a read without its cut shows a gap in any run
	readRounds = 200
)

func everything(string, string, []slog.Attr) bool { return true }

// next waits for the subscription's next delivery, failing the test where none comes in time
func next(t *testing.T, sub *Subscription) (control.Delivery, bool) {
	t.Helper()
	select {
	case delivery, open := <-sub.C():
		return delivery, open
	case <-time.After(testWait):
		t.Fatal("the subscription carried nothing")
		return control.Delivery{}, false
	}
}

// sequence numbers are gapless and in emission order however many goroutines emit
func TestSeqIsGaplessAcrossGoroutines(t *testing.T) {
	bus := New()
	const writers, each = 8, 100
	var emitting sync.WaitGroup
	for writer := range writers {
		emitting.Go(func() {
			for n := range each {
				bus.Emit(fmt.Sprintf("w%d.event.emitted", writer), "", slog.Int("n", n))
			}
		})
	}
	emitting.Wait()
	recorded := bus.Recorded(everything, 0)
	if len(recorded) != writers*each {
		t.Fatalf("recorded %d events of %d", len(recorded), writers*each)
	}
	last := map[string]int{}
	for i, event := range recorded {
		if event.Seq != uint64(i+1) {
			t.Fatalf("event %d carries seq %d", i, event.Seq)
		}
		n, err := strconv.Atoi(event.Attrs["n"])
		if err != nil {
			t.Fatal(err)
		}
		if previous, seen := last[event.Kind]; seen && n != previous+1 {
			t.Fatalf("%s went from %d to %d", event.Kind, previous, n)
		}
		last[event.Kind] = n
	}
}

// a subscriber that stops reading costs Emit nothing
// the run of events it missed goes with the next event its queue takes, and a run still open at its end is told by Dropped
func TestFullSubscriberCountsDropsWhileEmitReturns(t *testing.T) {
	bus := New()
	_, sub := bus.Subscribe(everything, 0)
	slowest := time.Duration(0)
	for range queueSize + 100 {
		start := time.Now()
		bus.Emit("babel.route.selected", "example/gateway/0@0")
		slowest = max(slowest, time.Since(start))
	}
	if slowest > emitBound {
		t.Errorf("an emit to a full subscriber took %s", slowest)
	}
	first, _ := next(t, sub)
	bus.Emit("kernel.pass", "")
	for range 7 {
		bus.Emit("babel.route.selected", "example/gateway/0@0")
	}
	sub.Close()
	deliveries := []control.Delivery{first}
	for delivery := range sub.C() {
		deliveries = append(deliveries, delivery)
	}
	if len(deliveries) != queueSize+1 {
		t.Fatalf("a queue of %d carried %d events", queueSize, len(deliveries))
	}
	for i, delivery := range deliveries[:queueSize] {
		if delivery.Dropped != 0 {
			t.Errorf("event %d of those queued before the overflow says %d were dropped before it", i, delivery.Dropped)
		}
	}
	if taken := deliveries[queueSize]; taken.Event.Kind != "kernel.pass" || taken.Dropped != 100 {
		t.Errorf("the first event taken after the overflow is %s after %d dropped, want kernel.pass after 100", taken.Event.Kind, taken.Dropped)
	}
	if dropped := sub.Dropped(); dropped != 7 {
		t.Errorf("a run of 7 at the end was told as %d", dropped)
	}
}

// Dropped takes a run once the queue holds no event before it, and answers 0 while one is queued
// the next event the queue takes carries none of a run already taken
func TestDroppedTakesARunOnceTheQueueIsEmpty(t *testing.T) {
	bus := New()
	_, sub := bus.Subscribe(everything, 0)
	defer sub.Close()
	for range queueSize + 5 {
		bus.Emit("babel.route.selected", "")
	}
	if dropped := sub.Dropped(); dropped != 0 {
		t.Errorf("a queue still holding its events told a run of %d", dropped)
	}
	for range queueSize {
		next(t, sub)
	}
	if dropped := sub.Dropped(); dropped != 5 {
		t.Errorf("a run of 5 after the queue emptied was told as %d", dropped)
	}
	if dropped := sub.Dropped(); dropped != 0 {
		t.Errorf("a run already taken was told again as %d", dropped)
	}
	bus.Emit("kernel.pass", "")
	if delivery, _ := next(t, sub); delivery.Dropped != 0 {
		t.Errorf("the event after a taken run carried %d dropped", delivery.Dropped)
	}
}

// a flood in one subsystem leaves another's history where it was, and keeps its own newest events
func TestFloodKeepsAnotherSubsystemsHistory(t *testing.T) {
	bus := New()
	bus.Emit("kernel.pass", "", slog.String("trigger", "mesh"))
	for range 5 * ringSize {
		bus.Emit("babel.route.selected", "example/gateway/0@0")
	}
	recorded := bus.Recorded(everything, 0)
	if len(recorded) != ringSize+1 || recorded[0].Kind != "kernel.pass" {
		t.Fatalf("after a flood the recorder holds %d events, the first %+v", len(recorded), recorded[0])
	}
	for i, event := range recorded[1:] {
		if want := uint64(4*ringSize + 2 + i); event.Seq != want {
			t.Fatalf("the flooded ring holds seq %d where seq %d belongs, so it kept other than its newest %d", event.Seq, want, ringSize)
		}
	}
}

// a window keeps the events that recent and no older one, and a match keeps the ones it takes
func TestRecordedHonorsTheWindow(t *testing.T) {
	bus := New()
	clock := bus.started
	bus.now = func() time.Time { return clock }
	for _, event := range []struct {
		after time.Duration
		peer  string
	}{{time.Second, "example/relay/0@0"}, {time.Minute, "example/gateway/0@0"}, {10 * time.Minute, "example/gateway/0@0"}} {
		clock = bus.started.Add(event.after)
		bus.Emit("dial.attempt", event.peer, slog.Duration("after", event.after))
	}
	if recent := bus.Recorded(everything, 5*time.Minute); len(recent) != 1 || recent[0].Attrs["after"] != "10m0s" {
		t.Errorf("the last five minutes hold %+v", recent)
	}
	if all := bus.Recorded(everything, 0); len(all) != 3 {
		t.Errorf("no window holds %d events of 3", len(all))
	}
	if matched := bus.Recorded(func(_, peer string, _ []slog.Attr) bool { return peer != "example/relay/0@0" }, 0); len(matched) != 2 {
		t.Errorf("a match leaving one event out took %d", len(matched))
	}
}

// a subscription taken while four emitters write to rings of their own meets its backlog exactly
// the backlog is every event so far, the first live event is the one after its last, and the live ones arrive in order
// an emitter stops short of filling its ring, so no event leaves the backlog by being overwritten
func TestSubscribeMeetsItsBacklog(t *testing.T) {
	raced := 0
	for range subscribeRounds {
		bus := New()
		var started, emitting sync.WaitGroup
		for writer := range 4 {
			started.Add(1)
			emitting.Go(func() {
				kind := fmt.Sprintf("w%d.event.emitted", writer)
				for n := range ringSize - 1 {
					bus.Emit(kind, "")
					if n == 0 {
						started.Done()
					}
				}
			})
		}
		started.Wait()
		backlog, sub := bus.Subscribe(everything, 0)
		emitting.Wait()
		sub.Close()
		for i, event := range backlog {
			if event.Seq != uint64(i+1) {
				t.Fatalf("the backlog holds seq %d at %d", event.Seq, i)
			}
		}
		seq := uint64(len(backlog))
		for delivery := range sub.C() {
			if delivery.Event.Seq <= seq || delivery.Dropped == 0 && delivery.Event.Seq != seq+1 {
				t.Fatalf("after seq %d and %d dropped the subscription carried seq %d, the backlog having ended at %d",
					seq, delivery.Dropped, delivery.Event.Seq, len(backlog))
			}
			seq = delivery.Event.Seq
		}
		if seq > uint64(len(backlog)) {
			raced++
		} else if len(backlog) != 4*(ringSize-1) {
			t.Fatalf("a subscription after the last emit holds %d events of %d", len(backlog), 4*(ringSize-1))
		}
	}
	t.Logf("%d of %d subscriptions met an emitter still writing", raced, subscribeRounds)
}

// a reader slow to select from the recorder holds up no emitter, since it selects outside every lock
func TestSlowReaderHoldsUpNoEmitter(t *testing.T) {
	for name, read := range map[string]func(*Bus, Match){
		"Recorded":  func(bus *Bus, match Match) { bus.Recorded(match, 0) },
		"Subscribe": func(bus *Bus, match Match) { _, sub := bus.Subscribe(match, 0); sub.Close() },
	} {
		t.Run(name, func(t *testing.T) {
			bus := New()
			bus.Emit("babel.route.selected", "example/gateway/0@0")
			selecting, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var calls atomic.Int32
			go func() {
				defer close(done)
				read(bus, func(string, string, []slog.Attr) bool {
					if calls.Add(1) == 1 {
						close(selecting)
						<-release
					}
					return true
				})
			}()
			select {
			case <-selecting:
			case <-time.After(testWait):
				t.Fatal("the read never reached its match")
			}
			emitted := make(chan struct{})
			go func() {
				bus.Emit("babel.route.selected", "example/gateway/0@0")
				bus.Emit("kernel.pass", "")
				close(emitted)
			}()
			select {
			case <-emitted:
			case <-time.After(testWait):
				t.Error("an emit waited on a reader selecting from the recorder")
			}
			close(release)
			<-done
		})
	}
}

// an emit of strings and integers copies its attributes once and renders nothing, which is left to whoever reads the event
// a subscriber whose queue is full refuses the event without its being rendered
func TestEmitAllocatesOnlyItsAttributes(t *testing.T) {
	bus := New()
	emit := func() {
		bus.Emit("babel.route.selected", "example/gateway/0@0", slog.String("route", "fd00:1::/64"), slog.Int("metric", 96))
	}
	// a full ring overwrites rather than grows
	for range ringSize {
		emit()
	}
	if allocations := testing.AllocsPerRun(100, emit); allocations != 1 {
		t.Errorf("an emit with two attributes allocated %v times", allocations)
	}
	_, sub := bus.Subscribe(everything, 0)
	defer sub.Close()
	for range queueSize {
		emit()
	}
	if allocations := testing.AllocsPerRun(100, emit); allocations != 1 {
		t.Errorf("an emit to a subscriber that fell behind allocated %v times", allocations)
	}
}

// eight first emits of one subsystem, made at once, all land in the one ring the subsystem gets
func TestFirstEmitsOfOneSubsystemAreAllRecorded(t *testing.T) {
	for range firstEmitRounds {
		bus := New()
		start := make(chan struct{})
		var emitting sync.WaitGroup
		for range 8 {
			emitting.Go(func() {
				<-start
				bus.Emit("dial.attempt", "")
			})
		}
		close(start)
		emitting.Wait()
		if recorded := bus.Recorded(everything, 0); len(recorded) != 8 {
			t.Fatalf("eight first emits of one subsystem left %d events in the recorder", len(recorded))
		}
	}
}

// a reader sizes its copy before it takes any ring's lock, so no ring is held while the copy grows
func TestCopyIsSizedBeforeAnyRingIsHeld(t *testing.T) {
	bus := New()
	// rotated rings, so each is copied in two parts
	for _, kind := range []string{"babel.route.selected", "dial.attempt", "kernel.pass"} {
		for range ringSize + 100 {
			bus.Emit(kind, "")
		}
	}
	if allocations := testing.AllocsPerRun(10, func() { bus.copied() }); allocations != 1 {
		t.Errorf("a copy of three full rings allocated %v times", allocations)
	}
}

// a ring is copied only into room made before its lock was taken, which a ring that recorded since its size was read does not find
// such a ring is copied whole once the copy has grown outside its lock
func TestRingIsCopiedOnlyIntoRoomMadeBeforeItsLock(t *testing.T) {
	bus := New()
	for range 3 {
		bus.Emit("dial.attempt", "")
	}
	dials := (*bus.rings.Load())["dial"]
	if out, fits := dials.copyTo(make([]record, 0, 2)); fits || len(out) != 0 {
		t.Errorf("a copy with room for 2 took %d of a ring holding 3, fits %v", len(out), fits)
	}
	// the size a reader reads before it copies lags behind a ring that recorded since
	dials.held.Store(1)
	if copied := bus.copied(); len(copied) != 3 {
		t.Errorf("a ring holding 3 and read as holding 1 was copied as %d", len(copied))
	}
}

// a match is asked about each event with its attributes, in the recorder and at every emit
func TestMatchSeesTheAttributes(t *testing.T) {
	bus := New()
	routed := func(_, _ string, attrs []slog.Attr) bool {
		return slices.ContainsFunc(attrs, func(attr slog.Attr) bool { return attr.Equal(slog.String("route", "fd00:2::/64")) })
	}
	for _, route := range []string{"fd00:1::/64", "fd00:2::/64"} {
		bus.Emit("babel.route.selected", "", slog.String("route", route))
	}
	backlog, sub := bus.Subscribe(routed, 0)
	defer sub.Close()
	for _, route := range []string{"fd00:3::/64", "fd00:2::/64"} {
		bus.Emit("babel.route.selected", "", slog.String("route", route))
	}
	if delivery, _ := next(t, sub); len(backlog) != 1 || backlog[0].Seq != 2 || delivery.Event.Seq != 4 {
		t.Errorf("a match taking one route took %+v from the recorder and seq %d live", backlog, delivery.Event.Seq)
	}
}

// a read of the recorder while four emitters write to rings of their own holds every event up to its last
// a read copies one ring at a time, and its cut keeps a later event of one ring out where an earlier one of another is not in the copy
func TestRecordedHoldsNoGap(t *testing.T) {
	read := 0
	for range readRounds {
		bus := New()
		var emitting sync.WaitGroup
		for writer := range 4 {
			emitting.Go(func() {
				kind := fmt.Sprintf("w%d.event.emitted", writer)
				for range ringSize - 1 {
					bus.Emit(kind, "")
				}
			})
		}
		done := make(chan struct{})
		go func() {
			emitting.Wait()
			close(done)
		}()
		for writing := true; writing; read++ {
			select {
			case <-done:
				writing = false
			default:
			}
			for i, event := range bus.Recorded(everything, 0) {
				if event.Seq != uint64(i+1) {
					t.Fatalf("a read while emitters wrote holds seq %d at %d", event.Seq, i)
				}
			}
		}
	}
	t.Logf("%d reads of %d buses", read, readRounds)
}

// an emit keeps a copy of the attributes it is handed, so a caller that reuses its slice changes no recorded event
func TestEmitKeepsItsOwnAttributes(t *testing.T) {
	bus := New()
	attrs := []slog.Attr{slog.String("route", "fd00:1::/64")}
	bus.Emit("babel.route.selected", "", attrs...)
	attrs[0] = slog.String("route", "fd00:2::/64")
	if got := bus.Recorded(everything, 0)[0].Attrs["route"]; got != "fd00:1::/64" {
		t.Errorf("an attribute its caller changed after the emit reads %q", got)
	}
}

// a float or a time is kept as the text it renders, so a match compares it without rendering it under the bus lock
func TestFloatAndTimeAreKeptAsTheirText(t *testing.T) {
	bus := New()
	stamp := time.Date(2026, 10, 6, 4, 0, 0, 500, time.FixedZone("", 5*60*60+45*60))
	bus.Emit("probe.kept.text", "", slog.Float64("loss", 0.5), slog.Time("at", stamp))
	var held []slog.Attr
	bus.Recorded(func(_, _ string, attrs []slog.Attr) bool {
		held = attrs
		return true
	}, 0)
	if len(held) != 2 || !held[0].Value.Equal(slog.StringValue("0.5")) || !held[1].Value.Equal(slog.StringValue(stamp.String())) {
		t.Errorf("a float and a time were kept as %v", held)
	}
}

// an event carries the time of its emit and how long after the bus started it came
func TestEventCarriesItsTimes(t *testing.T) {
	bus := New()
	started := time.Date(2026, 10, 6, 4, 0, 0, 0, time.UTC)
	bus.started = started
	bus.now = func() time.Time { return started.Add(5 * time.Second) }
	bus.Emit("probe.times.event", "")
	if event := bus.Recorded(everything, 0)[0]; !event.At.Equal(started.Add(5*time.Second)) || time.Duration(event.Mono) != 5*time.Second {
		t.Errorf("an event emitted 5 seconds after the bus started reads At %v Mono %v", event.At, time.Duration(event.Mono))
	}
}

// valuer renders through LogValue as something other than its own fmt form
type valuer struct{ routes int }

func (v valuer) LogValue() slog.Value { return slog.IntValue(v.routes * 10) }

// a LogValuer is kept as its LogValue renders it, as a log line shows it
func TestLogValuerIsKeptAsItsLogValue(t *testing.T) {
	bus := New()
	bus.Emit("probe.valuer.event", "", slog.Any("routes", valuer{routes: 4}))
	if got := bus.Recorded(everything, 0)[0].Attrs["routes"]; got != "40" {
		t.Errorf("a LogValuer rendering 40 was recorded as %q", got)
	}
}

// an attribute that points at state its emitter goes on changing is recorded as it was at the emit
func TestAttributeIsRecordedAsItWas(t *testing.T) {
	bus := New()
	state := &struct{ Routes int }{1}
	bus.Emit("babel.route.selected", "", slog.Any("state", state))
	state.Routes = 2
	if got := bus.Recorded(everything, 0)[0].Attrs["state"]; got != "&{1}" {
		t.Errorf("an attribute changed after its emit reads %q", got)
	}
}

// closing the bus ends every subscription and every later one, with the reason
func TestCloseEndsSubscriptions(t *testing.T) {
	bus := New()
	_, sub := bus.Subscribe(everything, 0)
	bus.Emit("daemon.stopping", "")
	bus.Close()
	if delivery, open := next(t, sub); !open || delivery.Event.Kind != "daemon.stopping" {
		t.Fatalf("the last event before the close read as %+v, open %v", delivery, open)
	}
	if _, open := next(t, sub); open || sub.Reason() != stopping {
		t.Errorf("a closed bus left its subscription open %v with reason %q", open, sub.Reason())
	}
	sub.Close()
	bus.Emit("daemon.late.event", "")
	backlog, late := bus.Subscribe(everything, 0)
	if _, open := next(t, late); open || late.Reason() != stopping || len(backlog) != 2 {
		t.Errorf("a subscription after the close is open %v, says %q and holds %d events", open, late.Reason(), len(backlog))
	}
}

// a node built without a bus emits into nothing
func TestNilBusRecordsNothing(t *testing.T) {
	var bus *Bus
	bus.Emit("dial.attempt", "example/gateway/0@0", slog.String("remote", "192.0.2.1:13000"))
}
