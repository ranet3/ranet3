// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// feed is a subscription with a bounded queue that never blocks its producer, as the bus's are
// a run of refused events goes with the next event the queue takes, as the bus's does
type feed struct {
	mu      sync.Mutex
	queue   chan Delivery
	refused uint64
	ended   bool
	reason  string
	closed  chan struct{}
}

func newFeed(size int) *feed {
	return &feed{queue: make(chan Delivery, size), closed: make(chan struct{})}
}

func (f *feed) emit(event Event) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ended {
		return
	}
	select {
	case f.queue <- Delivery{Event: event, Dropped: f.refused}:
		f.refused = 0
	default:
		f.refused++
	}
}

// end closes the feed from the producing side, as a daemon stopping does
func (f *feed) end(reason string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.ended {
		f.ended, f.reason = true, reason
		close(f.queue)
	}
}

func (f *feed) C() <-chan Delivery { return f.queue }

// Dropped takes the run once the queue holds no event before it, as the bus's does
func (f *feed) Dropped() uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.queue) > 0 {
		return 0
	}
	dropped := f.refused
	f.refused = 0
	return dropped
}

func (f *feed) Reason() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reason
}

func (f *feed) Close() {
	f.end("closed by its reader")
	select {
	case <-f.closed:
	default:
		close(f.closed)
	}
}

// streamSource hands every stream a fresh feed and the test that feed
type streamSource struct {
	fakeSource
	size  int
	feeds chan *feed
}

func newStreamSource(size int) *streamSource {
	return &streamSource{size: size, feeds: make(chan *feed, 8)}
}

func (s *streamSource) ProbeFollow() ([]Event, Subscription) {
	f := newFeed(s.size)
	s.feeds <- f
	return []Event{{Seq: 1, Kind: "probe.backlog.held"}}, f
}

func (s *streamSource) nextFeed(t *testing.T) *feed {
	t.Helper()
	select {
	case f := <-s.feeds:
		return f
	case <-time.After(testWait):
		t.Fatal("no stream subscribed")
		return nil
	}
}

const pathProbeStream = PathDebug + "probe-stream"

type probeStreamer interface {
	ProbeFollow() ([]Event, Subscription)
}

func init() {
	registerDebug(pathProbeStream, classRead, reflect.TypeFor[Event](), func(d *debugServer, w http.ResponseWriter, r *http.Request) {
		if !reading(w, r) {
			return
		}
		if source, ok := implements[probeStreamer](d, w, "probe stream"); ok {
			d.stream(w, r, source.ProbeFollow)
		}
	})
}

// events reads a stream into events until the daemon ends it, or the context, or a bad line
func events(ctx context.Context, client *Client) ([]Event, error) {
	var out []Event
	for line, err := range client.Stream(ctx, pathProbeStream, nil) {
		if err != nil {
			return out, err
		}
		var event Event
		if err := json.Unmarshal(line, &event); err != nil {
			return out, err
		}
		out = append(out, event)
	}
	return out, nil
}

const (
	// testWait is how long a test waits for something it expects, generous for a loaded machine
	testWait = 10 * time.Second
	// testPoll is how often a waiting test looks again
	testPoll = time.Millisecond
	// shortBound stands in for a timeout or budget a test needs to pass quickly
	shortBound = 100 * time.Millisecond
)

// serveStream serves src on a real socket through newServer, with the server shaped by shape
func serveStream(t *testing.T, src Source, shape func(*http.Server)) *Client {
	t.Helper()
	path := socketPath(t)
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	server := newServer(src)
	shape(server)
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })
	return Dial(path)
}

// a stream clears the write deadline the server puts on every answer, and its client reads with none of its own
// an event written well past both timeouts still arrives
func TestStreamOutlivesTheWriteAndReadTimeouts(t *testing.T) {
	src := newStreamSource(16)
	client := serveStream(t, src, func(server *http.Server) { server.WriteTimeout = shortBound })
	client.http.Timeout = shortBound
	ctx, cancel := context.WithTimeout(context.Background(), testWait)
	defer cancel()
	got := make(chan []Event, 1)
	go func() {
		read, _ := events(ctx, client)
		got <- read
	}()
	f := src.nextFeed(t)
	// four times either timeout, which a stream that kept one would not survive
	time.Sleep(4 * shortBound)
	f.emit(Event{Seq: 2, Kind: "probe.late.event"})
	f.end("the test is done")
	stream := <-got
	if len(stream) != 4 || stream[2].Kind != "probe.late.event" || stream[3].Kind != "stream.closed" {
		t.Fatalf("a stream past the write and read timeouts carried %+v", stream)
	}
}

// a reader that stops reading costs its producer nothing
// the stream then says how many events it missed, once and exactly, at the place it missed them
func TestStreamCountsWhatAPausedReaderMissed(t *testing.T) {
	src := newStreamSource(16)
	client := serveStream(t, src, func(*http.Server) {})
	ctx, cancel := context.WithTimeout(context.Background(), testWait)
	defer cancel()
	response, err := client.Raw(ctx, http.MethodGet, pathProbeStream, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if kind := response.Header.Get("Content-Type"); kind != "application/x-ndjson" {
		t.Errorf("a stream is sent as %q", kind)
	}
	f := src.nextFeed(t)

	// events go one at a time until one is not taken, so the stream is stuck on the paused reader
	padding := strings.Repeat("x", 64<<10)
	emitted := 0
	for stuck := false; !stuck; {
		emitted++
		f.emit(Event{Seq: uint64(emitted + 1), Kind: "probe.flood.event", Attrs: map[string]string{"padding": padding}})
		for wait := time.Now(); len(f.queue) > 0 && !stuck; {
			stuck = time.Since(wait) > 2*shortBound
			time.Sleep(testPoll)
		}
	}
	// then a flood the queue cannot hold
	slowest := time.Duration(0)
	for range 1000 {
		emitted++
		start := time.Now()
		f.emit(Event{Seq: uint64(emitted + 1), Kind: "probe.flood.event"})
		slowest = max(slowest, time.Since(start))
	}
	if slowest > shortBound {
		t.Errorf("an emit to a paused reader took %s", slowest)
	}
	last := uint64(emitted + 1)

	// the reader comes back and takes what was queued, and the run lost after that is noted once, before the next event
	read := make(chan []Event, 1)
	go func() {
		var stream []Event
		defer func() { read <- stream }()
		decoder := json.NewDecoder(response.Body)
		for {
			var event Event
			if decoder.Decode(&event) != nil {
				return
			}
			stream = append(stream, event)
			if event.Kind == "stream.closed" {
				return
			}
		}
	}()
	for deadline := time.Now().Add(testWait); len(f.queue) > 0; time.Sleep(testPoll) {
		if time.Now().After(deadline) {
			t.Fatal("the reader came back and the stream never took what was queued")
		}
	}
	f.emit(Event{Seq: last + 1, Kind: "probe.tail.event"})
	f.end("the test is done")
	stream := <-read

	var lines []string
	for _, event := range stream {
		lines = append(lines, fmt.Sprintf("%s %d %s", event.Kind, event.Seq, event.Attrs["count"]))
	}
	note := slices.IndexFunc(stream, func(event Event) bool { return event.Kind == "stream.dropped" })
	if note < 0 || note+1 >= len(stream) || stream[note+1].Kind != "probe.tail.event" ||
		slices.ContainsFunc(stream[note+1:], func(event Event) bool { return event.Kind == "stream.dropped" }) {
		t.Fatalf("the drop is not noted once, right before the first event after it: %q", lines)
	}
	dropped, err := strconv.Atoi(stream[note].Attrs["count"])
	if err != nil {
		t.Fatal(err)
	}
	delivered, newest := 0, uint64(0)
	for _, event := range stream[:note] {
		if event.Kind == "probe.flood.event" {
			delivered, newest = delivered+1, event.Seq
		}
	}
	if delivered+dropped != emitted || newest+uint64(dropped) != last {
		t.Errorf("of %d events up to seq %d, %d arrived up to seq %d and %d were reported dropped", emitted, last, delivered, newest, dropped)
	}
}

// one flush carries streamBatch events at most, so a flood is written as it arrives rather than after it
func TestDrainStopsAtABatch(t *testing.T) {
	f := newFeed(2 * streamBatch)
	for seq := range 2 * streamBatch {
		f.emit(Event{Seq: uint64(seq + 1), Kind: "probe.flood.event"})
	}
	first := <-f.C()
	if batch, open := drain(f, first, true); len(batch) != streamBatch || !open {
		t.Errorf("a feed holding %d events was drained %d at once, open %v", 2*streamBatch, len(batch), open)
	}
}

// a run of refused events still open when the feed ends is noted before the stream's last line
func TestDrainNotesARunStillOpenAtTheEnd(t *testing.T) {
	f := newFeed(1)
	for seq := range 3 {
		f.emit(Event{Seq: uint64(seq + 1), Kind: "probe.flood.event"})
	}
	f.end("the daemon is stopping")
	first, open := <-f.C()
	batch, open := drain(f, first, open)
	var lines []string
	for _, event := range batch {
		lines = append(lines, event.Kind+" "+event.Attrs["count"])
	}
	if want := []string{"probe.flood.event ", "stream.dropped 2", "stream.closed "}; !slices.Equal(lines, want) || open {
		t.Errorf("a feed that ended after refusing 2 drained to %q, open %v, want %q", lines, open, want)
	}
}

// a run refused while the queue still held events goes with the next event the queue takes, and is noted right before it
func TestDrainNotesARunBeforeTheEventThatFollowedIt(t *testing.T) {
	f := newFeed(2)
	for seq := range 3 {
		f.emit(Event{Seq: uint64(seq + 1), Kind: "probe.flood.event"})
	}
	first, open := <-f.C()
	f.emit(Event{Seq: 4, Kind: "probe.tail.event"})
	batch, open := drain(f, first, open)
	var lines []string
	for _, event := range batch {
		lines = append(lines, fmt.Sprintf("%s %d %s", event.Kind, event.Seq, event.Attrs["count"]))
	}
	if want := []string{"probe.flood.event 1 ", "probe.flood.event 2 ", "stream.dropped 0 1", "probe.tail.event 4 "}; !slices.Equal(lines, want) || !open {
		t.Errorf("a feed that refused 1 between two queued events drained to %q, open %v, want %q", lines, open, want)
	}
}

// a run refused after the last event an open feed queued is noted once the stream has taken that event
// the next event the queue takes carries none of it again
func TestDrainNotesAnOpenRunOnceTheQueueIsEmpty(t *testing.T) {
	f := newFeed(1)
	for seq := range 3 {
		f.emit(Event{Seq: uint64(seq + 1), Kind: "probe.flood.event"})
	}
	first, open := <-f.C()
	batch, open := drain(f, first, open)
	var lines []string
	for _, event := range batch {
		lines = append(lines, event.Kind+" "+event.Attrs["count"])
	}
	if want := []string{"probe.flood.event ", "stream.dropped 2"}; !slices.Equal(lines, want) || !open {
		t.Errorf("an open feed that refused 2 after its last queued event drained to %q, open %v, want %q", lines, open, want)
	}
	f.emit(Event{Seq: 4, Kind: "probe.tail.event"})
	if next := <-f.C(); next.Dropped != 0 {
		t.Errorf("the event after a noted run carried %d dropped again", next.Dropped)
	}
}

// a run refused after the last event an open feed queued is noted when the batch that empties the queue is a full one
// a burst that filled the bus's queue, a whole number of batches, ends at a full batch
func TestDrainNotesAnOpenRunAtAFullBatch(t *testing.T) {
	f := newFeed(streamBatch)
	for seq := range streamBatch + 2 {
		f.emit(Event{Seq: uint64(seq + 1), Kind: "probe.flood.event"})
	}
	first, open := <-f.C()
	batch, open := drain(f, first, open)
	if last := batch[len(batch)-1]; len(batch) != streamBatch+1 || last.Kind != "stream.dropped" || last.Attrs["count"] != "2" || !open {
		t.Errorf("an open feed of %d that refused 2 after its last queued event drained to %d lines ending in %s %s, open %v",
			streamBatch, len(batch), last.Kind, last.Attrs["count"], open)
	}
}

// the stream places are few, so a fifth stream is refused while the reads still answer
func TestFifthStreamIsRefusedAndReadsStillAnswer(t *testing.T) {
	src := newStreamSource(16)
	client := serveStream(t, src, func(*http.Server) {})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for range maxStreams {
		response, err := client.Raw(ctx, http.MethodGet, pathProbeStream, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		src.nextFeed(t)
	}
	for _, err := range client.Stream(ctx, pathProbeStream, nil) {
		if err == nil || !strings.Contains(err.Error(), "503") || !strings.Contains(err.Error(), "as many as it holds open") {
			t.Errorf("a fifth stream answered %v", err)
		}
		break
	}
	// the place is taken before the subscription, so a refused stream never had one
	if len(src.feeds) != 0 {
		t.Error("a refused stream subscribed")
	}
	if _, err := client.Status(); err != nil {
		t.Errorf("a read failed while every stream place was held: %v", err)
	}
}

// a reader that goes ends the stream, its subscription and every goroutine it held
func TestStreamEndsWithItsReader(t *testing.T) {
	src := newStreamSource(16)
	client := serveStream(t, src, func(*http.Server) {})
	before := runtime.NumGoroutine()
	ctx, cancel := context.WithCancel(context.Background())
	response, err := client.Raw(ctx, http.MethodGet, pathProbeStream, nil)
	if err != nil {
		t.Fatal(err)
	}
	f := src.nextFeed(t)
	cancel()
	response.Body.Close()
	select {
	case <-f.closed:
	case <-time.After(testWait):
		t.Fatal("the stream's subscription outlived its reader")
	}
	deadline := time.Now().Add(testWait)
	for runtime.NumGoroutine() > before {
		if time.Now().After(deadline) {
			t.Fatalf("%d goroutines remain against %d before the stream", runtime.NumGoroutine(), before)
		}
		time.Sleep(testPoll)
	}
}

// a stream.live note parts the recorded events from the subscription's, which come after it
func TestStreamMarksWhereTheRecordedEventsEnd(t *testing.T) {
	src := newStreamSource(16)
	client := serveStream(t, src, func(*http.Server) {})
	ctx, cancel := context.WithTimeout(context.Background(), testWait)
	defer cancel()
	got := make(chan []Event, 1)
	go func() {
		read, _ := events(ctx, client)
		got <- read
	}()
	f := src.nextFeed(t)
	f.emit(Event{Seq: 2, Kind: "probe.live.event"})
	f.end("the test is done")
	var kinds []string
	for _, event := range <-got {
		kinds = append(kinds, event.Kind)
	}
	if want := []string{"probe.backlog.held", "stream.live", "probe.live.event", "stream.closed"}; !slices.Equal(kinds, want) {
		t.Errorf("a stream carried %q, want %q", kinds, want)
	}
}

// a feed that ends says why, after everything it carried, and the stream ends with it
func TestStreamSaysWhyItClosed(t *testing.T) {
	src := newStreamSource(16)
	client := serveStream(t, src, func(*http.Server) {})
	ctx, cancel := context.WithTimeout(context.Background(), testWait)
	defer cancel()
	got := make(chan []Event, 1)
	go func() {
		read, _ := events(ctx, client)
		got <- read
	}()
	f := src.nextFeed(t)
	f.emit(Event{Seq: 2, Kind: "probe.last.event"})
	f.end("the daemon is stopping")
	stream := <-got
	last := stream[len(stream)-1]
	if stream[len(stream)-2].Kind != "probe.last.event" || last.Kind != "stream.closed" || last.Attrs["reason"] != "the daemon is stopping" {
		t.Errorf("a feed that ended streamed %+v", stream)
	}
}

// a quiet stream still writes, so a reader can tell it from a dead daemon
func TestQuietStreamWritesHeartbeats(t *testing.T) {
	src := newStreamSource(16)
	d := newDebugServer(src)
	d.heartbeat = shortBound / 5
	server := httptest.NewServer(d)
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), testWait)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+pathProbeStream, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	decoder := json.NewDecoder(response.Body)
	for _, want := range []string{"probe.backlog.held", "stream.live", "stream.heartbeat", "stream.heartbeat"} {
		var event Event
		if err := decoder.Decode(&event); err != nil || event.Kind != want {
			t.Fatalf("the stream carried %+v, %v where %s was due", event, err, want)
		}
	}
}

// a line under the bound is read whole, and one past it is an error rather than a read that never ends
func TestOverlongLineIsAnError(t *testing.T) {
	client := serveStream(t, fakeSource{}, func(server *http.Server) {
		server.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprintf(w, "%s\n%s\n", strings.Repeat("x", maxLine/2), strings.Repeat("x", maxLine+1))
		})
	})
	ctx, cancel := context.WithTimeout(context.Background(), testWait)
	defer cancel()
	var lines []int
	for line, err := range client.Stream(ctx, pathProbeStream, nil) {
		if err != nil {
			if len(lines) != 1 || lines[0] != maxLine/2 || errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("after lines of %v bytes the stream failed with %v", lines, err)
			}
			return
		}
		lines = append(lines, len(line))
	}
	t.Fatalf("lines of %v bytes ended the stream without an error", lines)
}

// a line the stream yielded reads as it was sent after the stream has read on
// lines of 3000 bytes outgrow the scanner's first buffer, which then moves what it holds to its start
func TestStreamLinesSurviveLaterReads(t *testing.T) {
	var sent []string
	for i := range 8 {
		sent = append(sent, strings.Repeat(string(rune('a'+i)), 3000))
	}
	client := serveStream(t, fakeSource{}, func(server *http.Server) {
		server.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			for _, line := range sent {
				fmt.Fprintln(w, line)
			}
		})
	})
	ctx, cancel := context.WithTimeout(context.Background(), testWait)
	defer cancel()
	var kept []json.RawMessage
	for line, err := range client.Stream(ctx, pathProbeStream, nil) {
		if err != nil {
			t.Fatal(err)
		}
		kept = append(kept, line)
	}
	if len(kept) != len(sent) {
		t.Fatalf("the stream yielded %d lines of %d", len(kept), len(sent))
	}
	for i, line := range kept {
		if string(line) != sent[i] {
			t.Errorf("line %d, sent as 3000 %c, reads %q once the stream read on", i, rune('a'+i), line[:min(len(line), 16)])
		}
	}
}

// a reader that stops reading is dropped once a write has waited one budget on it
func TestStreamDropsAReaderThatStopsReading(t *testing.T) {
	src := newStreamSource(16)
	d := newDebugServer(src)
	d.budget = shortBound
	client := serveStream(t, src, func(server *http.Server) { server.Handler = d })
	response, err := client.Raw(context.Background(), http.MethodGet, pathProbeStream, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	f := src.nextFeed(t)
	padding := strings.Repeat("x", 64<<10)
	for deadline := time.Now().Add(testWait); ; {
		select {
		case <-f.closed:
			return
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("the stream kept waiting on a reader that stopped reading")
		}
		f.emit(Event{Kind: "probe.flood.event", Attrs: map[string]string{"padding": padding}})
		time.Sleep(testPoll)
	}
}

// a daemon that never answers is an error of its own, not the context's
// so a caller that ends a stream at its deadline cannot take one for the other
func TestStreamNamesADaemonThatNeverAnswered(t *testing.T) {
	path := socketPath(t)
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		var held []net.Conn
		defer func() {
			for _, conn := range held {
				conn.Close()
			}
		}()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			held = append(held, conn)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), shortBound)
	defer cancel()
	for _, err := range Dial(path).Stream(ctx, pathProbeStream, nil) {
		if err == nil || errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "did not answer") {
			t.Errorf("a daemon that never answered gave %v", err)
		}
		return
	}
	t.Error("a daemon that never answered ended the stream without an error")
}
