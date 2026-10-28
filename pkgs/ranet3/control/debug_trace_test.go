// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// traceRecords is a source's trace the test feeds by hand, its records already in their wire form
type traceRecords struct {
	records chan TracePacket
	done    chan struct{}
	// refused is the counts for the rate and for the queue, set together
	refused atomic.Pointer[[2]uint64]
	// closed takes the why of the one Close the stream makes
	closed chan string
}

func newTraceRecords() *traceRecords {
	return &traceRecords{records: make(chan TracePacket, 1024), done: make(chan struct{}), closed: make(chan string, 1)}
}

func (t *traceRecords) Records() <-chan TracePacket { return t.records }

func (t *traceRecords) Done() <-chan struct{} { return t.done }

func (*traceRecords) Packet(packet TracePacket) TracePacket { return packet }

func (t *traceRecords) Refused() (rate, queue uint64) {
	if refused := t.refused.Load(); refused != nil {
		return refused[0], refused[1]
	}
	return 0, 0
}

func (*traceRecords) Reason() string { return "the daemon is stopping" }

func (t *traceRecords) Close(why string) { t.closed <- why }

// traceSource opens a trace of its own for every query, which the test takes from traces, and serves the probe stream beside it
type traceSource struct {
	*streamSource
	traces chan *traceRecords
	asked  chan TraceQuery
}

func newTraceSource() *traceSource {
	return &traceSource{streamSource: newStreamSource(16), traces: make(chan *traceRecords, 8), asked: make(chan TraceQuery, 8)}
}

func (s *traceSource) DebugTrace(_ context.Context, query TraceQuery) (TraceFeed, error) {
	records := newTraceRecords()
	s.asked <- query
	s.traces <- records
	return TraceFeedOf[TracePacket](records), nil
}

func (s *traceSource) nextTrace(t *testing.T) *traceRecords {
	t.Helper()
	select {
	case records := <-s.traces:
		return records
	case <-time.After(testWait):
		t.Fatal("no trace opened")
		return nil
	}
}

// traceServer serves src to uid 0 through a debug server shape changes
func traceServer(t *testing.T, src Source, shape func(*debugServer)) *httptest.Server {
	t.Helper()
	return traceServerFor(t, src, Caller{UID: 0}, shape)
}

// traceServerFor serves src to caller through a debug server shape changes
func traceServerFor(t *testing.T, src Source, caller Caller, shape func(*debugServer)) *httptest.Server {
	t.Helper()
	d := newDebugServer(src)
	shape(d)
	server := httptest.NewUnstartedServer(d)
	server.Config.ConnContext = func(ctx context.Context, _ net.Conn) context.Context { return withCaller(ctx, caller) }
	server.Start()
	t.Cleanup(server.Close)
	return server
}

// open starts a stream of path on server and returns its answer, which the test reads or leaves unread
func open(t *testing.T, server *httptest.Server, path string) *http.Response {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { response.Body.Close() })
	return response
}

// the trace is of the plaintext class, so --debug-access group does not open it to the daemon's own uid, and it opens nothing for the uid it refuses
func TestTraceIsForUIDZeroAlone(t *testing.T) {
	src := newTraceSource()
	server := traceServerFor(t, src, Caller{UID: 4242}, func(d *debugServer) { d.access, d.euid = DebugGroup, 4242 })
	response := open(t, server, PathDebugTrace)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("the daemon's own uid under --debug-access group was answered %s", response.Status)
	}
	if body, err := io.ReadAll(response.Body); err != nil || !strings.Contains(string(body), "uid 4242") {
		t.Errorf("the refusal read %q, %v, naming no uid 4242", body, err)
	}
	if len(src.traces) != 0 {
		t.Error("a refused caller opened a trace")
	}
}

// every query is read into the trace it asks for, and each value that does not parse or lies out of bounds is refused with 400, naming it
func TestTraceQueryParsesOrIsRefused(t *testing.T) {
	src := newTraceSource()
	server := traceServer(t, src, func(*debugServer) {})
	for _, c := range []struct {
		query string
		want  TraceQuery
	}{
		{"", TraceQuery{Rate: TraceRateDefault}},
		{"src=192.0.2.0/24&src=2001:db8::1&dst=198.51.100.7/24", TraceQuery{
			Sources:      []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("2001:db8::1/128")},
			Destinations: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
			Rate:         TraceRateDefault,
		}},
		{"proto=udp&decision=forward&peer=example/gateway&rate=1&payload=0", TraceQuery{Protocol: 17, Decision: "forward", Peer: "example/gateway", Rate: 1}},
		{"proto=58&rate=10000&payload=65535", TraceQuery{Protocol: 58, Rate: TraceRateMax, Payload: TracePayloadMax}},
	} {
		response := open(t, server, PathDebugTrace+"?"+c.query)
		if response.StatusCode != http.StatusOK {
			t.Errorf("%q answered %s", c.query, response.Status)
			continue
		}
		src.nextTrace(t)
		if got := <-src.asked; !reflect.DeepEqual(got, c.want) {
			t.Errorf("%q asked for %+v, want %+v", c.query, got, c.want)
		}
		response.Body.Close()
	}
	tooMany := strings.Repeat("src=192.0.2.1&", maxTracePrefixes+1)
	for _, c := range []struct{ query, names string }{
		{"src=192.0.2.0/33", "192.0.2.0/33"},
		{"dst=example.org", "example.org"},
		{"dst=fe80::1%25eth0", "fe80::1%eth0"},
		{tooMany, "17"},
		{"proto=256", "256"},
		{"proto=ospf", "ospf"},
		{"decision=accept", "accept"},
		{"rate=0", "0"},
		{"rate=10001", "10001"},
		{"rate=fast", "fast"},
		{"payload=-1", "-1"},
		{"payload=65536", "65536"},
		{"payload=%3B", ";"},
	} {
		status, body := get(t, server.Client(), server.URL+PathDebugTrace+"?"+c.query)
		if status != http.StatusBadRequest || !strings.Contains(body, c.names) {
			t.Errorf("%q answered %d %q, want 400 naming %q", c.query, status, body, c.names)
		}
	}
	if len(src.traces) != 0 {
		t.Error("a refused query opened a trace")
	}
	request, err := http.NewRequest(http.MethodHead, server.URL+PathDebugTrace, nil)
	if err != nil {
		t.Fatal(err)
	}
	if response, err := server.Client().Do(request); err != nil || response.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("a HEAD of the trace answered %v, %v", response, err)
	}
}

// the query a client sends reads back as itself, and the client refuses one out of bounds before it dials
func TestTraceQueryRoundTrips(t *testing.T) {
	query := TraceQuery{
		Sources:      []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("3fff::/20")},
		Destinations: []netip.Prefix{netip.MustParsePrefix("198.51.100.9/32")},
		Protocol:     6, Decision: "drop", Peer: "gateway", Rate: 7, Payload: 64,
	}
	if got, err := parseTraceQuery(query.values()); err != nil || !reflect.DeepEqual(got, query) {
		t.Errorf("%+v read back as %+v, %v", query, got, err)
	}
	for line, err := range Dial(socketPath(t)).Trace(t.Context(), TraceQuery{Rate: 0}) {
		if err == nil || !strings.Contains(err.Error(), "rate") {
			t.Errorf("a query of rate 0 gave %+v, %v", line, err)
		}
	}
}

// readLines decodes a trace's lines as they come, until the stream ends or a line fails
func readLines(response *http.Response, lines chan<- TraceLine) {
	defer close(lines)
	decoder := json.NewDecoder(response.Body)
	for {
		var line TraceLine
		if decoder.Decode(&line) != nil {
			return
		}
		lines <- line
	}
}

// the trace writes the stream.live note, the records in order, a stream.dropped note of both counts refused since the last
// and on the source's end a stream.closed note saying why, after which the stream closes the source's trace once, the source having ended it
func TestTraceStreamsRecordsAndNotes(t *testing.T) {
	src := newTraceSource()
	server := traceServer(t, src, func(d *debugServer) { d.tick = shortBound / 5 })
	lines := make(chan TraceLine, 64)
	go readLines(open(t, server, PathDebugTrace), lines)
	records := src.nextTrace(t)
	next := func() TraceLine {
		t.Helper()
		select {
		case line, ok := <-lines:
			if !ok {
				t.Fatal("the stream ended early")
			}
			return line
		case <-time.After(testWait):
			t.Fatal("no line came")
			return TraceLine{}
		}
	}
	if line := next(); line.Note == nil || line.Note.Kind != "stream.live" {
		t.Fatalf("the trace opened with %+v", line)
	}
	for _, length := range []int{60, 1280} {
		records.records <- TracePacket{Decision: "forward", Length: length}
	}
	for _, length := range []int{60, 1280} {
		if line := next(); line.Packet == nil || line.Packet.Length != length {
			t.Fatalf("the trace carried %+v, want the record of length %d", line, length)
		}
	}
	records.refused.Store(&[2]uint64{3, 5})
	if line := next(); line.Note == nil || line.Note.Kind != "stream.dropped" || line.Note.Attrs["rate"] != "3" || line.Note.Attrs["queue"] != "5" {
		t.Fatalf("a trace that refused 3 for its rate and 5 for its queue noted %+v", line)
	}
	records.refused.Store(&[2]uint64{4, 5})
	if line := next(); line.Note == nil || line.Note.Kind != "stream.dropped" || line.Note.Attrs["rate"] != "1" || line.Note.Attrs["queue"] != "0" {
		t.Fatalf("a trace that refused 1 more for its rate noted %+v", line)
	}
	close(records.done)
	if line := next(); line.Note == nil || line.Note.Kind != "stream.closed" || line.Note.Attrs["reason"] != "the daemon is stopping" {
		t.Fatalf("a trace its source ended closed with %+v", line)
	}
	select {
	case why := <-records.closed:
		if why != "" {
			t.Errorf("the stream closed a trace its source ended saying %q", why)
		}
	case <-time.After(testWait):
		t.Error("the stream left the trace its source ended open")
	}
}

// a trace its source ends with records still queued writes each of them before its stream.closed note, the records it counted recorded
func TestTraceWritesWhatItsQueueHeldAtItsEnd(t *testing.T) {
	src := newTraceSource()
	server := traceServer(t, src, func(*debugServer) {})
	response := open(t, server, PathDebugTrace)
	records := src.nextTrace(t)
	held := cap(records.records)
	for length := range held {
		records.records <- TracePacket{Decision: "forward", Length: length}
	}
	close(records.done)
	lines := make(chan TraceLine, held+8)
	readLines(response, lines)
	written := 0
	for line := range lines {
		switch {
		case line.Packet != nil:
			if line.Packet.Length != written {
				t.Fatalf("record %d of the stream is the record of length %d", written, line.Packet.Length)
			}
			written++
		case line.Note.Kind == "stream.closed":
			if written != held {
				t.Errorf("the stream wrote %d records of the %d queued before it closed", written, held)
			}
			return
		}
	}
	t.Error("the stream ended with no stream.closed note")
}

// a reader that stops reading ends the trace once a write has waited one budget on it, and the source's trace is closed saying so
func TestTraceDropsAReaderThatStopsReading(t *testing.T) {
	src := newTraceSource()
	server := traceServer(t, src, func(d *debugServer) { d.budget, d.heartbeat = shortBound, shortBound })
	open(t, server, PathDebugTrace)
	records := src.nextTrace(t)
	payload := make([]byte, TracePayloadMax)
	for deadline := time.Now().Add(testWait); ; {
		select {
		case why := <-records.closed:
			if why != "the reader stopped reading" {
				t.Errorf("a trace whose reader stopped was closed saying %q", why)
			}
			return
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("the trace kept waiting on a reader that stopped reading")
		}
		select {
		case records.records <- TracePacket{Decision: "forward", Payload: payload}:
		default:
		}
		time.Sleep(testPoll)
	}
}

// the trace streams count against the event streams' places, so a fifth of either kind is refused while four run
func TestFifthStreamIsRefusedAmongTraces(t *testing.T) {
	src := newTraceSource()
	server := traceServer(t, src, func(*debugServer) {})
	for i := range maxStreams {
		if i%2 == 0 {
			open(t, server, PathDebugTrace)
			src.nextTrace(t)
		} else {
			open(t, server, pathProbeStream)
			src.nextFeed(t)
		}
	}
	for _, path := range []string{PathDebugTrace, pathProbeStream} {
		if status, body := get(t, server.Client(), server.URL+path); status != http.StatusServiceUnavailable || !strings.Contains(body, "as many as it holds open") {
			t.Errorf("a fifth stream of %s answered %d %q", path, status, body)
		}
	}
	if len(src.traces) != 0 {
		t.Error("a refused trace opened")
	}
}

// traceLines is one record of each decision over both families, among the notes a trace writes
func traceLines() []TraceLine {
	at := time.Date(2026, 10, 28, 19, 30, 0, 0, time.UTC)
	gateway, relay := "example/gateway:0@1", "example/relay:1@0"
	a4, c4, b4 := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.3"), netip.MustParseAddr("192.0.2.2")
	a6, c6 := netip.MustParseAddr("3fff::1"), netip.MustParseAddr("3fff::3")
	packets := []TracePacket{
		{Arrival: "session", From: gateway, Decision: "forward", Next: relay, Source: a4, Destination: c4, Protocol: 17,
			Transport: true, SourcePort: 40000, DestinationPort: 9000, HopLimit: 64, Length: 48},
		{Arrival: "session", From: gateway, Decision: "forward", Next: relay, Source: a6, Destination: c6, Protocol: 6, Headers: []string{"hop-by-hop"},
			Transport: true, SourcePort: 40000, DestinationPort: 443, TCPFlags: 0x12, HopLimit: 64, Length: 1500, Fragments: 2},
		{Arrival: "session", From: gateway, Decision: "answer", Reason: "expired", Source: a4, Destination: c4, Protocol: 1,
			Transport: true, ICMPType: 8, HopLimit: 1, Length: 84, Answer: "expired", Outcome: "sent"},
		{Arrival: "session", From: gateway, Decision: "answer", Reason: "held", Source: a6, Destination: c6, Protocol: 58,
			Transport: true, ICMPType: 128, HopLimit: 63, Length: 104, Answer: "no_route", Outcome: "withheld"},
		{Arrival: "tun", Decision: "deliver", Source: c6, Destination: a6, Protocol: 17, HopLimit: 64, Length: 1232},
		{Arrival: "session", From: gateway, Decision: "egress", Source: a4, Destination: netip.MustParseAddr("203.0.113.9"), Protocol: 6,
			Transport: true, SourcePort: 40001, DestinationPort: 80, TCPFlags: 0x02, HopLimit: 63, Length: 60, Payload: []byte{0x45, 0x00, 0x00, 0x3c}},
		{Arrival: "tun", Decision: "drop", Reason: "forged", Source: netip.MustParseAddr("198.51.100.7"), Destination: c4, Protocol: 47, HopLimit: 64, Length: 120},
		{Arrival: "session", From: gateway, Decision: "drop", Reason: "budget", Next: relay,
			Source: a6, Destination: c6, Protocol: 17, HopLimit: 63, Length: 1280},
		{Arrival: "none", Decision: "drop", Reason: "martian", Source: netip.MustParseAddr("169.254.0.1"), Destination: b4, Protocol: 17, HopLimit: 64, Length: 28},
	}
	lines := []TraceLine{{Note: &Event{At: at, Kind: "stream.live"}}}
	for i := range packets {
		lines = append(lines, TraceLine{Packet: &packets[i]})
	}
	return append(lines,
		TraceLine{Note: &Event{At: at, Kind: "stream.dropped", Attrs: map[string]string{"rate": "12", "queue": "0"}}},
		TraceLine{Note: &Event{At: at, Kind: "stream.closed", Attrs: map[string]string{"reason": "the daemon is stopping"}}},
	)
}

// a trace prints one line a record or note, and its wire form one JSON line each that reads back as it was
func TestTraceGoldens(t *testing.T) {
	var text, wire bytes.Buffer
	encoder := json.NewEncoder(&wire)
	for _, line := range traceLines() {
		RenderTraceLine(&text, line)
		if err := encoder.Encode(line); err != nil {
			t.Fatal(err)
		}
	}
	golden(t, "trace.txt", text.Bytes())
	golden(t, "trace.ndjson", wire.Bytes())
	decoder := json.NewDecoder(&wire)
	for i, want := range traceLines() {
		var got TraceLine
		if err := decoder.Decode(&got); err != nil {
			t.Fatal(err)
		}
		var sent, read bytes.Buffer
		RenderTraceLine(&sent, want)
		RenderTraceLine(&read, got)
		if sent.String() != read.String() {
			t.Errorf("line %d reads back as %q, sent as %q", i, read.String(), sent.String())
		}
	}
}
