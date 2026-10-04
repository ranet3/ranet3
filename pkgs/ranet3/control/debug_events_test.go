// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// eventFixture is a dial, its session, a kernel pass and the notes a stream writes about itself
// the pass is stamped two hours east of UTC, which the wire form keeps and the text renders in UTC
func eventFixture() []Event {
	at := time.Date(2026, 10, 4, 12, 20, 1, 123456789, time.UTC)
	return []Event{
		{Seq: 41, At: at, Mono: Duration(62345 * time.Millisecond), Kind: "dial.attempt", Peer: "example/gateway/0@0",
			Attrs: map[string]string{"remote": "192.0.2.7:13000"}},
		{Seq: 42, At: at.Add(38 * time.Millisecond), Mono: Duration(62383 * time.Millisecond), Kind: "ike.session.established",
			Peer: "example/gateway/0@0", Attrs: map[string]string{"role": "initiator", "spi_in": "c0ffee01", "spi_out": "0badf00d"}},
		{Seq: 43, At: at.Add(time.Second).In(time.FixedZone("", 2*60*60)), Mono: Duration(63345 * time.Millisecond), Kind: "kernel.pass",
			Attrs: map[string]string{"trigger": "mesh", "took": "1.2ms", "err": "list routes: netlink is busy", "empty": ""}},
		{At: at.Add(1500 * time.Millisecond), Kind: "stream.live"},
		{At: at.Add(2 * time.Second), Kind: "stream.dropped", Attrs: map[string]string{"count": "12"}},
		{At: at.Add(3 * time.Second), Kind: "stream.closed", Attrs: map[string]string{"reason": "the daemon is stopping"}},
	}
}

func TestEventsRenderAsTheGoldenFiles(t *testing.T) {
	var text, wire bytes.Buffer
	encoder := json.NewEncoder(&wire)
	for _, event := range eventFixture() {
		RenderEvent(&text, event)
		if err := encoder.Encode(event); err != nil {
			t.Fatal(err)
		}
	}
	golden(t, "events.txt", text.Bytes())
	golden(t, "events.ndjson", wire.Bytes())
}

// eventSource records the query it was asked and answers from the fixture, with a feed to follow
type eventSource struct {
	fakeSource
	mu    sync.Mutex
	query EventQuery
	feed  *feed
}

func (s *eventSource) DebugEvents(query EventQuery) []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.query = query
	return eventFixture()[:3]
}

func (s *eventSource) DebugFollow(query EventQuery) ([]Event, Subscription) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.query = query
	return eventFixture()[:1], s.feed
}

func (s *eventSource) asked() EventQuery {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.query
}

// the recorder answers whole as one line per event, and the query reaches the source as asked
func TestEventsAnswerTheRecorder(t *testing.T) {
	src := &eventSource{}
	server := httptest.NewServer(Handler(src))
	defer server.Close()
	status, body := get(t, server.Client(), server.URL+PathDebugEvents+"?kind=dial&kind=ike.session&peer=gateway&attr=role%3Dinitiator&since=5m")
	if status != http.StatusOK || strings.Count(body, "\n") != 3 {
		t.Fatalf("the recorder answered %d %q", status, body)
	}
	want := EventQuery{Kinds: []string{"dial", "ike.session"}, Peer: "gateway", Attrs: map[string]string{"role": "initiator"}, Since: 5 * time.Minute}
	if !reflect.DeepEqual(src.asked(), want) {
		t.Errorf("the source was asked %+v, want %+v", src.asked(), want)
	}
	// a window that does not parse or runs backward, and a follow that is no boolean, are refused by name
	for _, query := range []string{"since=yesterday", "since=-5m", "follow=maybe"} {
		name, _, _ := strings.Cut(query, "=")
		if status, body := get(t, server.Client(), server.URL+PathDebugEvents+"?"+query); status != http.StatusBadRequest || !strings.Contains(body, name) {
			t.Errorf("%s answered %d %q", query, status, body)
		}
	}
	if refused := post(t, server.URL+PathDebugEvents, ""); refused.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("a POST to the recorder was answered %s", refused.Status)
	}
	// as many kinds as a query may name are read, one more is refused, and so is a query that does not parse
	kinds := strings.TrimPrefix(strings.Repeat("&kind=dial", maxEventKinds), "&")
	if status, body := get(t, server.Client(), server.URL+PathDebugEvents+"?"+kinds); status != http.StatusOK {
		t.Errorf("a query naming %d kinds answered %d %q", maxEventKinds, status, body)
	}
	if status, body := get(t, server.Client(), server.URL+PathDebugEvents+"?follow=1&kind=dial&"+kinds); status != http.StatusBadRequest || !strings.Contains(body, "kinds at most") {
		t.Errorf("a query naming %d kinds answered %d %q", maxEventKinds+1, status, body)
	}
	if status, body := get(t, server.Client(), server.URL+PathDebugEvents+"?kind=babel%zz&follow=1"); status != http.StatusBadRequest || !strings.Contains(body, "does not parse") {
		t.Errorf("a query that does not parse answered %d %q", status, body)
	}
	// as many attributes as a query may name are read, one more is refused, and so is one that is no key=value
	attrs := strings.TrimPrefix(strings.Repeat("&attr=role%3Dinitiator", maxEventAttrs), "&")
	if status, body := get(t, server.Client(), server.URL+PathDebugEvents+"?"+attrs); status != http.StatusOK {
		t.Errorf("a query naming %d attributes answered %d %q", maxEventAttrs, status, body)
	}
	if status, body := get(t, server.Client(), server.URL+PathDebugEvents+"?follow=1&attr=role%3Dinitiator&"+attrs); status != http.StatusBadRequest || !strings.Contains(body, "attributes at most") {
		t.Errorf("a query naming %d attributes answered %d %q", maxEventAttrs+1, status, body)
	}
	if status, body := get(t, server.Client(), server.URL+PathDebugEvents+"?attr=role"); status != http.StatusBadRequest || !strings.Contains(body, "key=value") {
		t.Errorf("an attribute without a value answered %d %q", status, body)
	}
}

// a wait's answer, for an event after the wait began and for one recorded before it
// and after a second, two minutes and an hour, where a unit is spelled in the singular, in minutes and in hours
// and after spans that are no whole number of milliseconds, which are spelled rounded to the millisecond
func TestWaitedRendersAsTheGoldenFiles(t *testing.T) {
	answers := []Waited{
		{Event: eventFixture()[1], After: Duration(38 * time.Millisecond)},
		{Event: eventFixture()[0], After: Duration(-1200 * time.Millisecond)},
		{Event: eventFixture()[2], After: Duration(time.Second)},
		{Event: eventFixture()[2], After: Duration(2 * time.Minute)},
		{Event: eventFixture()[2], After: Duration(time.Hour)},
		{Event: eventFixture()[2], After: Duration(38600 * time.Microsecond)},
		{Event: eventFixture()[2], After: Duration(1234567891)},
	}
	var text bytes.Buffer
	for _, answer := range answers {
		RenderWaited(&text, answer)
	}
	golden(t, "wait.txt", text.Bytes())
	goldenJSON(t, "wait.json", answers[0])
}

// following streams the recorder and then the events after it, which the client reads back as events
// the client passes on none of the heartbeats written between them
func TestEventsFollowTheRecorder(t *testing.T) {
	src := &eventSource{feed: newFeed(16)}
	d := newDebugServer(src)
	d.heartbeat = shortBound / 10
	client := serveStream(t, src, func(server *http.Server) { server.Handler = d })
	ctx, cancel := context.WithTimeout(context.Background(), testWait)
	defer cancel()
	go func() {
		time.Sleep(shortBound)
		src.feed.emit(eventFixture()[1])
		src.feed.end("the daemon is stopping")
	}()
	var kinds []string
	for event, err := range client.Events(ctx, EventQuery{Kinds: []string{"dial"}, Follow: true}) {
		if err != nil {
			t.Fatal(err)
		}
		kinds = append(kinds, event.Kind)
	}
	if want := []string{"dial.attempt", "stream.live", "ike.session.established", "stream.closed"}; !slices.Equal(kinds, want) {
		t.Errorf("following read %q, want %q", kinds, want)
	}
	if !src.asked().Follow || !slices.Equal(src.asked().Kinds, []string{"dial"}) {
		t.Errorf("the source was asked %+v", src.asked())
	}
}

// a source without events is told so by name
func TestEventsNameASourceWithoutThem(t *testing.T) {
	server := httptest.NewServer(Handler(fakeSource{}))
	defer server.Close()
	if status, body := get(t, server.Client(), server.URL+PathDebugEvents); status != http.StatusNotImplemented || !strings.Contains(body, "events view") {
		t.Errorf("a source without events answered %d %q", status, body)
	}
}
