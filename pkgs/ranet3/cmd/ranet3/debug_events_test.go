// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/control"
)

// followLong outlasts the stub's session coming up
// waitLong is a wait nothing here comes near the end of
// waitShort ends before anything it asks for comes
// pastLong reaches back past the stub's dial
// clockStep is how far back a test stamps an event, as a clock stepped back during a wait stamps it
const (
	followLong = 10 * sessionAfter
	waitLong   = 100 * sessionAfter
	waitShort  = 3 * sessionAfter
	pastLong   = 5 * dialAge
	clockStep  = 2 * dialAge
)

// debug events prints the recorder and exits, and with -f the events after it until --for has passed
func TestDebugEventsPrintsTheRecorderAndFollows(t *testing.T) {
	socket := serveStub(t)
	out, err := execute(t, "debug", "events", "--control", socket)
	if err != nil || !strings.Contains(out, "dial.attempt example/gateway/0@0") || strings.Contains(out, "ike.session") {
		t.Errorf("debug events printed %q, %v", out, err)
	}
	out, err = execute(t, "debug", "events", "-f", "--for", followLong.String(), "--json", "--control", socket)
	if err != nil {
		t.Fatalf("debug events -f ended with %v", err)
	}
	var kinds []string
	for line := range strings.Lines(out) {
		var event control.Event
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("debug events --json printed %q: %v", line, err)
		}
		kinds = append(kinds, event.Kind)
	}
	if strings.Join(kinds, " ") != "dial.attempt stream.live ike.session.established" {
		t.Errorf("debug events -f printed %q", kinds)
	}
	if _, err := execute(t, "debug", "events", "-f", "--for", "0s", "--control", socket); err == nil || !strings.Contains(err.Error(), "--for") {
		t.Errorf("debug events -f --for 0s ended with %v", err)
	}
}

// debug wait exits 0 printing the event and how long it took, and 1 saying so when none comes in time
func TestDebugWaitEndsWithTheEventOrTheTimeout(t *testing.T) {
	socket := serveStub(t)
	out, err := execute(t, "debug", "wait", "ike.session.established", "--attr", "role=initiator", "--timeout", waitLong.String(), "--control", socket)
	if err != nil || !strings.Contains(out, "ike.session.established example/gateway/0@0") || !strings.Contains(out, "after ") {
		t.Errorf("a wait for an event that came printed %q and ended with %v", out, err)
	}
	// the recorder's dial is older than the wait, so only --past reaches it
	out, err = execute(t, "debug", "wait", "dial.attempt", "--past", pastLong.String(), "--timeout", waitLong.String(), "--control", socket)
	if err != nil || !strings.Contains(out, "before the wait began") {
		t.Errorf("a wait reaching back for a recorded event printed %q and ended with %v", out, err)
	}
	for _, args := range [][]string{
		{"debug", "wait", "babel.neighbor.down", "--timeout", waitShort.String(), "--control", socket},
		{"debug", "wait", "dial.attempt", "--timeout", waitShort.String(), "--control", socket},
		{"debug", "wait", "ike.session.established", "--attr", "role=responder", "--timeout", waitShort.String(), "--control", socket},
	} {
		if out, err := execute(t, args...); !errors.Is(err, waitTimedOut) || !strings.Contains(out, "arrived within 300 milliseconds") {
			t.Errorf("%q printed %q and ended with %v, want the timeout", args, out, err)
		}
	}
}

// droppingSource is the stub whose follow lost events the wait takes before the first one it carries
type droppingSource struct{ stubSource }

func (droppingSource) DebugFollow(control.EventQuery) ([]control.Event, control.Subscription) {
	live := make(chan control.Delivery, 1)
	live <- control.Delivery{Event: control.Event{Seq: 9, At: time.Now(), Kind: "ike.session.established", Peer: "example/gateway/0@0"}, Dropped: 3}
	return nil, scripted{live}
}

// closingSource is the stub whose feed ends at once, as a daemon stopping ends it
type closingSource struct{ stubSource }

func (closingSource) DebugFollow(control.EventQuery) ([]control.Event, control.Subscription) {
	feed := make(chan control.Delivery)
	close(feed)
	return nil, stopping{scripted{feed}}
}

// stopping is a feed that ended because its daemon is stopping
type stopping struct{ scripted }

func (stopping) Reason() string { return "the daemon is stopping" }

// serveCutStream answers every request with a stream that ends after its stream.live line, with no word of why
func serveCutStream(t *testing.T) string {
	t.Helper()
	path := socketPath(t)
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, `{"kind":"stream.live"}`)
	})}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })
	return path
}

// a wait that could not watch for its event, or lost it, exits 2 saying why, apart from a wait whose event did not come
// a command line it cannot use is refused before the wait dials a stub whose session would answer it
func TestDebugWaitTellsAFailureToWatchFromATimeout(t *testing.T) {
	socket, dropping, closing, cut := serveStub(t), serve(t, droppingSource{}), serve(t, closingSource{}), serveCutStream(t)
	gone := filepath.Join(filepath.Dir(socketPath(t)), "gone.sock")
	for name, test := range map[string]struct {
		args []string
		want string
	}{
		"no daemon":                         {[]string{"dial.attempt", "--control", gone}, "daemon"},
		"events lost before it read":        {[]string{"ike.session.established", "--control", dropping}, "dropped"},
		"the daemon ending the stream":      {[]string{"ike.session.established", "--control", closing}, "the daemon is stopping"},
		"a stream ending without a word":    {[]string{"ike.session.established", "--control", cut}, "the stream ended"},
		"an attribute that is no key=value": {[]string{"ike.session.established", "--attr", "role", "--control", socket}, "key=value"},
		"a past below zero":                 {[]string{"ike.session.established", "--past", "-1s", "--control", socket}, "--past"},
	} {
		args := append([]string{"debug", "wait"}, append(test.args, "--timeout", waitLong.String())...)
		if out, err := execute(t, args...); !errors.Is(err, waitUnwatched) || !strings.Contains(out, test.want) {
			t.Errorf("%s: %q printed %q and ended with %v", name, args, out, err)
		}
	}
	args := []string{"debug", "wait", "ike.session.established", "--timeout", "0s", "--control", socket}
	if out, err := execute(t, args...); !errors.Is(err, waitUnwatched) || !strings.Contains(out, "--timeout") {
		t.Errorf("%q printed %q and ended with %v", args, out, err)
	}
}

// steppedSource is the stub whose session comes after the wait subscribed, stamped clockStep before the wait began
type steppedSource struct{ stubSource }

func (steppedSource) DebugFollow(control.EventQuery) ([]control.Event, control.Subscription) {
	live := make(chan control.Delivery, 1)
	live <- control.Delivery{Event: control.Event{Seq: 9, At: time.Now().Add(-clockStep), Kind: "ike.session.established", Peer: "example/gateway/0@0"}}
	return nil, scripted{live}
}

// an event that came after the wait subscribed is taken whatever its stamp, and never reads as before the wait began
func TestDebugWaitTakesALiveEventWhateverItsStamp(t *testing.T) {
	out, err := execute(t, "debug", "wait", "ike.session.established", "--timeout", waitLong.String(), "--control", serve(t, steppedSource{}))
	if err != nil || !strings.Contains(out, "ike.session.established example/gateway/0@0") || !strings.Contains(out, "after 0 milliseconds") {
		t.Errorf("a wait for an event stamped before it began printed %q and ended with %v", out, err)
	}
}

// askedSource is the stub that keeps every events query it was asked
type askedSource struct {
	stubSource
	mu    sync.Mutex
	asked []control.EventQuery
}

func (s *askedSource) note(query control.EventQuery) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.asked = append(s.asked, query)
}

func (s *askedSource) DebugEvents(query control.EventQuery) []control.Event {
	s.note(query)
	return s.stubSource.DebugEvents(query)
}

func (s *askedSource) DebugFollow(query control.EventQuery) ([]control.Event, control.Subscription) {
	s.note(query)
	return s.stubSource.DebugFollow(query)
}

// the selection flags of events and wait reach the daemon as the query they spell
// and wait answers --json with the wire form of its answer
func TestDebugSelectionReachesTheDaemon(t *testing.T) {
	src := &askedSource{}
	socket := serve(t, src)

	if _, err := execute(t, "debug", "events", "--kind", "dial", "--kind", "ike.session", "--peer", "gateway", "--since", "5m", "--control", socket); err != nil {
		t.Fatal(err)
	}
	out, err := execute(t, "debug", "wait", "ike.session.established", "--peer", "gateway", "--attr", "role=initiator", "--json", "--timeout", waitLong.String(), "--control", socket)
	if err != nil {
		t.Fatal(err)
	}
	var answer control.Waited
	if err := json.Unmarshal([]byte(out), &answer); err != nil || answer.Event.Kind != "ike.session.established" {
		t.Errorf("debug wait --json printed %q, %v", out, err)
	}
	src.mu.Lock()
	defer src.mu.Unlock()
	want := []control.EventQuery{
		{Kinds: []string{"dial", "ike.session"}, Peer: "gateway", Since: 5 * time.Minute},
		{Kinds: []string{"ike.session.established"}, Peer: "gateway", Attrs: map[string]string{"role": "initiator"}, Follow: true},
	}
	if !reflect.DeepEqual(src.asked, want) {
		t.Errorf("the daemon was asked %+v, want %+v", src.asked, want)
	}
}
