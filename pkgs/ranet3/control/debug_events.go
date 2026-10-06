// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"maps"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"
)

// PathDebugEvents is the event recorder, and with follow the events after it
const PathDebugEvents = PathDebug + "events"

func init() { registerDebug(PathDebugEvents, classRead, reflect.TypeFor[Event](), serveEvents) }

// EventSource is a Source that records events
type EventSource interface {
	// DebugEvents is the recorded events query selects, oldest first
	DebugEvents(query EventQuery) []Event
	// DebugFollow is DebugEvents and a subscription to every later event query selects
	DebugFollow(query EventQuery) ([]Event, Subscription)
}

// EventQuery selects events by kind, peer, attribute and age
type EventQuery struct {
	// Kinds keeps an event of one of them or under one, so babel keeps babel.neighbor.up
	// none keeps every kind
	Kinds []string
	// Peer keeps an event about one peer, named by its path, org/name or name
	Peer string
	// Attrs keeps an event carrying every attribute named, each rendering as the text given
	Attrs map[string]string
	// Since keeps the recorded events that recent, zero keeping every one
	Since time.Duration
	// Follow keeps the answer open for the events after the recorded ones
	Follow bool
}

func (q EventQuery) values() url.Values {
	values := url.Values{"kind": q.Kinds}
	if q.Peer != "" {
		values.Set("peer", q.Peer)
	}
	for _, key := range slices.Sorted(maps.Keys(q.Attrs)) {
		values.Add("attr", key+"="+q.Attrs[key])
	}
	if q.Since != 0 {
		values.Set("since", q.Since.String())
	}
	if q.Follow {
		values.Set("follow", "1")
	}
	return values
}

func parseEventQuery(values url.Values) (EventQuery, error) {
	query := EventQuery{Kinds: values["kind"], Peer: values.Get("peer")}
	if len(query.Kinds) > maxEventKinds {
		return EventQuery{}, fmt.Errorf("a query names %d kinds at most, and this one names %d", maxEventKinds, len(query.Kinds))
	}
	if attrs := values["attr"]; len(attrs) > 0 {
		if len(attrs) > maxEventAttrs {
			return EventQuery{}, fmt.Errorf("a query names %d attributes at most, and this one names %d", maxEventAttrs, len(attrs))
		}
		query.Attrs = make(map[string]string, len(attrs))
		for _, attr := range attrs {
			key, value, ok := strings.Cut(attr, "=")
			if !ok {
				return EventQuery{}, fmt.Errorf("attr takes key=value, not %q", attr)
			}
			query.Attrs[key] = value
		}
	}
	if since := values.Get("since"); since != "" {
		window, err := time.ParseDuration(since)
		if err != nil || window < 0 {
			return EventQuery{}, fmt.Errorf("since takes a duration such as 5m, not %q", since)
		}
		query.Since = window
	}
	if follow := values.Get("follow"); follow != "" {
		on, err := strconv.ParseBool(follow)
		if err != nil {
			return EventQuery{}, fmt.Errorf("follow takes 1 or 0, not %q", follow)
		}
		query.Follow = on
	}
	return query, nil
}

func serveEvents(d *debugServer, w http.ResponseWriter, r *http.Request) {
	if !reading(w, r) {
		return
	}
	source, ok := implements[EventSource](d, w, "events")
	if !ok {
		return
	}
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		http.Error(w, "the query does not parse: "+err.Error(), http.StatusBadRequest)
		return
	}
	query, err := parseEventQuery(values)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if query.Follow && r.Method == http.MethodGet {
		d.stream(w, r, func() ([]Event, Subscription) { return source.DebugFollow(query) })
		return
	}
	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	for _, event := range source.DebugEvents(query) {
		if err := encoder.Encode(event); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Write(body.Bytes())
}

// Events reads the recorded events query selects, and with Follow the events after them
// it ends with ctx or with the daemon closing the stream, whose stream.closed note it passes on
// it passes on the stream.live note that parts the recorded events from the later ones, and no heartbeat
func (c *Client) Events(ctx context.Context, query EventQuery) iter.Seq2[Event, error] {
	return func(yield func(Event, error) bool) {
		for line, err := range c.Stream(ctx, PathDebugEvents, query.values()) {
			if err != nil {
				yield(Event{}, err)
				return
			}
			var event Event
			if err := json.Unmarshal(line, &event); err != nil {
				yield(Event{}, fmt.Errorf("control: decoding %s: %w", PathDebugEvents, err))
				return
			}
			if event.Kind != "stream.heartbeat" && !yield(event, nil) {
				return
			}
		}
	}
}

// Waited is the event debug wait took and how long after the wait began it happened, negative for one recorded before
type Waited struct {
	Event Event    `json:"event"`
	After Duration `json:"after"`
}

// RenderWaited writes the event's line and then how long after the wait began it happened
func RenderWaited(w io.Writer, waited Waited) {
	RenderEvent(w, waited.Event)
	if after := time.Duration(waited.After); after < 0 {
		fmt.Fprintf(w, "%s before the wait began\n", Spelled(-after))
	} else {
		fmt.Fprintf(w, "After %s\n", Spelled(after))
	}
}

// RenderEvent writes one event as one line
// the time is the daemon's in UTC to the millisecond, then how long after its start, then the attributes by name
// a value is quoted where it is empty or would not read back as one word
func RenderEvent(w io.Writer, event Event) {
	line := []string{event.At.UTC().Format("2006-01-02T15:04:05.000Z07:00")}
	if event.Seq != 0 {
		line = append(line, "+"+shortDuration(time.Duration(event.Mono)), "#"+strconv.FormatUint(event.Seq, 10))
	}
	line = append(line, event.Kind)
	if event.Peer != "" {
		line = append(line, event.Peer)
	}
	for _, key := range slices.Sorted(maps.Keys(event.Attrs)) {
		value := event.Attrs[key]
		if quoted := strconv.Quote(value); value == "" || strings.ContainsAny(value, " =") || quoted != `"`+value+`"` {
			value = quoted
		}
		line = append(line, key+"="+value)
	}
	fmt.Fprintln(w, strings.Join(line, " "))
}
