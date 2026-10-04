// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"log/slog"
	"strconv"
	"time"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/internal/events"
)

// DebugEvents is the recorder's events query selects
func (c *Client) DebugEvents(query control.EventQuery) []control.Event {
	return c.events.Recorded(selects(query), query.Since)
}

// DebugFollow is DebugEvents and a subscription to the events after them
func (c *Client) DebugFollow(query control.EventQuery) ([]control.Event, control.Subscription) {
	return c.events.Subscribe(selects(query), query.Since)
}

// selects is the query as a match the bus applies to every event under its lock, before the event reaches a subscriber's queue
// a follow's queue holds only what its query takes, so a burst of events the query leaves out cannot crowd out one it takes
// the kinds become a set here, once, so a match looks up the event's kind and each part of it ending at a dot, whatever the query names
// each attribute's text is parsed here too, so a match compares values without rendering them
// the bus keeps a float or a time as the text it renders, which the text itself matches
// the attributes are tested before the kind, and the test stops at the first one named that the event lacks
// a peer is named the way redial names one
func selects(query control.EventQuery) events.Match {
	kinds := make(map[string]bool, len(query.Kinds))
	for _, kind := range query.Kinds {
		kinds[kind] = true
	}
	wanted := make([]attribute, 0, len(query.Attrs))
	for key, text := range query.Attrs {
		wanted = append(wanted, attribute{key: key, values: spellings(text)})
	}
	return func(kind, peer string, attrs []slog.Attr) bool {
		if query.Peer != "" && !matchesPeer(peer, query.Peer) {
			return false
		}
		for _, want := range wanted {
			if !want.heldBy(attrs) {
				return false
			}
		}
		if len(kinds) == 0 || kinds[kind] {
			return true
		}
		for at := range len(kind) {
			if kind[at] == '.' && kinds[kind[:at]] {
				return true
			}
		}
		return false
	}
}

// attribute is one a query names, with every value that renders as its text
type attribute struct {
	key    string
	values []slog.Value
}

// heldBy reports whether attrs carry the attribute, the last of its key being the one an event renders
func (a attribute) heldBy(attrs []slog.Attr) bool {
	for i := len(attrs) - 1; i >= 0; i-- {
		if attrs[i].Key != a.key {
			continue
		}
		for _, spelled := range a.values {
			if attrs[i].Value.Equal(spelled) {
				return true
			}
		}
		return false
	}
	return false
}

// spellings is every value that renders as text, of each kind an attribute holds once the bus recorded it
func spellings(text string) []slog.Value {
	values := []slog.Value{slog.StringValue(text)}
	if n, err := strconv.ParseInt(text, 10, 64); err == nil && strconv.FormatInt(n, 10) == text {
		values = append(values, slog.Int64Value(n))
	}
	if n, err := strconv.ParseUint(text, 10, 64); err == nil && strconv.FormatUint(n, 10) == text {
		values = append(values, slog.Uint64Value(n))
	}
	if b, err := strconv.ParseBool(text); err == nil && strconv.FormatBool(b) == text {
		values = append(values, slog.BoolValue(b))
	}
	if d, err := time.ParseDuration(text); err == nil && d.String() == text {
		values = append(values, slog.DurationValue(d))
	}
	return values
}
