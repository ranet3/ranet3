// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"slices"
	"strings"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/ike"
	"ranet3.com/pkgs/ranet3/internal/events"
)

// windowGap is how far apart a test emits two events so that a window takes the later alone
const windowGap = 200 * time.Millisecond

// a query keeps the kinds it names and every kind under them, a peer named the way redial names one, and an event carrying every attribute it names as the event renders it, the last of a key being the one rendered
func TestQuerySelectsKindsPeersAndAttributes(t *testing.T) {
	stamp := time.Date(2026, 10, 6, 4, 0, 0, 500, time.FixedZone("CEST", 2*60*60))
	bus := events.New()
	bus.Emit("babel.neighbor.up", "example/gateway/1@0", slog.String("route", "fd00:9::/64"), slog.String("route", "fd00:1::/64"), slog.Int("metric", 96),
		slog.Bool("all", false), slog.Duration("took", 1200*time.Microsecond), slog.Float64("loss", 0.5),
		slog.Any("uid", uint32(1000)), slog.Time("at", stamp), slog.Time("unnamed", stamp.In(time.FixedZone("", 5*60*60+30*60))),
		slog.Float64("lost", math.NaN()), slog.Float64("zero", math.Copysign(0, -1)))
	for name, test := range map[string]struct {
		query control.EventQuery
		want  bool
	}{
		"every event":                           {control.EventQuery{}, true},
		"the subsystem":                         {control.EventQuery{Kinds: []string{"babel"}}, true},
		"the thing":                             {control.EventQuery{Kinds: []string{"babel.neighbor"}}, true},
		"the kind":                              {control.EventQuery{Kinds: []string{"babel.neighbor.up"}}, true},
		"a kind under this one":                 {control.EventQuery{Kinds: []string{"babel.neighbor.up.again"}}, false},
		"part of a word":                        {control.EventQuery{Kinds: []string{"babel.neigh"}}, false},
		"one kind of several":                   {control.EventQuery{Kinds: []string{"kernel", "babel.neighbor"}}, true},
		"the peer by name":                      {control.EventQuery{Peer: "gateway"}, true},
		"the peer by org and name":              {control.EventQuery{Peer: "example/gateway"}, true},
		"another peer":                          {control.EventQuery{Peer: "relay"}, false},
		"the kind with another peer":            {control.EventQuery{Kinds: []string{"babel"}, Peer: "relay"}, false},
		"a string":                              {control.EventQuery{Attrs: map[string]string{"route": "fd00:1::/64"}}, true},
		"another string":                        {control.EventQuery{Attrs: map[string]string{"route": "fd00:2::/64"}}, false},
		"the first of a key carried twice":      {control.EventQuery{Attrs: map[string]string{"route": "fd00:9::/64"}}, false},
		"an integer":                            {control.EventQuery{Attrs: map[string]string{"metric": "96"}}, true},
		"an integer spelled otherwise":          {control.EventQuery{Attrs: map[string]string{"metric": "096"}}, false},
		"a boolean":                             {control.EventQuery{Attrs: map[string]string{"all": "false"}}, true},
		"a boolean spelled otherwise":           {control.EventQuery{Attrs: map[string]string{"all": "0"}}, false},
		"a duration":                            {control.EventQuery{Attrs: map[string]string{"took": "1.2ms"}}, true},
		"a duration spelled otherwise":          {control.EventQuery{Attrs: map[string]string{"took": "1200us"}}, false},
		"a float":                               {control.EventQuery{Attrs: map[string]string{"loss": "0.5"}}, true},
		"a float spelled otherwise":             {control.EventQuery{Attrs: map[string]string{"loss": ".5"}}, false},
		"a float that is no number":             {control.EventQuery{Attrs: map[string]string{"lost": "NaN"}}, true},
		"a negative zero":                       {control.EventQuery{Attrs: map[string]string{"zero": "-0"}}, true},
		"a negative zero read as zero":          {control.EventQuery{Attrs: map[string]string{"zero": "0"}}, false},
		"an unsigned integer":                   {control.EventQuery{Attrs: map[string]string{"uid": "1000"}}, true},
		"an unsigned integer spelled otherwise": {control.EventQuery{Attrs: map[string]string{"uid": "01000"}}, false},
		"a time":                                {control.EventQuery{Attrs: map[string]string{"at": stamp.String()}}, true},
		"the same instant in another zone":      {control.EventQuery{Attrs: map[string]string{"at": stamp.UTC().String()}}, false},
		"a time in a zone without a name":       {control.EventQuery{Attrs: map[string]string{"unnamed": stamp.In(time.FixedZone("", 5*60*60+30*60)).String()}}, true},
		"an attribute it does not carry":        {control.EventQuery{Attrs: map[string]string{"err": ""}}, false},
		"every attribute named":                 {control.EventQuery{Attrs: map[string]string{"route": "fd00:1::/64", "metric": "96"}}, true},
		"one attribute of two":                  {control.EventQuery{Attrs: map[string]string{"route": "fd00:1::/64", "metric": "97"}}, false},
		"another kind with the attribute":       {control.EventQuery{Kinds: []string{"kernel"}, Attrs: map[string]string{"metric": "96"}}, false},
	} {
		if got := len(bus.Recorded(selects(test.query), 0)) == 1; got != test.want {
			t.Errorf("%s: %+v took the event as %v, want %v", name, test.query, got, test.want)
		}
	}
}

func kindsOf(recorded []control.Event) []string {
	var kinds []string
	for _, event := range recorded {
		kinds = append(kinds, event.Kind)
	}
	return kinds
}

// the daemon applies a query to the recorder and to every event after it, so the view answers with what was asked alone
func TestEventsViewKeepsToItsQuery(t *testing.T) {
	c := &Client{events: events.New()}
	c.events.Emit("babel.route.selected", "example/relay/0@0")
	c.events.Emit("dial.attempt", "example/gateway/0@0")
	dials := control.EventQuery{Kinds: []string{"dial"}}
	if got := kindsOf(c.DebugEvents(dials)); !slices.Equal(got, []string{"dial.attempt"}) {
		t.Errorf("the recorder answered a query for dials with %q", got)
	}
	if got := kindsOf(c.DebugEvents(control.EventQuery{Peer: "relay"})); !slices.Equal(got, []string{"babel.route.selected"}) {
		t.Errorf("the recorder answered a query for one peer with %q", got)
	}
	backlog, sub := c.DebugFollow(dials)
	defer sub.Close()
	if got := kindsOf(backlog); !slices.Equal(got, []string{"dial.attempt"}) {
		t.Errorf("a follow of dials began with %q", got)
	}
	c.events.Emit("babel.route.selected", "example/relay/0@0")
	c.events.Emit("dial.failed", "example/gateway/0@0")
	select {
	case delivery := <-sub.C():
		if delivery.Event.Kind != "dial.failed" {
			t.Errorf("a follow of dials carried %s first", delivery.Event.Kind)
		}
	case <-time.After(convergeBudget):
		t.Error("a follow of dials carried nothing")
	}
}

// a verb is taken by every name of a peer it acted on, however the verb named the peer, and by no other name
// it is recorded once under the path of each session or dialer it acted on and nowhere else
// it carries the name it was given as its attribute peer, and no such attribute when it was given none
func TestVerbIsTakenByEveryNameOfWhatItActedOn(t *testing.T) {
	names := []string{"gateway", "example/gateway", "example/gateway/1@0", "other/gateway"}
	type ask struct {
		verb, peer string
		all        bool
	}
	asks := []ask{{verb: "rekey", all: true}, {verb: "redial", all: true}}
	for _, name := range names {
		asks = append(asks, ask{verb: "redial", peer: name}, ask{verb: "rekey", peer: name})
	}
	for _, ask := range asks {
		c := writable(t)
		c.events = events.New()
		c.sessions.close = func(*ike.Session) {}
		c.sessions.active = func(*ike.Session) bool { return true }
		c.sessions.rekey = func(*ike.Session) error { return nil }
		for _, path := range []string{"example/gateway/1@0", "example/gateway/2@0", "other/gateway/1@0"} {
			c.sessions.adoptPreferred(path, &ike.Session{}, true, nil)
			c.dialers[path] = &dialer{cancel: func() {}, wake: make(chan struct{}, 1)}
		}
		var result control.Result
		var err error
		if ask.verb == "redial" {
			result, err = c.Redial(context.Background(), ask.peer, ask.all)
		} else {
			result, err = c.Rekey(context.Background(), ask.peer, ask.all)
		}
		if err != nil {
			t.Fatalf("%+v: %v", ask, err)
		}
		verbs := recorded(c.events, "control.verb")
		if len(verbs) != len(result.Acted) {
			t.Errorf("%+v acted on %v and was recorded %d times", ask, result.Acted, len(verbs))
		}
		for _, event := range verbs {
			if peer, named := event.Attrs["peer"]; peer != ask.peer || named != (ask.peer != "") {
				t.Errorf("%+v was recorded as %+v", ask, event)
			}
		}
		for _, name := range names {
			want := 0
			for _, path := range result.Acted {
				if matchesPeer(path, name) {
					want++
				}
			}
			if taken := c.DebugEvents(control.EventQuery{Kinds: []string{"control.verb"}, Peer: name}); len(taken) != want {
				t.Errorf("%+v acted on %v, and --peer %s took %d of its events, want %d", ask, result.Acted, name, len(taken), want)
			}
		}
	}
}

// a window keeps the recorded events that recent, in the recorder and at the start of a follow
func TestEventsViewKeepsToItsWindow(t *testing.T) {
	c := &Client{events: events.New()}
	c.events.Emit("dial.attempt", "example/gateway/0@0")
	time.Sleep(2 * windowGap)
	c.events.Emit("dial.failed", "example/gateway/0@0")
	recent := control.EventQuery{Since: windowGap}
	if got := kindsOf(c.DebugEvents(recent)); !slices.Equal(got, []string{"dial.failed"}) {
		t.Errorf("the recorder answered a window with %q", got)
	}
	backlog, sub := c.DebugFollow(recent)
	sub.Close()
	if got := kindsOf(backlog); !slices.Equal(got, []string{"dial.failed"}) {
		t.Errorf("a follow with a window began with %q", got)
	}
}

// a follow's match costs an emit no allocation, whatever kinds, peer and attributes its query names
// two follows name sixteen kinds and two name a peer
// four name an attribute the emit carries, a string, an integer, a float and a time, each with another value
// the emit matches none of them
// it allocates as often under the eight follows as with none, keeping its float and its time as their text either way
// the kind emitted is longer than each kind named, which is longer than 32 bytes
// a match that joined a kind named and a dot to compare with the start of a longer kind would allocate here
// Go builds a joined string longer than 32 bytes on the heap
func TestFollowMatchAllocatesNothing(t *testing.T) {
	c := &Client{events: events.New()}
	stamp := time.Date(2026, 10, 6, 4, 0, 0, 0, time.UTC)
	emit := func() {
		c.events.Emit("babel.a-thing-with-a-long-name.a-change-with-a-long-name", "an-organization-with-a-long-name/a-gateway-with-a-long-name/0@0",
			slog.String("route", "fd00:1::/64"), slog.Int("metric", 96), slog.Float64("loss", 0.5), slog.Time("at", stamp))
	}
	// more than a ring holds, so the emits below overwrite rather than grow it
	for range 2048 {
		emit()
	}
	alone := testing.AllocsPerRun(100, emit)
	var kinds []string
	for kind := range 16 {
		kinds = append(kinds, fmt.Sprintf("%s.never%d", strings.Repeat("unmatched", 4), kind))
	}
	for _, query := range []control.EventQuery{{Kinds: kinds}, {Kinds: kinds}, {Peer: "relay"}, {Peer: "relay"},
		{Attrs: map[string]string{"route": "fd00:2::/64"}}, {Attrs: map[string]string{"metric": "97"}},
		{Attrs: map[string]string{"loss": "0.25"}}, {Attrs: map[string]string{"at": stamp.Add(time.Second).String()}}} {
		_, sub := c.DebugFollow(query)
		defer sub.Close()
	}
	if allocations := testing.AllocsPerRun(100, emit); allocations != alone {
		t.Errorf("an emit with eight follows to match allocated %v times, against %v with none", allocations, alone)
	}
}

// burst is more events of one kind than a follow's queue holds
const burst = 4096

// a follow queues only the events its query takes, so a burst of other events of its kind leaves room for the one it waits for
func TestFollowQueuesOnlyWhatItTakes(t *testing.T) {
	c := &Client{events: events.New()}
	_, sub := c.DebugFollow(control.EventQuery{Kinds: []string{"babel.route.selected"}, Attrs: map[string]string{"route": "fd00:ffff::/64"}, Follow: true})
	defer sub.Close()
	for n := range burst {
		c.events.Emit("babel.route.selected", "", slog.String("route", fmt.Sprintf("fd00:%x::/64", n)))
	}
	c.events.Emit("babel.route.selected", "", slog.String("route", "fd00:ffff::/64"))
	select {
	case delivery := <-sub.C():
		if delivery.Event.Attrs["route"] != "fd00:ffff::/64" || delivery.Dropped != 0 {
			t.Errorf("a follow of one route carried %+v first, after %d dropped", delivery.Event, delivery.Dropped)
		}
	case <-time.After(convergeBudget):
		t.Error("a follow of one route carried nothing")
	}
}
