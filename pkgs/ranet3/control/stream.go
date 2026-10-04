// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package control

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"net/http"
	"net/url"
	"slices"
	"time"
)

// Event is one state change the node recorded, or a note a stream wrote about itself
// a note's kind starts with stream. and it carries no sequence number
type Event struct {
	// Seq numbers the node's events without a gap, from 1
	Seq uint64    `json:"seq,omitzero"`
	At  time.Time `json:"at"`
	// Mono is how long after the daemon started the event happened, off the monotonic clock
	Mono  Duration          `json:"mono,omitzero"`
	Kind  string            `json:"kind"`
	Peer  string            `json:"peer,omitempty"`
	Attrs map[string]string `json:"attrs,omitempty"`
}

// Subscription is a live feed of events that a stream drains
type Subscription interface {
	// C carries the events in order, each after the run of events refused just before it, and is closed when the feed ends
	C() <-chan Delivery
	// Dropped takes the run of events refused after the last one C carried
	// it answers 0 while C still holds an event, since the run came after that event
	Dropped() uint64
	// Reason is why the feed ended, read once C is closed
	Reason() string
	// Close ends the feed from the reading side
	Close()
}

// Delivery is one event a feed carries
type Delivery struct {
	Event Event
	// Dropped is how many events the feed refused since the one it carried before, its queue being full
	Dropped uint64
}

// note is a line a stream writes about itself
func note(kind string, attrs map[string]string) Event {
	return Event{At: time.Now(), Kind: kind, Attrs: attrs}
}

// stream answers with the backlog follow returns, then a stream.live note, then its subscription
// until the reader goes, the subscription ends or a write misses its budget
// the note parts the events recorded before the subscription from those after it, whatever their stamps
// the place is taken before follow runs, so a refused stream never subscribes
func (d *debugServer) stream(w http.ResponseWriter, r *http.Request, follow func() ([]Event, Subscription)) {
	select {
	case d.streams <- struct{}{}:
		defer func() { <-d.streams }()
	default:
		http.Error(w, fmt.Sprintf("this daemon already serves %d streams, which is as many as it holds open at once", cap(d.streams)),
			http.StatusServiceUnavailable)
		return
	}
	backlog, sub := follow()
	defer sub.Close()
	controller := http.NewResponseController(w)
	w.Header().Set("Content-Type", "application/x-ndjson")
	encoder := json.NewEncoder(w)
	// every write sets its own deadline, which replaces the WriteTimeout the server put on the request
	// a stream outlives that, and a reader that stops reading is dropped after one budget
	write := func(events []Event) bool {
		if controller.SetWriteDeadline(time.Now().Add(d.budget)) != nil {
			return false
		}
		for _, event := range events {
			if encoder.Encode(event) != nil {
				return false
			}
		}
		return controller.Flush() == nil
	}
	if !write(append(backlog, note("stream.live", nil))) {
		return
	}
	heartbeat := time.NewTicker(d.heartbeat)
	defer heartbeat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-heartbeat.C:
			if !write([]Event{note("stream.heartbeat", nil)}) {
				return
			}
		case delivery, open := <-sub.C():
			batch, open := drain(sub, delivery, open)
			if !write(batch) || !open {
				return
			}
		}
	}
}

// drain takes what the subscription already holds after first, without waiting for more
// a run of refused events is noted where it was lost, before the event that followed it or before the feed's end
// a run after the last event taken is noted at the end of the batch, since no event may come to carry it
func drain(sub Subscription, first Delivery, open bool) ([]Event, bool) {
	var batch []Event
	for delivery := first; ; {
		dropped := delivery.Dropped
		if !open {
			dropped = sub.Dropped()
		}
		if dropped > 0 {
			batch = append(batch, note("stream.dropped", map[string]string{"count": fmt.Sprint(dropped)}))
		}
		if !open {
			return append(batch, note("stream.closed", map[string]string{"reason": sub.Reason()})), false
		}
		batch = append(batch, delivery.Event)
		if len(batch) < streamBatch {
			select {
			case delivery, open = <-sub.C():
				continue
			default:
			}
		}
		// a full batch asks too, since it may have taken the last event the queue held
		if dropped := sub.Dropped(); dropped > 0 {
			batch = append(batch, note("stream.dropped", map[string]string{"count": fmt.Sprint(dropped)}))
		}
		return batch, true
	}
}

// Stream reads a stream line by line as it arrives
// it ends when the daemon ends the stream, a line fails or ctx is done, the last two as an error
// a daemon that never answered is an error of its own rather than ctx's, which a caller ending a stream at a deadline needs to tell apart
func (c *Client) Stream(ctx context.Context, path string, query url.Values) iter.Seq2[json.RawMessage, error] {
	return func(yield func(json.RawMessage, error) bool) {
		target := path
		if len(query) > 0 {
			target += "?" + query.Encode()
		}
		response, err := c.Raw(ctx, http.MethodGet, target, nil)
		if err != nil && ctx.Err() != nil {
			err = fmt.Errorf("control: %s: the daemon did not answer: %v", path, ctx.Err())
		}
		if err != nil {
			yield(nil, err)
			return
		}
		defer response.Body.Close()
		lines := bufio.NewScanner(response.Body)
		lines.Buffer(nil, maxLine)
		if response.StatusCode != http.StatusOK {
			lines.Scan()
			yield(nil, fmt.Errorf("control: %s: %s: %s", path, response.Status, lines.Text()))
			return
		}
		for lines.Scan() {
			if !yield(slices.Clone(lines.Bytes()), nil) {
				return
			}
		}
		if err := lines.Err(); err != nil {
			yield(nil, fmt.Errorf("control: reading %s: %w", path, err))
		}
	}
}
