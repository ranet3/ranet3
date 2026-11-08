// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package control

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
)

// PathDebugSender is each session's sender: what it holds of its budgets, how many packets it sends between two waits, how long it waits for a batch to be sealed and how long a batch takes to seal
const PathDebugSender = PathDebug + "sender"

func init() { registerDebug(PathDebugSender, reflect.TypeFor[SenderInfo](), serveSender) }

// SenderSource is a Source whose sessions send through an ordered sender
type SenderSource interface {
	// DebugSender is the senders of one peer's sessions, or of every peer's where peer is empty
	DebugSender(peer string) SenderInfo
}

// SenderInfo is every session's sender the answer names
type SenderInfo struct {
	Sessions []SenderSession `json:"sessions"`
}

// SenderSession is one session's sender
type SenderSession struct {
	// Path is the session's path, Peer the canonical form of the node it is with
	Path string `json:"path"`
	Peer string `json:"peer"`
	// DataHeld is the bytes of the data budget the session's batches hold from their reservation until their transmit returns, of DataLimit
	DataHeld  int64 `json:"data_held"`
	DataLimit int64 `json:"data_limit"`
	// ControlHeld is the places of the control budget babel's packets hold the same way, of ControlLimit
	ControlHeld  int64 `json:"control_held"`
	ControlLimit int64 `json:"control_limit"`
	// Releases counts the packets the sender handed the transport between two of its waits, on its queue or on a batch to be sealed
	Releases SenderHistogram `json:"releases"`
	// HeadWaits is the nanoseconds the sender waited for the first batch of its queue to be sealed
	HeadWaits SenderHistogram `json:"head_waits"`
	// Seals is the nanoseconds a data batch took from its reservation to its seal
	Seals SenderHistogram `json:"seals"`
}

// SenderHistogram is a count of observations by bucket
// Counts[i] is how many fell at or under Bounds[i] and over the bound before it, and the last count is how many fell over every bound
// Sum is their total
type SenderHistogram struct {
	Bounds []uint64 `json:"bounds"`
	Counts []uint64 `json:"counts"`
	Sum    uint64   `json:"sum"`
}

func serveSender(d *debugServer, w http.ResponseWriter, r *http.Request) {
	if !reading(w, r) {
		return
	}
	if source, ok := implements[SenderSource](d, w, "sender"); ok {
		writeJSON(w, source.DebugSender(r.URL.Query().Get("peer")))
	}
}

// Sender reads the senders of one peer's sessions, named by its path, org/name:serial, org/name or name, or of every peer where peer is empty
// ctx bounds the exchange beside the client's own timeout
func (c *Client) Sender(ctx context.Context, peer string) (SenderInfo, error) {
	path := PathDebugSender
	if peer != "" {
		path += "?" + url.Values{"peer": {peer}}.Encode()
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://control"+path, nil)
	if err != nil {
		return SenderInfo{}, fmt.Errorf("control: %w", err)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return SenderInfo{}, c.explain(err)
	}
	return decode[SenderInfo](PathDebugSender, response)
}

// RenderSender writes each session's sender as name and value pairs, a blank line between two sessions
func RenderSender(w io.Writer, info SenderInfo) {
	if len(info.Sessions) == 0 {
		fmt.Fprintln(w, "No session")
		return
	}
	for i, s := range info.Sessions {
		if i > 0 {
			fmt.Fprintln(w)
		}
		pairs(w, [][]string{
			{"Session", s.Path},
			{"Peer", s.Peer},
			{"Data budget", fmt.Sprintf("%d of %d B held", s.DataHeld, s.DataLimit)},
			{"Control budget", fmt.Sprintf("%d of %d places held", s.ControlHeld, s.ControlLimit)},
			{"Releases", histogramLine(s.Releases, "release", senderPacketsText)},
			{"Head waits", histogramLine(s.HeadWaits, "wait", senderNanosText)},
			{"Seals", histogramLine(s.Seals, "seal", senderNanosText)},
		})
	}
}

// histogramLine is how many observations of unit the histogram holds, and the bucket bounds of their median, their 99th percentile and their largest, each written by bound
func histogramLine(h SenderHistogram, unit string, bound func(uint64) string) string {
	var count uint64
	for _, n := range h.Counts {
		count += n
	}
	if count == 0 {
		return "none"
	}
	quantile := func(share float64) string {
		var seen uint64
		for i, n := range h.Counts {
			if seen += n; n != 0 && float64(seen) >= share*float64(count) {
				if i == len(h.Bounds) {
					return "past " + bound(h.Bounds[i-1])
				}
				return "at most " + bound(h.Bounds[i])
			}
		}
		return ""
	}
	return fmt.Sprintf("%s: the median %s, the 99th percentile %s, the largest %s", countOf(int(count), unit), quantile(0.5), quantile(0.99), quantile(1))
}

func senderPacketsText(n uint64) string { return countOf(int(n), "packet") }

// senderNanosText writes a bucket's bound, a power of two of microseconds, in microseconds under a millisecond and in milliseconds to the microsecond above
func senderNanosText(ns uint64) string {
	us := ns / 1000
	if us < 1000 {
		return countOf(int(us), "microsecond")
	}
	return strconv.FormatFloat(float64(us)/1000, 'f', -1, 64) + " milliseconds"
}
