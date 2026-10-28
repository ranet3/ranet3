// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/internal/netstack"
)

// traceStopping is why every trace ends when the mesh closes, which it does only as the daemon stops
const traceStopping = "the daemon is stopping"

// DebugTrace opens a trace of the mesh's forwarding decision, recorded as control.trace.started with the caller the socket named
// it is recorded as control.trace.ended once it closes, with why and what it took and refused
func (c *Client) DebugTrace(ctx context.Context, query control.TraceQuery) (control.TraceFeed, error) {
	trace, err := c.openTrace(ctx, query)
	if err != nil {
		return nil, err
	}
	return control.TraceFeedOf[netstack.TraceRecord](trace), nil
}

// query is one TraceQuery.Check took, so a decision it names is one ParseTraceDecision reads, and an empty one reads as TraceAny
func (c *Client) openTrace(ctx context.Context, query control.TraceQuery) (*clientTrace, error) {
	decision, _ := netstack.ParseTraceDecision(query.Decision)
	filter := netstack.TraceFilter{Sources: query.Sources, Destinations: query.Destinations, Protocol: query.Protocol, Decision: decision, Peer: query.Peer}
	feed, err := c.Mesh.Trace(filter, query.Payload, query.Rate)
	if err != nil {
		return nil, err
	}
	attrs := []slog.Attr{slog.String("filter", traceFilterText(query)), slog.Int("rate", query.Rate), slog.Int("payload", feed.Payload())}
	if caller, known := control.CallerOf(ctx); known {
		attrs = append(attrs, slog.Any("uid", caller.UID), slog.Any("pid", caller.PID))
	}
	c.events.Emit("control.trace.started", "", attrs...)
	return &clientTrace{events: c.events.Emit, feed: feed}, nil
}

// traceFilterText is the query's filter as one line, each part as the query names it, or all for a filter selecting every packet
func traceFilterText(query control.TraceQuery) string {
	var parts []string
	for _, prefix := range query.Sources {
		parts = append(parts, "src="+prefix.String())
	}
	for _, prefix := range query.Destinations {
		parts = append(parts, "dst="+prefix.String())
	}
	if query.Protocol != 0 {
		parts = append(parts, fmt.Sprintf("proto=%d", query.Protocol))
	}
	if query.Decision != "" {
		parts = append(parts, "decision="+query.Decision)
	}
	if query.Peer != "" {
		parts = append(parts, "peer="+query.Peer)
	}
	if len(parts) == 0 {
		return "all"
	}
	return strings.Join(parts, " ")
}

// clientTrace is the mesh's feed as the control socket streams it
type clientTrace struct {
	events func(kind, peer string, attrs ...slog.Attr)
	feed   *netstack.TraceFeed
}

func (t *clientTrace) Records() <-chan netstack.TraceRecord { return t.feed.Records() }

func (t *clientTrace) Done() <-chan struct{} { return t.feed.Done() }

func (t *clientTrace) Refused() (rate, queue uint64) {
	counts := t.feed.Counts()
	return counts.RefusedRate, counts.RefusedQueue
}

func (*clientTrace) Reason() string { return traceStopping }

// Close takes the feed off the mesh and records why the trace ended, the mesh's close where it came first
func (t *clientTrace) Close(why string) {
	select {
	case <-t.feed.Done():
		why = traceStopping
	default:
	}
	t.feed.Close()
	counts := t.feed.Counts()
	t.events("control.trace.ended", "", slog.String("reason", why),
		slog.Uint64("recorded", counts.Recorded), slog.Uint64("refused_rate", counts.RefusedRate), slog.Uint64("refused_queue", counts.RefusedQueue))
}

func (*clientTrace) Packet(r netstack.TraceRecord) control.TracePacket {
	return control.TracePacket{
		Arrival: r.Arrival.String(), From: r.From, Decision: r.Decision.String(), Reason: r.Reason, Next: r.Next,
		Segment: r.Segment, Source: r.Source, Destination: r.Destination, Protocol: r.Protocol, Headers: r.Headers,
		Transport: r.Transport, SourcePort: r.SourcePort, DestinationPort: r.DestinationPort, TCPFlags: r.TCPFlags, ICMPType: r.ICMPType, ICMPCode: r.ICMPCode,
		HopLimit: r.HopLimit, Length: r.Length, Fragments: r.Fragments, Answer: r.Answer, Outcome: r.Outcome.String(), Payload: r.Payload,
	}
}
