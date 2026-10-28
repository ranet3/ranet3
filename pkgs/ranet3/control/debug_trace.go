// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package control

import (
	"cmp"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"maps"
	"net/http"
	"net/netip"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"
)

// PathDebugTrace streams each packet's forwarding decision as the node makes it
const PathDebugTrace = PathDebug + "trace"

func init() {
	registerDebug(PathDebugTrace, classPlaintext, reflect.TypeFor[TraceLine](), serveTrace)
}

// TraceDecisions is every decision a trace query may select, as a record names it
var TraceDecisions = []string{"deliver", "forward", "egress", "answer", "drop"}

// TraceProtocols is the protocols a trace query may name by name, beside any by number
var TraceProtocols = map[string]uint8{"icmp": 1, "tcp": 6, "udp": 17, "gre": 47, "esp": 50, "ah": 51, "icmpv6": 58, "sctp": 132}

// TraceQuery selects the packets a trace records, and how many and how much of each
type TraceQuery struct {
	// Sources and Destinations select a packet whose address lies in any one of the list, an empty list selecting all
	Sources, Destinations []netip.Prefix
	// Protocol selects the protocol after the IPv6 extension headers, or an IPv4 packet's, 0 selecting all
	Protocol uint8
	// Decision is one of TraceDecisions, empty selecting all
	Decision string
	// Peer selects a packet that arrived on that peer's session or goes to it, named by its path, by org/name:serial, by org/name or by name
	Peer string
	// Rate is the most records a second, within TraceRateMin and TraceRateMax
	Rate int
	// Payload is how many bytes of its packet a record carries, from the IP header on, within 0 and TracePayloadMax
	Payload int
}

func (q TraceQuery) values() url.Values {
	values := url.Values{}
	for _, prefix := range q.Sources {
		values.Add("src", prefix.String())
	}
	for _, prefix := range q.Destinations {
		values.Add("dst", prefix.String())
	}
	if q.Protocol != 0 {
		values.Set("proto", strconv.Itoa(int(q.Protocol)))
	}
	if q.Decision != "" {
		values.Set("decision", q.Decision)
	}
	if q.Peer != "" {
		values.Set("peer", q.Peer)
	}
	values.Set("rate", strconv.Itoa(q.Rate))
	if q.Payload != 0 {
		values.Set("payload", strconv.Itoa(q.Payload))
	}
	return values
}

// ParseTracePrefix reads a prefix, or an address as the prefix holding it alone
func ParseTracePrefix(text string) (netip.Prefix, error) {
	if prefix, err := netip.ParsePrefix(text); err == nil {
		return prefix.Masked(), nil
	}
	if address, err := netip.ParseAddr(text); err == nil && address.Zone() == "" {
		return netip.PrefixFrom(address, address.BitLen()), nil
	}
	return netip.Prefix{}, fmt.Errorf("a trace takes a prefix such as 192.0.2.0/24 or an address, not %q", text)
}

// ParseTraceProtocol reads a protocol by one of the names of TraceProtocols or by its number
func ParseTraceProtocol(text string) (uint8, error) {
	if number, ok := TraceProtocols[text]; ok {
		return number, nil
	}
	if number, err := strconv.ParseUint(text, 10, 8); err == nil {
		return uint8(number), nil
	}
	return 0, fmt.Errorf("a trace takes a protocol number from 0 to 255 or one of %v, not %q", slices.Sorted(maps.Keys(TraceProtocols)), text)
}

// Check refuses a query out of its bounds, naming the value
func (q TraceQuery) Check() error {
	switch {
	case len(q.Sources) > maxTracePrefixes || len(q.Destinations) > maxTracePrefixes:
		return fmt.Errorf("a trace names %d source and %d destination prefixes at most, and this one names %d and %d", maxTracePrefixes, maxTracePrefixes, len(q.Sources), len(q.Destinations))
	case q.Decision != "" && !slices.Contains(TraceDecisions, q.Decision):
		return fmt.Errorf("a trace's decision is one of %v, not %q", TraceDecisions, q.Decision)
	case q.Rate < TraceRateMin || q.Rate > TraceRateMax:
		return fmt.Errorf("a trace's rate is %d to %d records a second, not %d", TraceRateMin, TraceRateMax, q.Rate)
	case q.Payload < 0 || q.Payload > TracePayloadMax:
		return fmt.Errorf("a trace's payload is 0 to %d bytes, not %d", TracePayloadMax, q.Payload)
	}
	return nil
}

func parseTraceQuery(values url.Values) (TraceQuery, error) {
	query := TraceQuery{Decision: values.Get("decision"), Peer: values.Get("peer"), Rate: TraceRateDefault}
	for _, list := range []struct {
		key  string
		into *[]netip.Prefix
	}{{"src", &query.Sources}, {"dst", &query.Destinations}} {
		for _, text := range values[list.key] {
			prefix, err := ParseTracePrefix(text)
			if err != nil {
				return TraceQuery{}, fmt.Errorf("%s: %w", list.key, err)
			}
			*list.into = append(*list.into, prefix)
		}
	}
	if text := values.Get("proto"); text != "" {
		protocol, err := ParseTraceProtocol(text)
		if err != nil {
			return TraceQuery{}, err
		}
		query.Protocol = protocol
	}
	for _, number := range []struct {
		key  string
		into *int
	}{{"rate", &query.Rate}, {"payload", &query.Payload}} {
		if text := values.Get(number.key); text != "" {
			n, err := strconv.Atoi(text)
			if err != nil {
				return TraceQuery{}, fmt.Errorf("%s takes a number, not %q", number.key, text)
			}
			*number.into = n
		}
	}
	return query, query.Check()
}

// TracePacket is one packet's forwarding decision as a trace carries it, every field read from the packet as it arrived
// but a budget drop's, which follows the packet's forward record and is read from the packet as it was queued for its peer
type TracePacket struct {
	// Arrival is session, tun, or none for a packet of no session
	Arrival string `json:"arrival"`
	// From is the path of the session the packet arrived on
	From     string `json:"from,omitempty"`
	Decision string `json:"decision"`
	// Reason names why a packet was answered or dropped, as the transit counters name it, or budget
	Reason string `json:"reason,omitempty"`
	// Next is the path of the session a forwarded packet goes to, or a packet its budget refused was to go to
	Next string `json:"next,omitempty"`
	// Segment is the first segment of a packet a policy steered, the next segment of one End forwarded
	// and the segment of this node's that egressed or dropped one
	Segment     netip.Addr `json:"segment,omitzero"`
	Source      netip.Addr `json:"src"`
	Destination netip.Addr `json:"dst"`
	// Protocol is the protocol after the IPv6 extension headers, or an IPv4 packet's
	Protocol uint8 `json:"proto"`
	// Headers names the IPv6 extension headers walked, or the IPv4 options, in order
	Headers []string `json:"headers,omitempty"`
	// Transport is set where the packet carries the ports and TCP flags, or the ICMP type and code, which a fragment past the first does not
	Transport       bool   `json:"transport,omitempty"`
	SourcePort      uint16 `json:"src_port,omitzero"`
	DestinationPort uint16 `json:"dst_port,omitzero"`
	TCPFlags        uint8  `json:"tcp_flags,omitzero"`
	ICMPType        uint8  `json:"icmp_type,omitzero"`
	ICMPCode        uint8  `json:"icmp_code,omitzero"`
	// HopLimit is the hop limit or TTL, and Length the packet's bytes
	HopLimit uint8 `json:"hop_limit"`
	Length   int   `json:"length"`
	// Fragments is how many fragments a forwarded packet was cut into
	Fragments int `json:"fragments,omitzero"`
	// Answer names the ICMP error an answer is, and Outcome what became of it
	Answer  string `json:"answer,omitempty"`
	Outcome string `json:"outcome,omitempty"`
	// Payload is the packet's first bytes from the IP header on, as many as the trace asked for
	Payload []byte `json:"payload,omitempty"`
}

// TraceLine is one line of a trace, a packet's record or a note the stream wrote about itself
type TraceLine struct {
	Packet *TracePacket `json:"packet,omitempty"`
	Note   *Event       `json:"note,omitempty"`
}

// TraceSource is a Source that traces its forwarding decision
type TraceSource interface {
	// DebugTrace opens a trace of the packets query selects for the caller behind ctx, refused where the node can hold no more
	DebugTrace(ctx context.Context, query TraceQuery) (TraceFeed, error)
}

// TraceFeed is one open trace, which TraceFeedOf makes of a source's own
type TraceFeed interface {
	pour(d *debugServer, w http.ResponseWriter, r *http.Request)
}

// TraceRecords is a source's own trace, of records of type R
type TraceRecords[R any] interface {
	// Records carries the records, and is never closed
	Records() <-chan R
	// Done is closed once the source ended the trace
	Done() <-chan struct{}
	// Packet is a record's wire form
	Packet(R) TracePacket
	// Refused is how many records the trace refused since it opened, for its rate and for its queue
	Refused() (rate, queue uint64)
	// Reason is why the source ended the trace, read once Done is closed
	Reason() string
	// Close ends the trace from the stream's side, why naming what ended the stream, empty where the source ended it
	Close(why string)
}

// TraceFeedOf is the feed a trace stream drains from records
func TraceFeedOf[R any](records TraceRecords[R]) TraceFeed {
	return &traceFeed[R]{records: records}
}

// traceFeed is the lineFeed of a source's trace, whose Records never closes
type traceFeed[R any] struct {
	records TraceRecords[R]
	// reported holds the refusals the stream.dropped notes have counted so far, for the rate and for the queue
	reported [2]uint64
}

func (f *traceFeed[R]) pour(d *debugServer, w http.ResponseWriter, r *http.Request) {
	pour(d, w, r, nil, lineFeed[R, TraceLine](f))
}

func (f *traceFeed[R]) C() <-chan R { return f.records.Records() }

func (f *traceFeed[R]) Done() <-chan struct{} { return f.records.Done() }

// Take of a trace that ended writes the records its queue still holds, which the trace counted recorded, before its last notes
func (f *traceFeed[R]) Take(first R, open bool) ([]TraceLine, bool) {
	if !open {
		lines := append(f.queued(nil, len(f.records.Records())), f.Tick()...)
		return append(lines, f.Note(note("stream.closed", map[string]string{"reason": f.records.Reason()}))), false
	}
	packet := f.records.Packet(first)
	return f.queued([]TraceLine{{Packet: &packet}}, streamBatch-1), true
}

// queued is lines and the lines of up to n records the queue holds, taken without waiting
func (f *traceFeed[R]) queued(lines []TraceLine, n int) []TraceLine {
	for range n {
		select {
		case record := <-f.records.Records():
			packet := f.records.Packet(record)
			lines = append(lines, TraceLine{Packet: &packet})
		default:
			return lines
		}
	}
	return lines
}

// Tick is a stream.dropped note of what the trace refused since the last, for its rate and for its queue, and nothing while it refused none
func (f *traceFeed[R]) Tick() []TraceLine {
	rate, queue := f.records.Refused()
	if rate == f.reported[0] && queue == f.reported[1] {
		return nil
	}
	attrs := map[string]string{"rate": strconv.FormatUint(rate-f.reported[0], 10), "queue": strconv.FormatUint(queue-f.reported[1], 10)}
	f.reported = [2]uint64{rate, queue}
	return []TraceLine{f.Note(note("stream.dropped", attrs))}
}

func (*traceFeed[R]) Note(event Event) TraceLine { return TraceLine{Note: &event} }

func (f *traceFeed[R]) Close(why string) { f.records.Close(why) }

func serveTrace(d *debugServer, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "a trace is a stream, so it takes a GET", http.StatusMethodNotAllowed)
		return
	}
	source, ok := implements[TraceSource](d, w, "trace")
	if !ok {
		return
	}
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		http.Error(w, "the query does not parse: "+err.Error(), http.StatusBadRequest)
		return
	}
	query, err := parseTraceQuery(values)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	release, ok := d.place(w)
	if !ok {
		return
	}
	defer release()
	feed, err := source.DebugTrace(r.Context(), query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	feed.pour(d, w, r)
}

// tcpFlagNames names the TCP flags from the lowest bit, RFC 9293 section 3.1 and RFC 3168 section 6.1
var tcpFlagNames = []string{"fin", "syn", "rst", "psh", "ack", "urg", "ece", "cwr"}

// RenderTracePacket writes one record as one line: the decision, the protocol, source and destination, then the record's other fields by name
func RenderTracePacket(w io.Writer, p TracePacket) {
	protocol := strconv.Itoa(int(p.Protocol))
	for name, number := range TraceProtocols {
		if number == p.Protocol {
			protocol = name
		}
	}
	ported := p.Transport && (p.Protocol == 6 || p.Protocol == 17 || p.Protocol == 132)
	endpoint := func(address netip.Addr, port uint16) string {
		if ported {
			return netip.AddrPortFrom(address, port).String()
		}
		return address.String()
	}
	line := []string{p.Decision, protocol, endpoint(p.Source, p.SourcePort), ">", endpoint(p.Destination, p.DestinationPort)}
	add := func(key, value string) {
		if value != "" {
			line = append(line, key+"="+value)
		}
	}
	add("reason", p.Reason)
	add("arrival", p.Arrival)
	add("from", p.From)
	add("next", p.Next)
	if p.Segment.IsValid() {
		add("segment", p.Segment.String())
	}
	add("headers", strings.Join(p.Headers, ","))
	if p.Transport && p.Protocol == 6 {
		var flags []string
		for bit, name := range tcpFlagNames {
			if p.TCPFlags&(1<<bit) != 0 {
				flags = append(flags, name)
			}
		}
		add("tcp_flags", cmp.Or(strings.Join(flags, ","), "none"))
	}
	if p.Transport && (p.Protocol == 1 || p.Protocol == 58) {
		add("icmp_type", strconv.Itoa(int(p.ICMPType)))
		add("icmp_code", strconv.Itoa(int(p.ICMPCode)))
	}
	add("hop_limit", strconv.Itoa(int(p.HopLimit)))
	add("length", strconv.Itoa(p.Length))
	if p.Fragments != 0 {
		add("fragments", strconv.Itoa(p.Fragments))
	}
	add("answer", p.Answer)
	add("outcome", p.Outcome)
	add("payload", hex.EncodeToString(p.Payload))
	fmt.Fprintln(w, strings.Join(line, " "))
}

// RenderTraceLine writes a record as RenderTracePacket does and a note as RenderEvent does
func RenderTraceLine(w io.Writer, line TraceLine) {
	if line.Packet != nil {
		RenderTracePacket(w, *line.Packet)
	} else if line.Note != nil {
		RenderEvent(w, *line.Note)
	}
}

// Trace reads the records query selects as the node decides them, with the notes the stream writes about itself but its heartbeats
// it ends with ctx or with the daemon closing the stream, whose stream.closed note it passes on
func (c *Client) Trace(ctx context.Context, query TraceQuery) iter.Seq2[TraceLine, error] {
	return func(yield func(TraceLine, error) bool) {
		if err := query.Check(); err != nil {
			yield(TraceLine{}, err)
			return
		}
		for raw, err := range c.Stream(ctx, PathDebugTrace, query.values()) {
			if err != nil {
				yield(TraceLine{}, err)
				return
			}
			var line TraceLine
			if err := json.Unmarshal(raw, &line); err != nil {
				yield(TraceLine{}, fmt.Errorf("control: decoding %s: %w", PathDebugTrace, err))
				return
			}
			if line.Packet == nil && line.Note == nil {
				yield(TraceLine{}, errors.New("control: a trace line holds neither a packet nor a note"))
				return
			}
			if line.Note != nil && line.Note.Kind == "stream.heartbeat" {
				continue
			}
			if !yield(line, nil) {
				return
			}
		}
	}
}
