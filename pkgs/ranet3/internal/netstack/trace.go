// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// TraceDecision names the forwarding decision's action on one packet
type TraceDecision uint8

const (
	// TraceAny is the filter's decision selecting every one, and no record's
	TraceAny TraceDecision = iota
	TraceDeliver
	TraceForward
	TraceEgress
	TraceAnswer
	TraceDrop
	traceDecisionCount
)

var traceDecisionNames = [traceDecisionCount]string{
	TraceAny:     "any",
	TraceDeliver: "deliver",
	TraceForward: "forward",
	TraceEgress:  "egress",
	TraceAnswer:  "answer",
	TraceDrop:    "drop",
}

func (d TraceDecision) String() string {
	if d < traceDecisionCount {
		return traceDecisionNames[d]
	}
	return "decision(" + strconv.Itoa(int(d)) + ")"
}

// ParseTraceDecision is the decision name names, false for a name of none
func ParseTraceDecision(name string) (TraceDecision, bool) {
	if i := slices.Index(traceDecisionNames[:], name); i > 0 {
		return TraceDecision(i), true
	}
	return 0, false
}

// TraceArrival is where a traced packet came from
type TraceArrival uint8

const (
	// TraceArrivedNone is a packet of no session, handed to DeliverInbound
	TraceArrivedNone TraceArrival = iota
	TraceArrivedSession
	TraceArrivedTUN
)

func (a TraceArrival) String() string {
	switch a {
	case TraceArrivedSession:
		return "session"
	case TraceArrivedTUN:
		return "tun"
	}
	return "none"
}

// TraceOutcome names the fate of the answer a record's packet drew
type TraceOutcome uint8

const (
	// TraceNoAnswer is the outcome of every record but an answer's
	TraceNoAnswer TraceOutcome = iota
	// TraceSent is an answer built and handed to the tun or a session
	TraceSent
	// TraceWithheld is an answer the ICMP limits held back
	TraceWithheld
	// TraceUnanswered is an answer with no address of its family to come from, which TransitCounters.Unanswered counts
	TraceUnanswered
	// TraceNotAnswerable is a packet no ICMP error may answer, RFC 1812 section 4.3.2.7 and RFC 4443 section 2.4 (e)
	TraceNotAnswerable
	// TraceUnsent is an answer built for, or due to, a source the mesh routes it no way back to, or whose session had no room for it
	TraceUnsent
)

func (o TraceOutcome) String() string {
	switch o {
	case TraceSent:
		return "sent"
	case TraceWithheld:
		return "withheld"
	case TraceUnanswered:
		return "unanswered"
	case TraceNotAnswerable:
		return "not_answerable"
	case TraceUnsent:
		return "unsent"
	}
	return ""
}

// TraceFilter selects the packets a trace records
// the zero value selects every packet
type TraceFilter struct {
	// Sources and Destinations select a packet whose address lies in any one of the list, an empty list selecting all
	Sources, Destinations []netip.Prefix
	// Protocol selects the protocol after the extension headers or options, 0 selecting all
	Protocol uint8
	Decision TraceDecision
	// Peer selects a packet that arrived on that peer's session or goes to it, by its ID, empty selecting all
	Peer string
}

// TraceRecord is one packet's forwarding decision, every field read from the packet as it arrived
type TraceRecord struct {
	Arrival TraceArrival
	// From is the ID of the peer whose session the packet arrived on, empty for any other arrival
	From     string
	Decision TraceDecision
	// Reason names why a packet was answered or dropped, as the transit counters name it, or budget, empty for any other decision
	Reason string
	// Next is the ID of the peer a forwarded packet goes to
	Next string
	// Segment is the first segment of a packet a policy steered, and the next segment of one End forwarded
	Segment             netip.Addr
	Source, Destination netip.Addr
	// Protocol is the protocol after the IPv6 extension headers, or an IPv4 packet's
	Protocol uint8
	// Headers names the IPv6 extension headers walked, or the IPv4 options, in order
	Headers []string
	// Transport reports the ports and TCP flags, or the ICMP type and code, read, which a fragment past the first does not carry
	Transport                   bool
	SourcePort, DestinationPort uint16
	TCPFlags                    uint8
	ICMPType, ICMPCode          uint8
	// HopLimit is the hop limit or TTL, and Length the packet's bytes
	HopLimit uint8
	Length   int
	// Fragments is how many fragments a packet was cut into, 0 for one not cut
	Fragments int
	// Answer names the ICMP error an answer is, and Outcome what became of it
	Answer  string
	Outcome TraceOutcome
	// Payload is the packet's first bytes, as many as the client asked for, nil where it asked for none
	Payload []byte
}

// TraceCounts counts the records one feed took and refused since it opened
type TraceCounts struct {
	Recorded, RefusedRate, RefusedQueue uint64
}

// TraceFeed is one client's trace, open until Close or the mesh's own close
type TraceFeed struct {
	m *Mesh
	c *traceClient
}

// Records carries the feed's records, and is never closed
func (f *TraceFeed) Records() <-chan TraceRecord { return f.c.queue }

// Done is closed once the feed closes, by Close or by the mesh closing
func (f *TraceFeed) Done() <-chan struct{} { return f.c.done }

func (f *TraceFeed) Counts() TraceCounts {
	return TraceCounts{Recorded: f.c.recorded.Load(), RefusedRate: f.c.refusedRate.Load(), RefusedQueue: f.c.refusedQueue.Load()}
}

// Close takes the feed off the mesh, and is safe to call more than once
func (f *TraceFeed) Close() {
	f.m.traceMu.Lock()
	if current := f.m.tracer.Load(); current != nil {
		f.m.tracer.Store(current.without(f.c))
	}
	f.m.traceMu.Unlock()
	f.c.end()
}

// Trace opens a feed of the records filter selects, at most rate a second, each carrying up to payload bytes of its packet
// rate lies within TraceRateMin and TraceRateMax, and payload within 0 and TracePayloadMax
func (m *Mesh) Trace(filter TraceFilter, payload, rate int) (*TraceFeed, error) {
	switch {
	case rate < TraceRateMin || rate > TraceRateMax:
		return nil, fmt.Errorf("netstack: trace rate %d is outside %d to %d", rate, TraceRateMin, TraceRateMax)
	case payload < 0 || payload > TracePayloadMax:
		return nil, fmt.Errorf("netstack: trace payload %d is outside 0 to %d", payload, TracePayloadMax)
	case filter.Decision >= traceDecisionCount:
		return nil, fmt.Errorf("netstack: trace decision %d names none", filter.Decision)
	}
	for _, prefix := range slices.Concat(filter.Sources, filter.Destinations) {
		if !prefix.IsValid() {
			return nil, fmt.Errorf("netstack: trace prefix %s is not valid", prefix)
		}
	}
	c := &traceClient{
		filter:   filter,
		payload:  payload,
		interval: int64(time.Second) / int64(rate),
		queue:    make(chan TraceRecord, traceQueueLength),
		done:     make(chan struct{}),
	}
	m.traceMu.Lock()
	defer m.traceMu.Unlock()
	select {
	case <-m.closed:
		return nil, errors.New("netstack: the mesh is closed")
	default:
	}
	current := m.tracer.Load()
	if current != nil && len(current.clients) == maxTraceClients {
		return nil, fmt.Errorf("netstack: the mesh holds %d traces already", maxTraceClients)
	}
	m.tracer.Store(current.with(c))
	return &TraceFeed{m: m, c: c}, nil
}

// TraceClients is how many feeds are open
func (m *Mesh) TraceClients() int {
	if t := m.tracer.Load(); t != nil {
		return len(t.clients)
	}
	return 0
}

// closeTraces ends every feed once the mesh closes
func (m *Mesh) closeTraces() {
	m.traceMu.Lock()
	t := m.tracer.Swap(nil)
	m.traceMu.Unlock()
	if t != nil {
		for _, c := range t.clients {
			c.end()
		}
	}
}

// traceState is the trace's state, embedded in Mesh
type traceState struct {
	_ [linePad]byte
	// tracer is nil while no feed is open, and replaced whole under traceMu, so an emitter holding one sends to clients that may have closed
	tracer  atomic.Pointer[tracer]
	_       [linePad]byte
	traceMu sync.Mutex
}

// tracer is the clients one install holds, never changed once installed
type tracer struct {
	clients []*traceClient
	// start is the clock the clients' rates run on, kept by every tracer that replaces this one
	start time.Time
}

func (t *tracer) with(c *traceClient) *tracer {
	if t == nil {
		return &tracer{clients: []*traceClient{c}, start: time.Now()}
	}
	return &tracer{clients: append(slices.Clip(t.clients), c), start: t.start}
}

// without is nil once c was the last, which puts the cost of an idle trace back to one load a batch
func (t *tracer) without(c *traceClient) *tracer {
	i := slices.Index(t.clients, c)
	if i < 0 {
		return t
	}
	if len(t.clients) == 1 {
		return nil
	}
	return &tracer{clients: slices.Delete(slices.Clone(t.clients), i, i+1), start: t.start}
}

// now is nanoseconds since the tracer was first installed, on the monotonic clock
func (t *tracer) now() int64 { return int64(time.Since(t.start)) }

type traceClient struct {
	filter  TraceFilter
	payload int
	// interval is the nanoseconds one record takes from the rate, and tat the time the bucket next has room for one, a generic cell rate algorithm
	interval int64
	tat      atomic.Int64
	// queue is never closed, since an emitter may hold the tracer that holds it after the client leaves
	queue                               chan TraceRecord
	done                                chan struct{}
	endOnce                             sync.Once
	recorded, refusedRate, refusedQueue atomic.Uint64
}

func (c *traceClient) end() { c.endOnce.Do(func() { close(c.done) }) }

// draw takes one record's room from the rate at now, a burst of one second's worth allowed
func (c *traceClient) draw(now int64) bool {
	for {
		tat := c.tat.Load()
		next := max(tat, now) + c.interval
		if next-now > int64(traceBurst) {
			return false
		}
		if c.tat.CompareAndSwap(tat, next) {
			return true
		}
	}
}

// room reports the rate holding one record's room at now, which draw then takes, a load of the bucket alone
func (c *traceClient) room(now int64) bool {
	return max(c.tat.Load(), now)+c.interval-now <= int64(traceBurst)
}

// selects is the filter's test of what the decision did
func (c *traceClient) selects(site *traceSite) bool {
	if c.filter.Decision != TraceAny && c.filter.Decision != site.decision {
		return false
	}
	return c.filter.Peer == "" || site.from != nil && site.from.ID == c.filter.Peer || site.next != nil && site.next.ID == c.filter.Peer
}

// mayTake is selects for held, a forward held before its options and forwardOne
// which then forwards it toward held.next, or drops or answers it toward no peer, and never delivers or egresses it
func (c *traceClient) mayTake(held *traceSite) bool {
	if d := c.filter.Decision; d == TraceDrop || d == TraceAnswer {
		outcome := *held
		outcome.decision, outcome.next = d, nil
		return c.selects(&outcome)
	}
	return c.selects(held)
}

// within reports address inside one of prefixes, or prefixes empty
// netip.Prefix.Contains holds an IPv4-mapped address outside every IPv4 prefix
func within(prefixes []netip.Prefix, address netip.Addr) bool {
	if len(prefixes) == 0 {
		return true
	}
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

// traceSite holds the decision's action on one packet, as its site knows it
type traceSite struct {
	arrival  TraceArrival
	from     *Peer
	decision TraceDecision
	// reason is a transitReason, or traceBudget
	reason    transitReason
	next      *Peer
	segment   netip.Addr
	fragments int
	answer    answerKind
	outcome   TraceOutcome
}

// traceBudget is the reason of a packet its peer's budget refused, which Peer.Dropped counts rather than the transit counters
const traceBudget = transitReasonCount

func traceReasonName(reason transitReason) string {
	if reason == traceBudget {
		return "budget"
	}
	return transitReasonNames[reason]
}

var answerKindNames = [...]string{
	answerNoRoute:         "no_route",
	answerHostUnreachable: "host_unreachable",
	answerProhibited:      "prohibited",
	answerExpired:         "expired",
	answerParameter:       "parameter",
	answerTooBig:          "too_big",
	answerBeyondScope:     "beyond_scope",
}

// traceHold holds what a record of one packet needs, copied before a step that rewrites the packet, and the clients it was copied for
type traceHold struct {
	// taken marks the clients whose rate had room at the hold, which release draws from, and refused those whose rate had none, by their index in the tracer
	taken, refused uint64
	// final is a hold whose decision was made, so taken and refused mark only clients whose filter selects it
	final bool
	// now is the time of the hold on the tracer's clock, which the room and the draw are read at
	now      int64
	src, dst netip.Addr
	fields   traceFields
	// payload is the packet's first bytes, as many as a client of taken asks for
	payload []byte
}

// record records a packet of site whose decision is made and which nothing has rewritten
func (t *tracer) record(site traceSite, raw []byte) { t.recordAs(site, nil, raw) }

// recordAs records raw, a packet of site whose decision is made, for the clients whose filter selects view, nil for raw
// view holds the addresses and protocol an earlier record of the packet showed, which the filter of a budget drop reads in place of raw's
func (t *tracer) recordAs(site traceSite, view, raw []byte) {
	h := t.hold(&site, true, view, raw)
	t.release(&h, site)
}

// hold copies what a record of raw needs, for each client whose filter may select view, nil for raw, decided as site says, and whose rate has room
// final is a site whose decision is made, and otherwise site is a forward held before its options and forwardOne, which mayTake tests
// release draws from the rate, so a packet the client turns out not to select spends none of it
func (t *tracer) hold(site *traceSite, final bool, view, raw []byte) traceHold {
	aside := view != nil
	if !aside {
		view = raw
	}
	src, dst := tracedAddresses(view)
	h := traceHold{final: final}
	var viewed traceFields
	parsed := false
	payload := 0
	for i, c := range t.clients {
		if !within(c.filter.Sources, src) || !within(c.filter.Destinations, dst) || final && !c.selects(site) || !final && !c.mayTake(site) {
			continue
		}
		if c.filter.Protocol != 0 {
			if !parsed {
				viewed, parsed = parseTraced(view), true
			}
			if viewed.protocol != c.filter.Protocol {
				continue
			}
		}
		if h.now == 0 {
			h.now = t.now()
		}
		if !c.room(h.now) {
			h.refused |= 1 << i
			continue
		}
		h.taken |= 1 << i
		payload = max(payload, c.payload)
	}
	if h.taken == 0 {
		return h
	}
	h.src, h.dst, h.fields = src, dst, viewed
	if aside {
		h.src, h.dst = tracedAddresses(raw)
	}
	if aside || !parsed {
		h.fields = parseTraced(raw)
	}
	if payload = min(payload, len(raw)); payload != 0 {
		h.payload = slices.Clone(raw[:payload])
	}
	return h
}

// release records the packet h holds, decided as site says, for each client h holds it for whose filter selects it, drawing from the client's rate
// a client whose rate refused it, at the hold or here, counts it refused, and one whose filter does not select it spends nothing
func (t *tracer) release(h *traceHold, site traceSite) {
	for i, c := range t.clients {
		bit := uint64(1) << i
		if (h.taken|h.refused)&bit == 0 || !h.final && !c.selects(&site) {
			continue
		}
		if h.refused&bit != 0 || !c.draw(h.now) {
			c.refusedRate.Add(1)
			continue
		}
		record := h.build(&site, c.payload)
		select {
		case c.queue <- record:
			c.recorded.Add(1)
		default:
			c.refusedQueue.Add(1)
		}
	}
}

func (h *traceHold) build(site *traceSite, payload int) TraceRecord {
	f := &h.fields
	r := TraceRecord{
		Arrival:         site.arrival,
		Decision:        site.decision,
		Segment:         site.segment,
		Source:          h.src,
		Destination:     h.dst,
		Protocol:        f.protocol,
		Transport:       f.transport,
		SourcePort:      f.sourcePort,
		DestinationPort: f.destinationPort,
		TCPFlags:        f.tcpFlags,
		ICMPType:        f.icmpType,
		ICMPCode:        f.icmpCode,
		HopLimit:        f.hopLimit,
		Length:          f.length,
		Fragments:       site.fragments,
		Outcome:         site.outcome,
	}
	if site.from != nil {
		r.From = site.from.ID
	}
	if site.decision == TraceForward && site.next != nil {
		r.Next = site.next.ID
	}
	if site.decision == TraceAnswer || site.decision == TraceDrop {
		r.Reason = traceReasonName(site.reason)
	}
	if site.decision == TraceAnswer {
		r.Answer = answerKindNames[site.answer]
	}
	for _, header := range f.headers[:f.headerCount] {
		r.Headers = append(r.Headers, header.name(f.version))
	}
	if n := min(payload, len(h.payload)); n != 0 {
		r.Payload = h.payload[:n:n]
	}
	return r
}

func tracedAddresses(raw []byte) (netip.Addr, netip.Addr) {
	src, dst, _ := addrsOfAny(raw)
	return src, dst
}

// addrsOfAny is the addresses of raw where its fixed header holds them, whatever the length its header declares
func addrsOfAny(raw []byte) (src, dst netip.Addr, version byte) {
	switch {
	case len(raw) >= 20 && raw[0]>>4 == 4:
		return netip.AddrFrom4([4]byte(raw[12:16])), netip.AddrFrom4([4]byte(raw[16:20])), 4
	case len(raw) >= 40 && raw[0]>>4 == 6:
		return netip.AddrFrom16([16]byte(raw[8:24])), netip.AddrFrom16([16]byte(raw[24:40])), 6
	}
	return netip.Addr{}, netip.Addr{}, 0
}

// traceFields are the fields of a record read out of its packet
type traceFields struct {
	version                     byte
	protocol                    uint8
	headers                     [traceHeaders]tracedHeader
	headerCount                 uint8
	transport                   bool
	sourcePort, destinationPort uint16
	tcpFlags                    uint8
	icmpType, icmpCode          uint8
	hopLimit                    uint8
	length                      int
}

// tracedHeader is an IPv6 extension header's next header value, or an IPv4 option's type
type tracedHeader uint8

func (h tracedHeader) name(version byte) string {
	if version == 6 {
		switch h {
		case 0:
			return "hop-by-hop"
		case 43:
			return "routing"
		case 44:
			return "fragment"
		case 51:
			return "authentication"
		case 60:
			return "destination-options"
		}
	} else {
		switch h {
		case 7:
			return "record-route"
		case 68:
			return "timestamp"
		case 130:
			return "security"
		case 131:
			return "loose-source-route"
		case 137:
			return "strict-source-route"
		case 148:
			return "router-alert"
		}
	}
	return "option-" + strconv.Itoa(int(h))
}

// parseTraced reads the fields of a record out of raw, as far as raw holds them
func parseTraced(raw []byte) traceFields {
	f := traceFields{length: len(raw)}
	_, _, f.version = addrsOfAny(raw)
	var offset int
	first := true
	switch f.version {
	case 4:
		f.hopLimit, f.protocol = raw[8], raw[9]
		offset = int(raw[0]&0x0f) * 4
		// RFC 791 section 3.1, only the fragment at offset 0 carries the transport header
		first = binary.BigEndian.Uint16(raw[6:8])&0x1fff == 0
		if offset > len(raw) || offset < 20 {
			return f
		}
		f.walkOptions(raw[20:offset])
	case 6:
		f.hopLimit = raw[7]
		var ok bool
		if offset, first, ok = f.walkExtensions(raw); !ok {
			return f
		}
	default:
		return f
	}
	if !first {
		return f
	}
	transport := raw[offset:]
	switch f.protocol {
	case 6:
		if len(transport) >= 14 {
			f.sourcePort, f.destinationPort = binary.BigEndian.Uint16(transport), binary.BigEndian.Uint16(transport[2:])
			f.tcpFlags, f.transport = transport[13], true
		}
	case 17, 132:
		if len(transport) >= 4 {
			f.sourcePort, f.destinationPort = binary.BigEndian.Uint16(transport), binary.BigEndian.Uint16(transport[2:])
			f.transport = true
		}
	case 1, 58:
		if len(transport) >= 2 {
			f.icmpType, f.icmpCode, f.transport = transport[0], transport[1], true
		}
	}
	return f
}

// walkOptions names the options of an IPv4 option list, RFC 791 section 3.1, as far as their framing reads
func (f *traceFields) walkOptions(options []byte) {
	for i := 0; i < len(options) && f.headerCount < traceHeaders; {
		switch options[i] {
		case 0:
			return
		case 1:
			i++
			continue
		}
		if i+1 == len(options) || options[i+1] < 2 {
			return
		}
		f.headers[f.headerCount] = tracedHeader(options[i])
		f.headerCount++
		i += int(options[i+1])
	}
}

// walkExtensions walks the extension headers of raw, an IPv6 packet, RFC 8200 section 4, and reports where the transport header starts
// first is false behind a fragment header whose offset is not 0, and ok false where a header runs past raw or the walk past traceHeaders
func (f *traceFields) walkExtensions(raw []byte) (offset int, first, ok bool) {
	next, offset, first := raw[6], 40, true
	for {
		var length int
		switch next {
		case 0, 43, 60:
			if offset+2 > len(raw) {
				return offset, first, false
			}
			length = 8 * (1 + int(raw[offset+1]))
		case 44:
			length = 8
			if offset+length > len(raw) {
				return offset, first, false
			}
			first = binary.BigEndian.Uint16(raw[offset+2:])&0xfff8 == 0
		case 51:
			// RFC 4302 section 2.2, the length is in 4 byte units, less 2
			if offset+2 > len(raw) {
				return offset, first, false
			}
			length = 4 * (2 + int(raw[offset+1]))
		default:
			f.protocol = next
			return offset, first, true
		}
		if f.headerCount == traceHeaders || offset+length > len(raw) {
			f.protocol = next
			return offset, first, false
		}
		f.headers[f.headerCount] = tracedHeader(next)
		f.headerCount++
		next, offset = raw[offset], offset+length
	}
}
