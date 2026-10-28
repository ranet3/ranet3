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

	"ranet3.com/pkgs/ranet3/srv6"
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
// but a budget drop's, which follows the packet's forward record and is read from the packet as it was queued for its peer
type TraceRecord struct {
	Arrival TraceArrival
	// From is the ID of the peer whose session the packet arrived on, empty for any other arrival
	From     string
	Decision TraceDecision
	// Reason names why a packet was answered or dropped, as the transit counters name it, or budget, empty for any other decision
	Reason string
	// Next is the ID of the peer a forwarded packet goes to, or a packet its budget refused was to go to
	Next string
	// Segment is the first segment of a packet a policy steered, the next segment of one End forwarded
	// and the segment of this node's that egressed or dropped one
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

// sessionSite is a site of a packet the session to from delivered, nil for a packet of no session
func sessionSite(from *Peer, decision TraceDecision, reason transitReason) traceSite {
	site := traceSite{from: from, decision: decision, reason: reason}
	if from != nil {
		site.arrival = TraceArrivedSession
	}
	return site
}

// readSite is a site of a packet read off the tun
func readSite(decision TraceDecision, reason transitReason) traceSite {
	return traceSite{arrival: TraceArrivedTUN, decision: decision, reason: reason}
}

// answered is s for a packet answered with kind, the answer's fate outcome
func (s traceSite) answered(kind answerKind, outcome TraceOutcome) traceSite {
	s.decision, s.answer, s.outcome = TraceAnswer, kind, outcome
	return s
}

// forwardSite is s, a packet the forward path took toward next, as its reason, the fragments it was cut into and the fate of its answer say
func forwardSite(s traceSite, next *Peer, fragments int, outcome TraceOutcome) traceSite {
	switch {
	case s.reason == transitForwarded:
		s.decision, s.next, s.fragments = TraceForward, next, fragments
	case outcome != TraceNoAnswer:
		s = s.answered(answerTooBig, outcome)
	default:
		s.decision = TraceDrop
	}
	return s
}

// segmentSite is sessionSite for a packet one of this node's segments acted on, toward or at segment
func segmentSite(from *Peer, decision TraceDecision, reason transitReason, segment netip.Addr) traceSite {
	site := sessionSite(from, decision, reason)
	site.segment = segment
	return site
}

// endSite is the site of a packet End sent toward segment through next, cut into fragments where it was too big, and dropped where it was too big to cut
func endSite(from, next *Peer, segment netip.Addr, tooBig bool, fragments int) traceSite {
	if tooBig && fragments == 0 {
		return segmentSite(from, TraceDrop, transitTooBig, segment)
	}
	site := segmentSite(from, TraceForward, transitForwarded, segment)
	site.next, site.fragments = next, fragments
	return site
}

// segmentReason is the reason of a packet a segment of this node refused with err
func segmentReason(err error) transitReason {
	switch {
	case errors.Is(err, srv6.ErrHopLimit):
		return transitExpired
	case errors.Is(err, srv6.ErrSourceRefused):
		return transitRefused
	}
	return transitInvalid
}

// arrive copies packet to the end of arena before a segment of this node acts on it, and returns arena and the copy
// End rewrites a packet in place, and a forward or a drop it leads to is recorded as the packet arrived
// the copy is nil where no client could take such a record now, none whose filter's decision is any, forward or drop, whose prefixes and protocol take the packet
// and whose rate has room, as hold tests a forward it holds
// the peer is left to the record, since the route of the segment End writes decides it
// a segment of this node acts on an IPv6 packet alone
func (t *tracer) arrive(arena, packet []byte) ([]byte, []byte) {
	src, dst, version := addrsOfAny(packet)
	if version != 6 {
		return arena, nil
	}
	var protocol uint8
	parsed := false
	var now int64
	for _, c := range t.clients {
		if d := c.filter.Decision; d != TraceAny && d != TraceForward && d != TraceDrop || !within(c.filter.Sources, src) || !within(c.filter.Destinations, dst) {
			continue
		}
		if c.filter.Protocol != 0 {
			if !parsed {
				protocol, parsed = parseTraced(packet).protocol, true
			}
			if protocol != c.filter.Protocol {
				continue
			}
		}
		if now == 0 {
			now = t.now()
		}
		if !c.room(now) {
			continue
		}
		start := len(arena)
		arena = append(arena, packet...)
		return arena, arena[start:len(arena):len(arena)]
	}
	return arena, nil
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

// every site records through the methods below, each kept out of line, so the untraced path pays one branch a site
// and an untraced answer draws on the limits through takeICMPToken alone, as only a traced one draws through an answerDraw

// session records raw, a packet from's session delivered, decided as decision and reason say
//
//go:noinline
func (t *tracer) session(from *Peer, decision TraceDecision, reason transitReason, raw []byte) {
	t.record(sessionSite(from, decision, reason), raw)
}

// answered answers raw, one packet of version from's session delivered, with kind for reason as m.answer does, and records it with the answer's fate
// a site that answers calls it in place of m.answer, which draws through no answerDraw
//
//go:noinline
func (t *tracer) answered(m *Mesh, from *Peer, reason transitReason, kind answerKind, raw []byte, version byte) {
	var draw answerDraw
	fate := m.answerDrawn(raw, version, kind, 0, &draw)
	t.record(sessionSite(from, TraceAnswer, reason).answered(kind, fate), raw)
}

// beyondScope answers raw, a packet from's session delivered, as m.answerBeyondScope does, and records it with the answer's fate
//
//go:noinline
func (t *tracer) beyondScope(m *Mesh, from *Peer, raw []byte) {
	var draw answerDraw
	fate := draw.met(m.answerBeyondScope(raw, from, draw.take))
	t.record(sessionSite(from, TraceAnswer, transitMartian).answered(answerBeyondScope, fate), raw)
}

// holdForward holds raw in h, a packet from's session delivered that decide forwards toward next unless its options or forwardOne say otherwise
//
//go:noinline
func (t *tracer) holdForward(h *traceHold, from, next *Peer, raw []byte) {
	site := sessionSite(from, TraceForward, transitForwarded)
	site.next = next
	*h = t.hold(&site, false, nil, raw)
}

// releaseOptions releases h for a packet whose options dropped it for reason, the fate of the answer they drew outcome
//
//go:noinline
func (t *tracer) releaseOptions(h *traceHold, from *Peer, reason transitReason, outcome TraceOutcome) {
	site := sessionSite(from, TraceDrop, reason)
	if outcome != TraceNoAnswer {
		site = site.answered(answerParameter, outcome)
	}
	t.release(h, site)
}

// releaseForward releases h for a packet forwardOne took toward next, as its reason, fragments and the fate of its answer say
//
//go:noinline
func (t *tracer) releaseForward(h *traceHold, from, next *Peer, reason transitReason, fragments int, outcome TraceOutcome) {
	t.release(h, forwardSite(sessionSite(from, TraceForward, reason), next, fragments, outcome))
}

// read records raw, a packet read off the tun, decided as decision and reason say, toward segment where it is valid
//
//go:noinline
func (t *tracer) read(decision TraceDecision, reason transitReason, segment netip.Addr, raw []byte) {
	site := readSite(decision, reason)
	site.segment = segment
	t.record(site, raw)
}

// unroutedRead answers raw, a packet read off the tun, as m.answerUnroutedRead does, and records it with the answer's fate
//
//go:noinline
func (t *tracer) unroutedRead(m *Mesh, raw []byte, verdict Verdict, match Match, src, dst netip.Addr) {
	var draw answerDraw
	kind, fate := m.answerUnroutedRead(raw, verdict, match, src, dst, draw.take)
	reason := transitNoRoute
	if verdict == RouteHeld {
		reason = transitHeld
	}
	t.record(readSite(TraceAnswer, reason).answered(kind, draw.met(fate)), raw)
}

// tooBig takes sent, a read off the tun larger than mtu, the largest next's session carries, as m.tooBig does, and records raw, the read, as readSent says
// sent is raw behind the header a policy steered it with, or raw itself, and it reports the fragments queued for next and their bytes
//
//go:noinline
func (t *tracer) tooBig(m *Mesh, b *outboundBatch, raw, sent []byte, next *Peer, nextHeader byte, mtu int) (int, int) {
	var draw answerDraw
	count, bytes, kind, fate := m.tooBig(b, sent, len(sent)-len(raw), next, nextHeader, mtu, draw.take)
	t.readSent(raw, sent, next, true, count, kind, draw.met(fate))
	return count, bytes
}

// readSent records raw, a packet read off the tun that classify sent toward next as sent, cut into count fragments
// or, past next's session with count 0, dropped too big or answered with kind, the answer's fate outcome
// sent is raw behind the header a policy steered it with, whose destination is the first segment, or raw itself
//
//go:noinline
func (t *tracer) readSent(raw, sent []byte, next *Peer, tooBig bool, count int, kind answerKind, outcome TraceOutcome) {
	site := readSite(TraceForward, transitForwarded)
	site.next, site.fragments = next, count
	switch {
	case !tooBig || count != 0:
	case outcome != TraceNoAnswer && kind == answerParameter:
		site = readSite(TraceAnswer, transitInvalid).answered(kind, outcome)
	case outcome != TraceNoAnswer:
		site = readSite(TraceDrop, transitTooBig).answered(kind, outcome)
	default:
		site = readSite(TraceDrop, transitTooBig)
	}
	if len(sent) != len(raw) {
		_, site.segment, _, _ = addrsOf(sent)
	}
	t.record(site, raw)
}

// segmentRecords holds what the records of one batch the segments of this node act on read while a trace listens
type segmentRecords struct {
	trace *tracer
	// from is the peer of the session the batch came through, nil for packets of no session
	from *Peer
	// arena holds the copy arrive made of each forwarded segment and of the packet in hand, those of the forwarded ones its first kept bytes
	arena []byte
	kept  int
	// arrived is the packet in hand as it arrived, nil where arrive made no copy
	arrived []byte
	// arrivals holds, from the first forwarded segment arrive copied on, the copies in the order of the forwarded segments, nil for one it did not copy
	arrivals [][]byte
}

// actOnSegments is m.actOnSegments over act for a batch from's session delivered, recording what each packet met
// each packet is copied before act, since End rewrites it in place and a forward or drop it leads to is recorded as the packet arrived
//
//go:noinline
func (t *tracer) actOnSegments(m *Mesh, frames [][]byte, mtu int, from *Peer, act func([]byte) srv6.Result) ([][]byte, []bool) {
	r := segmentRecords{trace: t, from: from}
	return m.actOnSegments(frames, mtu, &r, func(packet []byte) srv6.Result {
		r.arena, r.arrived = t.arrive(r.arena[:r.kept], packet)
		return act(packet)
	})
}

// acted records raw, a packet of the batch, decided as decision and reason say
// at the segment whose step acted on acted, the packet as the step left it, whose destination names it
// raw nil is a packet arrive did not copy, which has no record
//
//go:noinline
func (r *segmentRecords) acted(decision TraceDecision, reason transitReason, acted, raw []byte) {
	if raw == nil {
		return
	}
	var segment netip.Addr
	if len(acted) >= 40 {
		segment = netip.AddrFrom16([16]byte(acted[24:40]))
	}
	r.trace.record(segmentSite(r.from, decision, reason, segment), raw)
}

// forwarded keeps the copy of the packet in hand, a forwarded segment behind before others, in arrivals sized for a batch of size packets
//
//go:noinline
func (r *segmentRecords) forwarded(before, size int) {
	if r.arrived != nil && r.arrivals == nil {
		r.arrivals = make([][]byte, before, size)
	}
	if r.arrivals != nil {
		r.arrivals, r.kept = append(r.arrivals, r.arrived), len(r.arena)
	}
}

// forwarding gives the copies, source and tracer forwardSegments records the batch's forwarded segments with, all nil for r nil
// and where no forwarded segment has a copy, since none then has a record
func (r *segmentRecords) forwarding() (arrived [][]byte, from *Peer, trace *tracer) {
	if r == nil || r.arrivals == nil {
		return nil, nil, nil
	}
	return r.arrivals, r.from, r.trace
}

// segmentAt records raw, a packet from's session delivered that End sent on, decided as decision and reason say, toward segment where it is valid
//
//go:noinline
func (t *tracer) segmentAt(from *Peer, decision TraceDecision, reason transitReason, segment netip.Addr, raw []byte) {
	t.record(segmentSite(from, decision, reason, segment), raw)
}

// end records raw, a packet from's session delivered that End sent toward segment through next, as endSite says
//
//go:noinline
func (t *tracer) end(from, next *Peer, segment netip.Addr, tooBig bool, fragments int, raw []byte) {
	t.record(endSite(from, next, segment, tooBig, fragments), raw)
}

// refusedSegments records each segment and fragment of peer's share, which its budget refused, dropped for budget
// each as it was queued, for the clients whose filter selects the packet as its forward record showed it, as it arrived
// arrived holds that packet for each segment and cutArrived for each fragment, nil where no filter takes it
//
//go:noinline
func (t *tracer) refusedSegments(segments []forwardedSegment, arrived [][]byte, cut *fragmentList, cutArrived [][]byte, from, peer *Peer) {
	site := sessionSite(from, TraceDrop, traceBudget)
	site.next = peer
	for i, segment := range segments {
		if segment.peer == peer && arrived[i] != nil {
			t.recordAs(site, arrived[i], segment.raw)
		}
	}
	for i, fragment := range cut.fragments {
		if fragment.peer == peer && cutArrived[i] != nil {
			t.recordAs(site, cutArrived[i], fragment.raw)
		}
	}
}

// refused records each packet and fragment of peer's share of b, which its budget refused, dropped for budget
// each as it was queued, for the clients whose filter selects the packet as its forward record showed it
//
//go:noinline
func (t *tracer) refused(b *outboundBatch, peer *Peer) {
	site := sessionSite(b.from, TraceDrop, traceBudget)
	if b.tun {
		site = readSite(TraceDrop, traceBudget)
	}
	site.next = peer
	if !t.selects(&site) {
		return
	}
	for i := range b.n {
		if b.peers[i] == peer {
			t.recordAs(site, b.steeredRead(b.packets[i]), b.packets[i])
		}
	}
	for _, fragment := range b.cut.fragments {
		if fragment.peer == peer {
			t.recordAs(site, b.steeredRead(fragment.raw), fragment.raw)
		}
	}
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

// selects reports a client whose filter selects what the decision did, as site says, before any test of the packet
func (t *tracer) selects(site *traceSite) bool {
	for _, c := range t.clients {
		if c.selects(site) {
			return true
		}
	}
	return false
}

// steeredRead is the read a policy steered that queued, one of b's packets or fragments, carries behind its routing header, which its forward record showed
// and nil for a packet whose addresses and protocol, which the filter reads, are those its forward record showed
// a tun read carrying a segment routing header of its own is dropped before it is queued, so a tun batch's packet that carries one was steered
func (b *outboundBatch) steeredRead(queued []byte) []byte {
	if !b.tun {
		return nil
	}
	if offset, ok := carriedPacket(queued); ok {
		return queued[offset:]
	}
	return nil
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
	if site.next != nil {
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
// each header's length is srv6.StepExtension's, the one the segments and the edge walk by
// first is false behind a fragment header whose offset is not 0, and ok false where a header runs past raw or the walk past traceHeaders
// the protocol is the header the walk stopped at
func (f *traceFields) walkExtensions(raw []byte) (offset int, first, ok bool) {
	next, offset, first := raw[6], 40, true
	for {
		switch next {
		case 0, 43, 44, 51, 60:
		default:
			f.protocol = next
			return offset, first, true
		}
		following, end, ok := srv6.StepExtension(raw, next, offset)
		if !ok || end > len(raw) || f.headerCount == traceHeaders {
			f.protocol = next
			return offset, first, false
		}
		if next == 44 {
			first = binary.BigEndian.Uint16(raw[offset+2:])&0xfff8 == 0
		}
		f.headers[f.headerCount] = tracedHeader(next)
		f.headerCount++
		next, offset = following, end
	}
}
