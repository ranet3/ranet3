// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"errors"
	"log"
	"log/slog"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"ranet3.com/pkgs/ranet3/esp"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/srv6"
	"ranet3.com/pkgs/ranet3/transport"
)

// floor is the least budget a session carries, the IPv6 minimum MTU
// a path too narrow for it in one datagram carries it in outer fragments
const floor = srv6.MinimumIPv6MTU

// why a session's budget moved, as pmtu.changed names it
const (
	movedByProbe    = "probe"
	movedByRoute    = "route"
	movedByRefusal  = "refusal"
	movedByEndpoint = "endpoint change"
	movedByFloor    = "floor"
	movedByLink     = "link.mtu"
)

// class numbers the inner sizes that seal to one datagram length
// ESP pads the plaintext and its two trailer octets to a multiple of 4, so sizes 4k-5 to 4k-2 are class k
func class(size int) int { return (size + 5) / 4 }

// top is the largest inner size of class k
func top(k int) int { return 4*k - 2 }

// searchPhase is where a session's search of its path MTU stands
type searchPhase int

const (
	// confirming has a probe of the budget out, the start or a target that just lowered, before it trusts it
	confirming searchPhase = iota
	// searchingUp probes between the largest class the path carried and the target
	// the budget stands on the largest class carried
	// no branch of the search tells it from searchingDown
	// the debug pmtu view is the reader that tells the two apart
	searchingUp
	// searchingDown probes under a size the budget stood on and the path lost
	// the budget stands at the floor until the path carries more
	// no branch of the search tells it from searchingUp
	// the debug pmtu view is the reader that tells the two apart
	searchingDown
	// confirmed holds the budget, confirms it every confirmInterval while data flows and searches up after raiseInterval
	confirmed
	// underFloor carries the floor in outer fragments, on a path too narrow for it in one datagram
	underFloor
)

// pathSearch is one session's search of its path MTU, RFC 8899's datagram PLPMTUD over Babel probes
// it decides the budget, the largest inner packet the session carries, and the probes to send
// sizes are inner packet sizes and the search moves by class, the grain ESP's padding leaves
type pathSearch struct {
	// link is link.mtu, and route the largest inner packet the host's route to the endpoint lets through
	link, route int
	budget      int
	phase       searchPhase
	// why is the reason the budget last moved
	why string
	// lo is the largest class the path carried, and lost the least class it lost maxProbes probes of in a row, zero for none
	lo, lost int
	probe    pathProbe
	// nonce is the last nonce an attempt took
	nonce uint16
	// send says an attempt of the probe waits to go out
	send bool
	// tick is when a confirmed search next confirms its budget, and raise when it next reads the route and searches up
	tick, raise time.Time
	// flowed says the session sent data since the last confirmation
	flowed bool
	// timeout is how long an attempt waits for its Ack, and interval how often a settled search confirms its budget
	timeout, interval time.Duration
	tally             probeTally
	// last is the last attempt an Ack answered or whose wait ran out
	last probeOutcome
}

// probeTally counts a search's attempts that left, those an Ack answered and those whose wait ran out
type probeTally struct{ sent, acked, lost uint64 }

// pathProbe is the probe a search has out
type pathProbe struct {
	// size is zero while none is out
	size int
	// attempts counts its attempts
	// they hold the search's last attempts nonces
	attempts int
	// until is when its last attempt counts as lost
	until time.Time
	// out says its last attempt left
	out bool
}

// probeOutcome is how one attempt ended
type probeOutcome struct {
	size  int
	acked bool
	at    time.Time
}

// newPathSearch starts the search of a session's path
// link is link.mtu, and route what the host's route to the endpoint lets through
func newPathSearch(link, route int, timeout, interval time.Duration, now time.Time) pathSearch {
	s := pathSearch{link: link, timeout: timeout, interval: interval}
	s.restart(route, "", now)
	return s
}

func (s *pathSearch) target() int { return min(s.link, s.route) }

// carried is the budget the largest class the path carried allows, the floor while it carried none at or above it
func (s *pathSearch) carried() int { return max(floor, min(top(s.lo), s.target())) }

func (s *pathSearch) set(budget int, why string) {
	if budget != s.budget {
		s.budget, s.why = budget, why
	}
}

// restart searches a path from the start, at min(target, DefaultMTU) while the first probe is out
func (s *pathSearch) restart(route int, why string, now time.Time) {
	s.route, s.lo, s.lost = route, class(floor)-1, 0
	if s.target() < floor {
		s.enterFloor(now)
		return
	}
	s.confirm(min(s.target(), netstack.DefaultMTU), why, now)
}

// moved restarts the search on the path to an endpoint the session moved to
func (s *pathSearch) moved(route int, now time.Time) {
	s.restart(route, movedByEndpoint, now)
}

// confirm moves the budget to size and probes it before the search goes on
func (s *pathSearch) confirm(size int, why string, now time.Time) {
	s.phase = confirming
	s.set(size, why)
	s.start(size, now)
}

// start puts a fresh probe of size out
func (s *pathSearch) start(size int, now time.Time) {
	s.probe = pathProbe{size: size}
	s.attempt(now)
}

// attempt sends the probe once more under a nonce of its own
func (s *pathSearch) attempt(now time.Time) {
	s.nonce++
	s.probe.attempts++
	s.probe.until = now.Add(s.timeout)
	s.probe.out = false
	s.send = true
}

// expired counts an attempt whose wait ran out as lost, where it left
func (s *pathSearch) expired(now time.Time) {
	if s.probe.out {
		s.tally.lost++
		s.last = probeOutcome{size: s.probe.size, at: now}
	}
}

// unsent takes back an attempt that never left, which goes again a probe timeout later
func (s *pathSearch) unsent(now time.Time) {
	s.nonce--
	s.probe.attempts--
	s.probe.until = now.Add(s.timeout)
}

// acked takes the Ack of nonce
// it counts for the probe out when nonce is among the last attempts nonces taken
// the distance back from the last nonce is taken in uint16
// an Ack of a nonce from before the wrap past 65535 therefore still counts
func (s *pathSearch) acked(nonce uint16, now time.Time) {
	if s.probe.size == 0 || s.nonce-nonce >= uint16(s.probe.attempts) {
		return
	}
	size := s.probe.size
	s.probe = pathProbe{}
	s.tally.acked++
	s.last = probeOutcome{size: size, acked: true, at: now}
	if s.phase == confirmed {
		return
	}
	if s.phase == confirming {
		s.phase = searchingUp
	}
	s.lo = max(s.lo, class(size))
	s.set(s.carried(), movedByProbe)
	s.next(now)
}

// lostProbe takes a size that lost maxProbes probes in a row
// a size the budget stood on going sends the search down from the floor, with the budget at the floor while it searches
func (s *pathSearch) lostProbe(now time.Time) {
	lost := class(s.probe.size)
	s.probe = pathProbe{}
	if s.phase == confirming || s.phase == confirmed {
		s.lo, s.phase = class(floor)-1, searchingDown
		s.set(floor, movedByProbe)
	}
	s.lost = lost
	s.next(now)
}

// next probes halfway between the largest class the path carried and the least it cannot, and settles where they meet
func (s *pathSearch) next(now time.Time) {
	hi := class(s.target()) + 1
	if s.lost != 0 {
		hi = min(hi, s.lost)
	}
	switch {
	case hi-s.lo > 1:
		s.start(min(top((s.lo+hi)/2), s.target()), now)
	case s.lo < class(floor):
		s.enterFloor(now)
	default:
		s.phase, s.flowed = confirmed, false
		s.tick, s.raise = now.Add(s.interval), now.Add(raiseInterval)
	}
}

// enterFloor carries the floor in outer fragments, on a path too narrow for it, and reads the route again after raiseInterval
func (s *pathSearch) enterFloor(now time.Time) {
	s.phase, s.probe, s.send = underFloor, pathProbe{}, false
	s.lo, s.lost = class(floor)-1, 0
	s.set(floor, movedByFloor)
	s.raise = now.Add(raiseInterval)
}

// timer runs what fell due by now
// flowed says the session sent data since the last call, and route reads the host's route afresh for a raise
func (s *pathSearch) timer(now time.Time, flowed bool, route func() int) {
	s.flowed = s.flowed || flowed
	switch {
	case s.probe.size != 0 && now.Before(s.probe.until):
	case s.probe.size != 0 && s.probe.attempts < maxProbes:
		s.expired(now)
		s.attempt(now)
	case s.probe.size != 0:
		s.expired(now)
		s.lostProbe(now)
	case (s.phase == confirmed || s.phase == underFloor) && !now.Before(s.raise):
		s.raised(route(), now)
	case s.phase == confirmed && !now.Before(s.tick):
		s.tick = now.Add(s.interval)
		if s.flowed {
			s.flowed = false
			s.start(s.budget, now)
		}
	}
}

// deadline is when the search next has something to do
func (s *pathSearch) deadline() time.Time {
	switch {
	case s.probe.size != 0:
		return s.probe.until
	case s.phase == confirmed && s.tick.Before(s.raise):
		return s.tick
	}
	return s.raise
}

// raised searches up from a route read afresh, which may have widened, with no lost size remembered
// a narrower route takes lo down to its class
// the next raise then searches up again once the route widens
// a path under the floor leaves it once its route carries the floor, probing the floor first
func (s *pathSearch) raised(route int, now time.Time) {
	s.route, s.lost = route, 0
	s.lo = min(s.lo, class(s.target()))
	switch {
	case s.target() < floor:
		s.enterFloor(now)
	case s.phase == underFloor:
		s.confirm(floor, movedByRoute, now)
	case s.budget > s.target():
		s.confirm(s.target(), movedByRoute, now)
	default:
		s.phase = searchingUp
		s.next(now)
	}
}

// lowered takes a narrower route, from a refusal the path reported or from the route read afresh, and never a wider one
// a budget past the new target drops to it at once and is confirmed there
func (s *pathSearch) lowered(route int, why string, now time.Time) {
	if route >= s.route || s.phase == underFloor {
		return
	}
	s.route = route
	if s.target() < floor {
		s.enterFloor(now)
		return
	}
	s.lo = min(s.lo, class(s.target()))
	if s.probe.size > s.target() {
		s.probe, s.send = pathProbe{}, false
	}
	switch {
	case s.budget > s.target():
		s.confirm(s.target(), why, now)
	case s.probe.size == 0 && s.phase != confirmed:
		s.next(now)
	}
}

// reconfirm probes the budget at once with the route read afresh, after the host's network changed or an operator asked
// the route only lowers the target here, and a path under the floor leaves it once its route carries the floor
func (s *pathSearch) reconfirm(route int, now time.Time) {
	if s.phase == underFloor {
		s.raised(route, now)
		return
	}
	s.lowered(route, movedByRoute, now)
	if s.phase == confirmed && s.probe.size == 0 {
		s.start(s.budget, now)
	}
}

// relinked takes the link.mtu a reload stored
// a lower one drops the budget past it at once, and a higher one sends a confirmed search up toward the new target
func (s *pathSearch) relinked(link int, now time.Time) {
	wider := link > s.link
	s.link = link
	switch {
	case s.phase == underFloor:
		return
	case wider && s.phase == confirmed:
		s.phase = searchingUp
		s.set(s.carried(), movedByLink)
		s.next(now)
		return
	case wider:
		return
	}
	// a lower link.mtu voids what the path carried past it
	// a later raise of link.mtu then probes past it before the budget moves there
	s.lo = min(s.lo, class(s.target()))
	if s.probe.size > s.target() {
		s.probe, s.send = pathProbe{}, false
	}
	switch {
	case s.phase == confirming && s.probe.size == 0:
		s.confirm(s.target(), movedByLink, now)
	case s.budget > s.target():
		s.set(s.target(), movedByLink)
	}
	if s.probe.size == 0 && s.phase != confirmed {
		s.next(now)
	}
}

// pathDriver runs one session's search on the session's goroutine and owns the session's budget
// the transmit's path reports, the speaker's Acks, a reload's sweep and IKE's endpoint changes reach it through its inbox
type pathDriver struct {
	mux    *transport.Mux
	peer   *netstack.Peer
	probe  func(peer *netstack.Peer, size int, nonce uint16) error
	events *events.Bus
	totals *probeTotals
	// steering is the node's steering table, whose longest segment list a steered 1280-byte packet carries
	steering func() *srv6.SteerTable
	// searching is false where the mux sends without DF, and the budget is then link.mtu
	searching bool
	// mu guards search, endpoint, refusals and changed, which the session's goroutine writes and the debug view reads
	mu     sync.Mutex
	search pathSearch
	// endpoint is the endpoint the search measures, and a report for another one is about a path the session left
	endpoint transport.Endpoint
	// refusals counts the path reports of sends the host refused on the way to endpoint
	refusals uint64
	// changed is the session's last budget change, zero before the first
	changed budgetChange
	// steeredShort says the budget is under what a steered 1280-byte packet needs
	steeredShort bool
	// timeout and interval are the search's, how long a probe waits for its Ack and how often a settled search confirms its budget
	timeout, interval time.Duration
	acks              chan uint16
	reports           chan *transport.PathMTUError
	nudges            chan struct{}
	// link is a link.mtu a reload stored that the search has not taken yet, zero for none
	link atomic.Int64
	// moved and reconfirm are an endpoint change and a confirmation the search has not taken yet
	moved, reconfirm atomic.Bool
}

// budgetChange is one move of a session's budget
type budgetChange struct {
	from, to int
	why      string
	at       time.Time
}

// probeTotals counts the probe attempts of every session, acked and lost
type probeTotals struct{ acked, lost atomic.Uint64 }

// newPathDriver is the driver of the search for the session on mux
// the caller sets its peer before open
// probe sends a probe through the session
// totals counts its attempts with every other session's
// steering reads the node's steering table
// timeout is how long one waits for its Ack
// interval is how often a settled search confirms its budget
func newPathDriver(mux *transport.Mux, probe func(peer *netstack.Peer, size int, nonce uint16) error, bus *events.Bus, totals *probeTotals, steering func() *srv6.SteerTable, timeout, interval time.Duration) *pathDriver {
	return &pathDriver{mux: mux, probe: probe, events: bus, totals: totals, steering: steering, timeout: timeout, interval: interval,
		acks: make(chan uint16, maxProbes), reports: make(chan *transport.PathMTUError, 1), nudges: make(chan struct{}, 1)}
}

// transmit is the peer's transmit, which hands a path report to the search
func (d *pathDriver) transmit(packets [][]byte) error {
	err := d.mux.SendESPBatch(packets)
	if err == nil {
		return nil
	}
	if report, ok := errors.AsType[*transport.PathMTUError](err); ok {
		select {
		case d.reports <- report:
		default:
		}
	}
	return err
}

// inner is the largest inner packet a path of mtu carries to the endpoint, unbounded where the read failed
func (d *pathDriver) inner(mtu int, err error) int {
	if err != nil {
		return math.MaxInt
	}
	header := 40
	if d.endpoint.AddrPort().Addr().Is4() {
		header = 20
	}
	return esp.Inner(mtu, header)
}

func (d *pathDriver) reread() int { return d.inner(d.mux.PathMTU()) }

// open reads the endpoint the search measures and the largest inner packet its route lets through
// it runs before the session is adopted, which keeps the syscall out of the set's lock
func (d *pathDriver) open() int {
	d.endpoint = d.mux.Endpoint()
	mtu, err := d.mux.PathMTU()
	d.searching = !errors.Is(err, errors.ErrUnsupported)
	return d.inner(mtu, err)
}

// start sets the session's first budget from link and the route open read
// it runs under the set's lock, so a reload's sweep either finds the session or stored the link.mtu it reads
func (d *pathDriver) start(link, route int) {
	if !d.searching {
		d.peer.SetMTU(link)
		return
	}
	d.search = newPathSearch(link, route, d.timeout, d.interval, time.Now())
	d.peer.SetMTU(d.search.budget)
}

// serve runs the search until one of the session's two halves ends, and returns how it ended
func (d *pathDriver) serve(results <-chan sessionResult) sessionResult {
	if !d.searching {
		return <-results
	}
	now := time.Now()
	d.mu.Lock()
	timer := time.NewTimer(d.search.deadline().Sub(now))
	defer timer.Stop()
	// the start carries the session's first budget, which no event reports
	d.apply(pathSearch{phase: confirming, budget: d.search.budget}, now, timer)
	d.mu.Unlock()
	for {
		var event func(now time.Time)
		select {
		case result := <-results:
			return result
		case nonce := <-d.acks:
			event = func(now time.Time) { d.search.acked(nonce, now) }
		case report := <-d.reports:
			event = func(now time.Time) {
				if report.Endpoint == d.endpoint {
					d.refusals++
					d.search.lowered(d.inner(report.MTU, nil), movedByRefusal, now)
				}
			}
		case <-d.nudges:
			event = d.nudged
		case <-timer.C:
			event = func(now time.Time) { d.search.timer(now, d.peer.TakeSent(), d.reread) }
		}
		d.mu.Lock()
		before, now := d.search, time.Now()
		event(now)
		d.apply(before, now, timer)
		d.mu.Unlock()
	}
}

// nudged takes what a reload, IKE or a confirmation asked for since the last nudge
func (d *pathDriver) nudged(now time.Time) {
	if link := d.link.Swap(0); link != 0 {
		d.search.relinked(int(link), now)
	}
	if d.moved.Swap(false) {
		if ep := d.mux.Endpoint(); ep != d.endpoint {
			d.endpoint = ep
			d.search.moved(d.reread(), now)
		}
	}
	if d.reconfirm.Swap(false) {
		d.search.reconfirm(d.reread(), now)
	}
}

// apply carries out an event's changes to the outer fragmenting, the budget, the probe to send and the timer
func (d *pathDriver) apply(before pathSearch, now time.Time, timer *time.Timer) {
	s := &d.search
	under := s.phase == underFloor
	// before the budget moves, so a datagram of the floor never meets a refusal
	// and on every event under the floor, which hands the fragmenting to an endpoint the session moved to
	if under || before.phase == underFloor {
		if err := d.mux.Fragment(under); err != nil {
			log.Printf("peer %s: fragmenting the sends of a path under the floor %v: %v", d.peer.ID, under, err)
		}
	}
	if under != (before.phase == underFloor) {
		d.events.Emit("pmtu.floor", d.peer.ID, slog.String("endpoint", d.endpoint.String()), slog.Bool("under", under))
	}
	if s.budget != before.budget {
		d.peer.SetMTU(s.budget)
		d.events.Emit("pmtu.changed", d.peer.ID, slog.String("endpoint", d.endpoint.String()),
			slog.Int("budget", s.budget), slog.Int("budget_was", before.budget), slog.String("reason", s.why))
		d.changed = budgetChange{from: before.budget, to: s.budget, why: s.why, at: now}
	}
	// a node that steers nothing needs the floor, which no budget falls under
	// a search confirming or climbing has not found what its path carries, so a fall waits while it confirms or climbs and a rise while it confirms
	// a family sending without DF holds its searches, and the budget a held search stands on is then what it carries
	need := d.steering().LeastMTU()
	settled := s.phase != confirming && s.phase != searchingUp || !d.mux.DontFragment()
	if short := s.budget < need; short != d.steeredShort && (settled || !short && s.phase != confirming) {
		d.steeredShort = !d.steeredShort
		if d.steeredShort {
			slog.Warn("a session's budget fell under what a steered 1280-byte packet needs", "peer", d.peer.ID, "budget", s.budget, "need", need)
		} else {
			slog.Info("a session's budget rose back to what a steered 1280-byte packet needs", "peer", d.peer.ID, "budget", s.budget, "need", need)
		}
		d.events.Emit("pmtu.steering", d.peer.ID, slog.Int("budget", s.budget), slog.Int("need", need), slog.Bool("under", d.steeredShort))
	}
	if s.send {
		s.send = false
		// a probe a fragmenting family carries measures nothing, and it waits for the family to send with DF again
		if !d.mux.DontFragment() || d.probe(d.peer, s.probe.size, s.nonce) != nil {
			s.unsent(now)
		} else {
			s.probe.out = true
			s.tally.sent++
		}
	}
	d.totals.acked.Add(s.tally.acked - before.tally.acked)
	d.totals.lost.Add(s.tally.lost - before.tally.lost)
	timer.Reset(s.deadline().Sub(now))
}

// ack hands the search an Ack the speaker heard through the session, and drops it while the inbox is full
func (d *pathDriver) ack(nonce uint16) {
	select {
	case d.acks <- nonce:
	default:
	}
}

// relink hands the session the link.mtu a reload stored, under the set's lock
func (d *pathDriver) relink(link int) {
	if !d.searching {
		d.peer.SetMTU(link)
		return
	}
	d.link.Store(int64(link))
	d.nudge()
}

// move tells the search IKE moved the session to another endpoint
func (d *pathDriver) move() {
	d.moved.Store(true)
	d.nudge()
}

// confirmNow asks the search to probe its budget at once
func (d *pathDriver) confirmNow() {
	d.reconfirm.Store(true)
	d.nudge()
}

func (d *pathDriver) nudge() {
	select {
	case d.nudges <- struct{}{}:
	default:
	}
}
