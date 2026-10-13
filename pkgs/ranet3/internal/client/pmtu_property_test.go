// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package client

import (
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/esp"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/pbt"
)

const (
	// searchSteps is the most events one case drives the search through before it lets it settle
	searchSteps = 60
	// settleSteps bounds the events a search takes to settle once nothing more is drawn
	settleSteps = 10000
	// modelMaxProbes is RFC 8899's MAX_PROBES, and the model never drops that many attempts in a row of a size the path carries
	modelMaxProbes = 3
	// widest is the largest link.mtu a case draws and the most a route exceeds what its path carries by, past a jumbo path
	widest = 9000
	// narrowest is the smallest wire MTU a path draws, under the floor in either family
	narrowest = 1300
)

// the moves a case draws
const (
	stepTimer = iota
	stepAck
	stepReport
	stepMove
	stepReconfirm
	stepRelink
	stepRaise
	stepLate
	searchMoves
)

var searchMoveNames = []string{"timer", "ack", "report", "move", "reconfirm", "relink", "raise", "late"}

// searchModel runs a search against a path of a known wire MTU and plays the driver's part
// the path carries an attempt whose sealed datagram fits the wire MTU, and drops one that does not
// it also drops one it carries at random, though never modelMaxProbes attempts of one probe in a row
type searchModel struct {
	ht  *hegel.T
	s   pathSearch
	now time.Time
	// wire is the largest outer IP packet the path to the endpoint carries, and header its family's outer IP header
	wire, header int
	// route is the largest inner packet the host's route lets through, which a forged report lowers under what the path carries
	route, link int
	// pending is the nonces of the attempts the path carried, whose Acks are on their way
	pending []uint16
	// late is the nonces of Acks the path holds past their probe's timeout
	// and of Acks it delivers a second time
	late []uint16
	// drops counts the attempts in a row the path dropped of the probe out
	// an attempt whose Ack the path holds past the timeout counts among them
	drops int
	// settling stops the random drops and refusals, leaving the search to meet only what the path cannot carry
	settling bool
}

// carries is the largest inner packet the path carries in one datagram
func (m *searchModel) carries() int { return esp.Inner(m.wire, m.header) }

// flush plays the driver after a search event and sends the attempt the search put out
// the speaker refuses one at random, which the search takes back
func (m *searchModel) flush() {
	if !m.s.send {
		return
	}
	m.s.send = false
	if !m.settling && hegel.Draw(m.ht, hegel.WeightedBooleans(1.0/10)) {
		m.s.unsent(m.now)
		return
	}
	if m.s.probe.attempts == 1 {
		m.drops = 0
	}
	fits := m.s.probe.size <= m.carries()
	if fits && (m.settling || m.drops == modelMaxProbes-1 || !hegel.Draw(m.ht, hegel.WeightedBooleans(1.0/3))) {
		m.pending = append(m.pending, m.s.nonce)
		return
	}
	// the path carries some of the attempts it seems to drop
	// their Acks arrive past the probe timeout
	if fits && hegel.Draw(m.ht, hegel.Booleans()) {
		m.late = append(m.late, m.s.nonce)
	}
	m.drops++
}

// deliver hands the search every Ack on its way, which arrives within a probe timeout of its attempt
// the path delivers one a second time at random, later
func (m *searchModel) deliver() {
	for len(m.pending) != 0 {
		nonce := m.pending[0]
		m.pending = m.pending[1:]
		m.s.acked(nonce, m.now)
		if !m.settling && hegel.Draw(m.ht, hegel.WeightedBooleans(1.0/10)) {
			m.late = append(m.late, nonce)
		}
		m.flush()
	}
}

// deliverLate hands the search the Acks the path held past their probe's timeout
// and the ones it delivers a second time
func (m *searchModel) deliverLate() {
	for len(m.late) != 0 {
		nonce := m.late[0]
		m.late = m.late[1:]
		m.s.acked(nonce, m.now)
		m.flush()
	}
}

// fire moves the clock to at least when the search next has something to do and runs its timer
func (m *searchModel) fire(at time.Time, flowed bool) {
	m.deliver()
	if at.After(m.now) {
		m.now = at
	}
	m.s.timer(m.now, flowed, func() int { return m.route })
	m.flush()
}

func drawFamily(ht *hegel.T) int {
	if hegel.Draw(ht, hegel.Booleans()) {
		return 40
	}
	return 20
}

// drawWire draws a path's wire MTU under a family's outer header, the floor's own and the one under it outright
func drawWire(ht *hegel.T, header int) int {
	// a wire MTU of header + 40 + 1284 carries the floor's class in one datagram, and one less does not
	exact := header + 40 + 4*class(floor)
	switch hegel.Draw(ht, pbt.Spanning(0, 3)) {
	case 0:
		return exact
	case 1:
		return exact - 1
	case 2:
		return hegel.Draw(ht, pbt.Spanning(narrowest, header+40+netstack.DefaultMTU))
	}
	return hegel.Draw(ht, pbt.Spanning(narrowest, header+40+widest))
}

// drawRoute draws the largest inner packet the host's route to a path carrying inner lets through, unbounded or wider by a drawn margin
func drawRoute(ht *hegel.T, inner int) int {
	if hegel.Draw(ht, hegel.Booleans()) {
		return math.MaxInt
	}
	return inner + hegel.Draw(ht, pbt.Spanning(0, widest))
}

// problem names the first rule the search breaks after a move, or nothing
func (m *searchModel) problem(move int, before pathSearch) string {
	s := &m.s
	switch {
	case s.budget < floor || s.budget > m.link:
		return fmt.Sprintf("the budget %d left the floor %d to link.mtu %d", s.budget, floor, m.link)
	case move == stepReport && s.budget > before.budget:
		return fmt.Sprintf("a report raised the budget from %d to %d", before.budget, s.budget)
	case s.lost != 0 && s.budget != floor && class(s.budget) >= s.lost:
		return fmt.Sprintf("the budget %d stands on class %d, which the path lost", s.budget, s.lost)
	case s.phase != confirming && s.budget > max(floor, m.carries()):
		return fmt.Sprintf("the budget %d outside a confirmation is past the %d the path carries", s.budget, m.carries())
	case s.phase != confirmed && s.phase != underFloor && s.probe.size == 0:
		return fmt.Sprintf("the search stands in phase %d at %d with no probe out to move it", s.phase, s.budget)
	case s.phase == underFloor && s.probe.size != 0:
		return fmt.Sprintf("the search under the floor holds a probe of %d", s.probe.size)
	case move != stepMove:
		return ""
	}
	target := min(m.link, m.route)
	if target < floor {
		if s.phase != underFloor || s.budget != floor {
			return fmt.Sprintf("a move to a route of %d left the search in phase %d at %d, want it under the floor", m.route, s.phase, s.budget)
		}
		return ""
	}
	if want := min(target, netstack.DefaultMTU); s.phase != confirming || s.budget != want || s.probe.size != want {
		return fmt.Sprintf("a move left the search in phase %d at %d probing %d, want it confirming its start of %d", s.phase, s.budget, s.probe.size, want)
	}
	return ""
}

// a search driven through drawn losses and refusals of its probes, path reports some of them forged, endpoint changes, reloads and timers
// and through Acks that arrive past their probe's timeout or a second time, after the search moved on
// keeps its budget from the floor to link.mtu, never lets a report raise it and never stands on a size the path lost
// and outside the confirmation of a budget holds none past what the path carries
// it holds a probe out whenever it is neither settled nor under the floor
// under the floor it holds none
// an endpoint change restarts it, confirming min(target, DefaultMTU) or under the floor
// once nothing more is drawn it settles on what the path, the route and link.mtu all carry, to the 4 byte grain, or under the floor where that is less
// a reload that then lowers link.mtu to the floor breaks none of these rules
func TestPathSearchSettlesOnWhatThePathCarries(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		m := &searchModel{ht: ht, now: time.Unix(0, 0), link: hegel.Draw(ht, pbt.Spanning(floor, widest))}
		m.header = drawFamily(ht)
		m.wire = drawWire(ht, m.header)
		m.route = drawRoute(ht, m.carries())
		m.s = newPathSearch(m.link, m.route, defaultProbeTimeout, confirmInterval, m.now)
		m.flush()
		var done []string
		for range hegel.Draw(ht, pbt.Spanning(1, searchSteps)) {
			move := hegel.Draw(ht, pbt.Spanning(0, searchMoves-1))
			done = append(done, searchMoveNames[move])
			before := m.s
			switch move {
			case stepTimer:
				m.fire(m.s.deadline(), hegel.Draw(ht, hegel.Booleans()))
			case stepAck:
				m.deliver()
			case stepReport:
				route := esp.Inner(drawWire(ht, m.header), m.header)
				m.route = min(m.route, route)
				m.s.lowered(route, movedByRefusal, m.now)
				m.flush()
			case stepMove:
				m.header = drawFamily(ht)
				m.wire = drawWire(ht, m.header)
				m.route, m.pending = drawRoute(ht, m.carries()), nil
				m.s.moved(m.route, m.now)
				m.flush()
			case stepReconfirm:
				m.s.reconfirm(m.route, m.now)
				m.flush()
			case stepRelink:
				m.link = hegel.Draw(ht, pbt.Spanning(floor, widest))
				m.s.relinked(m.link, m.now)
				m.flush()
			case stepRaise:
				m.fire(m.s.raise, false)
			case stepLate:
				m.deliverLate()
			}
			if problem := m.problem(move, before); problem != "" {
				ht.Fatalf("after %s: %s", strings.Join(done, ", "), problem)
			}
		}
		m.settling = true
		for range settleSteps {
			if m.s.probe.size == 0 && (m.s.phase == confirmed || m.s.phase == underFloor) {
				break
			}
			m.fire(m.s.deadline(), false)
			if problem := m.problem(stepTimer, m.s); problem != "" {
				ht.Fatalf("after %s and settling: %s", strings.Join(done, ", "), problem)
			}
		}
		want := min(m.link, m.route, m.carries())
		switch {
		case want < floor && m.s.phase != underFloor:
			ht.Fatalf("after %s: the search settled in phase %d at %d, want it under the floor on a path carrying %d", strings.Join(done, ", "), m.s.phase, m.s.budget, want)
		case want >= floor && (m.s.phase != confirmed || m.s.budget != want):
			ht.Fatalf("after %s: the search settled in phase %d at %d, want it confirmed at %d", strings.Join(done, ", "), m.s.phase, m.s.budget, want)
		}
		// the floor is no wider than any link.mtu a case draws
		// a reload that draws nothing keeps the cases the engine draws as they were
		before := m.s
		m.link = floor
		m.s.relinked(m.link, m.now)
		m.flush()
		if problem := m.problem(stepRelink, before); problem != "" {
			ht.Fatalf("after %s, settling and a reload of link.mtu %d: %s", strings.Join(done, ", "), floor, problem)
		}
	})
}
