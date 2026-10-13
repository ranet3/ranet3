// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package client

import (
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/esp"
	"ranet3.com/pkgs/ranet3/ike"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/transport"
)

const (
	// pathWait is how long a test waits for a search to reach the budget it expects
	pathWait = 30 * time.Second
	// driverProbeTimeout is the probe timeout of a search under test, short to make a lost size cost little
	driverProbeTimeout = 50 * time.Millisecond
	// heldFor is how long a test watches a held search do nothing, several probe timeouts
	heldFor = 10 * driverProbeTimeout
)

// pathRig is a search running on a mux of a loopback hub, whose probes the path answers up to a size
type pathRig struct {
	driver *pathDriver
	mux    *transport.Mux
	bus    *events.Bus
	// probes counts the probes the search sent
	probes atomic.Int32
}

func loopbackHub(t *testing.T) *transport.Hub {
	t.Helper()
	hub, err := transport.NewHub(":0", transport.Underlay{}, transport.Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	return hub
}

// newPathRig starts a search at link.mtu link for a session to the endpoint at to, on a path that carries probes of up to carries bytes
// route is the largest inner packet the start reads the route to let through
// it is math.MaxInt for a route wider than link.mtu
func newPathRig(t *testing.T, hub *transport.Hub, to string, link, route, carries int) *pathRig {
	t.Helper()
	address := netip.MustParseAddrPort(to)
	mux, err := hub.NewMux(net.IP(address.Addr().AsSlice()), int(address.Port()))
	if err != nil {
		t.Fatal(err)
	}
	r := &pathRig{mux: mux, bus: events.New()}
	r.driver = newPathDriver(mux, func(_ *netstack.Peer, size int, nonce uint16) error {
		r.probes.Add(1)
		if size <= carries {
			r.driver.ack(nonce)
		}
		return nil
	}, r.bus, driverProbeTimeout, confirmInterval)
	r.driver.peer = netstack.NewPeer("example/peer/0@0", nil, nil)
	r.driver.open()
	r.driver.start(link, route)
	results, served := make(chan sessionResult), make(chan struct{})
	go func() {
		r.driver.serve(results)
		close(served)
	}()
	t.Cleanup(func() {
		results <- sessionResult{}
		<-served
		_ = mux.Close()
	})
	return r
}

func (r *pathRig) waitBudget(t *testing.T, want int) {
	t.Helper()
	waitFor(t, pathWait, fmt.Sprintf("the session's budget to reach %d", want), func() bool { return r.driver.peer.MTU() == want })
}

// recorded is each pmtu event the search recorded, as the budget it moved from, the one it moved to and why, or the floor it entered or left
func (r *pathRig) recorded() []string {
	var out []string
	for _, event := range r.bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return strings.HasPrefix(kind, "pmtu.") }, 0) {
		if event.Kind == "pmtu.floor" {
			out = append(out, "under the floor "+event.Attrs["under"])
			continue
		}
		out = append(out, fmt.Sprintf("%s to %s by %s", event.Attrs["budget_was"], event.Attrs["budget"], event.Attrs["reason"]))
	}
	return out
}

// a reload's sweep hands a search the new link.mtu
// a lower one drops the budget to it at once, and a higher one sends the search up by probes to what the path carries
// the path proves again what it carried past the lower one
func TestSweepHandsTheSearchTheNewLinkMTU(t *testing.T) {
	const carries = 1998
	r := newPathRig(t, loopbackHub(t), "127.0.0.1:4500", 1402, math.MaxInt, carries)
	// the start of 1400 confirmed, which is 1402 in the same class
	r.waitBudget(t, 1402)
	r.driver.relink(1300)
	r.waitBudget(t, 1300)
	r.driver.relink(8918)
	r.waitBudget(t, carries)
	got := r.recorded()
	want := []string{"1400 to 1402 by probe", "1402 to 1300 by link.mtu", "1300 to 1302 by link.mtu"}
	if len(got) < len(want) || !slices.Equal(got[:len(want)], want) {
		t.Fatalf("the search recorded %q, want it to open with %q", got, want)
	}
	for _, line := range got[len(want):] {
		if !strings.HasSuffix(line, " by probe") {
			t.Errorf("the search recorded %q on its way up, want every move by a probe", line)
		}
	}
}

// a refusal's report lowers the budget at once to what the reported path carries, and a report under the floor puts the session under it
// a report for an endpoint the session moved away from changes nothing, which keeps a report racing a move off the new path's budget
// under the floor the family's sends fragment, until a confirmation finds the route carrying the floor again
// a session to an IPv6 endpoint takes the report's MTU under IPv6's 40 byte header
func TestReportLowersOnlyTheBudgetOfThePathItWasFor(t *testing.T) {
	for _, loopback := range []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.IPv6Loopback()} {
		t.Run(loopback.String(), func(t *testing.T) { reportLowersOnlyItsPath(t, loopback) })
	}
}

// reportLowersOnlyItsPath runs the reports of TestReportLowersOnlyTheBudgetOfThePathItWasFor on sessions to loopback
func reportLowersOnlyItsPath(t *testing.T, loopback netip.Addr) {
	header := 20
	if loopback.Is6() {
		header = 40
	}
	hub := loopbackHub(t)
	r := newPathRig(t, hub, netip.AddrPortFrom(loopback, 4500).String(), 1402, math.MaxInt, math.MaxInt)
	r.waitBudget(t, 1402)
	left := r.mux.Endpoint()
	refused := esp.Inner(1400, header)
	r.driver.reports <- &transport.PathMTUError{Endpoint: left, MTU: 1400}
	r.waitBudget(t, refused)
	other, err := hub.NewMux(net.IP(loopback.AsSlice()), 4501)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = other.Close() })
	r.mux.AdoptEndpoint(other.Endpoint())
	r.driver.move()
	r.waitBudget(t, 1402)
	// a report of 1360 for the path left changes nothing
	// one of 1300 for the path the session holds puts it under the floor in either family
	r.driver.reports <- &transport.PathMTUError{Endpoint: left, MTU: 1360}
	r.driver.reports <- &transport.PathMTUError{Endpoint: r.mux.Endpoint(), MTU: 1300}
	r.waitBudget(t, floor)
	if r.mux.DontFragment() {
		t.Error("a session under the floor sends with DF")
	}
	r.driver.confirmNow()
	waitFor(t, pathWait, "the session to leave the floor", r.mux.DontFragment)
	r.waitBudget(t, 1402)
	want := []string{
		"1400 to 1402 by probe", fmt.Sprintf("1402 to %d by refusal", refused), fmt.Sprintf("%d to 1400 by endpoint change", refused), "1400 to 1402 by probe",
		"under the floor true", "1402 to 1280 by floor", "under the floor false", "1280 to 1282 by probe",
	}
	got := r.recorded()
	if len(got) < len(want) || !slices.Equal(got[:len(want)], want) {
		t.Fatalf("the search recorded %q, want it to open with %q", got, want)
	}
}

// while a session of a family fragments its sends under the floor, the searches of the family's other sessions send no probe, which would measure nothing
// and lose no size meanwhile, and a held search goes on from where it stood once the family sends with DF again
func TestFragmentingFamilyHoldsItsOtherSearches(t *testing.T) {
	hub := loopbackHub(t)
	under, err := hub.NewMux(net.IPv4(127, 0, 0, 1), 4502)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = under.Close() })
	if err := under.Fragment(true); err != nil {
		t.Fatal(err)
	}
	r := newPathRig(t, hub, "127.0.0.1:4500", 1402, math.MaxInt, math.MaxInt)
	time.Sleep(heldFor)
	if sent := r.probes.Load(); sent != 0 {
		t.Errorf("a search sent %d probes while its family fragmented", sent)
	}
	if got := r.driver.peer.MTU(); got != netstack.DefaultMTU {
		t.Errorf("a held search moved its budget to %d, want its start of %d", got, netstack.DefaultMTU)
	}
	if err := under.Fragment(false); err != nil {
		t.Fatal(err)
	}
	r.waitBudget(t, 1402)
}

// a refusal the transmit meets lowers the budget at once, through the report the refusal answers
// linux and darwin refuse a datagram past what UDP carries
// the send then reports the MTU of the route to loopback
// the start reads the route as unbounded, as a failed read leaves it
// the search then climbs to link.mtu, past what loopback carries
func TestTransmitHandsARefusalToTheSearch(t *testing.T) {
	const link = 1 << 20
	r := newPathRig(t, loopbackHub(t), "127.0.0.1:4500", link, math.MaxInt, math.MaxInt)
	r.waitBudget(t, link)
	err := r.driver.transmit([][]byte{make([]byte, 65520)})
	report, ok := errors.AsType[*transport.PathMTUError](err)
	if !ok {
		t.Fatalf("the transmit of a datagram past what UDP carries answered %v, want a path report", err)
	}
	want := esp.Inner(report.MTU, 20)
	r.waitBudget(t, want)
	moved := fmt.Sprintf("%d to %d by refusal", link, want)
	waitFor(t, pathWait, fmt.Sprintf("the search to record %q", moved), func() bool { return slices.Contains(r.recorded(), moved) })
}

// a session whose route cannot carry the floor when it starts lets its family's sends fragment
// it does so before it sends any datagram
// its first budget is the floor
// it records that it went under the floor and sends no probe
func TestSessionStartingUnderTheFloorFragmentsAtOnce(t *testing.T) {
	r := newPathRig(t, loopbackHub(t), "127.0.0.1:4500", 1500, esp.Inner(1300, 20), math.MaxInt)
	if got := r.driver.peer.MTU(); got != floor {
		t.Errorf("the session under the floor starts with a budget of %d, want the floor", got)
	}
	waitFor(t, pathWait, "the session under the floor to let its family's sends fragment", func() bool { return !r.mux.DontFragment() })
	want := []string{"under the floor true"}
	waitFor(t, pathWait, fmt.Sprintf("the search to record %q", want), func() bool { return slices.Equal(r.recorded(), want) })
	if sent := r.probes.Load(); sent != 0 {
		t.Errorf("a search under the floor sent %d probes", sent)
	}
}

// IKE recording that a session moved to another endpoint tells that session's search alone
// an Ack reaches the search of the session it came through, and one through a peer that held the path before reaches none
// a change of the host's network, which probes every session as an operator's probe does, asks every search to confirm its budget
func TestSessionSetHandsMovesAndAcksToTheirSearch(t *testing.T) {
	local := ike.Identity{Organization: "example", CommonName: "alpha", SerialNumber: "1"}
	remote := ike.Identity{Organization: "example", CommonName: "bravo", SerialNumber: "2"}
	other := ike.Identity{Organization: "example", CommonName: "charlie", SerialNumber: "3"}
	c := &Client{events: events.New(), sessions: newSessionSet()}
	var searches []*pathDriver
	for _, path := range []string{sessionPath(remote, local), sessionPath(other, local)} {
		search := newPathDriver(nil, nil, c.events, driverProbeTimeout, confirmInterval)
		search.peer = netstack.NewPeer(path, nil, nil)
		c.sessions.live[path] = &liveSession{pmtu: search}
		searches = append(searches, search)
	}
	moved, kept := searches[0], searches[1]
	c.ikeEvent(local, remote, "ike.endpoint.moved", slog.String("endpoint", "198.51.100.7:4500"))
	if !moved.moved.Load() || len(moved.nudges) != 1 {
		t.Error("an endpoint change IKE recorded left the session's search unaware")
	}
	if kept.moved.Load() {
		t.Error("an endpoint change of one session reached the search of another")
	}
	c.sessions.probeAcked(netstack.NewPeer(moved.peer.ID, nil, nil), 1)
	c.sessions.probeAcked(moved.peer, 2)
	if got := len(moved.acks); got != 1 || <-moved.acks != 2 {
		t.Errorf("the search took %d Acks, want the one through its own peer alone, 2", got)
	}
	if got := len(kept.acks); got != 0 {
		t.Errorf("another session's search took %d Acks, want none", got)
	}
	c.sessions.probe = func(*ike.Session) {}
	c.sessions.matching("", true, c.sessions.startProbe)
	for _, search := range searches {
		if !search.reconfirm.Load() {
			t.Errorf("a change of the host's network left the search of %s without a confirmation to make", search.peer.ID)
		}
	}
}

// answered acks every probe the search puts out until it has none out
func answered(s *pathSearch, now time.Time) {
	for s.probe.size != 0 {
		s.send = false
		s.acked(s.nonce, now)
	}
}

// a settled search probes its budget as a confirmation interval in which data flowed ends, and sends nothing as one in which none did ends
// the Acks of its confirmations leave the raise due raiseInterval after the search settled
func TestSettledSearchConfirmsItsBudgetOnlyWhileDataFlows(t *testing.T) {
	now := time.Unix(0, 0)
	s := newPathSearch(netstack.DefaultMTU, math.MaxInt, defaultProbeTimeout, confirmInterval, now)
	answered(&s, now)
	if s.phase != confirmed || s.budget != netstack.DefaultMTU {
		t.Fatalf("a search on a path carrying its start stands in phase %d at %d, want it settled at %d", s.phase, s.budget, netstack.DefaultMTU)
	}
	settled := now
	route := func() int { return math.MaxInt }
	for i, flowed := range []bool{false, true, false, true} {
		now = s.deadline()
		s.timer(now, flowed, route)
		if probed := s.send && s.probe.size == s.budget; probed != flowed {
			t.Errorf("interval %d, data flowed %v: the search probed its budget %v, want %v", i+1, flowed, probed, flowed)
		}
		answered(&s, now)
		if !s.raise.Equal(settled.Add(raiseInterval)) {
			t.Errorf("interval %d, data flowed %v: the raise is due %s after the search settled, want %s", i+1, flowed, s.raise.Sub(settled), raiseInterval)
		}
	}
}

// a settled search asked to confirm, as a change of the host's network asks, probes its budget at once, data or none
// and a route read afresh under the budget drops the budget to the route first and probes that
func TestSettledSearchConfirmsAtOnceWhenAsked(t *testing.T) {
	now := time.Unix(0, 0)
	s := newPathSearch(netstack.DefaultMTU, math.MaxInt, defaultProbeTimeout, confirmInterval, now)
	answered(&s, now)
	for _, c := range []struct {
		name string
		// route is the largest inner packet the route read afresh lets through, and probed the budget the search then probes
		route, probed int
	}{
		{"the route as it was", math.MaxInt, netstack.DefaultMTU},
		{"a route narrowed to 1338", 1338, 1338},
	} {
		s.reconfirm(c.route, now)
		if !s.send || s.probe.size != c.probed || s.budget != c.probed {
			t.Errorf("%s: the search asked to confirm stands at %d with a probe of %d to send %v, want a probe of its budget %d", c.name, s.budget, s.probe.size, s.send, c.probed)
		}
		answered(&s, now)
	}
}

// a settled search reads the route afresh once the raise interval passed and searches up to what the route lets through now
// a route read under the budget drops the budget to it at once and confirms it there
// a route that narrowed at one raise and widened by the next is searched up again at the next
// a route a report narrowed under the budget is searched up at the raise once it widened
// a search under the floor waits raiseInterval from when it went under
// a search that started there and one a report put there wait alike
// it leaves the floor once the route carries the floor, which it probes first
func TestSearchReadsTheRouteAgainAfterTheRaiseInterval(t *testing.T) {
	for _, c := range []struct {
		name string
		// link is link.mtu
		// route is the largest inner packet the route lets through at the start
		// report is the route a report narrows it to a minute after the start, zero for none
		// raised is the largest the route lets through at the raise
		link, route, report, raised int
		// under is whether the search waits for the raise under the floor
		under bool
		// probed is the first size the raise probes and budget the budget it then stands at
		// settled is the budget the search settles on
		probed, budget, settled int
		// widened is the largest the route lets through at the raise after, zero for none
		widened int
	}{
		{"a route that widened", 1500, 1338, 0, 1500, false, 1422, 1338, 1500, 0},
		{"a route that narrowed under the budget", 1500, 1438, 0, 1338, false, 1338, 1338, 1338, 0},
		{"a route under the floor that came to carry it", 1500, 1238, 0, 1338, true, floor, floor, 1338, 0},
		{"a route a report put under the floor that came to carry it", 1500, 1438, 1238, 1338, true, floor, floor, 1338, 0},
		{"a route a report narrowed under the budget that widened by the raise", 1500, 1438, 1338, 1438, false, 1390, 1338, 1438, 0},
		{"a jumbo route that narrowed under the budget and widened again", 8918, 8938, 0, 1438, false, 1438, 1438, 1438, 8938},
		{"a route that narrowed under the default link.mtu and widened again", netstack.DefaultMTU, 1438, 0, 1338, false, 1338, 1338, 1338, 1438},
	} {
		now := time.Unix(0, 0)
		s := newPathSearch(c.link, c.route, defaultProbeTimeout, confirmInterval, now)
		answered(&s, now)
		if c.report != 0 {
			now = now.Add(time.Minute)
			s.lowered(c.report, movedByRefusal, now)
			answered(&s, now)
		}
		if c.under && (s.phase != underFloor || !s.deadline().Equal(now.Add(raiseInterval))) {
			t.Errorf("%s: the search stands in phase %d and next acts %s after it went under, want it under the floor for %s",
				c.name, s.phase, s.deadline().Sub(now), raiseInterval)
		}
		now = s.raise
		s.timer(now, false, func() int { return c.raised })
		if s.probe.size != c.probed || s.budget != c.budget {
			t.Errorf("%s: the raise probed %d at a budget of %d, want %d at %d", c.name, s.probe.size, s.budget, c.probed, c.budget)
		}
		answered(&s, now)
		if s.phase != confirmed || s.budget != c.settled {
			t.Errorf("%s: the raise left the search in phase %d at %d, want it settled at %d", c.name, s.phase, s.budget, c.settled)
		}
		if c.widened == 0 {
			continue
		}
		now = s.raise
		s.timer(now, false, func() int { return c.widened })
		if s.probe.size <= c.settled {
			t.Errorf("%s: the raise after the route widened again probed %d, want a size past the %d the search stood on", c.name, s.probe.size, c.settled)
		}
		answered(&s, now)
		if want := min(c.link, c.widened); s.phase != confirmed || s.budget != want {
			t.Errorf("%s: the raise after the route widened again left the search in phase %d at %d, want it settled back at %d", c.name, s.phase, s.budget, want)
		}
	}
}

// a report between the budget and the probe out drops that probe in the middle of a search
// the budget already stands within the reported route
// nothing is left to confirm
// the search puts a probe within the route out itself
// its timer waits on that probe
func TestReportUnderTheProbeOutSearchesOn(t *testing.T) {
	now := time.Unix(0, 0)
	s := newPathSearch(1500, math.MaxInt, defaultProbeTimeout, confirmInterval, now)
	s.send = false
	s.acked(s.nonce, now)
	out := s.probe.size
	if s.phase != searchingUp || out <= s.budget {
		t.Fatalf("after the start's Ack the search stands in phase %d at %d probing %d, want it searching up past its budget", s.phase, s.budget, out)
	}
	route := out - 8
	s.lowered(route, movedByRefusal, now)
	if s.probe.size == 0 || s.probe.size > route || !s.send {
		t.Errorf("a route of %d under the probe of %d left the search in phase %d at %d with a probe of %d to send %v, want a probe within the route",
			route, out, s.phase, s.budget, s.probe.size, s.send)
	}
	if got := s.deadline(); !got.After(now) {
		t.Errorf("the search next acts at %s, want a time after the report at %s", got, now)
	}
}

// a raise searches past a class the search lost before
// a black hole that has since cleared may have lost it
// the start of 1400 goes unanswered maxProbes times
// the search settles under it
// the path then carries 1500 again
// the raise after raiseInterval finds it
func TestRaiseSearchesPastAClassLostBefore(t *testing.T) {
	now := time.Unix(0, 0)
	route := func() int { return math.MaxInt }
	s := newPathSearch(1500, math.MaxInt, defaultProbeTimeout, confirmInterval, now)
	lost := s.probe.size
	for s.probe.size == lost {
		now = s.probe.until
		s.timer(now, false, route)
	}
	if s.lost != class(lost) {
		t.Fatalf("the start of %d went unanswered and the search lost class %d, want %d", lost, s.lost, class(lost))
	}
	answered(&s, now)
	if s.phase != confirmed || s.budget >= lost {
		t.Fatalf("the search stands in phase %d at %d, want it settled under the %d it lost", s.phase, s.budget, lost)
	}
	settled := s.budget
	now = s.raise
	s.timer(now, false, route)
	if s.probe.size <= settled {
		t.Errorf("the raise from %d probed %d, want a size past the class it lost", settled, s.probe.size)
	}
	answered(&s, now)
	if s.phase != confirmed || s.budget != 1500 {
		t.Errorf("after the raise the search stands in phase %d at %d, want it settled at the 1500 the path carries again", s.phase, s.budget)
	}
}

// a search on a wide route that lost every size down to the floor stands under it
// a reload's lower link.mtu then leaves it as it stands
// no probe goes out under the floor
// the raise stays where it was
func TestLowerLinkMTULeavesASearchUnderTheFloorAsItStands(t *testing.T) {
	now := time.Unix(0, 0)
	route := func() int { return math.MaxInt }
	s := newPathSearch(1500, math.MaxInt, defaultProbeTimeout, confirmInterval, now)
	end := now.Add(raiseInterval)
	for s.phase != underFloor && now.Before(end) {
		now = s.deadline()
		s.timer(now, false, route)
	}
	if s.phase != underFloor {
		t.Fatalf("a search that lost every probe stands in phase %d at %d, want it under the floor", s.phase, s.budget)
	}
	raise := s.raise
	s.relinked(1400, now)
	if s.phase != underFloor || s.budget != floor || s.probe.size != 0 || s.send || !s.deadline().Equal(raise) {
		t.Errorf("a lower link.mtu left the search in phase %d at %d with a probe of %d to send %v, next acting %s after, want it under the floor until its raise %s after",
			s.phase, s.budget, s.probe.size, s.send, s.deadline().Sub(now), raise.Sub(now))
	}
}

// an Ack counts for the probe out when one of the probe's attempts took its nonce
// an attempt taken back gives its nonce to the next one
// the nonces wrap past 65535
// attempts on either side of the wrap count their Acks alike
// an Ack of a nonce just outside the attempts counts for nothing
func TestAckCountsForTheProbeOutAcrossTheNonceWrap(t *testing.T) {
	route := func() int { return math.MaxInt }
	for _, c := range []struct {
		// ack is the nonce the Ack carries
		// counts is whether it counts for the start's probe
		ack    uint16
		counts bool
	}{
		{65533, false},
		{65534, true},
		{65535, true},
		{0, true},
		{1, false},
	} {
		now := time.Unix(0, 0)
		s := newPathSearch(1500, math.MaxInt, defaultProbeTimeout, confirmInterval, now)
		// the start's first attempt took 65534 some 65000 attempts into a session
		s.nonce = 65534
		// the driver takes back the second attempt the speaker refused
		now = s.probe.until
		s.timer(now, false, route)
		s.unsent(now)
		// the attempts after it take 65535 and 0
		for range maxProbes - 1 {
			now = s.probe.until
			s.timer(now, false, route)
		}
		s.send = false
		s.acked(c.ack, now)
		if counted := s.phase != confirming; counted != c.counts {
			t.Errorf("an Ack of %d to the start's attempts of 65534, 65535 and 0 counted %v, want %v", c.ack, counted, c.counts)
		}
	}
}
