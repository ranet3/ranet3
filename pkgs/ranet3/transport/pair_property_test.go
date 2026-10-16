// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package transport

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// pairModelPeers is how many peers the model's muxes reach, and pairModelMuxes how many muxes it holds open at most
// fewer peers than muxes, so two muxes share a pair
const (
	pairModelPeers = 3
	pairModelMuxes = 4
)

// pairModelDatagram is the size of the datagram the model's sends carry
const pairModelDatagram = 38

// errPairModelRead ends a socket's reading when the model fails it
var errPairModelRead = errors.New("the socket broke")

// pairOutcome is how a connect the model holds ends
type pairOutcome int

const (
	pairCarries pairOutcome = iota
	pairRefuses
	pairCannotConnect
)

// modelConnector holds every connect until the model ends it
type modelConnector struct {
	pairConnector
	// arrived takes each connect as it starts to wait, more than the model ever holds
	arrived chan *modelConnect
	// done closes as the case ends, failed or not, which ends every connect still waiting
	done    chan struct{}
	mu      sync.Mutex
	sockets []*fakePairSocket
}

// modelConnect is one connect that waits for the model to say how it ends, and the socket it connected
type modelConnect struct {
	key    pairKey
	ends   chan pairOutcome
	socket *fakePairSocket
}

func (c *modelConnector) connectPair(k pairKey) (pairSocket, receiveFunc, error) {
	connect := &modelConnect{key: k, ends: make(chan pairOutcome)}
	var outcome pairOutcome
	select {
	case c.arrived <- connect:
	case <-c.done:
		return nil, nil, net.ErrClosed
	}
	select {
	case outcome = <-connect.ends:
	case <-c.done:
		return nil, nil, net.ErrClosed
	}
	if outcome == pairCannotConnect {
		return nil, nil, unix.ECONNREFUSED
	}
	var refuse error
	if outcome == pairRefuses {
		refuse = unix.EADDRNOTAVAIL
	}
	s := newFakePairSocket(refuse, false)
	c.mu.Lock()
	c.sockets = append(c.sockets, s)
	c.mu.Unlock()
	connect.socket = s
	return s, s.receive, nil
}

func (c *modelConnector) live() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	live := 0
	for _, s := range c.sockets {
		if !s.isClosed() {
			live++
		}
	}
	return live
}

// pairModel holds the model's state of one pair while a mux holds it
type pairModel struct {
	peer int
	refs int
	// carried is the bytes since the last sweep while the pair had no socket
	carried int
	socket  bool
	// used is whether the socket carried something since the last sweep, held whether another open waits for the next sweep
	used, held bool
	// refuses is whether the socket refuses every send
	refuses bool
	// connect is the connect the hub started for the pair and the model still holds, nil while none waits
	connect *pendingConnect
	// hub is the hub's pair, and connected the socket the model last let it connect
	hub       *pair
	connected *fakePairSocket
}

// pendingConnect is a connect the model holds, the pair it was started for and the generation of drops it started in
type pendingConnect struct {
	pair    *pairModel
	gen     int
	connect *modelConnect
}

// pairMux is one of the model's open muxes, which sends to peer and holds the pair of the peer at once it sent
type pairMux struct {
	mux    *Mux
	peer   int
	joined bool
	at     int
}

type pairMachine struct {
	hub       *Hub
	connector *modelConnector
	events    *eventLog
	peers     []netip.AddrPort
	// keys are the pairs of the peers, and pairs the model of each pair a mux holds, by peer
	keys      []pairKey
	muxes     []*pairMux
	pairs     map[int]*pairModel
	pending   []*pendingConnect
	gen       int
	fallbacks uint64
	// seen is how many of the hub's events were held to the model, and want the ones the model expects next
	seen int
	want []string
}

func (m *pairMachine) recorded(peer int, kind string, attrs ...slog.Attr) {
	line := fmt.Sprintf("transport.pair.%s local=%s remote=%s", kind, fakeLocal, m.keys[peer].remote)
	for _, attr := range attrs {
		line += " " + attr.String()
	}
	m.want = append(m.want, line)
}

func (m *pairMachine) closed(p *pairModel, reason string, attrs ...slog.Attr) {
	p.socket = false
	m.recorded(p.peer, "closed", append([]slog.Attr{slog.String("reason", reason)}, attrs...)...)
}

// open is how many sockets the model holds open or connecting
func (m *pairMachine) open() int {
	open := len(m.pending)
	for _, p := range m.pairs {
		if p.socket {
			open++
		}
	}
	return open
}

// settle holds the events the last rule recorded to the ones the model expects, in any order, since a drop of every socket walks the pairs unordered
func (m *pairMachine) settle(tc hegel.TestCase) {
	got := m.events.recorded()[m.seen:]
	m.seen += len(got)
	want := m.want
	m.want = nil
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		tc.Errorf("the hub recorded %q, the model %q", got, want)
	}
}

func (m *pairMachine) pick(tc hegel.TestCase) (int, *pairMux) {
	tc.Assume(len(m.muxes) > 0)
	i := hegel.Draw(tc, hegel.Integers(0, len(m.muxes)-1))
	return i, m.muxes[i]
}

// join moves mux onto its peer's pair, as its first send to the peer does, and answers the hub's pair as the send found it
func (m *pairMachine) join(mux *pairMux) (*pairModel, *pair) {
	hub := mux.mux.pairFor(mux.mux.Endpoint())
	if !mux.joined || mux.at != mux.peer {
		p := m.pairs[mux.peer]
		if p == nil {
			p = &pairModel{peer: mux.peer}
			m.pairs[mux.peer] = p
		}
		p.refs++
		if mux.joined {
			m.leave(mux.at)
		}
		mux.joined, mux.at = true, mux.peer
	}
	p := m.pairs[mux.peer]
	p.hub = hub
	return p, hub
}

func (m *pairMachine) leave(peer int) {
	p := m.pairs[peer]
	p.refs--
	if p.refs > 0 {
		return
	}
	if p.socket {
		m.closed(p, pairReleasedClose)
	}
	delete(m.pairs, peer)
}

// carry models n bytes p carried, and takes the connect the hub starts past the threshold
// a pair with a socket only marks it used, and one held off waits for the next sweep
func (m *pairMachine) carry(tc hegel.TestCase, p *pairModel, n int) {
	if p.socket {
		p.used = true
		return
	}
	p.carried += n
	if p.carried < pairThreshold || p.held {
		return
	}
	p.held = true
	if m.open() >= pairCap {
		return
	}
	// the hub claims the open under the table's lock before its connect starts, so nothing falls between the two
	t := m.hub.pairs
	t.mu.Lock()
	claimed := p.hub.opening
	t.mu.Unlock()
	if !claimed {
		tc.Errorf("the pair to %s past the threshold claimed no open before its connect started", m.peers[p.peer])
	}
	select {
	case connect := <-m.connector.arrived:
		if connect.key != m.keys[p.peer] {
			tc.Errorf("a pair to %s past the threshold connected %v", m.peers[p.peer], connect.key)
		}
		p.connect = &pendingConnect{pair: p, gen: m.gen, connect: connect}
		m.pending = append(m.pending, p.connect)
	case <-time.After(arrivalBudget):
		tc.Errorf("the pair to %s carried %d bytes since the sweep and started no connect", m.peers[p.peer], p.carried)
	}
}

func (m *pairMachine) RuleDial(tc hegel.TestCase) {
	tc.Assume(len(m.muxes) < pairModelMuxes)
	peer := hegel.Draw(tc, hegel.Integers(0, pairModelPeers-1))
	at := m.peers[peer]
	mux, err := m.hub.NewMux(at.Addr().AsSlice(), int(at.Port()))
	if err != nil {
		tc.Errorf("dial %s: %v", at, err)
	}
	m.muxes = append(m.muxes, &pairMux{mux: mux, peer: peer})
	m.settle(tc)
}

func (m *pairMachine) RuleClose(tc hegel.TestCase) {
	i, mux := m.pick(tc)
	if err := mux.mux.Close(); err != nil {
		tc.Errorf("close the mux to %s: %v", m.peers[mux.peer], err)
	}
	m.muxes = slices.Delete(m.muxes, i, i+1)
	if mux.joined {
		m.leave(mux.at)
	}
	m.settle(tc)
}

func (m *pairMachine) RuleMove(tc hegel.TestCase) {
	_, mux := m.pick(tc)
	peer := hegel.Draw(tc, hegel.Integers(0, pairModelPeers-1))
	endpoint, err := m.hub.bind.ParseEndpoint(m.peers[peer].String())
	if err != nil {
		tc.Errorf("parse %s: %v", m.peers[peer], err)
	}
	mux.mux.AdoptEndpoint(endpoint)
	mux.peer = peer
	m.settle(tc)
}

// RuleSend sends one datagram through the mux, which the pair's socket carries once it has one
func (m *pairMachine) RuleSend(tc hegel.TestCase) {
	_, mux := m.pick(tc)
	p, _ := m.join(mux)
	had := p.socket
	if err := mux.mux.SendESP(make([]byte, pairModelDatagram)); err != nil {
		tc.Errorf("send to %s: %v", m.peers[mux.peer], err)
	}
	m.carry(tc, p, pairModelDatagram)
	if had && p.refuses {
		m.fallbacks++
		m.closed(p, pairFailedClose, slog.String("err", unix.EADDRNOTAVAIL.Error()))
	}
	m.settle(tc)
}

// RuleBusy carries bytes on a mux's pair as a send of them does, without the datagrams
func (m *pairMachine) RuleBusy(tc hegel.TestCase) {
	_, mux := m.pick(tc)
	n := hegel.Draw(tc, pbt.Spanning(1, pairThreshold))
	p, hub := m.join(mux)
	m.hub.carry(hub, n)
	m.carry(tc, p, n)
	m.settle(tc)
}

// RuleConnect ends one connect the model holds, which the hub keeps only for a pair it still holds since no drop overtook it
func (m *pairMachine) RuleConnect(tc hegel.TestCase) {
	tc.Assume(len(m.pending) > 0)
	i := hegel.Draw(tc, hegel.Integers(0, len(m.pending)-1))
	outcome := hegel.Draw(tc, hegel.SampledFrom([]pairOutcome{pairCarries, pairRefuses, pairCannotConnect}))
	pending := m.pending[i]
	m.pending = slices.Delete(m.pending, i, i+1)
	m.end(tc, pending, outcome)
	p := pending.pair
	switch {
	case outcome == pairCannotConnect:
	case p.refs == 0:
	case pending.gen != m.gen:
		p.held = false
	default:
		p.socket, p.used, p.refuses = true, true, outcome == pairRefuses
		p.connected = pending.connect.socket
		m.recorded(p.peer, "connected")
	}
	m.settle(tc)
}

// end lets one held connect end as outcome and waits until the hub has taken its socket or let it go
func (m *pairMachine) end(tc hegel.TestCase, pending *pendingConnect, outcome pairOutcome) {
	pending.connect.ends <- outcome
	pending.pair.connect = nil
	t := m.hub.pairs
	for deadline := time.Now().Add(arrivalBudget); ; time.Sleep(pairPoll) {
		t.mu.Lock()
		opening := pending.pair.hub.opening
		t.mu.Unlock()
		if !opening {
			return
		}
		if time.Now().After(deadline) {
			tc.Errorf("the connect to %s the model ended never ended in the hub", m.peers[pending.pair.peer])
			return
		}
	}
}

// RuleReadFails ends the reading of one pair's socket with an error no ICMP error is
func (m *pairMachine) RuleReadFails(tc hegel.TestCase) {
	var held []*pairModel
	for peer := range pairModelPeers {
		if p := m.pairs[peer]; p != nil && p.socket {
			held = append(held, p)
		}
	}
	tc.Assume(len(held) > 0)
	p := held[hegel.Draw(tc, hegel.Integers(0, len(held)-1))]
	p.connected.fails <- errPairModelRead
	for deadline := time.Now().Add(arrivalBudget); holdsSocket(m.hub, p.hub); time.Sleep(pairPoll) {
		if time.Now().After(deadline) {
			tc.Errorf("the pair to %s kept the socket whose read failed", m.peers[p.peer])
			break
		}
	}
	m.fallbacks++
	m.closed(p, pairFailedClose, slog.String("err", errPairModelRead.Error()))
	m.settle(tc)
}

func (m *pairMachine) RuleSweep(tc hegel.TestCase) {
	m.hub.sweepPairs()
	for _, p := range m.pairs {
		if p.socket {
			if p.used {
				p.used = false
				continue
			}
			m.closed(p, pairIdleClose)
		}
		p.carried = 0
		if p.connect == nil {
			p.held = false
		}
	}
	m.settle(tc)
}

func (m *pairMachine) RuleNetworkChange(tc hegel.TestCase) {
	m.hub.NetworkChanged()
	m.gen++
	for _, p := range m.pairs {
		if p.socket {
			m.closed(p, pairNetworkClose)
		}
		if p.connect == nil {
			p.held = false
		}
	}
	m.settle(tc)
}

func (m *pairMachine) InvariantPairsAgreeWithTheModel(tc hegel.TestCase) {
	sockets := 0
	for _, p := range m.pairs {
		if p.socket {
			sockets++
		}
	}
	if got := m.hub.PairSockets(); got != m.open() {
		tc.Errorf("the hub counts %d sockets open or connecting, the model %d", got, m.open())
	}
	if got := m.hub.PairFallbacks(); got != m.fallbacks {
		tc.Errorf("the hub counts %d fallbacks, the model %d", got, m.fallbacks)
	}
	if live := m.connector.live(); live != sockets {
		tc.Errorf("%d of the sockets connected are open, the model holds %d", live, sockets)
	}
	if n := len(m.connector.arrived); n != 0 {
		tc.Errorf("%d connects started that the model did not expect", n)
	}
	t := m.hub.pairs
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.pairs) != len(m.pairs) {
		tc.Errorf("the muxes hold %d pairs, the model %d", len(t.pairs), len(m.pairs))
	}
	for peer, want := range m.pairs {
		p := t.pairs[m.keys[peer]]
		if p == nil {
			tc.Errorf("no mux holds the pair to %s, which the model holds %d times", m.peers[peer], want.refs)
			continue
		}
		socket := p.socket.Load()
		if p.refs != want.refs || (socket != nil) != want.socket || p.held.Load() != want.held || p.opening != (want.connect != nil) {
			tc.Errorf("the pair to %s is held %d times with a socket %v, held off %v and connecting %v, the model %d times with a socket %v, held off %v and connecting %v",
				m.peers[peer], p.refs, socket != nil, p.held.Load(), p.opening, want.refs, want.socket, want.held, want.connect != nil)
		}
		if socket == nil && p.carried.Load() != int64(want.carried) {
			tc.Errorf("the pair to %s counts %d bytes toward its socket, the model %d", m.peers[peer], p.carried.Load(), want.carried)
		}
		if socket != nil && ((*socket).(*fakePairSocket).isClosed() || p.used.Load() != want.used) {
			tc.Errorf("the socket of the pair to %s is closed %v and used %v, the model open and used %v",
				m.peers[peer], (*socket).(*fakePairSocket).isClosed(), p.used.Load(), want.used)
		}
	}
}

// the hub starts one open for a pair once it carried pairThreshold within one sweep, and none other until the next sweep
// the connect runs while sends, sweeps, network changes and sessions come and go, and the hub keeps its socket only for a pair a mux still holds and that no drop of every socket overtook
// a socket closes when it carried nothing for a sweep, when its last mux closes or moves to another peer, when the network changes and when a send or a read fails
// the last two leave the pair on the shared socket until the next sweep and count a fallback
// every socket the hub opens or closes is recorded with why, and whatever is open or connecting when the hub closes closes with it
func TestPairSocketsAgreeWithTheModel(t *testing.T) {
	var peers []netip.AddrPort
	for range pairModelPeers {
		peers = append(peers, listenPeer(t, "udp4", "127.0.0.1").LocalAddr().(*net.UDPAddr).AddrPort())
	}
	pbt.Check(t, func(ht *hegel.T) {
		events := &eventLog{}
		hub, err := NewHub(":0", Underlay{}, Runtime{Events: events.record})
		if err != nil {
			ht.Fatal(err)
		}
		connector := &modelConnector{pairConnector: hub.pairs.connector, arrived: make(chan *modelConnect, 2*pairModelPeers), done: make(chan struct{})}
		hub.pairs.connector = connector
		// a failing case unwinds past the close below, and shrinking runs many of them in one process
		defer func() {
			_ = hub.Close()
			close(connector.done)
		}()
		m := &pairMachine{hub: hub, connector: connector, events: events, peers: peers, pairs: make(map[int]*pairModel)}
		for _, peer := range peers {
			endpoint, err := hub.bind.ParseEndpoint(peer.String())
			if err != nil {
				ht.Fatal(err)
			}
			m.keys = append(m.keys, connector.pairOf(endpoint))
		}
		hegel.RunStateful(ht, m, hegel.WithAlwaysCheckInvariants("InvariantPairsAgreeWithTheModel"))
		if err := hub.Close(); err != nil {
			ht.Fatal(err)
		}
		for _, p := range m.pairs {
			if p.socket {
				m.closed(p, pairHubClose)
			}
		}
		for _, pending := range m.pending {
			m.end(ht, pending, pairCarries)
		}
		m.settle(ht)
		if got := connector.live(); got != 0 {
			ht.Fatalf("%d sockets connected to one peer outlived the hub", got)
		}
		if got := hub.PairSockets(); got != 0 {
			ht.Fatalf("the closed hub counts %d sockets open", got)
		}
	})
}
