// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package transport

import (
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// pairKey is one of this host's addresses, the interface its sends leave by and one peer's address and port
// an invalid local leaves the address to the route the socket connects by, and a zero index the interface
type pairKey struct {
	local  netip.Addr
	index  int
	remote netip.AddrPort
}

// pairConnector is implemented by the bind on a platform that can open a socket on the hub's port connected to one peer
// the kernel hands that socket the peer's datagrams to its address, and its sends keep one cached route
// linux before 5.4 may hand them to another such socket of that address, whose reader feeds the same hub
type pairConnector interface {
	// pairOf is the pair sends to ep leave on
	pairOf(ep Endpoint) pairKey
	// connectPair opens a socket on the hub's port at k's local address, or the route's choice, connected to k's remote
	// the socket follows the path MTU discovery mode of its family's listener until it closes
	connectPair(k pairKey) (pairSocket, receiveFunc, error)
}

// pairSocket is a socket on the hub's port connected to one peer
type pairSocket interface {
	// transmit sends packets to the connected peer and reports how many left before an error
	// and whether the socket still carries the pair after it
	transmit(packets [][]byte, ep Endpoint) (sent int, kept bool, err error)
	// local is the address the socket is bound to
	local() netip.Addr
	Close() error
}

// the reasons a pair's socket closes, which its event names
const (
	pairIdleClose     = "idle"
	pairReleasedClose = "released"
	pairFailedClose   = "failed"
	pairNetworkClose  = "network"
	pairHubClose      = "closed"
)

// pairTable holds the pairs the muxes of one hub send on, and the sockets of the busy ones
type pairTable struct {
	connector pairConnector
	// events is the hub's, nil where the caller records nothing
	events func(kind string, attrs ...slog.Attr)

	mu    sync.Mutex
	pairs map[pairKey]*pair
	// open counts the sockets open and opening, which pairCap bounds
	open int
	// gen moves on when every socket is dropped, which discards an open that raced the drop
	gen uint64
	// fallbacks counts the sockets a send or a read failed on, whose pairs went back to the shared socket
	fallbacks atomic.Uint64
}

// pair is one address pair and its socket once it is busy
type pair struct {
	key pairKey

	// refs counts the muxes sending on the pair, and opening says a connect runs, both under pairTable.mu
	refs    int
	opening bool

	socket atomic.Pointer[pairSocket]
	// carried counts bytes since the last sweep while the pair has no socket
	carried atomic.Int64
	// used says the socket carried something since the last sweep
	used atomic.Bool
	// held stops another open until the next sweep, once an open started, failed or was refused
	// it is set under pairTable.mu with opening, and a sweep or a drop clears it only for a pair with neither a socket nor a connect
	// so one connect runs at a time, and a socket that fails leaves its pair on the shared socket until the next sweep
	held atomic.Bool
}

// carry counts n bytes the pair carried, and starts its open once the count reaches pairThreshold
// the connect runs on its own goroutine, so neither a send nor a receive loop waits for it
func (h *Hub) carry(p *pair, n int) {
	if p.socket.Load() != nil {
		if !p.used.Load() {
			p.used.Store(true)
		}
		return
	}
	if p.carried.Add(int64(n)) >= pairThreshold && !p.held.Load() {
		if gen, ok := h.startPair(p); ok {
			go h.openPair(p, gen)
		}
	}
}

// startPair claims p's open and answers the generation of drops it starts in
// nothing opens past pairCap, for a pair no mux holds any more, or on a closed hub
func (h *Hub) startPair(p *pair) (uint64, bool) {
	t := h.pairs
	t.mu.Lock()
	defer t.mu.Unlock()
	if p.held.Swap(true) || p.refs == 0 || t.open >= pairCap || h.closed.Load() {
		return 0, false
	}
	t.open++
	p.opening = true
	return t.gen, true
}

// openPair connects the socket startPair claimed for p and starts reading it into the hub's receive path
// an open that every socket's drop overtook leaves p free to open again
func (h *Hub) openPair(p *pair, gen uint64) {
	t := h.pairs
	socket, receive, err := t.connector.connectPair(p.key)
	t.mu.Lock()
	defer t.mu.Unlock()
	p.opening = false
	if err != nil || p.refs == 0 || t.gen != gen || h.closed.Load() {
		t.open--
		if err != nil {
			slog.Debug("transport could not connect a socket to a busy peer", "local", p.key.local, "interface", p.key.index, "remote", p.key.remote, "err", err)
			return
		}
		_ = socket.Close()
		if t.gen != gen {
			p.held.Store(false)
		}
		return
	}
	p.used.Store(true)
	p.socket.Store(&socket)
	slog.Debug("transport connected a socket to a busy peer", "local", socket.local(), "remote", p.key.remote)
	t.record("transport.pair.connected", p, socket)
	go h.receiveLoop(receive, func(err error) { h.dropPair(p, &socket, err) })
}

// dropPair closes p's socket after a send or a read on it failed with err, and leaves p on the shared socket until the next sweep
func (h *Hub) dropPair(p *pair, socket *pairSocket, err error) {
	t := h.pairs
	t.mu.Lock()
	defer t.mu.Unlock()
	if !p.socket.CompareAndSwap(socket, nil) {
		return
	}
	_ = (*socket).Close()
	t.open--
	t.fallbacks.Add(1)
	slog.Info("transport closed the socket connected to a peer after it failed, and sends to the peer take the shared socket",
		"local", (*socket).local(), "remote", p.key.remote, "err", err)
	t.record("transport.pair.closed", p, *socket, slog.String("reason", pairFailedClose), slog.String("err", err.Error()))
}

// dropPairs closes every socket connected to one peer for reason
// a busy pair connects again at its next send, from the address its pair names then
func (h *Hub) dropPairs(reason string) {
	t := h.pairs
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.gen++
	for _, p := range t.pairs {
		t.closeSocket(p, reason)
		if !p.opening {
			p.held.Store(false)
		}
	}
}

// NetworkChanged closes every socket connected to one peer after a move of the host's default or one of its addresses
// a socket keeps the source address it bound, which may be gone or no longer the one its route picks
// linux goes on sending from an IPv6 source the host lost
func (h *Hub) NetworkChanged() { h.dropPairs(pairNetworkClose) }

// PairSockets is how many sockets connected to one peer each the hub holds open or opening
func (h *Hub) PairSockets() int {
	t := h.pairs
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.open
}

// PairFallbacks is how many sockets connected to one peer a send or a read failed on, whose traffic then took the shared socket
func (h *Hub) PairFallbacks() uint64 {
	if h.pairs == nil {
		return 0
	}
	return h.pairs.fallbacks.Load()
}

// closeSocket needs t.mu held
func (t *pairTable) closeSocket(p *pair, reason string) {
	if socket := p.socket.Swap(nil); socket != nil {
		_ = (*socket).Close()
		t.open--
		slog.Debug("transport closed the socket connected to a peer", "local", (*socket).local(), "remote", p.key.remote, "reason", reason)
		t.record("transport.pair.closed", p, *socket, slog.String("reason", reason))
	}
}

func (t *pairTable) record(kind string, p *pair, socket pairSocket, attrs ...slog.Attr) {
	if t.events != nil {
		t.events(kind, append([]slog.Attr{slog.String("local", socket.local().String()), slog.String("remote", p.key.remote.String())}, attrs...)...)
	}
}

// sweepPairs closes every socket that carried nothing since the sweep before, and starts every count over
func (h *Hub) sweepPairs() {
	t := h.pairs
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, p := range t.pairs {
		if p.socket.Load() != nil {
			if p.used.Swap(false) {
				continue
			}
			t.closeSocket(p, pairIdleClose)
		}
		p.carried.Store(0)
		if !p.opening {
			p.held.Store(false)
		}
	}
}

func (h *Hub) sweepPairsEvery() {
	ticker := time.NewTicker(pairIdle)
	defer ticker.Stop()
	for {
		select {
		case <-h.done:
			return
		case <-ticker.C:
			h.sweepPairs()
		}
	}
}

// pairFor is the pair sends to endpoint leave on, and moves m onto it when m's endpoint changed pairs
// a pair no mux holds any more closes its socket
func (m *Mux) pairFor(endpoint Endpoint) *pair {
	t := m.hub.pairs
	if t == nil {
		return nil
	}
	key := t.connector.pairOf(endpoint)
	if p := m.pair.Load(); p != nil && p.key == key {
		return p
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if m.closed.Load() {
		return nil
	}
	if p := m.pair.Load(); p != nil && p.key == key {
		return p
	}
	next := t.pairs[key]
	if next == nil {
		next = &pair{key: key}
		t.pairs[key] = next
	}
	next.refs++
	if previous := m.pair.Swap(next); previous != nil {
		t.release(previous)
	}
	return next
}

func (m *Mux) leavePair() {
	t := m.hub.pairs
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if p := m.pair.Swap(nil); p != nil {
		t.release(p)
	}
}

// release needs t.mu held
func (t *pairTable) release(p *pair) {
	p.refs--
	if p.refs > 0 {
		return
	}
	delete(t.pairs, p.key)
	t.closeSocket(p, pairReleasedClose)
}
