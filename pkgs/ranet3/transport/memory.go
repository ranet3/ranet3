// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package transport

import (
	"net"
	"net/netip"
	"os"
	"sync"
	"time"
)

// MemoryNetwork carries UDP in this process between the hubs and sockets made on it
// a datagram goes to what holds the port it is sent to, whatever address it names, whole, copied at its send, and in order between one sender and one receiver
// a queue keeps what arrives until it is read, and a mux reads the path MTU of linux's loopback while no send is refused for its size
// a hub or socket waits on channels and timers the call that opens it makes, so one a synctest bubble uses is opened in that bubble
// a hub opened outside it receives outside it, and panics on the first datagram for a mux the bubble made
type MemoryNetwork struct {
	mu    sync.Mutex
	ports map[uint16]*memoryPort
	next  uint16
}

// NewMemoryNetwork returns a network on which no port is held
func NewMemoryNetwork() *MemoryNetwork {
	return &MemoryNetwork{ports: make(map[uint16]*memoryPort), next: memoryPortFirst}
}

type memoryPort struct {
	port uint16
	// local is a socket's address, and invalid for a hub
	local netip.Addr
	// queues are a hub's receive queues of IPv4 and IPv6, and a socket's one queue twice
	queues [2]*memoryQueue
	// closed is closed once the port is let go
	closed chan struct{}
}

// memoryQueue is read and written under its network's mu
type memoryQueue struct {
	datagrams []memoryDatagram
	// ready holds a token once a datagram arrives, for a reader that found the queue empty
	ready chan struct{}
}

type memoryDatagram struct {
	data   []byte
	source netip.AddrPort
}

func memoryFamily(addr netip.Addr) int {
	if addr.Is4() {
		return 0
	}
	return 1
}

// hold holds the next port, for a socket at local or for a hub where local is invalid
// a test opens a few ports on a network of its own, so the count never comes near the end of the port space
func (n *MemoryNetwork) hold(local netip.Addr) *memoryPort {
	n.mu.Lock()
	defer n.mu.Unlock()
	p := &memoryPort{port: n.next, local: local, closed: make(chan struct{})}
	n.next++
	p.queues[0] = &memoryQueue{ready: make(chan struct{}, 1)}
	p.queues[1] = p.queues[0]
	if !local.IsValid() {
		p.queues[1] = &memoryQueue{ready: make(chan struct{}, 1)}
	}
	n.ports[p.port] = p
	return p
}

// release reports whether it held p until now
func (n *MemoryNetwork) release(p *memoryPort) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.ports[p.port] != p {
		return false
	}
	delete(n.ports, p.port)
	close(p.closed)
	return true
}

// send drops data where nothing holds to's port
func (n *MemoryNetwork) send(p *memoryPort, data []byte, to netip.AddrPort) error {
	if to.Port() == 0 {
		if err := portZeroRefusal(p.local); err != nil {
			return err
		}
	}
	to = netip.AddrPortFrom(to.Addr().Unmap(), to.Port())
	source := p.local
	if !source.IsValid() {
		// the source linux chooses for a loopback destination
		source = netip.IPv6Loopback()
		if to.Addr().Is4() {
			source = netip.AddrFrom4([4]byte{127, 0, 0, 1})
		}
	}
	datagram := memoryDatagram{data: append([]byte(nil), data...), source: netip.AddrPortFrom(source, p.port)}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.ports[p.port] != p {
		return net.ErrClosed
	}
	receiver := n.ports[to.Port()]
	if receiver == nil {
		return nil
	}
	q := receiver.queues[memoryFamily(to.Addr())]
	q.datagrams = append(q.datagrams, datagram)
	select {
	case q.ready <- struct{}{}:
	default:
	}
	return nil
}

// take reports whether p is still held
func (n *MemoryNetwork) take(p *memoryPort, q *memoryQueue, limit int) ([]memoryDatagram, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.ports[p.port] != p {
		return nil, false
	}
	count := min(limit, len(q.datagrams))
	taken := q.datagrams[:count:count]
	q.datagrams = q.datagrams[count:]
	return taken, true
}

// memoryEndpoint carries no source of its own
type memoryEndpoint struct{ addr netip.AddrPort }

func (*memoryEndpoint) transportEndpoint()         {}
func (e *memoryEndpoint) String() string           { return net.UDPAddrFromAddrPort(e.addr).String() }
func (e *memoryEndpoint) AddrPort() netip.AddrPort { return e.addr }
func (e *memoryEndpoint) withoutSource() Endpoint  { return e }

func (e *memoryEndpoint) sameDestination(other Endpoint) bool {
	o, ok := other.(*memoryEndpoint)
	return ok && e.addr == o.addr
}

func newMemoryEndpoint(addr netip.AddrPort) *memoryEndpoint {
	return &memoryEndpoint{netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())}
}

// memoryBind answers the path MTU and DF a mux on linux's loopback reads, and sends a datagram of any size whole
type memoryBind struct {
	network *MemoryNetwork
	port    *memoryPort
}

func (b *memoryBind) ParseEndpoint(s string) (Endpoint, error) {
	addr, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return newMemoryEndpoint(addr), nil
}

func (b *memoryBind) Send(packets [][]byte, endpoint Endpoint) error {
	to := endpoint.(*memoryEndpoint).addr
	for _, packet := range packets {
		if err := b.network.send(b.port, packet, to); err != nil {
			return err
		}
	}
	return nil
}

func (b *memoryBind) Close() error {
	b.network.release(b.port)
	return nil
}

func (b *memoryBind) readPathMTU(ep Endpoint) (int, error) {
	if ep.AddrPort().Addr().Is4() {
		// linux caps an IPv4 path at the largest total length an IPv4 header holds
		return min(memoryLoopbackMTU, 65535), nil
	}
	return memoryLoopbackMTU, nil
}

func (b *memoryBind) fragment(Endpoint, bool) error { return nil }
func (b *memoryBind) dontFragment(Endpoint) bool    { return true }

// receiver takes every datagram q holds up to the vector's length, as the kernel bind reads a batch from its socket of one family
func (b *memoryBind) receiver(q *memoryQueue) receiveFunc {
	return func(bufs [][]byte, sizes []int, endpoints []Endpoint) (int, int, error) {
		for {
			taken, held := b.network.take(b.port, q, len(bufs))
			if !held {
				return 0, 0, net.ErrClosed
			}
			for i, d := range taken {
				bufs[i], sizes[i], endpoints[i] = d.data, len(d.data), newMemoryEndpoint(d.source)
			}
			if len(taken) > 0 {
				return len(taken), 0, nil
			}
			select {
			case <-q.ready:
			case <-b.port.closed:
			}
		}
	}
}

// NewHub opens a hub on the network at a port it draws, receiving in both families
func (n *MemoryNetwork) NewHub() (*Hub, error) {
	p := n.hold(netip.Addr{})
	b := &memoryBind{network: n, port: p}
	return startHub(b, []receiveFunc{b.receiver(p.queues[0]), b.receiver(p.queues[1])}, p.port, Underlay{}, 0, Runtime{}), nil
}

// Dial returns a mux to remoteIP and remotePort on a hub of its own on the network, which it closes when closed
func (n *MemoryNetwork) Dial(remoteIP net.IP, remotePort int) (*Mux, error) {
	h, err := n.NewHub()
	if err != nil {
		return nil, err
	}
	return dialOn(h, remoteIP, remotePort)
}

// MemoryConn is a UDP socket on a memory network, bound to one address and a port the network draws
type MemoryConn struct {
	network *MemoryNetwork
	port    *memoryPort
	// deadline is when a read stops waiting, zero for never, and moved is closed when it changes, both under network's mu
	deadline time.Time
	moved    chan struct{}
}

// ListenUDP opens a socket on the network at ip, the address it sends from
func (n *MemoryNetwork) ListenUDP(ip net.IP) (*MemoryConn, error) {
	addr, _ := netip.AddrFromSlice(ip)
	return &MemoryConn{network: n, port: n.hold(addr.Unmap()), moved: make(chan struct{})}, nil
}

func (c *MemoryConn) LocalAddr() net.Addr {
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(c.port.local, c.port.port))
}

// ReadFromUDP waits for the oldest datagram, copies what of it fits b and drops the rest
// as on net's sockets, a closed socket answers that first, and a deadline past answers that before any datagram
func (c *MemoryConn) ReadFromUDP(b []byte) (int, *net.UDPAddr, error) {
	q := c.port.queues[memoryFamily(c.port.local)]
	for {
		c.network.mu.Lock()
		deadline, moved := c.deadline, c.moved
		c.network.mu.Unlock()
		wait := time.Until(deadline)
		select {
		case <-c.port.closed:
			return 0, nil, c.fail("read", net.ErrClosed)
		default:
		}
		if !deadline.IsZero() && wait <= 0 {
			return 0, nil, c.fail("read", os.ErrDeadlineExceeded)
		}
		taken, held := c.network.take(c.port, q, 1)
		if !held {
			return 0, nil, c.fail("read", net.ErrClosed)
		}
		if len(taken) > 0 {
			return copy(b, taken[0].data), net.UDPAddrFromAddrPort(taken[0].source), nil
		}
		if deadline.IsZero() {
			select {
			case <-q.ready:
			case <-c.port.closed:
			case <-moved:
			}
			continue
		}
		timer := time.NewTimer(wait)
		select {
		case <-q.ready:
		case <-c.port.closed:
		case <-moved:
		case <-timer.C:
		}
		timer.Stop()
	}
}

// WriteToUDP sends a copy of b to addr
func (c *MemoryConn) WriteToUDP(b []byte, addr *net.UDPAddr) (int, error) {
	if err := c.network.send(c.port, b, addr.AddrPort()); err != nil {
		return 0, c.fail("write", err)
	}
	return len(b), nil
}

// SetReadDeadline wakes a read waiting now, which then waits until t
func (c *MemoryConn) SetReadDeadline(t time.Time) error {
	c.network.mu.Lock()
	defer c.network.mu.Unlock()
	close(c.moved)
	c.deadline, c.moved = t, make(chan struct{})
	return nil
}

// SetDeadline is SetReadDeadline, and a write past it goes where net's sockets refuse it
func (c *MemoryConn) SetDeadline(t time.Time) error { return c.SetReadDeadline(t) }

// Close lets the socket's port go and wakes a read waiting on it
func (c *MemoryConn) Close() error {
	if !c.network.release(c.port) {
		return c.fail("close", net.ErrClosed)
	}
	return nil
}

func (c *MemoryConn) fail(op string, err error) error {
	return &net.OpError{Op: op, Net: "udp", Source: c.LocalAddr(), Err: err}
}
