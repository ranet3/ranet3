// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package userspace

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"

	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/packet"
	"ranet3.com/pkgs/ranet3/srv6"
)

// The reasons a new TCP connection is refused past a limit of its own
const (
	reasonConnections = "connections"
	reasonDials       = "dials"
)

// tcpRelay ends each leaf's TCP connection in the stack and opens one of the
// host's own toward the server, copying between the two
type tcpRelay struct {
	x         *Exit
	forwarder *tcp.Forwarder

	mu sync.Mutex
	// dialing holds the leaf's SYN of each connection being dialed, from its
	// admission until the stack's request completes
	dialing map[stack.TransportEndpointID][]byte
	// dials and connections count the connections being dialed and those
	// admitted and not yet ended, dials among them
	dials, connections int
	// ctx ends each dial and flows holds each connection relayed, both
	// withdrawn at once, and resume makes ctx again
	ctx    context.Context
	cancel context.CancelFunc
	flows  map[*tcpFlow]struct{}
	// running counts the requests the forwarder handed over, which Close
	// waits for
	running  sync.WaitGroup
	copies   copies
	closed   closedEndpoints
	mappings tcpMappings
}

func newTCPRelay(x *Exit) *tcpRelay {
	r := &tcpRelay{x: x, dialing: map[stack.TransportEndpointID][]byte{}, flows: map[*tcpFlow]struct{}{}}
	r.closed.limit = x.rt.Limits.TimeWait
	r.ctx, r.cancel = context.WithCancel(context.Background())
	r.forwarder = tcp.NewForwarder(x.stack, x.rt.Limits.Window, x.rt.Limits.Dials+1, r.accept)
	x.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, r.handle)
	return r
}

// handle takes each TCP segment no endpoint of the stack holds. A SYN opening
// a connection is admitted within the source's share, the flows, the
// connections and the dials, below the forwarder's own bound so its silent
// drop never runs, and answered past the limit otherwise. Anything else
// draws the stack's reset, as the destination would answer it.
func (r *tcpRelay) handle(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	segment := header.TCP(pkt.TransportHeader().Slice())
	if len(segment) < header.TCPMinimumSize || segment.Flags()&(header.TCPFlagSyn|header.TCPFlagAck) != header.TCPFlagSyn {
		return false
	}
	source := addrOf(id.RemoteAddress)
	r.mu.Lock()
	if _, dialing := r.dialing[id]; dialing {
		r.mu.Unlock()
		return true
	}
	reason := ""
	switch {
	case r.dials >= r.x.rt.Limits.Dials:
		reason = reasonDials
	case r.connections >= r.x.rt.Limits.Connections:
		reason = reasonConnections
	default:
		reason, _ = r.x.flows.admit(source)
	}
	if reason != "" {
		r.mu.Unlock()
		r.x.refuse(pkt, reason)
		return true
	}
	view := pkt.ToView()
	r.dialing[id] = append([]byte(nil), view.AsSlice()...)
	view.Release()
	r.dials++
	r.connections++
	r.running.Add(1)
	r.mu.Unlock()
	if !r.forwarder.HandlePacket(id, pkt) {
		r.end(id, source, true)
		r.running.Done()
		return false
	}
	return true
}

// end gives back what an admitted connection held: its dial where dialing,
// its count among the connections and its flow
func (r *tcpRelay) end(id stack.TransportEndpointID, source netip.Addr, dialing bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if dialing {
		delete(r.dialing, id)
		r.dials--
	}
	r.connections--
	r.x.flows.release(source)
}

// accept dials the server a SYN asked for, and once the dial is up completes
// the leaf's handshake and relays the connection until both ends close
func (r *tcpRelay) accept(req *tcp.ForwarderRequest) {
	defer r.running.Done()
	id := req.ID()
	leaf := netip.AddrPortFrom(addrOf(id.RemoteAddress), id.RemotePort)
	server := netip.AddrPortFrom(addrOf(id.LocalAddress), id.LocalPort)
	r.mu.Lock()
	syn, ctx := r.dialing[id], r.ctx
	r.mu.Unlock()
	conn, mapping, failure := r.dial(ctx, leaf, server)
	defer r.mappings.release(mapping)
	if conn == nil {
		r.x.answerDialFailure(req, syn, failure)
		r.end(id, leaf.Addr(), true)
		return
	}
	var queue waiter.Queue
	ep, err := req.CreateEndpoint(&queue)
	if err != nil {
		req.Complete(true)
		_ = conn.Close()
		r.end(id, leaf.Addr(), true)
		return
	}
	req.Complete(false)
	ep.SocketOptions().SetKeepAlive(true)
	f := &tcpFlow{ep: ep, queue: &queue, conn: conn, copies: &r.copies, ipv6: leaf.Addr().Is6()}
	r.mu.Lock()
	delete(r.dialing, id)
	r.dials--
	withdrawn := ctx.Err() != nil
	if !withdrawn {
		r.flows[f] = struct{}{}
	}
	r.mu.Unlock()
	if withdrawn {
		f.reset()
	} else {
		f.relay()
	}
	r.mu.Lock()
	delete(r.flows, f)
	r.mu.Unlock()
	ep.Close()
	_ = conn.Close()
	r.end(id, leaf.Addr(), false)
	if e, ok := ep.(*tcp.Endpoint); ok {
		r.x.counts.closed.Add(uint64(r.closed.add(e)))
	}
}

// dial opens the host's connection from the outside endpoint of the leaf's
// mapping on the address the connection leaves from (tcpMappings), and returns
// the mapping, which the caller releases once the connection ends. The address
// is the one the leaf's class names, or under auto the one the route to this
// server picks, read through the platform's Prepare as the dial's socket
// carries it, so on every platform a socket binds the address its connection
// leaves from before its connect. Under auto a later server whose route picks
// another address, by another interface or as a source of its own, gets the
// leaf's mapping on that address, on Linux and on darwin alike, and no
// connection leaves under another route's source. A connection the mapping's
// endpoint cannot carry, its four-tuple held by the host or its port taken by
// a listener of the host's, leaves from a port the host gives on that address
// that no mapping holds, for that connection alone. The socket passes the
// platform's Prepare before it binds.
func (r *tcpRelay) dial(ctx context.Context, leaf, server netip.AddrPort) (*net.TCPConn, *tcpMapping, dialFailure) {
	network := "tcp4"
	if server.Addr().Is6() {
		network = "tcp6"
	}
	address := r.x.sourceFor(leaf.Addr())
	if !address.IsValid() {
		var err error
		if address, err = r.x.routeSource(server); err != nil {
			return nil, nil, dialFailure{err: err}
		}
		address = address.Unmap()
	}
	inside := tcpInside{leaf, address}
	var failure dialFailure
	for _, mapped := range []bool{true, false} {
		var mapping *tcpMapping
		bind := func(fd int) (err error) {
			// Go dials again with a new socket, through Control again, where
			// it takes a connect's EADDRNOTAVAIL for spurious or the socket
			// reached itself, and the earlier socket's mapping is then given
			// back
			r.mappings.release(mapping)
			mapping = nil
			if !mapped {
				return unix.Bind(fd, sockaddrOf(netip.AddrPortFrom(address, 0)))
			}
			mapping, err = r.mappings.bind(fd, inside)
			return err
		}
		queue := r.x.icmp.queue()
		dialer := net.Dialer{Control: r.control(server, bind, &queue)}
		conn, err := dialer.DialContext(ctx, network, server.String())
		cause, caused := queue.read(err)
		queue.close()
		if err == nil {
			return conn.(*net.TCPConn), mapping, dialFailure{}
		}
		r.mappings.release(mapping)
		failure = dialFailure{err: err, cause: cause, caused: caused}
		if !portTaken(err) {
			break
		}
	}
	return nil, nil, failure
}

// control readies a dial's socket: the platform's Prepare toward server,
// bind, and the error queue opened
func (r *tcpRelay) control(server netip.AddrPort, bind func(fd int) error, queue *errorQueue) func(string, string, syscall.RawConn) error {
	return func(network, _ string, raw syscall.RawConn) error {
		if err := r.x.rt.Platform.Prepare(network, server, raw); err != nil {
			return err
		}
		var set error
		if err := raw.Control(func(fd uintptr) {
			if set = bind(int(fd)); set == nil {
				set = queue.open(int(fd), server)
			}
		}); err != nil {
			return err
		}
		return set
	}
}

// tcpMappings keeps the outside endpoint of each inside endpoint, a leaf's
// address and port, on each address its connections leave from, while a
// socket of its connections is bound there, so its connections from one
// address leave from one address and port toward every server (RFC 5382
// REQ-1), and the inside endpoint of each outside endpoint, so no two share
// one (REQ-7). Every outside endpoint is the address and port its sockets
// bind, which their connections leave from, so the table and the host's
// sockets name one endpoint alike. A source address belongs to its uplink,
// whose network or tunnel peer may drop another uplink's (RFC 2827), so under
// auto an inside endpoint whose servers' routes pick two addresses keeps a
// mapping on each rather than send one route's source by another. A mapping
// ends with its last socket and never before it: RFC 5382 section 4.1 gives a
// mapping to the connections it serves, and sections 5 and 7.1 ask nothing of
// it past them.
type tcpMappings struct {
	mu        sync.Mutex
	byInside  map[tcpInside]*tcpMapping
	byOutside map[netip.AddrPort]*tcpMapping
}

// tcpInside is an inside endpoint and the address its connections leave
// from: the one its class names, or under auto the one the route picks
type tcpInside struct {
	leaf    netip.AddrPort
	address netip.Addr
}

// tcpMapping is an inside endpoint's outside endpoint, and how many sockets
// bound on it for its connections are not yet released
type tcpMapping struct {
	inside  tcpInside
	outside netip.AddrPort
	sockets int
}

// errPortHeld is a port the host gave a new mapping that another mapping
// holds on the same address
var errPortHeld = errors.New("userspace: the host gave a tcp mapping a port another mapping holds")

// bind binds fd, a dial's socket for inside, shared (shareDialPort): on its
// mapping's outside endpoint, else on inside's address at the leaf's port
// where no other mapping holds that endpoint and the host binds it, else at a
// port the host gives, which becomes the new mapping's. The host gives no port
// a socket holds on that address unless it shares ports among sockets that
// allow it, as Linux does under net.ipv4.ip_autobind_reuse=1, or a mapping's
// sockets have closed before its release: a port a mapping holds fails the
// bind with errPortHeld, and the table holds nothing of it. It returns the
// mapping, holding fd's socket.
func (t *tcpMappings) bind(fd int, inside tcpInside) (*tcpMapping, error) {
	if err := shareDialPort(fd); err != nil {
		return nil, err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if m := t.byInside[inside]; m != nil {
		if err := unix.Bind(fd, sockaddrOf(m.outside)); err != nil {
			return nil, err
		}
		m.sockets++
		return m, nil
	}
	outside := netip.AddrPortFrom(inside.address, inside.leaf.Port())
	// a leaf port of 0, which no leaf's connection carries, is the host's to give
	taken := outside.Port() == 0 || t.byOutside[outside] != nil
	if !taken {
		err := unix.Bind(fd, sockaddrOf(outside))
		if err != nil && !portTaken(err) {
			return nil, err
		}
		taken = err != nil
	}
	if taken {
		if err := unix.Bind(fd, sockaddrOf(netip.AddrPortFrom(inside.address, 0))); err != nil {
			return nil, err
		}
		bound, err := unix.Getsockname(fd)
		if err != nil {
			return nil, err
		}
		if outside = netip.AddrPortFrom(inside.address, sockaddrPort(bound).Port()); t.byOutside[outside] != nil {
			return nil, errPortHeld
		}
	}
	m := &tcpMapping{inside: inside, outside: outside, sockets: 1}
	if t.byInside == nil {
		t.byInside, t.byOutside = map[tcpInside]*tcpMapping{}, map[netip.AddrPort]*tcpMapping{}
	}
	t.byInside[inside] = m
	t.byOutside[outside] = m
	return m, nil
}

// release gives back one socket of m, ending m at its last. A nil m holds
// nothing.
func (t *tcpMappings) release(m *tcpMapping) {
	if m == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if m.sockets--; m.sockets == 0 {
		delete(t.byInside, m.inside)
		delete(t.byOutside, m.outside)
	}
}

// sockaddrOf is at as a socket address of its family
func sockaddrOf(at netip.AddrPort) unix.Sockaddr {
	if at.Addr().Is4() {
		return &unix.SockaddrInet4{Port: int(at.Port()), Addr: at.Addr().As4()}
	}
	return &unix.SockaddrInet6{Port: int(at.Port()), Addr: at.Addr().As16()}
}

// portTaken is a dial's or a mapping's failure that another port may not
// meet: the port held by another socket, refused to this process, or a dial's
// four-tuple held
func portTaken(err error) bool {
	return errors.Is(err, syscall.EADDRINUSE) || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EADDRNOTAVAIL)
}

// dialFailure is why a dial failed, and the ICMP error the host's socket was
// told of where caused
type dialFailure struct {
	err    error
	cause  icmpError
	caused bool
}

// completer is the stack's request a SYN made, which a failed dial completes
type completer interface{ Complete(sendReset bool) }

// answerDialFailure answers the leaf for a dial that failed: with the error
// the dial met where a server or router raised a destination unreachable,
// sent from it with its code and quoting the leaf's SYN, and with the reset
// the stack sends otherwise, as for a refused connection
func (x *Exit) answerDialFailure(req completer, syn []byte, failure dialFailure) {
	if failure.caused {
		if relayed := unreachableFrom(syn, failure.cause, x.hops(syn[0]>>4 == 6)); relayed != nil && x.link.send(relayed) {
			req.Complete(false)
			return
		}
	}
	req.Complete(true)
}

// unreachableFrom is the destination unreachable cause raised about the
// exit's own packet, answered about the leaf's offending packet from the
// same offender with the same code, at the TTL or hop limit hops, nil for
// any other error
func unreachableFrom(offending []byte, cause icmpError, hops uint8) []byte {
	always := func() bool { return true }
	switch {
	case cause.offender.Is4() && cause.kind == 3:
		return packet.Unreachable(offending, cause.offender, hops, cause.code, always)
	case cause.offender.Is6() && cause.kind == 1:
		return srv6.Unreachable(offending, cause.offender, hops, cause.code, always)
	}
	return nil
}

// refuse answers pkt, a new flow past a limit, past the limit through the
// answer lane, and counts it
func (x *Exit) refuse(pkt *stack.PacketBuffer, reason string) {
	view := pkt.ToView()
	defer view.Release()
	x.refused(view.AsSlice(), reason)
	x.answers.Answer(view.AsSlice(), netstack.ExitPastLimit, 0)
}

func (r *tcpRelay) withdraw() {
	r.mu.Lock()
	r.cancel()
	flows := make([]*tcpFlow, 0, len(r.flows))
	for f := range r.flows {
		flows = append(flows, f)
	}
	r.mu.Unlock()
	for _, f := range flows {
		f.reset()
	}
}

func (r *tcpRelay) resume() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ctx.Err() != nil {
		r.ctx, r.cancel = context.WithCancel(context.Background())
	}
}

// tcpFlow is one connection relayed: the stack's endpoint toward the leaf and
// the host's connection toward the server
type tcpFlow struct {
	ep     tcpip.Endpoint
	queue  *waiter.Queue
	conn   *net.TCPConn
	copies *copies
	// payload is the reader the flow hands the endpoint's Write, emptied
	// after each call, since the endpoint keeps the last reader it was handed
	payload payload
	// ipv6 is the flow's family, which the status counts it under
	ipv6 bool
}

// reset resets both ends: the leaf's from the stack and the server's from
// the host
func (f *tcpFlow) reset() {
	f.ep.Abort()
	_ = f.conn.SetLinger(0)
	_ = f.conn.Close()
}

// relay copies both ways until both ends have closed. A half close is passed
// on as one, and a reset as a reset.
func (f *tcpFlow) relay() {
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.toServer()
	}()
	f.toLeaf()
	<-done
}

// toServer copies what the leaf sends to the server, holding a copy buffer
// only while a read has bytes for it
func (f *tcpFlow) toServer() {
	entry, readable := waiter.NewChannelEntry(waiter.ReadableEvents | waiter.EventHUp | waiter.EventErr)
	f.queue.EventRegister(&entry)
	defer f.queue.EventUnregister(&entry)
	for {
		buf := f.copies.get()
		into := tcpip.SliceWriter(*buf)
		result, err := f.ep.Read(&into, tcpip.ReadOptions{})
		if err == nil {
			_, werr := f.conn.Write((*buf)[:result.Count])
			f.copies.put(buf)
			if werr != nil {
				f.reset()
				return
			}
			continue
		}
		f.copies.put(buf)
		switch err.(type) {
		case *tcpip.ErrWouldBlock:
			<-readable
		case *tcpip.ErrClosedForReceive:
			_ = f.conn.CloseWrite()
			return
		default:
			f.reset()
			return
		}
	}
}

// toLeaf copies what the server sends to the leaf, holding a copy buffer only
// once the host's socket has bytes for it
func (f *tcpFlow) toLeaf() {
	raw, err := f.conn.SyscallConn()
	if err != nil {
		f.reset()
		return
	}
	entry, writable := waiter.NewChannelEntry(waiter.WritableEvents | waiter.EventHUp | waiter.EventErr)
	f.queue.EventRegister(&entry)
	defer f.queue.EventUnregister(&entry)
	for {
		var peeked error
		if err := raw.Read(func(fd uintptr) bool {
			peeked = peek(fd)
			return !errors.Is(peeked, syscall.EAGAIN)
		}); err != nil || peeked != nil {
			f.ep.Abort()
			return
		}
		buf := f.copies.get()
		n, err := f.conn.Read(*buf)
		werr := f.write((*buf)[:n], writable)
		f.copies.put(buf)
		switch {
		case werr != nil:
			f.reset()
			return
		case errors.Is(err, io.EOF):
			f.ep.Shutdown(tcpip.ShutdownWrite)
			return
		case err != nil:
			f.ep.Abort()
			return
		}
	}
}

// peek reads whether the socket fd holds bytes or its end without taking
// them, EAGAIN where it holds neither. The poller wakes a reader only on new
// bytes, so a reader that waited while bytes were left would wait for good
// once the server stops sending into a full window. An error the socket held,
// a server's reset among them, is taken by the peek, so the read after it
// would see only the end, and peek returns it. Each such error ends the
// connection, since the dial's error queue is off once the dial is done.
func peek(fd uintptr) error {
	var probe [1]byte
	_, _, err := syscall.Recvfrom(int(fd), probe[:], syscall.MSG_PEEK|syscall.MSG_DONTWAIT)
	return err
}

// write hands b to the endpoint, waiting while its send buffer is full
func (f *tcpFlow) write(b []byte, writable <-chan struct{}) error {
	for len(b) > 0 {
		f.payload.data = b
		n, err := f.ep.Write(&f.payload, tcpip.WriteOptions{})
		f.payload.data = nil
		b = b[n:]
		switch err.(type) {
		case nil:
		case *tcpip.ErrWouldBlock:
			<-writable
		default:
			return errors.New(err.String())
		}
	}
	return nil
}

// payload is the reader a flow hands the endpoint's Write
type payload struct{ data []byte }

func (p *payload) Read(b []byte) (int, error) {
	if len(p.data) == 0 {
		return 0, io.EOF
	}
	n := copy(b, p.data)
	p.data = p.data[n:]
	return n, nil
}

func (p *payload) Len() int { return len(p.data) }

// copies is the pool of buffers the flows copy through, each held only while
// bytes move, and out the buffers held now
type copies struct {
	pool sync.Pool
	out  atomic.Int64
}

func (c *copies) get() *[]byte {
	c.out.Add(1)
	if buf, ok := c.pool.Get().(*[]byte); ok {
		return buf
	}
	buf := make([]byte, copyBuffer)
	return &buf
}

func (c *copies) put(buf *[]byte) {
	c.pool.Put(buf)
	c.out.Add(-1)
}

// icmpError is an ICMP error the host's socket was told of: its type and
// code, the router or host that raised it, and the word its message carries
// after the checksum as the kernel reads it, a too big's MTU or a parameter
// problem's pointer
type icmpError struct {
	offender   netip.Addr
	kind, code uint8
	info       uint32
}
