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
	running sync.WaitGroup
	copies  copies
	closed  closedEndpoints
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
	conn, failure := r.dial(ctx, leaf, server)
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

// dial opens the host's connection from the address the leaf's class names
// and the leaf's port where the host holds it free, as a translator keeps a
// leaf's port, else from one the host gives. Under auto it binds the address
// the route to the server picks where the platform's sockets bind it
// (bindsRouteSource), and leaves it to the connect elsewhere. The socket
// passes the platform's Prepare before it binds.
func (r *tcpRelay) dial(ctx context.Context, leaf, server netip.AddrPort) (*net.TCPConn, dialFailure) {
	network := "tcp4"
	if server.Addr().Is6() {
		network = "tcp6"
	}
	var source net.IP
	if address := r.x.sourceFor(leaf.Addr()); address.IsValid() {
		source = address.AsSlice()
	} else if bindsRouteSource {
		address, err := r.x.routeSource(server)
		if err != nil {
			return nil, dialFailure{err: err}
		}
		source = address.AsSlice()
	}
	var failure dialFailure
	for _, port := range []uint16{leaf.Port(), 0} {
		queue := r.x.icmp.queue()
		dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: source, Port: int(port)}, Control: r.control(server, port != 0, &queue)}
		conn, err := dialer.DialContext(ctx, network, server.String())
		cause, caused := queue.read(err)
		queue.close()
		if err == nil {
			return conn.(*net.TCPConn), dialFailure{}
		}
		failure = dialFailure{err: err, cause: cause, caused: caused}
		if !portTaken(err) {
			break
		}
	}
	return nil, failure
}

// control readies a dial's socket: the platform's Prepare toward server, the
// port shared where it binds the leaf's (shareDialPort), so one leaf port
// toward two servers keeps one outside port, and the error queue opened
func (r *tcpRelay) control(server netip.AddrPort, reuse bool, queue *errorQueue) func(string, string, syscall.RawConn) error {
	return func(network, _ string, raw syscall.RawConn) error {
		if err := r.x.rt.Platform.Prepare(network, server, raw); err != nil {
			return err
		}
		var set error
		if err := raw.Control(func(fd uintptr) {
			if reuse {
				set = shareDialPort(int(fd))
			}
			if set == nil {
				set = queue.open(int(fd), server)
			}
		}); err != nil {
			return err
		}
		return set
	}
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
