// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package userspace

import (
	"bytes"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// leafDial is shorter than the leaf's first SYN retransmission timeout, at one
// second, so a dial within it never waited for that timeout. Linux in
// SYN-SENT answers a segment whose ACK it does not accept, the dropped reset
// among them, by sending its SYN again after TCP_TIMEOUT_MIN, a few
// milliseconds, so a dial slower than that completes on the copy of its SYN,
// with the same sequence number, still within leafDial.
const leafDial = 900 * time.Millisecond

// The reset Abort sends from a TIME_WAIT endpoint leaves toward the leaf with
// its ACK the leaf's FIN plus one, and the leaf's own kernel, in SYN-SENT for
// the connection that reuses the port, drops it by RFC 9293 section 3.10.7.3,
// so the new connection completes within leafDial. The endpoint is aborted on
// the goroutine that hands the leaf's SYN to the exit, as a lane does.
func TestAbortedTimeWaitResetIsDroppedByTheLeafInSynSent(t *testing.T) {
	for _, family := range []struct {
		name         string
		leaf, server netip.Addr
	}{{"ipv4", rigLeaf4.Addr(), rigServer4.Addr()}, {"ipv6", rigLeaf6.Addr(), rigServer6.Addr()}} {
		t.Run(family.name, func(t *testing.T) {
			endpoints := make(chan tcpip.Endpoint, 4)
			r := newLeafRig(t, func(rt Runtime) (*Exit, error) {
				x, err := New(exitConfig(), rt)
				if err != nil {
					return nil, err
				}
				forwarder := tcp.NewForwarder(x.stack, 0, 16, func(req *tcp.ForwarderRequest) {
					var queue waiter.Queue
					ep, err := req.CreateEndpoint(&queue)
					req.Complete(err != nil)
					if err == nil {
						endpoints <- ep
					}
				})
				x.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, forwarder.HandlePacket)
				return x, nil
			})
			var w wire
			fromLeaf, toLeaf := w.record(true), w.record(false)
			r.tap.Store(&fromLeaf)
			r.back.Store(&toLeaf)
			server := netip.AddrPortFrom(family.server, 80)
			type abortion struct {
				state  string
				syn    uint32
				reused bool
			}
			aborted := make(chan abortion, 1)
			before := func(raw []byte) {
				p, ok := parse(raw)
				if !ok || p.protocol != protoTCP || p.flags&(tcpSYN|tcpACK) != tcpSYN {
					return
				}
				state, ep := endpointOf(r.exit.stack, netip.AddrPortFrom(p.src, p.srcPort), netip.AddrPortFrom(p.dst, p.dstPort))
				if ep == nil {
					return
				}
				if state == tcp.StateTimeWait {
					ep.Abort()
				}
				select {
				case aborted <- abortion{state.String(), p.seq, state == tcp.StateTimeWait}:
				default:
				}
			}
			r.before.Store(&before)
			const reconnects = 20
			completed, first, dropped := 0, 0, 0
			for i := range reconnects {
				leaf := netip.AddrPortFrom(family.leaf, uint16(42000+i))
				conn, err := r.dial(leaf, server, leafDial)
				if err != nil {
					t.Fatalf("first connection from %s: %v", leaf, err)
				}
				var ep tcpip.Endpoint
				select {
				case ep = <-endpoints:
				case <-time.After(rigSettle):
					t.Fatalf("no endpoint for %s within %s", leaf, rigSettle)
				}
				if _, err := ep.Write(bytes.NewReader([]byte("hello")), tcpip.WriteOptions{}); err != nil {
					t.Fatalf("the endpoint's write: %s", err)
				}
				ep.Close()
				if err := exchange(conn); err != nil {
					t.Fatalf("first connection from %s: %v", leaf, err)
				}
				closed := time.Now()
				deadline := time.Now().Add(rigSettle)
				for timeWaitOf(r.exit.stack, leaf, server) != tcp.StateTimeWait && time.Now().Before(deadline) {
					time.Sleep(time.Millisecond)
				}
				state := timeWaitOf(r.exit.stack, leaf, server)
				fin, finSeen := lastFIN(w.of(leaf.Port(), time.Time{}))
				start := time.Now()
				second, err := r.dial(leaf, server, leafDial)
				took := time.Since(start)
				var a abortion
				select {
				case a = <-aborted:
				default:
				}
				segments := w.of(leaf.Port(), start)
				// a reset without ACK may follow, answering a late segment of
				// the old connection once its endpoint is gone
				syns, resets, ack := 0, 0, uint32(0)
				for _, s := range segments {
					switch {
					case s.fromLeaf && s.flags&(tcpSYN|tcpACK) == tcpSYN:
						syns++
					case !s.fromLeaf && s.flags&tcpRST != 0:
						resets++
						if s.flags&tcpACK != 0 {
							ack = s.ack
						}
					}
				}
				t.Logf("reconnect %d port %d: endpoint %s %s after the close, leaf FIN seq %d (seen %t), new SYN seq %d after it %t, endpoint at the SYN %s aborted %t, reset toward the leaf %d with ack %d (FIN plus one %t), second connection %v in %s with %d SYNs",
					i, leaf.Port(), state, time.Since(closed).Round(time.Microsecond), fin, finSeen, a.syn, int32(a.syn-fin) > 0, a.state, a.reused, resets, ack, ack == fin+1, err, took.Round(time.Microsecond), syns)
				if err == nil {
					completed++
					second.Close()
					select {
					case ep := <-endpoints:
						ep.Abort()
					case <-time.After(rigSettle):
					}
				}
				if syns == 1 && err == nil {
					first++
				}
				if resets != 0 && ack == fin+1 {
					dropped++
				}
			}
			t.Logf("summary: %d of %d second connections completed within %s, %d on one SYN, %d drew a reset acking the FIN plus one", completed, reconnects, leafDial, first, dropped)
			if completed != reconnects || dropped != reconnects {
				t.Errorf("%d of %d completed within %s and %d drew the reset, want all", completed, reconnects, leafDial, dropped)
			}
		})
	}
}

// A leaf reconnecting from the same port as soon as the exit's endpoint of its
// last connection waits in TIME_WAIT, the server having closed first, reaches
// the server again through the relay within leafDial, twenty times in each
// family, each reuse counted, and the endpoints left waiting are held within
// Limits.TimeWait
func TestReconnectInTimeWaitCompletesBeforeItsSynTimesOut(t *testing.T) {
	r := newLeafRig(t, func(rt Runtime) (*Exit, error) { return New(exitConfig(), rt) })
	var w wire
	fromLeaf := w.record(true)
	r.tap.Store(&fromLeaf)
	const reconnects = 20
	for f, family := range []struct {
		name         string
		leaf, server netip.Addr
	}{{"ipv4", rigLeaf4.Addr(), rigServer4.Addr()}, {"ipv6", rigLeaf6.Addr(), rigServer6.Addr()}} {
		t.Run(family.name, func(t *testing.T) {
			server := r.listen(family.server, 80, serveHello)
			reused := r.exit.counts.reused.Load()
			for i := range reconnects {
				leaf := netip.AddrPortFrom(family.leaf, uint16(43000+100*f+i))
				conn, err := r.dial(leaf, server, leafDial)
				if err != nil {
					t.Fatalf("first connection from %s: %v", leaf, err)
				}
				if err := exchange(conn); err != nil {
					t.Fatalf("first connection from %s: %v", leaf, err)
				}
				closed := time.Now()
				r.waitFor(t, "the endpoint in TIME_WAIT", func() bool { return timeWaitOf(r.exit.stack, leaf, server) == tcp.StateTimeWait })
				waited := time.Since(closed)
				start := time.Now()
				second, err := r.dial(leaf, server, leafDial)
				syns := 0
				for _, s := range w.of(leaf.Port(), start) {
					if s.fromLeaf && s.flags&(tcpSYN|tcpACK) == tcpSYN {
						syns++
					}
				}
				t.Logf("reconnect %d port %d: TIME_WAIT %s after the close, second connection %v in %s with %d SYNs",
					i, leaf.Port(), waited.Round(time.Microsecond), err, time.Since(start).Round(time.Microsecond), syns)
				if err != nil {
					t.Errorf("second connection from %s: %v", leaf, err)
					continue
				}
				if err := exchange(second); err != nil {
					t.Errorf("second connection from %s: %v", leaf, err)
				}
			}
			if got := r.exit.counts.reused.Load() - reused; got != reconnects {
				t.Errorf("counted %d endpoints reused, want %d", got, reconnects)
			}
		})
	}
	// each second connection's endpoint still waits, and all but
	// Limits.TimeWait of them were closed early, the reused ones freed
	want := uint64(2*reconnects - testLimits().TimeWait)
	r.waitFor(t, "the endpoints past the limit closed", func() bool { return r.exit.counts.closed.Load() == want })
}

// timeWaitOf is the state of the stack's endpoint for leaf toward server
func timeWaitOf(s *stack.Stack, leaf, server netip.AddrPort) tcp.EndpointState {
	state, _ := endpointOf(s, leaf, server)
	return state
}

// endpointOf is the stack's endpoint for leaf toward server and its state,
// nil and closed where it holds none
func endpointOf(s *stack.Stack, leaf, server netip.AddrPort) (tcp.EndpointState, *tcp.Endpoint) {
	network := header.IPv4ProtocolNumber
	if server.Addr().Is6() {
		network = header.IPv6ProtocolNumber
	}
	id := stack.TransportEndpointID{
		LocalPort: server.Port(), LocalAddress: tcpip.AddrFromSlice(server.Addr().AsSlice()),
		RemotePort: leaf.Port(), RemoteAddress: tcpip.AddrFromSlice(leaf.Addr().AsSlice()),
	}
	ep, ok := s.FindTransportEndpoint(network, tcp.ProtocolNumber, id, nicID).(*tcp.Endpoint)
	if !ok {
		return tcp.StateClose, nil
	}
	return ep.EndpointState(), ep
}

// wired is one TCP segment the rig saw, from the leaf or toward it
type wired struct {
	fromLeaf bool
	flags    byte
	seq, ack uint32
	payload  int
	leafPort uint16
	at       time.Time
}

// wire records the TCP segments of every flow, both ways
type wire struct {
	mu   sync.Mutex
	seen []wired
}

func (w *wire) record(fromLeaf bool) func(raw []byte) {
	return func(raw []byte) {
		p, ok := parse(raw)
		if !ok || p.protocol != protoTCP {
			return
		}
		port := p.dstPort
		if fromLeaf {
			port = p.srcPort
		}
		w.mu.Lock()
		defer w.mu.Unlock()
		w.seen = append(w.seen, wired{fromLeaf: fromLeaf, flags: p.flags, seq: p.seq, ack: p.ack, payload: p.payload, leafPort: port, at: time.Now()})
	}
}

// of is each segment of the leaf's port seen since
func (w *wire) of(port uint16, since time.Time) []wired {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []wired
	for _, s := range w.seen {
		if s.leafPort == port && !s.at.Before(since) {
			out = append(out, s)
		}
	}
	return out
}

// lastFIN is the sequence number of the leaf's last FIN among segments
func lastFIN(segments []wired) (uint32, bool) {
	var fin uint32
	found := false
	for _, s := range segments {
		if s.fromLeaf && s.flags&tcpFIN != 0 {
			fin, found = s.seq+uint32(s.payload), true
		}
	}
	return fin, found
}

// exchange reads what the server sends until it closes, then closes
func exchange(conn *net.TCPConn) error {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(rigSettle))
	got, err := io.ReadAll(conn)
	if err != nil {
		return err
	}
	if !bytes.Equal(got, []byte("hello")) {
		return io.ErrUnexpectedEOF
	}
	return nil
}

// serveHello sends hello and closes first, so the exit's endpoint toward the
// leaf closes first and waits in TIME_WAIT
func serveHello(conn net.Conn) {
	_, _ = conn.Write([]byte("hello"))
	_ = conn.Close()
}
