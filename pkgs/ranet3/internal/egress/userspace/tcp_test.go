// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package userspace

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/schema"
)

// held is the relay's dials, connections and the exit's flows open
func (r *tcpRelay) held() [3]int {
	r.mu.Lock()
	dials, connections := r.dials, r.connections
	r.mu.Unlock()
	r.x.flows.mu.Lock()
	defer r.x.flows.mu.Unlock()
	return [3]int{dials, connections, r.x.flows.open}
}

// fakeRequest records how a failed dial completed the stack's request
type fakeRequest struct {
	completed, reset bool
}

func (r *fakeRequest) Complete(sendReset bool) { r.completed, r.reset = true, sendReset }

// hostTTL stands in for a host's default TTL other than the relayedTTL the
// exit starts at
const hostTTL = 101

// A failed dial is answered with the destination unreachable a server or
// router raised about it, from that offender with its code and quoting the
// leaf's SYN, an IPv4 one at the host's TTL, and with the stack's reset
// otherwise
func TestFailedDialIsAnsweredFromItsOffender(t *testing.T) {
	router4, router6 := netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("2001:db8:2::1")
	syn4 := tcpSegment(netip.AddrPortFrom(leaf4, 40000), netip.AddrPortFrom(server4, 80), 1000, 0, tcpSYN, nil)
	syn6 := tcpSegment(netip.AddrPortFrom(leaf6, 40000), netip.AddrPortFrom(server6, 80), 1000, 0, tcpSYN, nil)
	for _, c := range []struct {
		name       string
		syn        []byte
		leaf       netip.Addr
		failure    dialFailure
		reset      bool
		from       netip.Addr
		protocol   byte
		kind, code byte
	}{
		{"refused", syn4, leaf4, dialFailure{err: syscall.ECONNREFUSED}, true, netip.Addr{}, 0, 0, 0},
		{"host unreachable from a router", syn4, leaf4, dialFailure{err: syscall.EHOSTUNREACH, cause: icmpError{offender: router4, kind: 3, code: 1}, caused: true}, false, router4, protoICMP, 3, 1},
		{"port unreachable from the server", syn4, leaf4, dialFailure{err: syscall.ECONNREFUSED, cause: icmpError{offender: server4, kind: 3, code: 3}, caused: true}, false, server4, protoICMP, 3, 3},
		{"address unreachable over ipv6", syn6, leaf6, dialFailure{err: syscall.EHOSTUNREACH, cause: icmpError{offender: router6, kind: 1, code: 3}, caused: true}, false, router6, protoICMPv6, 1, 3},
		{"time exceeded", syn4, leaf4, dialFailure{err: syscall.EHOSTUNREACH, cause: icmpError{offender: router4, kind: 11}, caused: true}, true, netip.Addr{}, 0, 0, 0},
		{"timed out", syn6, leaf6, dialFailure{err: syscall.ETIMEDOUT}, true, netip.Addr{}, 0, 0, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			x := &Exit{link: newLink(1 << 20)}
			defer x.link.Close()
			x.SetHopLimits(hostTTL, relayedTTL)
			req := &fakeRequest{}
			x.answerDialFailure(req, c.syn, c.failure)
			if !req.completed || req.reset != c.reset {
				t.Fatalf("completed %t with reset %t, want reset %t", req.completed, req.reset, c.reset)
			}
			pkt := x.link.poll()
			if c.reset {
				if pkt != nil {
					t.Errorf("a reset dial also sent a packet of %d bytes", pkt.Size())
				}
				return
			}
			if pkt == nil {
				t.Fatal("nothing relayed")
			}
			view := pkt.ToView()
			raw := bytes.Clone(view.AsSlice())
			view.Release()
			x.link.release(pkt)
			p, ok := parse(raw)
			if !ok || p.protocol != c.protocol || p.kind != c.kind || p.code != c.code || p.src != c.from || p.dst != c.leaf {
				t.Fatalf("relayed %s, want type %d code %d from %s to %s", p, c.kind, c.code, c.from, c.leaf)
			}
			header := 20
			if c.from.Is6() {
				header = 40
			} else if raw[8] != hostTTL {
				t.Errorf("relayed at the TTL %d, want the host's %d", raw[8], hostTTL)
			}
			if quote := raw[header+8:]; !bytes.Equal(quote, c.syn) {
				t.Errorf("quoted %x, want the leaf's SYN %x", quote, c.syn)
			}
		})
	}
}

// Dials are held below Limits.Dials, connections below Limits.Connections and
// each source within its share, a SYN past any of them answered past the
// limit, and every count is back at zero once the dials have failed
func TestDialsConnectionsAndSharesComeBackAfterFailures(t *testing.T) {
	for _, c := range []struct {
		name         string
		dials, conns int
		share        uint32
		sources      int
		want         string
	}{
		{"past the dials", 2, 8, 0, 3, reasonDials},
		{"past the connections", 8, 2, 0, 3, reasonConnections},
		{"past the share", 8, 8, 2, 1, reasonShare},
	} {
		t.Run(c.name, func(t *testing.T) {
			release := make(chan struct{})
			released := sync.OnceFunc(func() { close(release) })
			mesh := newFakeMesh()
			p := &fakePlatform{routes4: true, routes6: true}
			rt := Runtime{Mesh: mesh, Platform: p.platform(), Limits: testLimits()}
			rt.Limits.Dials, rt.Limits.Connections = c.dials, c.conns
			rt.Platform.Prepare = func(string, netip.AddrPort, syscall.RawConn) error {
				<-release
				return syscall.ENETUNREACH
			}
			cfg := exitConfig()
			cfg.FlowsPerSource = c.share
			x, err := New(cfg, rt)
			if err != nil {
				t.Fatal(err)
			}
			x.answers = mesh.OpenLane()
			defer closeWithin(t, x)
			defer released()
			const syns = 3
			for i := range syns {
				leaf := netip.AddrPortFrom(leaf4, uint16(40000+i))
				if c.sources > 1 {
					leaf = netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(10 + i)}), 40000)
				}
				x.link.deliver(tcpSegment(leaf, netip.AddrPortFrom(server4, 80), 1000, 0, tcpSYN, nil))
			}
			if answers := mesh.answered(); len(answers) != 1 || answers[0].kind != netstack.ExitPastLimit {
				t.Errorf("answered %v, want one past the limit", answers)
			}
			x.counts.mu.Lock()
			refused := x.counts.refused[c.want]
			x.counts.mu.Unlock()
			if refused != 1 {
				t.Errorf("refused %d by %s, want 1", refused, c.want)
			}
			if held := x.tcp.held(); held != [3]int{syns - 1, syns - 1, syns - 1} {
				t.Errorf("dials, connections and flows %v while dialing, want %d each", held, syns-1)
			}
			released()
			deadline := time.Now().Add(exitWait)
			for x.tcp.held() != [3]int{} && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if held := x.tcp.held(); held != [3]int{} {
				t.Errorf("dials, connections and flows %v after every dial failed, want none", held)
			}
		})
	}
}

// closeWithin closes x, failing the test where Close waits past exitWait for
// a request the forwarder handed over, which it then leaves behind
func closeWithin(t *testing.T, x *Exit) {
	t.Helper()
	closed := make(chan error, 1)
	go func() { closed <- x.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Errorf("close: %v", err)
		}
	case <-time.After(exitWait):
		t.Errorf("Close waited past %s for the forwarder's requests", exitWait)
	}
}

// The reader a flow hands the endpoint's Write holds nothing once the write
// returns, so the endpoint, which keeps the last reader it was handed, keeps
// no copy buffer alive
func TestFlowWriteLeavesTheEndpointNoBuffer(t *testing.T) {
	h := newStackHarness(t)
	endpoints := h.forward()
	ep := h.open(t, endpoints, netip.AddrPortFrom(leaf4, 40000), netip.AddrPortFrom(server4, 80))
	f := &tcpFlow{ep: ep}
	writable := make(chan struct{})
	close(writable)
	if err := f.write(bytes.Repeat([]byte{'z'}, 300), writable); err != nil {
		t.Fatal(err)
	}
	if f.payload.data != nil {
		t.Errorf("the reader still holds %d of %d bytes of the buffer after the write", len(f.payload.data), cap(f.payload.data))
	}
}

// A server's reset reaches the leaf as a reset, not as the end of the stream,
// though the host's socket gives the reset to the first read that meets it
func TestServersResetReachesTheLeafAsAReset(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("no loopback to dial: %v", err)
	}
	defer listener.Close()
	conn, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	server, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	h := newStackHarness(t)
	endpoints, queues := make(chan tcpip.Endpoint, 1), make(chan *waiter.Queue, 1)
	forwarder := tcp.NewForwarder(h.stack, 0, 16, func(r *tcp.ForwarderRequest) {
		queue := new(waiter.Queue)
		ep, err := r.CreateEndpoint(queue)
		r.Complete(err != nil)
		if err == nil {
			queues <- queue
			endpoints <- ep
		}
	})
	h.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, forwarder.HandlePacket)
	leaf := netip.AddrPortFrom(leaf4, 40000)
	ep := h.open(t, endpoints, leaf, netip.AddrPortFrom(server4, 80))
	f := &tcpFlow{ep: ep, queue: <-queues, conn: conn, copies: &copies{}}
	relayed := make(chan struct{})
	go func() {
		defer close(relayed)
		f.relay()
	}()
	t.Cleanup(func() {
		f.reset()
		<-relayed
	})
	if err := server.SetLinger(0); err != nil {
		t.Fatal(err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	h.waitSent(t, "reset toward the leaf", func(p sent) bool {
		return p.protocol == protoTCP && p.flags&tcpRST != 0 && netip.AddrPortFrom(p.dst, p.dstPort) == leaf
	})
	for _, p := range h.sentSoFar() {
		if p.protocol == protoTCP && p.flags&tcpFIN != 0 {
			t.Errorf("the stack sent the leaf a FIN before the reset, the end of a stream the server reset")
		}
	}
}

// classed is a capability whose class from the default of to's family leaves
// under to
func classed(to netip.Addr) egress.Egress {
	every := netip.MustParsePrefix("0.0.0.0/0")
	if to.Is6() {
		every = netip.MustParsePrefix("::/0")
	}
	return egress.Egress{Translate: []egress.Class{{From: schema.PrefixFrom(every), To: egress.Translation{Addr: to}}}}
}

// A dial leaves from the address the leaf's class names, and from the one
// the host's route picks under auto
func TestDialLeavesFromTheAddressOfTheLeafsClass(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("no loopback to dial: %v", err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	server := listener.Addr().(*net.TCPAddr).AddrPort()
	for _, c := range []struct {
		name string
		cfg  egress.Egress
		want netip.Addr
	}{
		{"auto", egress.Egress{}, server.Addr()},
		{"an address", classed(netip.MustParseAddr("127.0.0.2")), netip.MustParseAddr("127.0.0.2")},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := &fakePlatform{}
			x := &Exit{cfg: c.cfg, rt: Runtime{Platform: p.platform()}}
			x.rt.Platform.Prepare = func(string, netip.AddrPort, syscall.RawConn) error { return nil }
			conn, failure := (&tcpRelay{x: x}).dial(context.Background(), netip.AddrPortFrom(leaf4, 0), server)
			if conn == nil {
				t.Fatalf("dial %s: %v", server, failure.err)
			}
			defer conn.Close()
			if got := conn.LocalAddr().(*net.TCPAddr).AddrPort().Addr().Unmap(); got != c.want {
				t.Errorf("the dial left from %s, want %s", got, c.want)
			}
		})
	}
}

// A dial binds the leaf's port where the host holds it free, toward a second
// server as well, and another the host gives where a socket holds the leaf's
// port or the process may not bind it, each socket passing Prepare toward the
// server first
func TestDialKeepsTheLeafsPortWhereFree(t *testing.T) {
	var servers []netip.AddrPort
	for range 2 {
		server, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Skipf("no loopback to dial: %v", err)
		}
		defer server.Close()
		go func() {
			for {
				conn, err := server.Accept()
				if err != nil {
					return
				}
				_ = conn.Close()
			}
		}()
		servers = append(servers, server.Addr().(*net.TCPAddr).AddrPort())
	}
	holder, err := net.Listen("tcp4", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	held := uint16(holder.Addr().(*net.TCPAddr).Port)
	// a port no socket of the host holds, zero in an arm standing for one
	// of its own, so no arm's port waits in TIME_WAIT from another's
	freePort := func() uint16 {
		free, err := net.Listen("tcp4", ":0")
		if err != nil {
			t.Fatal(err)
		}
		defer free.Close()
		return uint16(free.Addr().(*net.TCPAddr).Port)
	}
	for _, c := range []struct {
		name string
		port uint16
		to   []netip.AddrPort
		kept bool
	}{
		{"free", 0, servers[:1], true},
		{"free toward two servers", 0, servers, true},
		{"held by a listener", held, servers[:1], false},
		{"refused to the process", 80, servers[:1], false},
	} {
		t.Run(c.name, func(t *testing.T) {
			if c.port == 0 {
				c.port = freePort()
			}
			var prepared []netip.AddrPort
			p := &fakePlatform{}
			x := &Exit{rt: Runtime{Platform: p.platform()}}
			x.rt.Platform.Prepare = func(_ string, to netip.AddrPort, _ syscall.RawConn) error {
				prepared = append(prepared, to)
				return nil
			}
			r := &tcpRelay{x: x}
			for _, to := range c.to {
				prepared = prepared[:0]
				conn, failure := r.dial(context.Background(), netip.AddrPortFrom(leaf4, c.port), to)
				if conn == nil {
					t.Fatalf("dial from port %d toward %s failed: %v", c.port, to, failure.err)
				}
				defer conn.Close()
				local := conn.LocalAddr().(*net.TCPAddr).AddrPort().Port()
				if !c.kept && local == c.port {
					t.Skipf("this process binds port %d itself", c.port)
				}
				if kept := local == c.port; kept != c.kept {
					t.Errorf("dialed %s from port %d for the leaf's %d, kept %t, want %t", to, local, c.port, kept, c.kept)
				}
				wantPrepared := 1
				if !c.kept {
					wantPrepared = 2
				}
				if len(prepared) != wantPrepared {
					t.Errorf("Prepare readied %d sockets toward %s, want %d", len(prepared), to, wantPrepared)
				}
				for _, at := range prepared {
					if at != to {
						t.Errorf("Prepare readied a socket toward %s, want %s", at, to)
					}
				}
			}
		})
	}
}
