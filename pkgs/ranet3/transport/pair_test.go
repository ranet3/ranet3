// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package transport

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"runtime/pprof"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// pairPoll is how often a test looks again for a socket a pair opens on a goroutine of its own
const pairPoll = 5 * time.Millisecond

// pairDatagram is the size of the datagrams the tests carry toward pairThreshold
const pairDatagram = 1200

// pairQuiet is how long a peer hears nothing before a test takes what it queued for drained
const pairQuiet = 100 * time.Millisecond

// pairTestSPI is the inbound ESP SPI the tests register, and pairTestIKESPI the IKE one
const (
	pairTestSPI    = 0x0a0b0c0d
	pairTestIKESPI = 0x0102030405060708
)

// pairHub is a hub on loopback with a peer of the family loopback names, and a mux this node dialed to it
func pairHub(t *testing.T, network, loopback string) (*Hub, *net.UDPConn, *Mux) {
	t.Helper()
	hub, err := NewHub(":0", Underlay{}, Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	if hub.pairs == nil {
		t.Fatal("the bind on this platform connects no socket to one peer")
	}
	peer := listenPeer(t, network, loopback)
	at := peer.LocalAddr().(*net.UDPAddr)
	mux, err := hub.NewMux(at.IP, at.Port)
	if err != nil {
		t.Fatal(err)
	}
	return hub, peer, mux
}

// hubAddr is where peer reaches hub
func hubAddr(peer *net.UDPConn, hub *Hub) netip.AddrPort {
	return netip.AddrPortFrom(peer.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Unmap(), hub.port)
}

// numbered cuts count numbered packets of size from one allocation, so a send may segment them
func numbered(count, size int) [][]byte { return sized(slices.Repeat([]int{size}, count)...) }

// sized cuts packets of sizes from one allocation, each numbered by its place, so a send may segment neighbors
func sized(sizes ...int) [][]byte {
	total := 0
	for _, size := range sizes {
		total += size
	}
	storage := make([]byte, total)
	packets := make([][]byte, len(sizes))
	offset := 0
	for i, size := range sizes {
		packets[i] = storage[offset : offset+size]
		binary.BigEndian.PutUint32(packets[i], uint32(i))
		offset += size
	}
	return packets
}

// drain discards what peer queued
func drain(t *testing.T, peer *net.UDPConn) {
	t.Helper()
	buf := make([]byte, readBufferSize)
	for {
		if err := peer.SetReadDeadline(time.Now().Add(pairQuiet)); err != nil {
			t.Fatal(err)
		}
		if _, _, err := peer.ReadFrom(buf); err != nil {
			return
		}
	}
}

// openSockets is how many sockets hub's table counts open
func openSockets(hub *Hub) int {
	hub.pairs.mu.Lock()
	defer hub.pairs.mu.Unlock()
	return hub.pairs.open
}

// pairsHeld is how many pairs hub's muxes hold
func pairsHeld(hub *Hub) int {
	hub.pairs.mu.Lock()
	defer hub.pairs.mu.Unlock()
	return len(hub.pairs.pairs)
}

// opening reports whether a connect for p runs
func opening(hub *Hub, p *pair) bool {
	hub.pairs.mu.Lock()
	defer hub.pairs.mu.Unlock()
	return p.opening
}

// waitForSocket waits until p has a socket or the arrival budget runs out
func waitForSocket(p *pair) bool {
	for deadline := time.Now().Add(arrivalBudget); time.Now().Before(deadline); time.Sleep(pairPoll) {
		if p.socket.Load() != nil {
			return true
		}
	}
	return false
}

// holdsSocket reports whether p holds a socket, read under the table's lock, which a drop holds from taking the socket away to recording the close
func holdsSocket(hub *Hub, p *pair) bool {
	hub.pairs.mu.Lock()
	defer hub.pairs.mu.Unlock()
	return p.socket.Load() != nil
}

// openNow opens m's pair on the calling goroutine, as carry does once the pair is busy, whatever held the open off
func openNow(m *Mux) *pair {
	p := m.pairFor(m.Endpoint())
	if p.socket.Load() == nil {
		p.held.Store(false)
		if gen, ok := m.hub.startPair(p); ok {
			m.hub.openPair(p, gen)
		}
	}
	return p
}

// waitForOpen waits until no connect for p runs
func waitForOpen(t *testing.T, hub *Hub, p *pair) {
	t.Helper()
	for deadline := time.Now().Add(arrivalBudget); opening(hub, p); time.Sleep(pairPoll) {
		if time.Now().After(deadline) {
			t.Fatal("a connect never ended")
		}
	}
}

// readFrom reads datagrams from conn until one carries want, and answers where it came from
func readFrom(t *testing.T, conn *net.UDPConn, want []byte) netip.AddrPort {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(arrivalBudget)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, readBufferSize)
	for {
		n, from, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			t.Fatalf("%q never arrived on %s: %v", want, conn.LocalAddr(), err)
		}
		if bytes.Equal(buf[:n], want) {
			return netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		}
	}
}

// fakeLocal is the address every socket a fakeConnector connects is bound to
var fakeLocal = netip.MustParseAddr("127.0.0.1")

// fakeConnector connects sockets that carry nothing and read nothing until they are closed or told to fail
type fakeConnector struct {
	pairConnector
	mu      sync.Mutex
	sockets []*fakePairSocket
	// refuse is the error the sockets it connects from now on refuse a send with, after taking its first packet
	// and keeps whether such a socket still carries its pair after the refusal
	refuse error
	keeps  bool
	// gate holds each connect until it receives, where it is not nil
	gate chan struct{}
}

func (c *fakeConnector) connectPair(pairKey) (pairSocket, receiveFunc, error) {
	if c.gate != nil {
		<-c.gate
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	s := newFakePairSocket(c.refuse, c.keeps)
	c.sockets = append(c.sockets, s)
	return s, s.receive, nil
}

func (c *fakeConnector) connected() []*fakePairSocket {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*fakePairSocket(nil), c.sockets...)
}

type fakePairSocket struct {
	refuse error
	keeps  bool
	sent   atomic.Int64
	// fails ends the socket's reading with the error it receives
	fails  chan error
	closed chan struct{}
	once   sync.Once
}

func newFakePairSocket(refuse error, keeps bool) *fakePairSocket {
	return &fakePairSocket{refuse: refuse, keeps: keeps, fails: make(chan error, 1), closed: make(chan struct{})}
}

func (s *fakePairSocket) receive([][]byte, []int, []Endpoint) (int, int, error) {
	select {
	case <-s.closed:
		return 0, 0, net.ErrClosed
	case err := <-s.fails:
		return 0, 0, err
	}
}

func (s *fakePairSocket) transmit(packets [][]byte, _ Endpoint) (int, bool, error) {
	if s.refuse != nil {
		s.sent.Add(1)
		return 1, s.keeps, s.refuse
	}
	s.sent.Add(int64(len(packets)))
	return len(packets), true, nil
}

func (s *fakePairSocket) local() netip.Addr { return fakeLocal }

func (s *fakePairSocket) Close() error {
	s.once.Do(func() { close(s.closed) })
	return nil
}

func (s *fakePairSocket) isClosed() bool {
	select {
	case <-s.closed:
		return true
	default:
		return false
	}
}

// fakePairs puts a fakeConnector in the place of hub's bind for connecting, and keeps the bind's pairs
func fakePairs(hub *Hub) *fakeConnector {
	fake := &fakeConnector{pairConnector: hub.pairs.connector}
	hub.pairs.connector = fake
	return fake
}

// a pair gets a socket once it carried pairThreshold bytes, sent or received
// the socket shares the listener's port, so the peer sees the same address
func TestBusyPairGetsAConnectedSocket(t *testing.T) {
	for _, family := range []struct{ network, loopback string }{{"udp4", "127.0.0.1"}, {"udp6", "::1"}} {
		t.Run(family.network+"/sent", func(t *testing.T) {
			hub, peer, mux := pairHub(t, family.network, family.loopback)
			below := pairThreshold/pairDatagram - 1
			if err := mux.SendESPBatch(numbered(below, pairDatagram)); err != nil {
				t.Fatal(err)
			}
			p := mux.pair.Load()
			if p == nil || p.socket.Load() != nil || p.held.Load() {
				t.Fatalf("%d bytes opened a socket or started to", below*pairDatagram)
			}
			if err := mux.SendESPBatch(numbered(2, pairDatagram)); err != nil {
				t.Fatal(err)
			}
			if !waitForSocket(p) {
				t.Fatalf("%d bytes sent opened no socket", (below+2)*pairDatagram)
			}
			drain(t, peer)
			marker := []byte("after the socket opened")
			if err := mux.SendESP(marker); err != nil {
				t.Fatal(err)
			}
			if from := readFrom(t, peer, marker); from.Port() != hub.port {
				t.Fatalf("the peer heard from port %d, want the listener's %d", from.Port(), hub.port)
			}
		})
		t.Run(family.network+"/received", func(t *testing.T) {
			hub, peer, mux := pairHub(t, family.network, family.loopback)
			if err := mux.RegisterESP(pairTestSPI); err != nil {
				t.Fatal(err)
			}
			if err := mux.SendIKE([]byte("hello")); err != nil {
				t.Fatal(err)
			}
			p := mux.pair.Load()
			to := net.UDPAddrFromAddrPort(hubAddr(peer, hub))
			datagram := make([]byte, pairDatagram)
			binary.BigEndian.PutUint32(datagram, pairTestSPI)
			for sent := 0; sent <= pairThreshold && p.socket.Load() == nil; sent += len(datagram) {
				if _, err := peer.WriteToUDP(datagram, to); err != nil {
					t.Fatal(err)
				}
			}
			if !waitForSocket(p) {
				t.Fatalf("%d bytes received opened no socket", pairThreshold)
			}
		})
	}
}

// no more than pairCap sockets are open at once, and a pair past it stays on the shared socket
func TestPairSocketsStopAtTheCap(t *testing.T) {
	hub, err := NewHub(":0", Underlay{}, Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	fake := fakePairs(hub)
	var pairs []*pair
	for i := range pairCap + 1 {
		mux, err := hub.NewMux(net.IPv4(127, 0, 0, 1), 1024+i)
		if err != nil {
			t.Fatal(err)
		}
		pairs = append(pairs, openNow(mux))
	}
	if got := len(fake.connected()); got != pairCap {
		t.Fatalf("%d busy pairs connected %d sockets, want %d", len(pairs), got, pairCap)
	}
	if last := pairs[pairCap]; last.socket.Load() != nil {
		t.Fatal("the pair past the cap holds a socket")
	}
	if got := openSockets(hub); got != pairCap {
		t.Fatalf("the table counts %d sockets open, want %d", got, pairCap)
	}
}

// a send its socket refuses closes the socket, and what the socket did not send leaves the shared socket
// the pair waits for the next sweep before it opens again
func TestPairSocketThatFailsFallsBackToTheSharedSocket(t *testing.T) {
	hub, peer, mux := pairHub(t, "udp4", "127.0.0.1")
	fake := fakePairs(hub)
	fake.refuse = unix.EADDRNOTAVAIL
	p := openNow(mux)
	if p.socket.Load() == nil {
		t.Fatal("the pair opened no socket")
	}
	packets := numbered(3, pairDatagram)
	if err := mux.SendESPBatch(packets); err != nil {
		t.Fatalf("a send its socket refused failed: %v", err)
	}
	for _, from := range hearsOnly(t, peer, packets[1:]) {
		if from.Port() != hub.port {
			t.Fatalf("the peer heard from port %d, want the listener's %d", from.Port(), hub.port)
		}
	}
	socket := fake.connected()[0]
	if !socket.isClosed() || p.socket.Load() != nil || openSockets(hub) != 0 {
		t.Fatal("the socket that refused the send is still open")
	}
	if got := hub.PairFallbacks(); got != 1 {
		t.Fatalf("the hub counts %d fallbacks, want 1", got)
	}
	hub.carry(p, pairThreshold)
	if openSockets(hub) != 0 {
		t.Fatal("the pair opened again before the next sweep")
	}
	hub.sweepPairs()
	hub.carry(p, pairThreshold)
	if !waitForSocket(p) {
		t.Fatal("the pair opened no socket after the sweep")
	}
}

// hearsOnly reads what peer queued until it is quiet, fails unless that is want in order, and answers where each came from
// a datagram the socket connected to peer had sent already, heard again from the shared socket, fails it
func hearsOnly(t *testing.T, peer *net.UDPConn, want [][]byte) []netip.AddrPort {
	t.Helper()
	var from []netip.AddrPort
	buf := make([]byte, readBufferSize)
	for {
		wait := pairQuiet
		if len(from) < len(want) {
			wait = arrivalBudget
		}
		if err := peer.SetReadDeadline(time.Now().Add(wait)); err != nil {
			t.Fatal(err)
		}
		n, addr, err := peer.ReadFromUDPAddrPort(buf)
		if err != nil {
			if len(from) < len(want) {
				t.Fatalf("%s heard %d of the %d datagrams it should: %v", peer.LocalAddr(), len(from), len(want), err)
			}
			return from
		}
		if len(from) == len(want) || !bytes.Equal(buf[:n], want[len(from)]) {
			t.Fatalf("%s heard %q after %d datagrams, want only %q", peer.LocalAddr(), buf[:n], len(from), want)
		}
		from = append(from, netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port()))
	}
}

// a refusal that leaves its socket carrying the pair, as one for size does, hands only the unsent rest to the shared socket
// the pair keeps its socket and counts no fallback
func TestPairSocketThatKeepsItsPairPastARefusalHandsOnTheRest(t *testing.T) {
	hub, peer, mux := pairHub(t, "udp4", "127.0.0.1")
	fake := fakePairs(hub)
	fake.refuse, fake.keeps = unix.EMSGSIZE, true
	p := openNow(mux)
	packets := numbered(3, pairDatagram)
	if err := mux.SendESPBatch(packets); err != nil {
		t.Fatalf("a send its socket refused failed: %v", err)
	}
	hearsOnly(t, peer, packets[1:])
	if p.socket.Load() == nil || fake.connected()[0].isClosed() || openSockets(hub) != 1 || hub.PairFallbacks() != 0 {
		t.Fatalf("a refusal that leaves the socket working closed it, or counted %d fallbacks", hub.PairFallbacks())
	}
}

// a send that fails with an error the kernel reports for an ICMP error goes once more with what the failed write left
// the socket keeps its pair when that write goes or is refused for size, and loses it when the write fails for a cause of its own
// any other error ends the send at once and costs the socket its pair
func TestPairSendGoesOncePastAnICMPReport(t *testing.T) {
	for _, step := range []struct {
		name string
		// fails holds the error each write fails with in turn, after the first sent one datagram and where the second sent none
		fails []error
		sent  int
		kept  bool
		err   error
	}{
		{"the second write goes", []error{unix.ECONNREFUSED}, 3, true, nil},
		{"the second write is refused for size", []error{unix.ECONNREFUSED, unix.EMSGSIZE}, 1, true, unix.EMSGSIZE},
		{"the second write fails for a cause of its own", []error{unix.EHOSTUNREACH, unix.EADDRNOTAVAIL}, 1, false, unix.EADDRNOTAVAIL},
		{"the first write fails for a cause of its own", []error{unix.EADDRNOTAVAIL}, 1, false, unix.EADDRNOTAVAIL},
	} {
		t.Run(step.name, func(t *testing.T) {
			var handed []int
			sent, kept, err := pastICMP(func(packets [][]byte) (int, error) {
				handed = append(handed, len(packets))
				write := len(handed) - 1
				switch {
				case write >= len(step.fails):
					return len(packets), nil
				case write == 0:
					return 1, os.NewSyscallError("sendmmsg", step.fails[write])
				default:
					return 0, os.NewSyscallError("sendmmsg", step.fails[write])
				}
			}, numbered(3, pairDatagram))
			if sent != step.sent || kept != step.kept || !errors.Is(err, step.err) {
				t.Fatalf("the send answered %d sent, kept %v and %v, want %d, %v and %v", sent, kept, err, step.sent, step.kept, step.err)
			}
			want := []int{3, 2}
			if !icmpReported(step.fails[0]) {
				want = want[:1]
			}
			if !slices.Equal(handed, want) {
				t.Fatalf("the writes were handed %v datagrams, want %v", handed, want)
			}
		})
	}
}

// a socket connected to a closed port goes on past the port unreachable each of its datagrams draws, at its send and at its read
// the kernel hands the error to whichever comes first, and a send then carries its datagram and keeps the pair
// the second send waits out the time the platform withholds a repeat of the last port unreachable, so the datagram it sends again draws its own
func TestPairSocketGoesPastAPortUnreachable(t *testing.T) {
	for _, family := range []struct{ network, loopback string }{{"udp4", "127.0.0.1"}, {"udp6", "::1"}} {
		t.Run(family.network, func(t *testing.T) {
			hub, err := NewHub(":0", Underlay{}, Runtime{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = hub.Close() })
			closed := listenPeer(t, family.network, family.loopback)
			at := closed.LocalAddr().(*net.UDPAddr).AddrPort()
			if err := closed.Close(); err != nil {
				t.Fatal(err)
			}
			endpoint, err := hub.bind.ParseEndpoint(netip.AddrPortFrom(at.Addr().Unmap(), at.Port()).String())
			if err != nil {
				t.Fatal(err)
			}
			socket, receive, err := hub.pairs.connector.connectPair(hub.pairs.connector.pairOf(endpoint))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = socket.Close() })
			conn := pairConn(socket)
			repeat := unreachableRepeat(t)
			for i, when := range []string{"the first send", "a send after a port unreachable"} {
				if i > 0 {
					time.Sleep(repeat)
				}
				if sent, kept, err := socket.transmit([][]byte{[]byte("to a closed port")}, endpoint); sent != 1 || !kept || err != nil {
					t.Fatalf("%s answered %d sent, kept %v and %v, want 1 sent and the pair kept", when, sent, kept, err)
				}
				awaitSocketError(t, conn, when)
			}
			if err := conn.SetReadDeadline(time.Now().Add(pairQuiet)); err != nil {
				t.Fatal(err)
			}
			if _, _, err := receive(make([][]byte, 1), make([]int, 1), make([]Endpoint, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("a read after a port unreachable answered %v, want it to read on until its deadline", err)
			}
		})
	}
}

// awaitSocketError waits until the kernel holds an error for conn after what, which polls readable while no datagram reaches it
func awaitSocketError(t *testing.T, conn *net.UDPConn, what string) {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(arrivalBudget); ; time.Sleep(pairPoll) {
		var ready int
		var pollErr error
		if err := raw.Control(func(fd uintptr) {
			ready, pollErr = unix.Poll([]unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}, 0)
		}); err != nil {
			t.Fatal(err)
		}
		if pollErr != nil && !errors.Is(pollErr, unix.EINTR) {
			t.Fatal(pollErr)
		}
		if ready > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no ICMP error reached the socket after %s", what)
		}
	}
}

// icmpReportsHold fails unless a pair's reader and its send go past each of reported, the errors the platform hands a connected socket for an ICMP error
// and stop at each of others
func icmpReportsHold(t *testing.T, reported, others []unix.Errno) {
	t.Helper()
	for _, errno := range slices.Concat(reported, others) {
		past := slices.Contains(reported, errno)
		reads := 0
		receive := retryICMP(func([][]byte, []int, []Endpoint) (int, int, error) {
			reads++
			if reads == 1 {
				return 0, 0, os.NewSyscallError("recvmsg", errno)
			}
			return 1, 0, nil
		})
		n, _, err := receive(make([][]byte, 1), make([]int, 1), make([]Endpoint, 1))
		if read := n == 1 && err == nil; read != past || (!past && !errors.Is(err, errno)) {
			t.Errorf("a read that failed with %s answered %d datagrams and %v, want it read past %v", unix.ErrnoName(errno), n, err, past)
		}
		writes := 0
		sent, kept, err := pastICMP(func(packets [][]byte) (int, error) {
			writes++
			if writes == 1 {
				return 0, os.NewSyscallError("sendmsg", errno)
			}
			return len(packets), nil
		}, numbered(1, pairDatagram))
		if went := sent == 1 && kept && err == nil; went != past || (!past && (kept || !errors.Is(err, errno))) {
			t.Errorf("a send that failed with %s answered %d sent, kept %v and %v, want it sent past %v", unix.ErrnoName(errno), sent, kept, err, past)
		}
	}
}

// a send the host may fragment leaves the pair's socket like every other send, since that socket fragments with its family
func TestPairSocketCarriesWhatItsFamilyFragments(t *testing.T) {
	for _, family := range []struct{ network, loopback string }{{"udp4", "127.0.0.1"}, {"udp6", "::1"}} {
		t.Run(family.network, func(t *testing.T) {
			hub, _, mux := pairHub(t, family.network, family.loopback)
			fake := fakePairs(hub)
			p := openNow(mux)
			socket := fake.connected()[0]
			if err := mux.Fragment(true); err != nil {
				t.Fatal(err)
			}
			if err := mux.SendESP([]byte("while the mux fragments")); err != nil {
				t.Fatal(err)
			}
			if socket.sent.Load() != 1 || p.socket.Load() == nil {
				t.Fatalf("while the mux fragments the pair's socket carried %d datagrams, want 1 and the socket kept", socket.sent.Load())
			}
		})
	}
}

// a change of the host's network closes every pair's socket
// a busy pair connects again at its next send without waiting for a sweep, and so does one whose connect the change overtook
func TestNetworkChangeClosesEveryPairSocket(t *testing.T) {
	hub, _, mux := pairHub(t, "udp4", "127.0.0.1")
	fake := fakePairs(hub)
	if err := mux.SendESPBatch(numbered(pairThreshold/pairDatagram+1, pairDatagram)); err != nil {
		t.Fatal(err)
	}
	p := mux.pair.Load()
	if !waitForSocket(p) {
		t.Fatal("the busy pair opened no socket")
	}
	hub.NetworkChanged()
	if !fake.connected()[0].isClosed() || p.socket.Load() != nil || openSockets(hub) != 0 {
		t.Fatal("the pair's socket is still open after the network changed")
	}
	fake.gate = make(chan struct{})
	if err := mux.SendESP([]byte("after the change")); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(arrivalBudget); !opening(hub, p); time.Sleep(pairPoll) {
		if time.Now().After(deadline) {
			t.Fatal("the busy pair did not connect again after the network changed")
		}
	}
	hub.NetworkChanged()
	fake.gate <- struct{}{}
	for deadline := time.Now().Add(arrivalBudget); len(fake.connected()) < 2 || openSockets(hub) != 0; time.Sleep(pairPoll) {
		if time.Now().After(deadline) {
			t.Fatal("the connect the change overtook kept its socket")
		}
	}
	close(fake.gate)
	if err := mux.SendESP([]byte("after the second change")); err != nil {
		t.Fatal(err)
	}
	if !waitForSocket(p) || len(fake.connected()) != 3 {
		t.Fatal("the pair whose connect the change overtook did not connect again")
	}
}

// a socket that carried nothing for a whole sweep closes, and the pair opens one again once busy
func TestIdlePairClosesItsSocket(t *testing.T) {
	hub, _, mux := pairHub(t, "udp4", "127.0.0.1")
	fake := fakePairs(hub)
	p := openNow(mux)
	socket := fake.connected()[0]
	hub.sweepPairs()
	if err := mux.SendESP([]byte("keeps it open")); err != nil {
		t.Fatal(err)
	}
	hub.sweepPairs()
	if socket.isClosed() || p.socket.Load() == nil {
		t.Fatal("a socket that carried a datagram since the last sweep closed")
	}
	if socket.sent.Load() != 1 {
		t.Fatalf("the socket carried %d datagrams, want 1", socket.sent.Load())
	}
	hub.sweepPairs()
	if !socket.isClosed() || p.socket.Load() != nil || openSockets(hub) != 0 {
		t.Fatal("a socket that carried nothing for a whole sweep is still open")
	}
	hub.carry(p, pairThreshold)
	if !waitForSocket(p) {
		t.Fatal("the pair opened no socket once it was busy again")
	}
}

// a sweep starts the count toward a socket over, so bytes from either side of it do not add up to one
func TestSweepStartsTheCountOver(t *testing.T) {
	hub, _, mux := pairHub(t, "udp4", "127.0.0.1")
	fakePairs(hub)
	p := mux.pairFor(mux.Endpoint())
	hub.carry(p, pairThreshold-1)
	hub.sweepPairs()
	hub.carry(p, 1)
	if openSockets(hub) != 0 || p.held.Load() {
		t.Fatal("bytes from either side of a sweep opened a socket")
	}
	hub.carry(p, pairThreshold-1)
	if !waitForSocket(p) {
		t.Fatalf("%d bytes within one sweep opened no socket", pairThreshold)
	}
}

// a sweep or a drop of every socket while a pair connects starts no second open for the pair
// after a sweep the pair keeps the one socket its connect opened, and after a drop that socket closes and the pair connects again
func TestPairConnectsOnceAcrossASweepOrADrop(t *testing.T) {
	for _, drop := range []struct {
		name string
		act  func(*Hub)
		// kept is whether the connect that ran across act keeps its socket
		kept bool
	}{{"sweep", (*Hub).sweepPairs, true}, {"network change", (*Hub).NetworkChanged, false}} {
		t.Run(drop.name, func(t *testing.T) {
			hub, _, mux := pairHub(t, "udp4", "127.0.0.1")
			fake := fakePairs(hub)
			p := mux.pairFor(mux.Endpoint())
			gen, ok := hub.startPair(p)
			if !ok {
				t.Fatal("the pair started no open")
			}
			drop.act(hub)
			hub.carry(p, pairThreshold)
			if got := openSockets(hub); got != 1 || !p.held.Load() {
				t.Fatalf("a %s while the pair connected let another open start, and the table counts %d sockets", drop.name, got)
			}
			hub.openPair(p, gen)
			if kept := p.socket.Load() != nil; kept != drop.kept {
				t.Fatalf("the connect a %s ran across kept its socket %v, want %v", drop.name, kept, drop.kept)
			}
			if !drop.kept {
				hub.carry(p, pairThreshold)
				if !waitForSocket(p) {
					t.Fatal("the pair whose connect the drop overtook did not connect again")
				}
			}
			open := 0
			for _, socket := range fake.connected() {
				if !socket.isClosed() {
					open++
				}
			}
			if open != 1 || openSockets(hub) != 1 {
				t.Fatalf("the pair holds %d sockets open and the table counts %d, want 1 each", open, openSockets(hub))
			}
		})
	}
}

// a connect that ends after its pair's last session ended, or once the hub began to close, keeps no socket and records none
func TestConnectThatOutlivesItsPairKeepsNoSocket(t *testing.T) {
	for _, end := range []struct {
		name string
		act  func(*Hub, *Mux)
	}{
		{"its last session ends", func(_ *Hub, m *Mux) { _ = m.Close() }},
		// the hub marks itself closed before it drops every socket, and a connect can end between the two
		{"the hub begins to close", func(h *Hub, _ *Mux) { h.closed.Store(true) }},
	} {
		t.Run(end.name, func(t *testing.T) {
			events := &eventLog{}
			hub, err := NewHub(":0", Underlay{}, Runtime{Events: events.record})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = hub.Close() })
			fake := fakePairs(hub)
			fake.gate = make(chan struct{})
			at := listenPeer(t, "udp4", "127.0.0.1").LocalAddr().(*net.UDPAddr)
			mux, err := hub.NewMux(at.IP, at.Port)
			if err != nil {
				t.Fatal(err)
			}
			p := mux.pairFor(mux.Endpoint())
			hub.carry(p, pairThreshold)
			if !opening(hub, p) {
				t.Fatal("the busy pair started no connect")
			}
			end.act(hub, mux)
			close(fake.gate)
			waitForOpen(t, hub, p)
			sockets := fake.connected()
			if len(sockets) != 1 || !sockets[0].isClosed() || p.socket.Load() != nil || hub.PairSockets() != 0 {
				t.Fatalf("once %s, the connect kept its socket, and the hub counts %d sockets", end.name, hub.PairSockets())
			}
			if got := events.recorded(); len(got) != 0 {
				t.Fatalf("once %s, the hub recorded %q for the connect, want nothing", end.name, got)
			}
		})
	}
}

// a pair whose last session ended, or one on a hub that began to close, claims no connect at all
func TestPairPastItsSessionsOrItsHubStartsNoConnect(t *testing.T) {
	for _, end := range []struct {
		name string
		act  func(*Hub, *Mux)
	}{
		{"its last session ends", func(_ *Hub, m *Mux) { _ = m.Close() }},
		{"the hub begins to close", func(h *Hub, _ *Mux) { h.closed.Store(true) }},
	} {
		t.Run(end.name, func(t *testing.T) {
			hub, _, mux := pairHub(t, "udp4", "127.0.0.1")
			fakePairs(hub)
			p := mux.pairFor(mux.Endpoint())
			end.act(hub, mux)
			if _, ok := hub.startPair(p); ok || opening(hub, p) || hub.PairSockets() != 0 {
				t.Fatalf("once %s, the pair claimed a connect, and the hub counts %d sockets", end.name, hub.PairSockets())
			}
		})
	}
}

// a mux that closed joins no pair, so a send racing its close leaves the table nothing to hold
func TestClosedMuxJoinsNoPair(t *testing.T) {
	hub, _, mux := pairHub(t, "udp4", "127.0.0.1")
	if err := mux.Close(); err != nil {
		t.Fatal(err)
	}
	// where the datagram goes is beside the point, only that the send took no pair
	_ = mux.SendIKE([]byte("after the close"))
	if mux.pair.Load() != nil || pairsHeld(hub) != 0 {
		t.Fatalf("a closed mux joined a pair, and the table holds %d", pairsHeld(hub))
	}
}

// a read its socket fails closes the socket as a failed send does
// the hub records why and counts a fallback, and the pair takes the shared socket until the next sweep
func TestPairSocketWhoseReadFailsFallsBackToTheSharedSocket(t *testing.T) {
	events := &eventLog{}
	hub, err := NewHub(":0", Underlay{}, Runtime{Events: events.record})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	fake := fakePairs(hub)
	peer := listenPeer(t, "udp4", "127.0.0.1")
	at := peer.LocalAddr().(*net.UDPAddr)
	mux, err := hub.NewMux(at.IP, at.Port)
	if err != nil {
		t.Fatal(err)
	}
	p := openNow(mux)
	socket := fake.connected()[0]
	failure := errors.New("the socket broke")
	socket.fails <- failure
	for deadline := time.Now().Add(arrivalBudget); holdsSocket(hub, p); time.Sleep(pairPoll) {
		if time.Now().After(deadline) {
			t.Fatal("the pair kept the socket whose read failed")
		}
	}
	if !socket.isClosed() || openSockets(hub) != 0 || hub.PairFallbacks() != 1 {
		t.Fatalf("the socket whose read failed is still open, or the hub counts %d fallbacks, want 1", hub.PairFallbacks())
	}
	pair := fmt.Sprintf("local=%s remote=%s", fakeLocal, at.AddrPort())
	want := []string{"transport.pair.connected " + pair,
		"transport.pair.closed " + pair + " reason=" + pairFailedClose + " " + slog.String("err", failure.Error()).String()}
	if got := events.recorded(); !slices.Equal(got, want) {
		t.Fatalf("the hub recorded %q, want %q", got, want)
	}
	hub.carry(p, pairThreshold)
	if openSockets(hub) != 0 {
		t.Fatal("the pair opened again before the next sweep")
	}
	marker := []byte("after the read failed")
	if err := mux.SendESP(marker); err != nil {
		t.Fatal(err)
	}
	if from := readFrom(t, peer, marker); from.Port() != hub.port {
		t.Fatalf("the peer heard from port %d, want the listener's %d", from.Port(), hub.port)
	}
}

// a pair's socket closes once no mux sends on it, whether the muxes closed or moved to another endpoint
// two sessions to one peer share its pair while both live
func TestPairClosesWhenItsSessionsEnd(t *testing.T) {
	hub, peer, first := pairHub(t, "udp4", "127.0.0.1")
	fake := fakePairs(hub)
	second, err := hub.NewMuxTo(first.Endpoint())
	if err != nil {
		t.Fatal(err)
	}
	p := openNow(first)
	if got := second.pairFor(second.Endpoint()); got != p {
		t.Fatal("two muxes to one peer hold two pairs")
	}
	socket := fake.connected()[0]
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if socket.isClosed() {
		t.Fatal("the socket closed while a session still sends on it")
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	if !socket.isClosed() || p.socket.Load() != nil || pairsHeld(hub) != 0 || openSockets(hub) != 0 {
		t.Fatal("the socket outlived the last session on it")
	}

	at := peer.LocalAddr().(*net.UDPAddr)
	moving, err := hub.NewMux(at.IP, at.Port)
	if err != nil {
		t.Fatal(err)
	}
	openNow(moving)
	socket = fake.connected()[1]
	elsewhere, err := hub.bind.ParseEndpoint(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(at.Port+1)).String())
	if err != nil {
		t.Fatal(err)
	}
	moving.AdoptEndpoint(elsewhere)
	if err := moving.SendESP([]byte("from the new endpoint")); err != nil {
		t.Fatal(err)
	}
	if !socket.isClosed() || pairsHeld(hub) != 1 {
		t.Fatal("the socket of the endpoint a mux left is still open")
	}
}

// what the peer sends to the hub reaches its mux through the socket connected to it, IKE and ESP alike
// a NAT keepalive and ESP under an SPI no mux holds reach no mux, and the hub counts each
func TestConnectedSocketFeedsTheReceivePath(t *testing.T) {
	for _, family := range []struct{ network, loopback string }{{"udp4", "127.0.0.1"}, {"udp6", "::1"}} {
		t.Run(family.network, func(t *testing.T) {
			hub, peer, mux := pairHub(t, family.network, family.loopback)
			if err := mux.RegisterESP(pairTestSPI); err != nil {
				t.Fatal(err)
			}
			if err := mux.RegisterIKE(pairTestIKESPI); err != nil {
				t.Fatal(err)
			}
			if openNow(mux).socket.Load() == nil {
				t.Fatal("the pair opened no socket")
			}
			to := net.UDPAddrFromAddrPort(hubAddr(peer, hub))
			unknown := binary.BigEndian.AppendUint32(nil, pairTestSPI+1)
			unknown = append(unknown, "unknown"...)
			esp := binary.BigEndian.AppendUint32(nil, pairTestSPI)
			esp = append(esp, "esp"...)
			ike := binary.BigEndian.AppendUint64(make([]byte, nonESPMarkerLen), pairTestIKESPI)
			ike = append(ike, "ike"...)
			for _, datagram := range [][]byte{{natKeepaliveByte}, unknown, esp, ike} {
				if _, err := peer.WriteToUDP(datagram, to); err != nil {
					t.Fatal(err)
				}
			}
			got, err := mux.RecvESPUntil(time.Now().Add(arrivalBudget))
			if err != nil || !bytes.Equal(got, esp) {
				t.Fatalf("ESP from the peer arrived as %q, %v", got, err)
			}
			raw, from, err := mux.RecvIKEFromUntil(time.Now().Add(arrivalBudget))
			if err != nil || !bytes.Equal(raw, ike[nonESPMarkerLen:]) {
				t.Fatalf("IKE from the peer arrived as %q, %v", raw, err)
			}
			if want := peer.LocalAddr().(*net.UDPAddr).AddrPort(); from.AddrPort() != netip.AddrPortFrom(want.Addr().Unmap(), want.Port()) {
				t.Fatalf("IKE arrived from %s, want the peer at %s", from, want)
			}
			// the socket reads its datagrams in order, so the two ahead of the ESP were counted before it arrived
			if keepalives, refused := hub.Keepalives(), hub.Refused(); keepalives != 1 || refused != 1 {
				t.Fatalf("the hub counts %d NAT keepalives and %d refused datagrams from the peer, want 1 each", keepalives, refused)
			}
		})
	}
}

// every socket a pair connects and closes is recorded with the reason it closed
// and the hub counts the sockets open and those that fell back to the shared socket
func TestPairSocketsAreRecorded(t *testing.T) {
	events := &eventLog{}
	hub, err := NewHub(":0", Underlay{}, Runtime{Events: events.record})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	fake := fakePairs(hub)
	at := listenPeer(t, "udp4", "127.0.0.1").LocalAddr().(*net.UDPAddr)
	dial := func() *Mux {
		mux, err := hub.NewMux(at.IP, at.Port)
		if err != nil {
			t.Fatal(err)
		}
		return mux
	}
	mux := dial()
	pair := fmt.Sprintf("local=%s remote=%s", fakeLocal, at.AddrPort())
	connected := "transport.pair.connected " + pair
	closed := func(reason string) string { return "transport.pair.closed " + pair + " reason=" + reason }
	var want []string
	for _, step := range []struct {
		name      string
		act       func()
		recorded  []string
		open      int
		fallbacks uint64
	}{
		{"a busy pair connects", func() { openNow(mux) }, []string{connected}, 1, 0},
		{"its socket carries nothing for a sweep", func() { hub.sweepPairs(); hub.sweepPairs() }, []string{closed(pairIdleClose)}, 0, 0},
		{"the network changes", func() { openNow(mux); hub.NetworkChanged() }, []string{connected, closed(pairNetworkClose)}, 0, 0},
		{"its socket refuses a send", func() {
			fake.refuse = unix.EADDRNOTAVAIL
			openNow(mux)
			if err := mux.SendESP([]byte("refused")); err != nil {
				t.Fatal(err)
			}
			fake.refuse = nil
		}, []string{connected, closed(pairFailedClose) + " " + slog.String("err", unix.EADDRNOTAVAIL.Error()).String()}, 0, 1},
		{"its last session ends", func() { openNow(mux); _ = mux.Close() }, []string{connected, closed(pairReleasedClose)}, 0, 1},
		{"the hub closes", func() { openNow(dial()); _ = hub.Close() }, []string{connected, closed(pairHubClose)}, 0, 1},
	} {
		step.act()
		want = append(want, step.recorded...)
		if got := events.recorded(); !slices.Equal(got, want) {
			t.Fatalf("%s: the hub recorded %q, want %q", step.name, got, want)
		}
		if got := hub.PairSockets(); got != step.open {
			t.Errorf("%s: the hub counts %d sockets open, want %d", step.name, got, step.open)
		}
		if got := hub.PairFallbacks(); got != step.fallbacks {
			t.Errorf("%s: the hub counts %d fallbacks, want %d", step.name, got, step.fallbacks)
		}
	}
}

// a hub binds its port without SO_REUSEPORT and sets it once bound
// so a second hub on the port is refused rather than let in to take a share of its datagrams
// and so is a hub on a port another socket holds with SO_REUSEPORT set before its bind
func TestHubRefusesAPortItWouldShare(t *testing.T) {
	first, err := NewHub(":0", Underlay{}, Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close() })
	sharing := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		var err error
		if controlErr := raw.Control(func(fd uintptr) { err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1) }); controlErr != nil {
			return controlErr
		}
		return err
	}}
	held, err := sharing.ListenPacket(context.Background(), "udp4", ":0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = held.Close() })
	for _, holder := range []struct {
		name string
		port int
	}{{"another hub", int(first.port)}, {"a socket that shares it", held.LocalAddr().(*net.UDPAddr).Port}} {
		hub, err := NewHub(fmt.Sprintf(":%d", holder.port), Underlay{}, Runtime{})
		if err == nil {
			_ = hub.Close()
			t.Errorf("the hub took port %d while %s held it", holder.port, holder.name)
			continue
		}
		if !errors.Is(err, syscall.EADDRINUSE) {
			t.Errorf("the hub refused port %d, which %s holds, with %q, which is not the port being in use", holder.port, holder.name, err)
		}
	}
}

// the churn the race detector watches pairs through
const (
	pairChurnPeers    = 2
	pairChurnWorkers  = 4
	pairChurnSessions = 4
	// pairChurnDatagram fills one send call with pairThreshold, so a pair opens at its first send call whatever the sweep's pace
	// smaller datagrams spread the threshold over several calls, and darwin writes one datagram a syscall, slow enough for a sweep to fall between them
	pairChurnDatagram = pairThreshold / espSendBatch
)

// transportGoroutines counts the goroutines running this package's code outside a test's own, and answers their stacks
// a count of every goroutine also takes what the runtime and the testing package run, such as a finalizer, which comes and goes on its own schedule
func transportGoroutines() (int, []string) {
	var all strings.Builder
	_ = pprof.Lookup("goroutine").WriteTo(&all, 2)
	var stacks []string
	for _, stack := range strings.Split(all.String(), "\n\n") {
		if strings.Contains(stack, "ranet3.com/pkgs/ranet3/transport.") && !strings.Contains(stack, "testing.tRunner") {
			stacks = append(stacks, stack)
		}
	}
	return len(stacks), stacks
}

// sessions come and go while their pairs connect, carry, fragment and close
// meanwhile the sweep runs, the network changes and the hub stops listening and listens again
// none of it leaves a socket or a goroutine behind once the hub closes
func TestPairsLeaveNothingBehindTheHub(t *testing.T) {
	before, _ := transportGoroutines()
	events := &eventLog{}
	hub, err := NewHub(":0", Underlay{}, Runtime{Events: events.record})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	var peers []*net.UDPAddr
	for range pairChurnPeers {
		peers = append(peers, listenPeer(t, "udp4", "127.0.0.1").LocalAddr().(*net.UDPAddr))
	}
	stop := make(chan struct{})
	var others, churn sync.WaitGroup
	others.Go(func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(pairPoll):
			}
			hub.sweepPairs()
			hub.NetworkChanged()
			hub.Listen()
			hub.StopListening()
		}
	})
	for worker := range pairChurnWorkers {
		churn.Go(func() {
			busy := numbered(espSendBatch, pairChurnDatagram)
			for session := range pairChurnSessions {
				at := peers[(worker+session)%len(peers)]
				mux, err := hub.NewMux(at.IP, at.Port)
				if err != nil {
					t.Error(err)
					return
				}
				if err := mux.Fragment(session%2 == 0); err != nil {
					t.Error(err)
				}
				for range 2 {
					if err := mux.SendESPBatch(busy); err != nil {
						t.Error(err)
					}
				}
				if err := mux.Close(); err != nil {
					t.Error(err)
				}
			}
		})
	}
	churn.Wait()
	close(stop)
	others.Wait()
	if err := hub.Close(); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(arrivalBudget); ; time.Sleep(pairPoll) {
		after, stacks := transportGoroutines()
		if after <= before {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d goroutines run the transport's code once the hub closed, where %d did before it opened:\n%s", after, before, strings.Join(stacks, "\n\n"))
		}
	}
	if open, joined := hub.PairSockets(), pairsJoined(hub); open != 0 || joined != 0 {
		t.Fatalf("the hub counts %d sockets connected to one peer open and its bind %d, want none", open, joined)
	}
	if !slices.ContainsFunc(events.recorded(), func(line string) bool { return strings.HasPrefix(line, "transport.pair.connected ") }) {
		t.Fatal("no pair connected a socket, so the churn proves nothing")
	}
}

// readOn reads one datagram from conn and fails unless it carries want from the sender at from
func readOn(t *testing.T, conn *net.UDPConn, want string, from netip.AddrPort) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(arrivalBudget)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, readBufferSize)
	n, got, err := conn.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatalf("%s never received %q: %v", conn.LocalAddr(), want, err)
	}
	if got = netip.AddrPortFrom(got.Addr().Unmap(), got.Port()); string(buf[:n]) != want || got != from {
		t.Fatalf("%s received %q from %s, want %q from %s", conn.LocalAddr(), buf[:n], got, want, from)
	}
}

// deliveredApart sends a datagram from peer and one from other, both at host, to the port at to
// and fails unless the first arrives on connected and the second on listener
func deliveredApart(t *testing.T, connected, listener, peer, other *net.UDPConn, host netip.Addr, to netip.AddrPort) {
	t.Helper()
	if bound := connected.LocalAddr().(*net.UDPAddr).AddrPort(); bound.Port() != to.Port() {
		t.Fatalf("the connected socket is bound to %s, want the listener's port %d", bound, to.Port())
	}
	for sender, payload := range map[*net.UDPConn]string{peer: "peer", other: "other"} {
		if _, err := sender.WriteToUDPAddrPort([]byte(payload), to); err != nil {
			t.Fatal(err)
		}
	}
	at := func(conn *net.UDPConn) netip.AddrPort {
		return netip.AddrPortFrom(host, uint16(conn.LocalAddr().(*net.UDPAddr).Port))
	}
	readOn(t, connected, "peer", at(peer))
	readOn(t, listener, "other", at(other))
}
