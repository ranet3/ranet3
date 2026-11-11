// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package userspace

import (
	"errors"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/events"
)

const (
	// fakeMSL and fakeMargin are the MSL and the margin the tests' fake
	// platform reads, set apart, so a read short of the margin is told from
	// one short of the hold
	fakeMSL    = 15 * time.Second
	fakeMargin = 11 * time.Second
	// fakePorts is the fake platform's automatic range, whose half is above
	// every test's Flows
	fakePorts = 1 << 14
	// leafISN is the sequence number of every leaf's SYN
	leafISN = 1000
	// peerWait is how long a test reads a peer that should see nothing yet
	peerWait = 100 * time.Millisecond
	// later is a sweep far past every hold and margin of the fake platform
	later = 10 * time.Minute
)

// fakeHostSockets is a platform's bound on host ports whose sockets read the
// state a test sets for each by its local and remote ends, else fallback, and
// whose range a test narrows
type fakeHostSockets struct {
	mu       sync.Mutex
	ports    int
	states   map[[2]netip.AddrPort]hostState
	fallback hostState
	// gate, where set, holds the next state read until it closes, and reading
	// is told of that read once it waits there. The reads after it pass.
	gate    chan struct{}
	reading chan struct{}
}

func newFakeHostSockets(fallback hostState) *fakeHostSockets {
	return &fakeHostSockets{ports: fakePorts, states: map[[2]netip.AddrPort]hostState{}, fallback: fallback}
}

func (p *fakeHostSockets) platform() *hostSockets {
	return &hostSockets{
		state: p.state,
		ports: func() (int, error) {
			p.mu.Lock()
			defer p.mu.Unlock()
			return p.ports, nil
		},
		msl:    func() (time.Duration, error) { return fakeMSL, nil },
		margin: fakeMargin,
	}
}

// state reads the socket's ends, its remote one zero where the host no longer
// names it, as after a reset or a close, where the state set for its local
// end stands
func (p *fakeHostSockets) state(raw syscall.RawConn) (hostState, error) {
	var ends [2]netip.AddrPort
	var err error
	if controlErr := raw.Control(func(fd uintptr) {
		var sa unix.Sockaddr
		if sa, err = unix.Getsockname(int(fd)); err != nil {
			return
		}
		ends[0] = sockaddrPort(sa)
		if sa, peerErr := unix.Getpeername(int(fd)); peerErr == nil {
			ends[1] = sockaddrPort(sa)
		}
	}); controlErr != nil {
		return hostClosed, controlErr
	}
	if err != nil {
		return hostClosed, err
	}
	p.mu.Lock()
	gate, reading := p.gate, p.reading
	p.gate, p.reading = nil, nil
	state, set := p.states[ends]
	for at, s := range p.states {
		if !set && !ends[1].IsValid() && at[0] == ends[0] {
			state, set = s, true
		}
	}
	if !set {
		state = p.fallback
	}
	p.mu.Unlock()
	if gate != nil {
		reading <- struct{}{}
		<-gate
	}
	return state, nil
}

// set has conn's socket read state
func (p *fakeHostSockets) set(conn *net.TCPConn, state hostState) {
	var ends [2]netip.AddrPort
	for i, addr := range []net.Addr{conn.LocalAddr(), conn.RemoteAddr()} {
		end := addr.(*net.TCPAddr).AddrPort()
		ends[i] = netip.AddrPortFrom(end.Addr().Unmap(), end.Port())
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.states[ends] = state
}

// phases is the phase of each socket h holds, in its order
func phases(h *hostHolds) []holdPhase {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []holdPhase
	for _, s := range h.sockets {
		out = append(out, s.phase)
	}
	return out
}

// listed is how many sockets and margins h lists
func listed(h *hostHolds) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.sockets)
}

// sweepAt moves the hold's clock to at and runs a sweep there
func sweepAt(h *hostHolds, clock *testClock, at time.Time) {
	clock.set(at)
	h.pass()
}

// heldConns is the host sockets h holds
func heldConns(h *hostHolds) []*net.TCPConn {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []*net.TCPConn
	for _, s := range h.sockets {
		if s.conn != nil {
			out = append(out, s.conn)
		}
	}
	return out
}

// HostPorts is half the automatic range, and no more than half of Flows,
// whichever bound is lower: macOS's default range, Linux's, a narrowed range,
// Flows below twice the range's half, and a range of one port, which bounds
// to none
func TestHostPortsIsHalfTheRangeAndAtMostHalfOfFlows(t *testing.T) {
	for _, c := range []struct {
		name               string
		ports, flows, want int
	}{
		{"macOS's default range", 65535 - 49152 + 1, 65369, 8192},
		{"Linux's default range", 60999 - 32768 + 1, 1 << 20, 14116},
		{"a narrowed range", 100, 65369, 50},
		{"flows below twice the range's half", 65535 - 49152 + 1, 1152, 576},
		{"odd counts halve to the whole number below", 9, 9, 4},
		{"a range of one port", 1, 65369, 0},
	} {
		if got := hostPortsOf(c.ports, c.flows); got != c.want {
			t.Errorf("%s: %d ports and %d flows give %d host ports, want %d", c.name, c.ports, c.flows, got, c.want)
		}
	}
}

// hostPair is a connection to a loopback server of the test's own, readied
// as the exit's dial readies its sockets, and the server's end of it
func hostPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("no loopback to dial: %v", err)
	}
	defer listener.Close()
	dialer := net.Dialer{Control: func(_, _ string, raw syscall.RawConn) error {
		var set error
		if err := raw.Control(func(fd uintptr) { set = prepareHostSocket(int(fd)) }); err != nil {
			return err
		}
		return set
	}}
	dialed, err := dialer.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn := dialed.(*net.TCPConn)
	t.Cleanup(func() { _ = conn.Close() })
	server, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return conn, server
}

// peerSaw is the read of the server's end of a pair within wait: io.EOF for
// a FIN, ECONNRESET for a reset, and a timeout where the host sent neither
func peerSaw(server *net.TCPConn, wait time.Duration) error {
	_ = server.SetReadDeadline(time.Now().Add(wait))
	_, err := server.Read(make([]byte, 1))
	return err
}

// reset is whether err is a reset's
func reset(err error) bool { return errors.Is(err, syscall.ECONNRESET) }

// timedOut is whether err is a read's deadline
func timedOut(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// testClock is a hold's clock a test sets
type testClock struct {
	mu sync.Mutex
	at time.Time
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

// set moves the clock to at and returns it
func (c *testClock) set(at time.Time) time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = at
	return at
}

// holdOn is a hold on the fake platform on a clock of the test's own, its
// flows a share of 8 and a total of 16, and the clock's start
func holdOn(t *testing.T, fake *fakeHostSockets) (*hostHolds, *testClock, time.Time) {
	t.Helper()
	start := time.Unix(1_000_000, 0)
	clock := &testClock{at: start}
	h, err := newHostHolds(fake.platform(), newFlows(8, 16))
	if err != nil {
		t.Fatal(err)
	}
	h.now = clock.now
	t.Cleanup(h.close)
	return h, clock, start
}

// countingAborts has h count each abort it makes
func countingAborts(h *hostHolds) *atomic.Int32 {
	aborts := &atomic.Int32{}
	h.abort = func(conn *net.TCPConn) error {
		aborts.Add(1)
		return abortSocket(conn)
	}
	return aborts
}

// The end step, a sweep far past every deadline and the stop each act on the
// host socket's state: one closed is released at the end step. One in
// LAST_ACK or CLOSING is watched and never aborted while the exit runs, at
// any sweep, and is aborted at the stop. One in a FIN_WAIT state or in
// TIME_WAIT is aborted at the sweep past its hold and at the stop, and one in
// no closing state at the end step itself, each slot then kept the margin.
// The server reads each abort as a reset and each plain close as a FIN. A
// crossing FIN or a server's lost ACK cannot be made on loopback at will, so
// the states are set here.
func TestEndStepSweepAndStopActOnTheHostSocketsState(t *testing.T) {
	for _, c := range []struct {
		name               string
		state              hostState
		kept               bool
		atKeep, afterSweep []holdPhase
		// abortedAtKeep, abortedBySweep and abortedAtStop are the aborts made
		// by the end step, and by then the sweep or the stop
		abortedAtKeep, abortedBySweep, abortedAtStop int32
	}{
		{"closed", hostClosed, false, nil, nil, 0, 0, 0},
		{"last ack", hostLastAck, true, []holdPhase{holdWatch}, []holdPhase{holdWatch}, 0, 0, 1},
		{"closing", hostClosing, true, []holdPhase{holdWatch}, []holdPhase{holdWatch}, 0, 0, 1},
		{"fin wait", hostFinWait, true, []holdPhase{holdWatch}, []holdPhase{holdMargin}, 0, 1, 1},
		{"time wait", hostTimeWait, true, []holdPhase{holdTimeWait}, []holdPhase{holdMargin}, 0, 1, 1},
		{"other", hostOther, true, []holdPhase{holdMargin}, nil, 1, 1, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			source := leaf4
			h, clock, start := holdOn(t, newFakeHostSockets(c.state))
			aborts := countingAborts(h)
			conn, _ := hostPair(t)
			h.flows.admit(source)
			if kept := h.keep(source, conn); kept != c.kept {
				t.Fatalf("the end step kept the slot: %t, want %t", kept, c.kept)
			}
			if got := phases(h); !slices.Equal(got, c.atKeep) || aborts.Load() != c.abortedAtKeep {
				t.Errorf("after the end step the hold keeps %v with %d aborts, want %v with %d", got, aborts.Load(), c.atKeep, c.abortedAtKeep)
			}
			sweepAt(h, clock, start.Add(later))
			if got := phases(h); !slices.Equal(got, c.afterSweep) || aborts.Load() != c.abortedBySweep {
				t.Errorf("after a sweep past every deadline the hold keeps %v with %d aborts, want %v with %d", got, aborts.Load(), c.afterSweep, c.abortedBySweep)
			}

			stopped, _, _ := holdOn(t, newFakeHostSockets(c.state))
			aborts = countingAborts(stopped)
			conn, server := hostPair(t)
			stopped.flows.admit(source)
			if !stopped.keep(source, conn) {
				stopped.flows.release(source)
			}
			stopped.close()
			if aborts.Load() != c.abortedAtStop {
				t.Errorf("by the stop the hold made %d aborts, want %d", aborts.Load(), c.abortedAtStop)
			}
			if err := peerSaw(server, exitWait); c.abortedAtStop > 0 && !reset(err) || c.abortedAtStop == 0 && !errors.Is(err, io.EOF) {
				t.Errorf("by the stop the server read %v, want a reset where aborted and a FIN otherwise", err)
			}
			if held, open := stopped.flows.heldCount(), stopped.flows.open; held != 0 || open != 0 {
				t.Errorf("after the stop %d slots are held and %d flows open, want none", held, open)
			}
		})
	}
}

// The hold keeps each socket and its slot as its state says, on the exit's
// clock, and acts on a watched socket's state before its deadline. A socket
// in TIME_WAIT is aborted at the first sweep at or past twice the MSL after
// the end step, which its server reads as a reset, and its slot comes back
// the margin after the abort returns. One closed is released at once with a
// FIN. One in LAST_ACK is watched across every sweep and, once a sweep reads
// it closed, released there with no margin. One in CLOSING is never aborted,
// and once a sweep reads it in TIME_WAIT is kept twice the MSL from that
// sweep. One in a FIN_WAIT state is aborted at the hold's end, unless the
// sweep past it reads TIME_WAIT, which starts its hold there, or CLOSING,
// which keeps it watched.
func TestHoldKeepsEachSocketItsTimeOnTheExitsClock(t *testing.T) {
	source := leaf4
	t.Run("time wait", func(t *testing.T) {
		h, clock, start := holdOn(t, newFakeHostSockets(hostTimeWait))
		conn, server := hostPair(t)
		h.flows.admit(source)
		if !h.keep(source, conn) {
			t.Fatal("the end step released a socket in TIME_WAIT")
		}
		sweepAt(h, clock, start.Add(2*fakeMSL-time.Nanosecond))
		if err := peerSaw(server, peerWait); !timedOut(err) {
			t.Fatalf("short of twice the MSL the server read %v, want nothing", err)
		}
		sweepAt(h, clock, start.Add(2*fakeMSL))
		if err := peerSaw(server, exitWait); !reset(err) {
			t.Errorf("at twice the MSL the server read %v, want the abort's reset", err)
		}
		sweepAt(h, clock, start.Add(2*fakeMSL+fakeMargin-time.Nanosecond))
		if held := h.flows.heldCount(); held != 1 {
			t.Errorf("short of the margin past the abort %d slots are held, want 1", held)
		}
		sweepAt(h, clock, start.Add(2*fakeMSL+fakeMargin))
		if held, open := h.flows.heldCount(), h.flows.open; held != 0 || open != 0 {
			t.Errorf("past the margin %d slots are held and %d flows open, want none", held, open)
		}
	})
	t.Run("margin from the abort's return", func(t *testing.T) {
		h, clock, start := holdOn(t, newFakeHostSockets(hostTimeWait))
		const aborting = 3 * time.Second
		h.abort = func(conn *net.TCPConn) error {
			clock.set(clock.now().Add(aborting))
			return abortSocket(conn)
		}
		conn, _ := hostPair(t)
		h.flows.admit(source)
		h.keep(source, conn)
		sweepAt(h, clock, start.Add(2*fakeMSL))
		returned := start.Add(2*fakeMSL + aborting)
		sweepAt(h, clock, returned.Add(fakeMargin-time.Nanosecond))
		if held := h.flows.heldCount(); held != 1 {
			t.Errorf("short of the margin past the abort's return %d slots are held, want 1", held)
		}
		sweepAt(h, clock, returned.Add(fakeMargin))
		if held := h.flows.heldCount(); held != 0 {
			t.Errorf("at the margin past the abort's return %d slots are held, want none", held)
		}
	})
	t.Run("closed", func(t *testing.T) {
		h, _, _ := holdOn(t, newFakeHostSockets(hostClosed))
		conn, server := hostPair(t)
		h.flows.admit(source)
		if h.keep(source, conn) {
			t.Fatal("the end step kept a closed socket")
		}
		h.flows.release(source)
		if err := peerSaw(server, exitWait); !errors.Is(err, io.EOF) {
			t.Errorf("the server of a released socket read %v, want its FIN", err)
		}
		if held := listed(h); held != 0 {
			t.Errorf("the hold keeps %d sockets, want none", held)
		}
	})
	t.Run("last ack", func(t *testing.T) {
		fake := newFakeHostSockets(hostLastAck)
		h, clock, start := holdOn(t, fake)
		conn, server := hostPair(t)
		h.flows.admit(source)
		if !h.keep(source, conn) {
			t.Fatal("the end step released a socket in LAST_ACK")
		}
		for _, at := range []time.Duration{2 * fakeMSL, 2*fakeMSL + fakeMargin, later} {
			sweepAt(h, clock, start.Add(at))
		}
		if err := peerSaw(server, peerWait); !timedOut(err) {
			t.Fatalf("a socket in LAST_ACK drew %v, want nothing", err)
		}
		if got, held := phases(h), h.flows.heldCount(); !slices.Equal(got, []holdPhase{holdWatch}) || held != 1 {
			t.Fatalf("past every deadline a socket in LAST_ACK is kept as %v with %d slots, want watched with 1", got, held)
		}
		fake.set(conn, hostClosed)
		sweepAt(h, clock, start.Add(later+time.Nanosecond))
		if held, open := h.flows.heldCount(), h.flows.open; held != 0 || open != 0 || listed(h) != 0 {
			t.Errorf("at the sweep that read it closed %d slots are held and %d flows open, want none and no margin", held, open)
		}
		if err := peerSaw(server, exitWait); !errors.Is(err, io.EOF) {
			t.Errorf("the server of a socket read closed read %v, want its close", err)
		}
	})
	t.Run("closing", func(t *testing.T) {
		fake := newFakeHostSockets(hostClosing)
		h, clock, start := holdOn(t, fake)
		conn, server := hostPair(t)
		h.flows.admit(source)
		h.keep(source, conn)
		found := clock.set(start.Add(later))
		h.pass()
		if err := peerSaw(server, peerWait); !timedOut(err) {
			t.Fatalf("a socket in CLOSING drew %v, want nothing", err)
		}
		fake.set(conn, hostTimeWait)
		h.pass()
		sweepAt(h, clock, found.Add(2*fakeMSL-time.Nanosecond))
		if err := peerSaw(server, peerWait); !timedOut(err) {
			t.Fatalf("short of twice the MSL from the sweep that found TIME_WAIT the server read %v", err)
		}
		sweepAt(h, clock, found.Add(2*fakeMSL))
		if err := peerSaw(server, exitWait); !reset(err) {
			t.Errorf("at twice the MSL from the sweep the server read %v, want a reset", err)
		}
	})
	t.Run("fin wait", func(t *testing.T) {
		h, clock, start := holdOn(t, newFakeHostSockets(hostFinWait))
		conn, server := hostPair(t)
		h.flows.admit(source)
		h.keep(source, conn)
		sweepAt(h, clock, start.Add(2*fakeMSL-time.Nanosecond))
		if err := peerSaw(server, peerWait); !timedOut(err) {
			t.Fatalf("short of the hold's end a socket in FIN_WAIT drew %v", err)
		}
		sweepAt(h, clock, start.Add(2*fakeMSL))
		if err := peerSaw(server, exitWait); !reset(err) {
			t.Errorf("at the hold's end the server read %v, want a reset", err)
		}
		if held := h.flows.heldCount(); held != 1 {
			t.Errorf("after the abort %d slots are held, want 1 for the margin", held)
		}
	})
	t.Run("fin wait read in time wait past its deadline", func(t *testing.T) {
		fake := newFakeHostSockets(hostFinWait)
		h, clock, start := holdOn(t, fake)
		conn, server := hostPair(t)
		h.flows.admit(source)
		h.keep(source, conn)
		fake.set(conn, hostTimeWait)
		found := clock.set(start.Add(2*fakeMSL + mappingSweep))
		h.pass()
		if err := peerSaw(server, peerWait); !timedOut(err) {
			t.Fatalf("a sweep past the deadline that read TIME_WAIT drew %v, want nothing", err)
		}
		if got := phases(h); !slices.Equal(got, []holdPhase{holdTimeWait}) {
			t.Fatalf("the sweep that read TIME_WAIT keeps %v, want a hold in TIME_WAIT", got)
		}
		sweepAt(h, clock, found.Add(2*fakeMSL-time.Nanosecond))
		if err := peerSaw(server, peerWait); !timedOut(err) {
			t.Fatalf("short of twice the MSL from the sweep that read TIME_WAIT the server read %v", err)
		}
		sweepAt(h, clock, found.Add(2*fakeMSL))
		if err := peerSaw(server, exitWait); !reset(err) {
			t.Errorf("at twice the MSL from that sweep the server read %v, want a reset", err)
		}
	})
	t.Run("fin wait read in closing past its deadline", func(t *testing.T) {
		fake := newFakeHostSockets(hostFinWait)
		h, clock, start := holdOn(t, fake)
		conn, server := hostPair(t)
		h.flows.admit(source)
		h.keep(source, conn)
		fake.set(conn, hostClosing)
		sweepAt(h, clock, start.Add(2*fakeMSL+mappingSweep))
		sweepAt(h, clock, start.Add(later))
		if err := peerSaw(server, peerWait); !timedOut(err) {
			t.Fatalf("a socket read in CLOSING past its deadline drew %v, want nothing", err)
		}
		if got := phases(h); !slices.Equal(got, []holdPhase{holdWatch}) {
			t.Errorf("sweeps that read CLOSING keep %v, want it watched", got)
		}
	})
	t.Run("other", func(t *testing.T) {
		h, clock, start := holdOn(t, newFakeHostSockets(hostOther))
		conn, server := hostPair(t)
		h.flows.admit(source)
		h.keep(source, conn)
		if err := peerSaw(server, exitWait); !reset(err) {
			t.Errorf("a socket in no closing state drew %v, want a reset at once", err)
		}
		sweepAt(h, clock, start.Add(fakeMargin-time.Nanosecond))
		if held := h.flows.heldCount(); held != 1 {
			t.Errorf("short of the margin %d slots are held, want 1", held)
		}
	})
}

// refusingAbort has h's aborts refused with EINVAL, as XNU refuses the linger
// on a socket shut both ways that SONPX_SETOPTSHUT did not ready, while the
// returned flag is set
func refusingAbort(h *hostHolds) *atomic.Bool {
	refusing := &atomic.Bool{}
	refusing.Store(true)
	h.abort = func(conn *net.TCPConn) error {
		if refusing.Load() {
			return syscall.EINVAL
		}
		return abortSocket(conn)
	}
	return refusing
}

// An abort the host refuses ends no hold: the socket stays in the list as it
// was, open and its slot held past twice the MSL and the margin, and the next
// sweep aborts it again, where the host takes it, keeping the slot the margin
// from then. At the end step a socket in no closing state is kept and aborted
// the same way. The stop closes a socket the host refuses to abort without
// the linger and gives its slot back.
func TestRefusedAbortKeepsTheSocketForTheNextSweep(t *testing.T) {
	source := leaf4
	t.Run("at the hold's end", func(t *testing.T) {
		h, clock, start := holdOn(t, newFakeHostSockets(hostTimeWait))
		refusing := refusingAbort(h)
		conn, server := hostPair(t)
		h.flows.admit(source)
		h.keep(source, conn)
		sweepAt(h, clock, start.Add(2*fakeMSL))
		sweepAt(h, clock, start.Add(2*fakeMSL+fakeMargin))
		if err := peerSaw(server, peerWait); !timedOut(err) {
			t.Fatalf("after a refused abort the server read %v, want nothing", err)
		}
		if got, held := phases(h), h.flows.heldCount(); !slices.Equal(got, []holdPhase{holdTimeWait}) || held != 1 {
			t.Fatalf("past the hold and the margin after refused aborts the hold keeps %v with %d slots, want the hold in TIME_WAIT with 1", got, held)
		}
		refusing.Store(false)
		taken := clock.set(start.Add(3 * fakeMSL))
		h.pass()
		if err := peerSaw(server, exitWait); !reset(err) {
			t.Errorf("once the host took the abort the server read %v, want a reset", err)
		}
		sweepAt(h, clock, taken.Add(fakeMargin-time.Nanosecond))
		if held := h.flows.heldCount(); held != 1 {
			t.Errorf("short of the margin past the abort the host took %d slots are held, want 1", held)
		}
		sweepAt(h, clock, taken.Add(fakeMargin))
		if held := h.flows.heldCount(); held != 0 {
			t.Errorf("past the margin %d slots are held, want none", held)
		}
	})
	t.Run("at the end step", func(t *testing.T) {
		h, clock, start := holdOn(t, newFakeHostSockets(hostOther))
		refusing := refusingAbort(h)
		conn, server := hostPair(t)
		h.flows.admit(source)
		h.keep(source, conn)
		sweepAt(h, clock, start.Add(fakeMargin))
		if err := peerSaw(server, peerWait); !timedOut(err) {
			t.Fatalf("after a refused abort the server read %v, want nothing", err)
		}
		if held := h.flows.heldCount(); held != 1 {
			t.Fatalf("past the margin after a refused abort %d slots are held, want 1", held)
		}
		refusing.Store(false)
		sweepAt(h, clock, start.Add(2*fakeMargin))
		if err := peerSaw(server, exitWait); !reset(err) {
			t.Errorf("once the host took the abort the server read %v, want a reset", err)
		}
		if got := phases(h); !slices.Equal(got, []holdPhase{holdMargin}) {
			t.Errorf("after the abort the host took the hold keeps %v, want the margin", got)
		}
	})
	t.Run("stop", func(t *testing.T) {
		h, clock, start := holdOn(t, newFakeHostSockets(hostTimeWait))
		refusingAbort(h)
		conn, server := hostPair(t)
		h.flows.admit(source)
		h.keep(source, conn)
		sweepAt(h, clock, start.Add(2*fakeMSL))
		h.close()
		if err := peerSaw(server, exitWait); !errors.Is(err, io.EOF) {
			t.Errorf("the stop left a socket the host refused to abort to a server reading %v, want its close", err)
		}
		if held, open := h.flows.heldCount(), h.flows.open; held != 0 || open != 0 {
			t.Errorf("after the stop %d slots are held and %d flows open, want none", held, open)
		}
	})
}

// leafConn is one TCP connection a test plays the leaf of through a relay
// harness: the leaf's next sequence number and the stack's
type leafConn struct {
	leaf, server netip.AddrPort
	seq, ack     uint32
}

// refusals is the exit's count of refusals by reason
func (h *relayHarness) refusals() map[string]uint64 {
	h.x.counts.mu.Lock()
	defer h.x.counts.mu.Unlock()
	return maps.Clone(h.x.counts.refused)
}

// syn sends leaf's SYN toward server and reports the reason the exit refused
// it for, empty where it admitted it
func (h *relayHarness) syn(t *testing.T, leaf, server netip.AddrPort) string {
	t.Helper()
	before := h.refusals()
	if !h.x.link.deliver(tcpSegment(leaf, server, leafISN, 0, tcpSYN, nil)) {
		t.Fatal("the link refused the leaf's SYN")
	}
	for reason, n := range h.refusals() {
		if n > before[reason] {
			return reason
		}
	}
	return ""
}

// open runs leaf's handshake toward server through the relay once its dial is
// up, failing where the exit refused it
func (h *relayHarness) open(t *testing.T, leaf, server netip.AddrPort) *leafConn {
	t.Helper()
	if reason := h.syn(t, leaf, server); reason != "" {
		t.Fatalf("the exit refused %s's connection toward %s past %s", leaf, server, reason)
	}
	synAck := h.waitLaid(t, "the SYN-ACK toward "+leaf.String(), func(raw []byte) bool {
		p, ok := parse(raw)
		return ok && p.protocol == protoTCP && p.flags == tcpSYN|tcpACK && netip.AddrPortFrom(p.dst, p.dstPort) == leaf
	})
	p, _ := parse(synAck)
	c := &leafConn{leaf: leaf, server: server, seq: leafISN + 1, ack: p.seq + 1}
	if !h.x.link.deliver(tcpSegment(leaf, server, c.seq, c.ack, tcpACK, nil)) {
		t.Fatal("the link refused the leaf's ACK")
	}
	return c
}

// stackFIN waits for the FIN the stack sends c's leaf and reports the
// sequence number past it
func (h *relayHarness) stackFIN(t *testing.T, c *leafConn) uint32 {
	t.Helper()
	fin := h.waitLaid(t, "the stack's FIN toward "+c.leaf.String(), func(raw []byte) bool {
		p, ok := parse(raw)
		return ok && p.protocol == protoTCP && p.flags&tcpFIN != 0 && netip.AddrPortFrom(p.dst, p.dstPort) == c.leaf
	})
	p, _ := parse(fin)
	return p.seq + uint32(p.payload) + 1
}

// closeFirst closes c from the leaf first: its FIN, then once the server has
// closed in turn the ACK of the stack's FIN
func (h *relayHarness) closeFirst(t *testing.T, c *leafConn) {
	t.Helper()
	h.x.link.deliver(tcpSegment(c.leaf, c.server, c.seq, c.ack, tcpACK|tcpFIN, nil))
	c.seq++
	c.ack = h.stackFIN(t, c)
	h.x.link.deliver(tcpSegment(c.leaf, c.server, c.seq, c.ack, tcpACK, nil))
}

// closeAfter closes c from the leaf only once it has read the FIN the stack
// sent it for the server's end
func (h *relayHarness) closeAfter(t *testing.T, c *leafConn) {
	t.Helper()
	c.ack = h.stackFIN(t, c)
	h.x.link.deliver(tcpSegment(c.leaf, c.server, c.seq, c.ack, tcpACK|tcpFIN, nil))
}

// waitConnections waits until the relay counts connections open
func (h *relayHarness) waitConnections(t *testing.T, connections int) {
	t.Helper()
	deadline := time.Now().Add(exitWait)
	for h.x.tcp.held()[1] != connections {
		if time.Now().After(deadline) {
			t.Fatalf("the relay holds dials, connections and flows %v, want %d connections", h.x.tcp.held(), connections)
		}
		time.Sleep(time.Millisecond)
	}
}

// tcpServer is a loopback server of the test's own on address, answering each
// connection as serve does
func tcpServer(t *testing.T, address netip.Addr, serve func(*net.TCPConn)) netip.AddrPort {
	t.Helper()
	listener, err := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(netip.AddrPortFrom(address, 0)))
	if err != nil {
		t.Skipf("no loopback to serve on: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.AcceptTCP()
			if err != nil {
				return
			}
			go serve(conn)
		}
	}()
	return listener.Addr().(*net.TCPAddr).AddrPort()
}

// readsToTheEnd reads to the client's FIN and closes, so the host's socket
// closes first
func readsToTheEnd(conn *net.TCPConn) {
	_ = conn.SetDeadline(time.Now().Add(exitWait))
	_, _ = io.Copy(io.Discard, conn)
	_ = conn.Close()
}

// sendsAndCloses sends a byte and closes first
func sendsAndCloses(conn *net.TCPConn) {
	_, _ = conn.Write([]byte{1})
	_ = conn.Close()
}

// resetsOn resets each connection once now closes, so the exit's dial has
// returned before the reset reaches it, which a dial whose socket already
// holds the reset fails with
func resetsOn(now <-chan struct{}) func(*net.TCPConn) {
	return func(conn *net.TCPConn) {
		select {
		case <-now:
		case <-time.After(exitWait):
		}
		_ = conn.SetLinger(0)
		_ = conn.Close()
	}
}

// holdHarness is a relay harness whose platform bounds the host ports
// through platform, with a share of 4 and Flows of 12, so HostPorts is 6,
// events recorded on bus, IPv4's loopback reachable from a leaf through the
// stack, and each dial toward server6 held until release
func holdHarness(t *testing.T, platform *hostSockets) (h *relayHarness, bus *events.Bus, release func()) {
	t.Helper()
	gate := make(chan struct{})
	bus = events.New()
	h = newRelayHarness(t, func(rt *Runtime, cfg *egress.Egress) {
		rt.Platform.hostSockets = platform
		rt.Limits.Flows = 12
		rt.Events = bus
		cfg.FlowsPerSource = 4
		prepare := rt.Platform.Prepare
		rt.Platform.Prepare = func(network string, to netip.AddrPort, raw syscall.RawConn) error {
			if to.Addr() == server6 {
				<-gate
				return syscall.ENETUNREACH
			}
			return prepare(network, to, raw)
		}
	})
	release = sync.OnceFunc(func() { close(gate) })
	t.Cleanup(release)
	allowLoopback(t, h.x.stack)
	return h, bus, release
}

// allowLoopback has s take a leaf's segments toward IPv4's loopback, which
// gVisor drops on a NIC that is not a loopback by default, so a server of the
// test's own is reached through the stack as a server off the host is. IPv6
// takes the option only at a stack's start.
func allowLoopback(t *testing.T, s *stack.Stack) {
	t.Helper()
	allow := tcpip.AllowExternalLoopbackTrafficOption(true)
	if err := s.SetNetworkProtocolOption(ipv4.ProtocolNumber, &allow); err != nil {
		t.Fatalf("the stack takes no loopback: %s", err)
	}
}

// refusedReasons is the reasons of the egress.refused records on bus
func refusedReasons(bus *events.Bus) []string {
	var reasons []string
	for _, event := range bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "egress.refused" }, 0) {
		reasons = append(reasons, event.Attrs["reason"])
	}
	return reasons
}

// sourceHeld is the flows and the held flows the status reports for source
func sourceHeld(f *egress.Flows, source netip.Addr) (flows, held int) {
	for _, s := range f.Sources {
		if s.Source == source {
			return s.Flows, s.Held
		}
	}
	return 0, 0
}

// The relay's open TCP connections and its held slots count together against
// HostPorts, across families: with three IPv4 connections open and three
// IPv6 ones dialing a seventh is refused past the host ports, still once the
// IPv4 ones closed first and are held, which the status reports with the
// source's held count, and admitted once the dials have failed. A source
// whose slots held outnumber its open ones is refused past its share as share
// held, counted among the share's refusals, one holding fewer as share. A
// server-first close read closed and a server's reset give the slot back at
// the relay's end, and one read in LAST_ACK keeps it until a sweep reads it
// closed. A withdraw's reset leaves a socket it reads in TIME_WAIT to the end
// step, which holds it twice the MSL and its slot the margin past the abort,
// and aborts one in any state before, CLOSING and LAST_ACK among them, keeping
// none. On the exit's clock the held slots stay to twice the MSL and the
// margin, and come back past them. Each refusal is recorded with its reason.
func TestHostPortsCountOpenAndHeldConnectionsAcrossFamilies(t *testing.T) {
	loopback := netip.MustParseAddr("127.0.0.1")
	leafFirst := tcpServer(t, loopback, readsToTheEnd)
	third := netip.MustParseAddr("192.0.2.3")
	t.Run("host ports", func(t *testing.T) {
		h, bus, release := holdHarness(t, newFakeHostSockets(hostTimeWait).platform())
		var open []*leafConn
		for i := range 3 {
			open = append(open, h.open(t, netip.AddrPortFrom(leaf4, uint16(42100+i)), leafFirst))
			if reason := h.syn(t, netip.AddrPortFrom(leaf6, uint16(42100+i)), netip.AddrPortFrom(server6, 80)); reason != "" {
				t.Fatalf("the IPv6 dial %d was refused past %s", i, reason)
			}
		}
		seventh := netip.AddrPortFrom(third, 42199)
		if reason := h.syn(t, seventh, leafFirst); reason != reasonHostPorts {
			t.Fatalf("with six connections open a seventh was refused past %q, want %q", reason, reasonHostPorts)
		}
		for _, c := range open {
			h.closeFirst(t, c)
		}
		h.waitConnections(t, 3)
		if held := h.x.flows.heldCount(); held != 3 {
			t.Fatalf("%d slots held after three leaf-first closes, want 3", held)
		}
		status := h.x.Status().Flows
		if got := status.Host; got == nil || *got != (egress.HostHold{Held: 3, Ports: 6, Bound: 6}) {
			t.Errorf("with three held and three dialing the status counts %+v, want 3 held and 6 host ports of 6", got)
		}
		if flows, held := sourceHeld(status, leaf4); flows != 3 || held != 3 {
			t.Errorf("the status gives %s %d flows with %d held, want 3 with 3", leaf4, flows, held)
		}
		if reason := h.syn(t, seventh, leafFirst); reason != reasonHostPorts {
			t.Fatalf("with three held and three dialing a seventh was refused past %q, want %q", reason, reasonHostPorts)
		}
		release()
		h.waitConnections(t, 0)
		h.closeFirst(t, h.open(t, seventh, leafFirst))
		h.waitConnections(t, 0)
		if got := refusedReasons(bus); !slices.Equal(got, []string{reasonHostPorts}) {
			t.Errorf("recorded refusals %v, want one for the host ports", got)
		}
	})
	t.Run("share held", func(t *testing.T) {
		h, bus, _ := holdHarness(t, newFakeHostSockets(hostTimeWait).platform())
		for i := range 4 {
			h.closeFirst(t, h.open(t, netip.AddrPortFrom(leaf4, uint16(42200+i)), leafFirst))
		}
		h.waitConnections(t, 0)
		if reason := h.syn(t, netip.AddrPortFrom(leaf4, 42204), leafFirst); reason != reasonShareHeld {
			t.Fatalf("a source holding four closed slots was refused past %q, want %q", reason, reasonShareHeld)
		}
		if got := refusedReasons(bus); !slices.Equal(got, []string{reasonShareHeld}) {
			t.Errorf("recorded refusals %v, want one for share held", got)
		}
		if status := h.x.Status(); status.Refused4 != 1 || status.Refused6 != 0 {
			t.Errorf("the share's refusals count %d IPv4 and %d IPv6, want the one IPv4", status.Refused4, status.Refused6)
		}
	})
	t.Run("share", func(t *testing.T) {
		h, _, _ := holdHarness(t, newFakeHostSockets(hostTimeWait).platform())
		h.closeFirst(t, h.open(t, netip.AddrPortFrom(leaf4, 42250), leafFirst))
		for i := range 3 {
			h.open(t, netip.AddrPortFrom(leaf4, uint16(42251+i)), leafFirst)
		}
		h.waitConnections(t, 3)
		if reason := h.syn(t, netip.AddrPortFrom(leaf4, 42254), leafFirst); reason != reasonShare {
			t.Errorf("a source with three open and one held was refused past %q, want %q", reason, reasonShare)
		}
	})
	t.Run("server first and reset", func(t *testing.T) {
		h, _, _ := holdHarness(t, newFakeHostSockets(hostClosed).platform())
		serverFirst := tcpServer(t, loopback, sendsAndCloses)
		resetNow := make(chan struct{})
		resetting := tcpServer(t, loopback, resetsOn(resetNow))
		h.closeAfter(t, h.open(t, netip.AddrPortFrom(leaf4, 42300), serverFirst))
		h.waitConnections(t, 0)
		h.open(t, netip.AddrPortFrom(leaf4, 42301), resetting)
		close(resetNow)
		h.waitConnections(t, 0)
		if held := h.x.tcp.held(); held != [3]int{} || h.x.flows.heldCount() != 0 {
			t.Errorf("after a server-first close and a reset the relay holds %v and %d slots, want none", held, h.x.flows.heldCount())
		}
	})
	t.Run("server first in last ack", func(t *testing.T) {
		fake := newFakeHostSockets(hostLastAck)
		h, _, _ := holdHarness(t, fake.platform())
		serverFirst := tcpServer(t, loopback, sendsAndCloses)
		h.closeAfter(t, h.open(t, netip.AddrPortFrom(leaf4, 42310), serverFirst))
		h.waitConnections(t, 0)
		for range 2 * int((2*fakeMSL+fakeMargin)/mappingSweep) {
			h.advance(mappingSweep)
		}
		conns := heldConns(h.x.tcp.holds)
		if len(conns) != 1 || h.x.flows.heldCount() != 1 {
			t.Fatalf("past every deadline the hold keeps %d sockets and %d slots, want the one in LAST_ACK", len(conns), h.x.flows.heldCount())
		}
		fake.set(conns[0], hostClosed)
		h.advance(mappingSweep)
		if held := h.x.flows.heldCount(); held != 0 || listed(h.x.tcp.holds) != 0 {
			t.Errorf("at the sweep that read it closed %d slots are held, want none and no margin", held)
		}
	})
	t.Run("reset in time wait", func(t *testing.T) {
		h, _, _ := holdHarness(t, newFakeHostSockets(hostTimeWait).platform())
		h.open(t, netip.AddrPortFrom(leaf4, 42320), leafFirst)
		flow := listedFlow(t, h)
		h.x.tcp.withdraw()
		h.waitConnections(t, 0)
		if got, held := phases(h.x.tcp.holds), h.x.flows.heldCount(); !slices.Equal(got, []holdPhase{holdTimeWait}) || held != 1 {
			t.Fatalf("after a reset of a socket read in TIME_WAIT the hold keeps %v with %d slots, want the hold in TIME_WAIT with 1", got, held)
		}
		if err := stillOpen(flow.conn); err != nil {
			t.Fatalf("the reset aborted a socket it read in TIME_WAIT: %v", err)
		}
		h.advance(2*fakeMSL - time.Second)
		if err := stillOpen(flow.conn); err != nil {
			t.Fatalf("short of twice the MSL the hold aborted the socket: %v", err)
		}
		h.advance(time.Second)
		h.advance(fakeMargin - time.Second)
		if err := stillOpen(flow.conn); err == nil || h.x.flows.heldCount() != 1 {
			t.Errorf("short of the margin past the hold's end the socket is open: %t, with %d slots held, want aborted with 1", err == nil, h.x.flows.heldCount())
		}
		h.advance(time.Second)
		if held := h.x.flows.heldCount(); held != 0 {
			t.Errorf("at the margin past the hold's end %d slots are held, want none", held)
		}
	})
	t.Run("reset before time wait", func(t *testing.T) {
		for i, state := range []hostState{hostOther, hostFinWait, hostClosing, hostLastAck} {
			h, _, _ := holdHarness(t, newFakeHostSockets(state).platform())
			h.open(t, netip.AddrPortFrom(leaf4, uint16(42330+i)), leafFirst)
			flow := listedFlow(t, h)
			h.x.tcp.withdraw()
			h.waitConnections(t, 0)
			if held := h.x.flows.heldCount(); held != 0 || listed(h.x.tcp.holds) != 0 {
				t.Errorf("after a reset of a socket read in state %d %d slots are held, want none", state, held)
			}
			if err := stillOpen(flow.conn); err == nil {
				t.Errorf("a reset left a socket read in state %d open, want it aborted", state)
			}
		}
	})
	t.Run("on the exit's clock", func(t *testing.T) {
		h, _, _ := holdHarness(t, newFakeHostSockets(hostTimeWait).platform())
		for i := range 4 {
			h.closeFirst(t, h.open(t, netip.AddrPortFrom(leaf4, uint16(42400+i)), leafFirst))
		}
		h.waitConnections(t, 0)
		next := netip.AddrPortFrom(leaf4, 42404)
		h.advance(2 * fakeMSL)
		h.advance(fakeMargin - time.Second)
		if reason := h.syn(t, next, leafFirst); reason != reasonShareHeld {
			t.Fatalf("short of the margin past the aborts a new flow was refused past %q, want %q", reason, reasonShareHeld)
		}
		h.advance(2 * time.Second)
		if held := h.x.flows.heldCount(); held != 0 {
			t.Fatalf("past the margin %d slots are held, want none", held)
		}
		h.closeFirst(t, h.open(t, next, leafFirst))
	})
}

// On a platform that bounds no host ports, as Linux's, a leaf-first close
// closes its host socket and gives its slot back at the relay's end, nothing
// is held, and the status reports no bound and no held connection
func TestExitWithNoBoundOnHostPortsHoldsNothing(t *testing.T) {
	h := newRelayHarness(t, func(_ *Runtime, cfg *egress.Egress) { cfg.FlowsPerSource = 1 })
	allowLoopback(t, h.x.stack)
	server := tcpServer(t, netip.MustParseAddr("127.0.0.1"), readsToTheEnd)
	c := h.open(t, netip.AddrPortFrom(leaf4, 42800), server)
	flow := listedFlow(t, h)
	h.closeFirst(t, c)
	h.waitConnections(t, 0)
	if err := stillOpen(flow.conn); err == nil {
		t.Error("the relay's end left its host socket open")
	}
	if held := h.x.tcp.held(); held != [3]int{} || h.x.tcp.holds != nil {
		t.Errorf("the relay holds dials, connections and flows %v, want none and no hold", held)
	}
	h.closeFirst(t, h.open(t, netip.AddrPortFrom(leaf4, 42801), server))
	if got := h.x.Status().Flows.Host; got != nil {
		t.Errorf("the status reports a hold %+v, want none", *got)
	}
}

// A range of one port bounds HostPorts to none, which refuses every new TCP
// connection past the host ports rather than lifting the bound, and which the
// status reports as a bound of 0
func TestRangeOfOnePortRefusesEveryConnection(t *testing.T) {
	fake := newFakeHostSockets(hostTimeWait)
	fake.ports = 1
	h, _, _ := holdHarness(t, fake.platform())
	if reason := h.syn(t, netip.AddrPortFrom(leaf4, 42900), netip.AddrPortFrom(server4, 80)); reason != reasonHostPorts {
		t.Errorf("under a range of one port a connection was refused past %q, want %q", reason, reasonHostPorts)
	}
	if got := h.x.Status().Flows.Host; got == nil || *got != (egress.HostHold{}) {
		t.Errorf("under a range of one port the status reports a hold %+v, want a bound of 0 with none held", got)
	}
}

// The exit's stop aborts every host socket the hold keeps, one in LAST_ACK
// as one in TIME_WAIT, and gives every slot back
func TestExitCloseAbortsEverySocketTheHoldKeeps(t *testing.T) {
	fake := newFakeHostSockets(hostTimeWait)
	h, _, _ := holdHarness(t, fake.platform())
	server := tcpServer(t, netip.MustParseAddr("127.0.0.1"), readsToTheEnd)
	for i := range 2 {
		h.closeFirst(t, h.open(t, netip.AddrPortFrom(leaf4, uint16(42950+i)), server))
	}
	h.waitConnections(t, 0)
	conns := heldConns(h.x.tcp.holds)
	if len(conns) != 2 || h.x.flows.heldCount() != 2 {
		t.Fatalf("after two leaf-first closes the hold keeps %d sockets and %d slots, want 2 and 2", len(conns), h.x.flows.heldCount())
	}
	fake.set(conns[1], hostLastAck)
	aborts := countingAborts(h.x.tcp.holds)
	closeWithin(t, h.x)
	if n := aborts.Load(); n != 2 {
		t.Errorf("the stop made %d aborts, want 2", n)
	}
	for i, conn := range conns {
		if err := stillOpen(conn); err == nil {
			t.Errorf("the stop left held socket %d open", i)
		}
	}
	if held, open := h.x.flows.heldCount(), h.x.flows.open; held != 0 || open != 0 {
		t.Errorf("after the stop %d slots are held and %d flows open, want none", held, open)
	}
}

// A range narrowed between two sweeps lowers HostPorts for the admissions
// after the second: under a range of 10 ports HostPorts is 5, and with four
// dials held open a narrowing to 6 ports refuses a fifth dial past its 3 only
// once a sweep has read it
func TestNarrowedRangeLowersHostPortsAtTheNextSweep(t *testing.T) {
	fake := newFakeHostSockets(hostTimeWait)
	fake.ports = 10
	h, _, _ := holdHarness(t, fake.platform())
	for i := range 3 {
		if reason := h.syn(t, netip.AddrPortFrom(leaf6, uint16(42500+i)), netip.AddrPortFrom(server6, 80)); reason != "" {
			t.Fatalf("dial %d was refused past %s", i, reason)
		}
	}
	fake.mu.Lock()
	fake.ports = 6
	fake.mu.Unlock()
	if reason := h.syn(t, netip.AddrPortFrom(other6, 42503), netip.AddrPortFrom(server6, 80)); reason != "" {
		t.Fatalf("before the sweep a fourth dial was refused past %s", reason)
	}
	h.advance(mappingSweep)
	if reason := h.syn(t, netip.AddrPortFrom(other6, 42504), netip.AddrPortFrom(server6, 80)); reason != reasonHostPorts {
		t.Errorf("after the sweep read a range of 6 a fifth dial was refused past %q, want %q", reason, reasonHostPorts)
	}
}

// A connection whose leaf endpoint failed after its dial half closes its host
// socket and keeps its slot through the end step: in a FIN_WAIT state the
// slot stays held, and its dial and connection are given back
func TestFailedLeafEndpointKeepsTheSlotOfItsHalfClosedSocket(t *testing.T) {
	h, _, _ := holdHarness(t, newFakeHostSockets(hostFinWait).platform())
	conn, server := hostPair(t)
	id := stack.TransportEndpointID{LocalPort: 80, LocalAddress: tcpip.AddrFrom4(server4.As4()), RemotePort: 42600, RemoteAddress: tcpip.AddrFrom4(leaf4.As4())}
	r := h.x.tcp
	r.mu.Lock()
	r.dialing[id] = nil
	r.dials++
	r.connections++
	r.mu.Unlock()
	if reason, ok := h.x.flows.admit(leaf4); !ok {
		t.Fatalf("refused past %s", reason)
	}
	r.endpointFailed(id, leaf4, conn)
	if err := peerSaw(server, exitWait); !errors.Is(err, io.EOF) {
		t.Errorf("the server read %v, want the host's FIN", err)
	}
	if held := r.held(); held != [3]int{0, 0, 1} || h.x.flows.heldCount() != 1 {
		t.Errorf("the relay holds dials, connections and flows %v with %d held, want the one flow held", held, h.x.flows.heldCount())
	}
}

// The ended mark and the flow's leaving the list before its end step keep the
// host socket the end step owns from a withdraw: a withdraw that runs while
// the end step reads the socket's state leaves the socket the hold keeps
// open, and so does the reset of a withdraw that listed the flow before its
// end. The end step reads TIME_WAIT, and each reset after it a state it would
// abort in.
func TestWithdrawLeavesTheSocketTheEndStepKeeps(t *testing.T) {
	fake := newFakeHostSockets(hostTimeWait)
	h, _, _ := holdHarness(t, fake.platform())
	server := tcpServer(t, netip.MustParseAddr("127.0.0.1"), readsToTheEnd)
	c := h.open(t, netip.AddrPortFrom(leaf4, 42700), server)
	flow := listedFlow(t, h)
	gate, reading := make(chan struct{}), make(chan struct{})
	fake.mu.Lock()
	fake.gate, fake.reading = gate, reading
	fake.mu.Unlock()
	h.x.link.deliver(tcpSegment(c.leaf, c.server, c.seq, c.ack, tcpACK|tcpFIN, nil))
	select {
	case <-reading:
	case <-time.After(exitWait):
		t.Fatal("the end step read no state")
	}
	fake.set(flow.conn, hostOther)
	h.x.tcp.withdraw()
	close(gate)
	h.waitConnections(t, 0)
	kept := heldConns(h.x.tcp.holds)
	if len(kept) != 1 {
		t.Fatalf("the hold keeps %d sockets, want 1", len(kept))
	}
	if err := stillOpen(kept[0]); err != nil {
		t.Errorf("withdraw closed the socket the end step keeps: %v", err)
	}
	flow.reset()
	if err := stillOpen(kept[0]); err != nil {
		t.Errorf("the reset of a withdraw that listed the flow closed the socket the end step keeps: %v", err)
	}
}

// listedFlow waits for the relay to list its one flow, and returns it
func listedFlow(t *testing.T, h *relayHarness) *tcpFlow {
	t.Helper()
	deadline := time.Now().Add(exitWait)
	for {
		h.x.tcp.mu.Lock()
		for f := range h.x.tcp.flows {
			h.x.tcp.mu.Unlock()
			return f
		}
		h.x.tcp.mu.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("the relay lists no flow")
		}
		time.Sleep(time.Millisecond)
	}
}

// stillOpen is nil where conn's descriptor is open
func stillOpen(conn *net.TCPConn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	return raw.Control(func(uintptr) {})
}
