// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package userspace

import (
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// hostState is a host TCP socket's state as the hold reads it
type hostState uint8

const (
	hostClosed hostState = iota
	// hostLastAck waits for the server to acknowledge the host's FIN, the
	// server having closed first
	hostLastAck
	// hostClosing waits for the server to acknowledge the host's FIN, the two
	// FINs having crossed
	hostClosing
	// hostFinWait is FIN_WAIT_1 or FIN_WAIT_2
	hostFinWait
	hostTimeWait
	// hostOther is any state before both FINs: established, close wait or a
	// handshake's
	hostOther
)

// hostSockets is the platform's part of the bound on the host ports the TCP
// relay's closed connections pin
type hostSockets struct {
	// state reads a host socket's TCP state
	state func(raw syscall.RawConn) (hostState, error)
	// ports reads how many ports the host's automatic range holds
	ports func() (int, error)
	// msl reads the host's maximum segment lifetime
	msl func() (time.Duration, error)
	// margin keeps a slot past the close that ends a TIME_WAIT, while the
	// host may still reserve its port
	margin time.Duration
}

// hostPortsOf is the most host ports the relay's open TCP connections and its
// held slots take together: half the automatic range, so the host keeps the
// other half for its own connections, and half of flows, so the UDP and echo
// mappings keep at least the other half of every flow
func hostPortsOf(ports, flows int) int {
	return min(ports/2, flows/2)
}

// abortSocket closes conn with a linger of 0, which sends the server a reset
// in any state before TIME_WAIT, and ends a TIME_WAIT the host still holds
// with a reset as well. Where the host refuses the linger it leaves conn open
// and returns the refusal, for the caller to close or try again. A conn
// already closed has nothing left to abort.
func abortSocket(conn *net.TCPConn) error {
	if err := conn.SetLinger(0); errors.Is(err, net.ErrClosed) {
		return nil
	} else if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}

// holdPhase names a sweep's act on a held socket
type holdPhase uint8

const (
	// holdWatch reads the socket's state again. A socket in CLOSING or
	// LAST_ACK, whose last bytes may be unacknowledged, is never aborted while
	// the exit runs, only at its stop, and one in a FIN_WAIT state or an
	// earlier one is aborted at its deadline.
	holdWatch holdPhase = iota
	// holdTimeWait aborts a socket read in TIME_WAIT at its deadline, twice
	// the MSL from that read. The abort sends the server a reset wherever the
	// host still holds the TIME_WAIT, as XNU does past twice the MSL until its
	// PCB collector runs.
	holdTimeWait
	// holdMargin keeps the slot of a socket the hold aborted until its
	// deadline, the margin past that abort
	holdMargin
)

// heldSocket is one connection's slot kept past its relay's end, with its
// host socket until the hold closes it
type heldSocket struct {
	source netip.Addr
	conn   *net.TCPConn
	phase  holdPhase
	// until is the phase's deadline, zero for a socket watched with none
	until time.Time
}

// hostHolds keeps the slot of each TCP connection whose host socket may pin
// its port past the relay's end, in flows and against hostPortsOf. A nil
// hostHolds holds nothing and bounds nothing, as on a platform with no
// hostSockets.
type hostHolds struct {
	platform *hostSockets
	flows    *flows
	now      func() time.Time
	// abort is abortSocket
	abort func(*net.TCPConn) error
	// bound is hostPortsOf and msl the MSL in nanoseconds, as the last sweep
	// read them
	bound, msl atomic.Int64
	// unread is whether the last sweep failed to read the range or the MSL,
	// so a failure that persists is logged once
	unread bool
	// refusedOnce logs the first abort the host refuses
	refusedOnce sync.Once

	mu      sync.Mutex
	sockets []*heldSocket
}

// newHostHolds is the hold of a platform that bounds the host ports, nil
// where platform is nil, refused where the range or the MSL does not read
func newHostHolds(platform *hostSockets, f *flows) (*hostHolds, error) {
	if platform == nil {
		return nil, nil
	}
	h := &hostHolds{platform: platform, flows: f, now: time.Now, abort: abortSocket}
	if err := h.read(); err != nil {
		return nil, err
	}
	return h, nil
}

func (h *hostHolds) read() error {
	ports, err := h.platform.ports()
	if err != nil {
		return fmt.Errorf("egress: the userspace exit could not read the host's automatic port range: %w", err)
	}
	msl, err := h.platform.msl()
	if err != nil {
		return fmt.Errorf("egress: the userspace exit could not read the host's maximum segment lifetime: %w", err)
	}
	h.bound.Store(int64(hostPortsOf(ports, h.flows.total)))
	h.msl.Store(int64(msl))
	return nil
}

// limit is how many host ports the relay's open and held TCP connections may
// take together, with no bound where nothing holds
func (h *hostHolds) limit() int {
	if h == nil {
		return math.MaxInt
	}
	return int(h.bound.Load())
}

// state reads conn's state, hostClosed with the error where it does not read
func (h *hostHolds) state(conn *net.TCPConn) (hostState, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return hostClosed, err
	}
	return h.platform.state(raw)
}

// timeWait reports whether conn reads TIME_WAIT, false where nothing holds
func (h *hostHolds) timeWait(conn *net.TCPConn) bool {
	if h == nil {
		return false
	}
	state, err := h.state(conn)
	return err == nil && state == hostTimeWait
}

// keep is the end step for conn, a connection of source whose relay is over,
// and reports whether its slot stays. A socket read closed is closed and
// released. One in TIME_WAIT is held twice the MSL. One in CLOSING or LAST_ACK
// is watched with no deadline, and one in a FIN_WAIT state with a deadline
// twice the MSL on. One in any other state, or whose state does not read, is
// aborted at once and its slot kept the margin. Where nothing holds, conn is
// closed and released.
func (h *hostHolds) keep(source netip.Addr, conn *net.TCPConn) bool {
	if h == nil {
		_ = conn.Close()
		return false
	}
	state, err := h.state(conn)
	if err != nil {
		state = hostOther
	}
	if state == hostClosed {
		_ = conn.Close()
		return false
	}
	h.flows.hold(source)
	msl := time.Duration(h.msl.Load())
	s := &heldSocket{source: source, conn: conn}
	switch state {
	case hostTimeWait:
		s.phase, s.until = holdTimeWait, h.now().Add(2*msl)
	case hostFinWait:
		s.until = h.now().Add(2 * msl)
	case hostClosing, hostLastAck:
	default:
		s.until = h.now()
		h.end(s)
	}
	h.add(s)
	return true
}

func (h *hostHolds) add(s *heldSocket) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sockets = append(h.sockets, s)
}

// end aborts s's socket, whose slot then stays the margin from the abort's
// return. A refusal leaves s as it was, for the next sweep to try again.
func (h *hostHolds) end(s *heldSocket) {
	if err := h.abort(s.conn); err != nil {
		h.refusedOnce.Do(func() {
			slog.Warn("egress userspace exit keeps a host socket the host refused to abort, and its slot, and tries again at each sweep", "err", err)
		})
		return
	}
	s.phase, s.conn, s.until = holdMargin, nil, h.now().Add(h.platform.margin)
}

// pass is the hold's part of each sweep, at the hold's clock read once. It
// reads the range and the MSL again, gives back each slot past its margin,
// aborts each socket past its hold, and acts on each watched socket's state
// before any deadline: TIME_WAIT starts a hold of twice the MSL, CLOSING and
// LAST_ACK stay watched, a closed socket is closed and its slot given back,
// and a FIN_WAIT state or an earlier one is aborted at or past its deadline.
// It takes the list under h.mu and acts on its sockets with h.mu given up, as
// nothing else changes a listed socket, then lists those kept ahead of the
// ones the end step added meanwhile. Run's end stops the sweep before Close
// calls close, so no pass runs beside close.
func (h *hostHolds) pass() {
	if h == nil {
		return
	}
	now := h.now()
	if err := h.read(); err != nil {
		if !h.unread {
			slog.Warn("egress userspace exit keeps its last bound on host ports", "err", err)
		}
		h.unread = true
	} else {
		h.unread = false
	}
	h.mu.Lock()
	sockets := h.sockets
	h.sockets = nil
	h.mu.Unlock()
	msl := time.Duration(h.msl.Load())
	sockets = slices.DeleteFunc(sockets, func(s *heldSocket) bool {
		if !h.step(s, now, msl) {
			return false
		}
		h.flows.unhold(s.source)
		return true
	})
	h.mu.Lock()
	h.sockets = append(sockets, h.sockets...)
	h.mu.Unlock()
}

// step acts on s at now and reports whether its slot comes back
func (h *hostHolds) step(s *heldSocket, now time.Time, msl time.Duration) bool {
	switch {
	case s.phase == holdMargin:
		return !now.Before(s.until)
	case s.phase == holdWatch:
		state, err := h.state(s.conn)
		if err != nil {
			state = hostOther
		}
		switch state {
		case hostClosed:
			_ = s.conn.Close()
			return true
		case hostTimeWait:
			s.phase, s.until = holdTimeWait, now.Add(2*msl)
			return false
		case hostClosing, hostLastAck:
			return false
		}
		if s.until.IsZero() || now.Before(s.until) {
			return false
		}
	case now.Before(s.until):
		return false
	}
	h.end(s)
	return false
}

// close ends every hold as the exit stops, and gives every slot back. It
// aborts every socket, one in CLOSING or LAST_ACK too, at the cost of the last
// unacknowledged bytes of a connection closing at the stop: a stopped exit
// counts no slot, and a socket left to run would pin its port uncounted beside
// the next exit's bound, for as long as its server keeps a CLOSING or LAST_ACK.
// The stop has reset every open flow before. A socket whose abort the host
// refuses is closed without it and left to the host, which the log says.
func (h *hostHolds) close() {
	if h == nil {
		return
	}
	h.mu.Lock()
	sockets := h.sockets
	h.sockets = nil
	h.mu.Unlock()
	refused := 0
	var refusal error
	for _, s := range sockets {
		if s.conn != nil {
			if err := h.abort(s.conn); err != nil {
				_ = s.conn.Close()
				refused, refusal = refused+1, err
			}
		}
		h.flows.unhold(s.source)
	}
	if refused > 0 {
		slog.Warn("egress userspace exit closed host sockets the host refused to abort, and left them to the host", "sockets", refused, "err", refusal)
	}
}
