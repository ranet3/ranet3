// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package userspace

import (
	"net/netip"
	"slices"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// errorQueue is a dial's share of the errors the exit's ICMP sockets read on
// darwin, where a socket queues no error it can read back: the family's
// socket bound to no address reads the ICMP message itself,
// and hands the first that quotes the dial's addresses and ports here
type errorQueue struct {
	sockets *icmpSockets
	// fd is a descriptor of the dial's socket that outlives the dial's, whose
	// address the errors are matched against
	fd     int
	held   bool
	server netip.AddrPort
	caught chan icmpError
}

// queue is a dial's share of the errors the exit's ICMP sockets read
func (s *icmpSockets) queue() errorQueue { return errorQueue{sockets: s} }

// open holds a descriptor of fd, a dial's socket toward server, and has the
// errors about it handed here
func (q *errorQueue) open(fd int, server netip.AddrPort) error {
	held, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return err
	}
	q.fd, q.held, q.server, q.caught = held, true, server, make(chan icmpError, 1)
	q.sockets.dials.add(q)
	return nil
}

// read is the first ICMP error about the dial, false where none came. For a
// dial failure an ICMP error may have caused, it reads what the family's
// socket holds itself and waits up to dialErrorWait, since XNU ends the dial
// before it hands the message to the ICMP sockets.
func (q *errorQueue) read(failure error) (icmpError, bool) {
	if !q.held {
		return icmpError{}, false
	}
	select {
	case e := <-q.caught:
		return e, true
	default:
	}
	if failure == nil || !icmpErrno(failure) {
		return icmpError{}, false
	}
	q.sockets.drain(q.server.Addr().Is6())
	timer := time.NewTimer(dialErrorWait)
	defer timer.Stop()
	select {
	case e := <-q.caught:
		return e, true
	case <-timer.C:
		return icmpError{}, false
	}
}

// close stops the errors about the dial, which a connection it opened takes
// as nothing (RFC 5382 REQ-10), and gives its descriptor back
func (q *errorQueue) close() {
	if q.held {
		q.sockets.dials.remove(q)
		_ = unix.Close(q.fd)
		q.held = false
	}
}

// drain takes every message the family's socket bound to no address holds,
// without waiting, beside that socket's reader, which waits on it
func (s *icmpSockets) drain(ipv6 bool) {
	s.mu.Lock()
	socket := s.families[family(ipv6)].sockets[netip.Addr{}]
	s.mu.Unlock()
	if socket == nil {
		return
	}
	buf := buffers[1].Get().(*[]byte)
	defer buffers[1].Put(buf)
	for {
		n, from, err := socket.receive((*buf)[:cap(*buf)], false)
		if err != nil {
			return
		}
		s.take(socket, (*buf)[:n], from)
	}
}

// dialErrors holds the dials the TCP relay is making, by server
type dialErrors struct {
	mu     sync.Mutex
	queues map[netip.AddrPort][]*errorQueue
}

func (d *dialErrors) add(q *errorQueue) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.queues[q.server] = append(d.queues[q.server], q)
}

func (d *dialErrors) remove(q *errorQueue) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if queues := slices.DeleteFunc(d.queues[q.server], func(held *errorQueue) bool { return held == q }); len(queues) > 0 {
		d.queues[q.server] = queues
	} else {
		delete(d.queues, q.server)
	}
}

// take hands q, an error about a TCP segment, to the dial toward its quoted
// destination whose socket holds its quoted source, read back from the
// socket, and reports whether one did. A dial keeps the first error.
func (d *dialErrors) take(q quotedError) bool {
	if q.protocol != 6 {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, queue := range d.queues[q.to] {
		if sa, err := unix.Getsockname(queue.fd); err != nil || sockaddrPort(sa) != q.from {
			continue
		}
		select {
		case queue.caught <- q.icmpError:
		default:
		}
		return true
	}
	return false
}

// watchErrors queues nothing, since XNU keeps no error queue: the exit's ICMP
// sockets read the errors
func watchErrors(int, bool) error { return nil }

// drainErrors finds no error, since XNU keeps no error queue
func drainErrors(int, []byte, func(icmpError, []byte)) {}
