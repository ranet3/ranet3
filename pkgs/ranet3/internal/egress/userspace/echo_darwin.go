// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package userspace

import (
	"encoding/binary"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/packet"
	"ranet3.com/pkgs/ranet3/internal/underlay"
)

// reasonEchoQueue is an echo reply dropped past the replies its mapping holds
// toward its leaf
const reasonEchoQueue = "echo queue full"

// errEchoClosed is a read of an echo socket that closed
var errEchoClosed = errors.New("userspace: echo socket closed")

// icmpSockets is the ICMP datagram sockets the exit shares among its echo
// mappings on darwin. XNU keeps the identifier a request carries and hands
// every ICMP socket of a family every message the host receives, an echo
// reply or an error about any socket of the host's, so the exit picks its own
// identifiers, writes each into its mapping's requests, and takes from a read
// only what one of its mappings or sockets sent. Each family holds one socket
// bound to no address, which reads every message and sends the requests of
// mappings under auto, and one bound to the address of each class whose
// mappings are open, which sends their requests and reads only what comes to
// that address.
type icmpSockets struct {
	x *Exit

	mu       sync.Mutex
	families [2]icmpFamily
	closed   bool

	// readers counts the goroutines reading the sockets
	readers sync.WaitGroup
	// dials holds the dials the TCP relay is making, which the errors about
	// them reach
	dials dialErrors
}

// icmpFamily is one family's sockets by the address each is bound to, the
// zero Addr for the one bound to none, why that one could not open, which
// refuses every echo mapping of the family and leaves its errors unread, and
// the identifiers the mappings hold
type icmpFamily struct {
	sockets map[netip.Addr]*icmpSocket
	err     error
	ids     map[uint16]*echoSocket
	// next is the identifier tried after the one tried last for a mapping
	// whose leaf's identifier another mapping holds
	next uint16
}

// icmpSocket is one ICMP datagram socket, the mappings sending through it,
// and the destination its last send was scoped toward
type icmpSocket struct {
	ipv6   bool
	source netip.Addr
	file   *os.File
	raw    syscall.RawConn
	// users counts the mappings sending through it, and one bound to an
	// address closes with its last
	users int

	sendMu sync.Mutex
	scoped netip.Addr
}

// openICMP opens each family's socket bound to no address, a failure logged
// and kept as its family's refusal, and starts reading them
func openICMP(x *Exit) *icmpSockets {
	s := &icmpSockets{x: x, dials: dialErrors{queues: map[netip.AddrPort][]*errorQueue{}}}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.families {
		f := &s.families[i]
		f.sockets, f.ids = map[netip.Addr]*icmpSocket{}, map[uint16]*echoSocket{}
		socket, err := s.open(i == 1, netip.Addr{})
		if err != nil {
			f.err = err
			slog.Warn("egress userspace exit opened no ICMP socket, so it refuses echo in this family and relays no router's error about its sockets", "ipv6", i == 1, "err", err)
			continue
		}
		f.sockets[netip.Addr{}] = socket
	}
	return s
}

// open opens an ICMP datagram socket of ipv6's family, readied by the
// platform's Prepare as a socket that only receives, bound to source where it
// is valid, an ICMPv6 one narrowed to echo replies and the four error types,
// and starts its reader. s.mu is held.
func (s *icmpSockets) open(ipv6 bool, source netip.Addr) (*icmpSocket, error) {
	domain, protocol, network := unix.AF_INET, unix.IPPROTO_ICMP, "ip4:icmp"
	if ipv6 {
		domain, protocol, network = unix.AF_INET6, unix.IPPROTO_ICMPV6, "ip6:ipv6-icmp"
	}
	fd, err := unix.Socket(domain, unix.SOCK_DGRAM, protocol)
	if err != nil {
		return nil, err
	}
	unix.CloseOnExec(fd)
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	socket := &icmpSocket{ipv6: ipv6, source: source, file: os.NewFile(uintptr(fd), "icmp")}
	if socket.raw, err = socket.file.SyscallConn(); err == nil {
		err = s.x.rt.Platform.Prepare(network, netip.AddrPort{}, socket.raw)
	}
	if err == nil {
		err = socket.control(func(fd int) error { return readyICMP(fd, ipv6, source) })
	}
	if err != nil {
		_ = socket.file.Close()
		return nil, err
	}
	s.readers.Add(1)
	go s.read(socket)
	return socket, nil
}

// readyICMP narrows fd, an ICMPv6 socket, to echo replies and the error types
// 1 to 4 with ICMP6_FILTER, which XNU honors for root and for an
// ordinary user alike, and binds fd to source where it is valid
func readyICMP(fd int, ipv6 bool, source netip.Addr) error {
	if ipv6 {
		var filter unix.ICMPv6Filter
		for _, kind := range []uint8{1, 2, 3, 4, 129} {
			filter.Filt[kind>>5] |= 1 << (kind & 31)
		}
		if err := unix.SetsockoptICMPv6Filter(fd, unix.IPPROTO_ICMPV6, unix.ICMP6_FILTER, &filter); err != nil {
			return err
		}
	}
	switch {
	case !source.IsValid():
		return nil
	case ipv6:
		return unix.Bind(fd, &unix.SockaddrInet6{Addr: source.As16()})
	default:
		return unix.Bind(fd, &unix.SockaddrInet4{Addr: source.As4()})
	}
}

func (s *icmpSocket) control(f func(fd int) error) error {
	var err error
	if controlErr := s.raw.Control(func(fd uintptr) { err = f(int(fd)) }); controlErr != nil {
		return controlErr
	}
	return err
}

// read hands each message socket reads to take, through a pooled buffer, until
// the socket closes
func (s *icmpSockets) read(socket *icmpSocket) {
	defer s.readers.Done()
	for {
		buf := buffers[1].Get().(*[]byte)
		n, from, err := socket.receive((*buf)[:cap(*buf)], true)
		if err == nil {
			s.take(socket, (*buf)[:n], from)
		}
		buffers[1].Put(buf)
		if err != nil && (errors.Is(err, errEchoClosed) || !icmpErrno(err) && !errors.Is(err, syscall.EINTR)) {
			return
		}
	}
}

// receive reads one message into buf, waiting for one where wait is true,
// and reports its length and where it came from, errEchoClosed once the
// socket closes and EAGAIN where it waits for none and holds none. A read
// that waits for none goes through Control, which takes none of the
// descriptor's locks: the socket's reader holds its read lock while it waits
// (RawRead in Go's internal/poll), and takes it again before a waiter woken
// by its release runs, so a Read there waits for good once no message comes.
func (s *icmpSocket) receive(buf []byte, wait bool) (int, netip.Addr, error) {
	var (
		n    int
		from unix.Sockaddr
		err  error
	)
	read := func(fd uintptr) bool {
		n, from, err = unix.Recvfrom(int(fd), buf, unix.MSG_DONTWAIT)
		return !errors.Is(err, unix.EAGAIN)
	}
	var closed error
	if wait {
		closed = s.raw.Read(read)
	} else {
		closed = s.raw.Control(func(fd uintptr) { read(fd) })
	}
	if closed != nil {
		return 0, netip.Addr{}, errEchoClosed
	}
	if err != nil {
		return 0, netip.Addr{}, err
	}
	return n, sockaddrPort(from).Addr(), nil
}

// take hands b, one message socket read from from, to what it is about: an
// echo reply to the mapping holding its identifier that sent to from, an error
// to the flow of the exit's own socket whose datagram it quotes. Only the
// socket bound to no address takes errors, since it reads every one, and
// counts what is about no flow of the exit's. An IPv4 read holds the IP
// header ahead of the message, its length field in the host's order, and only
// its header length is read.
func (s *icmpSockets) take(socket *icmpSocket, b []byte, from netip.Addr) {
	unbound := !socket.source.IsValid()
	message := b
	if !socket.ipv6 {
		if len(b) < 20 || b[0]>>4 != 4 || len(b) < int(b[0]&0x0f)*4 {
			s.notOurs(unbound)
			return
		}
		message = b[int(b[0]&0x0f)*4:]
	}
	reply := byte(0)
	if socket.ipv6 {
		reply = 129
	}
	switch {
	case len(message) < 8:
		s.notOurs(unbound)
	case message[0] == reply:
		if !s.reply(socket, message, from) {
			s.notOurs(unbound)
		}
	case unbound:
		q, reason := readQuotedError(message, socket.ipv6, from, s.routeMTU)
		switch {
		case reason != "":
			s.x.counts.drop(reason)
		case s.x.udp.relayQuoted(q), s.dials.take(q):
		default:
			s.x.counts.drop(reasonNotOurs)
		}
	}
}

// notOurs counts a message about no flow of the exit's where the socket bound
// to no address read it, which reads every one, so each is counted once
func (s *icmpSockets) notOurs(unbound bool) {
	if unbound {
		s.x.counts.drop(reasonNotOurs)
	}
}

// routeMTU is the MTU of the link the platform routes address by, zero where
// it routes it by none
func (s *icmpSockets) routeMTU(address netip.Addr) int {
	if link, ok, err := s.x.rt.Platform.Route(address); err == nil && ok {
		return link.MTU
	}
	return 0
}

// reply hands message, an echo reply from from that socket read, to the
// mapping whose identifier it carries where that mapping sent to from, and
// reports whether it was one of the exit's. A mapping takes its replies from
// the socket it sends through alone, since a reply to a class's address
// reaches the socket bound to it and the one bound to none.
func (s *icmpSockets) reply(socket *icmpSocket, message []byte, from netip.Addr) bool {
	s.mu.Lock()
	e := s.families[family(socket.ipv6)].ids[binary.BigEndian.Uint16(message[4:6])]
	s.mu.Unlock()
	if e == nil || !e.sentTo(from) {
		return false
	}
	if e.socket == socket && !e.enqueue(message, from) {
		s.x.counts.drop(reasonEchoQueue)
	}
	return true
}

// enqueue queues a copy of message toward e's leaf, and reports whether it
// did: the queue holds at most perFlow bytes, the share Within gives a
// mapping, or one reply alone of any size, and echoReplies replies
func (e *echoSocket) enqueue(message []byte, from netip.Addr) bool {
	size := int64(len(message))
	if queued := e.queued.Add(size); queued > size && queued > perFlow {
		e.queued.Add(-size)
		return false
	}
	select {
	case e.replies <- echoReply{message: slices.Clone(message), from: from}:
		return true
	default:
		e.queued.Add(-size)
		return false
	}
}

// openEcho opens an echo mapping of ipv6's family that sends from source,
// the address of the leaf's class, or under auto from the address the route
// to each destination picks, through the family's socket bound to it, opened
// where none is. It holds id where no other mapping of the family does, else
// one the exit picks.
func (s *icmpSockets) openEcho(ipv6 bool, source netip.Addr, id uint16, _ netip.Addr) (*echoSocket, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := &s.families[family(ipv6)]
	switch {
	case s.closed:
		return nil, errEchoClosed
	case f.err != nil:
		return nil, f.err
	}
	socket := f.sockets[source]
	if socket == nil {
		var err error
		if socket, err = s.open(ipv6, source); err != nil {
			return nil, err
		}
		f.sockets[source] = socket
	}
	if id == 0 || f.ids[id] != nil {
		var ok bool
		if id, ok = f.free(); !ok {
			s.release(socket)
			return nil, syscall.EADDRINUSE
		}
	}
	e := &echoSocket{sockets: s, socket: socket, id: id, replies: make(chan echoReply, echoReplies), done: make(chan struct{})}
	f.ids[id] = e
	socket.users++
	return e, nil
}

// free is an identifier no mapping of the family holds, the first after the
// one it gave last, false where every one is held
func (f *icmpFamily) free() (uint16, bool) {
	for range 1 << 16 {
		f.next++
		if f.next != 0 && f.ids[f.next] == nil {
			return f.next, true
		}
	}
	return 0, false
}

// release closes socket where it is bound to an address and no mapping sends
// through it. s.mu is held.
func (s *icmpSockets) release(socket *icmpSocket) {
	if socket.users > 0 || !socket.source.IsValid() {
		return
	}
	_ = socket.file.Close()
	delete(s.families[family(socket.ipv6)].sockets, socket.source)
}

// close closes every socket and waits for their readers
func (s *icmpSockets) close() {
	s.mu.Lock()
	s.closed = true
	for i := range s.families {
		for source, socket := range s.families[i].sockets {
			_ = socket.file.Close()
			delete(s.families[i].sockets, source)
		}
	}
	s.mu.Unlock()
	s.readers.Wait()
}

// send sends message to to, the socket scoped by prepare toward to first where
// its last send was scoped elsewhere, so each request leaves by the link the
// platform names for its own destination: XNU follows IP_BOUND_IF and
// IPV6_BOUND_IF set before each send, and not IP_PKTINFO's interface over
// IPv4
func (s *icmpSocket) send(prepare underlay.Prepare, message []byte, to netip.Addr) error {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	if to != s.scoped {
		network := "ip4:icmp"
		if s.ipv6 {
			network = "ip6:ipv6-icmp"
		}
		if err := prepare(network, netip.AddrPortFrom(to, 0), s.raw); err != nil {
			s.scoped = netip.Addr{}
			return err
		}
		s.scoped = to
	}
	var sa unix.Sockaddr
	if s.ipv6 {
		sa = &unix.SockaddrInet6{Addr: to.As16()}
	} else {
		sa = &unix.SockaddrInet4{Addr: to.As4()}
	}
	var err error
	if writeErr := s.raw.Write(func(fd uintptr) bool {
		err = unix.Sendto(int(fd), message, 0, sa)
		return !errors.Is(err, unix.EAGAIN)
	}); writeErr != nil {
		return writeErr
	}
	return err
}

// echoSocket is one echo mapping's share of its family's socket: the
// identifier it holds, the replies taken for it, and the latest destinations
// it sent to, from which alone it takes a reply
type echoSocket struct {
	sockets *icmpSockets
	socket  *icmpSocket
	id      uint16
	replies chan echoReply
	// queued is the bytes of the replies queued, which enqueue bounds
	queued atomic.Int64
	done   chan struct{}
	once   sync.Once

	mu   sync.Mutex
	sent [echoDestinations]netip.Addr
	next int
}

// echoReply is an echo reply's ICMP message and where it came from
type echoReply struct {
	message []byte
	from    netip.Addr
}

// send sends message, an echo request, to to, with the mapping's identifier
// written in and, over IPv4, the checksum computed again, which XNU computes
// itself for ICMPv6
func (e *echoSocket) send(message []byte, to netip.Addr) error {
	request := slices.Clone(message)
	binary.BigEndian.PutUint16(request[4:6], e.id)
	binary.BigEndian.PutUint16(request[2:4], 0)
	if !e.socket.ipv6 {
		binary.BigEndian.PutUint16(request[2:4], ^uint16(packet.Sum(0, request)))
	}
	e.mu.Lock()
	if !slices.Contains(e.sent[:], to) {
		e.sent[e.next] = to
		e.next = (e.next + 1) % len(e.sent)
	}
	e.mu.Unlock()
	return e.socket.send(e.sockets.x.rt.Platform.Prepare, request, to)
}

// sentTo is whether to is among the latest destinations e sent to
func (e *echoSocket) sentTo(to netip.Addr) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Contains(e.sent[:], to)
}

// receive waits for one echo reply taken for e, copies it into b's buffer,
// taken only once the reply is there, and reports its length and where it
// came from, errEchoClosed once e closes, and errEchoTooLarge for a reply the
// buffer could hold only cut
func (e *echoSocket) receive(b *replyBuffer) (int, netip.Addr, error) {
	select {
	case r := <-e.replies:
		e.queued.Add(-int64(len(r.message)))
		buf := b.take()
		if len(r.message) > len(buf) {
			return 0, r.from, errEchoTooLarge
		}
		return copy(buf, r.message), r.from, nil
	case <-e.done:
		return 0, netip.Addr{}, errEchoClosed
	}
}

// identifier is the identifier e holds
func (e *echoSocket) identifier() (uint16, error) { return e.id, nil }

// close gives e's identifier back, and the socket it sends through, which
// closes where it is bound to an address no other mapping sends from
func (e *echoSocket) close() error {
	e.once.Do(func() {
		close(e.done)
		s := e.sockets
		s.mu.Lock()
		defer s.mu.Unlock()
		f := &s.families[family(e.socket.ipv6)]
		if f.ids[e.id] == e {
			delete(f.ids, e.id)
		}
		e.socket.users--
		s.release(e.socket)
	})
	return nil
}
