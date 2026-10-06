// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

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
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

type udpEndpoint struct {
	addr    *net.UDPAddr
	control []byte // immutable reply source address and interface
	// unpinned records a fallback that worked and is never cleared
	unpinned atomic.Bool
	// unsegmentedUntil is when sends segment again, on the bind's clock in nanoseconds, and zero while they never stopped
	unsegmentedUntil atomic.Int64
}

func pinnedEndpoint(addr *net.UDPAddr, source net.IP, index int, ipv6Socket bool) *udpEndpoint {
	ep := &udpEndpoint{addr: addr}
	if ipv6Socket {
		ep.control = (&ipv6.ControlMessage{Src: source, IfIndex: index}).Marshal()
	} else {
		ep.control = (&ipv4.ControlMessage{Src: source, IfIndex: index}).Marshal()
	}
	return ep
}

func (e *udpEndpoint) pin() []byte {
	if e.unpinned.Load() {
		return nil
	}
	return e.control
}

func (*udpEndpoint) transportEndpoint() {}
func (e *udpEndpoint) String() string   { return e.addr.String() }

// sameDestination compares the pin as sends now carry it, so a fallen-back endpoint differs from a fresh one
func (e *udpEndpoint) sameDestination(other Endpoint) bool {
	o, ok := other.(*udpEndpoint)
	return ok && e.addr.IP.Equal(o.addr.IP) && e.addr.Port == o.addr.Port && e.addr.Zone == o.addr.Zone &&
		bytes.Equal(e.pin(), o.pin())
}

func (e *udpEndpoint) AddrPort() netip.AddrPort {
	addr, ok := netip.AddrFromSlice(e.addr.IP)
	if !ok {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(addr.Unmap(), uint16(e.addr.Port))
}

func (e *udpEndpoint) withoutSource() Endpoint { return &udpEndpoint{addr: e.addr} }

type udpBatchConn interface {
	ReadBatch([]ipv4.Message, int) (int, error)
	WriteBatch([]ipv4.Message, int) (int, error)
}

type udpSocket struct {
	conn *net.UDPConn
	raw  syscall.RawConn
	pc   udpBatchConn
	ipv6 bool
	send sync.Pool
}

type udpBind struct {
	v4, v6 *udpSocket
	events func(kind string, attrs ...slog.Attr)
	// started is the clock unsegmentedUntil counts from, which a test moves back
	started time.Time
}

func (b *udpBind) ParseEndpoint(s string) (Endpoint, error) {
	addr, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &udpEndpoint{addr: net.UDPAddrFromAddrPort(addr)}, nil
}

func (b *udpBind) Close() error {
	var errs []error
	for _, socket := range []*udpSocket{b.v4, b.v6} {
		if socket != nil {
			errs = append(errs, socket.conn.Close())
		}
	}
	return errors.Join(errs...)
}

// linux keeps the underlay out of the mesh's routing with a socket mark and a
// policy rule, so it marks and does not bind. Underlay.refuse reads these.
const (
	marksSockets = true
	bindsSockets = false
)

// openPacketBind takes the one socket this node's IKE and ESP share. index
// names an interface to bind it to, which this platform never asks for.
func openPacketBind(port uint16, underlay Underlay, index int, routed bool, events func(string, ...slog.Attr)) (packetBind, []receiveFunc, uint16, error) {
	// The port selected by the IPv4 bind may already be occupied on IPv6.
	// Retry ephemeral allocation; an explicitly requested port still fails.
	var err error
	for range ephemeralPortRetries {
		var bind packetBind
		var receivers []receiveFunc
		var bound uint16
		bind, receivers, bound, err = listenPacketBind(port, underlay.Mark, events)
		if port != 0 || !errors.Is(err, unix.EADDRINUSE) {
			return bind, receivers, bound, err
		}
	}
	return nil, nil, 0, err
}

func listenPacketBind(port uint16, fwmark uint32, events func(string, ...slog.Attr)) (packetBind, []receiveFunc, uint16, error) {
	b := &udpBind{events: events, started: time.Now()}
	var receivers []receiveFunc
	for i, network := range []string{"udp4", "udp6"} {
		var markErr error
		lc := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
			if err := raw.Control(func(fd uintptr) {
				for _, option := range []int{unix.SO_RCVBUF, unix.SO_SNDBUF, unix.SO_RCVBUFFORCE, unix.SO_SNDBUFFORCE} {
					_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, option, socketBufferSize)
				}
				_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_GRO, 1)
				if fwmark != 0 {
					// Reported rather than ignored like the tuning above. The
					// mark exists to keep this socket's datagrams out of a
					// table that would route them into our own tun, so a
					// silent failure here is an underlay that disappears into
					// the overlay carrying it.
					markErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(fwmark))
				}
			}); err != nil {
				return err
			}
			return markErr
		}}
		pc, err := lc.ListenPacket(context.Background(), network, fmt.Sprintf(":%d", port))
		if err != nil {
			if errors.Is(err, unix.EAFNOSUPPORT) || errors.Is(err, unix.EPROTONOSUPPORT) {
				continue
			}
			_ = b.Close()
			return nil, nil, 0, err
		}
		socket := &udpSocket{conn: pc.(*net.UDPConn), ipv6: i == 1}
		socket.send.New = func() any { return newUDPSendBatch() }
		if socket.ipv6 {
			p := ipv6.NewPacketConn(pc)
			socket.pc, b.v6 = p, socket
			err = p.SetControlMessage(ipv6.FlagDst|ipv6.FlagInterface, true)
		} else {
			p := ipv4.NewPacketConn(pc)
			socket.pc, b.v4 = p, socket
			err = p.SetControlMessage(ipv4.FlagDst|ipv4.FlagInterface, true)
		}
		if err != nil {
			_ = b.Close()
			return nil, nil, 0, err
		}
		socket.raw, err = socket.conn.SyscallConn()
		if err != nil {
			_ = b.Close()
			return nil, nil, 0, err
		}
		port = uint16(pc.LocalAddr().(*net.UDPAddr).Port)
		receivers = append(receivers, socket.receiver())
	}
	if len(receivers) == 0 {
		return nil, nil, 0, unix.EAFNOSUPPORT
	}
	return b, receivers, port, nil
}

// receiver reads a full recvmmsg vector even when UDP_GRO is enabled. Each
// message may contain many datagrams; excess segments are returned on later
// calls before any receive storage is reused. ESP does not need source-address
// objects: only IKE packets retain a reply endpoint.
func (s *udpSocket) receiver() receiveFunc {
	messages := make([]ipv4.Message, espSendBatch)
	for i := range messages {
		messages[i].Buffers = [][]byte{make([]byte, readBufferSize)}
		messages[i].OOB = make([]byte, controlMessageSize)
	}
	read := func() (int, error) { return s.pc.ReadBatch(messages, 0) }
	if s.raw != nil {
		read = newUDPReader(s.raw, messages).read
	}
	var count, index, offset, segment, refused int
	return func(bufs [][]byte, sizes []int, endpoints []Endpoint) (int, int, error) {
		refused = 0
		if index == count {
			var err error
			count, err = read()
			if errors.Is(err, unix.ENOSYS) {
				// Older 32-bit kernels expose recvmmsg only via socketcall.
				read = func() (int, error) { return s.pc.ReadBatch(messages, 0) }
				count, err = read()
			}
			if err != nil {
				return 0, 0, err
			}
			index, offset, segment = 0, 0, 0
		}
		n := 0
		for index < count && n < len(bufs) {
			m := &messages[index]
			if offset == 0 {
				// Counted in datagrams, the unit the counter's help text names
				// and the third arm below already uses: one GRO
				// buffer is up to forty of them, so counting the message would
				// undercount by that much. A zero-length datagram is refused
				// too -- it arrived and goes nowhere, and leaving it out is
				// the "a flood reads as silence" case on the one platform this
				// is deployed on.
				if m.Flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || m.N == 0 {
					refused += datagramsIn(m)
					index++
					continue
				}
				var err error
				segment, err = udpGROSize(m.OOB[:m.NN])
				if err != nil {
					// The segment size itself would not parse, so this
					// is the one arm that cannot do better than one.
					refused++
					index++
					continue
				}
				if segment == 0 {
					segment = m.N
				}
			}
			end := min(offset+segment, m.N)
			raw := m.Buffers[0][offset:end]
			bufs[n], sizes[n], endpoints[n] = raw, len(raw), nil
			if len(raw) >= 4 && binary.BigEndian.Uint32(raw[:4]) == 0 {
				// A datagram whose control message will not parse is counted
				// and dropped, not returned as an error: receiveLoop fails the
				// whole hub on an error, which closes every session on this
				// node, and the GRO sizing two branches up already skips the
				// same class of failure. Without the endpoint the responder
				// cannot answer, so the datagram is of no use anyway.
				if ep, err := s.replyEndpoint(m); err == nil {
					endpoints[n] = ep
				} else {
					refused++
					offset = end
					if offset == m.N {
						index++
						offset = 0
					}
					continue
				}
			}
			n++
			offset = end
			if offset == m.N {
				index++
				offset = 0
			}
		}
		return n, refused, nil
	}
}

// datagramsIn is how many datagrams a received message carries, which is one
// unless the kernel coalesced it and said so. A control buffer that will not
// parse leaves one, which is the floor rather than a guess.
func datagramsIn(m *ipv4.Message) int {
	if m.N == 0 {
		return 1
	}
	segment, err := udpGROSize(m.OOB[:m.NN])
	if err != nil || segment <= 0 {
		return 1
	}
	return (m.N + segment - 1) / segment
}

func (s *udpSocket) replyEndpoint(m *ipv4.Message) (*udpEndpoint, error) {
	var addr *net.UDPAddr
	if source, ok := m.Addr.(*udpSource); ok {
		var err error
		addr, err = source.endpoint()
		if err != nil {
			return nil, err
		}
	} else {
		addr = m.Addr.(*net.UDPAddr)
	}
	if s.ipv6 {
		var cm ipv6.ControlMessage
		if err := cm.Parse(m.OOB[:m.NN]); err != nil {
			return nil, err
		}
		return pinnedEndpoint(addr, cm.Dst, cm.IfIndex, true), nil
	}
	var cm ipv4.ControlMessage
	if err := cm.Parse(m.OOB[:m.NN]); err != nil {
		return nil, err
	}
	return pinnedEndpoint(addr, cm.Dst, cm.IfIndex, false), nil
}

func udpGROSize(control []byte) (int, error) {
	for len(control) >= unix.CmsgLen(0) {
		header, data, rest, err := unix.ParseOneSocketControlMessage(control)
		if err != nil {
			return 0, err
		}
		if header.Level == unix.IPPROTO_UDP && header.Type == unix.UDP_GRO {
			if len(data) < 2 {
				return 0, errors.New("transport: short UDP_GRO control message")
			}
			return int(binary.NativeEndian.Uint16(data)), nil
		}
		control = rest
	}
	return 0, nil
}

type udpSendBatch struct {
	messages [espSendBatch]ipv4.Message
	ends     [espSendBatch]int
}

func newUDPSendBatch() *udpSendBatch {
	b := new(udpSendBatch)
	for i := range b.messages {
		b.messages[i].Buffers = make([][]byte, 1)
		b.messages[i].OOB = make([]byte, 0, controlMessageSize)
	}
	return b
}

func appendUDPSegment(control []byte, size int) []byte {
	start := len(control)
	control = append(control, make([]byte, unix.CmsgSpace(2))...)
	header := (*unix.Cmsghdr)(unsafe.Pointer(&control[start]))
	header.Level, header.Type = unix.IPPROTO_UDP, unix.UDP_SEGMENT
	header.SetLen(unix.CmsgLen(2))
	binary.NativeEndian.PutUint16(control[start+unix.CmsgLen(0):], uint16(size))
	return control
}

// prepare coalesces adjacent ciphertext from SealBatch without copying it.
// Nonadjacent packets stay separate: using spare capacity for packing could
// overwrite another packet that has not been sent yet.
func (b *udpSendBatch) prepare(packets [][]byte, to *net.UDPAddr, control []byte, segment bool) int {
	n := 0
	for first := 0; first < len(packets); {
		payload := packets[first]
		size := len(payload)
		end := first + 1
		if segment && size > 0 {
			for end < len(packets) && end-first < gsoMaxSegments && len(packets[end]) > 0 && len(packets[end]) <= size &&
				len(payload)+len(packets[end]) <= min(cap(payload), 65507) {
				if &payload[len(payload):cap(payload)][0] != &packets[end][0] {
					break
				}
				payload = payload[:len(payload)+len(packets[end])]
				end++
				if len(packets[end-1]) < size {
					break
				}
			}
		}
		m := &b.messages[n]
		m.Buffers[0], m.Addr = payload, to
		m.OOB = append(m.OOB[:0], control...)
		if end-first > 1 {
			m.OOB = appendUDPSegment(m.OOB, size)
		}
		b.ends[n] = end
		n++
		first = end
	}
	return n
}

// Send resends from the kernel's choice of source when a pinned one is refused as gone, and keeps that choice once it worked
func (b *udpBind) Send(packets [][]byte, endpoint Endpoint) error {
	ep := endpoint.(*udpEndpoint)
	socket := b.v4
	if ep.addr.IP.To4() == nil {
		socket = b.v6
	}
	if socket == nil {
		return unix.EAFNOSUPPORT
	}
	batch := socket.send.Get().(*udpSendBatch)
	defer socket.send.Put(batch)
	control := ep.pin()
	sent, err := b.sendWithSegmentFallback(socket, batch, packets, ep, control)
	if err == nil || control == nil || !unpinnable(err) {
		return err
	}
	if _, err := b.sendWithSegmentFallback(socket, batch, packets[sent:], ep, nil); err != nil {
		return err
	}
	if ep.unpinned.CompareAndSwap(false, true) {
		b.fellBack(ep, "transport.endpoint.unpinned", "transport stopped sending to an endpoint from the address its datagram arrived on", err)
	}
	return nil
}

// unpinnable reports whether err is linux refusing a source address or interface the host no longer has
func unpinnable(err error) bool {
	return errors.Is(err, unix.ENETUNREACH) || errors.Is(err, unix.EINVAL) ||
		errors.Is(err, unix.ENODEV) || errors.Is(err, unix.EADDRNOTAVAIL)
}

// sendWithSegmentFallback segments packets to ep unless sends to ep have stopped segmenting
// when linux refuses a message of several datagrams with an errno segments can cause and they then pass one to a message
// ep stops segmenting until linux forgets the path MTU it learned
func (b *udpBind) sendWithSegmentFallback(socket *udpSocket, batch *udpSendBatch, packets [][]byte, ep *udpEndpoint, control []byte) (int, error) {
	done := 0
	for {
		until := ep.unsegmentedUntil.Load()
		segment := until == 0 || int64(time.Since(b.started)) >= until
		sent, refused, err := socket.write(batch, packets[done:], ep.addr, control, segment)
		done += sent
		if err == nil || refused < 2 || !segmentRefusal(err) {
			return done, err
		}
		plain, _, plainErr := socket.write(batch, packets[done:done+refused], ep.addr, control, false)
		done += plain
		if plainErr != nil {
			return done, plainErr
		}
		if ep.unsegmentedUntil.CompareAndSwap(until, int64(time.Since(b.started)+unsegmentedFor)) {
			b.fellBack(ep, "transport.endpoint.unsegmented", "transport stopped segmenting sends to an endpoint", err)
		}
	}
}

// segmentRefusal reports whether err is linux refusing a message for its segments
// EMSGSIZE or EINVAL by kernel version for segments the path is too narrow for, EIO for a device or route that cannot segment
func segmentRefusal(err error) bool {
	return errors.Is(err, unix.EMSGSIZE) || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EIO)
}

// write stops at the first refused message and reports the datagrams sent before it and those it carried
func (s *udpSocket) write(batch *udpSendBatch, packets [][]byte, to *net.UDPAddr, control []byte, segment bool) (sent, refused int, err error) {
	for sent < len(packets) {
		n := batch.prepare(packets[sent:min(len(packets), sent+espSendBatch)], to, control, segment)
		var written int
		// sendmmsg answers -1 when the first message is refused and a short count with no error when a later one is
		written, err = s.pc.WriteBatch(batch.messages[:n], 0)
		for i := range n {
			batch.messages[i].Buffers[0], batch.messages[i].Addr = nil, nil
		}
		written = max(written, 0)
		start := 0
		if written > 0 {
			start = batch.ends[written-1]
		}
		sent += start
		if err != nil {
			if written < n {
				refused = batch.ends[written] - start
			}
			return sent, refused, err
		}
		if written == 0 {
			return sent, 0, errors.New("transport: UDP send made no progress")
		}
	}
	return sent, 0, nil
}

// fellBack logs and records a fallback a send to ep took after linux refused it with err
func (b *udpBind) fellBack(ep *udpEndpoint, kind, message string, err error) {
	errno, _ := errors.AsType[unix.Errno](err)
	attrs := []slog.Attr{slog.String("endpoint", ep.String()), slog.String("errno", unix.ErrnoName(errno))}
	slog.LogAttrs(context.Background(), slog.LevelInfo, message, attrs...)
	if b.events != nil {
		b.events(kind, attrs...)
	}
}
