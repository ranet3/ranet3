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
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/packet"
	"ranet3.com/pkgs/ranet3/schema"
)

type udpEndpoint struct {
	addr    *net.UDPAddr
	control []byte // immutable reply source address and interface
	// source and index are the address and interface control names, which a route lookup for a pinned send names too
	source net.IP
	index  int
	pinFallback
	// unsegmentedUntil is when sends segment again, on the bind's clock in nanoseconds, and zero while they never stopped
	unsegmentedUntil atomic.Int64
	// fragmenting is set while a mux lets sends to this endpoint fragment past the path MTU
	fragmenting atomic.Bool
}

func pinnedEndpoint(addr *net.UDPAddr, source net.IP, index int, ipv6Socket bool) *udpEndpoint {
	ep := &udpEndpoint{addr: addr, source: source, index: index}
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

// sameDestination compares the pin each endpoint arrived with, which a fallback drops except for unroutedHold after the kernel refused the pin with EHOSTUNREACH
func (e *udpEndpoint) sameDestination(other Endpoint) bool {
	o, ok := other.(*udpEndpoint)
	return ok && e.addr.IP.Equal(o.addr.IP) && e.addr.Port == o.addr.Port && e.addr.Zone == o.addr.Zone &&
		bytes.Equal(e.arrival(e.control), o.arrival(o.control))
}

func (e *udpEndpoint) AddrPort() netip.AddrPort {
	addr, ok := netip.AddrFromSlice(e.addr.IP)
	if !ok {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(addr.Unmap(), uint16(e.addr.Port))
}

func (e *udpEndpoint) zone() string { return e.addr.Zone }

func (e *udpEndpoint) withoutSource() Endpoint { return &udpEndpoint{addr: e.addr} }

type udpBatchConn interface {
	WriteBatch([]ipv4.Message, int) (int, error)
}

type udpSocket struct {
	conn *net.UDPConn
	raw  syscall.RawConn
	pc   udpBatchConn
	ipv6 bool
	send sync.Pool
	// fragmenting counts the muxes letting this socket's sends fragment
	// it is stored under its bind's fragmentMu and loaded by a send without the lock
	// the socket runs DO while it is zero and the mode discovery names for fragmenting while it is not
	fragmenting atomic.Int32
}

type udpBind struct {
	v4, v6 *udpSocket
	events func(kind string, attrs ...slog.Attr)
	// started is the clock unsegmentedUntil counts from, which a test moves back
	started time.Time
	// pathMTU reads the path MTU of the route a send to an endpoint takes, which a test answers in place of linux
	pathMTU func(*udpEndpoint) (int, error)
	// fragmentMu serializes each socket's count of the muxes letting its sends fragment, and pairs
	fragmentMu sync.Mutex
	// pairs holds the open sockets connected to one peer, each in its family's path MTU discovery mode
	pairs map[*udpPair]struct{}
	// discover sets a socket's path MTU discovery to fragment or back to DO
	// a test answers it in place of linux
	discover func(socket *udpSocket, fragment bool) error
	// cookie reads the cookie of a socket's network namespace, which a test answers in place of linux
	cookie func(syscall.RawConn) (uint64, error)
	// port and mark are the listener's, which a socket connected to one peer takes too
	port uint16
	mark uint32
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

// linux sets the underlay's sockets apart, where the process may set it, with
// a mark the reconciler's derived rules read, so it marks and does not bind.
// Underlay.refuse reads this.
const bindsSockets = false

// underlayMark is the mark every underlay socket of this process carries,
// schema.UnderlayMark, or none where the process may not set one. SO_MARK
// needs CAP_NET_ADMIN or CAP_NET_RAW in the socket's network namespace, and a
// policy rule needs CAP_NET_ADMIN there, so a process that cannot mark its
// sockets writes no rule that reads the mark.
var underlayMark = sync.OnceValue(func() uint32 {
	var fd int
	var err error
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		if fd, err = unix.Socket(family, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0); err == nil {
			break
		}
	}
	if err != nil {
		// the listener's own open reports what keeps a socket from opening
		return schema.UnderlayMark
	}
	defer unix.Close(fd)
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, int(schema.UnderlayMark)); errors.Is(err, unix.EPERM) {
		slog.Info("transport leaves the underlay sockets unmarked", "err", err,
			"detail", "this process holds neither CAP_NET_ADMIN nor CAP_NET_RAW, and without CAP_NET_ADMIN it writes no policy rule that reads the mark")
		return 0
	}
	return schema.UnderlayMark
})

// openPacketBind takes the one socket this node's IKE and ESP share.
func openPacketBind(port uint16, _ Selection, events func(string, ...slog.Attr)) (packetBind, []receiveFunc, uint16, error) {
	mark := underlayMark()
	// The port selected by the IPv4 bind may already be occupied on IPv6.
	// Retry ephemeral allocation, but an explicitly requested port still fails.
	var err error
	for range ephemeralPortRetries {
		var bind packetBind
		var receivers []receiveFunc
		var bound uint16
		bind, receivers, bound, err = listenPacketBind(port, mark, events)
		if port != 0 || !errors.Is(err, unix.EADDRINUSE) {
			return bind, receivers, bound, err
		}
	}
	return nil, nil, 0, err
}

func listenPacketBind(port uint16, fwmark uint32, events func(string, ...slog.Attr)) (packetBind, []receiveFunc, uint16, error) {
	b := &udpBind{events: events, started: time.Now(), pathMTU: func(ep *udpEndpoint) (int, error) { return routeMTU(ep, fwmark) },
		discover: setDiscovery, cookie: namespaceCookie, mark: fwmark, pairs: make(map[*udpPair]struct{})}
	var receivers []receiveFunc
	for i, network := range []string{"udp4", "udp6"} {
		lc := net.ListenConfig{Control: socketControl(i == 1, fwmark, socketBufferSize, false)}
		pc, err := lc.ListenPacket(context.Background(), network, fmt.Sprintf(":%d", port))
		if err != nil {
			if errors.Is(err, unix.EAFNOSUPPORT) || errors.Is(err, unix.EPROTONOSUPPORT) {
				continue
			}
			_ = b.Close()
			return nil, nil, 0, err
		}
		socket, err := newUDPSocket(pc.(*net.UDPConn), i == 1)
		if err == nil {
			// set only once bound, so a second process binding the port without it is still refused
			// while a socket connected to one peer may bind the port on one address
			var shareErr error
			if err = socket.raw.Control(func(fd uintptr) {
				shareErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			}); err == nil {
				err = shareErr
			}
		}
		if err != nil {
			_ = pc.Close()
			_ = b.Close()
			return nil, nil, 0, err
		}
		if socket.ipv6 {
			b.v6 = socket
		} else {
			b.v4 = socket
		}
		port = uint16(pc.LocalAddr().(*net.UDPAddr).Port)
		receivers = append(receivers, socket.receiver(espSendBatch))
	}
	if len(receivers) == 0 {
		return nil, nil, 0, unix.EAFNOSUPPORT
	}
	b.port = port
	return b, receivers, port, nil
}

// socketControl sets the buffers, UDP_GRO, the underlay's mark and DF on a socket before it binds
// and SO_REUSEPORT where it binds the listener's port on one address
func socketControl(ipv6 bool, fwmark uint32, buffer int, reusePort bool) func(string, string, syscall.RawConn) error {
	level, discover, mode := discovery(ipv6, false)
	return func(_, _ string, raw syscall.RawConn) error {
		var optionErr error
		if err := raw.Control(func(fd uintptr) {
			for _, option := range []int{unix.SO_RCVBUF, unix.SO_SNDBUF, unix.SO_RCVBUFFORCE, unix.SO_SNDBUFFORCE} {
				_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, option, buffer)
			}
			_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_GRO, 1)
			if reusePort {
				optionErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			}
			if fwmark != 0 && optionErr == nil {
				// Reported rather than ignored like the tuning above: an
				// unmarked datagram can follow the mesh's table into our own tun.
				optionErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(fwmark))
			}
			if optionErr == nil {
				// DF on every datagram, and linux refusing one past its route's path MTU rather than fragmenting it, which Send reports
				optionErr = unix.SetsockoptInt(int(fd), level, discover, mode)
			}
		}); err != nil {
			return err
		}
		return optionErr
	}
}

// newUDPSocket readies conn for batched reads and writes, with the control messages a reply endpoint is built from
// and the outer TOS or traffic class, whose ECN field a tunnel egress must read (RFC 7296 section 2.24)
func newUDPSocket(conn *net.UDPConn, v6 bool) (*udpSocket, error) {
	socket := &udpSocket{conn: conn, ipv6: v6}
	socket.send.New = func() any { return newUDPSendBatch() }
	var err error
	level, option := unix.IPPROTO_IP, unix.IP_RECVTOS
	if v6 {
		p := ipv6.NewPacketConn(conn)
		socket.pc, err = p, p.SetControlMessage(ipv6.FlagDst|ipv6.FlagInterface, true)
		level, option = unix.IPPROTO_IPV6, unix.IPV6_RECVTCLASS
	} else {
		p := ipv4.NewPacketConn(conn)
		socket.pc, err = p, p.SetControlMessage(ipv4.FlagDst|ipv4.FlagInterface, true)
	}
	if err != nil {
		return nil, err
	}
	if socket.raw, err = conn.SyscallConn(); err != nil {
		return nil, err
	}
	var setErr error
	if err := socket.raw.Control(func(fd uintptr) { setErr = unix.SetsockoptInt(int(fd), level, option, 1) }); err != nil {
		return nil, err
	}
	if setErr != nil {
		return nil, setErr
	}
	return socket, nil
}

// icmpErrnos are the errors linux hands a connected UDP socket for an ICMP error, read by its next send or receive
// udp_err passes icmp_err_convert's fatal entries, EMSGSIZE for a fragmentation needed and EPROTO for a parameter problem
// udpv6_err passes icmpv6_err_convert's fatal entries and EMSGSIZE for a packet too big
var icmpErrnos = []unix.Errno{unix.EACCES, unix.ECONNREFUSED, unix.EHOSTDOWN, unix.EHOSTUNREACH, unix.EMSGSIZE, unix.ENETUNREACH, unix.ENONET, unix.ENOPROTOOPT, unix.EPROTO}

// pairOf leaves the local address and the interface to the route where sends to the endpoint do, and otherwise takes both from the pin
func (b *udpBind) pairOf(endpoint Endpoint) pairKey {
	ep := endpoint.(*udpEndpoint)
	remote, _ := netip.AddrFromSlice(ep.addr.IP)
	k := pairKey{remote: netip.AddrPortFrom(remote.Unmap().WithZone(ep.addr.Zone), uint16(ep.addr.Port))}
	if source, ok := netip.AddrFromSlice(ep.source); ok && !ep.unpinned.Load() {
		k.local, k.index = source.Unmap(), ep.index
	}
	return k
}

// connectPair binds the hub's port on one address, which keeps the socket out of any reuseport group the listener is in
// and once connected the kernel prefers it to the wildcard listener for its peer's datagrams to that address
// a pinned pair leaves by its pin's interface as the shared socket's replies do, and a link-local source binds only on it
// a socket outside the listener's network namespace is refused before it binds
func (b *udpBind) connectPair(k pairKey) (pairSocket, receiveFunc, error) {
	network, listener := "udp4", b.v4
	if k.remote.Addr().Is6() {
		network, listener = "udp6", b.v6
	}
	if listener == nil {
		return nil, nil, unix.EAFNOSUPPORT
	}
	local := k.local
	if !local.IsValid() {
		var err error
		if local, err = b.routeSource(network, k.remote); err != nil {
			return nil, nil, err
		}
	}
	zoned := k.index != 0 && local.Is6() && local.IsLinkLocalUnicast()
	if zoned {
		local = local.WithZone(strconv.Itoa(k.index))
	}
	control := socketControl(network == "udp6", b.mark, pairBuffer, true)
	dialer := net.Dialer{LocalAddr: net.UDPAddrFromAddrPort(netip.AddrPortFrom(local, b.port)), Control: func(network, address string, raw syscall.RawConn) error {
		if err := sameNamespace(b.cookie, raw, listener.raw); err != nil {
			return err
		}
		if err := control(network, address, raw); err != nil || k.index == 0 || zoned {
			return err
		}
		return leaveBy(raw, network == "udp6", k.index)
	}}
	conn, err := dialer.Dial(network, k.remote.String())
	if err != nil {
		return nil, nil, err
	}
	socket, err := newUDPSocket(conn.(*net.UDPConn), network == "udp6")
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	pair := &udpPair{socket: socket, bind: b, address: local}
	if err := b.join(pair, listener); err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	return pair, retryICMP(socket.receiver(pairReadMessages)), nil
}

// errOtherNamespace refuses a socket that is not in its listener's network namespace
var errOtherNamespace = errors.New("transport: the socket is in another network namespace than its listener")

// sameNamespace refuses raw's socket unless it is in the network namespace of listener's
// a socket takes the namespace of the thread that makes it, and a connect runs on whatever thread its goroutine has
// so in a process whose threads sit in several namespaces a socket made in another would bind, route and send there
// SO_NETNS_COOKIE names a socket's namespace from linux 5.14, and an older kernel goes without the check
func sameNamespace(cookie func(syscall.RawConn) (uint64, error), raw, listener syscall.RawConn) error {
	var cookies [2]uint64
	for i, socket := range []syscall.RawConn{raw, listener} {
		var getErr error
		cookies[i], getErr = cookie(socket)
		if errors.Is(getErr, unix.ENOPROTOOPT) {
			return nil
		}
		if getErr != nil {
			return getErr
		}
	}
	if cookies[0] != cookies[1] {
		return errOtherNamespace
	}
	return nil
}

func namespaceCookie(raw syscall.RawConn) (uint64, error) {
	var cookie uint64
	var getErr error
	if err := raw.Control(func(fd uintptr) {
		cookie, getErr = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_NETNS_COOKIE)
	}); err != nil {
		return 0, err
	}
	return cookie, getErr
}

// leaveBy holds a socket's sends to interface index as a pin's control message holds the shared socket's replies
// IPv4 binds the socket to it with SO_BINDTOIFINDEX, which holds the route to that interface as ipi_ifindex does
// linux takes SO_BINDTOIFINDEX from 5.1, and from a process without CAP_NET_RAW from 5.7, so an older kernel leaves such a pair on the shared socket
// IPv6 names it with IPV6_UNICAST_IF, in network byte order, which beside a bound source prefers it only among the routes of the lowest metric, as ipi6_ifindex does
func leaveBy(raw syscall.RawConn, ipv6 bool, index int) error {
	level, option, value := unix.SOL_SOCKET, unix.SO_BINDTOIFINDEX, index
	if ipv6 {
		var order [4]byte
		binary.BigEndian.PutUint32(order[:], uint32(index))
		level, option, value = unix.IPPROTO_IPV6, unix.IPV6_UNICAST_IF, int(int32(binary.NativeEndian.Uint32(order[:])))
	}
	var setErr error
	if err := raw.Control(func(fd uintptr) { setErr = unix.SetsockoptInt(int(fd), level, option, value) }); err != nil {
		return err
	}
	return setErr
}

// join puts p in the path MTU discovery mode of its family's listener, which fragment then moves it with
func (b *udpBind) join(p *udpPair, listener *udpSocket) error {
	b.fragmentMu.Lock()
	defer b.fragmentMu.Unlock()
	if listener.fragmenting.Load() > 0 {
		if err := b.discover(p.socket, true); err != nil {
			return err
		}
	}
	b.pairs[p] = struct{}{}
	return nil
}

// routeSource is the source the route to remote picks under the underlay's mark, read off a socket connected there and closed
func (b *udpBind) routeSource(network string, remote netip.AddrPort) (netip.Addr, error) {
	dialer := net.Dialer{Control: socketControl(network == "udp6", b.mark, pairBuffer, false)}
	conn, err := dialer.Dial(network, remote.String())
	if err != nil {
		return netip.Addr{}, err
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Unmap(), nil
}

// udpPair is a socket connected to one peer, which segments by the record the bind keeps of that peer's path
// its sends carry no control message, which would cost the socket the cached route that keeps its transmit queue
type udpPair struct {
	socket  *udpSocket
	bind    *udpBind
	address netip.Addr
}

// transmit keeps the pair through a refusal of its segments, which stops the endpoint's segments here and on the shared socket alike
func (p *udpPair) transmit(packets [][]byte, endpoint Endpoint) (int, bool, error) {
	batch := p.socket.send.Get().(*udpSendBatch)
	defer p.socket.send.Put(batch)
	ep := endpoint.(*udpEndpoint)
	return pastICMP(func(packets [][]byte) (int, error) {
		return p.bind.sendWithSegmentFallback(p.socket, batch, packets, ep, nil, nil)
	}, packets)
}

func (p *udpPair) local() netip.Addr { return p.address }

func (p *udpPair) Close() error {
	p.bind.fragmentMu.Lock()
	delete(p.bind.pairs, p)
	p.bind.fragmentMu.Unlock()
	return p.socket.conn.Close()
}

// receiver reads a full recvmmsg vector even when UDP_GRO is enabled. Each
// message may contain many datagrams. Excess segments are returned on later
// calls before any receive storage is reused. Only IKE packets retain a reply
// endpoint.
func (s *udpSocket) receiver(vector int) receiveFunc {
	messages := receiveVector(vector)
	return s.walk(messages, newUDPReader(s.raw, messages).read)
}

// receiveVector is the storage of vector messages a socket receives into for its lifetime
func receiveVector(vector int) []ipv4.Message {
	messages := make([]ipv4.Message, vector)
	for i := range messages {
		messages[i].Buffers = [][]byte{make([]byte, readBufferSize)}
		messages[i].OOB = make([]byte, controlMessageSize)
	}
	return messages
}

// walk hands out the datagrams read leaves in messages and reads again once it has handed out the last
// a message is one sender's, since GRO coalesces only datagrams of one source address and port, so each of its datagrams takes the source read once for it
// and it carries one outer ECN field, since GRO flushes a flow on any difference of TOS or traffic class, so each of its datagrams takes the field read once for it too
func (s *udpSocket) walk(messages []ipv4.Message, read func() (int, error)) receiveFunc {
	var count, index, offset, segment, refused int
	var source netip.AddrPort
	var ecn packet.ECN
	var zones scopeZone
	return func(bufs [][]byte, sizes []int, endpoints []Endpoint, records []receiveRecord) (int, int, error) {
		refused = 0
		if index == count {
			var err error
			count, err = read()
			index, offset, segment = 0, 0, 0
			if err != nil {
				count = 0
				return 0, 0, err
			}
		}
		n := 0
		for index < count && n < len(bufs) {
			m := &messages[index]
			if offset == 0 {
				// Counted in datagrams, the unit the counter's help text names,
				// since one GRO buffer holds many. A zero-length datagram is
				// refused too, since it arrived and goes nowhere.
				if m.Flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || m.N == 0 {
					refused += datagramsIn(m)
					index++
					continue
				}
				var err error
				segment, ecn, err = parseReceived(m.OOB[:m.NN])
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
				source = netip.AddrPort{}
				if from, ok := m.Addr.(*udpSource); ok {
					source = from.addrPort(&zones)
				}
			}
			end := min(offset+segment, m.N)
			raw := m.Buffers[0][offset:end]
			bufs[n], sizes[n], endpoints[n], records[n] = raw, len(raw), nil, receiveRecord{source: source, ecn: ecn}
			if len(raw) >= 4 && binary.BigEndian.Uint32(raw[:4]) == 0 {
				// A datagram whose control message will not parse is counted
				// and dropped, not returned as an error: receiveLoop fails the
				// whole hub on an error, which closes every session on this
				// node, and the GRO sizing skips the same class of failure.
				// Without the endpoint the responder cannot answer, so the
				// datagram is of no use anyway.
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
	segment, _, err := parseReceived(m.OOB[:m.NN])
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

// linux hands the IPv4 TOS as one octet and the IPv6 traffic class as an int
func parseReceived(control []byte) (int, packet.ECN, error) {
	segment, ecn := 0, packet.NotECT
	for len(control) >= unix.CmsgLen(0) {
		header, data, rest, err := unix.ParseOneSocketControlMessage(control)
		if err != nil {
			return 0, packet.NotECT, err
		}
		switch {
		case header.Level == unix.IPPROTO_UDP && header.Type == unix.UDP_GRO:
			if len(data) < 2 {
				return 0, packet.NotECT, errors.New("transport: short UDP_GRO control message")
			}
			segment = int(binary.NativeEndian.Uint16(data))
		case header.Level == unix.IPPROTO_IP && header.Type == unix.IP_TOS && len(data) >= 1:
			ecn = packet.ECNOfTrafficClass(data[0])
		case header.Level == unix.IPPROTO_IPV6 && header.Type == unix.IPV6_TCLASS && len(data) >= 4:
			ecn = packet.ECNOfTrafficClass(uint8(binary.NativeEndian.Uint32(data)))
		}
		control = rest
	}
	return segment, ecn, nil
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
// a nil to sends to the peer a connected socket holds
func (b *udpSendBatch) prepare(packets [][]byte, to net.Addr, control []byte, segment bool) int {
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

// Send resends from the kernel's choice of source when a pinned one is refused, gone or with no route to the peer, and keeps that choice once it worked
// a datagram linux refuses as larger than its path ends the send in a PathMTUError, once the datagrams the path carries went
func (b *udpBind) Send(packets [][]byte, endpoint Endpoint) error {
	ep := endpoint.(*udpEndpoint)
	socket := b.socket(ep)
	if socket == nil {
		return unix.EAFNOSUPPORT
	}
	batch := socket.send.Get().(*udpSendBatch)
	defer socket.send.Put(batch)
	sent, err := b.sendFrom(socket, batch, packets, ep)
	if err == nil || !errors.Is(err, unix.EMSGSIZE) {
		return err
	}
	return b.sendWithin(socket, batch, packets[sent:], ep, err)
}

// socket is the socket of ep's family, nil where the host took none
func (b *udpBind) socket(ep *udpEndpoint) *udpSocket {
	if ep.addr.IP.To4() == nil {
		return b.v6
	}
	return b.v4
}

// sendFrom sends packets to ep from its pin, and from the kernel's choice of source once linux refuses the pin
// it reports how many went before an error
func (b *udpBind) sendFrom(socket *udpSocket, batch *udpSendBatch, packets [][]byte, ep *udpEndpoint) (int, error) {
	control := ep.pin()
	sent, refused := b.sendWithSegmentFallback(socket, batch, packets, ep, ep.addr, control)
	if refused == nil || control == nil || !unpinnable(refused) {
		return sent, refused
	}
	more, err := b.sendWithSegmentFallback(socket, batch, packets[sent:], ep, ep.addr, nil)
	// linux refuses a datagram as too large only once it has routed it from the source it chose
	if (err == nil || errors.Is(err, unix.EMSGSIZE)) && ep.unpin(refused) {
		unpinned(b.events, ep, refused)
	}
	return sent + more, err
}

// sendWithin sends the datagrams of packets the path to ep carries and drops the rest
// after linux refused the first of them with refused for its size
// it reads the path MTU the refusal was measured against from the route and reports it in a PathMTUError
func (b *udpBind) sendWithin(socket *udpSocket, batch *udpSendBatch, packets [][]byte, ep *udpEndpoint, refused error) error {
	mtu, err := b.pathMTU(ep)
	if err != nil {
		return fmt.Errorf("transport: read the path MTU to %s after %w: %w", ep, refused, err)
	}
	report := &PathMTUError{Endpoint: ep, MTU: mtu}
	largest := report.Largest()
	for first := 0; first < len(packets); {
		if len(packets[first]) > largest {
			first++
			continue
		}
		end := first + 1
		for end < len(packets) && len(packets[end]) <= largest {
			end++
		}
		if _, err := b.sendFrom(socket, batch, packets[first:end], ep); err != nil {
			return fmt.Errorf("%w, then %w", report, err)
		}
		first = end
	}
	return report
}

// sendWithSegmentFallback segments packets to ep unless sends to ep have stopped segmenting
// it never segments them while ep's mux lets them fragment
// linux numbers a message's segments up from one IPv4 ID
// the next message may start one ID on
// a router fragmenting both would put fragments of two datagrams under one ID
// when linux refuses a message of several datagrams with an errno segments can cause and they then pass one to a message
// ep stops segmenting for unsegmentedFor
// a socket connected to one peer runs its family's mode, which the family's listener counts
// an ICMP error leaves its errno pending on a connected socket, which fails the next send alone
// so a message refused with EMSGSIZE goes once more as it was before its segments count as refused
func (b *udpBind) sendWithSegmentFallback(socket *udpSocket, batch *udpSendBatch, packets [][]byte, ep *udpEndpoint, to net.Addr, control []byte) (int, error) {
	done, again := 0, -1
	for {
		until, segment := b.segmenting(ep)
		sent, refused, err := socket.write(batch, packets[done:], to, control, segment)
		done += sent
		if err == nil || refused < 2 || !segmentRefusal(err, b.socket(ep).fragmenting.Load() > 0) {
			return done, err
		}
		if errors.Is(err, unix.EMSGSIZE) && again != done {
			again = done
			continue
		}
		plain, _, plainErr := socket.write(batch, packets[done:done+refused], to, control, false)
		done += plain
		if plainErr != nil {
			return done, plainErr
		}
		if ep.unsegmentedUntil.CompareAndSwap(until, int64(time.Since(b.started)+unsegmentedFor)) {
			fellBack(b.events, ep, "transport.endpoint.unsegmented", "transport stopped segmenting sends to an endpoint", err)
		}
	}
}

// segmenting reports whether sends to ep segment now, and the stop it read
func (b *udpBind) segmenting(ep *udpEndpoint) (int64, bool) {
	until := ep.unsegmentedUntil.Load()
	return until, !ep.fragmenting.Load() && (until == 0 || int64(time.Since(b.started)) >= until)
}

// segmentRefusal reports whether err can be linux refusing a message for its segments, which a resend one datagram to a message tells apart
// EIO is a route through an IPsec policy, which passes single datagrams
// EINVAL is also a kernel before 6.14 refusing a segment past the path MTU, whose single datagrams meet the EMSGSIZE a later kernel answers at once
// EMSGSIZE is one too while the socket fragments
// either mode that fragments refuses a segment past the path MTU and fragments a single datagram
func segmentRefusal(err error, fragments bool) bool {
	return errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EIO) || (fragments && errors.Is(err, unix.EMSGSIZE))
}

// write stops at the first refused message and reports the datagrams sent before it and those it carried
func (s *udpSocket) write(batch *udpSendBatch, packets [][]byte, to net.Addr, control []byte, segment bool) (sent, refused int, err error) {
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
