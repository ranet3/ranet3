// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package userspace

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/packet"
)

// The reasons a UDP datagram is dropped or its flow refused
const (
	reasonUDPChecksum = "udp checksum"
	reasonFiltered    = "udp filtered"
	reasonTruncated   = "udp truncated"
	reasonDescriptors = "descriptors"
	reasonSocket      = "socket"
	reasonWithdrawn   = "withdrawn"
)

// udpRelay carries the leaves' UDP outside gVisor's endpoints, as RFC 4787
// has a NAT carry it: one mapping per leaf address and port, shared by every
// destination (REQ-1), on the leaf's port where the host holds it free and
// never on another mapping's (REQ-3), letting in what comes back only from an
// address the mapping sent to (REQ-8), hairpinning a leaf's datagram to
// another mapping (REQ-9), and kept past its last datagram out alone (REQ-5,
// REQ-6). Every socket it opens passes the platform's Prepare.
type udpRelay struct {
	x   *Exit
	now func() time.Time

	mu sync.RWMutex
	// mappings holds each mapping by its leaf's address and port, and ports
	// each by its address and port on the host, which a hairpinned datagram
	// names
	mappings map[netip.AddrPort]*mapping
	ports    map[externalPort]*mapping
	// withdrawn refuses every datagram from a withdrawal until resume
	withdrawn bool

	// readers counts the goroutines reading the mappings' sockets
	readers sync.WaitGroup
}

// externalPort is a mapping's address and port on the host: its class's
// address, or under auto the unspecified address of its family, which its
// receiving socket binds. Two classes' mappings may hold one port, each on its
// own address.
type externalPort struct {
	address netip.Addr
	port    uint16
}

// external is m's address and port on the host
func (m *mapping) external() externalPort {
	if m.source.IsValid() {
		return externalPort{m.source, m.port}
	}
	return externalPort{unspecified(m.leaf.Addr()), m.port}
}

// holding is the mapping holding port on address: the one whose class names
// address, else the one under auto holding port on every address, nil where
// neither does. u.mu is held.
func (u *udpRelay) holding(address netip.Addr, port uint16) *mapping {
	if m := u.ports[externalPort{address, port}]; m != nil {
		return m
	}
	return u.ports[externalPort{unspecified(address), port}]
}

// mapping is one leaf address and port's: a socket on the mapping's port that
// only receives, and a socket per destination on the same port connected to
// it. source is the address the leaf's class names, which every socket of the
// mapping binds, and the zero Addr under auto, where the receiving socket
// binds the wildcard address and each destination's the address the route to
// it picks.
type mapping struct {
	leaf     netip.AddrPort
	source   netip.Addr
	port     uint16
	wildcard *net.UDPConn
	// deadline is when the mapping ends, in unix nanoseconds, which each
	// datagram out moves later and nothing coming in moves
	deadline atomic.Int64

	mu           sync.RWMutex
	destinations map[netip.AddrPort]*destination
	// closed is the mapping ended, after which it takes no destination
	closed bool
	// hairpinned is the flow the mapping's hairpinned datagrams hold, from
	// the first on, which close gives back
	hairpinned bool
	// hairpinnedTo is each of the host's addresses the mapping's hairpinned
	// datagrams went to, which its filter lets in as a destination's
	hairpinnedTo []netip.Addr
}

// destination is a mapping's socket connected to one server
type destination struct {
	to       netip.AddrPort
	conn     *net.UDPConn
	deadline atomic.Int64

	// mu orders a send against a change of the socket's fragmenting, which
	// dontFragment records once fragmentSet
	mu                        sync.Mutex
	dontFragment, fragmentSet bool
}

func newUDPRelay(x *Exit) *udpRelay {
	return &udpRelay{x: x, now: time.Now, mappings: map[netip.AddrPort]*mapping{}, ports: map[externalPort]*mapping{}}
}

// datagram is a UDP datagram as take reads it from its packet: the leaf's
// address and port, the server's, and the UDP header and payload whole
type datagram struct {
	from, to netip.AddrPort
	udp      []byte
}

func (d datagram) payload() []byte { return d.udp[8:] }

// readDatagram reads raw, one IPv4 or IPv6 packet holding a whole UDP
// datagram right after its header, and reports false where the UDP length
// claims more than the packet holds or less than its header
func readDatagram(raw []byte) (datagram, bool) {
	raw, version := packet.Payload(raw)
	var d datagram
	var body []byte
	switch version {
	case 4:
		header := int(raw[0]&0x0f) * 4
		if raw[9] != 17 {
			return d, false
		}
		d.from = netip.AddrPortFrom(netip.AddrFrom4([4]byte(raw[12:16])), 0)
		d.to = netip.AddrPortFrom(netip.AddrFrom4([4]byte(raw[16:20])), 0)
		body = raw[header:]
	case 6:
		if raw[6] != 17 {
			return d, false
		}
		d.from = netip.AddrPortFrom(netip.AddrFrom16([16]byte(raw[8:24])), 0)
		d.to = netip.AddrPortFrom(netip.AddrFrom16([16]byte(raw[24:40])), 0)
		body = raw[40:]
	default:
		return d, false
	}
	if len(body) < 8 {
		return d, false
	}
	length := int(binary.BigEndian.Uint16(body[4:6]))
	if length < 8 || length > len(body) {
		return d, false
	}
	d.from = netip.AddrPortFrom(d.from.Addr(), binary.BigEndian.Uint16(body[0:2]))
	d.to = netip.AddrPortFrom(d.to.Addr(), binary.BigEndian.Uint16(body[2:4]))
	d.udp = body[:length]
	return d, true
}

// checksumValid is whether the datagram's checksum holds over RFC 768's
// pseudo header, RFC 8200 section 8.1's in IPv6. A zero checksum is none in
// IPv4 and passes, and in IPv6, where it is mandatory, fails.
func (d datagram) checksumValid() bool {
	if binary.BigEndian.Uint16(d.udp[6:8]) == 0 {
		return d.from.Addr().Is4()
	}
	return transportSum(d.from.Addr(), d.to.Addr(), 17, d.udp) == 0xffff
}

// transportSum is the one's complement sum of a transport message of protocol
// from source to destination over its pseudo header and itself, 0xffff where
// the message's checksum holds
func transportSum(source, destination netip.Addr, protocol byte, message []byte) uint32 {
	sum := packet.Sum(packet.Sum(0, source.AsSlice()), destination.AsSlice())
	var length [4]byte
	binary.BigEndian.PutUint16(length[0:2], uint16(protocol))
	binary.BigEndian.PutUint16(length[2:4], uint16(len(message)))
	return packet.Sum(packet.Sum(sum, length[:]), message)
}

// fastUDP is whether raw, a packet the lane's judgment delivers, is an
// unfragmented UDP datagram with no IPv6 extension header, which the relay
// takes without the stack, and whether no socket may fragment it: one with DF
// in IPv4, and every one in IPv6, whose routers fragment nothing
func fastUDP(raw []byte) (dontFragment, ok bool) {
	switch raw[0] >> 4 {
	case 4:
		fragment := binary.BigEndian.Uint16(raw[6:8])
		return fragment&0x4000 != 0, raw[9] == 17 && fragment&0x3fff == 0
	case 6:
		return true, raw[6] == 17
	}
	return false, false
}

// takeUDP takes each UDP datagram the stack hands its default handler as one
// packet with no fragment or extension header, which any socket may fragment,
// since its source did
func (x *Exit) takeUDP(_ stack.TransportEndpointID, pkt *stack.PacketBuffer) {
	raw, ok := reassembled(pkt, 17)
	if !ok {
		x.counts.drop(reasonMalformed)
		return
	}
	x.udp.take(raw, false)
}

// take relays raw, one UDP datagram a leaf sent, whole in one packet with no
// fragment or extension header, which the lane's fast path and the stack's
// default handler both hand here. dontFragment is whether the socket sending
// it may not fragment it. The checksum is checked first on both paths, since
// the socket computes a new one: a damaged datagram is dropped and counted,
// answered with no error, and touches no mapping (RFC 1122 section 4.1.3.4).
func (u *udpRelay) take(raw []byte, dontFragment bool) {
	d, ok := readDatagram(raw)
	switch {
	case !ok:
		u.x.counts.drop(reasonMalformed)
		return
	case !d.checksumValid():
		u.x.counts.drop(reasonUDPChecksum)
		return
	case u.x.heldDestination(d.to.Addr()):
		u.hairpin(raw, d)
		return
	}
	m, dst, reason := u.open(d.from, d.to)
	if dst == nil {
		u.refuse(raw, reason)
		return
	}
	// the deadlines move before the send, so whoever sees the datagram
	// arrive reads the deadlines it set
	now := u.now()
	dst.deadline.Store(now.Add(timeoutFor(d.to)).UnixNano())
	m.refresh(now, d.to)
	u.send(raw, d, dst, dontFragment)
}

// timeoutFor is how long a datagram to to keeps its mapping
func timeoutFor(to netip.AddrPort) time.Duration {
	if to.Port() == 53 {
		return dnsTimeout
	}
	return mappingTimeout
}

// refresh keeps m at least to's time past now
func (m *mapping) refresh(now time.Time, to netip.AddrPort) {
	next := now.Add(timeoutFor(to)).UnixNano()
	for {
		old := m.deadline.Load()
		if next <= old || m.deadline.CompareAndSwap(old, next) {
			return
		}
	}
}

// open is the mapping of leaf and its socket toward to, each opened where it
// is not open yet, and why it refused where it did. Each destination is one
// flow of the source's share and of the exit's total, RFC 6888 REQ-4 counting
// flows, and the mapping rides with its first: the flow is admitted before
// either opens, and a mapping this call opened that ends up with no
// destination is closed again, so a refused source holds no socket.
func (u *udpRelay) open(leaf, to netip.AddrPort) (*mapping, *destination, string) {
	if m, dst := u.opened(leaf, to); dst != nil {
		return m, dst, ""
	}
	if reason, ok := u.x.flows.admit(leaf.Addr()); !ok {
		return nil, nil, reason
	}
	for {
		m, created, reason := u.mapping(leaf)
		if m == nil {
			u.x.flows.release(leaf.Addr())
			return nil, nil, reason
		}
		dst, closed, opened, reason := u.destination(m, to)
		if closed {
			continue
		}
		if !opened {
			u.x.flows.release(leaf.Addr())
		}
		if dst == nil && created {
			u.drop(m)
		}
		return m, dst, reason
	}
}

// opened is leaf's mapping and its socket toward to where both are open
func (u *udpRelay) opened(leaf, to netip.AddrPort) (*mapping, *destination) {
	u.mu.RLock()
	m, withdrawn := u.mappings[leaf], u.withdrawn
	u.mu.RUnlock()
	if m == nil || withdrawn {
		return nil, nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m, m.destinations[to]
}

// mapping is leaf's mapping, opened where it has none, whether this call
// opened it, and why it refused
func (u *udpRelay) mapping(leaf netip.AddrPort) (*mapping, bool, string) {
	u.mu.RLock()
	m, withdrawn := u.mappings[leaf], u.withdrawn
	u.mu.RUnlock()
	switch {
	case withdrawn:
		return nil, false, reasonWithdrawn
	case m != nil:
		return m, false, ""
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	switch m := u.mappings[leaf]; {
	case u.withdrawn:
		return nil, false, reasonWithdrawn
	case m != nil:
		return m, false, ""
	}
	source := u.x.sourceFor(leaf.Addr())
	wildcard, err := u.listen(leaf, source)
	if err != nil {
		return nil, false, socketReason(err)
	}
	m = &mapping{leaf: leaf, source: source, port: uint16(wildcard.LocalAddr().(*net.UDPAddr).Port), wildcard: wildcard, destinations: map[netip.AddrPort]*destination{}}
	m.deadline.Store(u.now().Add(mappingSweep).UnixNano())
	u.mappings[leaf] = m
	u.ports[m.external()] = m
	u.readers.Add(1)
	go u.read(m, wildcard, false)
	return m, true, ""
}

// drop ends m, which open opened and could give no destination, unless
// another datagram gave it one meanwhile
func (u *udpRelay) drop(m *mapping) {
	u.mu.Lock()
	defer u.mu.Unlock()
	m.mu.RLock()
	empty := len(m.destinations) == 0
	m.mu.RUnlock()
	if !empty || u.mappings[m.leaf] != m {
		return
	}
	delete(u.mappings, m.leaf)
	delete(u.ports, m.external())
	u.close(m)
}

// destination is m's socket toward to, opened where it has none, whether this
// call opened it, and why it refused. closed reports m ended before it could
// take the destination. The caller has admitted the flow a new one is.
func (u *udpRelay) destination(m *mapping, to netip.AddrPort) (dst *destination, closed, opened bool, reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if dst := m.destinations[to]; dst != nil || m.closed {
		return dst, m.closed, false, ""
	}
	conn, err := u.connect(m.port, m.source, to)
	if err != nil {
		return nil, false, false, socketReason(err)
	}
	dst = &destination{to: to, conn: conn}
	m.destinations[to] = dst
	u.readers.Add(1)
	go u.read(m, conn, true)
	return dst, false, true, ""
}

// socketReason is why a socket's failure refused a flow: the descriptors where
// the process or the host has none left, the socket otherwise
func socketReason(err error) string {
	if errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE) {
		return reasonDescriptors
	}
	return reasonSocket
}

// refuse counts a datagram refused for reason, and answers it past the limit
// where a limit refused it: a source's share, the flows or the descriptors
func (u *udpRelay) refuse(raw []byte, reason string) {
	u.x.counts.refuse(reason)
	switch reason {
	case reasonShare, reasonTotal, reasonDescriptors:
		u.x.answers.Answer(raw, netstack.ExitPastLimit, 0)
	}
}

// listen opens leaf's mapping's receiving socket on source, the wildcard
// address where source is the zero Addr, on a port of mappingPorts' that the
// host holds free, the first, so a leaf's port is kept where free and a port
// below 1024 stays below 1024 where one of the lowPortSearch after it is
// free, else on one the host gives. A port the process may not bind ends the
// search at one the host gives, since every other low port is refused alike.
// No other socket holds the port taken, since the socket binds without
// SO_REUSEPORT and takes it only once bound, so the mapping's destination
// sockets may bind the port too.
func (u *udpRelay) listen(leaf netip.AddrPort, source netip.Addr) (*net.UDPConn, error) {
	network := udpNetwork(leaf.Addr())
	if !source.IsValid() {
		source = unspecified(leaf.Addr())
	}
	var conn *net.UDPConn
	var err error
	refused := false
	for _, port := range mappingPorts(leaf.Port()) {
		if refused && port != 0 {
			continue
		}
		config := net.ListenConfig{Control: func(network, _ string, raw syscall.RawConn) error {
			return u.x.rt.Platform.Prepare(network, netip.AddrPort{}, raw)
		}}
		var pc net.PacketConn
		if pc, err = config.ListenPacket(context.Background(), network, netip.AddrPortFrom(source, port).String()); err == nil {
			conn = pc.(*net.UDPConn)
			break
		}
		if !portTaken(err) {
			return nil, err
		}
		refused = errors.Is(err, syscall.EACCES)
	}
	if err != nil {
		return nil, err
	}
	if err := onSocket(conn, func(fd int) error { return unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1) }); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// mappingPorts is the ports a mapping of a leaf's port tries in turn: the
// leaf's, then for a port below 1024 the lowPortSearch ports below 1024 that
// follow it, 1023 followed by 1, as RFC 4787 REQ-3 (a) recommends a low port
// be mapped to a low port, then 0 for one the host gives
func mappingPorts(leaf uint16) []uint16 {
	ports := []uint16{leaf}
	if leaf > 0 && leaf < 1024 {
		for i := range uint16(lowPortSearch) {
			ports = append(ports, (leaf+i)%1023+1)
		}
	}
	return append(ports, 0)
}

// connect opens a mapping's socket toward to, on source, or the address the
// route to to picks where source is the zero Addr, and the mapping's port,
// connected, as the transport binds its pairs: beside the receiving socket,
// the kernel hands it to's datagrams alone
func (u *udpRelay) connect(port uint16, source netip.Addr, to netip.AddrPort) (*net.UDPConn, error) {
	network := udpNetwork(to.Addr())
	prepare := func(reuse bool) func(string, string, syscall.RawConn) error {
		return func(network, _ string, raw syscall.RawConn) error {
			if err := u.x.rt.Platform.Prepare(network, to, raw); err != nil || !reuse {
				return err
			}
			var set error
			if err := raw.Control(func(fd uintptr) { set = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1) }); err != nil {
				return err
			}
			return set
		}
	}
	if !source.IsValid() {
		route := net.Dialer{Control: prepare(false)}
		probe, err := route.Dial(network, to.String())
		if err != nil {
			return nil, err
		}
		source = probe.LocalAddr().(*net.UDPAddr).AddrPort().Addr()
		_ = probe.Close()
	}
	dialer := net.Dialer{LocalAddr: net.UDPAddrFromAddrPort(netip.AddrPortFrom(source, port)), Control: prepare(true)}
	conn, err := dialer.Dial(network, to.String())
	if err != nil {
		return nil, err
	}
	return conn.(*net.UDPConn), nil
}

func udpNetwork(address netip.Addr) string {
	if address.Is4() {
		return "udp4"
	}
	return "udp6"
}

func unspecified(address netip.Addr) netip.Addr {
	if address.Is4() {
		return netip.IPv4Unspecified()
	}
	return netip.IPv6Unspecified()
}

// onSocket runs set on conn's descriptor
func onSocket(conn *net.UDPConn, set func(fd int) error) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var setErr error
	if err := raw.Control(func(fd uintptr) { setErr = set(int(fd)) }); err != nil {
		return err
	}
	return setErr
}

// send sends d's payload toward its server, fragmenting it on the way out
// only where dontFragment is false, and answers a datagram the path cannot
// carry whole with a too big from the exit at the path's MTU (RFC 4787
// REQ-13). A send that meets an ICMP error the socket was told of earlier is
// sent again, since the error belongs to an earlier datagram.
func (u *udpRelay) send(raw []byte, d datagram, dst *destination, dontFragment bool) {
	dst.mu.Lock()
	defer dst.mu.Unlock()
	if !dst.fragmentSet || dontFragment != dst.dontFragment {
		if err := onSocket(dst.conn, func(fd int) error { return setDontFragment(fd, d.to.Addr().Is6(), dontFragment) }); err != nil {
			return
		}
		dst.dontFragment, dst.fragmentSet = dontFragment, true
	}
	_, err := dst.conn.Write(d.payload())
	if err != nil && !errors.Is(err, syscall.EMSGSIZE) && icmpErrno(err) {
		_, err = dst.conn.Write(d.payload())
	}
	if errors.Is(err, syscall.EMSGSIZE) && dontFragment {
		if mtu := u.pathMTU(dst); mtu > 0 {
			u.x.answers.Answer(raw, netstack.ExitTooBig, mtu)
		}
	}
}

// pathMTU is the MTU of the path dst's socket sends by, as the kernel learned
// it where it keeps one per socket, else the MTU of the link the platform
// routes dst's server by, 0 where it reads neither
func (u *udpRelay) pathMTU(dst *destination) int {
	if mtu, err := socketPathMTU(dst.conn, dst.to.Addr().Is6()); err == nil {
		return mtu
	}
	if link, ok, err := u.x.rt.Platform.Route(dst.to.Addr()); err == nil && ok {
		return link.MTU
	}
	return 0
}

// icmpErrno is an error a socket hands for an ICMP error it was told of
func icmpErrno(err error) bool {
	for _, errno := range []syscall.Errno{syscall.ECONNREFUSED, syscall.EHOSTUNREACH, syscall.ENETUNREACH, syscall.EHOSTDOWN, syscall.EMSGSIZE, syscall.EPROTO, syscall.EACCES, syscall.ENOPROTOOPT} {
		if errors.Is(err, errno) {
			return true
		}
	}
	return false
}

// read hands m's leaf each datagram conn receives, conn being m's wildcard
// socket or, where connected, one of its destination sockets, until conn
// closes. The wildcard socket lets in only a datagram from an address m has a
// destination at, any port, and drops the rest. A pooled buffer is held only
// while a datagram moves, so a mapping at rest holds none, and an ICMP error
// the socket was told of ends no mapping (RFC 4787 REQ-12).
func (u *udpRelay) read(m *mapping, conn *net.UDPConn, connected bool) {
	defer u.readers.Done()
	raw, err := conn.SyscallConn()
	if err != nil {
		return
	}
	headroom := udpHeadroom(m.leaf.Addr())
	for {
		var (
			buf     *[]byte
			n       int
			from    netip.AddrPort
			readErr error
		)
		if err := raw.Read(func(fd uintptr) bool {
			buf = buffers[1].Get().(*[]byte)
			window := (*buf)[headroom:cap(*buf)]
			var flags int
			var sa unix.Sockaddr
			n, _, flags, sa, readErr = unix.Recvmsg(int(fd), window, nil, unix.MSG_DONTWAIT)
			if errors.Is(readErr, unix.EAGAIN) {
				buffers[1].Put(buf)
				return false
			}
			if readErr == nil && flags&unix.MSG_TRUNC != 0 {
				readErr = errTruncated
			}
			from = sockaddrPort(sa)
			return true
		}); err != nil {
			return
		}
		switch {
		case errors.Is(readErr, errTruncated):
			u.x.counts.drop(reasonTruncated)
		case readErr != nil:
			if !icmpErrno(readErr) && !errors.Is(readErr, syscall.EINTR) {
				buffers[1].Put(buf)
				return
			}
		case !connected && !m.admits(from):
			u.x.counts.drop(reasonFiltered)
		default:
			ident := u.x.ident.Add(1)
			u.x.toLeaf(udpPacket((*buf)[:headroom+n], headroom, from, m.leaf, uint16(ident), u.x.hops(m.leaf.Addr().Is6())), ident)
		}
		buffers[1].Put(buf)
	}
}

var errTruncated = errors.New("userspace: datagram past the buffer")

// admits is whether m lets in a datagram from from: from an address it holds
// a destination at, or one of the host's its hairpinned datagrams went to,
// whatever the port, RFC 4787 REQ-8's address dependent filtering, which a
// hairpinned datagram meets as one from outside does
func (m *mapping) admits(from netip.AddrPort) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if slices.Contains(m.hairpinnedTo, from.Addr()) {
		return true
	}
	for to := range m.destinations {
		if to.Addr() == from.Addr() {
			return true
		}
	}
	return false
}

// hairpinTo records address, the host's address a datagram m hairpins went
// to, for m's filter. The host's addresses bound what it holds.
func (m *mapping) hairpinTo(address netip.Addr) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !slices.Contains(m.hairpinnedTo, address) {
		m.hairpinnedTo = append(m.hairpinnedTo, address)
	}
}

func sockaddrPort(sa unix.Sockaddr) netip.AddrPort {
	switch sa := sa.(type) {
	case *unix.SockaddrInet4:
		return netip.AddrPortFrom(netip.AddrFrom4(sa.Addr), uint16(sa.Port))
	case *unix.SockaddrInet6:
		return netip.AddrPortFrom(netip.AddrFrom16(sa.Addr).Unmap(), uint16(sa.Port))
	}
	return netip.AddrPort{}
}

// udpHeadroom is the IP and UDP headers ahead of a reply's payload in its
// buffer, of address's family
func udpHeadroom(address netip.Addr) int {
	if address.Is4() {
		return 20 + 8
	}
	return 40 + 8
}

// udpPacket writes the IP and UDP headers of a datagram from from to to in
// the headroom of buf, whose payload follows them, and returns the packet:
// with no DF, so the lane's session may cut an IPv4 one, hops its TTL or hop
// limit, and its checksum computed
func udpPacket(buf []byte, headroom int, from, to netip.AddrPort, ident uint16, hops uint8) []byte {
	pkt := buf
	udp := pkt[headroom-8:]
	binary.BigEndian.PutUint16(udp[0:2], from.Port())
	binary.BigEndian.PutUint16(udp[2:4], to.Port())
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	binary.BigEndian.PutUint16(udp[6:8], 0)
	checksum := ^uint16(transportSum(from.Addr(), to.Addr(), 17, udp))
	if checksum == 0 {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:8], checksum)
	leafHeader(pkt, from.Addr(), to.Addr(), 17, 0, hops, ident)
	return pkt
}

// leafHeader writes the IPv4 or IPv6 header of pkt, a packet the exit builds
// toward a leaf whose payload follows the header, from from to to: protocol
// its protocol or next header, ds its DS field, hops its TTL or hop limit,
// and an IPv4 one's identification ident, with no DF and its checksum
// computed
func leafHeader(pkt []byte, from, to netip.Addr, protocol, ds, hops byte, ident uint16) {
	if from.Is4() {
		h := pkt[:20]
		clear(h)
		h[0], h[1] = 4<<4|5, ds
		binary.BigEndian.PutUint16(h[2:4], uint16(len(pkt)))
		binary.BigEndian.PutUint16(h[4:6], ident)
		h[8], h[9] = hops, protocol
		copy(h[12:16], from.AsSlice())
		copy(h[16:20], to.AsSlice())
		binary.BigEndian.PutUint16(h[10:12], ^uint16(packet.Sum(0, h)))
		return
	}
	h := pkt[:40]
	clear(h)
	h[0], h[1] = 6<<4|ds>>4, ds<<4
	binary.BigEndian.PutUint16(h[4:6], uint16(len(pkt)-40))
	h[6], h[7] = protocol, hops
	copy(h[8:24], from.AsSlice())
	copy(h[24:40], to.AsSlice())
}

// toLeaf sends pkt, a packet the exit built toward a leaf, through the pump's
// lane, cut as its source cuts it where it is an IPv6 packet larger than the
// leaf's session carries (RFC 8200 section 4.5), ident naming its fragments.
// An IPv4 one goes whole, with no DF, for the lane to cut.
func (x *Exit) toLeaf(pkt []byte, ident uint32) {
	if pkt[0]>>4 == 6 {
		source, destination := netip.AddrFrom16([16]byte(pkt[8:24])), netip.AddrFrom16([16]byte(pkt[24:40]))
		if mtu := x.answers.MTU(source, destination); mtu > 0 && len(pkt) > mtu {
			if fragments, ok := packet.AppendFragments6(nil, pkt, mtu, ident); ok {
				for len(fragments) > 0 {
					size := 40 + int(binary.BigEndian.Uint16(fragments[4:6]))
					x.link.send(fragments[:size])
					fragments = fragments[size:]
				}
				return
			}
		}
	}
	x.link.send(pkt)
}

// hairpin carries d, a datagram toward an address the host holds, to the
// mapping holding its port there, from the sender's own mapping's port on
// that address (RFC 4787 REQ-9), where that mapping's filter lets the address
// in, as it would a datagram from outside, and drops and counts it otherwise.
// The sender's filter lets the address in from then on. It refuses d as toward
// the host itself where no mapping holds the port, so no leaf reaches the
// host's own services.
func (u *udpRelay) hairpin(raw []byte, d datagram) {
	u.mu.RLock()
	target := u.holding(d.to.Addr(), d.to.Port())
	u.mu.RUnlock()
	if target == nil || target.source.IsValid() && target.source != d.to.Addr() {
		u.x.counts.refuse(reasonDestination)
		u.x.answers.Answer(raw, netstack.ExitProhibited, 0)
		return
	}
	headroom := udpHeadroom(d.to.Addr())
	if headroom+len(d.payload()) > largeBuffer {
		u.x.counts.drop(reasonTruncated)
		return
	}
	sender, reason := u.hairpinFrom(d.from)
	if sender == nil {
		u.refuse(raw, reason)
		return
	}
	sender.refresh(u.now(), d.to)
	from := netip.AddrPortFrom(d.to.Addr(), sender.port)
	if sender.source.IsValid() {
		from = netip.AddrPortFrom(sender.source, sender.port)
	}
	sender.hairpinTo(d.to.Addr())
	if !target.admits(from) {
		u.x.counts.drop(reasonFiltered)
		return
	}
	buf := buffers[1].Get().(*[]byte)
	defer buffers[1].Put(buf)
	n := copy((*buf)[headroom:cap(*buf)], d.payload())
	ident := u.x.ident.Add(1)
	u.x.toLeaf(udpPacket((*buf)[:headroom+n], headroom, from, target.leaf, uint16(ident), u.x.hops(target.leaf.Addr().Is6())), ident)
}

// hairpinFrom is leaf's mapping for a datagram it hairpins, opened where it
// has none, its hairpinned datagrams holding one flow of the source's share
// and of the exit's total from the first on, and why it refused
func (u *udpRelay) hairpinFrom(leaf netip.AddrPort) (*mapping, string) {
	if m, _ := u.opened(leaf, netip.AddrPort{}); m != nil {
		m.mu.RLock()
		held := m.hairpinned
		m.mu.RUnlock()
		if held {
			return m, ""
		}
	}
	if reason, ok := u.x.flows.admit(leaf.Addr()); !ok {
		return nil, reason
	}
	for {
		m, _, reason := u.mapping(leaf)
		if m == nil {
			u.x.flows.release(leaf.Addr())
			return nil, reason
		}
		m.mu.Lock()
		closed, held := m.closed, m.hairpinned
		m.hairpinned = true
		m.mu.Unlock()
		switch {
		case closed:
			continue
		case held:
			u.x.flows.release(leaf.Addr())
		}
		return m, ""
	}
}

// expire ends each destination and each mapping past its time at now
func (u *udpRelay) expire(now time.Time) {
	at := now.UnixNano()
	u.mu.Lock()
	defer u.mu.Unlock()
	for leaf, m := range u.mappings {
		if m.deadline.Load() <= at {
			delete(u.mappings, leaf)
			delete(u.ports, m.external())
			u.close(m)
			continue
		}
		m.mu.Lock()
		for to, dst := range m.destinations {
			if dst.deadline.Load() <= at {
				delete(m.destinations, to)
				_ = dst.conn.Close()
				u.x.flows.release(leaf.Addr())
			}
		}
		m.mu.Unlock()
	}
}

// close ends m: its sockets closed and its flows given back
func (u *udpRelay) close(m *mapping) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	for to, dst := range m.destinations {
		delete(m.destinations, to)
		_ = dst.conn.Close()
		u.x.flows.release(m.leaf.Addr())
	}
	if m.hairpinned {
		u.x.flows.release(m.leaf.Addr())
	}
	_ = m.wildcard.Close()
}

func (u *udpRelay) withdraw() {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.withdrawn = true
	for leaf, m := range u.mappings {
		delete(u.mappings, leaf)
		delete(u.ports, m.external())
		u.close(m)
	}
}

func (u *udpRelay) resume() {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.withdrawn = false
}
