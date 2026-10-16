// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

//go:build darwin

package transport

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// This backend exists for one option the portable one cannot offer:
// IP_BOUND_IF and IPV6_BOUND_IF, which scope the socket carrying IKE and ESP
// to one interface. Nothing else on darwin keeps an underlay out of the mesh's
// own routing: there are no marks, no policy rules and one table shared by
// every program, so a real default route out of the mesh tun would otherwise
// carry this node's own ESP into the tunnel that ESP is carrying.
//
// Scoping the socket is necessary and, on this kernel, not sufficient. See
// reportBoundReach for what else the host needs and for the measurement.
//
// The portable bind is wireguard's StdNetBind, which keeps its descriptors to
// itself, so there is no seam to set a socket option through. The socket work
// here is otherwise the plainest form of what that one does: one datagram per
// read, one write per packet. darwin has neither recvmmsg nor UDP
// segmentation, so the batching the linux backend is built around has nothing
// to stand on here.

// darwinEndpoint is one peer address this socket sends to. A received datagram
// carries no reply source address, the same as under the portable bind, so an
// endpoint is the peer and nothing else.
type darwinEndpoint struct {
	addr netip.AddrPort
	// fragments lets darwin fragment this IPv6 endpoint's datagrams, each carrying an IPV6_DONTFRAG of 0
	fragments atomic.Bool
}

func (*darwinEndpoint) transportEndpoint() {}
func (e *darwinEndpoint) String() string   { return e.addr.String() }

// AddrPort drops the zone a link-local address arrives with. NAT detection
// hashes what this returns (RFC 7296 section 2.23), and the linux backend
// reaches these addresses through a sockaddr that carries no zone, so keeping
// one here would make the two ends of one mesh hash differently.
func (e *darwinEndpoint) AddrPort() netip.AddrPort {
	return netip.AddrPortFrom(e.addr.Addr().WithZone(""), e.addr.Port())
}

func (e *darwinEndpoint) sameDestination(other Endpoint) bool {
	o, ok := other.(*darwinEndpoint)
	return ok && e.addr == o.addr
}

func (e *darwinEndpoint) withoutSource() Endpoint { return e }

// darwinSocket is one bound UDP socket of one family. raw is retained for the
// whole life of the socket so the interface binding can be moved without
// reopening it: the socket carries every SA this node holds, and a new
// descriptor would drop all of them to follow a link change no peer saw.
type darwinSocket struct {
	conn *net.UDPConn
	raw  syscall.RawConn
	ipv6 bool
	// bindOption is the setsockopt this socket moves with, a field so a test
	// can fail one family and not the other. Every index the kernel refuses
	// it refuses for both, so a half-finished move cannot be produced from
	// outside and the rollback would otherwise go unmeasured.
	bindOption func(index int) error
	// fragmenting counts the muxes letting this IPv4 socket's sends fragment
	// it is stored under its bind's fragmentMu and loaded without the lock
	// the socket clears IP_DONTFRAG while it is above zero
	fragmenting atomic.Int32
}

// dontFragmentOption is the level and option name that sets DF on this family's datagrams
func dontFragmentOption(ipv6 bool) (level, option int) {
	if ipv6 {
		return unix.IPPROTO_IPV6, unix.IPV6_DONTFRAG
	}
	return unix.IPPROTO_IP, unix.IP_DONTFRAG
}

func (s *darwinSocket) setDontFragment(on bool) error {
	level, option := dontFragmentOption(s.ipv6)
	value := 0
	if on {
		value = 1
	}
	var setErr error
	if err := s.raw.Control(func(fd uintptr) { setErr = unix.SetsockoptInt(int(fd), level, option, value) }); err != nil {
		return err
	}
	return setErr
}

// boundInterfaceOption is the level and option name that binds this family's
// socket to one interface.
func (s *darwinSocket) boundInterfaceOption() (level, option int) {
	if s.ipv6 {
		return unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF
	}
	return unix.IPPROTO_IP, unix.IP_BOUND_IF
}

func (s *darwinSocket) setBoundInterface(index int) error {
	if s.bindOption != nil {
		return s.bindOption(index)
	}
	return s.setBoundInterfaceOption(index)
}

func (s *darwinSocket) setBoundInterfaceOption(index int) error {
	level, option := s.boundInterfaceOption()
	var setErr error
	if err := s.raw.Control(func(fd uintptr) {
		setErr = unix.SetsockoptInt(int(fd), level, option, index)
	}); err != nil {
		return err
	}
	return setErr
}

// darwinBind holds the one socket per family every session shares.
type darwinBind struct {
	// rebind serializes a move from one interface to the other, so the two
	// families cannot end up on different ones, and bound is the interface
	// both are on, which a half-finished move puts them back onto.
	rebind sync.Mutex
	bound  int
	v4, v6 *darwinSocket
	// fragmentMu serializes the IPv4 socket's count of muxes letting its sends fragment, and pairs
	fragmentMu sync.Mutex
	// pairs holds the open sockets connected to one peer, each IPv4 one with its listener's IP_DONTFRAG
	pairs map[*darwinPair]struct{}
	// setDontFragment sets or clears a socket's DF, which a test answers in place of darwin
	setDontFragment func(socket *darwinSocket, on bool) error
	// port is the listener's, which a socket connected to one peer binds too
	port uint16
	// connecting holds one connect at a time
	// XNU refuses to bind an address and port while another socket holds it unconnected
	connecting sync.Mutex
}

func (b *darwinBind) ParseEndpoint(s string) (Endpoint, error) {
	addr, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &darwinEndpoint{addr: netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())}, nil
}

func (b *darwinBind) Close() error {
	var errs []error
	for _, socket := range []*darwinSocket{b.v4, b.v6} {
		if socket != nil {
			errs = append(errs, socket.conn.Close())
		}
	}
	return errors.Join(errs...)
}

// bindInterface moves both families at once, where zero unbinds. A partial
// move is reported rather than left: one family on the old interface and one
// on the new is a node that reaches half its peers.
func (b *darwinBind) bindInterface(index int, routed bool) error {
	b.rebind.Lock()
	defer b.rebind.Unlock()
	var moved []*darwinSocket
	for _, socket := range []*darwinSocket{b.v4, b.v6} {
		if socket == nil {
			continue
		}
		if err := socket.setBoundInterface(index); err != nil {
			// Put back whatever already moved, so a half-finished move leaves
			// both families where they were rather than one on each
			// interface. b.bound holds where they were, from this process's
			// own record rather than from a guess.
			errs := []error{fmt.Errorf("transport: bind the underlay socket to interface %d: %w", index, err)}
			for _, done := range moved {
				if back := done.setBoundInterface(b.bound); back != nil {
					errs = append(errs, fmt.Errorf("transport: put the underlay socket back on interface %d: %w", b.bound, back))
				}
			}
			return errors.Join(errs...)
		}
		moved = append(moved, socket)
	}
	b.bound = index
	reportBoundReach(index, routed)
	return nil
}

// offLinkProbes are the destinations a bound socket is asked about, one per
// family, both from the documentation ranges so nothing is ever sent to a real
// host. connect on a UDP socket resolves a route and sends no packet, so this
// reads the forwarding table without touching the network.
var offLinkProbes = []netip.Addr{
	netip.MustParseAddr("192.0.2.1"),
	netip.MustParseAddr("2001:db8::1"),
}

// reportBoundReach checks that the binding left the socket able to reach
// anything at all, which on this platform does not follow from the binding.
//
// IP_BOUND_IF does not take a socket out of the forwarding table. Measured on
// Darwin 27.2.0 by TestDarwinBoundSocketNeedsAScopedDefault: a scoped lookup
// still finds the most specific route, and where that route leaves another
// interface, the lookup falls back only to a route already on the bound one.
// So an unscoped route out of another interface that holds its family's zero
// address takes the underlay with it unless the underlay's own interface
// carries a default of its own scoped to it. internal/kernel writes that
// default for a family only while such a route is in the table, another
// program's or its own, or while the reconciler is about to install its own,
// and otherwise writes nothing. routed says the caller has Runtime.Routes,
// which prepared the interface before the socket was bound to it, not that a
// default was written.
//
// Routed or not, an unreachable socket is reported rather than refused: the
// node stops holding a capturing route once its sessions die, so the state is
// recoverable and a refusal here would turn a bad route into a dead daemon.
func reportBoundReach(index int, routed bool) {
	if index == 0 {
		return
	}
	var unreachable []string
	for _, probe := range offLinkProbes {
		if err := boundReachProbe(index, probe); err != nil {
			unreachable = append(unreachable, probe.String())
		}
	}
	// Only when neither family can get off the link. A node on an IPv4-only
	// or IPv6-only uplink has one of these failing as a matter of course.
	if len(unreachable) < len(offLinkProbes) {
		return
	}
	if routed {
		slog.Warn("transport bound the underlay socket to an interface it still cannot reach off",
			"interface_index", index, "probes", strings.Join(unreachable, " "),
			"detail", "this node writes a default scoped to that interface only for a family whose zero address an unscoped route out of another interface holds or is about to hold, so see which route a lookup scoped to it finds, route -n get [-inet6] -ifscope <interface> <probe>")
		return
	}
	slog.Warn("transport bound the underlay socket to an interface it cannot reach off",
		"interface_index", index, "probes", strings.Join(unreachable, " "),
		"detail", "nothing here writes that interface's routing, so give it a default scoped to it, route -n add -net 0.0.0.0/0 <next hop> -ifscope <interface>")
}

// boundReachProbe is reachesWhenBound in production. A test replaces it,
// because what a host answers about an off-link address is the host's own
// business and this report's rules have to hold whatever it says.
var boundReachProbe = reachesWhenBound

// reachesWhenBound resolves one route the way the bound socket would. It opens
// its own descriptor rather than using the live one, because connect on the
// live socket would fix its destination.
func reachesWhenBound(index int, target netip.Addr) error {
	_, err := boundSource(index, netip.AddrPortFrom(target, 9))
	return err
}

// boundSource resolves one route the way a socket bound to index would, and answers the source it picks
// a link-local target's zone names the interface its route takes, and a link-local source comes back zoned by it
func boundSource(index int, target netip.AddrPort) (netip.Addr, error) {
	network, level, option := "udp4", unix.IPPROTO_IP, unix.IP_BOUND_IF
	if target.Addr().Is6() {
		network, level, option = "udp6", unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF
	}
	dialer := net.Dialer{Control: func(_, _ string, raw syscall.RawConn) error {
		var setErr error
		if err := raw.Control(func(fd uintptr) { setErr = unix.SetsockoptInt(int(fd), level, option, index) }); err != nil {
			return err
		}
		return setErr
	}}
	conn, err := dialer.Dial(network, target.String())
	if err != nil {
		return netip.Addr{}, err
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Unmap(), nil
}

// icmpErrnos are the errors XNU hands a connected UDP socket for an ICMP error, read by its next send or receive
// udp_ctlinput and udp6_ctlinput pass every errno of inetctlerrmap and inet6ctlerrmap to the socket's so_error
var icmpErrnos = []unix.Errno{unix.ECONNREFUSED, unix.EHOSTDOWN, unix.EHOSTUNREACH, unix.EMSGSIZE, unix.ENETUNREACH, unix.ENOPROTOOPT}

// pairOf leaves the local address to the route, since a darwin endpoint carries no source
func (b *darwinBind) pairOf(endpoint Endpoint) pairKey {
	return pairKey{remote: endpoint.(*darwinEndpoint).addr}
}

// connectPair binds the route's source on the hub's port beside the wildcard listener and connects to the peer
// XNU looks a datagram up by its exact 4-tuple before any wildcard socket
func (b *darwinBind) connectPair(k pairKey) (pairSocket, receiveFunc, error) {
	b.connecting.Lock()
	defer b.connecting.Unlock()
	b.rebind.Lock()
	index := b.bound
	b.rebind.Unlock()
	v6 := k.remote.Addr().Is6()
	network := "udp4"
	if v6 {
		network = "udp6"
	}
	local, err := boundSource(index, k.remote)
	if err != nil {
		return nil, nil, err
	}
	dialer := net.Dialer{LocalAddr: net.UDPAddrFromAddrPort(netip.AddrPortFrom(local, b.port)), Control: socketControl(v6, index, pairBuffer, true)}
	conn, err := dialer.Dial(network, k.remote.String())
	if err != nil {
		return nil, nil, err
	}
	socket := &darwinSocket{conn: conn.(*net.UDPConn), ipv6: v6}
	pair := &darwinPair{socket: socket, bind: b, address: local}
	if socket.raw, err = socket.conn.SyscallConn(); err == nil {
		err = b.join(pair)
	}
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	return pair, retryICMP(socket.receiver()), nil
}

// join gives an IPv4 p its listener's IP_DONTFRAG, which fragment then moves it with
func (b *darwinBind) join(p *darwinPair) error {
	b.fragmentMu.Lock()
	defer b.fragmentMu.Unlock()
	if !p.socket.ipv6 && b.v4 != nil && b.v4.fragmenting.Load() > 0 {
		if err := b.setDontFragment(p.socket, false); err != nil {
			return err
		}
	}
	b.pairs[p] = struct{}{}
	return nil
}

// darwinPair is a socket connected to one peer
type darwinPair struct {
	socket  *darwinSocket
	bind    *darwinBind
	address netip.Addr
}

// transmit writes one packet a call to the peer the socket holds, as one darwin may fragment while ep's IPv6 sends fragment
func (p *darwinPair) transmit(packets [][]byte, endpoint Endpoint) (int, bool, error) {
	fragments := endpoint.(*darwinEndpoint).fragments.Load()
	return pastICMP(func(packets [][]byte) (int, error) {
		for i, packet := range packets {
			var err error
			if fragments {
				_, _, err = p.socket.conn.WriteMsgUDP(packet, fragmentControl, nil)
			} else {
				_, err = p.socket.conn.Write(packet)
			}
			if err != nil {
				return i, err
			}
		}
		return len(packets), nil
	}, packets)
}

func (p *darwinPair) local() netip.Addr { return p.address }

func (p *darwinPair) Close() error {
	p.bind.fragmentMu.Lock()
	delete(p.bind.pairs, p)
	p.bind.fragmentMu.Unlock()
	return p.socket.conn.Close()
}

// Send writes one datagram at a time
// a datagram darwin refuses as larger than its interface's MTU ends the send in a PathMTUError, once the datagrams within that MTU went
func (b *darwinBind) Send(packets [][]byte, endpoint Endpoint) error {
	ep, ok := endpoint.(*darwinEndpoint)
	if !ok {
		return fmt.Errorf("transport: endpoint %T did not come from this bind", endpoint)
	}
	socket := b.v6
	if ep.addr.Addr().Is4() {
		socket = b.v4
	}
	if socket == nil {
		return unix.EAFNOSUPPORT
	}
	for i, packet := range packets {
		err := socket.write(packet, ep)
		if errors.Is(err, unix.EMSGSIZE) {
			return b.sendWithin(socket, packets[i:], ep, err)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// fragmentControl is the control message that lets darwin fragment one IPv6 datagram whatever IPV6_DONTFRAG its socket holds
var fragmentControl = func() []byte {
	control := make([]byte, unix.CmsgSpace(4))
	header := (*unix.Cmsghdr)(unsafe.Pointer(&control[0]))
	header.Level, header.Type = unix.IPPROTO_IPV6, unix.IPV6_DONTFRAG
	header.SetLen(unix.CmsgLen(4))
	return control
}()

// write sends one datagram to ep, as one darwin may fragment while ep's IPv6 sends fragment
func (s *darwinSocket) write(packet []byte, ep *darwinEndpoint) error {
	if ep.fragments.Load() {
		_, _, err := s.conn.WriteMsgUDPAddrPort(packet, fragmentControl, ep.addr)
		return err
	}
	_, err := s.conn.WriteToUDPAddrPort(packet, ep.addr)
	return err
}

// sendWithin sends the datagrams of packets the path to ep carries and drops the rest
// after darwin refused the first of them with refused for its size
// it reads the MTU the refusal was measured against and reports it in a PathMTUError
func (b *darwinBind) sendWithin(socket *darwinSocket, packets [][]byte, ep *darwinEndpoint, refused error) error {
	mtu, err := b.readPathMTU(ep)
	if err != nil {
		return fmt.Errorf("transport: read the path MTU to %s after %w: %w", ep, refused, err)
	}
	report := &PathMTUError{Endpoint: ep, MTU: mtu}
	for _, packet := range packets {
		if len(packet) > report.Largest() {
			continue
		}
		if err := socket.write(packet, ep); err != nil {
			return fmt.Errorf("%w, then %w", report, err)
		}
	}
	return report
}

var _ pathBind = (*darwinBind)(nil)

// readPathMTU reads the MTU of the interface sends to ep leave by, the bound one or else the one the host routes ep through
// darwin refuses a datagram with DF only past that MTU, and the probes find a narrower path beyond the interface
func (b *darwinBind) readPathMTU(endpoint Endpoint) (int, error) {
	b.rebind.Lock()
	index := b.bound
	b.rebind.Unlock()
	if index == 0 {
		var err error
		if index, err = routedInterface(endpoint.(*darwinEndpoint).addr); err != nil {
			return 0, err
		}
	}
	link, err := net.InterfaceByIndex(index)
	if err != nil {
		return 0, err
	}
	return link.MTU, nil
}

// routedInterface is the interface the host routes a datagram to addr through, the one holding the source a socket connected to addr takes
// connecting looks the route up and sends nothing
func routedInterface(addr netip.AddrPort) (int, error) {
	conn, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(addr))
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	local := conn.LocalAddr().(*net.UDPAddr)
	if local.Zone != "" {
		link, err := net.InterfaceByName(local.Zone)
		if err != nil {
			return 0, err
		}
		return link.Index, nil
	}
	links, err := net.Interfaces()
	if err != nil {
		return 0, err
	}
	for _, link := range links {
		addresses, err := link.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			if prefix, ok := address.(*net.IPNet); ok && prefix.IP.Equal(local.IP) {
				return link.Index, nil
			}
		}
	}
	return 0, fmt.Errorf("transport: no interface holds %s, the source of the route to %s", local.IP, addr)
}

// fragment clears DF on the IPv4 socket while any mux asks, since IP_DONTFRAG holds for a whole socket
// an IPv6 endpoint clears it on its own datagrams alone
// the IPv4 sockets connected to one peer move with the IPv4 socket, and one that cannot is closed, which hands its sends to the shared socket
func (b *darwinBind) fragment(endpoint Endpoint, on bool) error {
	ep := endpoint.(*darwinEndpoint)
	if !ep.addr.Addr().Is4() {
		ep.fragments.Store(on)
		return nil
	}
	if b.v4 == nil {
		return unix.EAFNOSUPPORT
	}
	b.fragmentMu.Lock()
	defer b.fragmentMu.Unlock()
	was := b.v4.fragmenting.Load()
	count := was - 1
	if on {
		count = was + 1
	}
	if (count > 0) != (was > 0) {
		if err := b.setDontFragment(b.v4, count == 0); err != nil {
			return err
		}
		for pair := range b.pairs {
			if !pair.socket.ipv6 && b.setDontFragment(pair.socket, count == 0) != nil {
				delete(b.pairs, pair)
				_ = pair.socket.conn.Close()
			}
		}
	}
	b.v4.fragmenting.Store(count)
	return nil
}

func (b *darwinBind) dontFragment(endpoint Endpoint) bool {
	ep := endpoint.(*darwinEndpoint)
	if !ep.addr.Addr().Is4() {
		return !ep.fragments.Load()
	}
	return b.v4 != nil && b.v4.fragmenting.Load() == 0
}

// receiver reads one datagram per call. The buffer is the receiver's own and
// its view stays valid until the next call, which is the contract every
// backend holds. The hub copies anything it keeps.
func (s *darwinSocket) receiver() receiveFunc {
	buf := make([]byte, readBufferSize)
	return func(bufs [][]byte, sizes []int, endpoints []Endpoint) (int, int, error) {
		n, from, err := s.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return 0, 0, err
		}
		bufs[0], sizes[0] = buf[:n], n
		endpoints[0] = &darwinEndpoint{addr: netip.AddrPortFrom(from.Addr().Unmap(), from.Port())}
		// Every datagram is handed straight through, so this bind refuses
		// none of its own. The hub counts the ones nothing wanted.
		return 1, 0, nil
	}
}

// darwin has no packet marks and no policy rules, and binds instead.
// Underlay.refuse reads these.
const (
	marksSockets = false
	bindsSockets = true
)

// openPacketBind takes the one socket this node's IKE and ESP share. index
// binds it to that interface, and zero leaves it following the forwarding
// table as every other socket on the machine does. routed says the caller has
// Runtime.Routes, which prepares an interface before the socket is bound to
// it, not that a default was written. See reportBoundReach.
func openPacketBind(port uint16, underlay Underlay, index int, routed bool, _ func(string, ...slog.Attr)) (packetBind, []receiveFunc, uint16, error) {
	// The port selected by the IPv4 bind may already be occupied on IPv6.
	// Retry ephemeral allocation, but an explicitly requested port still fails.
	var err error
	for range ephemeralPortRetries {
		var bind packetBind
		var receivers []receiveFunc
		var bound uint16
		bind, receivers, bound, err = listenPacketBind(port, index)
		if port != 0 || !errors.Is(err, unix.EADDRINUSE) {
			if err == nil {
				// The first binding goes through the listen hook rather than
				// bindInterface, and it is the one that matters most: a node
				// starting next to the default a previous run installed has no
				// working underlay from its first datagram.
				reportBoundReach(index, routed)
			}
			return bind, receivers, bound, err
		}
	}
	return nil, nil, 0, err
}

func listenPacketBind(port uint16, index int) (packetBind, []receiveFunc, uint16, error) {
	b := &darwinBind{pairs: make(map[*darwinPair]struct{}), setDontFragment: (*darwinSocket).setDontFragment}
	var receivers []receiveFunc
	for i, network := range []string{"udp4", "udp6"} {
		ipv6 := i == 1
		// the listener never sets SO_REUSEPORT, not even once bound as on linux
		// in_pcbbind in bsd/netinet/in_pcb.c and in6_pcbbind in bsd/netinet6/in6_pcb.c (xnu f6217f8) read a held socket's options again at each later bind
		// and skip the user check for a second bind of the wildcard address where the held socket has SO_REUSEPORT, which lets a process of any user share the port
		lc := net.ListenConfig{Control: socketControl(ipv6, index, socketBufferSize, false)}
		pc, err := lc.ListenPacket(context.Background(), network, fmt.Sprintf(":%d", port))
		if err != nil {
			if errors.Is(err, unix.EAFNOSUPPORT) || errors.Is(err, unix.EPROTONOSUPPORT) {
				continue
			}
			_ = b.Close()
			return nil, nil, 0, err
		}
		socket := &darwinSocket{conn: pc.(*net.UDPConn), ipv6: ipv6}
		if socket.raw, err = socket.conn.SyscallConn(); err != nil {
			_ = socket.conn.Close()
			_ = b.Close()
			return nil, nil, 0, err
		}
		if ipv6 {
			b.v6 = socket
		} else {
			b.v4 = socket
		}
		port = uint16(pc.LocalAddr().(*net.UDPAddr).Port)
		receivers = append(receivers, socket.receiver())
	}
	if len(receivers) == 0 {
		return nil, nil, 0, unix.EAFNOSUPPORT
	}
	// The first binding happens in the listen hook above rather than through
	// bindInterface, so this is where the bind learns where its sockets are.
	// A rollback reads it, and without it a half-finished first move would put
	// the family that had already moved onto no interface at all.
	b.bound = index
	b.port = port
	return b, receivers, port, nil
}

// socketControl sets the buffers, DF and the interface binding on a socket before it binds
// and SO_REUSEADDR where it binds the listener's port on one address, which XNU then allows beside the wildcard listener
func socketControl(ipv6 bool, index, buffer int, reuseAddr bool) func(string, string, syscall.RawConn) error {
	return func(_, _ string, raw syscall.RawConn) error {
		var optionErr error
		if err := raw.Control(func(fd uintptr) {
			for _, option := range []int{unix.SO_RCVBUF, unix.SO_SNDBUF} {
				// Tuning, so a kernel that clamps or refuses it costs
				// throughput and nothing else.
				_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, option, buffer)
			}
			if reuseAddr {
				optionErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
			}
			if optionErr == nil {
				// DF on every datagram, and darwin refusing one past its interface's MTU rather than fragmenting it, which Send reports
				level, option := dontFragmentOption(ipv6)
				optionErr = unix.SetsockoptInt(int(fd), level, option, 1)
			}
			if index == 0 || optionErr != nil {
				return
			}
			// Reported rather than ignored like the tuning above. This
			// binding keeps the ESP underlay out of the tun carrying it,
			// so a silent failure here is an underlay that disappears
			// into the overlay.
			level, option := unix.IPPROTO_IP, unix.IP_BOUND_IF
			if ipv6 {
				level, option = unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF
			}
			optionErr = unix.SetsockoptInt(int(fd), level, option, index)
		}); err != nil {
			return err
		}
		return optionErr
	}
}
