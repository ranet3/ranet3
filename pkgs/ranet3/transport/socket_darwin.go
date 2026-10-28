// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

//go:build darwin

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
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/packet"
)

// This backend exists for what the portable one cannot offer. The first is
// naming each datagram's interface, in IP_PKTINFO or IPV6_PKTINFO
// on the shared socket and in IP_BOUND_IF or IPV6_BOUND_IF on a socket
// connected to one peer. Nothing else on darwin keeps an underlay out of the
// mesh's own routing: there are no marks, no policy rules and one table shared
// by every program, so a route out of the mesh tun would otherwise carry this
// node's own ESP into the tunnel that ESP is carrying. The interface is the
// one Runtime.Selection answers, and rt_lookup_common in bsd/net/route.c
// refuses a send scoped to it rather than taking another interface's route,
// unless the socket caches a route to that address, as in_pcbladdr in
// bsd/netinet/in_pcb.c keeps whatever a send names. The second is the address
// and interface each datagram reached, and the third its outer ECN field.
//
// The portable bind is wireguard's StdNetBind, which keeps its descriptors to
// itself, so there is no seam to set a socket option through. The socket work
// here is otherwise the plainest form of what that one does: one datagram per
// read, one write per packet. darwin has neither recvmmsg nor UDP
// segmentation, so the batching the linux backend is built around has nothing
// to stand on here.

// darwinEndpoint is one peer address this socket sends to, and for an IKE datagram's sender the address the datagram reached
// RFC 7296 section 2.11: "It MUST specify the address and port at which the request was received as the source address and port in the response."
type darwinEndpoint struct {
	addr netip.AddrPort
	// source and index are the address and interface control names, invalid and zero where the kernel chooses
	source netip.Addr
	index  int
	// control names source, and fragmentingControl names it beside fragmentControl, both immutable and nil without a source
	control, fragmentingControl []byte
	pinFallback
	// fragments lets darwin fragment this IPv6 endpoint's datagrams, each carrying an IPV6_DONTFRAG of 0
	fragments atomic.Bool
	// selected is the interface the bind's Selection named for addr, nil until a send asks
	selected atomic.Pointer[selected]
}

// selected is the interface a Selection named for one endpoint under one generation, zero for no route,
// and the control messages naming it, the second beside fragmentControl, all immutable
type selected struct {
	generation         uint64
	index              int
	control            []byte
	fragmentingControl []byte
}

// pinnedEndpoint is addr answered from source by interface index, which zero leaves to the socket and the route
func pinnedEndpoint(addr netip.AddrPort, source netip.Addr, index int) *darwinEndpoint {
	ep := &darwinEndpoint{addr: addr, source: source, index: index}
	if source.Is4() {
		ep.control = (&ipv4.ControlMessage{Src: source.AsSlice(), IfIndex: index}).Marshal()
		return ep
	}
	ep.control = (&ipv6.ControlMessage{Src: source.AsSlice(), IfIndex: index}).Marshal()
	ep.fragmentingControl = append(slices.Clip(ep.control), fragmentControl...)
	return ep
}

// pin is the control message naming e's source, nil where sends leave the source to the kernel
func (e *darwinEndpoint) pin() []byte {
	if e.unpinned.Load() {
		return nil
	}
	return e.control
}

// pinnedControl is the control message a send from e's pin carries, beside an IPV6_DONTFRAG of 0 while e fragments
func (e *darwinEndpoint) pinnedControl() []byte {
	if e.fragments.Load() {
		return e.fragmentingControl
	}
	return e.control
}

// unpinnedControl is the control message a send to e that names neither a source nor an interface carries
func (e *darwinEndpoint) unpinnedControl() []byte {
	if e.fragments.Load() {
		return fragmentControl
	}
	return nil
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

// sameDestination compares the pin each endpoint arrived with, which a fallback drops except for unroutedHold after the kernel refused the pin with EHOSTUNREACH
func (e *darwinEndpoint) sameDestination(other Endpoint) bool {
	o, ok := other.(*darwinEndpoint)
	return ok && e.addr == o.addr && bytes.Equal(e.arrival(e.control), o.arrival(o.control))
}

func (e *darwinEndpoint) zone() string { return e.addr.Addr().Zone() }

func (e *darwinEndpoint) withoutSource() Endpoint { return &darwinEndpoint{addr: e.addr} }

// darwinSocket is one bound UDP socket of one family. raw is retained for the
// whole life of the socket so its options can be set without reopening it.
type darwinSocket struct {
	conn *net.UDPConn
	raw  syscall.RawConn
	ipv6 bool
	// released is the latest Selection generation this shared socket's cached route was released at
	released atomic.Uint64
	// fragmenting counts the muxes letting this IPv4 socket's sends fragment
	// it is stored under its bind's fragmentMu and loaded without the lock
	// the socket clears IP_DONTFRAG while it is above zero
	fragmenting atomic.Int32
}

// newDarwinSocket readies conn for reads that carry the destination address and interface a reply endpoint is built from
// and the outer TOS or traffic class, whose ECN field a tunnel egress must read (RFC 7296 section 2.24)
func newDarwinSocket(conn *net.UDPConn, ipv6Socket bool) (*darwinSocket, error) {
	socket := &darwinSocket{conn: conn, ipv6: ipv6Socket}
	var err error
	level, option := unix.IPPROTO_IP, unix.IP_RECVTOS
	if ipv6Socket {
		err = ipv6.NewPacketConn(conn).SetControlMessage(ipv6.FlagDst|ipv6.FlagInterface, true)
		level, option = unix.IPPROTO_IPV6, unix.IPV6_RECVTCLASS
	} else {
		err = ipv4.NewPacketConn(conn).SetControlMessage(ipv4.FlagDst|ipv4.FlagInterface, true)
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

// boundInterfaceOption is the level and option name that binds a socket of this family to one interface
func boundInterfaceOption(ipv6 bool) (level, option int) {
	if ipv6 {
		return unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF
	}
	return unix.IPPROTO_IP, unix.IP_BOUND_IF
}

// releaseRoute drops the route the socket caches once generation is past the last one it was dropped at
// in_pcbladdr in bsd/netinet/in_pcb.c reuses a socket's cached route for its destination whatever interface a send names,
// so a send naming the interface a selection left would take a later send naming its new one there
// the generation is stored before the drop, so a send of an older one that writes meanwhile finds it and drops what it cached
func (s *darwinSocket) releaseRoute(generation uint64) error {
	if s.released.Load() >= generation {
		return nil
	}
	s.released.Store(generation)
	return s.dropRoute()
}

// dropRoute releases the route the socket caches
// IP_BOUND_IF and IPV6_BOUND_IF of 0 leave the socket scoped to nothing and release the route, inp_bindif_common in bsd/netinet/in_pcb.c
func (s *darwinSocket) dropRoute() error {
	level, option := boundInterfaceOption(s.ipv6)
	var setErr error
	if err := s.raw.Control(func(fd uintptr) { setErr = unix.SetsockoptInt(int(fd), level, option, 0) }); err != nil {
		return err
	}
	return setErr
}

// darwinBind holds the one socket per family every session shares.
type darwinBind struct {
	v4, v6 *darwinSocket
	// selection names each unpinned datagram's interface, and nil names none
	selection Selection
	events    func(kind string, attrs ...slog.Attr)
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

// selectedFor is the interface b's Selection names for ep, built once a generation and kept in ep
// the first answer for ep and each that names another interface are recorded once, by whichever send kept it
func (b *darwinBind) selectedFor(ep *darwinEndpoint) *selected {
	last := ep.selected.Load()
	if last != nil && last.generation == b.selection.Generation() {
		return last
	}
	index, generation := b.selection.Interface(ep.addr.Addr())
	s := &selected{generation: generation, index: index}
	if index != 0 && ep.addr.Addr().Is4() {
		s.control = (&ipv4.ControlMessage{IfIndex: index}).Marshal()
	} else if index != 0 {
		s.control = (&ipv6.ControlMessage{IfIndex: index}).Marshal()
		s.fragmentingControl = append(slices.Clip(s.control), fragmentControl...)
	}
	if ep.selected.CompareAndSwap(last, s) && (last == nil || last.index != index) {
		b.selectedNow(ep, index)
	}
	return s
}

// selectedNow records index as the interface ep's datagrams name, an empty name and zero where no route holds ep
func (b *darwinBind) selectedNow(ep *darwinEndpoint, index int) {
	if b.events == nil {
		return
	}
	name := ""
	if index != 0 {
		if link, err := net.InterfaceByIndex(index); err == nil {
			name = link.Name
		}
	}
	b.events("transport.underlay.selected", slog.String("endpoint", ep.String()), slog.String("interface", name), slog.Int("interface_index", index))
}

// boundSource resolves one route the way a socket bound to index would, and answers the source it picks
// a link-local target's zone names the interface its route takes, and a link-local source comes back zoned by it
func boundSource(index int, target netip.AddrPort) (netip.Addr, error) {
	network := "udp4"
	if target.Addr().Is6() {
		network = "udp6"
	}
	level, option := boundInterfaceOption(target.Addr().Is6())
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

// pairOf takes the local address and a link-local source's interface from the pin, and otherwise leaves the address to the route
// and takes the interface the selection names, so a changed selection is a changed pair
func (b *darwinBind) pairOf(endpoint Endpoint) pairKey {
	ep := endpoint.(*darwinEndpoint)
	k := pairKey{remote: ep.addr}
	if ep.pin() != nil {
		k.local, k.index = ep.source, ep.index
	} else if b.selection != nil {
		k.index = b.selectedFor(ep).index
	}
	return k
}

// connectPair binds the pin, or else the source of the route scoped to k's interface, on the hub's port beside the wildcard listener
// and connects to the peer, scoped to k's interface
// XNU looks a datagram up by its exact 4-tuple before any wildcard socket
// a pair the selection names no interface for opens nothing, as its shared socket sends nothing
func (b *darwinBind) connectPair(k pairKey) (pairSocket, receiveFunc, error) {
	if b.selection != nil && k.index == 0 && !k.local.IsValid() {
		return nil, nil, unix.ENETUNREACH
	}
	b.connecting.Lock()
	defer b.connecting.Unlock()
	v6 := k.remote.Addr().Is6()
	network := "udp4"
	if v6 {
		network = "udp6"
	}
	local := k.local
	if k.index != 0 {
		local = local.WithZone(strconv.Itoa(k.index))
	}
	if !local.IsValid() {
		var err error
		if local, err = boundSource(k.index, k.remote); err != nil {
			return nil, nil, err
		}
	}
	dialer := net.Dialer{LocalAddr: net.UDPAddrFromAddrPort(netip.AddrPortFrom(local, b.port)), Control: socketControl(v6, k.index, pairBuffer, true)}
	conn, err := dialer.Dial(network, k.remote.String())
	if err != nil {
		return nil, nil, err
	}
	socket, err := newDarwinSocket(conn.(*net.UDPConn), v6)
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	pair := &darwinPair{socket: socket, bind: b, address: local}
	if err := b.join(pair); err != nil {
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

// darwinPair is a socket connected to one peer, bound to the pin of the endpoints it carries, so its sends name no source
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
// it resends from the kernel's choice of source when the kernel refuses the pin, gone or with no route to the peer, and keeps that choice once it worked
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
		err := b.sendFrom(socket, packet, ep)
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

// sendFrom sends one datagram to ep from its pin, and by the interface the selection names, from the kernel's choice of source,
// where ep has no pin or once darwin refused it
func (b *darwinBind) sendFrom(socket *darwinSocket, packet []byte, ep *darwinEndpoint) error {
	if ep.pin() == nil {
		control, generation, err := b.selectedControl(socket, ep)
		if err != nil {
			return err
		}
		return socket.writeSelected(packet, ep, control, generation)
	}
	refused := socket.write(packet, ep, ep.pinnedControl())
	if refused == nil || !unpinnable(refused) {
		return refused
	}
	control, generation, err := b.selectedControl(socket, ep)
	if err != nil {
		return err
	}
	err = socket.writeSelected(packet, ep, control, generation)
	// darwin refuses a datagram as too large only once it has routed it from the source it chose
	if (err == nil || errors.Is(err, unix.EMSGSIZE)) && ep.unpin(refused) {
		unpinned(b.events, ep, refused)
	}
	return err
}

// selectedControl is the control message a send to ep that leaves the source to the kernel carries on socket, and the generation it names an interface under:
// the interface the selection names, beside an IPV6_DONTFRAG of 0 while ep fragments, after the socket released a route it cached under an older generation
// it refuses a send the selection names no interface for, as a marked lookup that ends in an empty main does on linux
// with no selection it names no interface, under generation 0
func (b *darwinBind) selectedControl(socket *darwinSocket, ep *darwinEndpoint) ([]byte, uint64, error) {
	if b.selection == nil {
		return ep.unpinnedControl(), 0, nil
	}
	s := b.selectedFor(ep)
	if s.index == 0 {
		return nil, 0, unix.ENETUNREACH
	}
	if err := socket.releaseRoute(s.generation); err != nil {
		return nil, 0, err
	}
	if ep.fragments.Load() {
		return s.fragmentingControl, s.generation, nil
	}
	return s.control, s.generation, nil
}

// writeSelected sends one datagram to ep carrying control, which selectedControl built under generation
// a send whose generation is older than the socket's last release, which ran between the two, cached the route of the interface the old generation named,
// and a later send naming the new one would take that route, so the socket releases it again
func (s *darwinSocket) writeSelected(packet []byte, ep *darwinEndpoint, control []byte, generation uint64) error {
	err := s.write(packet, ep, control)
	if generation < s.released.Load() {
		return errors.Join(err, s.dropRoute())
	}
	return err
}

// write sends one datagram to ep carrying control
func (s *darwinSocket) write(packet []byte, ep *darwinEndpoint, control []byte) error {
	if control != nil {
		_, _, err := s.conn.WriteMsgUDPAddrPort(packet, control, ep.addr)
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
		if err := b.sendFrom(socket, packet, ep); err != nil {
			return fmt.Errorf("%w, then %w", report, err)
		}
	}
	return report
}

var _ pathBind = (*darwinBind)(nil)

// readPathMTU reads the MTU of the interface sends to ep name, the one holding their pin, or on a hub with no selection the one the host routes them by
// darwin refuses a datagram with DF only past that MTU, and the probes find a narrower path beyond the interface
func (b *darwinBind) readPathMTU(endpoint Endpoint) (int, error) {
	index, err := b.sendInterface(endpoint.(*darwinEndpoint))
	if err != nil {
		return 0, err
	}
	link, err := net.InterfaceByIndex(index)
	if err != nil {
		return 0, err
	}
	return link.MTU, nil
}

// sendInterface is the interface sends to ep name, the one holding their pin, or on a hub with no selection the one the host routes them by
// a send that names no source, since ep fell back or never had one, names the selection's interface, as does one from a source no interface holds, which falls back
func (b *darwinBind) sendInterface(ep *darwinEndpoint) (int, error) {
	if index := ep.pinInterface(); index != 0 {
		return index, nil
	}
	if b.selection == nil {
		return routedInterface(ep.addr)
	}
	if index := b.selectedFor(ep).index; index != 0 {
		return index, nil
	}
	return 0, unix.ENETUNREACH
}

// pinInterface is the interface ep's pin sends by, a link-local pin's arrival interface or the one holding its address,
// and zero where ep sends from no pin or no interface holds it
// ip_output in bsd/netinet/ip_output.c takes a send from a source by a route of the interface holding it, unless a route the socket cached decides
func (e *darwinEndpoint) pinInterface() int {
	if e.pin() == nil {
		return 0
	}
	if e.index != 0 {
		return e.index
	}
	index, _ := interfaceHolding(e.source)
	return index
}

// underlayPath is where sendInterface takes ep's datagrams, false where b names no interface
func (b *darwinBind) underlayPath(endpoint Endpoint) (UnderlayPath, bool) {
	ep, ok := endpoint.(*darwinEndpoint)
	if !ok || b.selection == nil {
		return UnderlayPath{}, false
	}
	path := UnderlayPath{Address: ep.addr.Addr()}
	if index := ep.pinInterface(); index != 0 {
		path.Pin = strconv.Itoa(index)
		if link, err := net.InterfaceByIndex(index); err == nil {
			path.Pin = link.Name
		}
	}
	return path, true
}

// routedInterface is the interface the host routes a datagram to addr by, the one holding the source a socket connected to addr takes,
// read on a hub with no selection, whose sends name no interface
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
	return interfaceHolding(local.AddrPort().Addr().Unmap())
}

// interfaceHolding is the interface that holds address
func interfaceHolding(address netip.Addr) (int, error) {
	links, err := net.Interfaces()
	if err != nil {
		return 0, err
	}
	for _, link := range links {
		addresses, err := link.Addrs()
		if err != nil {
			continue
		}
		for _, held := range addresses {
			if prefix, ok := held.(*net.IPNet); ok && prefix.IP.Equal(address.AsSlice()) {
				return link.Index, nil
			}
		}
	}
	return 0, fmt.Errorf("transport: no interface holds %s", address)
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
// backend holds. The hub copies anything it keeps. Only an IKE datagram gets
// an endpoint, which the hub reads for nothing else.
func (s *darwinSocket) receiver() receiveFunc {
	buf := make([]byte, readBufferSize)
	oob := make([]byte, controlMessageSize)
	return func(bufs [][]byte, sizes []int, endpoints []Endpoint, records []receiveRecord) (int, int, error) {
		n, oobn, flags, from, err := s.conn.ReadMsgUDPAddrPort(buf, oob)
		if err != nil {
			return 0, 0, err
		}
		// a datagram whose control message was cut or will not parse has no known outer ECN field, and an IKE one no address to be answered from
		// so it is counted as refused and dropped, since recording Not-ECT would discard a congestion mark
		// returning an error instead would end the hub
		if flags&unix.MSG_CTRUNC != 0 {
			return 0, 1, nil
		}
		ecn, err := outerECN(oob[:oobn])
		if err != nil {
			return 0, 1, nil
		}
		bufs[0], sizes[0], endpoints[0], records[0] = buf[:n], n, nil, receiveRecord{source: from, ecn: ecn}
		if n >= nonESPMarkerLen && binary.BigEndian.Uint32(buf) == 0 {
			ep, err := s.replyEndpoint(netip.AddrPortFrom(from.Addr().Unmap(), from.Port()), oob[:oobn])
			if err != nil {
				return 0, 1, nil
			}
			endpoints[0] = ep
		}
		return 1, 0, nil
	}
}

// darwin hands the IPv4 TOS as one octet under IP_RECVTOS and the IPv6 traffic class as an int under IPV6_TCLASS
func outerECN(control []byte) (packet.ECN, error) {
	for len(control) >= unix.CmsgLen(0) {
		header, data, rest, err := unix.ParseOneSocketControlMessage(control)
		if err != nil {
			return packet.NotECT, err
		}
		switch {
		case header.Level == unix.IPPROTO_IP && header.Type == unix.IP_RECVTOS && len(data) >= 1:
			return packet.ECNOfTrafficClass(data[0]), nil
		case header.Level == unix.IPPROTO_IPV6 && header.Type == unix.IPV6_TCLASS && len(data) >= 4:
			return packet.ECNOfTrafficClass(uint8(binary.NativeEndian.Uint32(data))), nil
		}
		control = rest
	}
	return packet.NotECT, nil
}

// replyEndpoint is the endpoint of from, answered from the address the datagram reached and by the interface it arrived on where that address is link-local
// it refuses a datagram whose control message names no destination
func (s *darwinSocket) replyEndpoint(from netip.AddrPort, control []byte) (*darwinEndpoint, error) {
	var dst net.IP
	var index int
	if s.ipv6 {
		var cm ipv6.ControlMessage
		if err := cm.Parse(control); err != nil {
			return nil, err
		}
		dst, index = cm.Dst, cm.IfIndex
	} else {
		var cm ipv4.ControlMessage
		if err := cm.Parse(control); err != nil {
			return nil, err
		}
		dst, index = cm.Dst, cm.IfIndex
	}
	source, ok := netip.AddrFromSlice(dst)
	if !ok {
		return nil, errors.New("transport: a datagram arrived without its destination address")
	}
	source = source.Unmap()
	// udp_output in bsd/netinet/udp_usrreq.c takes a nonzero ipi_ifindex over both ipi_spec_dst and IP_BOUND_IF
	// so only a link-local source, which needs its zone, names its interface
	if !source.Is6() || !source.IsLinkLocalUnicast() {
		index = 0
	}
	return pinnedEndpoint(from, source, index), nil
}

// openPacketBind takes the one socket this node's IKE and ESP share, whose
// unpinned sends name the interface selection answers.
func openPacketBind(port uint16, selection Selection, events func(string, ...slog.Attr)) (packetBind, []receiveFunc, uint16, error) {
	// The port selected by the IPv4 bind may already be occupied on IPv6.
	// Retry ephemeral allocation, but an explicitly requested port still fails.
	var err error
	for range ephemeralPortRetries {
		var bind packetBind
		var receivers []receiveFunc
		var bound uint16
		bind, receivers, bound, err = listenPacketBind(port, selection, events)
		if port != 0 || !errors.Is(err, unix.EADDRINUSE) {
			return bind, receivers, bound, err
		}
	}
	return nil, nil, 0, err
}

func listenPacketBind(port uint16, selection Selection, events func(string, ...slog.Attr)) (packetBind, []receiveFunc, uint16, error) {
	b := &darwinBind{selection: selection, events: events, pairs: make(map[*darwinPair]struct{}), setDontFragment: (*darwinSocket).setDontFragment}
	var receivers []receiveFunc
	for i, network := range []string{"udp4", "udp6"} {
		ipv6 := i == 1
		// the listener never sets SO_REUSEPORT, not even once bound as on linux
		// in_pcbbind in bsd/netinet/in_pcb.c and in6_pcbbind in bsd/netinet6/in6_pcb.c (xnu f6217f8) read a held socket's options again at each later bind
		// and skip the user check for a second bind of the wildcard address where the held socket has SO_REUSEPORT, which lets a process of any user share the port
		lc := net.ListenConfig{Control: socketControl(ipv6, 0, socketBufferSize, false)}
		pc, err := lc.ListenPacket(context.Background(), network, fmt.Sprintf(":%d", port))
		if err != nil {
			if errors.Is(err, unix.EAFNOSUPPORT) || errors.Is(err, unix.EPROTONOSUPPORT) {
				continue
			}
			_ = b.Close()
			return nil, nil, 0, err
		}
		socket, err := newDarwinSocket(pc.(*net.UDPConn), ipv6)
		if err != nil {
			_ = pc.Close()
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
	b.port = port
	return b, receivers, port, nil
}

// socketControl sets the buffers, DF and, where index is nonzero, the interface binding on a socket before it binds
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
			// reported rather than ignored like the tuning above, since a socket scoped to nothing follows a route out of the tun
			level, option := boundInterfaceOption(ipv6)
			optionErr = unix.SetsockoptInt(int(fd), level, option, index)
		}); err != nil {
			return err
		}
		return optionErr
	}
}
