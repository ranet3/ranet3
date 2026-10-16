// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package transport

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// routeMTU reads the path MTU of the route linux takes for a send to ep from a socket marked mark
// a socket with that mark, and with the source and interface of ep's pin while sends carry it, connects to ep
// connecting looks the route up as the send did and sends nothing
// IP_MTU and IPV6_MTU then read the route's MTU, a path MTU linux learned for it included
func routeMTU(ep *udpEndpoint, mark uint32) (int, error) {
	network, level, option := "udp4", unix.IPPROTO_IP, unix.IP_MTU
	if ep.addr.IP.To4() == nil {
		network, level, option = "udp6", unix.IPPROTO_IPV6, unix.IPV6_MTU
	}
	pinned := ep.pin() != nil
	dialer := net.Dialer{Control: func(_, _ string, raw syscall.RawConn) error {
		var err error
		if controlErr := raw.Control(func(fd uintptr) {
			if mark != 0 {
				err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark))
			}
			if err == nil && pinned && ep.index != 0 {
				err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BINDTOIFINDEX, ep.index)
			}
		}); controlErr != nil {
			return controlErr
		}
		return err
	}}
	if pinned {
		dialer.LocalAddr = &net.UDPAddr{IP: ep.source}
	}
	conn, err := dialer.Dial(network, ep.addr.String())
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	raw, err := conn.(*net.UDPConn).SyscallConn()
	if err != nil {
		return 0, err
	}
	var mtu int
	var readErr error
	if err := raw.Control(func(fd uintptr) { mtu, readErr = unix.GetsockoptInt(int(fd), level, option) }); err != nil {
		return 0, err
	}
	return mtu, readErr
}

var _ pathBind = (*udpBind)(nil)

func (b *udpBind) readPathMTU(ep Endpoint) (int, error) { return b.pathMTU(ep.(*udpEndpoint)) }

// fragment takes the socket of ep's family off DO as the first mux asks
// it puts the socket back on DO as the last mux stops
// off DO the socket fragments a datagram past the path MTU
// it still refuses a segment past the path MTU
// ep's own sends go one datagram to a message while its mux fragments
// the family's sockets connected to one peer move with it, and one that cannot is closed, which hands its sends to the shared socket
func (b *udpBind) fragment(ep Endpoint, on bool) error {
	endpoint := ep.(*udpEndpoint)
	socket := b.socket(endpoint)
	if socket == nil {
		return unix.EAFNOSUPPORT
	}
	b.fragmentMu.Lock()
	defer b.fragmentMu.Unlock()
	was := socket.fragmenting.Load()
	count := was - 1
	if on {
		count = was + 1
	}
	if (count > 0) != (was > 0) {
		if err := b.discover(socket, count > 0); err != nil {
			return err
		}
		for pair := range b.pairs {
			if pair.socket.ipv6 == socket.ipv6 && b.discover(pair.socket, count > 0) != nil {
				delete(b.pairs, pair)
				_ = pair.socket.conn.Close()
			}
		}
	}
	socket.fragmenting.Store(count)
	endpoint.fragmenting.Store(on)
	return nil
}

func (b *udpBind) dontFragment(ep Endpoint) bool {
	socket := b.socket(ep.(*udpEndpoint))
	return socket != nil && socket.fragmenting.Load() == 0
}

// discovery is the option and mode that refuse a datagram of the family past its path MTU
// or the mode that fragments it while the family fragments
// IPv4 then sends without DF
// a router ahead of a narrower hop can then fragment what the route lets through
// that hop answers nothing
// IPv6 sends what the route lets through whole in either mode, since no router fragments IPv6
func discovery(ipv6, fragment bool) (level, option, mode int) {
	switch {
	case ipv6 && fragment:
		return unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_WANT
	case ipv6:
		return unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_DO
	case fragment:
		return unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DONT
	}
	return unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO
}

func setDiscovery(socket *udpSocket, fragment bool) error {
	level, option, mode := discovery(socket.ipv6, fragment)
	var setErr error
	if err := socket.raw.Control(func(fd uintptr) { setErr = unix.SetsockoptInt(int(fd), level, option, mode) }); err != nil {
		return err
	}
	return setErr
}
