// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package userspace

import (
	"errors"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// setDontFragment has fd, a UDP socket of family ipv6 or IPv4, refuse a
// datagram past its path's MTU with EMSGSIZE where on is true, and fragment
// it otherwise
func setDontFragment(fd int, ipv6, on bool) error {
	value := 0
	if on {
		value = 1
	}
	if ipv6 {
		return unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_DONTFRAG, value)
	}
	return unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_DONTFRAG, value)
}

// fitDatagrams has fd, a UDP socket toward a server, send a datagram of the
// largest payload either family carries: XNU's sosend refuses a datagram past
// the socket's send buffer with EMSGSIZE, and a UDP socket's starts at
// net.inet.udp.maxdgram, 9216 bytes by default
func fitDatagrams(fd int) error {
	return unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, datagramBuffer)
}

// socketPathMTU reads nothing, so pathMTU takes the MTU of the interface the
// route picks (Platform.Route). XNU refuses a plain IPv4 datagram with DF
// against that same MTU, and against a figure that can be lower in two
// cases: an IPv4 one on an interface it translates IPv4 to IPv6 on (CLAT46),
// against the link's IPv6 MTU less the translation's overhead (ip_output),
// and an IPv6 one, against the link's MTU (IN6_LINKMTU in
// ip6_fragment_packet), which a router's advertisement can set below the
// interface's. In those two cases a datagram between the figure XNU refuses
// against and the interface's MTU is refused, written twice, counted unsent
// and answered nothing. A narrower hop past the link answers with an error
// of its own, which is relayed. XNU does keep
// a connected IPv6 socket's path MTU, which IPV6_PATHMTU hands
// (ip6_ctloutput), and the exit does not read it.
func socketPathMTU(*net.UDPConn, bool) (int, error) { return 0, errors.ErrUnsupported }

// platformICMPErrnos is none, since every errno XNU's inetctlerrmap and
// inet6ctlerrmap hand for an ICMP error is Linux's too
var platformICMPErrnos []syscall.Errno

// shareDialPort lets fd, a dial's socket, bind its mapping's address and port
// while another dial of the mapping holds it toward another server, which XNU
// allows two TCP sockets that both hold SO_REUSEPORT. The dial binds one
// address, never the wildcard one: in in_pcbbind (bsd/netinet/in_pcb.c, xnu
// f6217f8) a later bind of the wildcard address beside a socket holding
// SO_REUSEPORT skips the check that both belong to one user, so a socket
// holding it on the wildcard address would let a process of any user share
// the exit's port
func shareDialPort(fd int) error {
	return unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
}

// shareMappingPort lets fd, a socket of a mapping, its receiving socket or
// one toward a server, share the mapping's address and port with the
// mapping's other sockets, by SO_REUSEPORT, which another user cannot share on
// one address (see shareDialPort). XNU refuses a bind of an address and port
// another socket holds unconnected, so a mapping connects its sockets one at a
// time under its lock.
func shareMappingPort(fd int) error {
	return unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
}
