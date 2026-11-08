// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package raw

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/underlay"
)

// sources is how many addresses Sockets holds a socket bound to at once, the
// one past them closing another's, so addresses the host gives up do not
// keep sockets open
const sources = 16

// Sockets is a raw ICMP socket of each address the exit's errors leave from,
// bound to it, which XNU sends a whole error from as root with
// its quote untouched: the kernel writes the IP header from the socket's
// address and options, and over IPv6 the checksum too. Each send is scoped by
// Prepare toward its destination first, as every other socket of the exit's
// is.
type Sockets struct {
	prepare underlay.Prepare

	mu      sync.Mutex
	sockets map[netip.Addr]*socket
	closed  bool
}

// socket is one raw ICMP socket bound to an address
type socket struct {
	file *os.File
	raw  syscall.RawConn
}

// errNotICMP is a packet Send finds no IPv4 or IPv6 header holding an ICMP
// message at the start of
var errNotICMP = errors.New("raw: no IPv4 or IPv6 packet of an ICMP message")

// New opens a raw ICMP socket of each family once, to find whether the
// process may, which on darwin only root may, and readies every socket it
// sends from through prepare
func New(prepare underlay.Prepare) (*Sockets, error) {
	for _, family := range [][2]int{{unix.AF_INET, unix.IPPROTO_ICMP}, {unix.AF_INET6, unix.IPPROTO_ICMPV6}} {
		fd, err := unix.Socket(family[0], unix.SOCK_RAW, family[1])
		if err != nil {
			return nil, err
		}
		_ = unix.Close(fd)
	}
	return &Sockets{prepare: prepare, sockets: map[netip.Addr]*socket{}}, nil
}

// Send sends packet, a whole IPv4 or IPv6 packet holding one ICMP message,
// from its source address toward its destination, at its TTL or hop limit and
// with its traffic class
func (s *Sockets) Send(packet []byte) error {
	var (
		from, to    netip.Addr
		hops, class byte
		message     []byte
	)
	switch {
	case len(packet) >= 20 && packet[0]>>4 == 4:
		header := int(packet[0]&0x0f) * 4
		if header < 20 || len(packet) < header || packet[9] != unix.IPPROTO_ICMP {
			return errNotICMP
		}
		from, to = netip.AddrFrom4([4]byte(packet[12:16])), netip.AddrFrom4([4]byte(packet[16:20]))
		hops, class, message = packet[8], packet[1], packet[header:]
	case len(packet) >= 40 && packet[0]>>4 == 6:
		if packet[6] != unix.IPPROTO_ICMPV6 {
			return errNotICMP
		}
		from, to = netip.AddrFrom16([16]byte(packet[8:24])), netip.AddrFrom16([16]byte(packet[24:40]))
		hops, class, message = packet[7], byte(binary.BigEndian.Uint16(packet[0:2])>>4), packet[40:]
	default:
		return errNotICMP
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	sock, err := s.socket(from)
	if err != nil {
		return err
	}
	network := "ip4:icmp"
	if from.Is6() {
		network = "ip6:ipv6-icmp"
	}
	if err := s.prepare(network, netip.AddrPortFrom(to, 0), sock.raw); err != nil {
		return err
	}
	var sent error
	if err := sock.raw.Control(func(fd uintptr) { sent = sendFrom(int(fd), from.Is6(), to, hops, class, message) }); err != nil {
		return err
	}
	return sent
}

// sendFrom sends message to to from fd at hops with class
func sendFrom(fd int, ipv6 bool, to netip.Addr, hops, class byte, message []byte) error {
	if ipv6 {
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, int(hops)); err != nil {
			return err
		}
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_TCLASS, int(class)); err != nil {
			return err
		}
		return unix.Sendto(fd, message, 0, &unix.SockaddrInet6{Addr: to.As16()})
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TTL, int(hops)); err != nil {
		return err
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TOS, int(class)); err != nil {
		return err
	}
	return unix.Sendto(fd, message, 0, &unix.SockaddrInet4{Addr: to.As4()})
}

// socket is the socket bound to from, opened where none is, another closed
// where sources are open. s.mu is held.
func (s *Sockets) socket(from netip.Addr) (*socket, error) {
	if sock := s.sockets[from]; sock != nil {
		return sock, nil
	}
	if len(s.sockets) >= sources {
		for address, sock := range s.sockets {
			_ = sock.file.Close()
			delete(s.sockets, address)
			break
		}
	}
	domain, protocol := unix.AF_INET, unix.IPPROTO_ICMP
	var bound unix.Sockaddr
	if from.Is6() {
		domain, protocol, bound = unix.AF_INET6, unix.IPPROTO_ICMPV6, &unix.SockaddrInet6{Addr: from.As16()}
	} else {
		bound = &unix.SockaddrInet4{Addr: from.As4()}
	}
	fd, err := unix.Socket(domain, unix.SOCK_RAW, protocol)
	if err != nil {
		return nil, err
	}
	unix.CloseOnExec(fd)
	if err := unix.Bind(fd, bound); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	sock := &socket{file: os.NewFile(uintptr(fd), "raw")}
	if sock.raw, err = sock.file.SyscallConn(); err != nil {
		_ = sock.file.Close()
		return nil, err
	}
	s.sockets[from] = sock
	return sock, nil
}

// Close closes every socket
func (s *Sockets) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	var errs []error
	for address, sock := range s.sockets {
		errs = append(errs, sock.file.Close())
		delete(s.sockets, address)
	}
	return errors.Join(errs...)
}
