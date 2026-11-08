// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package userspace

import (
	"errors"
	"net/netip"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// echoSocket is one echo mapping's ICMP datagram socket. Linux writes the
// identifier the socket is bound to into each request it sends, and hands
// each reply only to the socket bound to the reply's identifier.
type echoSocket struct {
	file *os.File
	raw  syscall.RawConn
	ipv6 bool
}

// errEchoClosed is a read of an echo socket that closed
var errEchoClosed = errors.New("userspace: echo socket closed")

// openEcho opens an ICMP datagram socket of ipv6's family, readied by prepare
// before it binds, bound to source, the wildcard address where source is the
// zero Addr, and to id, or to one the kernel gives where id is 0 or the
// kernel refuses it as held, as a UDP mapping keeps the leaf's port
func openEcho(ipv6 bool, source netip.Addr, id uint16, prepare func(network string, raw syscall.RawConn) error) (*echoSocket, error) {
	family, protocol, network := unix.AF_INET, unix.IPPROTO_ICMP, "ip4:icmp"
	if ipv6 {
		family, protocol, network = unix.AF_INET6, unix.IPPROTO_ICMPV6, "ip6:ipv6-icmp"
	}
	fd, err := unix.Socket(family, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, protocol)
	if err != nil {
		return nil, err
	}
	s := &echoSocket{file: os.NewFile(uintptr(fd), "echo"), ipv6: ipv6}
	if s.raw, err = s.file.SyscallConn(); err == nil {
		err = prepare(network, s.raw)
	}
	if err == nil {
		if err = s.bind(source, id); err != nil && id != 0 && portTaken(err) {
			err = s.bind(source, 0)
		}
	}
	if err != nil {
		_ = s.file.Close()
		return nil, err
	}
	return s, nil
}

func (s *echoSocket) bind(source netip.Addr, id uint16) error {
	var sa unix.Sockaddr = &unix.SockaddrInet4{Port: int(id)}
	if s.ipv6 {
		sa = &unix.SockaddrInet6{Port: int(id)}
	}
	switch sa := sa.(type) {
	case *unix.SockaddrInet4:
		if source.Is4() {
			sa.Addr = source.As4()
		}
	case *unix.SockaddrInet6:
		if source.Is6() {
			sa.Addr = source.As16()
		}
	}
	var err error
	if controlErr := s.raw.Control(func(fd uintptr) { err = unix.Bind(int(fd), sa) }); controlErr != nil {
		return controlErr
	}
	return err
}

// send sends message, an echo request, to to, the kernel writing its
// identifier and checksum
func (s *echoSocket) send(message []byte, to netip.Addr) error {
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

// receive waits for one ICMP message into b's buffer, taken only once the
// socket is readable and given back where the read finds nothing, and reports
// its length and where it came from, errEchoClosed once the socket closes,
// and errEchoTooLarge for a message the buffer could hold only cut
func (s *echoSocket) receive(b *replyBuffer) (int, netip.Addr, error) {
	var (
		n, flags int
		from     unix.Sockaddr
		err      error
	)
	if readErr := s.raw.Read(func(fd uintptr) bool {
		n, _, flags, from, err = unix.Recvmsg(int(fd), b.take(), nil, unix.MSG_DONTWAIT)
		if errors.Is(err, unix.EAGAIN) {
			b.give()
			return false
		}
		return true
	}); readErr != nil {
		return 0, netip.Addr{}, errEchoClosed
	}
	switch {
	case err != nil:
		return 0, netip.Addr{}, err
	case flags&unix.MSG_TRUNC != 0:
		return 0, netip.Addr{}, errEchoTooLarge
	}
	return n, sockaddrPort(from).Addr(), nil
}

// identifier is the identifier the socket is bound to
func (s *echoSocket) identifier() (uint16, error) {
	var sa unix.Sockaddr
	var err error
	if controlErr := s.raw.Control(func(fd uintptr) { sa, err = unix.Getsockname(int(fd)) }); controlErr != nil {
		return 0, controlErr
	}
	if err != nil {
		return 0, err
	}
	return sockaddrPort(sa).Port(), nil
}

func (s *echoSocket) close() error { return s.file.Close() }
