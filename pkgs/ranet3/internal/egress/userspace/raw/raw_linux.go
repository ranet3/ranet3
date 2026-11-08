// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package raw

import (
	"errors"

	"golang.org/x/sys/unix"
)

// Sockets is a raw socket of each family, which sends a packet whole with the
// IP header its caller wrote, IPPROTO_RAW implying IP_HDRINCL and, since
// Linux 4.5, IPV6_HDRINCL
type Sockets struct {
	v4, v6 int
}

// errNotIP is a packet Send finds no IPv4 or IPv6 header at the start of
var errNotIP = errors.New("raw: no IPv4 or IPv6 header")

// New opens the raw sockets, which needs CAP_NET_RAW in the network
// namespace's user namespace
func New() (*Sockets, error) {
	v4, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_RAW)
	if err != nil {
		return nil, err
	}
	v6, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_RAW)
	if err != nil {
		_ = unix.Close(v4)
		return nil, err
	}
	return &Sockets{v4: v4, v6: v6}, nil
}

// Send sends packet, a whole IPv4 or IPv6 packet, toward its destination
func (s *Sockets) Send(packet []byte) error {
	switch {
	case len(packet) >= 20 && packet[0]>>4 == 4:
		return unix.Sendto(s.v4, packet, 0, &unix.SockaddrInet4{Addr: [4]byte(packet[16:20])})
	case len(packet) >= 40 && packet[0]>>4 == 6:
		return unix.Sendto(s.v6, packet, 0, &unix.SockaddrInet6{Addr: [16]byte(packet[24:40])})
	}
	return errNotIP
}

// Close closes both sockets
func (s *Sockets) Close() error {
	return errors.Join(unix.Close(s.v4), unix.Close(s.v6))
}
