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
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/underlay"
)

// A port unreachable Send sends from the address a mapping sends from, quoting
// a datagram a server of the test's sent to it, reaches that server's
// connected socket, which XNU tells of it, in both families: the kernel wrote
// the header from the socket bound to the mapping's address, which getsockname
// reads back, and the quote reached it whole (REQ-5). Each send passed Prepare
// toward the server first.
func TestPortUnreachableReachesTheServersSocket(t *testing.T) {
	var prepared []netip.AddrPort
	sockets := rootSockets(t, func(_ string, to netip.AddrPort, _ syscall.RawConn) error {
		prepared = append(prepared, to)
		return nil
	})
	for _, loopback := range []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.IPv6Loopback()} {
		t.Run(loopback.String(), func(t *testing.T) {
			network := "udp4"
			if loopback.Is6() {
				network = "udp6"
			}
			// the mapping's socket, which takes the datagram so the kernel
			// answers it with no error of its own
			mapping, err := net.ListenUDP(network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(loopback, 0)))
			if err != nil {
				t.Skipf("no loopback: %v", err)
			}
			defer mapping.Close()
			outside := mapping.LocalAddr().(*net.UDPAddr).AddrPort()
			server, err := net.DialUDP(network, nil, net.UDPAddrFromAddrPort(outside))
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			at := server.LocalAddr().(*net.UDPAddr).AddrPort()
			payload := []byte("a reply the leaf refuses")
			if _, err := server.Write(payload); err != nil {
				t.Fatal(err)
			}
			prepared = prepared[:0]
			if err := sockets.Send(portUnreachable(outside, at, payload)); err != nil {
				t.Fatalf("send: %v", err)
			}
			if bound := boundTo(t, sockets.sockets[outside.Addr()]); bound != outside.Addr() {
				t.Errorf("the raw socket is bound to %s, want the mapping's %s", bound, outside.Addr())
			}
			if len(prepared) != 1 || prepared[0] != netip.AddrPortFrom(at.Addr(), 0) {
				t.Errorf("Prepare readied sockets toward %v, want one toward %s", prepared, at.Addr())
			}
			_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := server.Read(make([]byte, 64)); !errors.Is(err, syscall.ECONNREFUSED) {
				t.Errorf("the server's socket read %v, want the port unreachable's ECONNREFUSED", err)
			}
		})
	}
}

// A packet that holds no ICMP message is refused before any socket opens
func TestSendRefusesWhatIsNoICMPMessage(t *testing.T) {
	sockets := rootSockets(t, func(string, netip.AddrPort, syscall.RawConn) error { return nil })
	udp := make([]byte, 28)
	udp[0], udp[9] = 0x45, 17
	for _, packet := range [][]byte{nil, udp, make([]byte, 40)} {
		if err := sockets.Send(packet); !errors.Is(err, errNotICMP) {
			t.Errorf("sent %x: %v, want it refused", packet, err)
		}
	}
	if len(sockets.sockets) != 0 {
		t.Errorf("%d sockets opened for packets refused", len(sockets.sockets))
	}
}

// boundTo is the address getsockname reads from sock, which is not nil
func boundTo(t *testing.T, sock *socket) netip.Addr {
	t.Helper()
	if sock == nil {
		t.Fatal("no raw socket held for the error's source")
	}
	var name unix.Sockaddr
	var err error
	if cerr := sock.raw.Control(func(fd uintptr) { name, err = unix.Getsockname(int(fd)) }); cerr != nil || err != nil {
		t.Fatalf("getsockname: %v %v", cerr, err)
	}
	switch sa := name.(type) {
	case *unix.SockaddrInet4:
		return netip.AddrFrom4(sa.Addr)
	case *unix.SockaddrInet6:
		return netip.AddrFrom16(sa.Addr)
	}
	return netip.Addr{}
}

// rootSockets is New over prepare, closed with t, in a run that sets
// RANET3_DARWIN_NETTEST=1 as root, and skips t in any other, since only root
// opens a raw socket on darwin
func rootSockets(t *testing.T, prepare underlay.Prepare) *Sockets {
	t.Helper()
	if os.Getenv("RANET3_DARWIN_NETTEST") != "1" {
		t.Skip("set RANET3_DARWIN_NETTEST=1 and run as root to open raw sockets")
	}
	if os.Geteuid() != 0 {
		t.Skip("RANET3_DARWIN_NETTEST=1 but this process is not root, and a raw socket needs root")
	}
	sockets, err := New(prepare)
	if err != nil {
		t.Fatalf("no raw socket as root: %v", err)
	}
	t.Cleanup(func() { _ = sockets.Close() })
	return sockets
}

// portUnreachable is the ICMP or ICMPv6 port unreachable from to's address
// to from, quoting the UDP datagram of payload from from to to, in an IP
// packet at hop limit 64. The IPv4 checksums are set, and the ICMPv6 one is
// the kernel's to set.
func portUnreachable(to, from netip.AddrPort, payload []byte) []byte {
	udp := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:2], from.Port())
	binary.BigEndian.PutUint16(udp[2:4], to.Port())
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], payload)
	if from.Addr().Is4() {
		quote := append(ip4(from.Addr(), to.Addr(), 17, udp), udp...)
		message := append([]byte{3, 3, 0, 0, 0, 0, 0, 0}, quote...)
		binary.BigEndian.PutUint16(message[2:4], checksum(message))
		return append(ip4(to.Addr(), from.Addr(), 1, message), message...)
	}
	quote := append(ip6(from.Addr(), to.Addr(), 17, udp), udp...)
	message := append([]byte{1, 4, 0, 0, 0, 0, 0, 0}, quote...)
	return append(ip6(to.Addr(), from.Addr(), 58, message), message...)
}

// ip4 is the IPv4 header of a packet holding payload, its checksum set
func ip4(src, dst netip.Addr, protocol byte, payload []byte) []byte {
	b := make([]byte, 20)
	b[0], b[8], b[9] = 0x45, 64, protocol
	binary.BigEndian.PutUint16(b[2:4], uint16(20+len(payload)))
	copy(b[12:16], src.AsSlice())
	copy(b[16:20], dst.AsSlice())
	binary.BigEndian.PutUint16(b[10:12], checksum(b))
	return b
}

// ip6 is the IPv6 header of a packet holding payload
func ip6(src, dst netip.Addr, next byte, payload []byte) []byte {
	b := make([]byte, 40)
	b[0], b[6], b[7] = 0x60, next, 64
	binary.BigEndian.PutUint16(b[4:6], uint16(len(payload)))
	copy(b[8:24], src.AsSlice())
	copy(b[24:40], dst.AsSlice())
	return b
}

// checksum is the internet checksum of b, RFC 1071
func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
