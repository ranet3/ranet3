// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package userspace

import (
	"encoding/binary"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// An ICMPv6 error of a type RFC 4443 does not name, about a datagram that
// left, reaches the leaf with its type, its code and the four octets past its
// checksum, since an error of unknown type is passed to the process that sent
// the datagram (RFC 4443 section 2.4 (a)), as Linux queues it on the
// destination's socket
func TestICMPv6ErrorOfUnknownTypeReachesTheLeaf(t *testing.T) {
	onLoopback(t, rigServer6)
	h := newRelayHarness(t, nil)
	h.x.rt.Platform.Prepare = func(string, netip.AddrPort, syscall.RawConn) error { return nil }
	server := rigLoopbackServer(t, rigServer6.Addr())
	leaf := netip.AddrPortFrom(leaf6, freeUDPPort(t, leaf6))
	payload := []byte("before the error")
	h.x.udp.take(udpDatagram(leaf, serverAt(server), payload), false)
	outside := readDatagramFrom(t, server, payload)
	sendICMP(t, outside.Addr(), append([]byte{100, 7, 0, 0, 0xde, 0xad, 0xbe, 0xef}, udpDatagram(outside, serverAt(server), payload)...))
	h.waitLaid(t, "relayed error of type 100", func(raw []byte) bool {
		p, ok := parse(raw)
		return ok && p.protocol == protoICMPv6 && p.kind == 100 && p.code == 7 && len(raw) >= 48 && binary.BigEndian.Uint32(raw[44:48]) == 0xdeadbeef
	})
}

// unknownOption is an option no kernel knows, which stands for the RFC 4884
// one a kernel before Linux 5.9 lacks
const unknownOption = 9999

// On a kernel before Linux 5.9, which refuses the option that says where an
// RFC 4884 extension starts in a queued error, watch, whose answer opens a
// destination's socket and a dial's error queue through watchErrors, turns
// the socket's errors on and fails nothing, and a UDP socket so set carries a
// datagram to its server. An option no kernel knows stands for the one such a
// kernel lacks.
func TestDestinationOpensWhereTheKernelLacksTheExtensionOption(t *testing.T) {
	for _, loopback := range []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.IPv6Loopback()} {
		t.Run(loopback.String(), func(t *testing.T) {
			level, option, _ := errorOptions(loopback.Is6())
			server := loopbackServer(t, loopback)
			for _, network := range []string{"tcp", "udp"} {
				var conn syscall.Conn
				if network == "tcp" {
					listener, err := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(netip.AddrPortFrom(loopback, 0)))
					if err != nil {
						t.Fatal(err)
					}
					defer listener.Close()
					dialed, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
					if err != nil {
						t.Fatal(err)
					}
					defer dialed.Close()
					conn = dialed
				} else {
					dialed, err := net.DialUDP(udpNetwork(loopback), nil, net.UDPAddrFromAddrPort(serverAt(server)))
					if err != nil {
						t.Fatal(err)
					}
					defer dialed.Close()
					conn = dialed
				}
				raw, err := conn.SyscallConn()
				if err != nil {
					t.Fatal(err)
				}
				var watched, refused error
				on := 0
				if err := raw.Control(func(fd uintptr) {
					refused = unix.SetsockoptInt(int(fd), level, unknownOption, 1)
					watched = watch(int(fd), level, option, unknownOption)
					on, _ = unix.GetsockoptInt(int(fd), level, option)
				}); err != nil {
					t.Fatal(err)
				}
				if refused != unix.ENOPROTOOPT || watched != nil || on != 1 {
					t.Errorf("%s: the kernel took option %d as %v, want ENOPROTOOPT, and past it watch gave %v with errors on %d, want nil and 1", network, unknownOption, refused, watched, on)
				}
				if udp, ok := conn.(*net.UDPConn); ok {
					payload := []byte("past the refused option")
					if _, err := udp.Write(payload); err != nil {
						t.Errorf("the socket past the refused option sent nothing: %v", err)
					}
					readDatagramFrom(t, server, payload)
				}
			}
		})
	}
}

// An RFC 4884 extension the kernel found at an offset and flagged invalid,
// as a router's nonzero octet where RFC 792 leaves one unused reads, is not
// taken for an extension's start, and one it did not flag is
func TestExtensionTheKernelFlagsInvalidIsNotCut(t *testing.T) {
	for _, c := range []struct {
		flags byte
		want  int
	}{{0, 128}, {unix.SO_EE_RFC4884_FLAG_INVALID, 0}} {
		data := make([]byte, sockExtendedErr+unix.SizeofSockaddrInet4)
		data[4], data[5], data[6] = unix.SO_EE_ORIGIN_ICMP, 3, 3
		binary.NativeEndian.PutUint16(data[12:14], 128)
		data[14] = c.flags
		data[sockExtendedErr] = unix.AF_INET
		copy(data[sockExtendedErr+4:], []byte{198, 51, 100, 1})
		oob := make([]byte, unix.CmsgSpace(len(data)))
		header := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
		header.Level, header.Type = unix.IPPROTO_IP, unix.IP_RECVERR
		header.SetLen(unix.CmsgLen(len(data)))
		copy(oob[unix.CmsgLen(0):], data)
		if _, extension, ok := queuedError(oob); !ok || extension != c.want {
			t.Errorf("an extension at 128 with flags %#x read as %d, %t, want %d", c.flags, extension, ok, c.want)
		}
	}
}
