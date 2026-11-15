// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package userspace

import (
	"bytes"
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

// A router's time exceeded about a leaf's datagram of 200 octets, quoting 128
// octets of it with a length attribute that says so and an RFC 4884 extension
// after them, reaches the leaf with the 128 octets alone on a kernel with the
// option that says where the extension starts, and on one without it, before
// Linux 5.9, with the extension's octets after them as the datagram's payload
// within its UDP length. The destination's socket stands for such a kernel's
// with the option off, as that kernel leaves it. Root alone sends the error.
func TestExtensionIsPayloadWhereTheKernelLacksTheOption(t *testing.T) {
	extension := []byte{2 << 4, 0, 0, 0, 0, 12, 2, 1, 'R', 'O', 'U', 'T', 'E', 'R', '!', '!'}
	for _, c := range []struct {
		name   string
		option bool
		server netip.Prefix
		leaf   netip.Addr
	}{
		{"ipv4 with the option", true, rigServer4, leaf4},
		{"ipv4 without it", false, rigServer4, leaf4},
		{"ipv6 with the option", true, rigServer6, leaf6},
		{"ipv6 without it", false, rigServer6, leaf6},
	} {
		t.Run(c.name, func(t *testing.T) {
			onLoopback(t, c.server)
			h := newRelayHarness(t, nil)
			h.x.rt.Platform.Prepare = func(string, netip.AddrPort, syscall.RawConn) error { return nil }
			server := rigLoopbackServer(t, c.server.Addr())
			to := serverAt(server)
			leaf := netip.AddrPortFrom(c.leaf, freeUDPPort(t, c.leaf))
			payload := bytes.Repeat([]byte{'L'}, 200)
			h.x.udp.take(udpDatagram(leaf, to, payload), false)
			outside := readDatagramFrom(t, server, payload)
			if !c.option {
				level, _, extension := errorOptions(c.server.Addr().Is6())
				if err := onSocket(h.mappingsOf(leaf)[0].destinations[to].conn, func(fd int) error { return unix.SetsockoptInt(fd, level, extension, 0) }); err != nil {
					t.Fatalf("turn the extension option off as a kernel that lacks it leaves it: %v", err)
				}
			}
			original := udpDatagram(outside, to, payload)[:128]
			message := append([]byte{11, 0, 0, 0, 0, 128 / 4, 0, 0}, original...)
			outer, headers := 20, 28
			if c.server.Addr().Is6() {
				message = append([]byte{3, 0, 0, 0, 128 / 8, 0, 0, 0}, original...)
				outer, headers = 40, 48
			}
			h.drainLaid()
			sendICMP(t, outside.Addr(), append(message, extension...))
			want := payload[:128-headers]
			if !c.option {
				want = append(bytes.Clone(want), extension...)
			}
			var quoted []byte
			h.waitLaid(t, "time exceeded", func(raw []byte) bool {
				p, ok := parse(raw)
				if !ok || p.protocol != protoICMP && p.protocol != protoICMPv6 || len(raw) < outer+8+headers {
					return false
				}
				quoted = raw[outer+8+headers:]
				return true
			})
			if !bytes.Equal(quoted, want) {
				t.Errorf("the leaf was told of %d octets of payload %q, want %d %q", len(quoted), quoted, len(want), want)
			}
		})
	}
}

// An offset where the kernel found an RFC 4884 extension and flagged it
// invalid is not taken for an extension's start, and one it did not flag is.
// Linux flags it only where the octets there read a version 2 extension whose
// checksum or objects fail (ip_icmp_error_rfc4884_validate). Octets of any
// other version read valid, so a nonzero length attribute of at least 128
// octets over the leaf's own octets still cuts the quote there.
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
