// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package userspace

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/egress/userspace/raw"
)

// A queued error's sock_extended_err names its type, code and offender, and
// ee_info in the host's byte order, a too big's MTU. An error the kernel
// raised itself names none.
func TestExtendedErrorReadsItsInfo(t *testing.T) {
	router4, router6 := netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("2001:db8:2::1")
	// extended is a sock_extended_err and the offender's sockaddr_in or
	// sockaddr_in6 after it, of which the family and the address are written
	extended := func(origin, kind, code byte, info uint32, offender netip.Addr) []byte {
		size, family, at := unix.SizeofSockaddrInet4, uint16(unix.AF_INET), 4
		if offender.Is6() {
			size, family, at = unix.SizeofSockaddrInet6, unix.AF_INET6, 8
		}
		data := make([]byte, sockExtendedErr+size)
		data[4], data[5], data[6] = origin, kind, code
		binary.NativeEndian.PutUint32(data[8:12], info)
		binary.NativeEndian.PutUint16(data[sockExtendedErr:], family)
		copy(data[sockExtendedErr+at:], offender.AsSlice())
		return data
	}
	for _, c := range []struct {
		name string
		data []byte
		want icmpError
		ok   bool
	}{
		{"ipv4 too big", extended(unix.SO_EE_ORIGIN_ICMP, 3, 4, 1300, router4), icmpError{router4, 3, 4, 1300}, true},
		{"ipv6 too big", extended(unix.SO_EE_ORIGIN_ICMP6, 2, 0, 1280, router6), icmpError{router6, 2, 0, 1280}, true},
		{"local", extended(unix.SO_EE_ORIGIN_LOCAL, 0, 0, 1500, router4), icmpError{}, false},
	} {
		if got, ok := extendedError(c.data); got != c.want || ok != c.ok {
			t.Errorf("%s: read %+v %t, want %+v %t", c.name, got, ok, c.want, c.ok)
		}
	}
}

// A server's error about a leaf's datagram reaches the leaf from the server
// with its type and code, quoting the leaf's datagram as it sent it, and ends
// neither the mapping nor its socket toward the server (RFC 4787 REQ-12): a
// datagram to another server goes out from the same port after it. Over
// IPv6's loopback alone, since IPv4's is network 127, which no error may come
// from. The root test below runs both families.
func TestServersErrorReachesTheLeafAndEndsNoMapping(t *testing.T) {
	server := netip.IPv6Loopback()
	live := loopbackServer(t, server)
	closed := netip.AddrPortFrom(server, freeUDPPort(t, server))
	h := newRelayHarness(t, nil)
	leaf := netip.AddrPortFrom(leaf6, freeUDPPort(t, leaf6))
	datagram := udpDatagram(leaf, closed, []byte("to a port no socket holds"))
	h.x.udp.take(datagram, false)
	laid := h.waitLaid(t, "the server's error", func(pkt []byte) bool {
		p, ok := parse(pkt)
		return ok && p.protocol == protoICMPv6
	})
	if p, _ := parse(laid); p.src != server || p.dst != leaf6 || p.kind != 1 || p.code != 4 {
		t.Errorf("relayed %s, want port unreachable from %s to %s", p, server, leaf6)
	}
	if quote := laid[40+8:]; !bytes.Equal(quote, datagram) {
		t.Errorf("quoted %x, want the leaf's datagram %x", quote, datagram)
	}
	port, ok := h.mappingOf(leaf)
	if !ok {
		t.Fatal("the error ended the leaf's mapping")
	}
	if !destinationLive(h.x, leaf, closed) {
		t.Error("the error ended the mapping's socket toward the server")
	}
	h.x.udp.take(udpDatagram(leaf, serverAt(live), []byte("after the error")), false)
	if from := readDatagramFrom(t, live, []byte("after the error")); from.Port() != port {
		t.Errorf("the datagram after the error left from port %d, want the mapping's %d", from.Port(), port)
	}
}

// A server's port unreachable about a leaf's datagram reaches the leaf's own
// socket, whose kernel matches the quote to the datagram it sent and tells it
// of the error from the server with the payload it sent, in both families,
// at the host's TTL or hop limit. The mapping and its socket toward the server
// live on.
func TestServersErrorReachesTheLeafsSocket(t *testing.T) {
	r := newLeafRig(t, func(rt Runtime) (*Exit, error) { return New(exitConfig(), rt) })
	r.exit.SetHopLimits(hostTTL, hostHopLimit)
	for _, family := range rigFamilies {
		t.Run(family.name, func(t *testing.T) {
			kind, code := byte(3), byte(3)
			if family.leaf.Is6() {
				kind, code = 1, 4
			}
			laid := make(chan uint8, 1)
			back := func(raw []byte) {
				if p, ok := parse(raw); ok && p.protocol == icmpProtocol(family.leaf) && p.kind == kind {
					select {
					case laid <- hopsOf(raw):
					default:
					}
				}
			}
			r.back.Store(&back)
			defer r.back.Store(nil)
			closed := netip.AddrPortFrom(family.servers[0], freeUDPPort(t, family.servers[0]))
			leaf := r.leafSocket(t, netip.AddrPortFrom(family.leaf, 0), func(fd int) error { return watchErrors(fd, family.leaf.Is6()) })
			payload := []byte("to a port no socket holds")
			if _, err := leaf.WriteToUDPAddrPort(payload, closed); err != nil {
				t.Fatal(err)
			}
			told, quoted := waitTold(t, r, leaf)
			if want := (icmpError{offender: closed.Addr(), kind: kind, code: code}); told != want || !bytes.Equal(quoted, payload) {
				t.Errorf("the leaf was told of %+v quoting %q, want %+v quoting %q", told, quoted, want, payload)
			}
			select {
			case got := <-laid:
				if got != hostHops(family.leaf) {
					t.Errorf("laid the error at %d, want the host's %d", got, hostHops(family.leaf))
				}
			default:
				t.Error("laid no error toward the leaf")
			}
			if !destinationLive(r.exit, serverAt(leaf), closed) {
				t.Error("the error ended the leaf's mapping or its socket toward the server")
			}
		})
	}
}

// waitTold is the first ICMP error conn's error queue holds within exitWait,
// and the payload it quoted
func waitTold(t *testing.T, r *leafRig, conn *net.UDPConn) (icmpError, []byte) {
	t.Helper()
	var told []icmpError
	var quoted [][]byte
	r.waitFor(t, "an error queued on "+serverAt(conn).String(), func() bool {
		_ = onSocket(conn, func(fd int) error {
			drainErrors(fd, make([]byte, 2048), func(e icmpError, prefix []byte) {
				told, quoted = append(told, e), append(quoted, bytes.Clone(prefix))
			})
			return nil
		})
		return len(told) != 0
	})
	return told[0], quoted[0]
}

// A leaf's port unreachable about a datagram its mapping delivered reaches
// the datagram's server through the raw socket, from the address the mapping
// sends to the server from, quoting the server's datagram, so the server's
// own socket is told of it with that offender and the payload it sent (RFC
// 5508 REQ-5). The mapping lives on.
func TestLeafErrorReachesTheServerThroughRaw(t *testing.T) {
	r := newLeafRig(t, func(rt Runtime) (*Exit, error) {
		sockets, err := raw.New()
		if err != nil {
			return nil, err
		}
		rt.Platform.Raw = sockets
		return New(exitConfig(), rt)
	})
	for _, family := range rigFamilies {
		t.Run(family.name, func(t *testing.T) {
			kind, code := byte(3), byte(3)
			if family.leaf.Is6() {
				kind, code = 1, 4
			}
			server := r.server(t, family.servers[0])
			if err := onSocket(server, func(fd int) error { return watchErrors(fd, family.leaf.Is6()) }); err != nil {
				t.Fatal(err)
			}
			leaf := r.leafSocket(t, netip.AddrPortFrom(family.leaf, 0), nil)
			local := serverAt(leaf)
			if _, err := leaf.WriteToUDPAddrPort([]byte("request"), serverAt(server)); err != nil {
				t.Fatal(err)
			}
			outside := readDatagramFrom(t, server, []byte("request"))
			_ = leaf.Close()
			reply := []byte("to a port the leaf closed")
			if _, err := server.WriteToUDPAddrPort(reply, outside); err != nil {
				t.Fatal(err)
			}
			told, quoted := waitTold(t, r, server)
			if want := (icmpError{offender: outside.Addr(), kind: kind, code: code}); told != want || !bytes.Equal(quoted, reply) {
				t.Errorf("the server was told of %+v quoting %q, want %+v quoting %q", told, quoted, want, reply)
			}
			if !destinationLive(r.exit, local, serverAt(server)) {
				t.Errorf("the leaf's error ended the mapping of %s or its socket toward the server", local)
			}
		})
	}
}
