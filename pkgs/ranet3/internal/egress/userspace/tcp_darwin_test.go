// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package userspace

import (
	"context"
	"net"
	"net/netip"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/egress"
)

// Two dials from one leaf port toward two servers of the test's own hold one
// local port, both connections established at once under SO_REUSEPORT,
// each bound to the address the route to its server picks and never the
// wildcard address, in both families. The route's
// address is read through Prepare toward the server before the dial's own
// socket is.
func TestDialsShareTheLeafsPortFromTheRoutesAddress(t *testing.T) {
	for _, family := range []struct {
		name     string
		loopback netip.Addr
		leaf     netip.Addr
	}{
		{"ipv4", netip.MustParseAddr("127.0.0.1"), leaf4},
		{"ipv6", netip.IPv6Loopback(), leaf6},
	} {
		t.Run(family.name, func(t *testing.T) {
			var servers []netip.AddrPort
			for range 2 {
				listener, err := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(netip.AddrPortFrom(family.loopback, 0)))
				if err != nil {
					t.Skipf("no loopback to dial: %v", err)
				}
				defer listener.Close()
				go func() {
					for {
						conn, err := listener.Accept()
						if err != nil {
							return
						}
						defer conn.Close()
					}
				}()
				servers = append(servers, listener.Addr().(*net.TCPAddr).AddrPort())
			}
			type prepared struct {
				network string
				to      netip.AddrPort
			}
			var seen []prepared
			x := dialingExit(t, egress.Egress{}, func(network string, to netip.AddrPort, _ syscall.RawConn) error {
				seen = append(seen, prepared{network, to})
				return nil
			})
			port := freeTCPPort(t, family.loopback)
			r := &tcpRelay{x: x}
			for _, server := range servers {
				seen = seen[:0]
				conn, _, failure := r.dial(context.Background(), netip.AddrPortFrom(family.leaf, port), server)
				if conn == nil {
					t.Fatalf("dial from port %d toward %s: %v", port, server, failure.err)
				}
				defer conn.Close()
				if local := conn.LocalAddr().(*net.TCPAddr).AddrPort(); local.Port() != port || local.Addr().Unmap() != family.loopback {
					t.Errorf("dialed %s from %s, want %s", server, local, netip.AddrPortFrom(family.loopback, port))
				}
				if got := socketOption(t, conn, unix.SOL_SOCKET, unix.SO_REUSEPORT); got == 0 {
					t.Errorf("the dial toward %s holds no SO_REUSEPORT, so a second dial from its port fails", server)
				}
				if len(seen) != 2 || seen[0].network[:3] != "udp" || seen[0].to != server || seen[1].network[:3] != "tcp" || seen[1].to != server {
					t.Errorf("Prepare readied %v, want the route's socket toward %s, then the dial's", seen, server)
				}
			}
		})
	}
}

// A mapping's receiving socket is bound to one address, the one the route to
// its destination picks, never the wildcard address, beside which XNU would
// let a process of any user bind its port, and holds SO_REUSEPORT, which only
// the exit's own sockets toward each server share
func TestMappingSocketSharesItsPortOnOneAddress(t *testing.T) {
	loopback := netip.MustParseAddr("127.0.0.1")
	server := loopbackServer(t, loopback)
	h := newRelayHarness(t, nil)
	leaf := netip.AddrPortFrom(leaf4, freeUDPPort(t, leaf4))
	h.x.udp.take(udpDatagram(leaf, serverAt(server), []byte("opens a mapping")), false)
	readDatagramFrom(t, server, []byte("opens a mapping"))
	m := h.mappingsOf(leaf)[0]
	if got := m.receiving.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Unmap(); got != loopback {
		t.Errorf("the mapping's receiving socket is bound to %s, want %s", got, loopback)
	}
	if socketOption(t, m.receiving, unix.SOL_SOCKET, unix.SO_REUSEPORT) == 0 {
		t.Error("the mapping's receiving socket holds no SO_REUSEPORT, so no socket toward a server binds its port")
	}
}

// socketOption is conn's integer option at level, failing t where it reads
// none
func socketOption(t *testing.T, conn syscall.Conn, level, option int) int {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var value int
	if controlErr := raw.Control(func(fd uintptr) { value, err = unix.GetsockoptInt(int(fd), level, option) }); controlErr != nil {
		t.Fatal(controlErr)
	}
	if err != nil {
		t.Fatal(err)
	}
	return value
}
