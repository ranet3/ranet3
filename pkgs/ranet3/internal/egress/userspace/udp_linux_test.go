// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package userspace

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"slices"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/netnstest"
	"ranet3.com/pkgs/ranet3/internal/netstack"
)

// pathMTU is loopback's MTU while a test holds a path narrower than the
// leaf's session
const pathMTU = 1300

// rigFamily is one family's addresses of the rig: the leaf's, and three
// servers' on loopback
type rigFamily struct {
	name    string
	leaf    netip.Addr
	servers [3]netip.Addr
}

var rigFamilies = []rigFamily{
	{"ipv4", rigLeaf4.Addr(), [3]netip.Addr{rigServer4.Addr(), rigOthers4[0].Addr(), rigOthers4[1].Addr()}},
	{"ipv6", rigLeaf6.Addr(), [3]netip.Addr{rigServer6.Addr(), rigOthers6[0].Addr(), rigOthers6[1].Addr()}},
}

// A leaf's datagrams to two servers leave the exit from one port, the leaf's
// own where free (RFC 4787 REQ-1, REQ-3). Each server's reply reaches the
// leaf's socket from that server, as does a datagram from another port of an
// address the leaf sent to, and none from an address it never sent to
// (REQ-8). Every socket the relay opened passed Prepare, the one that only
// receives with no destination.
func TestLeafDatagramsAreRelayedThroughPrepare(t *testing.T) {
	r := newLeafRig(t, func(rt Runtime) (*Exit, error) { return New(exitConfig(), rt) })
	for _, family := range rigFamilies {
		t.Run(family.name, func(t *testing.T) {
			r.mu.Lock()
			r.prepared = nil
			r.mu.Unlock()
			a, b, stranger := r.server(t, family.servers[0]), r.server(t, family.servers[1]), r.server(t, family.servers[2])
			beside := r.server(t, family.servers[0])
			port := freeUDPPort(t, family.leaf)
			leaf := r.leafSocket(t, netip.AddrPortFrom(family.leaf, port), nil)
			outside := map[*net.UDPConn]netip.AddrPort{}
			for _, server := range []*net.UDPConn{a, b} {
				payload := []byte("to " + serverAt(server).String())
				if _, err := leaf.WriteToUDPAddrPort(payload, serverAt(server)); err != nil {
					t.Fatal(err)
				}
				from := readDatagramFrom(t, server, payload)
				if from.Port() != port {
					t.Errorf("%s read the leaf's datagram from %s, want from the leaf's port %d", serverAt(server), from, port)
				}
				outside[server] = from
			}
			for _, server := range []*net.UDPConn{a, b, beside} {
				to := outside[server]
				if server == beside {
					to = outside[a]
				}
				payload := []byte("from " + serverAt(server).String())
				if _, err := server.WriteToUDPAddrPort(payload, to); err != nil {
					t.Fatal(err)
				}
				if from := readDatagramFrom(t, leaf, payload); from != serverAt(server) {
					t.Errorf("the leaf read %s's datagram from %s", serverAt(server), from)
				}
			}
			filtered := countOf(r.exit, false, reasonFiltered)
			if _, err := stranger.WriteToUDPAddrPort([]byte("unasked"), outside[a]); err != nil {
				t.Fatal(err)
			}
			r.waitFor(t, "the stranger's datagram dropped as filtered", func() bool { return countOf(r.exit, false, reasonFiltered) > filtered })
			if _, err := a.WriteToUDPAddrPort([]byte("after"), outside[a]); err != nil {
				t.Fatal(err)
			}
			if got, from := readNext(t, leaf); string(got) != "after" {
				t.Errorf("the leaf read %q from %s, want the server's datagram after the stranger's, the stranger's never", got, from)
			}
			r.mu.Lock()
			prepared := slices.Clone(r.prepared)
			r.mu.Unlock()
			if want := []netip.AddrPort{{}, serverAt(a), serverAt(a), serverAt(b), serverAt(b)}; !slices.Equal(prepared, want) {
				t.Errorf("Prepare readied sockets toward %v, want %v", prepared, want)
			}
		})
	}
}

// A leaf's datagram with DF that the path to its server cannot carry whole is
// answered too big at the path's MTU from the exit and reaches no server, and
// one the leaf lets be fragmented reaches the server whole (RFC 4787 REQ-13).
// A whole IPv6 datagram counts as one with DF, since no router fragments
// IPv6, and one the leaf fragmented itself is fragmented again.
func TestDatagramWithDFIsAnsweredTooBigPastThePath(t *testing.T) {
	r := newLeafRig(t, func(rt Runtime) (*Exit, error) { return New(exitConfig(), rt) })
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := netnstest.SetLinkMTU(lo.Index, pathMTU); err != nil {
		t.Fatalf("narrow loopback to %d: %v", pathMTU, err)
	}
	t.Cleanup(func() {
		if err := netnstest.SetLinkMTU(lo.Index, lo.MTU); err != nil {
			t.Errorf("restore loopback's MTU of %d: %v", lo.MTU, err)
		}
	})
	for _, family := range rigFamilies {
		t.Run(family.name, func(t *testing.T) {
			server := r.server(t, family.servers[0])
			whole := r.leafSocket(t, netip.AddrPortFrom(family.leaf, 0), func(fd int) error {
				if family.leaf.Is4() {
					return unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO)
				}
				return nil
			})
			payload := bytes.Repeat([]byte{0xdf}, pathMTU+50)
			answered := len(r.mesh.answered())
			if _, err := whole.WriteToUDPAddrPort(payload, serverAt(server)); err != nil {
				t.Fatal(err)
			}
			r.waitFor(t, "an answer to the datagram past the path", func() bool { return len(r.mesh.answered()) > answered })
			if answer := r.mesh.answered()[answered]; answer.kind != netstack.ExitTooBig || answer.mtu != pathMTU {
				t.Errorf("answered %v at %d, want too big at the path's %d", answer.kind, answer.mtu, pathMTU)
			}
			if _, err := whole.WriteToUDPAddrPort([]byte("fits"), serverAt(server)); err != nil {
				t.Fatal(err)
			}
			if got, from := readNext(t, server); string(got) != "fits" {
				t.Errorf("the server read %d bytes from %s, want the datagram that fits, the one past the path never", len(got), from)
			}

			size, set := pathMTU+50, func(fd int) error {
				return unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DONT)
			}
			if family.leaf.Is6() {
				size, set = leafMTU+100, nil
			}
			fragmented := r.leafSocket(t, netip.AddrPortFrom(family.leaf, 0), set)
			payload = bytes.Repeat([]byte{0xf7}, size)
			if _, err := fragmented.WriteToUDPAddrPort(payload, serverAt(server)); err != nil {
				t.Fatal(err)
			}
			if got, from := readNext(t, server); !bytes.Equal(got, payload) {
				t.Errorf("the server read %d bytes from %s, want the %d the leaf let be fragmented", len(got), from, len(payload))
			}
		})
	}
}

// Withdrawing the exit ends every mapping and gives back its flows, and once
// the exit is enabled again a datagram opens a mapping anew
func TestWithdrawalEndsEveryMapping(t *testing.T) {
	r := newLeafRig(t, func(rt Runtime) (*Exit, error) { return New(exitConfig(), rt) })
	server := r.server(t, rigServer4.Addr())
	leaf := r.leafSocket(t, netip.AddrPortFrom(rigLeaf4.Addr(), 0), nil)
	if _, err := leaf.WriteToUDPAddrPort([]byte("before"), serverAt(server)); err != nil {
		t.Fatal(err)
	}
	readDatagramFrom(t, server, []byte("before"))
	r.exit.SetEnabled(false)
	r.waitFor(t, "every mapping ended", func() bool {
		r.exit.udp.mu.RLock()
		defer r.exit.udp.mu.RUnlock()
		return len(r.exit.udp.mappings) == 0 && len(r.exit.udp.ports) == 0
	})
	r.exit.flows.mu.Lock()
	open := r.exit.flows.open
	r.exit.flows.mu.Unlock()
	if open != 0 {
		t.Errorf("%d flows held once the exit withdrew", open)
	}
	r.exit.SetEnabled(true)
	r.waitFor(t, "the exit taking again", r.exit.taking.Load)
	if _, err := leaf.WriteToUDPAddrPort([]byte("after"), serverAt(server)); err != nil {
		t.Fatal(err)
	}
	readDatagramFrom(t, server, []byte("after"))
}

// A leaf's port below 1024 that another socket holds maps to a port below
// 1024, RFC 4787 REQ-3 (a): the first of the lowPortSearch ports below 1024
// after it that the host holds free, 1023 followed by 1, and one the host
// gives once every one of them is held
func TestMappingKeepsALowPortLowWithinItsSearch(t *testing.T) {
	claim(t)
	const leafPort = 1020
	next := func(port uint16) uint16 {
		if port == 1023 {
			return 1
		}
		return port + 1
	}
	for _, c := range []struct {
		name string
		// held is how many ports from the leaf's on other sockets hold
		held int
		low  bool
	}{
		{"the last port of the search free", lowPortSearch, true},
		{"every port of the search held", lowPortSearch + 1, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			port := uint16(leafPort)
			for range c.held {
				holder, err := net.ListenUDP("udp4", &net.UDPAddr{Port: int(port)})
				if err != nil {
					t.Fatalf("hold port %d: %v", port, err)
				}
				t.Cleanup(func() { _ = holder.Close() })
				port = next(port)
			}
			p := &fakePlatform{}
			x := &Exit{rt: Runtime{Platform: p.platform()}}
			x.rt.Platform.Prepare = func(string, netip.AddrPort, syscall.RawConn) error { return nil }
			conn, err := newUDPRelay(x).listen(netip.AddrPortFrom(rigLeaf4.Addr(), leafPort), netip.Addr{})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			got := uint16(conn.LocalAddr().(*net.UDPAddr).Port)
			switch {
			case c.low && got != port:
				t.Errorf("the mapping of port %d took %d with %d ports held, want %d, the first free one", leafPort, got, c.held, port)
			case !c.low && got < 1024:
				t.Errorf("the mapping of port %d took %d with every port of its search held, want one the host gives", leafPort, got)
			}
		})
	}
}

// server is a UDP socket at address, on this namespace's loopback
func (r *leafRig) server(t *testing.T, address netip.Addr) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP(udpNetwork(address), net.UDPAddrFromAddrPort(netip.AddrPortFrom(address, 0)))
	if err != nil {
		t.Fatalf("a server at %s: %v", address, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// leafSocket is a UDP socket of the leaf's at local, opened in the leaf's
// namespace, set run on its descriptor before it binds where given
func (r *leafRig) leafSocket(t *testing.T, local netip.AddrPort, set func(fd int) error) *net.UDPConn {
	t.Helper()
	var conn *net.UDPConn
	err := r.leaf.Do(func() error {
		var config net.ListenConfig
		if set != nil {
			config.Control = func(_, _ string, raw syscall.RawConn) error {
				var setErr error
				if err := raw.Control(func(fd uintptr) { setErr = set(int(fd)) }); err != nil {
					return err
				}
				return setErr
			}
		}
		pc, err := config.ListenPacket(context.Background(), udpNetwork(local.Addr()), local.String())
		if err != nil {
			return err
		}
		conn = pc.(*net.UDPConn)
		return nil
	})
	if err != nil {
		t.Fatalf("a leaf socket at %s: %v", local, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// readNext is the next datagram conn reads within exitWait, and where it came
// from
func readNext(t *testing.T, conn *net.UDPConn) ([]byte, netip.AddrPort) {
	t.Helper()
	buf := make([]byte, 1<<16)
	_ = conn.SetReadDeadline(time.Now().Add(exitWait))
	n, from, err := conn.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatalf("%s read no datagram: %v", serverAt(conn), err)
	}
	return buf[:n], netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
}
