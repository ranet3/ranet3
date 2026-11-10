// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package userspace

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"os"
	"slices"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/netnstest"
	"ranet3.com/pkgs/ranet3/internal/netstack"
)

// pathMTU is loopback's MTU while a test holds a path narrower than the
// leaf's session
const pathMTU = 1300

// twoPrefixes are the two prefixes twoAddressesHeld gives loopback, whose
// routes pick each prefix's address toward the rest of it
var twoPrefixes = [2]netip.Prefix{netip.MustParsePrefix("198.51.100.1/25"), netip.MustParsePrefix("198.51.100.129/25")}

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
// own where free, on the address each server's route picks (RFC 4787 REQ-1
// from each address, REQ-3). Each server's reply reaches the
// leaf's socket from that server, as does a datagram from another port of an
// address the leaf sent to, and none from an address it never sent to
// (REQ-8). Every socket the relay opened passed Prepare: the route probe
// toward each server, the one that only receives with no destination of each
// address the servers' routes pick, and each server's own.
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
			var want []netip.AddrPort
			routes := map[netip.Addr]bool{}
			for _, server := range []*net.UDPConn{a, b} {
				want = append(want, serverAt(server))
				if route := routeAddress(t, serverAt(server)); !routes[route] {
					routes[route] = true
					want = append(want, netip.AddrPort{})
				}
				want = append(want, serverAt(server))
			}
			if !slices.Equal(prepared, want) {
				t.Errorf("Prepare readied sockets toward %v, want %v", prepared, want)
			}
		})
	}
}

// A leaf's datagram with DF that the path to its server cannot carry whole is
// answered too big at the path's MTU from the exit and reaches no server, and
// one the leaf lets be fragmented reaches the server whole (RFC 4787 REQ-13).
// The refusal for its size is not counted as one of the host's own.
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
			if got := countOf(r.exit, false, reasonUnsent); got != 0 {
				t.Errorf("counted %d datagrams unsent, want none, the one past the path refused for its size", got)
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

// The worst mix of flows, each a UDP mapping's first destination holding the
// mapping's receiving socket and its own connected one, keeps the exit's
// descriptors within the process's limit less the node's daemonFiles: Within
// holds Flows to what those descriptors hold at flowFiles each, and the flow
// past it is refused for the total
func TestWorstMixOfFlowsKeepsTheNodesDescriptors(t *testing.T) {
	const files = daemonFiles + 2*24
	limits, err := Within(Memory{GoLimit: 32 << 20}, files)
	if err != nil {
		t.Fatal(err)
	}
	h := newRelayHarness(t, func(rt *Runtime, _ *egress.Egress) { rt.Limits = limits })
	server := loopbackServer(t, netip.MustParseAddr("127.0.0.1"))
	before := openFiles(t)
	for i := range limits.Flows + 6 {
		leaf := netip.AddrPortFrom(leaf4, uint16(40000+i))
		h.x.udp.take(udpDatagram(leaf, serverAt(server), []byte("one destination")), false)
	}
	if held := openFiles(t) - before; held > files-daemonFiles {
		t.Errorf("%d flows hold %d descriptors, past the %d the process's limit leaves past the node's %d", limits.Flows, held, files-daemonFiles, daemonFiles)
	}
	if got := h.count(true, reasonTotal); got != 6 {
		t.Errorf("refused %d flows for the total, want the 6 past Flows %d", got, limits.Flows)
	}
}

// openFiles is how many descriptors the process holds open
func openFiles(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
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
			conn, err := newUDPRelay(x).listen(netip.AddrPortFrom(rigLeaf4.Addr(), leafPort), netip.IPv4Unspecified())
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

// With the host holding two addresses of one family, two leaves whose
// mappings leave from one address each, under auto by their routes or under
// two classes, hairpin to each other from each one's own mapping's address and
// port (RFC 4787 REQ-9 (a)), the sender holding none on the address its
// datagram went to, and each passes the other's filter once both have sent to
// the address the other leaves from: the first datagram of the punch is
// filtered, and every later one each way reaches its leaf from the other
// mapping's address, as from outside. A leaf's error about one reaches the
// sender from the address the sender sent to, the target's (RFC 5508 REQ-7
// (a)), and one quoting the sender's port at the target's address, which the
// sender never leaves from, is dropped.
func TestHairpinComesFromTheSendersOwnAddress(t *testing.T) {
	for _, classes := range []bool{false, true} {
		name := map[bool]string{false: "auto", true: "two classes"}[classes]
		t.Run(name, func(t *testing.T) {
			h, addresses := twoAddressesHeld(t)
			listener := netip.AddrPortFrom(leaf4, freeUDPPort(t, leaf4))
			sender := netip.AddrPortFrom(other4, freeUDPPort(t, other4))
			if classes {
				translate := append(classed(addresses[0].Addr()).Translate, classed(addresses[1].Addr()).Translate...)
				translate[0].From.Prefix, translate[1].From.Prefix = netip.PrefixFrom(listener.Addr(), 32), netip.PrefixFrom(sender.Addr(), 32)
				h.x.cfg.Translate = translate
			}
			toListener, toSender := openFrom(t, h, listener, addresses[0]), openFrom(t, h, sender, addresses[1])
			laid := punch(t, h, sender, toSender, listener, toListener)
			h.x.handle(h.lane, leafRefusal(listener.Addr(), toSender.Addr(), 3, 3, laid))
			out := h.waitLaid(t, "the listener's error to the sender", func(raw []byte) bool {
				p, ok := parse(raw)
				return ok && p.protocol == protoICMP && p.dst == sender.Addr()
			})
			checkServerError(t, out, toListener, sender, 3, 3, []byte("goes through"))
			forger := netip.AddrPortFrom(leaf4.Next(), freeUDPPort(t, leaf4))
			openFrom(t, h, forger, addresses[0])
			before := h.count(false, reasonLeafErrorUnmapped)
			quoted := udpDatagram(netip.AddrPortFrom(toListener.Addr(), toSender.Port()), forger, []byte("never sent"))
			h.x.handle(h.lane, leafRefusal(forger.Addr(), toListener.Addr(), 3, 3, quoted))
			if got := h.count(false, reasonLeafErrorUnmapped) - before; got != 1 {
				t.Errorf("dropped %d errors as about no datagram a mapping delivered, want the one quoting the sender's port at %s, which it never leaves from", got, toListener.Addr())
			}
		})
	}
}

// punch has sender and listener, which their peers know at toSender and
// toListener, hairpin to each other through the lane: the sender's first
// datagram is filtered, the listener's answer reaches the sender from
// toListener, and the sender's next reaches the listener from toSender, which
// punch returns as laid
func punch(t *testing.T, h *relayHarness, sender, toSender, listener, toListener netip.AddrPort) []byte {
	t.Helper()
	filtered := h.count(false, reasonFiltered)
	h.x.handle(h.lane, udpDatagram(sender, toListener, []byte("punches")))
	if got := h.count(false, reasonFiltered) - filtered; got != 1 {
		t.Fatalf("filtered %d hairpinned datagrams, want the first of the punch", got)
	}
	h.x.handle(h.lane, udpDatagram(listener, toSender, []byte("answers")))
	h.waitLaid(t, "the listener's datagram, from "+toListener.String(), func(raw []byte) bool {
		return isDatagram(raw, toListener, sender, []byte("answers"))
	})
	h.x.handle(h.lane, udpDatagram(sender, toListener, []byte("goes through")))
	return h.waitLaid(t, "the sender's datagram, from "+toSender.String(), func(raw []byte) bool {
		return isDatagram(raw, toSender, listener, []byte("goes through"))
	})
}

// twoAddressesHeld is a relay harness in this namespace, which holds the two
// prefixes it returns on loopback and readies every socket. Loopback takes
// each prefix as local, so a socket toward a server inside one leaves from
// that prefix's address.
func twoAddressesHeld(t *testing.T) (*relayHarness, [2]netip.Prefix) {
	t.Helper()
	prefixes := twoPrefixes
	onLoopback(t, prefixes[:]...)
	// New starts no goroutine, so nothing reads the platform while it changes
	h := newRelayHarness(t, nil)
	holdOnly(&h.x.rt, prefixes[0].Addr(), prefixes[1].Addr())
	h.x.rt.Platform.Prepare = func(string, netip.AddrPort, syscall.RawConn) error { return nil }
	return h, prefixes
}

// onLoopback claims this namespace and gives loopback each of prefixes it does
// not hold yet
func onLoopback(t *testing.T, prefixes ...netip.Prefix) {
	t.Helper()
	claim(t)
	if err := netnstest.BringUp("lo"); err != nil {
		t.Fatal(err)
	}
	netlink, err := netnstest.OpenNetlink()
	if err != nil {
		t.Fatal(err)
	}
	defer netlink.Close()
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	for _, prefix := range prefixes {
		if err := netlink.AddAddress(lo.Index, prefix); err != nil && err != unix.EEXIST {
			t.Fatal(err)
		}
	}
}

// openFrom opens leaf's mapping toward a server inside prefix and is the
// address and port it left from, failing t where that is not prefix's address
func openFrom(t *testing.T, h *relayHarness, leaf netip.AddrPort, prefix netip.Prefix) netip.AddrPort {
	t.Helper()
	server, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(prefix.Addr().Next().Next(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	h.x.udp.take(udpDatagram(leaf, serverAt(server), []byte("opens a mapping")), false)
	outside := readDatagramFrom(t, server, []byte("opens a mapping"))
	if outside.Addr() != prefix.Addr() {
		t.Fatalf("the mapping of %s left from %s, want %s", leaf, outside, prefix.Addr())
	}
	return outside
}

// Under auto, with the host's routes toward two servers leaving by two links,
// each holding an address of its own, a leaf's datagram toward each server
// leaves by that server's link from the link's own address at the leaf's
// port, as the far end of each link reads it there, under a mapping on each
// address. Neither mapping ends at the other's destination, and each server's
// reply reaches the leaf through its own.
func TestMappingUnderAutoLeavesEachLinkFromItsOwnAddress(t *testing.T) {
	claim(t)
	far := netnstest.StartThread(t)
	links := []struct {
		name, peer string
		here, far  netip.Prefix
	}{
		{"a0", "b0", netip.MustParsePrefix("203.0.113.1/26"), netip.MustParsePrefix("203.0.113.2/26")},
		{"a1", "b1", netip.MustParsePrefix("203.0.113.65/26"), netip.MustParsePrefix("203.0.113.66/26")},
	}
	servers := make([]*net.UDPConn, len(links))
	for i, link := range links {
		servers[i] = veth(t, far, link.name, link.peer, []netip.Prefix{link.here}, link.far, 1)[0]
	}
	h := newRelayHarness(t, nil)
	holdOnly(&h.x.rt, links[0].here.Addr(), links[1].here.Addr())
	h.x.rt.Platform.Prepare = func(string, netip.AddrPort, syscall.RawConn) error { return nil }
	leaf := netip.AddrPortFrom(leaf4, freeUDPPortOn(t, links[0].here.Addr(), links[1].here.Addr()))
	for i, server := range servers {
		payload := []byte("to the server beyond " + links[i].name)
		h.x.udp.take(udpDatagram(leaf, serverAt(server), payload), false)
		if got, want := readDatagramFrom(t, server, payload), netip.AddrPortFrom(links[i].here.Addr(), leaf.Port()); got != want {
			t.Errorf("%s carried the leaf's datagram from %s, want %s, its own address at the leaf's port", links[i].name, got, want)
		}
	}
	if mappings := h.mappingsOf(leaf); len(mappings) != len(links) {
		t.Errorf("%s holds %d mappings, want one on each link's address", leaf, len(mappings))
	}
	for i, server := range servers {
		payload := []byte("from the server beyond " + links[i].name)
		if _, err := server.WriteToUDPAddrPort(payload, netip.AddrPortFrom(links[i].here.Addr(), leaf.Port())); err != nil {
			t.Fatal(err)
		}
		h.waitLaid(t, "reply from beyond "+links[i].name, func(raw []byte) bool { return isDatagram(raw, serverAt(server), leaf, payload) })
	}
}

// veth makes the veth pair of name here, holding each of addresses, and peer in
// far's namespace, holding there, and is count servers at there's address on
// peer
func veth(t *testing.T, far *netnstest.Thread, name, peer string, addresses []netip.Prefix, there netip.Prefix, count int) []*net.UDPConn {
	t.Helper()
	here, err := netnstest.OpenNetlink()
	if err != nil {
		t.Fatal(err)
	}
	defer here.Close()
	if err := here.AddVeth(name, peer, 0, far.Path); err != nil {
		t.Fatalf("a veth pair %s and %s: %v", name, peer, err)
	}
	t.Cleanup(func() { _ = netnstest.DelLink(name) })
	if err := here.AddAddresses(name, addresses...); err != nil {
		t.Fatal(err)
	}
	servers := make([]*net.UDPConn, 0, count)
	t.Cleanup(func() {
		for _, server := range servers {
			_ = server.Close()
		}
	})
	if err := far.Do(func() error {
		netlink, err := netnstest.OpenNetlink()
		if err != nil {
			return err
		}
		defer netlink.Close()
		if err := netlink.AddAddresses(peer, there); err != nil {
			return err
		}
		for range count {
			server, err := onLink(there.Addr(), peer)
			if err != nil {
				return err
			}
			servers = append(servers, server)
		}
		return nil
	}); err != nil {
		t.Fatalf("servers on %s at the far end of %s: %v", peer, name, err)
	}
	return servers
}

// onLink is a UDP socket at address that reads only what arrives on link
func onLink(address netip.Addr, link string) (*net.UDPConn, error) {
	conn, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(address, 0)))
	if err != nil {
		return nil, err
	}
	if err := onSocket(conn, func(fd int) error { return unix.BindToDevice(fd, link) }); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// goneRig is a veth link holding gone and kept, whose far end holds an address
// inside both, so the host's route toward it leaves from gone by the longer
// prefix until gone is taken off, and one inside kept alone, toward which the
// route leaves from kept. The harness's platform holds what this namespace
// holds.
type goneRig struct {
	h            *relayHarness
	gone, kept   netip.Prefix
	both, keptBy *net.UDPConn
	leaf         netip.AddrPort
}

func newGoneRig(t *testing.T) *goneRig {
	t.Helper()
	claim(t)
	far := netnstest.StartThread(t)
	r := &goneRig{gone: netip.MustParsePrefix("203.0.113.1/26"), kept: netip.MustParsePrefix("203.0.113.5/25")}
	r.both = veth(t, far, "g0", "h0", []netip.Prefix{r.gone, r.kept}, netip.MustParsePrefix("203.0.113.2/25"), 1)[0]
	alone := netip.MustParsePrefix("203.0.113.70/25")
	if err := far.Do(func() error {
		netlink, err := netnstest.OpenNetlink()
		if err != nil {
			return err
		}
		defer netlink.Close()
		if err := netlink.AddAddresses("h0", alone); err != nil {
			return err
		}
		r.keptBy, err = onLink(alone.Addr(), "h0")
		return err
	}); err != nil {
		t.Fatalf("a server at %s on h0: %v", alone.Addr(), err)
	}
	t.Cleanup(func() { _ = r.keptBy.Close() })
	r.h = newRelayHarness(t, nil)
	r.h.x.rt.Platform.Held = namespaceHolds
	r.h.x.rt.Platform.Prepare = func(string, netip.AddrPort, syscall.RawConn) error { return nil }
	r.leaf = netip.AddrPortFrom(leaf4, freeUDPPortOn(t, r.gone.Addr(), r.kept.Addr()))
	return r
}

// send has the leaf send payload to server, and is where server read it from
func (r *goneRig) send(t *testing.T, server *net.UDPConn, payload string) netip.AddrPort {
	t.Helper()
	r.h.x.udp.take(udpDatagram(r.leaf, serverAt(server), []byte(payload)), false)
	return readDatagramFrom(t, server, []byte(payload))
}

// takeOff takes gone off the link
func (r *goneRig) takeOff(t *testing.T) {
	t.Helper()
	netlink, err := netnstest.OpenNetlink()
	if err != nil {
		t.Fatal(err)
	}
	defer netlink.Close()
	link, err := net.InterfaceByName("g0")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.DelAddress(link.Index, r.gone); err != nil {
		t.Fatalf("take %s off g0: %v", r.gone, err)
	}
}

// Under auto a mapping whose address the host gave up ends at the first
// datagram its socket then refuses, which is counted, and the leaf's mapping
// on the address the host still holds lives on with its destination. The next
// datagram toward the same server leaves from that address under that
// mapping, as the route read again picks it, and holds the one flow beside
// the mapping's first.
func TestMappingWhoseAddressTheHostGaveUpEndsAtItsNextSendAlone(t *testing.T) {
	r := newGoneRig(t)
	if got, want := r.send(t, r.keptBy, "to kept"), netip.AddrPortFrom(r.kept.Addr(), r.leaf.Port()); got != want {
		t.Fatalf("the server beyond %s alone read the datagram from %s, want %s", r.kept, got, want)
	}
	if got := r.send(t, r.both, "to both"); got.Addr() != r.gone.Addr() {
		t.Fatalf("the server inside both prefixes read the datagram from %s, want %s", got, r.gone.Addr())
	}
	mappings := r.h.mappingsOf(r.leaf)
	if len(mappings) != 2 {
		t.Fatalf("%s holds %d mappings, want one on each address", r.leaf, len(mappings))
	}
	kept, gone := mappings[0], mappings[1]
	r.takeOff(t)
	r.h.x.udp.take(udpDatagram(r.leaf, serverAt(r.both), []byte("refused")), false)
	if got := r.h.count(false, reasonUnsent); got != 1 {
		t.Errorf("counted %d datagrams unsent, want the one the socket on %s refused", got, r.gone.Addr())
	}
	if !ended(gone) || !slices.Equal(r.h.mappingsOf(r.leaf), []*mapping{kept}) {
		t.Fatalf("the mapping on %s ended %t, and %s holds %v, want it ended and the one on %s alone", r.gone.Addr(), ended(gone), r.leaf, r.h.mappingsOf(r.leaf), r.kept.Addr())
	}
	if got, want := r.send(t, r.both, "after"), kept.external(); got != want {
		t.Errorf("the server inside both prefixes read the next datagram from %s, want %s, the mapping on the address the route picks now", got, want)
	}
	kept.mu.RLock()
	held := len(kept.destinations)
	kept.mu.RUnlock()
	if !slices.Equal(r.h.mappingsOf(r.leaf), []*mapping{kept}) || held != 2 {
		t.Errorf("%s holds %v with %d destinations on %s, want the mapping on %s alone with both", r.leaf, r.h.mappingsOf(r.leaf), held, r.kept.Addr(), r.kept.Addr())
	}
	r.h.x.flows.mu.Lock()
	defer r.h.x.flows.mu.Unlock()
	if open := r.h.x.flows.open; open != 2 {
		t.Errorf("%d flows held, want one for each destination", open)
	}
}

// Under auto a mapping whose send the host refuses while it still holds the
// mapping's address, the route toward the server made unreachable, lives on:
// the datagram is counted unsent, and the mapping keeps its destination
func TestMappingWhoseAddressTheHostHoldsLivesPastARefusedSend(t *testing.T) {
	r := newGoneRig(t)
	if got := r.send(t, r.both, "left"); got.Addr() != r.gone.Addr() {
		t.Fatalf("the server read the datagram from %s, want %s", got, r.gone.Addr())
	}
	m := r.h.mappingsOf(r.leaf)[0]
	unreachable(t, netip.PrefixFrom(serverAt(r.both).Addr(), 32))
	r.h.x.udp.take(udpDatagram(r.leaf, serverAt(r.both), []byte("refused")), false)
	if got := r.h.count(false, reasonUnsent); got != 1 {
		t.Errorf("counted %d datagrams unsent, want the one the unreachable route refused", got)
	}
	if ended(m) || !slices.Equal(r.h.mappingsOf(r.leaf), []*mapping{m}) {
		t.Errorf("the mapping on %s, which the host holds, ended %t, want it kept", r.gone.Addr(), ended(m))
	}
}

// unreachable routes to as unreachable in the main table until the test ends,
// so a send toward it fails while the host keeps every address it holds
func unreachable(t *testing.T, to netip.Prefix) {
	t.Helper()
	netlink, err := netnstest.OpenNetlink()
	if err != nil {
		t.Fatal(err)
	}
	defer netlink.Close()
	header := []byte{unix.AF_INET, byte(to.Bits()), 0, 0, unix.RT_TABLE_MAIN, unix.RTPROT_BOOT, unix.RT_SCOPE_UNIVERSE, unix.RTN_UNREACHABLE, 0, 0, 0, 0}
	route := slices.Concat(header, netnstest.Attr(unix.RTA_DST, to.Addr().AsSlice()))
	if err := netlink.Request(unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_EXCL, route); err != nil {
		t.Fatalf("route %s unreachable: %v", to, err)
	}
	t.Cleanup(func() {
		netlink, err := netnstest.OpenNetlink()
		if err != nil {
			t.Error(err)
			return
		}
		defer netlink.Close()
		if err := netlink.Request(unix.RTM_DELROUTE, 0, route); err != nil {
			t.Errorf("remove the unreachable route to %s: %v", to, err)
		}
	})
}

// Under a class naming an address the host then gives up, a leaf that keeps
// sending sees each datagram counted unsent and its mapping end by its timer,
// timed from the last datagram that left, as a mapping with no datagram out
func TestMappingOnAClassAddressTheHostGaveUpEndsByItsTimer(t *testing.T) {
	r := newGoneRig(t)
	r.h.x.cfg.Translate = classed(r.gone.Addr()).Translate
	if got := r.send(t, r.both, "left"); got.Addr() != r.gone.Addr() {
		t.Fatalf("the server read the datagram from %s, want %s, the class's", got, r.gone.Addr())
	}
	m := r.h.mappingsOf(r.leaf)[0]
	r.takeOff(t)
	const tries = 4
	for i := range tries {
		r.h.advance(time.Minute)
		r.h.x.udp.take(udpDatagram(r.leaf, serverAt(r.both), []byte("refused")), false)
		if ended(m) {
			t.Fatalf("the mapping ended %d minutes after the last datagram that left, before its timer", i+1)
		}
	}
	if got := r.h.count(false, reasonUnsent); got != tries {
		t.Errorf("counted %d datagrams unsent, want each of the %d refused", got, tries)
	}
	r.h.advance(mappingTimeout - tries*time.Minute + time.Second)
	if !ended(m) {
		t.Errorf("the mapping lives %s past the last datagram that left", mappingTimeout+time.Second)
	}
}

// TestMappingsAreTheModels' property with servers whose routes pick two
// addresses of loopback's, so a leaf's destinations take a mapping on each
func TestMappingsAreTheModelsAcrossTwoRoutesAddresses(t *testing.T) {
	onLoopback(t, twoPrefixes[:]...)
	first, second := twoPrefixes[0].Addr().Next().Next(), twoPrefixes[1].Addr().Next().Next()
	mappingsAreTheModels(t, []netip.Addr{first, first.Next(), second}, second.Next(), func(rt *Runtime) {
		holdOnly(rt, twoPrefixes[0].Addr(), twoPrefixes[1].Addr())
		rt.Platform.Prepare = func(string, netip.AddrPort, syscall.RawConn) error { return nil }
	})
}
