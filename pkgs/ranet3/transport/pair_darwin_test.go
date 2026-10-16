// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin

package transport

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os/exec"
	"slices"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// the kernel hands a socket bound to one address on the listener's port and connected to a peer that peer's datagrams
// while a datagram from another peer to the same address and port reaches the listener
// XNU looks a datagram up by its exact 4-tuple before any socket bound to a wildcard address
func TestConnectedSocketReceivesItsPeerWhileTheListenerKeepsTheRest(t *testing.T) {
	for _, family := range []struct{ network, loopback string }{{"udp4", "127.0.0.1"}, {"udp6", "::1"}} {
		t.Run(family.network, func(t *testing.T) {
			listening, _, _, err := listenPacketBind(0, 0)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listening.Close() })
			bind := listening.(*darwinBind)
			listener := bind.v4
			if family.network == "udp6" {
				listener = bind.v6
			}
			host := netip.MustParseAddr(family.loopback)
			peer, other := listenPeer(t, family.network, family.loopback), listenPeer(t, family.network, family.loopback)
			remote := netip.AddrPortFrom(host, uint16(peer.LocalAddr().(*net.UDPAddr).Port))
			socket, _, err := bind.connectPair(pairKey{remote: remote})
			if err != nil {
				t.Fatalf("connect a socket to %s: %v", remote, err)
			}
			t.Cleanup(func() { _ = socket.Close() })
			deliveredApart(t, socket.(*darwinPair).socket.conn, listener.conn, peer, other, host, netip.AddrPortFrom(host, bind.port))
		})
	}
}

// pairsJoined is how many sockets connected to one peer the bind moves with their families
func pairsJoined(hub *Hub) int {
	b := hub.bind.(*darwinBind)
	b.fragmentMu.Lock()
	defer b.fragmentMu.Unlock()
	return len(b.pairs)
}

// pairSocketOf is the socket a pair to a peer of its own on loopback in network opened
func pairSocketOf(t *testing.T, hub *Hub, network, loopback string) (*Mux, *darwinSocket) {
	t.Helper()
	at := listenPeer(t, network, loopback).LocalAddr().(*net.UDPAddr)
	mux, err := hub.NewMux(at.IP, at.Port)
	if err != nil {
		t.Fatal(err)
	}
	socket := openNow(mux).socket.Load()
	if socket == nil {
		t.Fatalf("the pair to %s opened no socket", at)
	}
	return mux, (*socket).(*darwinPair).socket
}

// an IPv4 pair's socket clears DF while an IPv4 mux fragments and sets it again once the last one stops, as the IPv4 socket does
// a pair connected while IPv4 fragments starts without DF, and an IPv6 pair's socket keeps DF, since an IPv6 mux fragments its own datagrams alone
func TestPairSocketFollowsItsFamilysDontFragment(t *testing.T) {
	hub, err := NewHub(":0", Underlay{}, Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	listener := hub.bind.(*darwinBind).v4
	mux, first := pairSocketOf(t, hub, "udp4", "127.0.0.1")
	v6mux, v6 := pairSocketOf(t, hub, "udp6", "::1")
	if err := mux.Fragment(true); err != nil {
		t.Fatal(err)
	}
	if err := v6mux.Fragment(true); err != nil {
		t.Fatal(err)
	}
	_, later := pairSocketOf(t, hub, "udp4", "127.0.0.1")
	for name, socket := range map[string]*darwinSocket{"the IPv4 socket": listener, "the first IPv4 pair": first, "an IPv4 pair connected meanwhile": later} {
		if dontFragmentSet(t, socket) {
			t.Errorf("while an IPv4 mux fragments, %s sets DF", name)
		}
	}
	if !dontFragmentSet(t, v6) {
		t.Error("while an IPv6 mux fragments, its pair's socket clears DF")
	}
	if err := mux.Fragment(false); err != nil {
		t.Fatal(err)
	}
	for name, socket := range map[string]*darwinSocket{"the IPv4 socket": listener, "the first IPv4 pair": first, "an IPv4 pair connected meanwhile": later} {
		if !dontFragmentSet(t, socket) {
			t.Errorf("once the IPv4 mux stopped fragmenting, %s clears DF", name)
		}
	}
}

// a move of the underlay socket onto another interface closes every pair's socket, which a busy pair connects again bound where the listener now is
func TestUnderlayMoveClosesPairSockets(t *testing.T) {
	index, _ := twoInterfaces(t)
	events := &eventLog{}
	hub, err := NewHub(":0", Underlay{}, Runtime{Events: events.record})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	at := listenPeer(t, "udp4", "127.0.0.1").LocalAddr().(*net.UDPAddr)
	mux, err := hub.NewMux(at.IP, at.Port)
	if err != nil {
		t.Fatal(err)
	}
	p := openNow(mux)
	if p.socket.Load() == nil {
		t.Fatal("the pair opened no socket")
	}
	if err := hub.BindUnderlay(index); err != nil {
		t.Fatal(err)
	}
	if p.socket.Load() != nil || hub.PairSockets() != 0 {
		t.Fatalf("the pair's socket outlived the move of the underlay socket onto interface %d", index)
	}
	closed := "transport.pair.closed local=127.0.0.1 remote=" + at.AddrPort().String() + " reason=" + pairUnderlayClose
	if !slices.Contains(events.recorded(), closed) {
		t.Errorf("the hub recorded %q, want %q among them", events.recorded(), closed)
	}
}

// a move of the underlay socket also binds the pairs connected after it where the listener now is
// so a pair's sends leave by the interface the shared socket's do
func TestPairConnectedAfterAnUnderlayMoveIsBoundWhereTheListenerIs(t *testing.T) {
	index, _ := twoInterfaces(t)
	hub, _, mux := pairHub(t, "udp4", "127.0.0.1")
	if err := hub.BindUnderlay(index); err != nil {
		t.Fatal(err)
	}
	socket := openNow(mux).socket.Load()
	if socket == nil {
		t.Fatalf("the pair opened no socket once the underlay socket moved onto interface %d", index)
	}
	if got := boundInterface(t, (*socket).(*darwinPair).socket); got != index {
		t.Fatalf("the pair connected after the move is bound to interface %d, want the listener's %d", got, index)
	}
}

// hostRoute adds a route through route(8) and deletes it as the test ends
func hostRoute(t *testing.T, args ...string) {
	t.Helper()
	hostCommand(t, append([]string{"route", "-n", "add"}, args...)...)
	t.Cleanup(func() { _ = exec.Command("route", append([]string{"-n", "delete"}, args...)...).Run() })
}

// a pair of a hub bound to the near feth binds the near feth's address to a peer the host routes out of the far feth
// the near feth carries a route to the peer scoped to it, which XNU's lookup bound to the near feth takes past the host's own
// the host's own route to each peer leaves by the far feth from the far feth's address, which the test checks first
func TestPairOfABoundHubTakesItsSourceFromTheBoundInterface(t *testing.T) {
	requireFeth(t)
	fethPath(t)
	near, err := net.InterfaceByName(fethNear)
	if err != nil {
		t.Fatal(err)
	}
	paths := []struct {
		// family is route's flag for the family, and address is far in ifconfig's words
		family  string
		address []string
		// peers is the prefix of peer, which the host routes through via and the near feth through scoped
		peers, via, scoped, peer string
		// local is the near feth's address and far the far feth's
		local, far string
	}{
		{"-inet", []string{"inet", "198.51.100.1/24"}, "203.0.113.0/24", "198.51.100.9", "192.0.2.9", "203.0.113.9", "192.0.2.1", "198.51.100.1"},
		{"-inet6", []string{"inet6", "2001:db8:c::1", "prefixlen", "64"}, "2001:db8:e::/48", "2001:db8:c::9", "2001:db8:f::9", "2001:db8:e::9", "2001:db8:f::1", "2001:db8:c::1"},
	}
	for _, path := range paths {
		hostCommand(t, append([]string{"ifconfig", fethFar}, path.address...)...)
	}
	waitDAD(t, fethFar)
	for _, path := range paths {
		hostRoute(t, path.family, "-net", path.peers, path.via)
		hostRoute(t, path.family, "-net", path.peers, path.scoped, "-ifscope", fethNear)
		conn, err := net.Dial("udp", net.JoinHostPort(path.peer, "4500"))
		if err != nil {
			t.Fatal(err)
		}
		from := conn.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Unmap()
		_ = conn.Close()
		if from.String() != path.far {
			t.Fatalf("the host routes %s from %s, want the far feth's %s", path.peer, from, path.far)
		}
	}
	hub, err := NewHub(":0", Underlay{}, Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	if err := hub.BindUnderlay(near.Index); err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		mux, err := hub.NewMux(net.ParseIP(path.peer), 4500)
		if err != nil {
			t.Fatal(err)
		}
		socket := openNow(mux).socket.Load()
		if socket == nil {
			t.Fatalf("the pair to %s opened no socket on a hub bound to %s", path.peer, fethNear)
		}
		bound := pairConn(*socket).LocalAddr().(*net.UDPAddr).AddrPort()
		if got, want := netip.AddrPortFrom(bound.Addr().Unmap(), bound.Port()), netip.AddrPortFrom(netip.MustParseAddr(path.local), hub.port); got != want {
			t.Errorf("the pair to %s from a hub bound to %s is bound to %s, want %s rather than the host's own %s", path.peer, fethNear, got, want, path.far)
		}
	}
}

// a pair to a link-local peer connects by the interface the peer's zone names, from that interface's link-local address
func TestPairToALinkLocalPeerConnects(t *testing.T) {
	loopback, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Fatal(err)
	}
	addresses, err := loopback.Addrs()
	if err != nil {
		t.Fatal(err)
	}
	var local netip.Addr
	for _, address := range addresses {
		if prefix, ok := address.(*net.IPNet); ok && prefix.IP.IsLinkLocalUnicast() && prefix.IP.To4() == nil {
			local, _ = netip.AddrFromSlice(prefix.IP)
			local = local.WithZone(loopback.Name)
		}
	}
	if !local.IsValid() {
		t.Skip("lo0 holds no link-local IPv6 address")
	}
	peer, err := net.ListenUDP("udp6", net.UDPAddrFromAddrPort(netip.AddrPortFrom(local, 0)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	hub, err := NewHub(":0", Underlay{}, Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	endpoint, err := hub.bind.ParseEndpoint(peer.LocalAddr().(*net.UDPAddr).AddrPort().String())
	if err != nil {
		t.Fatal(err)
	}
	mux, err := hub.NewMuxTo(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	socket := openNow(mux).socket.Load()
	if socket == nil {
		t.Fatalf("the pair to %s opened no socket", endpoint)
	}
	if got := (*socket).local(); got != local {
		t.Fatalf("the pair to %s is bound to %s, want %s", endpoint, got, local)
	}
	marker := []byte("to a link-local peer")
	if sent, kept, err := (*socket).transmit([][]byte{marker}, endpoint); sent != 1 || !kept || err != nil {
		t.Fatalf("the pair's send answered %d sent, kept %v and %v", sent, kept, err)
	}
	if from, want := readFrom(t, peer, marker), netip.AddrPortFrom(local, hub.port); from != want {
		t.Fatalf("the peer heard from %s, want %s", from, want)
	}
}

// a pair's IPv4 socket that cannot take its family's DF closes, and the pair's sends take the shared socket, which can
func TestPairSocketThatCannotFollowItsFamilyCloses(t *testing.T) {
	hub, peer, mux := pairHub(t, "udp4", "127.0.0.1")
	bind := hub.bind.(*darwinBind)
	p := openNow(mux)
	if p.socket.Load() == nil {
		t.Fatal("the pair opened no socket")
	}
	bind.setDontFragment = func(socket *darwinSocket, on bool) error {
		if socket != bind.v4 {
			return unix.ENOPROTOOPT
		}
		return socket.setDontFragment(on)
	}
	if err := mux.Fragment(true); err != nil {
		t.Fatal(err)
	}
	marker := []byte("once the pair could not follow")
	if err := mux.SendESP(marker); err != nil {
		t.Fatal(err)
	}
	readFrom(t, peer, marker)
	if p.socket.Load() != nil || pairsJoined(hub) != 0 || hub.PairFallbacks() != 1 {
		t.Fatalf("the pair's socket that could not follow its family is still open, or counted %d fallbacks, want 1", hub.PairFallbacks())
	}
}

// pairConnectsAtOnce is how many connects run at once in each of pairConnectBatches
const (
	pairConnectsAtOnce = 16
	pairConnectBatches = 8
)

// pairs to several peers connect at once, each binding the listener's port on one address
// XNU refuses to bind an address and port another socket holds unconnected, which each socket does between its bind and its connect
func TestPairsToSeveralPeersConnectAtOnce(t *testing.T) {
	hub, err := NewHub(":0", Underlay{}, Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	var remotes []netip.AddrPort
	for range pairConnectsAtOnce {
		remotes = append(remotes, listenPeer(t, "udp4", "127.0.0.1").LocalAddr().(*net.UDPAddr).AddrPort())
	}
	for batch := range pairConnectBatches {
		sockets, errs := make([]pairSocket, len(remotes)), make([]error, len(remotes))
		var connects sync.WaitGroup
		for i, remote := range remotes {
			connects.Go(func() { sockets[i], _, errs[i] = hub.pairs.connector.connectPair(pairKey{remote: remote}) })
		}
		connects.Wait()
		for i, err := range errs {
			if err != nil {
				t.Fatalf("batch %d: the connect to %s beside %d others failed: %v", batch, remotes[i], len(remotes)-1, err)
			}
			_ = sockets[i].Close()
		}
	}
}

// a pair's socket refuses a datagram past lo0's MTU that its mux does not let fragment, and keeps the pair
// the shared socket refuses it too and reports the interface's MTU
func TestPairSocketKeepsItsPairPastADatagramTheInterfaceRefuses(t *testing.T) {
	loopback, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range []struct{ network, loopback string }{{"udp4", "127.0.0.1"}, {"udp6", "::1"}} {
		t.Run(family.network, func(t *testing.T) {
			hub, _, mux := pairHub(t, family.network, family.loopback)
			p := openNow(mux)
			socket := p.socket.Load()
			if socket == nil {
				t.Fatal("the pair opened no socket")
			}
			datagram := make([]byte, loopback.MTU+pastLoopback)
			if sent, kept, err := (*socket).transmit([][]byte{datagram}, mux.Endpoint()); sent != 0 || !kept || !errors.Is(err, unix.EMSGSIZE) {
				t.Fatalf("the pair's send of %d bytes past lo0's MTU answered %d sent, kept %v and %v, want EMSGSIZE and the pair kept", len(datagram), sent, kept, err)
			}
			err := mux.SendESP(datagram)
			if report, ok := err.(*PathMTUError); !ok || report.MTU != loopback.MTU {
				t.Fatalf("a send of %d bytes past lo0's MTU answered %v, want the report of its %d", len(datagram), err, loopback.MTU)
			}
			if p.socket.Load() == nil || hub.PairFallbacks() != 0 {
				t.Fatalf("a datagram past the interface cost the pair its socket, or counted %d fallbacks", hub.PairFallbacks())
			}
		})
	}
}

// a pair's reader and its send go past every error XNU hands a connected UDP socket for an ICMP error, and stop at errors of their own
// udp_ctlinput in bsd/netinet/udp_usrreq.c and udp6_ctlinput in bsd/netinet6/udp6_usrreq.c set so_error from inetctlerrmap in bsd/netinet/ip_input.c and inet6ctlerrmap in bsd/netinet6/ip6_input.c
func TestPairGoesPastEveryICMPErrorXNUHands(t *testing.T) {
	icmpReportsHold(t,
		[]unix.Errno{unix.ECONNREFUSED, unix.EHOSTDOWN, unix.EHOSTUNREACH, unix.EMSGSIZE, unix.ENETUNREACH, unix.ENOPROTOOPT},
		[]unix.Errno{unix.EACCES, unix.EADDRNOTAVAIL, unix.EINVAL, unix.EIO, unix.ENOBUFS, unix.EPROTO})
}

// pairConn is the socket a pair connected
func pairConn(socket pairSocket) *net.UDPConn { return socket.(*darwinPair).socket.conn }

// unreachableRepeat is how long XNU withholds a port unreachable for the addresses and ports of the last one it sent
// udp_input and udp6_input drop one within net.inet.udp.port_unreach_rlc_bucket_ms of it, from xnu-12377.41.6 on
// the kernel counts that bucket in whole milliseconds, so one more clears it
func unreachableRepeat(t *testing.T) time.Duration {
	t.Helper()
	if on, err := unix.SysctlUint32("net.inet.udp.port_unreach_rlc_enable"); err != nil || on == 0 {
		return 0
	}
	if timed, err := unix.SysctlUint32("net.inet.udp.port_unreach_rlc_use_ts"); err == nil && timed == 0 {
		t.Skip("XNU withholds every repeated port unreachable while net.inet.udp.port_unreach_rlc_use_ts is 0")
	}
	bucket, err := unix.SysctlUint32("net.inet.udp.port_unreach_rlc_bucket_ms")
	if err != nil {
		t.Fatal(err)
	}
	return time.Duration(bucket+1) * time.Millisecond
}

// pastLoopback is how far past lo0's MTU the datagram a pair sends in fragments runs
const pastLoopback = 1000

// a datagram past lo0's MTU leaves a pair's socket in fragments while its mux fragments and reaches the peer whole
// IPv4 through its socket's IP_DONTFRAG and IPv6 through the datagram's own IPV6_DONTFRAG
// the pair's own socket sends it, where one that kept DF would refuse it and hand it to the shared socket
func TestPairSocketSendsPastTheInterfaceWhileItsMuxFragments(t *testing.T) {
	loopback, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range []struct{ network, loopback string }{{"udp4", "127.0.0.1"}, {"udp6", "::1"}} {
		t.Run(family.network, func(t *testing.T) {
			_, peer, mux := pairHub(t, family.network, family.loopback)
			p := openNow(mux)
			socket := p.socket.Load()
			if socket == nil {
				t.Fatal("the pair opened no socket")
			}
			if err := mux.Fragment(true); err != nil {
				t.Fatal(err)
			}
			datagram := make([]byte, loopback.MTU+pastLoopback)
			binary.BigEndian.PutUint32(datagram, pairTestSPI)
			if sent, kept, err := (*socket).transmit([][]byte{datagram}, mux.Endpoint()); sent != 1 || !kept || err != nil {
				t.Fatalf("a datagram of %d bytes past lo0's MTU of %d left the pair's socket as %d sent, kept %v and %v", len(datagram), loopback.MTU, sent, kept, err)
			}
			readFrom(t, peer, datagram)
		})
	}
}
