// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package transport

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"slices"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

// a socket connected to one peer reads on past the ICMP error an earlier datagram drew
// and the next read asks the kernel again rather than answering nothing for good
func TestPairReceiveReadsPastAnICMPReport(t *testing.T) {
	reads := 0
	messages := receiveVector(pairReadMessages)
	receive := retryICMP((&udpSocket{}).walk(messages, func() (int, error) {
		reads++
		if reads == 2 {
			return 0, os.NewSyscallError("recvmmsg", unix.ECONNREFUSED)
		}
		m := &messages[0]
		m.N, m.NN = 8, 0
		binary.BigEndian.PutUint32(m.Buffers[0], pairTestSPI)
		binary.BigEndian.PutUint32(m.Buffers[0][4:], uint32(reads))
		return 1, nil
	}))
	packets, sizes, endpoints := make([][]byte, 1), make([]int, 1), make([]Endpoint, 1)
	for _, want := range []uint32{1, 3} {
		n, _, err := receive(packets, sizes, endpoints)
		if err != nil || n != 1 || binary.BigEndian.Uint32(packets[0][4:]) != want {
			t.Fatalf("the read that should carry datagram %d answered n=%d err=%v", want, n, err)
		}
	}
}

// a pair's reader and its send go past every error linux hands a connected UDP socket for an ICMP error, and stop at errors of their own
// udp_err in net/ipv4/udp.c passes the fatal entries of icmp_err_convert in net/ipv4/icmp.c, EMSGSIZE for a fragmentation needed and EPROTO for a parameter problem
// udpv6_err in net/ipv6/udp.c passes the fatal entries of icmpv6_err_convert in net/ipv6/icmp.c and EMSGSIZE for a packet too big
func TestPairGoesPastEveryICMPErrorLinuxHands(t *testing.T) {
	icmpReportsHold(t,
		[]unix.Errno{unix.EACCES, unix.ECONNREFUSED, unix.EHOSTDOWN, unix.EHOSTUNREACH, unix.EMSGSIZE, unix.ENETUNREACH, unix.ENONET, unix.ENOPROTOOPT, unix.EPROTO},
		[]unix.Errno{unix.EADDRNOTAVAIL, unix.EINVAL, unix.EIO, unix.ENOBUFS, unix.ENODEV, unix.EPERM})
}

// pairConn is the socket a pair connected
func pairConn(socket pairSocket) *net.UDPConn { return socket.(*udpPair).socket.conn }

// a socket whose network namespace cannot be read is refused, so its pair stays on the shared socket
// and one beside a socket of its own namespace is not
func TestPairSocketWhoseNamespaceCannotBeReadIsRefused(t *testing.T) {
	listener, err := listenPeer(t, "udp4", "127.0.0.1").SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = reader.Close(), writer.Close() })
	pipe, err := reader.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	if err := sameNamespace(namespaceCookie, pipe, listener); !errors.Is(err, unix.ENOTSOCK) {
		t.Fatalf("a descriptor that is no socket answered %v, want ENOTSOCK", err)
	}
	if err := sameNamespace(namespaceCookie, listener, listener); err != nil {
		t.Fatalf("a socket beside one of its own namespace answered %v", err)
	}
}

// a pair opens on a kernel before 5.14, whose answer of ENOPROTOOPT to SO_NETNS_COOKIE leaves the socket's namespace unchecked
func TestPairOpensWhereTheKernelCannotNameANamespace(t *testing.T) {
	hub, _, mux := pairHub(t, "udp4", "127.0.0.1")
	hub.bind.(*udpBind).cookie = func(syscall.RawConn) (uint64, error) { return 0, unix.ENOPROTOOPT }
	if openNow(mux).socket.Load() == nil {
		t.Fatal("the pair opened no socket where the kernel cannot name a socket's namespace")
	}
}

// unreachableRepeat is zero, since linux answers every datagram to a closed loopback port
// __icmp_send and icmpv4_xrlim_allow skip their rate limits on loopback, as icmp6_send and icmpv6_xrlim_allow do
func unreachableRepeat(*testing.T) time.Duration { return 0 }

// connectedKernel hands a connected socket's messages to the kernel addressed to the peer the socket is connected to
type connectedKernel struct {
	kernel *fakeKernel
	peer   *net.UDPAddr
}

func (c connectedKernel) WriteBatch(messages []ipv4.Message, _ int) (int, error) {
	for i := range messages {
		messages[i].Addr = c.peer
	}
	return c.kernel.write(messages)
}

// a pair's socket segments its sends where the shared socket's sends to the endpoint segment
// a route through an IPsec policy refuses a segmented message with EIO, and a locked path while the family fragments refuses a segment past it with EMSGSIZE
// either stops the endpoint's segments for a while once the shared socket's single datagrams went, and an endpoint whose mux fragments never segments
func TestPairSocketSegmentsWhereTheSharedSocketDoes(t *testing.T) {
	peer := netip.MustParseAddrPort("192.0.2.2:4500")
	for _, route := range []struct {
		name string
		// ready sets the route up and answers whether sends to ep segment on it
		ready func(t *testing.T, kernel *fakeKernel, bind *udpBind, ep *udpEndpoint) bool
	}{
		{"a plain route", func(*testing.T, *fakeKernel, *udpBind, *udpEndpoint) bool { return true }},
		{"a route through an IPsec policy", func(t *testing.T, kernel *fakeKernel, bind *udpBind, ep *udpEndpoint) bool {
			kernel.unsegmentable[peer.Addr()] = unix.EIO
			if err := bind.Send(numbered(3, pairDatagram), ep); err != nil {
				t.Fatal(err)
			}
			return false
		}},
		{"a locked path while the family fragments", func(t *testing.T, kernel *fakeKernel, bind *udpBind, ep *udpEndpoint) bool {
			kernel.pathMTU[peer.Addr()] = headerFor(peer.Addr()) + pairDatagram
			if err := bind.fragment(dialed("192.0.2.9:4500"), true); err != nil {
				t.Fatal(err)
			}
			if err := bind.Send(numbered(3, pairDatagram+1), ep); err != nil {
				t.Fatal(err)
			}
			return false
		}},
		{"an endpoint whose mux fragments", func(t *testing.T, _ *fakeKernel, bind *udpBind, ep *udpEndpoint) bool {
			if err := bind.fragment(ep, true); err != nil {
				t.Fatal(err)
			}
			return false
		}},
	} {
		t.Run(route.name, func(t *testing.T) {
			kernel := newFakeKernel()
			kernel.hold("192.0.2.1", 1)
			bind := kernelBind(kernel, &eventLog{})
			ep := dialed(peer.String())
			segments := route.ready(t, kernel, bind, ep)
			socket := &udpSocket{pc: connectedKernel{kernel, ep.addr}}
			socket.send.New = func() any { return newUDPSendBatch() }
			pair := &udpPair{socket: socket, bind: bind}
			before := len(kernel.messages())
			if sent, kept, err := pair.transmit(numbered(3, pairDatagram), ep); sent != 3 || !kept || err != nil {
				t.Fatalf("the pair's send answered %d sent, kept %v and %v, want all 3 sent", sent, kept, err)
			}
			want := []int{pairDatagram}
			if !segments {
				want = []int{0, 0, 0}
			}
			var got []int
			for _, message := range kernel.messages()[before:] {
				got = append(got, message.segment)
			}
			if !slices.Equal(got, want) {
				t.Fatalf("the pair's socket sent messages of segments %v, want %v", got, want)
			}
		})
	}
}

// a pair's socket keeps its pair through a refusal of its segments that reaches it before the shared socket's sends meet one
// it resends the refused message one datagram to a message as the shared socket does
// a route through an IPsec policy refuses the segments with EIO and passes the single datagrams, which stops the endpoint's segments
// a kernel before 6.14 refuses a segment past a path that narrowed with EINVAL, and the single datagrams meet the EMSGSIZE the shared socket reports the path for
// while the family fragments, a segment past the path is refused with EMSGSIZE and the single datagrams go in fragments, which stops the endpoint's segments
func TestPairSocketKeepsItsPairThroughARefusalOfItsSegments(t *testing.T) {
	peer := netip.MustParseAddrPort("192.0.2.2:4500")
	for _, route := range []struct {
		name  string
		ready func(t *testing.T, kernel *fakeKernel, bind *udpBind)
		// sent and err are the pair's send's answer, and stop names the errno the endpoint's segments stop for, none where they go on
		sent int
		err  error
		stop string
	}{
		{"a route through an IPsec policy", func(_ *testing.T, kernel *fakeKernel, _ *udpBind) { kernel.unsegmentable[peer.Addr()] = unix.EIO }, 3, nil, "EIO"},
		{"a kernel before 6.14 whose path narrowed under the segment", func(_ *testing.T, kernel *fakeKernel, _ *udpBind) {
			kernel.gsoErrno = unix.EINVAL
			kernel.pathMTU[peer.Addr()] = headerFor(peer.Addr()) + pairDatagram - 1
		}, 0, unix.EMSGSIZE, ""},
		{"a path narrower than the segment while the family fragments", func(t *testing.T, kernel *fakeKernel, bind *udpBind) {
			kernel.pathMTU[peer.Addr()] = headerFor(peer.Addr()) + pairDatagram - 1
			if err := bind.fragment(dialed("192.0.2.9:4500"), true); err != nil {
				t.Fatal(err)
			}
		}, 3, nil, "EMSGSIZE"},
	} {
		t.Run(route.name, func(t *testing.T) {
			kernel := newFakeKernel()
			kernel.hold("192.0.2.1", 1)
			events := &eventLog{}
			bind := kernelBind(kernel, events)
			ep := dialed(peer.String())
			route.ready(t, kernel, bind)
			socket := &udpSocket{pc: connectedKernel{kernel, ep.addr}}
			socket.send.New = func() any { return newUDPSendBatch() }
			pair := &udpPair{socket: socket, bind: bind}
			if sent, kept, err := pair.transmit(numbered(3, pairDatagram), ep); sent != route.sent || !kept || !errors.Is(err, route.err) {
				t.Fatalf("the pair's send answered %d sent, kept %v and %v, want %d sent, the pair kept and %v", sent, kept, err, route.sent, route.err)
			}
			sent := kernel.datagrams()
			if got := numbers(sent); !slices.Equal(got, sequence(route.sent)) {
				t.Fatalf("the datagrams went out as %v, want the %d sent each once in order", got, route.sent)
			}
			if slices.ContainsFunc(sent, func(datagram sentDatagram) bool { return datagram.segmented }) {
				t.Fatal("a datagram went out in a segmented message the route refuses")
			}
			if _, segments := bind.segmenting(ep); segments != (route.stop == "") {
				t.Fatalf("after the refusal, sends to the endpoint segment %v, want %v", segments, route.stop == "")
			}
			var want []string
			if route.stop != "" {
				want = []string{"transport.endpoint.unsegmented endpoint=" + ep.String() + " errno=" + route.stop}
			}
			if got := events.recorded(); !slices.Equal(got, want) {
				t.Fatalf("the bind recorded %q, want %q", got, want)
			}
		})
	}
}

// a Packet Too Big leaves EMSGSIZE pending on a connected socket, which the next send alone reports
// while the family fragments, EMSGSIZE is also linux refusing a segment past the path, so a message refused with it goes once more as it was
// on a path its segments fit, the message then goes segmented and the endpoint keeps segmenting
// a path narrower than the segment refuses it again, and the single datagrams go in fragments, which stops the endpoint's segments
func TestPairSocketStopsSegmentingOnlyWhenItsSegmentsAreRefusedTwice(t *testing.T) {
	peer := netip.MustParseAddrPort("[2001:db8::2]:4500")
	// fmt calls the Error method of exported fields alone, which spells an errno out
	type tried struct {
		Segment int
		Errno   unix.Errno
	}
	for _, route := range []struct {
		name string
		// mtu is the path MTU the Packet Too Big leaves, and tried each message the pair's socket handed the kernel
		mtu   int
		tried []tried
		// stop names the errno the endpoint's segments stop for, none where they go on
		stop string
	}{
		{"a path the segments fit", defaultPathMTU, []tried{{pairDatagram, unix.EMSGSIZE}, {pairDatagram, 0}}, ""},
		{"a path narrower than the segment", headerFor(peer.Addr()) + pairDatagram - 1,
			[]tried{{pairDatagram, unix.EMSGSIZE}, {pairDatagram, unix.EMSGSIZE}, {0, 0}, {0, 0}, {0, 0}}, "EMSGSIZE"},
	} {
		t.Run(route.name, func(t *testing.T) {
			kernel := newFakeKernel()
			kernel.hold("2001:db8::1", 1)
			events := &eventLog{}
			bind := kernelBind(kernel, events)
			if err := bind.fragment(dialed("[2001:db8::9]:4500"), true); err != nil {
				t.Fatal(err)
			}
			ep := dialed(peer.String())
			kernel.pathMTU[peer.Addr()] = route.mtu
			kernel.once = unix.EMSGSIZE
			socket := &udpSocket{pc: connectedKernel{kernel, ep.addr}, ipv6: true}
			socket.send.New = func() any { return newUDPSendBatch() }
			pair := &udpPair{socket: socket, bind: bind}
			if sent, kept, err := pair.transmit(numbered(3, pairDatagram), ep); sent != 3 || !kept || err != nil {
				t.Fatalf("the pair's send answered %d sent, kept %v and %v, want all 3 sent", sent, kept, err)
			}
			var got []tried
			for _, message := range kernel.messages() {
				got = append(got, tried{message.segment, message.errno})
			}
			if !slices.Equal(got, route.tried) {
				t.Fatalf("the pair's socket handed the kernel %v, want %v", got, route.tried)
			}
			if got := numbers(kernel.datagrams()); !slices.Equal(got, sequence(3)) {
				t.Fatalf("the datagrams went out as %v, want each once in order", got)
			}
			if _, segments := bind.segmenting(ep); segments != (route.stop == "") {
				t.Fatalf("after the send, sends to the endpoint segment %v, want %v", segments, route.stop == "")
			}
			var want []string
			if route.stop != "" {
				want = []string{"transport.endpoint.unsegmented endpoint=" + ep.String() + " errno=" + route.stop}
			}
			if got := events.recorded(); !slices.Equal(got, want) {
				t.Fatalf("the bind recorded %q, want %q", got, want)
			}
		})
	}
}

// pairsJoined is how many sockets connected to one peer the bind moves with their families
func pairsJoined(hub *Hub) int {
	b := hub.bind.(*udpBind)
	b.fragmentMu.Lock()
	defer b.fragmentMu.Unlock()
	return len(b.pairs)
}

// discoveryMode reads the path MTU discovery mode of a socket
func discoveryMode(t *testing.T, socket *udpSocket) int {
	t.Helper()
	level, option := unix.IPPROTO_IP, unix.IP_MTU_DISCOVER
	if socket.ipv6 {
		level, option = unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER
	}
	var mode int
	var readErr error
	if err := socket.raw.Control(func(fd uintptr) { mode, readErr = unix.GetsockoptInt(int(fd), level, option) }); err != nil {
		t.Fatal(err)
	}
	if readErr != nil {
		t.Fatal(readErr)
	}
	return mode
}

// a pair's socket that cannot take its family's mode closes, and the pair's sends take the shared socket, which can
func TestPairSocketThatCannotFollowItsFamilyCloses(t *testing.T) {
	hub, peer, mux := pairHub(t, "udp4", "127.0.0.1")
	bind := hub.bind.(*udpBind)
	p := openNow(mux)
	if p.socket.Load() == nil {
		t.Fatal("the pair opened no socket")
	}
	bind.discover = func(socket *udpSocket, fragment bool) error {
		if socket != bind.v4 {
			return unix.ENOPROTOOPT
		}
		return setDiscovery(socket, fragment)
	}
	if err := mux.Fragment(true); err != nil {
		t.Fatal(err)
	}
	marker := []byte("once the pair could not follow")
	if err := mux.SendESP(marker); err != nil {
		t.Fatal(err)
	}
	if from := readFrom(t, peer, marker); from.Port() != hub.port {
		t.Fatalf("the peer heard from port %d, want the listener's %d", from.Port(), hub.port)
	}
	if p.socket.Load() != nil || pairsJoined(hub) != 0 || hub.PairFallbacks() != 1 {
		t.Fatalf("the pair's socket that could not follow its family is still open, or counted %d fallbacks, want 1", hub.PairFallbacks())
	}
}

// a pair's socket takes the mode its family's listener fragments in while a mux of the family fragments, and DO again once the last one stops
// a pair connected while its family fragments starts in that mode, and the other family's pairs keep DO throughout
func TestPairSocketFollowsItsFamilysPathMTUDiscovery(t *testing.T) {
	hub, err := NewHub(":0", Underlay{}, Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	bind := hub.bind.(*udpBind)
	type family struct {
		network, loopback string
		// listener is the family's shared socket, and fragmenting the mode it fragments in
		listener    *udpSocket
		fragmenting int
		do          int
	}
	families := []family{
		{"udp4", "127.0.0.1", bind.v4, unix.IP_PMTUDISC_DONT, unix.IP_PMTUDISC_DO},
		{"udp6", "::1", bind.v6, unix.IPV6_PMTUDISC_WANT, unix.IPV6_PMTUDISC_DO},
	}
	// connected opens a pair to a peer of its own on the family's loopback and answers the mux and the pair's socket
	connected := func(f family) (*Mux, *udpSocket) {
		peer := listenPeer(t, f.network, f.loopback)
		at := peer.LocalAddr().(*net.UDPAddr)
		mux, err := hub.NewMux(at.IP, at.Port)
		if err != nil {
			t.Fatal(err)
		}
		socket := openNow(mux).socket.Load()
		if socket == nil {
			t.Fatalf("the pair to %s opened no socket", at)
		}
		return mux, (*socket).(*udpPair).socket
	}
	for i, fragmenting := range families {
		other := families[1-i]
		mux, first := connected(fragmenting)
		_, unmoved := connected(other)
		if err := mux.Fragment(true); err != nil {
			t.Fatal(err)
		}
		_, later := connected(fragmenting)
		for _, socket := range []*udpSocket{fragmenting.listener, first, later} {
			if got := discoveryMode(t, socket); got != fragmenting.fragmenting {
				t.Errorf("while a mux to %s fragments, a socket of its family is in mode %d, want %d", fragmenting.loopback, got, fragmenting.fragmenting)
			}
		}
		if got := discoveryMode(t, unmoved); got != other.do {
			t.Errorf("while a mux to %s fragments, a pair's socket of the other family is in mode %d, want %d", fragmenting.loopback, got, other.do)
		}
		if err := mux.Fragment(false); err != nil {
			t.Fatal(err)
		}
		for _, socket := range []*udpSocket{fragmenting.listener, first, later} {
			if got := discoveryMode(t, socket); got != fragmenting.do {
				t.Errorf("once the mux to %s stopped fragmenting, a socket of its family is in mode %d, want %d", fragmenting.loopback, got, fragmenting.do)
			}
		}
	}
}
