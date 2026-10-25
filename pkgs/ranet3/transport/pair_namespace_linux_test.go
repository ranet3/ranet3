// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package transport

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// pairAddresses are the near end's addresses, a kept one before a lost one for each family on the prefixes of farAddresses
// the first IPv4 address on a prefix is its primary, which linux keeps the prefix's route on
var pairAddresses = []netip.Prefix{
	netip.MustParsePrefix("192.0.2.3/24"), netip.MustParsePrefix("192.0.2.1/24"),
	netip.MustParsePrefix("2001:db8::3/64"), netip.MustParsePrefix("2001:db8::1/64"),
}

// the kernel hands a socket bound to one address on the listener's port and connected to a peer that peer's datagrams
// while a datagram from another peer to the same address and port reaches the listener
// a peer listens at the far end of a veth pair, in a network namespace of its own
//
// the listener holds the wildcard address and the connected socket one address, so the lookup meets the connected socket first
// __udp4_lib_lookup and __udp6_lib_lookup try the destination address's slot before the wildcard one, since 2.6.33
// where compute_score refuses a connected socket whose peer differs, which leaves the wildcard slot and the listener
// sharing the port needs SO_REUSEPORT on both sockets, which UDP has had since 3.9
func TestConnectedSocketReceivesItsPeerWhileTheListenerKeepsTheRest(t *testing.T) {
	far, _, _ := vethPair(t, 2, nearAddresses)
	listening, _, _, err := listenPacketBind(0, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listening.Close() })
	bind := listening.(*udpBind)
	for i, address := range farAddresses {
		peer, other := far.listeners[2*i], far.listeners[2*i+1]
		listener := bind.v4
		if address.Addr().Is6() {
			listener = bind.v6
		}
		remote := netip.AddrPortFrom(address.Addr(), uint16(peer.LocalAddr().(*net.UDPAddr).Port))
		socket, _, err := bind.connectPair(pairKey{remote: remote})
		if err != nil {
			t.Fatalf("connect a socket to %s: %v", remote, err)
		}
		t.Cleanup(func() { _ = socket.Close() })
		connected := socket.(*udpPair).socket.conn
		deliveredApart(t, connected, listener.conn, peer, other, address.Addr(), netip.AddrPortFrom(nearAddresses[i].Addr(), bind.port))
	}
}

// a pair connects only in its listener's network namespace and is refused from a thread in another
// a socket takes the network namespace of the thread that makes it, and openPair connects on whatever thread its goroutine has
// both namespaces here are new with loopback up, so without the check the connect from the other one would bind and connect there
func TestPairConnectsOnlyInItsListenersNamespace(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("making network namespaces needs root on linux")
	}
	runtime.LockOSThread()
	if err := loopbackNamespace(); err != nil {
		t.Fatal(err)
	}
	listening, _, _, err := listenPacketBind(0, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listening.Close() })
	bind := listening.(*udpBind)
	peer := listenPeer(t, "udp4", "127.0.0.1")
	key := pairKey{local: netip.MustParseAddr("127.0.0.1"), remote: peer.LocalAddr().(*net.UDPAddr).AddrPort()}
	type outcome struct {
		bound net.Addr
		err   error
	}
	other := make(chan outcome, 1)
	go func() {
		// never unlocked, so the runtime retires the thread with the goroutine
		runtime.LockOSThread()
		if err := loopbackNamespace(); err != nil {
			other <- outcome{err: err}
			return
		}
		socket, _, err := bind.connectPair(key)
		if err != nil {
			other <- outcome{err: err}
			return
		}
		defer socket.Close()
		other <- outcome{bound: pairConn(socket).LocalAddr()}
	}()
	if got := <-other; !errors.Is(got.err, errOtherNamespace) {
		t.Fatalf("a connect from a thread in another network namespace bound %v and answered %v, want %v", got.bound, got.err, errOtherNamespace)
	}
	socket, _, err := bind.connectPair(key)
	if err != nil {
		t.Fatalf("a connect from the listener's own network namespace failed: %v", err)
	}
	_ = socket.Close()
}

// loopbackNamespace moves the calling thread, which its caller locked, into a new and empty network namespace and brings its loopback up
func loopbackNamespace() error {
	if err := unshareEmptyNamespace(); err != nil {
		return err
	}
	netlink, err := openRouteNetlink()
	if err != nil {
		return err
	}
	defer netlink.close()
	// loopback is link 1 in every network namespace
	return netlink.configure(1, nil)
}

// a socket connected to a peer from an address the host then loses stops carrying the pair's datagrams
// which leave the shared socket from the kernel's choice of source
// linux refuses an IPv4 send from a source the host lost, which closes the socket at that send
// it sends on from a lost IPv6 source until the network watch's change closes the socket
// the families run in turn on the test's own goroutine, the one thread in the namespace
func TestPairSocketLeavesAnAddressTheHostLost(t *testing.T) {
	far, link, netlink := vethPair(t, 1, pairAddresses)
	index := link.Index
	hub, err := NewHub(":0", Underlay{}, Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	for i, address := range farAddresses {
		peer := far.listeners[i]
		kept, lost := pairAddresses[2*i].Addr(), pairAddresses[2*i+1]
		remote := netip.AddrPortFrom(address.Addr(), uint16(peer.LocalAddr().(*net.UDPAddr).Port))
		mux, err := hub.NewMuxTo(arrivedFrom(remote.String(), lost.Addr().String(), index))
		if err != nil {
			t.Fatal(err)
		}
		p := openNow(mux)
		if p.socket.Load() == nil {
			t.Fatalf("the pair from %s opened no socket", lost)
		}
		before, after := []byte("before"), []byte("after")
		if err := mux.SendESP(before); err != nil {
			t.Fatal(err)
		}
		if from, want := readFrom(t, peer, before), netip.AddrPortFrom(lost.Addr(), hub.port); from != want {
			t.Fatalf("the connected socket sent from %s, want %s", from, want)
		}
		if err := netlink.unconfigure(index, lost); err != nil {
			t.Fatalf("remove %s: %v", lost, err)
		}
		if lost.Addr().Is6() {
			// sent with no control message, which linux would refuse for naming the lost source
			meanwhile := []byte("meanwhile")
			if err := mux.SendESP(meanwhile); err != nil {
				t.Fatal(err)
			}
			if from, want := readFrom(t, peer, meanwhile), netip.AddrPortFrom(lost.Addr(), hub.port); from != want || p.socket.Load() == nil {
				t.Fatalf("before the network changed, a send after %s went arrived from %s, want %s on the pair's socket", lost, from, want)
			}
			hub.NetworkChanged()
		}
		if err := mux.SendESP(after); err != nil {
			t.Fatalf("a send after %s went failed: %v", lost, err)
		}
		if from, want := readFrom(t, peer, after), netip.AddrPortFrom(kept, hub.port); from != want {
			t.Fatalf("a send after %s went arrived from %s, want %s", lost, from, want)
		}
		if p.socket.Load() != nil {
			t.Fatalf("the socket connected from %s is still open", lost)
		}
	}
}

// a socket connected to a peer follows its family's path MTU discovery as the listener does, through a route locked at lockedPathMTU
// it sets DF, so linux refuses a datagram past the path rather than send it in fragments, and the pair keeps its socket
// the shared socket then refuses the datagram too, and the send reports the path
// while the family fragments the pair's socket sends that datagram in fragments, which the far end puts back together
// the hub's mark routes the far end through the locked route
func TestPairSocketFollowsItsFamilyAcrossALockedPath(t *testing.T) {
	far, _ := lockedFarEnd(t)
	hub, err := NewHub(":0", Underlay{}, Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	for i, address := range farAddresses {
		listener := far.listeners[i]
		at := listener.LocalAddr().(*net.UDPAddr)
		mux, err := hub.NewMux(address.Addr().AsSlice(), at.Port)
		if err != nil {
			t.Fatal(err)
		}
		p := openNow(mux)
		socket := p.socket.Load()
		if socket == nil {
			t.Fatalf("the pair to %s opened no socket", address.Addr())
		}
		// refused sends a datagram past the path on the pair's socket and then through the mux
		refused := func(when string) {
			t.Helper()
			datagram := make([]byte, 1400)
			if sent, kept, err := (*socket).transmit([][]byte{datagram}, mux.Endpoint()); sent != 0 || !kept || !errors.Is(err, unix.EMSGSIZE) {
				t.Errorf("%s, the pair's send past the path to %s answered %d sent, kept %v and %v, want EMSGSIZE and the pair kept", when, address.Addr(), sent, kept, err)
			}
			err := mux.SendESP(datagram)
			if report, ok := err.(*PathMTUError); !ok || *report != (PathMTUError{Endpoint: mux.Endpoint(), MTU: lockedPathMTU}) {
				t.Errorf("%s, a datagram past the path to %s answered %v, want the report of its %d byte path", when, address.Addr(), err, lockedPathMTU)
			}
			if p.socket.Load() != socket {
				t.Errorf("%s, the pair to %s lost its socket to a datagram past the path", when, address.Addr())
			}
		}
		refused("before the family fragments")
		if err := mux.Fragment(true); err != nil {
			t.Fatal(err)
		}
		datagram := sized(1400)[0]
		if sent, kept, err := (*socket).transmit([][]byte{datagram}, mux.Endpoint()); sent != 1 || !kept || err != nil {
			t.Errorf("while the family fragments, the pair's send past the path to %s answered %d sent, kept %v and %v", address.Addr(), sent, kept, err)
		}
		readFrom(t, listener, datagram)
		if err := mux.Fragment(false); err != nil {
			t.Fatal(err)
		}
		refused("once the family stopped fragmenting")
	}
	ipv4, ipv6, err := far.reassembled()
	if err != nil {
		t.Fatal(err)
	}
	if ipv4 != 1 || ipv6 != 1 {
		t.Errorf("the far end put %d IPv4 and %d IPv6 datagrams back together from fragments, want the 1 of each family sent while it fragmented", ipv4, ipv6)
	}
}

// reportedPathMTU is the path MTU the far end's forged ICMP errors report, the IPv6 floor and so a path either family takes
const reportedPathMTU = 1280

// a hop's report of a smaller path about a datagram a pair's socket sent, a fragmentation needed or a packet too big, leaves the pair its socket
// through the hub, the pair's reader meets the report, and a datagram the reported path carries then leaves the pair's socket
// one past it is refused there and on the shared socket alike, and the send reports the path
// a socket no reader drains hands the report to its next send, which goes past it with its datagram
// the far end forges each report from a raw socket in its namespace, so it arrives by the interface the pair sends by
func TestPairSocketKeepsItsPairPastAHopsPathReport(t *testing.T) {
	far, _, _ := vethPair(t, 2, nearAddresses)
	hub, err := NewHub(":0", Underlay{}, Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	bind := hub.bind.(*udpBind)
	for i, address := range farAddresses {
		local := netip.AddrPortFrom(nearAddresses[i].Addr(), hub.port)
		peer, other := far.listeners[2*i], far.listeners[2*i+1]
		at := func(listener *net.UDPConn) netip.AddrPort {
			return netip.AddrPortFrom(address.Addr(), uint16(listener.LocalAddr().(*net.UDPAddr).Port))
		}
		mux, err := hub.NewMux(address.Addr().AsSlice(), int(at(peer).Port()))
		if err != nil {
			t.Fatal(err)
		}
		p := openNow(mux)
		if p.socket.Load() == nil {
			t.Fatalf("the pair to %s opened no socket", at(peer))
		}
		if err := far.reportPath(local, at(peer), reportedPathMTU); err != nil {
			t.Fatal(err)
		}
		endpoint := mux.Endpoint().(*udpEndpoint)
		for deadline := time.Now().Add(arrivalBudget); ; time.Sleep(pairPoll) {
			if mtu, err := bind.pathMTU(endpoint); err == nil && mtu == reportedPathMTU {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("the route to %s never took the reported path of %d bytes", address.Addr(), reportedPathMTU)
			}
		}
		within := []byte("within the reported path")
		if err := mux.SendESP(within); err != nil {
			t.Fatalf("a datagram within the reported path to %s answered %v", address.Addr(), err)
		}
		readFrom(t, peer, within)
		err = mux.SendESP(make([]byte, reportedPathMTU))
		if report, ok := err.(*PathMTUError); !ok || *report != (PathMTUError{Endpoint: mux.Endpoint(), MTU: reportedPathMTU}) {
			t.Errorf("a datagram past the reported path to %s answered %v, want the report of its %d bytes", address.Addr(), err, reportedPathMTU)
		}
		if p.socket.Load() == nil || hub.PairFallbacks() != 0 {
			t.Fatalf("the report about a datagram to %s cost the pair its socket, or counted %d fallbacks", address.Addr(), hub.PairFallbacks())
		}

		socket, _, err := bind.connectPair(pairKey{remote: at(other)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = socket.Close() })
		if err := far.reportPath(local, at(other), reportedPathMTU); err != nil {
			t.Fatal(err)
		}
		awaitSocketError(t, pairConn(socket), "the forged report")
		if sent, kept, err := socket.transmit([][]byte{within}, dialed(at(other).String())); sent != 1 || !kept || err != nil {
			t.Fatalf("the send after the report to %s answered %d sent, kept %v and %v, want 1 sent and the pair kept", at(other), sent, kept, err)
		}
		readFrom(t, other, within)
	}
}

// pairNearLinkLocal and pairFarLinkLocal are link-local addresses the near and the far end of the veth pair hold beside their others
// and pairNearAside is an IPv6 address of the near end on a prefix a route of a lower metric takes over the dummy link
var (
	pairNearLinkLocal = netip.MustParsePrefix("fe80::1/64")
	pairFarLinkLocal  = netip.MustParsePrefix("fe80::2/64")
	pairNearAside     = netip.MustParsePrefix("2001:db8:1::1/64")
)

// pairAsideMetric is the metric of the route over the dummy link to pairNearAside's prefix, below the default of the one over the veth
const pairAsideMetric = 100

// a pair for a session its peer opened sends by the interface the shared socket's pinned reply leaves by
// a dummy link that carries nothing takes every other send to the far address
// IPv4 by a route more specific than the arrival interface's prefix, which a pinned reply passes over as it holds to the interface
// IPv6 by a route to the prefix ahead of the arrival interface's, of the same metric, which a pinned reply passes over for the one by its interface
// a link-local peer's pair binds its address on the arrival interface, which the pin names by index alone
// and where the dummy link's route to an IPv6 prefix has the lower metric, the pinned reply takes it and so does the pair
func TestPairSocketLeavesByTheInterfaceItsPeerArrivedOn(t *testing.T) {
	far, link, netlink := vethPairTo(t, 1, []netip.Prefix{nearAddresses[0], pairNearLinkLocal}, slices.Concat(farAddresses, []netip.Prefix{pairFarLinkLocal}))
	elsewhere, err := netlink.dummyLink("elsewhere")
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range []netip.Prefix{nearAddresses[1], pairNearAside} {
		if err := netlink.holdWithoutRoute(link.Index, address); err != nil {
			t.Fatalf("give the near end %s: %v", address, err)
		}
	}
	for _, route := range []struct {
		index  int
		to     netip.Prefix
		metric uint32
	}{
		{elsewhere, netip.PrefixFrom(farAddresses[0].Addr(), 32), 0},
		{elsewhere, nearAddresses[1].Masked(), 0},
		{link.Index, nearAddresses[1].Masked(), 0},
		{elsewhere, pairNearAside.Masked(), pairAsideMetric},
		{link.Index, pairNearAside.Masked(), 0},
	} {
		if err := netlink.routeOver(route.index, route.to, route.metric, unix.RT_TABLE_MAIN); err != nil {
			t.Fatalf("route %s over link %d: %v", route.to, route.index, err)
		}
	}
	hub, err := NewHub(":0", Underlay{}, Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	for _, arrival := range []struct {
		remote, local netip.Addr
		listener      *net.UDPConn
	}{
		{farAddresses[0].Addr(), nearAddresses[0].Addr(), far.listeners[0]},
		{farAddresses[1].Addr(), nearAddresses[1].Addr(), far.listeners[1]},
		{pairFarLinkLocal.Addr().WithZone(strconv.Itoa(link.Index)), pairNearLinkLocal.Addr(), far.listeners[1]},
	} {
		remote := netip.AddrPortFrom(arrival.remote, uint16(arrival.listener.LocalAddr().(*net.UDPAddr).Port))
		want := netip.AddrPortFrom(arrival.local, hub.port)
		mux, err := hub.NewMuxTo(arrivedFrom(remote.String(), arrival.local.String(), link.Index))
		if err != nil {
			t.Fatal(err)
		}
		reply := []byte("the shared socket's reply")
		if err := mux.SendESP(reply); err != nil {
			t.Fatalf("the shared socket's reply to %s answered %v", remote, err)
		}
		if from := readFrom(t, arrival.listener, reply); netip.AddrPortFrom(from.Addr().WithZone(""), from.Port()) != want {
			t.Fatalf("the shared socket's reply to %s arrived from %s, want %s", remote, from, want)
		}
		socket := openNow(mux).socket.Load()
		if socket == nil {
			t.Fatalf("the pair to %s opened no socket", remote)
		}
		sent := []byte("the pair's send")
		if n, kept, err := (*socket).transmit([][]byte{sent}, mux.Endpoint()); n != 1 || !kept || err != nil {
			t.Fatalf("the pair's send to %s answered %d sent, kept %v and %v", remote, n, kept, err)
		}
		if from := readFrom(t, arrival.listener, sent); netip.AddrPortFrom(from.Addr().WithZone(""), from.Port()) != want {
			t.Fatalf("the pair's send to %s arrived from %s, want %s", remote, from, want)
		}
	}

	remote := netip.AddrPortFrom(pairNearAside.Addr().Next(), uint16(far.listeners[1].LocalAddr().(*net.UDPAddr).Port))
	mux, err := hub.NewMuxTo(arrivedFrom(remote.String(), pairNearAside.Addr().String(), link.Index))
	if err != nil {
		t.Fatal(err)
	}
	before := linkSent(t, "elsewhere")
	if err := mux.SendESP([]byte("the shared socket's reply")); err != nil {
		t.Fatalf("the shared socket's reply to %s answered %v", remote, err)
	}
	if got := linkSent(t, "elsewhere") - before; got != 1 {
		t.Fatalf("the dummy link carried %d of the shared socket's replies to %s, want the 1 its route of the lower metric takes", got, remote)
	}
	socket := openNow(mux).socket.Load()
	if socket == nil {
		t.Fatalf("the pair to %s opened no socket", remote)
	}
	if n, kept, err := (*socket).transmit([][]byte{[]byte("the pair's send")}, mux.Endpoint()); n != 1 || !kept || err != nil {
		t.Fatalf("the pair's send to %s answered %d sent, kept %v and %v", remote, n, kept, err)
	}
	if got := linkSent(t, "elsewhere") - before; got != 2 {
		t.Fatalf("the dummy link carried %d of the reply and the pair's send to %s, want both", got, remote)
	}
}

// pairElsewhere are the dummy link's own addresses, one of each family in the order of farAddresses
var pairElsewhere = []netip.Prefix{netip.MustParsePrefix("198.51.100.1/24"), netip.MustParsePrefix("2001:db8:5::1/64")}

// a dialed pair binds the source of the route the underlay's mark selects, and its sends arrive from that source
// the main table routes each far address over a dummy link holding an address of its own, and only the mark's table over the veth
func TestPairBindsTheSourceOfTheRouteTheUnderlayMarkSelects(t *testing.T) {
	far, link, netlink := vethPair(t, 1, nearAddresses)
	elsewhere, err := netlink.dummyLink("elsewhere")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.configure(elsewhere, pairElsewhere); err != nil {
		t.Fatalf("configure the dummy link: %v", err)
	}
	for _, address := range farAddresses {
		to := netip.PrefixFrom(address.Addr(), address.Addr().BitLen())
		if err := netlink.steer(addressFamily(to.Addr()), markTable, 0, markRule); err != nil {
			t.Fatalf("route by the mark into table %d: %v", markTable, err)
		}
		if err := netlink.routeOver(link.Index, to, 0, markTable); err != nil {
			t.Fatalf("route %s over the veth in table %d: %v", to, markTable, err)
		}
		if err := netlink.routeOver(elsewhere, to, 0, unix.RT_TABLE_MAIN); err != nil {
			t.Fatalf("route %s over the dummy link: %v", to, err)
		}
	}
	hub, err := NewHub(":0", Underlay{}, Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	for i, address := range farAddresses {
		listener := far.listeners[i]
		mux, err := hub.NewMux(address.Addr().AsSlice(), listener.LocalAddr().(*net.UDPAddr).Port)
		if err != nil {
			t.Fatal(err)
		}
		socket := openNow(mux).socket.Load()
		if socket == nil {
			t.Fatalf("the pair to %s opened no socket", address.Addr())
		}
		want := netip.AddrPortFrom(nearAddresses[i].Addr(), hub.port)
		bound := pairConn(*socket).LocalAddr().(*net.UDPAddr).AddrPort()
		if got := netip.AddrPortFrom(bound.Addr().Unmap(), bound.Port()); got != want {
			t.Fatalf("the pair to %s is bound to %s, want %s rather than the dummy link's %s", address.Addr(), got, want, pairElsewhere[i].Addr())
		}
		sent := []byte("the pair's send")
		if n, kept, err := (*socket).transmit([][]byte{sent}, mux.Endpoint()); n != 1 || !kept || err != nil {
			t.Fatalf("the pair's send to %s answered %d sent, kept %v and %v", address.Addr(), n, kept, err)
		}
		if from := readFrom(t, listener, sent); from != want {
			t.Fatalf("the pair's send to %s arrived from %s, want %s", address.Addr(), from, want)
		}
	}
}

// linkSent is how many packets the link named name sent, read from this thread's network namespace
func linkSent(t *testing.T, name string) uint64 {
	t.Helper()
	text, err := os.ReadFile("/proc/thread-self/net/dev")
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.Lines(string(text)) {
		link, counters, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(link) != name {
			continue
		}
		// a link's line holds 8 received counters before the sent ones, the packets second among them
		fields := strings.Fields(counters)
		if len(fields) < 10 {
			break
		}
		sent, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		return sent
	}
	t.Fatalf("/proc/thread-self/net/dev counts nothing for %s", name)
	return 0
}

// holdWithoutRoute gives link index address without duplicate address detection and without the route to its prefix
func (n routeNetlink) holdWithoutRoute(index int, address netip.Prefix) error {
	header := []byte{addressFamily(address.Addr()), byte(address.Bits()), unix.IFA_F_NODAD, unix.RT_SCOPE_UNIVERSE, 0, 0, 0, 0}
	binary.NativeEndian.PutUint32(header[4:], uint32(index))
	raw := address.Addr().AsSlice()
	return n.request(unix.RTM_NEWADDR, unix.NLM_F_CREATE|unix.NLM_F_EXCL, slices.Concat(header, attribute(unix.IFA_LOCAL, raw), attribute(unix.IFA_ADDRESS, raw),
		attribute(unix.IFA_FLAGS, word(unix.IFA_F_NODAD|unix.IFA_F_NOPREFIXROUTE))))
}

// unconfigure takes address off link index
func (n routeNetlink) unconfigure(index int, address netip.Prefix) error {
	header := []byte{addressFamily(address.Addr()), byte(address.Bits()), 0, unix.RT_SCOPE_UNIVERSE, 0, 0, 0, 0}
	binary.NativeEndian.PutUint32(header[4:], uint32(index))
	raw := address.Addr().AsSlice()
	return n.request(unix.RTM_DELADDR, 0, slices.Concat(header, attribute(unix.IFA_LOCAL, raw), attribute(unix.IFA_ADDRESS, raw)))
}
