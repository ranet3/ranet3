// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package client

import (
	"fmt"
	"math"
	"net"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/esp"
	"ranet3.com/pkgs/ranet3/internal/netnstest"
	"ranet3.com/pkgs/ranet3/internal/netstack"
)

const (
	// holeLink is alpha's link.mtu, a jumbo session whose datagrams the near end of the veth pair carries whole
	holeLink = 8918
	// holeNear is the MTU of alpha's end of the veth pair
	holeNear = 9000
	// holeWire is the largest IPv4 packet bravo's end of the pair takes, and holeNarrowed the largest once the hole narrows
	holeWire     = 1400
	holeNarrowed = 1360
	// vlanSlack is the VLAN tag a veth takes past its MTU, which bravo's end leaves room for under holeWire
	vlanSlack = 4
	// holeProbeTimeout and holeConfirm are both nodes' probe timeout and confirmation interval
	// an Ack crosses both nodes and back well within a second on a loaded machine, a lost size costs three, and a session carrying data confirms its budget twice a second
	holeProbeTimeout = time.Second
	holeConfirm      = 500 * time.Millisecond
	// holePort is each node's IKE and ESP port, free in a namespace of its own, and streamPort the one bravo's end of the stream listens on
	holePort   = 4500
	streamPort = 7000
	// streamChunk is the size of one write of the stream, and streamFlowing the bytes a stream carries to count as flowing
	streamChunk   = 64 << 10
	streamFlowing = 1 << 20
	// streamWait bounds each wait for the stream or the budget once the stream runs
	streamWait = 60 * time.Second
	// handoverMTU is the MTU of the dummy link a session moves across under the floor
	// a path of it is under the floor in either family
	handoverMTU = 1300
	// narrowedLoopback is the MTU loopback narrows to under a session's budget of DefaultMTU
	narrowedLoopback = 1360
)

var (
	// holeAlpha and holeBravo are the addresses of alpha's and bravo's ends of the veth pair
	holeAlpha = netip.MustParsePrefix("192.0.2.1/24")
	holeBravo = netip.MustParsePrefix("192.0.2.2/24")
	// alphaHost and bravoHost are each node's address in its own prefix, carried on its tun
	alphaHost = netip.MustParsePrefix("fd00:a::1/128")
	bravoHost = netip.MustParsePrefix("fd00:b::1/128")
)

// a TCP stream keeps flowing through a black hole the search finds, at link.mtu 8918 over a path that drops IPv4 packets past 1400 bytes and answers nothing
// alpha's session starts at 1400, loses the probe confirming it and settles at inner(1400) before any data flows
// then the hole narrows to 1360 under a stream, and the confirmations the stream's data brings move the budget to inner(1360) and the stream goes on
// alpha holds the test's network namespace and bravo one of its own, joined by a veth pair whose far end drops what it cannot take
// a veth passes a segmented send whole whatever the size of its segments, so the near end takes one segment at a time and linux cuts a segmented send into datagrams first
// the searches read their routes on threads outside both namespaces, where a read fails or names another path, and either leaves the target past what the hole carries
func TestTUNStreamKeepsFlowingThroughABlackHole(t *testing.T) {
	netnstest.EnterEmpty(t)
	far := netnstest.StartThread(t)
	alpha, bravo, farLink := newHoleMesh(t, far)
	t.Cleanup(func() { t.Logf("alpha's search: %q", searchRecord(alpha.events)) })
	run(t, alpha, bravo)
	waitFor(t, convergeBudget, "alpha forwarding to bravo's prefix and bravo to alpha's", func() bool {
		found, verdict, _ := alpha.client.Mesh.Routes.Resolve(netip.Addr{}, bravoHost.Addr())
		back, backVerdict, _ := bravo.client.Mesh.Routes.Resolve(netip.Addr{}, alphaHost.Addr())
		return verdict == netstack.RoutePeer && found != nil && backVerdict == netstack.RoutePeer && back != nil
	})
	// looked up on every poll, since a simultaneous open replaces the first session and its peer with it
	settledAt := func(mtu int) func() bool {
		return func() bool {
			found, verdict, _ := alpha.client.Mesh.Routes.Resolve(netip.Addr{}, bravoHost.Addr())
			return verdict == netstack.RoutePeer && found != nil && found.MTU() == mtu
		}
	}
	settled := esp.Inner(holeWire, 20)
	waitFor(t, convergeBudget, fmt.Sprintf("alpha's session to bravo to settle at %d", settled), settledAt(settled))

	var listener net.Listener
	if err := far.Do(func() (err error) {
		listener, err = net.Listen("tcp6", netip.AddrPortFrom(bravoHost.Addr(), streamPort).String())
		return err
	}); err != nil {
		t.Fatalf("listen on bravo's end of the stream: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	var arrived atomic.Int64
	total := make(chan int64, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, streamChunk)
		for {
			n, err := conn.Read(buf)
			arrived.Add(int64(n))
			if err != nil {
				total <- arrived.Load()
				return
			}
		}
	}()
	conn, err := net.DialTimeout("tcp6", netip.AddrPortFrom(bravoHost.Addr(), streamPort).String(), streamWait)
	if err != nil {
		t.Fatalf("dial bravo's end of the stream: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	var written atomic.Int64
	stop, wrote := make(chan struct{}), make(chan error, 1)
	go func() {
		chunk := make([]byte, streamChunk)
		for {
			select {
			case <-stop:
				wrote <- conn.(*net.TCPConn).CloseWrite()
				return
			default:
			}
			if err := conn.SetWriteDeadline(time.Now().Add(streamWait)); err != nil {
				wrote <- err
				return
			}
			n, err := conn.Write(chunk)
			written.Add(int64(n))
			if err != nil {
				wrote <- err
				return
			}
		}
	}()
	flowing := func(what string) {
		t.Helper()
		from := arrived.Load()
		waitFor(t, streamWait, what, func() bool { return arrived.Load() >= from+streamFlowing })
	}
	flowing("the stream to carry a mebibyte through the hole")

	if err := far.Do(func() error { return netnstest.SetLinkMTU(farLink, holeNarrowed-vlanSlack) }); err != nil {
		t.Fatalf("narrow the hole: %v", err)
	}
	narrowed := esp.Inner(holeNarrowed, 20)
	waitFor(t, streamWait, fmt.Sprintf("alpha's session to bravo to settle at %d under the stream", narrowed), settledAt(narrowed))
	flowing("the stream to carry another mebibyte through the narrowed hole")
	close(stop)
	if err := <-wrote; err != nil {
		t.Fatalf("the stream's writer stopped on %v", err)
	}
	select {
	case got := <-total:
		if got != written.Load() {
			t.Errorf("the stream carried %d of the %d bytes written", got, written.Load())
		}
	case <-time.After(streamWait):
		t.Errorf("the stream's end had read %d of the %d bytes written and no end of it after %s", arrived.Load(), written.Load(), streamWait)
	}
}

// newHoleMesh builds alpha on a tun in the test's namespace and bravo on a tun in far's, joined by the veth pair holePair makes
// it returns the two nodes, not yet running, and the index of bravo's end of the pair
func newHoleMesh(t *testing.T, far *netnstest.Thread) (alpha, bravo *loopbackNode, farLink int) {
	t.Helper()
	nodes, private, reg := writeMesh(t, [2]uint16{holePort, holePort}, [2]string{holeAlpha.Addr().String(), holeBravo.Addr().String()})
	alpha, bravo = nodes[0], nodes[1]
	alpha.cfg.Link.MTU = holeLink

	alphaMesh, err := netstack.NewNamed(holeLink, "bhalpha", nil)
	if err != nil {
		t.Fatalf("open alpha's tun: %v", err)
	}
	t.Cleanup(alphaMesh.Close)
	var bravoMesh *netstack.Mesh
	if err := far.Do(func() (err error) {
		bravoMesh, err = netstack.NewNamed(0, "bhbravo", nil)
		return err
	}); err != nil {
		t.Fatalf("open bravo's tun: %v", err)
	}
	t.Cleanup(bravoMesh.Close)
	farLink = holePair(t, far, alphaMesh.Name, bravoMesh.Name)

	x := trust(t, reg)
	if alpha.client, err = newClient(alpha.cfg, private, x, alphaMesh, nil, alpha.events); err != nil {
		t.Fatalf("build alpha: %v", err)
	}
	if err := far.Do(func() (err error) {
		bravo.client, err = newClient(bravo.cfg, private, x, bravoMesh, nil, bravo.events)
		return err
	}); err != nil {
		alpha.client.Close()
		t.Fatalf("build bravo: %v", err)
	}
	for _, node := range []*loopbackNode{alpha, bravo} {
		node.client.probeTimeout, node.client.confirmEvery = holeProbeTimeout, holeConfirm
	}
	return alpha, bravo, farLink
}

// holePair makes the veth pair between the test's namespace and far's, alpha's end at holeNear and bravo's dropping IPv4 packets past holeWire
// alpha's end takes one segment at a time, and each end and each tun gets its address, each namespace a route to the other node's prefix through its tun
// it returns the index of bravo's end
func holePair(t *testing.T, far *netnstest.Thread, alphaTUN, bravoTUN string) int {
	t.Helper()
	other, err := unix.Open(far.Path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open bravo's namespace: %v", err)
	}
	defer unix.Close(other)
	peer := slices.Concat(netnstest.IfInfo(0, 0), netnstest.Attr(unix.IFLA_IFNAME, netnstest.CString("bhb")), netnstest.Attr(unix.IFLA_MTU, netnstest.U32(holeWire-vlanSlack)),
		netnstest.Attr(unix.IFLA_NET_NS_FD, netnstest.U32(uint32(other))))
	kind := slices.Concat(netnstest.Attr(unix.IFLA_INFO_KIND, netnstest.CString("veth")), netnstest.Attr(unix.IFLA_INFO_DATA, netnstest.Attr(netnstest.VethPeer, peer)))
	pair := slices.Concat(netnstest.IfInfo(0, 0), netnstest.Attr(unix.IFLA_IFNAME, netnstest.CString("bha")), netnstest.Attr(unix.IFLA_MTU, netnstest.U32(holeNear)),
		netnstest.Attr(unix.IFLA_GSO_MAX_SEGS, netnstest.U32(1)), netnstest.Attr(unix.IFLA_LINKINFO, kind))
	if err := addressEnds(func(netlink netnstest.Netlink) error {
		return netlink.Request(unix.RTM_NEWLINK, unix.NLM_F_CREATE|unix.NLM_F_EXCL, pair)
	}, "bha", holeAlpha, alphaTUN, alphaHost, bravoHost); err != nil {
		t.Fatalf("make and address alpha's end: %v", err)
	}
	var farLink int
	if err := far.Do(func() error {
		link, err := net.InterfaceByName("bhb")
		if err != nil {
			return err
		}
		farLink = link.Index
		return addressEnds(nil, "bhb", holeBravo, bravoTUN, bravoHost, alphaHost)
	}); err != nil {
		t.Fatalf("address bravo's end: %v", err)
	}
	return farLink
}

// addressEnds runs first, then gives the link named veth the address underlay and brings it up
// and gives the tun named tun the address host and a route to the prefix of the other node's address through it
// in the namespace of the calling thread
func addressEnds(first func(netnstest.Netlink) error, veth string, underlay netip.Prefix, tun string, host, other netip.Prefix) error {
	netlink, err := netnstest.OpenNetlink()
	if err != nil {
		return err
	}
	defer netlink.Close()
	if first != nil {
		if err := first(netlink); err != nil {
			return err
		}
	}
	for _, end := range []struct {
		name    string
		address netip.Prefix
	}{{veth, underlay}, {tun, host}} {
		link, err := net.InterfaceByName(end.name)
		if err != nil {
			return err
		}
		if err := netlink.AddAddress(link.Index, end.address); err != nil {
			return fmt.Errorf("add %s to %s: %w", end.address, end.name, err)
		}
		if end.name == tun {
			prefix := netip.PrefixFrom(other.Addr(), 64).Masked()
			if err := netlink.RouteThrough(link.Index, prefix); err != nil {
				return fmt.Errorf("route %s through %s: %w", prefix, end.name, err)
			}
		}
	}
	return nil
}

// IKE moves a session under the floor to an endpoint of the other family
// the session hands its fragmenting to that family
// the path to the new endpoint is under the floor too
// the old family's other muxes send with DF again
// the budget stays at the floor
// a dummy link at handoverMTU carries a prefix of each family
// the driver reads routes on whatever thread runs it
// the test holds the namespace kernelNamespace claims for the whole process
func TestSessionMovedUnderTheFloorHandsItsFragmentingOver(t *testing.T) {
	kernelNamespace(t)
	netlink, err := netnstest.OpenNetlink()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(netlink.Close)
	kind := netnstest.Attr(unix.IFLA_INFO_KIND, netnstest.CString("dummy"))
	link := slices.Concat(netnstest.IfInfo(0, 0), netnstest.Attr(unix.IFLA_IFNAME, netnstest.CString("narrow")), netnstest.Attr(unix.IFLA_MTU, netnstest.U32(handoverMTU)), netnstest.Attr(unix.IFLA_LINKINFO, kind))
	if err := netlink.Request(unix.RTM_NEWLINK, unix.NLM_F_CREATE|unix.NLM_F_EXCL, link); err != nil {
		t.Fatalf("make the dummy link: %v", err)
	}
	narrow, err := net.InterfaceByName("narrow")
	if err != nil {
		t.Fatal(err)
	}
	// the tests after it in the process find the namespace as the claim left it
	t.Cleanup(func() {
		if err := netlink.Request(unix.RTM_DELLINK, 0, netnstest.IfInfo(narrow.Index, 0)); err != nil {
			t.Errorf("delete the dummy link: %v", err)
		}
	})
	for _, address := range []string{"192.0.2.1/24", "2001:db8::1/64"} {
		if err := netlink.AddAddress(narrow.Index, netip.MustParsePrefix(address)); err != nil {
			t.Fatalf("add %s to the dummy link: %v", address, err)
		}
	}
	hub := loopbackHub(t)
	r := newPathRig(t, hub, "192.0.2.9:4500", 1500, esp.Inner(handoverMTU, 20), math.MaxInt)
	waitFor(t, pathWait, "the session under the floor to let IPv4 fragment", func() bool { return !r.mux.DontFragment() })
	neighbor, err := hub.NewMux(net.ParseIP("192.0.2.10"), 4500)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = neighbor.Close() })
	if neighbor.DontFragment() {
		t.Fatal("another IPv4 mux sends with DF while a session of the family stands under the floor")
	}
	other, err := hub.NewMux(net.ParseIP("2001:db8::9"), 4500)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = other.Close() })
	if mtu, err := other.PathMTU(); err != nil || esp.Inner(mtu, 40) >= floor {
		t.Fatalf("the path to %s reads %d, %v, want one under the floor", other.Endpoint(), mtu, err)
	}

	r.mux.AdoptEndpoint(other.Endpoint())
	r.driver.move()
	waitFor(t, pathWait, "the session's new IPv6 path to fragment", func() bool { return !r.mux.DontFragment() })
	waitFor(t, pathWait, "the IPv4 family to send with DF again", neighbor.DontFragment)
	if got := r.driver.peer.MTU(); got != floor {
		t.Errorf("the session moved under the floor carries %d, want the floor", got)
	}
}

// the refusal of a session's own data past a narrower route lowers the session's budget
// the session's peer sends through the driver's transmit
// the transmit hands the refusal to the search
// bravo's session to alpha settles at DefaultMTU over loopback
// loopback then narrows to narrowedLoopback
// data for alpha's prefix enters bravo's tun at the budget's size
// the sender reads the route a refusal reports on whatever thread runs it
// the test holds the namespace kernelNamespace claims for the whole process
func TestSessionLowersItsBudgetAtTheRefusalOfItsOwnData(t *testing.T) {
	kernelNamespace(t)
	mesh, err := netstack.NewNamed(0, "ownrefusal", nil)
	if err != nil {
		t.Fatalf("open bravo's tun: %v", err)
	}
	t.Cleanup(mesh.Close)
	alpha, bravo := newLoopbackMeshOn(t, mesh)
	run(t, alpha, bravo)
	waitFor(t, convergeBudget, fmt.Sprintf("bravo's session to alpha to settle at %d", netstack.DefaultMTU), func() bool {
		peer, verdict, _ := bravo.client.Mesh.Routes.Resolve(netip.Addr{}, alphaHost.Addr())
		return verdict == netstack.RoutePeer && peer != nil && peer.MTU() == netstack.DefaultMTU
	})

	netlink, err := netnstest.OpenNetlink()
	if err != nil {
		t.Fatal(err)
	}
	defer netlink.Close()
	tun, err := net.InterfaceByName(mesh.Name)
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.AddAddress(tun.Index, bravoHost); err != nil {
		t.Fatalf("add %s to bravo's tun: %v", bravoHost, err)
	}
	if err := netlink.RouteThrough(tun.Index, alpha.prefix); err != nil {
		t.Fatalf("route %s through bravo's tun: %v", alpha.prefix, err)
	}
	loopback, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := netnstest.SetLinkMTU(loopback.Index, narrowedLoopback); err != nil {
		t.Fatalf("narrow loopback: %v", err)
	}
	// the tests after it in the process find loopback as the claim left it
	t.Cleanup(func() {
		if err := netnstest.SetLinkMTU(loopback.Index, loopback.MTU); err != nil {
			t.Errorf("widen loopback again: %v", err)
		}
	})

	conn, err := net.DialUDP("udp6", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(alphaHost.Addr(), streamPort)))
	if err != nil {
		t.Fatalf("dial alpha's prefix through bravo's tun: %v", err)
	}
	defer conn.Close()
	// the payload of a UDP datagram whose IPv6 packet fills the budget
	datagram := make([]byte, netstack.DefaultMTU-40-8)
	refusal := fmt.Sprintf("%d to %d by refusal", netstack.DefaultMTU, esp.Inner(narrowedLoopback, 20))
	waitFor(t, pathWait, fmt.Sprintf("bravo's search to record %q", refusal), func() bool {
		_, _ = conn.Write(datagram)
		return slices.Contains(searchRecord(bravo.events), refusal)
	})
}
