// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package egresstest

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"testing"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/netnstest"
	"ranet3.com/pkgs/ranet3/internal/netstack"
)

// plan is the Linux network's prefixes in one family
type plan struct {
	name string
	// leaf is the leaf's prefix on its tun, mesh the exit's on the mesh's tun,
	// uplink the exit's on its uplink and class the address it holds beside it
	leaf, mesh, uplink, class netip.Prefix
	// up, far and narrow are the router's prefixes on its links to the exit
	// and to the server, farEnd and narrowEnd the server's ends of the last
	// two, and served the addresses the server holds behind them
	up, far, narrow   netip.Prefix
	farEnd, narrowEnd netip.Prefix
	served            [3]netip.Prefix
	// classes and serving are the prefixes the router routes to the exit's
	// class address and to the server's addresses
	classes, serving netip.Prefix
	// noHost sits on the router's link to the server where nothing holds it,
	// and noNetwork in nothing the router routes
	noHost, noNetwork netip.Addr
}

var plans = [2]plan{
	{
		name: "ipv4",
		leaf: netip.MustParsePrefix("192.0.2.2/24"), mesh: netip.MustParsePrefix("192.0.2.1/24"),
		uplink: netip.MustParsePrefix("198.51.100.1/28"), class: netip.MustParsePrefix("198.51.100.17/32"),
		up: netip.MustParsePrefix("198.51.100.2/28"), far: netip.MustParsePrefix("203.0.113.1/28"), narrow: netip.MustParsePrefix("203.0.113.33/28"),
		farEnd: netip.MustParsePrefix("203.0.113.2/28"), narrowEnd: netip.MustParsePrefix("203.0.113.34/28"),
		served:  [3]netip.Prefix{netip.MustParsePrefix("203.0.113.17/32"), netip.MustParsePrefix("203.0.113.18/32"), netip.MustParsePrefix("203.0.113.19/32")},
		classes: netip.MustParsePrefix("198.51.100.16/28"), serving: netip.MustParsePrefix("203.0.113.16/28"),
		noHost: netip.MustParseAddr("203.0.113.3"), noNetwork: netip.MustParseAddr("203.0.113.129"),
	},
	{
		name: "ipv6",
		leaf: netip.MustParsePrefix("3fff::2/64"), mesh: netip.MustParsePrefix("3fff::1/64"),
		uplink: netip.MustParsePrefix("2001:db8:1::1/64"), class: netip.MustParsePrefix("2001:db8:1:1::1/128"),
		up: netip.MustParsePrefix("2001:db8:1::2/64"), far: netip.MustParsePrefix("2001:db8:2::1/64"), narrow: netip.MustParsePrefix("2001:db8:4::1/64"),
		farEnd: netip.MustParsePrefix("2001:db8:2::2/64"), narrowEnd: netip.MustParsePrefix("2001:db8:4::2/64"),
		served:  [3]netip.Prefix{netip.MustParsePrefix("2001:db8:3::1/128"), netip.MustParsePrefix("2001:db8:3::2/128"), netip.MustParsePrefix("2001:db8:3::3/128")},
		classes: netip.MustParsePrefix("2001:db8:1:1::/64"), serving: netip.MustParsePrefix("2001:db8:3::/64"),
		noHost: netip.MustParseAddr("2001:db8:2::3"), noNetwork: netip.MustParseAddr("2001:db8:5::1"),
	},
}

func (p plan) family() Family {
	return Family{
		Name: p.name, Leaf: p.leaf.Addr(), Exit: []netip.Addr{p.mesh.Addr(), p.uplink.Addr(), p.class.Addr()},
		Uplink: p.uplink.Addr(), Class: p.class.Addr(),
		Server: p.served[0].Addr(), Transfer: p.served[1].Addr(), Second: p.served[2].Addr(),
		Router: p.up.Addr(), Narrow: p.narrowEnd.Addr(), NoHost: p.noHost, NoNetwork: p.noNetwork,
		MeshMTU: netstack.DefaultMTU, UplinkMTU: uplinkMTU, NarrowMTU: narrowMTU,
	}
}

// namespaces is the Linux network
type namespaces struct {
	leaf, exit, router, server *netnstest.Thread
	mesh                       *netstack.Mesh
	peer                       *netstack.Peer
	tun                        *os.File
	// read carries the leaf's packets from the tun's reader to the carrier,
	// until closed is
	read    chan []byte
	closed  chan struct{}
	running sync.WaitGroup

	mu   sync.Mutex
	back [][]byte
}

// Namespaces builds the Linux network in four network namespaces, each new and
// empty and held by a thread of its own. The mesh routes the leaf's addresses
// to a peer whose session writes what it carries into the leaf's tun.
func Namespaces(t testing.TB) Network {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("creating a tun needs root on linux")
	}
	n := &namespaces{
		leaf: netnstest.StartThread(t), exit: netnstest.StartThread(t), router: netnstest.StartThread(t), server: netnstest.StartThread(t),
		read: make(chan []byte, carryQueue), closed: make(chan struct{}),
	}
	t.Cleanup(n.close)
	for _, step := range []struct {
		what  string
		where *netnstest.Thread
		do    func(netnstest.Netlink) error
	}{
		{"give the exit's links their addresses at once", n.exit, atOnce},
		{"give the router's links their addresses at once", n.router, atOnce},
		{"give the server's links their addresses at once", n.server, atOnce},
		{"have the router pass on what the exit leaves untranslated", n.router, passUntranslated},
		{"make the exit's uplink and the mesh's tun", n.exit, n.makeExit},
		{"make the router's links to the server", n.router, n.makeRouter},
		{"make the leaf's tun", n.leaf, n.makeLeaf},
		{"address the exit", n.exit, n.addressExit},
		{"address the router", n.router, n.addressRouter},
		{"address the server", n.server, n.addressServer},
		{"address the leaf", n.leaf, n.addressLeaf},
		{"route the exit", n.exit, n.routeExit},
		{"route the router", n.router, n.routeRouter},
		{"route the server", n.server, n.routeServer},
		{"route the leaf", n.leaf, n.routeLeaf},
	} {
		if err := step.where.Do(func() error {
			netlink, err := netnstest.OpenNetlink()
			if err != nil {
				return err
			}
			defer netlink.Close()
			return step.do(netlink)
		}); err != nil {
			t.Fatalf("%s: %v", step.what, err)
		}
	}
	n.peer = netstack.NewPeer("example/leaf", func(int) (netstack.BatchSealer, error) { return seal, nil }, n.transmit, nil)
	for _, p := range plans {
		n.mesh.Routes.Set(netip.Prefix{}, host(p.leaf), n.peer)
	}
	n.running.Go(n.readLeaf)
	return n
}

func (n *namespaces) Family(v6 bool) Family {
	if v6 {
		return plans[1].family()
	}
	return plans[0].family()
}

func (n *namespaces) Exit() Host {
	members := []netip.Prefix{host(plans[0].leaf), host(plans[1].leaf)}
	return Host{
		Do: n.exit.Do, TUN: n.mesh.Name, Write: n.mesh.WriteHost,
		Mesh:    []netip.Addr{plans[0].mesh.Addr(), plans[1].mesh.Addr()},
		Members: func() []netip.Prefix { return slices.Clone(members) },
	}
}

func (n *namespaces) Leaf(f func() error) error { return n.leaf.Do(f) }

func (n *namespaces) Server(f func() error) error { return n.server.Do(f) }

func (n *namespaces) Carry(hand func(packets [][]byte)) {
	n.running.Go(func() {
		for {
			var batch [][]byte
			select {
			case packet := <-n.read:
				batch = append(batch, packet)
			case <-n.closed:
				return
			}
		waiting:
			for len(batch) < carryBatch {
				select {
				case packet := <-n.read:
					batch = append(batch, packet)
				default:
					break waiting
				}
			}
			hand(batch)
		}
	})
}

func (n *namespaces) Back() [][]byte {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.back[:len(n.back):len(n.back)]
}

// readLeaf reads the leaf's tun and passes on each packet from one of the
// leaf's own addresses, which a mesh carries, and none its stack sends from a
// link-local or unspecified source, which stays on the link
func (n *namespaces) readLeaf() {
	buf := make([]byte, readSize)
	for {
		size, err := n.tun.Read(buf)
		if err != nil {
			return
		}
		p, ok := parse(buf[:size])
		if !ok || p.src != plans[0].leaf.Addr() && p.src != plans[1].leaf.Addr() {
			continue
		}
		select {
		case n.read <- slices.Clone(buf[:size]):
		case <-n.closed:
			return
		}
	}
}

// transmit is the leaf's session sending what the mesh handed it, which comes
// back into the leaf's tun as a session's delivery would
func (n *namespaces) transmit(sealed [][]byte) error {
	n.mu.Lock()
	n.back = append(n.back, sealed...)
	n.mu.Unlock()
	for _, packet := range sealed {
		// a write the closing tun refuses is a packet no row reads any more
		_, _ = n.tun.Write(packet)
	}
	return nil
}

// seal carries the mesh's packets as they are, each copied out of the buffer
// the tun read it into
func seal(raw [][]byte, _ []byte, reuse [][]byte) ([][]byte, error) {
	sealed := reuse[:0]
	for _, packet := range raw {
		sealed = append(sealed, slices.Clone(packet))
	}
	return sealed, nil
}

// close stops the reader and the carrier, then the mesh and the leaf's peer
func (n *namespaces) close() {
	close(n.closed)
	if n.tun != nil {
		_ = n.tun.Close()
	}
	n.running.Wait()
	if n.mesh != nil {
		n.mesh.Close()
	}
	if n.peer != nil {
		n.peer.Close()
	}
}

func (n *namespaces) makeExit(netlink netnstest.Netlink) error {
	if err := forward(); err != nil {
		return err
	}
	if err := netlink.AddVeth(exitUplink, routerUplink, uplinkMTU, n.router.Path); err != nil {
		return fmt.Errorf("make %s: %w", exitUplink, err)
	}
	mesh, err := netstack.NewNamed(netstack.DefaultMTU, meshLink, nil)
	if err != nil {
		return err
	}
	n.mesh = mesh
	return nil
}

func (n *namespaces) makeRouter(netlink netnstest.Netlink) error {
	if err := forward(); err != nil {
		return err
	}
	if err := netlink.AddVeth(routerFar, serverFar, 0, n.server.Path); err != nil {
		return fmt.Errorf("make %s: %w", routerFar, err)
	}
	if err := netlink.AddVeth(routerNarrow, serverNarrow, narrowMTU, n.server.Path); err != nil {
		return fmt.Errorf("make %s: %w", routerNarrow, err)
	}
	return nil
}

// makeLeaf makes the leaf's tun, which hands its reader each packet whole
func (n *namespaces) makeLeaf(netnstest.Netlink) error {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	ifr, err := unix.NewIfreq(leafLink)
	if err == nil {
		ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
		err = unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr)
	}
	if err != nil {
		_ = unix.Close(fd)
		return fmt.Errorf("make %s: %w", leafLink, err)
	}
	n.tun = os.NewFile(uintptr(fd), leafLink)
	link, err := net.InterfaceByName(leafLink)
	if err != nil {
		return err
	}
	return netnstest.SetLinkMTU(link.Index, netstack.DefaultMTU)
}

func (n *namespaces) addressExit(netlink netnstest.Netlink) error {
	for _, p := range plans {
		for link, prefix := range map[string]netip.Prefix{n.mesh.Name: p.mesh, exitUplink: p.uplink, "lo": p.class} {
			if err := netlink.AddAddresses(link, prefix); err != nil {
				return err
			}
		}
	}
	return nil
}

// addressRouter addresses the router's links, and has its link to the server
// give up on an address nothing answers for after one probe
func (n *namespaces) addressRouter(netlink netnstest.Netlink) error {
	for _, family := range []string{"ipv4", "ipv6"} {
		for setting, value := range map[string]string{"mcast_solicit": neighborProbes, "retrans_time_ms": neighborRetransmit} {
			if err := os.WriteFile("/proc/sys/net/"+family+"/neigh/"+routerFar+"/"+setting, []byte(value), 0o644); err != nil {
				return err
			}
		}
	}
	for _, p := range plans {
		for link, prefix := range map[string]netip.Prefix{routerUplink: p.up, routerFar: p.far, routerNarrow: p.narrow} {
			if err := netlink.AddAddresses(link, prefix); err != nil {
				return err
			}
		}
	}
	return nil
}

func (n *namespaces) addressServer(netlink netnstest.Netlink) error {
	for _, p := range plans {
		if err := netlink.AddAddresses(serverFar, p.farEnd); err != nil {
			return err
		}
		if err := netlink.AddAddresses(serverNarrow, p.narrowEnd); err != nil {
			return err
		}
		if err := netlink.AddAddresses("lo", p.served[:]...); err != nil {
			return err
		}
	}
	return nil
}

func (n *namespaces) addressLeaf(netlink netnstest.Netlink) error {
	for _, p := range plans {
		if err := netlink.AddAddresses(leafLink, p.leaf); err != nil {
			return err
		}
	}
	return nil
}

// routeExit routes everything out of the uplink, as an exit does
func (n *namespaces) routeExit(netlink netnstest.Netlink) error {
	for _, p := range plans {
		if err := via(netlink, exitUplink, every(p.uplink), p.up.Addr()); err != nil {
			return err
		}
	}
	return nil
}

// routeRouter routes the exit's class addresses to the exit and the server's
// addresses to the server, and nothing else beyond its own links
func (n *namespaces) routeRouter(netlink netnstest.Netlink) error {
	for _, p := range plans {
		if err := via(netlink, routerUplink, p.classes, p.uplink.Addr()); err != nil {
			return err
		}
		if err := via(netlink, routerFar, p.serving, p.farEnd.Addr()); err != nil {
			return err
		}
	}
	return nil
}

func (n *namespaces) routeServer(netlink netnstest.Netlink) error {
	for _, p := range plans {
		if err := via(netlink, serverFar, every(p.farEnd), p.far.Addr()); err != nil {
			return err
		}
	}
	return nil
}

// routeLeaf routes everything into the leaf's tun, toward the exit
func (n *namespaces) routeLeaf(netlink netnstest.Netlink) error {
	for _, p := range plans {
		if err := via(netlink, leafLink, every(p.leaf), p.mesh.Addr()); err != nil {
			return err
		}
	}
	return nil
}

// via routes to through gateway on the link name
func via(netlink netnstest.Netlink, name string, to netip.Prefix, gateway netip.Addr) error {
	link, err := net.InterfaceByName(name)
	if err != nil {
		return err
	}
	if err := netlink.RouteVia(link.Index, to, gateway); err != nil {
		return fmt.Errorf("route %s through %s on %s: %w", to, gateway, name, err)
	}
	return nil
}

// atOnce has every link made here from now on skip duplicate address
// detection. While a link's link-local address is still tentative, the kernel
// sends no neighbor solicitation for a packet it forwards out of that link,
// which would hold back or drop the first packets of a flow.
func atOnce(netnstest.Netlink) error {
	return os.WriteFile("/proc/sys/net/ipv6/conf/default/accept_dad", []byte("0\n"), 0o644)
}

// passUntranslated turns IPv4's reverse path filter off for every link made
// here from now on. A namespace starts with the host's IPv4 settings, and a
// filter on the router would drop a packet from the leaf's own address, which
// it routes nowhere, so a packet the exit left untranslated would never reach
// the server to be seen. IPv6 has no such filter.
func passUntranslated(netnstest.Netlink) error {
	for _, conf := range []string{"all", "default"} {
		if err := os.WriteFile("/proc/sys/net/ipv4/conf/"+conf+"/rp_filter", []byte("0\n"), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// forward turns forwarding on in both families
func forward() error {
	for _, path := range []string{"/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv6/conf/all/forwarding"} {
		if err := os.WriteFile(path, []byte("1\n"), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// host is prefix's address alone
func host(prefix netip.Prefix) netip.Prefix {
	return netip.PrefixFrom(prefix.Addr(), prefix.Addr().BitLen())
}

// every is the default of prefix's family
func every(prefix netip.Prefix) netip.Prefix {
	if prefix.Addr().Is4() {
		return netip.PrefixFrom(netip.IPv4Unspecified(), 0)
	}
	return netip.PrefixFrom(netip.IPv6Unspecified(), 0)
}
