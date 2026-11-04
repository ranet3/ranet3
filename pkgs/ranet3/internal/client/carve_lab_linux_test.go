// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package client

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"sort"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/egress"
	kernelexit "ranet3.com/pkgs/ranet3/internal/egress/kernel"
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/netnstest"
	"ranet3.com/pkgs/ranet3/internal/netstack"
)

// carveLease is the leaf's lease on its uplink in one family, as wide as the overlay's prefix, and the far side's addresses in it:
// the gateway, a neighbor on the link, and an address of the overlay no node announces
var carveLease = map[int]struct{ lease, gateway, neighbor, unannounced, peer netip.Prefix }{
	4: {
		netip.MustParsePrefix("192.0.2.10/24"), netip.MustParsePrefix("192.0.2.254/24"), netip.MustParsePrefix("192.0.2.20/24"),
		netip.MustParsePrefix("192.0.2.99/24"), netip.MustParsePrefix("192.0.2.5/32"),
	},
	6: {
		netip.MustParsePrefix("3fff::10/20"), netip.MustParsePrefix("3fff::254/20"), netip.MustParsePrefix("3fff::20/20"),
		netip.MustParsePrefix("3fff::99/20"), netip.MustParsePrefix("3fff::5/128"),
	},
}

// carveHold is a prefix inside the lease in each family that the mesh's table holds unreachable
var carveHold = map[int]netip.Prefix{4: netip.MustParsePrefix("192.0.2.128/28"), 6: netip.MustParsePrefix("3fff::8000/116")}

// carveTable is the mesh table's routes the leaf converges on under the lease, each as its kind and prefix: each overlay prefix
// a throw in place of its hold, the peer inside the lease a route into the tun, and the held prefix inside it unreachable
var carveTable = []string{
	"throw 192.0.2.0/24", "throw 3fff::/20", "unicast 192.0.2.5/32", "unicast 3fff::5/128", "unreachable 192.0.2.128/28", "unreachable 3fff::8000/116",
}

// carveOther is the leaf's second link outside the mesh and the far end of it, in each family, from which a forger sends
var carveOther = map[int]struct{ leaf, far netip.Prefix }{
	4: {netip.MustParsePrefix("203.0.113.1/24"), netip.MustParsePrefix("203.0.113.2/24")},
	6: {netip.MustParsePrefix("2001:db8:c::1/64"), netip.MustParsePrefix("2001:db8:c::2/64")},
}

// a leaf whose uplink holds a lease as wide as the overlay in both families carves the lease out of the overlay:
// the gateway and a neighbor on the link answer the host's echo requests, a mesh peer inside the lease stays on the tun,
// an overlay address no node announces inside the lease leaves by the link, and the border takes the gateway's
// datagram from the link while it drops and counts one forged from the mesh peer's source
func TestTUNBorderKeepsAnOverlappingUplink(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("creating a tun needs root on linux")
	}
	leaf, far := netnstest.StartThread(t), netnstest.StartThread(t)
	rulesUplinkPair(t, leaf, far)
	if err := leaf.Do(func() error {
		netlink, err := netnstest.OpenNetlink()
		if err != nil {
			return err
		}
		defer netlink.Close()
		return netlink.AddAddresses(rulesUplink, carveLease[4].lease, carveLease[6].lease)
	}); err != nil {
		t.Fatalf("lease the leaf's uplink: %v", err)
	}
	if err := far.Do(func() error {
		netlink, err := netnstest.OpenNetlink()
		if err != nil {
			return err
		}
		defer netlink.Close()
		var addresses []netip.Prefix
		for _, family := range carveLease {
			addresses = append(addresses, family.gateway, family.neighbor, family.unannounced)
		}
		return netlink.AddAddresses(rulesFar, addresses...)
	}); err != nil {
		t.Fatalf("address the far side of the lease: %v", err)
	}
	other := netnstest.StartThread(t)
	carveOtherLink(t, leaf, other)
	d := startExitDaemon(t, leaf)
	for family, lease := range carveLease {
		d.node.Mesh.Routes.Set(netip.Prefix{}, lease.peer, d.learned)
		d.node.Mesh.Routes.Set(netip.Prefix{}, carveHold[family], netstack.Unreachable)
	}
	var held []string
	waitFor(t, convergeBudget, "the reconciler to throw the lease in place of the overlay's holds and look the overlay up in the mesh's table", func() bool {
		held = carveHeld(t, leaf)
		return slices.Equal(held, carveTable) && carveLooksUp(t, leaf)
	})
	t.Logf("the mesh's table holds %v", held)

	for _, family := range []int{4, 6} {
		for name, address := range map[string]netip.Addr{"gateway": carveLease[family].gateway.Addr(), "neighbor": carveLease[family].neighbor.Addr()} {
			answered := 0
			waitFor(t, convergeBudget, fmt.Sprintf("the %s %s to answer", name, address), func() bool {
				if err := leaf.Do(func() (err error) { answered, err = exitPing(address, exitPingBase+family); return err }); err != nil {
					t.Fatalf("ping the %s %s: %v", name, address, err)
				}
				return answered == exitPings
			})
		}
	}

	var tunCapture, farCapture int
	if err := leaf.Do(func() (err error) { tunCapture, err = openCapture(rulesTUN, labRetry); return err }); err != nil {
		t.Fatalf("capture the tun: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(tunCapture) })
	if err := far.Do(func() (err error) { farCapture, err = openCapture(rulesFar, labRetry); return err }); err != nil {
		t.Fatalf("capture the far end of the uplink: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(farCapture) })
	var probes []rulesProbe
	for _, family := range []int{4, 6} {
		probes = append(probes,
			rulesProbe{carveLease[family].peer.Addr(), rulesUnbound, rulesIntoTun, 0},
			rulesProbe{carveLease[family].unannounced.Addr(), rulesUnbound, rulesOutUplink, 0})
	}
	var fds []int
	if err := leaf.Do(func() error {
		for i, p := range probes {
			fd, outcome, err := rulesSend(p, "udp", i+1)
			if err != nil {
				return err
			}
			if outcome != rulesSent {
				return fmt.Errorf("the probe to %s was %s", p.destination, outcome)
			}
			fds = append(fds, fd)
		}
		return nil
	}); err != nil {
		t.Fatalf("send the probes: %v", err)
	}
	intoTun, outUplink := rulesDrain(tunCapture), rulesDrain(farCapture)
	for _, fd := range fds {
		_ = unix.Close(fd)
	}
	for i, p := range probes {
		key := rulesKey{"udp", i + 1}
		_, tun := intoTun[key]
		_, uplink := outUplink[key]
		got := rulesNowhere
		switch {
		case tun && uplink:
			got = rulesSeveral
		case tun:
			got = rulesIntoTun
		case uplink:
			got = rulesOutUplink
		}
		if got != p.want {
			t.Errorf("udp to %s went %s, want %s", p.destination, got, p.want)
		}
	}

	// the border carves the lease out of the overlay's drops: the gateway's datagram from the leased link reaches the
	// leaf's socket, and one forged from the mesh peer's source, the held prefix's or this node's own inside the lease is
	// dropped and counted as carved, in each family. From the second link the lease's unannounced address meets the
	// overlay's drop, since the carve-out passes only from its own link, and the mesh peer's meets the carved drop first.
	var border *kernelexit.BorderFilter
	if err := leaf.Do(func() (err error) {
		border, err = kernelexit.NewBorderFilter(d.node.config().Border(), d.node.BorderRuntime())
		return err
	}); err != nil {
		t.Fatalf("start the antispoof filter: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = border.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	if carved := border.Stats().CarveOuts; len(carved) != 2 {
		t.Fatalf("the antispoof filter carves %v, want the lease in each family", carved)
	}
	var receiver *net.UDPConn
	if err := leaf.Do(func() (err error) {
		receiver, err = net.ListenUDP("udp", &net.UDPAddr{Port: carvePort})
		return err
	}); err != nil {
		t.Fatalf("listen on the leaf: %v", err)
	}
	t.Cleanup(func() { _ = receiver.Close() })
	overlayBefore := map[int]uint64{}
	for _, family := range []int{4, 6} {
		overlayBefore[family] = borderDropped(t, leaf, border, carveOverlayDrop(family))
	}
	if err := far.Do(func() error {
		for _, family := range []int{4, 6} {
			lease := carveLease[family]
			for name, source := range map[string]netip.Addr{
				"gateway": lease.gateway.Addr(), "forged": lease.peer.Addr(), "held": carveHold[family].Addr().Next(), "own": rulesHost[family].own.Addr(),
			} {
				if err := carveSend(source, lease.lease.Addr(), name+" "+source.String()); err != nil {
					return err
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("send to the leaf from the far side: %v", err)
	}
	if err := other.Do(func() error {
		for _, family := range []int{4, 6} {
			lease := carveLease[family]
			for name, source := range map[string]netip.Addr{"unannounced": lease.unannounced.Addr(), "forged": lease.peer.Addr()} {
				if err := carveSend(source, lease.lease.Addr(), "second link "+name+" "+source.String()); err != nil {
					return err
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("send to the leaf from the second link: %v", err)
	}
	var delivered []string
	buf := make([]byte, 256)
	if err := receiver.SetReadDeadline(time.Now().Add(labQuiet)); err != nil {
		t.Fatal(err)
	}
	for {
		n, _, err := receiver.ReadFromUDPAddrPort(buf)
		if err != nil {
			break
		}
		delivered = append(delivered, string(buf[:n]))
	}
	slices.Sort(delivered)
	if want := []string{"gateway " + carveLease[6].gateway.Addr().String(), "gateway " + carveLease[4].gateway.Addr().String()}; !slices.Equal(delivered, slices.Sorted(slices.Values(want))) {
		t.Errorf("the leaf's socket took %q, want the gateway's datagram in each family alone", delivered)
	}
	// the border's table is new and nothing sent before it carried a carved source: the peer's, the held prefix's and
	// this node's own from the leased link, and the peer's from the second link
	for _, family := range []int{4, 6} {
		spec := fmt.Sprintf("drop ipv%d source @carved%d", family, family)
		waitFor(t, convergeBudget, "the antispoof filter to count the 4 forged datagrams on "+spec, func() bool { return borderDropped(t, leaf, border, spec) >= 4 })
		overlay := carveOverlayDrop(family)
		waitFor(t, convergeBudget, "the antispoof filter to count the second link's unannounced lease address on "+overlay, func() bool {
			return borderDropped(t, leaf, border, overlay) > overlayBefore[family]
		})
	}
}

// carveOverlayDrop is the rule comment of the overlay's drop in family, 4 or 6
func carveOverlayDrop(family int) string {
	if family == 4 {
		return "drop ipv4 source " + rulesOverlay[0].String()
	}
	return "drop ipv6 source " + rulesOverlay[1].String()
}

// carveOtherLink makes a second link from the leaf's namespace to other's, outside the mesh and the overlay, with other's
// route to the lease's addresses through it
func carveOtherLink(t *testing.T, leaf, other *netnstest.Thread) {
	t.Helper()
	if err := leaf.Do(func() error {
		netlink, err := netnstest.OpenNetlink()
		if err != nil {
			return err
		}
		defer netlink.Close()
		if err := netlink.AddVeth("carx", "carf", 0, other.Path); err != nil {
			return fmt.Errorf("make the second link: %w", err)
		}
		return netlink.AddAddresses("carx", carveOther[4].leaf, carveOther[6].leaf)
	}); err != nil {
		t.Fatalf("make the leaf's end of the second link: %v", err)
	}
	if err := other.Do(func() error {
		netlink, err := netnstest.OpenNetlink()
		if err != nil {
			return err
		}
		defer netlink.Close()
		if err := netlink.AddAddresses("carf", carveOther[4].far, carveOther[6].far); err != nil {
			return err
		}
		link, err := net.InterfaceByName("carf")
		if err != nil {
			return err
		}
		for family, lease := range carveLease {
			if err := netlink.RouteVia(link.Index, netip.PrefixFrom(lease.lease.Addr(), lease.lease.Addr().BitLen()), carveOther[family].leaf.Addr()); err != nil {
				return fmt.Errorf("route the lease's address through the second link: %w", err)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("make the far end of the second link: %v", err)
	}
}

// carvePointToPoint is a PPPoE uplink's addresses in the lab, the leaf's own outside the overlay and its gateway's inside it,
// and an address of the overlay off the link that a datagram from the far side forges
var carvePointToPoint = struct{ local, gateway, forged netip.Addr }{
	netip.MustParseAddr("198.51.100.9"), netip.MustParseAddr("192.0.2.254"), netip.MustParseAddr("192.0.2.5"),
}

// a leaf whose uplink is point to point, its gateway's address inside the overlay as a PPPoE peer's can be, carves the gateway
// alone: the mesh's table throws the gateway's host prefix, the border takes the gateway's datagram from the link, and it drops
// and counts one forged from another address of the overlay
func TestTUNBorderCarvesAPointToPointUplinksGateway(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("creating a tun needs root on linux")
	}
	leaf, far := netnstest.StartThread(t), netnstest.StartThread(t)
	rulesUplinkPair(t, leaf, far)
	p2p := carvePointToPoint
	if err := leaf.Do(func() error { return carvePeerAddress(rulesUplink, p2p.local, p2p.gateway) }); err != nil {
		t.Fatalf("address the leaf's end of the point-to-point uplink: %v", err)
	}
	if err := far.Do(func() error { return carvePeerAddress(rulesFar, p2p.gateway, p2p.local) }); err != nil {
		t.Fatalf("address the gateway's end of the point-to-point uplink: %v", err)
	}
	d := startExitDaemon(t, leaf)
	gateway := netip.PrefixFrom(p2p.gateway, 32)
	waitFor(t, convergeBudget, "the reconciler to throw the gateway in place of the overlay's hold", func() bool {
		return slices.Contains(carveHeld(t, leaf), "throw "+gateway.String())
	})
	var border *kernelexit.BorderFilter
	if err := leaf.Do(func() (err error) {
		border, err = kernelexit.NewBorderFilter(d.node.config().Border(), d.node.BorderRuntime())
		return err
	}); err != nil {
		t.Fatalf("start the antispoof filter: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = border.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	waitFor(t, convergeBudget, "the antispoof filter to carve the gateway", func() bool {
		return slices.ContainsFunc(border.Stats().CarveOuts, func(c egress.CarveOut) bool { return c.Link == rulesUplink && c.Prefix == gateway })
	})
	var receiver *net.UDPConn
	if err := leaf.Do(func() (err error) {
		receiver, err = net.ListenUDP("udp4", &net.UDPAddr{Port: carvePort})
		return err
	}); err != nil {
		t.Fatalf("listen on the leaf: %v", err)
	}
	t.Cleanup(func() { _ = receiver.Close() })
	const overlayDrop = "drop ipv4 source 192.0.2.0/24"
	before := borderDropped(t, leaf, border, overlayDrop)
	if err := far.Do(func() error {
		for name, source := range map[string]netip.Addr{"gateway": p2p.gateway, "forged": p2p.forged} {
			if err := carveSend(source, p2p.local, name+" "+source.String()); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("send to the leaf from the far side: %v", err)
	}
	var delivered []string
	buf := make([]byte, 256)
	if err := receiver.SetReadDeadline(time.Now().Add(labQuiet)); err != nil {
		t.Fatal(err)
	}
	for {
		n, _, err := receiver.ReadFromUDPAddrPort(buf)
		if err != nil {
			break
		}
		delivered = append(delivered, string(buf[:n]))
	}
	if want := []string{"gateway " + p2p.gateway.String()}; !slices.Equal(delivered, want) {
		t.Errorf("the leaf's socket took %q, want the gateway's datagram alone", delivered)
	}
	waitFor(t, convergeBudget, "the antispoof filter to count the forged datagram on "+overlayDrop, func() bool { return borderDropped(t, leaf, border, overlayDrop) > before })
}

// carvePeerAddress gives the link name the address local with peer at its far end, as pppd addresses a PPPoE link: IFA_LOCAL
// is the host's own and IFA_ADDRESS the peer's, a host prefix the kernel routes by the link
func carvePeerAddress(name string, local, peer netip.Addr) error {
	link, err := net.InterfaceByName(name)
	if err != nil {
		return err
	}
	netlink, err := netnstest.OpenNetlink()
	if err != nil {
		return err
	}
	defer netlink.Close()
	header := []byte{unix.AF_INET, 32, unix.IFA_F_NODAD, unix.RT_SCOPE_UNIVERSE, 0, 0, 0, 0}
	binary.NativeEndian.PutUint32(header[4:], uint32(link.Index))
	return netlink.Request(unix.RTM_NEWADDR, unix.NLM_F_CREATE|unix.NLM_F_EXCL,
		slices.Concat(header, netnstest.Attr(unix.IFA_LOCAL, local.AsSlice()), netnstest.Attr(unix.IFA_ADDRESS, peer.AsSlice())))
}

// carvePort is the leaf's port the far side sends to through the carve-out
const carvePort = 4790

// carveSend sends payload over UDP from source, which the host need not hold, to destination's carvePort. A transparent
// socket's route lookup takes any source, where one that only binds freely is refused one the host does not hold.
func carveSend(source, destination netip.Addr, payload string) error {
	config := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		var err error
		if control := raw.Control(func(fd uintptr) {
			if source.Is4() {
				err = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TRANSPARENT, 1)
			} else {
				err = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_TRANSPARENT, 1)
			}
		}); control != nil {
			return control
		}
		return err
	}}
	conn, err := config.ListenPacket(context.Background(), "udp", netip.AddrPortFrom(source, 0).String())
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.WriteTo([]byte(payload), net.UDPAddrFromAddrPort(netip.AddrPortFrom(destination, carvePort)))
	return err
}

// carveHeld is the routes of the reconciler's protocol in the mesh's table on the leaf, each as its kind and prefix, sorted
func carveHeld(t *testing.T, leaf *netnstest.Thread) []string {
	t.Helper()
	var routes []kernelRoute
	if err := leaf.Do(func() (err error) { routes, err = dumpRoutes(); return err }); err != nil {
		t.Fatalf("read the leaf's routes: %v", err)
	}
	kinds := map[uint8]string{unix.RTN_UNICAST: "unicast", unix.RTN_UNREACHABLE: "unreachable", unix.RTN_THROW: "throw"}
	var out []string
	for _, route := range routes {
		if route.table == kernel.DefaultTable && route.protocol == kernel.DefaultProtocol {
			kind, ok := kinds[route.kind]
			if !ok {
				kind = fmt.Sprintf("type %d", route.kind)
			}
			out = append(out, kind+" "+route.destination.String())
		}
	}
	sort.Strings(out)
	return out
}

// carveLooksUp reports whether the leaf holds the reconciler's rule at 5110 for each overlay prefix, looking it up in the mesh's
// table, without which main sends a mesh peer inside the lease out of the uplink
func carveLooksUp(t *testing.T, leaf *netnstest.Thread) bool {
	t.Helper()
	var rules []kernelRule
	if err := leaf.Do(func() (err error) { rules, err = dumpRules(); return err }); err != nil {
		t.Fatalf("read the leaf's rules: %v", err)
	}
	for _, prefix := range rulesOverlay {
		if !slices.ContainsFunc(rules, func(rule kernelRule) bool {
			return rule.protocol == kernel.DefaultProtocol && rule.priority == 5110 && rule.table == kernel.DefaultTable && rule.destination.String() == prefix.String()
		}) {
			return false
		}
	}
	return true
}
