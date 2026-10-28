// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package client

import (
	"context"
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

	kernelexit "ranet3.com/pkgs/ranet3/internal/egress/kernel"
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/netnstest"
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

// carveTable is the mesh table's routes the leaf converges on under the lease, each as its kind and prefix: each overlay prefix
// a throw in place of its hold, and the peer inside the lease a route into the tun
var carveTable = []string{"throw 192.0.2.0/24", "throw 3fff::/20", "unicast 192.0.2.5/32", "unicast 3fff::5/128"}

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
	d := startExitDaemon(t, leaf)
	for _, family := range carveLease {
		d.node.Mesh.Routes.Set(netip.Prefix{}, family.peer, d.learned)
	}
	var held []string
	waitFor(t, rulesSettle, "the reconciler to throw the lease in place of the overlay's holds", func() bool {
		held = carveHeld(t, leaf)
		return slices.Equal(held, carveTable)
	})
	t.Logf("the mesh's table holds %v", held)

	for _, family := range []int{4, 6} {
		for name, address := range map[string]netip.Addr{"gateway": carveLease[family].gateway.Addr(), "neighbor": carveLease[family].neighbor.Addr()} {
			answered := 0
			waitFor(t, rulesSettle, fmt.Sprintf("the %s %s to answer", name, address), func() bool {
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
	// leaf's socket, and one forged from the mesh peer's source inside the lease is dropped and counted, in each family
	var border *kernelexit.BorderFilter
	if err := leaf.Do(func() (err error) {
		border, err = kernelexit.NewBorderFilter(d.node.config().Cap.Border, d.node.BorderRuntime())
		return err
	}); err != nil {
		t.Fatalf("start the border: %v", err)
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
		t.Fatalf("the border carves %v, want the lease in each family", carved)
	}
	var receiver *net.UDPConn
	if err := leaf.Do(func() (err error) {
		receiver, err = net.ListenUDP("udp", &net.UDPAddr{Port: carvePort})
		return err
	}); err != nil {
		t.Fatalf("listen on the leaf: %v", err)
	}
	t.Cleanup(func() { _ = receiver.Close() })
	before := map[int]uint64{4: borderDropped(t, leaf, border, "drop ipv4 source @carved4"), 6: borderDropped(t, leaf, border, "drop ipv6 source @carved6")}
	if err := far.Do(func() error {
		for _, family := range []int{4, 6} {
			lease := carveLease[family]
			for name, source := range map[string]netip.Addr{"gateway": lease.gateway.Addr(), "forged": lease.peer.Addr()} {
				if err := carveSend(source, lease.lease.Addr(), name+" "+source.String()); err != nil {
					return err
				}
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
	slices.Sort(delivered)
	if want := []string{"gateway " + carveLease[6].gateway.Addr().String(), "gateway " + carveLease[4].gateway.Addr().String()}; !slices.Equal(delivered, slices.Sorted(slices.Values(want))) {
		t.Errorf("the leaf's socket took %q, want the gateway's datagram in each family alone", delivered)
	}
	for _, family := range []int{4, 6} {
		spec := fmt.Sprintf("drop ipv%d source @carved%d", family, family)
		waitFor(t, rulesSettle, "the border to count the forged datagram on "+spec, func() bool { return borderDropped(t, leaf, border, spec) > before[family] })
	}
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
