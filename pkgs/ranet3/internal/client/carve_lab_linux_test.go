// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package client

import (
	"fmt"
	"net/netip"
	"os"
	"slices"
	"sort"
	"testing"

	"golang.org/x/sys/unix"

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
// and an overlay address no node announces inside the lease leaves by the link
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
