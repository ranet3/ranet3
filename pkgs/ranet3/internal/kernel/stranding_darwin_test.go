// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package kernel

import (
	"net"
	"net/netip"
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/schema"
)

// Which sets of unscoped routes out of a tun cost a bound socket its route,
// measured rather than assumed, because schema.CapturesTheMachine's arm over
// the unspecified address is this table and nothing else.
//
// The rule the kernel applies: a socket bound with IP_BOUND_IF loses
// destination D exactly when the tun's unscoped routes best-match both D and
// the all-zeros address of D's family. The scoped lookup falls back to a
// longest-prefix match on the unspecified address and requires that answer to
// be on the bound interface, so the size of the covering prefix is beside the
// point: 0.0.0.0/24 takes the fallback away and 64.0.0.0/2 does not.
//
// A prefix length alone is the wrong predicate here, since 0.0.0.0/24 is
// longer than either floor and strands a bound socket as a default does.
func TestDarwinStrandsABoundSocketOnlyThroughTheZeroAddress(t *testing.T) {
	requireNetTest(t)
	mesh, _ := createUTUNWithFD(t)
	setInterfaceUp(t, mesh)
	device, err := net.InterfaceByName(mesh)
	if err != nil {
		t.Fatal(err)
	}
	host, _, err := lookupDefault(runningKernel{}, device.Index, netip.IPv4Unspecified())
	if err != nil {
		t.Skip(err)
	}
	// TEST-NET-1, which nothing on this machine routes specially.
	target := netip.MustParseAddr("192.0.2.1")
	if err := boundReach(host, target); err != nil {
		t.Skipf("a bound socket cannot reach %s before anything is installed: %v", target, err)
	}

	opened, err := newPlatform(
		Table{ID: DefaultTable, Proto: DefaultProtocol},
		Runtime{Interface: mesh, BoundUnderlay: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = opened.Close() })
	plat := opened.(*routePlatform)
	if plat.index == host {
		t.Skip("the test utun is the interface the host's own traffic leaves by")
	}
	if err := plat.AddAddr(prefix("198.51.100.1/24")); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		set     []string
		strands bool
	}{
		// Covers the target and the zero address: stranded.
		{[]string{"0.0.0.0/1", "128.0.0.0/1"}, true},
		{[]string{"0.0.0.0/1", "192.0.2.0/24"}, true},
		{[]string{"0.0.0.0/2", "64.0.0.0/2", "192.0.2.0/24"}, true},
		// The one a prefix length misses entirely: a /24 over the zero
		// address costs as much as half the space.
		{[]string{"0.0.0.0/24", "192.0.2.0/24"}, true},
		{[]string{"0.0.0.0/8", "192.0.2.0/24"}, true},
		// Covers the target and no zero address: the fallback survives.
		{[]string{"192.0.2.0/24"}, false},
		{[]string{"64.0.0.0/2", "192.0.2.0/24"}, false},
		{[]string{"128.0.0.0/1"}, false},
		// Covers the zero address and not the target, so the target's best
		// match is still the host's own route and no fallback is needed.
		{[]string{"0.0.0.0/1"}, false},
		{[]string{"0.0.0.0/2", "64.0.0.0/2"}, false},
	} {
		t.Run(strings.Join(test.set, " "), func(t *testing.T) {
			for _, one := range test.set {
				route := Route{Destination: prefix(one)}
				if err := plat.AddRoute(route); err != nil {
					t.Skipf("%s is held by another program on this host: %v", one, err)
				}
				t.Cleanup(func() { _ = plat.DelRoute(route) })
			}
			reachErr := boundReach(host, target)
			if test.strands && reachErr == nil {
				t.Errorf("a bound socket still reaches %s, so this set no longer needs the fallback", target)
			}
			if !test.strands && reachErr != nil {
				t.Errorf("a bound socket lost %s to a set covering no zero address: %v", target, reachErr)
			}
			// The predicate has to agree with the kernel: every set that
			// strands has a member the gate holds back, and holding those
			// back restores the fallback.
			held := false
			for _, one := range test.set {
				if schema.CapturesTheMachine(prefix(one), nil) {
					held = true
				}
			}
			if test.strands && !held {
				t.Error("the set strands a bound socket and the gate holds none of it back")
			}
		})
	}
}
