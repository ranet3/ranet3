// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package kernel

import (
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// coverProbeWait is how long a probe waits for its datagram on the tun.
const coverProbeWait = 300 * time.Millisecond

// No member contains its family's zero address, so by the rule
// TestDarwinStrandsABoundSocketOnlyThroughTheZeroAddress states a bound
// socket keeps the host's own default with nothing scoped to its interface.
var (
	measuredCover4 = []string{
		"1.0.0.0/8", "2.0.0.0/7", "4.0.0.0/6", "8.0.0.0/5",
		"16.0.0.0/4", "32.0.0.0/3", "64.0.0.0/2", "128.0.0.0/1",
	}
	measuredCover6 = []string{
		"100::/8", "200::/7", "400::/6", "800::/5",
		"1000::/4", "2000::/3", "4000::/2", "8000::/1",
	}
	measuredHole = []string{"0.1.2.3", "1::1", "64:ff9b::c000:201"}
)

// Every member goes in unscoped out of a test utun with no default scoped to
// the underlay interface. An unbound socket follows each member into the tun,
// a socket bound to the underlay still connects inside every member and its
// scoped lookup names the underlay, and the hole stays on the host's route.
func TestZMeasureTheZeroFreeCoverKeepsABoundSocket(t *testing.T) {
	requireNetTest(t)
	mesh, tun := createUTUNWithFD(t)
	setInterfaceUp(t, mesh)
	meshIndex := interfaceIndex(t, mesh)
	host4, gateway4, err := lookupDefault(runningKernel{}, meshIndex, netip.IPv4Unspecified())
	if err != nil {
		t.Skipf("this host has no IPv4 default to fall back on: %v", err)
	}
	host6 := hostDefault6(t, meshIndex)
	underlay := map[bool]int{true: host4, false: host6}
	t.Logf("IPv4 leaves by index %d via %s, IPv6 by index %d", host4, gateway4, host6)
	for is4, index := range underlay {
		if index == meshIndex {
			t.Fatal("the test utun is the interface the host's own traffic leaves by")
		}
		if scopedDefaultOn(t, index, is4) {
			t.Skipf("interface %d already carries a scoped default, so this measures nothing", index)
		}
	}
	before := defaultRoutesOnHost(t)

	plat := testTUNPlatform(t, mesh)
	if err := plat.AddAddr(prefix("198.51.100.1/24")); err != nil {
		t.Fatal(err)
	}
	if err := plat.AddAddr(prefix("2001:db8:bb::1/64")); err != nil {
		t.Fatal(err)
	}
	var members []netip.Prefix
	for _, one := range append(append([]string{}, measuredCover4...), measuredCover6...) {
		member := prefix(one)
		r := Route{Destination: member}
		if member.Addr().Is6() {
			r.Metric = defaultIPv6Metric
		}
		if err := plat.AddRoute(r); err != nil {
			t.Skipf("%s is held by another program on this host: %v", member, err)
		}
		t.Cleanup(func() { _ = plat.DelRoute(r) })
		members = append(members, member)
	}
	installed, err := plat.Routes()
	if err != nil {
		t.Fatal(err)
	}
	for _, member := range members {
		found := false
		for _, r := range installed {
			if r.Destination == member && !r.Scoped {
				found = true
			}
		}
		if !found {
			t.Errorf("the dump does not report %s installed unscoped: %v", member, installed)
		}
	}

	for _, member := range members {
		target := member.Addr().Next()
		index := underlay[target.Is4()]
		device, err := net.InterfaceByIndex(index)
		if err != nil {
			t.Fatal(err)
		}
		t.Run(member.String(), func(t *testing.T) {
			if !arrivesUnbound(t, tun, target) {
				t.Errorf("an unbound socket's datagram to %s did not go into the tun", target)
			}
			if err := boundConnect(index, target); err != nil {
				t.Errorf("a socket bound to %s cannot connect to %s: %v", device.Name, target, err)
			}
			if got := scopedLookup(t, device.Name, target); got != device.Name {
				t.Errorf("the lookup scoped to %s for %s names %q", device.Name, target, got)
			}
		})
	}

	for _, one := range measuredHole {
		target := netip.MustParseAddr(one)
		t.Run(one, func(t *testing.T) {
			answer, err := routeRequest(target, netip.Addr{})
			if err != nil {
				t.Fatalf("look up %s: %v", target, err)
			}
			if answer.Index != underlay[target.Is4()] {
				t.Errorf("%s leaves by index %d, want the host's own %d", target, answer.Index, underlay[target.Is4()])
			}
		})
	}

	if after := defaultRoutesOnHost(t); !sameDefaults(before, after) {
		t.Errorf("the host's default routes changed over the test\nbefore: %v\nafter:  %v", before, after)
	}
}

// hostDefault6 is the interface the host's unscoped ::/0 leaves by. A host
// with none gets one built on a second test utun, which goes away with the
// test.
func hostDefault6(t *testing.T, mesh int) int {
	t.Helper()
	rib, err := route.FetchRIB(unix.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		t.Fatal(err)
	}
	messages, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		t.Fatal(err)
	}
	if index, ok := unscopedDefaultIndex(messages, netip.PrefixFrom(netip.IPv6Unspecified(), 0)); ok && index != mesh {
		return index
	}
	uplink, _ := createUTUNWithFD(t)
	setInterfaceUp(t, uplink)
	if err := testTUNPlatform(t, uplink).AddAddr(prefix("2001:db8:aa::1/64")); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("route", "-n", "add", "-inet6", "-net", "::/0", "-interface", uplink).CombinedOutput()
	if err != nil {
		t.Skipf("this host will not take an unscoped ::/0: %v %s", err, out)
	}
	t.Cleanup(func() {
		if out, err := exec.Command("route", "-n", "delete", "-inet6", "-net", "::/0", "-interface", uplink).CombinedOutput(); err != nil {
			t.Errorf("the ::/0 this test added was left behind: %v %s", err, out)
		}
	})
	index := interfaceIndex(t, uplink)
	if !unscopedDefaultOn(t, index) {
		t.Skip("the ::/0 this test added was scoped by the kernel")
	}
	t.Logf("this host has no IPv6 default, so %s carries one for the test", uplink)
	return index
}

// scopedDefaultOn reports a default of one family scoped to that interface.
func scopedDefaultOn(t *testing.T, index int, is4 bool) bool {
	t.Helper()
	rib, err := route.FetchRIB(unix.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		t.Fatal(err)
	}
	messages, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		t.Fatal(err)
	}
	destination := defaultPrefixes[1]
	if is4 {
		destination = defaultPrefixes[0]
	}
	for _, message := range messages {
		rm, ok := message.(*route.RouteMessage)
		if ok && rm.Type == unix.RTM_GET && rm.Flags&unix.RTF_IFSCOPE != 0 && rm.Index == index && isDefaultKey(rm, destination) {
			return true
		}
	}
	return false
}

// arrivesUnbound sends one datagram from an unbound socket and reports whether
// it came out of the tun.
func arrivesUnbound(t *testing.T, tun int, target netip.Addr) bool {
	t.Helper()
	if target.Is4() {
		return reaches(t, tun, target, netip.Addr{}, 0)
	}
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("open a udp socket: %v", err)
	}
	defer unix.Close(fd)
	drainTUN(tun)
	if err := unix.Sendto(fd, []byte("cover probe"), 0, &unix.SockaddrInet6{Addr: target.As16(), Port: 9}); err != nil {
		t.Logf("sendto %s: %v", target, err)
		return false
	}
	return readTUN(tun, coverProbeWait)
}

func boundConnect(index int, target netip.Addr) error {
	if target.Is4() {
		return boundReach(index, target)
	}
	return boundReach6(index, target)
}

// scopedLookup is the interface `route -n get -ifscope` names for target.
func scopedLookup(t *testing.T, device string, target netip.Addr) string {
	t.Helper()
	args := []string{"-n", "get"}
	if target.Is6() {
		args = append(args, "-inet6")
	}
	args = append(args, "-ifscope", device, target.String())
	out, err := exec.Command("route", args...).CombinedOutput()
	t.Logf("route %s:\n%s", strings.Join(args, " "), out)
	if err != nil {
		t.Errorf("route get: %v", err)
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		if name, ok := strings.CutPrefix(strings.TrimSpace(line), "interface:"); ok {
			return strings.TrimSpace(name)
		}
	}
	return ""
}
