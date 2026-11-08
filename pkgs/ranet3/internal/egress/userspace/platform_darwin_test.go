// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package userspace

import (
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/schema"
)

// The daemon's platform routes an address by the interface the selection
// names for it, with that interface's name and MTU, and by none where it names
// none. Its Prepare scopes a socket to that interface, read back, and refuses
// one toward an address the selection names none for. Held is the watch's.
func TestDarwinPlatformRoutesAndScopesByTheSelection(t *testing.T) {
	loopback, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Skipf("no lo0: %v", err)
	}
	unrouted := netip.MustParseAddr("192.0.2.77")
	held := netip.MustParseAddr("198.51.100.9")
	p := Darwin(func(address netip.Addr) (int, uint64) {
		if address.IsLoopback() {
			return loopback.Index, 1
		}
		return 0, 1
	}, func(address netip.Addr, _ string) bool { return address == held }, nil)
	for _, c := range []struct {
		address netip.Addr
		link    Link
		ok      bool
	}{
		{netip.MustParseAddr("127.0.0.1"), Link{Name: "lo0", MTU: loopback.MTU}, true},
		{netip.IPv6Loopback(), Link{Name: "lo0", MTU: loopback.MTU}, true},
		{unrouted, Link{}, false},
	} {
		link, ok, err := p.Route(c.address)
		if err != nil || ok != c.ok || link != c.link {
			t.Errorf("Route(%s) = %+v %t %v, want %+v %t", c.address, link, ok, err, c.link, c.ok)
		}
	}
	if !p.Held(held, "") || p.Held(unrouted, "") {
		t.Errorf("Held(%s) %t and Held(%s) %t, want the watch's alone", held, p.Held(held, ""), unrouted, p.Held(unrouted, ""))
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("no loopback socket: %v", err)
	}
	defer conn.Close()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Prepare("udp4", netip.MustParseAddrPort("127.0.0.1:9"), raw); err != nil {
		t.Fatalf("Prepare toward loopback: %v", err)
	}
	var index int
	if controlErr := raw.Control(func(fd uintptr) { index, err = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF) }); controlErr != nil || err != nil {
		t.Fatalf("read the scope: %v %v", controlErr, err)
	}
	if index != loopback.Index {
		t.Errorf("the socket is scoped to interface %d, want lo0's %d", index, loopback.Index)
	}
	if err := p.Prepare("udp4", netip.AddrPortFrom(unrouted, 9), raw); !errors.Is(err, syscall.ENETUNREACH) {
		t.Errorf("Prepare toward %s: %v, want ENETUNREACH", unrouted, err)
	}
}

// The daemon's platform holds an IPv4 address for a socket scoped to a link
// only where the watch reads it on that link, and an IPv6 address on any link
// the watch reads it on, so a family whose IPv4 class address the selection's
// link does not hold is not ready, with a reason naming the address and the
// link
func TestDarwinHoldsAnIPv4ClassOnTheScopedLinkAlone(t *testing.T) {
	v4, v6 := netip.MustParseAddr("198.51.100.9"), netip.MustParseAddr("2001:db8::9")
	onLoopback := func(address netip.Addr, link string) bool {
		return (address == v4 || address == v6) && (link == "" || link == "lo0")
	}
	p := Darwin(func(netip.Addr) (int, uint64) { return 0, 1 }, onLoopback, nil)
	for _, c := range []struct {
		address netip.Addr
		link    string
		held    bool
	}{
		{v4, "", true},
		{v4, "lo0", true},
		{v4, "en9", false},
		{v6, "", true},
		{v6, "en9", true},
		{netip.MustParseAddr("198.51.100.10"), "", false},
		{netip.MustParseAddr("2001:db8::10"), "en9", false},
	} {
		if got := p.Held(c.address, c.link); got != c.held {
			t.Errorf("Held(%s, %q) %t, want %t", c.address, c.link, got, c.held)
		}
	}
	p.Route = func(netip.Addr) (Link, bool, error) { return Link{Name: "en9", MTU: 1500}, true, nil }
	cfg := exitConfig()
	cfg.Translate = []egress.Class{
		{From: schema.MustPrefix("0.0.0.0/0"), To: egress.Translation{Addr: v4}},
		{From: schema.MustPrefix("::/0"), To: egress.Translation{Addr: v6}},
	}
	x := &Exit{cfg: cfg, rt: Runtime{Platform: p}}
	ready4, _, why4 := x.readiness(egress.FamilyIPv4)
	ready6, _, why6 := x.readiness(egress.FamilyIPv6)
	if want := "this host does not hold 198.51.100.9, an address cap.egress translate names, on en9, the link this host reaches 0.0.0.0/0 by"; ready4 || why4 != want {
		t.Errorf("ipv4 ready %t, %q, want not ready, %q", ready4, why4, want)
	}
	if !ready6 || why6 != "" {
		t.Errorf("ipv6 ready %t, %q, want ready", ready6, why6)
	}
}
