// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"slices"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/netnstest"
)

// The chain drops and counts every IPv4-mapped source, from the mesh's tun as
// from outside and of the overlay or not, under a reason of its own, while a
// native IPv6 datagram from either side, an IPv4 one of the mesh and the drop
// of a forged IPv4 overlay source from outside stay as they were
func TestBorderDropsEveryIPv4MappedSource(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmpty(t)
	// an address the uplink takes is usable at once, with no duplicate detection to wait out
	if err := os.WriteFile("/proc/sys/net/ipv6/conf/default/accept_dad", []byte("0"), 0o644); err != nil {
		t.Fatal(err)
	}
	p, a := netip.MustParsePrefix, netip.MustParseAddr
	rt := borderRuntime(nil)
	tun, uplink := benchOpenTun(t, rt.Tun), benchOpenTun(t, "eth0")
	netlink, err := netnstest.OpenNetlink()
	if err != nil {
		t.Fatal(err)
	}
	defer netlink.Close()
	if err := netlink.AddAddresses("eth0", p("198.51.100.1/24"), p("2001:db8::1/64")); err != nil {
		t.Fatal(err)
	}
	if err := netlink.AddAddresses(rt.Tun, p("203.0.113.1/24"), p("3fff::1/64")); err != nil {
		t.Fatal(err)
	}
	be, err := newBorderBackend(nil, rt)
	if err != nil {
		t.Fatal(err)
	}
	f, err := startBorderFilter(overlay(t, "203.0.113.0/24", "3fff::/20"), rt, be)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.finish() })
	receiver, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6zero, Port: 9})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()

	var genuine netip.AddrPort
	for _, c := range []struct {
		name                string
		device              int
		source, destination netip.Addr
		delivered           bool
	}{
		{"native IPv6 from outside", uplink, a("2001:db8::2"), a("2001:db8::1"), true},
		{"native IPv6 of the mesh", tun, a("3fff::5"), a("3fff::1"), true},
		{"IPv4 of the mesh", tun, a("203.0.113.5"), a("203.0.113.1"), true},
		{"IPv4 overlay source from outside", uplink, a("203.0.113.5"), a("198.51.100.1"), false},
		{"mapped overlay source from outside", uplink, a("::ffff:203.0.113.5"), a("2001:db8::1"), false},
		{"mapped overlay source from the tun", tun, a("::ffff:203.0.113.5"), a("3fff::1"), false},
		{"mapped source outside the overlay from outside", uplink, a("::ffff:198.51.100.7"), a("2001:db8::1"), false},
	} {
		if _, err := unix.Write(c.device, benchUDP(c.source, c.destination)); err != nil {
			t.Fatalf("write the %s: %v", c.name, err)
		}
		wait := quietFor
		if c.delivered {
			wait = siteWait
		}
		if err := receiver.SetReadDeadline(time.Now().Add(wait)); err != nil {
			t.Fatal(err)
		}
		_, peer, err := receiver.ReadFromUDPAddrPort(make([]byte, 64))
		var timeout net.Error
		switch {
		case err != nil && !(errors.As(err, &timeout) && timeout.Timeout()):
			t.Fatal(err)
		case err == nil && !c.delivered:
			t.Errorf("the socket took the %s, from peer %s, the IPv4 of the mesh's being %s", c.name, peer, genuine)
		case err != nil && c.delivered:
			t.Errorf("the socket took no %s within %s", c.name, wait)
		case err == nil && c.source.Is4():
			genuine = peer
		}
	}
	for _, drop := range []struct {
		spec string
		want uint64
	}{
		{"drop ipv4 source 203.0.113.0/24", 1},
		{"drop ipv6 source 3fff::/20", 0},
		{mappedDrop, 3},
	} {
		if got := borderPackets(t, f, drop.spec); got != drop.want {
			t.Errorf("%s counted %d packets, want %d", drop.spec, got, drop.want)
		}
	}
	if err := f.reconcile(); err != nil {
		t.Fatal(err)
	}
	dropped := f.Stats().Dropped
	for kind, want := range map[egress.BorderDrop]uint64{
		{Reason: "overlay_source", Family: "ipv4"}: 1, {Reason: "overlay_source", Family: "ipv6"}: 0, {Reason: "mapped_source", Family: "ipv6"}: 3,
	} {
		if got := dropped[slices.Index(egress.BorderDropKinds[:], kind)]; got != want {
			t.Errorf("the pass counts %d packets as %s, want %d", got, kind.Name(), want)
		}
	}
}

// A start that finds the antispoof chain an earlier run wrote without the
// mapped drop reads it as a fault and writes the chain again with the drop
func TestBorderRewritesAChainHeldWithoutTheMappedDrop(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmpty(t)
	cfg, rt := overlay(t), borderRuntime(nil)
	earlier, err := newBorderBackend(nil, rt)
	if err != nil {
		t.Fatal(err)
	}
	rules, sets, _ := newBorderFilter(cfg, rt, earlier).desired()
	rules = slices.DeleteFunc(rules, func(rule BorderRule) bool { return rule.Class == BorderMapped })
	if err := earlier.Apply(rules, sets); err != nil {
		t.Fatalf("write the chain without the mapped drop: %v", err)
	}
	if err := earlier.Leave(); err != nil {
		t.Fatal(err)
	}
	be, err := newBorderBackend(nil, rt)
	if err != nil {
		t.Fatal(err)
	}
	f, err := startBorderFilter(cfg, rt, be)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.finish() })
	if !f.found || !f.ready {
		t.Errorf("the start found the earlier chain %v and reads ready %v (%s), want both", f.found, f.ready, f.unready)
	}
	if got := borderPackets(t, f, mappedDrop); got != 0 {
		t.Errorf("%s counted %d packets on a chain just written, want none", mappedDrop, got)
	}
}
