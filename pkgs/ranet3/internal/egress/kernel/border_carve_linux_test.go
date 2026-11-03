// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"net"
	"net/netip"
	"os"
	"slices"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/egress"
	meshkernel "ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/netnstest"
	"ranet3.com/pkgs/ranet3/internal/netstack"
)

const (
	sitePort = 4791
	// siteWait is how long a test waits for a datagram or a drop, generous for
	// a loaded machine, and siteProbeWait how long it waits for one datagram
	// before it sends the next
	siteWait      = 10 * time.Second
	siteProbeWait = 100 * time.Millisecond
)

// siteLink is a veth pair of the gateway, name holding here and far, in
// thread's namespace, holding there
type siteLink struct {
	name, far string
	thread    *netnstest.Thread
	here      netip.Prefix
	there     []netip.Prefix
}

// startSiteGateway starts the antispoof filter of a gateway with node address
// 203.0.113.1 announcing 203.0.113.0/25 and exempting it under eth1, on links,
// with the sets meshkernel.CarvedSets gives the node, and the gateway's
// socket on sitePort
func startSiteGateway(t *testing.T, links ...siteLink) (*BorderFilter, *net.UDPConn) {
	t.Helper()
	p := netip.MustParsePrefix
	netlink, err := netnstest.OpenNetlink()
	if err != nil {
		t.Fatal(err)
	}
	defer netlink.Close()
	var network meshkernel.NetworkState
	for _, link := range links {
		if err := netlink.AddVeth(link.name, link.far, 0, link.thread.Path); err != nil {
			t.Fatalf("make %s: %v", link.name, err)
		}
		if err := netlink.AddAddresses(link.name, link.here); err != nil {
			t.Fatal(err)
		}
		if err := link.thread.Do(func() error {
			far, err := netnstest.OpenNetlink()
			if err != nil {
				return err
			}
			defer far.Close()
			return far.AddAddresses(link.far, link.there...)
		}); err != nil {
			t.Fatalf("address the far end of %s: %v", link.name, err)
		}
		network.IPv4.Links = append(network.IPv4.Links, meshkernel.Link{Name: link.name, Prefixes: []netip.Prefix{link.here}})
	}
	cfg := overlay(t, "203.0.113.0/24")
	cfg.Antispoof = egress.Antispoof{Interface: map[string]egress.AntispoofInterface{"eth1": {Exempt: prefixes(t, "203.0.113.0/25")}}}
	cfg.Own, cfg.Addresses = []netip.Prefix{p("203.0.113.0/25")}, []netip.Prefix{p("203.0.113.1/32")}
	routes := netstack.NewRouteTable()
	routes.Set(netip.Prefix{}, p("203.0.113.0/25"), netstack.Local)
	routes.Set(netip.Prefix{}, p("203.0.113.1/32"), netstack.Assigned)
	rt := borderRuntime(nil)
	rt.Sets = func(border *egress.Border) egress.BorderSets {
		sets := egress.BorderSets{CarveOuts: meshkernel.CarveOuts(network, border.Overlay)}
		sets.Carved, sets.Conflicts = meshkernel.CarvedSets(border, sets.CarveOuts, routes.Snapshot())
		return sets
	}
	be, err := newBorderBackend(egress.BorderRuntime{})
	if err != nil {
		t.Fatalf("open the antispoof filter's backend: %v", err)
	}
	f, err := startBorderFilter(cfg, rt, be)
	if err != nil {
		t.Fatalf("start the antispoof filter: %v", err)
	}
	t.Cleanup(func() { _ = f.finish() })
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{Port: sitePort})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = receiver.Close() })
	return f, receiver
}

// siteSend sends payload from source in thread's namespace to the gateway's
// socket at to
func siteSend(t *testing.T, thread *netnstest.Thread, source, to netip.Addr, payload string) {
	t.Helper()
	if err := thread.Do(func() error {
		conn, err := net.DialUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(source, 0)), net.UDPAddrFromAddrPort(netip.AddrPortFrom(to, sitePort)))
		if err != nil {
			return err
		}
		defer conn.Close()
		_, err = conn.Write([]byte(payload))
		return err
	}); err != nil {
		t.Fatalf("send %s from %s: %v", payload, source, err)
	}
}

// siteRead is the payloads receiver takes until wait passes with none
func siteRead(t *testing.T, receiver *net.UDPConn, wait time.Duration) []string {
	t.Helper()
	var out []string
	buf := make([]byte, 64)
	for {
		if err := receiver.SetReadDeadline(time.Now().Add(wait)); err != nil {
			t.Fatal(err)
		}
		n, err := receiver.Read(buf)
		if err != nil {
			return out
		}
		out = append(out, string(buf[:n]))
	}
}

// borderPackets is the packets the rule spec of f's table counted, as a debug
// read finds them now
func borderPackets(t *testing.T, f *BorderFilter, spec string) uint64 {
	t.Helper()
	for _, chain := range f.Debug().Chains {
		for _, rule := range chain.Rules {
			if rule.Spec == spec && rule.Held {
				return rule.Packets
			}
		}
	}
	t.Fatalf("the antispoof filter holds no rule %s", spec)
	return 0
}

// carved4 gives the ranges the last pass of f asked carved4 to hold
func carved4(f *BorderFilter) []egress.Range {
	for _, set := range f.Stats().Sets {
		if set.Name == carvedSet+"4" {
			return set.Elements
		}
	}
	return nil
}

// A gateway announcing 203.0.113.0/25 and exempting it under eth1, whose own
// network 203.0.113.126/25 is the carve-out of that range, carves nothing but
// its own address, takes a site host's datagram from 203.0.113.65 arriving on
// eth1 and drops the same source arriving on eth0 at the overlay's drop
func TestBorderTakesTheExemptOwnRangeFromItsCarveOutsLinkAlone(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	enterThrowawayNamespace(t)
	p := netip.MustParsePrefix
	source := netip.MustParseAddr("203.0.113.65")
	site, uplink := netnstest.StartThread(t), netnstest.StartThread(t)
	f, receiver := startSiteGateway(t,
		siteLink{"eth1", "site0", site, p("203.0.113.126/25"), []netip.Prefix{p("203.0.113.65/25")}},
		siteLink{"eth0", "up0", uplink, p("198.51.100.2/24"), []netip.Prefix{p("198.51.100.3/24"), netip.PrefixFrom(source, 32)}},
	)
	if got, want := f.Stats().CarveOuts, []egress.CarveOut{{Link: "eth1", Prefix: p("203.0.113.0/25")}}; !slices.Equal(got, want) {
		t.Fatalf("the antispoof filter carves %v, want %v", got, want)
	}
	if got, want := carved4(f), ranges("203.0.113.1/32"); !slices.Equal(got, want) {
		t.Errorf("carved4 holds %v, want %v", got, want)
	}

	// the first datagrams may meet a veth whose carrier is not up yet
	var delivered []string
	for deadline := time.Now().Add(siteWait); len(delivered) == 0; {
		if time.Now().After(deadline) {
			t.Fatalf("no datagram from %s on eth1 reached the gateway within %s", source, siteWait)
		}
		siteSend(t, site, source, p("203.0.113.126/25").Addr(), "eth1")
		delivered = siteRead(t, receiver, siteProbeWait)
	}
	const overlayDrop, carvedDrop = "drop ipv4 source 203.0.113.0/24", "drop ipv4 source @carved4"
	for deadline := time.Now().Add(siteWait); borderPackets(t, f, overlayDrop) == 0; time.Sleep(siteProbeWait) {
		if time.Now().After(deadline) {
			t.Fatalf("the overlay's drop counted no datagram from %s on eth0 within %s", source, siteWait)
		}
		siteSend(t, uplink, source, p("198.51.100.2/24").Addr(), "eth0")
	}
	for _, payload := range slices.Concat(delivered, siteRead(t, receiver, quietFor)) {
		if payload != "eth1" {
			t.Errorf("the gateway's socket took a datagram from %s on %s", source, payload)
		}
	}
	if carved := borderPackets(t, f, carvedDrop); carved != 0 {
		t.Errorf("%s counted %d packets, want none", carvedDrop, carved)
	}
}

// The same gateway with a second carve-out inside its range, wlan0's network
// 203.0.113.5/28, which no exemption names, keeps that part carved and drops a
// neighbor's datagram from 203.0.113.6 arriving on wlan0 at the carved drop
func TestBorderKeepsTheOwnRangeCarvedWhereACarveOutHoldingItIsNotExempt(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	enterThrowawayNamespace(t)
	p := netip.MustParsePrefix
	source := netip.MustParseAddr("203.0.113.6")
	site, wlan := netnstest.StartThread(t), netnstest.StartThread(t)
	f, receiver := startSiteGateway(t,
		siteLink{"eth1", "site0", site, p("203.0.113.126/25"), []netip.Prefix{p("203.0.113.65/25")}},
		siteLink{"wlan0", "wl0", wlan, p("203.0.113.5/28"), []netip.Prefix{p("203.0.113.6/28")}},
	)
	if got, want := f.Stats().CarveOuts, []egress.CarveOut{{Link: "eth1", Prefix: p("203.0.113.0/25")}, {Link: "wlan0", Prefix: p("203.0.113.0/28")}}; !slices.Equal(got, want) {
		t.Fatalf("the antispoof filter carves %v, want %v", got, want)
	}
	if got, want := carved4(f), ranges("203.0.113.0/28"); !slices.Equal(got, want) {
		t.Errorf("carved4 holds %v, want %v", got, want)
	}

	// the first datagrams may meet a veth whose carrier is not up yet
	const carvedDrop = "drop ipv4 source @carved4"
	for deadline := time.Now().Add(siteWait); borderPackets(t, f, carvedDrop) == 0; time.Sleep(siteProbeWait) {
		if time.Now().After(deadline) {
			t.Fatalf("the carved drop counted no datagram from %s on wlan0 within %s, the socket taking %v", source, siteWait, siteRead(t, receiver, quietFor))
		}
		siteSend(t, wlan, source, p("203.0.113.5/28").Addr(), "wlan0")
	}
	if got := siteRead(t, receiver, quietFor); len(got) != 0 {
		t.Errorf("the gateway's socket took %q from %s on wlan0", got, source)
	}
}
