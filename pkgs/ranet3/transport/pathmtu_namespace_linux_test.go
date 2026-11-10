// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package transport

import (
	"net"
	"net/netip"
	"slices"
	"testing"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/netnstest"
	"ranet3.com/pkgs/ranet3/internal/underlay"
)

// pinnedSource, pinnedSource4 and pinnedLinkHost are the addresses of the link a pin names,
// and pinnedPeers and pinnedPeers4 the prefixes it and the link beside it route
var (
	pinnedSource   = netip.MustParsePrefix("2001:db8:7::1/64")
	pinnedSource4  = netip.MustParsePrefix("198.51.100.1/24")
	pinnedLinkHost = netip.MustParsePrefix("fe80::1/64")
	pinnedPeers    = netip.MustParsePrefix("2001:db8:8::/64")
	pinnedPeers4   = netip.MustParsePrefix("203.0.113.0/24")
)

// the route MTUs and metrics of the two links, the pinned link's routes to pinnedPeers and pinnedPeers4 at the higher metric and the narrower MTU at the lower
// and the pinned link's route to the link-local prefix at a metric under the one linux gives the prefix of an address
const (
	takenMTU     = 1300
	takenMetric  = 100
	pinnedMTU    = 1400
	pinnedMetric = 200
	localMTU     = 1350
	localMetric  = 100
)

// an IPv6 pin's path MTU is the route's its send takes, the lowest metric's whatever interface it pins
// linux names the pinned interface in IPV6_PKTINFO, which prefers it only among the routes of the lowest metric
// so a datagram past the lower metric's MTU is refused there, and the send reports that route's MTU and sends what it carries
// a link-local pin binds by its interface, and its path MTU is that interface's route's
// an IPv4 pin holds its interface, which IP_PKTINFO names for the send whatever the metrics, so its path MTU is the pinned link's route's
func TestPinnedPathMTUIsTheRouteTheSendTakes(t *testing.T) {
	netnstest.EnterEmpty(t)
	netlink, err := openRouteNetlink()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(netlink.close)
	taken, err := netlink.dummyLink("taken")
	if err != nil {
		t.Fatal(err)
	}
	pinned, err := netlink.dummyLink("pinned")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.configure(pinned, []netip.Prefix{pinnedSource, pinnedSource4, pinnedLinkHost}); err != nil {
		t.Fatalf("configure the pinned link: %v", err)
	}
	for _, route := range []struct {
		index       int
		to          netip.Prefix
		metric, mtu uint32
	}{
		{taken, pinnedPeers, takenMetric, takenMTU},
		{pinned, pinnedPeers, pinnedMetric, pinnedMTU},
		{taken, pinnedPeers4, takenMetric, takenMTU},
		{pinned, pinnedPeers4, pinnedMetric, pinnedMTU},
		{pinned, pinnedLinkHost.Masked(), localMetric, localMTU},
	} {
		if err := netlink.routeWithMTU(route.index, route.to, route.metric, route.mtu); err != nil {
			t.Fatalf("route %s over link %d: %v", route.to, route.index, err)
		}
	}
	listening, _, _, err := listenPacketBind(0, underlay.Unchanged, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listening.Close() })
	bind := listening.(*udpBind)

	peer := &net.UDPAddr{IP: pinnedPeers.Addr().Next().AsSlice(), Port: 4500}
	ep := pinnedEndpoint(peer, pinnedSource.Addr().AsSlice(), pinned, true)
	before := linkSent(t, "taken")
	if err := bind.Send([][]byte{make([]byte, 64)}, ep); err != nil {
		t.Fatal(err)
	}
	if got := linkSent(t, "taken") - before; got != 1 {
		t.Fatalf("the link of the lower metric carried %d of the pinned send's datagrams, want the 1 its route takes past the pinned link's", got)
	}
	if mtu, err := routeMTU(ep, underlay.Unchanged); err != nil || mtu != takenMTU {
		t.Fatalf("the pinned path MTU to %s reads %d and %v, want the taken route's %d rather than the pinned link's %d", peer, mtu, err, takenMTU, pinnedMTU)
	}
	sent := linkSent(t, "taken")
	err = bind.Send([][]byte{make([]byte, takenMTU), make([]byte, 64)}, ep)
	if report, ok := err.(*PathMTUError); !ok || report.MTU != takenMTU {
		t.Fatalf("a pinned send past the taken route answered %v, want the report of its %d alone", err, takenMTU)
	}
	if got := linkSent(t, "taken") - sent; got != 1 {
		t.Fatalf("the taken route carried %d datagrams of the refused send, want the 1 within its MTU", got)
	}

	linkPeer := &net.UDPAddr{IP: pinnedLinkHost.Addr().Next().AsSlice(), Port: 4500, Zone: "pinned"}
	linkEP := pinnedEndpoint(linkPeer, pinnedLinkHost.Addr().AsSlice(), pinned, true)
	if mtu, err := routeMTU(linkEP, underlay.Unchanged); err != nil || mtu != localMTU {
		t.Fatalf("the link-local pin's path MTU to %s reads %d and %v, want the pinned link's route's %d", linkPeer, mtu, err, localMTU)
	}

	peer4 := &net.UDPAddr{IP: pinnedPeers4.Addr().Next().AsSlice(), Port: 4500}
	ep4 := pinnedEndpoint(peer4, pinnedSource4.Addr().AsSlice(), pinned, false)
	before = linkSent(t, "pinned")
	if err := bind.Send([][]byte{make([]byte, 64)}, ep4); err != nil {
		t.Fatal(err)
	}
	if got := linkSent(t, "pinned") - before; got != 1 {
		t.Fatalf("the pinned link carried %d of the IPv4 pin's datagrams, want the 1 its pin holds there past the lower metric's route", got)
	}
	if mtu, err := routeMTU(ep4, underlay.Unchanged); err != nil || mtu != pinnedMTU {
		t.Fatalf("the IPv4 pin's path MTU to %s reads %d and %v, want the pinned link's route's %d rather than the lower metric's %d", peer4, mtu, err, pinnedMTU, takenMTU)
	}
}

// routeWithMTU routes to a prefix over link index in the main table at metric with a route MTU of mtu
func (n routeNetlink) routeWithMTU(index int, to netip.Prefix, metric, mtu uint32) error {
	header := []byte{addressFamily(to.Addr()), byte(to.Bits()), 0, 0, unix.RT_TABLE_MAIN, unix.RTPROT_BOOT, unix.RT_SCOPE_UNIVERSE, unix.RTN_UNICAST, 0, 0, 0, 0}
	body := slices.Concat(header, attribute(unix.RTA_DST, to.Addr().AsSlice()), attribute(unix.RTA_OIF, word(uint32(index))),
		attribute(unix.RTA_PRIORITY, word(metric)), attribute(unix.RTA_METRICS, attribute(unix.RTAX_MTU, word(mtu))))
	return n.request(unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_APPEND, body)
}
