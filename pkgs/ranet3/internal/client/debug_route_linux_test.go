// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package client

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/netnstest"
)

// routeViewWait bounds the wait for the kernel to count a packet written into
// a tun, and routeViewPoll is how often the wait reads the counters
const (
	routeViewWait = 2 * time.Second
	routeViewPoll = 20 * time.Millisecond
)

// routeViewMRTInit is MRT_INIT of linux/mroute.h, which x/sys does not carry
const routeViewMRTInit = 200

// An IPv6 packet arriving on in0 is forwarded by all's forwarding or in0's
// force_forwarding and never by in0's forwarding, and the route view names
// the drop exactly where the kernel counts one in place of a forwarded packet
func TestTUNDebugRouteNamesTheIPv6DropWhereTheKernelMakesIt(t *testing.T) {
	netnstest.EnterEmpty(t)
	netlink, err := netnstest.OpenNetlink()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(netlink.Close)
	dummy := netnstest.Attr(unix.IFLA_INFO_KIND, netnstest.CString("dummy"))
	if err := netlink.Request(unix.RTM_NEWLINK, unix.NLM_F_CREATE|unix.NLM_F_EXCL, slices.Concat(netnstest.IfInfo(0, 0), netnstest.Attr(unix.IFLA_IFNAME, netnstest.CString("up0")), netnstest.Attr(unix.IFLA_LINKINFO, dummy))); err != nil {
		t.Fatalf("make up0: %v", err)
	}
	fd := routeViewTUN(t, "in0")
	if err := netlink.AddAddresses("up0", netip.MustParsePrefix("2001:db8:1::2/64")); err != nil {
		t.Fatal(err)
	}
	if err := netlink.AddAddresses("in0", netip.MustParsePrefix("2001:db8:2::1/64")); err != nil {
		t.Fatal(err)
	}
	up, err := net.InterfaceByName("up0")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.RouteVia(up.Index, netip.MustParsePrefix("::/0"), netip.MustParseAddr("2001:db8:1::1")); err != nil {
		t.Fatalf("route ::/0 by up0: %v", err)
	}
	c, _, _, _ := reloadOf(t, func(*config.Config) {})
	src, dst := netip.MustParseAddr("2001:db8:2::5"), netip.MustParseAddr("2001:db8:ffff::10")
	packet := routeViewUDP(src, dst)
	_, forceErr := os.Stat("/proc/sys/net/ipv6/conf/in0/force_forwarding")
	// all's forwarding first, since writing it sets every link's forwarding and
	// clears every force_forwarding
	for _, setting := range []struct{ all, link, force string }{{"1", "0", ""}, {"0", "1", ""}, {"0", "0", "1"}, {"0", "1", "0"}} {
		if setting.force != "" && forceErr != nil {
			t.Logf("this kernel has no force_forwarding (%v), so all 0, in0 %s and force_forwarding %s is left out", forceErr, setting.link, setting.force)
			continue
		}
		routeViewSysctl(t, "net/ipv6/conf/all/forwarding", setting.all)
		routeViewSysctl(t, "net/ipv6/conf/in0/forwarding", setting.link)
		if setting.force != "" {
			routeViewSysctl(t, "net/ipv6/conf/in0/force_forwarding", setting.force)
		}
		info, err := c.DebugRoute(src, dst, "in0")
		if err != nil || info.Kernel == nil || info.Kernel.Err != "" {
			t.Fatalf("all %s, in0 %s, force_forwarding %q: the route view reads %+v, %v", setting.all, setting.link, setting.force, info.Kernel, err)
		}
		forwarded, dropped := routeViewCount(t, "Ip6OutForwDatagrams"), routeViewCount(t, "Ip6InAddrErrors")
		if _, err := unix.Write(fd, packet); err != nil {
			t.Fatalf("write the packet into in0: %v", err)
		}
		kernelForwarded, kernelDropped := false, false
		for deadline := time.Now().Add(routeViewWait); !kernelForwarded && !kernelDropped && time.Now().Before(deadline); time.Sleep(routeViewPoll) {
			kernelForwarded = routeViewCount(t, "Ip6OutForwDatagrams") > forwarded
			// ip6_forward counts a packet it does not forward as an address error
			kernelDropped = routeViewCount(t, "Ip6InAddrErrors") > dropped
		}
		if kernelForwarded == kernelDropped {
			t.Fatalf("all %s, in0 %s, force_forwarding %q: the kernel counted the packet forwarded %v and dropped %v", setting.all, setting.link, setting.force, kernelForwarded, kernelDropped)
		}
		if viewDrops := info.Kernel.Why == control.WhyForwardingOff; viewDrops != kernelDropped {
			t.Errorf("all %s, in0 %s, force_forwarding %q: the kernel dropped the packet %v, and the route view, reading %+v, says it drops %v", setting.all, setting.link, setting.force, kernelDropped, info.Kernel.Settings, viewDrops)
		}
	}
}

// Each kind of destination, as this host's own packet and as an arrival on
// in0, in both families where the kind exists, against the kernel of a fresh
// namespace: the answer RouteGet reads from it, and the view's Kernel, Rule,
// Route and Leaves lines, each naming the path the kernel takes for it in
// ip_route_output_key_hash_rcu, ip_route_input_rcu, ip_route_input_slow,
// ip6_route_input_lookup and the replies of inet_rtm_getroute and
// inet6_rtm_getroute, and the Socket line, which this host's own IPv6 packet
// to :: carries whatever the lookup answers and which names no path. up0
// holds the default routes and in0 the arrivals, IPv4 forwarding on in0 and
// IPv6's in all on but where a case turns it off, rp_filter 1 on in0, and
// in0 joined to 239.1.2.3 and ff0e::123, then IPv4 groups arriving with
// multicast routing on in all, then this host's own packet to :: with no
// IPv6 default
func TestTUNDebugRouteNamesThePathTheKernelTakesForEachDestinationKind(t *testing.T) {
	netnstest.EnterEmpty(t)
	netlink, err := netnstest.OpenNetlink()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(netlink.Close)
	dummy := netnstest.Attr(unix.IFLA_INFO_KIND, netnstest.CString("dummy"))
	for _, name := range []string{"up0", "in0"} {
		if err := netlink.Request(unix.RTM_NEWLINK, unix.NLM_F_CREATE|unix.NLM_F_EXCL, slices.Concat(netnstest.IfInfo(0, 0), netnstest.Attr(unix.IFLA_IFNAME, netnstest.CString(name)), netnstest.Attr(unix.IFLA_LINKINFO, dummy))); err != nil {
			t.Fatalf("make %s: %v", name, err)
		}
	}
	if err := netlink.AddAddresses("up0", netip.MustParsePrefix("198.51.100.2/25"), netip.MustParsePrefix("2001:db8:1::2/64")); err != nil {
		t.Fatal(err)
	}
	if err := netlink.AddAddresses("in0", netip.MustParsePrefix("198.51.100.130/25"), netip.MustParsePrefix("2001:db8:2::1/64")); err != nil {
		t.Fatal(err)
	}
	up, err := net.InterfaceByName("up0")
	if err != nil {
		t.Fatal(err)
	}
	in, err := net.InterfaceByName("in0")
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range [][2]string{{"0.0.0.0/0", "198.51.100.1"}, {"::/0", "2001:db8:1::1"}} {
		if err := netlink.RouteVia(up.Index, netip.MustParsePrefix(route[0]), netip.MustParseAddr(route[1])); err != nil {
			t.Fatalf("route %s by up0: %v", route[0], err)
		}
	}
	listener4, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(listener4) })
	if err := unix.SetsockoptIPMreqn(listener4, unix.IPPROTO_IP, unix.IP_ADD_MEMBERSHIP, &unix.IPMreqn{Multiaddr: [4]byte{239, 1, 2, 3}, Ifindex: int32(in.Index)}); err != nil {
		t.Fatalf("join 239.1.2.3 on in0: %v", err)
	}
	listener6, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(listener6) })
	if err := unix.SetsockoptIPv6Mreq(listener6, unix.IPPROTO_IPV6, unix.IPV6_JOIN_GROUP, &unix.IPv6Mreq{Multiaddr: netip.MustParseAddr("ff0e::123").As16(), Interface: uint32(in.Index)}); err != nil {
		t.Fatalf("join ff0e::123 on in0: %v", err)
	}
	routeViewSysctl(t, "net/ipv4/conf/all/rp_filter", "0")
	routeViewSysctl(t, "net/ipv4/conf/in0/rp_filter", "1")
	c, _, _, _ := reloadOf(t, func(*config.Config) {})
	const (
		mainRule  = "32766 all lookup main, kernel"
		localRule = "0 all lookup local, kernel"
		noEntry   = "none, the route below is the kernel's own for this destination, in no table a rule looks up"
		noWalk    = "none, the kernel walks no rule for this destination arriving on a link"
		default4  = "0.0.0.0/0 in table main, unicast, via 198.51.100.1 dev up0"
		default6  = "::/0 in table main, unicast, via 2001:db8:1::1 dev up0"
		byUp0     = "by up0, outside the mesh"
		delivered = "nowhere, the kernel delivers it to this host"
		joined    = "nowhere, the kernel delivers it to this host, which joined the group on in0"
		unjoined  = "EINVAL, a group this host has not joined on in0, or a source the kernel's checks refuse for it, reverse path filtering among them"
		group6    = "EMSGSIZE, which the kernel answers for a group arriving on a link in place of its route, and it delivers such a packet to this host where it joined the group on in0, forwards it by multicast routing where that is on, and drops it otherwise"
		noRoute6  = "none named, the answer carries no route"
	)
	const unspecified = ":: is the unspecified address, and a socket sends such a packet to ::1 or by the route, or refuses it, as its type and the platform decide, so the answer above may not be the packet's path"
	entry := func(route, kind, device string) string {
		return route + ", " + kind + ", dev " + device + ", the kernel's own for this destination, with no table entry behind it"
	}
	type kindRow struct {
		name, src, dst string
		// arrival is a packet arriving on in0, forwardingOff one with in0's
		// IPv4 forwarding or all's IPv6 forwarding off
		arrival, forwardingOff bool
		// answer is RouteGet's, a route as prefix, table and type or an errno
		answer                      string
		kernel, rule, route, leaves string
		// socket is the line this host's own IPv6 packet to :: carries
		socket string
	}
	check := func(row kindRow) {
		t.Helper()
		forwarding := "1"
		if row.forwardingOff {
			forwarding = "0"
		}
		routeViewSysctl(t, "net/ipv4/conf/in0/forwarding", forwarding)
		routeViewSysctl(t, "net/ipv6/conf/all/forwarding", forwarding)
		var src netip.Addr
		if row.src != "" {
			src = netip.MustParseAddr(row.src)
		}
		dst, iif := netip.MustParseAddr(row.dst), ""
		if row.arrival {
			iif = "in0"
		}
		route, err := kernel.RouteGet(src, dst, iif)
		answer := fmt.Sprintf("%s table %d %s", route.Prefix, route.Table, route.Type)
		if route.NoEntry {
			answer += " of no entry"
		}
		var errno syscall.Errno
		if errors.As(err, &errno) {
			answer = unix.ErrnoName(errno)
		}
		info, viewErr := c.DebugRoute(src, dst, iif)
		if viewErr != nil {
			t.Fatalf("%s: the route view refused the packet: %v", row.name, viewErr)
		}
		var out strings.Builder
		control.RenderRoute(&out, info)
		lines := map[string]string{}
		for line := range strings.Lines(out.String()) {
			name, value, _ := strings.Cut(strings.TrimSpace(line), " ")
			lines[name] = strings.TrimSpace(value)
		}
		got := [6]string{answer, lines["Kernel"], lines["Rule"], lines["Route"], lines["Leaves"], lines["Socket"]}
		if want := [6]string{row.answer, row.kernel, row.rule, row.route, row.leaves, row.socket}; got != want {
			t.Errorf("%s: the kernel answered %q, %v, and the view reads\n%s\nwant the answer, Kernel, Rule, Route, Leaves and Socket %q", row.name, answer, err, out.String(), want)
		}
	}
	for _, row := range []kindRow{
		{"own unicast route", "198.51.100.2", "203.0.113.10", false, false, "0.0.0.0/0 table 254 unicast", "", mainRule, default4, byUp0, ""},
		{"arriving unicast route", "198.51.100.140", "203.0.113.10", true, false, "0.0.0.0/0 table 254 unicast", "", mainRule, default4, byUp0, ""},
		{"arriving unicast route, forwarding off", "198.51.100.140", "203.0.113.10", true, true, "EHOSTUNREACH", "EHOSTUNREACH, forwarding is off on in0", "none named, the kernel refuses the packet after its walk, whose end the answer does not carry", "", "", ""},
		{"own local address", "198.51.100.2", "198.51.100.130", false, false, "198.51.100.130/32 table 254 local", "", localRule, "198.51.100.130/32 in table main, local, dev in0", delivered, ""},
		{"arriving local address", "198.51.100.140", "198.51.100.130", true, false, "198.51.100.130/32 table 254 local", "", localRule, "198.51.100.130/32 in table main, local, dev in0", delivered, ""},
		{"own subnet broadcast", "198.51.100.2", "198.51.100.255", false, false, "198.51.100.255/32 table 254 broadcast", "", localRule, "198.51.100.255/32 in table main, broadcast, dev in0", "by in0, outside the mesh", ""},
		{"arriving subnet broadcast", "198.51.100.140", "198.51.100.255", true, false, "198.51.100.255/32 table 254 broadcast", "", localRule, "198.51.100.255/32 in table main, broadcast, dev in0", delivered, ""},
		{"arriving broadcast of another link's subnet", "198.51.100.140", "198.51.100.127", true, false, "198.51.100.127/32 table 254 broadcast", "", localRule, "198.51.100.127/32 in table main, broadcast, dev up0", delivered, ""},
		{"own limited broadcast", "198.51.100.2", "255.255.255.255", false, false, "255.255.255.255/32 table 0 broadcast of no entry", "", noEntry, entry("255.255.255.255/32", "broadcast", "up0"), byUp0, ""},
		{"own limited broadcast with no source", "", "255.255.255.255", false, false, "0.0.0.0/0 table 254 broadcast", "", mainRule, "0.0.0.0/0 in table main, broadcast, via 198.51.100.1 dev up0", byUp0, ""},
		{"arriving limited broadcast", "198.51.100.140", "255.255.255.255", true, false, "255.255.255.255/32 table 0 broadcast of no entry", "", noEntry, entry("255.255.255.255/32", "broadcast", "lo"), delivered, ""},
		{"own joined group", "198.51.100.2", "239.1.2.3", false, false, "239.1.2.3/32 table 0 multicast of no entry", "", noEntry, entry("239.1.2.3/32", "multicast", "up0"), byUp0, ""},
		{"own joined group with no source", "", "239.1.2.3", false, false, "0.0.0.0/0 table 254 multicast", "", mainRule, "0.0.0.0/0 in table main, multicast, via 198.51.100.1 dev up0", byUp0, ""},
		{"arriving joined group", "198.51.100.140", "239.1.2.3", true, false, "239.1.2.3/32 table 0 multicast of no entry", "", noEntry, entry("239.1.2.3/32", "multicast", "lo"), joined, ""},
		{"own unjoined group", "198.51.100.2", "239.1.2.4", false, false, "239.1.2.4/32 table 0 multicast of no entry", "", noEntry, entry("239.1.2.4/32", "multicast", "up0"), byUp0, ""},
		{"arriving unjoined group", "198.51.100.140", "239.1.2.4", true, false, "EINVAL", unjoined, noWalk, "", "", ""},
		{"own link-local group", "198.51.100.2", "224.0.0.1", false, false, "224.0.0.1/32 table 0 multicast of no entry", "", noEntry, entry("224.0.0.1/32", "multicast", "up0"), byUp0, ""},
		{"arriving link-local group every link joins", "198.51.100.140", "224.0.0.1", true, false, "224.0.0.1/32 table 0 multicast of no entry", "", noEntry, entry("224.0.0.1/32", "multicast", "lo"), joined, ""},
		{"arriving unjoined link-local group", "198.51.100.140", "224.0.0.251", true, false, "EINVAL", unjoined, noWalk, "", "", ""},
		{"own 0.0.0.0", "198.51.100.2", "0.0.0.0", false, false, "0.0.0.0/32 table 0 local of no entry", "", noEntry, entry("0.0.0.0/32", "local", "lo"), delivered, ""},
		{"arriving 0.0.0.0", "198.51.100.140", "0.0.0.0", true, false, "EINVAL", "EINVAL, a martian destination or source", noWalk, "", "", ""},
		{"own link-local unicast", "198.51.100.2", "169.254.1.1", false, false, "0.0.0.0/0 table 254 unicast", "", mainRule, default4, byUp0, ""},
		{"arriving link-local unicast", "198.51.100.140", "169.254.1.1", true, false, "0.0.0.0/0 table 254 unicast", "", mainRule, default4, byUp0, ""},
		{"own IPv6 unicast route", "2001:db8:1::2", "2001:db8:ffff::10", false, false, "::/0 table 254 unicast", "", mainRule, default6, byUp0, ""},
		{"arriving IPv6 unicast route", "2001:db8:2::5", "2001:db8:ffff::10", true, false, "::/0 table 254 unicast", "", mainRule, default6, byUp0, ""},
		{"arriving IPv6 unicast route, forwarding off", "2001:db8:2::5", "2001:db8:ffff::10", true, true, "::/0 table 254 unicast", "", mainRule, default6, "nowhere, the kernel drops it after the lookup with forwarding off in all and force_forwarding not on for in0", ""},
		{"own IPv6 local address", "2001:db8:1::2", "2001:db8:2::1", false, false, "2001:db8:2::1/128 table 255 local", "", localRule, "2001:db8:2::1/128 in table local, local, dev in0", delivered, ""},
		{"arriving IPv6 local address", "2001:db8:2::5", "2001:db8:2::1", true, false, "2001:db8:2::1/128 table 255 local", "", localRule, "2001:db8:2::1/128 in table local, local, dev in0", delivered, ""},
		{"own IPv6 joined group", "2001:db8:1::2", "ff0e::123", false, false, "ff00::/8 table 255 multicast", "", localRule, "ff00::/8 in table local, multicast, dev up0", byUp0, ""},
		{"arriving IPv6 joined group", "2001:db8:2::5", "ff0e::123", true, false, "EMSGSIZE", group6, noRoute6, "", "", ""},
		{"own IPv6 unjoined group", "2001:db8:1::2", "ff0e::124", false, false, "ff00::/8 table 255 multicast", "", localRule, "ff00::/8 in table local, multicast, dev up0", byUp0, ""},
		{"arriving IPv6 unjoined group", "2001:db8:2::5", "ff0e::124", true, false, "EMSGSIZE", group6, noRoute6, "", "", ""},
		{"own IPv6 link-local group", "2001:db8:1::2", "ff02::1", false, false, "ff00::/8 table 255 multicast", "", localRule, "ff00::/8 in table local, multicast, dev up0", byUp0, ""},
		{"arriving IPv6 link-local group", "2001:db8:2::5", "ff02::1", true, false, "EMSGSIZE", group6, noRoute6, "", "", ""},
		{"own ::", "2001:db8:1::2", "::", false, false, "::/0 table 254 unicast", "", mainRule, default6, "", unspecified},
		{"arriving ::", "2001:db8:2::5", "::", true, false, "::/0 table 254 unicast", "", mainRule, default6, byUp0, ""},
		{"own IPv6 link-local unicast", "2001:db8:1::2", "fe80::1", false, false, "fe80::/64 table 254 unicast", "", mainRule, "fe80::/64 in table main, unicast, dev up0", byUp0, ""},
		{"arriving IPv6 link-local unicast", "2001:db8:2::5", "fe80::1", true, false, "fe80::/64 table 254 unicast", "", mainRule, "fe80::/64 in table main, unicast, dev in0", "by in0, outside the mesh", ""},
	} {
		check(row)
	}
	// multicast routing on in all, which MRT_INIT sets while its socket
	// stays open, and on no link of the namespace
	mroute, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_IGMP)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(mroute) })
	if err := unix.SetsockoptInt(mroute, unix.IPPROTO_IP, routeViewMRTInit, 1); err != nil {
		t.Fatalf("turn multicast routing on: %v", err)
	}
	const withheld = "EHOSTUNREACH, the route of a group arriving on in0, which the kernel's multicast routing withholds from its answer"
	for _, row := range []kindRow{
		{"arriving joined group under multicast routing", "198.51.100.140", "239.1.2.3", true, false, "EHOSTUNREACH", withheld, noWalk, "", "", ""},
		{"arriving joined group under multicast routing, forwarding off", "198.51.100.140", "239.1.2.3", true, true, "EHOSTUNREACH", withheld, noWalk, "", "", ""},
		{"arriving link-local group under multicast routing", "198.51.100.140", "224.0.0.1", true, false, "224.0.0.1/32 table 0 multicast of no entry", "", noEntry, entry("224.0.0.1/32", "multicast", "lo"), joined, ""},
	} {
		check(row)
	}
	noDefault := slices.Concat([]byte{unix.AF_INET6, 0, 0, 0, unix.RT_TABLE_MAIN, 0, 0, unix.RTN_UNICAST, 0, 0, 0, 0}, netnstest.Attr(unix.RTA_OIF, netnstest.U32(uint32(up.Index))))
	if err := netlink.Request(unix.RTM_DELROUTE, 0, noDefault); err != nil {
		t.Fatalf("delete ::/0 by up0: %v", err)
	}
	check(kindRow{"own :: with no IPv6 default", "2001:db8:1::2", "::", false, false, "ENETUNREACH", "ENETUNREACH, no route", "none named, the walk ends past the last rule", "", "", unspecified})
}

// routeViewTUN makes the tun name in this thread's namespace and answers its
// file descriptor, which the test closes at its end
func routeViewTUN(t *testing.T, name string) int {
	t.Helper()
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open /dev/net/tun: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		t.Fatalf("build an ifreq for %s: %v", name, err)
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		t.Fatalf("make the tun %s: %v", name, err)
	}
	return fd
}

// routeViewUDP is an empty UDP datagram from src to dst, which no hop on the
// way checks the checksum of
func routeViewUDP(src, dst netip.Addr) []byte {
	packet := make([]byte, 48)
	packet[0], packet[6], packet[7] = 0x60, unix.IPPROTO_UDP, 64
	binary.BigEndian.PutUint16(packet[4:], 8)
	s, d := src.As16(), dst.As16()
	copy(packet[8:], s[:])
	copy(packet[24:], d[:])
	binary.BigEndian.PutUint16(packet[40:], 9)
	binary.BigEndian.PutUint16(packet[42:], 9)
	binary.BigEndian.PutUint16(packet[44:], 8)
	return packet
}

// routeViewSysctl sets the sysctl at path under /proc/sys in this thread's
// namespace
func routeViewSysctl(t *testing.T, path, value string) {
	t.Helper()
	if err := os.WriteFile("/proc/sys/"+path, []byte(value), 0); err != nil {
		t.Fatalf("set %s to %s: %v", path, value, err)
	}
}

// routeViewCount is the IPv6 counter name of this thread's namespace
func routeViewCount(t *testing.T, name string) uint64 {
	t.Helper()
	count, err := labKernelCount("/proc/thread-self/net/snmp6", name)
	if err != nil {
		t.Fatal(err)
	}
	return count
}
