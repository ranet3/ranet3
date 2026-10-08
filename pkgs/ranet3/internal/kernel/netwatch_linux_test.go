// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"encoding/binary"
	"errors"
	"maps"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// otherTable is a table another routing daemon writes, the reconciler's own among them when it is not main
const otherTable = 100

// hostAddrMessage is the RTM_NEWADDR or RTM_DELADDR body of one address on one device
func hostAddrMessage(index uint32, prefix netip.Prefix) []byte {
	body := make([]byte, unix.SizeofIfAddrmsg)
	body[0] = unix.AF_INET
	if prefix.Addr().Is6() {
		body[0] = unix.AF_INET6
	}
	body[1] = uint8(prefix.Bits())
	binary.NativeEndian.PutUint32(body[4:], index)
	body = putAttr(body, unix.IFA_LOCAL, addressBytes(prefix.Addr()))
	return putAttr(body, unix.IFA_ADDRESS, addressBytes(prefix.Addr()))
}

// hostRouteMessage is the RTM_NEWROUTE or RTM_DELROUTE body of one IPv4 route out of one device, through gateway where it is valid
func hostRouteMessage(table, index uint32, destination netip.Prefix, gateway netip.Addr) []byte {
	body := make([]byte, unix.SizeofRtMsg)
	body[0] = unix.AF_INET
	body[1] = uint8(destination.Bits())
	body[5] = unix.RTPROT_BOOT
	body[6] = unix.RT_SCOPE_LINK
	body[7] = unix.RTN_UNICAST
	body = putAttrU32(body, unix.RTA_TABLE, table)
	if destination.Bits() > 0 {
		body = putAttr(body, unix.RTA_DST, addressBytes(destination.Addr()))
	}
	if gateway.IsValid() {
		body[6] = unix.RT_SCOPE_UNIVERSE
		body = putAttr(body, unix.RTA_GATEWAY, addressBytes(gateway))
	}
	return putAttrU32(body, unix.RTA_OIF, index)
}

// the watch wakes on a link, an address or a main table default outside the mesh's device
// another table, a route that is no default and the mesh's own device never wake it
func TestHostWakesOutsideTheMeshAndOtherTables(t *testing.T) {
	const uplink, mesh = 2, 9
	link := func(index uint32) []byte {
		body := make([]byte, unix.SizeofIfInfomsg)
		binary.NativeEndian.PutUint32(body[4:], index)
		return body
	}
	for name, arm := range map[string]struct {
		message nlMessage
		mesh    uint32
		want    bool
	}{
		"an uplink address":                    {nlMessage{Kind: unix.RTM_NEWADDR, Data: hostAddrMessage(uplink, prefix("192.0.2.10/24"))}, mesh, true},
		"an address on the mesh":               {nlMessage{Kind: unix.RTM_DELADDR, Data: hostAddrMessage(mesh, prefix("10.99.0.1/32"))}, mesh, false},
		"an uplink link":                       {nlMessage{Kind: unix.RTM_NEWLINK, Data: link(uplink)}, mesh, true},
		"the mesh's link":                      {nlMessage{Kind: unix.RTM_NEWLINK, Data: link(mesh)}, mesh, false},
		"a main default":                       {nlMessage{Kind: unix.RTM_NEWROUTE, Data: hostRouteMessage(unix.RT_TABLE_MAIN, uplink, prefix("0.0.0.0/0"), netip.MustParseAddr("192.0.2.1"))}, mesh, true},
		"a main route on the uplink":           {nlMessage{Kind: unix.RTM_DELROUTE, Data: hostRouteMessage(unix.RT_TABLE_MAIN, uplink, prefix("203.0.113.0/24"), netip.Addr{})}, mesh, false},
		"a main default out of the mesh":       {nlMessage{Kind: unix.RTM_NEWROUTE, Data: hostRouteMessage(unix.RT_TABLE_MAIN, mesh, prefix("0.0.0.0/0"), netip.Addr{})}, mesh, false},
		"a default in another table":           {nlMessage{Kind: unix.RTM_DELROUTE, Data: hostRouteMessage(otherTable, uplink, prefix("0.0.0.0/0"), netip.Addr{})}, mesh, false},
		"a main default on a node without one": {nlMessage{Kind: unix.RTM_NEWROUTE, Data: hostRouteMessage(unix.RT_TABLE_MAIN, mesh, prefix("0.0.0.0/0"), netip.Addr{})}, 0, true},
		"a rule":                               {nlMessage{Kind: unix.RTM_DELRULE, Data: make([]byte, sizeofFibRuleHdr)}, mesh, false},
	} {
		if got := hostWakes(arm.mesh)(arm.message); got != arm.want {
			t.Errorf("%s: the watch woke %v, want %v", name, got, arm.want)
		}
	}
}

// in a fresh namespace an address and a default route on an uplink signal as they come and go
// a route in another table, and an address and a route on the device standing in for the mesh, signal nothing
func TestNetworkWatchInNetworkNamespace(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real netlink path needs root on linux")
	}
	enterThrowawayNamespace(t)
	conn, err := dialNetlink()
	if err != nil {
		t.Fatalf("dial rtnetlink: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	requireEmptyNamespace(t, conn)
	const uplinkName, meshName = "ranetuplink0", "ranetwatch0"
	createTUN(t, uplinkName)
	createTUN(t, meshName)
	uplink, err := conn.link(0, uplinkName)
	if err != nil {
		t.Fatal(err)
	}
	mesh, err := conn.link(0, meshName)
	if err != nil {
		t.Fatal(err)
	}
	setLinkFlags(t, conn, uplink.index, unix.IFF_UP)
	setLinkFlags(t, conn, mesh.index, unix.IFF_UP)

	w, err := WatchNetwork(nil, meshName)
	if err != nil {
		t.Fatalf("open the watch: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })

	address, meshAddress := prefix("192.0.2.10/24"), prefix("10.99.0.1/32")
	gateway := netip.MustParseAddr("192.0.2.1")
	// the mesh's own default sits behind the uplink's, as an exit node's would in main
	meshDefault := putAttrU32(hostRouteMessage(unix.RT_TABLE_MAIN, mesh.index, prefix("0.0.0.0/0"), netip.Addr{}), unix.RTA_PRIORITY, 50)
	// a main route that is no default wakes nothing
	// the read the uplink default's removal costs meets the mesh's address and default, which no notification of their own reaches
	uplinkRoute := hostRouteMessage(unix.RT_TABLE_MAIN, uplink.index, prefix("203.0.113.0/24"), netip.Addr{})
	add, del := uint16(unix.NLM_F_CREATE|unix.NLM_F_EXCL|unix.NLM_F_ACK), uint16(unix.NLM_F_ACK)
	var changes []NetworkChange
	for _, step := range []struct {
		name        string
		kind, flags uint16
		body        []byte
		signals     bool
	}{
		{"an uplink address", unix.RTM_NEWADDR, add, hostAddrMessage(uplink.index, address), true},
		{"a default route", unix.RTM_NEWROUTE, add, hostRouteMessage(unix.RT_TABLE_MAIN, uplink.index, prefix("0.0.0.0/0"), gateway), true},
		{"a route in another table", unix.RTM_NEWROUTE, add, hostRouteMessage(otherTable, uplink.index, prefix("198.51.100.0/24"), netip.Addr{}), false},
		{"a default in another table", unix.RTM_NEWROUTE, add, hostRouteMessage(otherTable, uplink.index, prefix("0.0.0.0/0"), gateway), false},
		{"the other table emptied", unix.RTM_DELROUTE, del, hostRouteMessage(otherTable, uplink.index, prefix("198.51.100.0/24"), netip.Addr{}), false},
		{"an address on the mesh", unix.RTM_NEWADDR, add, hostAddrMessage(mesh.index, meshAddress), false},
		{"a main route out of the mesh", unix.RTM_NEWROUTE, add, hostRouteMessage(unix.RT_TABLE_MAIN, mesh.index, prefix("10.0.0.0/8"), netip.Addr{}), false},
		{"a default out of the mesh", unix.RTM_NEWROUTE, add, meshDefault, false},
		{"a main route on the uplink", unix.RTM_NEWROUTE, add, uplinkRoute, false},
		{"the default route gone", unix.RTM_DELROUTE, del, hostRouteMessage(unix.RT_TABLE_MAIN, uplink.index, prefix("0.0.0.0/0"), gateway), true},
		{"the mesh default gone", unix.RTM_DELROUTE, del, meshDefault, false},
		{"the mesh route gone", unix.RTM_DELROUTE, del, hostRouteMessage(unix.RT_TABLE_MAIN, mesh.index, prefix("10.0.0.0/8"), netip.Addr{}), false},
		{"the mesh address gone", unix.RTM_DELADDR, del, hostAddrMessage(mesh.index, meshAddress), false},
		{"the main route on the uplink gone", unix.RTM_DELROUTE, del, uplinkRoute, false},
		{"the uplink address gone", unix.RTM_DELADDR, del, hostAddrMessage(uplink.index, address), true},
	} {
		if _, err := conn.execute(step.kind, step.flags, step.body); err != nil {
			t.Fatalf("%s: %v", step.name, err)
		}
		select {
		case change := <-w.Changes():
			changes = append(changes, change)
			if !step.signals {
				t.Errorf("%s signaled %+v", step.name, change.Families())
			}
		case <-time.After(quietWindow):
			if step.signals {
				t.Errorf("%s signaled nothing", step.name)
			}
		}
	}
	if t.Failed() {
		return
	}
	if gone := changes[2].After.IPv4; gone.Default != (DefaultRoute{}) || !slices.Equal(gone.Addresses, []netip.Addr{address.Addr()}) {
		t.Errorf("with the uplink's default gone the watch reads %+v, want the uplink's address alone and none of the mesh's", gone)
	}
	if current, last := w.State(); current.IPv4.Default.Interface != "" || len(current.IPv4.Addresses) != 0 || !slices.Equal(last.Before.IPv4.Addresses, []netip.Addr{address.Addr()}) {
		t.Errorf("the watch ends reading %+v after a last change from %+v", current, last.Before)
	}
}

// routeBurst is how many routes that are no default a test adds to main and deletes again
const routeBurst = 64

// a burst of routes in main that are no default costs the watch no read, since a host may hold a full table there
// a default in main still costs one and signals
func TestNetworkWatchReadsNothingForMainRoutesThatAreNoDefault(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real netlink path needs root on linux")
	}
	enterThrowawayNamespace(t)
	conn, err := dialNetlink()
	if err != nil {
		t.Fatalf("dial rtnetlink: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	requireEmptyNamespace(t, conn)
	const uplinkName = "ranetuplink0"
	createTUN(t, uplinkName)
	uplink, err := conn.link(0, uplinkName)
	if err != nil {
		t.Fatal(err)
	}
	setLinkFlags(t, conn, uplink.index, unix.IFF_UP)
	add, del := uint16(unix.NLM_F_CREATE|unix.NLM_F_EXCL|unix.NLM_F_ACK), uint16(unix.NLM_F_ACK)
	if _, err := conn.execute(unix.RTM_NEWADDR, add, hostAddrMessage(uplink.index, prefix("192.0.2.10/24"))); err != nil {
		t.Fatal(err)
	}

	reader, err := dialNetlink()
	if err != nil {
		t.Fatalf("dial rtnetlink: %v", err)
	}
	monitor, err := openMonitor("rtnetlink-netwatch", watchGroups, hostWakes(0))
	if err != nil {
		_ = reader.Close()
		t.Fatal(err)
	}
	host := hostReader{conn: reader}
	var reads atomic.Int32
	read := func() (NetworkState, error) {
		reads.Add(1)
		return host.read()
	}
	w, err := newNetworkWatch(monitor.signal, read, func() error { return errors.Join(monitor.Close(), reader.Close()) })
	if err != nil {
		t.Fatalf("open the watch: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })
	// what bringing the uplink up still announces settles first
	time.Sleep(quietWindow)
	settled := reads.Load()

	for _, kind := range []struct {
		kind, flags uint16
	}{{unix.RTM_NEWROUTE, add}, {unix.RTM_DELROUTE, del}} {
		for i := range routeBurst {
			route := hostRouteMessage(unix.RT_TABLE_MAIN, uplink.index, netip.PrefixFrom(netip.AddrFrom4([4]byte{203, 0, 113, byte(i)}), 32), netip.Addr{})
			if _, err := conn.execute(kind.kind, kind.flags, route); err != nil {
				t.Fatalf("route %d: %v", i, err)
			}
		}
	}
	time.Sleep(quietWindow)
	if burst := reads.Load() - settled; burst != 0 {
		t.Errorf("%d changes to routes in main that are no default cost %d read(s) of the host", 2*routeBurst, burst)
	}

	if _, err := conn.execute(unix.RTM_NEWROUTE, add, hostRouteMessage(unix.RT_TABLE_MAIN, uplink.index, prefix("0.0.0.0/0"), netip.MustParseAddr("192.0.2.1"))); err != nil {
		t.Fatal(err)
	}
	select {
	case change := <-w.Changes():
		if change.After.IPv4.Default.Interface != uplinkName {
			t.Errorf("a default on the uplink signaled %+v", change.After.IPv4.Default)
		}
	case <-time.After(quietWindow):
		t.Error("a default in main signaled nothing")
	}
}

// linkMessage is the RTM_NEWLINK of one named link with its flags
func linkMessage(index uint32, name string, flags uint32) nlMessage {
	body := make([]byte, unix.SizeofIfInfomsg)
	binary.NativeEndian.PutUint32(body[4:], index)
	binary.NativeEndian.PutUint32(body[8:], flags)
	return nlMessage{Kind: unix.RTM_NEWLINK, Data: putAttrString(body, unix.IFLA_IFNAME, name)}
}

// the reader keeps the links that are up and leaves out a down one and the mesh's
func TestReaderKeepsUpLinksOutsideTheMesh(t *testing.T) {
	const mesh = 9
	got := upLinks([]nlMessage{
		linkMessage(2, "eth0", unix.IFF_UP|unix.IFF_RUNNING),
		linkMessage(3, "eth1", unix.IFF_RUNNING),
		linkMessage(mesh, "ranet0", unix.IFF_UP|unix.IFF_RUNNING),
	}, mesh)
	if want := map[uint32]string{2: "eth0"}; !maps.Equal(got, want) {
		t.Errorf("the reader takes %v as up, want %v", got, want)
	}
}

// addressMessage is the RTM_NEWADDR of one address, its IFA_LOCAL and IFA_ADDRESS each left out where invalid
// flags ride in ifa_flags, or in IFA_FLAGS alone where inAttribute is set, as the flags above the first byte do
func addressMessage(index uint32, local, address netip.Addr, flags uint32, inAttribute bool) nlMessage {
	body := make([]byte, unix.SizeofIfAddrmsg)
	body[0] = unix.AF_INET
	if local.Is6() || address.Is6() {
		body[0] = unix.AF_INET6
	}
	binary.NativeEndian.PutUint32(body[4:], index)
	if local.IsValid() {
		body = putAttr(body, unix.IFA_LOCAL, addressBytes(local))
	}
	if address.IsValid() {
		body = putAttr(body, unix.IFA_ADDRESS, addressBytes(address))
	}
	if inAttribute {
		body = putAttrU32(body, unix.IFA_FLAGS, flags)
	} else {
		body[2] = uint8(flags)
	}
	return nlMessage{Kind: unix.RTM_NEWADDR, Data: body}
}

// the reader keeps the global unicast addresses a socket can send from on an up link, the local end of a point-to-point one
// an address on a down link, a link-local one and one still in or failed by duplicate address detection stay out
func TestReaderKeepsAddressesASocketCanSendFrom(t *testing.T) {
	up := map[uint32]string{2: "eth0"}
	addr := netip.MustParseAddr
	none := netip.Addr{}
	v4 := upAddresses([]nlMessage{
		addressMessage(2, addr("192.0.2.10"), addr("192.0.2.10"), 0, false),
		addressMessage(3, addr("198.51.100.10"), addr("198.51.100.10"), 0, false),
		addressMessage(2, addr("169.254.1.1"), addr("169.254.1.1"), 0, false),
		addressMessage(2, addr("10.0.0.1"), addr("10.0.0.2"), 0, false),
		addressMessage(2, none, addr("2001:db8::9"), 0, false),
	}, unix.AF_INET, up)
	if want := addrs("10.0.0.1", "192.0.2.10"); !slices.Equal(v4, want) {
		t.Errorf("the reader takes IPv4 as %v, want %v", v4, want)
	}
	v6 := upAddresses([]nlMessage{
		addressMessage(2, none, addr("2001:db8::5"), unix.IFA_F_PERMANENT, false),
		addressMessage(2, none, addr("2001:db8::6"), unix.IFA_F_TENTATIVE, false),
		addressMessage(2, none, addr("2001:db8::7"), unix.IFA_F_DADFAILED, true),
		addressMessage(2, none, addr("fe80::1"), 0, false),
		addressMessage(2, addr("192.0.2.11"), addr("192.0.2.11"), 0, false),
	}, unix.AF_INET6, up)
	if want := addrs("2001:db8::5"); !slices.Equal(v6, want) {
		t.Errorf("the reader takes IPv6 as %v, want %v", v6, want)
	}
}

// defaultMessage is the RTM_NEWROUTE of one IPv4 default in main of a kind and metric out of index, through gateway where it is valid
func defaultMessage(index uint32, gateway netip.Addr, kind uint8, metric uint32) nlMessage {
	body := hostRouteMessage(unix.RT_TABLE_MAIN, index, prefix("0.0.0.0/0"), gateway)
	body[6] = unix.RT_SCOPE_UNIVERSE
	body[7] = kind
	return nlMessage{Kind: unix.RTM_NEWROUTE, Data: putAttrU32(body, unix.RTA_PRIORITY, metric)}
}

// the reader takes the unicast default of lowest metric, whatever order the dump holds the candidates in
// an unreachable default leaves by lo on IPv6, which is up, and is no way off the host
func TestReaderTakesTheLowestMetricUnicastDefault(t *testing.T) {
	up := map[uint32]string{1: "lo", 2: "en7", 3: "wlan0"}
	dockGateway, wifiGateway := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.1")
	dock := defaultMessage(2, dockGateway, unix.RTN_UNICAST, 100)
	wifi := defaultMessage(3, wifiGateway, unix.RTN_UNICAST, 600)
	unreachable := defaultMessage(1, netip.Addr{}, unix.RTN_UNREACHABLE, 0)
	nearer := nlMessage{Kind: unix.RTM_NEWROUTE, Data: hostRouteMessage(unix.RT_TABLE_MAIN, 3, prefix("203.0.113.0/24"), netip.Addr{})}
	for _, arm := range []struct {
		name  string
		dump  []nlMessage
		route DefaultRoute
	}{
		{"the dock after the wifi", []nlMessage{wifi, dock, unreachable, nearer}, DefaultRoute{Interface: "en7", Gateway: dockGateway}},
		{"the dock before the wifi", []nlMessage{unreachable, nearer, dock, wifi}, DefaultRoute{Interface: "en7", Gateway: dockGateway}},
		{"the dock gone", []nlMessage{unreachable, wifi}, DefaultRoute{Interface: "wlan0", Gateway: wifiGateway}},
		{"no unicast default", []nlMessage{unreachable, nearer}, DefaultRoute{}},
	} {
		if got := upDefault(arm.dump, unix.AF_INET, up); got != arm.route {
			t.Errorf("%s: the reader takes %+v, want %+v", arm.name, got, arm.route)
		}
	}
}

// nexthop is one rtnexthop of an RTA_MULTIPATH, its gateway left out where invalid
func nexthop(index uint32, flags uint8, gateway netip.Addr) []byte {
	hop := make([]byte, unix.SizeofRtNexthop)
	hop[2] = flags
	binary.NativeEndian.PutUint32(hop[4:], index)
	if gateway.IsValid() {
		hop = putAttr(hop, unix.RTA_GATEWAY, addressBytes(gateway))
	}
	binary.NativeEndian.PutUint16(hop, uint16(len(hop)))
	return hop
}

// the hop of a route is its own device unless the kernel marks it dead or without carrier, and the first live one of a multipath route
// a hop whose length does not fit ends the walk
func TestRouteHopTakesTheFirstLiveHop(t *testing.T) {
	first, second := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.1")
	single := func(flags uint32) nlMessage {
		body := hostRouteMessage(unix.RT_TABLE_MAIN, 2, prefix("0.0.0.0/0"), first)
		binary.NativeEndian.PutUint32(body[8:], flags)
		return nlMessage{Kind: unix.RTM_NEWROUTE, Data: body}
	}
	multipath := func(hops ...[]byte) nlMessage {
		body := make([]byte, unix.SizeofRtMsg)
		body[0] = unix.AF_INET
		body[7] = unix.RTN_UNICAST
		body = putAttrU32(body, unix.RTA_TABLE, unix.RT_TABLE_MAIN)
		return nlMessage{Kind: unix.RTM_NEWROUTE, Data: putAttr(body, unix.RTA_MULTIPATH, slices.Concat(hops...))}
	}
	sized := func(hop []byte, size uint16) []byte {
		binary.NativeEndian.PutUint16(hop, size)
		return hop
	}
	for _, arm := range []struct {
		name    string
		message nlMessage
		device  uint32
		gateway netip.Addr
	}{
		{"a single hop", single(0), 2, first},
		{"a single hop without carrier", single(unix.RTNH_F_LINKDOWN), 0, netip.Addr{}},
		{"a single dead hop", single(unix.RTNH_F_DEAD), 0, netip.Addr{}},
		{"a live first hop", multipath(nexthop(2, 0, first), nexthop(3, 0, second)), 2, first},
		{"a dead first hop", multipath(nexthop(2, unix.RTNH_F_DEAD, first), nexthop(3, 0, second)), 3, second},
		{"a first hop without carrier", multipath(nexthop(2, unix.RTNH_F_LINKDOWN, first), nexthop(3, 0, second)), 3, second},
		{"every hop down", multipath(nexthop(2, unix.RTNH_F_DEAD, first), nexthop(3, unix.RTNH_F_LINKDOWN, second)), 0, netip.Addr{}},
		{"a hop shorter than its header", multipath(sized(nexthop(2, 0, first), unix.SizeofRtNexthop-1), nexthop(3, 0, second)), 0, netip.Addr{}},
		{"a hop longer than the attribute", multipath(sized(nexthop(2, 0, first), 64)), 0, netip.Addr{}},
		{"a message shorter than its header", nlMessage{Kind: unix.RTM_NEWROUTE, Data: make([]byte, unix.SizeofRtMsg-1)}, 0, netip.Addr{}},
	} {
		if device, gateway := routeHop(arm.message); device != arm.device || gateway != arm.gateway {
			t.Errorf("%s: the hop is device %d through %v, want %d through %v", arm.name, device, gateway, arm.device, arm.gateway)
		}
	}
}
