// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"golang.org/x/sys/unix"
)

// WatchNetwork opens the network watch over rtnetlink, one socket for its notifications and one for its reads
// mesh names this node's tun, whose addresses and routes never signal, and is empty on a node without one
// host is read on darwin alone
func WatchNetwork(_ Host, mesh string) (*NetworkWatch, error) {
	conn, err := dialNetlink()
	if err != nil {
		return nil, err
	}
	var index uint32
	if mesh != "" {
		link, err := conn.link(0, mesh)
		if err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("kernel: look up interface %s: %w", mesh, err)
		}
		index = link.index
	}
	monitor, err := openMonitor("rtnetlink-netwatch", watchGroups, hostWakes(index))
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	host := hostReader{conn: conn, mesh: index}
	return newNetworkWatch(monitor.signal, host.read, func() error { return errors.Join(monitor.Close(), conn.Close()) })
}

// watchGroups are the rtnetlink groups whose notifications can move what hostReader reads
const watchGroups = unix.RTMGRP_LINK | unix.RTMGRP_IPV4_IFADDR | unix.RTMGRP_IPV6_IFADDR | unix.RTMGRP_IPV4_ROUTE | unix.RTMGRP_IPV6_ROUTE

// hostWakes takes a notification that can change what hostReader reads
// a route outside main, which holds the reconciler's own table whenever that is another one, and anything on the mesh's device never wakes it
// nor does a route that is no default, since the read looks at no other and main may hold a full table
func hostWakes(mesh uint32) func(nlMessage) bool {
	return func(message nlMessage) bool {
		switch message.Kind {
		case unix.RTM_NEWLINK, unix.RTM_DELLINK:
			return len(message.Data) >= unix.SizeofIfInfomsg && outsideMesh(binary.NativeEndian.Uint32(message.Data[4:]), mesh)
		case unix.RTM_NEWADDR, unix.RTM_DELADDR:
			return len(message.Data) >= unix.SizeofIfAddrmsg && outsideMesh(binary.NativeEndian.Uint32(message.Data[4:]), mesh)
		case unix.RTM_NEWROUTE, unix.RTM_DELROUTE:
			if len(message.Data) < unix.SizeofRtMsg || message.Data[1] != 0 {
				return false
			}
			oif, _ := routeHop(message)
			return notificationTable(message) == unix.RT_TABLE_MAIN && outsideMesh(oif, mesh)
		}
		return false
	}
}

// outsideMesh reports whether index names a device other than the mesh's, where mesh 0 is a node without one
func outsideMesh(index, mesh uint32) bool { return mesh == 0 || index != mesh }

// hostReader reads the host's network through the watch's own request socket
type hostReader struct {
	conn *nlConn
	mesh uint32
}

func (h hostReader) read() (NetworkState, error) {
	links, err := h.conn.execute(unix.RTM_GETLINK, unix.NLM_F_DUMP, make([]byte, unix.SizeofIfInfomsg))
	if err != nil {
		return NetworkState{}, fmt.Errorf("kernel: dump links: %w", err)
	}
	up := upLinks(links, h.mesh)
	var state NetworkState
	for _, family := range []struct {
		af  uint8
		out *NetworkFamily
	}{{unix.AF_INET, &state.IPv4}, {unix.AF_INET6, &state.IPv6}} {
		body := make([]byte, unix.SizeofIfAddrmsg)
		body[0] = family.af
		addresses, err := h.conn.execute(unix.RTM_GETADDR, unix.NLM_F_DUMP, body)
		if err != nil {
			return NetworkState{}, fmt.Errorf("kernel: dump addresses: %w", err)
		}
		body = make([]byte, unix.SizeofRtMsg)
		body[0] = family.af
		routes, err := h.conn.execute(unix.RTM_GETROUTE, unix.NLM_F_DUMP, putAttrU32(body, unix.RTA_TABLE, unix.RT_TABLE_MAIN))
		// main holding nothing yet ends its dump on ENOENT, as dumpTable reads an unwritten table
		if err != nil && !errors.Is(err, unix.ENOENT) {
			return NetworkState{}, fmt.Errorf("kernel: dump the main table: %w", err)
		}
		family.out.Addresses = upAddresses(addresses, family.af, up)
		family.out.Default = upDefault(routes, family.af, up)
	}
	return state, nil
}

// upLinks names every link of a link dump that is up, the mesh's device left out
func upLinks(replies []nlMessage, mesh uint32) map[uint32]string {
	up := make(map[uint32]string)
	for _, reply := range replies {
		if reply.Kind != unix.RTM_NEWLINK || len(reply.Data) < unix.SizeofIfInfomsg {
			continue
		}
		link := decodeLink(reply)
		if binary.NativeEndian.Uint32(reply.Data[8:])&unix.IFF_UP != 0 && outsideMesh(link.index, mesh) {
			up[link.index] = link.name
		}
	}
	return up
}

// upAddresses is every global unicast address of one family an address dump holds on a link in up
// an address still proving itself unique is not one a socket can send from yet
func upAddresses(replies []nlMessage, family uint8, up map[uint32]string) []netip.Addr {
	var out []netip.Addr
	for _, reply := range replies {
		// a kernel without one family answers its dump with the other's entries
		if reply.Kind != unix.RTM_NEWADDR || len(reply.Data) < unix.SizeofIfAddrmsg || reply.Data[0] != family {
			continue
		}
		if _, ok := up[binary.NativeEndian.Uint32(reply.Data[4:])]; !ok {
			continue
		}
		flags := uint32(reply.Data[2])
		var local, address netip.Addr
		for attr, value := range reply.attributes(unix.SizeofIfAddrmsg) {
			switch attr {
			case unix.IFA_LOCAL:
				local, _ = addressFromBytes(value)
			case unix.IFA_ADDRESS:
				address, _ = addressFromBytes(value)
			case unix.IFA_FLAGS:
				if len(value) == 4 {
					flags = binary.NativeEndian.Uint32(value)
				}
			}
		}
		// IFA_ADDRESS is the far end on a point-to-point link, IFA_LOCAL this one
		if !local.IsValid() {
			local = address
		}
		if local.IsGlobalUnicast() && flags&(unix.IFA_F_TENTATIVE|unix.IFA_F_DADFAILED) == 0 {
			out = append(out, local)
		}
	}
	return addressSet(out)
}

// upDefault is the default of one family a dump of main holds leaving by a link in up, the one of lowest metric where there are several
func upDefault(replies []nlMessage, family uint8, up map[uint32]string) DefaultRoute {
	var best DefaultRoute
	var bestMetric uint32
	for _, reply := range replies {
		if reply.Kind != unix.RTM_NEWROUTE || len(reply.Data) < unix.SizeofRtMsg || reply.Data[0] != family {
			continue
		}
		dstLen, srcLen, kind := reply.Data[1], reply.Data[2], reply.Data[7]
		if dstLen != 0 || srcLen != 0 || kind != unix.RTN_UNICAST || notificationTable(reply) != unix.RT_TABLE_MAIN {
			continue
		}
		oif, gateway := routeHop(reply)
		name, ok := up[oif]
		if !ok {
			continue
		}
		var metric uint32
		for attr, value := range reply.attributes(unix.SizeofRtMsg) {
			if attr == unix.RTA_PRIORITY && len(value) == 4 {
				metric = binary.NativeEndian.Uint32(value)
			}
		}
		if best.Interface == "" || metric < bestMetric {
			best, bestMetric = DefaultRoute{Interface: name, Gateway: gateway}, metric
		}
	}
	return best
}

// routeHop is the device and gateway of one route, the first live hop of a multipath one
// a hop the kernel marks dead or without carrier answers device 0
func routeHop(message nlMessage) (uint32, netip.Addr) {
	if len(message.Data) < unix.SizeofRtMsg {
		return 0, netip.Addr{}
	}
	var oif uint32
	var gateway netip.Addr
	var hops []byte
	for attr, value := range message.attributes(unix.SizeofRtMsg) {
		switch attr {
		case unix.RTA_OIF:
			if len(value) == 4 {
				oif = binary.NativeEndian.Uint32(value)
			}
		case unix.RTA_GATEWAY:
			gateway, _ = addressFromBytes(value)
		case unix.RTA_MULTIPATH:
			hops = value
		}
	}
	const down = unix.RTNH_F_DEAD | unix.RTNH_F_LINKDOWN
	if oif != 0 {
		if binary.NativeEndian.Uint32(message.Data[8:])&down != 0 {
			return 0, netip.Addr{}
		}
		return oif, gateway
	}
	for len(hops) >= unix.SizeofRtNexthop {
		size := int(binary.NativeEndian.Uint16(hops))
		if size < unix.SizeofRtNexthop || size > len(hops) {
			break
		}
		if hops[2]&down == 0 {
			hop := nlMessage{Data: hops[:size]}
			for attr, value := range hop.attributes(unix.SizeofRtNexthop) {
				if attr == unix.RTA_GATEWAY {
					gateway, _ = addressFromBytes(value)
				}
			}
			return binary.NativeEndian.Uint32(hops[4:]), gateway
		}
		hops = hops[rtaAlign(size):]
	}
	return 0, netip.Addr{}
}
