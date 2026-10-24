// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"iter"
	"net/netip"

	"golang.org/x/sys/unix"
)

func routeGet(src, dst netip.Addr, iif string) (MatchedRoute, error) {
	conn, err := dialNetlink()
	if err != nil {
		return MatchedRoute{}, err
	}
	defer conn.Close()
	var arrival uint32
	if iif != "" {
		link, err := conn.link(0, iif)
		if err != nil {
			return MatchedRoute{}, fmt.Errorf("kernel: look up interface %s: %w", iif, err)
		}
		arrival = link.index
	}
	route, indexes, err := conn.matchedRoute(src, dst, arrival)
	if err != nil {
		return MatchedRoute{}, err
	}
	for i, index := range indexes {
		link, err := conn.link(index, "")
		if err != nil {
			return MatchedRoute{}, fmt.Errorf("kernel: name interface %d: %w", index, err)
		}
		route.NextHops[i].Device = link.name
	}
	return route, nil
}

// matchedRoute is one RTM_GETROUTE under RTM_F_FIB_MATCH, for a packet from src
// to dst arriving on the device of index arrival, or this host's own for 0. It
// answers each next hop's interface index at its place in NextHops, whose
// Device it leaves empty
func (c *nlConn) matchedRoute(src, dst netip.Addr, arrival uint32) (MatchedRoute, []uint32, error) {
	body := make([]byte, unix.SizeofRtMsg)
	body[0] = unix.AF_INET6
	flags := uint32(unix.RTM_F_FIB_MATCH)
	if dst.Is4() {
		// IPv4 answers with main for the table unless asked for the one it
		// looked in, and IPv6 refuses the flag
		body[0], flags = unix.AF_INET, flags|unix.RTM_F_LOOKUP_TABLE
	}
	body[1] = uint8(dst.BitLen())
	if src.IsValid() {
		body[2] = uint8(src.BitLen())
	}
	binary.NativeEndian.PutUint32(body[8:], flags)
	body = putAttr(body, unix.RTA_DST, addressBytes(dst))
	if src.IsValid() {
		body = putAttr(body, unix.RTA_SRC, addressBytes(src))
	}
	if arrival != 0 {
		body = putAttrU32(body, unix.RTA_IIF, arrival)
	}
	replies, err := c.execute(unix.RTM_GETROUTE, 0, body)
	if err != nil {
		return MatchedRoute{}, nil, fmt.Errorf("kernel: look up the route to %s: %w", dst, err)
	}
	for _, reply := range replies {
		if reply.Kind != unix.RTM_NEWROUTE || len(reply.Data) < unix.SizeofRtMsg {
			continue
		}
		return decodeMatchedRoute(reply)
	}
	return MatchedRoute{}, nil, fmt.Errorf("kernel: the route to %s was not answered", dst)
}

// rtaNHID is RTA_NH_ID of linux/rtnetlink.h, which x/sys does not carry
const rtaNHID = 30

// decodeMatchedRoute answers each next hop's interface index at its place in
// NextHops, whose Device it leaves empty
func decodeMatchedRoute(reply nlMessage) (MatchedRoute, []uint32, error) {
	family, dstLen, srcLen := reply.Data[0], int(reply.Data[1]), int(reply.Data[2])
	route := MatchedRoute{
		Prefix: netip.PrefixFrom(unspecified(family), 0),
		Table:  notificationTable(reply),
		Type:   routeTypeName(reply.Data[7]),
	}
	var object uint32
	for attr, value := range reply.attributes(unix.SizeofRtMsg) {
		switch attr {
		case unix.RTA_DST:
			if address, ok := addressFromBytes(value); ok {
				route.Prefix = netip.PrefixFrom(address, dstLen)
			}
		case unix.RTA_SRC:
			if address, ok := addressFromBytes(value); ok {
				route.Source = netip.PrefixFrom(address, srcLen)
			}
		case rtaNHID:
			if len(value) == 4 {
				object = binary.NativeEndian.Uint32(value)
			}
		}
	}
	var indexes []uint32
	for hop, err := range routeNextHops(reply) {
		if err != nil {
			return MatchedRoute{}, nil, err
		}
		gateway := hop.gateway
		if !gateway.IsValid() {
			gateway = hop.via
		}
		route.NextHops = append(route.NextHops, NextHop{
			Gateway:  gateway,
			Dead:     hop.flags&unix.RTNH_F_DEAD != 0,
			LinkDown: hop.flags&unix.RTNH_F_LINKDOWN != 0,
		})
		indexes = append(indexes, hop.index)
	}
	// with nexthop_compat_mode 0 the kernel names the object alone
	if object != 0 && len(indexes) == 0 {
		return MatchedRoute{}, nil, fmt.Errorf("kernel: the route to %s names nexthop object %d without its hops", route.Prefix, object)
	}
	return route, indexes, nil
}

// routeNextHop is one hop of a route message, with the RTNH_F_ flags the
// kernel marks it with, and via the gateway RTA_VIA names in another family
type routeNextHop struct {
	index        uint32
	flags        uint32
	gateway, via netip.Addr
}

// routeNextHops yields the hop of RTA_OIF with rtm_flags, then each hop of
// RTA_MULTIPATH with its rtnh_flags, and ends on an error at a malformed one
func routeNextHops(message nlMessage) iter.Seq2[routeNextHop, error] {
	return func(yield func(routeNextHop, error) bool) {
		if len(message.Data) < unix.SizeofRtMsg {
			yield(routeNextHop{}, errors.New("kernel: truncated route message"))
			return
		}
		first := routeNextHop{flags: binary.NativeEndian.Uint32(message.Data[8:])}
		var multipath []byte
		for attr, value := range message.attributes(unix.SizeofRtMsg) {
			switch attr {
			case unix.RTA_OIF:
				if len(value) == 4 {
					first.index = binary.NativeEndian.Uint32(value)
				}
			case unix.RTA_MULTIPATH:
				multipath = value
			}
		}
		if first.index != 0 {
			first.gateway, first.via = gatewaysOf(message, unix.SizeofRtMsg)
			if !yield(first, nil) {
				return
			}
		}
		for len(multipath) > 0 {
			if len(multipath) < unix.SizeofRtNexthop {
				yield(routeNextHop{}, errors.New("kernel: truncated next hop in a route message"))
				return
			}
			size := int(binary.NativeEndian.Uint16(multipath))
			if size < unix.SizeofRtNexthop || size > len(multipath) {
				yield(routeNextHop{}, errors.New("kernel: malformed next hop length in a route message"))
				return
			}
			hop := routeNextHop{index: binary.NativeEndian.Uint32(multipath[4:]), flags: uint32(multipath[2])}
			hop.gateway, hop.via = gatewaysOf(nlMessage{Data: multipath[:size]}, unix.SizeofRtNexthop)
			if !yield(hop, nil) {
				return
			}
			multipath = multipath[min(rtaAlign(size), len(multipath)):]
		}
	}
}

func gatewaysOf(message nlMessage, offset int) (gateway, via netip.Addr) {
	for attr, value := range message.attributes(offset) {
		switch attr {
		case unix.RTA_GATEWAY:
			gateway, _ = addressFromBytes(value)
		case unix.RTA_VIA:
			// struct rtvia, a two byte family before the address
			if len(value) > 2 {
				via, _ = addressFromBytes(value[2:])
			}
		}
	}
	return gateway, via
}

// routeTypes names each rtm_type as ip-route(8) does
var routeTypes = [...]string{
	unix.RTN_UNSPEC:      "none",
	unix.RTN_UNICAST:     "unicast",
	unix.RTN_LOCAL:       "local",
	unix.RTN_BROADCAST:   "broadcast",
	unix.RTN_ANYCAST:     "anycast",
	unix.RTN_MULTICAST:   "multicast",
	unix.RTN_BLACKHOLE:   "blackhole",
	unix.RTN_UNREACHABLE: "unreachable",
	unix.RTN_PROHIBIT:    "prohibit",
	unix.RTN_THROW:       "throw",
	unix.RTN_NAT:         "nat",
	unix.RTN_XRESOLVE:    "xresolve",
}

func routeTypeName(kind uint8) string {
	if int(kind) < len(routeTypes) {
		return routeTypes[kind]
	}
	return fmt.Sprintf("type %d", kind)
}
