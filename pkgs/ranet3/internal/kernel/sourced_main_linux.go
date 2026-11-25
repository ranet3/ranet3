// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/schema"
)

// sourcedMainRoute is a complete main-table candidate, including routes from
// the kernel and RA rather than just routes carrying the daemon's protocol.
type sourcedMainRoute struct {
	to       netip.Prefix
	from     netip.Prefix
	protocol uint8
	metric   uint32
	kind     uint8
}

// sourcedMain reads main once per sourced pass. The kernel filters the table
// and family. Only destinations intersecting a named D survive this view.
func (p *netlinkPlatform) sourcedMain(destinations []schema.Prefix) ([]sourcedMainRoute, error) {
	view := p.sourcedRouteView(schema.TableMain)
	replies, err := view.dumpTable(unix.AF_INET6, 0)
	if err != nil {
		return nil, fmt.Errorf("kernel: read IPv6 main routes for sourced destinations: %w", err)
	}
	var routes []sourcedMainRoute
	for _, reply := range replies {
		if reply.Kind != unix.RTM_NEWROUTE || len(reply.Data) < unix.SizeofRtMsg || reply.Data[0] != unix.AF_INET6 {
			continue
		}
		bits := int(reply.Data[1])
		if bits == 0 {
			continue // suppressed at 5401, regardless of metric or origin
		}
		if bits > 128 || int(reply.Data[2]) > 128 {
			return nil, fmt.Errorf("kernel: invalid IPv6 main route prefix length %d/%d", bits, reply.Data[2])
		}
		route := sourcedMainRoute{protocol: reply.Data[5], kind: reply.Data[7]}
		var to, from netip.Addr
		table := uint32(reply.Data[4])
		for kind, value := range reply.Attributes(unix.SizeofRtMsg) {
			switch kind {
			case unix.RTA_TABLE:
				if len(value) != 4 {
					return nil, fmt.Errorf("kernel: invalid IPv6 main route table")
				}
				table = binary.NativeEndian.Uint32(value)
			case unix.RTA_DST:
				to, _ = addressFromBytes(value)
			case unix.RTA_SRC:
				from, _ = addressFromBytes(value)
			case unix.RTA_PRIORITY:
				if len(value) != 4 {
					return nil, fmt.Errorf("kernel: invalid IPv6 main route metric")
				}
				route.metric = binary.NativeEndian.Uint32(value)
			}
		}
		if table != uint32(schema.TableMain) {
			continue
		}
		if !to.Is6() {
			return nil, fmt.Errorf("kernel: invalid IPv6 main route destination")
		}
		route.to = netip.PrefixFrom(to, bits).Masked()
		if reply.Data[2] != 0 {
			if !from.Is6() {
				return nil, fmt.Errorf("kernel: invalid IPv6 main route source")
			}
			route.from = netip.PrefixFrom(from, int(reply.Data[2])).Masked()
		}
		for _, destination := range destinations {
			if destination.Prefix.Overlaps(route.to) && route.to.Bits() >= destination.Bits() {
				routes = append(routes, route)
				break
			}
		}
	}
	return routes, nil
}

// sourcedMainWinner applies Linux's destination-first, then source and metric
// preference within the retained candidates. The suppressor has already
// removed routes shorter than the named destination.
func sourcedMainWinner(routes []sourcedMainRoute, source, target netip.Addr) (sourcedMainRoute, bool) {
	var best sourcedMainRoute
	found := false
	for _, route := range routes {
		if !route.to.Contains(target) || route.from.IsValid() && !route.from.Contains(source) {
			continue
		}
		if !found || route.to.Bits() > best.to.Bits() || route.to.Bits() == best.to.Bits() &&
			(route.from.Bits() > best.from.Bits() || route.from.Bits() == best.from.Bits() && route.metric < best.metric) {
			best, found = route, true
		}
	}
	return best, found
}
