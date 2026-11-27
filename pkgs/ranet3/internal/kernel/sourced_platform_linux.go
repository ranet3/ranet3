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

	"ranet3.com/pkgs/ranet3/internal/netlink"
	"ranet3.com/pkgs/ranet3/schema"
)

// preflightSourcedStartup uses only read-only netlink requests before a
// daemon creates managed kernel objects. New repeats occupancy after the tun
// exists, so a writer intervening between the two checks is also refused.
func preflightSourcedStartup(t Table, announced []netip.Prefix, tun string) error {
	conn, err := dialNetlink()
	if err != nil {
		return fmt.Errorf("kernel: read sourced links before creating tun: %w", err)
	}
	defer conn.Close()
	return preflightSourcedOn(conn, t, announced, tun)
}

func preflightSourcedOn(conn netlinkConn, t Table, announced []netip.Prefix, tun string) error {
	links, err := conn.execute(unix.RTM_GETLINK, unix.NLM_F_DUMP, make([]byte, unix.SizeofIfInfomsg))
	if err != nil {
		return fmt.Errorf("kernel: dump sourced links before creating tun: %w", err)
	}
	var index uint32
	for _, reply := range links {
		if reply.Kind != unix.RTM_NEWLINK || len(reply.Data) < unix.SizeofIfInfomsg {
			continue
		}
		link := decodeLink(reply)
		if link.name == tun {
			index = link.index
			break
		}
	}
	addressRequest := make([]byte, unix.SizeofIfAddrmsg)
	addressRequest[0] = unix.AF_INET6
	addresses, err := conn.execute(unix.RTM_GETADDR, unix.NLM_F_DUMP, addressRequest)
	if err != nil {
		return fmt.Errorf("kernel: dump sourced addresses before creating tun: %w", err)
	}
	network := NetworkState{IPv6: NetworkFamily{Links: upAddresses(addresses, unix.AF_INET6, upLinks(links, index))}}
	if err := t.refuseSourcedCapacity(func() NetworkState { return network }, announced); err != nil {
		return err
	}
	if link, err := conn.link(0, tun); err == nil {
		index = link.index
	} else if !errors.Is(err, unix.ENODEV) {
		return fmt.Errorf("kernel: read sourced tun %s before creating it: %w", tun, err)
	}
	probe := &netlinkPlatform{table: t, index: index, conn: conn}
	return probe.preflightSourcedOccupancy(t, tun)
}

// sourcedRouteView uses the reconciler's socket and tun index, but never owns
// their lifetime. Its table marker is the second table's, not table 200's.
func (p *netlinkPlatform) sourcedRouteView(id schema.TableID) netlinkPlatform {
	return netlinkPlatform{table: Table{ID: id, Proto: p.table.Proto}, index: p.index, conn: p.conn}
}

// SourcedRoutes reads both families and every protocol in the second table.
// Even an unrelated object there is foreign to this reconciler's mirror. It
// cannot be withdrawn on the strength of a shared table number.
func (p *netlinkPlatform) SourcedRoutes(id schema.TableID) (ours []Route, foreign int, err error) {
	view := p.sourcedRouteView(id)
	for _, family := range []uint8{unix.AF_INET, unix.AF_INET6} {
		replies, readErr := view.dumpTable(family, 0)
		if readErr != nil {
			return nil, 0, readErr
		}
		for _, reply := range replies {
			if route, ok := view.decodeRoute(reply); ok && sourcedRouteShape(reply, route, id, p.index) {
				ours = append(ours, route)
			} else {
				foreign++
			}
		}
	}
	return ours, foreign, nil
}

// sourcedRouteShape accepts only the mirror's wire shape. The ordinary route
// decoder intentionally has a broader ownership contract.
func sourcedRouteShape(message netlink.Message, route Route, id schema.TableID, tun uint32) bool {
	data := message.Data
	if len(data) < unix.SizeofRtMsg || data[0] != unix.AF_INET6 ||
		data[3] != 0 || data[6] != unix.RT_SCOPE_UNIVERSE ||
		binary.NativeEndian.Uint32(data[8:12]) != 0 ||
		!route.Destination.Addr().Is6() {
		return false
	}
	table := uint8(unix.RT_TABLE_UNSPEC)
	if id <= 255 {
		table = uint8(id)
	}
	if data[4] != table || data[1] != uint8(route.Destination.Bits()) {
		return false
	}
	sourceBits := uint8(0)
	if route.Source.IsValid() {
		sourceBits = uint8(route.Source.Bits())
	}
	if data[2] != sourceBits {
		return false
	}
	seenTable, seenDst, seenSrc, seenOIF, seenMetric, seenCache, seenPref := false, false, false, false, false, false, false
	for attrs := data[unix.SizeofRtMsg:]; len(attrs) > 0; {
		if len(attrs) < unix.SizeofRtAttr {
			return false
		}
		length := int(binary.NativeEndian.Uint16(attrs))
		if length < unix.SizeofRtAttr || length > len(attrs) {
			return false
		}
		value := attrs[unix.SizeofRtAttr:length]
		switch binary.NativeEndian.Uint16(attrs[2:]) {
		case unix.RTA_TABLE:
			if seenTable || len(value) != 4 || binary.NativeEndian.Uint32(value) != uint32(id) {
				return false
			}
			seenTable = true
		case unix.RTA_DST:
			address, ok := addressFromBytes(value)
			if seenDst || !ok || route.Destination.Bits() == 0 || address != route.Destination.Addr() {
				return false
			}
			seenDst = true
		case unix.RTA_SRC:
			address, ok := addressFromBytes(value)
			if seenSrc || !ok || !route.Source.IsValid() || address != route.Source.Addr() {
				return false
			}
			seenSrc = true
		case unix.RTA_OIF:
			if seenOIF || len(value) != 4 {
				return false
			}
			oif := binary.NativeEndian.Uint32(value)
			if route.Unreachable || route.Throw {
				if oif != 1 { // Linux may report lo for a device-free IPv6 hold.
					return false
				}
			} else if oif != tun {
				return false
			}
			seenOIF = true
		case unix.RTA_PRIORITY:
			if seenMetric || len(value) != 4 || binary.NativeEndian.Uint32(value) != route.Metric {
				return false
			}
			seenMetric = true
		case unix.RTA_CACHEINFO:
			if seenCache || len(value) != 32 || binary.NativeEndian.Uint32(value[8:12]) != 0 {
				return false
			}
			seenCache = true
		case unix.RTA_PREF:
			if seenPref || len(value) != 1 || value[0] != 0 {
				return false
			}
			seenPref = true
		default:
			return false
		}
		next := netlink.AttrAlign(length)
		if next > len(attrs) {
			if length != len(attrs) {
				return false
			}
			break
		}
		attrs = attrs[next:]
	}
	return seenDst == (route.Destination.Bits() > 0) &&
		seenSrc == route.Source.IsValid() &&
		(route.Unreachable || route.Throw || seenOIF) && seenMetric
}

func (p *netlinkPlatform) AddSourcedRoute(id schema.TableID, route Route) error {
	view := p.sourcedRouteView(id)
	return view.AddRoute(route)
}

func (p *netlinkPlatform) DelSourcedRoute(id schema.TableID, route Route) error {
	view := p.sourcedRouteView(id)
	return view.DelRoute(route)
}

// preflightSourcedOccupancy refuses distinguishable foreign occupants before
// the first address, route, rule or fallback write. Exact dumped copies of
// our rule shapes remain adoptable across a process restart.
func (p *netlinkPlatform) preflightSourcedOccupancy(t Table, tun string) error {
	if t.Sourced == nil {
		return nil
	}
	_, foreign, err := p.SourcedRoutes(t.Sourced.ID)
	if err != nil {
		return fmt.Errorf("kernel: read sourced table %d before writing: %w", t.Sourced.ID, err)
	}
	if foreign != 0 {
		return fmt.Errorf("kernel: sourced table %d contains %d foreign routes", t.Sourced.ID, foreign)
	}
	rules, err := p.SourcedRules()
	if err != nil {
		return fmt.Errorf("kernel: read sourced rules before writing: %w", err)
	}
	for _, rule := range rules {
		if rule.Family != FamilyIPv6 || !sourcedPriority(rule.Priority) {
			continue
		}
		if !sourcedOccupiedShape(rule, t, tun) {
			return fmt.Errorf("kernel: sourced priority %d has an unexpected occupant: %+v", rule.Priority, rule)
		}
	}
	return nil
}

func sourcedPriority(priority uint32) bool {
	switch priority {
	case prioritySourcedTun, prioritySourcedMain, prioritySourcedGuard, prioritySourcedPeer, prioritySourcedRefused:
		return true
	}
	return false
}

func sourcedOccupiedShape(held DumpedRule, t Table, tun string) bool {
	if held.Protocol != t.Proto || held.Unread != 0 {
		return false
	}
	if held.Priority == prioritySourcedTun {
		return sourcedExactShape(held, sourcedIngressRule(tun), t.Proto)
	}
	if !held.To.IsValid() || !held.To.Addr().Is6() ||
		held.To.Bits() < schema.MinSubnetBits6 || held.To != held.To.Masked() {
		return false
	}
	to := schema.PrefixFrom(held.To)
	if held.Priority == prioritySourcedMain || held.Priority == prioritySourcedRefused {
		if held.IIF != linuxLoopback && (held.IIF != "" || !held.From.IsValid()) ||
			held.IIF == linuxLoopback && held.From.IsValid() {
			return false
		}
		rule := Rule{Family: FamilyIPv6, Priority: held.Priority, To: to, IIF: held.IIF}
		if held.From.IsValid() {
			rule.From = schema.PrefixFrom(held.From)
		}
		if held.Priority == prioritySourcedMain {
			rule.Table = schema.TableMain
			rule.suppress = SuppressUpTo(held.To.Bits() - 1)
		} else {
			rule.action = actionUnreachable
		}
		return sourcedExactShape(held, rule, t.Proto)
	}
	if !held.From.IsValid() || !held.From.Addr().Is6() || held.From.Bits() == 0 ||
		held.From != held.From.Masked() {
		return false
	}
	if held.Priority == prioritySourcedGuard {
		return sourcedExactShape(held, sourcedGuardRule(to, held.From), t.Proto)
	}
	if held.Priority == prioritySourcedPeer {
		return sourcedExactShape(held, sourcedPeerRule(to, held.From, t.Sourced.ID), t.Proto)
	}
	return false
}

// sourcedMainNotification watches only routes whose destination intersects a
// named destination. A malformed nondefault main notification wakes a pass
// rather than silently leaving a possibly changed main exception stale.
func sourcedMainNotification(message netlink.Message, destinations []schema.Prefix) bool {
	if len(message.Data) < unix.SizeofRtMsg || message.Data[0] != unix.AF_INET6 || message.Data[1] == 0 {
		return false
	}
	bits := int(message.Data[1])
	if bits > 128 {
		return true
	}
	var address netip.Addr
	for kind, value := range message.Attributes(unix.SizeofRtMsg) {
		if kind == unix.RTA_DST {
			address, _ = addressFromBytes(value)
			break
		}
	}
	if !address.IsValid() {
		return true
	}
	prefix, ok := canonicalPrefix(netip.PrefixFrom(address, bits))
	if !ok {
		return true
	}
	for _, destination := range destinations {
		if destination.Prefix.Overlaps(prefix) {
			return true
		}
	}
	return false
}
