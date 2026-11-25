// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"fmt"
	"net/netip"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/netlink"
	"ranet3.com/pkgs/ranet3/schema"
)

// preflightSourcedCapacity needs only link and IPv6 address dumps. Reading
// main routes or creating a tun here would move the capacity decision after
// the first managed kernel write.
func preflightSourcedCapacity(t Table, announced []netip.Prefix) error {
	conn, err := dialNetlink()
	if err != nil {
		return fmt.Errorf("kernel: read sourced links before creating tun: %w", err)
	}
	defer conn.Close()
	links, err := conn.execute(unix.RTM_GETLINK, unix.NLM_F_DUMP, make([]byte, unix.SizeofIfInfomsg))
	if err != nil {
		return fmt.Errorf("kernel: dump sourced links before creating tun: %w", err)
	}
	addressRequest := make([]byte, unix.SizeofIfAddrmsg)
	addressRequest[0] = unix.AF_INET6
	addresses, err := conn.execute(unix.RTM_GETADDR, unix.NLM_F_DUMP, addressRequest)
	if err != nil {
		return fmt.Errorf("kernel: dump sourced addresses before creating tun: %w", err)
	}
	network := NetworkState{IPv6: NetworkFamily{Links: upAddresses(addresses, unix.AF_INET6, upLinks(links, 0))}}
	return t.refuseSourcedCapacity(func() NetworkState { return network }, announced)
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
			if route, ok := view.decodeRoute(reply); ok && route.Destination.Addr().Is6() {
				ours = append(ours, route)
			} else {
				foreign++
			}
		}
	}
	return ours, foreign, nil
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
