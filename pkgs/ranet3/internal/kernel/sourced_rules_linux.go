// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"cmp"
	"maps"
	"net/netip"
	"slices"

	"ranet3.com/pkgs/ranet3/schema"
)

// sourcedStandingRules names the main exception and the refusal for each
// protected destination. Host lookups have no source restriction: the first
// lookup of an unbound socket has not selected its source yet. Forwarded
// lookups are scoped to the exact networks known at this pass.
func sourcedStandingRules(destinations []schema.Prefix, networks map[netip.Prefix]struct{}) []Rule {
	sources := slices.SortedFunc(maps.Keys(networks), comparePrefixes)
	rules := make([]Rule, 0, 2*len(destinations)*(1+len(sources)))
	for _, destination := range destinations {
		main := Rule{Family: FamilyIPv6, To: destination, IIF: linuxLoopback, Table: schema.TableMain,
			Priority: prioritySourcedMain, suppress: SuppressUpTo(destination.Bits() - 1)}
		refused := Rule{Family: FamilyIPv6, To: destination, IIF: linuxLoopback,
			Priority: prioritySourcedRefused, action: actionUnreachable}
		rules = append(rules, main, refused)
		for _, prefix := range sources {
			from := schema.PrefixFrom(prefix)
			main.IIF, main.From = "", from
			refused.IIF, refused.From = "", from
			rules = append(rules, main, refused)
		}
	}
	slices.SortStableFunc(rules, func(a, b Rule) int { return cmp.Compare(a.Priority, b.Priority) })
	return rules
}

func sourcedIngressRule(tun string) Rule {
	return Rule{Family: FamilyIPv6, Priority: prioritySourcedTun, IIF: tun, FWMask: ^uint32(0), action: actionGoto, target: priorityMain}
}

func sourcedPeerRule(to schema.Prefix, from netip.Prefix, table schema.TableID) Rule {
	return Rule{Family: FamilyIPv6, Priority: prioritySourcedPeer, To: to, From: schema.PrefixFrom(from), Table: table}
}

func sourcedGuardRule(to schema.Prefix, from netip.Prefix) Rule {
	return Rule{Family: FamilyIPv6, Priority: prioritySourcedGuard, To: to, From: schema.PrefixFrom(from), action: actionUnreachable}
}

// sourcedPeerRules arms a coarse pair only where some nondefault mesh peer
// entry overlaps the destination and the supported source. Its table lookup
// still tests the whole original entries, so a held child or source is never
// authorized by the existence of a peer elsewhere in the pair.
func sourcedPeerRules(destinations []schema.Prefix, networks map[netip.Prefix]struct{}, desired []Route, table schema.TableID) []Rule {
	var peers []Rule
	for _, destination := range destinations {
		for source := range networks {
			for _, route := range desired {
				if !route.Destination.IsValid() || !route.Destination.Addr().Is6() ||
					route.Destination.Bits() == 0 || route.Cover || route.Unreachable || route.Throw ||
					!route.Destination.Overlaps(destination.Prefix) {
					continue
				}
				if route.Source.IsValid() && !route.Source.Overlaps(source) {
					continue
				}
				peers = append(peers, sourcedPeerRule(destination, source, table))
				break
			}
		}
	}
	slices.SortFunc(peers, func(a, b Rule) int {
		if order := comparePrefixes(a.To.Prefix, b.To.Prefix); order != 0 {
			return order
		}
		return comparePrefixes(a.From.Prefix, b.From.Prefix)
	})
	return peers
}

// sourcedMirrors preserves each whole nondefault original entry, even when
// only a part of it intersects a named destination. The table's later lookup
// must still see broader peer, hold and source-specific entries as written.
// Original defaults and their derived cover members authorize no pair.
func sourcedMirrors(destinations []schema.Prefix, desired []Route) []Route {
	var mirrored []Route
	for _, route := range desired {
		if !route.Destination.IsValid() || !route.Destination.Addr().Is6() || route.Destination.Bits() == 0 || route.Cover {
			continue
		}
		for _, destination := range destinations {
			if route.Destination.Overlaps(destination.Prefix) {
				mirrored = append(mirrored, route)
				break
			}
		}
	}
	return mirrored
}

// sourcedExpectedDump is the full shape of one rule we request. Matching a
// protocol byte and priority alone is insufficient for a sourced delete:
// fib_rules can delete an unread-selector lookalike ahead of our rule.
func sourcedExpectedDump(rule Rule, proto uint8) DumpedRule {
	mask := rule.FWMask
	if rule.FWMark != 0 && mask == 0 {
		mask = ^uint32(0)
	}
	dumped := DumpedRule{
		Family: rule.Family, Priority: rule.Priority,
		To: rule.To.Prefix, From: rule.From.Prefix, IIF: rule.IIF, OIF: rule.oif,
		FWMark: rule.FWMark, FWMask: mask, L3mdev: rule.l3mdev, Invert: rule.invert,
		Action: rule.action.String(), Suppress: rule.suppress, Protocol: proto,
	}
	switch rule.action {
	case actionLookup:
		dumped.Table = uint32(rule.Table)
	case actionGoto:
		dumped.Goto = rule.target
	}
	return dumped
}

func sourcedExactShape(held DumpedRule, rule Rule, proto uint8) bool {
	return held == sourcedExpectedDump(rule, proto)
}

// sourcedShadowed reports that an earlier rule can be selected by a delete
// naming the requested rule. A full-shape read of the requested rule ends the
// search: Linux deletes the first matching rule at a priority. Extra unread
// selectors, inversion and suppression do not establish separate ownership.
func sourcedShadowed(all []DumpedRule, wanted Rule, proto uint8) bool {
	expected := sourcedExpectedDump(wanted, proto)
	for _, held := range all {
		if held == expected {
			return false
		}
		if sourcedDeleteEquivalent(held, expected) {
			return true
		}
	}
	return false
}

func sourcedDeleteEquivalent(held, expected DumpedRule) bool {
	return held.Family == expected.Family && held.Priority == expected.Priority &&
		held.To == expected.To && held.From == expected.From &&
		held.IIF == expected.IIF && held.Protocol == expected.Protocol &&
		held.FWMark == expected.FWMark && held.FWMask == expected.FWMask &&
		held.Action == expected.Action && held.Table == expected.Table && held.Goto == expected.Goto
}

func sourcedAmbiguous(all []DumpedRule, wanted Rule, proto uint8) bool {
	expected := sourcedExpectedDump(wanted, proto)
	for _, held := range all {
		if held != expected && sourcedDeleteEquivalent(held, expected) {
			return true
		}
	}
	return false
}
