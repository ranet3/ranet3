// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"cmp"
	"fmt"
	"maps"
	"net/netip"
	"slices"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/schema"
)

// sourcedSections partitions one prefix at every finer route boundary.
// A sample address in each returned section then has the same destination
// (or source) selectors for all the routes used to build it.
func sourcedSections(base netip.Prefix, cuts []netip.Prefix) []netip.Prefix {
	sections := []netip.Prefix{base}
	for _, cut := range cuts {
		if !cut.IsValid() || cut.Bits() <= base.Bits() || !base.Contains(cut.Addr()) {
			continue
		}
		for i, section := range sections {
			if section.Bits() >= cut.Bits() || !section.Contains(cut.Addr()) {
				continue
			}
			sections = slices.Delete(sections, i, i+1)
			for section.Bits() < cut.Bits() {
				bits := section.Bits()
				address := section.Addr().As16()
				address[bits/8] |= byte(0x80 >> (bits % 8))
				right := netip.PrefixFrom(netip.AddrFrom16(address), bits+1)
				left := netip.PrefixFrom(section.Addr(), bits+1)
				if right.Contains(cut.Addr()) {
					sections = append(sections, left)
					section = right
				} else {
					sections = append(sections, right)
					section = left
				}
			}
			sections = append(sections, section)
			break
		}
	}
	slices.SortFunc(sections, comparePrefixes)
	return sections
}

func sourcedReadRule(rules []DumpedRule, proto uint8, table schema.TableID, priority uint32, destination schema.Prefix, source netip.Addr) bool {
	return slices.ContainsFunc(rules, func(held DumpedRule) bool {
		if held.Priority != priority || held.To != destination.Prefix {
			return false
		}
		switch priority {
		case prioritySourcedMain, prioritySourcedRefused:
			rule, owned := sourcedStandingOwnedRule(held, proto)
			return owned && rule.Priority == priority && (held.From.IsValid() && held.From.Contains(source) || !source.IsValid() && rule.IIF == linuxLoopback)
		case prioritySourcedGuard, prioritySourcedPeer:
			if !source.IsValid() || !held.From.IsValid() || !held.From.Contains(source) {
				return false
			}
			if priority == prioritySourcedGuard {
				return sourcedExactShape(held, sourcedGuardRule(destination, held.From), proto)
			}
			return sourcedExactShape(held, sourcedPeerRule(destination, held.From, table), proto)
		}
		return false
	})
}

func sourcedMirrorWinner(routes []Route, source, target netip.Addr) (Route, bool) {
	var best Route
	found := false
	for _, route := range routes {
		if !route.Destination.Contains(target) || route.Source.IsValid() && !route.Source.Contains(source) {
			continue
		}
		if !found || route.Destination.Bits() > best.Destination.Bits() ||
			route.Destination.Bits() == best.Destination.Bits() &&
				(route.Source.Bits() > best.Source.Bits() || route.Source.Bits() == best.Source.Bits() && route.Metric < best.Metric) {
			best, found = route, true
		}
	}
	return best, found
}

func sourcedSameAnswer(a, b SourcedAnswer) bool {
	return a.Kind == b.Kind && a.MainPrefix == b.MainPrefix &&
		a.MainProtocol == b.MainProtocol && a.Protection == b.Protection
}

func sourcedAnswerAt(r *Reconciler, destination schema.Prefix, source, target netip.Addr,
	main []sourcedMainRoute, mirror, desired []Route, rules []DumpedRule, ingress, mainTarget bool) SourcedAnswer {
	answer := SourcedAnswer{To: destination.Prefix, Kind: "unknown"}
	if source.IsValid() {
		answer.From = netip.PrefixFrom(source, 128)
	}
	mainRule := sourcedReadRule(rules, r.table.Proto, r.table.Sourced.ID, prioritySourcedMain, destination, source)
	refusal := sourcedReadRule(rules, r.table.Proto, r.table.Sourced.ID, prioritySourcedRefused, destination, source)
	guard := sourcedReadRule(rules, r.table.Proto, r.table.Sourced.ID, prioritySourcedGuard, destination, source)
	answer.Protection = mainRule && (refusal || guard)
	if mainRule {
		if winner, ok := sourcedMainWinner(main, source, target); ok {
			answer.MainPrefix, answer.MainProtocol = winner.to, winner.protocol
			if winner.kind == unix.RTN_UNICAST || winner.kind == unix.RTN_LOCAL {
				answer.Kind = "main"
			} else {
				answer.Kind = "refused"
			}
			return answer
		}
	}
	if guard {
		answer.Kind = "refused"
		return answer
	}
	if !mainRule || !refusal {
		return answer
	}
	if source.IsValid() && ingress && mainTarget && sourcedReadRule(rules, r.table.Proto, r.table.Sourced.ID, prioritySourcedPeer, destination, source) {
		peer, verdict, _ := r.src.Resolve(source, target)
		if verdict == netstack.RoutePeer && peer != nil {
			if route, ok := sourcedMirrorWinner(mirror, source, target); ok && !route.Unreachable && !route.Throw {
				answer.Kind = "tunnel"
				return answer
			}
		}
	}
	if wanted, ok := sourcedMirrorWinner(desired, source, target); ok && wanted.Unreachable {
		if held, exists := sourcedMirrorWinner(mirror, source, target); !exists || !held.Unreachable {
			answer.Kind = "pending"
			return answer
		}
	}
	answer.Kind = "refused"
	return answer
}

func (p *netlinkPlatform) sourcedObserved(r *Reconciler, desired []Route) (SourcedStatus, error) {
	status := SourcedStatus{Named: len(r.table.Sourced.To), Supported: len(r.sourcedSources),
		Pairs: len(r.table.Sourced.To) * len(r.sourcedSources), Limited: r.sourcedLimited, State: "active"}
	if r.sourcedLimited {
		status.State = "limited"
	}
	if !r.enabled.Load() {
		status.State = "withdrawn"
	}
	rules, err := p.SourcedRules()
	if err != nil {
		return status, fmt.Errorf("kernel: read sourced admission for effective answers: %w", err)
	}
	for _, held := range rules {
		if held.Family == FamilyIPv6 && sourcedPriority(held.Priority) && sourcedOccupiedShape(held, r.table, r.rt.Interface) {
			status.Rules++
		}
	}
	mirror, foreign, err := p.SourcedRoutes(r.table.Sourced.ID)
	if err != nil {
		return status, fmt.Errorf("kernel: read sourced mirror for effective answers: %w", err)
	}
	if foreign != 0 {
		return status, fmt.Errorf("kernel: sourced mirror has %d foreign routes; effective answers unknown", foreign)
	}
	main, err := p.sourcedMain(r.table.Sourced.To)
	if err != nil {
		return status, err
	}
	ordinary, err := p.Rules()
	if err != nil {
		return status, fmt.Errorf("kernel: read main admission for effective answers: %w", err)
	}
	mainTarget := slices.ContainsFunc(ordinary, func(rule Rule) bool { return rule.Family == FamilyIPv6 && rule.Priority == priorityMain })
	ingress := slices.ContainsFunc(rules, func(held DumpedRule) bool {
		return sourcedExactShape(held, sourcedIngressRule(r.rt.Interface), r.table.Proto)
	})
	sources := slices.SortedFunc(maps.Keys(r.sourcedSources), comparePrefixes)
	for _, destination := range r.table.Sourced.To {
		var destinationCuts, sourceCuts []netip.Prefix
		for _, route := range main {
			if destination.Prefix.Overlaps(route.to) {
				destinationCuts = append(destinationCuts, route.to)
			}
			if route.from.IsValid() {
				sourceCuts = append(sourceCuts, route.from)
			}
		}
		for _, list := range [][]Route{mirror, desired} {
			for _, route := range list {
				if destination.Prefix.Overlaps(route.Destination) {
					destinationCuts = append(destinationCuts, route.Destination)
					if route.Source.IsValid() {
						sourceCuts = append(sourceCuts, route.Source)
					}
				}
			}
		}
		sections := sourcedSections(destination.Prefix, destinationCuts)
		baseSection := slices.MinFunc(sections, func(a, b netip.Prefix) int { return cmp.Compare(a.Bits(), b.Bits()) })
		baseline := sourcedAnswerAt(r, destination, netip.Addr{}, baseSection.Addr(), main, mirror, desired, rules, ingress, mainTarget)
		baseline.To = destination.Prefix
		status.Answers = append(status.Answers, baseline)
		hosts := make([]SourcedAnswer, len(sections))
		for i, section := range sections {
			host := sourcedAnswerAt(r, destination, netip.Addr{}, section.Addr(), main, mirror, desired, rules, ingress, mainTarget)
			host.To = section
			hosts[i] = host
			if !sourcedSameAnswer(host, baseline) {
				status.Answers = append(status.Answers, host)
			}
		}
		for _, supported := range sources {
			for _, part := range sourcedSections(supported, sourceCuts) {
				sourceBase := sourcedAnswerAt(r, destination, part.Addr(), baseSection.Addr(), main, mirror, desired, rules, ingress, mainTarget)
				sourceBase.To, sourceBase.From = destination.Prefix, part
				inherited := sourcedSameAnswer(sourceBase, baseline)
				if !inherited {
					status.Answers = append(status.Answers, sourceBase)
				}
				for i, section := range sections {
					answer := sourcedAnswerAt(r, destination, part.Addr(), section.Addr(), main, mirror, desired, rules, ingress, mainTarget)
					answer.To, answer.From = section, part
					if inherited && sourcedSameAnswer(answer, hosts[i]) || !inherited && sourcedSameAnswer(answer, sourceBase) {
						continue
					}
					status.Answers = append(status.Answers, answer)
				}
			}
		}
	}
	if slices.ContainsFunc(status.Answers, func(answer SourcedAnswer) bool { return answer.Kind == "pending" }) {
		status.State = "pending"
	}
	return status, nil
}
