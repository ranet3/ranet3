// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"errors"
	"fmt"
	"slices"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/schema"
)

// sourcedRuleView uses the all-protocol reader, never the ordinary rule view:
// a foreign rule with an unread selector is not proof our rule stands.
type sourcedRuleView struct {
	p     *netlinkPlatform
	rules []DumpedRule
}

func (v *sourcedRuleView) has(rule Rule) bool {
	for _, held := range v.rules {
		if sourcedExactShape(held, rule, v.p.table.Proto) {
			return true
		}
	}
	return false
}

func (v *sourcedRuleView) read() error {
	rules, err := v.p.SourcedRules()
	if err != nil {
		return fmt.Errorf("read all sourced rules: %w", err)
	}
	v.rules = rules
	return nil
}

// add reads back even after a lost acknowledgement. The failed write remains
// an error for the caller, not a license to delete the object a second writer
// might have placed at the same priority in the meantime.
func (v *sourcedRuleView) add(rule Rule) error {
	if v.has(rule) {
		return nil
	}
	writeErr := v.p.AddRule(rule)
	readErr := v.read()
	if writeErr != nil {
		return errors.Join(fmt.Errorf("add sourced rule %s: %w", rule, writeErr), readErr)
	}
	if readErr != nil {
		return readErr
	}
	if !v.has(rule) {
		return fmt.Errorf("sourced rule %s did not read back", rule)
	}
	return nil
}

// remove never sends a delete while an earlier indistinguishable netlink
// target is foreign. Linux would delete that target first, not our later F.
func (v *sourcedRuleView) remove(rule Rule) error {
	if !v.has(rule) {
		return nil
	}
	if sourcedShadowed(v.rules, rule, v.p.table.Proto) {
		return fmt.Errorf("sourced rule %s cannot be deleted before a foreign lookalike", rule)
	}
	writeErr := v.p.DelRule(rule)
	readErr := v.read()
	if writeErr != nil {
		return errors.Join(fmt.Errorf("delete sourced rule %s: %w", rule, writeErr), readErr)
	}
	if readErr != nil {
		return readErr
	}
	if v.has(rule) {
		return fmt.Errorf("sourced rule %s did not withdraw on readback", rule)
	}
	return nil
}

// standSourced installs refusal before main's limited exception, so a
// failed or interrupted pass cannot expose a named destination to ordinary
// main or mesh fallback. New links gain their refusal before other pass writes.
func (p *netlinkPlatform) standSourced(r *Reconciler, network passNetwork) error {
	key := r.table.Sourced
	if key == nil {
		return nil
	}
	sources := r.table.sourcedSources(func() NetworkState { return network.network }, r.rt.Announced)
	pairs := len(key.To) * len(sources)
	if !p.sourcedStarted && (len(key.To) > sourcedPairLimit || pairs > sourcedPairLimit) {
		return sourcedCapacityError(len(key.To), pairs)
	}
	v := sourcedRuleView{p: p}
	if err := v.read(); err != nil {
		return err
	}
	wanted := sourcedStandingRules(key.To, sources)
	for _, rule := range wanted {
		if rule.Priority == prioritySourcedRefused {
			if err := v.add(rule); err != nil {
				return err
			}
		}
	}
	for _, rule := range wanted {
		if rule.Priority == prioritySourcedMain {
			if err := v.add(rule); err != nil {
				return err
			}
		}
	}
	r.sourcedSources = sources
	r.sourcedLimited = pairs > sourcedPairLimit
	p.sourcedStarted = true
	return nil
}

// mirrorSourced writes holds and throws before tun entries. Each phase reads
// back the whole table, so no positive rule can be armed on an acknowledged
// but absent route. Another protocol's entry refuses every mirror write.
func (p *netlinkPlatform) mirrorSourced(r *Reconciler, desired []Route) error {
	key := r.table.Sourced
	if key == nil {
		return nil
	}
	wanted := sourcedMirrors(key.To, desired)
	held, foreign, err := p.SourcedRoutes(key.ID)
	if err != nil {
		return fmt.Errorf("read sourced table %d: %w", key.ID, err)
	}
	if foreign != 0 {
		return fmt.Errorf("sourced table %d holds %d foreign routes", key.ID, foreign)
	}
	for _, old := range held {
		if slices.Contains(wanted, old) {
			continue
		}
		if err := p.DelSourcedRoute(key.ID, old); err != nil {
			_, _, readErr := p.SourcedRoutes(key.ID)
			return errors.Join(fmt.Errorf("delete stale sourced mirror %s: %w", old, err), readErr)
		}
	}
	held, foreign, err = p.SourcedRoutes(key.ID)
	if err != nil {
		return fmt.Errorf("read back sourced table %d after retiring stale entries: %w", key.ID, err)
	}
	if foreign != 0 {
		return fmt.Errorf("sourced table %d gained %d foreign routes", key.ID, foreign)
	}
	for _, old := range held {
		if !slices.Contains(wanted, old) {
			return fmt.Errorf("stale sourced mirror %s did not withdraw", old)
		}
	}
	for _, refusal := range [...]bool{true, false} {
		var added []Route
		for _, route := range wanted {
			if (route.Unreachable || route.Throw) != refusal || slices.Contains(held, route) {
				continue
			}
			if err := p.AddSourcedRoute(key.ID, route); err != nil {
				// An acknowledgement can be lost after the object landed.
				// A fresh dump records the debt. No positive rule is armed.
				_, _, readErr := p.SourcedRoutes(key.ID)
				return errors.Join(fmt.Errorf("add sourced mirror %s: %w", route, err), readErr)
			}
			added = append(added, route)
		}
		if len(added) == 0 {
			continue
		}
		held, foreign, err = p.SourcedRoutes(key.ID)
		if err != nil {
			return fmt.Errorf("read back sourced table %d: %w", key.ID, err)
		}
		if foreign != 0 {
			return fmt.Errorf("sourced table %d gained %d foreign routes", key.ID, foreign)
		}
		for _, route := range added {
			if !slices.Contains(held, route) {
				return fmt.Errorf("sourced mirror %s did not read back", route)
			}
		}
	}
	return nil
}

// armSourced has no positive path until ordinary 5410, the running tun, its
// zero-mark ingress skip and every wanted mirror entry are read back. A down
// set keeps ingress and pair admission absent while the standing refusal
// remains, including on a staged start.
func (p *netlinkPlatform) armSourced(r *Reconciler, desired []Route) error {
	key := r.table.Sourced
	if key == nil {
		return nil
	}
	ordinary, err := p.Rules()
	if err != nil {
		return fmt.Errorf("read 5410 before sourced ingress: %w", err)
	}
	if slices.ContainsFunc(ordinary, isDownRule) {
		return nil
	}
	main := Rule{Family: FamilyIPv6, Priority: priorityMain, Table: schema.TableMain, suppress: SuppressUpTo(0)}
	if !slices.Contains(ordinary, main) {
		return fmt.Errorf("sourced ingress cannot jump to missing priority %d", priorityMain)
	}
	link, err := p.conn.link(p.index, "")
	if err != nil {
		return fmt.Errorf("read tun before sourced ingress: %w", err)
	}
	if link.flags&unix.IFF_UP == 0 {
		return nil
	}
	v := sourcedRuleView{p: p}
	if err := v.read(); err != nil {
		return err
	}
	if err := v.add(sourcedIngressRule(r.rt.Interface)); err != nil {
		return err
	}
	mirrored, foreign, err := p.SourcedRoutes(key.ID)
	if err != nil {
		return fmt.Errorf("read sourced mirror before pair admission: %w", err)
	}
	if foreign != 0 {
		return fmt.Errorf("sourced mirror gained %d foreign routes before pair admission", foreign)
	}
	for _, route := range sourcedMirrors(key.To, desired) {
		if !slices.Contains(mirrored, route) {
			return fmt.Errorf("sourced mirror %s disappeared before pair admission", route)
		}
	}
	for _, peer := range sourcedPeerRules(key.To, r.sourcedSources, desired, key.ID) {
		if r.sourcedLimited && !v.has(peer) {
			continue
		}
		if err := v.add(peer); err != nil {
			return err
		}
	}
	return nil
}

// retireSourced takes positive admission down before an ordinary route or a
// 201 mirror changes. Existing unrelated pairs remain armed when the complete
// mirror is unchanged. A replacement disarms every pair before old entries go.
func (p *netlinkPlatform) retireSourced(r *Reconciler, desired []Route, staged bool) error {
	key := r.table.Sourced
	if key == nil {
		return nil
	}
	held, foreign, err := p.SourcedRoutes(key.ID)
	if err != nil {
		return err
	}
	if foreign != 0 {
		return fmt.Errorf("sourced table %d holds %d foreign routes", key.ID, foreign)
	}
	wanted := sourcedMirrors(key.To, desired)
	different := len(held) != len(wanted)
	if !different {
		for _, route := range wanted {
			if !slices.Contains(held, route) {
				different = true
				break
			}
		}
	}
	link, err := p.conn.link(p.index, "")
	if err != nil {
		return fmt.Errorf("read sourced tun before retiring admission: %w", err)
	}
	staged = staged || link.flags&unix.IFF_UP == 0
	eligible := sourcedPeerRules(key.To, r.sourcedSources, desired, key.ID)
	v := sourcedRuleView{p: p}
	if err := v.read(); err != nil {
		return err
	}
	var processed []Rule
	for _, held := range v.rules {
		peer, owned := sourcedOwnedPeer(held, key, p.table.Proto)
		if !owned || slices.Contains(processed, peer) {
			continue
		}
		processed = append(processed, peer)
		if !staged && !different && slices.Contains(eligible, peer) {
			continue
		}
		if sourcedAmbiguous(v.rules, peer, p.table.Proto) {
			if err := v.add(sourcedGuardRule(peer.To, peer.From.Prefix)); err != nil {
				return err
			}
		}
		if sourcedShadowed(v.rules, peer, p.table.Proto) {
			continue // the guard now refuses this pair ahead of foreign X and F
		}
		if err := v.remove(peer); err != nil {
			return err
		}
	}
	if staged {
		ingress := sourcedIngressRule(r.rt.Interface)
		if sourcedAmbiguous(v.rules, ingress, p.table.Proto) {
			return fmt.Errorf("sourced tun ingress has an ambiguous foreign lookalike")
		}
		if err := v.remove(ingress); err != nil {
			return err
		}
	}
	return nil
}

func sourcedOwnedPeer(held DumpedRule, key *Sourced, proto uint8) (Rule, bool) {
	if held.Priority != prioritySourcedPeer || held.Family != FamilyIPv6 ||
		!held.To.IsValid() || !held.To.Addr().Is6() ||
		!held.From.IsValid() || !held.From.Addr().Is6() {
		return Rule{}, false
	}
	peer := sourcedPeerRule(schema.PrefixFrom(held.To), held.From, key.ID)
	return peer, sourcedDeleteEquivalent(held, sourcedExpectedDump(peer, proto))
}

// withdrawSourcedAdmission runs before ordinary 5410 can leave. A foreign
// first-match obstacle at 5399 prevents the ordinary withdrawal altogether.
// An ambiguous 5403 instead gets an earlier, read-back 5402 guard while the
// foreign rule and any unremovable owned copy remain intact.
func (p *netlinkPlatform) withdrawSourcedAdmission(r *Reconciler) (safe bool, err error) {
	key := r.table.Sourced
	if key == nil {
		return true, nil
	}
	v := sourcedRuleView{p: p}
	if err := v.read(); err != nil {
		return false, err
	}
	ingress := sourcedIngressRule(r.rt.Interface)
	if sourcedAmbiguous(v.rules, ingress, p.table.Proto) {
		return false, fmt.Errorf("sourced tun ingress has an ambiguous foreign lookalike")
	}
	if err := v.remove(ingress); err != nil {
		return false, err
	}
	var debts []error
	var processed []Rule
	for _, held := range v.rules {
		peer, owned := sourcedOwnedPeer(held, key, p.table.Proto)
		if !owned || slices.Contains(processed, peer) {
			continue
		}
		processed = append(processed, peer)
		ambiguous := sourcedAmbiguous(v.rules, peer, p.table.Proto)
		if ambiguous {
			if err := v.add(sourcedGuardRule(peer.To, peer.From.Prefix)); err != nil {
				return false, errors.Join(errors.Join(debts...), err)
			}
		}
		if sourcedShadowed(v.rules, peer, p.table.Proto) {
			debts = append(debts, fmt.Errorf("sourced peer %s remains behind a foreign lookalike under a 5402 guard", peer))
			continue
		}
		if err := v.remove(peer); err != nil {
			return false, errors.Join(errors.Join(debts...), err)
		}
		if ambiguous {
			debts = append(debts, fmt.Errorf("sourced peer %s has a foreign lookalike under a 5402 guard", peer))
		}
	}
	for _, held := range v.rules {
		if held.Priority != prioritySourcedGuard || held.Family != FamilyIPv6 ||
			!held.To.IsValid() || !held.From.IsValid() {
			continue
		}
		guard := sourcedGuardRule(schema.PrefixFrom(held.To), held.From)
		if !sourcedExactShape(held, guard, p.table.Proto) {
			continue
		}
		peer := sourcedPeerRule(guard.To, held.From, key.ID)
		if sourcedAmbiguous(v.rules, peer, p.table.Proto) || v.has(peer) {
			continue
		}
		if _, err := p.Rules(); err != nil {
			return false, errors.Join(errors.Join(debts...), fmt.Errorf("reread ordinary rules before removing 5402: %w", err))
		}
		if err := v.read(); err != nil {
			return false, errors.Join(errors.Join(debts...), err)
		}
		if sourcedAmbiguous(v.rules, peer, p.table.Proto) || v.has(peer) {
			continue
		}
		if err := v.remove(guard); err != nil {
			return false, errors.Join(errors.Join(debts...), err)
		}
	}
	routes, _, err := p.SourcedRoutes(key.ID)
	if err != nil {
		return false, errors.Join(errors.Join(debts...), fmt.Errorf("read sourced mirror for withdrawal: %w", err))
	}
	for _, route := range routes {
		if err := p.DelSourcedRoute(key.ID, route); err != nil {
			debts = append(debts, fmt.Errorf("delete sourced mirror %s: %w", route, err))
		}
	}
	remaining, _, readErr := p.SourcedRoutes(key.ID)
	if readErr != nil {
		debts = append(debts, fmt.Errorf("read back sourced mirror withdrawal: %w", readErr))
	} else if len(remaining) != 0 {
		debts = append(debts, fmt.Errorf("%d sourced mirror routes remain after withdrawal", len(remaining)))
	}
	return true, errors.Join(debts...)
}

// releaseSourcedGuards removes a pair's refusal only after a complete pass
// has established the new mirror and admission, and both rule views have
// confirmed that no foreign selector still makes the pair ambiguous.
func (p *netlinkPlatform) releaseSourcedGuards(r *Reconciler) error {
	v := sourcedRuleView{p: p}
	if err := v.read(); err != nil {
		return err
	}
	for _, held := range v.rules {
		if held.Priority != prioritySourcedGuard || held.Family != FamilyIPv6 ||
			!held.To.IsValid() || !held.From.IsValid() {
			continue
		}
		guard := sourcedGuardRule(schema.PrefixFrom(held.To), held.From)
		if !sourcedExactShape(held, guard, p.table.Proto) {
			continue
		}
		peer := sourcedPeerRule(guard.To, held.From, r.table.Sourced.ID)
		if sourcedAmbiguous(v.rules, peer, p.table.Proto) {
			continue
		}
		if _, err := p.Rules(); err != nil {
			return fmt.Errorf("reread ordinary rules before removing 5402: %w", err)
		}
		if err := v.read(); err != nil {
			return err
		}
		if sourcedAmbiguous(v.rules, peer, p.table.Proto) {
			continue
		}
		if err := v.remove(guard); err != nil {
			return err
		}
	}
	return nil
}

func sourcedStandingOwnedRule(held DumpedRule, proto uint8) (Rule, bool) {
	if held.Family != FamilyIPv6 || held.Protocol != proto ||
		held.Priority != prioritySourcedMain && held.Priority != prioritySourcedRefused ||
		!held.To.IsValid() || !held.To.Addr().Is6() {
		return Rule{}, false
	}
	destination := schema.PrefixFrom(held.To)
	rule := Rule{Family: FamilyIPv6, Priority: held.Priority, To: destination, IIF: linuxLoopback}
	if held.From.IsValid() {
		rule.IIF = ""
		rule.From = schema.PrefixFrom(held.From)
	}
	if held.Priority == prioritySourcedMain {
		rule.Table = schema.TableMain
		rule.suppress = SuppressUpTo(destination.Bits() - 1)
	} else {
		rule.action = actionUnreachable
	}
	return rule, sourcedExactShape(held, rule, proto)
}

// retireSourcedStanding removes obsolete D/source protection only after
// admission and the mirror have converged. A guard retains its D's refusals
// until the foreign selector leaves and a later pass removes the guard.
func (p *netlinkPlatform) retireSourcedStanding(r *Reconciler) error {
	wanted := sourcedStandingRules(r.table.Sourced.To, r.sourcedSources)
	v := sourcedRuleView{p: p}
	if err := v.read(); err != nil {
		return err
	}
	for _, priority := range []uint32{prioritySourcedMain, prioritySourcedRefused} {
		for _, held := range v.rules {
			if held.Priority != priority {
				continue
			}
			rule, owned := sourcedStandingOwnedRule(held, p.table.Proto)
			if !owned || slices.Contains(wanted, rule) {
				continue
			}
			if priority == prioritySourcedRefused && slices.ContainsFunc(v.rules, func(other DumpedRule) bool {
				return other.Family == FamilyIPv6 && other.Priority == prioritySourcedGuard &&
					other.Protocol == p.table.Proto && other.To == held.To &&
					(!held.From.IsValid() || other.From == held.From)
			}) {
				continue
			}
			if err := v.remove(rule); err != nil {
				return err
			}
		}
	}
	return nil
}

// clearSourcedStanding is only called after the ordinary down set has left.
// It includes prefixes from earlier network snapshots, not only today's S.
// A same-protocol foreign selector is never a deletion target by accident.
func (p *netlinkPlatform) clearSourcedStanding() error {
	v := sourcedRuleView{p: p}
	if err := v.read(); err != nil {
		return err
	}
	for _, held := range v.rules {
		if held.Family == FamilyIPv6 && held.Priority == prioritySourcedGuard &&
			held.Protocol == p.table.Proto {
			return fmt.Errorf("sourced pair guard remains while disabling")
		}
	}
	for _, priority := range []uint32{prioritySourcedMain, prioritySourcedRefused} {
		for _, held := range v.rules {
			if held.Priority != priority {
				continue
			}
			rule, owned := sourcedStandingOwnedRule(held, p.table.Proto)
			if !owned {
				continue
			}
			if err := v.remove(rule); err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *netlinkPlatform) removeSourcedKey(r *Reconciler) error {
	foreignSelector := func() error {
		all, err := p.SourcedRules()
		if err != nil {
			return err
		}
		for _, held := range all {
			if held.Family == FamilyIPv6 && sourcedPriority(held.Priority) &&
				held.Protocol == p.table.Proto && held.Unread != 0 {
				return fmt.Errorf("cannot remove sourced key while foreign selector stands at priority %d", held.Priority)
			}
		}
		return nil
	}
	if err := foreignSelector(); err != nil {
		return err
	}
	safe, err := p.withdrawSourcedAdmission(r)
	if !safe || err != nil {
		return err
	}
	if err := foreignSelector(); err != nil {
		return err
	}
	return p.clearSourcedStanding()
}
