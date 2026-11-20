// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"

	"ranet3.com/pkgs/ranet3/schema"
)

// ruleView is this reconciler's rules as a pass knows them: a listing, which
// each write that lands updates, and which a write that fails has reread, since
// the kernel may have taken it in part or another writer may have moved.
type ruleView struct {
	r     *Reconciler
	rules []Rule
	errs  []error
	// failed says a write of this pass failed, and broken that a reread after it
	// failed too, so the pass knows nothing more and writes nothing more
	failed, broken bool
	added, removed int
	// staged is every rule that may stand beside the down set while the start is staged (stagedSet), and staging says the pass
	// found a down rule beside no running set and entered the staged set ahead of its address and route writes (enterRules)
	staged  []Rule
	staging bool
	// held is the prefixes of the overlay whose pairs the down set holds this pass (heldOverlay)
	held []schema.Prefix
}

func (v *ruleView) has(rule Rule) bool { return slices.Contains(v.rules, rule) }

// list lists the rules into the view, and where the listing fails the pass knows nothing more
func (v *ruleView) list() {
	rules, err := v.r.rules.Rules()
	if err != nil {
		v.errs = append(v.errs, fmt.Errorf("list rules: %w", err))
		v.broken = true
		return
	}
	v.rules, v.broken = rules, false
}

// reread lists the rules again after a write that failed, unless the pass already knows nothing more
func (v *ruleView) reread() {
	if !v.broken {
		v.list()
	}
}

// fault records the failed write and rereads the rules
func (v *ruleView) fault(err error) {
	v.errs = append(v.errs, err)
	v.failed = true
	v.reread()
}

// add adds rule where the view lacks it, reporting whether the view holds it after
func (v *ruleView) add(rule Rule) bool {
	if v.broken {
		return false
	}
	if v.has(rule) {
		return true
	}
	if err := v.r.rules.AddRule(rule); err != nil {
		v.fault(fmt.Errorf("add rule %s: %w", rule, err))
		return !v.broken && v.has(rule)
	}
	v.rules = append(v.rules, rule)
	v.added++
	return true
}

// del deletes rule once for each copy the view holds when it is called, reporting whether the view holds none after
func (v *ruleView) del(rule Rule) bool {
	copies := 0
	for _, held := range v.rules {
		if held == rule {
			copies++
		}
	}
	for range copies {
		if v.broken {
			break
		}
		if err := v.r.rules.DelRule(rule); err != nil {
			v.fault(fmt.Errorf("delete rule %s: %w", rule, err))
			break
		}
		v.removed++
		if i := slices.Index(v.rules, rule); i >= 0 {
			v.rules = slices.Delete(v.rules, i, i+1)
		}
	}
	return !v.broken && !v.has(rule)
}

// prune deletes every rule of the view but the down rules and those keep holds, in withdrawOrder, so as a withdrawal the
// catch-alls and the mesh's lookups go ahead of the lookups of main and each goto ahead of its nop, reporting whether the view holds
// none of them after
func (v *ruleView) prune(keep func(Rule) bool) bool {
	pruned := true
	for _, rule := range withdrawOrder(v.rules) {
		if !isDownRule(rule) && !keep(rule) && !v.del(rule) {
			pruned = false
		}
	}
	return pruned
}

// down is the down rules the view holds, each family's refusals ahead of its lookups of main, the order a release deletes them in
func (v *ruleView) down(family Family) []Rule {
	var out []Rule
	for _, priority := range []uint32{priorityDownRefused, priorityDownMain} {
		for _, rule := range v.rules {
			if rule.Family == family && rule.Priority == priority && isDownRule(rule) && !slices.Contains(out, rule) {
				out = append(out, rule)
			}
		}
	}
	return out
}

// pairOf is the pair of down rules of to, the refusal first
func pairOf(to schema.Prefix) (refusal, lookup Rule) {
	pair := downRules([]schema.Prefix{to})
	return pair[0], pair[1]
}

// covered reports whether the view holds the pair of prefix, or of another prefix of the overlay that holds it
func (v *ruleView) covered(prefix netip.Prefix) bool {
	for _, to := range v.r.rt.Overlay {
		if !to.Prefix.Contains(prefix.Addr()) || to.Prefix.Bits() > prefix.Bits() {
			continue
		}
		if refusal, lookup := pairOf(to); v.has(refusal) && v.has(lookup) {
			return true
		}
	}
	return false
}

// addPairs adds the pair of each prefix of the down set where the view lacks a rule of it, its refusal 32765 first and its lookup 32764
// only once the refusal stands, so no lookup to the prefix meets the lookup alone and leaves by a shorter route of main
func (r *Reconciler) addPairs(v *ruleView) {
	for _, rule := range downRules(v.held) {
		if rule.Priority == priorityDownRefused {
			refusal, lookup := pairOf(rule.To)
			_ = v.add(refusal) && v.add(lookup)
		}
	}
}

// rePair brings the pairs of down rules to the down set's, for a pass that stages and for a stopped pass: each pair of a prefix a
// reload removed, or one a carve-out now equals, goes out lookup first, its 32764 and then, once that delete is confirmed and a
// pair that stands covers each prefix of the down set it overlaps, that prefix's own or an outer prefix's, its 32765, the reverse
// of a release's order, and each prefix of the down set gets its own pair where the view lacks a rule of it, 32765 first
// (addPairs). A removed prefix that overlaps one of the overlay loses its 32764 ahead of the adds, since standing first at 32764 it
// would send the overlay prefix's lookups to main's route of the removed prefix's length whatever pair the overlay prefix has,
// while its 32765 alone refuses. Every other removed prefix keeps its pair until the adds are done.
func (r *Reconciler) rePair(v *ruleView) {
	var gone []schema.Prefix
	for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
		for _, rule := range v.down(family) {
			if !slices.Contains(v.held, rule.To) && !slices.Contains(gone, rule.To) {
				gone = append(gone, rule.To)
			}
		}
	}
	overlaps := func(to schema.Prefix) bool {
		return slices.ContainsFunc(r.rt.Overlay, func(prefix schema.Prefix) bool { return prefix.Prefix.Overlaps(to.Prefix) })
	}
	looked := map[schema.Prefix]bool{}
	drop := func(early bool) {
		for _, to := range gone {
			if overlaps(to) == early {
				_, lookup := pairOf(to)
				looked[to] = v.del(lookup)
			}
		}
	}
	drop(true)
	r.addPairs(v)
	drop(false)
	open := func(to schema.Prefix) bool {
		return slices.ContainsFunc(v.held, func(prefix schema.Prefix) bool { return prefix.Prefix.Overlaps(to.Prefix) && !v.covered(prefix.Prefix) })
	}
	for _, to := range gone {
		if looked[to] && !open(to) {
			refusal, _ := pairOf(to)
			v.del(refusal)
		}
	}
}

// runs reports whether the view shows a node that runs: this reconciler's release committed since its last stop, no down rule
// stands, or a rule stands that a release adds only after its commit point whatever the mode, 5420, 5430 or 5440, which a
// take-back never leaves, so a down rule beside it is left over from a release that committed or a stop cut short
func (v *ruleView) runs() bool {
	return v.r.released || !slices.ContainsFunc(v.rules, isDownRule) ||
		slices.ContainsFunc(v.rules, func(rule Rule) bool { return stepOf(rule.Priority, true) == stepLate })
}

// enterRules lists the rules into the pass's view ahead of its address and route writes, also where the address listing will fail,
// and where the view shows a down rule and no node that runs enters the staged set: the own pair of each prefix of the down set in
// where the view lacks a rule of it, 32765 first, and the pair of each other prefix out, 32764 first (rePair), under
// fallback = "none" its refusing rules in, and every rule out but those of the staged set (stagedSet). So while the pass writes its
// routes no lookup of main or of the mesh's table stands ahead of the down set, a rule a failed take-back left among them, the
// host's traffic outside the overlay stays refused under none, and applyRules then stages exactly (stage).
func (r *Reconciler) enterRules(network passNetwork) *ruleView {
	if r.rules == nil {
		return nil
	}
	v := &ruleView{r: r, staged: r.stagedSet(network.network), held: heldOverlay(r.rt.Overlay, network.carved)}
	if v.list(); !v.broken {
		r.noteDeleted(v.rules)
	}
	if v.broken || v.runs() {
		return v
	}
	v.staging = true
	r.rePair(v)
	for _, rule := range v.staged {
		if stepOf(rule.Priority, false) != stepStaged {
			v.add(rule)
		}
	}
	v.prune(func(rule Rule) bool { return slices.Contains(v.staged, rule) })
	return v
}

// refuseBlind adds, under fallback = "none" where the pass could not list the rules, the refusing rules of the staged set, 5490,
// 5400 and 5450 for lo and each link forward expands to, without a listing and ahead of the pass's address and route writes, as a
// stop adds its down set where its listing fails, so a pass that knows nothing of the rules still holds the host's traffic outside
// the overlay refused. The kernel answers the add of one that stands with EEXIST, which AddRule takes as done, so none stands twice.
// A failed add is the pass's error, and the view stays as blind as it was.
func (r *Reconciler) refuseBlind(v *ruleView) {
	if v == nil || !v.broken || !r.refuses() {
		return
	}
	for _, rule := range v.staged {
		if stepOf(rule.Priority, false) == stepStaged {
			continue
		}
		if err := r.rules.AddRule(rule); err != nil {
			v.errs = append(v.errs, fmt.Errorf("add rule %s: %w", rule, err))
		}
	}
}

// noteDeleted warns of each rule the last pass or withdrawal left standing that listed lacks, listed being the first listing of a
// pass or withdrawal. Only another writer can have deleted such a rule, since this reconciler writes rules in its passes and
// withdrawals alone. A running node's 5110 another writer deletes sends the overlay by main until the pass puts it back, so the
// operator is told. A rule is warned of again only after a first listing has shown it standing, so a delete after the pass put it
// back and before such a listing goes untold. Routes are not watched here: another writer's delete of a hold route is put back
// with no warning.
func (r *Reconciler) noteDeleted(listed []Rule) {
	for _, rule := range r.standing {
		if !slices.Contains(listed, rule) && r.warnedDeleted.mark(rule) {
			slog.Warn("kernel found a rule of its own that another writer deleted", "rule", rule.String())
		}
	}
	r.warnedDeleted.end()
}

// refuses reports whether the configured mode refuses where its exit does not answer, fallback = "none", written or unwritten in
// mode 3, which a pass reads whether or not it can judge the mode
func (r *Reconciler) refuses() bool {
	mode := r.table.Mode()
	return mode != nil && mode.Refuses()
}

// stagedSet is every rule that may stand beside the down set while a start is staged, from the configured mode and the network
// alone, so a pass that cannot list the tun's addresses has it too: each family's 5190 and 5100 and the 5110 of each overlay
// prefix, and under fallback = "none" 5490, 5400 and 5450 for lo and each link forward expands to, as derivedRules gives them
func (r *Reconciler) stagedSet(network NetworkState) []Rule {
	refusing := r.refuses()
	var view exitView
	if refusing {
		forwarded, _ := expandForward(r.table.Mode().Forward, r.rt.Interface, network)
		view = exitView{on: true, fallback: true, forwarded: forwarded, unaddressed: []Family{FamilyIPv4, FamilyIPv6}}
	}
	return slices.DeleteFunc(derivedRules(r.table.ID, r.rt.Overlay, nil, view), func(rule Rule) bool {
		return stepOf(rule.Priority, refusing) != stepStaged
	})
}

// holdTouched is the innermost overlay prefix where a route write moves what its 5110 rests on: a delete of an unreachable route or a
// throw at or inside the prefix, the hold or a piece of it, a delete of a route at the prefix itself with no source, the mesh's own
// route there among them, which holdsAt keeps a 5110 on, or an add of a throw inside it
func (r *Reconciler) holdTouched(route Route, deleting bool) (netip.Prefix, bool) {
	at := slices.ContainsFunc(r.rt.Overlay, func(prefix schema.Prefix) bool { return prefix.Prefix.Masked() == route.Destination })
	if route.Source.IsValid() || !route.Throw && !(deleting && (route.Unreachable || at)) {
		return netip.Prefix{}, false
	}
	var inner netip.Prefix
	for _, prefix := range SchemaPrefixes(r.rt.Overlay) {
		if prefix.Contains(route.Destination.Addr()) && route.Destination.Bits() >= prefix.Bits() && (!inner.IsValid() || prefix.Bits() > inner.Bits()) {
			inner = prefix
		}
	}
	return inner, inner.IsValid()
}

// unstageOverlay deletes from v, while the pass stages, the 5110 of each overlay prefix where a write of del or add moves what that
// 5110 rests on (holdTouched), ahead of those writes, since beside an exit default 5110 would take every lookup to the prefix into
// the mesh until a route at the prefix itself is back. It returns the prefixes whose 5110 may still stand, those whose delete failed
// and every one where the pass knows nothing of the rules, whose route writes wait for the next pass. stage puts a 5110 back only
// once a reread of the routes shows a route of the reconciler's at the prefix itself with no source.
func (r *Reconciler) unstageOverlay(v *ruleView, del, add []Route) map[netip.Prefix]bool {
	if v == nil || (!v.broken && !v.staging) {
		return nil
	}
	blocked, seen := map[netip.Prefix]bool{}, map[netip.Prefix]bool{}
	visit := func(route Route, deleting bool) {
		prefix, ok := r.holdTouched(route, deleting)
		if !ok || seen[prefix] {
			return
		}
		seen[prefix] = true
		if v.broken || !v.prune(func(rule Rule) bool { return rule.Priority != priorityOverlay || rule.To.Prefix != prefix }) {
			blocked[prefix] = true
		}
	}
	for _, route := range del {
		visit(route, true)
	}
	for _, route := range add {
		visit(route, false)
	}
	return blocked
}

// holdsAt reports whether a route this pass wanted at prefix, with no source, stands as the pass's own listing of the routes and
// its writes read it (see holdsOverlay): the overlay's hold, the throw of a carve-out of the whole prefix, or the mesh's own route
// there, which keeps the prefix in the mesh where a carve-out equals it, so no lookup to the prefix meets a shorter route of the
// mesh's table
func (r *Reconciler) holdsAt(prefix netip.Prefix) bool {
	return r.routesListed && slices.ContainsFunc(r.wanted, func(route Route) bool {
		return route.Destination == prefix && !route.Source.IsValid() && r.installed[route]
	})
}

// startStep is when a start brings a priority of the derived set in: staged, beside the down set from the start's entry until its
// release, or added by the release before its commit point (stepFirst) or after it (stepLate). stepNone is a priority no start
// brings in.
type startStep int

const (
	stepNone startStep = iota
	stepStaged
	stepFirst
	stepLate
)

// startOrder is each priority of the derived set in the order a start brings it in, with its step. refusing marks the three
// staged under fallback = "none" alone, which stand from the start's entry on, so the host's traffic stays refused at the FIB,
// where no filter's state decides it: elsewhere 5490 and 5400 go in with the release's first adds and 5450 with its late ones. No
// staged rule but 5110 at a prefix its hold answers whole looks main or the mesh's table up, and before the commit point no rule of
// the release looks the mesh's table up, so no destination outside the overlay leaves another way than a completed down sends it,
// and no take-back can leave 5420 without 5410.
var startOrder = []struct {
	priority uint32
	step     startStep
	refusing bool
}{
	{priorityOverlayEnd, stepStaged, false},
	{priorityUnderlayPastOverlay, stepStaged, false},
	{priorityOverlay, stepStaged, false},
	{priorityMeshEnd, stepFirst, true},
	{priorityUnderlayPastMesh, stepFirst, true},
	{priorityUplinkSource, stepFirst, false},
	{priorityMain, stepFirst, false},
	{priorityLinkSource, stepFirst, false},
	{priorityOwnPastMesh, stepFirst, false},
	{priorityMesh, stepLate, false},
	{priorityOwn, stepLate, false},
	{priorityCatchAll, stepLate, false},
	{priorityRefused, stepLate, true},
}

// stepOf is the step a start brings priority in at, under fallback = "none" where refusing
func stepOf(priority uint32, refusing bool) startStep {
	for _, at := range startOrder {
		if at.priority == priority {
			if at.refusing && refusing {
				return stepStaged
			}
			return at.step
		}
	}
	return stepNone
}

// inStep is the rules of ruleSet a start brings in at step, in each family in startOrder's order, ruleSet's within a priority
func inStep(ruleSet []Rule, at startStep, refusing bool) []Rule {
	var out []Rule
	for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
		for _, order := range startOrder {
			if stepOf(order.priority, refusing) != at {
				continue
			}
			for _, rule := range ruleSet {
				if rule.Family == family && rule.Priority == order.priority {
					out = append(out, rule)
				}
			}
		}
	}
	return out
}

// applyRulesDown brings the rules to ruleSet in a view that holds a down rule. Where this reconciler's release committed since its
// last stop, or the view holds the whole set, the node runs and a down rule left is a delete still owed: the pass brings the set
// whole and deletes the down rules again (owe). Otherwise it stages (stage) and releases where it can (releaseRules).
func (r *Reconciler) applyRulesDown(v *ruleView, ruleSet []Rule) {
	refusing := r.refuses()
	whole := !slices.ContainsFunc(ruleSet, func(rule Rule) bool { return !v.has(rule) })
	if r.released || whole {
		r.released = true
		r.owe(v, ruleSet, refusing)
		return
	}
	if r.stage(v, ruleSet, refusing) {
		r.releaseRules(v, ruleSet, refusing)
	}
}

// converge deletes every rule of the view ruleSet does not hold but the down rules and adds what ruleSet holds that the view lacks
func (r *Reconciler) converge(v *ruleView, ruleSet []Rule) {
	v.prune(func(rule Rule) bool { return slices.Contains(ruleSet, rule) })
	for _, rule := range ruleSet {
		v.add(rule)
	}
}

// owe brings a running node's rules to ruleSet beside the down rules left: what ruleSet does not hold out, the rules a start
// brings in before its commit point in, the down rules out (dropDownSet), and the rest of ruleSet in, in the release's order. Each
// write that fails stays owed and the next pass writes it again, and nothing of the running set is taken down.
func (r *Reconciler) owe(v *ruleView, ruleSet []Rule, refusing bool) {
	v.prune(func(rule Rule) bool { return slices.Contains(ruleSet, rule) })
	for _, rule := range ruleSet {
		if stepOf(rule.Priority, refusing) != stepLate {
			v.add(rule)
		}
	}
	r.dropDownSet(v)
	for _, rule := range inStep(ruleSet, stepLate, refusing) {
		v.add(rule)
	}
}

// dropDownSet deletes the down rules of the view, in each family the refusals and then the lookups of main, keeping a lookup whose
// refusal's delete failed, so the refusal never stands alone where it would refuse the marked packet 5400 sends past the mesh
func (r *Reconciler) dropDownSet(v *ruleView) {
	for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
		var refused []schema.Prefix
		for _, rule := range v.down(family) {
			if rule.Priority == priorityDownMain && slices.Contains(refused, rule.To) {
				continue
			}
			if !v.del(rule) && rule.Priority == priorityDownRefused {
				refused = append(refused, rule.To)
			}
		}
	}
}

// stage writes, from a view holding a down rule, what stands beside the down set until the release: first the pairs as rePair
// brings them to the down set's, then it deletes every other rule but the down rules (prune), then adds the staged rules of ruleSet
// but 5110 in ruleSet's order, each nop ahead of its goto, and each 5110 whose prefix holds a route of the pass at the prefix itself
// (holdsAt), as the pass's listing and a reread of the routes both show it, and whose family's 5190 and 5100 stand. It reports
// whether the release can go: every hold of the down set's prefixes stands as the pass's own listing of the routes shows it, and
// every rule staged stands.
func (r *Reconciler) stage(v *ruleView, ruleSet []Rule, refusing bool) bool {
	r.rePair(v)
	var base, overlay, keep []Rule
	for _, rule := range ruleSet {
		switch {
		case stepOf(rule.Priority, refusing) != stepStaged:
		case rule.Priority == priorityOverlay:
			overlay = append(overlay, rule)
		default:
			base = append(base, rule)
		}
	}
	keep = append(keep, base...)
	for _, rule := range overlay {
		if r.holdsAt(rule.To.Prefix) {
			keep = append(keep, rule)
		}
	}
	v.prune(func(rule Rule) bool { return slices.Contains(keep, rule) })
	for _, rule := range base {
		v.add(rule)
	}
	// a reread of the routes, taken once and only for a 5110 the view lacks, so a hold whose write this pass moved has its 5110
	// back only where the kernel shows a route at the prefix itself
	var listed []Route
	read, readOK := false, false
	holdListed := func(prefix netip.Prefix) bool {
		if !read {
			read = true
			routes, err := r.plat.Routes()
			if err != nil {
				v.errs = append(v.errs, fmt.Errorf("list routes for the overlay's lookups: %w", err))
				v.failed = true
			}
			listed, readOK = routes, err == nil
		}
		return readOK && slices.ContainsFunc(listed, func(route Route) bool {
			return route.Destination == prefix && !route.Source.IsValid()
		})
	}
	for _, rule := range keep[len(base):] {
		if v.has(rule) {
			continue
		}
		if v.has(Rule{Family: rule.Family, Priority: priorityOverlayEnd, action: actionNop}) && slices.ContainsFunc(base, func(b Rule) bool {
			return b.Family == rule.Family && b.Priority == priorityUnderlayPastOverlay && v.has(b)
		}) && holdListed(rule.To.Prefix) {
			v.add(rule)
		}
	}
	// every 5110 kept rests on holdsAt, so on the pass's own listing of the routes
	return !v.failed && !v.broken && r.holdsOverlay(downRules(v.held), r.wanted) && len(keep) == len(base)+len(overlay) &&
		!slices.ContainsFunc(keep, func(rule Rule) bool { return !v.has(rule) })
}

// releaseRules puts the rest of ruleSet in and the down set out, from a staged view: in each family the rules of stepFirst, the
// second bypass where not staged and the lookups of main, then a reread that must show every rule of ruleSet but those of
// stepLate, the release's one commit point, then in each family the down set, refusals first (dropDownSet), then the rules of
// stepLate, the mesh's own lookups, the catch-all and 5450 where not staged. A write before the commit point that fails, the
// reread among them, takes back what the release put, in the reverse order, so the down set stands whole with the staged rules
// alone and the pass is retried. A rule whose take-back fails too stays beside the down set, owed in the status until a pass
// deletes it, the next pass first (enterRules). After the commit point nothing is taken back: a down rule's delete or an add that
// fails is owed, in the status, and every pass writes it again while the running rules stay (owe).
func (r *Reconciler) releaseRules(v *ruleView, ruleSet []Rule, refusing bool) {
	var put []Rule
	for _, rule := range inStep(ruleSet, stepFirst, refusing) {
		if v.has(rule) {
			continue
		}
		if !v.add(rule) {
			r.takeBack(v, put)
			return
		}
		put = append(put, rule)
	}
	reread, err := r.rules.Rules()
	if err != nil {
		// the release's adds landed as the view has them, so the take-back works from it, and a reread after it tells the record
		// what stands, or that it is not known
		v.errs = append(v.errs, fmt.Errorf("list rules: %w", err))
		v.failed = true
		r.takeBack(v, put)
		v.reread()
		return
	}
	v.rules = reread
	if missing := slices.DeleteFunc(slices.Clone(ruleSet), func(rule Rule) bool { return stepOf(rule.Priority, refusing) == stepLate || v.has(rule) }); len(missing) > 0 {
		v.errs = append(v.errs, fmt.Errorf("the rules reread after the release's adds lack %s", ruleNames(missing)))
		v.failed = true
		r.takeBack(v, put)
		return
	}
	r.released = true
	r.dropDownSet(v)
	for _, rule := range inStep(ruleSet, stepLate, refusing) {
		v.add(rule)
	}
}

// takeBack deletes put, the rules a failed release added, in the reverse order. One whose delete fails stays beside the down set,
// and the record owes its delete until a pass deletes it (reportRules).
func (r *Reconciler) takeBack(v *ruleView, put []Rule) {
	for _, rule := range slices.Backward(put) {
		v.del(rule)
	}
}

// debts is each delete a running node owes, by overlay prefix: the whole pair of a prefix or its refusal alone, each of which
// refuses some lookup the running set answers, the marked packet to an endpoint main reaches by a shorter route and, for a prefix
// a reload removed, the host's own send into it. A lookup 32764 alone answers no lookup another way than the running set and is
// deleted without a report.
func debts(v *ruleView) []string {
	var out []string
	for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
		for _, rule := range v.down(family) {
			if rule.Priority != priorityDownRefused {
				continue
			}
			if _, lookup := pairOf(rule.To); v.has(lookup) {
				out = append(out, fmt.Sprintf("delete the pair of %s (32765, 32764)", rule.To))
			} else {
				out = append(out, fmt.Sprintf("delete the refusal of %s (32765)", rule.To))
			}
		}
	}
	return out
}

// reportRules records what the view shows: where the pass knows nothing of the rules, that their count is not known, the writes
// owed kept as the last pass that listed them found them (heldNotKnown). Where the node runs (runs), no prefix as refused while
// down and each write it owes: the deletes of debts and the rules of ruleSet the view lacks, ruleSet being the derived set of the
// pass or, for a pass that cannot judge the mode, of the last pass that could. Where it is down or staged, the pairs that stand,
// and the delete of each rule beside them outside the staged set, which a failed take-back or another writer left. Each pass owes
// what stays until a pass writes it, and a change in what is owed is logged once.
func (r *Reconciler) reportRules(v *ruleView, ruleSet []Rule) {
	if v.broken {
		r.heldNotKnown()
		return
	}
	var owed []string
	held := 0
	if v.runs() {
		owed = debts(v)
		for _, rule := range ruleSet {
			if !v.has(rule) {
				owed = append(owed, "install "+rule.String())
			}
		}
	} else {
		var standing []Rule
		for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
			standing = append(standing, v.down(family)...)
		}
		held = heldPairs(standing)
		for _, rule := range v.rules {
			if !isDownRule(rule) && !slices.Contains(v.staged, rule) {
				owed = append(owed, "delete "+rule.String())
			}
		}
	}
	if len(owed) > 0 && !slices.Equal(owed, r.owedLogged) {
		slog.Warn("kernel owes rule writes, which each pass retries", "owed", strings.Join(owed, ", "))
	}
	r.owedLogged = owed
	r.routePass.Held, r.routePass.HeldUnknown, r.routePass.Owed = held, false, owed
}

// heldNotKnown records that the pass could not list the rules, so the count of the pairs that stand is not known, and keeps the
// writes owed as the last pass that listed them found them, since a debt leaves the record only where a listing shows it paid
func (r *Reconciler) heldNotKnown() {
	r.routePass.Held, r.routePass.HeldUnknown = 0, true
}

// ruleNames is rules written out on one line
func ruleNames(rules []Rule) string {
	out := make([]string, 0, len(rules))
	for _, rule := range rules {
		out = append(out, rule.String())
	}
	return strings.Join(out, ", ")
}
