// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/schema"
)

// downOverlay is the overlay of the down set's tests, a prefix of each family
var downOverlay = prefixes(prefix("192.0.2.0/25"), prefix("3fff::/21"))

// kernelWrite is one write the fake took: a route deleted, or a rule added or deleted
type kernelWrite struct {
	op    string
	rule  Rule
	route Route
}

// recordingKernel is the fake kernel noting each write it took, in the order taken, and failing the delete of each rule of failDel
type recordingKernel struct {
	*fakeKernel
	noted   sync.Mutex
	writes  []kernelWrite
	failDel map[Rule]error
	// armed is each failure the fake held at a listing of its rules, a pass's first or a reread, and met each one it answered
	// with, both under noted, so a row's cleanup tells that every failure it armed for a pass was met by a count
	armed, met map[string]int
}

// newRecording is the recording fake, which fails the row at its end where a failure it held at a listing of the rules was never met
func newRecording(t *testing.T) *recordingKernel {
	k := &recordingKernel{fakeKernel: newFakeKernel(t), armed: map[string]int{}, met: map[string]int{}}
	t.Cleanup(func() {
		k.noted.Lock()
		defer k.noted.Unlock()
		for _, name := range slices.Sorted(maps.Keys(k.armed)) {
			if k.met[name] == 0 {
				t.Errorf("the fake held the failure %q at %d listings of the rules and met it never", name, k.armed[name])
			}
		}
	})
	return k
}

// arm notes each failure the fake holds now
func (k *recordingKernel) arm() {
	var names []string
	k.mu.Lock()
	for rule, err := range k.failAddRule {
		if err != nil {
			names = append(names, "add rule "+rule.String())
		}
	}
	for route, err := range k.failAdd {
		if err != nil {
			names = append(names, "add route "+route.String())
		}
	}
	for name, err := range map[string]error{"list routes": k.failList, "list rules": k.failRules, "list addresses": k.failAddrs} {
		if err != nil {
			names = append(names, name)
		}
	}
	k.mu.Unlock()
	k.noted.Lock()
	defer k.noted.Unlock()
	for rule, err := range k.failDel {
		if err != nil {
			names = append(names, "delete rule "+rule.String())
		}
	}
	for _, name := range names {
		k.armed[name]++
	}
}

// meet counts a failure the fake answered with
func (k *recordingKernel) meet(name string) {
	k.noted.Lock()
	defer k.noted.Unlock()
	k.met[name]++
}

func (k *recordingKernel) Rules() ([]Rule, error) {
	k.arm()
	rules, err := k.fakeKernel.Rules()
	if err != nil {
		k.meet("list rules")
	}
	return rules, err
}

func (k *recordingKernel) Routes() ([]Route, error) {
	routes, err := k.fakeKernel.Routes()
	if err != nil {
		k.meet("list routes")
	}
	return routes, err
}

func (k *recordingKernel) Addrs() ([]netip.Prefix, error) {
	addrs, err := k.fakeKernel.Addrs()
	if err != nil {
		k.meet("list addresses")
	}
	return addrs, err
}

func (k *recordingKernel) AddRoute(route Route) error {
	err := k.fakeKernel.AddRoute(route)
	if err != nil {
		k.meet("add route " + route.String())
	}
	return err
}

func (k *recordingKernel) note(w kernelWrite) {
	k.noted.Lock()
	defer k.noted.Unlock()
	k.writes = append(k.writes, w)
}

// taken is every write noted so far
func (k *recordingKernel) taken() []kernelWrite {
	k.noted.Lock()
	defer k.noted.Unlock()
	return slices.Clone(k.writes)
}

func (k *recordingKernel) DelRoute(route Route) error {
	err := k.fakeKernel.DelRoute(route)
	if err == nil {
		k.note(kernelWrite{op: "delete route", route: route})
	}
	return err
}

func (k *recordingKernel) AddRule(rule Rule) error {
	err := k.fakeKernel.AddRule(rule)
	if err == nil {
		k.note(kernelWrite{op: "add rule", rule: rule})
	} else {
		k.meet("add rule " + rule.String())
	}
	return err
}

func (k *recordingKernel) DelRule(rule Rule) error {
	k.noted.Lock()
	failed := k.failDel[rule]
	k.noted.Unlock()
	if failed != nil {
		k.meet("delete rule " + rule.String())
		return failed
	}
	err := k.fakeKernel.DelRule(rule)
	if err == nil {
		k.note(kernelWrite{op: "delete rule", rule: rule})
	}
	return err
}

// holds reports whether the fake's rules are exactly rules
func (k *recordingKernel) holds(rules []Rule) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return sameRules(slices.Collect(maps.Keys(k.rules)), rules)
}

// sameRules reports whether have holds each rule of want and nothing else, as many as want holds
func sameRules[R comparable](have, want []R) bool {
	return len(have) == len(want) && !slices.ContainsFunc(want, func(rule R) bool { return !slices.Contains(have, rule) })
}

// dumpedDown is the down set of overlay as the kernel dumps it under protocol
func dumpedDown(overlay []schema.Prefix, protocol uint8) []DumpedRule {
	var out []DumpedRule
	for _, rule := range downRules(overlay) {
		out = append(out, rule.dumped(protocol))
	}
	return out
}

// holdsAny reports whether the fake holds any of rules
func (k *recordingKernel) holdsAny(rules []Rule) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return slices.ContainsFunc(rules, func(rule Rule) bool { return k.rules[rule] })
}

// downHarness is a reconciler over downOverlay on the recording fake, with a live leaf in each family
func downHarness(t *testing.T) (*Reconciler, *recordingKernel) {
	t.Helper()
	tbl := Table{Reconcile: schema.Duration(time.Minute)}.Normalized()
	k := newRecording(t)
	return newReconciler(tbl, Runtime{Interface: "ranet0", Overlay: downOverlay}, nil, downTable(), k), k
}

// downTable is the mesh's table downHarness reads, a live leaf in each family
func downTable() *netstack.RouteTable {
	table := netstack.NewRouteTable()
	table.Set(netip.Prefix{}, prefix("192.0.2.7/32"), nil)
	table.Set(netip.Prefix{}, prefix("3fff::7/128"), nil)
	return table
}

// runDown runs r until its derived rules stand, and returns the cancel of its run and a wait for its end
func runDown(t *testing.T, r *Reconciler, k *recordingKernel) (context.CancelCauseFunc, func()) {
	t.Helper()
	ctx, cancel := context.WithCancelCause(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	wait := sync.OnceFunc(func() {
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("run: %v", err)
			}
		case <-time.After(waitBudget):
			t.Error("run did not return after its cancel")
		}
	})
	t.Cleanup(func() {
		cancel(nil)
		wait()
	})
	// the pass that wrote the rules records its stats after its last write, so a row that reads the record next waits for it too
	waitFor(t, func() bool { return k.holdsDerived(r) && !k.holdsAny(downRules(downOverlay)) && !r.Stats().At.IsZero() })
	return cancel, wait
}

// stopOrder fails where writes, a stop's, do not add each rule of the down set, each prefix's refusal ahead of its lookup of
// main, before their first delete
func stopOrder(t *testing.T, writes []kernelWrite) {
	t.Helper()
	added := map[Rule]int{}
	first := len(writes)
	for i, w := range writes {
		switch w.op {
		case "add rule":
			added[w.rule] = i
		default:
			first = min(first, i)
		}
	}
	for _, rule := range downRules(downOverlay) {
		i, ok := added[rule]
		switch {
		case !ok:
			t.Errorf("the stop never added %s", rule)
		case i > first:
			t.Errorf("the stop added %s after its first delete, %+v", rule, writes[first])
		case rule.Priority == priorityDownMain:
			if refusal := (Rule{Family: rule.Family, Priority: priorityDownRefused, To: rule.To, action: actionUnreachable}); added[refusal] > i {
				t.Errorf("the stop added %s ahead of %s", rule, refusal)
			}
		}
	}
}

// Each stop but the operator's adds the down set before it deletes any route or rule, which is all the fake notes of a stop's
// writes, and leaves it as the reconciler's only rules, counted in the record of a down's withdrawal. A stop whose add of one rule
// of the down set fails keeps that family as stopWhoseAddFails says.
func TestStopAddsTheDownSetBeforeAnyRouteOrRuleLeaves(t *testing.T) {
	for _, c := range []struct {
		name string
		stop func(*Reconciler, context.CancelCauseFunc)
	}{
		{"ranet3 down", func(r *Reconciler, _ context.CancelCauseFunc) { r.SetEnabled(false) }},
		{"a clean stop", func(_ *Reconciler, cancel context.CancelCauseFunc) { cancel(nil) }},
		{"a stop for a failed mesh", func(_ *Reconciler, cancel context.CancelCauseFunc) { cancel(ErrMeshFailed) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			r, k := downHarness(t)
			cancel, _ := runDown(t, r, k)
			from := len(k.taken())
			c.stop(r, cancel)
			waitFor(t, func() bool { return k.holds(downRules(downOverlay)) && len(k.snapshot()) == 0 })
			stopOrder(t, k.taken()[from:])
			if c.name == "ranet3 down" {
				waitFor(t, func() bool { return r.Stats().Held == 2 })
			}
		})
		for _, failing := range downRules(downOverlay) {
			t.Run(fmt.Sprintf("%s whose add of %s fails", c.name, failing), func(t *testing.T) { stopWhoseAddFails(t, failing, c.name) })
		}
	}
}

// ranet3 disable reconciler withdraws the down set with the rest, of a running reconciler and of one a down stopped, and adds none,
// and a clean stop of a disabled reconciler adds none either, while a start makes the next stop hold again
func TestDisableTakesTheDownSet(t *testing.T) {
	r, k := downHarness(t)
	cancel, wait := runDown(t, r, k)
	down := downRules(downOverlay)
	disable := func(what string) {
		t.Helper()
		from := len(k.taken())
		r.DropHold()
		r.SetEnabled(false)
		waitFor(t, func() bool { return k.holds(nil) && len(k.snapshot()) == 0 })
		for _, w := range k.taken()[from:] {
			if w.op == "add rule" {
				t.Errorf("disable %s added %s", what, w.rule)
			}
		}
		waitFor(t, func() bool { return r.Stats().Held == 0 })
	}
	start := func() {
		t.Helper()
		r.SetEnabled(true)
		waitFor(t, func() bool { return k.holdsDerived(r) && !k.holdsAny(down) })
	}

	disable("of a running reconciler")
	start()
	r.SetEnabled(false)
	waitFor(t, func() bool { return k.holds(down) })
	disable("of a reconciler a down stopped")
	start()
	cancel(nil)
	wait()
	if !k.holds(down) {
		t.Errorf("a clean stop after a start left %v, want the down set", k.rules)
	}

	r, k = downHarness(t)
	cancel, wait = runDown(t, r, k)
	r.DropHold()
	r.SetEnabled(false)
	waitFor(t, func() bool { return k.holds(nil) })
	cancel(nil)
	wait()
	if !k.holds(nil) {
		t.Errorf("a clean stop of a disabled reconciler left %v, want nothing", k.rules)
	}
}

// A start keeps the down set a stop left, for its overlay and for prefixes an earlier overlay held, a length changed among them,
// until its pass added every rule it derives, 5110 among them, and holds a route at each overlay prefix, and then deletes it
func TestStartTakesTheDownSetOnceItsRulesStand(t *testing.T) {
	for _, c := range []struct {
		name string
		left []schema.Prefix
	}{
		{"this overlay's", downOverlay},
		{"this overlay's and a prefix it no longer holds", append(slices.Clone(downOverlay), schema.MustPrefix("198.51.100.0/24"))},
		{"an overlay whose prefixes were shorter", prefixes(prefix("192.0.2.0/26"), prefix("3fff::/22"))},
	} {
		t.Run(c.name, func(t *testing.T) {
			r, k := downHarness(t)
			left := downRules(c.left)
			for _, rule := range left {
				k.rules[rule] = true
			}
			if err := r.reconcile(); err != nil {
				t.Fatal(err)
			}
			writes := k.taken()
			last := -1
			for i, w := range writes {
				if w.op == "add rule" && w.rule.Priority == priorityOverlay {
					last = i
				}
			}
			if last < 0 {
				t.Fatalf("the start added no rule at %d: %+v", priorityOverlay, writes)
			}
			// the overlay's own pairs stay until the 5110 stand, and a pair of a prefix the overlay no longer holds goes out lookup
			// first
			for i, w := range writes {
				if w.op == "delete rule" && slices.Contains(downRules(downOverlay), w.rule) && i < last {
					t.Errorf("the start deleted %s ahead of its last add at %d, %+v", w.rule, priorityOverlay, writes[last])
				}
				if w.op == "delete rule" && w.rule.Priority == priorityDownRefused && slices.Contains(left, w.rule) && !slices.Contains(downRules(downOverlay), w.rule) {
					if _, lookup := pairOf(w.rule.To); !slices.ContainsFunc(writes[:i], func(before kernelWrite) bool { return before.op == "delete rule" && before.rule == lookup }) {
						t.Errorf("the start deleted %s ahead of its lookup", w.rule)
					}
				}
			}
			if !k.holdsDerived(r) || k.holdsAny(left) {
				t.Errorf("after the start the kernel holds %v, want the derived rules alone", k.rules)
			}
			if held := r.Stats().Held; held != 0 {
				t.Errorf("the start's record counts %d overlay prefixes held, want 0", held)
			}
		})
	}
}

// A start whose add of 5110 fails, or whose route at an overlay prefix the kernel refuses, keeps the down set, counted in its
// record, beside the staged rules alone: each family's 5190 and 5100, and 5110 of the IPv6 prefix, whose hold stands, and not of
// the IPv4 one. The pass after the failure releases.
func TestStartWhoseWritesFailKeepsTheDownSet(t *testing.T) {
	for _, c := range []struct {
		name       string
		fail, heal func(*fakeKernel)
	}{
		{"its add of 5110", func(f *fakeKernel) { f.failAddRule[downOverlayRule] = errors.New("netlink says no") }, func(f *fakeKernel) { delete(f.failAddRule, downOverlayRule) }},
		{"its route at an overlay prefix", func(f *fakeKernel) { f.failAdd[downOverlayHold] = errors.New("netlink says no") }, func(f *fakeKernel) { delete(f.failAdd, downOverlayHold) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			r, k := downHarness(t)
			down := downRules(downOverlay)
			for _, rule := range down {
				k.rules[rule] = true
			}
			c.fail(k.fakeKernel)
			if err := r.reconcile(); err == nil {
				t.Fatal("the pass reported no error")
			}
			staged := slices.DeleteFunc(derivedRules(r.table.ID, r.rt.Overlay, r.ownPrefixes(r.src.Snapshot()), exitView{}), func(rule Rule) bool {
				return rule.Priority != priorityOverlayEnd && rule.Priority != priorityUnderlayPastOverlay && rule.Priority != priorityOverlay || rule == downOverlayRule
			})
			if !k.holds(append(slices.Clone(down), staged...)) {
				t.Errorf("after the failed pass the kernel holds %v, want the down set and %v", k.rules, staged)
			}
			if held := r.Stats().Held; held != 2 {
				t.Errorf("the failed pass's record counts %d overlay prefixes held, want 2", held)
			}
			c.heal(k.fakeKernel)
			if err := r.reconcile(); err != nil {
				t.Fatal(err)
			}
			if !k.holdsDerived(r) || k.holdsAny(down) {
				t.Errorf("after the pass that healed the kernel holds %v, want the derived rules alone", k.rules)
			}
		})
	}
}

// downOverlayRule is 5110 for downOverlay's IPv4 prefix, and downOverlayHold the overlay's hold there
var (
	downOverlayRule = Rule{Family: FamilyIPv4, Priority: priorityOverlay, To: schema.PrefixFrom(prefix("192.0.2.0/25")), Table: DefaultTable}
	downOverlayHold = Route{Destination: prefix("192.0.2.0/25"), Metric: holdMetric, Unreachable: true}
)

// downWarned names each rule of the down set of downOverlay and the command that deletes it, as the warning of a start with no
// reconciler does
var downWarned = []string{
	"priority 32765 to 192.0.2.0/25 family ipv4 unreachable protocol 155",
	"priority 32764 to 192.0.2.0/25 family ipv4 lookup main suppress_prefixlength 24 protocol 155",
	"priority 32765 to 3fff::/21 family ipv6 unreachable protocol 155",
	"priority 32764 to 3fff::/21 family ipv6 lookup main suppress_prefixlength 20 protocol 155",
	"ip -4 rule del priority 32765 to 192.0.2.0/25 protocol 155",
	"ip -4 rule del priority 32764 to 192.0.2.0/25 protocol 155",
	"ip -6 rule del priority 32765 to 3fff::/21 protocol 155",
	"ip -6 rule del priority 32764 to 3fff::/21 protocol 155",
}

// downWarning is the message of that warning
const downWarning = "kernel found rules an earlier instance left to hold overlay prefixes"

// The warning of a start with no reconciler names each rule of its overlay's down set an earlier instance left under the default
// protocol, with the command that deletes it, once for them all, and nothing else: the down set's shape at a prefix the file does
// not hold, the down set under another protocol, a rule at the refusal's priority that looks a table up, and a main lookup whose
// suppress is not the prefix's length less one. With none of the down set it says nothing.
func TestStartWithNoReconcilerNamesEachRuleOfTheDownSetLeft(t *testing.T) {
	others := []DumpedRule{
		Rule{Family: FamilyIPv4, Priority: priorityDownRefused, To: schema.PrefixFrom(prefix("198.51.100.0/24")), action: actionUnreachable}.dumped(DefaultProtocol),
		Rule{Family: FamilyIPv4, Priority: priorityDownRefused, To: schema.PrefixFrom(prefix("192.0.2.0/25")), Table: 300}.dumped(DefaultProtocol),
		Rule{Family: FamilyIPv4, Priority: priorityDownMain, To: schema.PrefixFrom(prefix("192.0.2.0/25")), Table: schema.TableMain, suppress: SuppressUpTo(0)}.dumped(DefaultProtocol),
	}
	others = append(others, dumpedDown(downOverlay, 99)...)
	said := logged(t)
	warnOfDownSet(append(dumpedDown(downOverlay, DefaultProtocol), others...), downOverlay)
	text := said.String()
	if n := strings.Count(text, downWarning); n != 1 {
		t.Errorf("the start warned %d times, want once:\n%s", n, text)
	}
	for _, want := range downWarned {
		if !strings.Contains(text, want) {
			t.Errorf("the warning does not name %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "198.51.100.0/24") || strings.Contains(text, "lookup 300") || strings.Contains(text, "suppress_prefixlength 0") || strings.Contains(text, "protocol 99") {
		t.Errorf("the warning names a rule outside the down set:\n%s", text)
	}
	said.Reset()
	warnOfDownSet(others, downOverlay)
	if said.Len() != 0 {
		t.Errorf("with none of the down set the start warned:\n%s", said.String())
	}
}

// A stop deletes the reconciler's rules before any route, from the last priority to the first with each goto ahead of the nop it
// lands on, so 5110 and the overlay's holds go after every rule that looks main up, and the routes go once no rule looks the
// mesh's table up
func TestStopDeletesTheRulesFromTheLastAndTheRoutesAfterThem(t *testing.T) {
	r, k := downHarness(t)
	runDown(t, r, k)
	routes := len(k.snapshot())
	from := len(k.taken())
	r.SetEnabled(false)
	waitFor(t, func() bool { return k.holds(downRules(downOverlay)) && len(k.snapshot()) == 0 })
	var got []string
	for _, w := range k.taken()[from:] {
		switch w.op {
		case "delete route":
			got = append(got, "delete route")
		default:
			got = append(got, fmt.Sprintf("%s %d", w.op, w.rule.Priority))
		}
	}
	want := []string{"add rule 32765", "add rule 32764", "add rule 32765", "add rule 32764"}
	for _, priority := range []int{priorityMesh, priorityMain, priorityUnderlayPastMesh, priorityMeshEnd, priorityOverlay, priorityUnderlayPastOverlay, priorityOverlayEnd} {
		want = append(want, fmt.Sprintf("delete rule %d", priority), fmt.Sprintf("delete rule %d", priority))
	}
	for range routes {
		want = append(want, "delete route")
	}
	if !slices.Equal(got, want) {
		t.Errorf("the stop wrote\n%q\nwant\n%q", got, want)
	}
}

// In every mode the order a stop deletes in puts each rule that looks main up ahead of 5110, each goto just ahead of the nop it
// lands on, and every other rule after the rules of later priorities
func TestWithdrawOrderTakesTheRulesThatLookMainUpAheadOf5110(t *testing.T) {
	links := NetworkState{
		IPv4: NetworkFamily{Links: []Link{{Name: "eth0", Prefixes: []netip.Prefix{prefix("198.51.100.10/24")}}}},
		IPv6: NetworkFamily{Links: []Link{{Name: "eth0", Prefixes: []netip.Prefix{prefix("2001:db8:a::10/64")}}}},
	}
	own := []netip.Prefix{prefix("203.0.113.240/28"), prefix("2001:db8:f0::/48")}
	for _, c := range []struct {
		name string
		exit exitView
	}{
		{"mode off", exitView{}},
		{"mode 2", exitView{on: true, network: links, forwarded: []string{"eth1"}}},
		{"mode 2 under fallback none", exitView{on: true, network: links, forwarded: []string{"eth1"}, fallback: true, own: own}},
	} {
		t.Run(c.name, func(t *testing.T) {
			rules := derivedRules(DefaultTable, downOverlay, own, c.exit)
			order := withdrawOrder(rules)
			if len(order) != len(rules) {
				t.Fatalf("the order holds %d rules of %d", len(order), len(rules))
			}
			last := slices.IndexFunc(order, func(rule Rule) bool { return rule.Priority == priorityOverlay })
			for i, rule := range order {
				switch {
				case rule.action == actionLookup && rule.Table == schema.TableMain && i > last:
					t.Errorf("%s goes after 5110, at %d of %v", rule, i, order)
				case rule.action == actionGoto:
					// the next rule of its family, which a lookup of that family meets next
					next := slices.IndexFunc(order[i+1:], func(other Rule) bool { return other.Family == rule.Family })
					if next < 0 || order[i+1+next].action != actionNop || order[i+1+next].Priority != rule.target {
						t.Errorf("%s is not just ahead of the nop it lands on in %v", rule, order)
					}
				case rule.action != actionNop && i > 0 && order[i-1].action != actionNop && order[i-1].Priority < rule.Priority:
					t.Errorf("%s goes after %s in %v", rule, order[i-1], order)
				}
			}
		})
	}
}

// stopWhoseAddFails is a stop of the kind stop names whose add of failing fails. It keeps the routes and rules of failing's family
// as a kill leaves them and withdraws the other's, and says so: a down records the error with the other family's prefix held and
// adds the rule again on its retry, and a clean stop and a stop for a failed mesh return it, leaving that family as the last pass
// left it.
func stopWhoseAddFails(t *testing.T, failing Rule, stop string) {
	t.Helper()
	r, k := downHarness(t)
	ctx, cancel := context.WithCancelCause(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	t.Cleanup(func() { cancel(nil); <-done })
	waitFor(t, func() bool { return k.holdsDerived(r) && !k.holdsAny(downRules(downOverlay)) })
	family := func(rules map[Rule]bool, routes []Route) (map[Rule]bool, []Route) {
		kept := map[Rule]bool{}
		for rule := range rules {
			if rule.Family == failing.Family && !isDownRule(rule) {
				kept[rule] = true
			}
		}
		return kept, slices.DeleteFunc(slices.Clone(routes), func(route Route) bool { return familyOf(route.Destination.Addr()) != failing.Family })
	}
	k.mu.Lock()
	rules := maps.Clone(k.rules)
	k.mu.Unlock()
	wantRules, wantRoutes := family(rules, k.snapshot())
	other := slices.DeleteFunc(downRules(downOverlay), func(rule Rule) bool { return rule.Family == failing.Family })
	k.mu.Lock()
	k.failAddRule[failing] = errors.New("netlink says no")
	k.mu.Unlock()
	leftAsKilled := func() bool {
		k.mu.Lock()
		now := maps.Clone(k.rules)
		k.mu.Unlock()
		gotRules, gotRoutes := family(now, k.snapshot())
		for _, rule := range other {
			if !now[rule] {
				return false
			}
		}
		others := 0
		for rule := range now {
			if rule.Family != failing.Family && !slices.Contains(other, rule) {
				others++
			}
		}
		return others == 0 && maps.Equal(gotRules, wantRules) && slices.Equal(gotRoutes, wantRoutes) && len(k.snapshot()) == len(wantRoutes)
	}
	var err error
	switch stop {
	case "ranet3 down":
		r.SetEnabled(false)
		waitFor(t, func() bool { return leftAsKilled() && r.Stats().Err != "" })
		stats := r.Stats()
		if stats.Held != 1 || !strings.Contains(stats.Err, leftText(failing.Family)) || !strings.Contains(stats.Err, "netlink says no") {
			t.Errorf("the down's record reads %d held and %q, want 1 held and the %s routes and rules left", stats.Held, stats.Err, failing.Family)
		}
		k.mu.Lock()
		delete(k.failAddRule, failing)
		k.mu.Unlock()
		waitFor(t, func() bool {
			return k.holds(downRules(downOverlay)) && len(k.snapshot()) == 0 && r.Stats().Err == "" && r.Stats().Held == 2
		})
		return
	case "a clean stop":
		cancel(nil)
	default:
		cancel(ErrMeshFailed)
	}
	select {
	case err = <-done:
		done <- err
	case <-time.After(waitBudget):
		t.Fatal("run did not return after its cancel")
	}
	if err == nil || !strings.Contains(err.Error(), leftText(failing.Family)) {
		t.Errorf("the stop returned %v, want the %s routes and rules left", err, failing.Family)
	}
	if !leftAsKilled() {
		t.Errorf("the stop left %v and %v, want the %s routes and rules as the last pass left them and the other family's down set", k.rules, k.snapshot(), failing.Family)
	}
}

// leftText is the error's words for a family a withdrawal leaves
func leftText(family Family) string {
	return fmt.Sprintf("left the %s routes and every %s rule not deleted in place", family, family)
}

// A stop whose delete of a rule fails keeps that family's routes and its rules from that one on in withdrawOrder, and says so, at
// a down, which keeps the down set too, and at disable reconciler, which adds none, while the other family goes but for a down's
// down set
func TestStopWhoseRuleDeleteFailsKeepsTheRestOfThatFamily(t *testing.T) {
	for _, disable := range []bool{false, true} {
		t.Run(map[bool]string{false: "ranet3 down", true: "disable reconciler"}[disable], func(t *testing.T) {
			r, k := downHarness(t)
			runDown(t, r, k)
			held, err := k.Rules()
			if err != nil {
				t.Fatal(err)
			}
			order := withdrawOrder(held)
			at := slices.IndexFunc(order, func(rule Rule) bool { return rule.Family == FamilyIPv4 && rule.Priority == priorityOverlay })
			want := slices.DeleteFunc(slices.Clone(order[at:]), func(rule Rule) bool { return rule.Family != FamilyIPv4 })
			routes := slices.DeleteFunc(k.snapshot(), func(route Route) bool { return !route.Destination.Addr().Is4() })
			k.noted.Lock()
			k.failDel = map[Rule]error{order[at]: errors.New("netlink says no")}
			k.noted.Unlock()
			if disable {
				r.DropHold()
			} else {
				want = append(want, downRules(downOverlay)...)
			}
			r.SetEnabled(false)
			waitFor(t, func() bool { return k.holds(want) && slices.Equal(k.snapshot(), routes) && r.Stats().Err != "" })
			if got := r.Stats().Err; !strings.Contains(got, leftText(FamilyIPv4)) || strings.Contains(got, "held") {
				t.Errorf("the stop records %q, want it to say the ipv4 routes and the ipv4 rules not deleted stand", got)
			}
			// the run's last withdrawal, at its cancel, deletes the rest
			k.noted.Lock()
			k.failDel = nil
			k.noted.Unlock()
		})
	}
}

// A reload while a down stopped the reconciler that changes the overlay writes the down set of the new overlay in the order a start
// that stages writes it: the 32764 of each old prefix that overlaps a new one, then the new pairs, each refusal first, then the old
// refusals
func TestReloadWhileDownRewritesTheDownSet(t *testing.T) {
	r, k := downHarness(t)
	runDown(t, r, k)
	r.SetEnabled(false)
	waitFor(t, func() bool { return k.holds(downRules(downOverlay)) && len(k.snapshot()) == 0 && r.Stats().Held == 2 })
	// 3 prefixes where the stop's overlay holds 2, so the count read is the reload's own
	moved := prefixes(prefix("192.0.2.0/24"), prefix("198.51.100.0/24"), prefix("3fff::/20"))
	from, stopped := len(k.taken()), r.Stats().At
	if err := r.SetTable(r.Table(), moved, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return k.holds(downRules(moved)) && !r.Stats().At.Equal(stopped) })
	old := downRules(downOverlay)
	var want []kernelWrite
	for _, rule := range []Rule{old[1], old[3]} {
		want = append(want, kernelWrite{op: "delete rule", rule: rule})
	}
	for _, rule := range downRules(moved) {
		want = append(want, kernelWrite{op: "add rule", rule: rule})
	}
	for _, rule := range []Rule{old[0], old[2]} {
		want = append(want, kernelWrite{op: "delete rule", rule: rule})
	}
	if writes := k.taken()[from:]; !slices.Equal(writes, want) {
		t.Errorf("the reload wrote %+v, want %+v", writes, want)
	}
	if held := r.Stats().Held; held != 3 {
		t.Errorf("after the reload the record counts %d overlay prefixes held, want the new overlay's 3", held)
	}
}

// nestedOverlay is an overlay whose IPv4 prefixes nest, a /26 inside a /24
var nestedOverlay = prefixes(prefix("192.0.2.0/24"), prefix("192.0.2.0/26"), prefix("3fff::/21"))

// Where overlay prefixes nest each prefix of the down set gets its own pair, whatever pair of an outer prefix stands, so a clean
// stop, a stopped pass, a reload that adds the inner prefix and a stop whose listing of the rules fails each leave the same down
// set and count it whole, and a stop whose add of the inner refusal fails keeps that family and names the rule
func TestNestedOverlayGetsEachPrefixsOwnPair(t *testing.T) {
	busy := errors.New("netlink says no")
	tbl := Table{Reconcile: schema.Duration(time.Minute)}.Normalized()
	harness := func(t *testing.T, overlay []schema.Prefix) (*Reconciler, *recordingKernel) {
		k := newRecording(t)
		return newReconciler(tbl, Runtime{Interface: "ranet0", Overlay: overlay}, nil, downTable(), k), k
	}
	want := downRules(nestedOverlay)
	check := func(t *testing.T, k *recordingKernel, held int) {
		t.Helper()
		if !k.holds(want) {
			t.Errorf("the kernel holds %v, want the pair of each prefix of %v", k.rules, nestedOverlay)
		}
		if held != len(nestedOverlay) {
			t.Errorf("the record counts %d prefixes held, want %d", held, len(nestedOverlay))
		}
	}
	t.Run("a clean stop", func(t *testing.T) {
		r, k := harness(t, nestedOverlay)
		cancel, wait := runDown(t, r, k)
		cancel(nil)
		wait()
		check(t, k, r.routePass.Held)
	})
	t.Run("a stopped pass", func(t *testing.T) {
		r, k := harness(t, nestedOverlay)
		runDown(t, r, k)
		r.SetEnabled(false)
		waitFor(t, func() bool { return len(k.snapshot()) == 0 && r.Stats().Held > 0 })
		check(t, k, r.Stats().Held)
	})
	t.Run("a reload while down that adds the inner prefix", func(t *testing.T) {
		outer := prefixes(prefix("192.0.2.0/24"), prefix("3fff::/21"))
		r, k := harness(t, outer)
		runDown(t, r, k)
		r.SetEnabled(false)
		waitFor(t, func() bool { return k.holds(downRules(outer)) && len(k.snapshot()) == 0 && r.Stats().Held == 2 })
		at := r.Stats().At
		if err := r.SetTable(r.Table(), nestedOverlay, nil); err != nil {
			t.Fatal(err)
		}
		check(t, k, passAfter(t, r, at).Held)
	})
	t.Run("a stop whose listing of the rules fails", func(t *testing.T) {
		r, k := harness(t, nestedOverlay)
		if err := r.reconcile(); err != nil {
			t.Fatalf("the running pass: %v", err)
		}
		k.failing(nil, busy, nil)
		if err := r.withdraw(errStopped); err == nil {
			t.Fatal("the stop that could not list the rules reported no error")
		}
		k.failing(nil, nil, nil)
		// the stopped pass after it, as a wake of the stopped reconciler runs it
		if err := r.withdraw(errStopped); err != nil {
			t.Fatalf("the stopped pass: %v", err)
		}
		check(t, k, r.routePass.Held)
	})
	t.Run("a stop whose add of the inner refusal fails", func(t *testing.T) {
		r, k := harness(t, nestedOverlay)
		if err := r.reconcile(); err != nil {
			t.Fatalf("the running pass: %v", err)
		}
		inner, _ := pairOf(nestedOverlay[1])
		k.failAddRule[inner] = busy
		err := r.withdraw(errStopped)
		if err == nil || !strings.Contains(err.Error(), leftText(FamilyIPv4)) || !strings.Contains(err.Error(), inner.String()) {
			t.Errorf("the stop returned %v, want it to name %s and say the %s routes and rules are left", err, inner, FamilyIPv4)
		}
		delete(k.failAddRule, inner)
		if err := r.withdraw(errStopped); err != nil {
			t.Fatalf("the stopped pass: %v", err)
		}
		check(t, k, r.routePass.Held)
	})
}

// A pass or a stopped pass that cannot list the rules says the count is not known for it, rather than counting the pairs
// its adds alone name: a running pass, a disable after a down and a reload while down, each with the down set standing, and a
// stop whose listing after a failed add fails
func TestPassThatCannotListTheRulesSaysTheCountIsNotKnown(t *testing.T) {
	busy := errors.New("netlink says no")
	t.Run("a running pass", func(t *testing.T) {
		r, k := downHarness(t)
		for _, rule := range downRules(downOverlay) {
			k.rules[rule] = true
		}
		k.failAddRule[downOverlayRule] = busy
		if err := r.reconcile(); err == nil || r.routePass.Held != 2 || r.routePass.HeldUnknown {
			t.Fatalf("setup: the pass reported %v and counted %d held, unknown %v", err, r.routePass.Held, r.routePass.HeldUnknown)
		}
		k.failRules = busy
		if err := r.reconcile(); err == nil {
			t.Fatal("the pass that could not list the rules reported no error")
		}
		if r.routePass.Held != 0 || !r.routePass.HeldUnknown {
			t.Errorf("the pass that could not list the rules counted %d held, unknown %v, want the count not known", r.routePass.Held, r.routePass.HeldUnknown)
		}
		k.failRules = nil
		delete(k.failAddRule, downOverlayRule)
		if err := r.reconcile(); err != nil || r.routePass.HeldUnknown {
			t.Errorf("the pass after it reported %v, the count unknown %v", err, r.routePass.HeldUnknown)
		}
	})
	t.Run("a stop whose listing after a failed add fails", func(t *testing.T) {
		_, k := downHarness(t)
		r := newReconciler(Table{Reconcile: schema.Duration(time.Minute)}.Normalized(), Runtime{Interface: "ranet0", Overlay: downOverlay}, nil, downTable(), &faultBlind{k})
		if err := r.reconcile(); err != nil {
			t.Fatalf("the running pass: %v", err)
		}
		refusal, _ := pairOf(downOverlay[0])
		k.failAddRule[refusal] = busy
		if err := r.withdraw(errStopped); err == nil {
			t.Fatal("the stop reported no error")
		}
		if r.routePass.Held != 0 || !r.routePass.HeldUnknown {
			t.Errorf("the stop that could not list the rules after its failed add counted %d held, unknown %v, want the count not known", r.routePass.Held, r.routePass.HeldUnknown)
		}
	})
	for _, c := range []struct {
		what string
		ask  func(*Reconciler) error
	}{
		{"a disable after a down", func(r *Reconciler) error { r.DropHold(); r.SetEnabled(false); return nil }},
		{"a reload while down", func(r *Reconciler) error {
			return r.SetTable(r.Table(), prefixes(prefix("198.51.100.0/24"), prefix("3fff:100::/24")), nil)
		}},
	} {
		t.Run(c.what, func(t *testing.T) {
			r, k, _, _ := stoppedDown(t)
			k.failing(nil, busy, nil)
			t.Cleanup(func() { k.failing(nil, nil, nil) })
			at := r.Stats().At
			if err := c.ask(r); err != nil {
				t.Fatal(err)
			}
			if got := passAfter(t, r, at); got.Held != 0 || !got.HeldUnknown {
				t.Errorf("the stopped pass that could not list the rules counted %d held, unknown %v, want the count not known", got.Held, got.HeldUnknown)
			}
		})
	}
}

// A second copy of a refusal counts its prefix once
func TestHeldCountsAPrefixOnceWhateverItsCopies(t *testing.T) {
	down := downRules(downOverlay)
	if got := heldPairs([]Rule{down[0], down[0], down[1], down[2], down[3]}); got != 2 {
		t.Errorf("two pairs with a second copy of one refusal count %d prefixes, want 2", got)
	}
}

// A stop deletes the down set a stop left for a prefix the overlay no longer holds, which no pass listed since, with its other
// rules, so it leaves the down set of its overlay alone
func TestStopDeletesTheDownSetOfAPrefixTheOverlayNoLongerHolds(t *testing.T) {
	r, k := downHarness(t)
	cancel, wait := runDown(t, r, k)
	k.mu.Lock()
	for _, rule := range downRules(prefixes(prefix("198.51.100.0/24"), prefix("192.0.2.0/24"))) {
		k.rules[rule] = true
	}
	k.mu.Unlock()
	cancel(nil)
	wait()
	if !k.holds(downRules(downOverlay)) {
		t.Errorf("the stop left %v, want the down set of %v alone", k.rules, downOverlay)
	}
}

// Only the hold this pass wants at an overlay prefix for every source, which the kernel holds, holds the prefix. The throw of a
// carve-out of the whole prefix, whose prefix the down set leaves out, a throw the pass is deleting, a hold it has not put in, a
// route for some sources alone and the mesh's own route hold nothing, so the down set stays.
func TestOnlyARouteThePassWantsAndRefusesHoldsAnOverlayPrefix(t *testing.T) {
	r, _ := downHarness(t)
	down := downRules(downOverlay)
	each := func(route func(p netip.Prefix) Route) []Route {
		var out []Route
		for _, p := range downOverlay {
			out = append(out, route(p.Prefix))
		}
		return out
	}
	hold := func(p netip.Prefix) Route { return Route{Destination: p, Metric: holdMetric, Unreachable: true} }
	throw := func(p netip.Prefix) Route { return Route{Destination: p, Metric: holdMetric, Throw: true} }
	mesh := func(p netip.Prefix) Route { return Route{Destination: p} }
	sourced := func(p netip.Prefix) Route {
		return Route{Destination: p, Source: prefix("3fff:100::/24"), Unreachable: true}
	}
	for _, c := range []struct {
		what              string
		installed, wanted []Route
		holds             bool
	}{
		{"the hold, wanted and installed", each(hold), each(hold), true},
		{"the throw of a carve-out of the whole prefix, wanted and installed", each(throw), each(throw), false},
		{"a throw the pass no longer wants, whose delete failed", each(throw), each(hold), false},
		{"a hold the pass no longer wants, whose delete failed", each(hold), nil, false},
		{"the hold, wanted and not installed", nil, each(hold), false},
		{"the mesh's own route alone", each(mesh), each(mesh), false},
		{"a refusal for some sources alone", each(sourced), each(sourced), false},
	} {
		r.installed = map[Route]bool{}
		for _, route := range c.installed {
			r.installed[route] = true
		}
		if got := r.holdsOverlay(down, c.wanted); got != c.holds {
			t.Errorf("with %s the overlay is held %v, want %v", c.what, got, c.holds)
		}
	}
}

// holdsAll reports whether the fake holds every rule of rules, beside any others
func (k *recordingKernel) holdsAll(rules []Rule) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return !slices.ContainsFunc(rules, func(rule Rule) bool { return !k.rules[rule] })
}

// failing sets the fault of the fake's route listing, its rule listing and its delete of rule, nil clearing each
func (k *recordingKernel) failing(routes, rules error, del map[Rule]error) {
	k.mu.Lock()
	k.failList, k.failRules = routes, rules
	k.mu.Unlock()
	k.noted.Lock()
	k.failDel = del
	k.noted.Unlock()
}

// stoppedDown runs a reconciler over downOverlay and stops it for a down, returning once the stop's down set and record stand
func stoppedDown(t *testing.T) (*Reconciler, *recordingKernel, context.CancelCauseFunc, func()) {
	t.Helper()
	r, k := downHarness(t)
	cancel, wait := runDown(t, r, k)
	r.SetEnabled(false)
	waitFor(t, func() bool { return k.holds(downRules(downOverlay)) && len(k.snapshot()) == 0 && r.Stats().Held == 2 })
	return r, k, cancel, wait
}

// passAfter waits for a pass recorded after at, and returns its record
func passAfter(t *testing.T, r *Reconciler, at time.Time) Stats {
	t.Helper()
	waitFor(t, func() bool { return r.Stats().At.After(at) })
	return r.Stats()
}

// An up whose listing of the routes fails releases nothing, whatever an earlier pass's or withdrawal's record named, so
// the down set stands until a pass that lists the routes finds them at each overlay prefix. After a down the record is
// the withdrawal's, and after a down whose own route listing failed it is the last pass's before the down.
func TestUpWhoseRouteListingFailsKeepsTheDownSet(t *testing.T) {
	busy := errors.New("netlink is busy")
	for _, c := range []struct {
		what string
		down func(*testing.T) (*Reconciler, *recordingKernel)
	}{
		{"after a down", func(t *testing.T) (*Reconciler, *recordingKernel) {
			r, k, _, _ := stoppedDown(t)
			k.failing(busy, nil, nil)
			return r, k
		}},
		{"after a down whose route listing failed", func(t *testing.T) (*Reconciler, *recordingKernel) {
			r, k := downHarness(t)
			runDown(t, r, k)
			k.failing(busy, nil, nil)
			at := r.Stats().At
			r.SetEnabled(false)
			if got := passAfter(t, r, at); !strings.Contains(got.Err, "list routes") || !k.holdsAll(downRules(downOverlay)) {
				t.Fatalf("setup: the down recorded %q", got.Err)
			}
			return r, k
		}},
	} {
		t.Run(c.what, func(t *testing.T) {
			r, k := c.down(t)
			down := downRules(downOverlay)
			at := r.Stats().At
			r.SetEnabled(true)
			// a pass that derived the rules is the up's, where a stopped pass derives none
			waitFor(t, func() bool { return r.Stats().At.After(at) && r.derived.Load() != nil })
			if got := r.Stats(); !strings.Contains(got.Err, "list routes") {
				t.Fatalf("the up whose route listing failed recorded %q", got.Err)
			}
			if !k.holdsAll(down) {
				t.Fatalf("the up whose route listing failed released the down set with %d routes in the table", len(k.snapshot()))
			}
			if got := r.Stats().Held; got != 2 {
				t.Errorf("the up whose route listing failed counted %d prefixes held, want 2", got)
			}
			k.failing(nil, nil, nil)
			waitFor(t, func() bool { return !k.holdsAny(down) && len(k.snapshot()) > 0 && r.Stats().Held == 0 })
		})
	}
}

// An up and a down that land together on a reconciler stopped by the operator's disable leave the down set, since the
// stopped pass they wake writes what the stop asks now rather than what the stop before it was done for.
func TestUpAndDownBeforeTheLoopRunsLeaveTheDownSet(t *testing.T) {
	r, k := downHarness(t)
	runDown(t, r, k)
	at := r.Stats().At
	r.DropHold()
	r.SetEnabled(false)
	waitFor(t, func() bool { return k.holds(nil) && len(k.snapshot()) == 0 && r.Stats().At.After(at) })
	r.SetEnabled(true)
	r.SetEnabled(false)
	waitFor(t, func() bool { return k.holds(downRules(downOverlay)) && r.Stats().Held == 2 })
}

// A stop of the daemon after a reload the loop has not taken yet leaves the down set of the reload's overlay.
func TestStopOfTheDaemonAfterAReloadLeavesTheReloadsDownSet(t *testing.T) {
	moved := prefixes(prefix("198.51.100.0/24"), prefix("3fff:100::/24"))
	r, k := downHarness(t)
	if err := r.SetTable(r.Table(), moved, nil); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if !k.holds(downRules(moved)) {
		k.mu.Lock()
		defer k.mu.Unlock()
		t.Errorf("the stop after a reload left %v, want the down set of %v", slices.Collect(maps.Keys(k.rules)), moved)
	}
}

// A withdrawal that fails on a reconciler already stopped stays owed: the retry takes it up once the kernel answers,
// with no verb asking again.
func TestStoppedReconcilersFailedWithdrawalIsRetried(t *testing.T) {
	fault := errors.New("netlink is busy")
	for _, c := range []struct {
		what  string
		rules error
		del   func([]Rule) map[Rule]error
	}{
		{"the listing of the rules", fault, func([]Rule) map[Rule]error { return nil }},
		{"the delete of a rule of the down set", nil, func(down []Rule) map[Rule]error { return map[Rule]error{down[0]: fault} }},
	} {
		t.Run(c.what, func(t *testing.T) {
			r, k, _, _ := stoppedDown(t)
			down := downRules(downOverlay)
			k.failing(nil, c.rules, c.del(down))
			at := r.Stats().At
			r.DropHold()
			r.SetEnabled(false)
			if got := passAfter(t, r, at); got.Err == "" {
				t.Fatal("the disable whose withdrawal met the fault recorded no error")
			}
			k.failing(nil, nil, nil)
			waitFor(t, func() bool { return k.holds(nil) && r.Stats().Err == "" && r.Stats().Held == 0 })
		})
	}
}

// A down set another writer deleted while the node is down is put back by the next sweep, which logs the withdrawal it wrote.
func TestSweepPutsBackTheDownSetAnotherWriterDeleted(t *testing.T) {
	said := logged(t)
	r, k, cancel, wait := stoppedDown(t)
	swept := r.Table()
	swept.Reconcile = schema.Duration(schema.MinPassInterval)
	if err := r.SetTable(swept, downOverlay, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return r.Table().Reconcile.Duration() == schema.MinPassInterval })
	k.mu.Lock()
	for _, rule := range downRules(downOverlay) {
		delete(k.rules, rule)
	}
	k.mu.Unlock()
	waitFor(t, func() bool { return k.holds(downRules(downOverlay)) && r.Stats().Held == 2 })
	cancel(nil)
	wait()
	if got := strings.Count(said.String(), "kernel reconciler withdrawn"); got != 3 {
		t.Errorf("the stop, the sweep that put the down set back and the stop of the daemon logged %d withdrawals, want 3", got)
	}
}

// The held count is the overlay prefixes whose pair of down rules stands after the pass's writes, at a stop whose delete
// failed and keeps a family, and at a start whose release waits on a failed add and finds half a pair.
func TestHeldCountsThePairsThatStand(t *testing.T) {
	t.Run("a stop whose delete of 5110 failed", func(t *testing.T) {
		r, k := downHarness(t)
		runDown(t, r, k)
		held, _ := k.Rules()
		at := slices.IndexFunc(withdrawOrder(held), func(rule Rule) bool {
			return rule.Family == FamilyIPv4 && rule.Priority == priorityOverlay
		})
		k.failing(nil, nil, map[Rule]error{withdrawOrder(held)[at]: errors.New("netlink is busy")})
		t.Cleanup(func() { k.failing(nil, nil, nil) })
		r.SetEnabled(false)
		waitFor(t, func() bool { return r.Stats().Err != "" })
		if !k.holdsAll(downRules(downOverlay)) {
			t.Fatal("setup: the stop left the down set short")
		}
		if got := r.Stats().Held; got != 2 {
			t.Errorf("the stop that kept IPv4 counted %d prefixes held, want 2", got)
		}
	})
	t.Run("a reload while down whose delete of the old down set fails", func(t *testing.T) {
		moved := prefixes(prefix("198.51.100.0/24"), prefix("3fff:100::/24"))
		r, k, _, _ := stoppedDown(t)
		k.failing(nil, nil, map[Rule]error{downRules(downOverlay)[1]: errors.New("netlink is busy")})
		t.Cleanup(func() { k.failing(nil, nil, nil) })
		at := r.Stats().At
		if err := r.SetTable(r.Table(), moved, nil); err != nil {
			t.Fatal(err)
		}
		// the old IPv4 pair stands beside the new overlay's two
		if got := passAfter(t, r, at); got.Held != 3 || !k.holdsAll(append(downRules(moved), downRules(downOverlay)[:2]...)) {
			t.Errorf("the reload whose delete of the old IPv4 lookup failed counted %d prefixes held, want 3", got.Held)
		}
	})
	t.Run("a start finding half a pair, which it makes whole", func(t *testing.T) {
		r, k, _, _ := stoppedDown(t)
		down := downRules(downOverlay)
		k.mu.Lock()
		delete(k.rules, down[3])
		k.failAddRule[downOverlayRule] = errors.New("netlink is busy")
		k.mu.Unlock()
		at := r.Stats().At
		r.SetEnabled(true)
		if got := passAfter(t, r, at); got.Held != 2 || !k.holdsAll(down) {
			t.Errorf("a start that found the IPv4 pair and half the IPv6 one counted %d prefixes held, want 2, the IPv6 pair made whole", got.Held)
		}
		k.mu.Lock()
		delete(k.failAddRule, downOverlayRule)
		k.mu.Unlock()
	})
	t.Run("a start finding half a pair whose add of the other half fails", func(t *testing.T) {
		r, k, _, _ := stoppedDown(t)
		down := downRules(downOverlay)
		k.mu.Lock()
		delete(k.rules, down[3])
		k.failAddRule[down[3]] = errors.New("netlink is busy")
		k.mu.Unlock()
		at := r.Stats().At
		r.SetEnabled(true)
		if got := passAfter(t, r, at); got.Held != 1 || !k.holdsAll(down[:3]) {
			t.Errorf("a start that found the IPv4 pair and the IPv6 refusal alone counted %d prefixes held, want 1", got.Held)
		}
		k.mu.Lock()
		delete(k.failAddRule, down[3])
		k.mu.Unlock()
	})
}

// A stopped pass that finds the kernel as the stop asks writes nothing and logs no withdrawal, so a node down for days
// takes no write and no line at each sweep. The stop of the daemon after it logs its own.
func TestStoppedPassThatFindsTheKernelAsAskedWritesNothing(t *testing.T) {
	said := logged(t)
	r, k, cancel, wait := stoppedDown(t)
	before := len(k.taken())
	at := r.Stats().At
	r.SetEnabled(false)
	if got := passAfter(t, r, at); got.Err != "" || got.Held != 2 {
		t.Fatalf("the stopped pass recorded %q with %d prefixes held", got.Err, got.Held)
	}
	cancel(nil)
	wait()
	if got := k.taken()[before:]; len(got) != 0 {
		t.Errorf("the stopped pass and the stop of the daemon wrote %+v to a kernel already as the stop asks", got)
	}
	if got := strings.Count(said.String(), "kernel reconciler withdrawn"); got != 2 {
		t.Errorf("the stop, a stopped pass and the stop of the daemon logged %d withdrawals, want 2", got)
	}
	if got := strings.Count(said.String(), "kernel reconciler stopped, its routes withdrawn"); got != 1 {
		t.Errorf("the stop and a stopped pass logged the stop %d times, want once", got)
	}
}

// mainLookups is the rules the fake holds that look main up ahead of the down set
func (k *recordingKernel) mainLookups() []Rule {
	k.mu.Lock()
	defer k.mu.Unlock()
	var out []Rule
	for rule := range k.rules {
		if mainLookup(rule) {
			out = append(out, rule)
		}
	}
	return out
}

// main5410 is 5410 of family, which looks main up for every route of it longer than /0
func main5410(family Family) Rule {
	return Rule{Family: family, Priority: priorityMain, Table: schema.TableMain, suppress: SuppressUpTo(0)}
}

// A start that cannot release the down set, its route listing or its add of 5110 or its hold failing, adds no rule that looks
// main up and deletes one it finds beside the down set, so a lookup the down set refuses meets no route of main ahead of it.
// The pass that releases adds them and deletes the down set.
func TestStartThatCannotReleaseLeavesNoRuleThatLooksMainUp(t *testing.T) {
	busy := errors.New("netlink says no")
	for _, c := range []struct {
		what       string
		fail, heal func(*recordingKernel)
	}{
		{"its route listing", func(k *recordingKernel) { k.failList = busy }, func(k *recordingKernel) { k.failList = nil }},
		{"its add of 5110", func(k *recordingKernel) { k.failAddRule[downOverlayRule] = busy }, func(k *recordingKernel) { delete(k.failAddRule, downOverlayRule) }},
		{"its hold", func(k *recordingKernel) { k.failAdd[downOverlayHold] = busy }, func(k *recordingKernel) { delete(k.failAdd, downOverlayHold) }},
	} {
		t.Run(c.what, func(t *testing.T) {
			r, k := downHarness(t)
			down := downRules(downOverlay)
			for _, rule := range down {
				k.rules[rule] = true
			}
			// a rule that looks main up an earlier start left beside the down set
			k.rules[main5410(FamilyIPv6)] = true
			k.mu.Lock()
			c.fail(k)
			k.mu.Unlock()
			if err := r.reconcile(); err == nil {
				t.Fatal("the pass reported no error")
			}
			if got := k.mainLookups(); len(got) != 0 || !k.holdsAll(down) {
				t.Errorf("the start that cannot release left %v beside the down set, whole %v", got, k.holdsAll(down))
			}
			k.mu.Lock()
			c.heal(k)
			k.mu.Unlock()
			if err := r.reconcile(); err != nil {
				t.Fatal(err)
			}
			if !k.holdsDerived(r) || k.holdsAny(down) {
				t.Errorf("after the pass that releases the kernel holds %v, want the derived rules alone", k.rules)
			}
		})
	}
}

// A release whose add of a rule that looks main up fails takes back those it put, and keeps the down set for the next pass
func TestReleaseWhoseMainLookupAddFailsKeepsTheDownSetAlone(t *testing.T) {
	r, k := downHarness(t)
	down := downRules(downOverlay)
	for _, rule := range down {
		k.rules[rule] = true
	}
	k.failAddRule[main5410(FamilyIPv6)] = errors.New("netlink says no")
	if err := r.reconcile(); err == nil {
		t.Fatal("the pass reported no error")
	}
	if got := k.mainLookups(); len(got) != 0 || !k.holdsAll(down) || r.Stats().Held != 2 {
		t.Errorf("the release whose IPv6 5410 failed left %v beside the down set, whole %v, counted %d", got, k.holdsAll(down), r.Stats().Held)
	}
	delete(k.failAddRule, main5410(FamilyIPv6))
	if err := r.reconcile(); err != nil {
		t.Fatal(err)
	}
	if !k.holdsDerived(r) || k.holdsAny(down) {
		t.Errorf("after the pass that releases the kernel holds %v, want the derived rules alone", k.rules)
	}
}

// stealing is the fake taking each rule of steal right after the next listing of the rules, as another writer's delete
// between that listing and the writes after it
type stealing struct {
	*recordingKernel
	steal []Rule
}

func (p *stealing) Rules() ([]Rule, error) {
	held, err := p.recordingKernel.Rules()
	p.mu.Lock()
	for _, rule := range p.steal {
		delete(p.rules, rule)
	}
	p.mu.Unlock()
	p.steal = nil
	return held, err
}

// The last withdrawal, which no pass follows, lists the rules once more after its writes and puts back a rule of the down
// set another writer took between its listing and its writes
func TestLastWithdrawalPutsBackARuleTakenAfterItsListing(t *testing.T) {
	r0, k := downHarness(t)
	down := downRules(downOverlay)
	for _, rule := range down {
		k.rules[rule] = true
	}
	p := &stealing{recordingKernel: k, steal: down[:1]}
	t.Cleanup(func() {
		if p.steal != nil {
			t.Error("the fake's theft was never met by a listing")
		}
	})
	r := newReconciler(r0.table, r0.rt, nil, r0.src, p)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if !k.holds(down) {
		k.mu.Lock()
		defer k.mu.Unlock()
		t.Errorf("the last withdrawal left %v, want the down set whole", slices.Collect(maps.Keys(k.rules)))
	}
}

// A SetTable once Run has begun its last withdrawal is refused, since no withdrawal reads it, and the kernel keeps the down
// set of the overlay the withdrawal took
func TestSetTableAfterTheLastWithdrawalIsRefused(t *testing.T) {
	moved := prefixes(prefix("198.51.100.0/24"), prefix("3fff:100::/24"))
	r, k := downHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if err := r.SetTable(r.Table(), moved, nil); !errors.Is(err, ErrStopping) {
		t.Errorf("a SetTable after Run returned answered %v, want %v", err, ErrStopping)
	}
	if !k.holds(downRules(downOverlay)) {
		t.Errorf("after the refused SetTable the kernel holds %v, want the down set of %v", k.rules, downOverlay)
	}
}

// mainLookup reports whether rule is one of the mesh's ahead of the down set that main answers from: 5405, 5410, 5435 and 5445
func mainLookup(rule Rule) bool {
	return rule.action == actionLookup && rule.Table == schema.TableMain && rule.Priority < priorityDownMain
}

// A release whose delete of the IPv4 refusal fails has passed its commit
// point, so it keeps the running rules and the IPv4 pair whole and owes the pair's delete, and the pass after it deletes the pair
// and nothing else
func TestReleaseWhoseRefusalDeleteFailsOwesThePair(t *testing.T) {
	r, k := downHarness(t)
	down := downRules(downOverlay)
	for _, rule := range down {
		k.rules[rule] = true
	}
	k.failing(nil, nil, map[Rule]error{down[0]: errors.New("netlink says no")})
	if err := r.reconcile(); err == nil {
		t.Fatal("the pass whose delete of the IPv4 refusal failed reported no error")
	}
	mains := len(k.mainLookups())
	if mains == 0 || !k.holdsAll(down[:2]) || k.holdsAny(down[2:]) {
		t.Errorf("after the pass the kernel holds %d lookups of main, the IPv4 pair whole %v, an IPv6 down rule %v, want the running rules, the IPv4 pair and no IPv6 down rule", mains, k.holdsAll(down[:2]), k.holdsAny(down[2:]))
	}
	want := []string{"delete the pair of 192.0.2.0/25 (32765, 32764)"}
	if stats := r.Stats(); stats.Held != 0 || stats.HeldUnknown || !slices.Equal(stats.Owed, want) {
		t.Errorf("the record holds %d prefixes (not known %v) and owes %q, want 0 and %q", stats.Held, stats.HeldUnknown, stats.Owed, want)
	}
	k.failing(nil, nil, nil)
	for pass := range 2 {
		before := len(k.taken())
		if err := r.reconcile(); err != nil {
			t.Fatal(err)
		}
		if !k.holdsDerived(r) || k.holdsAny(down) || len(k.mainLookups()) != mains || len(r.Stats().Owed) != 0 {
			t.Errorf("after pass %d the kernel holds %v and the record owes %q, want the derived rules alone", pass+2, k.rules, r.Stats().Owed)
		}
		for _, w := range k.taken()[before:] {
			if w.op != "delete rule" || !isDownRule(w.rule) {
				t.Errorf("pass %d wrote %s %s, want the deletes of the IPv4 pair alone", pass+2, w.op, w.rule)
			}
		}
	}
}

// A start finding every derived rule and the down set, as a process stopped after
// its last adds leaves them, runs, and deletes the down set alone, each refusal ahead of its lookup
func TestStartFindingTheRunningRulesAndTheDownSetDeletesTheDownSetAlone(t *testing.T) {
	r, k := downHarness(t)
	if err := r.reconcile(); err != nil {
		t.Fatal(err)
	}
	down := downRules(downOverlay)
	for _, rule := range down {
		k.rules[rule] = true
	}
	r = newReconciler(r.table, r.rt, nil, downTable(), k)
	before := len(k.taken())
	if err := r.reconcile(); err != nil {
		t.Fatal(err)
	}
	var deleted []Rule
	for _, w := range k.taken()[before:] {
		if w.op != "delete rule" {
			t.Errorf("the start wrote %s %s %s, want the down set's deletes alone", w.op, w.rule, w.route)
		}
		deleted = append(deleted, w.rule)
	}
	if !slices.Equal(deleted, down) || !k.holdsDerived(r) {
		t.Errorf("the start deleted %v, want %v in that order, and the derived rules stay", deleted, down)
	}
}

// A start over the IPv4 pair alone whose route listing fails
// adds the IPv6 pair, its refusal first, and no lookup of main
func TestStartOverAnUncoveredPrefixAddsItsPairRefusalFirst(t *testing.T) {
	r, k := downHarness(t)
	down := downRules(downOverlay)
	k.rules[down[0]], k.rules[down[1]] = true, true
	k.failing(errors.New("the route dump fails"), nil, nil)
	if err := r.reconcile(); err == nil {
		t.Fatal("the pass reported no error")
	}
	var added []Rule
	for _, w := range k.taken() {
		if w.op == "add rule" && isDownRule(w.rule) {
			added = append(added, w.rule)
		}
	}
	if !slices.Equal(added, down[2:]) || !k.holdsAll(down) || len(k.mainLookups()) != 0 {
		t.Errorf("the start added %v of the down set, holds it whole %v and %d lookups of main, want %v in that order and none", added, k.holdsAll(down), len(k.mainLookups()), down[2:])
	}
}

// The release adds the lookups of main, rereads, deletes the down set, each refusal ahead of its lookup, and only then adds the
// mesh's own lookups 5420 and 5430
func TestReleaseAddsTheMeshsLookupsOnlyAfterTheDownSet(t *testing.T) {
	r, k := downHarness(t)
	down := downRules(downOverlay)
	for _, rule := range down {
		k.rules[rule] = true
	}
	if err := r.reconcile(); err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, w := range k.taken() {
		switch {
		case w.op == "add rule" && mainLookup(w.rule):
			order = append(order, "main")
		case w.op == "delete rule" && isDownRule(w.rule):
			order = append(order, fmt.Sprint(w.rule.Priority))
		case w.op == "add rule" && (w.rule.Priority == priorityMesh || w.rule.Priority == priorityOwn):
			order = append(order, "mesh")
		}
	}
	want := []string{"main", "main", "32765", "32764", "32765", "32764", "mesh", "mesh"}
	if !slices.Equal(order, want) {
		t.Errorf("the release wrote %v, want %v", order, want)
	}
}

// A release whose add fails before its commit point takes back what it put in the reverse order, and a take-back that fails too is
// owed in the record and deleted first by the next pass
func TestReleaseTakesBackInTheReverseOrderAndOwesWhatStays(t *testing.T) {
	r, k := downHarness(t)
	down := downRules(downOverlay)
	for _, rule := range down {
		k.rules[rule] = true
	}
	busy := errors.New("netlink says no")
	k.failAddRule[main5410(FamilyIPv6)] = busy
	k.failing(nil, nil, map[Rule]error{main5410(FamilyIPv4): busy})
	before := len(k.taken())
	if err := r.reconcile(); err == nil {
		t.Fatal("the pass reported no error")
	}
	var put, back []Rule
	for _, w := range k.taken()[before:] {
		switch {
		case w.op == "add rule" && !slices.Contains([]uint32{priorityOverlayEnd, priorityUnderlayPastOverlay, priorityOverlay}, w.rule.Priority):
			put = append(put, w.rule)
		case w.op == "delete rule":
			back = append(back, w.rule)
		}
	}
	want := slices.DeleteFunc(slices.Clone(put), func(rule Rule) bool { return rule == main5410(FamilyIPv4) })
	slices.Reverse(want)
	if len(put) == 0 || !slices.Equal(back, want) {
		t.Errorf("the release put %v and took back %v, want each but the IPv4 5410 in the reverse order", put, back)
	}
	owed := []string{"delete " + main5410(FamilyIPv4).String()}
	if stats := r.Stats(); stats.Held != 2 || !slices.Equal(stats.Owed, owed) || !k.holdsAll(down) {
		t.Errorf("the record holds %d prefixes and owes %q, the down set whole %v, want 2, %q and whole", stats.Held, stats.Owed, k.holdsAll(down), owed)
	}
	delete(k.failAddRule, main5410(FamilyIPv6))
	k.failing(nil, nil, nil)
	before = len(k.taken())
	if err := r.reconcile(); err != nil {
		t.Fatal(err)
	}
	if next := k.taken()[before:]; len(next) == 0 || next[0].op != "delete rule" || next[0].rule != main5410(FamilyIPv4) {
		t.Errorf("the next pass wrote %v first, want the delete of the IPv4 5410", next[:min(len(next), 1)])
	}
}

// A reload while staged takes out the pair of a prefix it removed lookup first, and where the removed prefix overlaps one of the
// overlay, ahead of the new prefix's pair, which goes refusal first
func TestReloadWhileStagedTakesOutTheRemovedPairLookupFirst(t *testing.T) {
	r, k := downHarness(t)
	down := downRules(downOverlay)
	for _, rule := range down {
		k.rules[rule] = true
	}
	inside := prefixes(prefix("192.0.2.0/26"), downOverlay[1].Prefix)
	r.rt.Overlay = inside
	k.failing(errors.New("the route dump fails"), nil, nil)
	_ = r.reconcile()
	var got []Rule
	for _, w := range k.taken() {
		if isDownRule(w.rule) {
			got = append(got, w.rule)
		}
	}
	added := downRules(inside)
	want := []Rule{down[1], added[0], added[1], down[0]}
	if !slices.Equal(got, want) || !k.holdsAll(added) || k.holdsAny(down[:2]) {
		t.Errorf("the reload wrote %v of the down sets, want %v in that order", got, want)
	}
}

// faultBlind is the fake failing every listing of the rules after a rule write fails, as a kernel that took the write in part and
// then stops answering
type faultBlind struct{ *recordingKernel }

func (p *faultBlind) AddRule(rule Rule) error {
	err := p.recordingKernel.AddRule(rule)
	if err != nil {
		p.mu.Lock()
		p.failRules = errors.New("the rule dump fails")
		p.mu.Unlock()
	}
	return err
}

// A pass whose reread after a failed write fails writes nothing more and says the count is not known, never a clean release
func TestPassBlindAfterAFailedWriteWritesNothingMoreAndSaysNotKnown(t *testing.T) {
	_, k := downHarness(t)
	down := downRules(downOverlay)
	for _, rule := range down {
		k.rules[rule] = true
	}
	k.failAddRule[downOverlayRule] = errors.New("netlink says no")
	blind := &faultBlind{k}
	r := newReconciler(Table{Reconcile: schema.Duration(time.Minute)}.Normalized(), Runtime{Interface: "ranet0", Overlay: downOverlay}, nil, downTable(), blind)
	if err := r.reconcile(); err == nil {
		t.Fatal("the pass reported no error")
	}
	writes := k.taken()
	if last := writes[len(writes)-1]; last.op == "add rule" && last.rule.Priority > priorityOverlay {
		t.Errorf("the pass wrote %s %s after its reread failed", last.op, last.rule)
	}
	if stats := r.Stats(); !stats.HeldUnknown || stats.Held != 0 || len(stats.Owed) != 0 || !k.holdsAll(down) {
		t.Errorf("the record holds %d prefixes, not known %v, owes %q, the down set whole %v, want not known and whole", stats.Held, stats.HeldUnknown, stats.Owed, k.holdsAll(down))
	}
}

// losing is the fake answering the add of each rule of lose as landed without taking it, as a kernel that loses a write
type losing struct {
	*recordingKernel
	lose []Rule
	// lost counts the adds it answered as landed without taking
	lost int
}

func (p *losing) AddRule(rule Rule) error {
	if slices.Contains(p.lose, rule) {
		p.lost++
		return nil
	}
	return p.recordingKernel.AddRule(rule)
}

// A release whose reread lacks a rule an add answered as landed takes back what it put and keeps the down set, so the commit
// point is the reread and not the answers
func TestReleaseWhoseRereadLacksAnAddKeepsTheDownSet(t *testing.T) {
	_, k := downHarness(t)
	down := downRules(downOverlay)
	for _, rule := range down {
		k.rules[rule] = true
	}
	lost := &losing{recordingKernel: k, lose: []Rule{main5410(FamilyIPv6)}}
	t.Cleanup(func() {
		if lost.lost == 0 {
			t.Error("the fake lost no add")
		}
	})
	r := newReconciler(Table{Reconcile: schema.Duration(time.Minute)}.Normalized(), Runtime{Interface: "ranet0", Overlay: downOverlay}, nil, downTable(), lost)
	if err := r.reconcile(); err == nil {
		t.Fatal("the pass reported no error")
	}
	if !k.holdsAll(down) || len(k.mainLookups()) != 0 || r.Stats().Held != 2 {
		t.Errorf("after the release whose reread lacked the IPv6 5410 the down set is whole %v beside %d lookups of main, counted %d, want whole, none and 2", k.holdsAll(down), len(k.mainLookups()), r.Stats().Held)
	}
	lost.lose = nil
	if err := r.reconcile(); err != nil {
		t.Fatal(err)
	}
	if !k.holdsDerived(r) || k.holdsAny(down) {
		t.Errorf("after the pass that releases the kernel holds %v, want the derived rules alone", k.rules)
	}
}

// listingOnce is the fake failing the next fails listings of the routes
type listingOnce struct {
	*recordingKernel
	fails, failed int
}

func (p *listingOnce) Routes() ([]Route, error) {
	p.mu.Lock()
	fail := p.fails > 0
	if fail {
		p.fails--
		p.failed++
	}
	p.mu.Unlock()
	if fail {
		return nil, errors.New("the route dump fails")
	}
	return p.recordingKernel.Routes()
}

// A start whose pass lists no routes keeps the down set, though a later reread of the routes for the overlay's lookups answers
// and the pass before it listed them
func TestUpWhoseRouteListingFailsOnceKeepsTheDownSet(t *testing.T) {
	_, k := downHarness(t)
	down := downRules(downOverlay)
	for _, rule := range down {
		k.rules[rule] = true
	}
	once := &listingOnce{recordingKernel: k}
	t.Cleanup(func() {
		if once.failed == 0 || once.fails != 0 {
			t.Errorf("the fake failed %d route listings with %d armed left, want some and none", once.failed, once.fails)
		}
	})
	r := newReconciler(Table{Reconcile: schema.Duration(time.Minute)}.Normalized(), Runtime{Interface: "ranet0", Overlay: downOverlay}, nil, downTable(), once)
	busy := errors.New("netlink says no")
	k.failAddRule[main5410(FamilyIPv4)] = busy
	if err := r.reconcile(); err == nil {
		t.Fatal("the pass whose 5410 failed reported no error")
	}
	delete(k.failAddRule, main5410(FamilyIPv4))
	once.fails = 1
	if err := r.reconcile(); err == nil {
		t.Fatal("the pass whose route listing failed reported no error")
	}
	if !k.holdsAll(down) || len(k.mainLookups()) != 0 {
		t.Errorf("after the pass whose route listing failed the down set is whole %v beside %d lookups of main, want whole and none", k.holdsAll(down), len(k.mainLookups()))
	}
}

// A rule a failed take-back left beside the down set stays owed in the record on every pass whose delete of it fails, and leaves
// the record with the pass that deletes it
func TestStrayStaysOwedUntilAPassDeletesIt(t *testing.T) {
	r, k := downHarness(t)
	for _, rule := range downRules(downOverlay) {
		k.rules[rule] = true
	}
	busy := errors.New("netlink says no")
	k.failAddRule[main5410(FamilyIPv6)] = busy
	k.failing(nil, nil, map[Rule]error{main5410(FamilyIPv4): busy})
	owed := []string{"delete " + main5410(FamilyIPv4).String()}
	for pass := range 3 {
		if err := r.reconcile(); err == nil {
			t.Fatalf("pass %d reported no error", pass)
		}
		if stats := r.Stats(); !slices.Equal(stats.Owed, owed) {
			t.Errorf("after pass %d the record owes %q, want %q", pass, stats.Owed, owed)
		}
	}
	// a pass that cannot list the rules keeps the debt it last knew
	k.failing(nil, errors.New("the rule dump fails"), map[Rule]error{main5410(FamilyIPv4): busy})
	if err := r.reconcile(); err == nil {
		t.Fatal("the pass whose rule listing failed reported no error")
	}
	if stats := r.Stats(); !stats.HeldUnknown || !slices.Equal(stats.Owed, owed) {
		t.Errorf("after the pass whose rule listing failed the record owes %q, not known %v, want %q and not known", stats.Owed, stats.HeldUnknown, owed)
	}
	delete(k.failAddRule, main5410(FamilyIPv6))
	k.failing(nil, nil, nil)
	if err := r.reconcile(); err != nil || len(r.Stats().Owed) != 0 {
		t.Errorf("the pass that deletes it reported %v and owes %q", err, r.Stats().Owed)
	}
}

// An idle pass lists the rules once, in mode off and in mode 2 under either fallback, so the entry's view serves the whole pass
func TestIdlePassListsTheRulesOnce(t *testing.T) {
	for name, mode := range map[string]*ExitMode{
		"mode off": nil,
		"uplink":   {Forward: []string{"docker0"}, Fallback: FallbackUplink},
		"none":     {Forward: []string{"docker0"}, Fallback: FallbackNone},
	} {
		r, k := fallbackHarness(t, mode)
		if err := r.reconcile(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		listed, added := k.ruleLists, k.ruleAdds
		if err := r.reconcile(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if k.ruleLists-listed != 1 || k.ruleAdds != added {
			t.Errorf("%s: an idle pass listed the rules %d times and added %d, want once and none", name, k.ruleLists-listed, k.ruleAdds-added)
		}
	}
}

// sticky is the fake answering every delete of a rule as done and keeping the rule, as a kernel matching the delete to another copy
type sticky struct{ *recordingKernel }

func (p *sticky) DelRule(rule Rule) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ruleDels++
	return nil
}

// A delete writes once for each copy the view holds when it is called, and takes the rule out of the view, so it ends whatever the
// kernel answers
func TestDeleteWritesOnceForEachCopyTheViewHolds(t *testing.T) {
	_, k := downHarness(t)
	rule := main5410(FamilyIPv4)
	k.rules[rule] = true
	p := &sticky{k}
	r := newReconciler(Table{Reconcile: schema.Duration(time.Minute)}.Normalized(), Runtime{Interface: "ranet0", Overlay: downOverlay}, nil, downTable(), p)
	v := &ruleView{r: r}
	v.list()
	v.rules = append(v.rules, rule)
	if !v.del(rule) || v.has(rule) || k.ruleDels != 2 || v.removed != 2 {
		t.Errorf("the delete of a rule the view holds twice wrote %d deletes, counted %d, the view holding it %v, want 2, 2 and not", k.ruleDels, v.removed, v.has(rule))
	}
	if !v.del(rule) || k.ruleDels != 2 {
		t.Errorf("a delete of a rule the view no longer holds wrote %d deletes in all, want 2", k.ruleDels)
	}
}

// relisting is the fake failing the listing of the rules that follows the add of after, once, and the next routeFails listings of
// the routes
type relisting struct {
	*recordingKernel
	after      Rule
	armed      bool
	routeFails int
	// failed counts the listings it failed, of the rules and of the routes
	rulesFailed, routesFailed int
}

func (p *relisting) AddRule(rule Rule) error {
	err := p.recordingKernel.AddRule(rule)
	if err == nil && rule == p.after {
		p.armed = true
	}
	return err
}

func (p *relisting) Rules() ([]Rule, error) {
	if p.armed {
		p.armed, p.after = false, Rule{}
		p.rulesFailed++
		return nil, errors.New("the rule dump fails")
	}
	return p.recordingKernel.Rules()
}

func (p *relisting) Routes() ([]Route, error) {
	if p.routeFails > 0 {
		p.routeFails--
		p.routesFailed++
		return nil, errors.New("the route dump fails")
	}
	return p.recordingKernel.Routes()
}

// A release rests on the pass's own listing of the routes, through holdsAt: after a staged pass whose release was taken back at its
// commit, every 5110 standing, a pass whose route listing fails keeps the down set and adds no rule that looks main up
func TestReleaseRestsOnThePassesOwnRouteListing(t *testing.T) {
	_, k := downHarness(t)
	down := downRules(downOverlay)
	for _, rule := range down {
		k.rules[rule] = true
	}
	p := &relisting{recordingKernel: k, after: main5410(FamilyIPv6)}
	t.Cleanup(func() {
		if p.rulesFailed != 1 || p.routesFailed != 1 || p.armed || p.routeFails != 0 {
			t.Errorf("the fake failed %d rule and %d route listings, armed still %v and %d, want 1, 1 and none", p.rulesFailed, p.routesFailed, p.armed, p.routeFails)
		}
	})
	r := newReconciler(Table{Reconcile: schema.Duration(time.Minute)}.Normalized(), Runtime{Interface: "ranet0", Overlay: downOverlay}, nil, downTable(), p)
	if err := r.reconcile(); err == nil {
		t.Fatal("the pass whose commit reread failed reported no error")
	}
	overlay := 0
	for rule := range k.rules {
		if rule.Priority == priorityOverlay {
			overlay++
		}
	}
	if overlay != 2 || !k.holdsAll(down) || len(k.mainLookups()) != 0 {
		t.Fatalf("setup: after the taken back release the fake holds %d 5110, the down set whole %v, %d lookups of main, want 2, whole and none", overlay, k.holdsAll(down), len(k.mainLookups()))
	}
	p.routeFails = 1
	if err := r.reconcile(); err == nil {
		t.Fatal("the pass whose route listing failed reported no error")
	}
	if !k.holdsAll(down) || len(k.mainLookups()) != 0 {
		t.Errorf("after the pass whose route listing failed the down set is whole %v beside %d lookups of main, want whole and none", k.holdsAll(down), len(k.mainLookups()))
	}
}

// Under fallback = "none" a start whose listing of the tun's addresses fails, a pass that judges no rule, still refuses the host's
// and the forwarded LAN's traffic: its entry adds 5490, 5400 and 5450 for lo and each link forward expands to, beside the down set
func TestNoneStartWhoseAddressListingFailsRefusesFromTheEntry(t *testing.T) {
	r, fake := fallbackHarness(t, &ExitMode{Forward: []string{"docker0"}, Fallback: FallbackNone})
	if err := r.reconcile(); err != nil {
		t.Fatal(err)
	}
	if err := r.withdraw(errStopped); err != nil {
		t.Fatal(err)
	}
	fake.failAddrs = errors.New("the address dump fails")
	if err := r.reconcile(); err == nil {
		t.Fatal("the pass whose address listing failed reported no error")
	}
	want := downRules(exitPassOverlay)
	for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
		want = append(want,
			Rule{Family: family, Priority: priorityMeshEnd, action: actionNop},
			Rule{Family: family, Priority: priorityUnderlayPastMesh, FWMark: schema.UnderlayMark, action: actionGoto, target: priorityMeshEnd},
			Rule{Family: family, Priority: priorityRefused, IIF: linuxLoopback, action: actionUnreachable},
			Rule{Family: family, Priority: priorityRefused, IIF: "docker0", action: actionUnreachable},
		)
	}
	if held := slices.Collect(maps.Keys(fake.rules)); !sameRules(held, want) {
		t.Errorf("after the pass whose address listing failed the fake holds %v, want %v", held, want)
	}
}

// The write that moves a hold of nested overlay prefixes names the innermost prefix that holds it, whose 5110 it deletes first
func TestHoldTouchedIsTheInnermostPrefix(t *testing.T) {
	k := newRecording(t)
	nested := prefixes(prefix("10.0.0.0/8"), prefix("10.20.0.0/16"))
	r := newReconciler(Table{Reconcile: schema.Duration(time.Minute)}.Normalized(), Runtime{Interface: "ranet0", Overlay: nested}, nil, downTable(), k)
	for _, route := range []Route{{Destination: prefix("10.20.0.0/16"), Unreachable: true}, {Destination: prefix("10.20.7.0/24"), Throw: true}, {Destination: prefix("10.20.0.0/16")}} {
		if got, ok := r.holdTouched(route, true); !ok || got != prefix("10.20.0.0/16") {
			t.Errorf("the delete of %s touches %s (%v), want 10.20.0.0/16", route, got, ok)
		}
	}
	// the mesh's route moves a 5110 only by its delete, and only at the prefix itself
	for _, c := range []struct {
		route    Route
		deleting bool
	}{{Route{Destination: prefix("10.20.0.0/16")}, false}, {Route{Destination: prefix("10.20.7.0/24")}, true}} {
		if got, ok := r.holdTouched(c.route, c.deleting); ok {
			t.Errorf("the write of %s (a delete %v) touches %s, want none", c.route, c.deleting, got)
		}
	}
}

// listFailing is the fake failing the next fails listings of the rules
type listFailing struct {
	*recordingKernel
	fails, failed int
}

func (p *listFailing) Rules() ([]Rule, error) {
	if p.fails > 0 {
		p.fails--
		p.failed++
		return nil, errors.New("the rule dump fails")
	}
	return p.recordingKernel.Rules()
}

// A pass whose first listing of the rules fails lists them once more for its rule step, and reports the first failure all the same,
// so the pass is retried, with the count known from the second listing
func TestEntryListingFailureIsReportedWhenTheSecondAnswers(t *testing.T) {
	_, k := downHarness(t)
	p := &listFailing{recordingKernel: k}
	t.Cleanup(func() {
		if p.failed == 0 || p.fails != 0 {
			t.Errorf("the fake failed %d rule listings with %d armed left, want some and none", p.failed, p.fails)
		}
	})
	r := newReconciler(Table{Reconcile: schema.Duration(time.Minute)}.Normalized(), Runtime{Interface: "ranet0", Overlay: downOverlay}, nil, downTable(), p)
	if err := r.reconcile(); err != nil {
		t.Fatal(err)
	}
	p.fails = 1
	err := r.reconcile()
	if err == nil || !strings.Contains(err.Error(), "list rules") {
		t.Errorf("the pass whose first listing of the rules failed reported %v, want that failure", err)
	}
	if stats := r.Stats(); stats.HeldUnknown || !k.holdsDerived(r) {
		t.Errorf("after it the count is not known %v and the derived rules stand %v, want known and standing", stats.HeldUnknown, k.holdsDerived(r))
	}
}

// A release past its commit point whose delete of the IPv4 refusal and every add after the commit fail leaves the down pair beside
// no rule of stepLate: the next pass of the same process owes, puts the set whole and deletes the pair, and deletes no running rule
func TestReleasePastItsCommitWhoseLaterWritesFailStillOwes(t *testing.T) {
	r, k := downHarness(t)
	down := downRules(downOverlay)
	for _, rule := range down {
		k.rules[rule] = true
	}
	k.failing(nil, nil, map[Rule]error{down[0]: errors.New("netlink says no")})
	late := 0
	for _, rule := range derivedRules(r.table.ID, downOverlay, nil, exitView{}) {
		if stepOf(rule.Priority, false) == stepLate {
			k.failAddRule[rule] = errors.New("netlink says no")
			late++
		}
	}
	if err := r.reconcile(); err == nil {
		t.Fatal("the pass whose writes after the commit failed reported no error")
	}
	if late == 0 || !k.holdsAll(down[:2]) || len(k.mainLookups()) == 0 {
		t.Fatalf("setup: %d late adds failed, the IPv4 pair whole %v beside %d lookups of main, want some, whole and some", late, k.holdsAll(down[:2]), len(k.mainLookups()))
	}
	k.failing(nil, nil, nil)
	clear(k.failAddRule)
	before := len(k.taken())
	if err := r.reconcile(); err != nil {
		t.Fatal(err)
	}
	if !k.holdsDerived(r) || k.holdsAny(down) {
		t.Errorf("after the next pass the kernel holds %v, want the derived rules alone", k.rules)
	}
	for _, w := range k.taken()[before:] {
		if w.op == "delete rule" && !isDownRule(w.rule) {
			t.Errorf("the next pass deleted %s, a rule of the running set", w.rule)
		}
	}
}

// After a release whose adds after its commit point fail, the record owes each install on every pass until a pass installs it
func TestInstallsStayOwedUntilTheyLand(t *testing.T) {
	r, k := downHarness(t)
	for _, rule := range downRules(downOverlay) {
		k.rules[rule] = true
	}
	var owed []string
	for _, rule := range derivedRules(r.table.ID, downOverlay, nil, exitView{}) {
		if rule.Priority == priorityMesh {
			k.failAddRule[rule] = errors.New("netlink says no")
			owed = append(owed, "install "+rule.String())
		}
	}
	for pass := range 3 {
		if err := r.reconcile(); err == nil {
			t.Fatalf("pass %d reported no error", pass)
		}
		if got := r.Stats().Owed; !slices.Equal(got, owed) {
			t.Errorf("after pass %d the record owes %q, want %q", pass, got, owed)
		}
	}
	clear(k.failAddRule)
	if err := r.reconcile(); err != nil || len(r.Stats().Owed) != 0 {
		t.Errorf("the pass that installs them reported %v and owes %q", err, r.Stats().Owed)
	}
}

// Another writer's delete of a rule of a running set or of the down set a stop leaves is warned of at the pass or stopped pass that
// finds it, once while it stays missing, and the pass writes it back, where a rule the reconciler deletes itself is warned of never
func TestAnotherWritersDeleteOfARuleIsWarnedOf(t *testing.T) {
	said := logged(t)
	r, k := downHarness(t)
	const line = "kernel found a rule of its own that another writer deleted"
	warned := func() int { return strings.Count(said.String(), line) }
	pass := func(what string) {
		t.Helper()
		if err := r.reconcile(); err != nil {
			t.Fatalf("%s: %v", what, err)
		}
	}
	pass("the running pass")
	pass("an idle pass")
	if n := warned(); n != 0 {
		t.Fatalf("the running and the idle pass warned %d times, want none:\n%s", n, said)
	}
	for i := range 2 {
		delete(k.rules, downOverlayRule)
		pass("the pass after another writer's delete")
		if n := warned(); n != i+1 || !strings.Contains(said.String(), downOverlayRule.String()) || !k.rules[downOverlayRule] {
			t.Errorf("after delete %d the passes warned %d times, the rule back %v, want %d naming %s:\n%s", i+1, n, k.rules[downOverlayRule], i+1, downOverlayRule, said)
		}
		pass("the pass after it")
		if n := warned(); n != i+1 {
			t.Errorf("the pass after delete %d's warned again, %d in all", i+1, n)
		}
	}
	if err := r.withdraw(errStopped); err != nil {
		t.Fatal(err)
	}
	if n := warned(); n != 2 {
		t.Errorf("the stop's own deletes were warned of, %d warnings in all, want 2", n)
	}
	down := downRules(downOverlay)
	delete(k.rules, down[0])
	if err := r.withdraw(errStopped); err != nil {
		t.Fatal(err)
	}
	if n := warned(); n != 3 || !k.rules[down[0]] {
		t.Errorf("the stopped pass after another writer's delete of %s warned %d times in all, the rule back %v, want 3 and back:\n%s", down[0], n, k.rules[down[0]], said)
	}
}

// startOrder holds every priority derivedRules writes in every mode, so no derived rule gets stepNone
func TestStartOrderHoldsEveryDerivedPriority(t *testing.T) {
	links := NetworkState{
		IPv4: NetworkFamily{Links: []Link{{Name: "eth0", Prefixes: []netip.Prefix{prefix("198.51.100.10/24")}}}},
		IPv6: NetworkFamily{Links: []Link{{Name: "eth0", Prefixes: []netip.Prefix{prefix("2001:db8:a::10/64")}}}},
	}
	own := []netip.Prefix{prefix("203.0.113.240/28"), prefix("2001:db8:f0::/48")}
	seen := map[uint32]bool{}
	for _, exit := range []exitView{
		{},
		{on: true, network: links, forwarded: []string{"eth1"}},
		{on: true, network: links, forwarded: []string{"eth1"}, unheld: true},
		{on: true, network: links, forwarded: []string{"eth1"}, fallback: true, own: own, lan: own},
		{on: true, network: links, forwarded: []string{"eth1"}, fallback: true, unaddressed: []Family{FamilyIPv4, FamilyIPv6}},
	} {
		for _, rule := range derivedRules(DefaultTable, downOverlay, own, exit) {
			seen[rule.Priority] = true
			for _, refusing := range []bool{false, true} {
				if stepOf(rule.Priority, refusing) == stepNone {
					t.Errorf("%s (refusing %v) has no step in startOrder", rule, refusing)
				}
			}
		}
	}
	if len(seen) != len(startOrder) {
		t.Errorf("the modes derive %d priorities, startOrder holds %d", len(seen), len(startOrder))
	}
}

// A priority startOrder lacks fails loud: no release adds it, so the reread after the release's adds lacks it at every pass, the
// pass fails naming it, and the down set stays whole
func TestStartOrderMissingAPriorityFailsTheRelease(t *testing.T) {
	saved := slices.Clone(startOrder)
	t.Cleanup(func() { startOrder = saved })
	startOrder = slices.DeleteFunc(slices.Clone(saved), func(at struct {
		priority uint32
		step     startStep
		refusing bool
	}) bool {
		return at.priority == priorityMesh
	})
	r, k := downHarness(t)
	down := downRules(downOverlay)
	for _, rule := range down {
		k.rules[rule] = true
	}
	for pass := range 2 {
		err := r.reconcile()
		if err == nil || !strings.Contains(err.Error(), "lack") || !strings.Contains(err.Error(), "priority 5420") {
			t.Errorf("pass %d answered %v, want the reread lacking the mesh's lookup", pass, err)
		}
		if !k.holdsAll(down) {
			t.Errorf("after pass %d the down set is not whole", pass)
		}
	}
}

// carvedOverlay is the overlay of the carve-out's rows: in each family a prefix the uplink's own network holds whole and one it does
// not, the IPv4 one holding a network of the uplink as a carved child
var carvedOverlay = prefixes(prefix("192.0.2.0/25"), prefix("203.0.113.0/24"), prefix("3fff::/21"), prefix("2001:db8:1::/48"))

// carvedHeld is the prefixes of carvedOverlay whose pairs the down set holds beside carvedNetwork, and carvedWhole those it leaves out
var (
	carvedHeld  = prefixes(prefix("203.0.113.0/24"), prefix("2001:db8:1::/48"))
	carvedWhole = prefixes(prefix("192.0.2.0/25"), prefix("3fff::/21"))
)

// carvedNetwork is the uplink of the carve-out's rows, whose networks hold 192.0.2.0/25 and 3fff::/21 whole and 203.0.113.64/26
// inside 203.0.113.0/24
var carvedNetwork = NetworkState{
	IPv4: NetworkFamily{Links: []Link{{Name: "eth0", Prefixes: []netip.Prefix{prefix("192.0.2.130/24"), prefix("203.0.113.70/26")}}}},
	IPv6: NetworkFamily{Links: []Link{{Name: "eth0", Prefixes: []netip.Prefix{prefix("3fff:800::10/20")}}}},
}

// carvedHarness is downHarness over carvedOverlay and table, with the host's network as network holds it, carvedNetwork to begin
// with
func carvedHarness(t *testing.T, table *netstack.RouteTable) (*Reconciler, *recordingKernel, *atomic.Pointer[NetworkState]) {
	t.Helper()
	network := new(atomic.Pointer[NetworkState])
	network.Store(&carvedNetwork)
	tbl := Table{Reconcile: schema.Duration(time.Minute)}.Normalized()
	k := newRecording(t)
	rt := Runtime{Interface: "ranet0", Overlay: carvedOverlay, Network: func() NetworkState { return *network.Load() }}
	return newReconciler(tbl, rt, nil, table, k), k, network
}

// Each stop but the operator's leaves the pair of each overlay prefix but one a carve-out equals, in both families: the uplink's own
// network covering a prefix leaves it none, so its addresses meet main while down as they do while the node runs, and a network
// inside a prefix leaves it its pair
func TestStopLeavesNoPairAtAPrefixACarveOutEquals(t *testing.T) {
	for _, c := range []struct {
		name string
		stop func(*Reconciler, context.CancelCauseFunc)
	}{
		{"ranet3 down", func(r *Reconciler, _ context.CancelCauseFunc) { r.SetEnabled(false) }},
		{"a clean stop", func(_ *Reconciler, cancel context.CancelCauseFunc) { cancel(nil) }},
		{"a stop for a failed mesh", func(_ *Reconciler, cancel context.CancelCauseFunc) { cancel(ErrMeshFailed) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			r, k, _ := carvedHarness(t, downTable())
			cancel, wait := runDown(t, r, k)
			c.stop(r, cancel)
			if c.name == "ranet3 down" {
				waitFor(t, func() bool { return len(k.snapshot()) == 0 && r.Stats().Held == 2 })
			} else {
				// the last withdrawal and the listing after it, which adds what it finds missing, have both ended
				wait()
			}
			if !k.holds(downRules(carvedHeld)) {
				t.Errorf("the stop left %v, want the pairs of %v alone", k.rules, carvedHeld)
			}
		})
	}
}

// A stopped reconciler's pass moves the down set with the carve-outs of the host's network as the watch reads it then: the uplink
// lost while the node is down gives the prefixes it held whole their pairs at the next stopped pass, and the uplink back takes them
// out, as a running pass moves such a prefix's hold
func TestStoppedPassMovesTheDownSetWithTheCarveOuts(t *testing.T) {
	r, k, network := carvedHarness(t, downTable())
	runDown(t, r, k)
	r.SetEnabled(false)
	waitFor(t, func() bool { return k.holds(downRules(carvedHeld)) && len(k.snapshot()) == 0 && r.Stats().Held == 2 })
	for _, c := range []struct {
		what    string
		network *NetworkState
		held    []schema.Prefix
	}{
		{"the uplink lost", &NetworkState{}, carvedOverlay},
		{"the uplink back", &carvedNetwork, carvedHeld},
	} {
		network.Store(c.network)
		// a wake of the stopped reconciler, as its sweep gives it in mode off, where a change of links alone wakes nothing
		r.SetEnabled(false)
		waitFor(t, func() bool { return k.holds(downRules(c.held)) && r.Stats().Held == len(c.held) })
	}
}

// A reload while a down stopped the reconciler writes the down set of the new overlay against the carve-outs: a prefix the reload
// adds that a carve-out equals gets no pair, and one no carve-out equals gets its pair
func TestReloadWhileDownLeavesOutThePrefixesACarveOutEquals(t *testing.T) {
	r, k, _ := carvedHarness(t, downTable())
	runDown(t, r, k)
	r.SetEnabled(false)
	waitFor(t, func() bool { return k.holds(downRules(carvedHeld)) && len(k.snapshot()) == 0 && r.Stats().Held == 2 })
	moved := prefixes(prefix("192.0.2.0/24"), prefix("198.51.100.0/24"), prefix("3fff::/20"), prefix("2001:db8:2::/48"))
	held := prefixes(prefix("198.51.100.0/24"), prefix("2001:db8:2::/48"))
	stopped := r.Stats().At
	if err := r.SetTable(r.Table(), moved, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return !r.Stats().At.Equal(stopped) && k.holds(downRules(held)) && r.Stats().Held == 2 })
}

// A start over a down set that holds a pair at a prefix a carve-out now equals, as a stop before the link came up left it, takes
// that pair out at its entry, 32764 first and ahead of any rule it adds, keeps the other pairs until its 5110 stand, and finishes
func TestStartTakesOutThePairOfAPrefixACarveOutEquals(t *testing.T) {
	r, k, _ := carvedHarness(t, downTable())
	for _, rule := range downRules(carvedOverlay) {
		k.rules[rule] = true
	}
	if err := r.reconcile(); err != nil {
		t.Fatal(err)
	}
	writes := k.taken()
	at := func(op string, rule Rule) int {
		return slices.IndexFunc(writes, func(w kernelWrite) bool { return w.op == op && w.rule == rule })
	}
	firstAdd := slices.IndexFunc(writes, func(w kernelWrite) bool { return w.op == "add rule" })
	for _, to := range carvedWhole {
		refusal, lookup := pairOf(to)
		if looked, refused := at("delete rule", lookup), at("delete rule", refusal); looked < 0 || refused < looked || refused > firstAdd {
			t.Errorf("the start deleted the pair of %s at %d and %d, its first add at %d, want the lookup first and both ahead of the add: %+v", to, looked, refused, firstAdd, writes)
		}
	}
	last := -1
	for i, w := range writes {
		if w.op == "add rule" && w.rule.Priority == priorityOverlay {
			last = i
		}
	}
	for _, rule := range downRules(carvedHeld) {
		if i := at("delete rule", rule); i < last {
			t.Errorf("the start deleted %s at %d, ahead of its last add at %d", rule, i, priorityOverlay)
		}
	}
	if !k.holdsDerived(r) || k.holdsAny(downRules(carvedOverlay)) || r.Stats().Held != 0 {
		t.Errorf("after the start the kernel holds %v and the record counts %d held, want the derived rules alone and none", k.rules, r.Stats().Held)
	}
}

// A start over the down set a stop left beside the uplink, where the mesh's table holds a prefix the uplink holds whole for every
// source, so no throw stands there, finishes as one where its throw stands
func TestStartFinishesWhereTheMeshHoldsACarvedPrefixWhole(t *testing.T) {
	table := downTable()
	table.Set(netip.Prefix{}, prefix("192.0.2.0/25"), nil)
	r, k, _ := carvedHarness(t, table)
	for _, rule := range downRules(carvedHeld) {
		k.rules[rule] = true
	}
	if err := r.reconcile(); err != nil {
		t.Fatal(err)
	}
	if !k.holdsDerived(r) || k.holdsAny(downRules(carvedOverlay)) || r.Stats().Held != 0 {
		t.Errorf("after the start the kernel holds %v and the record counts %d held, want the derived rules alone and none", k.rules, r.Stats().Held)
	}
}

// stolenKernel is the recording fake where another writer deletes stolen right after each add of it that succeeds
type stolenKernel struct {
	*recordingKernel
	stolen Route
}

func (k *stolenKernel) AddRoute(route Route) error {
	err := k.recordingKernel.AddRoute(route)
	if err == nil && route == k.stolen {
		k.mu.Lock()
		delete(k.routes, route)
		k.mu.Unlock()
	}
	return err
}

// A staged start keeps a 5110 only on a route of the pass at the prefix itself for every source that its own listing and writes
// show standing, and adds one only where its reread of the routes shows such a route too: a 5110 that stands beside a
// source-specific route at its prefix alone, or beside the mesh's route there whose add failed, goes, and one the start lacks stays
// out where another writer deleted the mesh's route ahead of the reread, a source-specific route at the prefix notwithstanding
func TestStagedStartKeepsA5110OnlyOnARouteForEverySourceThatStands(t *testing.T) {
	busy := errors.New("netlink says no")
	source := prefix("2001:db8:9::/48")
	for _, c := range []struct {
		what                       string
		at                         netip.Prefix
		whole, sourced, standing   bool
		failHold, failMesh, stolen bool
	}{
		{"a source-specific route alone, the hold's add failed", prefix("2001:db8:1::/48"), false, true, true, true, false, false},
		{"the mesh's route whose add failed", prefix("192.0.2.0/25"), true, false, true, false, true, false},
		{"the mesh's route another writer deleted ahead of the reread", prefix("3fff::/21"), true, true, false, false, false, true},
	} {
		t.Run(c.what, func(t *testing.T) {
			table := downTable()
			if c.whole {
				table.Set(netip.Prefix{}, c.at, nil)
			}
			if c.sourced {
				table.Set(source, c.at, nil)
			}
			mesh := Route{Destination: c.at, Metric: routeMetric(c.at, false)}
			network := new(atomic.Pointer[NetworkState])
			network.Store(&carvedNetwork)
			k := &stolenKernel{recordingKernel: newRecording(t)}
			if c.stolen {
				k.stolen = mesh
			}
			tbl := Table{Reconcile: schema.Duration(time.Minute)}.Normalized()
			rt := Runtime{Interface: "ranet0", Overlay: carvedOverlay, Network: func() NetworkState { return *network.Load() }}
			r := newReconciler(tbl, rt, nil, table, k)
			lookup := Rule{Family: familyOf(c.at.Addr()), Priority: priorityOverlay, To: schema.PrefixFrom(c.at), Table: tbl.ID}
			for _, rule := range downRules(carvedHeld) {
				k.rules[rule] = true
			}
			if c.standing {
				k.rules[lookup] = true
			}
			if c.failHold {
				k.failAdd[Route{Destination: c.at, Metric: holdMetric, Unreachable: true}] = busy
			}
			if c.failMesh {
				k.failAdd[mesh] = busy
			}
			_ = r.reconcile()
			if c.sourced && !k.has(Route{Destination: c.at, Source: source, Metric: routeMetric(c.at, false)}) {
				t.Fatalf("the source-specific route at %s does not stand: %v", c.at, k.snapshot())
			}
			if k.holdsAny([]Rule{lookup}) {
				t.Errorf("after the start's pass %s stands, want it gone", lookup)
			}
		})
	}
}

// A start over the down set a stop left beside the uplink, where an overlay prefix of host length is an address cap.table assigns
// and the uplink's network holds it whole, finishes in its first pass in both families: the mesh's entry there is none of the
// kernel's, so the carve-out's throw goes in, and its 5110 stages on it
func TestStartFinishesWhereCapTableAssignsAHostPrefixACarveOutEquals(t *testing.T) {
	assigned := []netip.Prefix{prefix("192.0.2.5/32"), prefix("3fff::5/128")}
	table := downTable()
	for _, p := range assigned {
		table.Set(netip.Prefix{}, p, netstack.Assigned)
	}
	network := new(atomic.Pointer[NetworkState])
	network.Store(&carvedNetwork)
	overlay := append(prefixes(assigned...), carvedHeld...)
	k := newRecording(t)
	tbl := Table{Reconcile: schema.Duration(time.Minute)}.Normalized()
	rt := Runtime{Interface: "ranet0", Overlay: overlay, Network: func() NetworkState { return *network.Load() }}
	r := newReconciler(tbl, rt, nil, table, k)
	for _, rule := range downRules(carvedHeld) {
		k.rules[rule] = true
	}
	if err := r.reconcile(); err != nil {
		t.Fatal(err)
	}
	if !k.holdsDerived(r) || k.holdsAny(downRules(overlay)) || r.Stats().Held != 0 {
		t.Errorf("after the start the kernel holds %v and the record counts %d held, want the derived rules alone and none", k.rules, r.Stats().Held)
	}
	for _, p := range assigned {
		if throw := (Route{Destination: p, Metric: holdMetric, Throw: true}); !k.has(throw) {
			t.Errorf("no throw at %s, an address cap.table assigns that the uplink holds: %v", p, k.snapshot())
		}
	}
}
