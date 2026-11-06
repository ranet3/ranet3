// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package kernel

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/netstack"
)

// rejectingKernel is the covering fake with darwin's switch: a reject at each
// key of the sets handed it, in the key space of the unscoped routes, so an
// unscoped route and a reject at one key refuse each other's add as darwin's
// kernel does. ops is each route add and refusal and each write and delete of
// the switch, in order.
type rejectingKernel struct {
	*coveringKernel
	smu sync.Mutex
	// rejects is each key the fake holds a reject at, and others each key
	// another program's route holds, described
	rejects map[netip.Prefix]bool
	others  map[netip.Prefix]string
	// rows is the switch as the pass's listing read it, which writes update,
	// nil before one
	rows rejectRows
	ops  []string
}

// fakeRejectsForm is darwin's switch as the fake's lines read it
var fakeRejectsForm = fallbackForm{where: "rejects on lo0", fix: "route -n delete", unheld: "the host's unbound traffic leaves by its own routes", routes: true, uncounted: true}

func (k *rejectingKernel) form() fallbackForm { return fakeRejectsForm }

func (k *rejectingKernel) note(op string) {
	k.smu.Lock()
	defer k.smu.Unlock()
	k.ops = append(k.ops, op)
}

// unscopedAt is an unscoped route of ours the fake holds at key, described
func (k *rejectingKernel) unscopedAt(key netip.Prefix) (string, bool) {
	k.fakeKernel.mu.Lock()
	defer k.fakeKernel.mu.Unlock()
	for r := range k.fakeKernel.routes {
		if r.Destination == key && !r.Scoped {
			return key.String() + " on ranet0", true
		}
	}
	return "", false
}

func (k *rejectingKernel) Routes() ([]Route, error) {
	routes, err := k.coveringKernel.Routes()
	k.smu.Lock()
	defer k.smu.Unlock()
	k.rows = nil
	if err != nil {
		return nil, err
	}
	k.rows = make(rejectRows)
	for _, key := range rejectKeys {
		switch {
		case k.rejects[key]:
			k.rows.record(key, true, true, false, nil)
		case k.others[key] != "":
			k.rows.record(key, false, false, false, func() string { return k.others[key] })
		}
	}
	for _, r := range routes {
		if !r.Scoped && slices.Contains(rejectKeys, r.Destination) {
			k.rows.record(r.Destination, false, false, true, func() string { return r.Destination.String() + " on ranet0" })
		}
	}
	return routes, nil
}

func (k *rejectingKernel) AddRoute(r Route) error {
	k.smu.Lock()
	taken := !k.scopes(r) && (k.rejects[r.Destination] || k.others[r.Destination] != "")
	k.smu.Unlock()
	if taken {
		k.note("refused " + r.Destination.String())
		return errRouteSkipped
	}
	k.note("add " + r.Destination.String())
	return k.coveringKernel.AddRoute(r)
}

func (k *rejectingKernel) writeFallback(sets fallbackSets, _ bool) error {
	k.note("write")
	k.smu.Lock()
	rows := k.rows
	k.smu.Unlock()
	if rows == nil {
		return errors.New("no listing of this pass")
	}
	return rows.write(sets.rejects, func(key netip.Prefix) error {
		if _, ok := k.unscopedAt(key); ok {
			return errKeyTaken
		}
		k.smu.Lock()
		defer k.smu.Unlock()
		if k.others[key] != "" {
			return errKeyTaken
		}
		k.rejects[key] = true
		return nil
	}, func(key netip.Prefix) string {
		k.smu.Lock()
		defer k.smu.Unlock()
		return k.others[key]
	})
}

func (k *rejectingKernel) readFallback(sets fallbackSets) (fallbackRead, error) {
	k.smu.Lock()
	defer k.smu.Unlock()
	if k.rows == nil {
		return fallbackRead{}, errors.New("no listing of this pass")
	}
	return fallbackRead{fault: k.rows.fault(sets.rejects)}, nil
}

func (k *rejectingKernel) deleteFallback() error {
	k.note("delete")
	k.smu.Lock()
	defer k.smu.Unlock()
	clear(k.rejects)
	k.rows = nil
	return nil
}

func (k *rejectingKernel) holdsFallback() (bool, error) {
	k.smu.Lock()
	defer k.smu.Unlock()
	return len(k.rejects) > 0, nil
}

// held is the keys the fake holds a reject at, in rejectKeys' order, and the ops so far
func (k *rejectingKernel) held() ([]netip.Prefix, []string) {
	k.smu.Lock()
	defer k.smu.Unlock()
	var out []netip.Prefix
	for _, key := range rejectKeys {
		if k.rejects[key] {
			out = append(out, key)
		}
	}
	return out, slices.Clone(k.ops)
}

// rejectingHarness is a reconciler on rejectingKernel with no policy rules, as
// darwin's, under mode over coverOverlay, a session live and the tun holding
// addresses
func rejectingHarness(t *testing.T, mode *ExitMode, addresses ...netip.Prefix) (*Reconciler, *netstack.RouteTable, *rejectingKernel) {
	t.Helper()
	reconciler, table, covering := coveredHarness(t, Table{}.WithMode(mode), Runtime{Sessions: func() int { return 1 }}, addresses...)
	reconciler.now = func() time.Time { return start }
	k := &rejectingKernel{coveringKernel: covering, rejects: map[netip.Prefix]bool{}, others: map[netip.Prefix]string{}}
	reconciler.plat = k
	return reconciler, table, k
}

// switchReads is the switch's state and fault as the last pass of reconciler reported them
func switchReads(reconciler *Reconciler) string {
	exit := reconciler.Stats().Exit
	if exit == nil || exit.Fallback == nil {
		return "off"
	}
	if exit.Fallback.Fault != "" {
		return fmt.Sprintf("%s: %s", exit.Fallback.State, exit.Fallback.Fault)
	}
	return string(exit.Fallback.State)
}

// On a covering platform with no policy rules a pass under fallback = "none"
// writes a reject at each key of both families' covers, though the tun holds
// an address of IPv4 alone, and reads them back as holding, reporting no drops
// since the rejects count none
func TestSwitchWithoutRulesWritesTheRejectsOfBothFamilies(t *testing.T) {
	reconciler, _, k := rejectingHarness(t, &ExitMode{Fallback: FallbackNone}, prefix("192.0.2.1/24"))
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if held, _ := k.held(); !slices.Equal(held, rejectKeys) {
		t.Errorf("the pass holds rejects at %v, want at %v", held, rejectKeys)
	}
	if got := switchReads(reconciler); got != string(FallbackHolding) {
		t.Errorf("the switch reads %s, want holding", got)
	}
	if fallback := reconciler.Stats().Exit.Fallback; fallback.DropsRead || !fallback.Uncounted {
		t.Errorf("the switch reports drops read %v and uncounted %v, want unread and uncounted", fallback.DropsRead, fallback.Uncounted)
	}
}

// opsFrom is ops past the first n
func opsFrom(ops []string, n int) []string { return ops[min(n, len(ops)):] }

// A pass asking for the switch writes it after its routes, and a pass that no
// longer asks for it deletes it before them, so the members of a default
// announced with the reload find their keys free and go in whole
func TestSwitchIsWrittenAfterTheRoutesAndDeletedBeforeThem(t *testing.T) {
	reconciler, table, k := rejectingHarness(t, &ExitMode{Fallback: FallbackNone}, coverAddresses...)
	table.Set(netip.Prefix{}, prefix("198.51.100.0/24"), nil)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	_, ops := k.held()
	if add, write := slices.Index(ops, "add 198.51.100.0/24"), slices.Index(ops, "write"); add < 0 || write < add {
		t.Errorf("the pass asking for the switch ran %v, want the route added before the switch is written", ops)
	}
	if err := reconciler.SetTable(reconciler.table.WithMode(&ExitMode{Fallback: FallbackUplink}), coverOverlay, nil); err != nil {
		t.Fatal(err)
	}
	reconciler.adopt()
	table.Set(netip.Prefix{}, prefix("0.0.0.0/0"), nil)
	before := len(ops)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	held, ops := k.held()
	turned := opsFrom(ops, before)
	if len(held) != 0 || len(turned) == 0 || turned[0] != "delete" {
		t.Errorf("the pass turning the switch off ran %v and left rejects at %v, want the switch deleted first", turned, held)
	}
	if v4, _ := coverMembers(k.fakeKernel); v4 != len(zeroFreeCover[true]) {
		t.Errorf("the pass turning the switch off installed %d IPv4 members, want %d: %v", v4, len(zeroFreeCover[true]), turned)
	}
}

// A reject gone from a key is written again by the next pass, and a key
// another program's route holds is named as the fault, written again by each
// pass and never taken over, the other keys holding their rejects
func TestSwitchFaultIsRewritten(t *testing.T) {
	reconciler, _, k := rejectingHarness(t, &ExitMode{Fallback: FallbackNone}, coverAddresses...)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	gone := prefix("128.0.0.0/1")
	k.smu.Lock()
	delete(k.rejects, gone)
	k.smu.Unlock()
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	if held, _ := k.held(); !slices.Contains(held, gone) || switchReads(reconciler) != string(FallbackHolding) {
		t.Errorf("after the reject at %s went the pass holds %v and reads %s, want it written again and holding", gone, held, switchReads(reconciler))
	}

	taken := prefix("2000::/3")
	k.smu.Lock()
	delete(k.rejects, taken)
	k.others[taken] = "2000::/3 on utun5"
	k.smu.Unlock()
	for range 2 {
		_, before := k.held()
		_ = reconciler.reconcile()
		if _, ops := k.held(); !slices.Contains(opsFrom(ops, len(before)), "write") {
			t.Errorf("a pass meeting another program's route at %s did not write the switch again: %v", taken, opsFrom(ops, len(before)))
		}
	}
	want := string(FallbackNotHolding) + ": another program's route 2000::/3 on utun5 holds a key of the switch's"
	if got := switchReads(reconciler); got != want {
		t.Errorf("the switch reads %q, want %q", got, want)
	}
	if held, _ := k.held(); slices.Contains(held, taken) || len(held) != len(rejectKeys)-1 {
		t.Errorf("beside another program's route at %s the fake holds rejects at %v, want every other key's", taken, held)
	}
}

// A failed mesh's stop leaves the rejects, which a second reconciler takes
// over with no write and no warning, and an operator's stop deletes them
func TestSwitchOutlivesAFailedStopAndGoesAtAnOperatorsStop(t *testing.T) {
	reconciler, table, k := rejectingHarness(t, &ExitMode{Fallback: FallbackNone}, coverAddresses...)
	table.Set(netip.Prefix{}, prefix("198.51.100.0/24"), nil)
	said := logged(t)
	stop := runThroughFirstPass(t, reconciler)
	stop(ErrMeshFailed)
	held, ops := k.held()
	if !slices.Equal(held, rejectKeys) || len(k.snapshot()) != 0 {
		t.Fatalf("the failed mesh's stop left rejects at %v and routes %v, want every reject and no route", held, k.snapshot())
	}
	if !strings.Contains(said.String(), leftLine+`" where="rejects on lo0" state=holding`) {
		t.Errorf("the failed mesh's stop did not warn that it leaves the rejects:\n%s", said)
	}

	second := newReconciler(reconciler.table, reconciler.rt, reconciler.addresses, table, k)
	second.plat, second.rules, second.look, second.now = k, nil, nil, reconciler.now
	written := strings.Count(said.String(), "\n")
	stop = runThroughFirstPass(t, second)
	if _, after := k.held(); slices.Contains(opsFrom(after, len(ops)), "write") || switchReads(second) != string(FallbackHolding) {
		t.Errorf("the second reconciler ran %v and reads %s, want the rejects taken over with no write", opsFrom(after, len(ops)), switchReads(second))
	}
	for _, line := range strings.Split(said.String(), "\n")[written:] {
		if strings.Contains(line, "level=WARN") {
			t.Errorf("the second reconciler warned: %s", line)
		}
	}
	stop(nil)
	if held, _ := k.held(); len(held) != 0 {
		t.Errorf("the operator's stop left rejects at %v", held)
	}
}

// routesAt is each route the fake holds at destination
func routesAt(fake *fakeKernel, destinations ...string) []Route {
	var out []Route
	for _, r := range fake.snapshot() {
		for _, destination := range destinations {
			if r.Destination == prefix(destination) {
				out = append(out, r)
			}
		}
	}
	return out
}

// An announced 128.0.0.0/1 in mode 2 goes in as 128.0.0.0/2 and 192.0.0.0/2
// while the switch is asked for, whole once it is not, and the reject takes
// its key
func TestSwitchSplitsARouteAtAKey(t *testing.T) {
	reconciler, table, k := rejectingHarness(t, &ExitMode{Fallback: FallbackNone}, coverAddresses...)
	table.Set(netip.Prefix{}, prefix("128.0.0.0/1"), nil)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	want := []Route{{Destination: prefix("128.0.0.0/2")}, {Destination: prefix("192.0.0.0/2")}}
	if got := routesAt(k.fakeKernel, "128.0.0.0/1", "128.0.0.0/2", "192.0.0.0/2"); !slices.Equal(got, want) || switchReads(reconciler) != string(FallbackPassing) {
		t.Errorf("under the switch the kernel holds %v and the switch reads %s, want %v and passing", got, switchReads(reconciler), want)
	}
	if err := reconciler.SetTable(reconciler.table.WithMode(&ExitMode{Fallback: FallbackUplink}), coverOverlay, nil); err != nil {
		t.Fatal(err)
	}
	reconciler.adopt()
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	want = []Route{{Destination: prefix("128.0.0.0/1")}}
	if got := routesAt(k.fakeKernel, "128.0.0.0/1", "128.0.0.0/2", "192.0.0.0/2"); !slices.Equal(got, want) {
		t.Errorf("with the switch off the kernel holds %v, want %v", got, want)
	}
}

// Under the switch a member row L6 scopes beneath the host's 64.0.0.0/2 goes
// in whole, keyed apart from the reject, and every other member as its
// halves, 15 IPv4 routes of the cover. With the switch off every member goes
// in whole.
func TestSwitchKeepsAScopedMemberWhole(t *testing.T) {
	for _, switched := range []bool{true, false} {
		mode := &ExitMode{Fallback: FallbackUplink}
		if switched {
			mode = &ExitMode{Fallback: FallbackNone}
		}
		reconciler, table, k := rejectingHarness(t, mode, coverAddresses...)
		reconciler.rt.Selection = newFakeSelection(hostRoute{destination: prefix("64.0.0.0/2"), index: 2})
		table.Set(netip.Prefix{}, prefix("0.0.0.0/0"), nil)
		if err := reconciler.reconcile(); err != nil {
			t.Fatal(err)
		}
		member := Route{Destination: prefix("64.0.0.0/2"), Cover: true, Scoped: true}
		v4, _ := coverMembers(k.fakeKernel)
		want := map[bool]int{true: 15, false: 8}[switched]
		if !k.has(member) || v4 != want {
			t.Errorf("with the switch asked for %v the cover is %d IPv4 routes holding %+v %v, want %d: %v", switched, v4, member, k.has(member), want, k.snapshot())
		}
	}
}

// A mesh route at a half's key that row L6 scopes beneath the host's route
// there withholds that half under the switch, as it withholds the whole member
// at its own key, and the other half goes in
func TestSwitchWithholdsAHalfUnderAScopedRouteAtItsKey(t *testing.T) {
	reconciler, table, k := rejectingHarness(t, &ExitMode{Fallback: FallbackNone}, coverAddresses...)
	reconciler.rt.Selection = newFakeSelection(hostRoute{destination: prefix("128.0.0.0/2"), index: 2})
	table.Set(netip.Prefix{}, prefix("0.0.0.0/0"), nil)
	table.Set(netip.Prefix{}, prefix("128.0.0.0/2"), nil)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	want := []Route{{Destination: prefix("128.0.0.0/2"), Scoped: true}, {Destination: prefix("192.0.0.0/2"), Cover: true}}
	if got := routesAt(k.fakeKernel, "128.0.0.0/1", "128.0.0.0/2", "192.0.0.0/2"); !slices.Equal(got, want) {
		t.Errorf("the kernel holds %v, want %v", got, want)
	}
}

// A half gives way to a route of ours at its own key, so one route goes in at
// that key, and the other half goes in
func TestSplitHalfGivesWayToARouteOfOursAtItsKey(t *testing.T) {
	member := Route{Destination: prefix("128.0.0.0/1"), Cover: true}
	announced := Route{Destination: prefix("128.0.0.0/2"), Metric: 7}
	got := splitAtKeys([]Route{member, announced}, rejectKeys, func(Route) bool { return false })
	want := []Route{announced, {Destination: prefix("192.0.0.0/2"), Cover: true}}
	if !slices.Equal(got, want) {
		t.Errorf("the split of %v beside %v is %v, want %v", member, announced, got, want)
	}
}

// Under the switch an endpoint in the overlay that the host routes by its
// 128.0.0.0/1 is cut out of the overlay's piece of the half that holds it, and
// the hole names that half, which goes in in place of the member, not the
// member
func TestSwitchCutsAnEndpointOutOfAHalf(t *testing.T) {
	reconciler, table, _ := rejectingHarness(t, &ExitMode{Fallback: FallbackNone}, coverAddresses...)
	endpoint := netip.MustParseAddr("192.0.2.9")
	reconciler.rt.Selection = newFakeSelection(hostRoute{destination: prefix("128.0.0.0/1"), index: 2})
	reconciler.rt.Underlay = func() []netip.Addr { return []netip.Addr{endpoint} }
	table.Set(netip.Prefix{}, prefix("0.0.0.0/0"), nil)
	if err := reconciler.reconcile(); err != nil {
		t.Fatal(err)
	}
	half := prefix("192.0.0.0/2")
	pieces := without(prefix("192.0.2.0/24"), hostPrefixes(endpoint))
	slices.SortFunc(pieces, comparePrefixes)
	if holes := reconciler.Stats().Holes; len(holes) != 1 || holes[0].Route != half || !slices.Equal(holes[0].Endpoints, []netip.Addr{endpoint}) || !slices.Equal(holes[0].Pieces, pieces) {
		t.Errorf("the pass reports the holes %+v, want %s cut around %s into %v", holes, half, endpoint, pieces)
	}
}
