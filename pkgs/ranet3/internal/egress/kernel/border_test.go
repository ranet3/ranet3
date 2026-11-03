// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/events"
	meshkernel "ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/logtest"
	"ranet3.com/pkgs/ranet3/schema"
)

// fakeBorder stands in for the kernel under the antispoof filter, as fakeBackend
// does under the translator
type fakeBorder struct {
	mu        sync.Mutex
	held      []Installed
	applied   int
	withdrawn int
	// failRules makes a host whose chain cannot be listed
	failRules bool
	// failApply makes a host that will not take the chain
	failApply bool
	// failWithdraw makes a host that will not let the table go
	failWithdraw bool
	// garble makes a host that holds the last rule written under a comment cut short
	garble bool
	// fault is how the table or the chain differs from what Apply writes. An
	// apply, which makes the table again, clears it unless stuck holds it.
	fault string
	stuck bool
	// sets is each set's prefixes as the last Apply or Fill left them, which a
	// readback against other prefixes reads as a fault
	sets borderSets
	// failFill makes a host that will not take a set's elements
	failFill bool
	// counts is each rule's packet counter by spec, as a readback finds it
	counts map[string]uint64
	// changed stands for another writer's changes to the table, nil for none
	changed chan struct{}
	// missed stands for notifications the backend lost, nil for none
	missed chan struct{}
	// log records each listing, apply and withdrawal in order
	log []string
	// only is the classes the host writes as rules of their own, every class
	// where it is nil
	only []BorderClass
	// unready is the reason a readback gives for the host not being ready
	// beside its rules, which no rewrite changes
	unready string
}

func (f *fakeBorder) entries() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.log)
}

// readback is the table as a read finds it, its rules read by comment against
// rules and each set against sets where each is not nil
func (f *fakeBorder) readback(rules []BorderRule, sets borderSets) chainReadback {
	out := slices.Clone(f.held)
	for i := range out {
		out[i].Packets = f.counts[out[i].Spec]
	}
	// a table read back with no rule and no fault is one nobody wrote
	read := chainReadback{rules: out, fault: f.fault, unready: f.unready, held: len(f.held) != 0 || f.fault != ""}
	if name := slices.Sorted(maps.Keys(sets.changed(f.sets))); sets != nil && read.fault == "" && len(name) > 0 {
		read.fault = "its set " + name[0] + " holds other elements"
	}
	same := slices.EqualFunc(out, rules, func(held Installed, rule BorderRule) bool { return held.Spec == rule.String() })
	if rules != nil && read.fault == "" && !same {
		read.fault = "its chains read back other than they were written"
	}
	return read
}

func (f *fakeBorder) Rules(rules []BorderRule, sets borderSets) (chainReadback, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log = append(f.log, "rules")
	if f.failRules {
		return chainReadback{}, errors.New("no")
	}
	return f.readback(rules, sets), nil
}

func (f *fakeBorder) Read() (chainReadback, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.readback(nil, nil), nil
}

// Fill logs fill and the names of the sets it fills, and refuses a move from
// ranges a set does not hold, which a delta would apply to the wrong elements
func (f *fakeBorder) Fill(was, sets borderSets) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log = append(f.log, "fill "+strings.Join(slices.Sorted(maps.Keys(sets)), " "))
	if f.failFill {
		return errors.New("no")
	}
	for name := range sets {
		if !slices.Equal(was[name], f.sets[name]) {
			return fmt.Errorf("fill moves set %s from %v, which holds %v", name, was[name], f.sets[name])
		}
	}
	if f.sets == nil {
		f.sets = borderSets{}
	}
	maps.Copy(f.sets, sets)
	return nil
}

func (f *fakeBorder) Apply(rules []BorderRule, sets borderSets) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log = append(f.log, "apply")
	if f.failApply {
		return errors.New("no")
	}
	f.applied++
	if !f.stuck {
		f.fault = ""
	}
	f.held = nil
	for _, rule := range rules {
		f.held = append(f.held, Installed{Spec: rule.String()})
	}
	f.sets = maps.Clone(sets)
	if f.garble && len(f.held) != 0 {
		last := &f.held[len(f.held)-1]
		last.Spec = last.Spec[:len(last.Spec)-1]
	}
	return nil
}

// Withdraw reports a table removed where a read would find one
func (f *fakeBorder) Withdraw() (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log = append(f.log, "withdraw")
	if f.failWithdraw {
		return false, errors.New("no")
	}
	f.withdrawn++
	removed := len(f.held) != 0 || f.fault != ""
	f.held = nil
	return removed, nil
}

func (f *fakeBorder) Changed() <-chan struct{} { return f.changed }

func (f *fakeBorder) Missed() <-chan struct{} { return f.missed }

func (f *fakeBorder) Close() error { return nil }

// where, chain and readings read as the linux backend's
func (f *fakeBorder) where(cfg *egress.Border) string {
	if cfg == nil {
		return "nftables table inet ranet3 chain mesh_entry"
	}
	return "nftables table inet ranet3 chains antispoof and mesh_entry"
}

func (f *fakeBorder) writes(class BorderClass) bool {
	return f.only == nil || slices.Contains(f.only, class)
}

func (f *fakeBorder) chain(name string) egress.BorderChainReading {
	hook, priority := "prerouting", -300
	if name == EntryChain {
		hook, priority = "postrouting", 110
	}
	return egress.BorderChainReading{Name: name, Hook: hook, Priority: &priority}
}

func (f *fakeBorder) readings(sets borderSets) []egress.BorderSetReading { return sets.readings() }

// allSpecs is both chains' rules as held
func (f *fakeBorder) allSpecs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, rule := range f.held {
		out = append(out, rule.Spec)
	}
	return out
}

// specs is the antispoof chain's rules as held, the entry chain's left out
func (f *fakeBorder) specs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.held))
	for _, rule := range f.held {
		if !strings.HasPrefix(rule.Spec, "return ") && !strings.HasSuffix(rule.Spec, " entering the mesh") {
			out = append(out, rule.Spec)
		}
	}
	return out
}

func (f *fakeBorder) setCount(spec string, packets uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.counts == nil {
		f.counts = map[string]uint64{}
	}
	f.counts[spec] = packets
}

// borderRuntime is a filter's runtime over the mesh tun and lo, recording on bus
func borderRuntime(bus *events.Bus) egress.BorderRuntime {
	return egress.BorderRuntime{Tun: "ranet0", Inside: []string{"ranet0", "lo"}, Events: bus}
}

// entryRules is the entry chain's rules, which follow the antispoof chain's
const entryRules = 10

// readyMoves is each move of the filter's readiness bus recorded, in order
func readyMoves(bus *events.Bus) []string {
	var out []string
	for _, event := range bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "antispoof.ready" }, 0) {
		out = append(out, event.Attrs["ready"])
	}
	return out
}

// overlay is a valid overlay list of both families
func overlay(t *testing.T, raw ...string) *egress.Border {
	t.Helper()
	if len(raw) == 0 {
		raw = []string{"198.18.0.0/15", "3fff::/20"}
	}
	return &egress.Border{Overlay: prefixes(t, raw...)}
}

// ranges is the addresses of raw's prefixes as ranges
func ranges(raw ...string) []egress.Range {
	prefixes := make([]netip.Prefix, 0, len(raw))
	for _, text := range raw {
		prefixes = append(prefixes, netip.MustParsePrefix(text))
	}
	return meshkernel.Ranges(prefixes)
}

// runBorder runs f until the test ends
func runBorder(t *testing.T, f *BorderFilter) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- f.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
}

// waitForPass waits for an antispoof.pass event woken by trigger
func waitForPass(t *testing.T, bus *events.Bus, trigger string) {
	t.Helper()
	for deadline := time.Now().Add(passWait); ; time.Sleep(passPoll) {
		var triggers []string
		for _, event := range bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "antispoof.pass" }, 0) {
			triggers = append(triggers, event.Attrs["trigger"])
		}
		if slices.Contains(triggers, trigger) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the antispoof filter recorded passes woken by %q, none by %s", triggers, trigger)
		}
	}
}

// The chain takes everything arriving on a device inside the mesh before it
// drops anything, then drops by source, the list in one order whatever order
// it was written in, with no carved drop while no carve-out exists
func TestBorderChainAcceptsTheInsideBeforeAnyDrop(t *testing.T) {
	be := &fakeBorder{}
	rt := borderRuntime(nil)
	rt.Inside = []string{"ranet0", "lo", "dummy0"}
	f, err := startBorderFilter(overlay(t, "3fff::/20", "198.18.0.0/15", "192.0.2.0/24"), rt, be)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"accept via ranet0",
		"accept via lo",
		"accept via dummy0",
		"drop ipv4 source 192.0.2.0/24",
		"drop ipv4 source 198.18.0.0/15",
		"drop ipv6 source 3fff::/20",
	}
	if got := be.specs(); !slices.Equal(got, want) {
		t.Errorf("installed %q, want %q", got, want)
	}
	if !f.Stats().Ready || f.Stats().Installed != len(want)+entryRules {
		t.Errorf("the pass reports %+v, want ready with %d rules", f.Stats(), len(want)+entryRules)
	}
}

// The entry chain lets a packet leave by the tun only as a reply, toward a
// link-local or multicast IPv6 destination, from a source this node owns or
// toward a none class's destination, family by family, and drops the rest,
// counted. A node with no overlay holds the entry chain alone, and the table
// is made again whole on every rewrite with or without one.
func TestEntryChainRunsWithAndWithoutTheBorder(t *testing.T) {
	want := []string{
		"return via other than ranet0",
		"return a reply",
		"return ipv6 to fe80::/10",
		"return ipv6 to ff00::/8",
		"return ipv4 source @owned4",
		"return ipv6 source @owned6",
		"return ipv4 to @none4",
		"return ipv6 to @none6",
		"drop ipv4 entering the mesh",
		"drop ipv6 entering the mesh",
	}
	for _, cfg := range []*egress.Border{overlay(t), nil} {
		be := &fakeBorder{}
		f, err := startBorderFilter(cfg, borderRuntime(nil), be)
		if err != nil {
			t.Fatal(err)
		}
		var entry []string
		for _, rule := range be.held {
			if !slices.Contains(be.specs(), rule.Spec) {
				entry = append(entry, rule.Spec)
			}
		}
		if !slices.Equal(entry, want) {
			t.Errorf("with overlay %v the entry chain holds %q, want %q", cfg, entry, want)
		}
		if bordered := len(be.specs()) != 0; bordered != (cfg != nil) {
			t.Errorf("with overlay %v the antispoof chain holds %q", cfg, be.specs())
		}
		if be.entries()[1] != "apply" || !f.ready {
			t.Errorf("with overlay %v the start went %q", cfg, be.entries())
		}
	}
}

// The sets follow what the runtime derives: a pass that finds them moved
// moves the moved ones alone, from what the table holds, and rewrites no
// chain, a pass woken by the mesh's table that finds nothing moved reads
// nothing, and another writer's change to a set's elements has the whole table
// rewritten
func TestBorderRefillsTheSetsThatMovedAlone(t *testing.T) {
	derived := egress.BorderSets{Owned: ranges("192.0.2.1/32")}
	rt := borderRuntime(nil)
	rt.Sets = func(*egress.Border) egress.BorderSets { return derived }
	be := &fakeBorder{}
	f, err := startBorderFilter(nil, rt, be)
	if err != nil {
		t.Fatal(err)
	}
	if got := be.sets[ownedSet+"4"]; !slices.Equal(got, derived.Owned) {
		t.Fatalf("the start wrote owned4 %v, want %v", got, derived.Owned)
	}
	f.trigger = "routes"
	mark := len(be.entries())
	if err := f.reconcile(); err != nil || len(be.entries()) != mark {
		t.Errorf("a pass that found nothing moved went %q with %v", be.entries()[mark:], err)
	}
	derived.Owned = append(derived.Owned, ranges("2001:db8::/48")...)
	derived.None = ranges("203.0.113.0/24")
	if err := f.reconcile(); err != nil {
		t.Fatal(err)
	}
	if got, want := be.entries()[mark:], []string{"rules", "fill none4 owned6", "rules"}; !slices.Equal(got, want) || !f.ready {
		t.Errorf("a pass with two sets moved went %q, ready %v, want %q", got, f.ready, want)
	}
	be.mu.Lock()
	be.sets[noneSet+"4"] = nil
	be.mu.Unlock()
	mark = len(be.entries())
	f.trigger = "changed"
	if err := f.reconcile(); err != nil {
		t.Fatal(err)
	}
	if got, want := be.entries()[mark:], []string{"rules", "apply", "rules"}; !slices.Equal(got, want) || !f.ready {
		t.Errorf("a pass after another writer emptied a set went %q, ready %v, want %q", got, f.ready, want)
	}
}

// Each pass derives its sets from the configuration it writes the rules
// from, the one the last SetConfig handed the filter, nil where overlay is
// not written
func TestBorderDerivesTheSetsFromTheConfigurationItRuns(t *testing.T) {
	var read []*egress.Border
	rt := borderRuntime(nil)
	rt.Sets = func(cfg *egress.Border) egress.BorderSets {
		read = append(read, cfg)
		return egress.BorderSets{}
	}
	if _, err := startBorderFilter(nil, rt, &fakeBorder{}); err != nil || len(read) != 1 || read[0] != nil {
		t.Fatalf("with no overlay the start derived the sets from %v, %v", read, err)
	}
	read = nil
	f, err := startBorderFilter(overlay(t), rt, &fakeBorder{})
	if err != nil {
		t.Fatal(err)
	}
	next := *overlay(t)
	next.Antispoof = egress.Antispoof{Interface: map[string]egress.AntispoofInterface{"eth1": {Exempt: prefixes(t, "198.18.1.0/24")}}}
	next.Own, next.Addresses = []netip.Prefix{netip.MustParsePrefix("198.18.1.0/25")}, []netip.Prefix{netip.MustParsePrefix("198.18.1.200/32")}
	if err := f.SetConfig(next); err != nil {
		t.Fatal(err)
	}
	if err := f.reconcile(); err != nil {
		t.Fatal(err)
	}
	if len(read) != 2 || read[1] == nil || !reflect.DeepEqual(*read[1], next) {
		t.Errorf("the pass after SetConfig derived the sets from %+v, want %+v", read, next)
	}
}

// A carve-out is accepted from its own link ahead of the overlay's drops and
// behind the drop of the mesh's prefixes inside any carve-out of its family,
// which a family with no carve-out leaves out, and each one coming and going
// is reported once, at warning and at info, with an event
func TestBorderCarveOutIsAcceptedFromItsLinkAndReportedOnce(t *testing.T) {
	var lines strings.Builder
	logtest.SetDefault(t, slog.New(slog.NewTextHandler(&lines, nil)))
	bus := events.New()
	lease := egress.CarveOut{Link: "eth0", Prefix: netip.MustParsePrefix("198.18.0.0/24")}
	derived := egress.BorderSets{CarveOuts: []egress.CarveOut{lease}, Carved: ranges("198.18.0.5/32")}
	rt := borderRuntime(bus)
	rt.Sets = func(*egress.Border) egress.BorderSets { return derived }
	be := &fakeBorder{}
	f, err := startBorderFilter(overlay(t), rt, be)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"accept via ranet0",
		"accept via lo",
		"drop ipv4 source @carved4",
		"accept via eth0 source 198.18.0.0/24",
		"drop ipv4 source 198.18.0.0/15",
		"drop ipv6 source 3fff::/20",
	}
	if got := be.specs(); !slices.Equal(got, want) {
		t.Errorf("installed %q, want %q", got, want)
	}
	if got := be.sets[carvedSet+"4"]; !slices.Equal(got, derived.Carved) {
		t.Errorf("carved4 holds %v, want %v", got, derived.Carved)
	}
	if got := f.Stats().CarveOuts; !slices.Equal(got, derived.CarveOuts) {
		t.Errorf("the status names the carve-outs %v, want %v", got, derived.CarveOuts)
	}
	f.reconcile()
	derived = egress.BorderSets{}
	f.reconcile()
	f.reconcile()
	if got := be.specs(); slices.Contains(got, "drop ipv4 source @carved4") {
		t.Errorf("with the carve-out gone the chain holds %q, its carved drop among them", got)
	}
	var got []string
	for _, event := range bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "antispoof.carve" }, 0) {
		got = append(got, event.Attrs["link"]+" "+event.Attrs["prefix"]+" "+event.Attrs["carved"])
	}
	if want := []string{"eth0 198.18.0.0/24 true", "eth0 198.18.0.0/24 false"}; !slices.Equal(got, want) {
		t.Errorf("recorded antispoof.carve %q, want %q", got, want)
	}
	if strings.Count(lines.String(), "level=WARN msg=\"antispoof carves the overlay for a link that holds part of it\"") != 1 ||
		strings.Count(lines.String(), "level=INFO msg=\"antispoof no longer carves the overlay for a link\"") != 1 {
		t.Errorf("the carve-out was not logged once each way:\n%s", lines.String())
	}
}

// Another node's prefix coming to overlap an exemption is reported once, at
// warning with an event naming the exemption, the prefix, its part the carved
// sets take, the peer it is routed via and the selected route's router-id,
// and its end at info with no event
func TestBorderExemptionConflictIsReportedOnce(t *testing.T) {
	var lines strings.Builder
	logtest.SetDefault(t, slog.New(slog.NewTextHandler(&lines, nil)))
	bus := events.New()
	p := netip.MustParsePrefix
	conflict := egress.ExemptConflict{Exemption: egress.Exemption{Interface: "eth1", Prefix: p("198.18.0.0/25")}, Prefix: p("198.18.0.64/28"), Carved: p("198.18.0.64/28"), Via: "example/peer", RouterID: "0102030405060708"}
	derived := egress.BorderSets{Carved: ranges("198.18.0.64/28"), Conflicts: []egress.ExemptConflict{conflict}}
	rt := borderRuntime(bus)
	rt.Sets = func(*egress.Border) egress.BorderSets { return derived }
	cfg := overlay(t)
	cfg.Antispoof = egress.Antispoof{Interface: map[string]egress.AntispoofInterface{"eth1": {Exempt: []schema.Prefix{schema.MustPrefix("198.18.0.0/25")}}}}
	f, err := startBorderFilter(cfg, rt, &fakeBorder{})
	if err != nil {
		t.Fatal(err)
	}
	f.reconcile()
	derived = egress.BorderSets{}
	f.reconcile()
	f.reconcile()
	var got []string
	for _, event := range bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "antispoof.conflict" }, 0) {
		got = append(got, strings.Join([]string{event.Attrs["exemption"], event.Attrs["interface"], event.Attrs["prefix"], event.Attrs["carved"], event.Attrs["routed_via"], event.Attrs["router_id"]}, " "))
	}
	if want := []string{"198.18.0.0/25 eth1 198.18.0.64/28 198.18.0.64/28 example/peer 0102030405060708"}; !slices.Equal(got, want) {
		t.Errorf("recorded antispoof.conflict %q, want %q", got, want)
	}
	if strings.Count(lines.String(), "level=WARN msg=\"antispoof drops part of an exemption, since another node's prefix holds it\"") != 1 ||
		strings.Count(lines.String(), "level=INFO msg=\"antispoof no longer drops part of an exemption for another node's prefix\"") != 1 {
		t.Errorf("the conflict was not logged once each way:\n%s", lines.String())
	}
}

// A conflict read through routes from two sources at once, whose route then
// moves to another peer and another router-id between two passes, and which a
// second source joins again, drops what it dropped, so the filter reports it
// once, the event naming the first route it read, and logs its end once, when
// the carved sets no longer hold it
func TestBorderExemptionConflictMovingItsRouteIsReportedOnce(t *testing.T) {
	var lines strings.Builder
	logtest.SetDefault(t, slog.New(slog.NewTextHandler(&lines, nil)))
	bus := events.New()
	p := netip.MustParsePrefix
	conflict := egress.ExemptConflict{Exemption: egress.Exemption{Interface: "eth1", Prefix: p("198.18.0.0/25")}, Prefix: p("198.18.0.64/28"), Carved: p("198.18.0.64/28"), Via: "example/peer-a", RouterID: "0102030405060708"}
	// the same drop the first pass reads through a route from another source too
	alongside := conflict
	alongside.Via = "example/peer-c"
	derived := egress.BorderSets{Carved: ranges("198.18.0.64/28"), Conflicts: []egress.ExemptConflict{conflict, alongside}}
	rt := borderRuntime(bus)
	rt.Sets = func(*egress.Border) egress.BorderSets { return derived }
	cfg := overlay(t)
	cfg.Antispoof = egress.Antispoof{Interface: map[string]egress.AntispoofInterface{"eth1": {Exempt: []schema.Prefix{schema.MustPrefix("198.18.0.0/25")}}}}
	f, err := startBorderFilter(cfg, rt, &fakeBorder{})
	if err != nil {
		t.Fatal(err)
	}
	moved := conflict
	moved.Via, moved.RouterID = "example/peer-b", "0807060504030201"
	derived.Conflicts = []egress.ExemptConflict{moved}
	f.reconcile()
	f.reconcile()
	if strings.Contains(lines.String(), "antispoof no longer drops part of an exemption") {
		t.Errorf("the filter logged the end of a drop whose route moved while the carved sets hold it:\n%s", lines.String())
	}
	joined := moved
	joined.Via = "example/peer-c"
	derived.Conflicts = []egress.ExemptConflict{moved, joined}
	f.reconcile()
	derived = egress.BorderSets{}
	f.reconcile()
	var got []string
	for _, event := range bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "antispoof.conflict" }, 0) {
		got = append(got, event.Attrs["routed_via"]+" "+event.Attrs["router_id"])
	}
	if want := []string{"example/peer-a 0102030405060708"}; !slices.Equal(got, want) {
		t.Errorf("recorded antispoof.conflict %q for one drop whose route moved, want %q", got, want)
	}
	if strings.Count(lines.String(), "level=WARN msg=\"antispoof drops part of an exemption, since another node's prefix holds it\"") != 1 ||
		strings.Count(lines.String(), "level=INFO msg=\"antispoof no longer drops part of an exemption for another node's prefix\"") != 1 {
		t.Errorf("a drop whose route moved was not logged once each way:\n%s", lines.String())
	}
}

// Another node's prefix inside one exemption written under two interfaces is
// two drops, each reported once, and the end of one is logged while the other
// stays
func TestBorderExemptionConflictUnderTwoInterfacesIsTwoReports(t *testing.T) {
	var lines strings.Builder
	logtest.SetDefault(t, slog.New(slog.NewTextHandler(&lines, nil)))
	bus := events.New()
	p := netip.MustParsePrefix
	on := func(name string) egress.ExemptConflict {
		return egress.ExemptConflict{Exemption: egress.Exemption{Interface: name, Prefix: p("198.18.0.0/25")}, Prefix: p("198.18.0.64/28"), Carved: p("198.18.0.64/28"), Via: "example/peer"}
	}
	derived := egress.BorderSets{Carved: ranges("198.18.0.64/28"), Conflicts: []egress.ExemptConflict{on("eth1"), on("eth2")}}
	rt := borderRuntime(bus)
	rt.Sets = func(*egress.Border) egress.BorderSets { return derived }
	cfg := overlay(t)
	cfg.Antispoof = egress.Antispoof{Interface: map[string]egress.AntispoofInterface{
		"eth1": {Exempt: []schema.Prefix{schema.MustPrefix("198.18.0.0/25")}},
		"eth2": {Exempt: []schema.Prefix{schema.MustPrefix("198.18.0.0/25")}},
	}}
	f, err := startBorderFilter(cfg, rt, &fakeBorder{})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, event := range bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "antispoof.conflict" }, 0) {
		got = append(got, event.Attrs["interface"])
	}
	if want := []string{"eth1", "eth2"}; !slices.Equal(got, want) {
		t.Errorf("one prefix under the exemption of eth1 and of eth2 recorded antispoof.conflict for %q, want %q", got, want)
	}
	started := lines.Len()
	derived.Conflicts = []egress.ExemptConflict{on("eth1")}
	f.reconcile()
	var ends []string
	for line := range strings.SplitSeq(lines.String()[started:], "\n") {
		if strings.Contains(line, "antispoof no longer drops part of an exemption") {
			ends = append(ends, line)
		}
	}
	if len(ends) != 1 || !strings.Contains(ends[0], "interface=eth2 prefix=198.18.0.64/28") {
		t.Errorf("eth2's drop went while eth1's stayed and the filter logged the ends %q:\n%s", ends, lines.String())
	}
}

// The chain accepts the inside, drops the carved sets' sources of each family
// with a carve-out or an exemption, accepts the carve-outs and then the
// exemptions, the shared ones first and then each interface's by name, each
// list in one order whatever order it was written in, and drops the overlay
// last. A family exempted with no carve-out holds its carved drop, and one
// neither carved nor exempted holds none.
func TestBorderAcceptsExemptionsBehindTheCarvedDropAndTheCarveOuts(t *testing.T) {
	cfg := overlay(t, "198.18.0.0/15", "3fff::/20")
	cfg.Antispoof = egress.Antispoof{
		Exempt: prefixes(t, "3fff:0:1::/48", "198.18.1.0/24"),
		Interface: map[string]egress.AntispoofInterface{
			"wl*":  {Exempt: prefixes(t, "198.18.3.0/24", "198.18.2.0/24")},
			"eth1": {Exempt: prefixes(t, "198.18.4.0/24")},
		},
	}
	lease := egress.CarveOut{Link: "eth0", Prefix: netip.MustParsePrefix("198.18.0.0/24")}
	rt := borderRuntime(nil)
	rt.Sets = func(*egress.Border) egress.BorderSets { return egress.BorderSets{CarveOuts: []egress.CarveOut{lease}} }
	be := &fakeBorder{}
	f, err := startBorderFilter(cfg, rt, be)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"accept via ranet0",
		"accept via lo",
		"drop ipv4 source @carved4",
		"drop ipv6 source @carved6",
		"accept via eth0 source 198.18.0.0/24",
		"accept exempt source 198.18.1.0/24",
		"accept exempt source 3fff:0:1::/48",
		"accept exempt via eth1 source 198.18.4.0/24",
		"accept exempt via wl* source 198.18.2.0/24",
		"accept exempt via wl* source 198.18.3.0/24",
		"drop ipv4 source 198.18.0.0/15",
		"drop ipv6 source 3fff::/20",
	}
	if got := be.specs(); !slices.Equal(got, want) || !f.ready {
		t.Errorf("installed %q, ready %v, want %q", got, f.ready, want)
	}
	for _, chain := range f.Debug().Chains {
		for _, rule := range chain.Rules {
			if strings.HasPrefix(rule.Spec, "accept exempt") && (rule.Verdict != "accept" || rule.Reason != "exempt") {
				t.Errorf("%s reads verdict %q and reason %q, want accept and exempt", rule.Spec, rule.Verdict, rule.Reason)
			}
		}
	}
	// an IPv6 exemption alone carves IPv6 alone
	cfg = overlay(t, "198.18.0.0/15", "3fff::/20")
	cfg.Antispoof = egress.Antispoof{Interface: map[string]egress.AntispoofInterface{"eth1": {Exempt: prefixes(t, "3fff:0:1::/48")}}}
	be = &fakeBorder{}
	if _, err := startBorderFilter(cfg, borderRuntime(nil), be); err != nil {
		t.Fatal(err)
	}
	want = []string{
		"accept via ranet0",
		"accept via lo",
		"drop ipv6 source @carved6",
		"accept exempt via eth1 source 3fff:0:1::/48",
		"drop ipv4 source 198.18.0.0/15",
		"drop ipv6 source 3fff::/20",
	}
	if got := be.specs(); !slices.Equal(got, want) {
		t.Errorf("with an IPv6 exemption alone installed %q, want %q", got, want)
	}
}

// A change of the host's links wakes a pass well inside a sweep: a lease
// overlapping the overlay that comes is carved, its accept and its carved drop
// written and its mesh prefixes in the carved set, and one that goes takes
// them with it
func TestBorderFollowsTheHostsLinksBetweenSweeps(t *testing.T) {
	lease := egress.BorderSets{CarveOuts: []egress.CarveOut{{Link: "eth0", Prefix: netip.MustParsePrefix("198.18.0.0/24")}}, Carved: ranges("198.18.0.5/32")}
	var mu sync.Mutex
	derived := egress.BorderSets{}
	network := make(chan struct{}, 1)
	rt := borderRuntime(nil)
	rt.Sets = func(*egress.Border) egress.BorderSets {
		mu.Lock()
		defer mu.Unlock()
		return derived
	}
	rt.Network = network
	be := &fakeBorder{}
	f, err := startBorderFilter(overlay(t), rt, be)
	if err != nil {
		t.Fatal(err)
	}
	f.sweep = lateSweep
	runBorder(t, f)
	carved := func() bool {
		be.mu.Lock()
		set := slices.Clone(be.sets[carvedSet+"4"])
		be.mu.Unlock()
		specs := be.specs()
		return slices.Contains(specs, "accept via eth0 source 198.18.0.0/24") && slices.Contains(specs, "drop ipv4 source @carved4") && slices.Equal(set, lease.Carved)
	}
	for _, step := range []struct {
		what string
		sets egress.BorderSets
		want bool
	}{{"a lease that came", lease, true}, {"a lease that went", egress.BorderSets{}, false}} {
		mu.Lock()
		derived = step.sets
		mu.Unlock()
		network <- struct{}{}
		for deadline := time.Now().Add(passWait); carved() != step.want; time.Sleep(passPoll) {
			if time.Now().After(deadline) {
				t.Fatalf("after %s the chain holds %q, carved %v, want carved %v", step.what, be.specs(), carved(), step.want)
			}
		}
	}
}

// Validation runs in this package, so an overlay list sent by a control plane
// is judged by the rules a written one is
func TestBorderRefusesWhatWouldNotFilter(t *testing.T) {
	for _, one := range []struct {
		name string
		cfg  *egress.Border
		want string
	}{
		{"an empty overlay", &egress.Border{}, "overlay is empty, so the antispoof filter would pass every forged mesh source"},
		{"an entry that is not a prefix", &egress.Border{Overlay: []schema.Prefix{{}}}, "is not a prefix"},
		{"bits below the length", &egress.Border{Overlay: []schema.Prefix{schema.MustPrefix("198.18.0.1/15")}}, "has bits set below its prefix length"},
		{"an IPv4 prefix written as IPv6", overlay(t, "::ffff:198.18.0.0/111"), "written as IPv6, so write it as 198.18.0.0/15"},
		{"every IPv4 address", overlay(t, "0.0.0.0/0"), "covers every address of its family"},
		{"every IPv6 address", overlay(t, "::/0"), "covers every address of its family"},
		{"an IPv4 prefix under the floor", overlay(t, "8.0.0.0/7"), "is shorter than /8 for IPv4 or /12 for IPv6"},
		{"an IPv6 prefix under the floor", overlay(t, "2000::/11"), "is shorter than /8 for IPv4 or /12 for IPv6"},
		{"an entry written twice", overlay(t, "198.18.0.0/15", "3fff::/20", "198.18.0.0/15"), "198.18.0.0/15 is written twice"},
	} {
		t.Run(one.name, func(t *testing.T) {
			f := newBorderFilter(overlay(t), borderRuntime(nil), &fakeBorder{})
			err := f.SetConfig(*one.cfg)
			if err == nil || !strings.Contains(err.Error(), one.want) {
				t.Fatalf("refused with %v, want a message containing %q", err, one.want)
			}
			if got := f.Capability(); len(got.Overlay) != 2 {
				t.Errorf("a refused reload left the filter at %v, want the overlay it ran", got)
			}
			if err := one.cfg.Validate(); err == nil || !strings.Contains(err.Error(), one.want) {
				t.Errorf("Validate refused with %v, want a message containing %q", err, one.want)
			}
		})
	}
	// each floor is the shortest prefix taken, not the longest refused
	if err := overlay(t, "10.0.0.0/8", "2000::/12", "192.0.2.7/32", "3fff::7/128").Validate(); err != nil {
		t.Errorf("an overlay at the floors and at full length was refused: %v", err)
	}
}

// The filter runs only with a device inside the mesh, the tun at least, since
// a chain with no accept would drop the mesh's own traffic on every hop
func TestBorderNeedsTheDevicesInsideTheMesh(t *testing.T) {
	_, err := NewBorderFilter(overlay(t), egress.BorderRuntime{})
	if err == nil || !strings.Contains(err.Error(), "needs the devices inside the mesh") {
		t.Fatalf("NewBorderFilter returned %v, want the missing inside list refused", err)
	}
}

// A node that asked for the filter does not start without it: the first pass
// runs before NewBorderFilter returns, and a chain that will not install or
// does not read back as written refuses the start, which withdraws a table the
// pass made and leaves any other: one it found, which the log names as left,
// and whatever is there where the first read failed, which it names nothing of.
// The log names a table withdrawn only where one went, which a first write
// that failed on a host with none leaves out.
func TestNewBorderRefusesAChainItCannotReadBack(t *testing.T) {
	for _, one := range []struct {
		name      string
		be        *fakeBorder
		want      string
		withdrawn int
		named     bool
		gone      bool
	}{
		{"a chain the host will not take", &fakeBorder{failApply: true}, "could not be installed in nftables table inet ranet3 chains antispoof and mesh_entry: install rules: no", 1, false, false},
		{"a chain that reads back otherwise", &fakeBorder{garble: true}, "is not ready, since its chains read back other than they were written", 1, false, true},
		{"a found table the host will not let be rewritten", &fakeBorder{failApply: true, fault: "its table holds no chain"}, "install rules: no", 0, true, false},
		{"a table the first read cannot list", &fakeBorder{failRules: true}, "list rules: no", 0, false, false},
	} {
		t.Run(one.name, func(t *testing.T) {
			var lines strings.Builder
			logtest.SetDefault(t, slog.New(slog.NewTextHandler(&lines, nil)))
			bus := events.New()
			f, err := startBorderFilter(overlay(t), borderRuntime(bus), one.be)
			if err == nil || !strings.Contains(err.Error(), one.want) {
				t.Fatalf("the start returned %v, want a refusal containing %q", err, one.want)
			}
			if f != nil {
				t.Error("a refused start handed back a filter")
			}
			if one.be.withdrawn != one.withdrawn {
				t.Errorf("the refused start withdrew %d times, want %d", one.be.withdrawn, one.withdrawn)
			}
			if named := strings.Contains(lines.String(), "antispoof filter is leaving the table it found"); named != one.named {
				t.Errorf("the refused start named a table it found as left %t, want %t:\n%s", named, one.named, lines.String())
			}
			if gone := strings.Contains(lines.String(), "antispoof filter withdrawn"); gone != one.gone {
				t.Errorf("the refused start named a table withdrawn %t, want %t:\n%s", gone, one.gone, lines.String())
			}
			if moves := readyMoves(bus); slices.Contains(moves, "true") {
				t.Errorf("the refused start reported the antispoof filter ready: %q", moves)
			}
		})
	}
	bus := events.New()
	be := &fakeBorder{}
	if _, err := startBorderFilter(overlay(t), borderRuntime(bus), be); err != nil {
		t.Fatal(err)
	}
	if got, moves := be.entries(), readyMoves(bus); !slices.Equal(got, []string{"rules", "apply", "rules"}) || !slices.Equal(moves, []string{"true"}) {
		t.Errorf("the start went %q with readiness moving %q, want a pass that installs and reads back, then ready", got, moves)
	}
}

// A filter closed before it ran reports itself not ready, withdraws the table
// its first pass made, and leaves one the pass found, whether it took that
// over as it was or rewrote it
func TestBorderClosedBeforeItRanLeavesOnlyTheTableItFound(t *testing.T) {
	for _, one := range []struct {
		name      string
		found     func(*fakeBorder)
		withdrawn int
	}{
		{"none found", func(*fakeBorder) {}, 1},
		{"one taken over", func(be *fakeBorder) {
			if _, err := startBorderFilter(overlay(t), borderRuntime(nil), be); err != nil {
				t.Fatal(err)
			}
		}, 0},
		{"one rewritten", func(be *fakeBorder) { be.fault = "its table holds no chain" }, 0},
	} {
		t.Run(one.name, func(t *testing.T) {
			be := &fakeBorder{}
			one.found(be)
			bus := events.New()
			f, err := startBorderFilter(overlay(t), borderRuntime(bus), be)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			if be.withdrawn != one.withdrawn {
				t.Errorf("the filter closed before it ran withdrew %d times, want %d", be.withdrawn, one.withdrawn)
			}
			if got, want := readyMoves(bus), []string{"true", "false"}; !slices.Equal(got, want) {
				t.Errorf("the antispoof filter's readiness moved %q, want %q", got, want)
			}
		})
	}
}

// A pass that rewrote the chain or failed is recorded with what woke it, and
// a quiet one is not
func TestBorderRecordsThePassesThatDidSomething(t *testing.T) {
	bus := events.New()
	be := &fakeBorder{}
	f := newBorderFilter(overlay(t), borderRuntime(bus), be)
	f.trigger = "sweep"
	f.reconcile()
	f.reconcile()
	be.held = nil
	be.failApply = true
	f.reconcile()
	var got [][]string
	for _, event := range bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "antispoof.pass" }, 0) {
		if event.Attrs["took"] == "" || event.Attrs["trigger"] != "sweep" {
			t.Errorf("a pass was recorded without its trigger or duration: %+v", event)
		}
		got = append(got, []string{event.Attrs["installed"], event.Attrs["err"]})
	}
	// the two inside accepts and the overlay's two drops, with no carve-out and so no carved drop
	if want := [][]string{{fmt.Sprint(4 + entryRules), ""}, {"0", "install rules: no"}}; !slices.EqualFunc(got, want, slices.Equal) {
		t.Errorf("the antispoof filter recorded %q, want %q", got, want)
	}
}

// Each pass reads the drop counters and records what each class dropped
// since the pass before, once, and only on a pass in which one moved, and
// logs nothing of it
func TestBorderReportsDropsOncePerPass(t *testing.T) {
	var lines strings.Builder
	logtest.SetDefault(t, slog.New(slog.NewTextHandler(&lines, nil)))
	bus := events.New()
	be := &fakeBorder{}
	// an IPv4 carve-out, so the chain holds the IPv4 carved drop
	rt := borderRuntime(bus)
	rt.Sets = func(*egress.Border) egress.BorderSets {
		return egress.BorderSets{CarveOuts: []egress.CarveOut{{Link: "eth0", Prefix: netip.MustParsePrefix("198.18.0.0/24")}}}
	}
	f := newBorderFilter(overlay(t), rt, be)
	f.reconcile()
	be.setCount("drop ipv4 source 198.18.0.0/15", 3)
	f.reconcile()
	f.reconcile()
	be.setCount("drop ipv4 source 198.18.0.0/15", 5)
	be.setCount("drop ipv6 source 3fff::/20", 2)
	be.setCount("drop ipv4 source @carved4", 1)
	be.setCount("drop ipv6 entering the mesh", 4)
	// another writer flushed the chain, so this pass lists, rewrites and reads back
	be.mu.Lock()
	be.held = nil
	be.mu.Unlock()
	f.reconcile()
	var got []string
	for _, event := range bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "antispoof.dropped" }, 0) {
		var counts []string
		for _, kind := range egress.BorderDropKinds {
			counts = append(counts, event.Attrs[kind.Name()])
		}
		got = append(got, strings.Join(counts, " "))
	}
	if want := []string{"3 0 0 0 0 0", "2 2 1 0 0 4"}; !slices.Equal(got, want) {
		t.Errorf("recorded antispoof.dropped %q, want %q", got, want)
	}
	// the event and the counters carry the drops, so no pass logs them
	if strings.Contains(lines.String(), "dropped packets") {
		t.Errorf("a pass logged the drops:\n%s", lines.String())
	}
	if want := (egress.BorderDrops{5, 2, 1, 0, 0, 4}); f.Stats().Dropped != want {
		t.Errorf("the last pass reports %+v dropped, want %+v", f.Stats().Dropped, want)
	}
}

// A counter below its last reading is a chain rewritten in between, which
// starts its counters from zero, so what it reads is all new
func TestBorderDropsAfterARewriteCountFromZero(t *testing.T) {
	was := egress.BorderDrops{10, 4}
	now := egress.BorderDrops{2, 6}
	if got, want := dropsSince(now, was), (egress.BorderDrops{2, 2}); got != want {
		t.Errorf("read %+v since %+v as %+v, want %+v", now, was, got, want)
	}
}

// Another writer changing the filter's table wakes it, and it reports the
// border not ready before the pass that puts the chain back and ready again
// after it, with no sweep due
func TestAnotherWritersChangeTakesTheBorderDownUntilThePassRestoresIt(t *testing.T) {
	bus := events.New()
	be := &fakeBorder{changed: make(chan struct{}, 1)}
	f, err := startBorderFilter(overlay(t), borderRuntime(bus), be)
	if err != nil {
		t.Fatal(err)
	}
	f.sweep = lateSweep
	runBorder(t, f)
	be.mu.Lock()
	be.held = nil
	be.mu.Unlock()
	mark := len(be.entries())
	be.changed <- struct{}{}
	waitForPass(t, bus, "changed")
	if got, want := be.entries()[mark:], []string{"rules", "apply", "rules"}; !slices.Equal(got, want) {
		t.Errorf("after the change the antispoof filter went %q, want %q", got, want)
	}
	if got, want := readyMoves(bus), []string{"true", "false", "true"}; !slices.Equal(got, want) {
		t.Errorf("the antispoof filter's readiness moved %q, want %q", got, want)
	}
}

// A rule another writer put in the chain, read back with no comment wherever
// it sits, the chain's rules in another order, and a table or a chain whose
// settings read back other than written each make the pass rewrite them,
// after which the filter reads ready. A chain nf_tables will not change in
// place is rewritten by deleting the table first. A setting the rewrite cannot
// put back leaves the filter not ready, naming it.
func TestBorderRewritesWhatReadsBackOtherThanWritten(t *testing.T) {
	be := &fakeBorder{}
	f, err := startBorderFilter(overlay(t), borderRuntime(nil), be)
	if err != nil {
		t.Fatal(err)
	}
	const dormant = "its table carries flags 0x1, where none are written and 0x1 is dormant"
	for _, change := range []struct {
		name  string
		apply func()
		pass  []string
	}{
		{"a rule with no comment at the head of the chain", func() { be.held = append([]Installed{{}}, be.held...) }, []string{"rules", "apply", "rules"}},
		{"a rule with no comment at the tail of the chain", func() { be.held = append(be.held, Installed{}) }, []string{"rules", "apply", "rules"}},
		{"the chain's rules in another order", func() { slices.Reverse(be.held) }, []string{"rules", "apply", "rules"}},
		{"a table set dormant", func() { be.fault = dormant }, []string{"rules", "apply", "rules"}},
		{"the chain made again at another priority", func() { be.fault = "its chain reads back at priority 0" }, []string{"rules", "apply", "rules"}},
	} {
		be.mu.Lock()
		change.apply()
		be.mu.Unlock()
		mark := len(be.entries())
		if err := f.reconcile(); err != nil {
			t.Fatalf("%s: %v", change.name, err)
		}
		if got := be.entries()[mark:]; !slices.Equal(got, change.pass) || !f.ready {
			t.Errorf("%s: the pass went %q and left the filter ready %v, want %q and ready", change.name, got, f.ready, change.pass)
		}
	}
	be.mu.Lock()
	be.fault, be.stuck = dormant, true
	be.mu.Unlock()
	if err := f.reconcile(); err != nil {
		t.Fatal(err)
	}
	if f.ready || f.unready != dormant || f.Stats().Unready != dormant {
		t.Errorf("a table the rewrite leaves dormant reads ready %v, unready %q", f.ready, f.unready)
	}
}

// Notifications the backend lost wake a pass with no sweep due that puts back
// whatever a lost deletion took, and never report the border not ready, since
// another table's large transaction overflows the socket as readily as a flush
// of this one
func TestMissedNotificationsWakeTheBorderAndLeaveItReady(t *testing.T) {
	bus := events.New()
	be := &fakeBorder{missed: make(chan struct{}, 1)}
	f, err := startBorderFilter(overlay(t), borderRuntime(bus), be)
	if err != nil {
		t.Fatal(err)
	}
	f.sweep = lateSweep
	runBorder(t, f)
	be.mu.Lock()
	be.held = nil
	be.mu.Unlock()
	mark := len(be.entries())
	be.missed <- struct{}{}
	waitForPass(t, bus, "missed")
	if got, want := be.entries()[mark:], []string{"rules", "apply", "rules"}; !slices.Equal(got, want) {
		t.Errorf("after the lost notifications the antispoof filter went %q, want %q", got, want)
	}
}

// A reload hands the filter a new overlay, and the run goroutine rewrites the
// chain at once rather than at the next sweep
func TestBorderReloadRewritesTheChainInPlace(t *testing.T) {
	bus := events.New()
	be := &fakeBorder{}
	f, err := startBorderFilter(overlay(t), borderRuntime(bus), be)
	if err != nil {
		t.Fatal(err)
	}
	f.sweep = lateSweep
	runBorder(t, f)
	if err := f.SetConfig(*overlay(t, "192.0.2.0/24")); err != nil {
		t.Fatal(err)
	}
	waitForPass(t, bus, "reload")
	want := []string{"accept via ranet0", "accept via lo", "drop ipv4 source 192.0.2.0/24"}
	if got := be.specs(); !slices.Equal(got, want) {
		t.Errorf("after the reload the chain holds %q, want %q", got, want)
	}
}

// A pass that fails is tried again on the backoff rather than at the next sweep
func TestBorderRetriesAFailedPass(t *testing.T) {
	bus := events.New()
	be := &fakeBorder{changed: make(chan struct{}, 1)}
	f, err := startBorderFilter(overlay(t), borderRuntime(bus), be)
	if err != nil {
		t.Fatal(err)
	}
	f.sweep = lateSweep
	be.mu.Lock()
	be.held, be.failApply = nil, true
	be.mu.Unlock()
	runBorder(t, f)
	be.changed <- struct{}{}
	waitForPass(t, bus, "retry")
}

// A filter that stops reports the border not ready and withdraws its table,
// and Run returns the withdrawal's error
func TestBorderStopsNotReadyAndWithdraws(t *testing.T) {
	for _, failing := range []bool{false, true} {
		bus := events.New()
		be := &fakeBorder{}
		f, err := startBorderFilter(overlay(t), borderRuntime(bus), be)
		if err != nil {
			t.Fatal(err)
		}
		be.failWithdraw = failing
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err = f.Run(ctx)
		if failing != (err != nil) {
			t.Errorf("a withdrawal failing %v stopped with %v", failing, err)
		}
		entries := be.entries()
		if got := entries[len(entries)-1]; got != "withdraw" {
			t.Errorf("the antispoof filter stopped by %q, want the withdrawal", got)
		}
		if got, want := readyMoves(bus), []string{"true", "false"}; !slices.Equal(got, want) {
			t.Errorf("the antispoof filter's readiness moved %q, want %q", got, want)
		}
	}
}

// A filter stopped for the mesh's failure reports itself not ready and leaves
// its table, and one stopped for any other cause withdraws it
func TestBorderLeavesItsTableOnlyWhenStoppedForTheMeshsFailure(t *testing.T) {
	for _, cause := range []error{meshkernel.ErrMeshFailed, fmt.Errorf("stop: %w", meshkernel.ErrMeshFailed), nil, errors.New("another cause")} {
		bus := events.New()
		be := &fakeBorder{}
		f, err := startBorderFilter(overlay(t), borderRuntime(bus), be)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancelCause(context.Background())
		cancel(cause)
		if err := f.Run(ctx); err != nil {
			t.Errorf("a filter stopped for %v returned %v", cause, err)
		}
		if left, want := be.withdrawn == 0, errors.Is(cause, meshkernel.ErrMeshFailed); left != want {
			t.Errorf("a filter stopped for %v left its table %v, want %v", cause, left, want)
		}
		if got, want := readyMoves(bus), []string{"true", "false"}; !slices.Equal(got, want) {
			t.Errorf("the antispoof filter's readiness moved %q for %v, want %q", got, cause, want)
		}
	}
}

// A debug read lays the table held now beside the one the configuration asks
// for: each chain with its hook and priority, each desired rule with its
// counters or as not held yet, then any rule held that the configuration does
// not ask for, and the sets as the last pass asked for them
func TestBorderDebugReadsTheChainBesideTheDesiredOne(t *testing.T) {
	be := &fakeBorder{}
	f, err := startBorderFilter(overlay(t), borderRuntime(nil), be)
	if err != nil {
		t.Fatal(err)
	}
	be.setCount("drop ipv4 source 198.18.0.0/15", 12)
	be.setCount("", 3)
	be.mu.Lock()
	be.held = slices.DeleteFunc(be.held, func(rule Installed) bool { return rule.Spec == "accept via lo" })
	be.held = append(be.held, Installed{Spec: "drop ipv4 source 192.0.2.0/24"}, Installed{})
	be.mu.Unlock()
	debug := f.Debug()
	if debug.Where != "nftables table inet ranet3 chains antispoof and mesh_entry" || !debug.Ready {
		t.Errorf("the debug read reports %+v", debug)
	}
	var got []string
	for _, chain := range debug.Chains {
		priority := "none"
		if chain.Priority != nil {
			priority = fmt.Sprint(*chain.Priority)
		}
		got = append(got, fmt.Sprintf("chain %s %s %s", chain.Name, chain.Hook, priority))
		for _, rule := range chain.Rules {
			got = append(got, fmt.Sprintf("%s|%s|%s|%s|%v|%d", rule.Spec, rule.Verdict, rule.Reason, rule.Family, rule.Held, rule.Packets))
		}
	}
	for _, set := range debug.Sets {
		got = append(got, fmt.Sprintf("set %s %v", set.Name, set.Elements))
	}
	want := []string{
		"chain antispoof prerouting -300",
		"accept via ranet0|accept|inside||true|0",
		"accept via lo|accept|inside||false|0",
		"drop ipv4 source 198.18.0.0/15|drop|overlay_source|ipv4|true|12",
		"drop ipv6 source 3fff::/20|drop|overlay_source|ipv6|true|0",
		"chain mesh_entry postrouting 110",
		"return via other than ranet0|return|outside||true|0",
		"return a reply|return|reply||true|0",
		"return ipv6 to fe80::/10|return|link_local|ipv6|true|0",
		"return ipv6 to ff00::/8|return|link_local|ipv6|true|0",
		"return ipv4 source @owned4|return|owned|ipv4|true|0",
		"return ipv6 source @owned6|return|owned|ipv6|true|0",
		"return ipv4 to @none4|return|none|ipv4|true|0",
		"return ipv6 to @none6|return|none|ipv6|true|0",
		"drop ipv4 entering the mesh|drop|mesh_entry|ipv4|true|0",
		"drop ipv6 entering the mesh|drop|mesh_entry|ipv6|true|0",
		"chain   none",
		"drop ipv4 source 192.0.2.0/24|drop|||true|0",
		"a rule with no comment||||true|3",
		"set carved4 []", "set carved6 []", "set none4 []", "set none6 []", "set owned4 []", "set owned6 []",
	}
	if !slices.Equal(got, want) {
		t.Errorf("the debug read lists\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// A backend that writes the entry chain's drops alone holds those two rules,
// which status and debug list alone, reports the carve-outs and no
// exemption's conflict, since no drop of the antispoof chain runs, and heads
// the debug read's chain as it says
func TestBorderListsOnlyTheRulesItsBackendWrites(t *testing.T) {
	bus := events.New()
	p := netip.MustParsePrefix
	lease := egress.CarveOut{Link: "eth0", Prefix: p("198.18.0.0/24")}
	conflict := egress.ExemptConflict{Exemption: egress.Exemption{Prefix: p("198.18.0.0/25")}, Prefix: p("198.18.0.64/28"), Carved: p("198.18.0.64/28"), Via: "example/peer"}
	rt := borderRuntime(bus)
	rt.Sets = func(*egress.Border) egress.BorderSets {
		return egress.BorderSets{CarveOuts: []egress.CarveOut{lease}, Conflicts: []egress.ExemptConflict{conflict}}
	}
	be := &fakeBorder{only: []BorderClass{EntryDrop}}
	f, err := startBorderFilter(overlay(t), rt, be)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"drop ipv4 entering the mesh", "drop ipv6 entering the mesh"}; !slices.Equal(be.allSpecs(), want) {
		t.Errorf("the backend holds %q, want %q", be.allSpecs(), want)
	}
	if f.AntispoofRuns() {
		t.Error("a backend writing no antispoof rule reads as running the chain")
	}
	if got := f.Stats(); !got.Ready || got.Installed != 2 || !slices.Equal(got.CarveOuts, []egress.CarveOut{lease}) {
		t.Errorf("the status reads %+v, want ready with two rules and the carve-out", got)
	}
	if n := len(bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "antispoof.conflict" }, 0)); n != 0 {
		t.Errorf("recorded %d antispoof.conflict, want none", n)
	}
	if n := len(bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "antispoof.carve" }, 0)); n != 1 {
		t.Errorf("recorded %d antispoof.carve, want one", n)
	}
	debug := f.Debug()
	if len(debug.Chains) != 1 || debug.Chains[0].Name != EntryChain || debug.Chains[0].Hook != "postrouting" || len(debug.Chains[0].Rules) != 2 {
		t.Errorf("the debug read lists %+v, want the entry chain's two drops", debug.Chains)
	}
}

// A readback whose rules read as written and which says the filter is not
// ready otherwise holds the filter not ready with its reason, and is never a
// reason to rewrite
func TestBorderNotReadyBesideItsRulesRewritesNothing(t *testing.T) {
	be := &fakeBorder{}
	f, err := startBorderFilter(overlay(t), borderRuntime(nil), be)
	if err != nil {
		t.Fatal(err)
	}
	be.mu.Lock()
	be.unready = "the host has stopped its filter"
	be.mu.Unlock()
	f.trigger = "sweep"
	if err := f.reconcile(); err != nil {
		t.Fatal(err)
	}
	if got := f.Stats(); got.Ready || got.Unready != "the host has stopped its filter" {
		t.Errorf("the status reads ready %v, unready %q", got.Ready, got.Unready)
	}
	if be.applied != 1 {
		t.Errorf("the pass applied %d times, want only the start's", be.applied)
	}
	be.mu.Lock()
	be.unready = ""
	be.mu.Unlock()
	if err := f.reconcile(); err != nil || !f.Stats().Ready {
		t.Errorf("the pass after reads ready %v (%v)", f.Stats().Ready, err)
	}
}
