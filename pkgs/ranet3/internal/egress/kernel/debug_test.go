// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"net/netip"
	"slices"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/egress"
)

// A debug read lists each rule the exit asks for with the counter the host
// holds now, not the last pass's, a rule the chains do not hold as not held,
// then a rule another writer put among them, and reads rp_filter on all and
// on each device the pass's routes leave by
func TestDebugReadsEachRuleNowBesideTheOnesNotHeld(t *testing.T) {
	cfg := egress.Egress{Advertise: prefixes(t, "0.0.0.0/0")}
	be := &fakeBackend{}
	read := map[string]string{"net/ipv4/conf/all/rp_filter": "0", "net/ipv4/conf/up0/rp_filter": "2"}
	member := netip.MustParsePrefix("192.0.2.64/26")
	tr := translator(t, cfg, Runtime{
		Members: func() []netip.Prefix { return []netip.Prefix{member} },
		Lookup: func(lookups []Lookup) ([]Answer, error) {
			answers := make([]Answer, len(lookups))
			for i := range lookups {
				answers[i] = Answer{Route: Route{Type: "unicast", Hops: []Hop{{Device: "up0"}, {Device: "up1", Dead: true}}}, ReplyIIF: "up0",
					Reply: Route{Type: "unicast", Hops: []Hop{{Device: "ranet0"}}}}
			}
			return answers, nil
		},
		Sysctl: func(path string) string { return read[path] },
	}, be)
	if err := tr.reconcile(); err != nil {
		t.Fatal(err)
	}
	desired := tr.desired()
	be.mu.Lock()
	be.held = slices.DeleteFunc(be.held, func(rule Installed) bool { return rule.Spec == desired[0].String() })
	be.held = append(be.held, Installed{Spec: "", Family: egress.FamilyIPv4, Chain: ChainName, Counted: true, Packets: 3})
	be.flows = 7
	be.mu.Unlock()

	debug := tr.Debug()
	if be.reads != 1 || debug.ReadErr != "" {
		t.Fatalf("the debug read listed the chains %d times, with %q", be.reads, debug.ReadErr)
	}
	if len(debug.Rules) != len(desired)+1 {
		t.Fatalf("the debug read lists %d rules, want the %d asked for and the one of no comment: %+v", len(debug.Rules), len(desired), debug.Rules)
	}
	for i, rule := range desired {
		got := debug.Rules[i]
		held := i != 0
		var packets uint64
		if held && rule.kind().counted() {
			packets = 7
		}
		if got.Spec != rule.String() || !got.Wanted || got.Held != held || got.Packets != packets {
			t.Errorf("rule %d reads %+v, want %s held %v with %d packets read now", i, got, rule, held, packets)
		}
	}
	if extra := debug.Rules[len(desired)]; extra.Spec != "" || extra.Wanted || !extra.Held || extra.Packets != 3+7 || extra.Counter != "flows" {
		t.Errorf("the rule of no comment reads %+v, want held, not asked for, with 10 flows", extra)
	}
	if len(debug.Families) != 1 || !debug.Families[0].Ready || !debug.Families[0].Forwarding || len(debug.Families[0].Lookups) != 1 || len(debug.Families[0].Answers) != 1 {
		t.Fatalf("the debug read holds the families %+v, want ipv4 ready on its one answered lookup", debug.Families)
	}
	want := []egress.Setting{{Name: "net/ipv4/conf/all/rp_filter", Value: "0"}, {Name: "net/ipv4/conf/ranet0/rp_filter"}, {Name: "net/ipv4/conf/up0/rp_filter", Value: "2"}, {Name: "net/ipv4/conf/up1/rp_filter"}}
	if !slices.Equal(debug.RPFilter, want) {
		t.Errorf("the debug read holds rp_filter %+v, want %+v", debug.RPFilter, want)
	}

	be.failRead = true
	if debug := tr.Debug(); debug.ReadErr == "" || debug.Rules[1].Held {
		t.Errorf("a debug read whose listing failed reads %q with %+v", debug.ReadErr, debug.Rules[1])
	}
}

// What each rule's counter counts follows the chain the rule sits in: flows in
// the translation's, packets in the forward hook's, and nothing where the rule
// keeps no counter, for a rule the exit asks for and one another writer put in
// either chain alike
func TestDebugNamesWhatEachCounterCounts(t *testing.T) {
	for _, c := range []struct {
		rule Rule
		want string
	}{
		{Rule{Family: egress.FamilyIPv4, Direction: Out, Interface: "ranet0"}, "flows"},
		{Rule{Family: egress.FamilyIPv4, Direction: Out, Interface: "ranet0", None: true}, "flows"},
		{Rule{Family: egress.FamilyIPv4, Direction: Out, Interface: "ranet0", Timeouts: UDPTimeouts}, ""},
		{Rule{Family: egress.FamilyIPv4, Direction: Out, Interface: "ranet0", Limit: 100}, "packets"},
		{Rule{Family: egress.FamilyIPv4, Direction: Out, Interface: "ranet0", Untracked: true}, "packets"},
		{Rule{Family: egress.FamilyIPv4, Direction: Out, Interface: "ranet0", Untracked: true, None: true}, ""},
		{Rule{Family: egress.FamilyIPv4, Direction: In, Interface: "ranet0", Drops: Information}, "packets"},
		{Rule{Family: egress.FamilyIPv4, Direction: Out, Interface: "ranet0", Protocol: dccp}, "packets"},
		{Rule{Family: egress.FamilyIPv6, Direction: Out, Interface: "ranet0", None: true, Protocol: udpLite}, ""},
	} {
		kind := c.rule.kind()
		if got := counterUnit(kind.chain(), kind.counted()); got != c.want {
			t.Errorf("%s counts %q, want %q", c.rule, got, c.want)
		}
		be := &fakeBackend{held: []Installed{{Family: egress.FamilyIPv4, Chain: kind.chain(), Counted: kind.counted()}}}
		debug := translator(t, egress.Egress{Advertise: prefixes(t, "0.0.0.0/0")}, Runtime{}, be).Debug()
		if extra := debug.Rules[len(debug.Rules)-1]; extra.Wanted || extra.Counter != c.want {
			t.Errorf("a rule of no comment where %s sits reads %+v, want it counting %q", c.rule, extra, c.want)
		}
	}
}
