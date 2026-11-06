// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package kernel

import (
	"slices"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/netstack"
)

// darwin has no policy routing, and New takes a capability there with no rule
// pass, which leaves the mirror's throw rows out too, while its overlay holds
// go in apart from the tun
// the loopback stands in for the tun
// New installs nothing and opens only route sockets, which need no root
func TestNewOnAPlatformWithoutRulesRunsNoRulePass(t *testing.T) {
	reconciler, err := New(Table{}, Runtime{Interface: Loopback, Overlay: prefixes(prefix("192.0.2.0/24"))}, netstack.NewRouteTable())
	if err != nil {
		t.Fatal(err)
	}
	defer reconciler.plat.Close()
	if reconciler.rules != nil {
		t.Fatal("darwin's platform answers for policy rules")
	}
	if err := reconciler.applyRules(reconciler.src.Snapshot(), exitView{}, true); err != nil || reconciler.DerivedRules() != nil {
		t.Errorf("a rule pass on darwin answered %v and published %v", err, reconciler.DerivedRules())
	}
	want := []Route{{Destination: prefix("192.0.2.0/24"), Metric: holdMetric, Unreachable: true}}
	if got := reconciler.desired(reconciler.src.Snapshot(), reconciler.readNetwork()); !slices.Equal(got, want) {
		t.Errorf("the mirror on darwin wants %v, want the overlay's hold alone", got)
	}
}
