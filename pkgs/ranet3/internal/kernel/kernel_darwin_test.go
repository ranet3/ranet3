// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package kernel

import (
	"testing"

	"ranet3.com/pkgs/ranet3/internal/netstack"
)

// darwin has no policy routing, and New takes a capability there with no rule
// pass, which leaves the mirror's throw rows and overlay holds out too
// the loopback stands in for the tun
// New installs nothing and opens only route sockets, which need no root
func TestNewOnAPlatformWithoutRulesRunsNoRulePass(t *testing.T) {
	reconciler, err := New(Table{}, Runtime{Interface: "lo0", Overlay: prefixes(prefix("192.0.2.0/24"))}, netstack.NewRouteTable())
	if err != nil {
		t.Fatal(err)
	}
	defer reconciler.plat.Close()
	if reconciler.rules != nil {
		t.Fatal("darwin's platform answers for policy rules")
	}
	if err := reconciler.applyRules(reconciler.src.Snapshot(), nil, false); err != nil || reconciler.DerivedRules() != nil {
		t.Errorf("a rule pass on darwin answered %v and published %v", err, reconciler.DerivedRules())
	}
}
