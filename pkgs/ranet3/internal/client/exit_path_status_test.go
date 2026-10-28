// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"net/netip"
	"slices"
	"testing"

	"ranet3.com/pkgs/ranet3/control"
)

// status carries the reconciler's path with the dataplane's own counts for it,
// in place of any the reconciler's half holds, and debug rules lists the two
// steered defaults of the reconciler's table by what the last pass left
// installed, with the path's state. Outside mode 3 neither names a path.
func TestStatusAndDebugRulesCarryTheExitPath(t *testing.T) {
	c, _ := reloadFixture(t)
	// the reconciler's half carries counts the mesh does not hold, which status replaces with the mesh's
	path := &control.KernelExitPath{Via: []string{"3fff:b:0:306::3"}, Source: "3fff::2", State: "down", Down: "3fff:b:0:306::3", Verdict: "held", Installed: []string{"ipv6"}, Steered: 7, Unrouted: 5}
	c.SetKernelStatus(func() control.KernelStatus {
		copied := *path
		return control.KernelStatus{Enabled: true, Table: 200, ExitPath: &copied}
	})
	status := c.kernel()
	counts := c.Mesh.PathCounters()
	if status.ExitPath == nil || status.ExitPath.Steered != counts.Steered || status.ExitPath.Unrouted != counts.Unrouted || status.ExitPath.Down != path.Down {
		t.Errorf("status carries the path %+v, want %+v with the counts %+v", status.ExitPath, path, counts)
	}
	steered := c.DebugRules().Steered
	want := &control.SteeredDefaults{Table: 200, State: "down", Down: "3fff:b:0:306::3", Verdict: "held", Routes: []control.SteeredDefault{
		{Family: "ipv4", To: netip.MustParsePrefix("0.0.0.0/0")},
		{Family: "ipv6", To: netip.MustParsePrefix("::/0"), Installed: true},
	}}
	if steered == nil || steered.Table != want.Table || steered.State != want.State || steered.Down != want.Down || steered.Verdict != want.Verdict || !slices.Equal(steered.Routes, want.Routes) {
		t.Errorf("debug rules lists the steered defaults as %+v, want %+v", steered, want)
	}

	c.SetKernelStatus(func() control.KernelStatus { return control.KernelStatus{Enabled: true, Table: 200} })
	if status := c.kernel(); status.ExitPath != nil {
		t.Errorf("mode 2 reports the path %+v", status.ExitPath)
	}
	if steered := c.DebugRules().Steered; steered != nil {
		t.Errorf("mode 2 lists the steered defaults %+v", steered)
	}
}
