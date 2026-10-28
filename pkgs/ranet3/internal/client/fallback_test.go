// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"errors"
	"reflect"
	"slices"
	"testing"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/kernel"
)

// Where the reconciler's last pass ran fallback = "none", the status names
// each endpoint name whose last lookup failed beside the switch's state, and
// debug rules carries the table as a read finds it with that state. Under
// "uplink" neither names the switch, and a read that fails is reported.
func TestStatusAndDebugRulesCarryTheSwitch(t *testing.T) {
	c, _, _, _ := reloadOf(t, func(*config.Config) {})
	c.sessions = newSessionSet()
	switchState := &control.KernelFallback{State: "holding", Dropped: 3, DroppedBytes: 180}
	c.SetKernelStatus(func() control.KernelStatus {
		return control.KernelStatus{Enabled: true, Exit: &control.KernelExit{Fallback: switchState}}
	})
	c.ruleDump = func() ([]kernel.DumpedRule, error) { return nil, nil }
	debug := kernel.FallbackDebug{
		Where: "nftables table inet ranet3_fallback chain fallback", Hook: "postrouting", Priority: 2147483646, Held: true,
		Rules: []kernel.FallbackDebugRule{{Spec: "counter drop", Packets: 3, Bytes: 180}},
		Sets:  []kernel.FallbackDebugSet{{Name: "lan4", Elements: []string{"198.51.100.0/25"}}},
	}
	var readErr error
	c.fallbackRead = func() (kernel.FallbackDebug, error) { return debug, readErr }
	c.unresolved.note("gateway.example.org", true)
	c.unresolved.note("relay.example.org", true)
	c.unresolved.note("relay.example.org", false)

	fallback := c.Status().Kernel.Exit.Fallback
	if fallback == nil || fallback.State != "holding" || fallback.Dropped != 3 || !slices.Equal(fallback.Unresolved, []string{"gateway.example.org"}) {
		t.Errorf("the status names the switch as %+v, want holding with gateway.example.org unresolved", fallback)
	}
	if switchState.Unresolved != nil {
		t.Errorf("the status wrote the unresolved names into the reconciler's own status %+v", switchState)
	}
	want := &control.FallbackTable{
		Where: debug.Where, Hook: "postrouting", Priority: 2147483646, State: "holding", Held: true,
		Rules: []control.FallbackTableRule{{Spec: "counter drop", Packets: 3, Bytes: 180}},
		Sets:  []control.FallbackTableSet{{Name: "lan4", Elements: []string{"198.51.100.0/25"}}},
	}
	if got := c.DebugRules().Fallback; !reflect.DeepEqual(got, want) {
		t.Errorf("debug rules carries the table %+v, want %+v", got, want)
	}
	readErr = errors.New("nftables: dump tables: operation not permitted")
	if got := c.DebugRules().Fallback; got == nil || got.Err != readErr.Error() {
		t.Errorf("debug rules carries the table %+v after a read that failed, want its error", got)
	}

	c.SetKernelStatus(func() control.KernelStatus { return control.KernelStatus{Enabled: true, Exit: &control.KernelExit{}} })
	if got := c.Status().Kernel.Exit.Fallback; got != nil {
		t.Errorf("under uplink the status names the switch as %+v", got)
	}
	if got := c.DebugRules().Fallback; got != nil {
		t.Errorf("under uplink debug rules carries the table %+v", got)
	}
}
