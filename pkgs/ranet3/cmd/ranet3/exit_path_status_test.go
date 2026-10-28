// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"net/netip"
	"reflect"
	"testing"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/internal/kernel"
)

// the control surface carries the reconciler's path as each state reads it, up with the families installed and down with the SID and the table's answer, and none outside mode 3
func TestExitPathStatusCarriesEachState(t *testing.T) {
	via := []netip.Addr{netip.MustParseAddr("3fff:b:0:206::1"), netip.MustParseAddr("3fff:b:0:306::3")}
	source := netip.MustParseAddr("3fff::2")
	for name, c := range map[string]struct {
		path *kernel.PathStatus
		want *control.KernelExitPath
	}{
		"outside mode 3": {},
		"up": {
			&kernel.PathStatus{Via: via, Source: source, Installed: []kernel.Family{kernel.FamilyIPv4, kernel.FamilyIPv6}},
			&control.KernelExitPath{Via: []string{"3fff:b:0:206::1", "3fff:b:0:306::3"}, Source: "3fff::2", State: "up", Installed: []string{"ipv4", "ipv6"}},
		},
		"down": {
			&kernel.PathStatus{Via: via, Source: source, Down: via[1], Verdict: "held"},
			&control.KernelExitPath{Via: []string{"3fff:b:0:206::1", "3fff:b:0:306::3"}, Source: "3fff::2", State: "down", Down: "3fff:b:0:306::3", Verdict: "held"},
		},
	} {
		if got := exitPathStatus(c.path); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: the path reads %+v, want %+v", name, got, c.want)
		}
	}
}
