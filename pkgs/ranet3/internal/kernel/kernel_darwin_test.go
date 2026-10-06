// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package kernel

import (
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/schema"
)

// darwin has no policy routing, and New refuses a configuration carrying cap.table rules there by name
// nothing else on darwin refuses rules
// a node taking one came up with a working mesh and no steering, and said nothing
// the loopback stands in for the tun
// New installs nothing and opens only route sockets, which need no root
func TestNewRefusesRulesOnAPlatformWithoutThem(t *testing.T) {
	rule := Rule{FWMark: 0x726c, Table: schema.TableMain, Priority: 40, Family: FamilyIPv4}
	reconciler, err := New(Table{Rules: []Rule{rule}}, Runtime{Interface: "lo0"}, netstack.NewRouteTable())
	if err == nil {
		_ = reconciler.plat.Close()
		t.Fatal("a configuration carrying a rule was taken on a platform with no policy routing")
	}
	if !strings.Contains(err.Error(), "cap.table rules") {
		t.Errorf("the refusal reads %q, want it to name the rules", err)
	}
}
