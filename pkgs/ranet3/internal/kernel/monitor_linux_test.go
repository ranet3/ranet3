// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"context"
	"os"
	"runtime"
	"slices"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/schema"
)

// ruleRestoreBudget is how soon a deleted rule of the reconciler's is back
// the periodic sweep alone takes DefaultReconcileInterval
const ruleRestoreBudget = time.Second

// the monitor wakes on a deleted rule carrying the reconciler's protocol and on nothing else about rules
// another writer's rule comes and goes without a pass, and a rule the reconciler adds itself is already in place
func TestRouteMonitorWakesOnlyOnADeletedRuleItOwns(t *testing.T) {
	plat, _ := writePlatform(t)
	monitor := &routeMonitor{table: uint32(plat.table.ID), proto: plat.table.Proto}
	owned := plat.ruleMessage(Rule{Family: FamilyIPv4, FWMark: 0x726c, Table: schema.TableMain, Priority: 40})
	for name, arm := range map[string]struct {
		kind uint16
		body []byte
		want bool
	}{
		"its own rule deleted":           {unix.RTM_DELRULE, owned, true},
		"its own rule added":             {unix.RTM_NEWRULE, owned, false},
		"another writer's rule deleted":  {unix.RTM_DELRULE, replaceProtocol(t, owned, unix.RTPROT_STATIC), false},
		"a rule without a protocol gone": {unix.RTM_DELRULE, stripProtocol(t, owned), false},
	} {
		if got := monitor.wakesOn(nlMessage{Kind: arm.kind, Data: arm.body}); got != arm.want {
			t.Errorf("%s: the monitor woke %v, want %v", name, got, arm.want)
		}
	}
}

// systemd-networkd deletes every rule it did not ask for whenever it configures a link
// the reconciler puts its own back within the settle window and one pass, long before the periodic sweep
func TestNetlinkRestoresADeletedRuleWithinASecond(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real netlink path needs root on linux")
	}
	enterThrowawayNamespace(t)
	conn, err := dialNetlink()
	if err != nil {
		t.Fatalf("dial rtnetlink: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	requireEmptyNamespace(t, conn)
	const device = "ranetrule0"
	createTUN(t, device)

	rule := Rule{To: schema.MustPrefix("198.18.104.0/24"), Table: DefaultTable, Priority: 100}
	r, err := New(Table{Rules: []Rule{rule}}, Runtime{Interface: device}, netstack.NewRouteTable())
	if err != nil {
		t.Fatalf("start the reconciler: %v", err)
	}
	plat := r.plat.(*netlinkPlatform)
	installed := rule
	installed.Family = FamilyIPv4
	// read through a socket of the test's own, since the loop owns the platform's
	held := func() bool {
		replies, err := conn.execute(unix.RTM_GETRULE, unix.NLM_F_DUMP, make([]byte, sizeofFibRuleHdr))
		if err != nil {
			t.Fatalf("dump rules: %v", err)
		}
		return slices.ContainsFunc(replies, func(reply nlMessage) bool {
			got, ok := plat.decodeRule(reply)
			return ok && got == installed
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("the reconciler stopped with %v", err)
		}
	})
	waitFor(t, held)

	if _, err := conn.execute(unix.RTM_DELRULE, unix.NLM_F_ACK, plat.ruleMessage(installed)); err != nil {
		t.Fatalf("delete the rule as networkd would: %v", err)
	}
	deleted := time.Now()
	waitFor(t, held)
	if took := time.Since(deleted); took > ruleRestoreBudget {
		t.Errorf("the deleted rule took %s to come back, want at most %s", took, ruleRestoreBudget)
	}
}
