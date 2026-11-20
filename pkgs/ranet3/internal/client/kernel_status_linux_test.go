// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package client

import (
	"context"
	"os"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/kernel/kerneltest"
	"ranet3.com/pkgs/ranet3/internal/netnstest"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/schema"
)

// ReconcilerOf hands the node a reconciler whose status counts the overlay prefixes a down's stop refuses, as the reconciler's own
// record does, and whose DropHold has the operator's stop that follows take them, the status counting 0 after it
func TestReconcilerOfCountsTheDownAndDropsItForTheOperatorsStop(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("the reconciler's netlink writes need root on linux")
	}
	ns := netnstest.StartThread(t)
	overlay := []schema.Prefix{schema.MustPrefix("192.0.2.0/25"), schema.MustPrefix("3fff::/21")}
	var routes *kernel.Reconciler
	if err := ns.Do(func() (err error) {
		routes, err = kernel.New(kernel.Table{ID: kernel.DefaultTable, Proto: kernel.DefaultProtocol}.Normalized(), kernel.Runtime{Interface: "lo", Overlay: overlay}, netstack.NewRouteTable())
		return err
	}); err != nil {
		t.Fatalf("build the reconciler: %v", err)
	}
	r := ReconcilerOf(routes)
	// a down's stop, before the first pass
	r.Enable(false)
	ctx, cancel := context.WithCancel(context.Background())
	runner := netnstest.JoinThread(t, ns.Path)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = runner.Do(func() error { return routes.Run(ctx) })
	}()
	t.Cleanup(func() { routes.DropHold(); cancel(); <-done })
	settled := func(held int) func() bool {
		return func() bool { stats := routes.Stats(); return !stats.At.IsZero() && stats.Held == held }
	}
	waitFor(t, convergeBudget, "the reconciler's own record to count the 2 overlay prefixes of the down set", settled(2))
	if got := r.Status().Held; got != 2 {
		t.Errorf("the down's status counts %d overlay prefixes refused, want the reconciler's 2", got)
	}
	if r.DropHold == nil {
		t.Fatal("ReconcilerOf left DropHold unset, so no operator's stop takes the down set")
	}
	r.DropHold()
	r.Enable(false)
	waitFor(t, convergeBudget, "the operator's stop after DropHold to leave the reconciler's own record counting 0 overlay prefixes", settled(0))
	if got := r.Status().Held; got != 0 {
		t.Errorf("the operator's stop's status counts %d overlay prefixes refused, want 0", got)
	}
	var dumped []kernel.DumpedRule
	if err := ns.Do(func() (err error) { dumped, err = kernel.DumpRules(); return err }); err != nil {
		t.Fatal(err)
	}
	if extra, _ := kerneltest.NotDownSet(dumped, nil); len(extra) != 0 {
		t.Errorf("the operator's stop left the rules %+v", extra)
	}
}
