// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package kernel_test

import (
	"testing"

	"ranet3.com/pkgs/ranet3/internal/client"
	"ranet3.com/pkgs/ranet3/internal/kernel"
)

// The node's Endpoints hook, as ReconcilerOf wires it to a reconciler, wakes
// that reconciler's pass, which every change of the endpoints rests on
func TestNodeEndpointsHookWakesTheReconcilersPass(t *testing.T) {
	kernel.WakesAPass(t, func(routes *kernel.Reconciler) {
		wake := client.ReconcilerOf(routes).Endpoints
		if wake == nil {
			t.Fatal("ReconcilerOf leaves the Endpoints hook unset")
		}
		wake()
	})
}
