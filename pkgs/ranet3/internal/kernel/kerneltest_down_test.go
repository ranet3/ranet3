// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package kernel_test

import (
	"testing"

	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/kernel/kerneltest"
	"ranet3.com/pkgs/ranet3/schema"
)

// kerneltest's restatement of the down set holds each rule a stop writes and no other, as many as it writes, so the tests
// of other packages that compare a dump with it compare with what the reconciler leaves
func TestKerneltestDownSetMatchesTheReconcilers(t *testing.T) {
	overlay := []schema.Prefix{schema.MustPrefix("192.0.2.0/25"), schema.MustPrefix("10.0.0.0/8"), schema.MustPrefix("3fff::/21")}
	written := kernel.DumpedDownSet(overlay)
	if extra, missing := kerneltest.NotDownSet(written, overlay); len(extra)+len(missing) != 0 {
		t.Errorf("against the down set a stop writes kerneltest finds %v outside its own and lacks %v", extra, missing)
	}
	if got, want := len(kerneltest.DownSet(overlay)), len(written); got != want {
		t.Errorf("kerneltest restates %d rules of the down set, a stop writes %d", got, want)
	}
}

// a dump holding a rule of the down set twice is not the down set, as a stop leaves one of each
func TestNotDownSetCountsASecondCopyAsExtra(t *testing.T) {
	overlay := []schema.Prefix{schema.MustPrefix("192.0.2.0/25")}
	down := kerneltest.DownSet(overlay)
	if extra, missing := kerneltest.NotDownSet(append(down, down[0]), overlay); len(extra) != 1 || extra[0] != down[0] || len(missing) != 0 {
		t.Errorf("a dump with %v twice gave extra %v and missing %v, want that rule extra once", down[0], extra, missing)
	}
}
