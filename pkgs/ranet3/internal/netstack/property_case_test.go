// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package netstack

import (
	"runtime"
	"slices"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// propertyCase is one case of a property as the helpers that build a mesh see it
// hegel's T passes Cleanup to the property's testing.T, which runs it once the property returns
// so every case a shrink runs would hold its mesh until then, where this runs it as the case ends
type propertyCase struct {
	*hegel.T
	cleanups []func()
}

// Cleanup has f run as the case ends, the last registered first, as testing.T runs its own
func (c *propertyCase) Cleanup(f func()) { c.cleanups = append(c.cleanups, f) }

// checkCases is pbt.Check with each case's cleanups run as that case ends, a failing one included
func checkCases(t *testing.T, fn func(*propertyCase)) {
	t.Helper()
	pbt.Check(t, func(ht *hegel.T) {
		c := &propertyCase{T: ht}
		defer c.end()
		fn(c)
	})
}

// end runs the case's cleanups, the last registered first, each one deferred so the rest still run when one panics or ends the goroutine
// a cleanup registered while they run is not run, where testing.T would run it, and no helper registers one
func (c *propertyCase) end() {
	for _, f := range c.cleanups {
		defer f()
	}
}

// a case's cleanups all run, the last registered first, when one of them panics, as Fatalf and Errorf do, or ends its goroutine
// and the panic still leaves the case, so the case fails
func TestPropertyCaseRunsEveryCleanupWhateverOneDoes(t *testing.T) {
	for _, c := range []struct {
		name  string
		stop  func()
		ended any
	}{
		{"a cleanup that panics", func() { panic("cleanup 2") }, "cleanup 2"},
		{"a cleanup that ends its goroutine", runtime.Goexit, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			var ran []int
			var ended any
			run := &propertyCase{}
			run.Cleanup(func() { ran = append(ran, 1) })
			run.Cleanup(func() { ran = append(ran, 2); c.stop() })
			run.Cleanup(func() { ran = append(ran, 3) })
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer func() { ended = recover() }()
				run.end()
			}()
			<-done
			if !slices.Equal(ran, []int{3, 2, 1}) || ended != c.ended {
				t.Errorf("the cleanups ran %v and the case ended with %v, want [3 2 1] and %v", ran, ended, c.ended)
			}
		})
	}
}
