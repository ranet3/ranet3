// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

// Package pbt holds the settings every property test in this module runs
// under, so the engine is configured in one place and a property is written
// against the same terms wherever it lives. Test files import it and nothing
// else does, which keeps the property engine out of the daemon.
//
// The engine is a prebuilt library that purego opens at run time, and purego
// does not build everywhere the daemon does: freebsd without cgo needs a
// compiler flag, and openbsd it does not build on at all. The property tests
// run on linux and darwin, the two platforms ranet3 supports, and this package
// and every file that imports the engine or this package carry a build
// constraint naming those two. go build and go vet over the whole tree then
// work on the others.
package pbt

import (
	"testing"

	"hegel.dev/go/hegel"
)

// Check runs fn as a property over generated inputs, and reports the smallest
// input it finds that makes fn fail.
//
// The example database is off. A run writes nothing into the tree and replays
// nothing an earlier run left behind, so the result depends on the code alone.
// The run is derandomized, though not to the point of repeating itself: hegel
// v0.9.13 hashes the labels of nested generators with a seed each process
// picks for itself, so a property built from them draws a different sample in
// each run. A failure is still printed shrunk, with what reproduces it. A
// boundary the code branches on is drawn outright, through Spanning or by
// name, rather than left to the sample. Each property gets 200 cases, twice
// the engine's default.
func Check(t *testing.T, fn func(*hegel.T)) {
	t.Helper()
	hegel.Test(t, fn,
		hegel.WithDatabase(""),
		hegel.WithDerandomize(true),
		hegel.WithTestCases(200),
	)
}

// Integer is every type the engine draws integers of.
type Integer interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 | ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr
}

// Spanning draws from lo to hi, with the two ends drawn outright a quarter of
// the time, so every run meets them rather than only a run whose sample
// happens to land there.
func Spanning[T Integer](lo, hi T) hegel.Generator[T] {
	return hegel.Composite(func(tc hegel.TestCase) T {
		if hegel.Draw(tc, hegel.WeightedBooleans(1.0/4)) {
			return hegel.Draw(tc, hegel.SampledFrom([]T{lo, hi}))
		}
		return hegel.Draw(tc, hegel.Integers(lo, hi))
	})
}
