// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

// Package pbt holds the settings every property test in this module runs
// under, so the engine is configured in one place and a property is written
// against the same terms wherever it lives. Test files import it and nothing
// else does, which keeps the property engine out of the daemon.
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
// The run is derandomized, so a property that fails fails on every run and a
// build never passes on a lucky seed. Each property gets 200 cases, twice the
// engine's default.
func Check(t *testing.T, fn func(*hegel.T)) {
	t.Helper()
	hegel.Test(t, fn,
		hegel.WithDatabase(""),
		hegel.WithDerandomize(true),
		hegel.WithTestCases(200),
	)
}
