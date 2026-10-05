// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package version

import "testing"

// a revision passed in at link time names a tree with uncommitted changes by its -dirty ending
// and the version string reads the same as the one passed in
func TestPassedRevisionCarriesItsTree(t *testing.T) {
	defer func(previous string) { Revision = previous }(Revision)
	for passed, want := range map[string]struct {
		revision string
		modified bool
	}{
		"ed50ac2":       {"ed50ac2", false},
		"ed50ac2-dirty": {"ed50ac2", true},
	} {
		Revision = passed
		if revision, modified := VCS(); revision != want.revision || modified != want.modified {
			t.Errorf("%s reads as revision %q modified %v", passed, revision, modified)
		}
		if got := String(); got != Value+"+"+passed {
			t.Errorf("%s gives the version %q", passed, got)
		}
	}
}
