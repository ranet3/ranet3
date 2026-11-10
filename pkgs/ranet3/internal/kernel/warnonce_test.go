// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"slices"
	"testing"
)

// each step marks some keys and ends the window, and new is the keys a mark
// of the step answered new for
func TestWarnOnceAnswersNewAgainstTheLastWindow(t *testing.T) {
	var w warnOnce[string]
	for i, step := range []struct {
		marks []string
		new   []string
	}{
		{marks: []string{"a", "b"}, new: []string{"a", "b"}},
		// a key the last window saw is not new
		{marks: []string{"a"}},
		// b was away for a window, so it is new when it returns
		{marks: []string{"a", "b"}, new: []string{"b"}},
		// a window that marks nothing empties the record, and two marks of one
		// key in one window both answer new
		{},
		{marks: []string{"a", "a"}, new: []string{"a", "a"}},
		{marks: []string{"a", "a"}},
	} {
		var got []string
		for _, key := range step.marks {
			if w.mark(key) {
				got = append(got, key)
			}
		}
		if !slices.Equal(got, step.new) {
			t.Fatalf("window %d answered new for %v, want %v", i, got, step.new)
		}
		w.end()
	}
}
