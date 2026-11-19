// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package dumptest

import (
	"os"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
)

// A fetch that fails with ENOMEM or ENOBUFS is fetched again up to Attempts times in all, the two counted under that one bound, the last failure is the answer, and an answer or any other failure ends the read at once
func TestRefetchedFetchesAgainOnlyWhileTheListGrows(t *testing.T) {
	grown, overrun := os.NewSyscallError("sysctl", unix.ENOMEM), os.NewSyscallError("sysctl", unix.ENOBUFS)
	// each last failure is a value of its own, so a read that answers an earlier one fails the row
	lastGrown, lastOverrun, refused := os.NewSyscallError("sysctl", unix.ENOMEM), os.NewSyscallError("sysctl", unix.ENOBUFS), os.NewSyscallError("sysctl", unix.EPERM)
	for _, c := range []struct {
		failures []error
		calls    int
		err      error
	}{
		{failures: slices.Repeat([]error{grown}, Attempts-1), calls: Attempts},
		{failures: slices.Repeat([]error{overrun}, Attempts-1), calls: Attempts},
		{failures: append(slices.Repeat([]error{grown}, Attempts-1), lastGrown, nil), calls: Attempts, err: lastGrown},
		{failures: append(slices.Repeat([]error{overrun}, Attempts-1), lastOverrun, nil), calls: Attempts, err: lastOverrun},
		{failures: []error{refused}, calls: 1, err: refused},
		{failures: nil, calls: 1},
		{failures: []error{grown, nil}, calls: 2},
		{failures: append(slices.Repeat([]error{grown, overrun}, Attempts/2), nil), calls: Attempts, err: overrun},
	} {
		calls := 0
		answer, err := Refetched(func() (int, error) {
			calls++
			if calls <= len(c.failures) && c.failures[calls-1] != nil {
				return 0, c.failures[calls-1]
			}
			return calls, nil
		})
		if calls != c.calls || err != c.err || err == nil && answer != calls {
			t.Errorf("failures %v: fetched %d times answering %d and %v, want %d times and %v", c.failures, calls, answer, err, c.calls, c.err)
		}
	}
}
