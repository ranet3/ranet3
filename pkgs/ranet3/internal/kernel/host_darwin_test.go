// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package kernel

import (
	"errors"
	"os"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
)

// A dump that fails with ENOMEM, as FetchRIB's does when the table grows past
// its sizing sysctl, is fetched again up to dumpAttempts times in all, and any
// other failure ends it at once
func TestDumpFetchesAgainOnlyWhileTheTableOutgrowsItsBuffer(t *testing.T) {
	grown := os.NewSyscallError("sysctl", unix.ENOMEM)
	refused := os.NewSyscallError("sysctl", unix.EPERM)
	rib := []byte{1, 2, 3}
	for _, c := range []struct {
		what    string
		answers []error
		calls   int
		err     error
	}{
		{what: "a fetch that succeeds", answers: []error{nil}, calls: 1},
		{what: "a fetch that outgrows its buffer once", answers: []error{grown, nil}, calls: 2},
		{what: "a fetch that outgrows its buffer every time", answers: slices.Repeat([]error{grown}, dumpAttempts+1), calls: dumpAttempts, err: grown},
		{what: "a fetch refused", answers: []error{refused, nil}, calls: 1, err: refused},
	} {
		calls := 0
		got, err := refetched(func() ([]byte, error) {
			answer := c.answers[calls]
			calls++
			if answer != nil {
				return nil, answer
			}
			return rib, nil
		})
		if calls != c.calls || !errors.Is(err, c.err) || c.err == nil && !slices.Equal(got, rib) {
			t.Errorf("%s: fetched %d times with %v and %v, want %d times with %v", c.what, calls, got, err, c.calls, c.err)
		}
	}
}
