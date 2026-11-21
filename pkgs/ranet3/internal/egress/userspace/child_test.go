// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package userspace

import (
	"os"
	"os/exec"
	"testing"
	"time"
)

// childMargin is the part of a test's time left to it past its child's
// timeout, to read the child's end and report it
const childMargin = 5 * time.Second

// childOf is a run of t alone in a process of its own, which t's end kills,
// and which times out childMargin short of t's deadline where t has one
func childOf(t *testing.T) *exec.Cmd {
	t.Helper()
	args := []string{"-test.run", "^" + t.Name() + "$", "-test.count=1", "-test.v"}
	if deadline, ok := t.Deadline(); ok {
		args = append(args, "-test.timeout", max(time.Until(deadline)-childMargin, time.Second).String())
	}
	return exec.CommandContext(t.Context(), os.Args[0], args...)
}
