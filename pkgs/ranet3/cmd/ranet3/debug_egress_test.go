// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// debug egress and debug segments take no argument and complete to nothing
func TestDebugEgressAndSegmentsTakeNoArgument(t *testing.T) {
	socket := serveStub(t)
	for _, view := range []string{"egress", "segments"} {
		if out, err := execute(t, "debug", view, "--control", socket, "ipv4"); err == nil {
			t.Errorf("debug %s took an argument: %q", view, out)
		}
		out, err := execute(t, cobra.ShellCompRequestCmd, "debug", view, "--control", socket, "")
		if err != nil {
			t.Fatal(err)
		}
		if offered, _, _ := strings.Cut(out, ":"); strings.TrimSpace(offered) != "" || !strings.Contains(out, ":4") {
			t.Errorf("debug %s completed to %q, want nothing and no files", view, out)
		}
	}
}
