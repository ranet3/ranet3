// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"strings"
	"testing"
)

// debug pmtu --help names what its two counts hold
func TestDebugPMTUHelpNamesWhatItsCountsHold(t *testing.T) {
	usage, err := execute(t, "debug", "pmtu", "--help")
	if err != nil {
		t.Fatal(err)
	}
	// the description is wrapped, so a phrase may break across lines
	usage = strings.Join(strings.Fields(usage), " ")
	for _, want := range []string{"packets too large to go on", "SYN-ACK's MSS to what a session carries"} {
		if !strings.Contains(usage, want) {
			t.Errorf("debug pmtu --help reads %q, want it to carry %q", usage, want)
		}
	}
}
