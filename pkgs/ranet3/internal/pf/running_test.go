// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package pf

import "testing"

// pf's status as pfctl printed it, and the enabled status as a third-party run
// on macOS 26.5.1 recorded its line
func TestPfctlsStatusParses(t *testing.T) {
	if running, err := ParseRunning(golden(t, "info-disabled.txt")); err != nil || running {
		t.Errorf("a disabled pf reads running %v (%v)", running, err)
	}
	if running, err := ParseRunning("Status: Enabled for 0 days 01:11:51 Debug: Urgent\n"); err != nil || !running {
		t.Errorf("an enabled pf reads running %v (%v)", running, err)
	}
}
