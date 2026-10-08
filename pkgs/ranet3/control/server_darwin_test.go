// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package control

import (
	"os"
	"path/filepath"
	"testing"
)

// launchd starts the daemon as root in the group its job names
// /var/run hands down its own group, daemon, instead
// root may give a directory a group of any number, which leaves the run's own groups out of it
func TestDarwinListenAsRootGivesTheEffectiveGroup(t *testing.T) {
	if os.Getenv("RANET3_DARWIN_NETTEST") != "1" {
		t.Skip("set RANET3_DARWIN_NETTEST=1 and run as root to give a directory a group of any number")
	}
	if os.Geteuid() != 0 {
		t.Skip("run as root to give a directory a group of any number")
	}
	parent := filepath.Dir(socketPath(t))
	foreign := os.Getegid() + 1
	if err := os.Chown(parent, -1, foreign); err != nil {
		t.Fatal(err)
	}
	listenUnderForeignGroup(t, parent, foreign)
}
