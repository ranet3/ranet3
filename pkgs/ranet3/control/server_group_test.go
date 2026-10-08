// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package control

import (
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
)

// BSD hands a new file the group of the directory it is made in
// linux does the same in a setgid directory
// a second group of the run's user stands in for the group /var/run is in
func TestListenGivesSocketAndDirectoriesTheEffectiveGroup(t *testing.T) {
	parent := filepath.Dir(socketPath(t))
	groups, err := os.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	foreign := -1
	for _, gid := range groups {
		if gid != os.Getegid() && os.Chown(parent, -1, gid) == nil {
			foreign = gid
			break
		}
	}
	if foreign < 0 {
		t.Skip("this user can give a directory no group besides its effective one")
	}
	// BSD needs no setgid bit
	// the darwin nix sandbox refuses one
	if runtime.GOOS == "linux" {
		if err := os.Chmod(parent, 0o750|os.ModeSetgid); err != nil {
			t.Skipf("this host refuses a setgid bit: %v", err)
		}
	}
	listenUnderForeignGroup(t, parent, foreign)
}

// listenUnderForeignGroup binds a socket in parent, a directory in group foreign that hands its group down
// and another socket two directories below parent, where Listen makes both directories
// the sockets and the directories Listen made take the effective group
// parent, which was there first, keeps its group and its mode
func listenUnderForeignGroup(t *testing.T, parent string, foreign int) {
	t.Helper()
	// the premise, without which every check below passes whatever Listen does
	probe := filepath.Join(parent, "probe")
	if err := os.WriteFile(probe, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, gid := modeAndGroup(t, probe); gid != foreign {
		t.Fatalf("a file made in %s is in group %d, not the directory's %d, which leaves Listen nothing to correct", parent, gid, foreign)
	}
	if err := os.Remove(probe); err != nil {
		t.Fatal(err)
	}
	before, _ := modeAndGroup(t, parent)
	for _, arm := range []struct{ name, path string }{
		{"existing directory", filepath.Join(parent, "control.sock")},
		{"made directories", filepath.Join(parent, "run", "ranet3", "control.sock")},
	} {
		t.Run(arm.name, func(t *testing.T) {
			listener, err := Listen(arm.path)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			for path := arm.path; path != parent; path = filepath.Dir(path) {
				mode, gid := modeAndGroup(t, path)
				if gid != os.Getegid() {
					t.Errorf("%s is in group %d, want the effective %d rather than %d from the directory it was made in", path, gid, os.Getegid(), foreign)
				}
				if mode.IsDir() && mode.Perm() != dirMode {
					t.Errorf("%s is mode %o, want %o so the group can traverse it", path, mode.Perm(), dirMode)
				}
			}
		})
	}
	if after, gid := modeAndGroup(t, parent); after != before || gid != foreign {
		t.Errorf("%s went from %v in group %d to %v in group %d, want it left as it was", parent, before, foreign, after, gid)
	}
}

// modeAndGroup reads path itself, a link included
func modeAndGroup(t *testing.T, path string) (os.FileMode, int) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode(), int(info.Sys().(*syscall.Stat_t).Gid)
}
