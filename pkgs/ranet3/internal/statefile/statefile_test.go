// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build unix

package statefile

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// a record one process holds is refused to a second until the first lets go
func TestSecondClaimIsRefusedWhileTheFirstHolds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "record.json")
	first, err := Take(path)
	if err != nil {
		t.Fatalf("the first claim: %v", err)
	}
	if second, err := Take(path); err == nil {
		_ = second.Close()
		t.Fatal("a second claim took a record the first holds")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := Take(path)
	if err != nil {
		t.Fatalf("a claim after the first let go: %v", err)
	}
	_ = again.Close()
}

// a record with no path is refused, whether claimed or written, so nothing is
// held with nothing recorded, and a write leaves the working directory alone
func TestRecordWithNoPathIsRefused(t *testing.T) {
	t.Chdir(t.TempDir())
	if lock, err := Take(""); !errors.Is(err, errNoPath) {
		if err == nil {
			_ = lock.Close()
		}
		t.Errorf("a claim of no path answered %v, want %v", err, errNoPath)
	}
	if err := Write("", []byte("{}")); !errors.Is(err, errNoPath) {
		t.Errorf("a write to no path answered %v, want %v", err, errNoPath)
	}
	if entries, err := os.ReadDir("."); err != nil || len(entries) != 0 {
		t.Errorf("the working directory holds %v (%v)", entries, err)
	}
}

// a lock file another open holds is refused at once, its error wrapping
// EWOULDBLOCK, which control's socket lock and Take each name in their own
// words, and taken again once the first lets go, at mode
func TestFlockRefusesALockAnotherHolds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.sock.lock")
	first, err := Flock(path)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != mode {
		t.Errorf("the lock file reads %v (%v), want mode %o", info, err, mode)
	}
	if second, err := Flock(path); !errors.Is(err, unix.EWOULDBLOCK) {
		if err == nil {
			_ = second.Close()
		}
		t.Errorf("a second lock answered %v, want EWOULDBLOCK", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := Flock(path)
	if err != nil {
		t.Fatalf("a lock after the first let go: %v", err)
	}
	_ = again.Close()
}

// each write, synced or not, lands on a new inode at mode and leaves no
// temporary file beside it, so a process killed mid-write leaves the earlier
// file whole, and a temporary file a crash left is written over
func TestWriteReplacesTheRecordWhole(t *testing.T) {
	for name, write := range map[string]func(string, []byte) error{"Write": Write, "WriteSynced": WriteSynced} {
		path := filepath.Join(t.TempDir(), "record.json")
		inode := func() uint64 {
			t.Helper()
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if perm := info.Mode().Perm(); perm != mode {
				t.Errorf("%s: the record is mode %o, want %o", name, perm, mode)
			}
			return info.Sys().(*syscall.Stat_t).Ino
		}
		if err := os.WriteFile(path+tempSuffix, []byte("a crash's half write, longer than the record"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := write(path, []byte("{}")); err != nil {
			t.Fatal(err)
		}
		first := inode()
		if err := write(path, []byte(`{"token":"1"}`)); err != nil {
			t.Fatal(err)
		}
		if second := inode(); second == first {
			t.Errorf("%s: both writes landed on inode %d, so the second rewrote the first in place", name, second)
		}
		if raw, err := os.ReadFile(path); err != nil || string(raw) != `{"token":"1"}` {
			t.Errorf("%s: the record holds %q (%v)", name, raw, err)
		}
		entries, err := os.ReadDir(filepath.Dir(path))
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 {
			t.Errorf("%s: the directory holds %d entries after two writes, want the record alone", name, len(entries))
		}
	}
}
