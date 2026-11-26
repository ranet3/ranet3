// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build unix

package statefile

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestReplaceSyncedStagesAndPathBytes(t *testing.T) {
	failure := errors.New("isolated failure")
	for _, test := range []struct {
		name    string
		stage   Stage
		renamed bool
		ops     replaceOps
	}{
		{"write", StageWrite, false, replaceOps{write: func(*os.File, []byte) (int, error) { return 0, failure }}},
		{"file sync", StageFileSync, false, replaceOps{fileSync: func(*os.File) error { return failure }}},
		{"rename", StageRename, false, replaceOps{rename: func(string, string) error { return failure }}},
		{"directory sync", StageDirectorySync, true, replaceOps{dirSync: func(*os.File) error { return failure }}},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "trust.store")
			old := []byte("prior image")
			fresh := []byte("replacement image")
			if err := os.WriteFile(path, old, 0600); err != nil {
				t.Fatal(err)
			}
			err := replaceSynced(path, fresh, test.ops)
			var staged *ReplaceError
			if !errors.As(err, &staged) || staged.Stage != test.stage || staged.Renamed != test.renamed || !errors.Is(err, failure) {
				t.Fatalf("failure %v, want stage %q and renamed %t", err, test.stage, test.renamed)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			want := old
			if test.renamed {
				want = fresh
			}
			if !bytes.Equal(got, want) {
				t.Errorf("path bytes %q, want %q", got, want)
			}
			if _, err := os.Stat(path + tempSuffix); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("temporary file remains: %v", err)
			}
			if test.renamed {
				if err := syncDirectory(path, replaceOps{dirSync: func(*os.File) error { return nil }}); err != nil {
					t.Fatal(err)
				}
				got, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(got, fresh) {
					t.Errorf("directory-only retry changed the image: %q, %v", got, err)
				}
			}
		})
	}
}

func TestReplaceSyncedSuccessAndMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trust.store")
	if err := ReplaceSynced(path, []byte("complete")); err != nil {
		t.Fatal(err)
	}
	stat, err := os.Stat(path)
	if err != nil || stat.Mode().Perm() != mode {
		t.Fatalf("output mode: %v, %v", stat, err)
	}
	if err := SyncDirectory(path); err != nil {
		t.Fatal(err)
	}
}
